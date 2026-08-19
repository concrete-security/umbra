import asyncio
import base64
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from fastapi import HTTPException

from umbra_console import routes as routes_module
from umbra_console import routes_oauth
from umbra_console import scheduler
from umbra_console.auth import CurrentUser
from umbra_console.profile_secrets import (
    decrypt_managed_secret_value,
    decrypt_profile_secret_value,
    encrypt_managed_secret_value,
)
from umbra_console.routes_oauth import (
    ManagedSecretUpsert,
    delete_profile_managed_secret,
    list_profile_managed_secrets,
    upsert_profile_managed_secret,
)
from umbra_console.scheduler import (
    exchange_refresh_token,
    jwt_exp_claim,
    maybe_rotate_managed_secrets,
    rotate_managed_secret_row,
)

TEST_KEK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
ENTITY_ID = UUID("00000000-0000-4000-8000-000000000001")
PROFILE_ID = UUID("00000000-0000-4000-8000-000000000060")
NOW = datetime(2026, 7, 14, 12, 0, tzinfo=timezone.utc)


class AsyncContext:
    def __init__(self, value=None):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return AsyncContext(self.conn)


class RotationConn:
    def __init__(self, *, fetchval_results=None, fetchrow_rows=None, fetch_rows=None):
        self.fetchval_results = list(fetchval_results or [])
        self.fetchrow_rows = list(fetchrow_rows or [])
        self.fetch_rows = list(fetch_rows or [])
        self.fetchval_calls = []
        self.fetchrow_calls = []
        self.fetch_calls = []
        self.execute_calls = []

    def transaction(self):
        return AsyncContext()

    async def fetchval(self, sql, *args):
        self.fetchval_calls.append((sql, args))
        if self.fetchval_results:
            return self.fetchval_results.pop(0)
        return None

    async def fetchrow(self, sql, *args):
        self.fetchrow_calls.append((sql, args))
        if self.fetchrow_rows:
            return self.fetchrow_rows.pop(0)
        return None

    async def fetch(self, sql, *args):
        self.fetch_calls.append((sql, args))
        return self.fetch_rows

    async def execute(self, sql, *args):
        self.execute_calls.append((sql, args))
        return "OK"


def _patch_audit(monkeypatch, module):
    audits = []

    async def fake_audit(conn, **kwargs):
        audits.append(kwargs)

    monkeypatch.setattr(module, "insert_audit_event", fake_audit)
    return audits


def unverified_jwt(exp: int) -> str:
    payload = base64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=")
    return f"header.{payload}.sig"


@pytest.fixture(autouse=True)
def _allow_token_url_egress(monkeypatch):
    # The rotation path re-validates the token endpoint against the SSRF guard
    # (real DNS); neutralize it by default so unit tests don't hit the network.
    # SSRF behavior itself is covered in test_oauth_endpoints.py.
    monkeypatch.setattr(scheduler, "assert_token_url_egress_allowed", lambda url: None)


CODEX_POLICY = {
    "secret_injections": [
        {
            "id": "codex-chatgpt-oauth",
            "match": {
                "scheme": "https",
                "host": "chatgpt.com",
                "ports": [443],
                "methods": ["GET", "POST"],
                "path_prefixes": ["/backend-api/codex"],
            },
            "type": "request_header",
            "header": "authorization",
            "value_template": "Bearer ${secret}",
        }
    ]
}


def managed_row(monkeypatch, **overrides):
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    row = {
        "profile_id": PROFILE_ID,
        "injection_id": "codex-chatgpt-oauth",
        "token_url": "https://auth.openai.com/oauth/token",
        "client_id": "app_test",
        "refresh_token_ciphertext": encrypt_managed_secret_value(
            profile_id=PROFILE_ID, injection_id="codex-chatgpt-oauth", value="refresh-1"
        ),
        "account_id": "acct-1",
        "access_token_expires_at": NOW,
        "updated_at": NOW,
        "entity_id": ENTITY_ID,
        "policy": CODEX_POLICY,
    }
    row.update(overrides)
    return row


def test_jwt_exp_claim() -> None:
    exp = int((NOW + timedelta(days=10)).timestamp())
    assert jwt_exp_claim(unverified_jwt(exp)) == datetime.fromtimestamp(exp, tz=timezone.utc)
    assert jwt_exp_claim("not-a-jwt") is None
    assert jwt_exp_claim("a.b.c") is None


def test_managed_secret_due_backs_off_after_recent_failure(monkeypatch) -> None:
    monkeypatch.setattr(scheduler, "managed_secret_failure_backoff_seconds", lambda: 3600)
    now = datetime.now(timezone.utc)
    base = {"access_token_expires_at": None}  # expiry-due

    # Recently failed -> not due (inside the backoff window).
    assert not scheduler.managed_secret_due(
        {**base, "last_error": "refresh_error:invalid_grant", "last_attempt_at": now}
    )
    # Failure older than the window -> due again.
    assert scheduler.managed_secret_due(
        {
            **base,
            "last_error": "refresh_error:invalid_grant",
            "last_attempt_at": now - timedelta(hours=2),
        }
    )
    # No prior error -> due regardless of last_attempt_at.
    assert scheduler.managed_secret_due(
        {**base, "last_error": None, "last_attempt_at": now}
    )


class FakeResponse:
    def __init__(self, status_code=200, payload=None, malformed=False):
        self.status_code = status_code
        self._payload = payload
        self._malformed = malformed

    def json(self):
        if self._malformed:
            raise ValueError("not json")
        return self._payload


class FakeAsyncClient:
    sent = []

    def __init__(self, response):
        self._response = response

    def __call__(self, *args, **kwargs):
        return self

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json=None, headers=None):
        FakeAsyncClient.sent.append({"url": url, "json": json, "headers": headers})
        return self._response


def test_exchange_refresh_token_posts_json_grant(monkeypatch) -> None:
    monkeypatch.setattr(
        scheduler.httpx, "AsyncClient", FakeAsyncClient(FakeResponse(payload={"access_token": "a"}))
    )
    FakeAsyncClient.sent = []

    payload, error = asyncio.run(
        exchange_refresh_token(
            "https://auth.openai.com/oauth/token", client_id="app_test", refresh_token="refresh-1"
        )
    )

    assert error is None
    assert payload == {"access_token": "a"}
    sent = FakeAsyncClient.sent[0]
    assert sent["json"] == {
        "client_id": "app_test",
        "grant_type": "refresh_token",
        "refresh_token": "refresh-1",
    }


def test_rotate_managed_secret_row_success_rotates_and_mints(monkeypatch) -> None:
    audits = _patch_audit(monkeypatch, scheduler)
    row = managed_row(monkeypatch)
    access_token = unverified_jwt(int((NOW + timedelta(days=10)).timestamp()))

    async def fake_exchange(token_url, *, client_id, refresh_token):
        assert refresh_token == "refresh-1"
        return {"access_token": access_token, "refresh_token": "refresh-2"}, None

    monkeypatch.setattr(scheduler, "exchange_refresh_token", fake_exchange)
    conn = RotationConn(fetchval_results=[1])

    rotated, error = asyncio.run(rotate_managed_secret_row(conn, row))

    assert (rotated, error) == (True, None)
    guard_sql, guard_args = conn.fetchval_calls[0]
    assert "UPDATE profile_managed_secrets" in guard_sql
    assert "updated_at = $5" in guard_sql
    new_refresh_ciphertext = guard_args[2]
    assert new_refresh_ciphertext.startswith("v2:")
    assert (
        decrypt_managed_secret_value(
            profile_id=PROFILE_ID,
            injection_id="codex-chatgpt-oauth",
            ciphertext=new_refresh_ciphertext,
        )
        == "refresh-2"
    )
    material_sql, material_args = conn.execute_calls[0]
    assert "INSERT INTO profile_secret_material" in material_sql
    assert (
        decrypt_profile_secret_value(
            profile_id=PROFILE_ID,
            injection_id="codex-chatgpt-oauth",
            ciphertext=material_args[2],
        )
        == access_token
    )
    bump_sql, _ = conn.execute_calls[1]
    assert "policy_version = policy_version + 1" in bump_sql
    assert audits[0]["action"] == "PROFILE_SECRET_ROTATED"
    assert audits[0]["after"]["refresh_token_rotated"] is True
    assert access_token not in json.dumps(audits[0]["after"])


def test_rotate_managed_secret_row_failure_records_error(monkeypatch) -> None:
    audits = _patch_audit(monkeypatch, scheduler)
    row = managed_row(monkeypatch)

    async def failing_exchange(token_url, *, client_id, refresh_token):
        return None, "refresh_status:401"

    monkeypatch.setattr(scheduler, "exchange_refresh_token", failing_exchange)
    conn = RotationConn(fetchval_results=[1])  # failure CAS matches the row

    rotated, error = asyncio.run(rotate_managed_secret_row(conn, row))

    assert rotated is False
    assert error == "refresh_status:401"
    failure_sql, failure_args = conn.fetchval_calls[0]
    assert "last_error = $3" in failure_sql
    assert "updated_at = $4" in failure_sql  # CAS predicate present
    assert failure_args[2] == "refresh_status:401"
    assert failure_args[3] == NOW  # captured updated_at
    assert audits[0]["action"] == "PROFILE_SECRET_ROTATION_FAILED"


def test_rotate_managed_secret_row_failure_cas_miss_skips_audit(monkeypatch) -> None:
    # A stale failed attempt must not clobber a re-uploaded grant, nor emit a
    # misleading failure audit, when the CAS predicate no longer matches.
    audits = _patch_audit(monkeypatch, scheduler)
    row = managed_row(monkeypatch)

    async def failing_exchange(token_url, *, client_id, refresh_token):
        return None, "refresh_status:401"

    monkeypatch.setattr(scheduler, "exchange_refresh_token", failing_exchange)
    conn = RotationConn(fetchval_results=[None])  # CAS matched nothing

    rotated, error = asyncio.run(rotate_managed_secret_row(conn, row))

    assert (rotated, error) == (False, "refresh_status:401")
    assert audits == []


def test_rotate_managed_secret_row_rejects_over_long_rendered_value(monkeypatch) -> None:
    audits = _patch_audit(monkeypatch, scheduler)
    row = managed_row(monkeypatch)
    huge = "x" * 9000  # "Bearer " + 9000 > 8192

    async def fake_exchange(token_url, *, client_id, refresh_token):
        return {"access_token": huge}, None

    monkeypatch.setattr(scheduler, "exchange_refresh_token", fake_exchange)
    conn = RotationConn(fetchval_results=[1])

    rotated, error = asyncio.run(rotate_managed_secret_row(conn, row))

    assert (rotated, error) == (False, "rendered_value_too_long")
    # No material was written — only the failure CAS ran.
    assert not any("profile_secret_material" in sql for sql, _ in conn.execute_calls)
    assert audits[0]["action"] == "PROFILE_SECRET_ROTATION_FAILED"


def test_rotate_managed_secret_row_blocks_ssrf_token_url(monkeypatch) -> None:
    from umbra_console.oauth_endpoints import TokenEndpointError

    _patch_audit(monkeypatch, scheduler)
    row = managed_row(monkeypatch, token_url="https://internal.local/oauth/token")

    def deny(url):
        raise TokenEndpointError("blocked")

    monkeypatch.setattr(scheduler, "assert_token_url_egress_allowed", deny)
    exchanged = []

    async def fake_exchange(token_url, *, client_id, refresh_token):
        exchanged.append(token_url)
        return {"access_token": "a"}, None

    monkeypatch.setattr(scheduler, "exchange_refresh_token", fake_exchange)
    conn = RotationConn(fetchval_results=[1])

    rotated, error = asyncio.run(rotate_managed_secret_row(conn, row))

    assert (rotated, error) == (False, "token_url_not_allowed")
    assert exchanged == []  # never reached the provider


def test_rotate_managed_secret_row_superseded_skips(monkeypatch) -> None:
    audits = _patch_audit(monkeypatch, scheduler)
    row = managed_row(monkeypatch)

    async def fake_exchange(token_url, *, client_id, refresh_token):
        return {"access_token": unverified_jwt(int((NOW + timedelta(days=1)).timestamp()))}, None

    monkeypatch.setattr(scheduler, "exchange_refresh_token", fake_exchange)
    conn = RotationConn(fetchval_results=[None])  # guard update matched nothing

    rotated, error = asyncio.run(rotate_managed_secret_row(conn, row))

    assert (rotated, error) == (False, "superseded")
    assert conn.execute_calls == []  # no material write, no bump
    assert audits == []


def test_maybe_rotate_managed_secrets_gate_and_lock(monkeypatch) -> None:
    monkeypatch.setattr(scheduler, "_last_managed_secret_rotation_wall", None)
    conn = RotationConn(fetchval_results=[True])  # advisory lock granted
    conn.fetch_rows = []

    events = asyncio.run(maybe_rotate_managed_secrets(conn))
    assert events == []
    lock_sql, lock_args = conn.fetchval_calls[0]
    assert "pg_try_advisory_lock" in lock_sql
    assert lock_args == (scheduler.MANAGED_SECRET_ROTATION_LOCK_ID,)
    unlock_sql, _ = conn.execute_calls[-1]
    assert "pg_advisory_unlock" in unlock_sql

    # Within the wall-clock gate: no second lock attempt.
    conn2 = RotationConn(fetchval_results=[True])
    events = asyncio.run(maybe_rotate_managed_secrets(conn2))
    assert events == []
    assert conn2.fetchval_calls == []

    # Lock contention: skip silently without unlocking.
    monkeypatch.setattr(scheduler, "_last_managed_secret_rotation_wall", None)
    conn3 = RotationConn(fetchval_results=[False])
    events = asyncio.run(maybe_rotate_managed_secrets(conn3))
    assert events == []
    assert conn3.execute_calls == []


def test_rotate_managed_secret_locked_skips_when_per_secret_lock_busy(monkeypatch) -> None:
    # Scheduler path (blocking=False): another worker holds the per-secret
    # lock, so this pass skips the row rather than double-submitting.
    conn = RotationConn(fetchval_results=[False])  # pg_try_advisory_lock -> False
    rotated, error = asyncio.run(
        scheduler.rotate_managed_secret_locked(
            conn, profile_id=PROFILE_ID, injection_id="codex-chatgpt-oauth", blocking=False
        )
    )
    assert (rotated, error) == (False, "locked")
    # No unlock issued (we never acquired it) and no rotation ran.
    assert not any("pg_advisory_unlock" in sql for sql, _ in conn.execute_calls)


def test_rotate_managed_secret_locked_blocking_takes_and_releases_lock(monkeypatch) -> None:
    # PUT path (blocking=True): acquire the blocking lock, and if the secret is
    # already fresh (rotated by the scheduler meanwhile) report success without
    # burning another one-shot refresh; always release the lock.
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    # Far-future expiry so the row is unambiguously not-due regardless of the
    # real wall clock the due-check reads.
    fresh = managed_row(monkeypatch, access_token_expires_at=NOW + timedelta(days=3650))
    conn = RotationConn(fetchrow_rows=[fresh])
    exchanged = []

    async def fake_exchange(token_url, *, client_id, refresh_token):
        exchanged.append(token_url)
        return {"access_token": "a"}, None

    monkeypatch.setattr(scheduler, "exchange_refresh_token", fake_exchange)

    rotated, error = asyncio.run(
        scheduler.rotate_managed_secret_locked(
            conn, profile_id=PROFILE_ID, injection_id="codex-chatgpt-oauth", blocking=True
        )
    )

    assert (rotated, error) == (True, None)  # not-due treated as success
    assert exchanged == []  # no second rotation
    assert any("pg_advisory_lock(" in sql for sql, _ in conn.execute_calls)
    assert any("pg_advisory_unlock(" in sql for sql, _ in conn.execute_calls)


def test_rotate_due_managed_secrets_isolates_per_row_failures(monkeypatch) -> None:
    good = UUID("00000000-0000-4000-8000-0000000000a1")
    poison = UUID("00000000-0000-4000-8000-0000000000a2")
    conn = RotationConn(
        fetch_rows=[
            {"profile_id": poison, "injection_id": "x", "updated_at": NOW, "entity_id": ENTITY_ID},
            {"profile_id": good, "injection_id": "y", "updated_at": NOW, "entity_id": ENTITY_ID},
        ]
    )
    failures = []

    async def fake_failure(inner, row, error):
        failures.append((row["profile_id"], error))

    async def fake_locked(inner, *, profile_id, injection_id, blocking):
        if profile_id == poison:
            raise RuntimeError("corrupt ciphertext")
        return True, None

    monkeypatch.setattr(scheduler, "rotate_managed_secret_locked", fake_locked)
    monkeypatch.setattr(scheduler, "_record_managed_secret_failure", fake_failure)

    events = asyncio.run(scheduler.rotate_due_managed_secrets(conn))

    # The poison row is recorded and the batch continues to the good row.
    assert any(str(poison) in e and e.endswith(":error") for e in events)
    assert any(str(good) in e and e.endswith(":ok") for e in events)
    assert failures and failures[0][0] == poison


# --- endpoints -----------------------------------------------------------------


def admin_user(*, permissions=("USER_MANAGE",)):
    return CurrentUser(
        id=UUID("00000000-0000-4000-8000-000000000061"),
        email="admin@acme.test",
        name="Admin",
        entity_id=ENTITY_ID,
        entity_name="acme",
        permissions=frozenset(permissions),
    )


def profile_write_row(member_count=1, assigned=True):
    return {
        "id": PROFILE_ID,
        "entity_id": ENTITY_ID,
        "policy": {
            "secret_injections": [
                {
                    "id": "codex-chatgpt-oauth",
                    "match": {
                        "scheme": "https",
                        "host": "chatgpt.com",
                        "ports": [443],
                        "methods": ["GET", "POST"],
                        "path_prefixes": ["/backend-api/codex"],
                    },
                    "type": "request_header",
                    "header": "authorization",
                    "value_template": "Bearer ${secret}",
                }
            ]
        },
        "assigned": assigned,
        "member_count": member_count,
    }


def full_row():
    return {
        "profile_id": PROFILE_ID,
        "injection_id": "codex-chatgpt-oauth",
        "provider": "oauth_refresh_token",
        "token_url": "https://auth.openai.com/oauth/token",
        "client_id": "app_test",
        "account_id": "acct-1",
        "access_token_expires_at": NOW,
        "last_rotated_at": NOW,
        "last_attempt_at": NOW,
        "last_error": None,
        "created_at": NOW,
        "updated_at": NOW,
    }


def upsert_body():
    return ManagedSecretUpsert(
        token_url="https://auth.openai.com/oauth/token",
        client_id="app_test",
        refresh_token="refresh-1",
        account_id="acct-1",
    )


def test_upsert_managed_secret_stores_encrypted_and_first_rotates(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    audits = _patch_audit(monkeypatch, routes_oauth)
    rotations = []

    async def fake_rotate_now(conn, *, profile_id, injection_id):
        rotations.append((profile_id, injection_id))
        return True, None

    async def fake_full_row(conn, profile_id, injection_id):
        return full_row()

    monkeypatch.setattr(scheduler, "rotate_managed_secret_now", fake_rotate_now)
    monkeypatch.setattr(routes_oauth, "fetch_managed_secret_full_row", fake_full_row)
    conn = RotationConn(fetchrow_rows=[profile_write_row()])

    result = asyncio.run(
        upsert_profile_managed_secret(
            profile_id=PROFILE_ID,
            injection_id="codex-chatgpt-oauth",
            body=upsert_body(),
            current_user=admin_user(),
            pool=FakePool(conn),
        )
    )

    assert result["rotated"] is True
    assert "rotation_error" not in result
    assert "refresh-1" not in json.dumps(result)
    assert "refresh_token_ciphertext" not in result
    insert_sql, insert_args = conn.execute_calls[0]
    assert "INSERT INTO profile_managed_secrets" in insert_sql
    assert insert_args[4].startswith("v2:")
    assert "refresh-1" not in insert_args[4]
    assert rotations == [(PROFILE_ID, "codex-chatgpt-oauth")]
    assert audits[0]["action"] == "PROFILE_MANAGED_SECRET_CONFIGURED"
    assert "refresh-1" not in json.dumps(audits[0]["after"])


def test_upsert_managed_secret_surfaces_first_rotation_failure(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    _patch_audit(monkeypatch, routes_oauth)

    async def fake_rotate_now(conn, *, profile_id, injection_id):
        return False, "refresh_status:401"

    async def fake_full_row(conn, profile_id, injection_id):
        row = full_row()
        row["last_error"] = "refresh_status:401"
        return row

    monkeypatch.setattr(scheduler, "rotate_managed_secret_now", fake_rotate_now)
    monkeypatch.setattr(routes_oauth, "fetch_managed_secret_full_row", fake_full_row)
    conn = RotationConn(fetchrow_rows=[profile_write_row()])

    result = asyncio.run(
        upsert_profile_managed_secret(
            profile_id=PROFILE_ID,
            injection_id="codex-chatgpt-oauth",
            body=upsert_body(),
            current_user=admin_user(),
            pool=FakePool(conn),
        )
    )

    assert result["rotated"] is False
    assert result["rotation_error"] == "refresh_status:401"
    assert result["last_error"] == "refresh_status:401"


def test_upsert_managed_secret_enforces_write_rule_and_declaration(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    _patch_audit(monkeypatch, routes_oauth)

    conn = RotationConn(fetchrow_rows=[profile_write_row(member_count=2)])
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            upsert_profile_managed_secret(
                profile_id=PROFILE_ID,
                injection_id="codex-chatgpt-oauth",
                body=upsert_body(),
                current_user=admin_user(permissions=()),
                pool=FakePool(conn),
            )
        )
    assert exc.value.status_code == 409

    conn = RotationConn(fetchrow_rows=[profile_write_row()])
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            upsert_profile_managed_secret(
                profile_id=PROFILE_ID,
                injection_id="not-declared",
                body=upsert_body(),
                current_user=admin_user(),
                pool=FakePool(conn),
            )
        )
    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["state"] == "unknown_injection"


def test_list_managed_secrets_redacts_and_404s_non_members(monkeypatch) -> None:
    conn = RotationConn(fetchrow_rows=[{"entity_id": ENTITY_ID, "assigned": True}])
    conn.fetch_rows = [full_row()]

    result = asyncio.run(
        list_profile_managed_secrets(
            profile_id=PROFILE_ID, current_user=admin_user(permissions=()), pool=FakePool(conn)
        )
    )
    entry = result["managed_secrets"][0]
    assert entry["injection_id"] == "codex-chatgpt-oauth"
    assert "refresh_token_ciphertext" not in entry
    assert entry["access_token_expires_at"].endswith("Z")

    conn = RotationConn(fetchrow_rows=[{"entity_id": ENTITY_ID, "assigned": False}])
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            list_profile_managed_secrets(
                profile_id=PROFILE_ID, current_user=admin_user(permissions=()), pool=FakePool(conn)
            )
        )
    assert exc.value.status_code == 404


def test_delete_managed_secret_deletes_row_only(monkeypatch) -> None:
    audits = _patch_audit(monkeypatch, routes_oauth)

    class DeleteConn(RotationConn):
        async def execute(self, sql, *args):
            self.execute_calls.append((sql, args))
            if "DELETE FROM profile_managed_secrets" in sql:
                return "DELETE 1"
            return "OK"

    conn = DeleteConn(fetchrow_rows=[profile_write_row()])

    response = asyncio.run(
        delete_profile_managed_secret(
            profile_id=PROFILE_ID,
            injection_id="codex-chatgpt-oauth",
            current_user=admin_user(),
            pool=FakePool(conn),
        )
    )

    assert response.status_code == 204
    delete_sql, _ = conn.execute_calls[0]
    assert "DELETE FROM profile_managed_secrets" in delete_sql
    assert not any("profile_secret_material" in sql for sql, _ in conn.execute_calls)
    assert audits[0]["action"] == "PROFILE_MANAGED_SECRET_DELETED"


def test_profile_secrets_status_reports_material_managed_and_connection(monkeypatch) -> None:
    from umbra_console.routes_oauth import profile_secrets_status

    class StatusConn(RotationConn):
        def __init__(self):
            super().__init__(
                fetchrow_rows=[
                    {
                        "entity_id": ENTITY_ID,
                        "assigned": True,
                        "policy": profile_write_row()["policy"],
                    },
                    {"integration_name": "slack", "used_at": None, "error": "exchange_status:500"},
                ]
            )
            self.fetch_queue = [
                [{"injection_id": "codex-chatgpt-oauth", "updated_at": NOW}],
                [
                    {
                        "injection_id": "codex-chatgpt-oauth",
                        "account_id": "acct-1",
                        "access_token_expires_at": NOW,
                        "last_rotated_at": NOW,
                        "last_attempt_at": NOW,
                        "last_error": None,
                    }
                ],
            ]

        async def fetch(self, sql, *args):
            if self.fetch_queue:
                return self.fetch_queue.pop(0)
            return []

    conn = StatusConn()
    result = asyncio.run(
        profile_secrets_status(
            profile_id=PROFILE_ID,
            current_user=admin_user(permissions=()),
            pool=FakePool(conn),
        )
    )

    entry = result["injections"][0]
    assert entry["injection_id"] == "codex-chatgpt-oauth"
    assert entry["material_present"] is True
    assert entry["managed"]["access_token_expires_at"].endswith("Z")
    assert entry["managed"]["last_error"] is None
    assert result["last_connection"] == {
        "integration": "slack",
        "connected_at": None,
        "error": "exchange_status:500",
    }
    assert "ciphertext" not in json.dumps(result)


def test_profile_secrets_status_404s_non_members() -> None:
    from umbra_console.routes_oauth import profile_secrets_status

    conn = RotationConn(
        fetchrow_rows=[{"entity_id": ENTITY_ID, "assigned": False, "policy": {}}]
    )
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            profile_secrets_status(
                profile_id=PROFILE_ID,
                current_user=admin_user(permissions=()),
                pool=FakePool(conn),
            )
        )
    assert exc.value.status_code == 404


def test_prune_expired_oauth_connection_states(monkeypatch) -> None:
    monkeypatch.setenv("OAUTH_CONNECTION_STATE_RETENTION_SECONDS", "2592000")

    class PruneConn:
        def __init__(self, result):
            self.result = result
            self.calls = []

        async def execute(self, sql, *args):
            self.calls.append((sql, args))
            return self.result

    conn = PruneConn("DELETE 5")
    events = asyncio.run(scheduler.prune_expired_oauth_connection_states(conn))
    assert events == ["maintenance:oauth_connection_states:5"]
    assert "DELETE FROM oauth_connection_states" in conn.calls[0][0]

    # Nothing to prune -> no event.
    conn = PruneConn("DELETE 0")
    assert asyncio.run(scheduler.prune_expired_oauth_connection_states(conn)) == []
