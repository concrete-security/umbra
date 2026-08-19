import asyncio
import json
from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest
from fastapi import HTTPException
from pydantic import ValidationError

from umbra_console import routes as routes_module
from umbra_console import routes_oauth
from umbra_console.auth import CurrentUser
from umbra_console.profile_secrets import (
    decrypt_oauth_client_secret,
    decrypt_profile_secret_value,
    encrypt_oauth_client_secret,
    encrypt_profile_secret_value,
)
from umbra_console.routes import validate_profile_policy
from umbra_console.routes_oauth import (
    OAuthIntegrationUpsert,
    ProfileConnectionCreate,
    build_connect_url,
    create_profile_connection,
    delete_oauth_integration,
    exchange_authorization_code,
    list_oauth_integrations,
    oauth_connection_callback,
    resolve_json_pointer,
    upsert_oauth_integration,
)

TEST_KEK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
ENTITY_ID = UUID("00000000-0000-4000-8000-000000000001")
OTHER_ENTITY_ID = UUID("00000000-0000-4000-8000-000000000002")
PROFILE_ID = UUID("00000000-0000-4000-8000-000000000060")
STATE_ID = UUID("00000000-0000-4000-8000-000000000090")
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


class SequencedConn:
    """fetchrow pops canned rows in order; fetch returns one canned list;
    execute records calls."""

    def __init__(self, fetchrow_rows=None, fetch_rows=None, fetchval_results=None):
        self.fetchrow_rows = list(fetchrow_rows or [])
        self.fetch_rows = list(fetch_rows or [])
        self.fetchval_results = list(fetchval_results or [])
        self.fetchrow_calls = []
        self.fetchval_calls = []
        self.execute_calls = []

    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, sql, *args):
        self.fetchrow_calls.append((sql, args))
        if self.fetchrow_rows:
            return self.fetchrow_rows.pop(0)
        return None

    async def fetchval(self, sql, *args):
        self.fetchval_calls.append((sql, args))
        if self.fetchval_results:
            return self.fetchval_results.pop(0)
        return None

    async def fetch(self, sql, *args):
        return self.fetch_rows

    async def execute(self, sql, *args):
        self.execute_calls.append((sql, args))
        return "OK"


def admin_user(*, entity_id=ENTITY_ID, permissions=("USER_MANAGE",)):
    return CurrentUser(
        id=UUID("00000000-0000-4000-8000-000000000061"),
        email="admin@acme.test",
        name="Admin",
        entity_id=entity_id,
        entity_name="acme",
        permissions=frozenset(permissions),
    )


def _patch_audit(monkeypatch):
    audits = []

    async def fake_audit(conn, **kwargs):
        audits.append(kwargs)

    monkeypatch.setattr(routes_oauth, "insert_audit_event", fake_audit)
    return audits


def integration_body(**overrides):
    body = {
        "authorize_url": "https://slack.com/oauth/v2/authorize?user_scope=chat:write",
        "token_url": "https://slack.com/api/oauth.v2.access",
        "client_id": "1234.5678",
        "client_secret": "shhh-client-secret",
        "scopes": "",
        "token_pointer": "/authed_user/access_token",
    }
    body.update(overrides)
    return OAuthIntegrationUpsert(**body)


def integration_row(**overrides):
    row = {
        "entity_id": ENTITY_ID,
        "name": "slack",
        "authorize_url": "https://slack.com/oauth/v2/authorize?user_scope=chat:write",
        "token_url": "https://slack.com/api/oauth.v2.access",
        "client_id": "1234.5678",
        "scopes": "",
        "token_pointer": "/authed_user/access_token",
        "profile_policy_template": None,
        "created_at": NOW,
        "updated_at": NOW,
    }
    row.update(overrides)
    return row


# --- crypto -----------------------------------------------------------------


def test_oauth_client_secret_round_trips(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    ciphertext = encrypt_oauth_client_secret(entity_id=ENTITY_ID, name="slack", value="s3cret")
    assert ciphertext.startswith("v2:")
    assert "s3cret" not in ciphertext
    assert (
        decrypt_oauth_client_secret(entity_id=ENTITY_ID, name="slack", ciphertext=ciphertext)
        == "s3cret"
    )


def test_oauth_client_secret_aad_domain_is_disjoint_from_profile_secrets(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    profile_ciphertext = encrypt_profile_secret_value(
        profile_id=ENTITY_ID, injection_id="slack", value="s3cret"
    )
    with pytest.raises(Exception):
        decrypt_oauth_client_secret(
            entity_id=ENTITY_ID, name="slack", ciphertext=profile_ciphertext
        )
    oauth_ciphertext = encrypt_oauth_client_secret(entity_id=ENTITY_ID, name="slack", value="x")
    with pytest.raises(Exception):
        decrypt_profile_secret_value(
            profile_id=ENTITY_ID, injection_id="slack", ciphertext=oauth_ciphertext
        )


# --- template validation mode -----------------------------------------------


def template_policy(with_value: bool = False, value_from: bool = False):
    injection = {
        "id": "slack-user-token",
        "match": {
            "scheme": "https",
            "host": "slack.com",
            "ports": [443],
            "methods": ["POST"],
            "path_prefixes": ["/api/"],
        },
        "type": "request_header",
        "header": "authorization",
        "value_template": "Bearer ${secret}",
    }
    if with_value:
        injection["value"] = "xoxp-inline"
    if value_from:
        injection["value_from"] = {"user_secret": "slack-personal"}
    return {"secret_injections": [injection]}


def test_validate_profile_policy_template_mode_forbids_inline_values() -> None:
    validate_profile_policy(template_policy(), require_injection_values=False)

    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(template_policy(with_value=True), require_injection_values=False)
    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "value_forbidden" for error in errors)

    # Configure mode requires each injection to bind exactly one value source
    # (inline `value` XOR per-user `value_from`); a bare injection with neither
    # is rejected as value_xor_value_from. (Template mode above allows a
    # neither-injection as a mint-later placeholder.)
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(template_policy())
    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "value_xor_value_from" for error in errors)


# --- integration upsert / list ------------------------------------------------


def test_upsert_oauth_integration_encrypts_and_audits(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    audits = _patch_audit(monkeypatch)
    conn = SequencedConn(fetchrow_rows=[integration_row()])

    result = asyncio.run(
        upsert_oauth_integration(
            entity_id=ENTITY_ID,
            name="slack",
            body=integration_body(),
            current_user=admin_user(),
            pool=FakePool(conn),
        )
    )

    assert result["name"] == "slack"
    assert "client_secret" not in result
    assert "client_secret_ciphertext" not in result
    sql, args = conn.fetchrow_calls[0]
    assert "INSERT INTO oauth_integrations" in sql
    ciphertext = args[5]
    assert ciphertext.startswith("v2:")
    assert "shhh-client-secret" not in ciphertext
    assert audits[0]["action"] == "OAUTH_INTEGRATION_CONFIGURED"
    assert "client_secret" not in json.dumps(audits[0]["after"])
    assert "shhh" not in json.dumps(audits[0]["after"])


def test_upsert_oauth_integration_preserves_secret_when_omitted(monkeypatch) -> None:
    # Update with no client_secret: the row exists, so COALESCE keeps the
    # stored ciphertext and no new ciphertext is passed.
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    _patch_audit(monkeypatch)
    conn = SequencedConn(fetchrow_rows=[integration_row()], fetchval_results=[1])  # exists

    result = asyncio.run(
        upsert_oauth_integration(
            entity_id=ENTITY_ID,
            name="slack",
            body=integration_body(client_secret=None),
            current_user=admin_user(),
            pool=FakePool(conn),
        )
    )

    assert result["name"] == "slack"
    sql, args = conn.fetchrow_calls[0]
    assert "COALESCE(" in sql
    assert args[5] is None  # no new ciphertext -> COALESCE preserves the old one


def test_upsert_oauth_integration_requires_secret_on_create(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    _patch_audit(monkeypatch)
    conn = SequencedConn(fetchval_results=[None])  # no existing row

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            upsert_oauth_integration(
                entity_id=ENTITY_ID,
                name="slack",
                body=integration_body(client_secret=None),
                current_user=admin_user(),
                pool=FakePool(conn),
            )
        )

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["field"] == "client_secret"


def test_upsert_oauth_integration_requires_user_manage(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    conn = SequencedConn()

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            upsert_oauth_integration(
                entity_id=ENTITY_ID,
                name="slack",
                body=integration_body(),
                current_user=admin_user(permissions=()),
                pool=FakePool(conn),
            )
        )

    assert exc.value.status_code == 403


def test_upsert_oauth_integration_rejects_bad_name_and_template(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    _patch_audit(monkeypatch)
    conn = SequencedConn(fetchrow_rows=[integration_row()])

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            upsert_oauth_integration(
                entity_id=ENTITY_ID,
                name="Bad_Name!",
                body=integration_body(),
                current_user=admin_user(),
                pool=FakePool(conn),
            )
        )
    assert exc.value.status_code == 422

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            upsert_oauth_integration(
                entity_id=ENTITY_ID,
                name="slack",
                body=integration_body(profile_policy_template=template_policy(with_value=True)),
                current_user=admin_user(),
                pool=FakePool(conn),
            )
        )
    assert exc.value.status_code == 422

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            upsert_oauth_integration(
                entity_id=ENTITY_ID,
                name="slack",
                body=integration_body(profile_policy_template={"allowed_destinations": []}),
                current_user=admin_user(),
                pool=FakePool(conn),
            )
        )
    assert exc.value.status_code == 422

    # A value_from-only template validates in template mode but is not
    # connectable — a connect link mints a provider token into an inline-value
    # slot — so it is rejected for lacking a mintable injection.
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            upsert_oauth_integration(
                entity_id=ENTITY_ID,
                name="slack",
                body=integration_body(profile_policy_template=template_policy(value_from=True)),
                current_user=admin_user(),
                pool=FakePool(conn),
            )
        )
    assert exc.value.status_code == 422


def test_oauth_integration_body_validators() -> None:
    with pytest.raises(ValidationError):
        integration_body(authorize_url="http://slack.com/authorize")
    with pytest.raises(ValidationError):
        integration_body(token_url="https://")
    with pytest.raises(ValidationError):
        integration_body(token_pointer="no-leading-slash")
    with pytest.raises(ValidationError):
        integration_body(token_pointer="/")
    with pytest.raises(ValidationError):
        integration_body(client_secret="line1\nline2")
    assert integration_body(token_pointer="/access_token").token_pointer == "/access_token"


def test_list_oauth_integrations_redacts(monkeypatch) -> None:
    conn = SequencedConn()
    conn.fetch_rows = [integration_row()]

    result = asyncio.run(
        list_oauth_integrations(
            entity_id=ENTITY_ID, current_user=admin_user(), pool=FakePool(conn)
        )
    )

    assert result["integrations"][0]["name"] == "slack"
    assert "client_secret_ciphertext" not in result["integrations"][0]
    assert result["integrations"][0]["has_profile_policy_template"] is False


class DeleteConn(SequencedConn):
    def __init__(self, delete_result):
        super().__init__()
        self._delete_result = delete_result

    async def execute(self, sql, *args):
        self.execute_calls.append((sql, args))
        if "DELETE FROM oauth_integrations" in sql:
            return self._delete_result
        return "OK"


def test_delete_oauth_integration_purges_and_audits(monkeypatch) -> None:
    audits = _patch_audit(monkeypatch)
    conn = DeleteConn("DELETE 1")

    response = asyncio.run(
        delete_oauth_integration(
            entity_id=ENTITY_ID, name="slack", current_user=admin_user(), pool=FakePool(conn)
        )
    )

    assert response.status_code == 204
    assert any("DELETE FROM oauth_integrations" in sql for sql, _ in conn.execute_calls)
    assert audits[0]["action"] == "OAUTH_INTEGRATION_DELETED"


def test_delete_oauth_integration_missing_is_404(monkeypatch) -> None:
    audits = _patch_audit(monkeypatch)
    conn = DeleteConn("DELETE 0")

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            delete_oauth_integration(
                entity_id=ENTITY_ID, name="nope", current_user=admin_user(), pool=FakePool(conn)
            )
        )

    assert exc.value.status_code == 404
    assert audits == []


def test_delete_oauth_integration_requires_user_manage(monkeypatch) -> None:
    conn = DeleteConn("DELETE 1")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            delete_oauth_integration(
                entity_id=ENTITY_ID,
                name="slack",
                current_user=admin_user(permissions=()),
                pool=FakePool(conn),
            )
        )
    assert exc.value.status_code == 403


# --- connect link creation -----------------------------------------------------


def profile_row():
    return {
        "id": PROFILE_ID,
        "entity_id": ENTITY_ID,
        "policy": {
            "secret_injections": [
                {
                    "id": "slack-user-token",
                    "match": {"scheme": "https", "host": "slack.com", "ports": [443]},
                    "type": "request_header",
                    "header": "authorization",
                    "value_template": "Bearer ${secret}",
                }
            ]
        },
    }


def test_create_profile_connection_mints_hashed_single_use_state(monkeypatch) -> None:
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.test/")
    audits = _patch_audit(monkeypatch)
    conn = SequencedConn(fetchrow_rows=[profile_row(), integration_row()])

    result = asyncio.run(
        create_profile_connection(
            profile_id=PROFILE_ID,
            body=ProfileConnectionCreate(integration="slack"),
            current_user=admin_user(),
            pool=FakePool(conn),
        )
    )

    connect_url = result["connect_url"]
    assert connect_url.startswith("https://slack.com/oauth/v2/authorize?")
    assert "user_scope=chat%3Awrite" in connect_url or "user_scope=chat:write" in connect_url
    assert "redirect_uri=https%3A%2F%2Fconsole.example.test%2Foauth%2Fcallback" in connect_url
    assert "response_type=code" in connect_url
    assert "state=" in connect_url
    raw_state = connect_url.split("state=")[1].split("&")[0]

    insert_sql, insert_args = conn.execute_calls[0]
    assert "INSERT INTO oauth_connection_states" in insert_sql
    stored_hash = insert_args[3]
    assert stored_hash != raw_state
    assert len(stored_hash) == 64
    assert raw_state not in json.dumps(audits[0]["after"])
    assert json.loads(insert_args[5]) == ["slack-user-token"]
    assert audits[0]["action"] == "PROFILE_CONNECTION_LINK_CREATED"


def test_create_profile_connection_rejects_unknown_injection(monkeypatch) -> None:
    _patch_audit(monkeypatch)
    conn = SequencedConn(fetchrow_rows=[profile_row(), integration_row()])

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            create_profile_connection(
                profile_id=PROFILE_ID,
                body=ProfileConnectionCreate(integration="slack", injection_ids=["nope"]),
                current_user=admin_user(),
                pool=FakePool(conn),
            )
        )

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["state"] == "unknown_injection"


def test_create_profile_connection_404s_without_profile_or_integration(monkeypatch) -> None:
    _patch_audit(monkeypatch)
    conn = SequencedConn(fetchrow_rows=[])
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            create_profile_connection(
                profile_id=PROFILE_ID,
                body=ProfileConnectionCreate(integration="slack"),
                current_user=admin_user(),
                pool=FakePool(conn),
            )
        )
    assert exc.value.status_code == 404

    conn = SequencedConn(fetchrow_rows=[profile_row()])
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            create_profile_connection(
                profile_id=PROFILE_ID,
                body=ProfileConnectionCreate(integration="slack"),
                current_user=admin_user(),
                pool=FakePool(conn),
            )
        )
    assert exc.value.status_code == 404


def test_build_connect_url_merges_existing_query_params(monkeypatch) -> None:
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.test")
    url = build_connect_url(integration_row(scopes="users:read"), "STATE123")
    assert "user_scope=chat:write" in url
    assert "scope=users%3Aread" in url
    assert "state=STATE123" in url


# --- pointer + exchange ---------------------------------------------------------


def test_resolve_json_pointer() -> None:
    payload = {"authed_user": {"access_token": "xoxp-1"}, "list": [{"a": "b"}]}
    assert resolve_json_pointer(payload, "/authed_user/access_token") == "xoxp-1"
    assert resolve_json_pointer(payload, "/list/0/a") == "b"
    assert resolve_json_pointer(payload, "/missing") is None
    assert resolve_json_pointer({"a~b": {"c/d": "v"}}, "/a~0b/c~1d") == "v"


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

    async def post(self, url, data=None, headers=None):
        FakeAsyncClient.sent.append({"url": url, "data": data, "headers": headers})
        return self._response


def run_exchange(monkeypatch, response):
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.test")
    monkeypatch.setattr(routes_oauth.httpx, "AsyncClient", FakeAsyncClient(response))
    # Stub the egress guard so the exchange never resolves the real token host
    # (slack.com) — network-restricted runs would otherwise fail here. The
    # guard's own behavior is covered by test_oauth_endpoints.py.
    monkeypatch.setattr(routes_oauth, "assert_token_url_egress_allowed", lambda *a, **k: None)
    FakeAsyncClient.sent = []
    return asyncio.run(
        exchange_authorization_code(
            integration_row(), client_secret="shhh-client-secret", code="the-code"
        )
    )


def test_exchange_authorization_code_success(monkeypatch) -> None:
    token, error = run_exchange(
        monkeypatch,
        FakeResponse(payload={"ok": True, "authed_user": {"access_token": "xoxp-token "}}),
    )
    assert error is None
    assert token == "xoxp-token"
    sent = FakeAsyncClient.sent[0]
    assert sent["data"]["grant_type"] == "authorization_code"
    assert sent["data"]["client_secret"] == "shhh-client-secret"
    assert sent["data"]["redirect_uri"] == "https://console.example.test/oauth/callback"


def test_exchange_authorization_code_error_paths(monkeypatch) -> None:
    _, error = run_exchange(monkeypatch, FakeResponse(status_code=500, payload={}))
    assert error == "exchange_status:500"

    _, error = run_exchange(monkeypatch, FakeResponse(malformed=True))
    assert error == "exchange_malformed_response"

    _, error = run_exchange(
        monkeypatch, FakeResponse(payload={"ok": False, "error": "invalid_code"})
    )
    assert error == "exchange_error:invalid_code"

    _, error = run_exchange(
        monkeypatch, FakeResponse(payload={"error": {"code": "bad_grant", "message": "no"}})
    )
    assert error == "exchange_error:bad_grant"

    _, error = run_exchange(monkeypatch, FakeResponse(payload={"ok": True}))
    assert error == "token_pointer_miss"


# --- public callback -------------------------------------------------------------


CREATED_BY = UUID("00000000-0000-4000-8000-0000000000c1")


def state_row():
    return {
        "id": STATE_ID,
        "entity_id": ENTITY_ID,
        "integration_name": "slack",
        "profile_id": PROFILE_ID,
        "injection_ids": ["slack-user-token"],
        "created_by": CREATED_BY,
    }


def profile_authz_row(*, member=True, is_manager=False):
    # The callback's consume-time authorization re-check row.
    return {
        "policy": profile_row()["policy"],
        "actor_email": "dev@acme.test",
        "member": member,
        "is_manager": is_manager,
    }


def callback_integration_row(monkeypatch):
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", TEST_KEK)
    return integration_row(
        client_secret_ciphertext=encrypt_oauth_client_secret(
            entity_id=ENTITY_ID, name="slack", value="shhh-client-secret"
        )
    )


def test_callback_rejects_missing_unknown_or_reused_state(monkeypatch) -> None:
    conn = SequencedConn(fetchrow_rows=[])
    response = asyncio.run(oauth_connection_callback(state=None, pool=FakePool(conn)))
    assert response.status_code == 400

    response = asyncio.run(
        oauth_connection_callback(code="c", state="unknown", pool=FakePool(conn))
    )
    assert response.status_code == 400
    assert b"invalid, expired, or already used" in response.body


def test_callback_records_provider_denial(monkeypatch) -> None:
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.test")
    conn = SequencedConn(fetchrow_rows=[state_row()])

    response = asyncio.run(
        oauth_connection_callback(
            state="raw-state", error="access_denied", pool=FakePool(conn)
        )
    )

    assert response.status_code == 303
    assert (
        response.headers["location"]
        == "https://console.example.test/connect/slack?connect_error=provider_denied"
    )
    error_sql, error_args = conn.execute_calls[-1]
    assert "SET error" in error_sql
    assert error_args == (STATE_ID, "provider:access_denied")


def test_callback_records_exchange_failure(monkeypatch) -> None:
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.test")
    conn = SequencedConn(
        fetchrow_rows=[state_row(), profile_authz_row(), callback_integration_row(monkeypatch)]
    )

    async def failing_exchange(integration, *, client_secret, code):
        assert client_secret == "shhh-client-secret"
        return None, "exchange_status:500"

    monkeypatch.setattr(routes_oauth, "exchange_authorization_code", failing_exchange)

    response = asyncio.run(
        oauth_connection_callback(code="the-code", state="raw-state", pool=FakePool(conn))
    )

    assert response.status_code == 303
    assert response.headers["location"].endswith("/connect/slack?connect_error=exchange_failed")
    error_sql, error_args = conn.execute_calls[-1]
    assert "SET error" in error_sql
    assert error_args == (STATE_ID, "exchange_status:500")


def test_callback_refuses_revoked_initiator(monkeypatch) -> None:
    # Membership removed after the link was minted: no profile authz row comes
    # back (LEFT JOIN yields member=False, is_manager=False) -> refuse + record.
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.test")
    conn = SequencedConn(
        fetchrow_rows=[state_row(), profile_authz_row(member=False, is_manager=False)]
    )
    exchanged = []

    async def fake_exchange(integration, *, client_secret, code):
        exchanged.append(code)
        return "tok", None

    monkeypatch.setattr(routes_oauth, "exchange_authorization_code", fake_exchange)

    response = asyncio.run(
        oauth_connection_callback(code="the-code", state="raw-state", pool=FakePool(conn))
    )

    assert response.status_code == 303
    assert response.headers["location"].endswith("/connect/slack?connect_error=authorization_revoked")
    assert exchanged == []  # never exchanged the code
    error_sql, error_args = conn.execute_calls[-1]
    assert "SET error" in error_sql
    assert error_args == (STATE_ID, "authorization_revoked")


def test_callback_revoked_during_exchange_failure(monkeypatch) -> None:
    # The revocation lands AFTER the pre-exchange check passes but before the
    # mint: the provider exchange runs, but the locked in-transaction re-check
    # (member=False) must abort the mint. Guards the callback race.
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.test")
    conn = SequencedConn(
        fetchrow_rows=[
            state_row(),
            profile_authz_row(),  # pre-exchange check passes
            callback_integration_row(monkeypatch),
            profile_authz_row(member=False, is_manager=False),  # revoked under lock
        ]
    )
    exchanged: list[str] = []
    upserts: list[Any] = []

    async def fake_exchange(integration, *, client_secret, code):
        exchanged.append(code)
        return "xoxp-minted-token", None

    async def fake_upsert(inner_conn, *, profile_id, secret_values):
        upserts.append((profile_id, secret_values))

    monkeypatch.setattr(routes_oauth, "exchange_authorization_code", fake_exchange)
    monkeypatch.setattr(routes_module, "upsert_profile_secret_material", fake_upsert)

    response = asyncio.run(
        oauth_connection_callback(code="the-code", state="raw-state", pool=FakePool(conn))
    )

    assert response.status_code == 303
    assert response.headers["location"].endswith("/connect/slack?connect_error=authorization_revoked")
    assert exchanged == ["the-code"]  # exchange happened...
    assert upserts == []  # ...but the mint was aborted
    assert not any("SET completed_at = now()" in sql for sql, _ in conn.execute_calls)
    error_sql, error_args = conn.execute_calls[-1]
    assert "SET error" in error_sql
    assert error_args == (STATE_ID, "authorization_revoked")


def test_callback_over_long_rendered_value_failure(monkeypatch) -> None:
    # A concurrent `profile configure` lengthens the value_template during the
    # provider exchange. The mint's under-lock length check reads the locked
    # policy (not the pre-exchange copy) and must abort rather than store a
    # token that renders past the SC cap (which would fail-close the whole CVM).
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.test")
    long_policy = {
        "secret_injections": [
            {"id": "slack-user-token", "value_template": "Bearer " + "x" * 9000 + "${secret}"}
        ]
    }
    conn = SequencedConn(
        fetchrow_rows=[
            state_row(),
            profile_authz_row(),  # pre-exchange check passes (short policy)
            callback_integration_row(monkeypatch),
            {**profile_authz_row(), "policy": long_policy},  # locked policy now over-long
        ]
    )
    upserts: list[Any] = []

    async def fake_exchange(integration, *, client_secret, code):
        return "xoxp-minted-token", None

    async def fake_upsert(inner_conn, *, profile_id, secret_values):
        upserts.append((profile_id, secret_values))

    monkeypatch.setattr(routes_oauth, "exchange_authorization_code", fake_exchange)
    monkeypatch.setattr(routes_module, "upsert_profile_secret_material", fake_upsert)

    response = asyncio.run(
        oauth_connection_callback(code="the-code", state="raw-state", pool=FakePool(conn))
    )

    assert response.status_code == 303
    assert response.headers["location"].endswith("/connect/slack?connect_error=token_too_long")
    assert upserts == []  # mint aborted before writing
    error_sql, error_args = conn.execute_calls[-1]
    assert "SET error" in error_sql
    assert error_args == (STATE_ID, "rendered_value_too_long")


def test_callback_success_mints_bumps_and_audits(monkeypatch) -> None:
    conn = SequencedConn(
        # state claim, pre-exchange authz, integration, then the locked
        # in-transaction authz re-check just before minting.
        fetchrow_rows=[
            state_row(),
            profile_authz_row(),
            callback_integration_row(monkeypatch),
            profile_authz_row(),
        ]
    )
    audits = _patch_audit(monkeypatch)
    upserts = []
    bumps = []

    async def fake_upsert(inner_conn, *, profile_id, secret_values):
        upserts.append((profile_id, secret_values))

    async def fake_bump(inner_conn, profile_id):
        bumps.append(profile_id)

    async def fake_exchange(integration, *, client_secret, code):
        return "xoxp-minted-token", None

    monkeypatch.setattr(routes_module, "upsert_profile_secret_material", fake_upsert)
    monkeypatch.setattr(routes_module, "bump_attached_cvm_policy_versions", fake_bump)
    monkeypatch.setattr(routes_oauth, "exchange_authorization_code", fake_exchange)

    monkeypatch.setenv("CONSOLE_URL", "https://console.example.test")
    response = asyncio.run(
        oauth_connection_callback(code="the-code", state="raw-state", pool=FakePool(conn))
    )

    assert response.status_code == 303
    assert response.headers["location"].endswith("/connect/slack?connected=1")
    assert upserts == [(PROFILE_ID, {"slack-user-token": "xoxp-minted-token"})]
    assert bumps == [PROFILE_ID]
    assert audits[0]["action"] == "PROFILE_SECRET_MINTED"
    assert audits[0]["after"]["via"] == "oauth_connection"
    assert "xoxp-minted-token" not in json.dumps(audits[0]["after"])
    # Mint attributed to the initiating user, not a system actor.
    assert audits[0]["actor_id"] == CREATED_BY
    assert audits[0]["actor_email"] == "dev@acme.test"
    # completed_at is the sole connected signal, set in the mint transaction.
    assert any("SET completed_at = now()" in sql for sql, _ in conn.execute_calls)
    claim_sql, claim_args = conn.fetchrow_calls[0][0], conn.fetchrow_calls[0][1]
    assert "SET used_at = now()" in claim_sql
    assert "used_at IS NULL" in claim_sql
    assert "expires_at > now()" in claim_sql
    assert claim_args[0] != "raw-state"  # hashed, never the raw state
