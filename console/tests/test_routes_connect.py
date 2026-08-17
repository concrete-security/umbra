import asyncio
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import asyncpg
import pytest
from fastapi import HTTPException, Response

from umbra_console import routes as routes_module
from umbra_console import routes_connect
from umbra_console.app import apply_response_headers, path_exempt_from_rate_limit
from umbra_console.auth import CurrentUser
from umbra_console.routes_auth import connect_oauth_redirect_uri, is_allowed_redirect_uri
from umbra_console.routes_connect import (
    ConnectAttach,
    connect_attach_cvm,
    connect_create_connection,
    connect_profile_name,
    connect_provision_profile,
    connect_status,
)

ENTITY_ID = UUID("00000000-0000-4000-8000-000000000001")
USER_ID = UUID("00000000-0000-4000-8000-000000000061")
PROFILE_ID = UUID("00000000-0000-4000-8000-000000000060")
CVM_ID = UUID("00000000-0000-4000-8000-000000000031")
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


class ConnectConn:
    """Queued fakes: fetchrow/fetch/fetchval pop canned results in call order."""

    def __init__(self, *, fetchrow_rows=None, fetch_results=None, fetchval_results=None):
        self.fetchrow_rows = list(fetchrow_rows or [])
        self.fetch_results = list(fetch_results or [])
        self.fetchval_results = list(fetchval_results or [])
        self.execute_calls = []
        self.fail_profile_insert_once = False

    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, sql, *args):
        if self.fetchrow_rows:
            return self.fetchrow_rows.pop(0)
        return None

    async def fetch(self, sql, *args):
        if self.fetch_results:
            return self.fetch_results.pop(0)
        return []

    async def fetchval(self, sql, *args):
        if self.fetchval_results:
            return self.fetchval_results.pop(0)
        return None

    async def execute(self, sql, *args):
        if self.fail_profile_insert_once and "INSERT INTO entity_profiles" in sql:
            self.fail_profile_insert_once = False
            raise asyncpg.UniqueViolationError("duplicate key")
        self.execute_calls.append((sql, args))
        return "OK"


def dev_user(*, permissions=("CVM_LAUNCH",)):
    return CurrentUser(
        id=USER_ID,
        email="dev.name@acme.test",
        name="Dev",
        entity_id=ENTITY_ID,
        entity_name="acme",
        permissions=frozenset(permissions),
    )


def template():
    return {
        "secret_injections": [
            {
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
        ]
    }


def integration_row(**overrides):
    row = {
        "entity_id": ENTITY_ID,
        "name": "slack",
        "authorize_url": "https://slack.com/oauth/v2/authorize?user_scope=chat:write",
        "token_url": "https://slack.com/api/oauth.v2.access",
        "client_id": "1234.5678",
        "scopes": "",
        "token_pointer": "/authed_user/access_token",
        "profile_policy_template": template(),
    }
    row.update(overrides)
    return row


def link_row(**overrides):
    row = {
        "profile_id": PROFILE_ID,
        "template_sha256": "a" * 64,
        "name": "conn-slack-dev-name",
        "policy": template(),
        "created_at": NOW,
        "profile_deleted": False,
        "member": True,
    }
    row.update(overrides)
    return row


def _patch_audit(monkeypatch):
    audits = []

    async def fake_audit(conn, **kwargs):
        audits.append(kwargs)

    monkeypatch.setattr(routes_connect, "insert_audit_event", fake_audit)
    return audits


def _patch_quota(monkeypatch):
    calls = []

    async def fake_quota(conn, entity_id, resource):
        calls.append((entity_id, resource))

    monkeypatch.setattr(routes_module, "enforce_entity_quota", fake_quota)
    return calls


# --- plumbing ------------------------------------------------------------------


def test_connect_redirect_uri_is_allowlisted() -> None:
    settings = SimpleNamespace(console_url="https://console.example.test")
    assert connect_oauth_redirect_uri(settings) == "https://console.example.test/connect/oauth/callback"
    assert is_allowed_redirect_uri(
        "https://console.example.test/connect/oauth/callback", settings=settings
    )
    assert not is_allowed_redirect_uri(
        "https://evil.example.test/connect/oauth/callback", settings=settings
    )


def test_connect_paths_get_page_csp_and_rate_limit_exemption() -> None:
    assert path_exempt_from_rate_limit("/connect/slack")
    assert path_exempt_from_rate_limit("/connect/assets/connect.js")
    assert not path_exempt_from_rate_limit("/api/v1/connect/slack")

    request = SimpleNamespace(url=SimpleNamespace(path="/connect/slack"))
    response = Response()
    apply_response_headers(request, response, "req-1")
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]

    api_request = SimpleNamespace(url=SimpleNamespace(path="/api/v1/connect/slack"))
    api_response = Response()
    apply_response_headers(api_request, api_response, "req-2")
    assert api_response.headers["Content-Security-Policy"].startswith("default-src 'none'")


def test_connect_profile_name_sanitizes() -> None:
    assert connect_profile_name("slack", "Dev.Name+x@acme.test") == "conn-slack-dev-name-x"
    assert connect_profile_name("slack", "---@acme.test") == "conn-slack-dev"
    assert len(connect_profile_name("slack", ("a" * 200) + "@x.test")) <= 100


# --- status ---------------------------------------------------------------------


def test_connect_status_unknown_integration_404s() -> None:
    conn = ConnectConn(fetchrow_rows=[None])
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            connect_status(integration="slack", current_user=dev_user(), pool=FakePool(conn))
        )
    assert exc.value.status_code == 404

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            connect_status(integration="Bad!", current_user=dev_user(), pool=FakePool(conn))
        )
    assert exc.value.status_code == 404


def test_connect_status_unentitled_is_200_with_flag() -> None:
    conn = ConnectConn(fetchrow_rows=[integration_row(), None])

    result = asyncio.run(
        connect_status(
            integration="slack", current_user=dev_user(permissions=()), pool=FakePool(conn)
        )
    )

    assert result["entitled"] is False
    assert result["profile"] is None
    assert result["secrets"]["complete"] is False


def test_connect_status_reports_secrets_connection_and_cvms() -> None:
    conn = ConnectConn(
        fetchrow_rows=[
            integration_row(),
            link_row(),
            {"completed_at": NOW, "error": None},
        ],
        fetch_results=[
            [{"injection_id": "slack-user-token"}],
            [{"id": CVM_ID, "fqdn": "cvm-x.test", "state": "RUNNING", "attached": False}],
        ],
    )

    result = asyncio.run(
        connect_status(integration="slack", current_user=dev_user(), pool=FakePool(conn))
    )

    assert result["profile"]["id"] == str(PROFILE_ID)
    assert result["secrets"] == {
        "required": ["slack-user-token"],
        "minted": ["slack-user-token"],
        "complete": True,
    }
    assert result["connection"]["last_connected_at"].endswith("Z")
    assert result["cvms"] == [
        {"id": str(CVM_ID), "fqdn": "cvm-x.test", "state": "RUNNING", "attached": False}
    ]


def test_connect_status_treats_revoked_link_as_no_profile() -> None:
    # Membership was revoked after the link row was written: the wizard sees
    # no usable profile (and thus routes back through provision, which refuses).
    conn = ConnectConn(fetchrow_rows=[integration_row(), link_row(member=False)])

    result = asyncio.run(
        connect_status(integration="slack", current_user=dev_user(), pool=FakePool(conn))
    )

    assert result["profile"] is None
    assert result["secrets"]["complete"] is False


# --- provision -------------------------------------------------------------------


def test_provision_requires_cvm_launch() -> None:
    conn = ConnectConn()
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            connect_provision_profile(
                integration="slack", current_user=dev_user(permissions=()), pool=FakePool(conn)
            )
        )
    assert exc.value.status_code == 403


def test_provision_returns_existing_link_without_writes(monkeypatch) -> None:
    _patch_audit(monkeypatch)
    conn = ConnectConn(fetchrow_rows=[integration_row(), link_row()])

    result = asyncio.run(
        connect_provision_profile(
            integration="slack", current_user=dev_user(), pool=FakePool(conn)
        )
    )

    assert result == {
        "profile_id": str(PROFILE_ID),
        "name": "conn-slack-dev-name",
        "created": False,
    }
    # Only the advisory lock ran; no rows were written.
    assert not any("INSERT INTO" in sql for sql, _ in conn.execute_calls)


def _value_from_only_template():
    # A template whose sole injection is per-user (value_from): valid in template
    # mode, but a connect link mints a provider token into an inline-value slot,
    # so there is nothing here for it to mint.
    policy = template()
    policy["secret_injections"][0]["value_from"] = {"user_secret": "slack-personal"}
    return policy


@pytest.mark.parametrize(
    "bad_template",
    [None, _value_from_only_template()],
    ids=["no_template", "value_from_only"],
)
def test_provision_unconnectable_template_conflicts(monkeypatch, bad_template) -> None:
    """Provision refuses a template with no mintable injection — absent entirely,
    or declaring only value_from injections a connect link cannot mint."""
    _patch_audit(monkeypatch)
    conn = ConnectConn(fetchrow_rows=[integration_row(profile_policy_template=bad_template), None])

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            connect_provision_profile(
                integration="slack", current_user=dev_user(), pool=FakePool(conn)
            )
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["details"]["state"] == "template_missing"


def test_provision_clones_template_membership_and_link(monkeypatch) -> None:
    audits = _patch_audit(monkeypatch)
    quota_calls = _patch_quota(monkeypatch)
    conn = ConnectConn(fetchrow_rows=[integration_row(), None])

    result = asyncio.run(
        connect_provision_profile(
            integration="slack", current_user=dev_user(), pool=FakePool(conn)
        )
    )

    assert result["created"] is True
    assert result["name"] == "conn-slack-dev-name"
    assert quota_calls == [(ENTITY_ID, "profiles")]
    # Provisioning is serialized under a per-(entity, integration, user) lock.
    assert any("pg_advisory_xact_lock" in sql for sql, _ in conn.execute_calls)
    execs = [(sql, args) for sql, args in conn.execute_calls if "INSERT INTO" in sql]
    profile_sql, profile_args = execs[0]
    assert "INSERT INTO entity_profiles" in profile_sql
    assert json.loads(profile_args[4])["secret_injections"][0]["id"] == "slack-user-token"
    membership_sql, membership_args = execs[1]
    assert "INSERT INTO profile_users" in membership_sql
    assert membership_args[1] == USER_ID
    link_sql, link_args = execs[2]
    assert "INSERT INTO integration_profiles" in link_sql
    assert link_args[1] == "slack"
    assert len(link_args[4]) == 64  # template sha256
    assert [audit["action"] for audit in audits] == ["PROFILE_CREATED", "PROFILE_USER_ASSIGNED"]
    assert all(audit["after"]["via"] == "connect" for audit in audits)


def test_provision_retries_name_collision_with_suffix(monkeypatch) -> None:
    _patch_audit(monkeypatch)
    _patch_quota(monkeypatch)
    conn = ConnectConn(fetchrow_rows=[integration_row(), None])
    conn.fail_profile_insert_once = True

    result = asyncio.run(
        connect_provision_profile(
            integration="slack", current_user=dev_user(), pool=FakePool(conn)
        )
    )

    assert result["created"] is True
    assert result["name"].startswith("conn-slack-dev-name-")
    assert result["name"] != "conn-slack-dev-name"


def test_provision_refuses_revoked_membership(monkeypatch) -> None:
    # A live keyed profile the dev was removed from must not silently
    # re-grant membership through the self-service flow.
    _patch_audit(monkeypatch)
    _patch_quota(monkeypatch)
    conn = ConnectConn(fetchrow_rows=[integration_row(), link_row(member=False)])

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            connect_provision_profile(
                integration="slack", current_user=dev_user(), pool=FakePool(conn)
            )
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["details"]["state"] == "membership_revoked"
    # No profile was created.
    assert not any("INSERT INTO entity_profiles" in sql for sql, _ in conn.execute_calls)


def test_provision_reprovisions_after_soft_delete(monkeypatch) -> None:
    # A soft-deleted keyed profile is a reset, not a brick: provision fresh.
    _patch_audit(monkeypatch)
    _patch_quota(monkeypatch)
    conn = ConnectConn(
        fetchrow_rows=[integration_row(), link_row(profile_deleted=True, member=False)]
    )

    result = asyncio.run(
        connect_provision_profile(
            integration="slack", current_user=dev_user(), pool=FakePool(conn)
        )
    )

    assert result["created"] is True
    assert any("INSERT INTO entity_profiles" in sql for sql, _ in conn.execute_calls)


# --- connections ------------------------------------------------------------------


def test_connect_connection_requires_provisioned_profile(monkeypatch) -> None:
    _patch_audit(monkeypatch)
    conn = ConnectConn(fetchrow_rows=[integration_row(), None])

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            connect_create_connection(
                integration="slack", current_user=dev_user(), pool=FakePool(conn)
            )
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["details"]["state"] == "profile_not_provisioned"


def test_connect_connection_mints_state_for_own_profile(monkeypatch) -> None:
    monkeypatch.setenv("CONSOLE_URL", "https://console.example.test")
    audits = _patch_audit(monkeypatch)
    conn = ConnectConn(fetchrow_rows=[integration_row(), link_row()])

    result = asyncio.run(
        connect_create_connection(
            integration="slack", current_user=dev_user(), pool=FakePool(conn)
        )
    )

    assert result["authorize_url"].startswith("https://slack.com/oauth/v2/authorize?")
    assert "state=" in result["authorize_url"]
    state_sql, state_args = conn.execute_calls[0]
    assert "INSERT INTO oauth_connection_states" in state_sql
    assert state_args[4] == PROFILE_ID
    assert len(state_args[3]) == 64  # sha256, never the raw state
    assert audits[0]["action"] == "PROFILE_CONNECTION_LINK_CREATED"
    assert audits[0]["after"]["via"] == "connect"


# --- attach ------------------------------------------------------------------------


def cvm_row(**overrides):
    row = {
        "id": CVM_ID,
        "entity_id": ENTITY_ID,
        "owner_id": USER_ID,
        "state": "RUNNING",
        "policy_version": 4,
    }
    row.update(overrides)
    return row


def run_attach(conn):
    return asyncio.run(
        connect_attach_cvm(
            integration="slack",
            body=ConnectAttach(cvm_id=CVM_ID),
            current_user=dev_user(),
            pool=FakePool(conn),
        )
    )


def test_attach_owner_gate_404s_foreign_cvm(monkeypatch) -> None:
    _patch_audit(monkeypatch)
    other_owner = UUID("00000000-0000-4000-8000-000000000099")
    conn = ConnectConn(fetchrow_rows=[link_row(), cvm_row(owner_id=other_owner)])

    with pytest.raises(HTTPException) as exc:
        run_attach(conn)

    assert exc.value.status_code == 404


def test_attach_blocks_unminted_profile(monkeypatch) -> None:
    _patch_audit(monkeypatch)
    conn = ConnectConn(
        fetchrow_rows=[link_row(), cvm_row()],
        fetchval_results=[1],  # membership
        fetch_results=[[]],  # no minted material
    )

    with pytest.raises(HTTPException) as exc:
        run_attach(conn)

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["details"]["state"] == "secrets_not_minted"


def test_attach_blocks_missing_user_secret(monkeypatch) -> None:
    # Self-attach must run the same user-secret preflight as the generic attach:
    # a value_from injection whose secret the CVM owner has not set is rejected
    # (else the SC would silently fail-close that destination after attach).
    _patch_audit(monkeypatch)
    policy = {
        "secret_injections": [
            {
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
                "value_from": {"user_secret": "slack-personal"},
            }
        ]
    }
    conn = ConnectConn(
        fetchrow_rows=[link_row(policy=policy), cvm_row()],
        fetchval_results=[1],  # membership
        fetch_results=[[]],  # owner has no matching user secret
    )

    with pytest.raises(HTTPException) as exc:
        run_attach(conn)

    assert exc.value.status_code == 422
    errors = exc.value.detail["error"]["details"]["errors"]
    assert errors[0]["type"] == "user_secret_missing"
    assert errors[0]["secret_name"] == "slack-personal"


def test_attach_binds_bumps_and_audits(monkeypatch) -> None:
    audits = _patch_audit(monkeypatch)

    class AttachConn(ConnectConn):
        async def execute(self, sql, *args):
            self.execute_calls.append((sql, args))
            if "INSERT INTO cvm_profiles" in sql:
                return "INSERT 0 1"
            return "OK"

    conn = AttachConn(
        fetchrow_rows=[link_row(), cvm_row()],
        fetchval_results=[1],
        fetch_results=[
            [{"profile_id": PROFILE_ID, "injection_id": "slack-user-token"}],  # minted
            [],  # existing policies
        ],
    )

    result = run_attach(conn)

    assert result == {"attached": True, "already_attached": False}
    assert any("INSERT INTO cvm_profiles" in sql for sql, _ in conn.execute_calls)
    assert any("policy_version = policy_version + 1" in sql for sql, _ in conn.execute_calls)
    assert audits[0]["action"] == "CVM_PROFILE_ATTACHED"
    assert audits[0]["after"]["via"] == "connect"


def test_attach_already_attached_is_idempotent(monkeypatch) -> None:
    audits = _patch_audit(monkeypatch)

    class NoopConn(ConnectConn):
        async def execute(self, sql, *args):
            self.execute_calls.append((sql, args))
            if "INSERT INTO cvm_profiles" in sql:
                return "INSERT 0 0"
            return "OK"

    conn = NoopConn(
        fetchrow_rows=[link_row(), cvm_row()],
        fetchval_results=[1],
        fetch_results=[
            [{"profile_id": PROFILE_ID, "injection_id": "slack-user-token"}],
            [],
        ],
    )

    result = run_attach(conn)

    assert result == {"attached": True, "already_attached": True}
    assert audits == []
    assert not any("policy_version" in sql for sql, _ in conn.execute_calls)
