import asyncio
from datetime import datetime, timedelta, timezone
import json
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from concrete_console import auth as auth_module
from concrete_console.auth import CurrentUser, require_current_user
from concrete_console.app import app
from concrete_console.db import get_pool
from concrete_console.internal_auth import parse_service_bearer_authorization
from concrete_console import routes_auth
from concrete_console.routes_auth import (
    DevicePollRequest,
    DeviceStartRequest,
    RefreshRequest,
    device_poll,
    device_poll_too_soon,
    device_start,
    refresh,
    request_ip,
)


def current_user(*, permissions: set[str] | None = None) -> CurrentUser:
    return CurrentUser(
        id=UUID("00000000-0000-4000-8000-000000000001"),
        email="admin@example.com",
        name="Admin",
        entity_id=UUID("00000000-0000-4000-8000-000000000002"),
        entity_name="Example",
        permissions=frozenset(permissions or set()),
    )


class AsyncContext:
    def __init__(self, value=None):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, exc_type, exc, tb):
        return None


class LogoutNoBodyConn:
    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, query, *args):
        raise AssertionError("logout without credentials should not fetch actor rows")

    async def execute(self, query, *args):
        raise AssertionError("logout without credentials should not write rows")


class FakePool:
    def __init__(self, conn):
        self.conn = conn

    def acquire(self):
        return AsyncContext(self.conn)


class NoAcquirePool:
    def acquire(self):
        raise AssertionError("invalid JWT claims should fail before database access")


class FakeJwtManager:
    def __init__(self, claims: dict[str, str]):
        self.claims = claims

    def verify_access_token(self, token: str):
        assert token == "token"
        return self.claims


class RefreshReplayConn:
    def __init__(self):
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []

    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, query, *args):
        return {
            "redeemed_at": datetime(2026, 5, 16, 15, 12, 0, tzinfo=timezone.utc),
            "family_id": UUID("00000000-0000-4000-8000-000000000011"),
            "jti": UUID("00000000-0000-4000-8000-000000000012"),
            "user_id": UUID("00000000-0000-4000-8000-000000000020"),
            "actor_email": "dev@example.com",
            "entity_id": UUID("00000000-0000-4000-8000-000000000001"),
        }

    async def fetch(self, query, *args):
        return [
            {
                "access_jti": UUID("00000000-0000-4000-8000-000000000013"),
                "access_expires_at": datetime(2026, 5, 16, 16, 12, 0, tzinfo=timezone.utc),
            }
        ]

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "INSERT 0 1"


class AuthPruneConn:
    def __init__(self):
        self.execute_calls: list[str] = []

    async def execute(self, query, *args):
        self.execute_calls.append(query)
        return "DELETE 1"


class DevicePollMissingConn:
    def __init__(self):
        self.execute_calls: list[str] = []

    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, query, *args):
        return None

    async def execute(self, query, *args):
        self.execute_calls.append(query)
        return "DELETE 0"


class DevicePollBadSecretConn:
    def __init__(self):
        self.execute_calls: list[str] = []

    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, query, *args):
        return {
            "device_code": "device-code",
            "polling_secret_hash": routes_auth.sha256_hex("correct-secret-value"),
            "expires_at": datetime.now(timezone.utc) + timedelta(minutes=5),
            "interval_seconds": 5,
            "last_polled_at": None,
        }

    async def execute(self, query, *args):
        self.execute_calls.append(query)
        return "DELETE 0"


def test_require_permission_allows_granted_permission() -> None:
    current_user(permissions={"USER_MANAGE"}).require_permission("USER_MANAGE")


def test_require_permission_rejects_missing_permission() -> None:
    with pytest.raises(HTTPException) as exc:
        current_user().require_permission("USER_MANAGE")

    assert exc.value.status_code == 403
    assert exc.value.detail["error"]["code"] == "FORBIDDEN"


def test_require_entity_hides_other_entity_without_platform_operator() -> None:
    with pytest.raises(HTTPException) as exc:
        current_user().require_entity(UUID("00000000-0000-4000-8000-000000000003"))

    assert exc.value.status_code == 404
    assert exc.value.detail["error"]["code"] == "NOT_FOUND"


def test_require_entity_allows_platform_operator_cross_entity() -> None:
    current_user(permissions={"PLATFORM_OPERATOR"}).require_entity(
        UUID("00000000-0000-4000-8000-000000000003")
    )


def test_require_current_user_rejects_whitespace_slop_before_db_lookup() -> None:
    with pytest.raises(HTTPException) as exc:
        asyncio.run(require_current_user("Bearer  not-a-token"))

    assert exc.value.status_code == 401
    assert exc.value.detail["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.parametrize("claim_name", ["sub", "entity_id", "jti"])
def test_require_current_user_rejects_non_v4_uuid_claims_before_db_lookup(monkeypatch, claim_name) -> None:
    claims = {
        "sub": "00000000-0000-4000-8000-000000000001",
        "entity_id": "00000000-0000-4000-8000-000000000002",
        "jti": "00000000-0000-4000-8000-000000000003",
    }
    claims[claim_name] = "00000000-0000-1000-8000-000000000001"
    monkeypatch.setattr(auth_module, "get_jwt_manager", lambda: FakeJwtManager(claims))

    with pytest.raises(HTTPException) as exc:
        asyncio.run(require_current_user("Bearer token", pool=NoAcquirePool()))

    assert exc.value.status_code == 401
    assert exc.value.detail["error"]["code"] == "UNAUTHORIZED"


def test_parse_service_bearer_rejects_jwt_shape_before_db_lookup() -> None:
    with pytest.raises(HTTPException) as exc:
        parse_service_bearer_authorization("Bearer header.payload.signature")

    assert exc.value.status_code == 401
    assert exc.value.detail["error"]["code"] == "UNAUTHORIZED"


@pytest.mark.parametrize("token", ["opaque.token", "opaque*token"])
def test_parse_service_bearer_rejects_non_base64url_opaque_shape(token) -> None:
    with pytest.raises(HTTPException) as exc:
        parse_service_bearer_authorization(f"Bearer {token}")

    assert exc.value.status_code == 401
    assert exc.value.detail["error"]["code"] == "UNAUTHORIZED"


def test_parse_service_bearer_accepts_opaque_token() -> None:
    assert parse_service_bearer_authorization("Bearer opaque_token-123") == "opaque_token-123"


def test_device_start_rejects_non_google_provider_before_provider_call() -> None:
    with pytest.raises(HTTPException) as exc:
        asyncio.run(device_start(body=DeviceStartRequest(provider="github"), pool=object()))

    assert exc.value.status_code == 400
    assert exc.value.detail["error"]["code"] == "BAD_REQUEST"


def test_prune_expired_auth_rows_uses_skip_locked_now_cutoff() -> None:
    conn = AuthPruneConn()

    asyncio.run(routes_auth.prune_expired_auth_rows(conn))

    assert len(conn.execute_calls) == 2
    assert all("expires_at < now()" in query for query in conn.execute_calls)
    assert all("FOR UPDATE SKIP LOCKED" in query for query in conn.execute_calls)
    assert any("DELETE FROM loopback_auth_pending" in query for query in conn.execute_calls)
    assert any("DELETE FROM device_flow_pending" in query for query in conn.execute_calls)


def test_device_poll_too_soon_honors_full_interval() -> None:
    last_polled_at = datetime(2026, 5, 16, 15, 10, 0, tzinfo=timezone.utc)

    assert device_poll_too_soon(
        now=last_polled_at + timedelta(seconds=4, milliseconds=999),
        last_polled_at=last_polled_at,
        interval_seconds=5,
    )
    assert not device_poll_too_soon(
        now=last_polled_at + timedelta(seconds=5),
        last_polled_at=last_polled_at,
        interval_seconds=5,
    )
    assert not device_poll_too_soon(now=last_polled_at, last_polled_at=None, interval_seconds=5)


def test_device_poll_prunes_expired_auth_rows_on_missing_code() -> None:
    conn = DevicePollMissingConn()
    request = SimpleNamespace(state=SimpleNamespace(request_id="poll-request"), headers={}, client=None)

    response = asyncio.run(
        device_poll(
            DevicePollRequest(device_code="missing-device", polling_secret="s" * 20),
            request=request,
            pool=FakePool(conn),
        )
    )

    assert response.status_code == 400
    assert json.loads(response.body) == {"error": "access_denied"}
    assert len(conn.execute_calls) == 2
    assert all("FOR UPDATE SKIP LOCKED" in query for query in conn.execute_calls)


def test_device_poll_prunes_expired_auth_rows_before_bad_secret_error() -> None:
    conn = DevicePollBadSecretConn()
    request = SimpleNamespace(state=SimpleNamespace(request_id="poll-request"), headers={}, client=None)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            device_poll(
                DevicePollRequest(device_code="device-code", polling_secret="wrong-secret-value-1"),
                request=request,
                pool=FakePool(conn),
            )
        )

    assert exc.value.status_code == 401
    assert len(conn.execute_calls) == 2
    assert all("FOR UPDATE SKIP LOCKED" in query for query in conn.execute_calls)


def test_logout_accepts_missing_body() -> None:
    app.dependency_overrides[get_pool] = lambda: FakePool(LogoutNoBodyConn())
    try:
        response = TestClient(app).post("/api/v1/auth/logout")
    finally:
        app.dependency_overrides.pop(get_pool, None)

    assert response.status_code == 204
    assert response.content == b""


def test_refresh_replay_error_envelope_includes_request_id(monkeypatch) -> None:
    audit_calls: list[dict[str, object]] = []

    async def fake_insert_audit_event(_conn, **kwargs):
        audit_calls.append(kwargs)

    monkeypatch.setattr(routes_auth, "insert_audit_event", fake_insert_audit_event)
    request = SimpleNamespace(
        state=SimpleNamespace(request_id="refresh-replay-request"),
        headers={},
        client=SimpleNamespace(host="127.0.0.1"),
    )

    response = asyncio.run(
        refresh(
            RefreshRequest(refresh_token="r" * 20),
            request=request,
            pool=FakePool(RefreshReplayConn()),
        )
    )

    assert response.status_code == 401
    assert json.loads(response.body) == {
        "error": {
            "code": "UNAUTHORIZED",
            "message": "invalid refresh token",
            "details": {},
            "request_id": "refresh-replay-request",
        }
    }
    assert audit_calls[0]["action"] == "AUTH_REFRESH_REUSE_DETECTED"


def test_auth_request_ip_uses_forwarded_header_resolution(monkeypatch) -> None:
    monkeypatch.setenv("TRUST_FORWARDED_HEADERS", "true")
    request = SimpleNamespace(
        client=SimpleNamespace(host="10.0.0.5"),
        headers={"x-forwarded-for": "10.0.0.1, 8.8.4.4"},
    )

    assert request_ip(request) == "8.8.4.4"
