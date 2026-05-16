import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import HTTPException

from concrete_console.auth import CurrentUser, require_current_user
from concrete_console.internal_auth import parse_service_bearer_authorization
from concrete_console.routes_auth import DeviceStartRequest, device_poll_too_soon, device_start, request_ip


def current_user(*, permissions: set[str] | None = None) -> CurrentUser:
    return CurrentUser(
        id=UUID("00000000-0000-4000-8000-000000000001"),
        email="admin@example.com",
        name="Admin",
        entity_id=UUID("00000000-0000-4000-8000-000000000002"),
        entity_name="Example",
        permissions=frozenset(permissions or set()),
    )


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


def test_parse_service_bearer_rejects_jwt_shape_before_db_lookup() -> None:
    with pytest.raises(HTTPException) as exc:
        parse_service_bearer_authorization("Bearer header.payload.signature")

    assert exc.value.status_code == 401
    assert exc.value.detail["error"]["code"] == "UNAUTHORIZED"


def test_parse_service_bearer_accepts_opaque_token() -> None:
    assert parse_service_bearer_authorization("Bearer opaque_token-123") == "opaque_token-123"


def test_device_start_rejects_non_google_provider_before_provider_call() -> None:
    with pytest.raises(HTTPException) as exc:
        asyncio.run(device_start(body=DeviceStartRequest(provider="github"), pool=object()))

    assert exc.value.status_code == 400
    assert exc.value.detail["error"]["code"] == "BAD_REQUEST"


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


def test_auth_request_ip_uses_forwarded_header_resolution(monkeypatch) -> None:
    monkeypatch.setenv("TRUST_FORWARDED_HEADERS", "true")
    request = SimpleNamespace(
        client=SimpleNamespace(host="10.0.0.5"),
        headers={"x-forwarded-for": "10.0.0.1, 8.8.4.4"},
    )

    assert request_ip(request) == "8.8.4.4"
