import asyncio
from uuid import UUID

import pytest
from fastapi import HTTPException

from concrete_console.auth import CurrentUser, require_current_user


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
