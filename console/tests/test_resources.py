from datetime import datetime, timezone
from uuid import UUID

from concrete_console.resources import (
    entity_quota_resource,
    profile_resource,
    ssh_key_resource,
    user_quota_resource,
    user_resource,
)


def user_row(**overrides):
    row = {
        "id": UUID("00000000-0000-4000-8000-000000000001"),
        "email": "admin@example.com",
        "name": "Admin",
        "entity_id": UUID("00000000-0000-4000-8000-000000000002"),
        "entity_name": "Example",
        "permissions": ["USER_MANAGE"],
        "profiles": [],
        "deactivated_at": None,
        "created_at": datetime(2026, 5, 15, 18, 0, tzinfo=timezone.utc),
        "deleted_at": None,
    }
    row.update(overrides)
    return row


def test_user_resource_marks_active_user() -> None:
    resource = user_resource(user_row())

    assert resource["state"] == "active"
    assert resource["deactivated_at"] is None


def test_user_resource_marks_deactivated_user() -> None:
    deactivated_at = datetime(2026, 5, 15, 18, 1, tzinfo=timezone.utc)

    resource = user_resource(user_row(deactivated_at=deactivated_at))

    assert resource["state"] == "deactivated"
    assert resource["deactivated_at"] == "2026-05-15T18:01:00Z"


def test_user_resource_marks_erased_user() -> None:
    deleted_at = datetime(2026, 5, 15, 18, 2, tzinfo=timezone.utc)

    resource = user_resource(user_row(deleted_at=deleted_at))

    assert resource["state"] == "erased"


def test_profile_resource_parses_json_policy() -> None:
    resource = profile_resource(
        {
            "id": UUID("00000000-0000-4000-8000-000000000010"),
            "entity_id": UUID("00000000-0000-4000-8000-000000000002"),
            "name": "default",
            "description": "",
            "policy": '{"sandbox_env":{"PLACEHOLDER":"value"}}',
            "assigned": True,
            "attached_cvms": [],
            "attached_cvm_count": 0,
            "created_at": datetime(2026, 5, 15, 18, 3, tzinfo=timezone.utc),
            "updated_at": datetime(2026, 5, 15, 18, 4, tzinfo=timezone.utc),
        }
    )

    assert resource["policy"] == {"sandbox_env": {"PLACEHOLDER": "value"}}
    assert resource["assigned"] is True


def test_ssh_key_resource_formats_created_at() -> None:
    resource = ssh_key_resource(
        {
            "id": UUID("00000000-0000-4000-8000-000000000011"),
            "label": "laptop",
            "fingerprint": "SHA256:test",
            "public_key": "ssh-ed25519 AAAA",
            "created_at": datetime(2026, 5, 15, 18, 5, tzinfo=timezone.utc),
        }
    )

    assert resource["created_at"] == "2026-05-15T18:05:00Z"


def test_quota_resources_format_optional_setter() -> None:
    set_at = datetime(2026, 5, 15, 18, 50, tzinfo=timezone.utc)

    entity_quota = entity_quota_resource(
        {
            "entity_id": UUID("00000000-0000-4000-8000-000000000002"),
            "resource": "users",
            "limit": 10,
            "source": "override",
            "current_usage": 2,
            "set_by": UUID("00000000-0000-4000-8000-000000000020"),
            "set_at": set_at,
        }
    )
    user_quota = user_quota_resource(
        {
            "user_id": UUID("00000000-0000-4000-8000-000000000020"),
            "resource": "dev_cvms",
            "limit": 5,
            "source": "default",
            "current_usage": 0,
            "set_by": None,
            "set_at": None,
        }
    )

    assert entity_quota["set_by"] == "00000000-0000-4000-8000-000000000020"
    assert entity_quota["set_at"] == "2026-05-15T18:50:00Z"
    assert user_quota["set_by"] is None
    assert user_quota["set_at"] is None
