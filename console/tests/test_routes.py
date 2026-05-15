from datetime import datetime, timezone
from uuid import UUID

import pytest
from fastapi import HTTPException

from concrete_console.routes import policy_sha256, profile_etag, require_if_match, validate_profile_policy


def profile_row(**overrides):
    row = {
        "id": UUID("00000000-0000-4000-8000-000000000010"),
        "updated_at": datetime(1970, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc),
    }
    row.update(overrides)
    return row


def test_profile_etag_uses_updated_at_microseconds() -> None:
    assert profile_etag(profile_row()) == 'W/"00000000-0000-4000-8000-000000000010:123456"'


def test_require_if_match_rejects_missing_header() -> None:
    with pytest.raises(HTTPException) as exc:
        require_if_match(profile_row(), None)

    assert exc.value.status_code == 428
    assert exc.value.detail["error"]["code"] == "PRECONDITION_REQUIRED"


def test_require_if_match_rejects_stale_header() -> None:
    with pytest.raises(HTTPException) as exc:
        require_if_match(profile_row(), 'W/"stale"')

    assert exc.value.status_code == 412
    assert exc.value.detail["error"]["code"] == "PRECONDITION_FAILED"


def test_policy_sha256_is_canonical() -> None:
    assert policy_sha256({"b": 2, "a": 1}) == policy_sha256({"a": 1, "b": 2})


def test_validate_profile_policy_accepts_sandbox_env() -> None:
    validate_profile_policy({"sandbox_env": {"PLACEHOLDER": "value"}, "opaque": {"kept": True}})


def test_validate_profile_policy_rejects_bad_sandbox_env() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "sandbox_env": {
                    "1BAD": "value",
                    "PATH": "/tmp/bin",
                    "TOKEN": "sk-" + "a" * 32,
                }
            }
        )

    assert exc.value.status_code == 422
    errors = exc.value.detail["error"]["details"]["errors"]
    assert {error["type"] for error in errors} == {"invalid_name", "reserved_name", "value_denied"}
