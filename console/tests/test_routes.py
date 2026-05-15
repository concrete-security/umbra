from datetime import datetime, timezone
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import HTTPException

from concrete_console.routes import (
    AuditExportCreate,
    policy_sha256,
    profile_etag,
    require_idempotency_key,
    require_if_match,
    ssh_key_fingerprint,
    user_etag,
    validate_audit_export_request,
    validate_permission_symbol,
    validate_profile_policy,
)


def profile_row(**overrides):
    row = {
        "id": UUID("00000000-0000-4000-8000-000000000010"),
        "updated_at": datetime(1970, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc),
    }
    row.update(overrides)
    return row


def user_row(**overrides):
    row = {
        "id": UUID("00000000-0000-4000-8000-000000000020"),
        "email": "dev@example.com",
        "name": "Dev User",
        "entity_id": UUID("00000000-0000-4000-8000-000000000002"),
        "entity_name": "Example",
        "permissions": ["CVM_LAUNCH"],
        "created_at": datetime(2026, 5, 15, 18, 40, tzinfo=timezone.utc),
        "deactivated_at": None,
        "deleted_at": None,
    }
    row.update(overrides)
    return row


def test_profile_etag_uses_updated_at_microseconds() -> None:
    assert profile_etag(profile_row()) == 'W/"00000000-0000-4000-8000-000000000010:123456"'


def test_user_etag_changes_with_permissions() -> None:
    assert user_etag(user_row(permissions=[])) != user_etag(user_row(permissions=["CVM_LAUNCH"]))


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


def test_require_idempotency_key_rejects_missing_header() -> None:
    with pytest.raises(HTTPException) as exc:
        require_idempotency_key(None)

    assert exc.value.status_code == 400
    assert exc.value.detail["error"]["details"]["errors"][0]["type"] == "missing_idempotency_key"


def test_require_idempotency_key_rejects_invalid_header() -> None:
    with pytest.raises(HTTPException) as exc:
        require_idempotency_key("bad key")

    assert exc.value.status_code == 400
    assert exc.value.detail["error"]["details"]["errors"][0]["type"] == "invalid_idempotency_key"


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


def test_validate_permission_symbol_rejects_unknown_permission() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_permission_symbol("NOT_A_PERMISSION")

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["code"] == "VALIDATION_ERROR"


def test_validate_audit_export_request_accepts_supported_format_and_action() -> None:
    validate_audit_export_request(AuditExportCreate(format="ndjson", action="USER_REGISTERED"))


def test_validate_audit_export_request_rejects_unsupported_format() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_audit_export_request(AuditExportCreate(format="xlsx"))

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["errors"][0]["type"] == "unsupported_format"


def test_validate_audit_export_request_rejects_unknown_action() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_audit_export_request(AuditExportCreate(format="csv", action="NOT_A_REAL_ACTION"))

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["errors"][0]["type"] == "unknown_action"


def test_ssh_key_fingerprint_accepts_openssh_public_key() -> None:
    public_key = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode("utf-8")
    )

    fingerprint = ssh_key_fingerprint(f"{public_key} laptop")

    assert fingerprint.startswith("SHA256:")


def test_ssh_key_fingerprint_rejects_malformed_public_key() -> None:
    with pytest.raises(HTTPException) as exc:
        ssh_key_fingerprint("not-a-key")

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["errors"][0]["type"] == "malformed_public_key"
