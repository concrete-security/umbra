from datetime import datetime, timezone
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import HTTPException

from concrete_console.routes import (
    AdminKeysRotate,
    AuditExportCreate,
    SECURITY_CVM_PROVISION_REDACTION,
    cvm_etag,
    erased_user_email,
    ensure_no_sandbox_env_conflict,
    policy_sha256,
    redacted_security_cvm_provision_result,
    profile_etag,
    require_cvm_profile_mutable,
    require_idempotency_key,
    require_if_match,
    ssh_key_fingerprint,
    user_etag,
    validate_audit_export_request,
    validate_permission_symbol,
    validate_profile_policy,
)
from concrete_console.routes_internal import (
    TrafficLogBatch,
    TrafficLogIn,
    etag_matches,
    merge_profile_policies,
    sc_control_etag,
    validate_traffic_log_batch_shape,
    validate_traffic_log_timestamps,
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


def cvm_row(**overrides):
    row = {
        "id": UUID("00000000-0000-4000-8000-000000000030"),
        "state": "RUNNING",
        "policy_version": 4,
        "updated_at": datetime(1970, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc),
    }
    row.update(overrides)
    return row


def test_profile_etag_uses_updated_at_microseconds() -> None:
    assert profile_etag(profile_row()) == 'W/"00000000-0000-4000-8000-000000000010:123456"'


def test_cvm_etag_includes_policy_version() -> None:
    assert cvm_etag(cvm_row()) == 'W/"00000000-0000-4000-8000-000000000030:4:123456"'


def test_require_cvm_profile_mutable_rejects_terminated_cvm() -> None:
    with pytest.raises(HTTPException) as exc:
        require_cvm_profile_mutable(cvm_row(state="TERMINATED"), action="detach")

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["details"]["state"] == "cvm_terminated"


def test_user_etag_changes_with_permissions() -> None:
    assert user_etag(user_row(permissions=[])) != user_etag(user_row(permissions=["CVM_LAUNCH"]))


def test_erased_user_email_is_stable_tombstone() -> None:
    assert (
        erased_user_email(UUID("00000000-0000-4000-8000-000000000020"), "example.com")
        == "<erased-4bcc13e151d8>@example.com"
    )


def test_admin_keys_rotate_defaults_retirement_window() -> None:
    body = AdminKeysRotate(new_kid="next-key_2026.05.15")

    assert body.retire_old_after_seconds == 3600


@pytest.mark.parametrize("new_kid", ["bad key", "bad/key"])
def test_admin_keys_rotate_rejects_invalid_kid(new_kid: str) -> None:
    with pytest.raises(ValueError):
        AdminKeysRotate(new_kid=new_kid)


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


def test_ensure_no_sandbox_env_conflict_rejects_different_values() -> None:
    with pytest.raises(HTTPException) as exc:
        ensure_no_sandbox_env_conflict(
            [
                {
                    "profile_id": UUID("00000000-0000-4000-8000-000000000031"),
                    "policy": {"sandbox_env": {"API_KEY": "placeholder-a"}},
                },
                {
                    "profile_id": UUID("00000000-0000-4000-8000-000000000032"),
                    "policy": {"sandbox_env": {"API_KEY": "placeholder-b"}},
                },
            ]
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["details"]["state"] == "sandbox_env_conflict"
    assert exc.value.detail["error"]["details"]["name"] == "API_KEY"


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


def test_redacted_security_cvm_provision_result_redacts_one_shot_bearers() -> None:
    result = {
        "security_cvm": {"id": "00000000-0000-4000-8000-000000000040", "state": "RUNNING"},
        "ingest_token": "ingest-plaintext",
        "ca_export_token": "ca-plaintext",
    }

    redacted = redacted_security_cvm_provision_result(result)

    assert redacted == {
        "security_cvm": {"id": "00000000-0000-4000-8000-000000000040", "state": "RUNNING"},
        "ingest_token": SECURITY_CVM_PROVISION_REDACTION,
        "ca_export_token": SECURITY_CVM_PROVISION_REDACTION,
    }
    assert result["ingest_token"] == "ingest-plaintext"
    assert result["ca_export_token"] == "ca-plaintext"


def test_redacted_security_cvm_provision_result_accepts_json_payload() -> None:
    redacted = redacted_security_cvm_provision_result(
        '{"security_cvm":{"id":"sc-1"},"ingest_token":"ingest","ca_export_token":"ca"}'
    )

    assert redacted["security_cvm"] == {"id": "sc-1"}
    assert redacted["ingest_token"] == SECURITY_CVM_PROVISION_REDACTION
    assert redacted["ca_export_token"] == SECURITY_CVM_PROVISION_REDACTION


def traffic_log(**overrides) -> TrafficLogIn:
    value = {
        "timestamp": datetime.now(timezone.utc),
        "cvm_id": UUID("00000000-0000-4000-8000-000000000042"),
        "source_ip": "10.0.0.2",
        "destination_ip": "93.184.216.34",
        "destination_host": "example.com",
        "protocol": "https",
        "port": 443,
        "method": "GET",
        "path": "/",
        "response_code": 200,
        "bytes_transferred": 1234,
    }
    value.update(overrides)
    return TrafficLogIn(**value)


def test_validate_traffic_log_batch_shape_rejects_missing_cvm_id() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_traffic_log_batch_shape(TrafficLogBatch(idempotency_key="batch-1", logs=[traffic_log(cvm_id=None)]))

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["errors"][0]["type"] == "missing_cvm_id"


def test_validate_traffic_log_batch_shape_rejects_invalid_key() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_traffic_log_batch_shape(TrafficLogBatch(idempotency_key="bad key", logs=[traffic_log()]))

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["errors"][0]["type"] == "invalid_idempotency_key"


def test_validate_traffic_log_timestamps_rejects_skew() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_traffic_log_timestamps([traffic_log(timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))])

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["errors"][0]["type"] == "timestamp_skew"


def test_merge_profile_policies_field_typed() -> None:
    merged = merge_profile_policies(
        [
            {
                "profile_id": "profile-a",
                "policy": {
                    "allowed_destinations": [{"id": "anthropic", "host": "api.anthropic.com"}],
                    "blocked_destinations": [{"id": "admin", "host": "admin.example.com"}],
                    "secret_patterns": [{"id": "openai", "pattern": "sk-[A-Za-z0-9]+"}],
                    "sandbox_env": {"ANTHROPIC_API_KEY": "concrete-proxy-injected"},
                },
            },
            {
                "profile_id": "profile-b",
                "policy": {
                    "allowed_destinations": [{"id": "github", "host": "api.github.com"}],
                    "blocked_destinations": [{"id": "admin", "host": "admin.example.com"}],
                    "secret_injections": [{"id": "anthropic-key", "header": "authorization"}],
                    "sandbox_env": {"OPENAI_API_KEY": "concrete-proxy-injected"},
                },
            },
        ]
    )

    assert merged == {
        "allowed_destinations": [
            {"id": "anthropic", "host": "api.anthropic.com"},
            {"id": "github", "host": "api.github.com"},
        ],
        "blocked_destinations": [{"id": "admin", "host": "admin.example.com"}],
        "secret_patterns": [{"id": "openai", "pattern": "sk-[A-Za-z0-9]+"}],
        "secret_injections": [{"id": "anthropic-key", "header": "authorization"}],
        "sandbox_env": [
            {"name": "ANTHROPIC_API_KEY", "value": "concrete-proxy-injected"},
            {"name": "OPENAI_API_KEY", "value": "concrete-proxy-injected"},
        ],
    }


def test_merge_profile_policies_denies_intersect_with_missing_field() -> None:
    merged = merge_profile_policies(
        [
            {"policy": {"blocked_destinations": [{"id": "admin", "host": "admin.example.com"}]}},
            {"policy": {"allowed_destinations": [{"id": "github", "host": "api.github.com"}]}},
        ]
    )

    assert merged["blocked_destinations"] == []


def test_merge_profile_policies_rejects_sandbox_env_conflict() -> None:
    with pytest.raises(HTTPException) as exc:
        merge_profile_policies(
            [
                {"policy": {"sandbox_env": {"API_KEY": "placeholder-a"}}},
                {"policy": {"sandbox_env": {"API_KEY": "placeholder-b"}}},
            ]
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["details"]["state"] == "sandbox_env_conflict"


def test_sc_control_etag_matches_quoted_and_bare_values() -> None:
    body = {"entries": [{"cvm_id": "00000000-0000-4000-8000-000000000042", "policy_version": 1}]}
    etag = sc_control_etag(body)

    assert etag_matches(etag, etag)
    assert etag_matches(etag.strip('"'), etag)
    assert not etag_matches('"stale"', etag)


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
