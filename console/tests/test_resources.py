from datetime import datetime, timezone
from uuid import UUID

from concrete_console.resources import (
    cvm_resource,
    entity_quota_resource,
    operation_resource,
    profile_member_resource,
    profile_resource,
    security_cvm_attestation_resource,
    security_cvm_resource,
    ssh_key_resource,
    traffic_log_resource,
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
        "last_login_at": None,
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
    assert resource["last_login_at"] is None


def test_user_resource_formats_profiles_and_last_login() -> None:
    last_login_at = datetime(2026, 5, 15, 18, 30, tzinfo=timezone.utc)

    resource = user_resource(
        user_row(
            profiles='[{"id":"00000000-0000-4000-8000-000000000010","name":"default"}]',
            last_login_at=last_login_at,
        )
    )

    assert resource["profiles"] == [{"id": "00000000-0000-4000-8000-000000000010", "name": "default"}]
    assert resource["last_login_at"] == "2026-05-15T18:30:00Z"


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
            "attached_cvms": (
                '[{"id":"00000000-0000-4000-8000-000000000030",'
                '"fqdn":"cvm.example.test","state":"RUNNING"}]'
            ),
            "attached_cvm_count": 1,
            "created_at": datetime(2026, 5, 15, 18, 3, tzinfo=timezone.utc),
            "updated_at": datetime(2026, 5, 15, 18, 4, tzinfo=timezone.utc),
        }
    )

    assert resource["policy"] == {"sandbox_env": {"PLACEHOLDER": "value"}}
    assert resource["assigned"] is True
    assert resource["attached_cvms"] == [
        {
            "id": "00000000-0000-4000-8000-000000000030",
            "fqdn": "cvm.example.test",
            "state": "RUNNING",
        }
    ]
    assert resource["attached_cvm_count"] == 1


def test_profile_member_resource_formats_membership() -> None:
    resource = profile_member_resource(
        {
            "user_id": UUID("00000000-0000-4000-8000-000000000020"),
            "email": "dev@example.com",
            "added_at": datetime(2026, 5, 15, 18, 4, tzinfo=timezone.utc),
        }
    )

    assert resource == {
        "user_id": "00000000-0000-4000-8000-000000000020",
        "email": "dev@example.com",
        "added_at": "2026-05-15T18:04:00Z",
    }


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


def test_operation_resource_formats_target_progress_and_payloads() -> None:
    resource = operation_resource(
        {
            "id": UUID("00000000-0000-4000-8000-000000000030"),
            "kind": "audit.export",
            "status": "succeeded",
            "actor_id": UUID("00000000-0000-4000-8000-000000000001"),
            "target_type": "audit_export",
            "target_id": UUID("00000000-0000-4000-8000-000000000030"),
            "progress_step": "finalise",
            "progress_percent": 100,
            "result": '{"row_count":1,"sha256":"abc"}',
            "error": None,
            "created_at": datetime(2026, 5, 15, 19, 40, tzinfo=timezone.utc),
            "updated_at": datetime(2026, 5, 15, 19, 41, tzinfo=timezone.utc),
            "expires_at": datetime(2026, 6, 14, 19, 41, tzinfo=timezone.utc),
        }
    )

    assert resource["target"] == {
        "type": "audit_export",
        "id": "00000000-0000-4000-8000-000000000030",
    }
    assert resource["progress"] == {"step": "finalise", "percent": 100}
    assert resource["result"] == {"row_count": 1, "sha256": "abc"}
    assert resource["error"] is None
    assert resource["expires_at"] == "2026-06-14T19:41:00Z"


def test_traffic_log_resource_formats_fields() -> None:
    resource = traffic_log_resource(
        {
            "id": UUID("00000000-0000-4000-8000-000000000040"),
            "timestamp": datetime(2026, 5, 15, 20, 0, tzinfo=timezone.utc),
            "security_cvm_id": UUID("00000000-0000-4000-8000-000000000041"),
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
    )

    assert resource["timestamp"] == "2026-05-15T20:00:00Z"
    assert resource["security_cvm_id"] == "00000000-0000-4000-8000-000000000041"
    assert resource["cvm_id"] == "00000000-0000-4000-8000-000000000042"
    assert resource["bytes_transferred"] == 1234


def test_cvm_resource_formats_nested_profiles_and_keys() -> None:
    resource = cvm_resource(
        {
            "id": UUID("00000000-0000-4000-8000-000000000050"),
            "owner_id": UUID("00000000-0000-4000-8000-000000000051"),
            "owner_email": "dev@example.com",
            "entity_id": UUID("00000000-0000-4000-8000-000000000002"),
            "profiles": '[{"id":"00000000-0000-4000-8000-000000000060","name":"default"}]',
            "state": "RUNNING",
            "instance_type": "tdx.small",
            "region": "us",
            "ssh_keys": '[{"id":"00000000-0000-4000-8000-000000000061","label":"laptop"}]',
            "fqdn": "cvm.example.test",
            "expected_image_measurement": "a" * 96,
            "image_measurement": "b" * 96,
            "rtmr3_digest": "c" * 96,
            "attestation_verified_at": datetime(2026, 5, 15, 20, 10, tzinfo=timezone.utc),
            "error_reason": None,
            "created_at": datetime(2026, 5, 15, 20, 5, tzinfo=timezone.utc),
            "updated_at": datetime(2026, 5, 15, 20, 6, tzinfo=timezone.utc),
        }
    )

    assert resource["owner"] == {"id": "00000000-0000-4000-8000-000000000051", "email": "dev@example.com"}
    assert resource["profiles"] == [{"id": "00000000-0000-4000-8000-000000000060", "name": "default"}]
    assert resource["ssh_keys"] == [{"id": "00000000-0000-4000-8000-000000000061", "label": "laptop"}]
    assert resource["attestation_verified_at"] == "2026-05-15T20:10:00Z"


def test_security_cvm_resource_omits_secret_material() -> None:
    resource = security_cvm_resource(
        {
            "id": UUID("00000000-0000-4000-8000-000000000070"),
            "entity_id": UUID("00000000-0000-4000-8000-000000000002"),
            "state": "RUNNING",
            "fqdn": "sc.example.test",
            "instance_type": "tdx.small",
            "region": "us",
            "error_reason": None,
            "policy_version": 3,
            "expected_image_measurement": "a" * 96,
            "image_measurement": "b" * 96,
            "rtmr3_digest": "c" * 96,
            "attestation_verified_at": None,
            "created_at": datetime(2026, 5, 15, 20, 11, tzinfo=timezone.utc),
            "updated_at": datetime(2026, 5, 15, 20, 12, tzinfo=timezone.utc),
            "ca_cert_pem": "must-not-appear",
            "ingest_token_plaintext": "must-not-appear",
            "ca_export_token_plaintext": "must-not-appear",
        }
    )

    assert resource["policy_version"] == 3
    assert resource["attestation_verified_at"] is None
    assert "ca_cert_pem" not in resource
    assert "ingest_token_plaintext" not in resource
    assert "ca_export_token_plaintext" not in resource


def test_security_cvm_attestation_resource_reports_persisted_verdict() -> None:
    resource = security_cvm_attestation_resource(
        {
            "id": UUID("00000000-0000-4000-8000-000000000070"),
            "fqdn": "sc.example.test",
            "expected_image_measurement": "a" * 96,
            "image_measurement": "a" * 96,
            "rtmr3_digest": "c" * 96,
            "attestation_verified_at": datetime(2026, 5, 15, 20, 13, tzinfo=timezone.utc),
            "error_reason": None,
        }
    )

    assert resource == {
        "security_cvm_id": "00000000-0000-4000-8000-000000000070",
        "fqdn": "sc.example.test",
        "expected_image_measurement": "a" * 96,
        "verdict": {
            "verified": True,
            "failure_reason": None,
            "image_measurement_seen": "a" * 96,
            "rtmr3_digest_seen": "c" * 96,
            "verified_at": "2026-05-15T20:13:00Z",
        },
    }


def test_security_cvm_attestation_resource_derives_image_mismatch() -> None:
    resource = security_cvm_attestation_resource(
        {
            "id": UUID("00000000-0000-4000-8000-000000000070"),
            "fqdn": "sc.example.test",
            "expected_image_measurement": "a" * 96,
            "image_measurement": "b" * 96,
            "rtmr3_digest": "c" * 96,
            "attestation_verified_at": datetime(2026, 5, 15, 20, 13, tzinfo=timezone.utc),
            "error_reason": None,
        }
    )

    assert resource["verdict"]["verified"] is False
    assert resource["verdict"]["failure_reason"] == "ATTESTATION_IMAGE_MISMATCH"
