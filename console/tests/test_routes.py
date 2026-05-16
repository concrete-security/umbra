import asyncio
from datetime import datetime, timezone
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import HTTPException
from pydantic import ValidationError

from concrete_console.routes import (
    AdminKeysRotate,
    AdminReconcile,
    AuditExportCreate,
    CVMCreate,
    SECURITY_CVM_PROVISION_REDACTION,
    SecurityCVMCreate,
    apply_provider_cvm_lifecycle_action,
    cvm_etag,
    cvm_provider_app_id,
    deprovision_security_cvm_dns_records,
    entity_quota_usage,
    erased_user_email,
    ensure_no_sandbox_env_conflict,
    fetch_live_security_cvm_id,
    policy_sha256,
    redacted_security_cvm_provision_result,
    profile_etag,
    require_cvm_profile_mutable,
    require_idempotency_key,
    require_if_match,
    render_dev_cvm_compose_config,
    render_security_cvm_compose_config,
    resolve_cvm_launch_config,
    resolve_security_cvm_provision_config,
    security_cvm_provider_app_id,
    ssh_key_fingerprint,
    terminate_provider_security_cvm,
    user_quota_usage,
    user_etag,
    validate_audit_export_request,
    validate_permission_symbol,
    validate_profile_policy,
    validate_reconcile_dependencies,
)
from concrete_console.dns_provider.cloudflare import CloudflareError
from concrete_console.tee_provider.phala import PhalaError
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


def cvm_create(**overrides) -> CVMCreate:
    body = {
        "profile_ids": [UUID("00000000-0000-4000-8000-000000000031")],
        "ssh_key_ids": [UUID("00000000-0000-4000-8000-000000000032")],
    }
    body.update(overrides)
    return CVMCreate(**body)


def security_cvm_create(**overrides) -> SecurityCVMCreate:
    return SecurityCVMCreate(**overrides)


def test_profile_etag_uses_updated_at_microseconds() -> None:
    assert profile_etag(profile_row()) == 'W/"00000000-0000-4000-8000-000000000010:123456"'


def test_cvm_etag_includes_policy_version() -> None:
    assert cvm_etag(cvm_row()) == 'W/"00000000-0000-4000-8000-000000000030:4:123456"'


def test_cvm_provider_app_id_reads_phala_metadata() -> None:
    assert cvm_provider_app_id(cvm_row(metadata={"app_id": "app-123"})) == "app-123"
    assert cvm_provider_app_id(cvm_row(metadata={})) is None


def test_apply_provider_cvm_lifecycle_action_calls_phala(monkeypatch) -> None:
    calls = []

    class FakePhalaClient:
        async def start(self, app_id: str) -> None:
            calls.append(("start", app_id))

        async def stop(self, app_id: str) -> None:
            calls.append(("stop", app_id))

    fake = FakePhalaClient()
    monkeypatch.setattr(
        "concrete_console.tee_provider.phala.PhalaClient.from_settings",
        classmethod(lambda cls, *, timeout_seconds=None: calls.append(("timeout", timeout_seconds)) or fake),
    )

    asyncio.run(apply_provider_cvm_lifecycle_action(app_id="app-123", action="start"))
    asyncio.run(apply_provider_cvm_lifecycle_action(app_id="app-123", action="stop"))

    assert calls == [
        ("timeout", 30.0),
        ("start", "app-123"),
        ("timeout", 30.0),
        ("stop", "app-123"),
    ]


def test_apply_provider_cvm_lifecycle_action_wraps_phala_error(monkeypatch) -> None:
    class FailingPhalaClient:
        async def start(self, app_id: str) -> None:
            raise PhalaError("cli_failed")

        async def stop(self, app_id: str) -> None:
            raise AssertionError("unexpected stop call")

    fake = FailingPhalaClient()
    monkeypatch.setattr(
        "concrete_console.tee_provider.phala.PhalaClient.from_settings",
        classmethod(lambda cls, *, timeout_seconds=None: fake),
    )

    with pytest.raises(HTTPException) as exc:
        asyncio.run(apply_provider_cvm_lifecycle_action(app_id="app-123", action="start"))

    assert exc.value.status_code == 502
    assert exc.value.detail["error"]["code"] == "UPSTREAM_ERROR"
    assert exc.value.detail["error"]["details"] == {"adapter": "phala", "reason": "cli_failed"}


def test_security_cvm_provider_app_id_reads_phala_metadata() -> None:
    assert security_cvm_provider_app_id({"metadata": {"app_id": "sc-app-123"}}) == "sc-app-123"
    assert security_cvm_provider_app_id({"metadata": {}}) is None


def test_terminate_provider_security_cvm_calls_phala_delete(monkeypatch) -> None:
    calls = []

    class FakePhalaClient:
        async def delete(self, app_id: str) -> None:
            calls.append(app_id)

    fake = FakePhalaClient()
    monkeypatch.setattr(
        "concrete_console.tee_provider.phala.PhalaClient.from_settings",
        classmethod(lambda cls, *, timeout_seconds=None: fake),
    )

    asyncio.run(terminate_provider_security_cvm(app_id="sc-app-123"))

    assert calls == ["sc-app-123"]


def test_terminate_provider_security_cvm_wraps_phala_error(monkeypatch) -> None:
    class FailingPhalaClient:
        async def delete(self, app_id: str) -> None:
            raise PhalaError("cli_failed")

    fake = FailingPhalaClient()
    monkeypatch.setattr(
        "concrete_console.tee_provider.phala.PhalaClient.from_settings",
        classmethod(lambda cls, *, timeout_seconds=None: fake),
    )

    with pytest.raises(HTTPException) as exc:
        asyncio.run(terminate_provider_security_cvm(app_id="sc-app-123"))

    assert exc.value.status_code == 502
    assert exc.value.detail["error"]["code"] == "UPSTREAM_ERROR"
    assert exc.value.detail["error"]["details"] == {"adapter": "phala", "reason": "cli_failed"}


def test_deprovision_security_cvm_dns_records_uses_security_zone(monkeypatch) -> None:
    calls = []

    class FakeCloudflareClient:
        async def delete_record(self, record_id: str) -> None:
            calls.append(("delete", record_id))

    fake = FakeCloudflareClient()
    monkeypatch.setattr(
        "concrete_console.dns_provider.cloudflare.CloudflareClient.from_settings",
        classmethod(
            lambda cls, *, zone_id_key="CLOUDFLARE_ZONE_ID": calls.append(("zone", zone_id_key)) or fake
        ),
    )

    deleted = asyncio.run(
        deprovision_security_cvm_dns_records(
            {
                "id": UUID("00000000-0000-4000-8000-000000000040"),
                "txt_dns_record_id": "txt-record",
                "cname_dns_record_id": "cname-record",
            }
        )
    )

    assert deleted == {"txt_dns_record_id", "cname_dns_record_id"}
    assert calls == [
        ("zone", "SECURITY_CVM_ZONE_ID"),
        ("delete", "txt-record"),
        ("delete", "cname-record"),
    ]


def test_deprovision_security_cvm_dns_records_keeps_failed_record_ids(monkeypatch) -> None:
    class FakeCloudflareClient:
        async def delete_record(self, record_id: str) -> None:
            if record_id == "txt-record":
                raise CloudflareError("api_error")

    fake = FakeCloudflareClient()
    monkeypatch.setattr(
        "concrete_console.dns_provider.cloudflare.CloudflareClient.from_settings",
        classmethod(lambda cls, *, zone_id_key="CLOUDFLARE_ZONE_ID": fake),
    )

    deleted = asyncio.run(
        deprovision_security_cvm_dns_records(
            {
                "id": UUID("00000000-0000-4000-8000-000000000040"),
                "txt_dns_record_id": "txt-record",
                "cname_dns_record_id": "cname-record",
            }
        )
    )

    assert deleted == {"cname_dns_record_id"}


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


def test_cvm_create_rejects_duplicate_profile_ids() -> None:
    profile_id = UUID("00000000-0000-4000-8000-000000000031")

    with pytest.raises(ValidationError):
        cvm_create(profile_ids=[profile_id, profile_id])


def test_resolve_cvm_launch_config_uses_defaults(monkeypatch) -> None:
    monkeypatch.delenv("DEV_CVM_DEFAULT_INSTANCE_TYPE", raising=False)
    monkeypatch.setenv("DEV_CVM_DEFAULT_REGION", "FR-PARIS-1")
    monkeypatch.setenv("DEV_CVM_IMAGE", "ghcr.io/concrete-security/dev-cvm/user-sandbox@sha256:abc")
    monkeypatch.setenv("DEV_CVM_IMAGE_MEASUREMENT", "A" * 64)
    monkeypatch.setenv("CLOUDFLARE_BASE_DOMAIN", "dev.example.com")

    resolved = resolve_cvm_launch_config(cvm_create())

    assert resolved["instance_type"] == "tdx.small"
    assert resolved["region"] == "FR-PARIS-1"
    assert resolved["expected_image_measurement"] == "a" * 64
    assert resolved["base_domain"] == "dev.example.com"


def test_resolve_cvm_launch_config_requires_region(monkeypatch) -> None:
    monkeypatch.delenv("DEV_CVM_DEFAULT_REGION", raising=False)

    with pytest.raises(HTTPException) as exc:
        resolve_cvm_launch_config(cvm_create())

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["errors"][0]["field"] == "region"


def test_resolve_cvm_launch_config_requires_image(monkeypatch) -> None:
    monkeypatch.setenv("DEV_CVM_DEFAULT_REGION", "FR-PARIS-1")
    monkeypatch.delenv("DEV_CVM_IMAGE", raising=False)

    with pytest.raises(HTTPException) as exc:
        resolve_cvm_launch_config(cvm_create())

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "dev_cvm_image"


def test_resolve_cvm_launch_config_requires_image_measurement(monkeypatch) -> None:
    monkeypatch.setenv("DEV_CVM_DEFAULT_REGION", "FR-PARIS-1")
    monkeypatch.setenv("DEV_CVM_IMAGE", "ghcr.io/concrete-security/dev-cvm/user-sandbox@sha256:abc")
    monkeypatch.setenv("DEV_CVM_IMAGE_MEASUREMENT", "not-hex")

    with pytest.raises(HTTPException) as exc:
        resolve_cvm_launch_config(cvm_create())

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "dev_cvm_image_measurement"


def test_resolve_cvm_launch_config_requires_base_domain(monkeypatch) -> None:
    monkeypatch.setenv("DEV_CVM_DEFAULT_REGION", "FR-PARIS-1")
    monkeypatch.setenv("DEV_CVM_IMAGE", "ghcr.io/concrete-security/dev-cvm/user-sandbox@sha256:abc")
    monkeypatch.setenv("DEV_CVM_IMAGE_MEASUREMENT", "a" * 64)
    monkeypatch.delenv("CLOUDFLARE_BASE_DOMAIN", raising=False)

    with pytest.raises(HTTPException) as exc:
        resolve_cvm_launch_config(cvm_create())

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "cloudflare_base_domain"


def test_render_dev_cvm_compose_config_keeps_runtime_values_as_placeholders() -> None:
    compose = render_dev_cvm_compose_config(
        {
            "image": "ghcr.io/concrete-security/dev-cvm/user-sandbox@sha256:abc",
            "instance_type": "tdx.small",
            "region": "FR-PARIS-1",
            "expected_image_measurement": "a" * 64,
            "base_domain": "dev.example.com",
        }
    )

    assert "ghcr.io/concrete-security/dev-cvm/user-sandbox@sha256:abc" in compose
    assert "${SECURITY_CVM_PROXY_TOKEN}" in compose
    assert "${AUTHORIZED_SSH_KEYS_B64}" in compose
    assert "token_urlsafe" not in compose


def test_resolve_security_cvm_provision_config_uses_defaults(monkeypatch) -> None:
    monkeypatch.delenv("PHALA_DEFAULT_INSTANCE_TYPE", raising=False)
    monkeypatch.setenv("PHALA_REGION", "FR-PARIS-1")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_REF", "ghcr.io/concrete-security/security-cvm/mitmproxy@sha256:abc")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_MEASUREMENT", "B" * 64)
    monkeypatch.setenv("SECURITY_CVM_BASE_DOMAIN", "sc.example.com")

    resolved = resolve_security_cvm_provision_config(security_cvm_create())

    assert resolved["instance_type"] == "tdx.small"
    assert resolved["region"] == "FR-PARIS-1"
    assert resolved["expected_image_measurement"] == "b" * 64
    assert resolved["base_domain"] == "sc.example.com"


def test_resolve_security_cvm_provision_config_requires_image_pair(monkeypatch) -> None:
    with pytest.raises(HTTPException) as exc:
        resolve_security_cvm_provision_config(security_cvm_create(image_ref="ghcr.io/example/sc@sha256:abc"))

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["errors"][0]["type"] == "paired_image_measurement"


def test_resolve_security_cvm_provision_config_requires_image(monkeypatch) -> None:
    monkeypatch.setenv("PHALA_REGION", "FR-PARIS-1")
    monkeypatch.setenv("SECURITY_CVM_BASE_DOMAIN", "sc.example.com")
    monkeypatch.delenv("SECURITY_CVM_IMAGE_REF", raising=False)

    with pytest.raises(HTTPException) as exc:
        resolve_security_cvm_provision_config(security_cvm_create())

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "security_cvm_image"


def test_resolve_security_cvm_provision_config_requires_base_domain(monkeypatch) -> None:
    monkeypatch.setenv("PHALA_REGION", "FR-PARIS-1")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_REF", "ghcr.io/concrete-security/security-cvm/mitmproxy@sha256:abc")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_MEASUREMENT", "b" * 64)
    monkeypatch.delenv("SECURITY_CVM_BASE_DOMAIN", raising=False)

    with pytest.raises(HTTPException) as exc:
        resolve_security_cvm_provision_config(security_cvm_create())

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "security_cvm_base_domain"


def test_render_security_cvm_compose_config_keeps_runtime_values_as_placeholders() -> None:
    compose = render_security_cvm_compose_config(
        {
            "image_ref": "ghcr.io/concrete-security/security-cvm/mitmproxy@sha256:abc",
            "instance_type": "tdx.small",
            "region": "FR-PARIS-1",
            "expected_image_measurement": "b" * 64,
            "base_domain": "sc.example.com",
        }
    )

    assert "ghcr.io/concrete-security/security-cvm/mitmproxy@sha256:abc" in compose
    assert "${CONSOLE_INGEST_TOKEN}" in compose
    assert "${CA_EXPORT_TOKEN}" in compose
    assert "token_urlsafe" not in compose


class FakeFetchValConn:
    def __init__(self, value):
        self.value = value
        self.queries: list[str] = []

    async def fetchval(self, query, *args):
        self.queries.append(query)
        return self.value


def test_dev_cvm_quota_usage_counts_non_terminated_rows() -> None:
    entity_conn = FakeFetchValConn(3)
    user_conn = FakeFetchValConn(2)

    entity_usage = asyncio.run(
        entity_quota_usage(entity_conn, UUID("00000000-0000-4000-8000-000000000001"), "dev_cvms")
    )
    user_usage = asyncio.run(
        user_quota_usage(user_conn, UUID("00000000-0000-4000-8000-000000000002"), "dev_cvms")
    )

    assert entity_usage == 3
    assert user_usage == 2
    assert "state <> 'TERMINATED'" in entity_conn.queries[0]
    assert "state <> 'TERMINATED'" in user_conn.queries[0]


def test_fetch_live_security_cvm_id_requires_running_security_cvm() -> None:
    conn = FakeFetchValConn(None)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(fetch_live_security_cvm_id(conn, UUID("00000000-0000-4000-8000-000000000001")))

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["details"]["state"] == "no_security_cvm"


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


def test_admin_reconcile_defaults_to_orphan_cleanup() -> None:
    assert AdminReconcile().include_orphans is True


def test_validate_reconcile_dependencies_requires_phala(monkeypatch) -> None:
    monkeypatch.delenv("PHALA_API_TOKEN", raising=False)

    with pytest.raises(HTTPException) as exc:
        validate_reconcile_dependencies(include_orphans=False)

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "phala_adapter"


def test_validate_reconcile_dependencies_requires_cloudflare_for_orphans(monkeypatch) -> None:
    monkeypatch.setenv("PHALA_API_TOKEN", "phala-token")
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)
    monkeypatch.setenv("CLOUDFLARE_ZONE_ID", "dev-zone")
    monkeypatch.setenv("SECURITY_CVM_ZONE_ID", "security-zone")

    with pytest.raises(HTTPException) as exc:
        validate_reconcile_dependencies(include_orphans=True)

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "cloudflare_adapter"


def test_validate_reconcile_dependencies_allows_no_orphans_without_cloudflare(monkeypatch) -> None:
    monkeypatch.setenv("PHALA_API_TOKEN", "phala-token")
    monkeypatch.delenv("CLOUDFLARE_API_TOKEN", raising=False)

    validate_reconcile_dependencies(include_orphans=False)


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
