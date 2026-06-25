import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import HTTPException
from pydantic import ValidationError

from concrete_console import attestation
from concrete_console import routes as routes_module
from concrete_console.routes import (
    AdminKeysRotate,
    AdminReconcile,
    AssignedFilter,
    AuditExportCreate,
    CVMCreate,
    CvmStateFilter,
    SECURITY_CVM_PROVISION_REDACTION,
    SecurityCVMCreate,
    UserStatusFilter,
    apply_provider_cvm_lifecycle_action,
    cvm_etag,
    cvm_list_state_clauses,
    profile_list_assigned_clauses,
    user_list_assigned_clauses,
    user_list_status_clauses,
    cvm_provider_app_id,
    deprovision_security_cvm_dns_records,
    entity_quota_usage,
    erased_user_email,
    ensure_no_sandbox_env_conflict,
    fetch_live_security_cvm_id,
    policy_sha256,
    redacted_security_cvm_provision_result,
    profile_etag,
    require_cvm_owner_or_manager,
    require_cvm_profile_mutable,
    require_idempotency_key,
    require_if_match,
    replace_profile_secret_material,
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
from concrete_console.profile_secrets import encrypt_profile_secret_value
from concrete_console.tee_provider.phala import PhalaError
from concrete_console.routes_internal import (
    TrafficLogBatch,
    TrafficLogIn,
    enforce_traffic_log_volume_limit,
    etag_matches,
    get_dev_security_cvm_atls_policy,
    get_dev_security_cvm_ca,
    merge_profile_policies,
    record_sc_control_pull_observation,
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


def test_random_dns_token_is_128_bit_base32(monkeypatch) -> None:
    monkeypatch.setattr(routes_module.secrets, "token_bytes", lambda size: b"\0" * size)

    token = routes_module.random_dns_token()

    assert token == "a" * 26


def test_profile_etag_uses_updated_at_microseconds() -> None:
    assert profile_etag(profile_row()) == 'W/"00000000-0000-4000-8000-000000000010:123456"'


def test_cvm_etag_includes_policy_version() -> None:
    assert cvm_etag(cvm_row()) == 'W/"00000000-0000-4000-8000-000000000030:4:123456"'


def test_cvm_provider_app_id_reads_phala_metadata() -> None:
    assert cvm_provider_app_id(cvm_row(metadata={"app_id": "app-123"})) == "app-123"
    assert cvm_provider_app_id(cvm_row(metadata={})) is None


def test_require_cvm_owner_or_manager_allows_owner_without_manage() -> None:
    require_cvm_owner_or_manager(
        cvm_row(owner_id=UUID("00000000-0000-4000-8000-000000000020")),
        SimpleNamespace(id=UUID("00000000-0000-4000-8000-000000000020"), permissions=["CVM_LAUNCH"]),
    )


def test_require_cvm_owner_or_manager_allows_manager_for_other_owner() -> None:
    require_cvm_owner_or_manager(
        cvm_row(owner_id=UUID("00000000-0000-4000-8000-000000000021")),
        SimpleNamespace(id=UUID("00000000-0000-4000-8000-000000000020"), permissions=["CVM_MANAGE"]),
    )


def test_require_cvm_owner_or_manager_hides_other_owner_without_manage() -> None:
    with pytest.raises(HTTPException) as exc:
        require_cvm_owner_or_manager(
            cvm_row(owner_id=UUID("00000000-0000-4000-8000-000000000021")),
            SimpleNamespace(id=UUID("00000000-0000-4000-8000-000000000020"), permissions=["CVM_LAUNCH"]),
        )

    assert exc.value.status_code == 404
    assert exc.value.detail["error"]["code"] == "NOT_FOUND"


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
    assert exc.value.detail["error"]["details"] == {"adapter": "cvm_provider", "reason": "cli_failed"}


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
    assert exc.value.detail["error"]["details"] == {"adapter": "cvm_provider", "reason": "cli_failed"}


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


@pytest.mark.parametrize(
    ("state", "expected_clauses", "expected_values"),
    [
        # Omitted / alive: live rows only, no state predicate (the default).
        (None, ["c.deleted_at IS NULL"], []),
        (CvmStateFilter.alive, ["c.deleted_at IS NULL"], []),
        # all: drop the live-row clause -> includes terminated.
        (CvmStateFilter.all, [], []),
        # terminated: drop the live-row clause (it is soft-deleted) and match it.
        (CvmStateFilter.terminated, ["c.state = $2"], ["TERMINATED"]),
        # Concrete states: live rows + state match; value UPPERCASE and bound at
        # $2 (never interpolated -- asserting the exact clause proves it).
        (CvmStateFilter.provisioning, ["c.deleted_at IS NULL", "c.state = $2"], ["PROVISIONING"]),
        (CvmStateFilter.running, ["c.deleted_at IS NULL", "c.state = $2"], ["RUNNING"]),
        (CvmStateFilter.stopped, ["c.deleted_at IS NULL", "c.state = $2"], ["STOPPED"]),
        (CvmStateFilter.failed, ["c.deleted_at IS NULL", "c.state = $2"], ["FAILED"]),
    ],
)
def test_cvm_list_state_clauses(state, expected_clauses, expected_values) -> None:
    clauses, values = cvm_list_state_clauses(state, next_param_index=2)
    assert clauses == expected_clauses
    assert values == expected_values


def test_cvm_list_state_clauses_binds_state_at_the_given_param_index() -> None:
    # The `$N` placeholder follows the index the caller passes (the route puts
    # it after entity_id); the value is bound, never string-interpolated.
    clauses, values = cvm_list_state_clauses(CvmStateFilter.failed, next_param_index=5)
    assert clauses == ["c.deleted_at IS NULL", "c.state = $5"]
    assert values == ["FAILED"]


@pytest.mark.parametrize(
    ("assigned", "expected_clauses"),
    [
        # Omitted: no membership predicate (every visible profile).
        (None, []),
        # yes / no: the current-user membership LEFT JOIN exposes pu.user_id.
        (AssignedFilter.yes, ["pu.user_id IS NOT NULL"]),
        (AssignedFilter.no, ["pu.user_id IS NULL"]),
    ],
)
def test_profile_list_assigned_clauses(assigned, expected_clauses) -> None:
    assert profile_list_assigned_clauses(assigned) == expected_clauses


@pytest.mark.parametrize(
    ("status", "expected_clauses"),
    [
        # Omitted: all non-erased users (the default live-row clause).
        (None, ["u.deleted_at IS NULL"]),
        # active / deactivated keep the live-row clause and split on deactivated_at.
        (UserStatusFilter.active, ["u.deactivated_at IS NULL", "u.deleted_at IS NULL"]),
        (UserStatusFilter.deactivated, ["u.deactivated_at IS NOT NULL", "u.deleted_at IS NULL"]),
        # erased: drops the base live-row clause and matches soft-deleted rows
        # (keeping `deleted_at IS NULL` would always return nothing).
        (UserStatusFilter.erased, ["u.deleted_at IS NOT NULL"]),
    ],
)
def test_user_list_status_clauses(status, expected_clauses) -> None:
    assert user_list_status_clauses(status) == expected_clauses


@pytest.mark.parametrize(
    ("assigned", "expected_clauses"),
    [
        # Omitted: no membership predicate (any membership).
        (None, []),
        # yes / no: belongs to >=1 live profile, or to none. The EXISTS joins
        # entity_profiles and drops soft-deleted profiles so the filter matches
        # the displayed `profiles` subquery.
        (
            AssignedFilter.yes,
            [
                "EXISTS (SELECT 1 FROM profile_users pu "
                "JOIN entity_profiles ep ON ep.id = pu.profile_id "
                "WHERE pu.user_id = u.id AND ep.deleted_at IS NULL)"
            ],
        ),
        (
            AssignedFilter.no,
            [
                "NOT EXISTS (SELECT 1 FROM profile_users pu "
                "JOIN entity_profiles ep ON ep.id = pu.profile_id "
                "WHERE pu.user_id = u.id AND ep.deleted_at IS NULL)"
            ],
        ),
    ],
)
def test_user_list_assigned_clauses(assigned, expected_clauses) -> None:
    assert user_list_assigned_clauses(assigned) == expected_clauses


def test_resolve_cvm_launch_config_uses_defaults(monkeypatch) -> None:
    monkeypatch.delenv("DEV_CVM_DEFAULT_INSTANCE_TYPE", raising=False)
    monkeypatch.setenv("DEV_CVM_DEFAULT_REGION", "FR-PARIS-1")
    monkeypatch.setenv("PHALA_REGION", "US-ASHBURN-1")
    monkeypatch.setenv("DEV_CVM_IMAGE", "ghcr.io/concrete-security/dev-cvm/user-sandbox@sha256:abc")
    monkeypatch.setenv("DEV_CVM_IMAGE_MEASUREMENT", "A" * 96)
    monkeypatch.setenv("CLOUDFLARE_BASE_DOMAIN", "dev.example.com")

    resolved = resolve_cvm_launch_config(cvm_create())

    assert resolved["instance_type"] == "tdx.small"
    assert resolved["region"] == "FR-PARIS-1"
    assert resolved["expected_image_measurement"] == "a" * 96
    assert resolved["base_domain"] == "dev.example.com"


def test_resolve_cvm_launch_config_falls_back_to_phala_region(monkeypatch) -> None:
    monkeypatch.delenv("DEV_CVM_DEFAULT_REGION", raising=False)
    monkeypatch.setenv("PHALA_REGION", "FR-PARIS-1")
    monkeypatch.setenv("DEV_CVM_IMAGE", "ghcr.io/concrete-security/dev-cvm/user-sandbox@sha256:abc")
    monkeypatch.setenv("DEV_CVM_IMAGE_MEASUREMENT", "A" * 96)
    monkeypatch.setenv("CLOUDFLARE_BASE_DOMAIN", "dev.example.com")

    resolved = resolve_cvm_launch_config(cvm_create())

    assert resolved["region"] == "FR-PARIS-1"


def test_resolve_cvm_launch_config_requires_region(monkeypatch) -> None:
    monkeypatch.setenv("DEV_CVM_DEFAULT_REGION", "")
    monkeypatch.setenv("PHALA_REGION", "")

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
    monkeypatch.setenv("DEV_CVM_IMAGE_MEASUREMENT", "a" * 96)
    monkeypatch.delenv("CLOUDFLARE_BASE_DOMAIN", raising=False)

    with pytest.raises(HTTPException) as exc:
        resolve_cvm_launch_config(cvm_create())

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "cloudflare_base_domain"


def test_resolve_cvm_launch_config_rejects_cert_cn_too_long_base_domain(monkeypatch) -> None:
    monkeypatch.setenv("DEV_CVM_DEFAULT_REGION", "FR-PARIS-1")
    monkeypatch.setenv("DEV_CVM_IMAGE", "ghcr.io/concrete-security/dev-cvm/user-sandbox@sha256:abc")
    monkeypatch.setenv("DEV_CVM_IMAGE_MEASUREMENT", "a" * 96)
    monkeypatch.setenv("CLOUDFLARE_BASE_DOMAIN", f"{'a' * 23}.example.com")

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
            "expected_image_measurement": "a" * 96,
            "base_domain": "dev.example.com",
        }
    )

    assert "ghcr.io/concrete-security/dev-cvm/user-sandbox@sha256:abc" in compose
    user_sandbox_section = compose.split("  dev-egress-forwarder:", 1)[0]
    forwarder_section = compose.split("  dev-egress-forwarder:", 1)[1].split("  dev-tunnel:", 1)[0]
    assert "${SECURITY_CVM_PROXY_TOKEN}" not in user_sandbox_section
    assert "${SECURITY_CVM_ATLS_POLICY_B64}" not in user_sandbox_section
    assert "${DEV_CVM_CONTROL_TOKEN}" not in user_sandbox_section
    assert "${CONSOLE_URL:-}" not in user_sandbox_section
    assert "${SECURITY_CVM_PROXY_TOKEN}" in forwarder_section
    assert "${SECURITY_CVM_ATLS_POLICY_B64}" in forwarder_section
    assert "${DEV_CVM_CONTROL_TOKEN}" in forwarder_section
    assert "${CONSOLE_URL:-}" in forwarder_section
    assert "${SECURITY_CVM_CONNECT_HOST:-}" in compose
    assert "${AUTHORIZED_SSH_KEYS_B64}" in compose
    assert "  dev-egress-forwarder:" in compose
    assert "entrypoint: [\"concrete-dev-egress-forwarder\"]" in compose
    assert "  dev-tunnel:" in compose
    assert "entrypoint: [\"concrete-dev-tunnel\"]" in compose
    assert "runtime: sysbox-runc" in compose
    assert "internal: true" in compose
    assert "no-new-privileges:true" in compose
    assert "ports:" not in compose
    assert "token_urlsafe" not in compose


def test_resolve_security_cvm_provision_config_uses_defaults(monkeypatch) -> None:
    monkeypatch.delenv("PHALA_DEFAULT_INSTANCE_TYPE", raising=False)
    monkeypatch.setenv("SECURITY_CVM_DEFAULT_REGION", "FR-PARIS-1")
    monkeypatch.setenv("PHALA_REGION", "US-ASHBURN-1")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_REF", "ghcr.io/concrete-security/security-cvm/mitmproxy@sha256:abc")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_MEASUREMENT", "B" * 96)
    monkeypatch.setenv("SECURITY_CVM_BASE_DOMAIN", "sc.example.com")

    resolved = resolve_security_cvm_provision_config(security_cvm_create())

    assert resolved["instance_type"] == "tdx.small"
    assert resolved["region"] == "FR-PARIS-1"
    assert resolved["expected_image_measurement"] == "b" * 96
    assert resolved["base_domain"] == "sc.example.com"


def test_resolve_security_cvm_provision_config_falls_back_to_phala_region(monkeypatch) -> None:
    monkeypatch.delenv("SECURITY_CVM_DEFAULT_REGION", raising=False)
    monkeypatch.setenv("PHALA_REGION", "FR-PARIS-1")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_REF", "ghcr.io/concrete-security/security-cvm/mitmproxy@sha256:abc")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_MEASUREMENT", "B" * 96)
    monkeypatch.setenv("SECURITY_CVM_BASE_DOMAIN", "sc.example.com")

    resolved = resolve_security_cvm_provision_config(security_cvm_create())

    assert resolved["region"] == "FR-PARIS-1"


def test_resolve_security_cvm_provision_config_requires_region(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_CVM_DEFAULT_REGION", "")
    monkeypatch.setenv("PHALA_REGION", "")

    with pytest.raises(HTTPException) as exc:
        resolve_security_cvm_provision_config(security_cvm_create())

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["errors"][0]["field"] == "region"


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
    monkeypatch.setenv("SECURITY_CVM_IMAGE_MEASUREMENT", "b" * 96)
    monkeypatch.delenv("SECURITY_CVM_BASE_DOMAIN", raising=False)

    with pytest.raises(HTTPException) as exc:
        resolve_security_cvm_provision_config(security_cvm_create())

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "security_cvm_base_domain"


def test_resolve_security_cvm_provision_config_rejects_cert_cn_too_long_base_domain(monkeypatch) -> None:
    monkeypatch.setenv("PHALA_REGION", "FR-PARIS-1")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_REF", "ghcr.io/concrete-security/security-cvm/mitmproxy@sha256:abc")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_MEASUREMENT", "b" * 96)
    monkeypatch.setenv("SECURITY_CVM_BASE_DOMAIN", f"{'a' * 24}.example.com")

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
            "expected_image_measurement": "b" * 96,
            "base_domain": "sc.example.com",
        }
    )

    assert "ghcr.io/concrete-security/security-cvm/mitmproxy@sha256:abc" in compose
    assert "  mitmproxy:" in compose
    assert "command: [\"concrete-security-mitmproxy\"]" in compose
    assert "  proxy-tunnel:" in compose
    assert "command: [\"concrete-security-proxy-tunnel\"]" in compose
    assert "SC_PROXY_TUNNEL_PATH: /concrete/proxy" in compose
    assert "${ENTITY_ID}" in compose
    assert "${SC_ID}" in compose
    assert "${SC_FQDN}" not in compose
    assert "${CONSOLE_INGEST_TOKEN}" in compose
    assert "${CA_EXPORT_TOKEN}" in compose
    assert "SC_MITMPROXY_CONFDIR: /tmp/mitmproxy" in compose
    assert "no-new-privileges:true" in compose
    assert "token_urlsafe" not in compose


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


class DevControlPolicyConn:
    def __init__(self, row):
        self.row = row
        self.args = None

    async def fetchrow(self, query, *args):
        self.args = args
        return self.row


def test_dev_control_security_cvm_atls_policy_requires_verified_sc() -> None:
    conn = DevControlPolicyConn(
        {
            "cvm_id": UUID("00000000-0000-4000-8000-000000000031"),
            "security_cvm_id": UUID("00000000-0000-4000-8000-000000000041"),
            "security_cvm_fqdn": "sc.example.com",
            "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n",
            "metadata": {
                "passthrough_host": "app-443s.dstack.example.com",
                "atls_policy": {
                    "type": "dstack_tdx",
                    "expected_bootchain": {"mrtd": "a" * 96},
                    "app_compose": {"docker_compose_file": "services: {}\n"},
                    "os_image_hash": "b" * 64,
                },
            },
            "expected_image_measurement": "a" * 96,
            "image_measurement": "a" * 96,
            "attestation_verified_at": datetime(2026, 5, 28, 12, 0, tzinfo=timezone.utc),
            "error_reason": None,
        }
    )
    principal = SimpleNamespace(
        principal_id=UUID("00000000-0000-4000-8000-000000000031"),
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
    )

    result = asyncio.run(
        get_dev_security_cvm_atls_policy(
            response=SimpleNamespace(headers={}),
            current_principal=principal,
            pool=FakePool(conn),
        )
    )

    assert conn.args == (
        UUID("00000000-0000-4000-8000-000000000031"),
        UUID("00000000-0000-4000-8000-000000000001"),
    )
    assert result["security_cvm_fqdn"] == "sc.example.com"
    assert result["connect_host"] == "app-443s.dstack.example.com"
    assert result["ca_cert_sha256"] == "6ed8689d60a419e4b9785827a35338b06c974ac432960f7a9b397eba64c1c574"
    assert result["atls_policy"]["type"] == "dstack_tdx"


def test_dev_control_security_cvm_atls_policy_rejects_unverified_sc() -> None:
    conn = DevControlPolicyConn(
        {
            "cvm_id": UUID("00000000-0000-4000-8000-000000000031"),
            "security_cvm_id": UUID("00000000-0000-4000-8000-000000000041"),
            "security_cvm_fqdn": "sc.example.com",
            "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n",
            "metadata": {"atls_policy": {"type": "dstack_tdx"}},
            "expected_image_measurement": "a" * 96,
            "image_measurement": "b" * 96,
            "attestation_verified_at": datetime(2026, 5, 28, 12, 0, tzinfo=timezone.utc),
            "error_reason": None,
        }
    )
    principal = SimpleNamespace(
        principal_id=UUID("00000000-0000-4000-8000-000000000031"),
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
    )

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            get_dev_security_cvm_atls_policy(
                response=SimpleNamespace(headers={}),
                current_principal=principal,
                pool=FakePool(conn),
            )
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["details"]["state"] == "security_cvm_attestation_unverified"


def test_dev_control_security_cvm_atls_policy_rejects_drifted_sc() -> None:
    conn = DevControlPolicyConn(
        {
            "cvm_id": UUID("00000000-0000-4000-8000-000000000031"),
            "security_cvm_id": UUID("00000000-0000-4000-8000-000000000041"),
            "security_cvm_fqdn": "sc.example.com",
            "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n",
            "metadata": {"atls_policy": {"type": "dstack_tdx"}},
            "expected_image_measurement": "a" * 96,
            "image_measurement": "a" * 96,
            "attestation_verified_at": datetime(2026, 5, 28, 12, 0, tzinfo=timezone.utc),
            "error_reason": "ATTESTATION_DRIFT",
        }
    )
    principal = SimpleNamespace(
        principal_id=UUID("00000000-0000-4000-8000-000000000031"),
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
    )

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            get_dev_security_cvm_atls_policy(
                response=SimpleNamespace(headers={}),
                current_principal=principal,
                pool=FakePool(conn),
            )
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["details"]["state"] == "security_cvm_attestation_unverified"


def test_dev_control_security_cvm_ca_returns_ca_for_verified_sc() -> None:
    conn = DevControlPolicyConn(
        {
            "cvm_id": UUID("00000000-0000-4000-8000-000000000031"),
            "security_cvm_id": UUID("00000000-0000-4000-8000-000000000041"),
            "security_cvm_fqdn": "sc.example.com",
            "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n",
            "expected_image_measurement": "a" * 96,
            "image_measurement": "a" * 96,
            "attestation_verified_at": datetime(2026, 5, 28, 12, 0, tzinfo=timezone.utc),
            "error_reason": None,
        }
    )
    principal = SimpleNamespace(
        principal_id=UUID("00000000-0000-4000-8000-000000000031"),
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
    )

    response = SimpleNamespace(headers={})
    result = asyncio.run(
        get_dev_security_cvm_ca(
            response=response,
            current_principal=principal,
            pool=FakePool(conn),
        )
    )

    assert conn.args == (
        UUID("00000000-0000-4000-8000-000000000031"),
        UUID("00000000-0000-4000-8000-000000000001"),
    )
    assert result["security_cvm_fqdn"] == "sc.example.com"
    assert result["ca_cert_pem"] == "-----BEGIN CERTIFICATE-----\nMIIB\n"
    assert result["ca_cert_sha256"] == "6ed8689d60a419e4b9785827a35338b06c974ac432960f7a9b397eba64c1c574"
    assert response.headers["Cache-Control"] == "no-store"


def test_dev_control_security_cvm_ca_rejects_unverified_sc() -> None:
    conn = DevControlPolicyConn(
        {
            "cvm_id": UUID("00000000-0000-4000-8000-000000000031"),
            "security_cvm_id": UUID("00000000-0000-4000-8000-000000000041"),
            "security_cvm_fqdn": "sc.example.com",
            "ca_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIB\n",
            "expected_image_measurement": "a" * 96,
            "image_measurement": "b" * 96,
            "attestation_verified_at": datetime(2026, 5, 28, 12, 0, tzinfo=timezone.utc),
            "error_reason": None,
        }
    )
    principal = SimpleNamespace(
        principal_id=UUID("00000000-0000-4000-8000-000000000031"),
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
    )

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            get_dev_security_cvm_ca(
                response=SimpleNamespace(headers={}),
                current_principal=principal,
                pool=FakePool(conn),
            )
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["details"]["state"] == "security_cvm_attestation_unverified"


class SecurityCvmAttestationProbeConn:
    def __init__(self):
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []
        self.audit_calls: list[dict[str, object]] = []

    def transaction(self):
        return AsyncContext()

    async def fetch(self, query, *args):
        if "FROM service_principal_tokens" in query:
            return [
                {"purpose": "INGEST", "token_hash": "b" * 64},
                {"purpose": "CA_EXPORT", "token_hash": "c" * 64},
            ]
        raise AssertionError(f"unexpected fetch query: {query}")

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "UPDATE 1"


class FetchSecurityCvmRowConn:
    def __init__(self):
        self.query = ""

    async def fetchrow(self, query, *args):
        self.query = query
        return security_cvm_attestation_row()


def security_cvm_attestation_row(**overrides):
    row = {
        "id": UUID("00000000-0000-4000-8000-000000000041"),
        "entity_id": UUID("00000000-0000-4000-8000-000000000001"),
        "state": "RUNNING",
        "fqdn": "sc.example.com",
        "metadata": {"provider": "phala", "passthrough_host": "sc-app-443s.dstack.example.com"},
        "compose_config": "services: {}\n",
        "expected_image_measurement": "a" * 96,
        "image_measurement": None,
        "rtmr3_digest": None,
        "attestation_verified_at": None,
        "error_reason": None,
    }
    row.update(overrides)
    return row


def test_fetch_security_cvm_row_includes_metadata_for_route_hints() -> None:
    conn = FetchSecurityCvmRowConn()

    row = asyncio.run(routes_module.fetch_security_cvm_row(conn, UUID("00000000-0000-4000-8000-000000000001")))

    assert row is not None
    assert "metadata" in conn.query


def current_user(**overrides):
    row = {
        "id": UUID("00000000-0000-4000-8000-000000000020"),
        "email": "admin@example.com",
    }
    row.update(overrides)
    return SimpleNamespace(**row)


def test_run_security_cvm_attestation_probe_persists_success(monkeypatch) -> None:
    conn = SecurityCvmAttestationProbeConn()
    captured_request: dict[str, object] = {}

    class FakeVerifier:
        async def verify(self, request, *, timeout_seconds):
            captured_request.update(request)
            assert timeout_seconds == 30
            return attestation.AttestationReport(image_measurement="a" * 96, rtmr3_digest="d" * 96)

    async def fake_insert_audit_event(_conn, **kwargs):
        conn.audit_calls.append(kwargs)

    monkeypatch.setenv("CONSOLE_URL", "https://console.example.com")
    monkeypatch.setattr(attestation.AtlasVerifierClient, "from_settings", classmethod(lambda cls: FakeVerifier()))
    monkeypatch.setattr(routes_module, "insert_audit_event", fake_insert_audit_event)

    result = asyncio.run(
        routes_module.run_security_cvm_attestation_probe(
            conn,
            security_cvm_attestation_row(),
            current_user=current_user(),
        )
    )

    assert captured_request["kind"] == "security_cvm"
    assert captured_request["connect_host"] == "sc-app-443s.dstack.example.com"
    assert captured_request["policy"]["rtmr3_binding"]["ingest_token_sha256"] == "b" * 64
    assert result["verdict"]["verified"] is True
    security_cvm_updates = [args for query, args in conn.execute_calls if "UPDATE security_cvms" in query]
    assert security_cvm_updates[0][:3] == (
        UUID("00000000-0000-4000-8000-000000000041"),
        "a" * 96,
        "d" * 96,
    )
    assert conn.audit_calls[0]["action"] == "SECURITY_CVM_ATTESTATION_VERIFIED"
    assert conn.audit_calls[0]["after"]["source"] == "on_demand"


def test_run_security_cvm_attestation_probe_reports_drift_without_update(monkeypatch) -> None:
    conn = SecurityCvmAttestationProbeConn()

    class FakeVerifier:
        async def verify(self, request, *, timeout_seconds):
            return attestation.AttestationReport(image_measurement="e" * 96, rtmr3_digest="f" * 96)

    async def fake_insert_audit_event(_conn, **kwargs):
        conn.audit_calls.append(kwargs)

    monkeypatch.setattr(attestation.AtlasVerifierClient, "from_settings", classmethod(lambda cls: FakeVerifier()))
    monkeypatch.setattr(routes_module, "insert_audit_event", fake_insert_audit_event)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            routes_module.run_security_cvm_attestation_probe(
                conn,
                security_cvm_attestation_row(image_measurement="a" * 96, rtmr3_digest="d" * 96),
                current_user=current_user(),
            )
        )

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["details"]["state"] == "attestation_drift"
    assert conn.audit_calls[0]["action"] == "SECURITY_CVM_ATTESTATION_DRIFT"
    assert not [query for query, _args in conn.execute_calls if "UPDATE security_cvms" in query]


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
    validate_profile_policy({"sandbox_env": {"PLACEHOLDER": "value"}})


def test_validate_profile_policy_accepts_egress_boundary() -> None:
    validate_profile_policy({"egress_boundary": True})


def test_validate_profile_policy_rejects_non_boolean_egress_boundary() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy({"egress_boundary": "true"})

    errors = exc.value.detail["error"]["details"]["errors"]
    assert errors == [{"field": "policy.egress_boundary", "type": "boolean_required"}]


def test_validate_profile_policy_rejects_unknown_top_level_field() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy({"sandbox_env": {"PLACEHOLDER": "value"}, "opaque": {"kept": True}})

    assert exc.value.status_code == 422
    errors = exc.value.detail["error"]["details"]["errors"]
    assert errors == [{"field": "policy.opaque", "type": "unknown_field"}]


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


def test_validate_profile_policy_rejects_invalid_destination_schema() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "allowed_destinations": [
                    {
                        "id": "bad-destination",
                        "scheme": "https",
                        "host": "slack.com:443",
                        "ports": [443],
                        "methods": ["post"],
                        "path_prefixes": ["/api/conversations.history/../chat.postMessage"],
                    }
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error == {"field": "policy.allowed_destinations.0.host", "type": "invalid_host"} for error in errors)
    assert any(error == {"field": "policy.allowed_destinations.0.methods.0", "type": "invalid_method"} for error in errors)
    assert any(
        error == {"field": "policy.allowed_destinations.0.path_prefixes.0", "type": "invalid_path_prefix"}
        for error in errors
    )


def test_validate_profile_policy_accepts_wildcard_destination_host() -> None:
    validate_profile_policy(
        {
            "allowed_destinations": [
                {
                    "id": "internet-https",
                    "scheme": "https",
                    "host": "*",
                    "ports": [443],
                    "methods": ["GET", "POST"],
                    "path_prefixes": ["/"],
                }
            ],
            "blocked_destinations": [
                {
                    "id": "block-public-internet",
                    "scheme": "https",
                    "host": "*",
                    "ports": [443],
                    "methods": ["POST"],
                    "path_prefixes": ["/upload"],
                }
            ],
        }
    )


def test_validate_profile_policy_rejects_malformed_wildcard_destination_host() -> None:
    for host in ("*.", "**", "*.com"):
        with pytest.raises(HTTPException) as exc:
            validate_profile_policy(
                {
                    "allowed_destinations": [
                        {
                            "id": "bad-wildcard",
                            "scheme": "https",
                            "host": host,
                            "ports": [443],
                            "methods": ["GET"],
                            "path_prefixes": ["/"],
                        }
                    ]
                }
            )
        errors = exc.value.detail["error"]["details"]["errors"]
        assert {"field": "policy.allowed_destinations.0.host", "type": "invalid_host"} in errors


def test_validate_profile_policy_allows_npm_scoped_package_path_prefix() -> None:
    validate_profile_policy(
        {
            "allowed_destinations": [
                {
                    "id": "npm-scoped-package",
                    "scheme": "https",
                    "host": "registry.npmjs.org",
                    "ports": [443],
                    "methods": ["GET"],
                    "path_prefixes": ["/@openclaw%2fslack"],
                }
            ]
        }
    )


def test_validate_profile_policy_accepts_body_assertions_and_traffic_log_attributes() -> None:
    validate_profile_policy(
        {
            "allowed_destinations": [
                {
                    "id": "slack-read",
                    "scheme": "https",
                    "host": "slack.com",
                    "ports": [443],
                    "methods": ["POST"],
                    "path_prefixes": ["/api/conversations.history"],
                    "body_assertions": [
                        {"kind": "form", "field": "/channel", "allow_values": ["C0ALLOWED1"]},
                        {"kind": "json", "field": "/channel", "allow_values": ["C0ALLOWED1"]},
                    ],
                    "traffic_log_attributes": [
                        {"name": "slack_channel", "kind": "form", "field": "/channel"},
                    ],
                }
            ]
        }
    )


def test_validate_profile_policy_rejects_body_assertions_on_blocked_destination() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "blocked_destinations": [
                    {
                        "id": "block-this",
                        "scheme": "https",
                        "host": "slack.com",
                        "ports": [443],
                        "methods": ["POST"],
                        "path_prefixes": ["/api/chat.postMessage"],
                        "body_assertions": [
                            {"kind": "form", "field": "/channel", "allow_values": ["X"]}
                        ],
                    }
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "forbidden_field" for error in errors)


def test_validate_profile_policy_rejects_body_assertions_on_injection_match() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "secret_injections": [
                    {
                        "id": "slack-bearer",
                        "match": {
                            "scheme": "https",
                            "host": "slack.com",
                            "ports": [443],
                            "methods": ["POST"],
                            "path_prefixes": ["/api/"],
                            "body_assertions": [
                                {"kind": "form", "field": "/channel", "allow_values": ["X"]}
                            ],
                        },
                        "type": "request_header",
                        "header": "authorization",
                        "value": "xoxb-real",
                        "value_template": "Bearer ${secret}",
                    }
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "forbidden_field" for error in errors)


def test_validate_profile_policy_rejects_invalid_secret_injection_match() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "secret_injections": [
                    {
                        "id": "slack-bearer",
                        "match": {
                            "scheme": "https",
                            "host": "slack.com:443",
                            "ports": [443],
                            "methods": ["POST"],
                            "path_prefixes": ["/api/conversations.history/%2e%2e/chat.postMessage"],
                        },
                        "type": "request_header",
                        "header": "proxy-authorization",
                        "value": "xoxb-real",
                        "value_template": "Bearer ${secret}",
                    }
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["field"] == "policy.secret_injections.0.match.host" and error["type"] == "invalid_host" for error in errors)
    assert any(
        error["field"] == "policy.secret_injections.0.match.path_prefixes.0"
        and error["type"] == "invalid_path_prefix"
        for error in errors
    )
    assert any(error["field"] == "policy.secret_injections.0.header" and error["type"] == "invalid_header" for error in errors)


def test_validate_profile_policy_rejects_duplicate_secret_injection_ids() -> None:
    injection = {
        "id": "slack-bearer",
        "match": {
            "scheme": "https",
            "host": "slack.com",
            "ports": [443],
            "methods": ["POST"],
            "path_prefixes": ["/api/"],
        },
        "type": "request_header",
        "header": "authorization",
        "value": "xoxb-real",
        "value_template": "Bearer ${secret}",
    }
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy({"secret_injections": [injection, dict(injection)]})

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["field"] == "policy.secret_injections.1.id" and error["type"] == "duplicate_id" for error in errors)


def test_replace_profile_secret_material_encrypts_values(monkeypatch) -> None:
    class FakeConn:
        def __init__(self) -> None:
            self.calls = []

        async def execute(self, sql, *args):
            self.calls.append((sql, args))
            return "OK"

    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    conn = FakeConn()
    profile_id = UUID("00000000-0000-4000-8000-000000000010")

    asyncio.run(
        replace_profile_secret_material(
            conn,
            profile_id=profile_id,
            secret_values={"anthropic-key": "sk-ant-real"},
        )
    )

    assert len(conn.calls) == 2
    assert "DELETE FROM profile_secret_material" in conn.calls[0][0]
    assert conn.calls[0][1] == (profile_id, ["anthropic-key"])
    assert "INSERT INTO profile_secret_material" in conn.calls[1][0]
    assert conn.calls[1][1][0:2] == (profile_id, "anthropic-key")
    ciphertext = conn.calls[1][1][2]
    assert ciphertext.startswith("v1:")
    assert "sk-ant-real" not in ciphertext


def test_validate_profile_policy_rejects_secret_pattern_that_security_cvm_cannot_compile() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "secret_patterns": [
                    {
                        "id": "bad-regex",
                        "name": "Bad regex",
                        "pattern": "(",
                        "scan_headers": True,
                        "scan_body": True,
                    }
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert errors == [{"field": "policy.secret_patterns.0.pattern", "type": "invalid_regex"}]


def test_validate_profile_policy_rejects_invalid_body_assertion_kind() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "allowed_destinations": [
                    {
                        "body_assertions": [
                            {"kind": "yaml", "field": "/channel", "allow_values": ["X"]}
                        ]
                    }
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "invalid_kind" for error in errors)


def test_validate_profile_policy_rejects_form_pointer_with_multiple_segments() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "allowed_destinations": [
                    {
                        "body_assertions": [
                            {"kind": "form", "field": "/a/b", "allow_values": ["X"]}
                        ]
                    }
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "invalid_field" for error in errors)


def test_validate_profile_policy_rejects_json_pointer_with_too_many_segments() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "allowed_destinations": [
                    {
                        "body_assertions": [
                            {"kind": "json", "field": "/a/b/c/d/e", "allow_values": ["X"]}
                        ]
                    }
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "invalid_field" for error in errors)


def test_validate_profile_policy_rejects_traffic_log_attribute_invalid_name() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "allowed_destinations": [
                    {
                        "traffic_log_attributes": [
                            {"name": "SlackChannel", "kind": "form", "field": "/channel"}
                        ]
                    }
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "invalid_name" for error in errors)


def test_validate_profile_policy_rejects_traffic_log_attribute_duplicate_name() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "allowed_destinations": [
                    {
                        "traffic_log_attributes": [
                            {"name": "slack_channel", "kind": "form", "field": "/channel"},
                            {"name": "slack_channel", "kind": "form", "field": "/channel"},
                        ]
                    }
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "duplicate_name" for error in errors)


def test_validate_profile_policy_rejects_body_assertion_empty_allow_values() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "allowed_destinations": [
                    {
                        "body_assertions": [
                            {"kind": "form", "field": "/channel", "allow_values": []}
                        ]
                    }
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "invalid_allow_values" for error in errors)


def _ws_assertion(**overrides: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "direction": "inbound",
        "when": {"/type": "events_api"},
        "require": {"/payload/event/channel": {"in": ["C0ALLOWED"]}},
        "on_violation": "drop",
        "on_drop_emit": {"envelope_id": "{/envelope_id}"},
    }
    entry.update(overrides)
    return entry


def _ws_rule(**overrides: object) -> dict[str, object]:
    rule: dict[str, object] = {
        "id": "slack-socket-mode",
        "scheme": "https",
        "host": "wss-primary.slack.com",
        "ports": [443],
        "methods": ["GET"],
        "path_prefixes": ["/"],
        "websocket_assertions": [_ws_assertion()],
    }
    rule.update(overrides)
    return rule


def test_validate_profile_policy_accepts_websocket_assertions() -> None:
    validate_profile_policy({"allowed_destinations": [_ws_rule()]})


def test_validate_profile_policy_rejects_websocket_assertions_on_blocked_destination() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy({"blocked_destinations": [_ws_rule()]})

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(
        error == {"field": "policy.blocked_destinations.0.websocket_assertions", "type": "forbidden_field"}
        for error in errors
    )


def test_validate_profile_policy_rejects_websocket_assertions_on_injection_match() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "secret_injections": [
                    {
                        "id": "slack-bearer",
                        "match": {
                            "scheme": "https",
                            "host": "wss-primary.slack.com",
                            "ports": [443],
                            "methods": ["GET"],
                            "path_prefixes": ["/"],
                            "websocket_assertions": [_ws_assertion()],
                        },
                        "type": "request_header",
                        "header": "authorization",
                        "value": "xoxb-real",
                        "value_template": "Bearer ${secret}",
                    }
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "forbidden_field" for error in errors)


def test_validate_profile_policy_rejects_lifecycle_when_target() -> None:
    # Lifecycle frames are governed solely by the SC bound; a when:{/type:hello}
    # guard is dead/misleading and must be rejected at authoring time.
    for lifecycle_type in ("hello", "disconnect"):
        with pytest.raises(HTTPException) as exc:
            validate_profile_policy(
                {
                    "allowed_destinations": [
                        _ws_rule(
                            websocket_assertions=[
                                _ws_assertion(
                                    when={"/type": lifecycle_type},
                                    require={"/num_connections": {"in": ["1"]}},
                                )
                            ]
                        )
                    ]
                }
            )

        errors = exc.value.detail["error"]["details"]["errors"]
        assert any(error["type"] == "lifecycle_when_forbidden" for error in errors)


def test_validate_profile_policy_rejects_websocket_outbound_direction() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {"allowed_destinations": [_ws_rule(websocket_assertions=[_ws_assertion(direction="outbound")])]}
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "invalid_direction" for error in errors)


def test_validate_profile_policy_rejects_websocket_invalid_on_violation() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {"allowed_destinations": [_ws_rule(websocket_assertions=[_ws_assertion(on_violation="redact")])]}
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "invalid_on_violation" for error in errors)


def test_validate_profile_policy_rejects_websocket_require_without_in_matcher() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "allowed_destinations": [
                    _ws_rule(
                        websocket_assertions=[
                            _ws_assertion(require={"/payload/event/channel": {"eq": "C0ALLOWED"}})
                        ]
                    )
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "invalid_matcher" for error in errors)


def test_validate_profile_policy_rejects_websocket_require_pointer_too_many_segments() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "allowed_destinations": [
                    _ws_rule(websocket_assertions=[_ws_assertion(require={"/a/b/c/d/e": {"in": ["x"]}})])
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "invalid_field" for error in errors)


def test_validate_profile_policy_rejects_websocket_invalid_emit_template() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "allowed_destinations": [
                    _ws_rule(websocket_assertions=[_ws_assertion(on_drop_emit={"envelope_id": "literal"})])
                ]
            }
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "invalid_emit_template" for error in errors)


def test_validate_profile_policy_rejects_websocket_empty_when() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {"allowed_destinations": [_ws_rule(websocket_assertions=[_ws_assertion(when={})])]}
        )

    errors = exc.value.detail["error"]["details"]["errors"]
    assert any(error["type"] == "invalid_when" for error in errors)


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
    assert exc.value.detail["error"]["details"]["component"] == "cvm_provider_adapter"


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
        "ca_export_token": "ca-plaintext",
    }

    redacted = redacted_security_cvm_provision_result(result)

    assert redacted == {
        "security_cvm": {"id": "00000000-0000-4000-8000-000000000040", "state": "RUNNING"},
        "ca_export_token": SECURITY_CVM_PROVISION_REDACTION,
    }
    assert result["ca_export_token"] == "ca-plaintext"


def test_redacted_security_cvm_provision_result_accepts_json_payload() -> None:
    redacted = redacted_security_cvm_provision_result(
        '{"security_cvm":{"id":"sc-1"},"ca_export_token":"ca"}'
    )

    assert redacted["security_cvm"] == {"id": "sc-1"}
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


def test_traffic_log_in_accepts_attributes() -> None:
    log = traffic_log(attributes={"slack_channel": "C0ALLOWED1"})
    assert log.attributes == {"slack_channel": "C0ALLOWED1"}


def test_traffic_log_in_defaults_attributes_to_empty_dict() -> None:
    log = traffic_log()
    assert log.attributes == {}


def test_traffic_log_in_rejects_invalid_attribute_name() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        traffic_log(attributes={"BadName": "x"})


def test_traffic_log_in_rejects_too_many_attributes() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        traffic_log(attributes={f"k_{i}": "v" for i in range(5)})


def test_traffic_log_in_rejects_overlong_attribute_value() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        traffic_log(attributes={"slack_channel": "x" * 257})


def test_traffic_log_in_rejects_path_with_query_string() -> None:
    with pytest.raises(ValidationError):
        traffic_log(path="/api/chat.postMessage?token=not-logged")


class TrafficLogVolumeLimitConn:
    def __init__(self, current_count: int):
        self.current_count = current_count
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []
        self.fetchval_calls: list[tuple[str, tuple[object, ...]]] = []

    async def execute(self, query: str, *args):
        self.execute_calls.append((query, args))
        return "SELECT 1"

    async def fetchval(self, query: str, *args):
        self.fetchval_calls.append((query, args))
        return self.current_count


def test_enforce_traffic_log_volume_limit_allows_within_budget() -> None:
    security_cvm_id = UUID("00000000-0000-4000-8000-000000000041")
    conn = TrafficLogVolumeLimitConn(current_count=4990)

    asyncio.run(enforce_traffic_log_volume_limit(conn, security_cvm_id=security_cvm_id, row_count=10))

    assert "pg_advisory_xact_lock" in conn.execute_calls[0][0]
    assert conn.fetchval_calls[0][1] == (security_cvm_id,)


def test_enforce_traffic_log_volume_limit_rejects_over_budget() -> None:
    security_cvm_id = UUID("00000000-0000-4000-8000-000000000041")
    conn = TrafficLogVolumeLimitConn(current_count=4991)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(enforce_traffic_log_volume_limit(conn, security_cvm_id=security_cvm_id, row_count=10))

    assert exc.value.status_code == 429
    assert exc.value.headers == {"Retry-After": "60"}
    assert exc.value.detail["error"]["details"] == {
        "retry_after_seconds": 60,
        "limit": "traffic_log_principal_logs",
    }


def test_merge_profile_policies_field_typed(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    profile_b = "profile-b"
    ciphertext = encrypt_profile_secret_value(
        profile_id=profile_b,
        injection_id="anthropic-key",
        value="sk-ant-real",
    )
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
                "profile_id": profile_b,
                "policy": {
                    "allowed_destinations": [{"id": "github", "host": "api.github.com"}],
                    "blocked_destinations": [{"id": "admin", "host": "admin.example.com"}],
                    "secret_injections": [
                        {
                            "id": "anthropic-key",
                            "header": "authorization",
                            "value_template": "Bearer ${secret}",
                        }
                    ],
                    "sandbox_env": {"OPENAI_API_KEY": "concrete-proxy-injected"},
                },
                "secret_material": {"anthropic-key": ciphertext},
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
        "secret_injections": [
            {
                "id": "anthropic-key",
                "header": "authorization",
                "value": "sk-ant-real",
                "value_template": "Bearer ${secret}",
            }
        ],
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


def test_merge_profile_policies_boundary_allow_list_ignores_open_profile() -> None:
    boundary_rule = {
        "id": "github-only",
        "scheme": "https",
        "host": "api.github.com",
        "ports": [443],
        "methods": ["GET"],
        "path_prefixes": ["/"],
    }
    open_rule = {
        "id": "internet-https",
        "scheme": "https",
        "host": "*",
        "ports": [443],
        "methods": ["GET"],
        "path_prefixes": ["/"],
    }

    merged = merge_profile_policies(
        [
            {"policy": {"allowed_destinations": [open_rule]}},
            {"policy": {"egress_boundary": True, "allowed_destinations": [boundary_rule]}},
        ]
    )

    assert merged["allowed_destinations"] == [boundary_rule]


def test_merge_profile_policies_boundary_air_gap_ignores_open_profile() -> None:
    merged = merge_profile_policies(
        [
            {
                "policy": {
                    "allowed_destinations": [
                        {
                            "id": "internet-https",
                            "scheme": "https",
                            "host": "*",
                            "ports": [443],
                            "methods": ["GET"],
                            "path_prefixes": ["/"],
                        }
                    ]
                }
            },
            {"policy": {"egress_boundary": True, "allowed_destinations": []}},
        ]
    )

    assert merged["allowed_destinations"] == []


def test_merge_profile_policies_multiple_boundaries_union_their_allow_lists() -> None:
    github_rule = {"id": "github", "host": "api.github.com"}
    anthropic_rule = {"id": "anthropic", "host": "api.anthropic.com"}

    merged = merge_profile_policies(
        [
            {"policy": {"egress_boundary": True, "allowed_destinations": [github_rule]}},
            {"policy": {"egress_boundary": True, "allowed_destinations": [anthropic_rule]}},
        ]
    )

    assert merged["allowed_destinations"] == [github_rule, anthropic_rule]


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


class ExecuteRecorder:
    def __init__(self) -> None:
        self.execute_calls: list[tuple[str, tuple[object, ...]]] = []

    async def execute(self, query, *args):
        self.execute_calls.append((query, args))
        return "UPDATE 1"


def test_record_sc_control_pull_observation_updates_policy_pull_columns() -> None:
    conn = ExecuteRecorder()
    security_cvm_id = UUID("00000000-0000-4000-8000-000000000041")
    entity_id = UUID("00000000-0000-4000-8000-000000000001")

    asyncio.run(
        record_sc_control_pull_observation(
            conn,
            security_cvm_id=security_cvm_id,
            entity_id=entity_id,
            etag='"abc"',
            entry_count=2,
        )
    )

    query, args = conn.execute_calls[0]
    assert "last_policy_pull_at = now()" in query
    assert "updated_at = now()" not in query
    assert args == (security_cvm_id, entity_id, '"abc"', 2)


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
