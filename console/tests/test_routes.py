import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi import HTTPException
from pydantic import ValidationError

from umbra_console import attestation
from umbra_console import routes as routes_module
from umbra_console.routes import (
    AdminKeysRotate,
    AdminReconcile,
    AssignedFilter,
    AuditExportCreate,
    CVMCreate,
    CvmStateFilter,
    SECURITY_CVM_PROVISION_REDACTION,
    SecurityCVMCreate,
    UserSecretPut,
    UserStatusFilter,
    delete_user_secret,
    list_user_secrets,
    lock_cvm_for_lifecycle_action,
    put_user_secret,
    apply_provider_cvm_lifecycle_action,
    cvm_etag,
    cvm_list_state_clauses,
    profile_list_assigned_clauses,
    user_list_assigned_clauses,
    user_list_status_clauses,
    cvm_provider_app_id,
    default_quota_limit,
    deprovision_security_cvm_dns_records,
    enforce_disk_quotas,
    entity_quota_usage,
    user_quota_limit,
    erased_user_email,
    ensure_no_sandbox_env_conflict,
    fetch_live_security_cvm_id,
    policy_sha256,
    redacted_security_cvm_provision_result,
    profile_etag,
    require_cvm_owner_or_manager,
    require_cvm_update_supported,
    require_cvm_profile_mutable,
    require_idempotency_key,
    require_if_match,
    replace_profile_secret_material,
    render_dev_cvm_compose_config,
    render_security_cvm_compose_config,
    resolve_cvm_launch_config,
    resolve_dev_cvm_disk_gb,
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
from umbra_console.dns_provider.cloudflare import CloudflareError
from umbra_console.profile_secrets import encrypt_profile_secret_value, encrypt_user_secret_value
from umbra_console.tee_provider.phala import PhalaError
from umbra_console.routes_internal import (
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


def test_require_cvm_update_supported_legacy_marker_failure() -> None:
    """A preserved legacy marker rejects update with the safe replacement path."""
    with pytest.raises(HTTPException) as exc:
        require_cvm_update_supported(cvm_row(error_reason="SECURITY_CVM_REBIND_REQUIRED"))

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["code"] == "CONFLICT"
    assert exc.value.detail["error"]["details"] == {
        "state": "legacy_cvm_replacement_required",
        "error_reason": "SECURITY_CVM_REBIND_REQUIRED",
    }
    assert "pre-Umbra control plane" in exc.value.detail["error"]["message"]
    assert "launch a replacement under Umbra" in exc.value.detail["error"]["message"]
    assert "`umbra cvm update` is not a recovery path" in exc.value.detail["error"]["message"]


def test_lock_cvm_for_lifecycle_action_selects_error_reason_success() -> None:
    """The row lock carries the legacy marker into the update guard."""

    class LockConn:
        query = ""

        async def fetchrow(self, query, *args):
            self.query = query
            return cvm_row(error_reason="SECURITY_CVM_REBIND_REQUIRED")

    conn = LockConn()
    row = asyncio.run(
        lock_cvm_for_lifecycle_action(
            conn,
            cvm_id=UUID("00000000-0000-4000-8000-000000000030"),
            current_user=SimpleNamespace(entity_id=UUID("00000000-0000-4000-8000-000000000002")),
        )
    )

    assert "error_reason" in conn.query
    assert row["error_reason"] == "SECURITY_CVM_REBIND_REQUIRED"


def test_apply_provider_cvm_lifecycle_action_calls_phala(monkeypatch) -> None:
    calls = []

    class FakePhalaClient:
        async def start(self, app_id: str) -> None:
            calls.append(("start", app_id))

        async def stop(self, app_id: str) -> None:
            calls.append(("stop", app_id))

    fake = FakePhalaClient()
    monkeypatch.setattr(
        "umbra_console.tee_provider.phala.PhalaClient.from_settings",
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
        "umbra_console.tee_provider.phala.PhalaClient.from_settings",
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
        "umbra_console.tee_provider.phala.PhalaClient.from_settings",
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
        "umbra_console.tee_provider.phala.PhalaClient.from_settings",
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
        "umbra_console.dns_provider.cloudflare.CloudflareClient.from_settings",
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
        "umbra_console.dns_provider.cloudflare.CloudflareClient.from_settings",
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
        # Explicit states: live rows + state match; value UPPERCASE and bound at
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
    monkeypatch.setenv("DEV_CVM_IMAGE", "registry.invalid/umbra/dev-cvm@sha256:abc")
    monkeypatch.setenv("DEV_CVM_IMAGE_MEASUREMENT", "A" * 96)
    monkeypatch.setenv("CLOUDFLARE_BASE_DOMAIN", "dev.example.com")

    resolved = resolve_cvm_launch_config(cvm_create())

    assert resolved["instance_type"] == "tdx.small"
    assert resolved["region"] == "FR-PARIS-1"
    assert resolved["expected_image_measurement"] == "a" * 96
    assert resolved["base_domain"] == "dev.example.com"
    assert resolved["disk_size_gb"] == 40


def test_resolve_dev_cvm_disk_gb_uses_default_when_omitted() -> None:
    assert resolve_dev_cvm_disk_gb(None, {}) == 40


def test_resolve_dev_cvm_disk_gb_accepts_in_range_request() -> None:
    assert resolve_dev_cvm_disk_gb(100, {"DEV_CVM_MIN_DISK_GB": "40", "DEV_CVM_MAX_DISK_GB": "2000"}) == 100


def test_resolve_dev_cvm_disk_gb_rejects_out_of_range_request() -> None:
    with pytest.raises(HTTPException) as exc:
        resolve_dev_cvm_disk_gb(5, {"DEV_CVM_MIN_DISK_GB": "40", "DEV_CVM_MAX_DISK_GB": "2000"})

    assert exc.value.status_code == 422
    err = exc.value.detail["error"]["details"]["errors"][0]
    assert err["field"] == "disk_size_gb"
    assert err["type"] == "out_of_range"


def test_resolve_dev_cvm_disk_gb_rejects_out_of_range_default() -> None:
    # A misconfigured server default is an operator fault, not a client fault.
    with pytest.raises(HTTPException) as exc:
        resolve_dev_cvm_disk_gb(None, {"DEV_CVM_DEFAULT_DISK_GB": "5", "DEV_CVM_MIN_DISK_GB": "40"})

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "dev_cvm_default_disk_gb"


def test_resolve_cvm_launch_config_falls_back_to_phala_region(monkeypatch) -> None:
    monkeypatch.delenv("DEV_CVM_DEFAULT_REGION", raising=False)
    monkeypatch.setenv("PHALA_REGION", "FR-PARIS-1")
    monkeypatch.setenv("DEV_CVM_IMAGE", "registry.invalid/umbra/dev-cvm@sha256:abc")
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
    monkeypatch.setenv("DEV_CVM_IMAGE", "registry.invalid/umbra/dev-cvm@sha256:abc")
    monkeypatch.setenv("DEV_CVM_IMAGE_MEASUREMENT", "not-hex")

    with pytest.raises(HTTPException) as exc:
        resolve_cvm_launch_config(cvm_create())

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "dev_cvm_image_measurement"


def test_resolve_cvm_launch_config_requires_base_domain(monkeypatch) -> None:
    monkeypatch.setenv("DEV_CVM_DEFAULT_REGION", "FR-PARIS-1")
    monkeypatch.setenv("DEV_CVM_IMAGE", "registry.invalid/umbra/dev-cvm@sha256:abc")
    monkeypatch.setenv("DEV_CVM_IMAGE_MEASUREMENT", "a" * 96)
    monkeypatch.delenv("CLOUDFLARE_BASE_DOMAIN", raising=False)

    with pytest.raises(HTTPException) as exc:
        resolve_cvm_launch_config(cvm_create())

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "cloudflare_base_domain"


def test_resolve_cvm_launch_config_rejects_cert_cn_too_long_base_domain(monkeypatch) -> None:
    monkeypatch.setenv("DEV_CVM_DEFAULT_REGION", "FR-PARIS-1")
    monkeypatch.setenv("DEV_CVM_IMAGE", "registry.invalid/umbra/dev-cvm@sha256:abc")
    monkeypatch.setenv("DEV_CVM_IMAGE_MEASUREMENT", "a" * 96)
    monkeypatch.setenv("CLOUDFLARE_BASE_DOMAIN", f"{'a' * 23}.example.com")

    with pytest.raises(HTTPException) as exc:
        resolve_cvm_launch_config(cvm_create())

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "cloudflare_base_domain"


def test_render_dev_cvm_compose_config_keeps_runtime_values_as_placeholders() -> None:
    compose = render_dev_cvm_compose_config(
        {
            "image": "registry.invalid/umbra/dev-cvm@sha256:abc",
            "instance_type": "tdx.small",
            "region": "FR-PARIS-1",
            "expected_image_measurement": "a" * 96,
            "base_domain": "dev.example.com",
        }
    )

    assert "registry.invalid/umbra/dev-cvm@sha256:abc" in compose
    user_sandbox_section = compose.split("  dev-egress-forwarder:", 1)[0]
    forwarder_section = compose.split("  dev-egress-forwarder:", 1)[1].split("  dev-tunnel:", 1)[0]
    assert "${SECURITY_CVM_PROXY_TOKEN}" not in user_sandbox_section
    assert "SECURITY_CVM_ATLS_POLICY_B64" not in compose
    assert "SECURITY_CVM_ATLS_POLICY_GZIP_B64" not in compose
    assert "${DEV_CVM_CONTROL_TOKEN}" not in user_sandbox_section
    assert "${CONSOLE_URL:-}" not in user_sandbox_section
    assert "SECURITY_CVM_FQDN: ${SECURITY_CVM_FQDN}" in user_sandbox_section
    assert "${SECURITY_CVM_PROXY_TOKEN}" in forwarder_section
    assert "${DEV_CVM_CONTROL_TOKEN}" in forwarder_section
    assert "${CONSOLE_URL:-}" in forwarder_section
    assert "${SECURITY_CVM_CONNECT_HOST:-}" not in compose
    assert "${AUTHORIZED_SSH_KEYS_B64}" in compose
    assert "  dev-egress-forwarder:" in compose
    assert "entrypoint: [\"umbra-dev-egress-forwarder\"]" in compose
    assert "cvm-ca:/var/lib/umbra-ca:ro" in user_sandbox_section
    assert "cvm-ca:/var/lib/umbra-ca" in forwarder_section
    assert "  dev-tunnel:" in compose
    assert "entrypoint: [\"umbra-dev-tunnel\"]" in compose
    assert "runtime: sysbox-runc" in compose
    assert "internal: true" in compose
    assert "no-new-privileges:true" in compose
    assert "ports:" not in compose
    assert "token_urlsafe" not in compose


DEV_CVM_COMPOSE_PATH = Path(__file__).resolve().parents[2] / "cvms" / "dev" / "docker-compose.yml"
DEV_CVM_IMAGE_PLACEHOLDER = "${DEV_CVM_IMAGE:?set DEV_CVM_IMAGE to a digest-pinned GHCR image}"
DEV_CVM_PINNED_IMAGE = "registry.invalid/umbra/dev-cvm@sha256:abc"
_ABSENT = "<absent>"


def _dev_cvm_compose_pair() -> tuple[dict, dict]:
    """Parse the checked-in dev compose and the launch-time rendered compose.

    The single classified-legitimate difference is each service's `image`: the checked-in
    file is driven by the ${DEV_CVM_IMAGE} shell placeholder while the renderer pins the
    launch digest. It is normalised away here; every other key is security/runtime
    relevant and must match.
    """
    local = yaml.safe_load(DEV_CVM_COMPOSE_PATH.read_text())
    rendered = yaml.safe_load(render_dev_cvm_compose_config({"image": DEV_CVM_PINNED_IMAGE}))
    for service in local["services"].values():
        assert service["image"] == DEV_CVM_IMAGE_PLACEHOLDER
    for service in rendered["services"].values():
        assert service["image"] == DEV_CVM_PINNED_IMAGE
        service["image"] = DEV_CVM_IMAGE_PLACEHOLDER
    return local, rendered


def _dev_cvm_compose_drift(local: object, rendered: object, path: str = "") -> list[str]:
    """Recursively collect ``key: checked-in=… rendered=…`` lines for every mismatch."""
    if isinstance(local, dict) and isinstance(rendered, dict):
        drift: list[str] = []
        for key in sorted(set(local) | set(rendered)):
            drift += _dev_cvm_compose_drift(local.get(key, _ABSENT), rendered.get(key, _ABSENT), f"{path}/{key}")
        return drift
    if isinstance(local, list) and isinstance(rendered, list):
        if sorted(map(repr, local)) == sorted(map(repr, rendered)):
            return []
    elif local == rendered:
        return []
    return [f"{path or '/'}: checked-in={local!r} rendered={rendered!r}"]


def test_render_dev_cvm_compose_config_matches_checked_in_compose_success() -> None:
    """Pin the two Dev CVM composes together: the renderer's output is what actually
    launches production CVMs and what ops/deploy/measure-dev-cvm-image.py measures, while
    cvms/dev/docker-compose.yml is the reviewed reference. Drift between them (e.g. the
    missing sidecar `healthcheck: disable`) silently ships a different runtime than the
    one the repo documents and tests.
    """
    local, rendered = _dev_cvm_compose_pair()

    drift = _dev_cvm_compose_drift(local, rendered)

    assert not drift, "rendered Dev CVM compose drifted from cvms/dev/docker-compose.yml:\n" + "\n".join(drift)


@pytest.mark.parametrize(
    "service, expected_healthcheck",
    [
        (
            "user-sandbox",
            {
                "test": ["CMD-SHELL", "pgrep -x sshd >/dev/null"],
                "interval": "500ms",
                "timeout": "2s",
                "start_period": "3s",
                "retries": 5,
            },
        ),
        ("dev-egress-forwarder", {"disable": True}),
        ("dev-tunnel", {"disable": True}),
    ],
    ids=["sandbox-probes-sshd", "forwarder-disabled", "tunnel-disabled"],
)
def test_render_dev_cvm_compose_config_healthchecks_success(service: str, expected_healthcheck: dict) -> None:
    """dev-cvm.md §3.3: the sshd probe applies to user-sandbox only, the sidecars reuse the
    same image artifact and MUST disable the inherited probe (otherwise they sit permanently
    unhealthy), and no service may gate startup on another's health.
    """
    rendered = yaml.safe_load(render_dev_cvm_compose_config({"image": DEV_CVM_PINNED_IMAGE}))

    assert rendered["services"][service].get("healthcheck", _ABSENT) == expected_healthcheck
    assert "depends_on" not in rendered["services"][service]


def test_resolve_security_cvm_provision_config_uses_defaults(monkeypatch) -> None:
    monkeypatch.delenv("PHALA_DEFAULT_INSTANCE_TYPE", raising=False)
    monkeypatch.setenv("SECURITY_CVM_DEFAULT_REGION", "FR-PARIS-1")
    monkeypatch.setenv("PHALA_REGION", "US-ASHBURN-1")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_REF", "registry.invalid/umbra/security-cvm@sha256:abc")
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
    monkeypatch.setenv("SECURITY_CVM_IMAGE_REF", "registry.invalid/umbra/security-cvm@sha256:abc")
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
    monkeypatch.setenv("SECURITY_CVM_IMAGE_REF", "registry.invalid/umbra/security-cvm@sha256:abc")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_MEASUREMENT", "b" * 96)
    monkeypatch.delenv("SECURITY_CVM_BASE_DOMAIN", raising=False)

    with pytest.raises(HTTPException) as exc:
        resolve_security_cvm_provision_config(security_cvm_create())

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "security_cvm_base_domain"


def test_resolve_security_cvm_provision_config_rejects_cert_cn_too_long_base_domain(monkeypatch) -> None:
    monkeypatch.setenv("PHALA_REGION", "FR-PARIS-1")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_REF", "registry.invalid/umbra/security-cvm@sha256:abc")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_MEASUREMENT", "b" * 96)
    monkeypatch.setenv("SECURITY_CVM_BASE_DOMAIN", f"{'a' * 24}.example.com")

    with pytest.raises(HTTPException) as exc:
        resolve_security_cvm_provision_config(security_cvm_create())

    assert exc.value.status_code == 503
    assert exc.value.detail["error"]["details"]["component"] == "security_cvm_base_domain"


def test_render_security_cvm_compose_config_keeps_runtime_values_as_placeholders() -> None:
    compose = render_security_cvm_compose_config(
        {
            "image_ref": "registry.invalid/umbra/security-cvm@sha256:abc",
            "instance_type": "tdx.small",
            "region": "FR-PARIS-1",
            "expected_image_measurement": "b" * 96,
            "base_domain": "sc.example.com",
        }
    )

    assert "registry.invalid/umbra/security-cvm@sha256:abc" in compose
    assert "  mitmproxy:" in compose
    assert "command: [\"umbra-security-mitmproxy\"]" in compose
    assert "  proxy-tunnel:" in compose
    assert "command: [\"umbra-security-proxy-tunnel\"]" in compose
    assert "SC_PROXY_TUNNEL_PATH: /umbra/proxy" in compose
    assert "SC_PROXY_TUNNEL_UPGRADE: umbra-proxy" in compose
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
    assert "connect_host" not in result
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
        "metadata": {"provider": "phala"},
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

    async def fake_materialize(_snapshot):
        return {
            "app_compose": {"runner": "docker-compose", "docker_compose_file": "services: {}\n"},
            "expected_bootchain": {"mrtd": "e" * 96},
            "os_image_hash": "f" * 64,
        }

    monkeypatch.setenv("CONSOLE_URL", "https://console.example.com")
    monkeypatch.setattr(attestation.AtlasVerifierClient, "from_settings", classmethod(lambda cls: FakeVerifier()))
    monkeypatch.setattr(routes_module, "insert_audit_event", fake_insert_audit_event)
    monkeypatch.setattr(
        "umbra_console.scheduler.materialize_security_cvm_shade_policy_for_attestation",
        fake_materialize,
    )

    result = asyncio.run(
        routes_module.run_security_cvm_attestation_probe(
            conn,
            security_cvm_attestation_row(),
            current_user=current_user(),
        )
    )

    assert captured_request["kind"] == "security_cvm"
    assert "connect_host" not in captured_request
    assert captured_request["policy"]["rtmr3_binding"]["ingest_token_sha256"] == "b" * 64
    # Full runtime verification (never dev()): shade-derived fields present in the probe policy.
    assert captured_request["policy"]["expected_bootchain"] == {"mrtd": "e" * 96}
    assert captured_request["policy"]["os_image_hash"] == "f" * 64
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

    async def fake_materialize(_snapshot):
        return {
            "app_compose": {"runner": "docker-compose", "docker_compose_file": "services: {}\n"},
            "expected_bootchain": {"mrtd": "e" * 96},
            "os_image_hash": "f" * 64,
        }

    monkeypatch.setattr(attestation.AtlasVerifierClient, "from_settings", classmethod(lambda cls: FakeVerifier()))
    monkeypatch.setattr(routes_module, "insert_audit_event", fake_insert_audit_event)
    monkeypatch.setattr(
        "umbra_console.scheduler.materialize_security_cvm_shade_policy_for_attestation",
        fake_materialize,
    )

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


def test_dev_cvm_quota_usage_counts_live_rows_excluding_terminated_and_failed() -> None:
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
    # FAILED launches must not count (self-inflicted quota denial otherwise).
    assert "state NOT IN ('TERMINATED', 'FAILED')" in entity_conn.queries[0]
    assert "state NOT IN ('TERMINATED', 'FAILED')" in user_conn.queries[0]


def test_disk_quota_usage_sums_total_and_maxes_per_cvm() -> None:
    total_conn = FakeFetchValConn(120)
    per_cvm_conn = FakeFetchValConn(80)

    total_usage = asyncio.run(
        entity_quota_usage(total_conn, UUID("00000000-0000-4000-8000-000000000001"), "disk_gb_total")
    )
    per_cvm_usage = asyncio.run(
        user_quota_usage(per_cvm_conn, UUID("00000000-0000-4000-8000-000000000002"), "disk_gb_per_cvm")
    )

    assert total_usage == 120
    assert per_cvm_usage == 80
    assert "SUM(disk_size_gb)" in total_conn.queries[0]
    assert "MAX(disk_size_gb)" in per_cvm_conn.queries[0]
    assert "state NOT IN ('TERMINATED', 'FAILED')" in total_conn.queries[0]
    assert "state NOT IN ('TERMINATED', 'FAILED')" in per_cvm_conn.queries[0]


class FakeQuotaConn:
    """Serves quota-limit lookups (``fetchrow``) and usage sums (``fetchval``).

    A ``fetchrow`` returning a row models a stored override for that resource; a
    ``None`` lets the code fall back to the resolved default — the per-user
    default for a user-scope read, the per-entity default for an entity-scope
    read (``user_quota_limit`` / ``entity_quota_limit``).
    """

    def __init__(self, *, per_cvm_override=None, total_override=None, total_usage=0):
        self.per_cvm_override = per_cvm_override
        self.total_override = total_override
        self.total_usage = total_usage

    async def fetchrow(self, query, *args):
        resource = args[-1]
        if resource == "disk_gb_per_cvm" and self.per_cvm_override is not None:
            return {"limit_value": self.per_cvm_override, "set_by": None, "set_at": None}
        if resource == "disk_gb_total" and self.total_override is not None:
            return {"limit_value": self.total_override, "set_by": None, "set_at": None}
        return None

    async def fetchval(self, query, *args):
        if "FROM users" in query:
            return UUID("00000000-0000-4000-8000-0000000000ee")
        if "SUM(disk_size_gb)" in query:
            return self.total_usage
        return 0


_DISK_USER = UUID("00000000-0000-4000-8000-000000000002")
_DISK_ENTITY = UUID("00000000-0000-4000-8000-0000000000ee")


def test_enforce_disk_quotas_rejects_over_per_cvm_cap() -> None:
    conn = FakeQuotaConn(per_cvm_override=100)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(enforce_disk_quotas(conn, _DISK_USER, _DISK_ENTITY, 200))

    assert exc.value.status_code == 403
    details = exc.value.detail["error"]["details"]
    assert details["resource"] == "disk_gb_per_cvm"
    assert details["scope"] == "user"
    assert details["limit"] == 100
    assert details["current_usage"] == 200


def test_enforce_disk_quotas_rejects_over_total_budget() -> None:
    # Existing summed disk (450) + requested (100) exceeds the 500 total budget.
    conn = FakeQuotaConn(total_override=500, total_usage=450)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(enforce_disk_quotas(conn, _DISK_USER, _DISK_ENTITY, 100))

    assert exc.value.status_code == 403
    assert exc.value.detail["error"]["details"]["resource"] == "disk_gb_total"


def test_enforce_disk_quotas_allows_within_budget(monkeypatch) -> None:
    for name in (
        "DEFAULT_QUOTA_DISK_GB_PER_CVM_PER_ENTITY",
        "DEFAULT_QUOTA_DISK_GB_TOTAL_PER_ENTITY",
    ):
        monkeypatch.delenv(name, raising=False)
    conn = FakeQuotaConn(total_usage=100)

    # No overrides: the per-user caps (disk_gb_per_cvm 200, disk_gb_total 1000)
    # and the per-entity caps both comfortably admit a 100 GB launch on top of
    # 100 GB already provisioned.
    asyncio.run(enforce_disk_quotas(conn, _DISK_USER, _DISK_ENTITY, 100))


class FakeQuotaResolutionConn:
    """Serves the three reads in ``user_quota_limit``: the ``user_quotas`` lookup,
    the ``SELECT entity_id FROM users`` hop, and the ``entity_quotas`` lookup. A
    ``None`` row models "no override at that scope"."""

    def __init__(self, *, user_row=None, entity_row=None):
        self.user_row = user_row
        self.entity_row = entity_row

    async def fetchrow(self, query, *args):
        if "FROM user_quotas" in query:
            return self.user_row
        if "FROM entity_quotas" in query:
            return self.entity_row
        return None

    async def fetchval(self, query, *args):
        # SELECT entity_id FROM users WHERE id = $1
        return _DISK_ENTITY


def test_user_quota_limit_uses_per_user_default_not_entity(monkeypatch) -> None:
    # Deterministic fallbacks: with no env overrides the per-user and per-entity
    # defaults differ, so we can prove the resolver picked the per-user one.
    for name in (
        "DEFAULT_QUOTA_DEV_CVMS_PER_USER",
        "DEFAULT_QUOTA_DEV_CVMS_PER_ENTITY",
        "DEFAULT_QUOTA_SSH_KEYS_PER_USER",
        "DEFAULT_QUOTA_SSH_KEYS_PER_ENTITY",
        "DEFAULT_QUOTA_DISK_GB_PER_CVM_PER_USER",
        "DEFAULT_QUOTA_DISK_GB_PER_CVM_PER_ENTITY",
        "DEFAULT_QUOTA_DISK_GB_TOTAL_PER_USER",
        "DEFAULT_QUOTA_DISK_GB_TOTAL_PER_ENTITY",
    ):
        monkeypatch.delenv(name, raising=False)
    conn = FakeQuotaResolutionConn()  # no user override, no entity override
    for resource in ("dev_cvms", "ssh_keys", "disk_gb_per_cvm", "disk_gb_total"):
        limit, source, set_by, set_at = asyncio.run(user_quota_limit(conn, _DISK_USER, resource))
        assert source == "default"
        assert (set_by, set_at) == (None, None)
        # The per-user default applies — NOT the (larger) per-entity default.
        assert limit == default_quota_limit(resource, scope="user")
        assert limit != default_quota_limit(resource, scope="entity")


def test_user_quota_limit_entity_override_supersedes_user_default() -> None:
    conn = FakeQuotaResolutionConn(entity_row={"limit_value": 42, "set_by": None, "set_at": None})
    limit, source, _, _ = asyncio.run(user_quota_limit(conn, _DISK_USER, "dev_cvms"))
    assert (limit, source) == (42, "entity_override")


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


def test_validate_profile_policy_rejects_author_supplied_unfulfilled_field() -> None:
    # `unfulfilled_secret_injections` is Console-generated wire-only material
    # (added at SC-control materialization when an owner grant is unusable). It
    # is not part of the authoring surface, so a profile author cannot inject
    # one to fail-close destinations for other members.
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy({"unfulfilled_secret_injections": []})

    assert exc.value.status_code == 422
    errors = exc.value.detail["error"]["details"]["errors"]
    assert errors == [{"field": "policy.unfulfilled_secret_injections", "type": "unknown_field"}]


def test_validate_profile_policy_rejects_bad_sandbox_env() -> None:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(
            {
                "sandbox_env": {
                    "1BAD": "value",
                    "PATH": "/tmp/bin",
                    "UMBRA_RUNTIME": "reserved",
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


def _secret_injection_policy(**overrides):
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
        "value_template": "Bearer ${secret}",
    }
    injection.update(overrides)
    return {"secret_injections": [injection]}


def _profile_policy_errors(policy) -> list[dict]:
    with pytest.raises(HTTPException) as exc:
        validate_profile_policy(policy)
    return exc.value.detail["error"]["details"]["errors"]


def test_validate_profile_policy_accepts_value_from_injection() -> None:
    validate_profile_policy(_secret_injection_policy(value_from={"user_secret": "slack-user-token"}))


def test_validate_profile_policy_rejects_value_and_value_from_together() -> None:
    errors = _profile_policy_errors(
        _secret_injection_policy(value="xoxb-real", value_from={"user_secret": "slack-user-token"})
    )
    assert any(
        error["field"] == "policy.secret_injections.0.value" and error["type"] == "value_xor_value_from"
        for error in errors
    )


def test_validate_profile_policy_rejects_injection_without_value_source() -> None:
    errors = _profile_policy_errors(_secret_injection_policy())
    assert any(
        error["field"] == "policy.secret_injections.0.value" and error["type"] == "value_xor_value_from"
        for error in errors
    )


@pytest.mark.parametrize(
    "value_from",
    [
        "slack-user-token",
        {},
        {"user_secret": "slack-user-token", "extra": True},
        {"user_secret": 7},
        {"user_secret": "bad name!"},
        {"user_secret": "x" * 101},
    ],
)
def test_validate_profile_policy_rejects_malformed_value_from(value_from) -> None:
    errors = _profile_policy_errors(_secret_injection_policy(value_from=value_from))
    assert any(
        error["field"] == "policy.secret_injections.0.value_from" and error["type"] == "invalid_value_from"
        for error in errors
    )


def test_validate_profile_policy_bounds_value_from_template_residual() -> None:
    from umbra_console.routes import POLICY_MAX_RENDERED_SECRET_LEN, USER_SECRET_VALUE_MAX_LEN

    # Residual = the template with "${secret}" removed. For value_from entries the
    # value is unknown at authoring time, so the residual is capped so that even a
    # maximal user-secret value renders within the SC's cap. Derive the boundary
    # from the constants so a value-cap change fails loudly here instead of
    # silently letting a too-long render through.
    residual_cap = POLICY_MAX_RENDERED_SECRET_LEN - USER_SECRET_VALUE_MAX_LEN
    validate_profile_policy(
        _secret_injection_policy(
            value_from={"user_secret": "slack-user-token"},
            value_template="${secret}" + "x" * residual_cap,
        )
    )
    errors = _profile_policy_errors(
        _secret_injection_policy(
            value_from={"user_secret": "slack-user-token"},
            value_template="${secret}" + "x" * (residual_cap + 1),
        )
    )
    assert any(
        error["field"] == "policy.secret_injections.0.value_template"
        and error["type"] == "rendered_value_too_long"
        for error in errors
    )


def test_value_from_render_caps_line_up_with_sc_rendered_cap(monkeypatch) -> None:
    """The three-constant coupling flagged in review: the user-secret value cap
    plus the value_from template-residual cap must equal the SC's rendered-header
    cap (a literal 8192 in cvms/security/.../policy.py `_parse_secret_injections`).
    If they drift, a secret that passed `secret set` and a profile that passed
    validation could be silently omitted at materialization after a green launch,
    or a policy could reach the SC that deny_alls the CVM. Pins the boundary as
    *inclusive*: a maximal value + maximal residual renders to exactly the cap and
    is NOT omitted."""
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    from umbra_console.profile_secrets import (
        SECRET_INJECTION_RENDERED_MAX_LEN,
        expand_policy_secret_values_for_owner,
    )
    from umbra_console.routes import POLICY_MAX_RENDERED_SECRET_LEN, USER_SECRET_VALUE_MAX_LEN

    # The console validator cap and the materializer cap are the same number, and
    # it is the SC's literal 8192. (The SC value is not importable here; if it ever
    # changes, this literal must change with it.)
    assert POLICY_MAX_RENDERED_SECRET_LEN == SECRET_INJECTION_RENDERED_MAX_LEN == 8192

    residual_cap = POLICY_MAX_RENDERED_SECRET_LEN - USER_SECRET_VALUE_MAX_LEN
    value = "z" * USER_SECRET_VALUE_MAX_LEN
    template = "t" * residual_cap + "${secret}"
    owner_secrets = {
        "big": {
            "ciphertext": encrypt_user_secret_value(user_id="user-a", name="big", value=value),
            "allowed_hosts": ["api.example.com"],
        }
    }
    omitted: list = []

    expanded = expand_policy_secret_values_for_owner(
        profile_id="p",
        policy={
            "secret_injections": [
                {
                    "id": "big",
                    "match": {"scheme": "https", "host": "api.example.com"},
                    "type": "request_header",
                    "header": "authorization",
                    "value_from": {"user_secret": "big"},
                    "value_template": template,
                }
            ]
        },
        secret_material={},
        owner_id="user-a",
        owner_secrets=owner_secrets,
        on_unresolved=lambda *args: omitted.append(args),
    )

    assert omitted == []
    injections = expanded["secret_injections"]
    assert len(injections) == 1
    rendered = template.replace("${secret}", injections[0]["value"])
    assert len(rendered) == POLICY_MAX_RENDERED_SECRET_LEN  # exactly at the cap, inclusive


def test_validate_profile_policy_still_bounds_inline_rendered_value() -> None:
    errors = _profile_policy_errors(
        _secret_injection_policy(value="v" * 5000, value_template="${secret}" + "x" * 5000)
    )
    assert any(
        error["field"] == "policy.secret_injections.0.value_template"
        and error["type"] == "rendered_value_too_long"
        for error in errors
    )


def test_replace_profile_secret_material_encrypts_values_success(monkeypatch) -> None:
    """Profile replacement persists only a fresh encrypted v2 envelope."""
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
    assert ciphertext.startswith("v2:")
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


def test_traffic_log_in_accepts_decision_and_ignores_unknown_fields() -> None:
    assert traffic_log().decision is None
    assert traffic_log(decision="secret_injection_unfulfilled").decision == "secret_injection_unfulfilled"
    # extra="ignore": a newer SC image may ship traffic fields this Console does
    # not model yet; ingest tolerates (drops) them instead of 422-rejecting the
    # whole batch during an SC-before-Console rollout.
    tolerated = traffic_log(some_future_field="whatever")
    assert not hasattr(tolerated, "some_future_field")


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
                    "sandbox_env": {"ANTHROPIC_API_KEY": "umbra-proxy-injected"},
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
                    "sandbox_env": {"OPENAI_API_KEY": "umbra-proxy-injected"},
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
            {"name": "ANTHROPIC_API_KEY", "value": "umbra-proxy-injected"},
            {"name": "OPENAI_API_KEY", "value": "umbra-proxy-injected"},
        ],
    }


_SLACK_MATCH = {
    "scheme": "https",
    "host": "api.slack.com",
    "ports": [443],
    "methods": ["POST"],
    "path_prefixes": ["/"],
}


def _slack_unfulfilled_marker():
    return {"id": "slack-token", "match": _SLACK_MATCH, "header": "authorization"}


def _value_from_profile_rows():
    return [
        {
            "profile_id": "profile-slack",
            "policy": {
                "secret_injections": [
                    {
                        "id": "slack-token",
                        "match": dict(_SLACK_MATCH),
                        "type": "request_header",
                        "header": "authorization",
                        "value_from": {"user_secret": "slack-user-token"},
                        "value_template": "Bearer ${secret}",
                    }
                ]
            },
        }
    ]


def _owner_secret_material(owner_id: str, value: str):
    return {
        "slack-user-token": {
            "ciphertext": encrypt_user_secret_value(
                user_id=owner_id, name="slack-user-token", value=value
            ),
            "allowed_hosts": ["api.slack.com"],
        }
    }


def test_merge_profile_policies_resolves_value_from_per_owner(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

    merged_alice = merge_profile_policies(
        _value_from_profile_rows(),
        owner_id="alice",
        owner_secrets=_owner_secret_material("alice", "xoxp-alice"),
        cvm_id="cvm-a",
    )
    merged_bob = merge_profile_policies(
        _value_from_profile_rows(),
        owner_id="bob",
        owner_secrets=_owner_secret_material("bob", "xoxp-bob"),
        cvm_id="cvm-b",
    )

    assert merged_alice["secret_injections"][0]["value"] == "xoxp-alice"
    assert merged_bob["secret_injections"][0]["value"] == "xoxp-bob"
    assert "value_from" not in merged_alice["secret_injections"][0]
    assert "value_from" not in merged_bob["secret_injections"][0]
    # Same profile rows, different owners: the SC control payload diverges, so
    # the content ETag rotates per owner and secret updates propagate on poll.
    assert sc_control_etag({"entries": [{"merged_policy": merged_alice}]}) != sc_control_etag(
        {"entries": [{"merged_policy": merged_bob}]}
    )


def test_merge_profile_policies_marks_unfulfilled_without_owner_context(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

    merged = merge_profile_policies(_value_from_profile_rows())

    # No owner context → the grant can't resolve → the SC gets a fail-closed
    # marker for that destination, not a silent uncredentialed passthrough.
    assert merged["secret_injections"] == []
    assert merged["unfulfilled_secret_injections"] == [_slack_unfulfilled_marker()]


def test_merge_profile_policies_marks_unfulfilled_when_owner_missing_secret(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

    merged = merge_profile_policies(
        _value_from_profile_rows(),
        owner_id="alice",
        owner_secrets={},
        cvm_id="cvm-a",
    )

    assert merged["secret_injections"] == []
    assert merged["unfulfilled_secret_injections"] == [_slack_unfulfilled_marker()]


def test_merge_profile_policies_omits_unfulfilled_key_when_all_resolve(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

    merged = merge_profile_policies(
        _value_from_profile_rows(),
        owner_id="alice",
        owner_secrets=_owner_secret_material("alice", "xoxp-alice"),
        cvm_id="cvm-a",
    )

    # Fulfilled → the credential is injected and the wire policy carries no
    # unfulfilled key at all (keeps merged_policy/ETag unchanged for the common
    # case and bounds old-SC exposure during an SC-before-Console rollout).
    assert merged["secret_injections"][0]["value"] == "xoxp-alice"
    assert "unfulfilled_secret_injections" not in merged


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


def test_operation_result_for_read_discloses_once_then_scrubs_db(monkeypatch) -> None:
    """The CA-export token is handed to the initiating actor on the single first read,
    and the plaintext is scrubbed from the stored operations.result at that moment so it
    does not linger at rest (security hardening — operation_resource_for_read)."""
    import json

    from umbra_console.auth import CurrentUser

    actor_id = UUID("00000000-0000-4000-8000-000000000051")
    entity_id = UUID("00000000-0000-4000-8000-000000000001")
    op_id = UUID("00000000-0000-4000-8000-000000000052")
    now = datetime(2026, 6, 29, tzinfo=timezone.utc)
    locked_row = {
        "id": op_id,
        "kind": "security_cvm.provision",
        "status": "succeeded",
        "actor_id": actor_id,
        "actor_entity_id": entity_id,
        "target_type": "security_cvm",
        "target_id": UUID("00000000-0000-4000-8000-000000000041"),
        "result": {"security_cvm": {"id": "sc"}, "ca_export_token": "super-secret-plaintext"},
        "error": None,
        "progress_step": None,
        "progress_percent": None,
        "created_at": now,
        "updated_at": now,
        "expires_at": None,
        "result_disclosed_at": None,
    }

    class DiscloseConn:
        def __init__(self) -> None:
            self.execute_calls: list[tuple[str, tuple]] = []

        def transaction(self):
            return AsyncContext()

        async def fetchrow(self, query, *args):
            return dict(locked_row)

        async def execute(self, query, *args):
            self.execute_calls.append((query, args))
            return "UPDATE 1"

    conn = DiscloseConn()

    async def fake_insert_audit_event(_conn, **kwargs):
        return None

    monkeypatch.setattr(routes_module, "insert_audit_event", fake_insert_audit_event)

    current_user = CurrentUser(
        id=actor_id,
        email="op@example.com",
        name="Op",
        entity_id=entity_id,
        entity_name="Entity",
        permissions=frozenset(),
    )

    resource = asyncio.run(
        routes_module.operation_resource_for_read(FakePool(conn), dict(locked_row), current_user)
    )

    # 1) The initiator receives the full plaintext token on the one-time first read.
    assert resource["result"]["ca_export_token"] == "super-secret-plaintext"

    # 2) The stored result is scrubbed in the same transaction (not just the response).
    scrub_updates = [
        args for query, args in conn.execute_calls
        if "UPDATE operations" in query and "result = $2" in query
    ]
    assert scrub_updates, "disclosure must rewrite operations.result with the redacted payload"
    written = json.loads(scrub_updates[0][1])
    assert written["ca_export_token"] == SECURITY_CVM_PROVISION_REDACTION


# -- instance-type catalog: launch allowlist + endpoint --------------------------


def dev_launch_env(monkeypatch) -> None:
    monkeypatch.setenv("DEV_CVM_IMAGE", "registry.invalid/umbra/dev-cvm@sha256:abc")
    monkeypatch.setenv("DEV_CVM_IMAGE_MEASUREMENT", "A" * 96)
    monkeypatch.setenv("CLOUDFLARE_BASE_DOMAIN", "dev.example.com")
    monkeypatch.setenv("PHALA_REGION", "FR-PARIS-1")


def test_launch_rejects_unknown_instance_type_with_valid_set_and_catalog(monkeypatch) -> None:
    dev_launch_env(monkeypatch)

    with pytest.raises(HTTPException) as exc:
        resolve_cvm_launch_config(cvm_create(instance_type="tdx.big"))

    assert exc.value.status_code == 422
    error = exc.value.detail["error"]
    assert error["code"] == "VALIDATION_ERROR"
    # The message itself enumerates the valid set (readable before any CLI parsing).
    assert "tdx.big" in error["message"] and "tdx.small" in error["message"]
    details = error["details"]
    error_item = details["errors"][0]
    assert error_item["type"] == "unknown_instance_type"
    assert error_item["requested"] == "tdx.big"
    assert "tdx.small" in error_item["valid_instance_types"]
    # GPU types are catalogued but NOT launchable, so they are absent from the valid set.
    assert "h200.small" not in error_item["valid_instance_types"]
    assert error_item["valid_instance_types"] == sorted(error_item["valid_instance_types"])
    catalog = details["catalog"]
    assert catalog["source"] == "bootstrap_fallback"
    assert "stale" in catalog and "fetched_at" in catalog
    assert "refresh_in_progress" in catalog and "last_refresh_error" in catalog
    assert "umbra cvm instance-types" in details["hint"]


def test_launch_accepts_a_cataloged_cpu_instance_type(monkeypatch) -> None:
    dev_launch_env(monkeypatch)

    resolved = resolve_cvm_launch_config(cvm_create(instance_type="tdx.xlarge"))

    assert resolved["instance_type"] == "tdx.xlarge"


def sc_launch_env(monkeypatch) -> None:
    monkeypatch.setenv("SECURITY_CVM_IMAGE_REF", "registry.invalid/umbra/security-cvm@sha256:abc")
    monkeypatch.setenv("SECURITY_CVM_IMAGE_MEASUREMENT", "B" * 96)
    monkeypatch.setenv("SECURITY_CVM_BASE_DOMAIN", "sc.example.com")
    monkeypatch.setenv("PHALA_REGION", "FR-PARIS-1")


# The 2x2 launch allowlist matrix: Dev CVM and Security CVM launches both reject an
# unknown type (`unknown_instance_type`) and a catalogued GPU type
# (`instance_type_not_launchable`). The full 422 envelope shape (catalog block,
# hint, valid set) is asserted once in
# test_launch_rejects_unknown_instance_type_with_valid_set_and_catalog.
@pytest.mark.parametrize("path", ["dev", "sc"])
@pytest.mark.parametrize(
    ("requested", "expected_type"),
    [
        ("tdx.big", "unknown_instance_type"),
        ("h200.small", "instance_type_not_launchable"),
    ],
)
def test_launch_rejects_bad_instance_type(monkeypatch, path, requested, expected_type) -> None:
    if path == "dev":
        dev_launch_env(monkeypatch)
    else:
        sc_launch_env(monkeypatch)

    with pytest.raises(HTTPException) as exc:
        if path == "dev":
            resolve_cvm_launch_config(cvm_create(instance_type=requested))
        else:
            resolve_security_cvm_provision_config(security_cvm_create(instance_type=requested))

    assert exc.value.status_code == 422
    error_item = exc.value.detail["error"]["details"]["errors"][0]
    assert error_item["type"] == expected_type
    assert error_item["requested"] == requested
    assert requested not in error_item["valid_instance_types"]


def test_launch_validation_never_calls_the_provider(monkeypatch) -> None:
    dev_launch_env(monkeypatch)

    def forbidden(*args, **kwargs):
        raise AssertionError("launch validation must not construct a provider client")

    import umbra_console.instance_types as instance_types_module

    monkeypatch.setattr(instance_types_module.CvmProvider, "from_settings", forbidden)

    resolved = resolve_cvm_launch_config(cvm_create(instance_type="tdx.small"))

    assert resolved["instance_type"] == "tdx.small"


def test_get_instance_types_serves_cache_and_flags_default(monkeypatch) -> None:
    import umbra_console.instance_types as instance_types_module

    service = instance_types_module.InstanceTypeCatalogService()
    monkeypatch.setattr(instance_types_module, "_service", service)
    monkeypatch.setattr(service, "spawn_refresh_if_due", lambda *, reason: True)
    monkeypatch.setenv("DEV_CVM_DEFAULT_INSTANCE_TYPE", "tdx.large")

    payload = asyncio.run(routes_module.get_instance_types(refresh=False, current_user=None))

    names = [entry["name"] for entry in payload["instance_types"]]
    assert "tdx.small" in names and "h200.small" in names
    defaults = [entry["name"] for entry in payload["instance_types"] if entry["default"]]
    assert defaults == ["tdx.large"]
    assert payload["catalog"]["source"] == "bootstrap_fallback"


def test_get_instance_types_stale_read_spawns_a_single_background_refresh(monkeypatch) -> None:
    import umbra_console.instance_types as instance_types_module

    service = instance_types_module.InstanceTypeCatalogService()
    monkeypatch.setattr(instance_types_module, "_service", service)

    async def scenario():
        await routes_module.get_instance_types(refresh=False, current_user=None)
        assert len(service._background_tasks) == 1
        # A refresh already pending counts as in-progress: no second spawn.
        payload = await routes_module.get_instance_types(refresh=False, current_user=None)
        assert len(service._background_tasks) == 1
        assert payload["catalog"]["refresh_in_progress"] is True
        for task in service._background_tasks:
            task.cancel()

    asyncio.run(scenario())


def test_get_instance_types_refresh_true_fetches_inline_and_degrades(monkeypatch) -> None:
    import umbra_console.instance_types as instance_types_module

    service = instance_types_module.InstanceTypeCatalogService()
    monkeypatch.setattr(instance_types_module, "_service", service)
    calls = []

    async def failing_refresh(*, reason, timeout_seconds=None):
        calls.append((reason, timeout_seconds))
        return False

    monkeypatch.setattr(service, "refresh", failing_refresh)

    payload = asyncio.run(routes_module.get_instance_types(refresh=True, current_user=None))

    assert calls == [("manual", instance_types_module.INLINE_REFRESH_TIMEOUT_SECONDS)]
    # Inline refresh failed: the current cache is served, with its metadata.
    assert payload["catalog"]["source"] == "bootstrap_fallback"
    assert [entry["name"] for entry in payload["instance_types"]][0] == "tdx.small"


class UserSecretConn:
    def __init__(self, *, existing=None, count=0):
        self.existing = existing or {}
        self.count = count
        self.executed = []
        self.insert_args = None

    def transaction(self):
        return AsyncContext()

    async def execute(self, sql, *args):
        self.executed.append((sql, args))
        return "OK"

    async def fetchval(self, sql, *args):
        if "SELECT 1 FROM user_secret_material" in sql:
            return 1 if args[1] in self.existing else None
        if "count(*)" in sql:
            return self.count
        raise AssertionError(f"unexpected fetchval: {sql}")

    async def fetchrow(self, sql, *args):
        if "INSERT INTO user_secret_material" in sql:
            self.insert_args = args
            return {
                "name": args[1],
                "allowed_hosts": args[3],
                "created_at": datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc),
                "updated_at": datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc),
            }
        if "DELETE FROM user_secret_material" in sql:
            return self.existing.get(args[1])
        raise AssertionError(f"unexpected fetchrow: {sql}")

    async def fetch(self, sql, *args):
        return list(self.existing.values())


def _secret_user():
    from umbra_console.auth import CurrentUser

    return CurrentUser(
        id=UUID("00000000-0000-4000-8000-000000000077"),
        email="dev@example.com",
        name="Dev",
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
        entity_name="Entity",
        permissions=frozenset(),
    )


def _capture_audit(monkeypatch):
    events = []

    async def fake_insert_audit_event(_conn, **kwargs):
        events.append(kwargs)

    monkeypatch.setattr(routes_module, "insert_audit_event", fake_insert_audit_event)
    return events


def test_put_user_secret_rejects_invalid_name(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            put_user_secret(
                name="bad name!",
                body=UserSecretPut(value="xoxp-token", allowed_hosts=["api.slack.com"]),
                current_user=_secret_user(),
                pool=FakePool(UserSecretConn()),
            )
        )

    assert exc.value.status_code == 422
    errors = exc.value.detail["error"]["details"]["errors"]
    assert errors == [{"field": "name", "type": "invalid_name"}]


def test_put_user_secret_enforces_count_cap(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    _capture_audit(monkeypatch)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            put_user_secret(
                name="slack-user-token",
                body=UserSecretPut(value="xoxp-token", allowed_hosts=["api.slack.com"]),
                current_user=_secret_user(),
                pool=FakePool(UserSecretConn(count=64)),
            )
        )

    assert exc.value.status_code == 403
    details = exc.value.detail["error"]["details"]
    assert details == {"resource": "user_secrets", "scope": "user", "limit": 64, "current_usage": 64}


def test_put_user_secret_updates_existing_despite_cap(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    _capture_audit(monkeypatch)
    conn = UserSecretConn(existing={"slack-user-token": {}}, count=64)

    result = asyncio.run(
        put_user_secret(
            name="slack-user-token",
            body=UserSecretPut(value="xoxp-rotated", allowed_hosts=["api.slack.com"]),
            current_user=_secret_user(),
            pool=FakePool(conn),
        )
    )

    assert result["name"] == "slack-user-token"


def test_put_user_secret_encrypts_without_returning_value_success(monkeypatch) -> None:
    """A user-secret write persists v2 ciphertext and returns metadata only."""
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    events = _capture_audit(monkeypatch)
    conn = UserSecretConn()

    result = asyncio.run(
        put_user_secret(
            name="slack-user-token",
            body=UserSecretPut(value="xoxp-plaintext", allowed_hosts=["api.slack.com", "*.slack.com"]),
            current_user=_secret_user(),
            pool=FakePool(conn),
        )
    )

    ciphertext = conn.insert_args[2]
    assert ciphertext.startswith("v2:")
    assert "xoxp-plaintext" not in ciphertext
    assert set(result) == {"name", "allowed_hosts", "created_at", "updated_at"}
    assert result["allowed_hosts"] == ["api.slack.com", "*.slack.com"]
    assert "xoxp-plaintext" not in json.dumps(result)
    assert len(events) == 1
    assert events[0]["action"] == "USER_SECRET_SET"
    assert "xoxp-plaintext" not in json.dumps(events[0]["after"])


def test_list_user_secrets_returns_metadata_only(monkeypatch) -> None:
    row = {
        "name": "slack-user-token",
        "allowed_hosts": '["api.slack.com"]',
        "created_at": datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc),
        "updated_at": datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc),
    }
    conn = UserSecretConn(existing={"slack-user-token": row})

    result = asyncio.run(list_user_secrets(current_user=_secret_user(), pool=FakePool(conn)))

    assert result["items"] == [
        {
            "name": "slack-user-token",
            "allowed_hosts": ["api.slack.com"],
            "created_at": "2026-07-07T12:00:00Z",
            "updated_at": "2026-07-07T12:00:00Z",
        }
    ]


def test_delete_user_secret_404_when_absent(monkeypatch) -> None:
    _capture_audit(monkeypatch)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            delete_user_secret(
                name="absent",
                current_user=_secret_user(),
                pool=FakePool(UserSecretConn()),
            )
        )

    assert exc.value.status_code == 404


def test_delete_user_secret_deletes_and_audits(monkeypatch) -> None:
    events = _capture_audit(monkeypatch)
    conn = UserSecretConn(
        existing={"slack-user-token": {"name": "slack-user-token", "allowed_hosts": '["api.slack.com"]'}}
    )

    response = asyncio.run(
        delete_user_secret(name="slack-user-token", current_user=_secret_user(), pool=FakePool(conn))
    )

    assert response.status_code == 204
    assert len(events) == 1
    assert events[0]["action"] == "USER_SECRET_DELETED"
    assert events[0]["before"] == {"name": "slack-user-token", "allowed_hosts": ["api.slack.com"]}


def test_user_secret_put_model_rejects_bad_values() -> None:
    with pytest.raises(ValidationError):
        UserSecretPut(value="line\nbreak", allowed_hosts=["api.slack.com"])
    with pytest.raises(ValidationError):
        UserSecretPut(value="nul\x00byte", allowed_hosts=["api.slack.com"])
    with pytest.raises(ValidationError):
        UserSecretPut(value="x" * 4097, allowed_hosts=["api.slack.com"])
    with pytest.raises(ValidationError):
        UserSecretPut(value="ok", allowed_hosts=[])
    with pytest.raises(ValidationError):
        UserSecretPut(value="ok", allowed_hosts=["host.example"] + [f"h{i}.example.com" for i in range(16)])
    with pytest.raises(ValidationError):
        UserSecretPut(value="ok", allowed_hosts=["Upper.Case.Com"])
    with pytest.raises(ValidationError):
        UserSecretPut(value="ok", allowed_hosts=["api.slack.com", "api.slack.com"])
    model = UserSecretPut(value="ok", allowed_hosts=["*", "*.slack.com", "api.slack.com"])
    assert model.allowed_hosts == ["*", "*.slack.com", "api.slack.com"]


class SecretReferenceConn:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.fetch_calls = 0

    async def fetch(self, sql, *args):
        self.fetch_calls += 1
        assert "FROM user_secret_material" in sql
        return self.rows


def _slack_value_from_profile(profile_id="00000000-0000-4000-8000-000000000050", **match_overrides):
    match = {"scheme": "https", "host": "api.slack.com"}
    match.update(match_overrides)
    return {
        "profile_id": UUID(profile_id),
        "policy": {
            "secret_injections": [
                {
                    "id": "slack-token",
                    "match": match,
                    "type": "request_header",
                    "header": "authorization",
                    "value_from": {"user_secret": "slack-user-token"},
                    "value_template": "Bearer ${secret}",
                }
            ]
        },
    }


def test_ensure_user_secret_references_skips_query_without_references() -> None:
    conn = SecretReferenceConn()
    profile = {"profile_id": UUID("00000000-0000-4000-8000-000000000050"), "policy": {"sandbox_env": {}}}

    asyncio.run(
        routes_module.ensure_user_secret_references(
            conn,
            profile_rows=[profile],
            user_id=UUID("00000000-0000-4000-8000-000000000077"),
            context="launcher",
        )
    )

    assert conn.fetch_calls == 0


def test_ensure_user_secret_references_passes_when_satisfied() -> None:
    conn = SecretReferenceConn(rows=[{"name": "slack-user-token", "allowed_hosts": '["api.slack.com"]'}])

    asyncio.run(
        routes_module.ensure_user_secret_references(
            conn,
            profile_rows=[_slack_value_from_profile()],
            user_id=UUID("00000000-0000-4000-8000-000000000077"),
            context="launcher",
        )
    )


def test_ensure_user_secret_references_rejects_missing_secret() -> None:
    conn = SecretReferenceConn(rows=[])

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            routes_module.ensure_user_secret_references(
                conn,
                profile_rows=[_slack_value_from_profile()],
                user_id=UUID("00000000-0000-4000-8000-000000000077"),
                context="launcher",
            )
        )

    assert exc.value.status_code == 422
    details = exc.value.detail["error"]["details"]
    assert details["member"] == "launcher"
    assert details["errors"] == [
        {
            "field": "policy.secret_injections",
            "profile_id": "00000000-0000-4000-8000-000000000050",
            "injection_id": "slack-token",
            "secret_name": "slack-user-token",
            "type": "user_secret_missing",
        }
    ]


def test_ensure_user_secret_references_rejects_scheme_and_host_violations() -> None:
    rows = [{"name": "slack-user-token", "allowed_hosts": '["api.slack.com"]'}]

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            routes_module.ensure_user_secret_references(
                SecretReferenceConn(rows=rows),
                profile_rows=[_slack_value_from_profile(scheme="http")],
                user_id=UUID("00000000-0000-4000-8000-000000000077"),
                context="launcher",
            )
        )
    assert exc.value.detail["error"]["details"]["errors"][0]["type"] == "user_secret_scheme_not_https"

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            routes_module.ensure_user_secret_references(
                SecretReferenceConn(rows=rows),
                profile_rows=[_slack_value_from_profile(host="files.slack.com")],
                user_id=UUID("00000000-0000-4000-8000-000000000077"),
                context="launcher",
            )
        )
    error = exc.value.detail["error"]["details"]["errors"][0]
    assert error["type"] == "user_secret_host_not_allowed"
    assert error["match_host"] == "files.slack.com"
    assert "allowed_hosts" not in error


ATTACH_OWNER_ID = UUID("00000000-0000-4000-8000-000000000088")
ATTACH_CVM_ID = UUID("00000000-0000-4000-8000-000000000031")
ATTACH_PROFILE_ID = UUID("00000000-0000-4000-8000-000000000050")


class AttachProfileConn:
    def __init__(self, *, owner_is_member: bool, owner_secret_rows=None):
        self.owner_is_member = owner_is_member
        self.owner_secret_rows = owner_secret_rows or []
        self.membership_args = None
        self.executed = []
        self.cvm_row = {
            "id": ATTACH_CVM_ID,
            "entity_id": UUID("00000000-0000-4000-8000-000000000001"),
            "owner_id": ATTACH_OWNER_ID,
            "state": "RUNNING",
            "policy_version": 3,
            "updated_at": datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc),
        }

    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, sql, *args):
        if "FROM cvms" in sql:
            return dict(self.cvm_row)
        if "FROM entity_profiles" in sql:
            return _slack_value_from_profile() | {"entity_id": args[1], "name": "slack"}
        raise AssertionError(f"unexpected fetchrow: {sql}")

    async def fetchval(self, sql, *args):
        assert "FROM profile_users" in sql
        self.membership_args = args
        return 1 if (self.owner_is_member and args[1] == ATTACH_OWNER_ID) else None

    async def fetch(self, sql, *args):
        if "FROM user_secret_material" in sql:
            return self.owner_secret_rows
        if "FROM cvm_profiles" in sql:
            return []
        raise AssertionError(f"unexpected fetch: {sql}")

    async def execute(self, sql, *args):
        self.executed.append((sql, args))
        return "INSERT 0 1" if "INSERT INTO cvm_profiles" in sql else "UPDATE 1"


def _run_attach(conn, monkeypatch):
    events = _capture_audit(monkeypatch)

    async def fake_fetch_visible_cvm_resource(pool, *, cvm_id, current_user, response):
        return {"id": str(cvm_id)}

    monkeypatch.setattr(routes_module, "fetch_visible_cvm_resource", fake_fetch_visible_cvm_resource)
    attacher = routes_module.CurrentUser(
        id=UUID("00000000-0000-4000-8000-000000000099"),
        email="admin@example.com",
        name="Admin",
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
        entity_name="Entity",
        permissions=frozenset({"CVM_MANAGE"}),
    )
    result = asyncio.run(
        routes_module.attach_cvm_profile(
            cvm_id=ATTACH_CVM_ID,
            body=routes_module.CVMProfileAttach(profile_id=ATTACH_PROFILE_ID),
            response=SimpleNamespace(headers={}),
            if_match=cvm_etag(conn.cvm_row),
            current_user=attacher,
            pool=FakePool(conn),
        )
    )
    return result, events


def test_attach_cvm_profile_requires_owner_membership(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    conn = AttachProfileConn(owner_is_member=False)

    with pytest.raises(HTTPException) as exc:
        _run_attach(conn, monkeypatch)

    assert exc.value.status_code == 403
    details = exc.value.detail["error"]["details"]
    assert details["member"] == "cvm_owner"
    assert details["owner_id"] == str(ATTACH_OWNER_ID)
    # The membership query must be bound to the CVM owner, not the attacher.
    assert conn.membership_args == (ATTACH_PROFILE_ID, ATTACH_OWNER_ID)


def test_attach_cvm_profile_checks_owner_user_secrets(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    conn = AttachProfileConn(owner_is_member=True, owner_secret_rows=[])

    with pytest.raises(HTTPException) as exc:
        _run_attach(conn, monkeypatch)

    assert exc.value.status_code == 422
    details = exc.value.detail["error"]["details"]
    assert details["member"] == "cvm_owner"
    assert details["user_id"] == str(ATTACH_OWNER_ID)
    assert details["errors"][0]["type"] == "user_secret_missing"


def test_attach_cvm_profile_attaches_for_entitled_owner(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    conn = AttachProfileConn(
        owner_is_member=True,
        owner_secret_rows=[{"name": "slack-user-token", "allowed_hosts": '["api.slack.com"]'}],
    )

    result, events = _run_attach(conn, monkeypatch)

    assert result == {"id": str(ATTACH_CVM_ID)}
    assert any("INSERT INTO cvm_profiles" in sql for sql, _ in conn.executed)
    assert len(events) == 1
    assert events[0]["action"] == "CVM_PROFILE_ATTACHED"
    assert events[0]["after"]["owner_id"] == str(ATTACH_OWNER_ID)


class SCControlConn:
    def __init__(self, rows):
        self.rows = rows

    async def fetch(self, sql, *args):
        assert "FROM cvms c" in sql and "owner_secret_material" in sql
        return self.rows

    async def execute(self, sql, *args):
        return "UPDATE 1"


def _sc_control_row(cvm_id, owner_id, token_hash):
    return {
        "id": UUID(cvm_id),
        "fqdn": f"cvm-{cvm_id[-4:]}.example.com",
        "policy_version": 1,
        "updated_at": datetime(2026, 7, 7, 12, 0, tzinfo=timezone.utc),
        "owner_id": owner_id,
        "proxy_token_hash": token_hash,
        "owner_secret_material": json.dumps(_owner_secret_material(owner_id, f"xoxp-{owner_id}")),
        "profile_policies": json.dumps(_value_from_profile_rows()),
    }


def _scan_payload_for_key(value, key):
    if isinstance(value, dict):
        return key in value or any(_scan_payload_for_key(item, key) for item in value.values())
    if isinstance(value, list):
        return any(_scan_payload_for_key(item, key) for item in value)
    return False


def test_list_sc_control_cvms_emits_per_owner_hydrated_wire_shape(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    from umbra_console.routes_internal import list_sc_control_cvms

    rows = [
        _sc_control_row("00000000-0000-4000-8000-0000000000a1", "alice", "a" * 64),
        _sc_control_row("00000000-0000-4000-8000-0000000000b2", "bob", "b" * 64),
    ]
    response = SimpleNamespace(headers={})
    principal = SimpleNamespace(
        principal_id=UUID("00000000-0000-4000-8000-000000000041"),
        entity_id=UUID("00000000-0000-4000-8000-000000000001"),
    )

    body = asyncio.run(
        list_sc_control_cvms(
            response=response,
            if_none_match=None,
            current_principal=principal,
            pool=FakePool(SCControlConn(rows)),
        )
    )

    entries = body["entries"]
    assert len(entries) == 2
    # The wire shape is pinned: the SC's policy parser rejects unknown injection
    # fields (deny_all), so no new keys may appear at either level.
    assert set(entries[0]) == {"cvm_id", "fqdn", "proxy_token_hash", "merged_policy", "policy_version", "updated_at"}
    injections = {entry["cvm_id"]: entry["merged_policy"]["secret_injections"] for entry in entries}
    values = {cvm: [injection["value"] for injection in items] for cvm, items in injections.items()}
    assert values["00000000-0000-4000-8000-0000000000a1"] == ["xoxp-alice"]
    assert values["00000000-0000-4000-8000-0000000000b2"] == ["xoxp-bob"]
    assert not _scan_payload_for_key(body, "value_from")
    assert response.headers["ETag"].startswith('"')

MINT_PROFILE_ID = UUID("00000000-0000-4000-8000-000000000060")
MINT_ENTITY_ID = UUID("00000000-0000-4000-8000-000000000001")
MINT_TEST_KEK = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


class MintProfileConn:
    def __init__(self, row):
        self.row = row
        self.execute_calls = []

    def transaction(self):
        return AsyncContext()

    async def fetchrow(self, sql, *args):
        self.fetchrow_args = args
        return self.row

    async def execute(self, sql, *args):
        self.execute_calls.append((sql, args))
        return "OK"


def mint_profile_row(**overrides):
    row = {
        "id": MINT_PROFILE_ID,
        "entity_id": MINT_ENTITY_ID,
        "policy": {
            "secret_injections": [
                {
                    "id": "claude-code-oauth",
                    "match": {"scheme": "https", "host": "api.anthropic.com", "ports": [443]},
                    "type": "request_header",
                    "header": "authorization",
                    "value_template": "Bearer ${secret}",
                }
            ]
        },
        "assigned": True,
        "member_count": 1,
    }
    row.update(overrides)
    return row


def mint_current_user(*, permissions=(), entity_id=MINT_ENTITY_ID):
    from umbra_console.auth import CurrentUser

    return CurrentUser(
        id=UUID("00000000-0000-4000-8000-000000000061"),
        email="dev@acme.test",
        name="Dev",
        entity_id=entity_id,
        entity_name="acme",
        permissions=frozenset(permissions),
    )


def run_mint(conn, user, *, injection_id="claude-code-oauth", value="sk-ant-oat01-real-token"):
    return asyncio.run(
        routes_module.mint_profile_secret(
            profile_id=MINT_PROFILE_ID,
            injection_id=injection_id,
            body=routes_module.ProfileSecretMint(value=value),
            current_user=user,
            pool=FakePool(conn),
        )
    )


def _patch_mint_collaborators(monkeypatch):
    audits = []
    bumps = []

    async def fake_audit(conn, **kwargs):
        audits.append(kwargs)

    async def fake_bump(conn, profile_id):
        bumps.append(profile_id)

    monkeypatch.setattr(routes_module, "insert_audit_event", fake_audit)
    monkeypatch.setattr(routes_module, "bump_attached_cvm_policy_versions", fake_bump)
    return audits, bumps


def test_mint_profile_secret_sole_member_upserts_bumps_and_audits(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", MINT_TEST_KEK)
    audits, bumps = _patch_mint_collaborators(monkeypatch)
    conn = MintProfileConn(mint_profile_row())

    result = run_mint(conn, mint_current_user())

    assert result["profile_id"] == str(MINT_PROFILE_ID)
    assert result["injection_id"] == "claude-code-oauth"
    assert result["minted_at"].endswith("Z")
    assert len(conn.execute_calls) == 1
    sql, args = conn.execute_calls[0]
    assert "INSERT INTO profile_secret_material" in sql
    assert "ON CONFLICT (profile_id, injection_id)" in sql
    assert args[2].startswith("v2:")
    assert "sk-ant-oat01-real-token" not in args[2]
    assert bumps == [MINT_PROFILE_ID]
    assert [audit["action"] for audit in audits] == ["PROFILE_SECRET_MINTED"]
    assert audits[0]["after"] == {"injection_id": "claude-code-oauth"}
    assert audits[0]["target_type"] == "profile"


def test_mint_profile_secret_non_member_is_not_found(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", MINT_TEST_KEK)
    _patch_mint_collaborators(monkeypatch)
    conn = MintProfileConn(mint_profile_row(assigned=False))

    with pytest.raises(HTTPException) as exc:
        run_mint(conn, mint_current_user())

    assert exc.value.status_code == 404
    assert conn.execute_calls == []


def test_mint_profile_secret_multi_member_conflicts_for_non_admin(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", MINT_TEST_KEK)
    _patch_mint_collaborators(monkeypatch)
    conn = MintProfileConn(mint_profile_row(member_count=2))

    with pytest.raises(HTTPException) as exc:
        run_mint(conn, mint_current_user())

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["details"]["state"] == "multi_member_profile"
    assert conn.execute_calls == []


def test_mint_profile_secret_user_manage_bypasses_membership(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", MINT_TEST_KEK)
    audits, bumps = _patch_mint_collaborators(monkeypatch)
    conn = MintProfileConn(mint_profile_row(assigned=False, member_count=3))

    result = run_mint(conn, mint_current_user(permissions=("USER_MANAGE",)))

    assert result["injection_id"] == "claude-code-oauth"
    assert len(conn.execute_calls) == 1
    assert bumps == [MINT_PROFILE_ID]
    assert len(audits) == 1


def test_mint_profile_secret_cross_entity_is_not_found(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", MINT_TEST_KEK)
    _patch_mint_collaborators(monkeypatch)
    conn = MintProfileConn(mint_profile_row())

    with pytest.raises(HTTPException) as exc:
        run_mint(conn, mint_current_user(entity_id=UUID("00000000-0000-4000-8000-000000000002")))

    assert exc.value.status_code == 404
    assert conn.execute_calls == []


def test_mint_profile_secret_undeclared_injection_rejected(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", MINT_TEST_KEK)
    _patch_mint_collaborators(monkeypatch)
    conn = MintProfileConn(mint_profile_row())

    with pytest.raises(HTTPException) as exc:
        run_mint(conn, mint_current_user(), injection_id="slack-bearer")

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["state"] == "unknown_injection"
    assert conn.execute_calls == []


def test_mint_profile_secret_rejects_value_from_injection(monkeypatch) -> None:
    # A value_from injection is resolved per CVM owner from a user secret; the
    # SC never reads profile-side material for it, so minting must be refused
    # rather than silently storing a dead value.
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", MINT_TEST_KEK)
    _patch_mint_collaborators(monkeypatch)
    row = mint_profile_row(
        policy={
            "secret_injections": [
                {
                    "id": "slack-user-token",
                    "match": {"scheme": "https", "host": "slack.com", "ports": [443]},
                    "type": "request_header",
                    "header": "authorization",
                    "value_from": {"user_secret": "slack-user-token"},
                    "value_template": "Bearer ${secret}",
                }
            ]
        }
    )
    conn = MintProfileConn(row)

    with pytest.raises(HTTPException) as exc:
        run_mint(conn, mint_current_user(), injection_id="slack-user-token")

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["state"] == "not_material_backed"
    assert conn.execute_calls == []


def test_mint_profile_secret_rejects_malformed_injection_id(monkeypatch) -> None:
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", MINT_TEST_KEK)
    _patch_mint_collaborators(monkeypatch)
    conn = MintProfileConn(mint_profile_row())

    with pytest.raises(HTTPException) as exc:
        run_mint(conn, mint_current_user(), injection_id="bad id!")

    assert exc.value.status_code == 422


def test_mint_profile_secret_rejects_over_long_rendered_value(monkeypatch) -> None:
    # "Bearer " + token must stay within the SC's 8192-char rendered cap, or
    # the merged policy fail-closes the CVM. The raw token is under the 8192
    # body limit but the rendered value is not.
    monkeypatch.setenv("SECRET_INJECTION_KEK_B64", MINT_TEST_KEK)
    _patch_mint_collaborators(monkeypatch)
    conn = MintProfileConn(mint_profile_row())

    with pytest.raises(HTTPException) as exc:
        run_mint(conn, mint_current_user(), value="x" * 8190)

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["details"]["state"] == "rendered_value_too_long"
    assert conn.execute_calls == []


def test_rendered_injection_value_length_helper() -> None:
    policy = {
        "secret_injections": [
            {"id": "a", "value_template": "Bearer ${secret}"},
            {"id": "b", "value_template": "${secret}"},
        ]
    }
    assert routes_module.rendered_injection_value_length(policy, "a", "tok") == len("Bearer tok")
    assert routes_module.rendered_injection_value_length(policy, "b", "tok") == 3
    # Unknown injection falls back to the raw length.
    assert routes_module.rendered_injection_value_length(policy, "missing", "tok") == 3


def test_material_backed_secret_injection_ids_excludes_value_from() -> None:
    # Inline-value and mint-later (neither value nor value_from) injections are
    # material-backed; value_from (per-user) injections are not.
    policy = {
        "secret_injections": [
            {"id": "inline", "value": "x"},
            {"id": "mint-later", "value_template": "Bearer ${secret}"},
            {"id": "per-user", "value_from": {"user_secret": "s"}},
        ]
    }
    assert routes_module.material_backed_secret_injection_ids(policy) == ["inline", "mint-later"]
    assert routes_module.declared_secret_injection_ids(policy) == ["inline", "mint-later", "per-user"]


def test_profile_secret_mint_value_rejects_control_characters() -> None:
    with pytest.raises(ValidationError):
        routes_module.ProfileSecretMint(value="line1\nline2")
    with pytest.raises(ValidationError):
        routes_module.ProfileSecretMint(value="   ")
    assert routes_module.ProfileSecretMint(value="  sk-token  ").value == "sk-token"


class SecretGateConn:
    def __init__(self, material_rows):
        self.material_rows = material_rows
        self.fetch_calls = []

    async def fetch(self, sql, *args):
        self.fetch_calls.append((sql, args))
        return self.material_rows


def test_ensure_profile_secret_material_complete_blocks_unminted() -> None:
    rows = [
        {
            "profile_id": MINT_PROFILE_ID,
            "policy": {"secret_injections": [{"id": "claude-code-oauth"}, {"id": "slack-bearer"}]},
        }
    ]
    conn = SecretGateConn([{"profile_id": MINT_PROFILE_ID, "injection_id": "claude-code-oauth"}])

    with pytest.raises(HTTPException) as exc:
        asyncio.run(routes_module.ensure_profile_secret_material_complete(conn, rows, status_code=409))

    assert exc.value.status_code == 409
    assert exc.value.detail["error"]["code"] == "CONFLICT"
    details = exc.value.detail["error"]["details"]
    assert details["state"] == "secrets_not_minted"
    assert details["missing"] == [{"profile_id": str(MINT_PROFILE_ID), "injection_id": "slack-bearer"}]


def test_ensure_profile_secret_material_complete_launch_maps_to_422() -> None:
    rows = [
        {"profile_id": MINT_PROFILE_ID, "policy": {"secret_injections": [{"id": "claude-code-oauth"}]}}
    ]
    conn = SecretGateConn([])

    with pytest.raises(HTTPException) as exc:
        asyncio.run(routes_module.ensure_profile_secret_material_complete(conn, rows, status_code=422))

    assert exc.value.status_code == 422
    assert exc.value.detail["error"]["code"] == "VALIDATION_ERROR"


def test_ensure_profile_secret_material_complete_passes_minted_and_plain_profiles() -> None:
    rows = [
        {"profile_id": MINT_PROFILE_ID, "policy": {"secret_injections": [{"id": "claude-code-oauth"}]}},
        {"profile_id": UUID("00000000-0000-4000-8000-000000000070"), "policy": {}},
    ]
    conn = SecretGateConn([{"profile_id": MINT_PROFILE_ID, "injection_id": "claude-code-oauth"}])

    asyncio.run(routes_module.ensure_profile_secret_material_complete(conn, rows, status_code=409))

    assert len(conn.fetch_calls) == 1
    assert conn.fetch_calls[0][1] == ([MINT_PROFILE_ID],)


def test_ensure_profile_secret_material_complete_skips_lookup_without_injections() -> None:
    conn = SecretGateConn([])

    asyncio.run(
        routes_module.ensure_profile_secret_material_complete(
            conn, [{"profile_id": MINT_PROFILE_ID, "policy": {}}], status_code=409
        )
    )

    assert conn.fetch_calls == []

