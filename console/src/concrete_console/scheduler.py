from __future__ import annotations

import asyncio
import base64
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
import socket
import time
from typing import Any
from uuid import UUID

from concrete_console.audit_anchor import publish_audit_anchor_if_due
from concrete_console.audit import insert_audit_event
from concrete_console.audit_export import (
    AuditExportStorageError,
    audit_export_object_key,
    audit_export_storage_uri,
    read_audit_export_artifact,
    serialize_audit_export,
    write_audit_export_artifact,
)
from concrete_console.config import load_settings
from concrete_console.db import get_pool
from concrete_console.log_config import logger
from concrete_console.resources import (
    cvm_resource,
    json_payload,
    operation_error_payload,
    security_cvm_resource,
    timestamp,
)

log = logger()
_last_successful_tick_monotonic: float | None = None
_last_traffic_prune_wall: datetime | None = None
TRAFFIC_LOG_PRUNE_LOCK_ID = 884_422_001
TRAFFIC_LOG_DELETE_CHUNK = 10_000
OPERATION_START_STEPS = {
    "audit.export": ("materialize", 20),
    "cvm.launch": ("phala_deploy", 20),
    "cvm.update": ("provider_update", 20),
    "cvm.terminate": ("phala_terminate", 25),
    "security_cvm.provision": ("phala_deploy", 20),
    "security_cvm.update": ("provider_update", 20),
}
CVM_LAUNCH_EXECUTABLE_STEPS = {
    "phala_deploy",
    "cf_txt_create",
    "cf_cname_create",
    "verify_attestation",
    "await_sc_pull",
    "policy_push",
    "finalise",
}
CVM_LAUNCH_PROGRESS = {
    "cf_txt_create": 40,
    "cf_cname_create": 50,
    "verify_attestation": 60,
    "await_sc_pull": 70,
    "policy_push": 80,
    "finalise": 90,
}
CVM_UPDATE_EXECUTABLE_STEPS = {
    "provider_update",
    "await_provider_running",
    "verify_attestation",
    "await_sc_pull",
    "policy_push",
    "finalise",
}
CVM_UPDATE_PROGRESS = {
    "await_provider_running": 35,
    "verify_attestation": 45,
    "await_sc_pull": 60,
    "policy_push": 75,
    "finalise": 90,
}
SECURITY_CVM_PROVISION_EXECUTABLE_STEPS = {
    "phala_deploy",
    "cf_txt_create",
    "cf_cname_create",
    "await_phala_running",
    "verify_attestation",
    "fetch_ca",
    "finalise",
}
SECURITY_CVM_PROVISION_PROGRESS = {
    "cf_txt_create": 40,
    "cf_cname_create": 50,
    "await_phala_running": 55,
    "verify_attestation": 60,
    "fetch_ca": 80,
    "finalise": 90,
}
SECURITY_CVM_UPDATE_EXECUTABLE_STEPS = {
    "provider_update",
    "await_provider_running",
    "verify_attestation",
    "fetch_ca",
    "finalise",
}
SECURITY_CVM_UPDATE_PROGRESS = {
    "await_provider_running": 40,
    "verify_attestation": 55,
    "fetch_ca": 75,
    "finalise": 90,
}
PROVIDER_ERROR_OUTPUT_LOG_LIMIT = 12_000
AUDIT_EXPORT_EXECUTABLE_STEPS = {"materialize"}
AUDIT_EXPORT_ROW_CAP = 1_000_000
SECURITY_CVM_TOKEN_PLAINTEXT_TTL_SECONDS = 3600


@dataclass(frozen=True)
class ReconciliationSummary:
    cvms_advanced: list[str]
    security_cvms_advanced: list[str]
    orphans_cleaned: list[str]


@dataclass(frozen=True)
class CvmKind:
    """The Dev-vs-Security-CVM axis the reconciler and attestation writers vary over,
    captured once so each shared helper takes a single descriptor instead of a fistful of
    parallel string kwargs. This is type metadata, NOT instance data: there are exactly two
    frozen values (``DEV_CVM`` / ``SECURITY_CVM``); a CVM's own fields live in its DB ``row``.
    Every field is an internal literal — ``table``/``alias`` are interpolated into SQL, never
    user input. Add a field here when a new structural difference appears, and the two
    constants below force you to define it for both families."""

    slug: str  # structlog event namespace: "dev_cvm" / "security_cvm"
    table: str  # "cvms" / "security_cvms"
    alias: str  # short SELECT alias: "c" / "sc"
    audit_target: str  # audit target_type: "cvm" / "security_cvm"
    audit_prefix: str  # audit action prefix: "CVM" / "SECURITY_CVM"
    log_id_key: str  # structlog id field: "cvm_id" / "security_cvm_id"


DEV_CVM = CvmKind(
    slug="dev_cvm",
    table="cvms",
    alias="c",
    audit_target="cvm",
    audit_prefix="CVM",
    log_id_key="cvm_id",
)
SECURITY_CVM = CvmKind(
    slug="security_cvm",
    table="security_cvms",
    alias="sc",
    audit_target="security_cvm",
    audit_prefix="SECURITY_CVM",
    log_id_key="security_cvm_id",
)


def provider_error_log_fields(exc: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "adapter": "cvm_provider",
        "provider": getattr(exc, "provider", "unknown"),
        "reason": getattr(exc, "code", "unknown"),
    }
    output = getattr(exc, "output", "")
    if isinstance(output, str) and output:
        fields["provider_output"] = output[:PROVIDER_ERROR_OUTPUT_LOG_LIMIT]
        fields["provider_output_truncated"] = len(output) > PROVIDER_ERROR_OUTPUT_LOG_LIMIT
    return fields


def shade_error_log_fields(exc: Any) -> dict[str, Any]:
    fields: dict[str, Any] = {
        "adapter": "shade",
        "reason": getattr(exc, "code", "unknown"),
    }
    field = getattr(exc, "field", None)
    if isinstance(field, str) and field:
        fields["field"] = field
    output = getattr(exc, "output", "")
    if isinstance(output, str) and output:
        fields["shade_output"] = output[:PROVIDER_ERROR_OUTPUT_LOG_LIMIT]
        fields["shade_output_truncated"] = len(output) > PROVIDER_ERROR_OUTPUT_LOG_LIMIT
    return fields


def phala_error_log_fields(exc: Any) -> dict[str, Any]:
    # Surface the Phala CLI's real stderr/stdout (already api_token-scrubbed by the adapter)
    # instead of collapsing every failure to a bare PHALA_DEPLOY_FAILED code. Mirrors
    # shade_error_log_fields so provision failures stop being silent.
    fields: dict[str, Any] = {
        "adapter": "phala",
        "reason": getattr(exc, "code", "unknown"),
    }
    field = getattr(exc, "field", None)
    if isinstance(field, str) and field:
        fields["field"] = field
    output = getattr(exc, "output", "")
    if isinstance(output, str) and output:
        fields["phala_output"] = output[:PROVIDER_ERROR_OUTPUT_LOG_LIMIT]
        fields["phala_output_truncated"] = len(output) > PROVIDER_ERROR_OUTPUT_LOG_LIMIT
    return fields


def shade_error_is_compose_mismatch(exc: Any) -> bool:
    output = getattr(exc, "output", "")
    return getattr(exc, "code", "") == "cli_failed" and isinstance(output, str) and "docker-compose mismatch" in output


def shade_error_is_transient_connect_failure(exc: Any) -> bool:
    if getattr(exc, "code", "") != "cli_failed":
        return False
    output = getattr(exc, "output", "")
    if not isinstance(output, str):
        return False
    markers = (
        "Failed to connect to",
        "UNEXPECTED_EOF_WHILE_READING",
        "Connection refused",
        "Connection reset",
        "tls handshake eof",
        "TLS handshake",
    )
    lowered = output.lower()
    return any(marker.lower() in lowered for marker in markers)


def reconciler_interval_seconds() -> float:
    raw = load_settings().raw.get("RECONCILER_INTERVAL_SECONDS", "30").strip() or "30"
    try:
        interval = float(raw)
    except ValueError as exc:
        raise RuntimeError("RECONCILER_INTERVAL_SECONDS must be numeric") from exc
    if interval < 1:
        raise RuntimeError("RECONCILER_INTERVAL_SECONDS must be at least 1")
    return interval


def operation_scheduler_batch_size() -> int:
    raw = load_settings().raw.get("OPERATION_SCHEDULER_BATCH_SIZE", "10").strip() or "10"
    try:
        batch_size = int(raw)
    except ValueError as exc:
        raise RuntimeError("OPERATION_SCHEDULER_BATCH_SIZE must be an integer") from exc
    if batch_size < 1:
        raise RuntimeError("OPERATION_SCHEDULER_BATCH_SIZE must be at least 1")
    return batch_size


def sc_pull_propagation_timeout_seconds() -> int:
    raw = load_settings().raw.get("SC_PULL_PROPAGATION_TIMEOUT_SECONDS", "15").strip() or "15"
    try:
        timeout = int(raw)
    except ValueError as exc:
        raise RuntimeError("SC_PULL_PROPAGATION_TIMEOUT_SECONDS must be an integer") from exc
    if timeout < 0 or timeout > 300:
        raise RuntimeError("SC_PULL_PROPAGATION_TIMEOUT_SECONDS must be between 0 and 300")
    return timeout


def provider_update_timeout_seconds() -> int:
    raw = load_settings().raw.get("PROVIDER_UPDATE_TIMEOUT_SECONDS", "900").strip() or "900"
    try:
        timeout = int(raw)
    except ValueError as exc:
        raise RuntimeError("PROVIDER_UPDATE_TIMEOUT_SECONDS must be an integer") from exc
    if timeout < 300 or timeout > 1800:
        raise RuntimeError("PROVIDER_UPDATE_TIMEOUT_SECONDS must be between 300 and 1800")
    return timeout


def dev_cvm_attestation_timeout_seconds() -> int:
    raw = load_settings().raw.get("DEV_CVM_ATTESTATION_TIMEOUT_SECONDS", "180").strip() or "180"
    try:
        timeout = int(raw)
    except ValueError as exc:
        raise RuntimeError("DEV_CVM_ATTESTATION_TIMEOUT_SECONDS must be an integer") from exc
    if timeout < 30 or timeout > 600:
        raise RuntimeError("DEV_CVM_ATTESTATION_TIMEOUT_SECONDS must be between 30 and 600")
    return timeout


def security_cvm_attestation_timeout_seconds() -> int:
    raw = load_settings().raw.get("SECURITY_CVM_ATTESTATION_TIMEOUT_SECONDS", "180").strip() or "180"
    try:
        timeout = int(raw)
    except ValueError as exc:
        raise RuntimeError("SECURITY_CVM_ATTESTATION_TIMEOUT_SECONDS must be an integer") from exc
    if timeout < 30 or timeout > 600:
        raise RuntimeError("SECURITY_CVM_ATTESTATION_TIMEOUT_SECONDS must be between 30 and 600")
    return timeout


def security_cvm_fqdn_resolve_timeout_seconds() -> int:
    raw = load_settings().raw.get("SECURITY_CVM_FQDN_RESOLVE_TIMEOUT_SECONDS", "120").strip() or "120"
    try:
        timeout = int(raw)
    except ValueError as exc:
        raise RuntimeError("SECURITY_CVM_FQDN_RESOLVE_TIMEOUT_SECONDS must be an integer") from exc
    if timeout < 10 or timeout > 600:
        raise RuntimeError("SECURITY_CVM_FQDN_RESOLVE_TIMEOUT_SECONDS must be between 10 and 600")
    return timeout


def reconciler_attestation_interval_seconds() -> int:
    raw = load_settings().raw.get("RECONCILER_ATTESTATION_INTERVAL_SECONDS", "21600").strip() or "21600"
    try:
        interval = int(raw)
    except ValueError as exc:
        raise RuntimeError("RECONCILER_ATTESTATION_INTERVAL_SECONDS must be an integer") from exc
    if interval < 3600 or interval > 86400:
        raise RuntimeError("RECONCILER_ATTESTATION_INTERVAL_SECONDS must be between 3600 and 86400")
    return interval


def keep_failed_cvm_resources() -> bool:
    """Debug aid: when truthy, a failed Dev CVM launch is NOT torn down.

    Default false (production behavior: compensate/destroy on failure). Set
    CONCRETE_KEEP_FAILED_CVM=1 to leave the Phala app and DNS records in place so the
    in-CVM logs (e.g. nginx-cert-manager / ACME cert issuance) survive for inspection.
    Re-enable teardown by unsetting the flag.
    """
    raw = load_settings().raw.get("CONCRETE_KEEP_FAILED_CVM", "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def start_operation_scheduler() -> asyncio.Task[None]:
    return asyncio.create_task(operation_scheduler_loop(), name="operation-scheduler")


async def stop_operation_scheduler(task: asyncio.Task[None]) -> None:
    task.cancel()
    with suppress(asyncio.CancelledError):
        await task


async def operation_scheduler_loop() -> None:
    while True:
        try:
            await run_scheduler_tick()
            mark_scheduler_tick_success()
        except asyncio.CancelledError:
            log.info("operation_scheduler_cancelled")
            raise
        except Exception as exc:  # noqa: BLE001
            log.error("operation_scheduler_tick_failed", error_type=type(exc).__name__)
        await asyncio.sleep(reconciler_interval_seconds())


async def run_scheduler_tick() -> None:
    await run_operation_scheduler_pass()
    await run_reconciliation_pass()


async def run_operation_scheduler_pass(*, batch_size: int | None = None) -> list[str]:
    pool = await get_pool()
    claimed_ids: list[str] = []
    executable_ids: list[Any] = []
    async with pool.acquire() as conn:
        async with conn.transaction():
            rows = await claim_active_operations(conn, batch_size=batch_size or operation_scheduler_batch_size())
            for row in rows:
                if _row_value(row, "status") == "running":
                    leased = await lease_running_operation(conn, row)
                    if leased:
                        executable_ids.append(_row_value(row, "id"))
                        claimed_ids.append(str(_row_value(row, "id")))
                    continue
                if await advance_claimed_operation(conn, row):
                    if pending_operation_start_is_executable(row):
                        executable_ids.append(_row_value(row, "id"))
                    claimed_ids.append(str(_row_value(row, "id")))
    for operation_id in executable_ids:
        await execute_running_operation(operation_id)
    return claimed_ids


async def claim_active_operations(conn: Any, *, batch_size: int) -> list[Any]:
    return list(
        await conn.fetch(
            """
            SELECT
                id,
                kind,
                status::text AS status,
                progress_step,
                progress_percent
            FROM operations
            WHERE status IN ('pending', 'running')
              AND updated_at < now() - INTERVAL '30 seconds'
            ORDER BY created_at
            LIMIT $1
            FOR UPDATE SKIP LOCKED
            """,
            batch_size,
        )
    )


async def advance_claimed_operation(conn: Any, row: Any) -> bool:
    if _row_value(row, "status") != "pending":
        log.info(
            "operation_scheduler_running_operation_claimed",
            operation_id=str(_row_value(row, "id")),
            kind=_row_value(row, "kind"),
            step=_row_value(row, "progress_step"),
        )
        return False

    progress = pending_operation_start_progress(
        _row_value(row, "kind"),
        progress_step=_row_value(row, "progress_step"),
        progress_percent=_row_value(row, "progress_percent"),
    )
    if progress is None:
        log.warning(
            "operation_scheduler_unknown_kind",
            operation_id=str(_row_value(row, "id")),
            kind=_row_value(row, "kind"),
        )
        return False
    next_step, next_percent = progress
    result = await conn.execute(
        """
        UPDATE operations
        SET status = 'running',
            progress_step = $2,
            progress_percent = $3,
            updated_at = now()
        WHERE id = $1
          AND status = 'pending'
        """,
        _row_value(row, "id"),
        next_step,
        next_percent,
    )
    advanced = result == "UPDATE 1"
    if advanced:
        log.info(
            "operation_scheduler_operation_started",
            operation_id=str(_row_value(row, "id")),
            kind=_row_value(row, "kind"),
            step=next_step,
        )
    return advanced


async def lease_running_operation(conn: Any, row: Any) -> bool:
    if not executable_running_operation(row):
        log.info(
            "operation_scheduler_running_operation_claimed",
            operation_id=str(_row_value(row, "id")),
            kind=_row_value(row, "kind"),
            step=_row_value(row, "progress_step"),
        )
        return False
    result = await conn.execute(
        """
        UPDATE operations
        SET updated_at = now()
        WHERE id = $1
          AND status = 'running'
        """,
        _row_value(row, "id"),
    )
    leased = result == "UPDATE 1"
    if leased:
        log.info(
            "operation_scheduler_operation_leased",
            operation_id=str(_row_value(row, "id")),
            kind=_row_value(row, "kind"),
            step=_row_value(row, "progress_step"),
        )
    return leased


def executable_running_operation(row: Any) -> bool:
    kind = _row_value(row, "kind")
    step = _row_value(row, "progress_step")
    return (kind == "cvm.terminate" and step == "phala_terminate") or (
        kind == "cvm.launch" and step in CVM_LAUNCH_EXECUTABLE_STEPS
    ) or (
        kind == "cvm.update" and step in CVM_UPDATE_EXECUTABLE_STEPS
    ) or (
        kind == "security_cvm.provision" and step in SECURITY_CVM_PROVISION_EXECUTABLE_STEPS
    ) or (
        kind == "security_cvm.update" and step in SECURITY_CVM_UPDATE_EXECUTABLE_STEPS
    ) or (
        kind == "audit.export" and step in AUDIT_EXPORT_EXECUTABLE_STEPS
    )


def pending_operation_start_is_executable(row: Any) -> bool:
    progress = pending_operation_start_progress(
        _row_value(row, "kind"),
        progress_step=_row_value(row, "progress_step"),
        progress_percent=_row_value(row, "progress_percent"),
    )
    if progress is None:
        return False
    next_step, _next_percent = progress
    return executable_running_operation(
        {"kind": _row_value(row, "kind"), "status": "running", "progress_step": next_step}
    )


async def execute_running_operation(operation_id: Any) -> bool:
    pool = await get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT id, kind, status::text AS status, progress_step
            FROM operations
            WHERE id = $1
            """,
            operation_id,
        )
    if row is None or _row_value(row, "status") != "running":
        return False
    kind = _row_value(row, "kind")
    step = _row_value(row, "progress_step")
    if kind == "cvm.terminate" and step == "phala_terminate":
        await execute_operation_step_with_logging(
            operation_id,
            kind=kind,
            step=step,
            handler=lambda: execute_cvm_terminate_operation(operation_id),
        )
        return True
    if kind == "cvm.launch" and step in CVM_LAUNCH_EXECUTABLE_STEPS:
        await execute_operation_step_with_logging(
            operation_id,
            kind=kind,
            step=step,
            handler=lambda: execute_cvm_launch_operation(operation_id, step),
        )
        return True
    if kind == "cvm.update" and step in CVM_UPDATE_EXECUTABLE_STEPS:
        await execute_operation_step_with_logging(
            operation_id,
            kind=kind,
            step=step,
            handler=lambda: execute_cvm_update_operation(operation_id, step),
        )
        return True
    if kind == "security_cvm.provision" and step in SECURITY_CVM_PROVISION_EXECUTABLE_STEPS:
        await execute_operation_step_with_logging(
            operation_id,
            kind=kind,
            step=step,
            handler=lambda: execute_security_cvm_provision_operation(operation_id, step),
        )
        return True
    if kind == "security_cvm.update" and step in SECURITY_CVM_UPDATE_EXECUTABLE_STEPS:
        await execute_operation_step_with_logging(
            operation_id,
            kind=kind,
            step=step,
            handler=lambda: execute_security_cvm_update_operation(operation_id, step),
        )
        return True
    if kind == "audit.export" and step in AUDIT_EXPORT_EXECUTABLE_STEPS:
        await execute_operation_step_with_logging(
            operation_id,
            kind=kind,
            step=step,
            handler=lambda: execute_audit_export_operation(operation_id),
        )
        return True
    return False


async def execute_operation_step_with_logging(
    operation_id: Any,
    *,
    kind: str,
    step: str,
    handler: Any,
) -> None:
    started = time.monotonic()
    log.info(
        "operation_scheduler_step_started",
        operation_id=str(operation_id),
        kind=kind,
        step=step,
    )
    try:
        await handler()
    except Exception as exc:
        elapsed_ms = int((time.monotonic() - started) * 1000)
        log.error(
            "operation_scheduler_step_failed",
            operation_id=str(operation_id),
            kind=kind,
            step=step,
            elapsed_ms=elapsed_ms,
            error_type=type(exc).__name__,
        )
        raise
    elapsed_ms = int((time.monotonic() - started) * 1000)
    log.info(
        "operation_scheduler_step_finished",
        operation_id=str(operation_id),
        kind=kind,
        step=step,
        elapsed_ms=elapsed_ms,
    )


async def execute_cvm_launch_operation(operation_id: Any, step: str) -> None:
    if step == "phala_deploy":
        await execute_cvm_launch_phala_deploy_operation(operation_id)
        return
    if step == "cf_txt_create":
        await execute_cvm_launch_txt_operation(operation_id)
        return
    if step == "cf_cname_create":
        await execute_cvm_launch_cname_operation(operation_id)
        return
    if step == "verify_attestation":
        await execute_cvm_launch_attestation_gate_operation(operation_id)
        return
    if step == "await_sc_pull":
        await execute_cvm_launch_await_sc_pull_operation(operation_id)
        return
    if step == "policy_push":
        await execute_cvm_launch_policy_push_operation(operation_id)
        return
    if step == "finalise":
        await execute_cvm_launch_finalise_operation(operation_id)
        return


async def execute_cvm_update_operation(operation_id: Any, step: str) -> None:
    if step == "provider_update":
        await execute_cvm_update_phala_operation(operation_id)
        return
    if step == "await_provider_running":
        await execute_cvm_update_await_provider_running_operation(operation_id)
        return
    if step == "verify_attestation":
        await execute_cvm_update_attestation_gate_operation(operation_id)
        return
    if step == "await_sc_pull":
        await execute_cvm_update_await_sc_pull_operation(operation_id)
        return
    if step == "policy_push":
        await execute_cvm_update_policy_push_operation(operation_id)
        return
    if step == "finalise":
        await execute_cvm_update_finalise_operation(operation_id)
        return


async def execute_security_cvm_provision_operation(operation_id: Any, step: str) -> None:
    if step == "phala_deploy":
        await execute_security_cvm_phala_deploy_operation(operation_id)
        return
    if step == "cf_txt_create":
        await execute_security_cvm_txt_operation(operation_id)
        return
    if step == "cf_cname_create":
        await execute_security_cvm_cname_operation(operation_id)
        return
    if step == "await_phala_running":
        await execute_security_cvm_await_phala_running_operation(operation_id)
        return
    if step == "verify_attestation":
        await execute_security_cvm_attestation_gate_operation(operation_id)
        return
    if step == "fetch_ca":
        await execute_security_cvm_fetch_ca_operation(operation_id)
        return
    if step == "finalise":
        await execute_security_cvm_finalise_operation(operation_id)
        return


async def execute_security_cvm_update_operation(operation_id: Any, step: str) -> None:
    if step == "provider_update":
        await execute_security_cvm_update_phala_operation(operation_id)
        return
    if step == "await_provider_running":
        await execute_security_cvm_update_await_phala_running_operation(operation_id)
        return
    if step == "verify_attestation":
        await execute_security_cvm_update_attestation_gate_operation(operation_id)
        return
    if step == "fetch_ca":
        await execute_security_cvm_update_fetch_ca_operation(operation_id)
        return
    if step == "finalise":
        await execute_security_cvm_update_finalise_operation(operation_id)
        return


async def execute_audit_export_operation(operation_id: Any) -> None:
    pool = await get_pool()
    settings = load_settings()
    bucket_uri = settings.raw.get("AUDIT_EXPORT_BUCKET", "").strip()
    if not bucket_uri:
        await mark_operation_failed(
            operation_id,
            code="AUDIT_EXPORT_BUCKET_UNCONFIGURED",
            details={"component": "audit_export_bucket"},
        )
        return

    async with pool.acquire() as conn:
        snapshot = await fetch_audit_export_snapshot(conn, operation_id)
        if snapshot is None:
            await mark_operation_failed(
                operation_id,
                code="AUDIT_EXPORT_REQUEST_NOT_FOUND",
                details={"state": "missing_export_request"},
            )
            return
        request_filters = json_payload(_row_value(snapshot, "filters") or {})
        if not isinstance(request_filters, dict):
            await mark_operation_failed(
                operation_id,
                code="AUDIT_EXPORT_REQUEST_INVALID",
                details={"field": "filters"},
            )
            return
        export_format = request_filters.get("format")
        if export_format not in {"csv", "ndjson"}:
            await mark_operation_failed(
                operation_id,
                code="AUDIT_EXPORT_REQUEST_INVALID",
                details={"field": "format"},
            )
            return
        try:
            rows = await fetch_audit_export_rows_for_filters(
                conn,
                _row_value(snapshot, "entity_id"),
                request_filters,
                limit=AUDIT_EXPORT_ROW_CAP + 1,
            )
        except ValueError as exc:
            await mark_operation_failed(
                operation_id,
                code="AUDIT_EXPORT_REQUEST_INVALID",
                details={"message": str(exc)},
            )
            return
        if len(rows) > AUDIT_EXPORT_ROW_CAP:
            await mark_operation_failed(
                operation_id,
                code="AUDIT_EXPORT_ROW_CAP_EXCEEDED",
                details={"limit": AUDIT_EXPORT_ROW_CAP},
            )
            return
        artifact = serialize_audit_export(rows, str(export_format))

    object_key = audit_export_object_key(operation_id, str(export_format))
    try:
        storage_uri = await write_audit_export_artifact_idempotently(bucket_uri, object_key, artifact)
    except AuditExportStorageError:
        await mark_operation_failed(
            operation_id,
            code="AUDIT_EXPORT_STORE_FAILED",
            details={"component": "audit_export_store"},
        )
        return

    download_token = secrets.token_urlsafe(32)
    download_token_hash = hashlib.sha256(download_token.encode("utf-8")).hexdigest()
    download_expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
    console_url = settings.raw.get("CONSOLE_URL", "http://localhost:8000").rstrip("/")
    result = {
        "download_url": f"{console_url}/api/v1/audit/exports/{download_token}",
        "expires_at": timestamp(download_expires_at),
        "content_type": artifact.content_type,
        "sha256": artifact.sha256,
        "row_count": artifact.row_count,
        "byte_size": artifact.byte_size,
    }
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                INSERT INTO audit_export_artifacts (
                    operation_id,
                    storage_uri,
                    download_token_hash,
                    content_type,
                    sha256,
                    row_count,
                    byte_size,
                    expires_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (operation_id) DO UPDATE
                SET storage_uri = EXCLUDED.storage_uri,
                    download_token_hash = EXCLUDED.download_token_hash,
                    content_type = EXCLUDED.content_type,
                    sha256 = EXCLUDED.sha256,
                    row_count = EXCLUDED.row_count,
                    byte_size = EXCLUDED.byte_size,
                    expires_at = EXCLUDED.expires_at,
                    redeemed_at = NULL
                """,
                operation_id,
                storage_uri,
                download_token_hash,
                artifact.content_type,
                artifact.sha256,
                artifact.row_count,
                artifact.byte_size,
                download_expires_at,
            )
            if not await audit_export_issued_event_exists(conn, operation_id):
                await insert_audit_event(
                    conn,
                    entity_id=_row_value(snapshot, "entity_id"),
                    actor_id=_row_value(snapshot, "actor_id"),
                    actor_email=_row_value(snapshot, "actor_email"),
                    action="AUDIT_EXPORT_ISSUED",
                    target_type="audit_export",
                    target_id=operation_id,
                    after={
                        "row_count": artifact.row_count,
                        "byte_size": artifact.byte_size,
                        "sha256": artifact.sha256,
                    },
                )
            await conn.execute(
                """
                UPDATE operations
                SET status = 'succeeded',
                    progress_step = 'completed',
                    progress_percent = 100,
                    result = $2::jsonb,
                    error = NULL,
                    updated_at = now(),
                    expires_at = $3
                WHERE id = $1
                  AND kind = 'audit.export'
                  AND status = 'running'
                """,
                operation_id,
                json.dumps(result),
                operation_expiry(),
            )


async def write_audit_export_artifact_idempotently(bucket_uri: str, object_key: str, artifact: Any) -> str:
    try:
        return await write_audit_export_artifact(bucket_uri, object_key, artifact)
    except AuditExportStorageError as write_error:
        try:
            storage_uri = audit_export_storage_uri(bucket_uri, object_key)
            existing = await read_audit_export_artifact(bucket_uri, storage_uri)
        except (AuditExportStorageError, ValueError) as read_error:
            raise write_error from read_error
        if hashlib.sha256(existing).hexdigest() != artifact.sha256:
            raise write_error
        return storage_uri


async def audit_export_issued_event_exists(conn: Any, operation_id: Any) -> bool:
    return bool(
        await conn.fetchval(
            """
            SELECT 1
            FROM audit_events
            WHERE action = 'AUDIT_EXPORT_ISSUED'
              AND target_type = 'audit_export'
              AND target_id = $1
            LIMIT 1
            """,
            str(operation_id),
        )
    )


async def fetch_audit_export_snapshot(conn: Any, operation_id: Any) -> Any | None:
    return await conn.fetchrow(
        """
        SELECT
            o.id,
            o.actor_id,
            o.actor_email,
            r.entity_id,
            r.filters
        FROM operations o
        JOIN audit_export_requests r ON r.operation_id = o.id
        WHERE o.id = $1
          AND o.kind = 'audit.export'
          AND o.status = 'running'
        """,
        operation_id,
    )


async def fetch_audit_export_rows_for_filters(
    conn: Any,
    entity_id: Any,
    filters: dict[str, Any],
    *,
    limit: int,
) -> list[Any]:
    clauses = ["(entity_id = $1 OR actor_id IN (SELECT id FROM users WHERE entity_id = $1))"]
    values: list[Any] = [entity_id]

    def bind(value: Any) -> str:
        values.append(value)
        return f"${len(values)}"

    if filters.get("actor_id") is not None:
        clauses.append(f"actor_id = {bind(UUID(str(filters['actor_id'])))}")
    if filters.get("target_type") is not None:
        clauses.append(f"target_type = {bind(str(filters['target_type']))}")
    if filters.get("target_id") is not None:
        clauses.append(f"target_id = {bind(str(filters['target_id']))}")
    if filters.get("action") is not None:
        clauses.append(f"action = {bind(str(filters['action']))}")
    if filters.get("from") is not None:
        clauses.append(f"timestamp >= {bind(audit_export_datetime_filter(filters['from']))}")
    if filters.get("to") is not None:
        clauses.append(f"timestamp <= {bind(audit_export_datetime_filter(filters['to']))}")

    values.append(limit)
    query = f"""
        SELECT
            seq, id, entity_id, actor_id, actor_email, action, target_type, target_id,
            before, after, ip_address, description, request_id, timestamp, prev_hash, row_hash
        FROM audit_events
        WHERE {' AND '.join(clauses)}
        ORDER BY seq ASC
        LIMIT ${len(values)}
    """
    return list(await conn.fetch(query, *values))


def audit_export_datetime_filter(value: Any) -> datetime:
    if isinstance(value, datetime):
        return _as_utc(value)
    if not isinstance(value, str):
        raise ValueError("timestamp filter must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("timestamp filter is invalid") from exc
    return _as_utc(parsed)


async def execute_security_cvm_phala_deploy_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_security_cvm_provision_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_security_cvm_provision_failed(operation_id, code="SECURITY_CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "state") != "PROVISIONING":
        await mark_security_cvm_provision_failed(
            operation_id,
            code="INVALID_STATE",
            details={"state": _row_value(snapshot, "state")},
        )
        return
    if provider_app_id(_row_value(snapshot, "metadata")) is not None:
        await advance_security_cvm_provision_step(operation_id, "cf_txt_create")
        return
    from concrete_console.shade_provider.shade import ShadeClient, ShadeError
    from concrete_console.tee_provider.phala import PhalaClient, PhalaError

    env: dict[str, str] | None = None
    bearers: dict[str, str] | None = None
    try:
        name = security_cvm_provider_name(_row_value(snapshot, "id"))
        shade_result = await ShadeClient.from_settings().build(
            shade_config_yaml=render_security_cvm_shade_config(snapshot, name=name),
            app_compose_yaml=_row_value(snapshot, "compose_config"),
        )
        bearers = mint_security_cvm_provision_bearers()
        await persist_security_cvm_provision_bearers(
            operation_id,
            snapshot,
            ingest_token_hash=bearers["ingest_token_hash"],
            ca_export_token_hash=bearers["ca_export_token_hash"],
            ca_export_token_plaintext=bearers["ca_export_token"],
        )
        env = build_security_cvm_provision_env(
            snapshot,
            ingest_token=bearers["ingest_token"],
            ca_export_token=bearers["ca_export_token"],
        )
        deploy_result = await PhalaClient.from_settings().deploy(
            name=name,
            compose_yaml=shade_result.compose_yaml,
            env=env,
            instance_type=_row_value(snapshot, "instance_type"),
            region=_row_value(snapshot, "region"),
        )
    except ShadeError as exc:
        log.warning("shade_adapter_failed", operation_id=str(operation_id), **shade_error_log_fields(exc))
        await mark_security_cvm_provision_failed(
            operation_id,
            code="SHADE_BUILD_FAILED",
            details={"adapter": "shade", "reason": exc.code},
        )
        return
    except PhalaError as exc:
        log.warning(
            "phala_adapter_failed",
            operation_id=str(operation_id),
            step="phala_deploy",
            **phala_error_log_fields(exc),
        )
        await mark_security_cvm_provision_failed(
            operation_id,
            code="PHALA_DEPLOY_FAILED",
            details=phala_error_log_fields(exc),
        )
        return
    finally:
        if env is not None:
            env["CONSOLE_INGEST_TOKEN"] = ""
            env["CA_EXPORT_TOKEN"] = ""
        if bearers is not None:
            bearers["ingest_token"] = ""
            bearers["ca_export_token"] = ""

    await persist_security_cvm_phala_result(
        operation_id,
        snapshot,
        metadata=security_cvm_provision_metadata(
            name=name,
            app_id=deploy_result.app_id,
            gateway_host=deploy_result.gateway_host,
            status=deploy_result.status,
            deploy_compose_yaml=shade_result.compose_yaml,
        ),
    )


async def execute_security_cvm_txt_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_security_cvm_provision_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_security_cvm_provision_failed(operation_id, code="SECURITY_CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "txt_dns_record_id"):
        await advance_security_cvm_provision_step(operation_id, "cf_cname_create")
        return
    app_id = provider_app_id(_row_value(snapshot, "metadata"))
    if app_id is None:
        await mark_security_cvm_provision_failed(operation_id, code="PHALA_APP_MISSING", details={"field": "metadata.app_id"})
        return

    from concrete_console.dns_provider.cloudflare import CloudflareClient, CloudflareError

    try:
        record_id = await CloudflareClient.from_settings(zone_id_key="SECURITY_CVM_ZONE_ID").ensure_dstack_txt(
            fqdn=_row_value(snapshot, "fqdn"),
            app_id=app_id,
        )
    except CloudflareError as exc:
        await compensate_security_cvm_provision_resources(snapshot)
        await mark_security_cvm_provision_failed(
            operation_id,
            code="CLOUDFLARE_TXT_FAILED",
            details={"adapter": "cloudflare", "reason": exc.code},
        )
        return
    await persist_security_cvm_dns_record(operation_id, snapshot, field="txt", record_id=record_id)


async def execute_security_cvm_cname_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_security_cvm_provision_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_security_cvm_provision_failed(operation_id, code="SECURITY_CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "cname_dns_record_id"):
        await advance_security_cvm_provision_step(operation_id, "await_phala_running")
        return
    gateway_host = provider_gateway_host(_row_value(snapshot, "metadata"))
    if gateway_host is None:
        await mark_security_cvm_provision_failed(
            operation_id,
            code="PHALA_GATEWAY_MISSING",
            details={"field": "metadata.gateway_host"},
        )
        return

    from concrete_console.dns_provider.cloudflare import CloudflareClient, CloudflareError

    try:
        record_id = await CloudflareClient.from_settings(zone_id_key="SECURITY_CVM_ZONE_ID").ensure_gateway_cname(
            fqdn=_row_value(snapshot, "fqdn"),
            gateway_host=gateway_host,
        )
    except CloudflareError as exc:
        await compensate_security_cvm_provision_resources(snapshot)
        await mark_security_cvm_provision_failed(
            operation_id,
            code="CLOUDFLARE_CNAME_FAILED",
            details={"adapter": "cloudflare", "reason": exc.code},
        )
        return
    await persist_security_cvm_dns_record(operation_id, snapshot, field="cname", record_id=record_id)


async def execute_security_cvm_await_phala_running_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_security_cvm_provision_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_security_cvm_provision_failed(operation_id, code="SECURITY_CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "state") == "RUNNING":
        await advance_security_cvm_provision_step(operation_id, "verify_attestation")
        return
    log.info(
        "security_cvm_await_phala_pending",
        operation_id=str(operation_id),
        security_cvm_id=str(_row_value(snapshot, "id")),
        state=_row_value(snapshot, "state"),
    )


async def resolve_fqdn_ip(fqdn: str, *, timeout_seconds: int, interval_seconds: float = 2.0) -> str | None:
    """Resolve ``fqdn`` to an IP, retrying past the transient NXDOMAIN a freshly-created
    gateway CNAME returns from the Console's own resolver (127.0.0.11 -> GCP) for the first
    minutes while a negative-cache entry ages out. Returns the resolved IP, or None on
    timeout. Callers connect to this pinned address (TLS SNI / HTTP Host stay the FQDN) so
    the single-shot connect never re-resolves and cannot hit one of those gaps."""
    loop = asyncio.get_running_loop()
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            infos = await loop.getaddrinfo(fqdn, 443, type=socket.SOCK_STREAM)
            if infos:
                return infos[0][4][0]
        except OSError:
            pass
        if time.monotonic() + interval_seconds > deadline:
            return None
        await asyncio.sleep(interval_seconds)


async def execute_security_cvm_attestation_gate_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_security_cvm_provision_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_security_cvm_provision_failed(operation_id, code="SECURITY_CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "image_measurement") is None or _row_value(snapshot, "attestation_verified_at") is None:
        verified = await run_security_cvm_provision_attestation_verifier(operation_id, snapshot)
        if verified:
            return
        log.info(
            "security_cvm_provision_attestation_waiting",
            operation_id=str(operation_id),
            security_cvm_id=str(_row_value(snapshot, "id")),
        )
        return
    if _row_value(snapshot, "image_measurement") != _row_value(snapshot, "expected_image_measurement"):
        await compensate_security_cvm_provision_resources(snapshot)
        await mark_security_cvm_provision_failed(
            operation_id,
            code="ATTESTATION_IMAGE_MISMATCH",
            details={
                "expected": _row_value(snapshot, "expected_image_measurement"),
                "actual": _row_value(snapshot, "image_measurement"),
            },
        )
        return
    if _row_value(snapshot, "rtmr3_digest") is None:
        await compensate_security_cvm_provision_resources(snapshot)
        await mark_security_cvm_provision_failed(
            operation_id,
            code="ATTESTATION_RTMR_MISMATCH",
            details={"state": "missing_rtmr3_digest"},
        )
        return
    await advance_security_cvm_provision_step(operation_id, "fetch_ca")


async def run_security_cvm_provision_attestation_verifier(operation_id: Any, snapshot: Any) -> bool:
    from concrete_console.attestation import (
        AtlasVerifierClient,
        AttestationVerifierError,
        AttestationVerifierUnavailable,
        build_security_cvm_attestation_request,
        verify_with_fetch_retries,
    )
    from concrete_console.shade_provider.shade import ShadeError

    try:
        verifier = AtlasVerifierClient.from_settings()
    except AttestationVerifierUnavailable:
        return False
    pool = await get_pool()
    async with pool.acquire() as conn:
        token_hashes = await fetch_security_cvm_token_hashes(conn, _row_value(snapshot, "id"))
    try:
        shade_policy = await materialize_security_cvm_shade_policy_for_attestation(snapshot)
        request = build_security_cvm_attestation_request(
            snapshot,
            token_hashes=token_hashes,
            console_url=load_settings().raw.get("CONSOLE_URL", "http://localhost:8000"),
            shade_policy=shade_policy,
        )
        report = await verify_with_fetch_retries(
            verifier,
            request,
            timeout_seconds=security_cvm_attestation_timeout_seconds(),
        )
    except AttestationVerifierUnavailable:
        return False
    except ShadeError as exc:
        log.warning("shade_adapter_failed", operation_id=str(operation_id), **shade_error_log_fields(exc))
        await compensate_security_cvm_provision_resources(snapshot)
        await mark_security_cvm_provision_failed(
            operation_id,
            code="SHADE_BUILD_FAILED",
            details={"adapter": "shade", "reason": exc.code},
        )
        return True
    except AttestationVerifierError as exc:
        log.warning(
            "security_cvm_attestation_failed",
            operation_id=str(operation_id),
            security_cvm_id=str(_row_value(snapshot, "id")),
            code=exc.code,
            **{k: v for k, v in exc.details.items() if k != "message"},
        )
        await compensate_security_cvm_provision_resources(snapshot)
        await mark_security_cvm_provision_failed(operation_id, code=exc.code, details=exc.details)
        return True

    if report.image_measurement != _row_value(snapshot, "expected_image_measurement"):
        await compensate_security_cvm_provision_resources(snapshot)
        await mark_security_cvm_provision_failed(
            operation_id,
            code="ATTESTATION_IMAGE_MISMATCH",
            details={
                "expected_image_measurement": _row_value(snapshot, "expected_image_measurement"),
                "reported_image_measurement": report.image_measurement,
            },
        )
        return True

    async with pool.acquire() as conn:
        async with conn.transaction():
            verified_at = datetime.now(timezone.utc)
            result = await conn.execute(
                """
                UPDATE security_cvms
                SET image_measurement = $2,
                    rtmr3_digest = $3,
                    attestation_verified_at = $4,
                    metadata = $5::jsonb,
                    updated_at = now()
                WHERE id = $1
                  AND state IN ('PROVISIONING', 'RUNNING')
                  AND deleted_at IS NULL
                """,
                _row_value(snapshot, "id"),
                report.image_measurement,
                report.rtmr3_digest,
                verified_at,
                json.dumps(metadata_with_atls_policy(_row_value(snapshot, "metadata"), shade_policy)),
            )
            if result != "UPDATE 1":
                # State changed concurrently (terminated/failed) — the snapshot was fetched
                # without FOR UPDATE. Don't write a misleading "verified" audit or advance the
                # saga; return False so the caller re-evaluates on the next tick.
                log.warning(
                    "security_cvm_provision_attestation_persist_skipped",
                    operation_id=str(operation_id),
                    security_cvm_id=str(_row_value(snapshot, "id")),
                    result=result,
                )
                return False
            await insert_audit_event(
                conn,
                entity_id=_row_value(snapshot, "entity_id"),
                actor_id=_row_value(snapshot, "actor_id"),
                actor_email=_row_value(snapshot, "actor_email"),
                action="SECURITY_CVM_ATTESTATION_VERIFIED",
                target_type="security_cvm",
                target_id=_row_value(snapshot, "id"),
                before={
                    "image_measurement": _row_value(snapshot, "image_measurement"),
                    "rtmr3_digest": _row_value(snapshot, "rtmr3_digest"),
                },
                after={
                    "image_measurement": report.image_measurement,
                    "rtmr3_digest": report.rtmr3_digest,
                    "attestation_verified_at": verified_at.isoformat().replace("+00:00", "Z"),
                    "source": "provisioning",
                },
            )
            await advance_security_cvm_provision_step_with_conn(conn, operation_id, "fetch_ca")
    return True


async def execute_security_cvm_fetch_ca_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_security_cvm_provision_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_security_cvm_provision_failed(operation_id, code="SECURITY_CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "ca_cert_pem"):
        await advance_security_cvm_provision_step(operation_id, "finalise")
        return
    if not security_cvm_ca_export_stash_available(snapshot):
        await compensate_security_cvm_provision_resources(snapshot)
        await mark_security_cvm_provision_failed(operation_id, code="CA_EXPORT_TTL_EXPIRED", details={})
        return
    fqdn = _row_value(snapshot, "fqdn")
    # Pin a freshly-resolved IP for the connect: the gateway CNAME's resolution flaps for
    # minutes, so re-resolving inside open_connection can hit an NXDOMAIN gap and tear the
    # whole provision down (CA_FETCH_FAILED). Resolve once here (retrying past the gaps),
    # then connect by IP.
    connect_host = await resolve_fqdn_ip(fqdn, timeout_seconds=security_cvm_fqdn_resolve_timeout_seconds())
    if connect_host is None:
        log.warning(
            "security_cvm_ca_fetch_failed",
            operation_id=str(operation_id),
            security_cvm_id=str(_row_value(snapshot, "id")),
            fqdn=fqdn,
            http_status=0,
            reason="fqdn_unresolvable",
        )
        await compensate_security_cvm_provision_resources(snapshot)
        await mark_security_cvm_provision_failed(
            operation_id,
            code="CA_FETCH_FAILED",
            details={"http_status": 0, "reason": "fqdn_unresolvable"},
        )
        return
    try:
        ca_pem = await fetch_security_cvm_ca_pem(
            fqdn=fqdn,
            ca_export_token=_row_value(snapshot, "ca_export_token_plaintext"),
            connect_host=connect_host,
        )
    except SecurityCVMCAFetchError as exc:
        log.warning(
            "security_cvm_ca_fetch_failed",
            operation_id=str(operation_id),
            security_cvm_id=str(_row_value(snapshot, "id")),
            fqdn=fqdn,
            http_status=exc.http_status,
            reason=exc.reason,
        )
        await compensate_security_cvm_provision_resources(snapshot)
        await mark_security_cvm_provision_failed(
            operation_id,
            code="CA_FETCH_FAILED",
            details={"http_status": exc.http_status, "reason": exc.reason},
        )
        return
    await persist_security_cvm_ca_pem(operation_id, security_cvm_id=_row_value(snapshot, "id"), ca_pem=ca_pem)


async def execute_security_cvm_finalise_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_security_cvm_provision_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_security_cvm_provision_failed(operation_id, code="SECURITY_CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if not _row_value(snapshot, "ca_cert_pem"):
        await compensate_security_cvm_provision_resources(snapshot)
        await mark_security_cvm_provision_failed(operation_id, code="CA_FETCH_FAILED", details={"state": "missing_ca_cert"})
        return
    if not security_cvm_ca_export_stash_available(snapshot):
        await compensate_security_cvm_provision_resources(snapshot)
        await mark_security_cvm_provision_failed(operation_id, code="CA_EXPORT_TTL_EXPIRED", details={})
        return
    result_ca_export_token = _row_value(snapshot, "ca_export_token_plaintext")
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE security_cvms
                SET state = 'RUNNING',
                    error_reason = NULL,
                    ca_export_token_plaintext = NULL,
                    ca_export_token_stashed_at = NULL,
                    updated_at = now()
                WHERE id = $1
                  AND state = 'RUNNING'
                  AND deleted_at IS NULL
                """,
                _row_value(snapshot, "id"),
            )
            security_cvm_payload = await fetch_security_cvm_resource_for_scheduler(conn, _row_value(snapshot, "id"))
            result = {
                "security_cvm": security_cvm_payload,
                "ca_export_token": result_ca_export_token,
            }
            await insert_audit_event(
                conn,
                entity_id=_row_value(snapshot, "entity_id"),
                actor_id=_row_value(snapshot, "actor_id"),
                actor_email=_row_value(snapshot, "actor_email"),
                action="SECURITY_CVM_PROVISIONED",
                target_type="security_cvm",
                target_id=_row_value(snapshot, "id"),
                before={"state": _row_value(snapshot, "state")},
                after={"state": "RUNNING"},
            )
            await conn.execute(
                """
                UPDATE operations
                SET status = 'succeeded',
                    progress_step = 'finalise',
                    progress_percent = 100,
                    result = $2::jsonb,
                    error = NULL,
                    updated_at = now(),
                    expires_at = $3
                WHERE id = $1
                  AND kind = 'security_cvm.provision'
                  AND status = 'running'
                """,
                operation_id,
                json.dumps(result),
                operation_expiry(),
            )


async def execute_security_cvm_update_phala_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_security_cvm_update_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_security_cvm_update_failed(operation_id, code="SECURITY_CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "state") not in {"RUNNING", "STOPPED", "FAILED"}:
        await mark_security_cvm_update_failed(operation_id, code="INVALID_STATE", details={"state": _row_value(snapshot, "state")})
        return
    deployment_id = provider_deployment_id(_row_value(snapshot, "metadata"))
    if deployment_id is None:
        await mark_security_cvm_update_failed(
            operation_id,
            code="PROVIDER_DEPLOYMENT_MISSING",
            details={"field": "metadata.deployment_id"},
        )
        return
    try:
        update_material = security_cvm_update_material()
    except ValueError as exc:
        await mark_security_cvm_update_failed(
            operation_id,
            code=str(exc),
            details={"component": "security_cvm_update_config"},
        )
        return

    from concrete_console.shade_provider.shade import ShadeClient, ShadeError
    from concrete_console.tee_provider import CvmProviderError, cvm_provider_from_settings

    env: dict[str, str] | None = None
    bearers: dict[str, str] | None = None
    try:
        name = security_cvm_provider_name_from_metadata(snapshot)
        shade_result = await ShadeClient.from_settings().build(
            shade_config_yaml=render_security_cvm_shade_config(snapshot, name=name),
            app_compose_yaml=update_material["compose_config"],
        )
        bearers = mint_security_cvm_provision_bearers()
        await persist_security_cvm_update_bearers(
            operation_id,
            snapshot,
            ingest_token_hash=bearers["ingest_token_hash"],
            ca_export_token_hash=bearers["ca_export_token_hash"],
            ca_export_token_plaintext=bearers["ca_export_token"],
        )
        env = build_security_cvm_provision_env(
            snapshot,
            ingest_token=bearers["ingest_token"],
            ca_export_token=bearers["ca_export_token"],
        )
        deploy_result = await cvm_provider_from_settings(
            timeout_seconds=provider_update_timeout_seconds()
        ).update_deployment(
            deployment_id=deployment_id,
            compose_yaml=shade_result.compose_yaml,
            env=env,
        )
    except ShadeError as exc:
        log.warning("shade_adapter_failed", operation_id=str(operation_id), **shade_error_log_fields(exc))
        await mark_security_cvm_update_failed(
            operation_id,
            code="SHADE_BUILD_FAILED",
            details={"adapter": "shade", "reason": exc.code},
        )
        return
    except CvmProviderError as exc:
        log.warning(
            "security_cvm_update_provider_update_failed",
            operation_id=str(operation_id),
            **provider_error_log_fields(exc),
        )
        await mark_security_cvm_update_failed(
            operation_id,
            code="PROVIDER_UPDATE_FAILED",
            details={"adapter": "cvm_provider", "reason": exc.code},
        )
        return
    finally:
        if env is not None:
            env["CONSOLE_INGEST_TOKEN"] = ""
            env["CA_EXPORT_TOKEN"] = ""
        if bearers is not None:
            bearers["ingest_token"] = ""
            bearers["ca_export_token"] = ""

    metadata = security_cvm_update_metadata(
        _row_value(snapshot, "metadata"),
        name=name,
        deployment_id=deploy_result.deployment_id,
        gateway_host=deploy_result.gateway_host,
        status=deploy_result.status,
        deploy_compose_yaml=shade_result.compose_yaml,
    )
    if _row_value(snapshot, "ca_cert_pem"):
        metadata["previous_ca_cert_sha256"] = sha256_text(_row_value(snapshot, "ca_cert_pem"))
    await persist_security_cvm_update_provider_result(
        operation_id,
        snapshot,
        metadata=metadata,
        compose_config=update_material["compose_config"],
        expected_image_measurement=update_material["expected_image_measurement"],
    )


async def execute_security_cvm_update_await_phala_running_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_security_cvm_update_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_security_cvm_update_failed(operation_id, code="SECURITY_CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    deployment_id = provider_deployment_id(_row_value(snapshot, "metadata"))
    if deployment_id is None:
        await mark_security_cvm_update_failed(
            operation_id,
            code="PROVIDER_DEPLOYMENT_MISSING",
            details={"field": "metadata.deployment_id"},
        )
        return

    from concrete_console.tee_provider import CvmProviderError, cvm_provider_from_settings

    try:
        provider_status = await cvm_provider_from_settings(timeout_seconds=30.0).status(deployment_id)
    except CvmProviderError as exc:
        log.warning(
            "security_cvm_update_provider_status_failed",
            security_cvm_id=str(_row_value(snapshot, "id")),
            reason=exc.code,
        )
        return
    if provider_status == "RUNNING":
        await advance_security_cvm_update_step(operation_id, "verify_attestation")
        return
    if provider_status == "FAILED":
        await mark_security_cvm_update_failed(
            operation_id,
            code="PROVIDER_UPDATE_FAILED",
            details={"adapter": "cvm_provider", "reason": "provider_status_failed"},
            mark_security_cvm_failed=True,
        )
        return
    log.info(
        "security_cvm_update_await_provider_pending",
        operation_id=str(operation_id),
        security_cvm_id=str(_row_value(snapshot, "id")),
        provider_status=provider_status,
    )


async def execute_security_cvm_update_attestation_gate_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_security_cvm_update_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_security_cvm_update_failed(operation_id, code="SECURITY_CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "image_measurement") is None or _row_value(snapshot, "attestation_verified_at") is None:
        verified = await run_security_cvm_update_attestation_verifier(operation_id, snapshot)
        if verified:
            return
        log.info(
            "security_cvm_update_attestation_waiting",
            operation_id=str(operation_id),
            security_cvm_id=str(_row_value(snapshot, "id")),
        )
        return
    if _row_value(snapshot, "image_measurement") != _row_value(snapshot, "expected_image_measurement"):
        await mark_security_cvm_update_failed(
            operation_id,
            code="ATTESTATION_IMAGE_MISMATCH",
            details={
                "expected": _row_value(snapshot, "expected_image_measurement"),
                "actual": _row_value(snapshot, "image_measurement"),
            },
            mark_security_cvm_failed=True,
        )
        return
    if _row_value(snapshot, "rtmr3_digest") is None:
        await mark_security_cvm_update_failed(
            operation_id,
            code="ATTESTATION_RTMR_MISMATCH",
            details={"state": "missing_rtmr3_digest"},
            mark_security_cvm_failed=True,
        )
        return
    await advance_security_cvm_update_step(operation_id, "fetch_ca")


async def run_security_cvm_update_attestation_verifier(operation_id: Any, snapshot: Any) -> bool:
    from concrete_console.attestation import (
        AtlasVerifierClient,
        AttestationVerifierError,
        AttestationVerifierUnavailable,
        build_security_cvm_attestation_request,
        verify_with_fetch_retries,
    )
    from concrete_console.shade_provider.shade import ShadeError

    try:
        verifier = AtlasVerifierClient.from_settings()
    except AttestationVerifierUnavailable:
        return False
    pool = await get_pool()
    async with pool.acquire() as conn:
        token_hashes = await fetch_security_cvm_token_hashes(conn, _row_value(snapshot, "id"))
    try:
        shade_policy = await materialize_security_cvm_shade_policy_for_attestation(snapshot)
        request = build_security_cvm_attestation_request(
            snapshot,
            token_hashes=token_hashes,
            console_url=load_settings().raw.get("CONSOLE_URL", "http://localhost:8000"),
            shade_policy=shade_policy,
        )
        report = await verify_with_fetch_retries(
            verifier,
            request,
            timeout_seconds=security_cvm_attestation_timeout_seconds(),
        )
    except AttestationVerifierUnavailable:
        return False
    except ShadeError as exc:
        log.warning("shade_adapter_failed", operation_id=str(operation_id), **shade_error_log_fields(exc))
        await mark_security_cvm_update_failed(
            operation_id,
            code="SHADE_BUILD_FAILED",
            details={"adapter": "shade", "reason": exc.code},
        )
        return True
    except AttestationVerifierError as exc:
        await mark_security_cvm_update_failed(operation_id, code=exc.code, details=exc.details, mark_security_cvm_failed=True)
        return True

    if report.image_measurement != _row_value(snapshot, "expected_image_measurement"):
        await mark_security_cvm_update_failed(
            operation_id,
            code="ATTESTATION_IMAGE_MISMATCH",
            details={
                "expected_image_measurement": _row_value(snapshot, "expected_image_measurement"),
                "reported_image_measurement": report.image_measurement,
            },
            mark_security_cvm_failed=True,
        )
        return True

    async with pool.acquire() as conn:
        async with conn.transaction():
            verified_at = datetime.now(timezone.utc)
            result = await conn.execute(
                """
                UPDATE security_cvms
                SET image_measurement = $2,
                    rtmr3_digest = $3,
                    attestation_verified_at = $4,
                    metadata = $5::jsonb,
                    updated_at = now()
                WHERE id = $1
                  AND state IN ('RUNNING', 'STOPPED', 'FAILED')
                  AND deleted_at IS NULL
                """,
                _row_value(snapshot, "id"),
                report.image_measurement,
                report.rtmr3_digest,
                verified_at,
                json.dumps(metadata_with_atls_policy(_row_value(snapshot, "metadata"), shade_policy)),
            )
            if result != "UPDATE 1":
                # State changed concurrently — don't write a misleading "verified" audit or
                # advance the saga; return False so the caller re-evaluates on the next tick.
                log.warning(
                    "security_cvm_update_attestation_persist_skipped",
                    operation_id=str(operation_id),
                    security_cvm_id=str(_row_value(snapshot, "id")),
                    result=result,
                )
                return False
            await insert_audit_event(
                conn,
                entity_id=_row_value(snapshot, "entity_id"),
                actor_id=_row_value(snapshot, "actor_id"),
                actor_email=_row_value(snapshot, "actor_email"),
                action="SECURITY_CVM_ATTESTATION_VERIFIED",
                target_type="security_cvm",
                target_id=_row_value(snapshot, "id"),
                before={
                    "image_measurement": _row_value(snapshot, "image_measurement"),
                    "rtmr3_digest": _row_value(snapshot, "rtmr3_digest"),
                },
                after={
                    "image_measurement": report.image_measurement,
                    "rtmr3_digest": report.rtmr3_digest,
                    "attestation_verified_at": verified_at.isoformat().replace("+00:00", "Z"),
                    "source": "update",
                },
            )
            await advance_security_cvm_update_step_with_conn(conn, operation_id, "fetch_ca")
    return True


async def execute_security_cvm_update_fetch_ca_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_security_cvm_update_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_security_cvm_update_failed(operation_id, code="SECURITY_CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if not security_cvm_ca_export_stash_available(snapshot):
        await mark_security_cvm_update_failed(operation_id, code="CA_EXPORT_TTL_EXPIRED", details={})
        return
    try:
        ca_pem = await fetch_security_cvm_ca_pem(
            fqdn=_row_value(snapshot, "fqdn"),
            ca_export_token=_row_value(snapshot, "ca_export_token_plaintext"),
        )
    except SecurityCVMCAFetchError as exc:
        log.warning(
            "security_cvm_ca_fetch_failed",
            operation_id=str(operation_id),
            security_cvm_id=str(_row_value(snapshot, "id")),
            fqdn=_row_value(snapshot, "fqdn"),
            http_status=exc.http_status,
            reason=exc.reason,
            phase="update",
        )
        await mark_security_cvm_update_failed(
            operation_id,
            code="CA_FETCH_FAILED",
            details={"http_status": exc.http_status, "reason": exc.reason},
        )
        return
    await persist_security_cvm_update_ca_pem(operation_id, security_cvm_id=_row_value(snapshot, "id"), ca_pem=ca_pem)


async def execute_security_cvm_update_finalise_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_security_cvm_update_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_security_cvm_update_failed(operation_id, code="SECURITY_CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if not _row_value(snapshot, "ca_cert_pem"):
        await mark_security_cvm_update_failed(operation_id, code="CA_FETCH_FAILED", details={"state": "missing_ca_cert"})
        return
    metadata = json_payload(_row_value(snapshot, "metadata") or {})
    previous_ca_sha256 = metadata.get("previous_ca_cert_sha256") if isinstance(metadata, dict) else None
    current_ca_sha256 = sha256_text(_row_value(snapshot, "ca_cert_pem"))
    ca_changed = previous_ca_sha256 != current_ca_sha256
    final_metadata = dict(metadata) if isinstance(metadata, dict) else {}
    final_metadata.pop("previous_ca_cert_sha256", None)
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE security_cvms
                SET state = 'RUNNING',
                    error_reason = NULL,
                    metadata = $2::jsonb,
                    ca_export_token_plaintext = NULL,
                    ca_export_token_stashed_at = NULL,
                    policy_version = policy_version + 1,
                    updated_at = now()
                WHERE id = $1
                  AND state IN ('RUNNING', 'STOPPED', 'FAILED')
                  AND deleted_at IS NULL
                """,
                _row_value(snapshot, "id"),
                json.dumps(final_metadata),
            )
            impacted_dev_cvms: list[str] = []
            if ca_changed:
                impacted_rows = await conn.fetch(
                    """
                    UPDATE cvms
                    SET error_reason = 'SECURITY_CVM_REBIND_REQUIRED',
                        updated_at = now()
                    WHERE security_cvm_id = $1
                      AND state IN ('RUNNING', 'STOPPED')
                      AND deleted_at IS NULL
                    RETURNING id
                    """,
                    _row_value(snapshot, "id"),
                )
                impacted_dev_cvms = [str(row["id"]) for row in impacted_rows]
            security_cvm_payload = await fetch_security_cvm_resource_for_scheduler(conn, _row_value(snapshot, "id"))
            result = {
                "security_cvm": security_cvm_payload,
                "dev_cvms_requiring_update": impacted_dev_cvms,
            }
            await insert_audit_event(
                conn,
                entity_id=_row_value(snapshot, "entity_id"),
                actor_id=_row_value(snapshot, "actor_id"),
                actor_email=_row_value(snapshot, "actor_email"),
                action="SECURITY_CVM_UPDATED",
                target_type="security_cvm",
                target_id=_row_value(snapshot, "id"),
                before={"state": _row_value(snapshot, "state")},
                after={
                    "state": "RUNNING",
                    "ca_changed": ca_changed,
                    "dev_cvms_requiring_update": impacted_dev_cvms,
                },
            )
            await conn.execute(
                """
                UPDATE operations
                SET status = 'succeeded',
                    progress_step = 'finalise',
                    progress_percent = 100,
                    result = $2::jsonb,
                    error = NULL,
                    updated_at = now(),
                    expires_at = $3
                WHERE id = $1
                  AND kind = 'security_cvm.update'
                  AND status = 'running'
                """,
                operation_id,
                json.dumps(result),
                operation_expiry(),
            )


async def execute_cvm_launch_phala_deploy_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_launch_snapshot(conn, operation_id)
        if snapshot is not None:
            public_keys = await fetch_cvm_launch_public_keys(conn, _row_value(snapshot, "cvm_id"))
            profile_rows = await fetch_cvm_launch_profile_policies(conn, _row_value(snapshot, "cvm_id"))
    if snapshot is None:
        await mark_cvm_launch_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "state") != "PROVISIONING":
        await mark_cvm_launch_failed(
            operation_id,
            code="INVALID_STATE",
            details={"state": _row_value(snapshot, "state")},
        )
        return
    if not _row_value(snapshot, "security_cvm_ca_cert_pem"):
        await mark_cvm_launch_failed(
            operation_id,
            code="SECURITY_CVM_CA_UNAVAILABLE",
            details={"component": "security_cvm_ca_cert"},
        )
        return
    if stored_security_cvm_atls_policy(snapshot) is None:
        await mark_cvm_launch_failed(
            operation_id,
            code="SECURITY_CVM_ATLS_POLICY_UNAVAILABLE",
            details={"component": "security_cvm_atls_policy"},
        )
        return

    from concrete_console.shade_provider.shade import ShadeClient, ShadeError
    from concrete_console.tee_provider.phala import PhalaClient, PhalaError

    proxy_token = secrets.token_urlsafe(32)
    dev_control_token = secrets.token_urlsafe(32)
    try:
        env, binding = build_cvm_launch_env(
            snapshot,
            public_keys=public_keys,
            profile_rows=profile_rows,
            proxy_token=proxy_token,
            dev_control_token=dev_control_token,
        )
        name = cvm_launch_provider_name(_row_value(snapshot, "cvm_id"))
        shade_result = await ShadeClient.from_settings().build(
            shade_config_yaml=render_dev_cvm_shade_config(snapshot, name=name),
            app_compose_yaml=_row_value(snapshot, "compose_config"),
        )
        deploy_result = await PhalaClient.from_settings().deploy(
            name=name,
            compose_yaml=shade_result.compose_yaml,
            env=env,
            instance_type=_row_value(snapshot, "instance_type"),
            region=_row_value(snapshot, "region"),
            disk_size_gb=_row_value(snapshot, "disk_size_gb"),
        )
    except ShadeError as exc:
        log.warning("shade_adapter_failed", operation_id=str(operation_id), **shade_error_log_fields(exc))
        await mark_cvm_launch_failed(
            operation_id,
            code="SHADE_BUILD_FAILED",
            details={"adapter": "shade", "reason": exc.code},
        )
        return
    except PhalaError as exc:
        log.warning(
            "phala_adapter_failed",
            operation_id=str(operation_id),
            step="phala_deploy",
            **phala_error_log_fields(exc),
        )
        await mark_cvm_launch_failed(
            operation_id,
            code="PHALA_DEPLOY_FAILED",
            details=phala_error_log_fields(exc),
        )
        return
    finally:
        if "env" in locals():
            env["SECURITY_CVM_PROXY_TOKEN"] = ""
            env["DEV_CVM_CONTROL_TOKEN"] = ""
        proxy_token = ""
        dev_control_token = ""

    metadata = cvm_launch_metadata(
        name=name,
        app_id=deploy_result.app_id,
        gateway_host=deploy_result.gateway_host,
        status=deploy_result.status,
        policy_bundle=build_cvm_policy_bundle(
            snapshot,
            rtmr3_binding=binding,
            deploy_compose_yaml=shade_result.compose_yaml,
        ),
    )
    await persist_cvm_launch_phala_result(
        operation_id,
        cvm_id=_row_value(snapshot, "cvm_id"),
        actor_id=_row_value(snapshot, "actor_id"),
        metadata=metadata,
        proxy_token_hash=binding["security_cvm_proxy_token_sha256"],
        dev_control_token_hash=binding["dev_cvm_control_token_sha256"],
    )


async def execute_cvm_launch_txt_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_launch_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_cvm_launch_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "txt_dns_record_id"):
        await advance_cvm_launch_step(operation_id, "cf_cname_create")
        return
    app_id = provider_app_id(_row_value(snapshot, "metadata"))
    if app_id is None:
        await mark_cvm_launch_failed(operation_id, code="PHALA_APP_MISSING", details={"field": "metadata.app_id"})
        return

    from concrete_console.dns_provider.cloudflare import CloudflareClient, CloudflareError

    try:
        record_id = await CloudflareClient.from_settings().ensure_dstack_txt(
            fqdn=_row_value(snapshot, "fqdn"),
            app_id=app_id,
        )
    except CloudflareError as exc:
        await compensate_cvm_launch_resources(snapshot)
        await mark_cvm_launch_failed(
            operation_id,
            code="CLOUDFLARE_TXT_FAILED",
            details={"adapter": "cloudflare", "reason": exc.code},
        )
        return
    await persist_cvm_dns_record(operation_id, cvm_id=_row_value(snapshot, "cvm_id"), field="txt", record_id=record_id)


async def execute_cvm_launch_cname_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_launch_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_cvm_launch_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "cname_dns_record_id"):
        await advance_cvm_launch_step(operation_id, "verify_attestation")
        return
    gateway_host = provider_gateway_host(_row_value(snapshot, "metadata"))
    if gateway_host is None:
        await mark_cvm_launch_failed(
            operation_id,
            code="PHALA_GATEWAY_MISSING",
            details={"field": "metadata.gateway_host"},
        )
        return

    from concrete_console.dns_provider.cloudflare import CloudflareClient, CloudflareError

    try:
        record_id = await CloudflareClient.from_settings().ensure_gateway_cname(
            fqdn=_row_value(snapshot, "fqdn"),
            gateway_host=gateway_host,
        )
    except CloudflareError as exc:
        await compensate_cvm_launch_resources(snapshot)
        await mark_cvm_launch_failed(
            operation_id,
            code="CLOUDFLARE_CNAME_FAILED",
            details={"adapter": "cloudflare", "reason": exc.code},
        )
        return
    await persist_cvm_dns_record(
        operation_id,
        cvm_id=_row_value(snapshot, "cvm_id"),
        field="cname",
        record_id=record_id,
    )


async def execute_cvm_launch_attestation_gate_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_launch_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_cvm_launch_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "image_measurement") is None or _row_value(snapshot, "attestation_verified_at") is None:
        verified = await run_cvm_launch_attestation_verifier(operation_id, snapshot)
        if verified:
            return
        if _row_value(snapshot, "image_measurement") is None or _row_value(snapshot, "attestation_verified_at") is None:
            log.info(
                "cvm_launch_attestation_waiting",
                operation_id=str(operation_id),
                cvm_id=str(_row_value(snapshot, "cvm_id")),
            )
        return
    if _row_value(snapshot, "image_measurement") != _row_value(snapshot, "expected_image_measurement"):
        await mark_cvm_launch_failed(
            operation_id,
            code="ATTESTATION_IMAGE_MISMATCH",
            details={
                "expected": _row_value(snapshot, "expected_image_measurement"),
                "actual": _row_value(snapshot, "image_measurement"),
            },
        )
        return
    if _row_value(snapshot, "rtmr3_digest") is None:
        await mark_cvm_launch_failed(
            operation_id,
            code="ATTESTATION_RTMR_MISMATCH",
            details={"state": "missing_rtmr3_digest"},
        )
        return
    await advance_cvm_launch_step(operation_id, "await_sc_pull")


async def run_cvm_launch_attestation_verifier(operation_id: Any, snapshot: Any) -> bool:
    from concrete_console.attestation import (
        AtlasVerifierClient,
        AttestationVerifierError,
        AttestationVerifierUnavailable,
        build_dev_cvm_attestation_request,
        verify_with_fetch_retries,
    )
    from concrete_console.shade_provider.shade import ShadeError

    try:
        verifier = AtlasVerifierClient.from_settings()
        policy_bundle = await materialize_cvm_policy_bundle_for_attestation(
            snapshot,
            bundle_key="policy_bundle",
        )
        metadata = metadata_with_policy_bundle(_row_value(snapshot, "metadata"), policy_bundle)
        request_snapshot = dict(snapshot)
        request_snapshot["metadata"] = metadata
        request = build_dev_cvm_attestation_request(request_snapshot)
        report = await verify_with_fetch_retries(
            verifier,
            request,
            timeout_seconds=dev_cvm_attestation_timeout_seconds(),
        )
    except ShadeError as exc:
        log.warning("shade_adapter_failed", operation_id=str(operation_id), **shade_error_log_fields(exc))
        await compensate_cvm_launch_resources(snapshot)
        await mark_cvm_launch_failed(
            operation_id,
            code="SHADE_BUILD_FAILED",
            details={"adapter": "shade", "reason": exc.code},
        )
        return True
    except AttestationVerifierUnavailable:
        return False
    except AttestationVerifierError as exc:
        await compensate_cvm_launch_resources(snapshot)
        await mark_cvm_launch_failed(operation_id, code=exc.code, details=exc.details)
        return True

    if report.image_measurement != _row_value(snapshot, "expected_image_measurement"):
        await compensate_cvm_launch_resources(snapshot)
        await mark_cvm_launch_failed(
            operation_id,
            code="ATTESTATION_IMAGE_MISMATCH",
            details={
                "expected_image_measurement": _row_value(snapshot, "expected_image_measurement"),
                "reported_image_measurement": report.image_measurement,
            },
        )
        return True

    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            verified_at = datetime.now(timezone.utc)
            result = await conn.execute(
                """
                UPDATE cvms
                SET image_measurement = $2,
                    rtmr3_digest = $3,
                    attestation_verified_at = $4,
                    metadata = $5::jsonb,
                    updated_at = now()
                WHERE id = $1
                  AND state = 'PROVISIONING'
                """,
                _row_value(snapshot, "cvm_id"),
                report.image_measurement,
                report.rtmr3_digest,
                verified_at,
                json.dumps(metadata),
            )
            if result != "UPDATE 1":
                # State changed concurrently (terminated/failed) — the snapshot was fetched
                # without FOR UPDATE. Don't write a misleading "verified" audit or advance the
                # saga; return False so the caller re-evaluates on the next tick.
                log.warning(
                    "cvm_launch_attestation_persist_skipped",
                    operation_id=str(operation_id),
                    cvm_id=str(_row_value(snapshot, "cvm_id")),
                    result=result,
                )
                return False
            await insert_audit_event(
                conn,
                entity_id=_row_value(snapshot, "entity_id"),
                actor_id=_row_value(snapshot, "actor_id"),
                actor_email=_row_value(snapshot, "actor_email"),
                action="CVM_ATTESTATION_VERIFIED",
                target_type="cvm",
                target_id=_row_value(snapshot, "cvm_id"),
                before={
                    "image_measurement": _row_value(snapshot, "image_measurement"),
                    "rtmr3_digest": _row_value(snapshot, "rtmr3_digest"),
                },
                after={
                    "image_measurement": report.image_measurement,
                    "rtmr3_digest": report.rtmr3_digest,
                    "attestation_verified_at": verified_at.isoformat().replace("+00:00", "Z"),
                    "source": "launch",
                },
            )
            await advance_cvm_launch_step_with_conn(conn, operation_id, "await_sc_pull")
    return True


async def execute_cvm_launch_await_sc_pull_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_launch_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_cvm_launch_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    proxy_token_created_at = _row_value(snapshot, "proxy_token_created_at")
    if proxy_token_created_at is None:
        await compensate_cvm_launch_resources(snapshot)
        await mark_cvm_launch_failed(
            operation_id,
            code="PROXY_AUTH_MISSING",
            details={"state": "missing_proxy_token"},
        )
        return
    last_pull_at = _row_value(snapshot, "security_cvm_last_policy_pull_at")
    if last_pull_at is not None and last_pull_at >= proxy_token_created_at:
        log.info(
            "cvm_launch_sc_pull_observed",
            operation_id=str(operation_id),
            cvm_id=str(_row_value(snapshot, "cvm_id")),
            security_cvm_id=str(_row_value(snapshot, "security_cvm_id")),
            pull_etag=_row_value(snapshot, "security_cvm_last_policy_pull_etag"),
        )
        await advance_cvm_launch_step(operation_id, "policy_push")
        return
    elapsed = datetime.now(timezone.utc) - proxy_token_created_at
    timeout = timedelta(seconds=sc_pull_propagation_timeout_seconds())
    if elapsed < timeout:
        log.info(
            "cvm_launch_awaiting_sc_pull",
            operation_id=str(operation_id),
            cvm_id=str(_row_value(snapshot, "cvm_id")),
            security_cvm_id=str(_row_value(snapshot, "security_cvm_id")),
            elapsed_seconds=int(elapsed.total_seconds()),
            timeout_seconds=int(timeout.total_seconds()),
        )
        return
    log.warning(
        "cvm_launch_sc_pull_observation_stale",
        operation_id=str(operation_id),
        cvm_id=str(_row_value(snapshot, "cvm_id")),
        security_cvm_id=str(_row_value(snapshot, "security_cvm_id")),
        elapsed_seconds=int(elapsed.total_seconds()),
        timeout_seconds=int(timeout.total_seconds()),
    )
    await compensate_cvm_launch_resources(snapshot)
    await mark_cvm_launch_failed(
        operation_id,
        code="SC_PULL_TIMEOUT",
        details={
            "elapsed_seconds": int(elapsed.total_seconds()),
            "timeout_seconds": int(timeout.total_seconds()),
        },
    )


async def execute_cvm_launch_policy_push_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_launch_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_cvm_launch_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    async with pool.acquire() as conn:
        async with conn.transaction():
            metadata = json_payload(_row_value(snapshot, "metadata") or {})
            if not isinstance(metadata, dict):
                metadata = {}
            if metadata.get("launch_policy_pushed") is not True:
                await conn.execute(
                    """
                    UPDATE cvms
                    SET policy_version = policy_version + 1,
                        metadata = jsonb_set(metadata, '{launch_policy_pushed}', 'true'::jsonb, true),
                        updated_at = now()
                    WHERE id = $1
                    """,
                    _row_value(snapshot, "cvm_id"),
                )
                await conn.execute(
                    """
                    UPDATE security_cvms
                    SET policy_version = policy_version + 1,
                        updated_at = now()
                    WHERE id = $1
                    """,
                    _row_value(snapshot, "security_cvm_id"),
                )
            await advance_cvm_launch_step_with_conn(conn, operation_id, "finalise")


async def execute_cvm_launch_finalise_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_launch_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_cvm_launch_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    metadata = json_payload(_row_value(snapshot, "metadata") or {})
    if not isinstance(metadata, dict) or not isinstance(metadata.get("policy_bundle"), dict):
        await compensate_cvm_launch_resources(snapshot)
        await mark_cvm_launch_failed(
            operation_id,
            code="POLICY_BUNDLE_MISSING",
            details={"field": "metadata.policy_bundle"},
        )
        return
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE cvms
                SET state = 'RUNNING',
                    error_reason = NULL,
                    atls_policy_bundle = $2::jsonb,
                    atls_policy_revision = atls_policy_revision + 1,
                    updated_at = now()
                WHERE id = $1
                  AND state = 'PROVISIONING'
                """,
                _row_value(snapshot, "cvm_id"),
                json.dumps(metadata["policy_bundle"]),
            )
            cvm_payload = await fetch_cvm_resource_for_scheduler(conn, _row_value(snapshot, "cvm_id"))
            policy_version = await conn.fetchval(
                """
                SELECT policy_version
                FROM cvms
                WHERE id = $1
                """,
                _row_value(snapshot, "cvm_id"),
            )
            result = {"cvm": cvm_payload, "policy_bundle": metadata["policy_bundle"]}
            await insert_audit_event(
                conn,
                entity_id=_row_value(snapshot, "entity_id"),
                actor_id=_row_value(snapshot, "actor_id"),
                actor_email=_row_value(snapshot, "actor_email"),
                action="CVM_LAUNCHED",
                target_type="cvm",
                target_id=_row_value(snapshot, "cvm_id"),
                before={"state": _row_value(snapshot, "state")},
                after={"state": "RUNNING"},
            )
            await insert_audit_event(
                conn,
                entity_id=_row_value(snapshot, "entity_id"),
                actor_id=_row_value(snapshot, "actor_id"),
                actor_email=_row_value(snapshot, "actor_email"),
                action="SUBDOMAIN_PROVISIONED",
                target_type="cvm",
                target_id=_row_value(snapshot, "cvm_id"),
                before={"txt_dns_record_id": None, "cname_dns_record_id": None},
                after={
                    "txt_dns_record_id": _row_value(snapshot, "txt_dns_record_id"),
                    "cname_dns_record_id": _row_value(snapshot, "cname_dns_record_id"),
                },
            )
            for profile in await fetch_cvm_launch_profiles_for_audit(conn, _row_value(snapshot, "cvm_id")):
                await insert_audit_event(
                    conn,
                    entity_id=_row_value(snapshot, "entity_id"),
                    actor_id=_row_value(snapshot, "actor_id"),
                    actor_email=_row_value(snapshot, "actor_email"),
                    action="CVM_PROFILE_ATTACHED",
                    target_type="cvm_profile",
                    target_id=profile["profile_id"],
                    before=None,
                    after={
                        "cvm_id": str(_row_value(snapshot, "cvm_id")),
                        "profile_id": str(profile["profile_id"]),
                        "profile_name": profile["profile_name"],
                        "policy_version": policy_version,
                    },
                )
            await conn.execute(
                """
                UPDATE operations
                SET status = 'succeeded',
                    progress_step = 'finalise',
                    progress_percent = 100,
                    result = $2::jsonb,
                    error = NULL,
                    updated_at = now(),
                    expires_at = $3
                WHERE id = $1
                  AND status = 'running'
                """,
                operation_id,
                json.dumps(result),
                operation_expiry(),
            )


async def execute_cvm_update_phala_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_update_snapshot(conn, operation_id)
        if snapshot is not None:
            public_keys = await fetch_cvm_launch_public_keys(conn, _row_value(snapshot, "cvm_id"))
            profile_rows = await fetch_cvm_launch_profile_policies(conn, _row_value(snapshot, "cvm_id"))
    if snapshot is None:
        await mark_cvm_update_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "state") not in {"RUNNING", "STOPPED", "FAILED"}:
        await mark_cvm_update_failed(operation_id, code="INVALID_STATE", details={"state": _row_value(snapshot, "state")})
        return
    if not _row_value(snapshot, "security_cvm_ca_cert_pem"):
        await mark_cvm_update_failed(
            operation_id,
            code="SECURITY_CVM_CA_UNAVAILABLE",
            details={"component": "security_cvm_ca_cert"},
        )
        return
    if stored_security_cvm_atls_policy(snapshot) is None:
        await mark_cvm_update_failed(
            operation_id,
            code="SECURITY_CVM_ATLS_POLICY_UNAVAILABLE",
            details={"component": "security_cvm_atls_policy"},
        )
        return
    deployment_id = provider_deployment_id(_row_value(snapshot, "metadata"))
    if deployment_id is None:
        await mark_cvm_update_failed(operation_id, code="PROVIDER_DEPLOYMENT_MISSING", details={"field": "metadata.deployment_id"})
        return
    try:
        update_material = dev_cvm_update_material()
    except ValueError as exc:
        await mark_cvm_update_failed(operation_id, code=str(exc), details={"component": "dev_cvm_update_config"})
        return

    from concrete_console.shade_provider.shade import ShadeClient, ShadeError
    from concrete_console.tee_provider import CvmProviderError, cvm_provider_from_settings

    proxy_token = secrets.token_urlsafe(32)
    dev_control_token = secrets.token_urlsafe(32)
    try:
        env, binding = build_cvm_launch_env(
            snapshot,
            public_keys=public_keys,
            profile_rows=profile_rows,
            proxy_token=proxy_token,
            dev_control_token=dev_control_token,
        )
        shade_client = ShadeClient.from_settings()
        shade_result = await shade_client.build(
            shade_config_yaml=render_dev_cvm_shade_config(snapshot, name=cvm_provider_name_from_metadata(snapshot)),
            app_compose_yaml=update_material["compose_config"],
        )
        deploy_result = await cvm_provider_from_settings(
            timeout_seconds=provider_update_timeout_seconds()
        ).update_deployment(
            deployment_id=deployment_id,
            compose_yaml=shade_result.compose_yaml,
            env=env,
        )
    except ShadeError as exc:
        log.warning("shade_adapter_failed", operation_id=str(operation_id), **shade_error_log_fields(exc))
        await mark_cvm_update_failed(
            operation_id,
            code="SHADE_BUILD_FAILED",
            details={"adapter": "shade", "reason": exc.code},
        )
        return
    except CvmProviderError as exc:
        log.warning(
            "cvm_update_provider_update_failed",
            operation_id=str(operation_id),
            **provider_error_log_fields(exc),
        )
        await mark_cvm_update_failed(
            operation_id,
            code="PROVIDER_UPDATE_FAILED",
            details={"adapter": "cvm_provider", "reason": exc.code},
        )
        return
    finally:
        if "env" in locals():
            env["SECURITY_CVM_PROXY_TOKEN"] = ""
            env["DEV_CVM_CONTROL_TOKEN"] = ""
        proxy_token = ""
        dev_control_token = ""

    policy_snapshot = dict(snapshot)
    policy_snapshot["compose_config"] = update_material["compose_config"]
    pending_policy_bundle = build_cvm_policy_bundle(
        policy_snapshot,
        rtmr3_binding=binding,
        deploy_compose_yaml=shade_result.compose_yaml,
    )
    metadata = cvm_update_metadata(
        _row_value(snapshot, "metadata"),
        deployment_id=deploy_result.deployment_id,
        gateway_host=deploy_result.gateway_host,
        status=deploy_result.status,
        pending_policy_bundle=pending_policy_bundle,
    )
    await persist_cvm_update_provider_result(
        operation_id,
        cvm_id=_row_value(snapshot, "cvm_id"),
        actor_id=_row_value(snapshot, "actor_id"),
        metadata=metadata,
        compose_config=update_material["compose_config"],
        expected_image_measurement=update_material["expected_image_measurement"],
        proxy_token_hash=binding["security_cvm_proxy_token_sha256"],
        dev_control_token_hash=binding["dev_cvm_control_token_sha256"],
    )


async def execute_cvm_update_await_provider_running_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_update_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_cvm_update_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    deployment_id = provider_deployment_id(_row_value(snapshot, "metadata"))
    if deployment_id is None:
        await mark_cvm_update_failed(operation_id, code="PROVIDER_DEPLOYMENT_MISSING", details={"field": "metadata.deployment_id"})
        return

    from concrete_console.tee_provider import CvmProviderError, cvm_provider_from_settings

    try:
        provider = cvm_provider_from_settings(timeout_seconds=30.0)
        provider_status = await provider.status(deployment_id)
    except CvmProviderError as exc:
        log.warning(
            "cvm_update_provider_status_failed",
            cvm_id=str(_row_value(snapshot, "cvm_id")),
            reason=exc.code,
        )
        return
    if provider_status == "RUNNING":
        expected_compose_sha256 = pending_update_deploy_compose_sha256(_row_value(snapshot, "metadata"))
        if expected_compose_sha256 is not None:
            try:
                provider_compose_sha256 = await provider.deployment_compose_sha256(deployment_id)
            except CvmProviderError as exc:
                log.warning(
                    "cvm_update_provider_compose_hash_failed",
                    operation_id=str(operation_id),
                    cvm_id=str(_row_value(snapshot, "cvm_id")),
                    **provider_error_log_fields(exc),
                )
                return
            if provider_compose_sha256 != expected_compose_sha256:
                if cvm_update_provider_wait_timed_out(snapshot):
                    await mark_cvm_update_failed(
                        operation_id,
                        code="PROVIDER_COMPOSE_NOT_APPLIED",
                        details={
                            "adapter": "cvm_provider",
                            "expected_compose_sha256": expected_compose_sha256,
                            "provider_compose_sha256": provider_compose_sha256,
                        },
                    )
                    return
                log.info(
                    "cvm_update_provider_compose_waiting",
                    operation_id=str(operation_id),
                    cvm_id=str(_row_value(snapshot, "cvm_id")),
                    expected_compose_sha256=expected_compose_sha256,
                    provider_compose_sha256=provider_compose_sha256,
                )
                return
        await advance_cvm_update_step(operation_id, "verify_attestation")
        return
    if provider_status == "FAILED":
        await mark_cvm_update_failed(
            operation_id,
            code="PROVIDER_UPDATE_FAILED",
            details={"adapter": "cvm_provider", "reason": "provider_status_failed"},
            mark_cvm_failed=True,
        )
        return
    log.info(
        "cvm_update_await_provider_pending",
        operation_id=str(operation_id),
        cvm_id=str(_row_value(snapshot, "cvm_id")),
        provider_status=provider_status,
    )


async def execute_cvm_update_attestation_gate_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_update_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_cvm_update_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    if _row_value(snapshot, "image_measurement") is None or _row_value(snapshot, "attestation_verified_at") is None:
        verified = await run_cvm_update_attestation_verifier(operation_id, snapshot)
        if verified:
            return
        if _row_value(snapshot, "image_measurement") is None or _row_value(snapshot, "attestation_verified_at") is None:
            log.info(
                "cvm_update_attestation_waiting",
                operation_id=str(operation_id),
                cvm_id=str(_row_value(snapshot, "cvm_id")),
            )
        return
    if _row_value(snapshot, "image_measurement") != _row_value(snapshot, "expected_image_measurement"):
        await mark_cvm_update_failed(
            operation_id,
            code="ATTESTATION_IMAGE_MISMATCH",
            details={
                "expected": _row_value(snapshot, "expected_image_measurement"),
                "actual": _row_value(snapshot, "image_measurement"),
            },
            mark_cvm_failed=True,
        )
        return
    if _row_value(snapshot, "rtmr3_digest") is None:
        await mark_cvm_update_failed(
            operation_id,
            code="ATTESTATION_RTMR_MISMATCH",
            details={"state": "missing_rtmr3_digest"},
            mark_cvm_failed=True,
        )
        return
    await advance_cvm_update_step(operation_id, "await_sc_pull")


async def run_cvm_update_attestation_verifier(operation_id: Any, snapshot: Any) -> bool:
    from concrete_console.attestation import (
        AtlasVerifierClient,
        AttestationVerifierError,
        AttestationVerifierUnavailable,
        build_dev_cvm_attestation_request,
        verify_with_fetch_retries,
    )
    from concrete_console.shade_provider.shade import ShadeError

    try:
        verifier = AtlasVerifierClient.from_settings()
        pending_policy_bundle = await materialize_cvm_policy_bundle_for_attestation(
            snapshot,
            bundle_key="pending_policy_bundle",
        )
        metadata = metadata_with_pending_policy_bundle(_row_value(snapshot, "metadata"), pending_policy_bundle)
        request_snapshot = dict(snapshot)
        request_snapshot["metadata"] = metadata
        request_snapshot = snapshot_with_pending_policy_bundle(request_snapshot)
        request = build_dev_cvm_attestation_request(request_snapshot)
        report = await verify_with_fetch_retries(
            verifier,
            request,
            timeout_seconds=dev_cvm_attestation_timeout_seconds(),
        )
    except ShadeError as exc:
        log.warning("shade_adapter_failed", operation_id=str(operation_id), **shade_error_log_fields(exc))
        if shade_error_is_compose_mismatch(exc) and not cvm_update_provider_wait_timed_out(snapshot):
            log.info(
                "cvm_update_attestation_compose_waiting",
                operation_id=str(operation_id),
                cvm_id=str(_row_value(snapshot, "cvm_id")),
            )
            return False
        await mark_cvm_update_failed(
            operation_id,
            code="SHADE_BUILD_FAILED",
            details={"adapter": "shade", "reason": exc.code},
        )
        return True
    except AttestationVerifierUnavailable:
        return False
    except AttestationVerifierError as exc:
        await mark_cvm_update_failed(operation_id, code=exc.code, details=exc.details, mark_cvm_failed=True)
        return True

    if report.image_measurement != _row_value(snapshot, "expected_image_measurement"):
        await mark_cvm_update_failed(
            operation_id,
            code="ATTESTATION_IMAGE_MISMATCH",
            details={
                "expected_image_measurement": _row_value(snapshot, "expected_image_measurement"),
                "reported_image_measurement": report.image_measurement,
            },
            mark_cvm_failed=True,
        )
        return True

    updated_metadata = metadata

    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            verified_at = datetime.now(timezone.utc)
            result = await conn.execute(
                """
                UPDATE cvms
                SET image_measurement = $2,
                    rtmr3_digest = $3,
                    attestation_verified_at = $4,
                    metadata = $5::jsonb,
                    updated_at = now()
                WHERE id = $1
                  AND state IN ('RUNNING', 'STOPPED', 'FAILED')
                  AND deleted_at IS NULL
                """,
                _row_value(snapshot, "cvm_id"),
                report.image_measurement,
                report.rtmr3_digest,
                verified_at,
                json.dumps(updated_metadata),
            )
            if result != "UPDATE 1":
                # State changed concurrently — don't write a misleading "verified" audit or
                # advance the saga; return False so the caller re-evaluates on the next tick.
                log.warning(
                    "cvm_update_attestation_persist_skipped",
                    operation_id=str(operation_id),
                    cvm_id=str(_row_value(snapshot, "cvm_id")),
                    result=result,
                )
                return False
            await insert_audit_event(
                conn,
                entity_id=_row_value(snapshot, "entity_id"),
                actor_id=_row_value(snapshot, "actor_id"),
                actor_email=_row_value(snapshot, "actor_email"),
                action="CVM_ATTESTATION_VERIFIED",
                target_type="cvm",
                target_id=_row_value(snapshot, "cvm_id"),
                before={
                    "image_measurement": _row_value(snapshot, "image_measurement"),
                    "rtmr3_digest": _row_value(snapshot, "rtmr3_digest"),
                },
                after={
                    "image_measurement": report.image_measurement,
                    "rtmr3_digest": report.rtmr3_digest,
                    "attestation_verified_at": verified_at.isoformat().replace("+00:00", "Z"),
                    "source": "update",
                },
            )
            await advance_cvm_update_step_with_conn(conn, operation_id, "await_sc_pull")
    return True


async def execute_cvm_update_await_sc_pull_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_update_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_cvm_update_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    proxy_token_created_at = _row_value(snapshot, "proxy_token_created_at")
    if proxy_token_created_at is None:
        await mark_cvm_update_failed(operation_id, code="PROXY_AUTH_MISSING", details={"state": "missing_proxy_token"})
        return
    last_pull_at = _row_value(snapshot, "security_cvm_last_policy_pull_at")
    if last_pull_at is not None and last_pull_at >= proxy_token_created_at:
        await advance_cvm_update_step(operation_id, "policy_push")
        return
    elapsed = datetime.now(timezone.utc) - proxy_token_created_at
    timeout = timedelta(seconds=sc_pull_propagation_timeout_seconds())
    if elapsed < timeout:
        log.info(
            "cvm_update_awaiting_sc_pull",
            operation_id=str(operation_id),
            cvm_id=str(_row_value(snapshot, "cvm_id")),
            security_cvm_id=str(_row_value(snapshot, "security_cvm_id")),
            elapsed_seconds=int(elapsed.total_seconds()),
            timeout_seconds=int(timeout.total_seconds()),
        )
        return
    await mark_cvm_update_failed(
        operation_id,
        code="SC_PULL_TIMEOUT",
        details={
            "elapsed_seconds": int(elapsed.total_seconds()),
            "timeout_seconds": int(timeout.total_seconds()),
        },
    )


async def execute_cvm_update_policy_push_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_update_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_cvm_update_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE cvms
                SET policy_version = policy_version + 1,
                    updated_at = now()
                WHERE id = $1
                """,
                _row_value(snapshot, "cvm_id"),
            )
            await conn.execute(
                """
                UPDATE security_cvms
                SET policy_version = policy_version + 1,
                    updated_at = now()
                WHERE id = $1
                """,
                _row_value(snapshot, "security_cvm_id"),
            )
            await advance_cvm_update_step_with_conn(conn, operation_id, "finalise")


async def execute_cvm_update_finalise_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_update_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_cvm_update_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    metadata = json_payload(_row_value(snapshot, "metadata") or {})
    if not isinstance(metadata, dict) or not isinstance(metadata.get("pending_policy_bundle"), dict):
        await mark_cvm_update_failed(
            operation_id,
            code="POLICY_BUNDLE_MISSING",
            details={"field": "metadata.pending_policy_bundle"},
        )
        return
    policy_bundle = metadata["pending_policy_bundle"]
    final_metadata = metadata_with_policy_bundle(metadata, policy_bundle)
    final_metadata.pop("pending_policy_bundle", None)
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE cvms
                SET state = 'RUNNING',
                    error_reason = NULL,
                    metadata = $2::jsonb,
                    atls_policy_bundle = $3::jsonb,
                    atls_policy_revision = atls_policy_revision + 1,
                    updated_at = now()
                WHERE id = $1
                  AND state IN ('RUNNING', 'STOPPED', 'FAILED')
                  AND deleted_at IS NULL
                """,
                _row_value(snapshot, "cvm_id"),
                json.dumps(final_metadata),
                json.dumps(policy_bundle),
            )
            cvm_payload = await fetch_cvm_resource_for_scheduler(conn, _row_value(snapshot, "cvm_id"))
            result = {"cvm": cvm_payload, "policy_bundle": policy_bundle}
            await insert_audit_event(
                conn,
                entity_id=_row_value(snapshot, "entity_id"),
                actor_id=_row_value(snapshot, "actor_id"),
                actor_email=_row_value(snapshot, "actor_email"),
                action="CVM_UPDATED",
                target_type="cvm",
                target_id=_row_value(snapshot, "cvm_id"),
                before={"state": _row_value(snapshot, "state")},
                after={
                    "state": "RUNNING",
                    "image_measurement": _row_value(snapshot, "image_measurement"),
                    "rtmr3_digest": _row_value(snapshot, "rtmr3_digest"),
                    "atls_policy_revision": (_row_value(snapshot, "atls_policy_revision") or 0) + 1,
                },
            )
            await conn.execute(
                """
                UPDATE operations
                SET status = 'succeeded',
                    progress_step = 'finalise',
                    progress_percent = 100,
                    result = $2::jsonb,
                    error = NULL,
                    updated_at = now(),
                    expires_at = $3
                WHERE id = $1
                  AND kind = 'cvm.update'
                  AND status = 'running'
                """,
                operation_id,
                json.dumps(result),
                operation_expiry(),
            )


async def execute_cvm_terminate_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await conn.fetchrow(
            """
            SELECT
                o.id AS operation_id,
                o.actor_id,
                o.actor_email,
                o.target_id AS cvm_id,
                c.entity_id,
                c.state::text AS state,
                c.metadata,
                c.txt_dns_record_id,
                c.cname_dns_record_id
            FROM operations o
            JOIN cvms c ON c.id = o.target_id
            WHERE o.id = $1
              AND o.kind = 'cvm.terminate'
              AND o.status = 'running'
            """,
            operation_id,
        )
    if snapshot is None:
        await mark_operation_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return

    if _row_value(snapshot, "state") not in {"RUNNING", "STOPPED", "FAILED", "TERMINATED"}:
        await mark_operation_failed(
            operation_id,
            code="INVALID_STATE",
            details={"state": _row_value(snapshot, "state")},
        )
        return

    app_id = provider_app_id(_row_value(snapshot, "metadata"))
    if app_id is not None:
        from concrete_console.tee_provider.phala import PhalaClient, PhalaError

        try:
            await PhalaClient.from_settings().delete(app_id)
        except PhalaError as exc:
            log.warning(
                "phala_adapter_failed",
                operation_id=str(operation_id),
                step="phala_terminate",
                **phala_error_log_fields(exc),
            )
            await mark_operation_failed(
                operation_id,
                code="PHALA_TERMINATE_FAILED",
                details=phala_error_log_fields(exc),
            )
            return

    dns_deleted = await deprovision_cvm_dns_records(snapshot)
    await finalise_cvm_terminate_operation(operation_id, snapshot, dns_deleted=dns_deleted)


async def deprovision_cvm_dns_records(snapshot: Any) -> bool:
    from concrete_console.dns_provider.cloudflare import CloudflareClient, CloudflareError

    record_ids = [
        _row_value(snapshot, "txt_dns_record_id"),
        _row_value(snapshot, "cname_dns_record_id"),
    ]
    record_ids = [record_id for record_id in record_ids if isinstance(record_id, str) and record_id]
    if not record_ids:
        return False
    try:
        client = CloudflareClient.from_settings()
    except CloudflareError as exc:
        log.warning(
            "cvm_dns_deprovision_skipped",
            cvm_id=str(_row_value(snapshot, "cvm_id")),
            reason=exc.code,
        )
        return False
    deleted = False
    for record_id in record_ids:
        try:
            await client.delete_record(record_id)
            deleted = True
        except CloudflareError as exc:
            log.warning(
                "cvm_dns_deprovision_failed",
                cvm_id=str(_row_value(snapshot, "cvm_id")),
                record_id=record_id,
                reason=exc.code,
            )
    return deleted


async def finalise_cvm_terminate_operation(operation_id: Any, snapshot: Any, *, dns_deleted: bool) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE service_principal_tokens
                SET deleted_at = now(),
                    deleted_by = $1
                WHERE principal_type = 'dev_cvm'
                  AND principal_id = $2
                  AND deleted_at IS NULL
                """,
                _row_value(snapshot, "actor_id"),
                _row_value(snapshot, "cvm_id"),
            )
            await conn.execute(
                """
                UPDATE cvms
                SET state = 'TERMINATED',
                    deleted_at = COALESCE(deleted_at, now()),
                    deleted_by = COALESCE(deleted_by, $1),
                    updated_at = now(),
                    txt_dns_record_id = NULL,
                    cname_dns_record_id = NULL
                WHERE id = $2
                """,
                _row_value(snapshot, "actor_id"),
                _row_value(snapshot, "cvm_id"),
            )
            result = await fetch_cvm_resource_for_scheduler(conn, _row_value(snapshot, "cvm_id"))
            await insert_audit_event(
                conn,
                entity_id=_row_value(snapshot, "entity_id"),
                actor_id=_row_value(snapshot, "actor_id"),
                actor_email=_row_value(snapshot, "actor_email"),
                action="CVM_TERMINATED",
                target_type="cvm",
                target_id=_row_value(snapshot, "cvm_id"),
                before={"state": _row_value(snapshot, "state")},
                after={"state": "TERMINATED"},
            )
            if dns_deleted:
                await insert_audit_event(
                    conn,
                    entity_id=_row_value(snapshot, "entity_id"),
                    actor_id=_row_value(snapshot, "actor_id"),
                    actor_email=_row_value(snapshot, "actor_email"),
                    action="SUBDOMAIN_DEPROVISIONED",
                    target_type="cvm",
                    target_id=_row_value(snapshot, "cvm_id"),
                    before={
                        "txt_dns_record_id": _row_value(snapshot, "txt_dns_record_id"),
                        "cname_dns_record_id": _row_value(snapshot, "cname_dns_record_id"),
                    },
                    after={"txt_dns_record_id": None, "cname_dns_record_id": None},
                )
            await conn.execute(
                """
                UPDATE operations
                SET status = 'succeeded',
                    progress_step = 'finalise',
                    progress_percent = 100,
                    result = $2::jsonb,
                    error = NULL,
                    updated_at = now(),
                    expires_at = $3
                WHERE id = $1
                  AND status = 'running'
                """,
                operation_id,
                json.dumps(result),
                operation_expiry(),
            )


async def mark_operation_failed(operation_id: Any, *, code: str, details: dict[str, Any]) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE operations
            SET status = 'failed',
                error = $2::jsonb,
                updated_at = now(),
                expires_at = $3
            WHERE id = $1
              AND status = 'running'
            """,
            operation_id,
            json.dumps(operation_error_payload({"code": code, "details": details})),
            operation_expiry(),
        )


async def fetch_cvm_resource_for_scheduler(conn: Any, cvm_id: Any) -> dict[str, Any]:
    row = await conn.fetchrow(
        """
        SELECT
            c.id,
            c.owner_id,
            owner.email AS owner_email,
            c.entity_id,
            c.state::text AS state,
            c.instance_type,
            c.region,
            c.fqdn,
            c.expected_image_measurement,
            c.image_measurement,
            c.rtmr3_digest,
            c.attestation_verified_at,
            c.error_reason,
            c.policy_version,
            c.created_at,
            c.updated_at,
            COALESCE(
                (
                    SELECT jsonb_agg(
                        jsonb_build_object('id', ep.id, 'name', ep.name)
                        ORDER BY ep.name, ep.id
                    )
                    FROM cvm_profiles cp
                    JOIN entity_profiles ep ON ep.id = cp.profile_id
                    WHERE cp.cvm_id = c.id
                      AND ep.deleted_at IS NULL
                ),
                '[]'::jsonb
            ) AS profiles,
            COALESCE(
                (
                    SELECT jsonb_agg(
                        jsonb_build_object('id', sk.id, 'label', sk.label)
                        ORDER BY sk.label, sk.id
                    )
                    FROM cvm_ssh_keys csk
                    JOIN ssh_keys sk ON sk.id = csk.ssh_key_id
                    WHERE csk.cvm_id = c.id
                      AND sk.deleted_at IS NULL
                ),
                '[]'::jsonb
            ) AS ssh_keys
        FROM cvms c
        JOIN users owner ON owner.id = c.owner_id
        WHERE c.id = $1
        """,
        cvm_id,
    )
    if row is None:
        raise RuntimeError("CVM target disappeared before terminate finalise")
    return cvm_resource(row)


async def fetch_security_cvm_resource_for_scheduler(conn: Any, security_cvm_id: Any) -> dict[str, Any]:
    row = await conn.fetchrow(
        """
        SELECT
            id,
            entity_id,
            state::text AS state,
            fqdn,
            instance_type,
            region,
            error_reason,
            policy_version,
            expected_image_measurement,
            image_measurement,
            rtmr3_digest,
            attestation_verified_at,
            created_at,
            updated_at
        FROM security_cvms
        WHERE id = $1
        """,
        security_cvm_id,
    )
    if row is None:
        raise RuntimeError("Security CVM target disappeared before provision finalise")
    return security_cvm_resource(row)


def _security_cvm_snapshot_query(*, kind: str, include_previous_ca: bool = False) -> str:
    """Build the SC provision/update snapshot SELECT. ``kind`` is an internal literal
    (never user input). ``include_previous_ca`` projects ``ca_cert_pem`` a second time as
    ``previous_ca_cert_pem`` for the update flow (it must diff old vs new CA after a bump)."""
    previous_ca_col = "sc.ca_cert_pem AS previous_ca_cert_pem,\n            " if include_previous_ca else ""
    return f"""
        SELECT
            sc.id,
            o.id AS operation_id,
            o.actor_id,
            o.actor_email,
            o.updated_at AS operation_updated_at,
            sc.entity_id,
            sc.state::text AS state,
            sc.fqdn,
            sc.instance_type,
            sc.region,
            sc.metadata,
            sc.compose_config,
            sc.txt_dns_record_id,
            sc.cname_dns_record_id,
            sc.proxy_port,
            sc.ca_cert_pem,
            {previous_ca_col}sc.ca_export_token_plaintext,
            sc.ca_export_token_stashed_at,
            sc.expected_image_measurement,
            sc.image_measurement,
            sc.rtmr3_digest,
            sc.attestation_verified_at,
            sc.policy_version
        FROM operations o
        JOIN security_cvms sc ON sc.id = o.target_id
        WHERE o.id = $1
          AND o.kind = '{kind}'
          AND o.status = 'running'
          AND sc.deleted_at IS NULL
        """


async def fetch_security_cvm_provision_snapshot(conn: Any, operation_id: Any) -> Any | None:
    return await conn.fetchrow(
        _security_cvm_snapshot_query(kind="security_cvm.provision"),
        operation_id,
    )


async def fetch_security_cvm_update_snapshot(conn: Any, operation_id: Any) -> Any | None:
    return await conn.fetchrow(
        _security_cvm_snapshot_query(kind="security_cvm.update", include_previous_ca=True),
        operation_id,
    )


async def fetch_cvm_launch_snapshot(conn: Any, operation_id: Any) -> Any | None:
    return await conn.fetchrow(
        """
        SELECT
            o.id AS operation_id,
            o.actor_id,
            o.actor_email,
            o.updated_at AS operation_updated_at,
            o.target_id AS cvm_id,
            c.entity_id,
            c.state::text AS state,
            c.fqdn,
            c.instance_type,
            c.region,
            c.disk_size_gb,
            c.metadata,
            c.compose_config,
            c.txt_dns_record_id,
            c.cname_dns_record_id,
            c.expected_image_measurement,
            c.image_measurement,
            c.rtmr3_digest,
            c.attestation_verified_at,
            c.policy_version,
            c.security_cvm_id,
            sc.fqdn AS security_cvm_fqdn,
            COALESCE(sc.proxy_port, 8080) AS security_cvm_proxy_port,
            sc.ca_cert_pem AS security_cvm_ca_cert_pem,
            sc.metadata AS security_cvm_metadata,
            sc.expected_image_measurement AS security_cvm_expected_image_measurement,
            sc.image_measurement AS security_cvm_image_measurement,
            sc.rtmr3_digest AS security_cvm_rtmr3_digest,
            sc.compose_config AS security_cvm_compose_config,
            sc.last_policy_pull_at AS security_cvm_last_policy_pull_at,
            sc.last_policy_pull_etag AS security_cvm_last_policy_pull_etag,
            proxy_token.created_at AS proxy_token_created_at
        FROM operations o
        JOIN cvms c ON c.id = o.target_id
        JOIN security_cvms sc
          ON sc.id = c.security_cvm_id
         AND sc.state = 'RUNNING'
         AND sc.deleted_at IS NULL
        LEFT JOIN LATERAL (
            SELECT spt.created_at
            FROM service_principal_tokens spt
            WHERE spt.principal_type = 'dev_cvm'
              AND spt.principal_id = c.id
              AND spt.purpose = 'PROXY_AUTH'
              AND spt.deleted_at IS NULL
              AND (spt.expires_at IS NULL OR spt.expires_at > now())
            ORDER BY spt.created_at DESC
            LIMIT 1
        ) proxy_token ON true
        WHERE o.id = $1
          AND o.kind = 'cvm.launch'
          AND o.status = 'running'
        """,
        operation_id,
    )


async def fetch_cvm_update_snapshot(conn: Any, operation_id: Any) -> Any | None:
    return await conn.fetchrow(
        """
        SELECT
            o.id AS operation_id,
            o.actor_id,
            o.actor_email,
            o.updated_at AS operation_updated_at,
            o.target_id AS cvm_id,
            c.entity_id,
            c.state::text AS state,
            c.fqdn,
            c.instance_type,
            c.region,
            c.metadata,
            c.compose_config,
            c.expected_image_measurement,
            c.image_measurement,
            c.rtmr3_digest,
            c.attestation_verified_at,
            c.policy_version,
            c.atls_policy_bundle,
            c.atls_policy_revision,
            c.security_cvm_id,
            sc.fqdn AS security_cvm_fqdn,
            COALESCE(sc.proxy_port, 8080) AS security_cvm_proxy_port,
            sc.ca_cert_pem AS security_cvm_ca_cert_pem,
            sc.metadata AS security_cvm_metadata,
            sc.expected_image_measurement AS security_cvm_expected_image_measurement,
            sc.image_measurement AS security_cvm_image_measurement,
            sc.rtmr3_digest AS security_cvm_rtmr3_digest,
            sc.compose_config AS security_cvm_compose_config,
            sc.last_policy_pull_at AS security_cvm_last_policy_pull_at,
            sc.last_policy_pull_etag AS security_cvm_last_policy_pull_etag,
            proxy_token.created_at AS proxy_token_created_at
        FROM operations o
        JOIN cvms c ON c.id = o.target_id
        JOIN security_cvms sc
          ON sc.id = c.security_cvm_id
         AND sc.state = 'RUNNING'
         AND sc.deleted_at IS NULL
        LEFT JOIN LATERAL (
            SELECT spt.created_at
            FROM service_principal_tokens spt
            WHERE spt.principal_type = 'dev_cvm'
              AND spt.principal_id = c.id
              AND spt.purpose = 'PROXY_AUTH'
              AND spt.deleted_at IS NULL
              AND spt.expires_at IS NULL
            ORDER BY spt.created_at DESC
            LIMIT 1
        ) proxy_token ON true
        WHERE o.id = $1
          AND o.kind = 'cvm.update'
          AND o.status = 'running'
          AND c.deleted_at IS NULL
        """,
        operation_id,
    )


async def fetch_cvm_launch_profiles_for_audit(conn: Any, cvm_id: Any) -> list[Any]:
    return list(
        await conn.fetch(
            """
            SELECT
                cp.profile_id,
                ep.name AS profile_name
            FROM cvm_profiles cp
            JOIN entity_profiles ep ON ep.id = cp.profile_id
            WHERE cp.cvm_id = $1
            ORDER BY ep.name, cp.profile_id
            """,
            cvm_id,
        )
    )


async def fetch_cvm_launch_public_keys(conn: Any, cvm_id: Any) -> list[str]:
    rows = await conn.fetch(
        """
        SELECT sk.public_key
        FROM cvm_ssh_keys csk
        JOIN ssh_keys sk ON sk.id = csk.ssh_key_id
        WHERE csk.cvm_id = $1
        ORDER BY sk.public_key
        """,
        cvm_id,
    )
    return [row["public_key"] for row in rows]


async def fetch_cvm_launch_profile_policies(conn: Any, cvm_id: Any) -> list[Any]:
    return list(
        await conn.fetch(
            """
            SELECT cp.profile_id, ep.policy
            FROM cvm_profiles cp
            JOIN entity_profiles ep ON ep.id = cp.profile_id
            WHERE cp.cvm_id = $1
            ORDER BY cp.attached_at, cp.profile_id
            """,
            cvm_id,
        )
    )


def build_cvm_launch_env(
    snapshot: Any,
    *,
    public_keys: list[str],
    profile_rows: list[Any],
    proxy_token: str,
    dev_control_token: str,
) -> tuple[dict[str, str], dict[str, Any]]:
    authorized_keys = render_authorized_ssh_keys(public_keys)
    sandbox_env = render_sandbox_env_placeholders(profile_rows)
    ca_cert_pem = _row_value(snapshot, "security_cvm_ca_cert_pem")
    proxy_token_hash = sha256_text(proxy_token)
    dev_control_token_hash = sha256_text(dev_control_token)
    console_url = load_settings().raw.get("CONSOLE_URL", "").strip()
    binding = {
        "cvm_id": str(_row_value(snapshot, "cvm_id")),
        "console_url": console_url,
        "dev_cvm_control_token_sha256": dev_control_token_hash,
        "security_cvm_fqdn": _row_value(snapshot, "security_cvm_fqdn"),
        "security_cvm_proxy_port": int(_row_value(snapshot, "security_cvm_proxy_port")),
        "security_cvm_proxy_token_sha256": proxy_token_hash,
        "security_cvm_ca_cert_sha256": sha256_text(ca_cert_pem),
        "authorised_ssh_keys_sha256": sha256_text(authorized_keys),
    }
    env = {
        "SECURITY_CVM_FQDN": _row_value(snapshot, "security_cvm_fqdn"),
        "SECURITY_CVM_PROXY_PORT": str(_row_value(snapshot, "security_cvm_proxy_port")),
        "SECURITY_CVM_PROXY_TOKEN": proxy_token,
        "DEV_CVM_CONTROL_TOKEN": dev_control_token,
        "SECURITY_CVM_CA_CERT_B64": b64_text(ca_cert_pem),
        "SECURITY_CVM_ATLS_POLICY_B64": b64_json(security_cvm_atls_policy(snapshot)),
        "AUTHORIZED_SSH_KEYS_B64": b64_text(authorized_keys),
        "SANDBOX_ENV_PLACEHOLDERS_B64": b64_text(sandbox_env),
        "CONSOLE_URL": console_url,
    }
    env.update(dstack_docker_pull_env())
    return env, binding


def render_authorized_ssh_keys(public_keys: list[str]) -> str:
    keys = sorted(key.strip() for key in public_keys if key.strip())
    return "".join(f"{key}\n" for key in keys)


def render_sandbox_env_placeholders(profile_rows: list[Any]) -> str:
    merged: dict[str, str] = {}
    for row in profile_rows:
        policy = json_payload(_row_value(row, "policy"))
        if not isinstance(policy, dict):
            continue
        sandbox_env = policy.get("sandbox_env", {})
        if not isinstance(sandbox_env, dict):
            continue
        for name, value in sandbox_env.items():
            if isinstance(name, str) and isinstance(value, str):
                merged[name] = value
    return "".join(f"{name}={merged[name]}\n" for name in sorted(merged))


def stored_security_cvm_atls_policy(snapshot: Any) -> dict[str, Any] | None:
    metadata = json_payload(_row_value(snapshot, "security_cvm_metadata") or {})
    if not isinstance(metadata, dict):
        return None
    policy = metadata.get("atls_policy")
    return policy if isinstance(policy, dict) else None


def security_cvm_atls_policy(snapshot: Any) -> dict[str, Any]:
    policy = stored_security_cvm_atls_policy(snapshot)
    if policy is None:
        raise ValueError("security_cvm_atls_policy_missing")
    return policy


def render_dev_cvm_shade_config(snapshot: Any, *, name: str) -> str:
    return "\n".join(
        [
            "app:",
            f"  name: {name}",
            "",
            "services:",
            "  dev-tunnel:",
            "    networks: [proxy]",
            "",
            "cvm:",
            f"  domain: {_row_value(snapshot, 'fqdn')}",
            f"  instance_type: {_row_value(snapshot, 'instance_type')}",
            f"  region: {_row_value(snapshot, 'region')}",
            "  routes:",
            "    - path: /concrete/tunnel",
            "      service: dev-tunnel",
            "      port: 8090",
            "      websocket: true",
            "      cors: false",
            "",
        ]
    )


def render_security_cvm_shade_config(snapshot: Any, *, name: str) -> str:
    # The SC leaf cert MUST be Let's Encrypt PRODUCTION (publicly trusted): the attestation
    # verifier's aTLS client (atlas-rs connect.rs) validates the TLS handshake against the
    # webpki public roots before binding the leaf to the quote, so an LE *staging* ("Fake LE")
    # cert fails the handshake → ATTESTATION_FETCH_FAILED. We therefore do NOT emit a cvm.tls
    # block (shade defaults letsencrypt_staging=false = production). Cold-start LE rate-limit is
    # handled in shade's cert-manager (FQDN-resolution pre-check before calling LE), not here.
    return "\n".join(
        [
            "app:",
            f"  name: {name}",
            "",
            "services:",
            "  mitmproxy:",
            "    networks: [proxy]",
            "  proxy-tunnel:",
            "    networks: [proxy]",
            "",
            "cvm:",
            f"  domain: {_row_value(snapshot, 'fqdn')}",
            f"  instance_type: {_row_value(snapshot, 'instance_type')}",
            f"  region: {_row_value(snapshot, 'region')}",
            "  routes:",
            "    - path: /concrete/proxy",
            "      service: proxy-tunnel",
            "      port: 8082",
            "      websocket: true",
            "      cors: false",
            "    - path: /ca.pem",
            "      service: mitmproxy",
            "      port: 8081",
            "      cors: false",
            "",
        ]
    )


def mint_security_cvm_provision_bearers() -> dict[str, str]:
    ingest_token = secrets.token_urlsafe(32)
    ca_export_token = secrets.token_urlsafe(32)
    return {
        "ingest_token": ingest_token,
        "ca_export_token": ca_export_token,
        "ingest_token_hash": sha256_text(ingest_token),
        "ca_export_token_hash": sha256_text(ca_export_token),
    }


def build_security_cvm_provision_env(snapshot: Any, *, ingest_token: str, ca_export_token: str) -> dict[str, str]:
    raw = load_settings().raw
    env = {
        "CONSOLE_URL": raw.get("CONSOLE_URL", "http://localhost:8000"),
        "ENTITY_ID": str(_row_value(snapshot, "entity_id")),
        "SC_ID": str(_row_value(snapshot, "id")),
        "SECURITY_CVM_FQDN": _row_value(snapshot, "fqdn"),
        "CONSOLE_INGEST_TOKEN": ingest_token,
        "CA_EXPORT_TOKEN": ca_export_token,
    }
    env.update(dstack_docker_pull_env(raw))
    return env


def dstack_docker_pull_env(raw: dict[str, str] | None = None) -> dict[str, str]:
    raw = load_settings().raw if raw is None else raw
    registry = raw.get("DSTACK_DOCKER_REGISTRY", "").strip() or raw.get("DOCKER_REGISTRY", "").strip()
    username = raw.get("DSTACK_DOCKER_USERNAME", "").strip() or raw.get("GHCR_USER", "").strip()
    password = raw.get("DSTACK_DOCKER_PASSWORD", "").strip() or raw.get("GHCR_TOKEN", "").strip()
    env: dict[str, str] = {}
    if registry:
        env["DSTACK_DOCKER_REGISTRY"] = phala_docker_registry_value(registry)
    if username and password:
        env["DSTACK_DOCKER_USERNAME"] = username
        env["DSTACK_DOCKER_PASSWORD"] = password
    return env


def phala_docker_registry_value(registry: str) -> str:
    if registry == "ghcr.io":
        # Phala's pre-launch GHCR verifier treats digest refs as tags when this value is exactly "ghcr.io".
        # Docker login still authenticates pulls for ghcr.io when the registry is passed with a scheme.
        return "https://ghcr.io"
    return registry


def provider_deployment_id(metadata: Any) -> str | None:
    current = json_payload(metadata or {})
    if not isinstance(current, dict):
        return None
    deployment_id = current.get("deployment_id") or current.get("app_id")
    return deployment_id if isinstance(deployment_id, str) and deployment_id else None


def provider_name(metadata: Any) -> str | None:
    current = json_payload(metadata or {})
    if not isinstance(current, dict):
        return None
    provider = current.get("provider")
    return provider if isinstance(provider, str) and provider else None


def security_cvm_provision_metadata(
    *,
    name: str,
    app_id: str,
    gateway_host: str,
    status: str,
    deploy_compose_yaml: str,
    atls_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "provider": "phala",
        "name": name,
        "deployment_id": app_id,
        "app_id": app_id,
        "gateway_host": gateway_host,
        "status": status,
        "deploy_compose_yaml": deploy_compose_yaml,
    }
    if atls_policy is not None:
        metadata["atls_policy"] = atls_policy
    return metadata


def security_cvm_update_metadata(
    metadata: Any,
    *,
    name: str,
    deployment_id: str,
    gateway_host: str,
    status: str,
    deploy_compose_yaml: str,
) -> dict[str, Any]:
    current = json_payload(metadata or {})
    if not isinstance(current, dict):
        current = {}
    updated = dict(current)
    updated.update(
        {
            "provider": current.get("provider", "phala"),
            "name": name,
            "deployment_id": deployment_id,
            "app_id": deployment_id,
            "gateway_host": gateway_host,
            "status": status,
            "deploy_compose_yaml": deploy_compose_yaml,
        }
    )
    return updated


def security_cvm_provider_name_from_metadata(snapshot: Any) -> str:
    metadata = json_payload(_row_value(snapshot, "metadata") or {})
    if isinstance(metadata, dict):
        name = metadata.get("name")
        if isinstance(name, str) and name:
            return name
    return security_cvm_provider_name(_row_value(snapshot, "id"))


def metadata_with_atls_policy(metadata: Any, policy: dict[str, Any]) -> dict[str, Any]:
    current = json_payload(metadata or {})
    if not isinstance(current, dict):
        current = {}
    updated = dict(current)
    updated["atls_policy"] = policy
    return updated


def metadata_with_policy_bundle(metadata: Any, policy_bundle: dict[str, Any]) -> dict[str, Any]:
    current = json_payload(metadata or {})
    if not isinstance(current, dict):
        current = {}
    updated = dict(current)
    updated["policy_bundle"] = policy_bundle
    return updated


def metadata_with_pending_policy_bundle(metadata: Any, policy_bundle: dict[str, Any]) -> dict[str, Any]:
    current = json_payload(metadata or {})
    if not isinstance(current, dict):
        current = {}
    updated = dict(current)
    updated["pending_policy_bundle"] = policy_bundle
    return updated


def snapshot_with_pending_policy_bundle(snapshot: Any) -> dict[str, Any]:
    row = dict(snapshot)
    metadata = json_payload(row.get("metadata") or {})
    if not isinstance(metadata, dict):
        metadata = {}
    pending_policy_bundle = metadata.get("pending_policy_bundle")
    if isinstance(pending_policy_bundle, dict):
        metadata = dict(metadata)
        metadata["policy_bundle"] = pending_policy_bundle
        row["metadata"] = metadata
    return row


async def generate_policy_with_connect_retries(
    shade: Any,
    *,
    domain: str,
    deploy_compose_yaml: str,
    timeout_seconds: int,
    retry_seconds: float = 10.0,
) -> Any:
    from concrete_console.shade_provider.shade import ShadeError

    deadline = time.monotonic() + max(timeout_seconds, 0)
    retry_delay = max(retry_seconds, 0.0)
    last_error: ShadeError | None = None
    while True:
        try:
            return await shade.generate_policy(
                domain=domain,
                deploy_compose_yaml=deploy_compose_yaml,
            )
        except ShadeError as exc:
            last_error = exc
            if not shade_error_is_transient_connect_failure(exc):
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0 or (retry_delay > 0 and remaining < retry_delay):
                raise
            log.info(
                "shade_policy_connect_waiting",
                domain=domain,
                reason=exc.code,
            )
            await asyncio.sleep(min(retry_delay, remaining))
    raise last_error  # pragma: no cover


async def materialize_cvm_policy_bundle_for_attestation(snapshot: Any, *, bundle_key: str) -> dict[str, Any]:
    from concrete_console.shade_provider.shade import ShadeClient, ShadeError

    metadata = json_payload(_row_value(snapshot, "metadata") or {})
    if not isinstance(metadata, dict):
        metadata = {}
    policy_bundle = metadata.get(bundle_key)
    if not isinstance(policy_bundle, dict):
        raise ShadeError("missing_policy_bundle", field=f"metadata.{bundle_key}")
    deploy_compose_yaml = policy_bundle.get("deploy_compose_yaml")
    if not isinstance(deploy_compose_yaml, str) or not deploy_compose_yaml:
        raise ShadeError("missing_deploy_compose", field=f"metadata.{bundle_key}.deploy_compose_yaml")
    rtmr3_binding = policy_bundle.get("rtmr3_binding")
    if not isinstance(rtmr3_binding, dict):
        raise ShadeError("missing_rtmr3_binding", field=f"metadata.{bundle_key}.rtmr3_binding")
    if "app_compose" in policy_bundle or "app_compose_json" in policy_bundle:
        return dict(policy_bundle)

    policy_result = await generate_policy_with_connect_retries(
        ShadeClient.from_settings(),
        domain=_row_value(snapshot, "fqdn"),
        deploy_compose_yaml=deploy_compose_yaml,
        timeout_seconds=dev_cvm_attestation_timeout_seconds(),
    )
    return build_cvm_policy_bundle(
        snapshot,
        shade_policy=policy_result.policy,
        rtmr3_binding=rtmr3_binding,
        deploy_compose_yaml=deploy_compose_yaml,
    )


def deployed_compose_from_metadata(metadata: Any) -> str | None:
    current = json_payload(metadata or {})
    if not isinstance(current, dict):
        return None
    deploy_compose_yaml = current.get("deploy_compose_yaml")
    if isinstance(deploy_compose_yaml, str) and deploy_compose_yaml:
        return deploy_compose_yaml
    policy_bundle = current.get("policy_bundle")
    if isinstance(policy_bundle, dict):
        deploy_compose_yaml = policy_bundle.get("deploy_compose_yaml")
        if isinstance(deploy_compose_yaml, str) and deploy_compose_yaml:
            return deploy_compose_yaml
    return None


async def materialize_security_cvm_shade_policy_for_attestation(snapshot: Any) -> dict[str, Any]:
    from concrete_console.shade_provider.shade import ShadeClient, ShadeError

    metadata = json_payload(_row_value(snapshot, "metadata") or {})
    if not isinstance(metadata, dict):
        metadata = {}
    # Always regenerate the SC aTLS policy from the *currently deployed* compose. A prior
    # short-circuit (8bf96c0) returned the stored `metadata.atls_policy` whenever it carried an
    # `os_image_hash`, so the policy was never refreshed after an SC image update: the stored
    # policy's `app_compose` kept the OLD image digest while the SC actually ran the NEW image.
    # The Dev egress forwarder verifies the SC against this policy, so it saw an
    # app_compose_hash_mismatch against the new-image quote and fail-closed every egress CONNECT
    # with a 502 — even though the Console's own verify (which uses the current compose_config)
    # passed. Regenerating from `deploy_compose_yaml` keeps the forwarder's policy in lockstep
    # with the deployed image. See 21f1fbb (the sibling Console-verify fix).
    deploy_compose_yaml = deployed_compose_from_metadata(metadata)
    if deploy_compose_yaml is None:
        raise ShadeError("missing_deploy_compose", field="metadata.deploy_compose_yaml")
    policy_result = await generate_policy_with_connect_retries(
        ShadeClient.from_settings(),
        domain=_row_value(snapshot, "fqdn"),
        deploy_compose_yaml=deploy_compose_yaml,
        timeout_seconds=security_cvm_attestation_timeout_seconds(),
    )
    return dict(policy_result.policy)


def build_cvm_policy_bundle(
    snapshot: Any,
    *,
    rtmr3_binding: dict[str, Any],
    deploy_compose_yaml: str,
    shade_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    shade_policy = shade_policy or {}
    app_compose = json_payload(shade_policy.get("app_compose", {}))
    if not isinstance(app_compose, dict):
        app_compose = {}
    expected_bootchain = json_payload(shade_policy.get("expected_bootchain", {}))
    if not isinstance(expected_bootchain, dict):
        expected_bootchain = {}
    bundle: dict[str, Any] = {
        "cvm_id": str(_row_value(snapshot, "cvm_id")),
        "policy_template_version": str(shade_policy.get("policy_template_version", "shade")),
        "compose_template": app_compose.get("docker_compose_file") or _row_value(snapshot, "compose_config"),
        "deploy_compose_yaml": deploy_compose_yaml,
        "rtmr3_binding": rtmr3_binding,
        "security_cvm_fqdn": _row_value(snapshot, "security_cvm_fqdn"),
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    if app_compose:
        bundle["app_compose"] = app_compose
        bundle["app_compose_json"] = json.dumps(app_compose, separators=(",", ":"))
    if expected_bootchain:
        bundle["expected_bootchain"] = expected_bootchain
    if isinstance(shade_policy.get("os_image_hash"), str):
        bundle["os_image_hash"] = shade_policy["os_image_hash"]
    return bundle


def cvm_launch_metadata(
    *,
    name: str,
    app_id: str,
    gateway_host: str,
    status: str,
    policy_bundle: dict[str, Any],
) -> dict[str, Any]:
    return {
        "provider": "phala",
        "name": name,
        "deployment_id": app_id,
        "app_id": app_id,
        "gateway_host": gateway_host,
        "status": status,
        "policy_bundle": policy_bundle,
    }


def cvm_update_metadata(
    metadata: Any,
    *,
    deployment_id: str,
    gateway_host: str,
    status: str,
    pending_policy_bundle: dict[str, Any],
) -> dict[str, Any]:
    current = json_payload(metadata or {})
    if not isinstance(current, dict):
        current = {}
    updated = dict(current)
    updated.update(
        {
            "provider": current.get("provider", "phala"),
            "deployment_id": deployment_id,
            "app_id": deployment_id,
            "gateway_host": gateway_host,
            "status": status,
            "provider_update_submitted_at": timestamp(datetime.now(timezone.utc)),
            "pending_policy_bundle": pending_policy_bundle,
        }
    )
    return updated


def pending_update_deploy_compose_yaml(metadata: Any) -> str | None:
    current = json_payload(metadata or {})
    if not isinstance(current, dict):
        return None
    pending_policy_bundle = current.get("pending_policy_bundle")
    if not isinstance(pending_policy_bundle, dict):
        return None
    compose_yaml = pending_policy_bundle.get("deploy_compose_yaml")
    return compose_yaml if isinstance(compose_yaml, str) and compose_yaml else None


def pending_update_deploy_compose_sha256(metadata: Any) -> str | None:
    compose_yaml = pending_update_deploy_compose_yaml(metadata)
    if compose_yaml is None:
        return None
    return hashlib.sha256(compose_yaml.encode("utf-8")).hexdigest()


def cvm_update_provider_submitted_at(metadata: Any) -> datetime | None:
    current = json_payload(metadata or {})
    if not isinstance(current, dict):
        return None
    value = current.get("provider_update_submitted_at")
    if not isinstance(value, str) or not value:
        return None
    try:
        return _as_utc(datetime.fromisoformat(value.replace("Z", "+00:00")))
    except ValueError:
        return None


def cvm_update_provider_wait_timed_out(snapshot: Any) -> bool:
    submitted_at = cvm_update_provider_submitted_at(_row_value(snapshot, "metadata"))
    if submitted_at is None:
        return False
    elapsed = datetime.now(timezone.utc) - submitted_at
    return elapsed > timedelta(seconds=provider_update_timeout_seconds())


def cvm_provider_name_from_metadata(snapshot: Any) -> str:
    metadata = json_payload(_row_value(snapshot, "metadata") or {})
    if isinstance(metadata, dict):
        name = metadata.get("name")
        if isinstance(name, str) and name:
            return name
    return cvm_launch_provider_name(_row_value(snapshot, "cvm_id"))


async def persist_security_cvm_phala_result(operation_id: Any, snapshot: Any, *, metadata: dict[str, Any]) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE security_cvms
                SET metadata = $2::jsonb,
                    updated_at = now()
                WHERE id = $1
                  AND state = 'PROVISIONING'
                """,
                _row_value(snapshot, "id"),
                json.dumps(metadata),
            )
            await insert_audit_event(
                conn,
                entity_id=_row_value(snapshot, "entity_id"),
                actor_id=_row_value(snapshot, "actor_id"),
                actor_email=_row_value(snapshot, "actor_email"),
                action="SECURITY_CVM_PROVISIONING_STARTED",
                target_type="security_cvm",
                target_id=_row_value(snapshot, "id"),
                before={"provider": provider_name(_row_value(snapshot, "metadata"))},
                after={
                    "provider": metadata.get("provider", "unknown"),
                    "deployment_recorded": True,
                },
            )
            await advance_security_cvm_provision_step_with_conn(conn, operation_id, "cf_txt_create")


async def persist_security_cvm_provision_bearers(
    operation_id: Any,
    snapshot: Any,
    *,
    ingest_token_hash: str,
    ca_export_token_hash: str,
    ca_export_token_plaintext: str,
) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE service_principal_tokens
                SET deleted_at = now(),
                    deleted_by = $2
                WHERE principal_type = 'security_cvm'
                  AND principal_id = $1
                  AND purpose IN ('INGEST', 'CA_EXPORT')
                  AND deleted_at IS NULL
                """,
                _row_value(snapshot, "id"),
                _row_value(snapshot, "actor_id"),
            )
            await conn.executemany(
                """
                INSERT INTO service_principal_tokens (
                    principal_type,
                    principal_id,
                    purpose,
                    token_hash
                )
                VALUES ('security_cvm', $1, $2, $3)
                """,
                [
                    (_row_value(snapshot, "id"), "INGEST", ingest_token_hash),
                    (_row_value(snapshot, "id"), "CA_EXPORT", ca_export_token_hash),
                ],
            )
            await conn.execute(
                """
                UPDATE security_cvms
                SET ca_export_token_plaintext = $2,
                    ca_export_token_stashed_at = now(),
                    updated_at = now()
                WHERE id = $1
                  AND state = 'PROVISIONING'
                """,
                _row_value(snapshot, "id"),
                ca_export_token_plaintext,
            )


async def persist_security_cvm_update_bearers(
    operation_id: Any,
    snapshot: Any,
    *,
    ingest_token_hash: str,
    ca_export_token_hash: str,
    ca_export_token_plaintext: str,
) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE service_principal_tokens
                SET expires_at = COALESCE(expires_at, now() + INTERVAL '1 hour')
                WHERE principal_type = 'security_cvm'
                  AND principal_id = $1
                  AND purpose IN ('INGEST', 'CA_EXPORT')
                  AND deleted_at IS NULL
                  AND expires_at IS NULL
                """,
                _row_value(snapshot, "id"),
            )
            await conn.executemany(
                """
                INSERT INTO service_principal_tokens (
                    principal_type,
                    principal_id,
                    purpose,
                    token_hash
                )
                VALUES ('security_cvm', $1, $2, $3)
                """,
                [
                    (_row_value(snapshot, "id"), "INGEST", ingest_token_hash),
                    (_row_value(snapshot, "id"), "CA_EXPORT", ca_export_token_hash),
                ],
            )
            await conn.execute(
                """
                UPDATE security_cvms
                SET ca_export_token_plaintext = $2,
                    ca_export_token_stashed_at = now(),
                    updated_at = now()
                WHERE id = $1
                  AND state IN ('RUNNING', 'STOPPED', 'FAILED')
                """,
                _row_value(snapshot, "id"),
                ca_export_token_plaintext,
            )


async def persist_security_cvm_update_provider_result(
    operation_id: Any,
    snapshot: Any,
    *,
    metadata: dict[str, Any],
    compose_config: str,
    expected_image_measurement: str,
) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE security_cvms
                SET metadata = $2::jsonb,
                    compose_config = $3,
                    expected_image_measurement = $4,
                    image_measurement = NULL,
                    rtmr3_digest = NULL,
                    attestation_verified_at = NULL,
                    updated_at = now()
                WHERE id = $1
                  AND state IN ('RUNNING', 'STOPPED', 'FAILED')
                  AND deleted_at IS NULL
                """,
                _row_value(snapshot, "id"),
                json.dumps(metadata),
                compose_config,
                expected_image_measurement,
            )
            await advance_security_cvm_update_step_with_conn(conn, operation_id, "await_provider_running")
async def persist_security_cvm_dns_record(operation_id: Any, snapshot: Any, *, field: str, record_id: str) -> None:
    if field == "txt":
        column = "txt_dns_record_id"
        next_step = "cf_cname_create"
    elif field == "cname":
        column = "cname_dns_record_id"
        next_step = "await_phala_running"
    else:
        raise ValueError("unknown Security CVM DNS record field")
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                f"""
                UPDATE security_cvms
                SET {column} = $2,
                    updated_at = now()
                WHERE id = $1
                  AND state = 'PROVISIONING'
                """,
                _row_value(snapshot, "id"),
                record_id,
            )
            if field == "cname":
                await insert_audit_event(
                    conn,
                    entity_id=_row_value(snapshot, "entity_id"),
                    actor_id=_row_value(snapshot, "actor_id"),
                    actor_email=_row_value(snapshot, "actor_email"),
                    action="SUBDOMAIN_PROVISIONED",
                    target_type="security_cvm",
                    target_id=_row_value(snapshot, "id"),
                    before={"txt_dns_record_id": _row_value(snapshot, "txt_dns_record_id"), "cname_dns_record_id": None},
                    after={"txt_dns_record_id": _row_value(snapshot, "txt_dns_record_id"), "cname_dns_record_id": record_id},
                )
            await advance_security_cvm_provision_step_with_conn(conn, operation_id, next_step)


async def persist_security_cvm_ca_pem(operation_id: Any, *, security_cvm_id: Any, ca_pem: str) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE security_cvms
                SET ca_cert_pem = $2,
                    updated_at = now()
                WHERE id = $1
                  AND state = 'RUNNING'
                  AND deleted_at IS NULL
                """,
                security_cvm_id,
                ca_pem,
            )
            await advance_security_cvm_provision_step_with_conn(conn, operation_id, "finalise")


async def persist_security_cvm_update_ca_pem(operation_id: Any, *, security_cvm_id: Any, ca_pem: str) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE security_cvms
                SET ca_cert_pem = $2,
                    updated_at = now()
                WHERE id = $1
                  AND state IN ('RUNNING', 'STOPPED', 'FAILED')
                  AND deleted_at IS NULL
                """,
                security_cvm_id,
                ca_pem,
            )
            await advance_security_cvm_update_step_with_conn(conn, operation_id, "finalise")


async def advance_security_cvm_provision_step(operation_id: Any, next_step: str) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await advance_security_cvm_provision_step_with_conn(conn, operation_id, next_step)


_ADVANCEABLE_OPERATION_KINDS = frozenset(
    {"cvm.launch", "cvm.update", "security_cvm.provision", "security_cvm.update"}
)


async def _advance_operation_step_with_conn(
    conn: Any, operation_id: Any, next_step: str, *, kind: str, progress: dict[str, int]
) -> None:
    """Advance a running operation's progress step. ``kind`` is an internal operation-kind
    literal (never user input) interpolated into the SQL; ``progress`` is its step→percent
    map. The whitelist assert guards this 4-caller chokepoint against any future caller
    passing an unvetted ``kind`` into the f-string."""
    if kind not in _ADVANCEABLE_OPERATION_KINDS:
        raise ValueError(f"unsupported operation kind: {kind!r}")
    await conn.execute(
        f"""
        UPDATE operations
        SET progress_step = $2,
            progress_percent = GREATEST(progress_percent, $3),
            updated_at = now()
        WHERE id = $1
          AND kind = '{kind}'
          AND status = 'running'
        """,
        operation_id,
        next_step,
        progress[next_step],
    )


async def advance_security_cvm_provision_step_with_conn(conn: Any, operation_id: Any, next_step: str) -> None:
    await _advance_operation_step_with_conn(
        conn, operation_id, next_step,
        kind="security_cvm.provision", progress=SECURITY_CVM_PROVISION_PROGRESS,
    )


async def advance_security_cvm_update_step(operation_id: Any, next_step: str) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await advance_security_cvm_update_step_with_conn(conn, operation_id, next_step)


async def advance_security_cvm_update_step_with_conn(conn: Any, operation_id: Any, next_step: str) -> None:
    await _advance_operation_step_with_conn(
        conn, operation_id, next_step,
        kind="security_cvm.update", progress=SECURITY_CVM_UPDATE_PROGRESS,
    )


async def mark_security_cvm_provision_failed(operation_id: Any, *, code: str, details: dict[str, Any]) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT
                    o.target_id,
                    o.actor_id,
                    o.actor_email,
                    sc.entity_id,
                    sc.state::text AS state,
                    sc.error_reason
                FROM operations o
                LEFT JOIN security_cvms sc ON sc.id = o.target_id
                WHERE o.id = $1
                  AND o.kind = 'security_cvm.provision'
                """,
                operation_id,
            )
            if row is not None and row["target_id"] is not None:
                await scrub_security_cvm_plaintext_stash_with_conn(conn, row["target_id"])
                await conn.execute(
                    """
                    UPDATE service_principal_tokens
                    SET deleted_at = now()
                    WHERE principal_type = 'security_cvm'
                      AND principal_id = $1
                      AND deleted_at IS NULL
                    """,
                    row["target_id"],
                )
                await conn.execute(
                    """
                    UPDATE security_cvms
                    SET state = 'FAILED',
                        error_reason = $2,
                        updated_at = now()
                    WHERE id = $1
                      AND state IN ('PROVISIONING', 'RUNNING')
                      AND deleted_at IS NULL
                      AND ca_cert_pem IS NULL
                    """,
                    row["target_id"],
                    code,
                )
                if row["entity_id"] is not None:
                    await insert_audit_event(
                        conn,
                        entity_id=row["entity_id"],
                        actor_id=row["actor_id"],
                        actor_email=row["actor_email"],
                        action="SECURITY_CVM_PROVISIONING_FAILED",
                        target_type="security_cvm",
                        target_id=row["target_id"],
                        before={"state": row["state"], "error_reason": row["error_reason"]},
                        after={"state": "FAILED", "error_reason": code},
                    )
            await conn.execute(
                """
                UPDATE operations
                SET status = 'failed',
                    error = $2::jsonb,
                    updated_at = now(),
                    expires_at = $3
                WHERE id = $1
                  AND status = 'running'
                """,
                operation_id,
                json.dumps(operation_error_payload({"code": code, "details": details})),
                operation_expiry(),
            )


async def mark_security_cvm_update_failed(
    operation_id: Any,
    *,
    code: str,
    details: dict[str, Any],
    mark_security_cvm_failed: bool = False,
) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT
                    o.target_id,
                    o.actor_id,
                    o.actor_email,
                    sc.entity_id,
                    sc.state::text AS state,
                    sc.error_reason
                FROM operations o
                LEFT JOIN security_cvms sc ON sc.id = o.target_id
                WHERE o.id = $1
                  AND o.kind = 'security_cvm.update'
                """,
                operation_id,
            )
            if row is not None and row["target_id"] is not None:
                await scrub_security_cvm_plaintext_stash_with_conn(conn, row["target_id"])
                if mark_security_cvm_failed:
                    await conn.execute(
                        """
                        UPDATE security_cvms
                        SET state = 'FAILED',
                            error_reason = $2,
                            updated_at = now()
                        WHERE id = $1
                          AND state IN ('RUNNING', 'STOPPED', 'FAILED')
                          AND deleted_at IS NULL
                        """,
                        row["target_id"],
                        code,
                    )
                if row["entity_id"] is not None:
                    await insert_audit_event(
                        conn,
                        entity_id=row["entity_id"],
                        actor_id=row["actor_id"],
                        actor_email=row["actor_email"],
                        action="SECURITY_CVM_UPDATE_FAILED",
                        target_type="security_cvm",
                        target_id=row["target_id"],
                        before={"state": row["state"], "error_reason": row["error_reason"]},
                        after={"state": "FAILED" if mark_security_cvm_failed else row["state"], "error_reason": code},
                    )
            await conn.execute(
                """
                UPDATE operations
                SET status = 'failed',
                    error = $2::jsonb,
                    updated_at = now(),
                    expires_at = $3
                WHERE id = $1
                  AND status = 'running'
                """,
                operation_id,
                json.dumps(operation_error_payload({"code": code, "details": details})),
                operation_expiry(),
            )


async def scrub_security_cvm_plaintext_stash_with_conn(conn: Any, security_cvm_id: Any) -> None:
    await conn.execute(
        """
        UPDATE security_cvms
        SET ca_export_token_plaintext = NULL,
            ca_export_token_stashed_at = NULL,
            updated_at = now()
        WHERE id = $1
        """,
        security_cvm_id,
    )


async def compensate_security_cvm_provision_resources(snapshot: Any) -> None:
    from concrete_console.dns_provider.cloudflare import CloudflareClient, CloudflareError
    from concrete_console.tee_provider.phala import PhalaClient, PhalaError

    with suppress(CloudflareError):
        cloudflare = CloudflareClient.from_settings(zone_id_key="SECURITY_CVM_ZONE_ID")
        for field in ("cname_dns_record_id", "txt_dns_record_id"):
            record_id = _row_value(snapshot, field)
            if isinstance(record_id, str) and record_id:
                await cloudflare.delete_record(record_id)
    app_id = provider_app_id(_row_value(snapshot, "metadata"))
    if app_id is not None:
        with suppress(PhalaError):
            await PhalaClient.from_settings().delete(app_id)


async def persist_cvm_launch_phala_result(
    operation_id: Any,
    *,
    cvm_id: Any,
    actor_id: Any,
    metadata: dict[str, Any],
    proxy_token_hash: str,
    dev_control_token_hash: str,
) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE service_principal_tokens
                SET deleted_at = now(),
                    deleted_by = $2
                WHERE principal_type = 'dev_cvm'
                  AND principal_id = $1
                  AND purpose IN ('PROXY_AUTH', 'DEV_CONTROL')
                  AND deleted_at IS NULL
                """,
                cvm_id,
                actor_id,
            )
            await conn.execute(
                """
                INSERT INTO service_principal_tokens (
                    principal_type,
                    principal_id,
                    purpose,
                    token_hash
                )
                VALUES ('dev_cvm', $1, 'PROXY_AUTH', $2)
                """,
                cvm_id,
                proxy_token_hash,
            )
            await conn.execute(
                """
                INSERT INTO service_principal_tokens (
                    principal_type,
                    principal_id,
                    purpose,
                    token_hash
                )
                VALUES ('dev_cvm', $1, 'DEV_CONTROL', $2)
                """,
                cvm_id,
                dev_control_token_hash,
            )
            await conn.execute(
                """
                UPDATE cvms
                SET metadata = $2::jsonb,
                    updated_at = now()
                WHERE id = $1
                  AND state = 'PROVISIONING'
                """,
                cvm_id,
                json.dumps(metadata),
            )
            await conn.execute(
                """
                UPDATE operations
                SET progress_step = 'cf_txt_create',
                    progress_percent = $3,
                    updated_at = now()
                WHERE id = $1
                  AND target_id = $2
                  AND kind = 'cvm.launch'
                  AND status = 'running'
                """,
                operation_id,
                cvm_id,
                CVM_LAUNCH_PROGRESS["cf_txt_create"],
            )


async def persist_cvm_update_provider_result(
    operation_id: Any,
    *,
    cvm_id: Any,
    actor_id: Any,
    metadata: dict[str, Any],
    compose_config: str,
    expected_image_measurement: str,
    proxy_token_hash: str,
    dev_control_token_hash: str,
) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                """
                UPDATE service_principal_tokens
                SET expires_at = COALESCE(expires_at, now() + INTERVAL '10 minutes')
                WHERE principal_type = 'dev_cvm'
                  AND principal_id = $1
                  AND purpose IN ('PROXY_AUTH', 'DEV_CONTROL')
                  AND deleted_at IS NULL
                  AND expires_at IS NULL
                """,
                cvm_id,
            )
            await conn.execute(
                """
                INSERT INTO service_principal_tokens (
                    principal_type,
                    principal_id,
                    purpose,
                    token_hash
                )
                VALUES ('dev_cvm', $1, 'PROXY_AUTH', $2)
                """,
                cvm_id,
                proxy_token_hash,
            )
            await conn.execute(
                """
                INSERT INTO service_principal_tokens (
                    principal_type,
                    principal_id,
                    purpose,
                    token_hash
                )
                VALUES ('dev_cvm', $1, 'DEV_CONTROL', $2)
                """,
                cvm_id,
                dev_control_token_hash,
            )
            await conn.execute(
                """
                UPDATE cvms
                SET metadata = $2::jsonb,
                    compose_config = $3,
                    expected_image_measurement = $4,
                    image_measurement = NULL,
                    rtmr3_digest = NULL,
                    attestation_verified_at = NULL,
                    updated_at = now()
                WHERE id = $1
                  AND state IN ('RUNNING', 'STOPPED', 'FAILED')
                  AND deleted_at IS NULL
                """,
                cvm_id,
                json.dumps(metadata),
                compose_config,
                expected_image_measurement,
            )
            await conn.execute(
                """
                UPDATE operations
                SET progress_step = 'await_provider_running',
                    progress_percent = $3,
                    updated_at = now()
                WHERE id = $1
                  AND target_id = $2
                  AND kind = 'cvm.update'
                  AND status = 'running'
                """,
                operation_id,
                cvm_id,
                CVM_UPDATE_PROGRESS["await_provider_running"],
            )


async def persist_cvm_dns_record(operation_id: Any, *, cvm_id: Any, field: str, record_id: str) -> None:
    if field == "txt":
        column = "txt_dns_record_id"
        next_step = "cf_cname_create"
    elif field == "cname":
        column = "cname_dns_record_id"
        next_step = "verify_attestation"
    else:
        raise ValueError("unknown CVM DNS record field")
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                f"""
                UPDATE cvms
                SET {column} = $2,
                    updated_at = now()
                WHERE id = $1
                  AND state = 'PROVISIONING'
                """,
                cvm_id,
                record_id,
            )
            await advance_cvm_launch_step_with_conn(conn, operation_id, next_step)


async def advance_cvm_launch_step(operation_id: Any, next_step: str) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await advance_cvm_launch_step_with_conn(conn, operation_id, next_step)


async def advance_cvm_launch_step_with_conn(conn: Any, operation_id: Any, next_step: str) -> None:
    await _advance_operation_step_with_conn(
        conn, operation_id, next_step,
        kind="cvm.launch", progress=CVM_LAUNCH_PROGRESS,
    )


async def advance_cvm_update_step(operation_id: Any, next_step: str) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await advance_cvm_update_step_with_conn(conn, operation_id, next_step)


async def advance_cvm_update_step_with_conn(conn: Any, operation_id: Any, next_step: str) -> None:
    await _advance_operation_step_with_conn(
        conn, operation_id, next_step,
        kind="cvm.update", progress=CVM_UPDATE_PROGRESS,
    )


async def mark_cvm_launch_failed(operation_id: Any, *, code: str, details: dict[str, Any]) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT target_id
                FROM operations
                WHERE id = $1
                  AND kind = 'cvm.launch'
                """,
                operation_id,
            )
            if row is not None and row["target_id"] is not None:
                await conn.execute(
                    """
                    UPDATE service_principal_tokens
                    SET deleted_at = now()
                    WHERE principal_type = 'dev_cvm'
                      AND principal_id = $1
                      AND purpose IN ('PROXY_AUTH', 'DEV_CONTROL')
                      AND deleted_at IS NULL
                    """,
                    row["target_id"],
                )
                await conn.execute(
                    """
                    UPDATE cvms
                    SET state = 'FAILED',
                        error_reason = $2,
                        updated_at = now()
                    WHERE id = $1
                      AND state = 'PROVISIONING'
                    """,
                    row["target_id"],
                    code,
                )
            await conn.execute(
                """
                UPDATE operations
                SET status = 'failed',
                    error = $2::jsonb,
                    updated_at = now(),
                    expires_at = $3
                WHERE id = $1
                  AND status = 'running'
                """,
                operation_id,
                json.dumps(operation_error_payload({"code": code, "details": details})),
                operation_expiry(),
            )


async def mark_cvm_update_failed(
    operation_id: Any,
    *,
    code: str,
    details: dict[str, Any],
    mark_cvm_failed: bool = False,
) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT
                    o.target_id,
                    o.actor_id,
                    o.actor_email,
                    c.entity_id,
                    c.state::text AS state,
                    c.error_reason
                FROM operations o
                LEFT JOIN cvms c ON c.id = o.target_id
                WHERE o.id = $1
                  AND o.kind = 'cvm.update'
                """,
                operation_id,
            )
            if row is not None and row["target_id"] is not None:
                if mark_cvm_failed:
                    await conn.execute(
                        """
                        UPDATE cvms
                        SET state = 'FAILED',
                            error_reason = $2,
                            updated_at = now()
                        WHERE id = $1
                          AND state IN ('RUNNING', 'STOPPED', 'FAILED')
                          AND deleted_at IS NULL
                        """,
                        row["target_id"],
                        code,
                    )
                if row["entity_id"] is not None:
                    await insert_audit_event(
                        conn,
                        entity_id=row["entity_id"],
                        actor_id=row["actor_id"],
                        actor_email=row["actor_email"],
                        action="CVM_UPDATE_FAILED",
                        target_type="cvm",
                        target_id=row["target_id"],
                        before={"state": row["state"], "error_reason": row["error_reason"]},
                        after={"state": "FAILED" if mark_cvm_failed else row["state"], "error_reason": code},
                    )
            await conn.execute(
                """
                UPDATE operations
                SET status = 'failed',
                    error = $2::jsonb,
                    updated_at = now(),
                    expires_at = $3
                WHERE id = $1
                  AND status = 'running'
                """,
                operation_id,
                json.dumps(operation_error_payload({"code": code, "details": details})),
                operation_expiry(),
            )


async def compensate_cvm_launch_resources(snapshot: Any) -> None:
    from concrete_console.dns_provider.cloudflare import CloudflareClient, CloudflareError
    from concrete_console.tee_provider.phala import PhalaClient, PhalaError

    if keep_failed_cvm_resources():
        # Debug-only log line: derive everything from `metadata` (guaranteed present —
        # used unconditionally just below). Never reference snapshot keys that may be
        # absent: `_row_value` is a hard subscript and a KeyError here would crash the
        # saga step inside its except handler and trigger an infinite retry loop.
        metadata = _row_value(snapshot, "metadata")
        log.warning(
            "cvm_launch_compensation_skipped",
            reason="CONCRETE_KEEP_FAILED_CVM",
            app_id=provider_app_id(metadata),
        )
        return

    with suppress(CloudflareError):
        cloudflare = CloudflareClient.from_settings()
        for field in ("cname_dns_record_id", "txt_dns_record_id"):
            record_id = _row_value(snapshot, field)
            if isinstance(record_id, str) and record_id:
                await cloudflare.delete_record(record_id)
    app_id = provider_app_id(_row_value(snapshot, "metadata"))
    if app_id is not None:
        with suppress(PhalaError):
            await PhalaClient.from_settings().delete(app_id)


class SecurityCVMCAFetchError(RuntimeError):
    def __init__(self, *, http_status: int, reason: str = ""):
        super().__init__(f"ca_fetch_failed: {reason or http_status}")
        self.http_status = http_status
        # `http_status == 0` covers several distinct connection-level failures (TLS, connect,
        # no/garbled response); `reason` disambiguates them so the failure is not opaque.
        self.reason = reason


async def fetch_security_cvm_ca_pem(*, fqdn: str, ca_export_token: str, connect_host: str | None = None) -> str:
    import ssl

    # Connect to a pre-resolved IP when supplied so the freshly-created gateway CNAME's
    # intermittent NXDOMAIN cannot fail this single-shot connect; TLS SNI and HTTP Host
    # stay the FQDN (the leaf cert and gateway routing key remain the FQDN).
    target_host = connect_host or fqdn
    request = (
        "GET /ca.pem HTTP/1.1\r\n"
        f"Host: {fqdn}\r\n"
        f"Authorization: Bearer {ca_export_token}\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    try:
        context = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, 443, ssl=context, server_hostname=fqdn),
            timeout=15.0,
        )
        writer.write(request.encode("utf-8"))
        await writer.drain()
        raw_response = await asyncio.wait_for(reader.read(), timeout=15.0)
        writer.close()
        await writer.wait_closed()
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        raise SecurityCVMCAFetchError(http_status=0, reason=f"{type(exc).__name__}: {exc}") from exc
    header_bytes, separator, body_bytes = raw_response.partition(b"\r\n\r\n")
    if not separator:
        raise SecurityCVMCAFetchError(http_status=0, reason="no_http_separator")
    status_line = header_bytes.splitlines()[0].decode("iso-8859-1", errors="replace")
    try:
        status_code = int(status_line.split()[1])
    except (IndexError, ValueError) as exc:
        raise SecurityCVMCAFetchError(http_status=0, reason="bad_status_line") from exc
    if status_code != 200:
        raise SecurityCVMCAFetchError(http_status=status_code, reason="non_200")
    body = body_bytes.decode("utf-8", errors="replace")
    if "-----BEGIN CERTIFICATE-----" not in body or "-----END CERTIFICATE-----" not in body:
        raise SecurityCVMCAFetchError(http_status=200, reason="no_certificate_in_body")
    return body


def security_cvm_ca_export_stash_available(snapshot: Any) -> bool:
    ca_export_token = _row_value(snapshot, "ca_export_token_plaintext")
    ca_export_stashed_at = _row_value(snapshot, "ca_export_token_stashed_at")
    if not all(
        [
            isinstance(ca_export_token, str) and ca_export_token,
            isinstance(ca_export_stashed_at, datetime),
        ]
    ):
        return False
    return datetime.now(timezone.utc) - _as_utc(ca_export_stashed_at) <= timedelta(
        seconds=SECURITY_CVM_TOKEN_PLAINTEXT_TTL_SECONDS
    )


def provider_gateway_host(metadata: Any) -> str | None:
    metadata = json_payload(metadata or {})
    if not isinstance(metadata, dict):
        return None
    gateway_host = metadata.get("gateway_host")
    return gateway_host if isinstance(gateway_host, str) and gateway_host else None


def cvm_launch_provider_name(cvm_id: Any) -> str:
    token = str(cvm_id).replace("-", "")[:16]
    return f"concrete-v0-cvm-{token}"


def security_cvm_provider_name(security_cvm_id: Any) -> str:
    token = str(security_cvm_id).replace("-", "")[:16]
    return f"concrete-v0-sc-{token}"


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def b64_text(value: str) -> str:
    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def b64_json(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"))
    return b64_text(payload)


def provider_app_id(metadata: Any) -> str | None:
    metadata = json_payload(metadata or {})
    if not isinstance(metadata, dict):
        return None
    app_id = metadata.get("app_id")
    return app_id if isinstance(app_id, str) and app_id else None


def dev_cvm_update_material() -> dict[str, str]:
    raw = load_settings().raw
    image = raw.get("DEV_CVM_IMAGE", "").strip()
    measurement = raw.get("DEV_CVM_IMAGE_MEASUREMENT", "").strip().lower()
    if not image:
        raise ValueError("DEV_CVM_IMAGE_UNCONFIGURED")
    if not is_hex_measurement(measurement):
        raise ValueError("DEV_CVM_IMAGE_MEASUREMENT_UNCONFIGURED")
    from concrete_console.routes import render_dev_cvm_compose_config

    return {
        "compose_config": render_dev_cvm_compose_config({"image": image}),
        "expected_image_measurement": measurement,
    }


def security_cvm_update_material() -> dict[str, str]:
    raw = load_settings().raw
    image = raw.get("SECURITY_CVM_IMAGE_REF", "").strip()
    measurement = raw.get("SECURITY_CVM_IMAGE_MEASUREMENT", "").strip().lower()
    if not image:
        raise ValueError("SECURITY_CVM_IMAGE_UNCONFIGURED")
    if not is_hex_measurement(measurement):
        raise ValueError("SECURITY_CVM_IMAGE_MEASUREMENT_UNCONFIGURED")
    from concrete_console.routes import render_security_cvm_compose_config

    return {
        "compose_config": render_security_cvm_compose_config({"image_ref": image}),
        "expected_image_measurement": measurement,
    }


def is_hex_measurement(value: str) -> bool:
    return len(value) == 96 and all(char in "0123456789abcdef" for char in value)


def operation_expiry() -> datetime:
    raw = load_settings().raw.get("OPERATION_RETENTION_DAYS", "30").strip() or "30"
    try:
        days = int(raw)
    except ValueError:
        days = 30
    return datetime.now(timezone.utc) + timedelta(days=min(max(days, 1), 365))


def pending_operation_start_progress(
    kind: str,
    *,
    progress_step: str | None,
    progress_percent: int | None,
) -> tuple[str, int] | None:
    next_progress = OPERATION_START_STEPS.get(kind)
    if next_progress is None:
        return None
    next_step, minimum_percent = next_progress
    return next_step, max(progress_percent or 0, minimum_percent)


def _row_value(row: Any, key: str) -> Any:
    return row[key]


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def traffic_log_retention_days() -> int:
    raw = load_settings().raw.get("TRAFFIC_LOG_RETENTION_DAYS", "90").strip() or "90"
    try:
        days = int(raw)
    except ValueError:
        return 90
    return min(max(days, 7), 730)


def security_cvm_provisioning_meta_dict(metadata: Any) -> dict[str, Any]:
    base = json_payload(metadata or {})
    return dict(base) if isinstance(base, dict) else {}


def security_cvm_metadata_phala_failed_since(metadata: dict[str, Any]) -> datetime | None:
    prov = metadata.get("provisioning")
    if not isinstance(prov, dict):
        return None
    raw = prov.get("phala_failed_since")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return _as_utc(datetime.fromisoformat(raw.replace("Z", "+00:00")))
    except ValueError:
        return None


def security_cvm_metadata_with_phala_failed(metadata: dict[str, Any], *, failed_at: datetime | None) -> dict[str, Any]:
    out = dict(metadata)
    prov = out.get("provisioning")
    if not isinstance(prov, dict):
        prov = {}
    else:
        prov = dict(prov)
    if failed_at is None:
        prov.pop("phala_failed_since", None)
    elif "phala_failed_since" not in prov:
        prov["phala_failed_since"] = failed_at.isoformat().replace("+00:00", "Z")
    if prov:
        out["provisioning"] = prov
    else:
        out.pop("provisioning", None)
    return out


async def fetch_security_cvm_await_phala_candidates(conn: Any) -> list[Any]:
    async with conn.transaction():
        return list(
            await conn.fetch(
                """
                SELECT
                    sc.id,
                    sc.entity_id,
                    sc.metadata,
                    o.id AS operation_id
                FROM security_cvms sc
                JOIN operations o ON o.target_id = sc.id
                WHERE sc.state = 'PROVISIONING'
                  AND sc.deleted_at IS NULL
                  AND o.kind = 'security_cvm.provision'
                  AND o.status = 'running'
                  AND o.progress_step = 'await_phala_running'
                  AND sc.metadata ? 'app_id'
                ORDER BY sc.created_at
                LIMIT 10
                FOR UPDATE OF sc SKIP LOCKED
                """
            )
        )


async def reconcile_security_cvm_await_phala(conn: Any) -> list[str]:
    from concrete_console.tee_provider.phala import PhalaClient, PhalaError

    try:
        client = PhalaClient.from_settings(timeout_seconds=30.0)
    except PhalaError as exc:
        log.warning("security_cvm_await_phala_skipped", reason=exc.code)
        return []

    advanced: list[str] = []
    rows = await fetch_security_cvm_await_phala_candidates(conn)
    now = datetime.now(timezone.utc)
    for row in rows:
        app_id = provider_app_id(_row_value(row, "metadata"))
        if app_id is None:
            continue
        try:
            provider_status = await client.status(app_id)
        except PhalaError as exc:
            log.warning(
                "security_cvm_await_phala_status_failed",
                security_cvm_id=str(_row_value(row, "id")),
                reason=exc.code,
            )
            continue
        meta = security_cvm_provisioning_meta_dict(_row_value(row, "metadata"))
        if provider_status == "RUNNING":
            cleared = security_cvm_metadata_with_phala_failed(meta, failed_at=None)
            async with conn.transaction():
                result = await conn.execute(
                    """
                    UPDATE security_cvms
                    SET state = 'RUNNING',
                        metadata = $2::jsonb,
                        updated_at = now()
                    WHERE id = $1
                      AND state = 'PROVISIONING'
                      AND deleted_at IS NULL
                    """,
                    _row_value(row, "id"),
                    json.dumps(cleared),
                )
                if result == "UPDATE 1":
                    advanced.append(str(_row_value(row, "id")))
            continue
        if provider_status == "FAILED":
            first_failed = security_cvm_metadata_phala_failed_since(meta)
            updated = security_cvm_metadata_with_phala_failed(meta, failed_at=first_failed or now)
            async with conn.transaction():
                await conn.execute(
                    """
                    UPDATE security_cvms
                    SET metadata = $2::jsonb,
                        updated_at = now()
                    WHERE id = $1
                      AND state = 'PROVISIONING'
                      AND deleted_at IS NULL
                    """,
                    _row_value(row, "id"),
                    json.dumps(updated),
                )
            failed_since = first_failed or now
            if (now - failed_since).total_seconds() > 300:
                operation_id = _row_value(row, "operation_id")
                # The reconciler candidate row carries only id/entity_id/metadata; fetch the
                # full provision snapshot (DNS record ids + metadata) so compensation can tear
                # down the dangling Phala app + Cloudflare records, not just mark FAILED.
                snapshot = await fetch_security_cvm_provision_snapshot(conn, operation_id)
                if snapshot is not None:
                    await compensate_security_cvm_provision_resources(snapshot)
                await mark_security_cvm_provision_failed(
                    operation_id,
                    code="PHALA_NEVER_RUNNING",
                    details={"elapsed_seconds": int((now - failed_since).total_seconds())},
                )
            continue
        if security_cvm_metadata_phala_failed_since(meta) is not None:
            cleared = security_cvm_metadata_with_phala_failed(meta, failed_at=None)
            async with conn.transaction():
                await conn.execute(
                    """
                    UPDATE security_cvms
                    SET metadata = $2::jsonb,
                        updated_at = now()
                    WHERE id = $1
                      AND state = 'PROVISIONING'
                      AND deleted_at IS NULL
                    """,
                    _row_value(row, "id"),
                    json.dumps(cleared),
                )
    return advanced


async def prune_traffic_logs_one_chunk(conn: Any, *, cutoff: datetime, limit: int) -> int:
    status = await conn.execute(
        """
        DELETE FROM traffic_logs
        WHERE id IN (
            SELECT id FROM traffic_logs
            WHERE timestamp < $1
            ORDER BY timestamp
            LIMIT $2
        )
        """,
        cutoff,
        limit,
    )
    return deleted_row_count(status)


async def prune_traffic_log_batches_one_chunk(conn: Any, *, cutoff: datetime, limit: int) -> int:
    status = await conn.execute(
        """
        DELETE FROM traffic_log_batches
        WHERE id IN (
            SELECT id FROM traffic_log_batches tlb
            WHERE tlb.accepted_at < $1
              AND NOT EXISTS (SELECT 1 FROM traffic_logs tl WHERE tl.batch_id = tlb.id)
            ORDER BY tlb.accepted_at
            LIMIT $2
        )
        """,
        cutoff,
        limit,
    )
    return deleted_row_count(status)


async def prune_traffic_logs_retention_pass(conn: Any) -> tuple[int, int]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=traffic_log_retention_days())
    logs_total = 0
    batches_total = 0
    while True:
        async with conn.transaction():
            n = await prune_traffic_logs_one_chunk(conn, cutoff=cutoff, limit=TRAFFIC_LOG_DELETE_CHUNK)
        logs_total += n
        if n < TRAFFIC_LOG_DELETE_CHUNK:
            break
    while True:
        async with conn.transaction():
            n = await prune_traffic_log_batches_one_chunk(conn, cutoff=cutoff, limit=TRAFFIC_LOG_DELETE_CHUNK)
        batches_total += n
        if n < TRAFFIC_LOG_DELETE_CHUNK:
            break
    return logs_total, batches_total


async def maybe_prune_traffic_logs_retention(conn: Any) -> list[str]:
    global _last_traffic_prune_wall
    now = datetime.now(timezone.utc)
    if _last_traffic_prune_wall is not None and (now - _last_traffic_prune_wall).total_seconds() < 86400:
        return []
    locked = await conn.fetchval("SELECT pg_try_advisory_lock($1)", TRAFFIC_LOG_PRUNE_LOCK_ID)
    if not locked:
        return []
    try:
        logs_pruned, batches_pruned = await prune_traffic_logs_retention_pass(conn)
    finally:
        await conn.execute("SELECT pg_advisory_unlock($1)", TRAFFIC_LOG_PRUNE_LOCK_ID)
    _last_traffic_prune_wall = now
    if logs_pruned or batches_pruned:
        log.info("RETENTION_PRUNED", traffic_logs_deleted=logs_pruned, traffic_log_batches_deleted=batches_pruned)
        return [f"maintenance:traffic_logs:{logs_pruned}:{batches_pruned}"]
    return []


async def run_reconciliation_pass(*, include_orphans: bool = True) -> ReconciliationSummary:
    pool = await get_pool()
    async with pool.acquire() as conn:
        cvms_advanced = await reconcile_dev_cvm_provider_drift(conn)
        security_cvms_advanced = await reconcile_security_cvm_await_phala(conn)
        security_cvms_advanced.extend(await reconcile_security_cvm_provider_drift(conn))
        orphans_cleaned = await cleanup_orphan_dns_records(conn) if include_orphans else []
        orphans_cleaned.extend(await prune_expired_auth_flow_rows(conn))
        orphans_cleaned.extend(await prune_expired_reconciler_rows(conn))
        operation_prune_count = await prune_expired_operations(conn)
        if operation_prune_count:
            orphans_cleaned.append(f"maintenance:operations:{operation_prune_count}")
        orphans_cleaned.extend(await maybe_prune_traffic_logs_retention(conn))
        security_cvms_advanced.extend(await reconcile_security_cvm_attestations(conn))
        cvms_advanced.extend(await reconcile_dev_cvm_attestations(conn))
        await publish_audit_anchor_if_due(conn)
    return ReconciliationSummary(
        cvms_advanced=cvms_advanced,
        security_cvms_advanced=security_cvms_advanced,
        orphans_cleaned=orphans_cleaned,
    )


async def _reconcile_cvm_provider_drift(
    conn: Any,
    kind: CvmKind,
    *,
    fetch_candidates: Any,
    persist_drift: Any,
) -> list[str]:
    """Shared provider-drift reconciler loop for Dev CVMs and Security CVMs: poll the Phala
    status of each RUNNING candidate and persist FAILED/STOPPED drift. ``kind`` namespaces the
    structlog events and the id field they carry."""
    from concrete_console.tee_provider.phala import PhalaClient, PhalaError

    try:
        client = PhalaClient.from_settings(timeout_seconds=30.0)
    except PhalaError as exc:
        log.warning(f"{kind.slug}_provider_drift_skipped", reason=exc.code)
        return []

    advanced: list[str] = []
    rows = await fetch_candidates(conn)
    for row in rows:
        app_id = provider_app_id(_row_value(row, "metadata"))
        if app_id is None:
            continue
        try:
            provider_status = await client.status(app_id)
        except PhalaError as exc:
            log.warning(
                f"{kind.slug}_provider_drift_status_failed",
                reason=exc.code,
                **{kind.log_id_key: str(_row_value(row, "id"))},
            )
            continue
        target_state = provider_drift_target_state(provider_status)
        if target_state is None:
            continue
        if await persist_drift(conn, row, provider_status=provider_status, target_state=target_state):
            advanced.append(str(_row_value(row, "id")))
    return advanced


async def reconcile_dev_cvm_provider_drift(conn: Any) -> list[str]:
    return await _reconcile_cvm_provider_drift(
        conn,
        DEV_CVM,
        fetch_candidates=fetch_dev_cvm_provider_drift_candidates,
        persist_drift=persist_dev_cvm_provider_drift,
    )


async def reconcile_security_cvm_provider_drift(conn: Any) -> list[str]:
    return await _reconcile_cvm_provider_drift(
        conn,
        SECURITY_CVM,
        fetch_candidates=fetch_security_cvm_provider_drift_candidates,
        persist_drift=persist_security_cvm_provider_drift,
    )


def _provider_drift_candidates_query(kind: CvmKind) -> str:
    """RUNNING CVMs with a provider app_id and no in-flight operation — the reconciler's
    provider-drift candidate set."""
    return f"""
        SELECT
            {kind.alias}.id,
            {kind.alias}.entity_id,
            {kind.alias}.state::text AS state,
            {kind.alias}.metadata,
            {kind.alias}.error_reason
        FROM {kind.table} {kind.alias}
        WHERE {kind.alias}.state = 'RUNNING'
          AND {kind.alias}.deleted_at IS NULL
          AND {kind.alias}.metadata ? 'app_id'
          AND NOT EXISTS (
            SELECT 1
            FROM operations o
            WHERE o.target_id = {kind.alias}.id
              AND o.status IN ('pending', 'running')
          )
        ORDER BY {kind.alias}.created_at
        LIMIT 10
        FOR UPDATE SKIP LOCKED
        """


async def fetch_dev_cvm_provider_drift_candidates(conn: Any) -> list[Any]:
    async with conn.transaction():
        return list(await conn.fetch(_provider_drift_candidates_query(DEV_CVM)))


async def fetch_security_cvm_provider_drift_candidates(conn: Any) -> list[Any]:
    async with conn.transaction():
        return list(await conn.fetch(_provider_drift_candidates_query(SECURITY_CVM)))


def provider_drift_target_state(provider_status: str) -> str | None:
    if provider_status in {"FAILED", "STOPPED"}:
        return provider_status
    return None


async def _persist_cvm_provider_drift(
    conn: Any,
    row: Any,
    kind: CvmKind,
    *,
    provider_status: str,
    target_state: str,
) -> bool:
    """Shared reconciler drift writer for Dev CVMs and Security CVMs."""
    if target_state not in {"FAILED", "STOPPED"}:
        raise ValueError("unsupported provider drift state")
    error_reason = "PHALA_OBSERVED_FAILED" if target_state == "FAILED" else None
    action = (
        f"{kind.audit_prefix}_FAILED" if target_state == "FAILED" else f"{kind.audit_prefix}_STOPPED"
    )
    async with conn.transaction():
        result = await conn.execute(
            f"""
            UPDATE {kind.table}
            SET state = $2::cvm_state,
                error_reason = $3,
                updated_at = now()
            WHERE id = $1
              AND state = 'RUNNING'
              AND deleted_at IS NULL
              AND NOT EXISTS (
                SELECT 1
                FROM operations o
                WHERE o.target_id = {kind.table}.id
                  AND o.status IN ('pending', 'running')
              )
            """,
            _row_value(row, "id"),
            target_state,
            error_reason,
        )
        if result != "UPDATE 1":
            return False
        after: dict[str, Any] = {
            "state": target_state,
            "provider_status": provider_status,
            "source": "reconciler",
        }
        if error_reason is not None:
            after["error_reason"] = error_reason
        await insert_audit_event(
            conn,
            entity_id=_row_value(row, "entity_id"),
            actor_id=None,
            actor_email="reconciler@concrete.system",
            action=action,
            target_type=kind.audit_target,
            target_id=_row_value(row, "id"),
            before={
                "state": _row_value(row, "state"),
                "error_reason": _row_value(row, "error_reason"),
            },
            after=after,
        )
    return True


async def persist_dev_cvm_provider_drift(
    conn: Any,
    row: Any,
    *,
    provider_status: str,
    target_state: str,
) -> bool:
    return await _persist_cvm_provider_drift(
        conn, row, DEV_CVM, provider_status=provider_status, target_state=target_state
    )


async def persist_security_cvm_provider_drift(
    conn: Any,
    row: Any,
    *,
    provider_status: str,
    target_state: str,
) -> bool:
    return await _persist_cvm_provider_drift(
        conn, row, SECURITY_CVM, provider_status=provider_status, target_state=target_state
    )


async def prune_expired_reconciler_rows(conn: Any) -> list[str]:
    cleaned: list[str] = []
    for table, key_column in (
        ("revoked_tokens", "jti"),
        ("idempotency_keys", "id"),
    ):
        status = await conn.execute(
            f"""
            WITH expired AS (
                SELECT {key_column}
                FROM {table}
                WHERE expires_at < now() - INTERVAL '1 day'
                ORDER BY expires_at
                LIMIT 1000
                FOR UPDATE SKIP LOCKED
            )
            DELETE FROM {table}
            WHERE {key_column} IN (SELECT {key_column} FROM expired)
            """
        )
        count = deleted_row_count(status)
        if count:
            cleaned.append(f"maintenance:{table}:{count}")
    return cleaned


async def prune_expired_auth_flow_rows(conn: Any) -> list[str]:
    cleaned: list[str] = []
    for table, key_column in (
        ("loopback_auth_pending", "state"),
        ("device_flow_pending", "device_code"),
    ):
        status = await conn.execute(
            f"""
            WITH expired AS (
                SELECT {key_column}
                FROM {table}
                WHERE expires_at < now()
                ORDER BY expires_at
                LIMIT 1000
                FOR UPDATE SKIP LOCKED
            )
            DELETE FROM {table}
            WHERE {key_column} IN (SELECT {key_column} FROM expired)
            """
        )
        count = deleted_row_count(status)
        if count:
            cleaned.append(f"maintenance:{table}:{count}")
    return cleaned


async def prune_expired_operations(conn: Any) -> int:
    status = await conn.execute(
        """
        WITH expired AS (
            SELECT id
            FROM operations
            WHERE expires_at IS NOT NULL
              AND expires_at < now()
            ORDER BY expires_at
            LIMIT 1000
            FOR UPDATE SKIP LOCKED
        )
        DELETE FROM operations
        WHERE id IN (SELECT id FROM expired)
        """
    )
    return deleted_row_count(status)


def deleted_row_count(status: str) -> int:
    try:
        command, count = status.rsplit(" ", 1)
    except ValueError:
        return 0
    if command != "DELETE":
        return 0
    try:
        return int(count)
    except ValueError:
        return 0


async def cleanup_orphan_dns_records(conn: Any) -> list[str]:
    from concrete_console.dns_provider.cloudflare import CloudflareClient, CloudflareError

    cleaned: list[str] = []
    async with conn.transaction():
        dev_rows = await conn.fetch(
            """
            SELECT id, txt_dns_record_id, cname_dns_record_id
            FROM cvms
            WHERE deleted_at IS NOT NULL
              AND deleted_at < now() - INTERVAL '5 minutes'
              AND (txt_dns_record_id IS NOT NULL OR cname_dns_record_id IS NOT NULL)
            ORDER BY deleted_at
            LIMIT 50
            FOR UPDATE SKIP LOCKED
            """
        )
        security_rows = await conn.fetch(
            """
            SELECT id, txt_dns_record_id, cname_dns_record_id
            FROM security_cvms
            WHERE deleted_at IS NOT NULL
              AND deleted_at < now() - INTERVAL '5 minutes'
              AND (txt_dns_record_id IS NOT NULL OR cname_dns_record_id IS NOT NULL)
            ORDER BY deleted_at
            LIMIT 50
            FOR UPDATE SKIP LOCKED
            """
        )
        if dev_rows:
            try:
                client = CloudflareClient.from_settings()
            except CloudflareError as exc:
                log.warning("orphan_dev_dns_cleanup_skipped", reason=exc.code)
            else:
                cleaned.extend(await cleanup_orphan_dns_rows(conn, dev_rows, table="cvms", resource="cvm", client=client))
        if security_rows:
            try:
                client = CloudflareClient.from_settings(zone_id_key="SECURITY_CVM_ZONE_ID")
            except CloudflareError as exc:
                log.warning("orphan_security_cvm_dns_cleanup_skipped", reason=exc.code)
            else:
                cleaned.extend(
                    await cleanup_orphan_dns_rows(
                        conn,
                        security_rows,
                        table="security_cvms",
                        resource="security_cvm",
                        client=client,
                    )
            )
    return cleaned


async def cleanup_orphan_dns_rows(conn: Any, rows: list[Any], *, table: str, resource: str, client: Any) -> list[str]:
    from concrete_console.dns_provider.cloudflare import CloudflareError

    cleaned: list[str] = []
    for row in rows:
        for field in ("txt_dns_record_id", "cname_dns_record_id"):
            record_id = _row_value(row, field)
            if not isinstance(record_id, str) or not record_id:
                continue
            try:
                await client.delete_record(record_id)
            except CloudflareError as exc:
                log.warning(
                    "orphan_dns_cleanup_failed",
                    resource=resource,
                    resource_id=str(_row_value(row, "id")),
                    record_id=record_id,
                    reason=exc.code,
                )
                continue
            await null_orphan_dns_record(conn, table=table, field=field, row_id=_row_value(row, "id"))
            cleaned.append(f"{resource}:{_row_value(row, 'id')}:{field}")
    return cleaned


async def null_orphan_dns_record(conn: Any, *, table: str, field: str, row_id: Any) -> None:
    if table not in {"cvms", "security_cvms"}:
        raise ValueError("unsupported orphan DNS table")
    if field not in {"txt_dns_record_id", "cname_dns_record_id"}:
        raise ValueError("unsupported orphan DNS field")
    await conn.execute(
        f"""
        UPDATE {table}
        SET {field} = NULL,
            updated_at = now()
        WHERE id = $1
        """,
        row_id,
    )


async def reconcile_security_cvm_attestations(conn: Any) -> list[str]:
    from concrete_console.attestation import (
        AtlasVerifierClient,
        AttestationVerifierError,
        AttestationVerifierUnavailable,
        build_security_cvm_attestation_request,
    )
    from concrete_console.shade_provider.shade import ShadeError

    try:
        verifier = AtlasVerifierClient.from_settings()
    except AttestationVerifierUnavailable:
        return []
    interval = reconciler_attestation_interval_seconds()
    advanced: list[str] = []
    # Claim candidates in a SHORT transaction, then release the FOR UPDATE locks and the
    # in-transaction connection BEFORE running the shade + verifier subprocesses: a reconciler
    # step never holds a transaction across an external call (console.md §13.1) — otherwise a
    # slow/cold shade or verify pins the pool connection and locks up to 10 SC rows for the
    # whole window. Each persist then re-opens its own short, state-guarded transaction.
    async with conn.transaction():
        rows = await conn.fetch(
            """
            SELECT
                sc.id,
                sc.entity_id,
                sc.fqdn,
                sc.compose_config,
                sc.expected_image_measurement,
                sc.image_measurement,
                sc.rtmr3_digest,
                sc.attestation_verified_at,
                sc.error_reason,
                sc.metadata
            FROM security_cvms sc
            WHERE sc.state = 'RUNNING'
              AND sc.deleted_at IS NULL
              AND (
                sc.attestation_verified_at IS NULL
                OR sc.attestation_verified_at < now() - ($1::int * INTERVAL '1 second')
              )
              AND NOT EXISTS (
                SELECT 1
                FROM operations o
                WHERE o.target_id = sc.id
                  AND o.status IN ('pending', 'running')
              )
            ORDER BY sc.created_at
            LIMIT 10
            FOR UPDATE SKIP LOCKED
            """,
            interval,
        )
        candidates = [dict(row) for row in rows]
    for row in candidates:
        token_hashes = await fetch_security_cvm_token_hashes(conn, _row_value(row, "id"))
        try:
            # Full runtime re-verification (never dev()): regenerate the shade policy from
            # the deployed compose so drift detection actually exercises compose-hash +
            # bootchain + RTMR3 against the live quote (T-30 runtime-config tampering, §9.2),
            # not just the shared MRTD.
            shade_policy = await materialize_security_cvm_shade_policy_for_attestation(row)
            request = build_security_cvm_attestation_request(
                row,
                token_hashes=token_hashes,
                console_url=load_settings().raw.get("CONSOLE_URL", "http://localhost:8000"),
                shade_policy=shade_policy,
            )
            report = await verifier.verify(request, timeout_seconds=30)
        except ShadeError as exc:
            log.warning(
                "security_cvm_attestation_refresh_shade_failed",
                security_cvm_id=str(_row_value(row, "id")),
                **shade_error_log_fields(exc),
            )
            continue
        except AttestationVerifierError as exc:
            log.warning(
                "security_cvm_attestation_refresh_failed",
                security_cvm_id=str(_row_value(row, "id")),
                code=exc.code,
            )
            continue

        drift_kind = attestation_drift_kind(
            expected_image_measurement=_row_value(row, "expected_image_measurement"),
            persisted_image_measurement=_row_value(row, "image_measurement"),
            persisted_rtmr3_digest=_row_value(row, "rtmr3_digest"),
            reported_image_measurement=report.image_measurement,
            reported_rtmr3_digest=report.rtmr3_digest,
        )
        async with conn.transaction():
            if drift_kind is None:
                persisted = await persist_security_cvm_attestation_refresh(conn, row, report)
            else:
                persisted = await record_security_cvm_attestation_refresh_drift(conn, row, report, drift_kind=drift_kind)
        if persisted:
            advanced.append(str(_row_value(row, "id")))
    return advanced


async def reconcile_dev_cvm_attestations(conn: Any) -> list[str]:
    from concrete_console.attestation import (
        AtlasVerifierClient,
        AttestationVerifierError,
        AttestationVerifierUnavailable,
        build_dev_cvm_attestation_request,
    )

    try:
        verifier = AtlasVerifierClient.from_settings()
    except AttestationVerifierUnavailable:
        return []
    interval = reconciler_attestation_interval_seconds()
    advanced: list[str] = []
    # Claim candidates in a SHORT transaction, then release the FOR UPDATE locks before the
    # verifier subprocess: a reconciler step never holds a transaction across an external call
    # (console.md §13.1). Each persist then re-opens its own short, state-guarded transaction.
    async with conn.transaction():
        rows = await conn.fetch(
            """
            SELECT
                c.id,
                c.entity_id,
                c.fqdn,
                c.metadata,
                c.expected_image_measurement,
                c.image_measurement,
                c.rtmr3_digest,
                c.attestation_verified_at,
                c.error_reason
            FROM cvms c
            WHERE c.state = 'RUNNING'
              AND c.deleted_at IS NULL
              AND (
                c.attestation_verified_at IS NULL
                OR c.attestation_verified_at < now() - ($1::int * INTERVAL '1 second')
              )
              AND NOT EXISTS (
                SELECT 1
                FROM operations o
                WHERE o.target_id = c.id
                  AND o.status IN ('pending', 'running')
              )
            ORDER BY c.created_at
            LIMIT 10
            FOR UPDATE SKIP LOCKED
            """,
            interval,
        )
        candidates = [dict(row) for row in rows]
    for row in candidates:
        try:
            request = build_dev_cvm_attestation_request(row)
            report = await verifier.verify(request, timeout_seconds=30)
        except AttestationVerifierError as exc:
            log.warning(
                "dev_cvm_attestation_refresh_failed",
                cvm_id=str(_row_value(row, "id")),
                code=exc.code,
            )
            continue

        drift_kind = attestation_drift_kind(
            expected_image_measurement=_row_value(row, "expected_image_measurement"),
            persisted_image_measurement=_row_value(row, "image_measurement"),
            persisted_rtmr3_digest=_row_value(row, "rtmr3_digest"),
            reported_image_measurement=report.image_measurement,
            reported_rtmr3_digest=report.rtmr3_digest,
        )
        async with conn.transaction():
            if drift_kind is None:
                persisted = await persist_dev_cvm_attestation_refresh(conn, row, report)
            else:
                persisted = await record_dev_cvm_attestation_refresh_drift(conn, row, report, drift_kind=drift_kind)
        if persisted:
            advanced.append(str(_row_value(row, "id")))
    return advanced


async def fetch_security_cvm_token_hashes(conn: Any, security_cvm_id: Any) -> dict[str, str]:
    rows = await conn.fetch(
        """
        SELECT purpose::text AS purpose, token_hash
        FROM service_principal_tokens
        WHERE principal_type = 'security_cvm'
          AND principal_id = $1
          AND purpose IN ('INGEST', 'CA_EXPORT')
          AND deleted_at IS NULL
          AND (expires_at IS NULL OR expires_at > now())
        ORDER BY purpose::text, expires_at NULLS FIRST, issued_at DESC
        """,
        security_cvm_id,
    )
    hashes: dict[str, str] = {}
    for row in rows:
        hashes.setdefault(row["purpose"], row["token_hash"])
    return hashes


def attestation_drift_kind(
    *,
    expected_image_measurement: str,
    persisted_image_measurement: str | None,
    persisted_rtmr3_digest: str | None,
    reported_image_measurement: str,
    reported_rtmr3_digest: str,
) -> str | None:
    image_drift = reported_image_measurement != expected_image_measurement
    if persisted_image_measurement is not None and persisted_image_measurement != reported_image_measurement:
        image_drift = True
    rtmr3_drift = persisted_rtmr3_digest is not None and persisted_rtmr3_digest != reported_rtmr3_digest
    if image_drift and rtmr3_drift:
        return "both"
    if image_drift:
        return "image"
    if rtmr3_drift:
        return "rtmr3"
    return None


async def _persist_cvm_attestation_refresh(conn: Any, row: Any, report: Any, kind: CvmKind) -> bool:
    """Shared reconciler attestation-refresh writer for Dev CVMs and Security CVMs. Returns
    True iff the row was still RUNNING and persisted. The reconciler claims candidates then
    releases the row lock before the (slow) verify, so the CVM may have been terminated/failed
    concurrently — if the state-guarded UPDATE matches 0 rows, skip the (otherwise misleading)
    audit event and report no progress, mirroring the per-operation verifier guard."""
    verified_at = datetime.now(timezone.utc)
    result = await conn.execute(
        f"""
        UPDATE {kind.table}
        SET image_measurement = $2,
            rtmr3_digest = $3,
            attestation_verified_at = $4,
            error_reason = NULL,
            updated_at = now()
        WHERE id = $1
          AND state = 'RUNNING'
          AND deleted_at IS NULL
        """,
        _row_value(row, "id"),
        report.image_measurement,
        report.rtmr3_digest,
        verified_at,
    )
    if result != "UPDATE 1":
        log.warning(
            f"{kind.slug}_attestation_refresh_skipped",
            **{kind.log_id_key: str(_row_value(row, "id"))},
            result=result,
        )
        return False
    await insert_audit_event(
        conn,
        entity_id=_row_value(row, "entity_id"),
        actor_id=None,
        actor_email="reconciler@concrete.system",
        action=f"{kind.audit_prefix}_ATTESTATION_VERIFIED",
        target_type=kind.audit_target,
        target_id=_row_value(row, "id"),
        before={
            "image_measurement": _row_value(row, "image_measurement"),
            "rtmr3_digest": _row_value(row, "rtmr3_digest"),
        },
        after={
            "image_measurement": report.image_measurement,
            "rtmr3_digest": report.rtmr3_digest,
            "attestation_verified_at": verified_at.isoformat().replace("+00:00", "Z"),
            "source": "reconciler",
        },
    )
    return True


async def _record_cvm_attestation_refresh_drift(
    conn: Any, row: Any, report: Any, kind: CvmKind, *, drift_kind: str
) -> bool:
    """Returns True iff the still-RUNNING row was marked drifted. See
    _persist_cvm_attestation_refresh for why the rowcount is guarded."""
    result = await conn.execute(
        f"""
        UPDATE {kind.table}
        SET error_reason = 'ATTESTATION_DRIFT',
            updated_at = now()
        WHERE id = $1
          AND state = 'RUNNING'
          AND deleted_at IS NULL
        """,
        _row_value(row, "id"),
    )
    if result != "UPDATE 1":
        log.warning(
            f"{kind.slug}_attestation_drift_skipped",
            **{kind.log_id_key: str(_row_value(row, "id"))},
            result=result,
        )
        return False
    await insert_audit_event(
        conn,
        entity_id=_row_value(row, "entity_id"),
        actor_id=None,
        actor_email="reconciler@concrete.system",
        action=f"{kind.audit_prefix}_ATTESTATION_DRIFT",
        target_type=kind.audit_target,
        target_id=_row_value(row, "id"),
        before={
            "image_measurement": _row_value(row, "image_measurement"),
            "rtmr3_digest": _row_value(row, "rtmr3_digest"),
        },
        after={
            "image_measurement": report.image_measurement,
            "rtmr3_digest": report.rtmr3_digest,
            "drift_kind": drift_kind,
            "source": "reconciler",
        },
    )
    return True


async def persist_security_cvm_attestation_refresh(conn: Any, row: Any, report: Any) -> bool:
    return await _persist_cvm_attestation_refresh(conn, row, report, SECURITY_CVM)


async def record_security_cvm_attestation_refresh_drift(conn: Any, row: Any, report: Any, *, drift_kind: str) -> bool:
    return await _record_cvm_attestation_refresh_drift(conn, row, report, SECURITY_CVM, drift_kind=drift_kind)


async def persist_dev_cvm_attestation_refresh(conn: Any, row: Any, report: Any) -> bool:
    return await _persist_cvm_attestation_refresh(conn, row, report, DEV_CVM)


async def record_dev_cvm_attestation_refresh_drift(conn: Any, row: Any, report: Any, *, drift_kind: str) -> bool:
    return await _record_cvm_attestation_refresh_drift(conn, row, report, DEV_CVM, drift_kind=drift_kind)


def mark_scheduler_tick_success(*, now: float | None = None) -> None:
    global _last_successful_tick_monotonic
    _last_successful_tick_monotonic = time.monotonic() if now is None else now


def check_operation_scheduler_recent(*, now: float | None = None) -> None:
    if _last_successful_tick_monotonic is None:
        raise RuntimeError("operation scheduler has not ticked")
    current = time.monotonic() if now is None else now
    if current - _last_successful_tick_monotonic > 2 * reconciler_interval_seconds():
        raise RuntimeError("operation scheduler tick is stale")


def scheduler_last_tick_age_seconds(*, now: float | None = None) -> float | None:
    if _last_successful_tick_monotonic is None:
        return None
    current = time.monotonic() if now is None else now
    return max(0.0, current - _last_successful_tick_monotonic)
