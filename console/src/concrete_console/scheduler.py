from __future__ import annotations

import asyncio
import base64
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import secrets
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
OPERATION_START_STEPS = {
    "audit.export": ("materialize", 20),
    "cvm.launch": ("phala_deploy", 20),
    "cvm.terminate": ("phala_terminate", 25),
    "security_cvm.provision": ("phala_deploy", 20),
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
SECURITY_CVM_PROVISION_EXECUTABLE_STEPS = {
    "phala_deploy",
    "cf_txt_create",
    "cf_cname_create",
    "verify_attestation",
    "fetch_ca",
    "finalise",
}
SECURITY_CVM_PROVISION_PROGRESS = {
    "cf_txt_create": 40,
    "cf_cname_create": 50,
    "verify_attestation": 60,
    "fetch_ca": 80,
    "finalise": 90,
}
AUDIT_EXPORT_EXECUTABLE_STEPS = {"materialize"}
AUDIT_EXPORT_ROW_CAP = 1_000_000
SECURITY_CVM_TOKEN_PLAINTEXT_TTL_SECONDS = 3600


@dataclass(frozen=True)
class ReconciliationSummary:
    cvms_advanced: list[str]
    security_cvms_advanced: list[str]
    orphans_cleaned: list[str]


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


def reconciler_attestation_interval_seconds() -> int:
    raw = load_settings().raw.get("RECONCILER_ATTESTATION_INTERVAL_SECONDS", "21600").strip() or "21600"
    try:
        interval = int(raw)
    except ValueError as exc:
        raise RuntimeError("RECONCILER_ATTESTATION_INTERVAL_SECONDS must be an integer") from exc
    if interval < 3600 or interval > 86400:
        raise RuntimeError("RECONCILER_ATTESTATION_INTERVAL_SECONDS must be between 3600 and 86400")
    return interval


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
        kind == "security_cvm.provision" and step in SECURITY_CVM_PROVISION_EXECUTABLE_STEPS
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
    if kind == "security_cvm.provision" and step in SECURITY_CVM_PROVISION_EXECUTABLE_STEPS:
        await execute_operation_step_with_logging(
            operation_id,
            kind=kind,
            step=step,
            handler=lambda: execute_security_cvm_provision_operation(operation_id, step),
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
    if step == "verify_attestation":
        await execute_security_cvm_attestation_gate_operation(operation_id)
        return
    if step == "fetch_ca":
        await execute_security_cvm_fetch_ca_operation(operation_id)
        return
    if step == "finalise":
        await execute_security_cvm_finalise_operation(operation_id)
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
        )
    except ShadeError as exc:
        await mark_security_cvm_provision_failed(
            operation_id,
            code="SHADE_BUILD_FAILED",
            details={"adapter": "shade", "reason": exc.code},
        )
        return
    except PhalaError as exc:
        await mark_security_cvm_provision_failed(
            operation_id,
            code="PHALA_DEPLOY_FAILED",
            details={"adapter": "phala", "reason": exc.code},
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
        await advance_security_cvm_provision_step(operation_id, "verify_attestation")
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

    try:
        verifier = AtlasVerifierClient.from_settings()
    except AttestationVerifierUnavailable:
        return False
    pool = await get_pool()
    async with pool.acquire() as conn:
        token_hashes = await fetch_security_cvm_token_hashes(conn, _row_value(snapshot, "id"))
    try:
        request = build_security_cvm_attestation_request(
            snapshot,
            token_hashes=token_hashes,
            console_url=load_settings().raw.get("CONSOLE_URL", "http://localhost:8000"),
        )
        report = await verify_with_fetch_retries(
            verifier,
            request,
            timeout_seconds=security_cvm_attestation_timeout_seconds(),
        )
    except AttestationVerifierUnavailable:
        return False
    except AttestationVerifierError as exc:
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

    from concrete_console.shade_provider.shade import ShadeClient, ShadeError

    try:
        deploy_compose_yaml = deployed_compose_from_metadata(_row_value(snapshot, "metadata"))
        if deploy_compose_yaml is None:
            raise ShadeError("missing_deploy_compose", field="metadata.deploy_compose_yaml")
        policy_result = await ShadeClient.from_settings().generate_policy(
            domain=_row_value(snapshot, "fqdn"),
            deploy_compose_yaml=deploy_compose_yaml,
            connect_host=provider_passthrough_host(_row_value(snapshot, "metadata")),
        )
    except ShadeError as exc:
        await compensate_security_cvm_provision_resources(snapshot)
        await mark_security_cvm_provision_failed(
            operation_id,
            code="SHADE_BUILD_FAILED",
            details={"adapter": "shade", "reason": exc.code},
        )
        return True

    async with pool.acquire() as conn:
        async with conn.transaction():
            verified_at = datetime.now(timezone.utc)
            await conn.execute(
                """
                UPDATE security_cvms
                SET image_measurement = $2,
                    rtmr3_digest = $3,
                    attestation_verified_at = $4,
                    metadata = $5::jsonb,
                    updated_at = now()
                WHERE id = $1
                  AND state = 'PROVISIONING'
                """,
                _row_value(snapshot, "id"),
                report.image_measurement,
                report.rtmr3_digest,
                verified_at,
                json.dumps(metadata_with_atls_policy(_row_value(snapshot, "metadata"), policy_result.policy)),
            )
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
        await mark_security_cvm_provision_failed(operation_id, code="CA_EXPORT_TTL_EXPIRED", details={})
        return
    try:
        ca_pem = await fetch_security_cvm_ca_pem(
            fqdn=_row_value(snapshot, "fqdn"),
            connect_host=provider_passthrough_host(_row_value(snapshot, "metadata")),
            ca_export_token=_row_value(snapshot, "ca_export_token_plaintext"),
        )
    except SecurityCVMCAFetchError as exc:
        await mark_security_cvm_provision_failed(
            operation_id,
            code="CA_FETCH_FAILED",
            details={"http_status": exc.http_status},
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
        await mark_security_cvm_provision_failed(operation_id, code="CA_FETCH_FAILED", details={"state": "missing_ca_cert"})
        return
    if not security_cvm_ca_export_stash_available(snapshot):
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
                  AND state = 'PROVISIONING'
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
    try:
        env, binding = build_cvm_launch_env(
            snapshot,
            public_keys=public_keys,
            profile_rows=profile_rows,
            proxy_token=proxy_token,
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
        )
    except ShadeError as exc:
        await mark_cvm_launch_failed(
            operation_id,
            code="SHADE_BUILD_FAILED",
            details={"adapter": "shade", "reason": exc.code},
        )
        return
    except PhalaError as exc:
        await mark_cvm_launch_failed(
            operation_id,
            code="PHALA_DEPLOY_FAILED",
            details={"adapter": "phala", "reason": exc.code},
        )
        return
    finally:
        if "env" in locals():
            env["SECURITY_CVM_PROXY_TOKEN"] = ""
        proxy_token = ""

    metadata = cvm_launch_metadata(
        name=name,
        app_id=deploy_result.app_id,
        gateway_host=deploy_result.gateway_host,
        status=deploy_result.status,
        policy_bundle=build_cvm_policy_bundle(
            snapshot,
            rtmr3_binding=binding,
            deploy_compose_yaml=shade_result.compose_yaml,
            connect_host=phala_passthrough_host(deploy_result.app_id, deploy_result.gateway_host),
        ),
    )
    await persist_cvm_launch_phala_result(
        operation_id,
        cvm_id=_row_value(snapshot, "cvm_id"),
        actor_id=_row_value(snapshot, "actor_id"),
        metadata=metadata,
        proxy_token_hash=binding["security_cvm_proxy_token_sha256"],
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

    try:
        verifier = AtlasVerifierClient.from_settings()
        request = build_dev_cvm_attestation_request(snapshot)
        report = await verify_with_fetch_retries(
            verifier,
            request,
            timeout_seconds=dev_cvm_attestation_timeout_seconds(),
        )
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

    from concrete_console.shade_provider.shade import ShadeClient, ShadeError

    try:
        metadata = json_payload(_row_value(snapshot, "metadata") or {})
        if not isinstance(metadata, dict):
            metadata = {}
        policy_bundle = metadata.get("policy_bundle")
        if not isinstance(policy_bundle, dict):
            raise ShadeError("missing_policy_bundle", field="metadata.policy_bundle")
        deploy_compose_yaml = deployed_compose_from_metadata(metadata)
        if deploy_compose_yaml is None:
            raise ShadeError("missing_deploy_compose", field="metadata.policy_bundle.deploy_compose_yaml")
        rtmr3_binding = policy_bundle.get("rtmr3_binding")
        if not isinstance(rtmr3_binding, dict):
            raise ShadeError("missing_rtmr3_binding", field="metadata.policy_bundle.rtmr3_binding")
        policy_result = await ShadeClient.from_settings().generate_policy(
            domain=_row_value(snapshot, "fqdn"),
            deploy_compose_yaml=deploy_compose_yaml,
            connect_host=provider_passthrough_host(metadata),
        )
        updated_metadata = metadata_with_policy_bundle(
            metadata,
            build_cvm_policy_bundle(
                snapshot,
                shade_policy=policy_result.policy,
                rtmr3_binding=rtmr3_binding,
                deploy_compose_yaml=deploy_compose_yaml,
            ),
        )
    except ShadeError as exc:
        await compensate_cvm_launch_resources(snapshot)
        await mark_cvm_launch_failed(
            operation_id,
            code="SHADE_BUILD_FAILED",
            details={"adapter": "shade", "reason": exc.code},
        )
        return True

    pool = await get_pool()
    async with pool.acquire() as conn:
        async with conn.transaction():
            verified_at = datetime.now(timezone.utc)
            await conn.execute(
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
                json.dumps(updated_metadata),
            )
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
    elapsed = datetime.now(timezone.utc) - _row_value(snapshot, "operation_updated_at")
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
    )
    await advance_cvm_launch_step(operation_id, "policy_push")


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
                    updated_at = now()
                WHERE id = $1
                  AND state = 'PROVISIONING'
                """,
                _row_value(snapshot, "cvm_id"),
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
            await mark_operation_failed(
                operation_id,
                code="PHALA_TERMINATE_FAILED",
                details={"adapter": "phala", "reason": exc.code},
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


async def fetch_security_cvm_provision_snapshot(conn: Any, operation_id: Any) -> Any | None:
    return await conn.fetchrow(
        """
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
            sc.ca_export_token_plaintext,
            sc.ca_export_token_stashed_at,
            sc.expected_image_measurement,
            sc.image_measurement,
            sc.rtmr3_digest,
            sc.attestation_verified_at,
            sc.policy_version
        FROM operations o
        JOIN security_cvms sc ON sc.id = o.target_id
        WHERE o.id = $1
          AND o.kind = 'security_cvm.provision'
          AND o.status = 'running'
          AND sc.deleted_at IS NULL
        """,
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
) -> tuple[dict[str, str], dict[str, Any]]:
    authorized_keys = render_authorized_ssh_keys(public_keys)
    sandbox_env = render_sandbox_env_placeholders(profile_rows)
    ca_cert_pem = _row_value(snapshot, "security_cvm_ca_cert_pem")
    proxy_token_hash = sha256_text(proxy_token)
    binding = {
        "cvm_id": str(_row_value(snapshot, "cvm_id")),
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
        "SECURITY_CVM_CA_CERT_B64": b64_text(ca_cert_pem),
        "SECURITY_CVM_ATLS_POLICY_B64": b64_json(security_cvm_atls_policy(snapshot)),
        "AUTHORIZED_SSH_KEYS_B64": b64_text(authorized_keys),
        "SANDBOX_ENV_PLACEHOLDERS_B64": b64_text(sandbox_env),
    }
    security_cvm_connect_host = provider_passthrough_host(_row_value(snapshot, "security_cvm_metadata"))
    if security_cvm_connect_host:
        env["SECURITY_CVM_CONNECT_HOST"] = security_cvm_connect_host
    env.update(shade_acme_dns01_env())
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
    return "\n".join(
        [
            "app:",
            f"  name: {name}",
            "",
            "services:",
            "  mitmproxy:",
            "    networks: [proxy]",
            "",
            "cvm:",
            f"  domain: {_row_value(snapshot, 'fqdn')}",
            f"  instance_type: {_row_value(snapshot, 'instance_type')}",
            f"  region: {_row_value(snapshot, 'region')}",
            "  routes:",
            "    - path: /ca.pem",
            "      service: mitmproxy",
            "      port: 8081",
            "      cors: false",
            "    - path: /",
            "      service: mitmproxy",
            "      port: 8080",
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
    env.update(shade_acme_dns01_env(raw))
    env.update(dstack_docker_pull_env(raw))
    return env


def shade_acme_dns01_env(raw: dict[str, str] | None = None) -> dict[str, str]:
    raw = load_settings().raw if raw is None else raw
    token = raw.get("SHADE_CLOUDFLARE_API_TOKEN", "").strip() or raw.get("CLOUDFLARE_API_TOKEN", "").strip()
    if not token:
        return {}
    propagation_seconds = raw.get("CLOUDFLARE_PROPAGATION_SECONDS", "").strip() or "60"
    return {
        "CLOUDFLARE_API_TOKEN": token,
        "CLOUDFLARE_PROPAGATION_SECONDS": propagation_seconds,
    }


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


def phala_passthrough_host(app_id: str, gateway_host: str) -> str:
    return f"{app_id}-443s.{gateway_host}"


def provider_passthrough_host(metadata: Any) -> str | None:
    current = json_payload(metadata or {})
    if not isinstance(current, dict):
        return None
    value = current.get("passthrough_host") or current.get("connect_host")
    if isinstance(value, str) and value.strip():
        return value.strip()
    policy_bundle = current.get("policy_bundle")
    if isinstance(policy_bundle, dict):
        value = policy_bundle.get("connect_host")
        if isinstance(value, str) and value.strip():
            return value.strip()
    app_id = current.get("app_id")
    gateway_host = current.get("gateway_host")
    if (
        current.get("provider") == "phala"
        and isinstance(app_id, str)
        and app_id
        and isinstance(gateway_host, str)
        and gateway_host
    ):
        return phala_passthrough_host(app_id, gateway_host)
    return None


def security_cvm_provision_metadata(
    *,
    name: str,
    app_id: str,
    gateway_host: str,
    status: str,
    deploy_compose_yaml: str,
    atls_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    passthrough_host = phala_passthrough_host(app_id, gateway_host)
    metadata: dict[str, Any] = {
        "provider": "phala",
        "name": name,
        "app_id": app_id,
        "gateway_host": gateway_host,
        "passthrough_host": passthrough_host,
        "status": status,
        "deploy_compose_yaml": deploy_compose_yaml,
    }
    if atls_policy is not None:
        metadata["atls_policy"] = atls_policy
    return metadata


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


def build_cvm_policy_bundle(
    snapshot: Any,
    *,
    rtmr3_binding: dict[str, Any],
    deploy_compose_yaml: str,
    shade_policy: dict[str, Any] | None = None,
    connect_host: str | None = None,
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
    if connect_host:
        bundle["connect_host"] = connect_host
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
    passthrough_host = phala_passthrough_host(app_id, gateway_host)
    return {
        "provider": "phala",
        "name": name,
        "app_id": app_id,
        "gateway_host": gateway_host,
        "passthrough_host": passthrough_host,
        "status": status,
        "policy_bundle": policy_bundle,
    }


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
                before={"metadata": _row_value(snapshot, "metadata")},
                after={"metadata": metadata},
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
async def persist_security_cvm_dns_record(operation_id: Any, snapshot: Any, *, field: str, record_id: str) -> None:
    if field == "txt":
        column = "txt_dns_record_id"
        next_step = "cf_cname_create"
    elif field == "cname":
        column = "cname_dns_record_id"
        next_step = "verify_attestation"
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
                  AND state = 'PROVISIONING'
                """,
                security_cvm_id,
                ca_pem,
            )
            await advance_security_cvm_provision_step_with_conn(conn, operation_id, "finalise")


async def advance_security_cvm_provision_step(operation_id: Any, next_step: str) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await advance_security_cvm_provision_step_with_conn(conn, operation_id, next_step)


async def advance_security_cvm_provision_step_with_conn(conn: Any, operation_id: Any, next_step: str) -> None:
    await conn.execute(
        """
        UPDATE operations
        SET progress_step = $2,
            progress_percent = GREATEST(progress_percent, $3),
            updated_at = now()
        WHERE id = $1
          AND kind = 'security_cvm.provision'
          AND status = 'running'
        """,
        operation_id,
        next_step,
        SECURITY_CVM_PROVISION_PROGRESS[next_step],
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
                      AND state = 'PROVISIONING'
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
                  AND purpose = 'PROXY_AUTH'
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
    await conn.execute(
        """
        UPDATE operations
        SET progress_step = $2,
            progress_percent = GREATEST(progress_percent, $3),
            updated_at = now()
        WHERE id = $1
          AND kind = 'cvm.launch'
          AND status = 'running'
        """,
        operation_id,
        next_step,
        CVM_LAUNCH_PROGRESS[next_step],
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
                      AND purpose = 'PROXY_AUTH'
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


async def compensate_cvm_launch_resources(snapshot: Any) -> None:
    from concrete_console.dns_provider.cloudflare import CloudflareClient, CloudflareError
    from concrete_console.tee_provider.phala import PhalaClient, PhalaError

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
    def __init__(self, *, http_status: int):
        super().__init__("ca_fetch_failed")
        self.http_status = http_status


async def fetch_security_cvm_ca_pem(*, fqdn: str, ca_export_token: str, connect_host: str | None = None) -> str:
    import ssl

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
        if connect_host:
            context.check_hostname = False
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, 443, ssl=context, server_hostname=target_host),
            timeout=15.0,
        )
        if connect_host:
            ssl_object = writer.get_extra_info("ssl_object")
            if ssl_object is None:
                raise SecurityCVMCAFetchError(http_status=0)
            verify_peer_certificate_hostname(ssl_object.getpeercert(), fqdn)
        writer.write(request.encode("utf-8"))
        await writer.drain()
        raw_response = await asyncio.wait_for(reader.read(), timeout=15.0)
        writer.close()
        await writer.wait_closed()
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        raise SecurityCVMCAFetchError(http_status=0) from exc
    header_bytes, separator, body_bytes = raw_response.partition(b"\r\n\r\n")
    if not separator:
        raise SecurityCVMCAFetchError(http_status=0)
    status_line = header_bytes.splitlines()[0].decode("iso-8859-1", errors="replace")
    try:
        status_code = int(status_line.split()[1])
    except (IndexError, ValueError) as exc:
        raise SecurityCVMCAFetchError(http_status=0) from exc
    if status_code != 200:
        raise SecurityCVMCAFetchError(http_status=status_code)
    body = body_bytes.decode("utf-8", errors="replace")
    if "-----BEGIN CERTIFICATE-----" not in body or "-----END CERTIFICATE-----" not in body:
        raise SecurityCVMCAFetchError(http_status=200)
    return body


def verify_peer_certificate_hostname(peer_cert: dict[str, Any], hostname: str) -> None:
    hostname = hostname.rstrip(".").lower()
    names: list[str] = []
    for key, value in peer_cert.get("subjectAltName", ()):
        if key == "DNS" and isinstance(value, str):
            names.append(value)
    if not names:
        for subject in peer_cert.get("subject", ()):
            for key, value in subject:
                if key == "commonName" and isinstance(value, str):
                    names.append(value)
    if not any(dns_name_matches(pattern, hostname) for pattern in names):
        raise SecurityCVMCAFetchError(http_status=0)


def dns_name_matches(pattern: str, hostname: str) -> bool:
    pattern = pattern.rstrip(".").lower()
    if pattern == hostname:
        return True
    if not pattern.startswith("*."):
        return False
    suffix = pattern[1:]
    return hostname.endswith(suffix) and hostname.count(".") == pattern.count(".")


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


async def run_reconciliation_pass(*, include_orphans: bool = True) -> ReconciliationSummary:
    pool = await get_pool()
    async with pool.acquire() as conn:
        cvms_advanced = await reconcile_dev_cvm_provider_drift(conn)
        security_cvms_advanced = await reconcile_security_cvm_provider_drift(conn)
        orphans_cleaned = await cleanup_orphan_dns_records(conn) if include_orphans else []
        orphans_cleaned.extend(await prune_expired_auth_flow_rows(conn))
        orphans_cleaned.extend(await prune_expired_reconciler_rows(conn))
        operation_prune_count = await prune_expired_operations(conn)
        if operation_prune_count:
            orphans_cleaned.append(f"maintenance:operations:{operation_prune_count}")
        security_cvms_advanced.extend(await reconcile_security_cvm_attestations(conn))
        cvms_advanced.extend(await reconcile_dev_cvm_attestations(conn))
        await publish_audit_anchor_if_due(conn)
    return ReconciliationSummary(
        cvms_advanced=cvms_advanced,
        security_cvms_advanced=security_cvms_advanced,
        orphans_cleaned=orphans_cleaned,
    )


async def reconcile_dev_cvm_provider_drift(conn: Any) -> list[str]:
    from concrete_console.tee_provider.phala import PhalaClient, PhalaError

    try:
        client = PhalaClient.from_settings(timeout_seconds=30.0)
    except PhalaError as exc:
        log.warning("dev_cvm_provider_drift_skipped", reason=exc.code)
        return []

    advanced: list[str] = []
    rows = await fetch_dev_cvm_provider_drift_candidates(conn)
    for row in rows:
        app_id = provider_app_id(_row_value(row, "metadata"))
        if app_id is None:
            continue
        try:
            provider_status = await client.status(app_id)
        except PhalaError as exc:
            log.warning(
                "dev_cvm_provider_drift_status_failed",
                cvm_id=str(_row_value(row, "id")),
                reason=exc.code,
            )
            continue
        target_state = provider_drift_target_state(provider_status)
        if target_state is None:
            continue
        if await persist_dev_cvm_provider_drift(conn, row, provider_status=provider_status, target_state=target_state):
            advanced.append(str(_row_value(row, "id")))
    return advanced


async def reconcile_security_cvm_provider_drift(conn: Any) -> list[str]:
    from concrete_console.tee_provider.phala import PhalaClient, PhalaError

    try:
        client = PhalaClient.from_settings(timeout_seconds=30.0)
    except PhalaError as exc:
        log.warning("security_cvm_provider_drift_skipped", reason=exc.code)
        return []

    advanced: list[str] = []
    rows = await fetch_security_cvm_provider_drift_candidates(conn)
    for row in rows:
        app_id = provider_app_id(_row_value(row, "metadata"))
        if app_id is None:
            continue
        try:
            provider_status = await client.status(app_id)
        except PhalaError as exc:
            log.warning(
                "security_cvm_provider_drift_status_failed",
                security_cvm_id=str(_row_value(row, "id")),
                reason=exc.code,
            )
            continue
        target_state = provider_drift_target_state(provider_status)
        if target_state is None:
            continue
        if await persist_security_cvm_provider_drift(
            conn,
            row,
            provider_status=provider_status,
            target_state=target_state,
        ):
            advanced.append(str(_row_value(row, "id")))
    return advanced


async def fetch_dev_cvm_provider_drift_candidates(conn: Any) -> list[Any]:
    async with conn.transaction():
        return list(
            await conn.fetch(
                """
                SELECT
                    c.id,
                    c.entity_id,
                    c.state::text AS state,
                    c.metadata,
                    c.error_reason
                FROM cvms c
                WHERE c.state = 'RUNNING'
                  AND c.deleted_at IS NULL
                  AND c.metadata ? 'app_id'
                  AND NOT EXISTS (
                    SELECT 1
                    FROM operations o
                    WHERE o.target_id = c.id
                      AND o.status IN ('pending', 'running')
                  )
                ORDER BY c.created_at
                LIMIT 10
                FOR UPDATE SKIP LOCKED
                """
            )
        )


async def fetch_security_cvm_provider_drift_candidates(conn: Any) -> list[Any]:
    async with conn.transaction():
        return list(
            await conn.fetch(
                """
                SELECT
                    sc.id,
                    sc.entity_id,
                    sc.state::text AS state,
                    sc.metadata,
                    sc.error_reason
                FROM security_cvms sc
                WHERE sc.state = 'RUNNING'
                  AND sc.deleted_at IS NULL
                  AND sc.metadata ? 'app_id'
                  AND NOT EXISTS (
                    SELECT 1
                    FROM operations o
                    WHERE o.target_id = sc.id
                      AND o.status IN ('pending', 'running')
                  )
                ORDER BY sc.created_at
                LIMIT 10
                FOR UPDATE SKIP LOCKED
                """
            )
        )


def provider_drift_target_state(provider_status: str) -> str | None:
    if provider_status in {"FAILED", "STOPPED"}:
        return provider_status
    return None


async def persist_dev_cvm_provider_drift(
    conn: Any,
    row: Any,
    *,
    provider_status: str,
    target_state: str,
) -> bool:
    if target_state not in {"FAILED", "STOPPED"}:
        raise ValueError("unsupported provider drift state")
    error_reason = "PHALA_OBSERVED_FAILED" if target_state == "FAILED" else None
    action = "CVM_FAILED" if target_state == "FAILED" else "CVM_STOPPED"
    async with conn.transaction():
        result = await conn.execute(
            """
            UPDATE cvms
            SET state = $2::cvm_state,
                error_reason = $3,
                updated_at = now()
            WHERE id = $1
              AND state = 'RUNNING'
              AND deleted_at IS NULL
              AND NOT EXISTS (
                SELECT 1
                FROM operations o
                WHERE o.target_id = cvms.id
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
            target_type="cvm",
            target_id=_row_value(row, "id"),
            before={
                "state": _row_value(row, "state"),
                "error_reason": _row_value(row, "error_reason"),
            },
            after=after,
        )
    return True


async def persist_security_cvm_provider_drift(
    conn: Any,
    row: Any,
    *,
    provider_status: str,
    target_state: str,
) -> bool:
    if target_state not in {"FAILED", "STOPPED"}:
        raise ValueError("unsupported provider drift state")
    error_reason = "PHALA_OBSERVED_FAILED" if target_state == "FAILED" else None
    action = "SECURITY_CVM_FAILED" if target_state == "FAILED" else "SECURITY_CVM_STOPPED"
    async with conn.transaction():
        result = await conn.execute(
            """
            UPDATE security_cvms
            SET state = $2::cvm_state,
                error_reason = $3,
                updated_at = now()
            WHERE id = $1
              AND state = 'RUNNING'
              AND deleted_at IS NULL
              AND NOT EXISTS (
                SELECT 1
                FROM operations o
                WHERE o.target_id = security_cvms.id
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
            target_type="security_cvm",
            target_id=_row_value(row, "id"),
            before={
                "state": _row_value(row, "state"),
                "error_reason": _row_value(row, "error_reason"),
            },
            after=after,
        )
    return True


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

    try:
        verifier = AtlasVerifierClient.from_settings()
    except AttestationVerifierUnavailable:
        return []
    interval = reconciler_attestation_interval_seconds()
    advanced: list[str] = []
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
                sc.error_reason
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
        for row in rows:
            token_hashes = await fetch_security_cvm_token_hashes(conn, _row_value(row, "id"))
            try:
                request = build_security_cvm_attestation_request(
                    row,
                    token_hashes=token_hashes,
                    console_url=load_settings().raw.get("CONSOLE_URL", "http://localhost:8000"),
                )
                report = await verifier.verify(request, timeout_seconds=30)
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
            if drift_kind is None:
                await persist_security_cvm_attestation_refresh(conn, row, report)
            else:
                await record_security_cvm_attestation_refresh_drift(conn, row, report, drift_kind=drift_kind)
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
    async with conn.transaction():
        rows = await conn.fetch(
            """
            SELECT
                c.id AS cvm_id,
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
        for row in rows:
            try:
                request = build_dev_cvm_attestation_request(row)
                report = await verifier.verify(request, timeout_seconds=30)
            except AttestationVerifierError as exc:
                log.warning(
                    "dev_cvm_attestation_refresh_failed",
                    cvm_id=str(_row_value(row, "cvm_id")),
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
            if drift_kind is None:
                await persist_dev_cvm_attestation_refresh(conn, row, report)
            else:
                await record_dev_cvm_attestation_refresh_drift(conn, row, report, drift_kind=drift_kind)
            advanced.append(str(_row_value(row, "cvm_id")))
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
        """,
        security_cvm_id,
    )
    return {row["purpose"]: row["token_hash"] for row in rows}


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


async def persist_security_cvm_attestation_refresh(conn: Any, row: Any, report: Any) -> None:
    verified_at = datetime.now(timezone.utc)
    await conn.execute(
        """
        UPDATE security_cvms
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
    await insert_audit_event(
        conn,
        entity_id=_row_value(row, "entity_id"),
        actor_id=None,
        actor_email="reconciler@concrete.system",
        action="SECURITY_CVM_ATTESTATION_VERIFIED",
        target_type="security_cvm",
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


async def record_security_cvm_attestation_refresh_drift(conn: Any, row: Any, report: Any, *, drift_kind: str) -> None:
    await conn.execute(
        """
        UPDATE security_cvms
        SET error_reason = 'ATTESTATION_DRIFT',
            updated_at = now()
        WHERE id = $1
          AND state = 'RUNNING'
          AND deleted_at IS NULL
        """,
        _row_value(row, "id"),
    )
    await insert_audit_event(
        conn,
        entity_id=_row_value(row, "entity_id"),
        actor_id=None,
        actor_email="reconciler@concrete.system",
        action="SECURITY_CVM_ATTESTATION_DRIFT",
        target_type="security_cvm",
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


async def persist_dev_cvm_attestation_refresh(conn: Any, row: Any, report: Any) -> None:
    verified_at = datetime.now(timezone.utc)
    await conn.execute(
        """
        UPDATE cvms
        SET image_measurement = $2,
            rtmr3_digest = $3,
            attestation_verified_at = $4,
            error_reason = NULL,
            updated_at = now()
        WHERE id = $1
          AND state = 'RUNNING'
          AND deleted_at IS NULL
        """,
        _row_value(row, "cvm_id"),
        report.image_measurement,
        report.rtmr3_digest,
        verified_at,
    )
    await insert_audit_event(
        conn,
        entity_id=_row_value(row, "entity_id"),
        actor_id=None,
        actor_email="reconciler@concrete.system",
        action="CVM_ATTESTATION_VERIFIED",
        target_type="cvm",
        target_id=_row_value(row, "cvm_id"),
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


async def record_dev_cvm_attestation_refresh_drift(conn: Any, row: Any, report: Any, *, drift_kind: str) -> None:
    await conn.execute(
        """
        UPDATE cvms
        SET error_reason = 'ATTESTATION_DRIFT',
            updated_at = now()
        WHERE id = $1
          AND state = 'RUNNING'
          AND deleted_at IS NULL
        """,
        _row_value(row, "cvm_id"),
    )
    await insert_audit_event(
        conn,
        entity_id=_row_value(row, "entity_id"),
        actor_id=None,
        actor_email="reconciler@concrete.system",
        action="CVM_ATTESTATION_DRIFT",
        target_type="cvm",
        target_id=_row_value(row, "cvm_id"),
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


def mark_scheduler_tick_success(*, now: float | None = None) -> None:
    global _last_successful_tick_monotonic
    _last_successful_tick_monotonic = time.monotonic() if now is None else now


def check_operation_scheduler_recent(*, now: float | None = None) -> None:
    if _last_successful_tick_monotonic is None:
        raise RuntimeError("operation scheduler has not ticked")
    current = time.monotonic() if now is None else now
    if current - _last_successful_tick_monotonic > 2 * reconciler_interval_seconds():
        raise RuntimeError("operation scheduler tick is stale")
