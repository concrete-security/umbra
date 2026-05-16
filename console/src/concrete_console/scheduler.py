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

from concrete_console.audit import insert_audit_event
from concrete_console.config import load_settings
from concrete_console.db import get_pool
from concrete_console.log_config import logger
from concrete_console.resources import cvm_resource, json_payload

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
    if _row_value(row, "kind") == "cvm.terminate" and _row_value(row, "progress_step") == "phala_terminate":
        await execute_cvm_terminate_operation(operation_id)
        return True
    if _row_value(row, "kind") == "cvm.launch" and _row_value(row, "progress_step") in CVM_LAUNCH_EXECUTABLE_STEPS:
        await execute_cvm_launch_operation(operation_id, _row_value(row, "progress_step"))
        return True
    return False


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
        shade_result = await ShadeClient.from_settings().build_with_policy(
            shade_config_yaml=render_dev_cvm_shade_config(snapshot, name=name),
            app_compose_yaml=_row_value(snapshot, "compose_config"),
            domain=_row_value(snapshot, "fqdn"),
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
            shade_policy=shade_result.policy,
            rtmr3_binding=binding,
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


async def execute_cvm_launch_await_sc_pull_operation(operation_id: Any) -> None:
    pool = await get_pool()
    async with pool.acquire() as conn:
        snapshot = await fetch_cvm_launch_snapshot(conn, operation_id)
    if snapshot is None:
        await mark_cvm_launch_failed(operation_id, code="CVM_NOT_FOUND", details={"state": "missing_target"})
        return
    elapsed = datetime.now(timezone.utc) - _row_value(snapshot, "operation_updated_at")
    timeout = timedelta(seconds=sc_pull_propagation_timeout_seconds())
    if elapsed < timeout:
        log.info(
            "cvm_launch_awaiting_sc_pull",
            operation_id=str(operation_id),
            cvm_id=str(_row_value(snapshot, "cvm_id")),
            elapsed_seconds=int(elapsed.total_seconds()),
            timeout_seconds=int(timeout.total_seconds()),
        )
        return
    log.warning(
        "cvm_launch_sc_pull_observation_unavailable",
        operation_id=str(operation_id),
        cvm_id=str(_row_value(snapshot, "cvm_id")),
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
            json.dumps({"code": code, "details": details}),
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
            sc.expected_image_measurement AS security_cvm_expected_image_measurement,
            sc.image_measurement AS security_cvm_image_measurement,
            sc.rtmr3_digest AS security_cvm_rtmr3_digest,
            sc.compose_config AS security_cvm_compose_config
        FROM operations o
        JOIN cvms c ON c.id = o.target_id
        JOIN security_cvms sc
          ON sc.id = c.security_cvm_id
         AND sc.state = 'RUNNING'
         AND sc.deleted_at IS NULL
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


def security_cvm_atls_policy(snapshot: Any) -> dict[str, Any]:
    return {
        "type": "dstack_tdx",
        "allowed_tcb_status": ["UpToDate"],
        "fqdn": _row_value(snapshot, "security_cvm_fqdn"),
        "expected_image_measurement": _row_value(snapshot, "security_cvm_expected_image_measurement"),
        "image_measurement": _row_value(snapshot, "security_cvm_image_measurement"),
        "rtmr3_digest": _row_value(snapshot, "security_cvm_rtmr3_digest"),
    }


def render_dev_cvm_shade_config(snapshot: Any, *, name: str) -> str:
    return "\n".join(
        [
            "app:",
            f"  name: {name}",
            "cvm:",
            f"  domain: {_row_value(snapshot, 'fqdn')}",
            f"  instance_type: {_row_value(snapshot, 'instance_type')}",
            f"  region: {_row_value(snapshot, 'region')}",
            "",
        ]
    )


def build_cvm_policy_bundle(
    snapshot: Any,
    *,
    shade_policy: dict[str, Any],
    rtmr3_binding: dict[str, Any],
) -> dict[str, Any]:
    app_compose = json_payload(shade_policy.get("app_compose", {}))
    if not isinstance(app_compose, dict):
        app_compose = {}
    expected_bootchain = json_payload(shade_policy.get("expected_bootchain", {}))
    if not isinstance(expected_bootchain, dict):
        expected_bootchain = {}
    return {
        "cvm_id": str(_row_value(snapshot, "cvm_id")),
        "policy_template_version": str(shade_policy.get("policy_template_version", "shade")),
        "compose_template": app_compose.get("docker_compose_file") or _row_value(snapshot, "compose_config"),
        "expected_bootchain": expected_bootchain,
        "os_image_hash": shade_policy.get("os_image_hash") or _row_value(snapshot, "expected_image_measurement"),
        "rtmr3_binding": rtmr3_binding,
        "security_cvm_fqdn": _row_value(snapshot, "security_cvm_fqdn"),
        "issued_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


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
        "app_id": app_id,
        "gateway_host": gateway_host,
        "status": status,
        "policy_bundle": policy_bundle,
    }


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
                json.dumps({"code": code, "details": details}),
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


def provider_gateway_host(metadata: Any) -> str | None:
    metadata = json_payload(metadata or {})
    if not isinstance(metadata, dict):
        return None
    gateway_host = metadata.get("gateway_host")
    return gateway_host if isinstance(gateway_host, str) and gateway_host else None


def cvm_launch_provider_name(cvm_id: Any) -> str:
    token = str(cvm_id).replace("-", "")[:16]
    return f"concrete-v0-cvm-{token}"


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


async def run_reconciliation_pass(*, include_orphans: bool = True) -> ReconciliationSummary:
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            DELETE FROM operations
            WHERE expires_at IS NOT NULL
              AND expires_at < now()
            """
        )
    return ReconciliationSummary(cvms_advanced=[], security_cvms_advanced=[], orphans_cleaned=[])


def mark_scheduler_tick_success(*, now: float | None = None) -> None:
    global _last_successful_tick_monotonic
    _last_successful_tick_monotonic = time.monotonic() if now is None else now


def check_operation_scheduler_recent(*, now: float | None = None) -> None:
    if _last_successful_tick_monotonic is None:
        raise RuntimeError("operation scheduler has not ticked")
    current = time.monotonic() if now is None else now
    if current - _last_successful_tick_monotonic > 2 * reconciler_interval_seconds():
        raise RuntimeError("operation scheduler tick is stale")
