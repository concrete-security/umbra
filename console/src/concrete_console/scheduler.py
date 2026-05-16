from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
import time
from typing import Any

from concrete_console.config import load_settings
from concrete_console.db import get_pool
from concrete_console.log_config import logger

log = logger()
_last_successful_tick_monotonic: float | None = None
OPERATION_START_STEPS = {
    "audit.export": ("materialize", 20),
    "cvm.launch": ("phala_deploy", 20),
    "cvm.terminate": ("phala_terminate", 25),
    "security_cvm.provision": ("phala_deploy", 20),
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
    async with pool.acquire() as conn:
        async with conn.transaction():
            rows = await claim_active_operations(conn, batch_size=batch_size or operation_scheduler_batch_size())
            for row in rows:
                advanced = await advance_claimed_operation(conn, row)
                if advanced:
                    claimed_ids.append(str(_row_value(row, "id")))
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
