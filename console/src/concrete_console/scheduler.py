from __future__ import annotations

import asyncio
from contextlib import suppress
from dataclasses import dataclass
import time

from concrete_console.config import load_settings
from concrete_console.db import get_pool
from concrete_console.log_config import logger

log = logger()
_last_successful_tick_monotonic: float | None = None


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
    await run_reconciliation_pass()


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
