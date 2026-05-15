from __future__ import annotations

import asyncio
from typing import Literal

from concrete_console.db import get_pool
from concrete_console.jwt_keys import get_jwt_manager

CheckState = Literal["ok", "failed"]


async def run_ready_checks() -> dict[str, CheckState]:
    results = await asyncio.gather(
        _capped("database", _check_database(), timeout=1.0),
        _capped("jwt_keys", _check_jwt_keys(), timeout=1.0),
    )
    return dict(results)


async def _capped(name: str, awaitable, *, timeout: float) -> tuple[str, CheckState]:
    try:
        await asyncio.wait_for(awaitable, timeout=timeout)
    except Exception:  # noqa: BLE001
        return name, "failed"
    return name, "ok"


async def _check_database() -> None:
    async def select_one() -> None:
        pool = await get_pool()
        async with pool.acquire() as conn:
            value = await conn.fetchval("SELECT 1")
            if value != 1:
                raise RuntimeError("database readiness query returned unexpected value")

    await asyncio.wait_for(select_one(), timeout=0.2)


async def _check_jwt_keys() -> None:
    def load_keys() -> None:
        manager = get_jwt_manager()
        active_kid = manager.active_kid
        if active_kid not in manager.verifying_keys:
            raise RuntimeError("active JWT kid is not in verifying key set")

    await asyncio.to_thread(load_keys)
