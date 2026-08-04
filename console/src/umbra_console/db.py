from __future__ import annotations

import asyncpg

from umbra_console.config import asyncpg_dsn, load_settings

_pool: asyncpg.Pool | None = None


async def get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        settings = load_settings()
        _pool = await asyncpg.create_pool(asyncpg_dsn(settings.database_url), min_size=1, max_size=10)
    return _pool


async def close_pool() -> None:
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
