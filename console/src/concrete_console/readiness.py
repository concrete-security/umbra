from __future__ import annotations

import asyncio
from typing import Literal

import httpx

from concrete_console.config import load_settings
from concrete_console.db import get_pool
from concrete_console.jwt_keys import get_jwt_manager
from concrete_console.oidc import load_google_jwks

CheckState = Literal["ok", "failed"]


async def run_ready_checks() -> dict[str, CheckState]:
    results = await asyncio.gather(
        _capped("database", _check_database(), timeout=1.0),
        _capped("jwt_keys", _check_jwt_keys(), timeout=1.0),
        _capped("oidc_jwks", _check_oidc_jwks(), timeout=1.0),
        _capped("cloudflare_adapter", _check_cloudflare_adapter(), timeout=1.0),
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


async def _check_oidc_jwks() -> None:
    async def load_keys() -> None:
        keys = await load_google_jwks(force=False)
        if not keys:
            raise RuntimeError("OIDC JWKS did not return any keys")

    await asyncio.wait_for(load_keys(), timeout=0.5)


async def _check_cloudflare_adapter() -> None:
    raw = load_settings().raw
    api_token = raw.get("CLOUDFLARE_API_TOKEN", "").strip()
    zone_ids = [
        raw.get("CLOUDFLARE_ZONE_ID", "").strip(),
        raw.get("SECURITY_CVM_ZONE_ID", "").strip(),
    ]
    configured_zone_ids = [zone_id for zone_id in zone_ids if zone_id]
    if not api_token and not configured_zone_ids:
        return
    if not api_token or len(configured_zone_ids) != len(zone_ids):
        raise RuntimeError("Cloudflare adapter is partially configured")

    headers = {"Authorization": f"Bearer {api_token}"}
    async with httpx.AsyncClient(timeout=0.5) as client:
        responses = await asyncio.gather(
            *(
                client.get(f"https://api.cloudflare.com/client/v4/zones/{zone_id}", headers=headers)
                for zone_id in configured_zone_ids
            )
        )
    if any(response.status_code != 200 for response in responses):
        raise RuntimeError("Cloudflare zone probe failed")
