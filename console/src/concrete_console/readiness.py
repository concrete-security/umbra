from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Literal

import httpx

from concrete_console.config import load_settings
from concrete_console.db import get_pool
from concrete_console.jwt_keys import get_jwt_manager
from concrete_console.oidc import load_google_jwks

CheckState = Literal["ok", "failed"]
DEFAULT_PHALA_CLI_PATH = "/usr/local/bin/phala"


async def run_ready_checks() -> dict[str, CheckState]:
    results = await asyncio.gather(
        _capped("database", _check_database(), timeout=1.0),
        _capped("jwt_keys", _check_jwt_keys(), timeout=1.0),
        _capped("oidc_jwks", _check_oidc_jwks(), timeout=1.0),
        _capped("cloudflare_adapter", _check_cloudflare_adapter(), timeout=1.0),
        _capped("phala_adapter", _check_phala_adapter(), timeout=1.0),
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


async def _check_phala_adapter() -> None:
    await verify_configured_phala_cli(fetch_timeout=0.5)


async def verify_configured_phala_cli(*, fetch_timeout: float) -> None:
    raw = load_settings().raw
    if not raw.get("PHALA_API_TOKEN", "").strip():
        return
    expected_sha256 = raw.get("PHALA_CLI_SHA256", "").strip().lower()
    if not expected_sha256:
        raise RuntimeError("PHALA_CLI_SHA256 is required when Phala is configured")

    phala_cli_path = raw.get("PHALA_CLI_PATH", DEFAULT_PHALA_CLI_PATH).strip() or DEFAULT_PHALA_CLI_PATH
    version = phala_package_version(phala_cli_path)
    tarball_url = phala_tarball_url(version)
    async with httpx.AsyncClient(timeout=fetch_timeout, follow_redirects=True) as client:
        response = await client.get(tarball_url)
    response.raise_for_status()
    actual_sha256 = hashlib.sha256(response.content).hexdigest()
    if actual_sha256 != expected_sha256:
        raise RuntimeError("Phala CLI tarball digest mismatch")


def phala_package_version(phala_cli_path: str) -> str:
    resolved = Path(phala_cli_path).resolve(strict=True)
    for directory in (resolved.parent, *resolved.parents):
        package_json = directory / "package.json"
        if not package_json.is_file():
            continue
        package = json.loads(package_json.read_text())
        if package.get("name") == "phala":
            version = package.get("version")
            if isinstance(version, str) and version:
                return version
            raise RuntimeError("installed phala package has no version")
    raise RuntimeError("installed phala package metadata was not found")


def phala_tarball_url(version: str) -> str:
    lockfile = Path("package-lock.json")
    if lockfile.is_file():
        lock = json.loads(lockfile.read_text())
        phala_package = lock.get("packages", {}).get("node_modules/phala", {})
        if phala_package.get("version") == version and isinstance(phala_package.get("resolved"), str):
            return phala_package["resolved"]
    return f"https://registry.npmjs.org/phala/-/phala-{version}.tgz"
