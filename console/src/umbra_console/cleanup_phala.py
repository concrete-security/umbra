from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
import sys
from typing import Any, TextIO

from umbra_console.tee_provider.phala import (
    PhalaClient,
    PhalaError,
    managed_cvm_name,
    validate_app_id,
)

APP_ID_KEYS = ("id", "app_id", "appId", "cvm_id", "cvmId")


class PhalaCleanupError(RuntimeError):
    pass


@dataclass(frozen=True)
class CleanupSummary:
    deleted: int


def managed_cvm_app_id(row: dict[str, Any]) -> str | None:
    for key in APP_ID_KEYS:
        value = row.get(key)
        if isinstance(value, str) and value:
            validate_app_id(value)
            return value
    return None


async def delete_managed_cvms(client: PhalaClient, *, out: TextIO = sys.stderr) -> CleanupSummary:
    rows = await client.list()
    deleted = 0
    for row in rows:
        name = managed_cvm_name(row)
        if name is None:
            continue
        app_id = managed_cvm_app_id(row)
        if app_id is None:
            raise PhalaCleanupError("managed Phala CVM list response has no valid app id")
        await client.delete(app_id)
        deleted += 1
    if deleted == 0:
        print("clean-phala: no umbra-v0 Phala CVMs found", file=out)
    else:
        print(f"clean-phala: deleted {deleted} Umbra-managed Phala CVM(s)", file=out)
    return CleanupSummary(deleted=deleted)


async def run() -> int:
    if not os.environ.get("PHALA_API_TOKEN"):
        print("clean-phala: PHALA_API_TOKEN is not set; skipping Phala CVM cleanup", file=sys.stderr)
        return 0
    try:
        client = PhalaClient.from_settings()
        await delete_managed_cvms(client)
    except PhalaCleanupError as exc:
        print(f"clean-phala: Phala CVM cleanup failed: {exc}", file=sys.stderr)
        return 1
    except PhalaError as exc:
        print(f"clean-phala: Phala CVM cleanup failed: {exc.code}", file=sys.stderr)
        return 1
    return 0


def main() -> None:
    raise SystemExit(asyncio.run(run()))


if __name__ == "__main__":
    main()
