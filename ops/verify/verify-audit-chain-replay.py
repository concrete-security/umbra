#!/usr/bin/env python3
"""Audit chain replay verification (docs/specs/console.md §19.6)."""
from __future__ import annotations

import asyncio
import os
import sys

import asyncpg

from umbra_console.audit import EMPTY_HASH, audit_row_hash


async def main() -> int:
    dsn = os.environ.get("DATABASE_URL", "").replace("postgresql+asyncpg://", "postgresql://", 1)
    if not dsn:
        print("DATABASE_URL required", file=sys.stderr)
        return 2
    conn = await asyncpg.connect(dsn)
    try:
        rows = await conn.fetch(
            """
            SELECT
                seq, id, entity_id, actor_id, actor_email, action, target_type, target_id,
                before, after, ip_address, description, request_id, timestamp, prev_hash, row_hash
            FROM audit_events
            ORDER BY seq ASC
            """
        )
        prev_hash = EMPTY_HASH
        for row in rows:
            if row["prev_hash"] != prev_hash:
                print(
                    f"chain mismatch at seq={row['seq']}: expected prev_hash={prev_hash} got {row['prev_hash']}",
                    file=sys.stderr,
                )
                return 1
            computed = audit_row_hash(
                {
                    "seq": row["seq"],
                    "id": str(row["id"]),
                    "entity_id": str(row["entity_id"]) if row["entity_id"] else None,
                    "actor_id": str(row["actor_id"]) if row["actor_id"] else None,
                    "actor_email": row["actor_email"],
                    "action": row["action"],
                    "target_type": row["target_type"],
                    "target_id": row["target_id"],
                    "before": row["before"],
                    "after": row["after"],
                    "ip_address": row["ip_address"],
                    "description": row["description"],
                    "request_id": row["request_id"],
                    "timestamp": row["timestamp"].isoformat().replace("+00:00", "Z"),
                    "prev_hash": row["prev_hash"],
                }
            )
            if computed != row["row_hash"]:
                print(f"row_hash mismatch at seq={row['seq']}", file=sys.stderr)
                return 1
            prev_hash = row["row_hash"]
        if not rows:
            return 0
        tip = rows[-1]
        anchor = await conn.fetchrow(
            """
            SELECT last_seq, last_row_hash
            FROM audit_anchors
            ORDER BY anchored_at DESC, last_seq DESC
            LIMIT 1
            """
        )
        if anchor is None:
            print("no audit_anchors row", file=sys.stderr)
            return 1
        if int(anchor["last_seq"]) != int(tip["seq"]) or str(anchor["last_row_hash"]) != str(tip["row_hash"]):
            print("latest anchor does not match chain tip", file=sys.stderr)
            return 1
    finally:
        await conn.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
