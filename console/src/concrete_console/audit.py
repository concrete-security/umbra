from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

import asyncpg

EMPTY_HASH = hashlib.sha256(b"").hexdigest()


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def audit_row_hash(row: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(row).encode("utf-8")).hexdigest()


async def insert_audit_event(
    conn: asyncpg.Connection,
    *,
    entity_id: UUID | None,
    actor_id: UUID | None,
    actor_email: str,
    action: str,
    target_type: str | None,
    target_id: UUID | None,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> None:
    await conn.execute("LOCK TABLE audit_events IN EXCLUSIVE MODE")
    prev_hash = await conn.fetchval("SELECT row_hash FROM audit_events ORDER BY seq DESC LIMIT 1")
    prev_hash = prev_hash or EMPTY_HASH
    seq = await conn.fetchval("SELECT nextval('audit_events_seq_seq')")
    event_id = uuid4()
    created_at = datetime.now(timezone.utc)
    before_payload = before or {}
    after_payload = after or {}
    hash_payload = {
        "seq": seq,
        "id": str(event_id),
        "entity_id": str(entity_id) if entity_id else None,
        "actor_id": str(actor_id) if actor_id else None,
        "actor_email": actor_email,
        "action": action,
        "target_type": target_type,
        "target_id": str(target_id) if target_id else None,
        "before": before_payload,
        "after": after_payload,
        "request_id": request_id,
        "ip_address": ip_address,
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "prev_hash": prev_hash,
    }
    row_hash = audit_row_hash(hash_payload)

    await conn.execute(
        """
        INSERT INTO audit_events (
            seq, id, entity_id, actor_id, actor_email, action, target_type, target_id,
            before, after, request_id, ip_address, created_at, prev_hash, row_hash
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8,
            $9::jsonb, $10::jsonb, $11, $12, $13, $14, $15
        )
        """,
        seq,
        event_id,
        entity_id,
        actor_id,
        actor_email,
        action,
        target_type,
        target_id,
        json.dumps(before_payload),
        json.dumps(after_payload),
        request_id,
        ip_address,
        created_at,
        prev_hash,
        row_hash,
    )
