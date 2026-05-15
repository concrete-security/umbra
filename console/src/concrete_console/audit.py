from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from typing import Any
from uuid import UUID, uuid4

import asyncpg

EMPTY_HASH = hashlib.sha256(b"").hexdigest()
AUDIT_CHAIN_LOCK_ID = 612401837045733343
AUDIT_ACTIONS = (
    "ENTITY_CREATED",
    "ENTITY_UPDATED",
    "USER_REGISTERED",
    "USER_DEACTIVATED",
    "USER_REACTIVATED",
    "USER_ERASED",
    "PERMISSION_GRANTED",
    "PERMISSION_REVOKED",
    "PROFILE_CREATED",
    "PROFILE_DELETED",
    "PROFILE_USER_ASSIGNED",
    "PROFILE_USER_REMOVED",
    "SSH_KEY_ADDED",
    "SSH_KEY_REMOVED",
    "CVM_LAUNCHED",
    "CVM_STARTED",
    "CVM_STOPPED",
    "CVM_TERMINATED",
    "SUBDOMAIN_PROVISIONED",
    "SUBDOMAIN_DEPROVISIONED",
    "SECURITY_CVM_PROVISIONING_STARTED",
    "SECURITY_CVM_PROVISIONED",
    "SECURITY_CVM_PROVISIONING_FAILED",
    "SECURITY_CVM_DECOMMISSIONED",
    "SECURITY_CVM_ATTESTATION_VERIFIED",
    "SECURITY_CVM_ATTESTATION_DRIFT",
    "CVM_ATTESTATION_VERIFIED",
    "CVM_ATTESTATION_DRIFT",
    "CVM_PROFILE_ATTACHED",
    "CVM_PROFILE_DETACHED",
    "PROFILE_POLICY_UPDATED",
    "AUTH_SESSION_ISSUED",
    "AUTH_SESSION_REFRESHED",
    "AUTH_SESSION_REVOKED",
    "AUTH_REFRESH_REUSE_DETECTED",
    "OAUTH_IDENTITY_LINKED",
    "OAUTH_REBIND_REFUSED",
    "OPERATION_RESULT_DISCLOSED",
    "AUDIT_EXPORT_REQUESTED",
    "AUDIT_EXPORT_ISSUED",
    "JWT_KEY_ROTATED",
    "QUOTA_SET",
    "QUOTA_CLEARED",
    "SESSIONS_REVOKED",
)
AUDIT_DESCRIPTIONS = {action: action.lower().replace("_", " ") for action in AUDIT_ACTIONS}


def canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def audit_row_hash(row: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(row).encode("utf-8")).hexdigest()


async def insert_audit_event(
    conn: asyncpg.Connection,
    *,
    entity_id: UUID | None,
    actor_id: UUID | None,
    actor_email: str | None,
    action: str,
    target_type: str,
    target_id: UUID | str,
    before: dict[str, Any] | None = None,
    after: dict[str, Any] | None = None,
    description: str | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
) -> None:
    if action not in AUDIT_DESCRIPTIONS:
        raise ValueError(f"unknown audit action: {action}")

    await conn.execute("SELECT pg_advisory_xact_lock($1)", AUDIT_CHAIN_LOCK_ID)
    prev_hash = await conn.fetchval("SELECT row_hash FROM audit_events ORDER BY seq DESC LIMIT 1")
    prev_hash = prev_hash or EMPTY_HASH
    seq = await conn.fetchval("SELECT nextval('audit_events_seq_seq')")
    event_id = uuid4()
    event_timestamp = datetime.now(timezone.utc)
    target_id_text = str(target_id)
    description_value = description if description is not None else AUDIT_DESCRIPTIONS[action]
    hash_payload = {
        "seq": seq,
        "id": str(event_id),
        "entity_id": str(entity_id) if entity_id else None,
        "actor_id": str(actor_id) if actor_id else None,
        "actor_email": actor_email,
        "action": action,
        "target_type": target_type,
        "target_id": target_id_text,
        "before": before,
        "after": after,
        "ip_address": ip_address,
        "description": description_value,
        "request_id": request_id,
        "timestamp": event_timestamp.isoformat().replace("+00:00", "Z"),
        "prev_hash": prev_hash,
    }
    row_hash = audit_row_hash(hash_payload)

    await conn.execute(
        """
        INSERT INTO audit_events (
            seq, id, entity_id, actor_id, actor_email, action, target_type, target_id,
            before, after, ip_address, description, request_id, timestamp, prev_hash, row_hash
        )
        VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8,
            $9::jsonb, $10::jsonb, $11, $12, $13, $14, $15, $16
        )
        """,
        seq,
        event_id,
        entity_id,
        actor_id,
        actor_email,
        action,
        target_type,
        target_id_text,
        json.dumps(before) if before is not None else None,
        json.dumps(after) if after is not None else None,
        ip_address,
        description_value,
        request_id,
        event_timestamp,
        prev_hash,
        row_hash,
    )
