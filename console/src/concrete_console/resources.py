from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Any


def timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def entity_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    return {
        "id": str(row["id"]),
        "name": row["name"],
        "domain": row["domain"],
        "created_at": timestamp(row["created_at"]),
    }


def user_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    return {
        "id": str(row["id"]),
        "email": row["email"],
        "name": row["name"],
        "entity": {
            "id": str(row["entity_id"]),
            "name": row["entity_name"],
        },
        "permissions": sorted(row["permissions"]),
        "profiles": row.get("profiles", []),
        "created_at": timestamp(row["created_at"]),
        "deleted_at": timestamp(row["deleted_at"]) if row["deleted_at"] else None,
    }


def list_page(items: list[dict[str, Any]], *, next_cursor: str | None = None) -> dict[str, Any]:
    return {
        "items": items,
        "next_cursor": next_cursor,
    }


def audit_event_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    return {
        "seq": row["seq"],
        "id": str(row["id"]),
        "entity_id": str(row["entity_id"]) if row["entity_id"] else None,
        "actor_id": str(row["actor_id"]) if row["actor_id"] else None,
        "actor_email": row["actor_email"],
        "action": row["action"],
        "target_type": row["target_type"],
        "target_id": str(row["target_id"]) if row["target_id"] else None,
        "before": json_payload(row["before"]),
        "after": json_payload(row["after"]),
        "ip_address": row["ip_address"],
        "description": row["description"],
        "request_id": row["request_id"],
        "timestamp": timestamp(row["timestamp"]),
        "prev_hash": row["prev_hash"],
        "row_hash": row["row_hash"],
    }


def json_payload(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value
