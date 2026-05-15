from __future__ import annotations

from datetime import datetime, timezone
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
