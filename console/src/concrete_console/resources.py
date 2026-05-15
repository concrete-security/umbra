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
        "state": user_state(row),
        "deactivated_at": timestamp(row["deactivated_at"]) if row["deactivated_at"] else None,
        "created_at": timestamp(row["created_at"]),
        "deleted_at": timestamp(row["deleted_at"]) if row["deleted_at"] else None,
    }


def user_state(row: dict[str, Any]) -> str:
    if row["deleted_at"]:
        return "erased"
    if row["deactivated_at"]:
        return "deactivated"
    return "active"


def list_page(items: list[dict[str, Any]], *, next_cursor: str | None = None) -> dict[str, Any]:
    return {
        "items": items,
        "next_cursor": next_cursor,
    }


def profile_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    return {
        "id": str(row["id"]),
        "entity_id": str(row["entity_id"]),
        "name": row["name"],
        "description": row["description"],
        "policy": json_payload(row["policy"]),
        "assigned": bool(row.get("assigned", False)),
        "attached_cvms": row.get("attached_cvms", []),
        "attached_cvm_count": row.get("attached_cvm_count", 0),
        "created_at": timestamp(row["created_at"]),
        "updated_at": timestamp(row["updated_at"]),
    }


def ssh_key_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    return {
        "id": str(row["id"]),
        "label": row["label"],
        "fingerprint": row["fingerprint"],
        "public_key": row["public_key"],
        "created_at": timestamp(row["created_at"]),
    }


def entity_quota_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    return {
        "entity_id": str(row["entity_id"]),
        "resource": row["resource"],
        "limit": row["limit"],
        "source": row["source"],
        "current_usage": row["current_usage"],
        "set_by": str(row["set_by"]) if row["set_by"] else None,
        "set_at": timestamp(row["set_at"]) if row["set_at"] else None,
    }


def user_quota_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    return {
        "user_id": str(row["user_id"]),
        "resource": row["resource"],
        "limit": row["limit"],
        "source": row["source"],
        "current_usage": row["current_usage"],
        "set_by": str(row["set_by"]) if row["set_by"] else None,
        "set_at": timestamp(row["set_at"]) if row["set_at"] else None,
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


def operation_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    progress = None
    if row["progress_step"] is not None:
        progress = {
            "step": row["progress_step"],
            "percent": row["progress_percent"],
        }
    return {
        "id": str(row["id"]),
        "kind": row["kind"],
        "status": row["status"],
        "actor_id": str(row["actor_id"]) if row["actor_id"] else None,
        "target": {
            "type": row["target_type"],
            "id": str(row["target_id"]) if row["target_id"] else None,
        },
        "result": json_payload(row["result"]) if row["result"] is not None else None,
        "error": json_payload(row["error"]) if row["error"] is not None else None,
        "progress": progress,
        "created_at": timestamp(row["created_at"]),
        "updated_at": timestamp(row["updated_at"]),
        "expires_at": timestamp(row["expires_at"]) if row["expires_at"] else None,
    }


def traffic_log_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    return {
        "id": str(row["id"]),
        "timestamp": timestamp(row["timestamp"]),
        "security_cvm_id": str(row["security_cvm_id"]),
        "cvm_id": str(row["cvm_id"]) if row["cvm_id"] else None,
        "source_ip": row["source_ip"],
        "destination_ip": row["destination_ip"],
        "destination_host": row["destination_host"],
        "protocol": row["protocol"],
        "port": row["port"],
        "method": row["method"],
        "path": row["path"],
        "response_code": row["response_code"],
        "bytes_transferred": row["bytes_transferred"],
    }


def json_payload(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value
