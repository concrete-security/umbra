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
    attached_cvms = json_payload(row.get("attached_cvms", []))
    return {
        "id": str(row["id"]),
        "entity_id": str(row["entity_id"]),
        "name": row["name"],
        "description": row["description"],
        "policy": json_payload(row["policy"]),
        "assigned": bool(row.get("assigned", False)),
        "attached_cvms": [
            {"id": str(cvm["id"]), "fqdn": cvm["fqdn"], "state": cvm["state"]} for cvm in attached_cvms
        ],
        "attached_cvm_count": row.get("attached_cvm_count", 0),
        "created_at": timestamp(row["created_at"]),
        "updated_at": timestamp(row["updated_at"]),
    }


def profile_member_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    return {
        "user_id": str(row["user_id"]),
        "email": row["email"],
        "added_at": timestamp(row["added_at"]),
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


def cvm_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    profiles = json_payload(row.get("profiles", []))
    ssh_keys = json_payload(row.get("ssh_keys", []))
    return {
        "id": str(row["id"]),
        "owner": {
            "id": str(row["owner_id"]),
            "email": row["owner_email"],
        },
        "entity_id": str(row["entity_id"]),
        "profiles": [{"id": str(profile["id"]), "name": profile["name"]} for profile in profiles],
        "state": row["state"],
        "instance_type": row["instance_type"],
        "region": row["region"],
        "ssh_keys": [{"id": str(key["id"]), "label": key["label"]} for key in ssh_keys],
        "fqdn": row["fqdn"],
        "expected_image_measurement": row["expected_image_measurement"],
        "image_measurement": row["image_measurement"],
        "rtmr3_digest": row["rtmr3_digest"],
        "attestation_verified_at": timestamp(row["attestation_verified_at"]) if row["attestation_verified_at"] else None,
        "error_reason": row["error_reason"],
        "created_at": timestamp(row["created_at"]),
        "updated_at": timestamp(row["updated_at"]),
    }


def security_cvm_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    return {
        "id": str(row["id"]),
        "entity_id": str(row["entity_id"]),
        "state": row["state"],
        "fqdn": row["fqdn"],
        "instance_type": row["instance_type"],
        "region": row["region"],
        "error_reason": row["error_reason"],
        "policy_version": row["policy_version"],
        "expected_image_measurement": row["expected_image_measurement"],
        "image_measurement": row["image_measurement"],
        "rtmr3_digest": row["rtmr3_digest"],
        "attestation_verified_at": timestamp(row["attestation_verified_at"]) if row["attestation_verified_at"] else None,
        "created_at": timestamp(row["created_at"]),
        "updated_at": timestamp(row["updated_at"]),
    }


def security_cvm_attestation_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    verified = (
        row["error_reason"] is None
        and row["expected_image_measurement"] is not None
        and row["image_measurement"] == row["expected_image_measurement"]
        and row["rtmr3_digest"] is not None
        and row["attestation_verified_at"] is not None
    )
    failure_reason = security_cvm_attestation_failure_reason(row, verified=verified)
    return {
        "security_cvm_id": str(row["id"]),
        "fqdn": row["fqdn"],
        "expected_image_measurement": row["expected_image_measurement"],
        "verdict": {
            "verified": verified,
            "failure_reason": failure_reason,
            "image_measurement_seen": row["image_measurement"],
            "rtmr3_digest_seen": row["rtmr3_digest"],
            "verified_at": timestamp(row["attestation_verified_at"]) if row["attestation_verified_at"] else None,
        },
    }


def security_cvm_attestation_failure_reason(row: dict[str, Any], *, verified: bool) -> str | None:
    if verified:
        return None
    if row["error_reason"]:
        return row["error_reason"]
    if (
        row["expected_image_measurement"] is not None
        and row["image_measurement"] is not None
        and row["image_measurement"] != row["expected_image_measurement"]
    ):
        return "ATTESTATION_IMAGE_MISMATCH"
    return None


def json_payload(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value
