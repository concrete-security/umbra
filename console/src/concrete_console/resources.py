from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import math
from typing import Any

from concrete_console.profile_secrets import redacted_profile_policy as redact_profile_policy


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
    profiles = json_payload(row.get("profiles", []))
    return {
        "id": str(row["id"]),
        "email": row["email"],
        "name": row["name"],
        "entity": {
            "id": str(row["entity_id"]),
            "name": row["entity_name"],
        },
        "permissions": sorted(row["permissions"]),
        "profiles": [{"id": str(profile["id"]), "name": profile["name"]} for profile in profiles],
        "state": user_state(row),
        "deactivated_at": timestamp(row["deactivated_at"]) if row["deactivated_at"] else None,
        "last_login_at": timestamp(row["last_login_at"]) if row.get("last_login_at") else None,
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
        "policy": redacted_profile_policy(row["policy"]),
        "assigned": bool(row.get("assigned", False)),
        "attached_cvms": [
            {"id": str(cvm["id"]), "fqdn": cvm["fqdn"], "state": cvm["state"]} for cvm in attached_cvms
        ],
        "attached_cvm_count": row.get("attached_cvm_count", 0),
        "created_at": timestamp(row["created_at"]),
        "updated_at": timestamp(row["updated_at"]),
    }


def redacted_profile_policy(policy: Any) -> Any:
    parsed = json_payload(policy)
    return redact_profile_policy(parsed)


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
        "error": operation_error_payload(row["error"]) if row["error"] is not None else None,
        "progress": progress,
        "created_at": timestamp(row["created_at"]),
        "updated_at": timestamp(row["updated_at"]),
        "expires_at": timestamp(row["expires_at"]) if row["expires_at"] else None,
    }


def traffic_log_resource(row: Any) -> dict[str, Any]:
    row = dict(row)
    attributes = json_payload(row.get("attributes", {})) if "attributes" in row else {}
    if not isinstance(attributes, dict):
        attributes = {}
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
        "attributes": attributes,
    }


# Egress blocked at the Security CVM is logged as HTTP 403 (enforcement.py _blocked_result).
TRAFFIC_BLOCK_CODE = 403

# Bound how many time buckets one timeseries request can ask for so the query and
# the SVG chart stay cheap regardless of the selected range.
TRAFFIC_TIMESERIES_MAX_BUCKETS = 500
TRAFFIC_TIMESERIES_DEFAULT_BUCKETS = 60
# Default lookback when the caller does not pin a time range.
TRAFFIC_TIMESERIES_DEFAULT_WINDOW = timedelta(hours=24)

# Calendar-aligned granularities. "auto" falls back to fixed-width epoch buckets
# sized to fit the range. The calendar units truncate to UTC boundaries (day =
# midnight, week = Monday, month = the 1st) so day-to-day / week-to-week /
# month-to-month comparisons line up exactly.
TRAFFIC_TIMESERIES_GRANULARITIES = ("auto", "hour", "day", "week", "month")
_CALENDAR_DEFAULT_WINDOW = {
    "hour": timedelta(hours=48),
    "day": timedelta(days=30),
    "week": timedelta(weeks=12),
    "month": timedelta(days=365),
}


def _floor_to_calendar_unit(dt: datetime, unit: str) -> datetime:
    dt = dt.astimezone(timezone.utc)
    if unit == "hour":
        return dt.replace(minute=0, second=0, microsecond=0)
    day = dt.replace(hour=0, minute=0, second=0, microsecond=0)
    if unit == "day":
        return day
    if unit == "week":
        return day - timedelta(days=day.weekday())  # back to Monday
    if unit == "month":
        return day.replace(day=1)
    raise ValueError(f"unsupported calendar unit: {unit}")


def _next_calendar_unit(dt: datetime, unit: str) -> datetime:
    if unit == "hour":
        return dt + timedelta(hours=1)
    if unit == "day":
        return dt + timedelta(days=1)
    if unit == "week":
        return dt + timedelta(weeks=1)
    if unit == "month":
        return dt.replace(year=dt.year + 1, month=1) if dt.month == 12 else dt.replace(month=dt.month + 1)
    raise ValueError(f"unsupported calendar unit: {unit}")


def resolve_traffic_timeseries(
    from_: datetime | None,
    to: datetime | None,
    buckets: int,
    granularity: str | None,
    *,
    now: datetime,
) -> dict[str, Any]:
    """Resolve a traffic-timeseries plan: window, bucket boundaries, and bucketing mode.

    Returns a dict with ``lo``/``hi`` (datetimes), ``granularity`` (the resolved
    mode), ``starts`` (the ordered bucket-start datetimes, gap-free), and exactly
    one of ``unit`` (calendar ``date_trunc`` unit) or ``bucket_seconds`` (fixed
    epoch width) describing how the DB query must bucket rows.
    """
    granularity = (granularity or "auto").lower()
    if granularity not in TRAFFIC_TIMESERIES_GRANULARITIES:
        granularity = "auto"
    hi = to or now

    if granularity == "auto":
        lo = from_ if from_ is not None else hi - TRAFFIC_TIMESERIES_DEFAULT_WINDOW
        if lo >= hi:
            lo = hi - TRAFFIC_TIMESERIES_DEFAULT_WINDOW
        buckets = max(1, min(TRAFFIC_TIMESERIES_MAX_BUCKETS, buckets))
        span = (hi - lo).total_seconds()
        width = max(1, math.ceil(span / buckets))
        lo_epoch = math.floor(lo.timestamp() / width) * width
        hi_epoch = math.floor(hi.timestamp() / width) * width
        starts = [
            datetime.fromtimestamp(epoch, tz=timezone.utc)
            for epoch in range(lo_epoch, hi_epoch + 1, width)
        ]
        return {
            "lo": datetime.fromtimestamp(lo_epoch, tz=timezone.utc),
            "hi": hi,
            "granularity": "auto",
            "unit": None,
            "bucket_seconds": width,
            "starts": starts,
        }

    lo = from_ if from_ is not None else hi - _CALENDAR_DEFAULT_WINDOW[granularity]
    if lo >= hi:
        lo = hi - _CALENDAR_DEFAULT_WINDOW[granularity]
    starts: list[datetime] = []
    cur = _floor_to_calendar_unit(lo, granularity)
    while cur <= hi:
        starts.append(cur)
        cur = _next_calendar_unit(cur, granularity)
    # Safety bound: keep the most recent buckets if an extreme range/unit combo
    # would blow past the cap (the UI never offers such combos).
    if len(starts) > TRAFFIC_TIMESERIES_MAX_BUCKETS:
        starts = starts[-TRAFFIC_TIMESERIES_MAX_BUCKETS:]
    return {
        "lo": starts[0] if starts else _floor_to_calendar_unit(lo, granularity),
        "hi": hi,
        "granularity": granularity,
        "unit": granularity,
        "bucket_seconds": None,
        "starts": starts,
    }


def traffic_timeseries_payload(rows: Any, plan: dict[str, Any]) -> dict[str, Any]:
    """Build a gap-free, cumulative timeseries payload from grouped rows.

    DB rows are sparse (only buckets with traffic appear); this fills every bucket
    start in ``plan["starts"]`` with zeros, adds a running cumulative total (proof
    of growth across the window), and reports the per-bucket peak (the spikes).
    """
    counts: dict[int, tuple[int, int]] = {}
    for row in rows:
        bucket = row["bucket"]
        if bucket.tzinfo is None:
            bucket = bucket.replace(tzinfo=timezone.utc)
        counts[int(bucket.timestamp())] = (int(row["allowed"]), int(row["blocked"]))

    points: list[dict[str, Any]] = []
    total_allowed = 0
    total_blocked = 0
    cumulative = 0
    peak = 0
    peak_ts: str | None = None
    for start in plan["starts"]:
        allowed, blocked = counts.get(int(start.timestamp()), (0, 0))
        bucket_total = allowed + blocked
        total_allowed += allowed
        total_blocked += blocked
        cumulative += bucket_total
        ts = timestamp(start)
        if bucket_total > peak:
            peak = bucket_total
            peak_ts = ts
        points.append(
            {
                "ts": ts,
                "allowed": allowed,
                "blocked": blocked,
                "cumulative": cumulative,
            }
        )

    return {
        "from": timestamp(plan["lo"]),
        "to": timestamp(plan["hi"]),
        "granularity": plan["granularity"],
        "bucket_seconds": plan["bucket_seconds"],
        "buckets": points,
        "totals": {
            "allowed": total_allowed,
            "blocked": total_blocked,
            "total": total_allowed + total_blocked,
            "peak": peak,
            "peak_ts": peak_ts,
        },
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


def operation_error_payload(value: Any) -> Any:
    payload = json_payload(value)
    if not isinstance(payload, dict):
        return payload
    code = payload.get("code")
    if not isinstance(code, str) or "message" in payload:
        return payload
    normalized = dict(payload)
    normalized["message"] = operation_error_message(code)
    normalized["details"] = normalized.get("details") or {}
    return normalized


def operation_error_message(code: str) -> str:
    return code.lower().replace("_", " ")
