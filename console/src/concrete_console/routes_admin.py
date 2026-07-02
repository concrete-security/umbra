from __future__ import annotations

import asyncio
import json
import re
import time
from datetime import datetime, timezone
from typing import Annotated, Any, AsyncIterator
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, StreamingResponse

from concrete_console.admin_log_buffer import (
    acquire_log_stream_slot,
    recent_log_events,
    release_log_stream_slot,
)
from concrete_console.audit import AUDIT_ACTIONS
from concrete_console.auth import CurrentUser, require_current_user
from concrete_console.db import get_pool
from concrete_console.errors import api_error
from concrete_console.log_config import logger
from concrete_console.metrics import prometheus_text
from concrete_console.readiness import run_ready_checks
from concrete_console.resources import (
    audit_event_resource,
    cvm_resource,
    entity_resource,
    list_page,
    security_cvm_resource,
    timestamp,
    traffic_log_resource,
    TRAFFIC_TIMESERIES_DEFAULT_BUCKETS,
    TRAFFIC_TIMESERIES_MAX_BUCKETS,
    resolve_traffic_timeseries,
    traffic_timeseries_payload,
)
from concrete_console.routes import (
    fetch_traffic_timeseries_rows,
    parse_audit_cursor,
    parse_traffic_log_cursor,
    traffic_log_cursor,
)
from concrete_console.scheduler import scheduler_last_tick_age_seconds
from concrete_console.tee_provider.phala import PhalaClient, PhalaError, concrete_cvm_name

router = APIRouter(prefix="/api/v1/admin")

log = logger()

PHALA_CVM_NAME_PREFIX = re.compile(r"^concrete-v0-cvm-")


def require_platform_operator(current_user: CurrentUser) -> None:
    current_user.require_permission("PLATFORM_OPERATOR")


def phala_name_for_cvm_id(cvm_id: UUID) -> str:
    return f"concrete-v0-cvm-{str(cvm_id).replace('-', '')[:12]}"


def admin_operation_summary(row: Any) -> dict[str, Any]:
    row = dict(row)
    progress = None
    if row.get("progress_step") is not None:
        progress = {"step": row["progress_step"], "percent": row["progress_percent"]}
    error = None
    if row.get("error") is not None:
        payload = row["error"]
        if isinstance(payload, str):
            payload = json.loads(payload)
        if isinstance(payload, dict):
            error = {"code": payload.get("code")}
    return {
        "id": str(row["id"]),
        "kind": row["kind"],
        "status": row["status"],
        "actor_id": str(row["actor_id"]) if row.get("actor_id") else None,
        "actor_email": row.get("actor_email"),
        "target": {
            "type": row.get("target_type"),
            "id": str(row["target_id"]) if row.get("target_id") else None,
        },
        "progress": progress,
        "error": error,
        "created_at": timestamp(row["created_at"]),
        "updated_at": timestamp(row["updated_at"]),
    }


def admin_cvm_summary(row: Any, *, phala_by_name: dict[str, dict[str, Any]]) -> dict[str, Any]:
    base = cvm_resource(row)
    name = phala_name_for_cvm_id(row["id"])
    phala = phala_by_name.get(name, {})
    return {
        **base,
        "entity_name": row["entity_name"],
        "phala_name": name,
        "phala_status": phala.get("status"),
        "phala_uptime": phala.get("uptime"),
    }


def operation_cursor(row: asyncpg.Record) -> str:
    return f"{timestamp(row['updated_at'])}|{row['id']}"


def parse_operation_cursor(cursor: str | None) -> tuple[datetime, UUID] | None:
    if cursor is None:
        return None
    if "|" not in cursor:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "invalid cursor",
            {"errors": [{"type": "invalid_cursor", "field": "cursor"}]},
        )
    ts_text, id_text = cursor.split("|", 1)
    try:
        parsed_ts = datetime.fromisoformat(ts_text.replace("Z", "+00:00"))
        if parsed_ts.tzinfo is None:
            parsed_ts = parsed_ts.replace(tzinfo=timezone.utc)
        return parsed_ts.astimezone(timezone.utc), UUID(id_text)
    except (ValueError, TypeError) as exc:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "invalid cursor",
            {"errors": [{"type": "invalid_cursor", "field": "cursor"}]},
        ) from exc


# Live Phala CVM status enriches the dashboard's CVM list and overview, but the
# underlying call spawns the Phala CLI (subprocess + network round-trip). The
# dashboard polls every ~10s, so we cache the result process-wide and serve it
# stale-while-revalidate: a stale read returns the last known value immediately
# and refreshes in the background, keeping the CLI off every request's hot path.
PHALA_STATUS_TTL_SECONDS = 20.0
_phala_status_cache: dict[str, dict[str, Any]] = {}
_phala_status_cache_at: float | None = None
_phala_status_refresh_task: asyncio.Task[None] | None = None


async def _fetch_phala_status_by_name() -> dict[str, dict[str, Any]]:
    try:
        client = PhalaClient.from_settings()
    except PhalaError:
        return {}
    try:
        rows = await client.list()
    except PhalaError:
        return {}
    by_name: dict[str, dict[str, Any]] = {}
    for row in rows:
        name = concrete_cvm_name(row) or row.get("name") or row.get("cvm")
        if not isinstance(name, str) or not PHALA_CVM_NAME_PREFIX.match(name):
            continue
        by_name[name] = {
            "app_id": row.get("app_id") or row.get("appId"),
            "status": row.get("status"),
            "uptime": row.get("uptime"),
        }
    return by_name


async def _refresh_phala_status_cache() -> None:
    global _phala_status_cache, _phala_status_cache_at
    _phala_status_cache = await _fetch_phala_status_by_name()
    _phala_status_cache_at = time.monotonic()


async def _refresh_phala_status_background() -> None:
    try:
        await _refresh_phala_status_cache()
    except Exception:  # best-effort: keep serving the last known status
        log.warning("phala_status_refresh_failed", exc_info=True)


async def phala_status_by_name() -> dict[str, dict[str, Any]]:
    global _phala_status_refresh_task
    if _phala_status_cache_at is None:
        # Cold cache: the first caller must wait for a real result.
        await _refresh_phala_status_cache()
    elif time.monotonic() - _phala_status_cache_at >= PHALA_STATUS_TTL_SECONDS:
        # Stale: serve the cached value now and refresh in the background.
        if _phala_status_refresh_task is None or _phala_status_refresh_task.done():
            _phala_status_refresh_task = asyncio.create_task(_refresh_phala_status_background())
    return _phala_status_cache


def parse_metrics_summary() -> dict[str, Any]:
    text = prometheus_text()
    requests: list[tuple[int, str]] = []
    redacted_total = 0
    for line in text.splitlines():
        if line.startswith("concrete_console_requests_total{"):
            match = re.search(r'\{route="([^"]*)",method="([^"]*)",status="(\d+)"\} (\d+)$', line)
            if match:
                route, method, status, value = match.group(1), match.group(2), match.group(3), int(match.group(4))
                requests.append((value, f"{method} {route} {status}"))
        if line.startswith("concrete_console_redacted_value_in_log_total"):
            parts = line.rsplit(" ", 1)
            if len(parts) == 2:
                try:
                    redacted_total += int(parts[1])
                except ValueError:
                    pass
    requests.sort(reverse=True)
    return {
        "requests_total_top": [{"count": count, "label": label} for count, label in requests[:12]],
        "redacted_log_events_total": redacted_total,
    }


@router.get("/overview")
async def admin_overview(
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    require_platform_operator(current_user)
    async with pool.acquire() as conn:
        counts = await conn.fetchrow(
            """
            SELECT
                (SELECT count(*)::int FROM entities) AS entities,
                (SELECT count(*)::int FROM users WHERE deleted_at IS NULL) AS users,
                (SELECT count(*)::int FROM cvms WHERE deleted_at IS NULL) AS dev_cvms,
                (SELECT count(*)::int FROM cvms WHERE deleted_at IS NULL AND state = 'RUNNING') AS dev_cvms_running,
                (SELECT count(*)::int FROM security_cvms WHERE deleted_at IS NULL) AS security_cvms,
                (SELECT count(*)::int FROM security_cvms WHERE deleted_at IS NULL AND state = 'RUNNING') AS security_cvms_running,
                (SELECT count(*)::int FROM operations WHERE status IN ('pending', 'running')) AS active_operations,
                (SELECT count(*)::int FROM traffic_logs WHERE timestamp > now() - interval '5 minutes') AS traffic_events_5m,
                (SELECT count(*)::int FROM audit_events WHERE timestamp > now() - interval '5 minutes') AS audit_events_5m
            """
        )
    checks = await run_ready_checks()
    phala_rows = await phala_status_by_name()
    return {
        "generated_at": timestamp(datetime.now(timezone.utc)),
        "counts": dict(counts) if counts else {},
        "scheduler_last_tick_seconds_ago": scheduler_last_tick_age_seconds(),
        "readiness": checks,
        "phala_cvms": [
            {"name": name, **status}
            for name, status in sorted(phala_rows.items())
        ],
    }


@router.get("/operations")
async def admin_list_operations(
    status: str | None = Query(default=None, max_length=32),
    kind: str | None = Query(default=None, max_length=64),
    entity_id: UUID | None = None,
    since: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=128),
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    require_platform_operator(current_user)
    cursor_anchor = parse_operation_cursor(cursor)
    clauses: list[str] = ["(o.expires_at IS NULL OR o.expires_at > now())"]
    values: list[object] = []

    def bind(value: object) -> str:
        values.append(value)
        return f"${len(values)}"

    if status is not None:
        clauses.append(f"o.status = {bind(status)}::operation_status")
    if kind is not None:
        clauses.append(f"o.kind = {bind(kind)}")
    if since is not None:
        clauses.append(f"o.updated_at >= {bind(since)}")
    if entity_id is not None:
        entity_bind = bind(entity_id)
        clauses.append(
            f"(u.entity_id = {entity_bind} OR c.entity_id = {entity_bind} OR sc.entity_id = {entity_bind})"
        )
    if cursor_anchor is not None:
        cursor_ts, cursor_id = cursor_anchor
        clauses.append(f"(o.updated_at, o.id) < ({bind(cursor_ts)}, {bind(cursor_id)})")

    values.append(limit + 1)
    query = f"""
        SELECT
            o.id,
            o.kind,
            o.status::text AS status,
            o.actor_id,
            o.actor_email,
            o.target_type,
            o.target_id,
            o.progress_step,
            o.progress_percent,
            o.error,
            o.created_at,
            o.updated_at
        FROM operations o
        LEFT JOIN users u ON u.id = o.actor_id
        LEFT JOIN cvms c ON c.id = o.target_id AND o.target_type = 'cvm'
        LEFT JOIN security_cvms sc ON sc.id = o.target_id AND o.target_type = 'security_cvm'
        WHERE {' AND '.join(clauses)}
        ORDER BY o.updated_at DESC, o.id DESC
        LIMIT ${len(values)}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *values)
    next_cursor = operation_cursor(rows[limit - 1]) if len(rows) > limit else None
    return list_page([admin_operation_summary(row) for row in rows[:limit]], next_cursor=next_cursor)


@router.get("/audit/events")
async def admin_list_audit_events(
    entity_id: UUID | None = None,
    actor_id: UUID | None = None,
    target_type: str | None = Query(default=None, max_length=50),
    target_id: str | None = Query(default=None, max_length=255),
    action: str | None = Query(default=None, max_length=100),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None, max_length=32),
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    require_platform_operator(current_user)
    if action is not None and action not in AUDIT_ACTIONS:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "unknown audit action",
            {"errors": [{"type": "unknown_action", "field": "action"}]},
        )
    after_seq = parse_audit_cursor(cursor)
    clauses: list[str] = ["TRUE"]
    values: list[object] = []

    def bind(value: object) -> str:
        values.append(value)
        return f"${len(values)}"

    if entity_id is not None:
        clauses.append(f"entity_id = {bind(entity_id)}")
    if actor_id is not None:
        clauses.append(f"actor_id = {bind(actor_id)}")
    if target_type is not None:
        clauses.append(f"target_type = {bind(target_type)}")
    if target_id is not None:
        clauses.append(f"target_id = {bind(target_id)}")
    if action is not None:
        clauses.append(f"action = {bind(action)}")
    if from_ is not None:
        clauses.append(f"timestamp >= {bind(from_)}")
    if to is not None:
        clauses.append(f"timestamp <= {bind(to)}")
    if after_seq is not None:
        clauses.append(f"seq < {bind(after_seq)}")

    values.append(limit + 1)
    query = f"""
        SELECT
            seq, id, entity_id, actor_id, actor_email, action, target_type, target_id,
            before, after, ip_address, description, request_id, timestamp, prev_hash, row_hash
        FROM audit_events
        WHERE {' AND '.join(clauses)}
        ORDER BY seq DESC
        LIMIT ${len(values)}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *values)
    next_cursor = str(rows[limit - 1]["seq"]) if len(rows) > limit else None
    return list_page([audit_event_resource(row) for row in rows[:limit]], next_cursor=next_cursor)


@router.get("/traffic-logs")
async def admin_list_traffic_logs(
    entity_id: UUID | None = None,
    cvm_id: UUID | None = None,
    destination_host: str | None = Query(default=None, max_length=255),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    cursor: str | None = Query(default=None, max_length=128),
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    require_platform_operator(current_user)
    cursor_value = parse_traffic_log_cursor(cursor)
    clauses: list[str] = ["TRUE"]
    values: list[object] = []

    def bind(value: object) -> str:
        values.append(value)
        return f"${len(values)}"

    if entity_id is not None:
        clauses.append(f"sc.entity_id = {bind(entity_id)}")
    if cvm_id is not None:
        clauses.append(f"tl.cvm_id = {bind(cvm_id)}")
    if destination_host is not None:
        clauses.append(f"tl.destination_host = {bind(destination_host)}")
    if from_ is not None:
        clauses.append(f"tl.timestamp >= {bind(from_)}")
    if to is not None:
        clauses.append(f"tl.timestamp <= {bind(to)}")
    if cursor_value is not None:
        cursor_timestamp, cursor_id = cursor_value
        clauses.append(f"(tl.timestamp, tl.id) < ({bind(cursor_timestamp)}, {bind(cursor_id)})")

    values.append(limit + 1)
    query = f"""
        SELECT
            tl.id,
            tl.timestamp,
            tl.security_cvm_id,
            tl.cvm_id,
            sc.entity_id,
            tl.source_ip,
            tl.destination_ip,
            tl.destination_host,
            tl.protocol,
            tl.port,
            tl.method,
            tl.path,
            tl.response_code,
            tl.bytes_transferred
        FROM traffic_logs tl
        JOIN security_cvms sc ON sc.id = tl.security_cvm_id
        WHERE {' AND '.join(clauses)}
        ORDER BY tl.timestamp DESC, tl.id DESC
        LIMIT ${len(values)}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *values)
    next_cursor = traffic_log_cursor(rows[limit - 1]) if len(rows) > limit else None
    items = []
    for row in rows[:limit]:
        payload = traffic_log_resource(row)
        payload["entity_id"] = str(row["entity_id"])
        items.append(payload)
    return list_page(items, next_cursor=next_cursor)


@router.get("/traffic-logs/summary")
async def admin_traffic_log_host_summary(
    entity_id: UUID | None = None,
    cvm_id: UUID | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    require_platform_operator(current_user)
    clauses: list[str] = ["tl.destination_host IS NOT NULL"]
    values: list[object] = []

    def bind(value: object) -> str:
        values.append(value)
        return f"${len(values)}"

    if entity_id is not None:
        clauses.append(f"sc.entity_id = {bind(entity_id)}")
    if cvm_id is not None:
        clauses.append(f"tl.cvm_id = {bind(cvm_id)}")
    if from_ is not None:
        clauses.append(f"tl.timestamp >= {bind(from_)}")
    if to is not None:
        clauses.append(f"tl.timestamp <= {bind(to)}")

    values.append(limit)
    query = f"""
        SELECT tl.destination_host AS host, count(*)::int AS count
        FROM traffic_logs tl
        JOIN security_cvms sc ON sc.id = tl.security_cvm_id
        WHERE {' AND '.join(clauses)}
        GROUP BY tl.destination_host
        ORDER BY count DESC, tl.destination_host ASC
        LIMIT ${len(values)}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *values)
    return {"hosts": [{"host": row["host"], "count": row["count"]} for row in rows]}


@router.get("/traffic-logs/timeseries")
async def admin_traffic_log_timeseries(
    entity_id: UUID | None = None,
    cvm_id: UUID | None = None,
    destination_host: str | None = Query(default=None, max_length=255),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    buckets: int = Query(default=TRAFFIC_TIMESERIES_DEFAULT_BUCKETS, ge=1, le=TRAFFIC_TIMESERIES_MAX_BUCKETS),
    granularity: str | None = Query(default=None, max_length=8),
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    require_platform_operator(current_user)
    plan = resolve_traffic_timeseries(from_, to, buckets, granularity, now=datetime.now(timezone.utc))
    clauses = ["TRUE"]
    values: list[object] = []

    def bind(value: object) -> str:
        values.append(value)
        return f"${len(values)}"

    clauses.append(f"tl.timestamp >= {bind(plan['lo'])}")
    clauses.append(f"tl.timestamp <= {bind(plan['hi'])}")
    if entity_id is not None:
        clauses.append(f"sc.entity_id = {bind(entity_id)}")
    if cvm_id is not None:
        clauses.append(f"tl.cvm_id = {bind(cvm_id)}")
    if destination_host is not None:
        clauses.append(f"tl.destination_host = {bind(destination_host)}")

    rows = await fetch_traffic_timeseries_rows(pool, clauses, values, plan)
    return traffic_timeseries_payload(rows, plan)


@router.get("/cvms")
async def admin_list_cvms(
    entity_id: UUID | None = None,
    state: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=200, ge=1, le=500),
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    require_platform_operator(current_user)
    clauses = ["c.deleted_at IS NULL"]
    values: list[object] = []

    def bind(value: object) -> str:
        values.append(value)
        return f"${len(values)}"

    if entity_id is not None:
        clauses.append(f"c.entity_id = {bind(entity_id)}")
    if state is not None:
        clauses.append(f"c.state = {bind(state)}::cvm_state")

    values.append(limit)
    query = f"""
        SELECT
            c.id,
            c.owner_id,
            owner.email AS owner_email,
            c.entity_id,
            e.name AS entity_name,
            c.state::text AS state,
            c.instance_type,
            c.region,
            c.disk_size_gb,
            c.fqdn,
            c.expected_image_measurement,
            c.image_measurement,
            c.rtmr3_digest,
            c.attestation_verified_at,
            c.error_reason,
            c.policy_version,
            c.created_at,
            c.updated_at,
            COALESCE(
                (
                    SELECT jsonb_agg(
                        jsonb_build_object('id', ep.id, 'name', ep.name)
                        ORDER BY ep.name, ep.id
                    )
                    FROM cvm_profiles cp
                    JOIN entity_profiles ep ON ep.id = cp.profile_id
                    WHERE cp.cvm_id = c.id
                      AND ep.deleted_at IS NULL
                ),
                '[]'::jsonb
            ) AS profiles,
            COALESCE(
                (
                    SELECT jsonb_agg(
                        jsonb_build_object('id', sk.id, 'label', sk.label)
                        ORDER BY sk.label, sk.id
                    )
                    FROM cvm_ssh_keys csk
                    JOIN ssh_keys sk ON sk.id = csk.ssh_key_id
                    WHERE csk.cvm_id = c.id
                      AND sk.deleted_at IS NULL
                ),
                '[]'::jsonb
            ) AS ssh_keys
        FROM cvms c
        JOIN users owner ON owner.id = c.owner_id
        JOIN entities e ON e.id = c.entity_id
        WHERE {' AND '.join(clauses)}
        ORDER BY c.updated_at DESC, c.id DESC
        LIMIT ${len(values)}
    """
    phala_by_name = await phala_status_by_name()
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *values)
    return list_page([admin_cvm_summary(row, phala_by_name=phala_by_name) for row in rows])


@router.get("/security-cvms")
async def admin_list_security_cvms(
    entity_id: UUID | None = None,
    state: str | None = Query(default=None, max_length=32),
    limit: int = Query(default=50, ge=1, le=100),
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    require_platform_operator(current_user)
    clauses = ["sc.deleted_at IS NULL"]
    values: list[object] = []

    def bind(value: object) -> str:
        values.append(value)
        return f"${len(values)}"

    if entity_id is not None:
        clauses.append(f"sc.entity_id = {bind(entity_id)}")
    if state is not None:
        clauses.append(f"sc.state = {bind(state)}::cvm_state")

    values.append(limit)
    query = f"""
        SELECT
            sc.id,
            sc.entity_id,
            e.name AS entity_name,
            sc.state::text AS state,
            sc.fqdn,
            sc.instance_type,
            sc.region,
            sc.error_reason,
            sc.policy_version,
            sc.expected_image_measurement,
            sc.image_measurement,
            sc.rtmr3_digest,
            sc.attestation_verified_at,
            sc.created_at,
            sc.updated_at
        FROM security_cvms sc
        JOIN entities e ON e.id = sc.entity_id
        WHERE {' AND '.join(clauses)}
        ORDER BY sc.updated_at DESC, sc.id DESC
        LIMIT ${len(values)}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *values)
    items = []
    for row in rows:
        payload = security_cvm_resource(row)
        payload["entity_name"] = row["entity_name"]
        items.append(payload)
    return list_page(items)


@router.get("/entities/{entity_id}/summary")
async def admin_entity_summary(
    entity_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    require_platform_operator(current_user)
    async with pool.acquire() as conn:
        entity_row = await conn.fetchrow(
            "SELECT id, name, domain, created_at FROM entities WHERE id = $1",
            entity_id,
        )
        if entity_row is None:
            raise api_error(404, "NOT_FOUND", "resource not found")
        user_count = await conn.fetchval(
            "SELECT count(*)::int FROM users WHERE entity_id = $1 AND deleted_at IS NULL",
            entity_id,
        )
        profile_count = await conn.fetchval(
            """
            SELECT count(*)::int FROM entity_profiles
            WHERE entity_id = $1 AND deleted_at IS NULL
            """,
            entity_id,
        )
        cvm_rows = await conn.fetch(
            """
            SELECT id, state::text AS state, fqdn, owner_id, updated_at
            FROM cvms
            WHERE entity_id = $1 AND deleted_at IS NULL
            ORDER BY updated_at DESC
            LIMIT 20
            """,
            entity_id,
        )
        sc_row = await conn.fetchrow(
            """
            SELECT id, state::text AS state, fqdn, updated_at
            FROM security_cvms
            WHERE entity_id = $1 AND deleted_at IS NULL
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            entity_id,
        )
        op_rows = await conn.fetch(
            """
            SELECT
                o.id,
                o.kind,
                o.status::text AS status,
                o.actor_id,
                o.actor_email,
                o.target_type,
                o.target_id,
                o.progress_step,
                o.progress_percent,
                o.error,
                o.created_at,
                o.updated_at
            FROM operations o
            LEFT JOIN users u ON u.id = o.actor_id
            LEFT JOIN cvms c ON c.id = o.target_id
            WHERE u.entity_id = $1 OR c.entity_id = $1
            ORDER BY o.updated_at DESC
            LIMIT 10
            """,
            entity_id,
        )
    return {
        "entity": entity_resource(entity_row),
        "user_count": user_count,
        "profile_count": profile_count,
        "dev_cvms": [
            {
                "id": str(row["id"]),
                "state": row["state"],
                "fqdn": row["fqdn"],
                "owner_id": str(row["owner_id"]),
                "updated_at": timestamp(row["updated_at"]),
            }
            for row in cvm_rows
        ],
        "security_cvm": (
            {
                "id": str(sc_row["id"]),
                "state": sc_row["state"],
                "fqdn": sc_row["fqdn"],
                "updated_at": timestamp(sc_row["updated_at"]),
            }
            if sc_row
            else None
        ),
        "recent_operations": [admin_operation_summary(row) for row in op_rows],
    }


@router.get("/system")
async def admin_system(
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    require_platform_operator(current_user)
    migration_head = None
    pool_size = None
    pool_idle = None
    async with pool.acquire() as conn:
        migration_head = await conn.fetchval("SELECT version_num FROM alembic_version LIMIT 1")
        pool_size = pool.get_size()
        pool_idle = pool.get_idle_size()
    return {
        "db_migration_head": migration_head,
        "db_pool": {"size": pool_size, "idle": pool_idle},
        "scheduler_last_tick_seconds_ago": scheduler_last_tick_age_seconds(),
        "metrics": parse_metrics_summary(),
    }


@router.get("/logs/stream")
async def admin_logs_stream(
    current_user: CurrentUser = Depends(require_current_user),
) -> StreamingResponse:
    require_platform_operator(current_user)
    if not acquire_log_stream_slot():
        raise api_error(429, "RATE_LIMITED", "too many log streams", {"limit": "concurrent_streams"})

    async def event_generator() -> AsyncIterator[str]:
        last_index = len(recent_log_events())
        try:
            while True:
                events = recent_log_events()
                while last_index < len(events):
                    payload = json.dumps(events[last_index], default=str)
                    last_index += 1
                    yield f"data: {payload}\n\n"
                yield ": heartbeat\n\n"
                await asyncio.sleep(1.0)
        finally:
            release_log_stream_slot()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
    )
