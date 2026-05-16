from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from uuid import UUID, uuid4

import asyncpg

from concrete_console.audit import canonical_json
from concrete_console.config import load_settings
from concrete_console.db import get_pool
from concrete_console.log_config import logger

log = logger()
DEFAULT_POSTGRES_ANCHOR_TABLE = "concrete_audit_anchors"
POSTGRES_ANCHOR_WRITE_TIMEOUT_SECONDS = 5.0
POSTGRES_SCHEMES = {"postgres", "postgresql"}
ANCHOR_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


class AuditAnchorError(RuntimeError):
    pass


@dataclass(frozen=True)
class PostgresAnchorTarget:
    dsn: str
    table: str
    public_uri: str


@dataclass(frozen=True)
class AuditAnchorPublication:
    anchor_id: UUID
    last_seq: int
    last_row_hash: str
    external_anchor_uri: str
    external_anchor_digest: str
    anchored_at: datetime


def configured_anchor_target() -> str:
    return load_settings().raw.get("AUDIT_ANCHOR_TARGET", "").strip()


def audit_anchor_interval_seconds() -> int:
    raw = load_settings().raw.get("AUDIT_ANCHOR_INTERVAL_SECONDS", "3600").strip() or "3600"
    try:
        interval = int(raw)
    except ValueError as exc:
        raise AuditAnchorError("AUDIT_ANCHOR_INTERVAL_SECONDS must be an integer") from exc
    if interval < 60 or interval > 86400:
        raise AuditAnchorError("AUDIT_ANCHOR_INTERVAL_SECONDS must be between 60 and 86400")
    return interval


def parse_postgres_anchor_target(target: str) -> PostgresAnchorTarget:
    parsed = urlparse(target)
    if parsed.scheme not in POSTGRES_SCHEMES:
        raise AuditAnchorError("AUDIT_ANCHOR_TARGET must use postgresql:// for the v0 anchor writer")
    query_items = parse_qsl(parsed.query, keep_blank_values=True)
    table_values = [value for key, value in query_items if key == "table"]
    if len(table_values) > 1:
        raise AuditAnchorError("AUDIT_ANCHOR_TARGET must include at most one table query parameter")
    table = table_values[0] if table_values else DEFAULT_POSTGRES_ANCHOR_TABLE
    if not ANCHOR_TABLE_RE.fullmatch(table):
        raise AuditAnchorError("AUDIT_ANCHOR_TARGET table must be an unqualified SQL identifier")
    dsn_query = urlencode([(key, value) for key, value in query_items if key != "table"])
    dsn = urlunparse(parsed._replace(query=dsn_query, fragment=""))
    host = parsed.hostname or ""
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    public_query = urlencode([("table", table)])
    public_uri = urlunparse((parsed.scheme, host, parsed.path, "", public_query, ""))
    return PostgresAnchorTarget(dsn=dsn, table=table, public_uri=public_uri)


def quoted_identifier(identifier: str) -> str:
    if not ANCHOR_TABLE_RE.fullmatch(identifier):
        raise AuditAnchorError("invalid SQL identifier")
    return f'"{identifier}"'


def anchor_payload(*, last_seq: int, last_row_hash: str, anchored_at: datetime, console_kid: str) -> dict[str, Any]:
    return {
        "anchored_at": isoformat_z(anchored_at),
        "console_kid": console_kid,
        "last_row_hash": last_row_hash,
        "last_seq": last_seq,
    }


def anchor_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


async def check_audit_anchor_target() -> None:
    target = configured_anchor_target()
    if not target:
        return
    postgres_target = parse_postgres_anchor_target(target)
    conn = await asyncpg.connect(postgres_target.dsn, timeout=0.5)
    try:
        await conn.execute(f"SELECT 1 FROM {quoted_identifier(postgres_target.table)} LIMIT 0")
    finally:
        await conn.close()


async def publish_audit_anchor_if_due(conn: Any, *, now: datetime | None = None) -> AuditAnchorPublication | None:
    target = configured_anchor_target()
    if not target:
        return None
    current = now or datetime.now(timezone.utc)
    latest_event = await conn.fetchrow(
        """
        SELECT seq, row_hash
        FROM audit_events
        ORDER BY seq DESC
        LIMIT 1
        """
    )
    if latest_event is None:
        return None
    latest_anchor = await conn.fetchrow(
        """
        SELECT last_seq, anchored_at
        FROM audit_anchors
        ORDER BY anchored_at DESC, last_seq DESC
        LIMIT 1
        """
    )
    if latest_anchor is not None:
        anchored_at = as_utc(row_value(latest_anchor, "anchored_at"))
        if current - anchored_at < timedelta(seconds=audit_anchor_interval_seconds()):
            return None
    return await publish_audit_anchor(
        conn,
        last_seq=int(row_value(latest_event, "seq")),
        last_row_hash=str(row_value(latest_event, "row_hash")),
        anchored_at=current,
        target=target,
    )


async def publish_audit_anchor_now(*, now: datetime | None = None) -> AuditAnchorPublication | None:
    target = configured_anchor_target()
    if not target:
        return None
    pool = await get_pool()
    async with pool.acquire() as conn:
        latest_event = await conn.fetchrow(
            """
            SELECT seq, row_hash
            FROM audit_events
            ORDER BY seq DESC
            LIMIT 1
            """
        )
        if latest_event is None:
            return None
        return await publish_audit_anchor(
            conn,
            last_seq=int(row_value(latest_event, "seq")),
            last_row_hash=str(row_value(latest_event, "row_hash")),
            anchored_at=now or datetime.now(timezone.utc),
            target=target,
        )


async def publish_audit_anchor(
    conn: Any,
    *,
    last_seq: int,
    last_row_hash: str,
    anchored_at: datetime,
    target: str,
) -> AuditAnchorPublication:
    postgres_target = parse_postgres_anchor_target(target)
    anchor_id = uuid4()
    console_kid = load_settings().raw.get("JWT_ACTIVE_KID", "").strip()
    payload = anchor_payload(
        last_seq=last_seq,
        last_row_hash=last_row_hash,
        anchored_at=anchored_at,
        console_kid=console_kid,
    )
    digest = anchor_digest(payload)
    external_uri = f"{postgres_target.public_uri}#anchors/{anchor_id}"
    await write_postgres_anchor(postgres_target, anchor_id=anchor_id, payload=payload, payload_sha256=digest)
    await conn.execute(
        """
        INSERT INTO audit_anchors (
            id, last_seq, last_row_hash, external_anchor_uri, external_anchor_digest,
            anchored_at, anchored_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, NULL)
        """,
        anchor_id,
        last_seq,
        last_row_hash,
        external_uri,
        digest,
        anchored_at,
    )
    log.info("audit_anchor_published", last_seq=last_seq, external_anchor_uri=external_uri)
    return AuditAnchorPublication(
        anchor_id=anchor_id,
        last_seq=last_seq,
        last_row_hash=last_row_hash,
        external_anchor_uri=external_uri,
        external_anchor_digest=digest,
        anchored_at=anchored_at,
    )


async def write_postgres_anchor(
    target: PostgresAnchorTarget,
    *,
    anchor_id: UUID,
    payload: dict[str, Any],
    payload_sha256: str,
) -> None:
    conn = await asyncpg.connect(target.dsn, timeout=POSTGRES_ANCHOR_WRITE_TIMEOUT_SECONDS)
    try:
        await conn.execute(
            f"""
            INSERT INTO {quoted_identifier(target.table)} (
                id, last_seq, last_row_hash, anchored_at, console_kid, payload, payload_sha256
            )
            VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
            """,
            anchor_id,
            payload["last_seq"],
            payload["last_row_hash"],
            parse_iso_z(payload["anchored_at"]),
            payload["console_kid"],
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
            payload_sha256,
        )
    finally:
        await conn.close()


def row_value(row: Any, key: str) -> Any:
    return row[key]


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def isoformat_z(value: datetime) -> str:
    return as_utc(value).isoformat().replace("+00:00", "Z")


def parse_iso_z(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))
