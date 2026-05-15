from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from typing import Any
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field

from concrete_console.db import get_pool
from concrete_console.errors import api_error
from concrete_console.idempotency import advisory_lock_key, request_body_sha256
from concrete_console.internal_auth import CurrentServicePrincipal, require_security_cvm_ingest_principal

router = APIRouter(prefix="/internal")

TRAFFIC_LOG_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
TRAFFIC_LOG_ROUTE = "POST /internal/traffic-logs"
TRAFFIC_LOG_MAX_BODY_BYTES = 4 * 1024 * 1024
TRAFFIC_LOG_TIMESTAMP_SKEW = timedelta(minutes=10)


class TrafficLogIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    cvm_id: UUID | None = None
    source_ip: str = Field(min_length=1, max_length=45)
    destination_ip: str = Field(min_length=1, max_length=45)
    destination_host: str | None = Field(default=None, max_length=255)
    protocol: str = Field(min_length=1, max_length=20)
    port: int = Field(ge=0, le=65535)
    method: str | None = Field(default=None, max_length=20)
    path: str | None = Field(default=None, max_length=2000)
    response_code: int | None = None
    bytes_transferred: int = Field(ge=0)


class TrafficLogBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=128)
    logs: list[TrafficLogIn] = Field(min_length=1, max_length=1000)


@router.post("/traffic-logs")
async def ingest_traffic_logs(
    body: TrafficLogBatch,
    request: Request,
    current_principal: CurrentServicePrincipal = Depends(require_security_cvm_ingest_principal),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict[str, Any]:
    raw_body = await request.body()
    if len(raw_body) > TRAFFIC_LOG_MAX_BODY_BYTES:
        raise api_error(
            413,
            "PAYLOAD_TOO_LARGE",
            "request body is too large",
            {"limit_bytes": TRAFFIC_LOG_MAX_BODY_BYTES},
        )
    validate_traffic_log_batch_shape(body)
    body_sha256 = request_body_sha256(raw_body)
    credential_id = str(current_principal.principal_id)
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute(
                "SELECT pg_advisory_xact_lock($1)",
                advisory_lock_key(
                    credential_id=credential_id,
                    idempotency_key=body.idempotency_key,
                    route=TRAFFIC_LOG_ROUTE,
                ),
            )
            cached = await conn.fetchrow(
                """
                SELECT request_body_sha256, row_count
                FROM traffic_log_batches
                WHERE security_cvm_id = $1
                  AND idempotency_key = $2
                """,
                current_principal.principal_id,
                body.idempotency_key,
            )
            if cached is not None:
                if cached["request_body_sha256"] != body_sha256:
                    raise api_error(
                        409,
                        "IDEMPOTENCY_CONFLICT",
                        "traffic log idempotency key was used with a different request body",
                        {"idempotency_key": body.idempotency_key},
                    )
                return {"accepted": cached["row_count"], "deduplicated": True}

            validate_traffic_log_timestamps(body.logs)
            await validate_traffic_log_cvms(conn, entity_id=current_principal.entity_id, logs=body.logs)
            batch_id = await conn.fetchval(
                """
                INSERT INTO traffic_log_batches (
                    security_cvm_id, idempotency_key, request_body_sha256, row_count
                )
                VALUES ($1, $2, $3, $4)
                RETURNING id
                """,
                current_principal.principal_id,
                body.idempotency_key,
                body_sha256,
                len(body.logs),
            )
            await conn.executemany(
                """
                INSERT INTO traffic_logs (
                    batch_id,
                    timestamp,
                    security_cvm_id,
                    cvm_id,
                    source_ip,
                    destination_ip,
                    destination_host,
                    protocol,
                    port,
                    method,
                    path,
                    response_code,
                    bytes_transferred
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                """,
                [
                    (
                        batch_id,
                        ensure_aware(log.timestamp),
                        current_principal.principal_id,
                        log.cvm_id,
                        log.source_ip,
                        log.destination_ip,
                        log.destination_host,
                        log.protocol,
                        log.port,
                        log.method,
                        log.path,
                        log.response_code,
                        log.bytes_transferred,
                    )
                    for log in body.logs
                ],
            )
    return {"accepted": len(body.logs), "deduplicated": False}


def validate_traffic_log_batch_shape(body: TrafficLogBatch) -> None:
    if not TRAFFIC_LOG_IDEMPOTENCY_KEY_RE.fullmatch(body.idempotency_key):
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "invalid traffic log idempotency key",
            {"errors": [{"type": "invalid_idempotency_key", "field": "idempotency_key"}]},
        )
    errors: list[dict[str, Any]] = []
    for index, log in enumerate(body.logs):
        if log.cvm_id is None:
            errors.append({"type": "missing_cvm_id", "field": f"logs.{index}.cvm_id"})
    if errors:
        raise api_error(422, "VALIDATION_ERROR", "invalid traffic log batch", {"errors": errors})


def validate_traffic_log_timestamps(logs: list[TrafficLogIn]) -> None:
    newest = max(ensure_aware(log.timestamp) for log in logs)
    now = datetime.now(timezone.utc)
    if newest < now - TRAFFIC_LOG_TIMESTAMP_SKEW or newest > now + TRAFFIC_LOG_TIMESTAMP_SKEW:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "traffic log timestamp outside accepted window",
            {"errors": [{"type": "timestamp_skew", "field": "logs.timestamp"}]},
        )


async def validate_traffic_log_cvms(
    conn: asyncpg.Connection,
    *,
    entity_id: UUID,
    logs: list[TrafficLogIn],
) -> None:
    cvm_ids = sorted({log.cvm_id for log in logs if log.cvm_id is not None}, key=str)
    rows = await conn.fetch(
        """
        SELECT id
        FROM cvms
        WHERE entity_id = $1
          AND id = ANY($2::uuid[])
        """,
        entity_id,
        cvm_ids,
    )
    found = {row["id"] for row in rows}
    missing = [cvm_id for cvm_id in cvm_ids if cvm_id not in found]
    if missing:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "traffic log batch references a CVM outside the principal entity",
            {
                "errors": [
                    {
                        "type": "cross_tenant_cvm",
                        "field": "logs.cvm_id",
                        "cvm_id": str(cvm_id),
                    }
                    for cvm_id in missing
                ]
            },
        )


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
