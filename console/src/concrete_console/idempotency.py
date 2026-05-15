from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any

import asyncpg

from concrete_console.errors import api_error

IDEMPOTENCY_TTL_SQL = "interval '24 hours'"


@dataclass(frozen=True)
class CachedIdempotencyResponse:
    status_code: int
    body: Any
    headers: dict[str, str]


def request_body_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def advisory_lock_key(*, credential_id: str, idempotency_key: str, route: str) -> int:
    digest = hashlib.sha256(f"{credential_id}\0{idempotency_key}\0{route}".encode("utf-8")).digest()
    value = int.from_bytes(digest[:8], byteorder="big", signed=False)
    if value >= 2**63:
        value -= 2**64
    return value


async def acquire_idempotency_lock(
    conn: asyncpg.Connection,
    *,
    credential_id: str,
    idempotency_key: str,
    route: str,
) -> None:
    await conn.execute(
        "SELECT pg_advisory_xact_lock($1)",
        advisory_lock_key(credential_id=credential_id, idempotency_key=idempotency_key, route=route),
    )


async def lookup_idempotency_response(
    conn: asyncpg.Connection,
    *,
    credential_id: str,
    idempotency_key: str,
    route: str,
    body_sha256: str,
) -> CachedIdempotencyResponse | None:
    await conn.execute(
        """
        DELETE FROM idempotency_keys
        WHERE credential_id = $1
          AND idempotency_key = $2
          AND route = $3
          AND expires_at <= now()
        """,
        credential_id,
        idempotency_key,
        route,
    )
    row = await conn.fetchrow(
        """
        SELECT request_body_sha256, response_status, response_body, response_headers
        FROM idempotency_keys
        WHERE credential_id = $1
          AND idempotency_key = $2
          AND route = $3
        """,
        credential_id,
        idempotency_key,
        route,
    )
    if row is None:
        return None
    if row["request_body_sha256"] != body_sha256:
        raise api_error(
            409,
            "IDEMPOTENCY_CONFLICT",
            "Idempotency-Key was used with a different request body",
            {"idempotency_key": idempotency_key},
        )
    return CachedIdempotencyResponse(
        status_code=row["response_status"],
        body=json_payload(row["response_body"]),
        headers={str(key): str(value) for key, value in json_payload(row["response_headers"]).items()},
    )


async def store_idempotency_response(
    conn: asyncpg.Connection,
    *,
    credential_id: str,
    idempotency_key: str,
    route: str,
    body_sha256: str,
    status_code: int,
    response_body: Any,
    response_headers: dict[str, str] | None = None,
) -> None:
    await conn.execute(
        f"""
        INSERT INTO idempotency_keys (
            credential_id,
            idempotency_key,
            route,
            request_body_sha256,
            response_status,
            response_body,
            response_headers,
            expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7::jsonb, now() + {IDEMPOTENCY_TTL_SQL})
        """,
        credential_id,
        idempotency_key,
        route,
        body_sha256,
        status_code,
        json.dumps(response_body) if response_body is not None else None,
        json.dumps(response_headers or {}),
    )


def json_payload(value: Any) -> Any:
    if isinstance(value, str):
        return json.loads(value)
    return value
