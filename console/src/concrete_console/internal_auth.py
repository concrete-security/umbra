from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

import asyncpg
from fastapi import Depends, Header

from concrete_console.crypto import sha256_hex
from concrete_console.db import get_pool
from concrete_console.errors import api_error
from concrete_console.log_config import bind_actor


@dataclass(frozen=True)
class CurrentServicePrincipal:
    principal_type: str
    principal_id: UUID
    purpose: str
    entity_id: UUID

    @property
    def actor_email(self) -> str:
        return f"{self.principal_type}:{self.principal_id}:{self.purpose}"


def parse_service_bearer_authorization(authorization: str | None) -> str:
    if authorization is None:
        raise api_error(401, "UNAUTHORIZED", "missing bearer token")
    try:
        scheme, token = authorization.split(" ", 1)
    except ValueError:
        raise api_error(401, "UNAUTHORIZED", "missing bearer token") from None
    if scheme != "Bearer" or not token or token.strip() != token or " " in token:
        raise api_error(401, "UNAUTHORIZED", "missing bearer token")
    if token.count(".") >= 2:
        raise api_error(401, "UNAUTHORIZED", "invalid bearer token")
    return token


async def require_security_cvm_ingest_principal(
    authorization: Annotated[str | None, Header()] = None,
    pool: asyncpg.Pool = Depends(get_pool),
) -> CurrentServicePrincipal:
    token = parse_service_bearer_authorization(authorization)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                spt.principal_type::text AS principal_type,
                spt.principal_id,
                spt.purpose::text AS purpose,
                sc.entity_id
            FROM service_principal_tokens spt
            JOIN security_cvms sc
              ON spt.principal_type = 'security_cvm'
             AND sc.id = spt.principal_id
            WHERE spt.token_hash = $1
              AND spt.deleted_at IS NULL
              AND (spt.expires_at IS NULL OR spt.expires_at > now())
              AND sc.deleted_at IS NULL
            """,
            sha256_hex(token),
        )
    if row is None or row["principal_type"] != "security_cvm" or row["purpose"] != "INGEST":
        raise api_error(401, "UNAUTHORIZED", "invalid bearer token")
    principal = CurrentServicePrincipal(
        principal_type=row["principal_type"],
        principal_id=row["principal_id"],
        purpose=row["purpose"],
        entity_id=row["entity_id"],
    )
    bind_actor(principal.actor_email)
    return principal
