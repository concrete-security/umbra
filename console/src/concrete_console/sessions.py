from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

import asyncpg

from concrete_console.config import load_settings
from concrete_console.crypto import random_token_urlsafe, sha256_hex
from concrete_console.errors import api_error
from concrete_console.jwt_keys import get_jwt_manager


@dataclass(frozen=True)
class IssuedTokenPair:
    user_id: UUID
    entity_id: UUID
    actor_email: str
    access_jti: UUID
    access_expires_at: datetime
    refresh_jti: UUID
    refresh_expires_at: datetime
    response: dict[str, str | int]


def refresh_token_ttl_seconds() -> int:
    return int(load_settings().raw.get("JWT_REFRESH_TOKEN_TTL_SECONDS", "2592000"))


async def issue_token_pair(
    conn: asyncpg.Connection,
    *,
    user_id: UUID,
    family_id: UUID | None = None,
    parent_jti: UUID | None = None,
    ip_address: str | None = None,
    request_id: str | None = None,
) -> IssuedTokenPair:
    row = await conn.fetchrow(
        """
        SELECT id, email, entity_id
        FROM users
        WHERE id = $1
          AND deactivated_at IS NULL
          AND deleted_at IS NULL
        """,
        user_id,
    )
    if row is None:
        raise api_error(401, "UNAUTHORIZED", "user is not active")

    signing_result = get_jwt_manager().issue_access_token(user_id=row["id"], entity_id=row["entity_id"])
    refresh_token = random_token_urlsafe()
    refresh_jti = uuid4()
    refresh_family_id = family_id or refresh_jti
    refresh_ttl = refresh_token_ttl_seconds()
    refresh_expires_at = datetime.now(timezone.utc) + timedelta(seconds=refresh_ttl)
    await conn.execute(
        """
        INSERT INTO refresh_tokens (
            jti,
            user_id,
            token_hash,
            family_id,
            parent_jti,
            access_jti,
            access_expires_at,
            expires_at,
            ip_address,
            request_id
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        """,
        refresh_jti,
        row["id"],
        sha256_hex(refresh_token),
        refresh_family_id,
        parent_jti,
        signing_result.jti,
        signing_result.expires_at,
        refresh_expires_at,
        ip_address,
        request_id,
    )
    return IssuedTokenPair(
        user_id=row["id"],
        entity_id=row["entity_id"],
        actor_email=row["email"],
        access_jti=signing_result.jti,
        access_expires_at=signing_result.expires_at,
        refresh_jti=refresh_jti,
        refresh_expires_at=refresh_expires_at,
        response={
            "access_token": signing_result.access_token,
            "token_type": "Bearer",
            "expires_in": get_jwt_manager().settings.access_ttl_seconds,
            "refresh_token": refresh_token,
            "refresh_expires_in": refresh_ttl,
        },
    )
