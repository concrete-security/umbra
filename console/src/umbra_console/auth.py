from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

import asyncpg
from fastapi import Depends, Header
import jwt

from umbra_console.db import get_pool
from umbra_console.errors import api_error
from umbra_console.jwt_keys import get_jwt_manager
from umbra_console.log_config import bind_actor


@dataclass(frozen=True)
class CurrentUser:
    id: UUID
    email: str
    name: str
    entity_id: UUID
    entity_name: str
    permissions: frozenset[str]

    def require_permission(self, permission: str) -> None:
        if permission not in self.permissions:
            raise api_error(403, "FORBIDDEN", "missing required permission", {"required": permission})

    def require_entity(self, entity_id: UUID) -> None:
        if self.entity_id != entity_id and "PLATFORM_OPERATOR" not in self.permissions:
            raise api_error(404, "NOT_FOUND", "resource not found")


def parse_uuid4_claim(value: object) -> UUID:
    parsed = UUID(str(value))
    if parsed.version != 4:
        raise ValueError("claim is not a UUIDv4")
    return parsed


async def load_current_user(pool: asyncpg.Pool, user_id: UUID, entity_id: UUID) -> CurrentUser:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                u.id,
                u.email,
                u.name,
                u.entity_id,
                e.name AS entity_name,
                COALESCE(array_agg(up.permission::text ORDER BY up.permission::text)
                    FILTER (WHERE up.permission IS NOT NULL), ARRAY[]::text[]) AS permissions
            FROM users u
            JOIN entities e ON e.id = u.entity_id
            LEFT JOIN user_permissions up ON up.user_id = u.id
            WHERE u.id = $1
              AND u.deleted_at IS NULL
              AND u.deactivated_at IS NULL
            GROUP BY u.id, e.name
            """,
            user_id,
        )
    if row is None or row["entity_id"] != entity_id:
        raise api_error(401, "UNAUTHORIZED", "user is not active")
    return CurrentUser(
        id=row["id"],
        email=row["email"],
        name=row["name"],
        entity_id=row["entity_id"],
        entity_name=row["entity_name"],
        permissions=frozenset(row["permissions"]),
    )


async def require_current_user(
    authorization: Annotated[str | None, Header()] = None,
    pool: asyncpg.Pool = Depends(get_pool),
) -> CurrentUser:
    if authorization is None:
        raise api_error(401, "UNAUTHORIZED", "missing bearer token")
    try:
        scheme, token = authorization.split(" ", 1)
    except ValueError:
        raise api_error(401, "UNAUTHORIZED", "missing bearer token") from None
    if scheme != "Bearer" or not token or token.strip() != token or " " in token:
        raise api_error(401, "UNAUTHORIZED", "missing bearer token")
    try:
        claims = get_jwt_manager().verify_access_token(token)
        user_id = parse_uuid4_claim(claims["sub"])
        entity_id = parse_uuid4_claim(claims["entity_id"])
        jti = parse_uuid4_claim(claims["jti"])
    except (KeyError, ValueError, jwt.PyJWTError):
        raise api_error(401, "UNAUTHORIZED", "invalid bearer token") from None

    async with pool.acquire() as conn:
        revoked = await conn.fetchval("SELECT 1 FROM revoked_tokens WHERE jti = $1 LIMIT 1", jti)
    if revoked:
        raise api_error(401, "UNAUTHORIZED", "token has been revoked")

    current_user = await load_current_user(pool, user_id, entity_id)
    bind_actor(str(current_user.id))
    return current_user
