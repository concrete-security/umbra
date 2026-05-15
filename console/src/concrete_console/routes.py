from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID, uuid4

import asyncpg
from fastapi import APIRouter, Depends, Header, Query
from pydantic import BaseModel, ConfigDict, Field, field_validator

from concrete_console.audit import AUDIT_ACTIONS, insert_audit_event
from concrete_console.auth import CurrentUser, require_current_user
from concrete_console.bootstrap import email_domain
from concrete_console.db import get_pool
from concrete_console.errors import api_error
from concrete_console.resources import audit_event_resource, entity_resource, list_page, user_resource

PERMISSIONS = {
    "CVM_LAUNCH",
    "CVM_MANAGE",
    "SECURITY_CVM_CONFIGURE",
    "TRAFFIC_LOGS_VIEW",
    "AUDIT_VIEW",
    "AUDIT_EXPORT",
    "USER_MANAGE",
    "PERMISSION_MANAGE",
    "QUOTA_MANAGE",
    "PLATFORM_OPERATOR",
}

router = APIRouter(prefix="/api/v1")


class EntityCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=200)
    domain: str = Field(min_length=1, max_length=255)

    @field_validator("domain")
    @classmethod
    def lower_domain(cls, value: str) -> str:
        return value.strip().lower()


class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=3, max_length=254)
    name: str = Field(default="", max_length=100)
    permissions: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("email")
    @classmethod
    def lower_email(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("name")
    @classmethod
    def no_control_chars(cls, value: str) -> str:
        if any(char in value for char in "\r\n\t"):
            raise ValueError("name must not contain CR, LF, or TAB")
        return value.strip()

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - PERMISSIONS)
        if unknown:
            raise ValueError(f"unknown permissions: {', '.join(unknown)}")
        if "PLATFORM_OPERATOR" in value:
            raise ValueError("PLATFORM_OPERATOR cannot be granted through user creation")
        return sorted(set(value))


def require_idempotency_key(value: str | None) -> None:
    if not value:
        raise api_error(
            400,
            "BAD_REQUEST",
            "missing Idempotency-Key",
            {"errors": [{"type": "missing_idempotency_key"}]},
        )


async def fetch_user_resource(conn: asyncpg.Connection, user_id: UUID) -> dict:
    row = await conn.fetchrow(
        """
        SELECT
            u.id,
            u.email,
            u.name,
            u.entity_id,
            e.name AS entity_name,
            COALESCE(array_agg(up.permission::text ORDER BY up.permission::text)
                FILTER (WHERE up.permission IS NOT NULL), ARRAY[]::text[]) AS permissions,
            u.created_at,
            u.deactivated_at,
            u.deleted_at
        FROM users u
        JOIN entities e ON e.id = u.entity_id
        LEFT JOIN user_permissions up ON up.user_id = u.id
        WHERE u.id = $1
        GROUP BY u.id, e.name
        """,
        user_id,
    )
    if row is None:
        raise api_error(404, "NOT_FOUND", "resource not found")
    return user_resource({**dict(row), "profiles": []})


@router.get("/me")
async def get_me(
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    async with pool.acquire() as conn:
        return await fetch_user_resource(conn, current_user.id)


@router.post("/entities", status_code=201)
async def create_entity(
    body: EntityCreate,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    require_idempotency_key(idempotency_key)
    current_user.require_permission("PLATFORM_OPERATOR")
    entity_id = uuid4()
    async with pool.acquire() as conn:
        async with conn.transaction():
            try:
                row = await conn.fetchrow(
                    """
                    INSERT INTO entities (id, name, domain)
                    VALUES ($1, $2, $3)
                    RETURNING id, name, domain, created_at
                    """,
                    entity_id,
                    body.name.strip(),
                    body.domain,
                )
            except asyncpg.UniqueViolationError:
                raise api_error(409, "CONFLICT", "entity domain is already registered", {"state": "domain_taken"}) from None
            await insert_audit_event(
                conn,
                entity_id=entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="ENTITY_CREATED",
                target_type="entity",
                target_id=entity_id,
                after={"name": body.name.strip(), "domain": body.domain},
            )
    return entity_resource(row)


@router.get("/entities/{entity_id}")
async def get_entity(
    entity_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_entity(entity_id)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, name, domain, created_at FROM entities WHERE id = $1",
            entity_id,
        )
    if row is None:
        raise api_error(404, "NOT_FOUND", "resource not found")
    return entity_resource(row)


@router.get("/entities/{entity_id}/users")
async def list_users(
    entity_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_entity(entity_id)
    current_user.require_permission("USER_MANAGE")
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                u.id,
                u.email,
                u.name,
                u.entity_id,
                e.name AS entity_name,
                COALESCE(array_agg(up.permission::text ORDER BY up.permission::text)
                    FILTER (WHERE up.permission IS NOT NULL), ARRAY[]::text[]) AS permissions,
                u.created_at,
                u.deactivated_at,
                u.deleted_at
            FROM users u
            JOIN entities e ON e.id = u.entity_id
            LEFT JOIN user_permissions up ON up.user_id = u.id
            WHERE u.entity_id = $1
              AND u.deleted_at IS NULL
            GROUP BY u.id, e.name
            ORDER BY u.email
            """,
            entity_id,
        )
    return list_page([user_resource({**dict(row), "profiles": []}) for row in rows])


@router.post("/entities/{entity_id}/users", status_code=201)
async def create_user(
    entity_id: UUID,
    body: UserCreate,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    require_idempotency_key(idempotency_key)
    current_user.require_entity(entity_id)
    current_user.require_permission("USER_MANAGE")
    if body.permissions:
        current_user.require_permission("PERMISSION_MANAGE")

    async with pool.acquire() as conn:
        entity = await conn.fetchrow("SELECT id, name, domain FROM entities WHERE id = $1", entity_id)
        if entity is None:
            raise api_error(404, "NOT_FOUND", "resource not found")
        try:
            if email_domain(body.email) != entity["domain"]:
                raise api_error(
                    422,
                    "VALIDATION_ERROR",
                    "email domain must match entity domain",
                    {"errors": [{"type": "email_domain_mismatch", "field": "email"}]},
                )
        except ValueError:
            raise api_error(
                422,
                "VALIDATION_ERROR",
                "email must contain a valid domain",
                {"errors": [{"type": "email_domain_mismatch", "field": "email"}]},
            ) from None

        user_id = uuid4()
        async with conn.transaction():
            try:
                await conn.execute(
                    """
                    INSERT INTO users (id, email, name, entity_id)
                    VALUES ($1, $2, $3, $4)
                    """,
                    user_id,
                    body.email,
                    body.name or body.email,
                    entity_id,
                )
            except asyncpg.UniqueViolationError:
                raise api_error(409, "CONFLICT", "email is already registered", {"state": "email_taken"}) from None
            for permission in body.permissions:
                await conn.execute(
                    """
                    INSERT INTO user_permissions (user_id, permission)
                    VALUES ($1, $2)
                    """,
                    user_id,
                    permission,
                )
            await insert_audit_event(
                conn,
                entity_id=entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="USER_REGISTERED",
                target_type="user",
                target_id=user_id,
                after={"email": body.email, "name": body.name or body.email, "entity_id": str(entity_id)},
            )
            for permission in body.permissions:
                await insert_audit_event(
                    conn,
                    entity_id=entity_id,
                    actor_id=current_user.id,
                    actor_email=current_user.email,
                    action="PERMISSION_GRANTED",
                    target_type="user",
                    target_id=user_id,
                    after={"permission": permission},
                )
            return await fetch_user_resource(conn, user_id)


@router.post("/entities/{entity_id}/users/{user_id}/actions/deactivate")
async def deactivate_user(
    entity_id: UUID,
    user_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_entity(entity_id)
    current_user.require_permission("USER_MANAGE")
    async with pool.acquire() as conn:
        async with conn.transaction():
            user = await lock_user_for_lifecycle(conn, entity_id=entity_id, user_id=user_id)
            if user["deleted_at"] is not None:
                raise api_error(409, "CONFLICT", "user has been erased", {"state": "already_erased"})
            if user["deactivated_at"] is not None:
                raise api_error(409, "CONFLICT", "user is already deactivated", {"state": "already_deactivated"})
            revoked_rows = await conn.fetch(
                """
                UPDATE refresh_tokens
                SET revoked_at = COALESCE(revoked_at, now())
                WHERE user_id = $1
                  AND revoked_at IS NULL
                RETURNING access_jti, access_expires_at
                """,
                user_id,
            )
            for row in revoked_rows:
                await conn.execute(
                    """
                    INSERT INTO revoked_tokens (jti, expires_at, revoked_by)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (jti) DO NOTHING
                    """,
                    row["access_jti"],
                    row["access_expires_at"],
                    current_user.id,
                )
            updated = await conn.fetchrow(
                """
                UPDATE users
                SET deactivated_at = now(), deactivated_by = $1
                WHERE id = $2
                RETURNING deactivated_at
                """,
                current_user.id,
                user_id,
            )
            await insert_audit_event(
                conn,
                entity_id=entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="USER_DEACTIVATED",
                target_type="user",
                target_id=user_id,
                before={"deactivated_at": None},
                after={
                    "deactivated_at": updated["deactivated_at"].isoformat().replace("+00:00", "Z"),
                    "deactivated_by": str(current_user.id),
                },
            )
            return await fetch_user_resource(conn, user_id)


@router.post("/entities/{entity_id}/users/{user_id}/actions/reactivate")
async def reactivate_user(
    entity_id: UUID,
    user_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_entity(entity_id)
    current_user.require_permission("USER_MANAGE")
    async with pool.acquire() as conn:
        async with conn.transaction():
            user = await lock_user_for_lifecycle(conn, entity_id=entity_id, user_id=user_id)
            if user["deleted_at"] is not None:
                raise api_error(409, "CONFLICT", "user has been erased", {"state": "already_erased"})
            if user["deactivated_at"] is None:
                raise api_error(409, "CONFLICT", "user is not deactivated", {"state": "not_deactivated"})
            before = {
                "deactivated_at": user["deactivated_at"].isoformat().replace("+00:00", "Z"),
                "deactivated_by": str(user["deactivated_by"]) if user["deactivated_by"] else None,
            }
            await conn.execute(
                """
                UPDATE users
                SET deactivated_at = NULL, deactivated_by = NULL
                WHERE id = $1
                """,
                user_id,
            )
            await insert_audit_event(
                conn,
                entity_id=entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="USER_REACTIVATED",
                target_type="user",
                target_id=user_id,
                before=before,
                after={"deactivated_at": None},
            )
            return await fetch_user_resource(conn, user_id)


@router.get("/audit/events")
async def list_audit_events(
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
    current_user.require_permission("AUDIT_VIEW")
    if action is not None and action not in AUDIT_ACTIONS:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "unknown audit action",
            {"errors": [{"type": "unknown_action", "field": "action"}]},
        )
    after_seq = parse_audit_cursor(cursor)
    clauses = ["entity_id = $1"]
    values: list[object] = [current_user.entity_id]

    def bind(value: object) -> str:
        values.append(value)
        return f"${len(values)}"

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
        clauses.append(f"seq > {bind(after_seq)}")

    values.append(limit + 1)
    query = f"""
        SELECT
            seq, id, entity_id, actor_id, actor_email, action, target_type, target_id,
            before, after, ip_address, description, request_id, timestamp, prev_hash, row_hash
        FROM audit_events
        WHERE {' AND '.join(clauses)}
        ORDER BY seq ASC
        LIMIT ${len(values)}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *values)
    next_cursor = str(rows[limit]["seq"]) if len(rows) > limit else None
    return list_page([audit_event_resource(row) for row in rows[:limit]], next_cursor=next_cursor)


def parse_audit_cursor(cursor: str | None) -> int | None:
    if cursor is None:
        return None
    try:
        value = int(cursor)
    except ValueError:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "invalid cursor",
            {"errors": [{"type": "invalid_cursor", "field": "cursor"}]},
        ) from None
    if value < 0:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "invalid cursor",
            {"errors": [{"type": "invalid_cursor", "field": "cursor"}]},
        )
    return value


async def lock_user_for_lifecycle(conn: asyncpg.Connection, *, entity_id: UUID, user_id: UUID) -> asyncpg.Record:
    row = await conn.fetchrow(
        """
        SELECT id, entity_id, email, name, deactivated_at, deactivated_by, deleted_at
        FROM users
        WHERE id = $1
          AND entity_id = $2
        FOR UPDATE
        """,
        user_id,
        entity_id,
    )
    if row is None:
        raise api_error(404, "NOT_FOUND", "resource not found")
    return row
