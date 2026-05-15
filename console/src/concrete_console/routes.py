from __future__ import annotations

from typing import Annotated
from uuid import UUID, uuid4

import asyncpg
from fastapi import APIRouter, Depends, Header
from pydantic import BaseModel, ConfigDict, Field, field_validator

from concrete_console.audit import insert_audit_event
from concrete_console.auth import CurrentUser, require_current_user
from concrete_console.bootstrap import email_domain
from concrete_console.db import get_pool
from concrete_console.errors import api_error
from concrete_console.resources import entity_resource, list_page, user_resource

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
