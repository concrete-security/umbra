from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Annotated, Any
from uuid import UUID, uuid4

import asyncpg
from fastapi import APIRouter, Depends, Header, Query, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from concrete_console.audit import AUDIT_ACTIONS, insert_audit_event
from concrete_console.auth import CurrentUser, require_current_user
from concrete_console.bootstrap import email_domain
from concrete_console.config import load_settings
from concrete_console.db import get_pool
from concrete_console.errors import api_error
from concrete_console.resources import (
    audit_event_resource,
    entity_quota_resource,
    entity_resource,
    json_payload,
    list_page,
    profile_resource,
    user_quota_resource,
    user_resource,
)

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
SANDBOX_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
SANDBOX_ENV_RESERVED_NAMES = {"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "PATH", "HOME"}
SANDBOX_ENV_RESERVED_PREFIXES = ("CONCRETE_", "SECURITY_CVM_", "AUTHORIZED_SSH_", "SANDBOX_ENV_")
DEFAULT_SANDBOX_ENV_VALUE_DENYLIST = (
    r"^sk-ant-[A-Za-z0-9_-]+$",
    r"^sk-[A-Za-z0-9]{32,}$",
    r"^gh[pousr]_[A-Za-z0-9]{36,}$",
    r"^AKIA[0-9A-Z]{16}$",
    r"^ASIA[0-9A-Z]{16}$",
)
ENTITY_QUOTA_RESOURCES = ("dev_cvms", "ssh_keys", "users", "profiles")
USER_QUOTA_RESOURCES = ("dev_cvms", "ssh_keys")
DEFAULT_ENTITY_QUOTAS = {
    "dev_cvms": ("DEFAULT_QUOTA_DEV_CVMS_PER_ENTITY", 50),
    "ssh_keys": ("DEFAULT_QUOTA_SSH_KEYS_PER_ENTITY", 1000),
    "users": ("DEFAULT_QUOTA_USERS_PER_ENTITY", 1000),
    "profiles": ("DEFAULT_QUOTA_PROFILES_PER_ENTITY", 50),
}
DEFAULT_USER_QUOTAS = {
    "dev_cvms": ("DEFAULT_QUOTA_DEV_CVMS_PER_USER", 5),
    "ssh_keys": ("DEFAULT_QUOTA_SSH_KEYS_PER_USER", 10),
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


class PermissionGrant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    permissions: list[str] = Field(min_length=1, max_length=16)

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, value: list[str]) -> list[str]:
        unknown = sorted(set(value) - PERMISSIONS)
        if unknown:
            raise ValueError(f"unknown permissions: {', '.join(unknown)}")
        return sorted(set(value))


class QuotaPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    limit: int = Field(ge=0)


class ProfileCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=1000)

    @field_validator("name", "description")
    @classmethod
    def no_control_chars(cls, value: str) -> str:
        if any(char in value for char in "\r\n\t"):
            raise ValueError("field must not contain CR, LF, or TAB")
        return value.strip()


class ProfilePatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=1000)
    policy: dict[str, Any] | None = None

    @field_validator("name", "description")
    @classmethod
    def no_control_chars(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if any(char in value for char in "\r\n\t"):
            raise ValueError("field must not contain CR, LF, or TAB")
        return value.strip()

    @model_validator(mode="after")
    def reject_explicit_nulls(self) -> ProfilePatch:
        for field_name in ("name", "description", "policy"):
            if field_name in self.model_fields_set and getattr(self, field_name) is None:
                raise ValueError(f"{field_name} must not be null")
        return self


class ProfileUserAssign(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID


def require_idempotency_key(value: str | None) -> None:
    if not value:
        raise api_error(
            400,
            "BAD_REQUEST",
            "missing Idempotency-Key",
            {"errors": [{"type": "missing_idempotency_key"}]},
        )


def profile_etag(row: asyncpg.Record | dict) -> str:
    row = dict(row)
    updated_at = row["updated_at"]
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=timezone.utc)
    epoch_us = int(updated_at.timestamp() * 1_000_000)
    return f'W/"{row["id"]}:{epoch_us}"'


def user_etag(row: asyncpg.Record | dict) -> str:
    payload = user_resource({**dict(row), "profiles": []})
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return f'W/"{payload["id"]}:{digest}"'


def require_matching_etag(current: str, if_match: str | None) -> None:
    if not if_match:
        raise api_error(428, "PRECONDITION_REQUIRED", "missing If-Match header", {"etag": current})
    if if_match != current:
        raise api_error(412, "PRECONDITION_FAILED", "resource changed since last read", {"etag": current})


def require_if_match(row: asyncpg.Record | dict, if_match: str | None) -> None:
    require_matching_etag(profile_etag(row), if_match)


def policy_sha256(policy: dict[str, Any]) -> str:
    payload = json.dumps(policy, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sandbox_env_value_denylist() -> list[re.Pattern[str]]:
    raw = load_settings().raw.get("SANDBOX_ENV_VALUE_DENYLIST")
    patterns = raw.split(",") if raw is not None else list(DEFAULT_SANDBOX_ENV_VALUE_DENYLIST)
    return [re.compile(pattern) for pattern in patterns if pattern]


def validate_profile_policy(policy: dict[str, Any]) -> None:
    sandbox_env = policy.get("sandbox_env")
    if sandbox_env is None:
        return
    errors: list[dict[str, Any]] = []
    if not isinstance(sandbox_env, dict):
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "policy.sandbox_env must be an object",
            {"errors": [{"field": "policy.sandbox_env", "type": "object_required"}]},
        )
    if len(sandbox_env) > 64:
        errors.append({"field": "policy.sandbox_env", "type": "too_many_entries", "limit": 64})
    denylist = sandbox_env_value_denylist()
    for name, value in sandbox_env.items():
        field = f"policy.sandbox_env.{name}"
        if not isinstance(name, str) or not SANDBOX_ENV_NAME_RE.fullmatch(name):
            errors.append({"field": field, "type": "invalid_name"})
            continue
        if name in SANDBOX_ENV_RESERVED_NAMES or any(name.startswith(prefix) for prefix in SANDBOX_ENV_RESERVED_PREFIXES):
            errors.append({"field": field, "type": "reserved_name"})
        if not isinstance(value, str):
            errors.append({"field": field, "type": "string_required"})
            continue
        if len(value) > 1024:
            errors.append({"field": field, "type": "value_too_long", "limit": 1024})
        if "\x00" in value or "\n" in value or "\r" in value:
            errors.append({"field": field, "type": "invalid_value"})
        if any(pattern.search(value) for pattern in denylist):
            errors.append({"field": field, "type": "value_denied"})
    if errors:
        raise api_error(422, "VALIDATION_ERROR", "invalid profile policy", {"errors": errors})


def validate_permission_symbol(permission: str) -> None:
    if permission not in PERMISSIONS:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "unknown permission",
            {"errors": [{"field": "permission", "type": "unknown_permission"}]},
        )


def validate_entity_quota_resource(resource: str) -> None:
    if resource not in ENTITY_QUOTA_RESOURCES:
        raise api_error(
            400,
            "VALIDATION_ERROR",
            "unknown quota resource",
            {"errors": [{"field": "resource", "type": "unknown_quota_resource"}]},
        )


def validate_user_quota_resource(resource: str) -> None:
    validate_entity_quota_resource(resource)
    if resource not in USER_QUOTA_RESOURCES:
        raise api_error(
            400,
            "VALIDATION_ERROR",
            "quota resource is not user-scoped",
            {"errors": [{"field": "resource", "type": "entity_only_quota_resource"}]},
        )


def default_quota_limit(resource: str, *, scope: str) -> int:
    defaults = DEFAULT_USER_QUOTAS if scope == "user" else DEFAULT_ENTITY_QUOTAS
    env_name, fallback = defaults[resource]
    return int(load_settings().raw.get(env_name, fallback))


async def entity_quota_limit(conn: asyncpg.Connection, entity_id: UUID, resource: str) -> tuple[int, str, UUID | None, datetime | None]:
    row = await conn.fetchrow(
        """
        SELECT limit_value, set_by, set_at
        FROM entity_quotas
        WHERE entity_id = $1
          AND resource = $2
        """,
        entity_id,
        resource,
    )
    if row is None:
        return default_quota_limit(resource, scope="entity"), "default", None, None
    return row["limit_value"], "override", row["set_by"], row["set_at"]


async def user_quota_limit(conn: asyncpg.Connection, user_id: UUID, resource: str) -> tuple[int, str, UUID | None, datetime | None]:
    row = await conn.fetchrow(
        """
        SELECT uq.limit_value, uq.set_by, uq.set_at
        FROM user_quotas uq
        WHERE uq.user_id = $1
          AND uq.resource = $2
        """,
        user_id,
        resource,
    )
    if row is not None:
        return row["limit_value"], "user_override", row["set_by"], row["set_at"]
    entity_id = await conn.fetchval("SELECT entity_id FROM users WHERE id = $1", user_id)
    limit, entity_source, set_by, set_at = await entity_quota_limit(conn, entity_id, resource)
    source = "entity_override" if entity_source == "override" else "default"
    return limit, source, set_by, set_at


async def entity_quota_usage(conn: asyncpg.Connection, entity_id: UUID, resource: str) -> int:
    if resource == "users":
        return await conn.fetchval(
            "SELECT count(*) FROM users WHERE entity_id = $1 AND deleted_at IS NULL",
            entity_id,
        )
    if resource == "profiles":
        return await conn.fetchval(
            "SELECT count(*) FROM entity_profiles WHERE entity_id = $1 AND deleted_at IS NULL",
            entity_id,
        )
    return 0


async def user_quota_usage(conn: asyncpg.Connection, user_id: UUID, resource: str) -> int:
    return 0


async def entity_quota_payload(conn: asyncpg.Connection, entity_id: UUID, resource: str) -> dict[str, object]:
    limit, source, set_by, set_at = await entity_quota_limit(conn, entity_id, resource)
    return {
        "entity_id": entity_id,
        "resource": resource,
        "limit": limit,
        "source": source,
        "current_usage": await entity_quota_usage(conn, entity_id, resource),
        "set_by": set_by,
        "set_at": set_at,
    }


async def user_quota_payload(conn: asyncpg.Connection, user_id: UUID, resource: str) -> dict[str, object]:
    limit, source, set_by, set_at = await user_quota_limit(conn, user_id, resource)
    return {
        "user_id": user_id,
        "resource": resource,
        "limit": limit,
        "source": source,
        "current_usage": await user_quota_usage(conn, user_id, resource),
        "set_by": set_by,
        "set_at": set_at,
    }


async def enforce_entity_quota(conn: asyncpg.Connection, entity_id: UUID, resource: str) -> None:
    limit, _, _, _ = await entity_quota_limit(conn, entity_id, resource)
    current_usage = await entity_quota_usage(conn, entity_id, resource)
    if current_usage >= limit:
        raise api_error(
            403,
            "QUOTA_EXCEEDED",
            "entity quota exceeded",
            {"resource": resource, "scope": "entity", "limit": limit, "current_usage": current_usage},
        )


async def fetch_user_row(conn: asyncpg.Connection, user_id: UUID) -> asyncpg.Record:
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
    return row


async def fetch_user_resource(conn: asyncpg.Connection, user_id: UUID, response: Response | None = None) -> dict:
    row = await fetch_user_row(conn, user_id)
    if response is not None:
        response.headers["ETag"] = user_etag(row)
    return user_resource({**dict(row), "profiles": []})


@router.get("/me")
async def get_me(
    response: Response,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    async with pool.acquire() as conn:
        return await fetch_user_resource(conn, current_user.id, response)


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


@router.get("/entities/{entity_id}/users/{user_id}")
async def get_user(
    entity_id: UUID,
    user_id: UUID,
    response: Response,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_entity(entity_id)
    current_user.require_permission("USER_MANAGE")
    async with pool.acquire() as conn:
        row = await fetch_user_row(conn, user_id)
    if row["entity_id"] != entity_id or row["deleted_at"] is not None:
        raise api_error(404, "NOT_FOUND", "resource not found")
    response.headers["ETag"] = user_etag(row)
    return user_resource({**dict(row), "profiles": []})


@router.get("/entities/{entity_id}/quotas")
async def get_entity_quotas(
    entity_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_entity(entity_id)
    current_user.require_permission("USER_MANAGE")
    async with pool.acquire() as conn:
        if await conn.fetchval("SELECT 1 FROM entities WHERE id = $1", entity_id) is None:
            raise api_error(404, "NOT_FOUND", "resource not found")
        quotas = [entity_quota_resource(await entity_quota_payload(conn, entity_id, resource)) for resource in ENTITY_QUOTA_RESOURCES]
    return {"quotas": quotas}


@router.patch("/entities/{entity_id}/quotas/{resource}")
async def set_entity_quota(
    entity_id: UUID,
    resource: str,
    body: QuotaPatch,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    validate_entity_quota_resource(resource)
    current_user.require_permission("PLATFORM_OPERATOR")
    async with pool.acquire() as conn:
        async with conn.transaction():
            if await conn.fetchval("SELECT 1 FROM entities WHERE id = $1", entity_id) is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            if resource in USER_QUOTA_RESOURCES:
                user_quota_count = await conn.fetchval(
                    """
                    SELECT count(*)
                    FROM user_quotas uq
                    JOIN users u ON u.id = uq.user_id
                    WHERE u.entity_id = $1
                      AND uq.resource = $2
                      AND uq.limit_value > $3
                    """,
                    entity_id,
                    resource,
                    body.limit,
                )
                if user_quota_count:
                    raise api_error(
                        409,
                        "CONFLICT",
                        "user quotas exceed requested entity quota",
                        {"state": "user_quota_above_new_entity_quota", "user_quota_count": user_quota_count},
                    )
            before = await entity_quota_payload(conn, entity_id, resource)
            await conn.execute(
                """
                INSERT INTO entity_quotas (entity_id, resource, limit_value, set_by, set_at)
                VALUES ($1, $2, $3, $4, now())
                ON CONFLICT (entity_id, resource) DO UPDATE
                SET limit_value = EXCLUDED.limit_value,
                    set_by = EXCLUDED.set_by,
                    set_at = EXCLUDED.set_at
                """,
                entity_id,
                resource,
                body.limit,
                current_user.id,
            )
            after = await entity_quota_payload(conn, entity_id, resource)
            await insert_audit_event(
                conn,
                entity_id=entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="QUOTA_SET",
                target_type="entity",
                target_id=entity_id,
                before={"scope": "entity", "scope_id": str(entity_id), "resource": resource, "limit": before["limit"]},
                after={"scope": "entity", "scope_id": str(entity_id), "resource": resource, "limit": body.limit},
            )
    return entity_quota_resource(after)


@router.delete("/entities/{entity_id}/quotas/{resource}", status_code=204)
async def clear_entity_quota(
    entity_id: UUID,
    resource: str,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    validate_entity_quota_resource(resource)
    current_user.require_permission("PLATFORM_OPERATOR")
    async with pool.acquire() as conn:
        async with conn.transaction():
            if await conn.fetchval("SELECT 1 FROM entities WHERE id = $1", entity_id) is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            before = await entity_quota_payload(conn, entity_id, resource)
            result = await conn.execute(
                """
                DELETE FROM entity_quotas
                WHERE entity_id = $1
                  AND resource = $2
                """,
                entity_id,
                resource,
            )
            if result == "DELETE 1":
                await insert_audit_event(
                    conn,
                    entity_id=entity_id,
                    actor_id=current_user.id,
                    actor_email=current_user.email,
                    action="QUOTA_CLEARED",
                    target_type="entity",
                    target_id=entity_id,
                    before={"scope": "entity", "scope_id": str(entity_id), "resource": resource, "limit": before["limit"]},
                    after=None,
                )
    return Response(status_code=204)


@router.get("/entities/{entity_id}/profiles")
async def list_profiles(
    entity_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_entity(entity_id)
    can_manage = "USER_MANAGE" in current_user.permissions
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                ep.id,
                ep.entity_id,
                ep.name,
                ep.description,
                ep.policy,
                (pu.user_id IS NOT NULL) AS assigned,
                ep.created_at,
                ep.updated_at
            FROM entity_profiles ep
            LEFT JOIN profile_users pu
              ON pu.profile_id = ep.id
             AND pu.user_id = $2
            WHERE ep.entity_id = $1
              AND ep.deleted_at IS NULL
              AND ($3 OR pu.user_id IS NOT NULL)
            ORDER BY ep.name
            """,
            entity_id,
            current_user.id,
            can_manage,
        )
    return list_page([profile_resource({**dict(row), "attached_cvms": [], "attached_cvm_count": 0}) for row in rows])


@router.post("/entities/{entity_id}/profiles", status_code=201)
async def create_profile(
    entity_id: UUID,
    response: Response,
    body: ProfileCreate,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    require_idempotency_key(idempotency_key)
    current_user.require_entity(entity_id)
    current_user.require_permission("USER_MANAGE")
    profile_id = uuid4()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await enforce_entity_quota(conn, entity_id, "profiles")
            try:
                row = await conn.fetchrow(
                    """
                    INSERT INTO entity_profiles (id, entity_id, name, description, policy)
                    VALUES ($1, $2, $3, $4, '{}'::jsonb)
                    RETURNING id, entity_id, name, description, policy, false AS assigned,
                              created_at, updated_at
                    """,
                    profile_id,
                    entity_id,
                    body.name,
                    body.description,
                )
            except asyncpg.UniqueViolationError:
                raise api_error(409, "CONFLICT", "profile name is already registered", {"state": "profile_name_taken"}) from None
            await insert_audit_event(
                conn,
                entity_id=entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="PROFILE_CREATED",
                target_type="profile",
                target_id=profile_id,
                after={"name": body.name, "description": body.description},
            )
    response.headers["ETag"] = profile_etag(row)
    return profile_resource({**dict(row), "attached_cvms": [], "attached_cvm_count": 0})


@router.post("/entities/{entity_id}/users", status_code=201)
async def create_user(
    entity_id: UUID,
    response: Response,
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
            await enforce_entity_quota(conn, entity_id, "users")
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
            return await fetch_user_resource(conn, user_id, response)


@router.get("/profiles/{profile_id}")
async def get_profile(
    profile_id: UUID,
    response: Response,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                ep.id,
                ep.entity_id,
                ep.name,
                ep.description,
                ep.policy,
                (pu.user_id IS NOT NULL) AS assigned,
                ep.created_at,
                ep.updated_at
            FROM entity_profiles ep
            LEFT JOIN profile_users pu
              ON pu.profile_id = ep.id
             AND pu.user_id = $2
            WHERE ep.id = $1
              AND ep.deleted_at IS NULL
            """,
            profile_id,
            current_user.id,
        )
    if row is None:
        raise api_error(404, "NOT_FOUND", "resource not found")
    current_user.require_entity(row["entity_id"])
    if "USER_MANAGE" not in current_user.permissions and not row["assigned"]:
        raise api_error(404, "NOT_FOUND", "resource not found")
    response.headers["ETag"] = profile_etag(row)
    return profile_resource({**dict(row), "attached_cvms": [], "attached_cvm_count": 0})


@router.patch("/profiles/{profile_id}")
async def patch_profile(
    profile_id: UUID,
    response: Response,
    body: ProfilePatch,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    async with pool.acquire() as conn:
        async with conn.transaction():
            profile = await conn.fetchrow(
                """
                SELECT id, entity_id, name, description, policy, updated_at
                FROM entity_profiles
                WHERE id = $1
                  AND deleted_at IS NULL
                FOR UPDATE
                """,
                profile_id,
            )
            if profile is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            current_user.require_entity(profile["entity_id"])
            current_user.require_permission("USER_MANAGE")
            require_if_match(profile, if_match)

            old_policy = json_payload(profile["policy"])
            next_name = body.name if "name" in body.model_fields_set else profile["name"]
            next_description = body.description if "description" in body.model_fields_set else profile["description"]
            next_policy = body.policy if "policy" in body.model_fields_set else old_policy
            validate_profile_policy(next_policy)
            changed = (
                next_name != profile["name"]
                or next_description != profile["description"]
                or next_policy != old_policy
            )
            if changed:
                try:
                    row = await conn.fetchrow(
                        """
                        UPDATE entity_profiles
                        SET name = $2,
                            description = $3,
                            policy = $4::jsonb,
                            updated_at = now()
                        WHERE id = $1
                        RETURNING id, entity_id, name, description, policy, created_at, updated_at,
                                  EXISTS (
                                      SELECT 1
                                      FROM profile_users pu
                                      WHERE pu.profile_id = entity_profiles.id
                                        AND pu.user_id = $5
                                  ) AS assigned
                        """,
                        profile_id,
                        next_name,
                        next_description,
                        json.dumps(next_policy),
                        current_user.id,
                    )
                except asyncpg.UniqueViolationError:
                    raise api_error(
                        409,
                        "CONFLICT",
                        "profile name is already registered",
                        {"state": "profile_name_taken"},
                    ) from None
                if next_policy != old_policy:
                    await insert_audit_event(
                        conn,
                        entity_id=profile["entity_id"],
                        actor_id=current_user.id,
                        actor_email=current_user.email,
                        action="PROFILE_POLICY_UPDATED",
                        target_type="profile",
                        target_id=profile_id,
                        before={"policy_sha256": policy_sha256(old_policy)},
                        after={"policy_sha256": policy_sha256(next_policy)},
                    )
            else:
                row = await conn.fetchrow(
                    """
                    SELECT ep.id, ep.entity_id, ep.name, ep.description, ep.policy,
                           ep.created_at, ep.updated_at, (pu.user_id IS NOT NULL) AS assigned
                    FROM entity_profiles ep
                    LEFT JOIN profile_users pu
                      ON pu.profile_id = ep.id
                     AND pu.user_id = $2
                    WHERE ep.id = $1
                    """,
                    profile_id,
                    current_user.id,
                )
    response.headers["ETag"] = profile_etag(row)
    return profile_resource({**dict(row), "attached_cvms": [], "attached_cvm_count": 0})


@router.delete("/profiles/{profile_id}", status_code=204)
async def delete_profile(
    profile_id: UUID,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    async with pool.acquire() as conn:
        async with conn.transaction():
            profile = await conn.fetchrow(
                """
                SELECT id, entity_id, name, updated_at
                FROM entity_profiles
                WHERE id = $1
                  AND deleted_at IS NULL
                FOR UPDATE
                """,
                profile_id,
            )
            if profile is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            current_user.require_entity(profile["entity_id"])
            current_user.require_permission("USER_MANAGE")
            require_if_match(profile, if_match)
            await conn.execute(
                """
                UPDATE entity_profiles
                SET deleted_at = now(),
                    deleted_by = $2,
                    updated_at = now()
                WHERE id = $1
                """,
                profile_id,
                current_user.id,
            )
            await insert_audit_event(
                conn,
                entity_id=profile["entity_id"],
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="PROFILE_DELETED",
                target_type="profile",
                target_id=profile_id,
                before={"name": profile["name"]},
            )
    return Response(status_code=204)


@router.post("/profiles/{profile_id}/users", status_code=204)
async def assign_profile_user(
    profile_id: UUID,
    body: ProfileUserAssign,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    async with pool.acquire() as conn:
        async with conn.transaction():
            profile = await conn.fetchrow(
                """
                SELECT id, entity_id, name, updated_at
                FROM entity_profiles
                WHERE id = $1
                  AND deleted_at IS NULL
                FOR UPDATE
                """,
                profile_id,
            )
            if profile is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            current_user.require_entity(profile["entity_id"])
            current_user.require_permission("USER_MANAGE")
            require_if_match(profile, if_match)
            target_user = await conn.fetchrow(
                """
                SELECT id
                FROM users
                WHERE id = $1
                  AND entity_id = $2
                  AND deleted_at IS NULL
                """,
                body.user_id,
                profile["entity_id"],
            )
            if target_user is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            result = await conn.execute(
                """
                INSERT INTO profile_users (profile_id, user_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                """,
                profile_id,
                body.user_id,
            )
            if result == "INSERT 0 1":
                await conn.execute(
                    """
                    UPDATE entity_profiles
                    SET updated_at = now()
                    WHERE id = $1
                    """,
                    profile_id,
                )
                await insert_audit_event(
                    conn,
                    entity_id=profile["entity_id"],
                    actor_id=current_user.id,
                    actor_email=current_user.email,
                    action="PROFILE_USER_ASSIGNED",
                    target_type="profile",
                    target_id=profile_id,
                    after={"user_id": str(body.user_id)},
                )
    return Response(status_code=204)


@router.delete("/profiles/{profile_id}/users/{user_id}", status_code=204)
async def remove_profile_user(
    profile_id: UUID,
    user_id: UUID,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    async with pool.acquire() as conn:
        async with conn.transaction():
            profile = await conn.fetchrow(
                """
                SELECT id, entity_id, name, updated_at
                FROM entity_profiles
                WHERE id = $1
                  AND deleted_at IS NULL
                FOR UPDATE
                """,
                profile_id,
            )
            if profile is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            current_user.require_entity(profile["entity_id"])
            current_user.require_permission("USER_MANAGE")
            require_if_match(profile, if_match)
            target_user = await conn.fetchrow(
                """
                SELECT id
                FROM users
                WHERE id = $1
                  AND entity_id = $2
                  AND deleted_at IS NULL
                """,
                user_id,
                profile["entity_id"],
            )
            if target_user is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            result = await conn.execute(
                """
                DELETE FROM profile_users
                WHERE profile_id = $1
                  AND user_id = $2
                """,
                profile_id,
                user_id,
            )
            if result == "DELETE 1":
                await conn.execute(
                    """
                    UPDATE entity_profiles
                    SET updated_at = now()
                    WHERE id = $1
                    """,
                    profile_id,
                )
                await insert_audit_event(
                    conn,
                    entity_id=profile["entity_id"],
                    actor_id=current_user.id,
                    actor_email=current_user.email,
                    action="PROFILE_USER_REMOVED",
                    target_type="profile",
                    target_id=profile_id,
                    before={"user_id": str(user_id)},
                )
    return Response(status_code=204)


@router.post("/users/{user_id}/permissions")
async def grant_user_permissions(
    user_id: UUID,
    body: PermissionGrant,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    if "PLATFORM_OPERATOR" in body.permissions:
        raise api_error(403, "FORBIDDEN", "PLATFORM_OPERATOR cannot be granted by this route", {"required": "self_grant_forbidden"})
    async with pool.acquire() as conn:
        async with conn.transaction():
            target = await conn.fetchrow(
                """
                SELECT id, entity_id, deleted_at
                FROM users
                WHERE id = $1
                FOR UPDATE
                """,
                user_id,
            )
            if target is None or target["deleted_at"] is not None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            current_user.require_entity(target["entity_id"])
            current_user.require_permission("PERMISSION_MANAGE")
            user_row = await fetch_user_row(conn, user_id)
            require_matching_etag(user_etag(user_row), if_match)
            for permission in body.permissions:
                result = await conn.execute(
                    """
                    INSERT INTO user_permissions (user_id, permission)
                    VALUES ($1, $2)
                    ON CONFLICT DO NOTHING
                    """,
                    user_id,
                    permission,
                )
                if result == "INSERT 0 1":
                    await insert_audit_event(
                        conn,
                        entity_id=target["entity_id"],
                        actor_id=current_user.id,
                        actor_email=current_user.email,
                        action="PERMISSION_GRANTED",
                        target_type="user",
                        target_id=user_id,
                        after={"permission": permission},
                    )
            permissions = await conn.fetch(
                """
                SELECT permission::text AS permission
                FROM user_permissions
                WHERE user_id = $1
                ORDER BY permission::text
                """,
                user_id,
            )
    return {"user_id": str(user_id), "permissions": [row["permission"] for row in permissions]}


@router.delete("/users/{user_id}/permissions/{permission}", status_code=204)
async def revoke_user_permission(
    user_id: UUID,
    permission: str,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    validate_permission_symbol(permission)
    async with pool.acquire() as conn:
        async with conn.transaction():
            target = await conn.fetchrow(
                """
                SELECT id, entity_id, deleted_at
                FROM users
                WHERE id = $1
                FOR UPDATE
                """,
                user_id,
            )
            if target is None or target["deleted_at"] is not None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            current_user.require_entity(target["entity_id"])
            current_user.require_permission("PERMISSION_MANAGE")
            user_row = await fetch_user_row(conn, user_id)
            require_matching_etag(user_etag(user_row), if_match)
            result = await conn.execute(
                """
                DELETE FROM user_permissions
                WHERE user_id = $1
                  AND permission = $2
                """,
                user_id,
                permission,
            )
            if result == "DELETE 1":
                await insert_audit_event(
                    conn,
                    entity_id=target["entity_id"],
                    actor_id=current_user.id,
                    actor_email=current_user.email,
                    action="PERMISSION_REVOKED",
                    target_type="user",
                    target_id=user_id,
                    before={"permission": permission},
                )
    return Response(status_code=204)


@router.get("/users/{user_id}/quotas")
async def get_user_quotas(
    user_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    async with pool.acquire() as conn:
        target = await conn.fetchrow("SELECT id, entity_id, deleted_at FROM users WHERE id = $1", user_id)
        if target is None or target["deleted_at"] is not None:
            raise api_error(404, "NOT_FOUND", "resource not found")
        if current_user.id != user_id:
            current_user.require_entity(target["entity_id"])
            if "USER_MANAGE" not in current_user.permissions and "QUOTA_MANAGE" not in current_user.permissions:
                raise api_error(403, "FORBIDDEN", "missing required permission", {"required": "USER_MANAGE_OR_QUOTA_MANAGE"})
        quotas = [user_quota_resource(await user_quota_payload(conn, user_id, resource)) for resource in USER_QUOTA_RESOURCES]
    return {"quotas": quotas}


@router.patch("/users/{user_id}/quotas/{resource}")
async def set_user_quota(
    user_id: UUID,
    resource: str,
    body: QuotaPatch,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    validate_user_quota_resource(resource)
    async with pool.acquire() as conn:
        async with conn.transaction():
            target = await conn.fetchrow("SELECT id, entity_id, deleted_at FROM users WHERE id = $1", user_id)
            if target is None or target["deleted_at"] is not None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            if "PLATFORM_OPERATOR" not in current_user.permissions:
                current_user.require_entity(target["entity_id"])
                current_user.require_permission("QUOTA_MANAGE")
            entity_limit, _, _, _ = await entity_quota_limit(conn, target["entity_id"], resource)
            if body.limit > entity_limit:
                raise api_error(
                    409,
                    "CONFLICT",
                    "user quota exceeds effective entity quota",
                    {"state": "user_quota_above_entity_quota", "entity_quota": entity_limit},
                )
            before = await user_quota_payload(conn, user_id, resource)
            await conn.execute(
                """
                INSERT INTO user_quotas (user_id, resource, limit_value, set_by, set_at)
                VALUES ($1, $2, $3, $4, now())
                ON CONFLICT (user_id, resource) DO UPDATE
                SET limit_value = EXCLUDED.limit_value,
                    set_by = EXCLUDED.set_by,
                    set_at = EXCLUDED.set_at
                """,
                user_id,
                resource,
                body.limit,
                current_user.id,
            )
            after = await user_quota_payload(conn, user_id, resource)
            await insert_audit_event(
                conn,
                entity_id=target["entity_id"],
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="QUOTA_SET",
                target_type="user",
                target_id=user_id,
                before={"scope": "user", "scope_id": str(user_id), "resource": resource, "limit": before["limit"]},
                after={"scope": "user", "scope_id": str(user_id), "resource": resource, "limit": body.limit},
            )
    return user_quota_resource(after)


@router.delete("/users/{user_id}/quotas/{resource}", status_code=204)
async def clear_user_quota(
    user_id: UUID,
    resource: str,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    validate_user_quota_resource(resource)
    async with pool.acquire() as conn:
        async with conn.transaction():
            target = await conn.fetchrow("SELECT id, entity_id, deleted_at FROM users WHERE id = $1", user_id)
            if target is None or target["deleted_at"] is not None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            if "PLATFORM_OPERATOR" not in current_user.permissions:
                current_user.require_entity(target["entity_id"])
                current_user.require_permission("QUOTA_MANAGE")
            before = await user_quota_payload(conn, user_id, resource)
            result = await conn.execute(
                """
                DELETE FROM user_quotas
                WHERE user_id = $1
                  AND resource = $2
                """,
                user_id,
                resource,
            )
            if result == "DELETE 1":
                await insert_audit_event(
                    conn,
                    entity_id=target["entity_id"],
                    actor_id=current_user.id,
                    actor_email=current_user.email,
                    action="QUOTA_CLEARED",
                    target_type="user",
                    target_id=user_id,
                    before={"scope": "user", "scope_id": str(user_id), "resource": resource, "limit": before["limit"]},
                    after=None,
                )
    return Response(status_code=204)


@router.post("/entities/{entity_id}/users/{user_id}/actions/deactivate")
async def deactivate_user(
    entity_id: UUID,
    user_id: UUID,
    response: Response,
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
            return await fetch_user_resource(conn, user_id, response)


@router.post("/entities/{entity_id}/users/{user_id}/actions/reactivate")
async def reactivate_user(
    entity_id: UUID,
    user_id: UUID,
    response: Response,
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
            return await fetch_user_resource(conn, user_id, response)


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
