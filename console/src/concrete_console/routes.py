from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
import hashlib
import json
import re
from typing import Annotated, Any
from uuid import UUID, uuid4

import asyncpg
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from concrete_console.audit import AUDIT_ACTIONS, insert_audit_event, redact_user_audit_trail
from concrete_console.auth import CurrentUser, require_current_user
from concrete_console.bootstrap import email_domain
from concrete_console.config import load_settings
from concrete_console.db import get_pool
from concrete_console.errors import api_error
from concrete_console.idempotency import (
    acquire_idempotency_lock,
    lookup_idempotency_response,
    request_body_sha256,
    store_idempotency_response,
)
from concrete_console.jwt_keys import get_jwt_manager
from concrete_console.resources import (
    audit_event_resource,
    cvm_resource,
    entity_quota_resource,
    entity_resource,
    json_payload,
    list_page,
    operation_resource,
    profile_member_resource,
    profile_resource,
    security_cvm_attestation_resource,
    security_cvm_resource,
    ssh_key_resource,
    timestamp,
    traffic_log_resource,
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
IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
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
CREATE_ENTITY_ROUTE = "POST /api/v1/entities"
CREATE_SSH_KEY_ROUTE = "POST /api/v1/me/keys"
ADMIN_SESSIONS_REVOKE_ROUTE = "POST /api/v1/admin/sessions/revoke"
ADMIN_KEYS_ROTATE_ROUTE = "POST /api/v1/admin/keys/rotate"
AUDIT_EXPORT_ROUTE = "POST /api/v1/audit/export"
OPERATION_KIND_PERMISSIONS = {
    "audit.export": "AUDIT_EXPORT",
    "cvm.launch": "CVM_LAUNCH",
    "cvm.terminate": "CVM_MANAGE",
    "security_cvm.provision": "SECURITY_CVM_CONFIGURE",
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


class AuditExportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    format: str = Field(min_length=1, max_length=16)
    actor_id: UUID | None = None
    target_type: str | None = Field(default=None, max_length=50)
    target_id: str | None = Field(default=None, max_length=255)
    action: str | None = Field(default=None, max_length=100)
    from_: datetime | None = Field(default=None, alias="from")
    to: datetime | None = None


class AdminSessionsRevoke(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: UUID | None = None
    entity_id: UUID | None = None
    issued_before: datetime | None = None


class AdminKeysRotate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    new_kid: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    retire_old_after_seconds: int = Field(default=3600, ge=0, le=86_400)


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


class CVMProfileAttach(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_id: UUID


class SSHKeyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=100)
    public_key: str = Field(min_length=1, max_length=20480)

    @field_validator("label")
    @classmethod
    def no_control_chars(cls, value: str) -> str:
        if any(char in value for char in "\r\n\t"):
            raise ValueError("label must not contain CR, LF, or TAB")
        return value.strip()

    @field_validator("public_key")
    @classmethod
    def trim_public_key(cls, value: str) -> str:
        return value.strip()


def require_idempotency_key(value: str | None) -> str:
    if not value:
        raise api_error(
            400,
            "BAD_REQUEST",
            "missing Idempotency-Key",
            {"errors": [{"type": "missing_idempotency_key"}]},
        )
    if not IDEMPOTENCY_KEY_RE.fullmatch(value):
        raise api_error(
            400,
            "BAD_REQUEST",
            "invalid Idempotency-Key",
            {"errors": [{"type": "invalid_idempotency_key"}]},
        )
    return value


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


def erased_user_email(user_id: UUID, domain: str) -> str:
    digest = hashlib.sha256(str(user_id).encode("utf-8")).hexdigest()[:12]
    return f"<erased-{digest}>@{domain}"


def cvm_etag(row: asyncpg.Record | dict) -> str:
    row = dict(row)
    updated_at = row["updated_at"]
    if updated_at.tzinfo is None:
        updated_at = updated_at.replace(tzinfo=timezone.utc)
    epoch_us = int(updated_at.timestamp() * 1_000_000)
    return f'W/"{row["id"]}:{row["policy_version"]}:{epoch_us}"'


def require_cvm_profile_mutable(row: asyncpg.Record | dict, *, action: str) -> None:
    if row["state"] == "TERMINATED":
        preposition = "to" if action == "attach" else "from"
        raise api_error(
            409,
            "CONFLICT",
            f"cannot {action} a profile {preposition} a terminated CVM",
            {"state": "cvm_terminated"},
        )


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


def ssh_key_fingerprint(public_key: str) -> str:
    if any(char in public_key for char in "\r\n\t"):
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "malformed SSH public key",
            {"errors": [{"field": "public_key", "type": "malformed_public_key"}]},
        )
    parts = public_key.split()
    if len(parts) < 2:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "malformed SSH public key",
            {"errors": [{"field": "public_key", "type": "malformed_public_key"}]},
        )
    key_material = f"{parts[0]} {parts[1]}".encode("utf-8")
    try:
        load_ssh_public_key(key_material)
        key_blob = base64.b64decode(parts[1], validate=True)
    except (ValueError, binascii.Error):
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "malformed SSH public key",
            {"errors": [{"field": "public_key", "type": "malformed_public_key"}]},
        ) from None
    digest = base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


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
    if resource == "ssh_keys":
        return await conn.fetchval(
            """
            SELECT count(*)
            FROM ssh_keys sk
            JOIN users u ON u.id = sk.user_id
            WHERE u.entity_id = $1
              AND sk.deleted_at IS NULL
              AND u.deleted_at IS NULL
            """,
            entity_id,
        )
    return 0


async def user_quota_usage(conn: asyncpg.Connection, user_id: UUID, resource: str) -> int:
    if resource == "ssh_keys":
        return await conn.fetchval(
            "SELECT count(*) FROM ssh_keys WHERE user_id = $1 AND deleted_at IS NULL",
            user_id,
        )
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


async def enforce_user_quota(conn: asyncpg.Connection, user_id: UUID, resource: str) -> None:
    limit, _, _, _ = await user_quota_limit(conn, user_id, resource)
    current_usage = await user_quota_usage(conn, user_id, resource)
    if current_usage >= limit:
        raise api_error(
            403,
            "QUOTA_EXCEEDED",
            "user quota exceeded",
            {"resource": resource, "scope": "user", "limit": limit, "current_usage": current_usage},
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
            (
                SELECT COALESCE(array_agg(up.permission::text ORDER BY up.permission::text), ARRAY[]::text[])
                FROM user_permissions up
                WHERE up.user_id = u.id
            ) AS permissions,
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


@router.get("/me/keys")
async def list_ssh_keys(
    limit: int = Query(default=100, ge=1, le=100),
    cursor: str | None = Query(default=None, max_length=80),
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    cursor_anchor = parse_ssh_key_cursor(cursor)
    values: list[object] = [current_user.id]
    clauses = ["user_id = $1", "deleted_at IS NULL"]
    if cursor_anchor is not None:
        values.extend([cursor_anchor[0], cursor_anchor[1]])
        clauses.append("(created_at, id) < ($2, $3)")
    values.append(limit + 1)
    query = f"""
        SELECT id, label, fingerprint, public_key, created_at
        FROM ssh_keys
        WHERE {' AND '.join(clauses)}
        ORDER BY created_at DESC, id DESC
        LIMIT ${len(values)}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *values)
    next_cursor = ssh_key_cursor(rows[limit]) if len(rows) > limit else None
    return list_page([ssh_key_resource(row) for row in rows[:limit]], next_cursor=next_cursor)


@router.post("/me/keys", status_code=201)
async def create_ssh_key(
    request: Request,
    body: SSHKeyCreate,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    idempotency_key_value = require_idempotency_key(idempotency_key)
    body_sha256 = request_body_sha256(await request.body())
    fingerprint = ssh_key_fingerprint(body.public_key)
    key_id = uuid4()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await acquire_idempotency_lock(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=CREATE_SSH_KEY_ROUTE,
            )
            cached = await lookup_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=CREATE_SSH_KEY_ROUTE,
                body_sha256=body_sha256,
            )
            if cached is not None:
                return JSONResponse(status_code=cached.status_code, content=cached.body, headers=cached.headers)

            await enforce_user_quota(conn, current_user.id, "ssh_keys")
            await enforce_entity_quota(conn, current_user.entity_id, "ssh_keys")
            row = await conn.fetchrow(
                """
                INSERT INTO ssh_keys (id, user_id, label, public_key, fingerprint)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING id, label, fingerprint, public_key, created_at
                """,
                key_id,
                current_user.id,
                body.label,
                body.public_key,
                fingerprint,
            )
            await insert_audit_event(
                conn,
                entity_id=current_user.entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="SSH_KEY_ADDED",
                target_type="ssh_key",
                target_id=key_id,
                after={"label": body.label, "fingerprint": fingerprint},
            )
            response_body = ssh_key_resource(row)
            await store_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=CREATE_SSH_KEY_ROUTE,
                body_sha256=body_sha256,
                status_code=201,
                response_body=response_body,
            )
            return response_body


@router.delete("/me/keys/{key_id}", status_code=204)
async def delete_ssh_key(
    key_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                UPDATE ssh_keys
                SET deleted_at = now(), deleted_by = $1
                WHERE id = $2
                  AND user_id = $1
                  AND deleted_at IS NULL
                RETURNING id, label, fingerprint
                """,
                current_user.id,
                key_id,
            )
            if row is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            await insert_audit_event(
                conn,
                entity_id=current_user.entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="SSH_KEY_REMOVED",
                target_type="ssh_key",
                target_id=key_id,
                before={"label": row["label"], "fingerprint": row["fingerprint"]},
            )
    return Response(status_code=204)


@router.post("/entities", status_code=201)
async def create_entity(
    request: Request,
    body: EntityCreate,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    idempotency_key_value = require_idempotency_key(idempotency_key)
    current_user.require_permission("PLATFORM_OPERATOR")
    body_sha256 = request_body_sha256(await request.body())
    entity_id = uuid4()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await acquire_idempotency_lock(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=CREATE_ENTITY_ROUTE,
            )
            cached = await lookup_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=CREATE_ENTITY_ROUTE,
                body_sha256=body_sha256,
            )
            if cached is not None:
                return JSONResponse(status_code=cached.status_code, content=cached.body, headers=cached.headers)

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
            response_body = entity_resource(row)
            await store_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=CREATE_ENTITY_ROUTE,
                body_sha256=body_sha256,
                status_code=201,
                response_body=response_body,
            )
    return response_body


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
    request: Request,
    body: QuotaPatch,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    validate_entity_quota_resource(resource)
    idempotency_key_value = require_idempotency_key(idempotency_key)
    current_user.require_permission("PLATFORM_OPERATOR")
    route = f"PATCH /api/v1/entities/{entity_id}/quotas/{resource}"
    body_sha256 = request_body_sha256(await request.body())
    async with pool.acquire() as conn:
        async with conn.transaction():
            await acquire_idempotency_lock(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
            )
            cached = await lookup_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
                body_sha256=body_sha256,
            )
            if cached is not None:
                return JSONResponse(status_code=cached.status_code, content=cached.body, headers=cached.headers)

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
            response_body = entity_quota_resource(after)
            await store_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
                body_sha256=body_sha256,
                status_code=200,
                response_body=response_body,
            )
    return response_body


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
        profiles = await with_profile_cvm_summaries(conn, rows)
    return list_page([profile_resource(row) for row in profiles])


@router.post("/entities/{entity_id}/profiles", status_code=201)
async def create_profile(
    entity_id: UUID,
    request: Request,
    response: Response,
    body: ProfileCreate,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    idempotency_key_value = require_idempotency_key(idempotency_key)
    current_user.require_entity(entity_id)
    current_user.require_permission("USER_MANAGE")
    route = f"POST /api/v1/entities/{entity_id}/profiles"
    body_sha256 = request_body_sha256(await request.body())
    profile_id = uuid4()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await acquire_idempotency_lock(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
            )
            cached = await lookup_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
                body_sha256=body_sha256,
            )
            if cached is not None:
                return JSONResponse(status_code=cached.status_code, content=cached.body, headers=cached.headers)

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
            etag = profile_etag(row)
            response.headers["ETag"] = etag
            response_body = profile_resource({**dict(row), "attached_cvms": [], "attached_cvm_count": 0})
            await store_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
                body_sha256=body_sha256,
                status_code=201,
                response_body=response_body,
                response_headers={"ETag": etag},
            )
    return response_body


@router.post("/entities/{entity_id}/users", status_code=201)
async def create_user(
    entity_id: UUID,
    request: Request,
    response: Response,
    body: UserCreate,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    idempotency_key_value = require_idempotency_key(idempotency_key)
    current_user.require_entity(entity_id)
    current_user.require_permission("USER_MANAGE")
    if body.permissions:
        current_user.require_permission("PERMISSION_MANAGE")
    route = f"POST /api/v1/entities/{entity_id}/users"
    body_sha256 = request_body_sha256(await request.body())

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
            await acquire_idempotency_lock(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
            )
            cached = await lookup_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
                body_sha256=body_sha256,
            )
            if cached is not None:
                return JSONResponse(status_code=cached.status_code, content=cached.body, headers=cached.headers)

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
            response_body = await fetch_user_resource(conn, user_id, response)
            await store_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
                body_sha256=body_sha256,
                status_code=201,
                response_body=response_body,
                response_headers={"ETag": response.headers["ETag"]},
            )
            return response_body


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
        row = (await with_profile_cvm_summaries(conn, [row]))[0]
    response.headers["ETag"] = profile_etag(row)
    return profile_resource(row)


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
                policy_changed = next_policy != old_policy
                if policy_changed:
                    await ensure_profile_policy_update_compatible(conn, profile_id=profile_id, next_policy=next_policy)
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
                if policy_changed:
                    await bump_attached_cvm_policy_versions(conn, profile_id)
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
        row = (await with_profile_cvm_summaries(conn, [row]))[0]
    response.headers["ETag"] = profile_etag(row)
    return profile_resource(row)


async def with_profile_cvm_summaries(conn: asyncpg.Connection, rows: list[Any]) -> list[dict[str, Any]]:
    profiles = [dict(row) for row in rows]
    if not profiles:
        return []
    profile_ids = [profile["id"] for profile in profiles]
    summary_rows = await conn.fetch(
        """
        WITH attached AS (
            SELECT
                cp.profile_id,
                c.id,
                c.fqdn,
                c.state::text AS state,
                row_number() OVER (PARTITION BY cp.profile_id ORDER BY c.created_at, c.id) AS rn,
                count(*) OVER (PARTITION BY cp.profile_id) AS attached_cvm_count
            FROM cvm_profiles cp
            JOIN cvms c ON c.id = cp.cvm_id
            WHERE cp.profile_id = ANY($1::uuid[])
              AND c.deleted_at IS NULL
        )
        SELECT
            profile_id,
            max(attached_cvm_count)::int AS attached_cvm_count,
            COALESCE(
                jsonb_agg(
                    jsonb_build_object('id', id, 'fqdn', fqdn, 'state', state)
                    ORDER BY rn
                ) FILTER (WHERE rn <= 100),
                '[]'::jsonb
            ) AS attached_cvms
        FROM attached
        GROUP BY profile_id
        """,
        profile_ids,
    )
    summaries = {
        row["profile_id"]: {
            "attached_cvms": json_payload(row["attached_cvms"]),
            "attached_cvm_count": row["attached_cvm_count"],
        }
        for row in summary_rows
    }
    return [
        {
            **profile,
            **summaries.get(profile["id"], {"attached_cvms": [], "attached_cvm_count": 0}),
        }
        for profile in profiles
    ]


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
            attached_cvm_count = await conn.fetchval(
                """
                SELECT count(*)
                FROM cvm_profiles cp
                JOIN cvms c ON c.id = cp.cvm_id
                WHERE cp.profile_id = $1
                  AND c.deleted_at IS NULL
                  AND c.state <> 'TERMINATED'
                """,
                profile_id,
            )
            if attached_cvm_count:
                raise api_error(
                    409,
                    "CONFLICT",
                    "profile is attached to live CVMs",
                    {"state": "cvms_attached", "attached_cvm_count": attached_cvm_count},
                )
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


@router.get("/profiles/{profile_id}/users")
async def list_profile_users(
    profile_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    async with pool.acquire() as conn:
        profile = await conn.fetchrow(
            """
            SELECT
                ep.id,
                ep.entity_id,
                (pu.user_id IS NOT NULL) AS assigned
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
        if profile is None:
            raise api_error(404, "NOT_FOUND", "resource not found")
        current_user.require_entity(profile["entity_id"])
        if "USER_MANAGE" not in current_user.permissions and not profile["assigned"]:
            raise api_error(404, "NOT_FOUND", "resource not found")
        rows = await conn.fetch(
            """
            SELECT
                pu.user_id,
                u.email,
                pu.added_at
            FROM profile_users pu
            JOIN users u ON u.id = pu.user_id
            WHERE pu.profile_id = $1
              AND u.deleted_at IS NULL
            ORDER BY u.email, pu.user_id
            """,
            profile_id,
        )
    return list_page([profile_member_resource(row) for row in rows])


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
    request: Request,
    body: QuotaPatch,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    validate_user_quota_resource(resource)
    idempotency_key_value = require_idempotency_key(idempotency_key)
    route = f"PATCH /api/v1/users/{user_id}/quotas/{resource}"
    body_sha256 = request_body_sha256(await request.body())
    async with pool.acquire() as conn:
        async with conn.transaction():
            target = await conn.fetchrow("SELECT id, entity_id, deleted_at FROM users WHERE id = $1", user_id)
            if target is None or target["deleted_at"] is not None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            if "PLATFORM_OPERATOR" not in current_user.permissions:
                current_user.require_entity(target["entity_id"])
                current_user.require_permission("QUOTA_MANAGE")
            await acquire_idempotency_lock(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
            )
            cached = await lookup_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
                body_sha256=body_sha256,
            )
            if cached is not None:
                return JSONResponse(status_code=cached.status_code, content=cached.body, headers=cached.headers)

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
            response_body = user_quota_resource(after)
            await store_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
                body_sha256=body_sha256,
                status_code=200,
                response_body=response_body,
            )
    return response_body


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


@router.delete("/entities/{entity_id}/users/{user_id}", status_code=204)
async def erase_user(
    entity_id: UUID,
    user_id: UUID,
    request: Request,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    idempotency_key_value = require_idempotency_key(idempotency_key)
    current_user.require_entity(entity_id)
    if current_user.id != user_id and "PLATFORM_OPERATOR" not in current_user.permissions:
        raise api_error(
            403,
            "FORBIDDEN",
            "user erasure requires self or platform operator",
            {"required": "self_or_platform_operator"},
        )
    route = f"DELETE /api/v1/entities/{entity_id}/users/{user_id}"
    body_sha256 = request_body_sha256(await request.body())

    async with pool.acquire() as conn:
        async with conn.transaction():
            await acquire_idempotency_lock(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
            )
            cached = await lookup_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
                body_sha256=body_sha256,
            )
            if cached is not None:
                return Response(status_code=cached.status_code, headers=cached.headers)

            user = await lock_user_for_lifecycle(conn, entity_id=entity_id, user_id=user_id)
            if user["deleted_at"] is not None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            if if_match is not None:
                require_matching_etag(user_etag(user), if_match)

            live_cvm_count = await conn.fetchval(
                """
                SELECT count(*)
                FROM cvms
                WHERE owner_id = $1
                  AND deleted_at IS NULL
                  AND state <> 'TERMINATED'
                """,
                user_id,
            )
            if live_cvm_count:
                rows = await conn.fetch(
                    """
                    SELECT id
                    FROM cvms
                    WHERE owner_id = $1
                      AND deleted_at IS NULL
                      AND state <> 'TERMINATED'
                    ORDER BY created_at, id
                    LIMIT 100
                    """,
                    user_id,
                )
                raise api_error(
                    409,
                    "CONFLICT",
                    "user owns live CVMs",
                    {
                        "state": "user_owns_cvms",
                        "live_cvm_count": live_cvm_count,
                        "live_cvm_ids": [str(row["id"]) for row in rows],
                    },
                )

            revoked_rows = await conn.fetch(
                """
                SELECT access_jti, access_expires_at
                FROM refresh_tokens
                WHERE user_id = $1
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

            tombstone_email = erased_user_email(user_id, user["entity_domain"])
            await insert_audit_event(
                conn,
                entity_id=entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="USER_ERASED",
                target_type="user",
                target_id=user_id,
                before={"email": user["email"], "name": user["name"]},
                after={"email": tombstone_email, "name": "<erased>", "deleted_by": str(current_user.id)},
            )
            await conn.execute(
                """
                UPDATE users
                SET email = $2,
                    name = '<erased>',
                    deleted_at = now(),
                    deleted_by = $3
                WHERE id = $1
                """,
                user_id,
                tombstone_email,
                current_user.id,
            )
            await conn.execute("DELETE FROM oauth_identities WHERE user_id = $1", user_id)
            await conn.execute("DELETE FROM ssh_keys WHERE user_id = $1", user_id)
            await conn.execute("DELETE FROM user_permissions WHERE user_id = $1", user_id)
            await conn.execute("DELETE FROM profile_users WHERE user_id = $1", user_id)
            await conn.execute("DELETE FROM refresh_tokens WHERE user_id = $1", user_id)
            await redact_user_audit_trail(conn, email=user["email"], replacement=tombstone_email)
            await store_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
                body_sha256=body_sha256,
                status_code=204,
                response_body=None,
            )
    return Response(status_code=204)


@router.post("/admin/sessions/revoke")
async def revoke_admin_sessions(
    request: Request,
    body: AdminSessionsRevoke,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    idempotency_key_value = require_idempotency_key(idempotency_key)
    current_user.require_permission("PLATFORM_OPERATOR")
    if body.user_id is None and body.entity_id is None and body.issued_before is None:
        raise api_error(400, "BAD_REQUEST", "at least one revoke filter is required")
    body_sha256 = request_body_sha256(await request.body())

    clauses = ["rt.revoked_at IS NULL"]
    values: list[object] = []

    def bind(value: object) -> str:
        values.append(value)
        return f"${len(values)}"

    if body.user_id is not None:
        clauses.append(f"rt.user_id = {bind(body.user_id)}")
    if body.entity_id is not None:
        clauses.append(f"u.entity_id = {bind(body.entity_id)}")
    if body.issued_before is not None:
        clauses.append(f"rt.issued_at < {bind(body.issued_before)}")

    query = f"""
        SELECT rt.jti, rt.access_jti, rt.access_expires_at
        FROM refresh_tokens rt
        JOIN users u ON u.id = rt.user_id
        WHERE {' AND '.join(clauses)}
        FOR UPDATE OF rt
    """
    revoked_jti_count = 0
    revoked_refresh_token_count = 0
    response_body: dict[str, int]
    async with pool.acquire() as conn:
        async with conn.transaction():
            await acquire_idempotency_lock(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=ADMIN_SESSIONS_REVOKE_ROUTE,
            )
            cached = await lookup_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=ADMIN_SESSIONS_REVOKE_ROUTE,
                body_sha256=body_sha256,
            )
            if cached is not None:
                return JSONResponse(status_code=cached.status_code, content=cached.body, headers=cached.headers)

            rows = await conn.fetch(query, *values)
            revoked_refresh_token_count = len(rows)
            for row in rows:
                inserted = await conn.fetchval(
                    """
                    INSERT INTO revoked_tokens (jti, expires_at, revoked_by)
                    VALUES ($1, $2, $3)
                    ON CONFLICT (jti) DO NOTHING
                    RETURNING 1
                    """,
                    row["access_jti"],
                    row["access_expires_at"],
                    current_user.id,
                )
                if inserted:
                    revoked_jti_count += 1
            if rows:
                await conn.execute(
                    """
                    UPDATE refresh_tokens
                    SET revoked_at = now()
                    WHERE jti = ANY($1::uuid[])
                    """,
                    [row["jti"] for row in rows],
                )
            await insert_audit_event(
                conn,
                entity_id=current_user.entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="SESSIONS_REVOKED",
                target_type="admin_sessions",
                target_id=current_user.id,
                after={
                    "user_id": str(body.user_id) if body.user_id else None,
                    "entity_id": str(body.entity_id) if body.entity_id else None,
                    "issued_before": timestamp(body.issued_before) if body.issued_before else None,
                    "revoked_jti_count": revoked_jti_count,
                    "revoked_refresh_token_count": revoked_refresh_token_count,
                },
            )
            response_body = {
                "revoked_jti_count": revoked_jti_count,
                "revoked_refresh_token_count": revoked_refresh_token_count,
            }
            await store_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=ADMIN_SESSIONS_REVOKE_ROUTE,
                body_sha256=body_sha256,
                status_code=200,
                response_body=response_body,
            )
    return response_body


@router.post("/admin/keys/rotate")
async def rotate_admin_keys(
    request: Request,
    body: AdminKeysRotate,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    idempotency_key_value = require_idempotency_key(idempotency_key)
    current_user.require_permission("PLATFORM_OPERATOR")
    body_sha256 = request_body_sha256(await request.body())

    async with pool.acquire() as conn:
        async with conn.transaction():
            await acquire_idempotency_lock(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=ADMIN_KEYS_ROTATE_ROUTE,
            )
            cached = await lookup_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=ADMIN_KEYS_ROTATE_ROUTE,
                body_sha256=body_sha256,
            )
            if cached is not None:
                return JSONResponse(status_code=cached.status_code, content=cached.body, headers=cached.headers)

            try:
                rotation = get_jwt_manager().rotate(
                    new_kid=body.new_kid,
                    retire_old_after_seconds=body.retire_old_after_seconds,
                )
            except ValueError as exc:
                raise api_error(
                    503,
                    "SERVICE_UNAVAILABLE",
                    "JWT key material is not ready for rotation",
                    {"component": "jwt_key_store"},
                ) from exc

            response_body = {
                "active_kid": rotation.active_kid,
                "retiring_kids": list(rotation.retiring_kids),
            }
            await insert_audit_event(
                conn,
                entity_id=current_user.entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="JWT_KEY_ROTATED",
                target_type="jwt_key",
                target_id=rotation.active_kid,
                before={"active_kid": rotation.old_active_kid},
                after={
                    **response_body,
                    "retire_old_after_seconds": body.retire_old_after_seconds,
                },
            )
            await store_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=ADMIN_KEYS_ROTATE_ROUTE,
                body_sha256=body_sha256,
                status_code=200,
                response_body=response_body,
            )
    return response_body


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
    clauses = ["(entity_id = $1 OR actor_id IN (SELECT id FROM users WHERE entity_id = $1))"]
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


@router.post("/audit/export", status_code=202)
async def create_audit_export(
    body: AuditExportCreate,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
) -> dict:
    require_idempotency_key(idempotency_key)
    current_user.require_permission("AUDIT_EXPORT")
    validate_audit_export_request(body)
    if not load_settings().raw.get("AUDIT_EXPORT_BUCKET", "").strip():
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "audit export bucket is not configured",
            {"component": "audit_export_bucket"},
        )
    raise api_error(
        503,
        "SERVICE_UNAVAILABLE",
        "audit export storage backend is not implemented",
        {"component": "audit_export_store"},
    )


def validate_audit_export_request(body: AuditExportCreate) -> None:
    if body.format not in {"csv", "ndjson"}:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "unsupported audit export format",
            {"errors": [{"type": "unsupported_format", "field": "format"}]},
        )
    if body.action is not None and body.action not in AUDIT_ACTIONS:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "unknown audit action",
            {"errors": [{"type": "unknown_action", "field": "action"}]},
        )


@router.get("/cvms")
async def list_cvms(
    profile_id: UUID | None = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    clauses = ["c.entity_id = $1", "c.deleted_at IS NULL"]
    values: list[object] = [current_user.entity_id]
    if "CVM_MANAGE" not in current_user.permissions:
        values.append(current_user.id)
        clauses.append(f"c.owner_id = ${len(values)}")
    if profile_id is not None:
        values.append(profile_id)
        clauses.append(
            f"""
            EXISTS (
                SELECT 1
                FROM cvm_profiles cp_filter
                JOIN entity_profiles ep_filter ON ep_filter.id = cp_filter.profile_id
                WHERE cp_filter.cvm_id = c.id
                  AND ep_filter.id = ${len(values)}
                  AND ep_filter.entity_id = c.entity_id
                  AND ep_filter.deleted_at IS NULL
            )
            """
        )
    rows = await fetch_cvm_rows(pool, where_clause=" AND ".join(clauses), values=values)
    return list_page([cvm_resource(row) for row in rows])


@router.get("/cvms/{cvm_id}")
async def get_cvm(
    cvm_id: UUID,
    response: Response,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    clauses = ["c.id = $1", "c.entity_id = $2", "c.deleted_at IS NULL"]
    values: list[object] = [cvm_id, current_user.entity_id]
    if "CVM_MANAGE" not in current_user.permissions:
        values.append(current_user.id)
        clauses.append(f"c.owner_id = ${len(values)}")
    rows = await fetch_cvm_rows(pool, where_clause=" AND ".join(clauses), values=values)
    if not rows:
        raise api_error(404, "NOT_FOUND", "resource not found")
    response.headers["ETag"] = cvm_etag(rows[0])
    return cvm_resource(rows[0])


@router.post("/cvms/{cvm_id}/profiles")
async def attach_cvm_profile(
    cvm_id: UUID,
    body: CVMProfileAttach,
    response: Response,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_permission("CVM_MANAGE")
    changed = False
    async with pool.acquire() as conn:
        async with conn.transaction():
            cvm = await lock_cvm_for_policy_mutation(conn, cvm_id=cvm_id, current_user=current_user)
            require_matching_etag(cvm_etag(cvm), if_match)
            require_cvm_profile_mutable(cvm, action="attach")
            profile = await conn.fetchrow(
                """
                SELECT id AS profile_id, entity_id, name, policy
                FROM entity_profiles
                WHERE id = $1
                  AND entity_id = $2
                  AND deleted_at IS NULL
                """,
                body.profile_id,
                current_user.entity_id,
            )
            if profile is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            membership = await conn.fetchval(
                """
                SELECT 1
                FROM profile_users
                WHERE profile_id = $1
                  AND user_id = $2
                LIMIT 1
                """,
                body.profile_id,
                current_user.id,
            )
            if membership is None:
                raise api_error(
                    403,
                    "FORBIDDEN",
                    "profile membership is required",
                    {"required": "profile_member", "profile_id": str(body.profile_id)},
                )
            existing_policies = await conn.fetch(
                """
                SELECT ep.id AS profile_id, ep.policy
                FROM cvm_profiles cp
                JOIN entity_profiles ep ON ep.id = cp.profile_id
                WHERE cp.cvm_id = $1
                  AND ep.deleted_at IS NULL
                ORDER BY cp.attached_at, cp.profile_id
                """,
                cvm_id,
            )
            ensure_no_sandbox_env_conflict([*existing_policies, profile])
            result = await conn.execute(
                """
                INSERT INTO cvm_profiles (cvm_id, profile_id, attached_by)
                VALUES ($1, $2, $3)
                ON CONFLICT DO NOTHING
                """,
                cvm_id,
                body.profile_id,
                current_user.id,
            )
            changed = result == "INSERT 0 1"
            if changed:
                await bump_cvm_policy_version(conn, cvm_id)
                await insert_audit_event(
                    conn,
                    entity_id=current_user.entity_id,
                    actor_id=current_user.id,
                    actor_email=current_user.email,
                    action="CVM_PROFILE_ATTACHED",
                    target_type="cvm",
                    target_id=cvm_id,
                    after={
                        "cvm_id": str(cvm_id),
                        "profile_id": str(profile["profile_id"]),
                        "profile_name": profile["name"],
                        "policy_version": cvm["policy_version"] + 1,
                    },
                )
    return await fetch_visible_cvm_resource(pool, cvm_id=cvm_id, current_user=current_user, response=response)


@router.delete("/cvms/{cvm_id}/profiles/{profile_id}")
async def detach_cvm_profile(
    cvm_id: UUID,
    profile_id: UUID,
    response: Response,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_permission("CVM_MANAGE")
    async with pool.acquire() as conn:
        async with conn.transaction():
            cvm = await lock_cvm_for_policy_mutation(conn, cvm_id=cvm_id, current_user=current_user)
            require_matching_etag(cvm_etag(cvm), if_match)
            require_cvm_profile_mutable(cvm, action="detach")
            attachment = await conn.fetchrow(
                """
                SELECT ep.id, ep.name
                FROM cvm_profiles cp
                JOIN entity_profiles ep ON ep.id = cp.profile_id
                WHERE cp.cvm_id = $1
                  AND ep.id = $2
                  AND ep.entity_id = $3
                  AND ep.deleted_at IS NULL
                """,
                cvm_id,
                profile_id,
                current_user.entity_id,
            )
            if attachment is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            attachment_count = await conn.fetchval("SELECT count(*) FROM cvm_profiles WHERE cvm_id = $1", cvm_id)
            if attachment_count <= 1:
                raise api_error(409, "CONFLICT", "cannot detach the last CVM profile", {"state": "last_profile"})
            await conn.execute("DELETE FROM cvm_profiles WHERE cvm_id = $1 AND profile_id = $2", cvm_id, profile_id)
            await bump_cvm_policy_version(conn, cvm_id)
            await insert_audit_event(
                conn,
                entity_id=current_user.entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="CVM_PROFILE_DETACHED",
                target_type="cvm",
                target_id=cvm_id,
                before={
                    "cvm_id": str(cvm_id),
                    "profile_id": str(attachment["id"]),
                    "profile_name": attachment["name"],
                    "policy_version_before": cvm["policy_version"],
                },
                after={"policy_version_after": cvm["policy_version"] + 1},
            )
    return await fetch_visible_cvm_resource(pool, cvm_id=cvm_id, current_user=current_user, response=response)


async def lock_cvm_for_policy_mutation(
    conn: asyncpg.Connection,
    *,
    cvm_id: UUID,
    current_user: CurrentUser,
) -> asyncpg.Record:
    row = await conn.fetchrow(
        """
        SELECT id, entity_id, state::text AS state, policy_version, updated_at
        FROM cvms
        WHERE id = $1
          AND entity_id = $2
          AND deleted_at IS NULL
        FOR UPDATE
        """,
        cvm_id,
        current_user.entity_id,
    )
    if row is None:
        raise api_error(404, "NOT_FOUND", "resource not found")
    return row


async def bump_cvm_policy_version(conn: asyncpg.Connection, cvm_id: UUID) -> None:
    await conn.execute(
        """
        UPDATE cvms
        SET policy_version = policy_version + 1,
            updated_at = now()
        WHERE id = $1
        """,
        cvm_id,
    )


async def bump_attached_cvm_policy_versions(conn: asyncpg.Connection, profile_id: UUID) -> None:
    await conn.execute(
        """
        UPDATE cvms c
        SET policy_version = policy_version + 1,
            updated_at = now()
        FROM cvm_profiles cp
        WHERE cp.cvm_id = c.id
          AND cp.profile_id = $1
          AND c.deleted_at IS NULL
          AND c.state <> 'TERMINATED'
        """,
        profile_id,
    )


async def ensure_profile_policy_update_compatible(
    conn: asyncpg.Connection,
    *,
    profile_id: UUID,
    next_policy: dict[str, Any],
) -> None:
    rows = await conn.fetch(
        """
        SELECT c.id AS cvm_id, ep.id AS profile_id, ep.policy
        FROM cvms c
        JOIN cvm_profiles target_cp
          ON target_cp.cvm_id = c.id
         AND target_cp.profile_id = $1
        JOIN cvm_profiles cp ON cp.cvm_id = c.id
        JOIN entity_profiles ep
          ON ep.id = cp.profile_id
         AND ep.entity_id = c.entity_id
         AND ep.deleted_at IS NULL
        WHERE c.deleted_at IS NULL
          AND c.state <> 'TERMINATED'
        ORDER BY c.id, cp.attached_at, cp.profile_id
        """,
        profile_id,
    )
    grouped: dict[UUID, list[dict[str, Any]]] = {}
    for row in rows:
        policy = next_policy if row["profile_id"] == profile_id else row["policy"]
        grouped.setdefault(row["cvm_id"], []).append({"profile_id": row["profile_id"], "policy": policy})
    for profile_rows in grouped.values():
        ensure_no_sandbox_env_conflict(profile_rows)


def ensure_no_sandbox_env_conflict(profile_rows: list[Any]) -> None:
    merged: dict[str, tuple[str, str]] = {}
    for row in profile_rows:
        policy = json_payload(row["policy"])
        if not isinstance(policy, dict):
            continue
        sandbox_env = policy.get("sandbox_env", {})
        if not isinstance(sandbox_env, dict):
            continue
        for name, value in sandbox_env.items():
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            existing = merged.get(name)
            if existing is not None and existing[0] != value:
                raise api_error(
                    409,
                    "CONFLICT",
                    "attached profiles contain conflicting sandbox_env values",
                    {
                        "state": "sandbox_env_conflict",
                        "name": name,
                        "profile_ids": sorted([existing[1], str(row["profile_id"])]),
                    },
                )
            merged[name] = (value, str(row["profile_id"]))


async def fetch_visible_cvm_resource(
    pool: asyncpg.Pool,
    *,
    cvm_id: UUID,
    current_user: CurrentUser,
    response: Response | None = None,
) -> dict:
    clauses = ["c.id = $1", "c.entity_id = $2", "c.deleted_at IS NULL"]
    rows = await fetch_cvm_rows(pool, where_clause=" AND ".join(clauses), values=[cvm_id, current_user.entity_id])
    if not rows:
        raise api_error(404, "NOT_FOUND", "resource not found")
    if response is not None:
        response.headers["ETag"] = cvm_etag(rows[0])
    return cvm_resource(rows[0])


async def fetch_cvm_rows(
    pool: asyncpg.Pool,
    *,
    where_clause: str,
    values: list[object],
) -> list[asyncpg.Record]:
    query = f"""
        SELECT
            c.id,
            c.owner_id,
            owner.email AS owner_email,
            c.entity_id,
            c.state::text AS state,
            c.instance_type,
            c.region,
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
        WHERE {where_clause}
        ORDER BY c.created_at DESC, c.id
    """
    async with pool.acquire() as conn:
        return await conn.fetch(query, *values)


@router.get("/entities/{entity_id}/security-cvm")
async def get_security_cvm(
    entity_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    if current_user.entity_id != entity_id:
        raise api_error(404, "NOT_FOUND", "resource not found")
    current_user.require_permission("SECURITY_CVM_CONFIGURE")
    async with pool.acquire() as conn:
        row = await fetch_security_cvm_row(conn, entity_id)
    if row is None:
        raise api_error(404, "NOT_FOUND", "resource not found")
    return security_cvm_resource(row)


@router.get("/entities/{entity_id}/security-cvm/attestation")
async def get_security_cvm_attestation(
    entity_id: UUID,
    probe: bool = False,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    if current_user.entity_id != entity_id:
        raise api_error(404, "NOT_FOUND", "resource not found")
    if "USER_MANAGE" not in current_user.permissions and "PLATFORM_OPERATOR" not in current_user.permissions:
        raise api_error(
            403,
            "FORBIDDEN",
            "missing required permission",
            {"required": "USER_MANAGE|PLATFORM_OPERATOR"},
        )
    async with pool.acquire() as conn:
        row = await fetch_security_cvm_row(conn, entity_id)
    if row is None:
        raise api_error(404, "NOT_FOUND", "resource not found")
    if probe:
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "security CVM attestation probe is not implemented",
            {"component": "security_cvm_attestation_probe"},
        )
    return security_cvm_attestation_resource(row)


async def fetch_security_cvm_row(conn: asyncpg.Connection, entity_id: UUID) -> asyncpg.Record | None:
    return await conn.fetchrow(
        """
        SELECT
            id,
            entity_id,
            state::text AS state,
            fqdn,
            instance_type,
            region,
            error_reason,
            policy_version,
            expected_image_measurement,
            image_measurement,
            rtmr3_digest,
            attestation_verified_at,
            created_at,
            updated_at
        FROM security_cvms
        WHERE entity_id = $1
          AND deleted_at IS NULL
        ORDER BY created_at DESC
        LIMIT 1
        """,
        entity_id,
    )


@router.get("/traffic-logs")
async def list_traffic_logs(
    cvm_id: UUID | None = None,
    security_cvm_id: UUID | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    cursor: str | None = Query(default=None, max_length=128),
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_permission("TRAFFIC_LOGS_VIEW")
    cursor_value = parse_traffic_log_cursor(cursor)
    clauses = ["sc.entity_id = $1"]
    values: list[object] = [current_user.entity_id]

    def bind(value: object) -> str:
        values.append(value)
        return f"${len(values)}"

    if cvm_id is not None:
        clauses.append(f"tl.cvm_id = {bind(cvm_id)}")
    if security_cvm_id is not None:
        clauses.append(f"tl.security_cvm_id = {bind(security_cvm_id)}")
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
    next_cursor = traffic_log_cursor(rows[limit]) if len(rows) > limit else None
    return list_page([traffic_log_resource(row) for row in rows[:limit]], next_cursor=next_cursor)


@router.get("/operations/{operation_id}")
async def get_operation(
    operation_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
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
                o.result,
                o.error,
                o.created_at,
                o.updated_at,
                o.expires_at,
                u.entity_id AS actor_entity_id
            FROM operations o
            LEFT JOIN users u ON u.id = o.actor_id
            WHERE o.id = $1
              AND (o.expires_at IS NULL OR o.expires_at > now())
            """,
            operation_id,
        )
    if row is None:
        raise api_error(404, "NOT_FOUND", "resource not found")
    if row["actor_id"] != current_user.id:
        if "PLATFORM_OPERATOR" not in current_user.permissions and row["actor_entity_id"] != current_user.entity_id:
            raise api_error(404, "NOT_FOUND", "resource not found")
        required_permission = OPERATION_KIND_PERMISSIONS.get(row["kind"])
        if required_permission is None:
            raise api_error(404, "NOT_FOUND", "resource not found")
        current_user.require_permission(required_permission)
    return operation_resource(row)


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


def traffic_log_cursor(row: asyncpg.Record) -> str:
    return f"{timestamp(row['timestamp'])}|{row['id']}"


def parse_traffic_log_cursor(cursor: str | None) -> tuple[datetime, UUID] | None:
    if cursor is None:
        return None
    try:
        timestamp_text, id_text = cursor.split("|", 1)
        timestamp_value = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
        id_value = UUID(id_text)
    except (ValueError, AttributeError):
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "invalid cursor",
            {"errors": [{"type": "invalid_cursor", "field": "cursor"}]},
        ) from None
    if timestamp_value.tzinfo is None:
        timestamp_value = timestamp_value.replace(tzinfo=timezone.utc)
    return timestamp_value, id_value


def ssh_key_cursor(row: asyncpg.Record) -> str:
    return f"{timestamp(row['created_at'])}|{row['id']}"


def parse_ssh_key_cursor(cursor: str | None) -> tuple[datetime, UUID] | None:
    if cursor is None:
        return None
    try:
        created_at_raw, key_id_raw = cursor.split("|", 1)
        created_at = datetime.fromisoformat(created_at_raw.replace("Z", "+00:00"))
        key_id = UUID(key_id_raw)
    except (ValueError, TypeError):
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "invalid cursor",
            {"errors": [{"type": "invalid_cursor", "field": "cursor"}]},
        ) from None
    return created_at, key_id


async def lock_user_for_lifecycle(conn: asyncpg.Connection, *, entity_id: UUID, user_id: UUID) -> asyncpg.Record:
    row = await conn.fetchrow(
        """
        SELECT
            u.id,
            u.entity_id,
            u.email,
            u.name,
            e.name AS entity_name,
            e.domain AS entity_domain,
            (
                SELECT COALESCE(array_agg(up.permission::text ORDER BY up.permission::text), ARRAY[]::text[])
                FROM user_permissions up
                WHERE up.user_id = u.id
            ) AS permissions,
            u.created_at,
            u.deactivated_at,
            u.deactivated_by,
            u.deleted_at
        FROM users u
        JOIN entities e ON e.id = u.entity_id
        WHERE u.id = $1
          AND u.entity_id = $2
        FOR UPDATE OF u
        """,
        user_id,
        entity_id,
    )
    if row is None:
        raise api_error(404, "NOT_FOUND", "resource not found")
    return row
