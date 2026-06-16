from __future__ import annotations

import base64
import binascii
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
import re
import secrets
from typing import Annotated, Any
from urllib.parse import unquote
from uuid import UUID, uuid4

import asyncpg
import re2
from cryptography.hazmat.primitives.serialization import load_ssh_public_key
from fastapi import APIRouter, Depends, Header, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from concrete_console.audit import AUDIT_ACTIONS, insert_audit_event, redact_user_audit_trail
from concrete_console.audit_export import (
    AuditExportStorageError,
    read_audit_export_artifact,
)
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
from concrete_console.log_config import logger
from concrete_console.profile_secrets import encrypt_profile_secret_value, split_profile_policy_secret_values
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
    TRAFFIC_BLOCK_CODE,
    TRAFFIC_TIMESERIES_DEFAULT_BUCKETS,
    TRAFFIC_TIMESERIES_MAX_BUCKETS,
    resolve_traffic_timeseries,
    traffic_timeseries_payload,
    user_quota_resource,
    user_resource,
)
from concrete_console.scheduler import run_reconciliation_pass

log = logger()
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
POLICY_TOP_LEVEL_FIELDS = {
    "egress_boundary",
    "allowed_destinations",
    "blocked_destinations",
    "secret_patterns",
    "secret_injections",
    "sandbox_env",
}
POLICY_DESTINATION_FIELDS = {
    "id",
    "scheme",
    "host",
    "ports",
    "methods",
    "path_prefixes",
    "body_assertions",
    "websocket_assertions",
    "traffic_log_attributes",
}
POLICY_DESTINATION_EXTENSION_FIELDS = {"body_assertions", "websocket_assertions", "traffic_log_attributes"}
POLICY_DESTINATION_MATCH_FIELDS = {"scheme", "host", "ports", "methods", "path_prefixes"}
POLICY_SECRET_PATTERN_FIELDS = {"id", "name", "pattern", "scan_headers", "scan_body"}
POLICY_SECRET_INJECTION_FIELDS = {"id", "match", "type", "header", "value", "value_template"}
POLICY_BODY_ASSERTION_KINDS = {"form", "json"}
POLICY_BODY_ASSERTION_FIELDS = {"kind", "field", "allow_values"}
POLICY_WEBSOCKET_ASSERTION_FIELDS = {"direction", "when", "require", "on_violation", "on_drop_emit"}
POLICY_WEBSOCKET_DIRECTIONS = {"inbound"}
POLICY_WEBSOCKET_ON_VIOLATIONS = {"drop"}
POLICY_EMIT_TEMPLATE_RE = re.compile(r"^\{(/[^{}]*)\}$")
POLICY_TRAFFIC_LOG_ATTR_FIELDS = {"name", "kind", "field"}
POLICY_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,100}$")
POLICY_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
POLICY_HEADER_RE = re.compile(r"^[a-z][a-z0-9-]{0,126}$")
POLICY_POINTER_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
POLICY_TRAFFIC_LOG_ATTR_NAME_RE = re.compile(r"^[a-z_]{1,32}$")
POLICY_PATH_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
POLICY_PATH_BAD_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
POLICY_PATH_AMBIGUOUS_ESCAPE_RE = re.compile(r"%(?:2[eE]|5[cC])")
POLICY_HOP_BY_HOP_HEADERS = {
    "connection",
    "content-length",
    "host",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}
POLICY_MAX_BODY_ASSERTIONS_PER_RULE = 16
POLICY_MAX_WEBSOCKET_ASSERTIONS_PER_RULE = 16
POLICY_MAX_WEBSOCKET_WHEN_PREDICATES = 8
POLICY_MAX_WEBSOCKET_REQUIRE_PREDICATES = 8
POLICY_MAX_WEBSOCKET_EMIT_FIELDS = 8
POLICY_MAX_TRAFFIC_LOG_ATTRIBUTES_PER_RULE = 4
POLICY_MAX_POINTER_SEGMENTS_JSON = 4
POLICY_MAX_ALLOW_VALUES = 256
POLICY_MAX_ALLOW_VALUE_LEN = 256
POLICY_MAX_SECRET_PATTERN_LEN = 4096
IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
CVM_CONFIG_VALUE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SECURITY_CVM_INSTANCE_TYPE_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
HEX64_RE = re.compile(r"^[0-9a-fA-F]{64}$")
IMAGE_MEASUREMENT_RE = re.compile(r"^[0-9a-fA-F]{96}$")
DNS_RANDOM_TOKEN_BYTES = 16
DNS_RANDOM_TOKEN_CHARS = 26
DNS_FQDN_MAX_LENGTH = 253
DNS_CERT_COMMON_NAME_MAX_LENGTH = 64
DEV_CVM_FQDN_PREFIX = "cvm"
SECURITY_CVM_FQDN_PREFIX = "sc"
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
CREATE_CVM_ROUTE = "POST /api/v1/cvms"
ADMIN_SESSIONS_REVOKE_ROUTE = "POST /api/v1/admin/sessions/revoke"
ADMIN_KEYS_ROTATE_ROUTE = "POST /api/v1/admin/keys/rotate"
AUDIT_EXPORT_ROUTE = "POST /api/v1/audit/export"
AUDIT_EXPORT_DOWNLOAD_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,256}$")
PROVIDER_CVM_SYNC_ACTION_TIMEOUT_SECONDS = 30.0
OPERATION_KIND_PERMISSIONS = {
    "audit.export": "AUDIT_EXPORT",
    "cvm.launch": "CVM_LAUNCH",
    "cvm.update": "CVM_MANAGE",
    "cvm.terminate": "CVM_MANAGE",
    "security_cvm.provision": "SECURITY_CVM_CONFIGURE",
    "security_cvm.update": "SECURITY_CVM_CONFIGURE",
}
SECURITY_CVM_PROVISION_KIND = "security_cvm.provision"
SECURITY_CVM_PROVISION_REDACTION = "<redacted-after-first-read>"
SECURITY_CVM_PROVISION_SECRET_FIELDS = ("ca_export_token",)
OPERATION_READ_SELECT = """
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
        o.result_disclosed_at,
        o.created_at,
        o.updated_at,
        o.expires_at,
        u.entity_id AS actor_entity_id
    FROM operations o
    LEFT JOIN users u ON u.id = o.actor_id
    WHERE o.id = $1
      AND (o.expires_at IS NULL OR o.expires_at > now())
"""

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


class AdminReconcile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    include_orphans: bool = True


class SecurityCVMCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instance_type: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    region: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    image_ref: str | None = Field(default=None, min_length=1, max_length=512)
    image_measurement: str | None = Field(
        default=None,
        min_length=96,
        max_length=96,
        pattern=r"^[0-9a-fA-F]{96}$",
    )


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


class CVMCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    profile_ids: list[UUID] = Field(min_length=1, max_length=16)
    instance_type: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9._-]+$",
    )
    ssh_key_ids: list[UUID] = Field(min_length=1, max_length=16)
    region: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        pattern=r"^[A-Za-z0-9._-]+$",
    )

    @field_validator("profile_ids", "ssh_key_ids")
    @classmethod
    def reject_duplicate_ids(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("ids must be unique")
        return value


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


def optional_idempotency_key(value: str | None) -> str | None:
    if value is None:
        return None
    return require_idempotency_key(value)


def random_dns_token() -> str:
    return base64.b32encode(secrets.token_bytes(DNS_RANDOM_TOKEN_BYTES)).decode("ascii").rstrip("=").lower()


def generated_cvm_fqdn(prefix: str, base_domain: str) -> str:
    return f"{prefix}-{random_dns_token()}.{base_domain}"


def validate_generated_fqdn_base_domain(*, base_domain: str, prefix: str, component: str, message: str) -> None:
    expected_fqdn = f"{prefix}-{'a' * DNS_RANDOM_TOKEN_CHARS}.{base_domain}"
    if (
        len(expected_fqdn) > DNS_FQDN_MAX_LENGTH
        or len(expected_fqdn) > DNS_CERT_COMMON_NAME_MAX_LENGTH
        or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*[a-z0-9]", base_domain)
    ):
        raise api_error(503, "SERVICE_UNAVAILABLE", message, {"component": component})


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


def require_cvm_owner_or_manager(row: asyncpg.Record | dict, current_user: CurrentUser) -> None:
    if row["owner_id"] != current_user.id and "CVM_MANAGE" not in current_user.permissions:
        raise api_error(404, "NOT_FOUND", "resource not found")


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
    errors: list[dict[str, Any]] = []
    for key in sorted(set(policy) - POLICY_TOP_LEVEL_FIELDS):
        errors.append({"field": f"policy.{key}", "type": "unknown_field"})
    egress_boundary = policy.get("egress_boundary")
    if egress_boundary is not None and not isinstance(egress_boundary, bool):
        errors.append({"field": "policy.egress_boundary", "type": "boolean_required"})
    sandbox_env = policy.get("sandbox_env")
    if sandbox_env is not None:
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
            if name in SANDBOX_ENV_RESERVED_NAMES or any(
                name.startswith(prefix) for prefix in SANDBOX_ENV_RESERVED_PREFIXES
            ):
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
    _validate_destination_rules(
        policy.get("allowed_destinations"),
        "allowed_destinations",
        errors,
        allow_extensions=True,
    )
    _validate_destination_rules(
        policy.get("blocked_destinations"),
        "blocked_destinations",
        errors,
        allow_extensions=False,
    )
    _validate_secret_patterns(policy.get("secret_patterns"), errors)
    _validate_secret_injections(policy.get("secret_injections"), errors)
    if errors:
        raise api_error(422, "VALIDATION_ERROR", "invalid profile policy", {"errors": errors})


def _validate_destination_rules(
    rules: Any,
    list_field: str,
    errors: list[dict[str, Any]],
    *,
    allow_extensions: bool,
) -> None:
    if rules is None:
        return
    if not isinstance(rules, list):
        errors.append({"field": f"policy.{list_field}", "type": "array_required"})
        return
    for index, rule in enumerate(rules):
        _validate_destination_rule(
            rule,
            f"policy.{list_field}.{index}",
            errors,
            require_id=True,
            allow_extensions=allow_extensions,
        )


def _validate_destination_rule(
    rule: Any,
    field: str,
    errors: list[dict[str, Any]],
    *,
    require_id: bool,
    allow_extensions: bool,
) -> None:
    if not isinstance(rule, dict):
        errors.append({"field": field, "type": "object_required"})
        return
    base_fields = POLICY_DESTINATION_FIELDS if require_id else POLICY_DESTINATION_MATCH_FIELDS
    allowed_fields = base_fields if allow_extensions else (base_fields - POLICY_DESTINATION_EXTENSION_FIELDS)
    for key in sorted(set(rule) - allowed_fields):
        errors.append({"field": f"{field}.{key}", "type": "unknown_field"})
    if require_id:
        rule_id = rule.get("id")
        if not isinstance(rule_id, str) or not POLICY_ID_RE.fullmatch(rule_id):
            errors.append({"field": f"{field}.id", "type": "invalid_id"})
    elif "id" in rule:
        errors.append({"field": f"{field}.id", "type": "forbidden_field"})
    scheme = rule.get("scheme")
    if scheme not in {"http", "https"}:
        errors.append({"field": f"{field}.scheme", "type": "invalid_scheme"})
    host = rule.get("host")
    if not isinstance(host, str) or not _valid_policy_host(host):
        errors.append({"field": f"{field}.host", "type": "invalid_host"})
    _validate_ports(rule.get("ports"), scheme if isinstance(scheme, str) else None, f"{field}.ports", errors)
    _validate_methods(rule.get("methods"), f"{field}.methods", errors)
    _validate_path_prefixes(rule.get("path_prefixes"), f"{field}.path_prefixes", errors)
    if not allow_extensions:
        for forbidden in ("body_assertions", "websocket_assertions", "traffic_log_attributes"):
            if forbidden in rule:
                errors.append({"field": f"{field}.{forbidden}", "type": "forbidden_field"})
        return
    _validate_body_assertions(
        rule.get("body_assertions"),
        f"{field}.body_assertions",
        errors,
    )
    _validate_websocket_assertions(
        rule.get("websocket_assertions"),
        f"{field}.websocket_assertions",
        errors,
    )
    _validate_traffic_log_attributes(
        rule.get("traffic_log_attributes"),
        f"{field}.traffic_log_attributes",
        errors,
    )


def _validate_ports(raw: Any, scheme: str | None, field: str, errors: list[dict[str, Any]]) -> None:
    if raw is None:
        if scheme in {"http", "https"}:
            return
        errors.append({"field": field, "type": "invalid_ports"})
        return
    if not isinstance(raw, list) or not 1 <= len(raw) <= 16:
        errors.append({"field": field, "type": "invalid_ports"})
        return
    for index, port in enumerate(raw):
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            errors.append({"field": f"{field}.{index}", "type": "invalid_port"})


def _validate_methods(raw: Any, field: str, errors: list[dict[str, Any]]) -> None:
    if not isinstance(raw, list) or not 1 <= len(raw) <= 16:
        errors.append({"field": field, "type": "invalid_methods"})
        return
    for index, method in enumerate(raw):
        if not isinstance(method, str) or not method or method != method.upper() or len(method) > 20:
            errors.append({"field": f"{field}.{index}", "type": "invalid_method"})


def _validate_path_prefixes(raw: Any, field: str, errors: list[dict[str, Any]]) -> None:
    if not isinstance(raw, list) or not 1 <= len(raw) <= 32:
        errors.append({"field": field, "type": "invalid_path_prefixes"})
        return
    for index, prefix in enumerate(raw):
        if not isinstance(prefix, str) or not _valid_policy_path(prefix):
            errors.append({"field": f"{field}.{index}", "type": "invalid_path_prefix"})


def _valid_policy_host(host: str) -> bool:
    if host == "*":
        return True
    if host != host.lower() or host.endswith(".") or len(host) > 253:
        return False
    if host.startswith("*."):
        suffix = host[2:]
        return "." in suffix and _valid_dns_name(suffix)
    return _valid_dns_name(host)


def _valid_dns_name(host: str) -> bool:
    labels = host.split(".")
    return len(labels) >= 2 and all(POLICY_DNS_LABEL_RE.fullmatch(label) for label in labels)


def _valid_policy_path(path: str) -> bool:
    if not path.startswith("/"):
        return False
    if POLICY_PATH_CONTROL_RE.search(path) or "\\" in path or "?" in path or "#" in path:
        return False
    if POLICY_PATH_BAD_PERCENT_RE.search(path) or POLICY_PATH_AMBIGUOUS_ESCAPE_RE.search(path):
        return False
    decoded = unquote(path)
    if not decoded.startswith("/") or "\\" in decoded or POLICY_PATH_CONTROL_RE.search(decoded):
        return False
    if decoded != "/" and "//" in decoded:
        return False
    segments = decoded.split("/")
    for index, segment in enumerate(segments[1:], start=1):
        if segment in {".", ".."}:
            return False
        if segment == "" and index != len(segments) - 1:
            return False
    return True


def _validate_secret_patterns(raw: Any, errors: list[dict[str, Any]]) -> None:
    if raw is None:
        return
    if not isinstance(raw, list):
        errors.append({"field": "policy.secret_patterns", "type": "array_required"})
        return
    for index, item in enumerate(raw):
        field = f"policy.secret_patterns.{index}"
        if not isinstance(item, dict):
            errors.append({"field": field, "type": "object_required"})
            continue
        for key in sorted(set(item) - POLICY_SECRET_PATTERN_FIELDS):
            errors.append({"field": f"{field}.{key}", "type": "unknown_field"})
        pattern_id = item.get("id")
        if not isinstance(pattern_id, str) or not POLICY_ID_RE.fullmatch(pattern_id):
            errors.append({"field": f"{field}.id", "type": "invalid_id"})
        name = item.get("name")
        if not isinstance(name, str) or len(name) > 100:
            errors.append({"field": f"{field}.name", "type": "invalid_name"})
        pattern = item.get("pattern")
        if not isinstance(pattern, str) or not pattern or len(pattern) > POLICY_MAX_SECRET_PATTERN_LEN:
            errors.append({"field": f"{field}.pattern", "type": "invalid_pattern"})
        else:
            try:
                re2.compile(pattern)
            except Exception:
                errors.append({"field": f"{field}.pattern", "type": "invalid_regex"})
        if not isinstance(item.get("scan_headers"), bool) or not isinstance(item.get("scan_body"), bool):
            errors.append({"field": field, "type": "invalid_scan_flags"})


def _validate_secret_injections(raw: Any, errors: list[dict[str, Any]]) -> None:
    if raw is None:
        return
    if not isinstance(raw, list):
        errors.append({"field": "policy.secret_injections", "type": "array_required"})
        return
    seen_ids: set[str] = set()
    for index, item in enumerate(raw):
        field = f"policy.secret_injections.{index}"
        if not isinstance(item, dict):
            errors.append({"field": field, "type": "object_required"})
            continue
        for key in sorted(set(item) - POLICY_SECRET_INJECTION_FIELDS):
            errors.append({"field": f"{field}.{key}", "type": "unknown_field"})
        injection_id = item.get("id")
        if not isinstance(injection_id, str) or not POLICY_ID_RE.fullmatch(injection_id):
            errors.append({"field": f"{field}.id", "type": "invalid_id"})
        elif injection_id in seen_ids:
            errors.append({"field": f"{field}.id", "type": "duplicate_id"})
        else:
            seen_ids.add(injection_id)
        if item.get("type") != "request_header":
            errors.append({"field": f"{field}.type", "type": "invalid_type"})
        _validate_destination_rule(
            item.get("match"),
            f"{field}.match",
            errors,
            require_id=False,
            allow_extensions=False,
        )
        header = item.get("header")
        if (
            not isinstance(header, str)
            or not POLICY_HEADER_RE.fullmatch(header)
            or header in POLICY_HOP_BY_HOP_HEADERS
        ):
            errors.append({"field": f"{field}.header", "type": "invalid_header"})
        value = item.get("value")
        if not isinstance(value, str):
            errors.append({"field": f"{field}.value", "type": "string_required"})
            value = ""
        template = item.get("value_template")
        if not isinstance(template, str) or template.count("${secret}") != 1:
            errors.append({"field": f"{field}.value_template", "type": "invalid_template"})
        elif len(template.replace("${secret}", value)) > 8192:
            errors.append({"field": f"{field}.value_template", "type": "rendered_value_too_long"})


def _validate_body_assertions(raw: Any, field: str, errors: list[dict[str, Any]]) -> None:
    if raw is None:
        return
    if not isinstance(raw, list):
        errors.append({"field": field, "type": "array_required"})
        return
    if len(raw) > POLICY_MAX_BODY_ASSERTIONS_PER_RULE:
        errors.append({"field": field, "type": "too_many", "limit": POLICY_MAX_BODY_ASSERTIONS_PER_RULE})
        return
    for index, item in enumerate(raw):
        item_field = f"{field}.{index}"
        if not isinstance(item, dict):
            errors.append({"field": item_field, "type": "object_required"})
            continue
        unknown = set(item) - POLICY_BODY_ASSERTION_FIELDS
        for key in sorted(unknown):
            errors.append({"field": f"{item_field}.{key}", "type": "unknown_field"})
        kind = item.get("kind")
        if kind not in POLICY_BODY_ASSERTION_KINDS:
            errors.append({"field": f"{item_field}.kind", "type": "invalid_kind"})
            continue
        if not _validate_pointer(item.get("field"), kind, f"{item_field}.field", errors):
            continue
        _validate_allow_values(item.get("allow_values"), f"{item_field}.allow_values", errors)


def _validate_websocket_assertions(raw: Any, field: str, errors: list[dict[str, Any]]) -> None:
    if raw is None:
        return
    if not isinstance(raw, list):
        errors.append({"field": field, "type": "array_required"})
        return
    if len(raw) > POLICY_MAX_WEBSOCKET_ASSERTIONS_PER_RULE:
        errors.append({"field": field, "type": "too_many", "limit": POLICY_MAX_WEBSOCKET_ASSERTIONS_PER_RULE})
        return
    for index, item in enumerate(raw):
        _validate_websocket_assertion(item, f"{field}.{index}", errors)


def _validate_websocket_assertion(item: Any, field: str, errors: list[dict[str, Any]]) -> None:
    if not isinstance(item, dict):
        errors.append({"field": field, "type": "object_required"})
        return
    for key in sorted(set(item) - POLICY_WEBSOCKET_ASSERTION_FIELDS):
        errors.append({"field": f"{field}.{key}", "type": "unknown_field"})
    if item.get("direction") not in POLICY_WEBSOCKET_DIRECTIONS:
        errors.append({"field": f"{field}.direction", "type": "invalid_direction"})
    if item.get("on_violation") not in POLICY_WEBSOCKET_ON_VIOLATIONS:
        errors.append({"field": f"{field}.on_violation", "type": "invalid_on_violation"})
    _validate_websocket_when(item.get("when"), f"{field}.when", errors)
    _validate_websocket_require(item.get("require"), f"{field}.require", errors)
    _validate_websocket_emit(item.get("on_drop_emit"), f"{field}.on_drop_emit", errors)


def _validate_websocket_when(raw: Any, field: str, errors: list[dict[str, Any]]) -> None:
    if not isinstance(raw, dict) or not 1 <= len(raw) <= POLICY_MAX_WEBSOCKET_WHEN_PREDICATES:
        errors.append({"field": field, "type": "invalid_when"})
        return
    for pointer, expected in raw.items():
        if not _validate_pointer(pointer, "json", f"{field}.{pointer}", errors):
            continue
        if not _is_bounded_scalar(expected):
            errors.append({"field": f"{field}.{pointer}", "type": "invalid_when_value"})
            continue
        # Lifecycle-typed frames (hello/disconnect) are governed SOLELY by the
        # SC's lifecycle bound, never by `websocket_assertions`; a
        # `when:{"/type":"hello"}` guard is dead and misleading (the SC resolves
        # lifecycle frames before selection), so reject it at authoring time.
        if pointer == "/type" and expected in ("hello", "disconnect"):
            errors.append({"field": f"{field}.{pointer}", "type": "lifecycle_when_forbidden"})


def _validate_websocket_require(raw: Any, field: str, errors: list[dict[str, Any]]) -> None:
    if not isinstance(raw, dict) or not 1 <= len(raw) <= POLICY_MAX_WEBSOCKET_REQUIRE_PREDICATES:
        errors.append({"field": field, "type": "invalid_require"})
        return
    for pointer, matcher in raw.items():
        if not _validate_pointer(pointer, "json", f"{field}.{pointer}", errors):
            continue
        if not isinstance(matcher, dict) or set(matcher) != {"in"}:
            errors.append({"field": f"{field}.{pointer}", "type": "invalid_matcher"})
            continue
        _validate_allow_values(matcher.get("in"), f"{field}.{pointer}.in", errors)


def _validate_websocket_emit(raw: Any, field: str, errors: list[dict[str, Any]]) -> None:
    if raw is None:
        return
    if not isinstance(raw, dict) or not 1 <= len(raw) <= POLICY_MAX_WEBSOCKET_EMIT_FIELDS:
        errors.append({"field": field, "type": "invalid_on_drop_emit"})
        return
    for key, template in raw.items():
        if not isinstance(key, str) or not POLICY_TRAFFIC_LOG_ATTR_NAME_RE.fullmatch(key):
            errors.append({"field": f"{field}.{key}", "type": "invalid_emit_key"})
            continue
        match = POLICY_EMIT_TEMPLATE_RE.fullmatch(template) if isinstance(template, str) else None
        if match is None:
            errors.append({"field": f"{field}.{key}", "type": "invalid_emit_template"})
            continue
        _validate_pointer(match.group(1), "json", f"{field}.{key}", errors)


def _is_bounded_scalar(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, str):
        return 1 <= len(value) <= POLICY_MAX_ALLOW_VALUE_LEN
    return isinstance(value, (int, float))


def _validate_traffic_log_attributes(raw: Any, field: str, errors: list[dict[str, Any]]) -> None:
    if raw is None:
        return
    if not isinstance(raw, list):
        errors.append({"field": field, "type": "array_required"})
        return
    if len(raw) > POLICY_MAX_TRAFFIC_LOG_ATTRIBUTES_PER_RULE:
        errors.append(
            {"field": field, "type": "too_many", "limit": POLICY_MAX_TRAFFIC_LOG_ATTRIBUTES_PER_RULE}
        )
        return
    seen: set[str] = set()
    for index, item in enumerate(raw):
        item_field = f"{field}.{index}"
        if not isinstance(item, dict):
            errors.append({"field": item_field, "type": "object_required"})
            continue
        unknown = set(item) - POLICY_TRAFFIC_LOG_ATTR_FIELDS
        for key in sorted(unknown):
            errors.append({"field": f"{item_field}.{key}", "type": "unknown_field"})
        name = item.get("name")
        if not isinstance(name, str) or not POLICY_TRAFFIC_LOG_ATTR_NAME_RE.fullmatch(name):
            errors.append({"field": f"{item_field}.name", "type": "invalid_name"})
            continue
        if name in seen:
            errors.append({"field": f"{item_field}.name", "type": "duplicate_name"})
            continue
        kind = item.get("kind")
        if kind not in POLICY_BODY_ASSERTION_KINDS:
            errors.append({"field": f"{item_field}.kind", "type": "invalid_kind"})
            continue
        if not _validate_pointer(item.get("field"), kind, f"{item_field}.field", errors):
            continue
        seen.add(name)


def _validate_pointer(raw: Any, kind: str, field: str, errors: list[dict[str, Any]]) -> bool:
    if not isinstance(raw, str) or not raw.startswith("/"):
        errors.append({"field": field, "type": "invalid_field"})
        return False
    segments = raw[1:].split("/")
    if not segments or any(not segment for segment in segments):
        errors.append({"field": field, "type": "invalid_field"})
        return False
    max_segments = 1 if kind == "form" else POLICY_MAX_POINTER_SEGMENTS_JSON
    if len(segments) > max_segments:
        errors.append({"field": field, "type": "invalid_field"})
        return False
    for segment in segments:
        if not POLICY_POINTER_SEGMENT_RE.fullmatch(segment):
            errors.append({"field": field, "type": "invalid_field"})
            return False
    return True


def _validate_allow_values(raw: Any, field: str, errors: list[dict[str, Any]]) -> None:
    if not isinstance(raw, list) or not 1 <= len(raw) <= POLICY_MAX_ALLOW_VALUES:
        errors.append({"field": field, "type": "invalid_allow_values"})
        return
    for index, value in enumerate(raw):
        if not isinstance(value, str) or not 1 <= len(value) <= POLICY_MAX_ALLOW_VALUE_LEN:
            errors.append({"field": f"{field}.{index}", "type": "invalid_allow_value"})
            return


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


def resolve_cvm_launch_config(body: CVMCreate) -> dict[str, str]:
    raw = load_settings().raw
    instance_type = (body.instance_type or raw.get("DEV_CVM_DEFAULT_INSTANCE_TYPE", "tdx.small")).strip()
    if not instance_type:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "Dev CVM instance type is required",
            {"errors": [{"field": "instance_type", "type": "missing_default"}]},
        )
    if not CVM_CONFIG_VALUE_RE.fullmatch(instance_type):
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Dev CVM default instance type is invalid",
            {"component": "dev_cvm_default_instance_type"},
        )

    default_region = raw.get("DEV_CVM_DEFAULT_REGION", "").strip()
    region = (body.region or default_region or raw.get("PHALA_REGION", "FR-PARIS-1")).strip()
    if not region:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "Dev CVM region is required",
            {"errors": [{"field": "region", "type": "missing_default"}]},
        )
    if not CVM_CONFIG_VALUE_RE.fullmatch(region):
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Dev CVM default region is invalid",
            {"component": "dev_cvm_default_region"},
        )

    image = raw.get("DEV_CVM_IMAGE", "").strip()
    if not image:
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Dev CVM image is not configured",
            {"component": "dev_cvm_image"},
        )
    expected_image_measurement = raw.get("DEV_CVM_IMAGE_MEASUREMENT", "").strip()
    if not expected_image_measurement or not IMAGE_MEASUREMENT_RE.fullmatch(expected_image_measurement):
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Dev CVM image measurement is not configured",
            {"component": "dev_cvm_image_measurement"},
        )
    base_domain = raw.get("CLOUDFLARE_BASE_DOMAIN", "").strip().strip(".").lower()
    if not base_domain:
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Dev CVM base domain is not configured",
            {"component": "cloudflare_base_domain"},
        )
    validate_generated_fqdn_base_domain(
        base_domain=base_domain,
        prefix=DEV_CVM_FQDN_PREFIX,
        component="cloudflare_base_domain",
        message="Dev CVM base domain is invalid",
    )
    return {
        "instance_type": instance_type,
        "region": region,
        "image": image,
        "expected_image_measurement": expected_image_measurement.lower(),
        "base_domain": base_domain,
    }


def render_dev_cvm_compose_config(resolved: dict[str, str]) -> str:
    image = json.dumps(resolved["image"])
    return "\n".join(
        [
            "services:",
            "  user-sandbox:",
            f"    image: {image}",
            "    runtime: sysbox-runc",
            "    read_only: false",
            "    tmpfs:",
            "      - /run",
            "    environment:",
            "      HTTP_PROXY: http://dev-egress-forwarder:3128",
            "      HTTPS_PROXY: http://dev-egress-forwarder:3128",
            "      http_proxy: http://dev-egress-forwarder:3128",
            "      https_proxy: http://dev-egress-forwarder:3128",
            "      NO_PROXY: localhost,127.0.0.1,user-sandbox,dev-tunnel,dev-egress-forwarder",
            "      no_proxy: localhost,127.0.0.1,user-sandbox,dev-tunnel,dev-egress-forwarder",
            "      NPM_CONFIG_IGNORE_SCRIPTS: \"true\"",
            "      NPM_CONFIG_AUDIT: \"false\"",
            "      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: \"1\"",
            "      PYTHONDONTWRITEBYTECODE: \"1\"",
            "      SECURITY_CVM_CA_CERT_B64: ${SECURITY_CVM_CA_CERT_B64}",
            "      AUTHORIZED_SSH_KEYS_B64: ${AUTHORIZED_SSH_KEYS_B64}",
            "      SANDBOX_ENV_PLACEHOLDERS_B64: ${SANDBOX_ENV_PLACEHOLDERS_B64}",
            "    volumes:",
            "      - dev-home:/home/dev",
            "      - dev-workspaces:/home/dev/workspaces",
            "      - dev-local:/home/dev/.local",
            "      - dev-claude:/home/dev/.claude",
            "      - dev-codex:/home/dev/.codex",
            "      - dev-cursor-server:/home/dev/.cursor-server",
            "      - dev-vscode-server:/home/dev/.vscode-server",
            "      - dev-docker-data:/var/lib/docker",
            "      - cvm-ca:/var/lib/concrete-ca:ro",
            "    expose:",
            "      - \"22\"",
            "    healthcheck:",
            "      test: [\"CMD-SHELL\", \"pgrep -x sshd >/dev/null\"]",
            "      interval: 500ms",
            "      timeout: 2s",
            "      start_period: 3s",
            "      retries: 5",
            "    networks:",
            "      - cvm-internal",
            "",
            "  dev-egress-forwarder:",
            f"    image: {image}",
            "    entrypoint: [\"concrete-dev-egress-forwarder\"]",
            "    read_only: true",
            "    tmpfs:",
            "      - /tmp",
            "      - /run",
            "    cap_drop:",
            "      - ALL",
            "    security_opt:",
            "      - no-new-privileges:true",
            "    environment:",
            "      SECURITY_CVM_FQDN: ${SECURITY_CVM_FQDN}",
            "      SECURITY_CVM_PROXY_PORT: ${SECURITY_CVM_PROXY_PORT}",
            "      SECURITY_CVM_ATLS_POLICY_B64: ${SECURITY_CVM_ATLS_POLICY_B64}",
            "      SECURITY_CVM_CA_CERT_B64: ${SECURITY_CVM_CA_CERT_B64}",
            "      SECURITY_CVM_PROXY_TOKEN: ${SECURITY_CVM_PROXY_TOKEN}",
            "      DEV_CVM_CONTROL_TOKEN: ${DEV_CVM_CONTROL_TOKEN}",
            "      CONSOLE_URL: ${CONSOLE_URL:-}",
            "    volumes:",
            "      - cvm-ca:/var/lib/concrete-ca",
            "    expose:",
            "      - \"3128\"",
            "    networks:",
            "      - cvm-internal",
            "      - egress-uplink",
            "",
            "  dev-tunnel:",
            f"    image: {image}",
            "    entrypoint: [\"concrete-dev-tunnel\"]",
            "    read_only: true",
            "    tmpfs:",
            "      - /tmp",
            "    cap_drop:",
            "      - ALL",
            "    security_opt:",
            "      - no-new-privileges:true",
            "    environment:",
            "      DEV_CVM_SSH_HOST: user-sandbox",
            "      DEV_CVM_SSH_PORT: \"22\"",
            "    depends_on:",
            "      user-sandbox:",
            "        condition: service_healthy",
            "    expose:",
            "      - \"8090\"",
            "    networks:",
            "      - cvm-internal",
            "      - proxy",
            "",
            "networks:",
            "  proxy:",
            "    driver: bridge",
            "  cvm-internal:",
            "    driver: bridge",
            "    internal: true",
            "  egress-uplink:",
            "    driver: bridge",
            "",
            "volumes:",
            "  dev-home:",
            "  dev-workspaces:",
            "  dev-local:",
            "  dev-claude:",
            "  dev-codex:",
            "  dev-cursor-server:",
            "  dev-vscode-server:",
            "  dev-docker-data:",
            "  cvm-ca:",
            "",
        ]
    )


def resolve_security_cvm_provision_config(body: SecurityCVMCreate) -> dict[str, str]:
    raw = load_settings().raw
    instance_type = (body.instance_type or raw.get("PHALA_DEFAULT_INSTANCE_TYPE", "tdx.small")).strip()
    if not instance_type:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "Security CVM instance type is required",
            {"errors": [{"field": "instance_type", "type": "missing_default"}]},
        )
    if not SECURITY_CVM_INSTANCE_TYPE_RE.fullmatch(instance_type):
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Security CVM default instance type is invalid",
            {"component": "security_cvm_default_instance_type"},
        )

    default_region = raw.get("SECURITY_CVM_DEFAULT_REGION", "").strip()
    region = (body.region or default_region or raw.get("PHALA_REGION", "FR-PARIS-1")).strip()
    if not region:
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "Security CVM region is required",
            {"errors": [{"field": "region", "type": "missing_default"}]},
        )
    if not CVM_CONFIG_VALUE_RE.fullmatch(region):
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Security CVM default region is invalid",
            {"component": "security_cvm_default_region"},
        )

    if (body.image_ref is None) != (body.image_measurement is None):
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "Security CVM image reference and measurement must be supplied together",
            {"errors": [{"field": "image_ref", "type": "paired_image_measurement"}]},
        )
    image_ref = (body.image_ref or raw.get("SECURITY_CVM_IMAGE_REF", "")).strip()
    image_measurement = (body.image_measurement or raw.get("SECURITY_CVM_IMAGE_MEASUREMENT", "")).strip()
    if not image_ref:
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Security CVM image is not configured",
            {"component": "security_cvm_image"},
        )
    if not image_measurement or not IMAGE_MEASUREMENT_RE.fullmatch(image_measurement):
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Security CVM image measurement is not configured",
            {"component": "security_cvm_image_measurement"},
        )

    base_domain = raw.get("SECURITY_CVM_BASE_DOMAIN", "").strip().strip(".").lower()
    if not base_domain:
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Security CVM base domain is not configured",
            {"component": "security_cvm_base_domain"},
        )
    validate_generated_fqdn_base_domain(
        base_domain=base_domain,
        prefix=SECURITY_CVM_FQDN_PREFIX,
        component="security_cvm_base_domain",
        message="Security CVM base domain is invalid",
    )
    return {
        "instance_type": instance_type,
        "region": region,
        "image_ref": image_ref,
        "expected_image_measurement": image_measurement.lower(),
        "base_domain": base_domain,
    }


def render_security_cvm_compose_config(resolved: dict[str, str]) -> str:
    image = json.dumps(resolved["image_ref"])
    return "\n".join(
        [
            "services:",
            "  mitmproxy:",
            f"    image: {image}",
            "    command: [\"concrete-security-mitmproxy\"]",
            "    read_only: true",
            "    tmpfs:",
            "      - /tmp",
            "      - /run",
            "    cap_drop:",
            "      - ALL",
            "    security_opt:",
            "      - no-new-privileges:true",
            "    environment:",
            "      CONSOLE_URL: ${CONSOLE_URL}",
            "      ENTITY_ID: ${ENTITY_ID}",
            "      SC_ID: ${SC_ID}",
            "      CONSOLE_INGEST_TOKEN: ${CONSOLE_INGEST_TOKEN}",
            "      CA_EXPORT_TOKEN: ${CA_EXPORT_TOKEN}",
            "      SC_MANAGEMENT_HOST: 0.0.0.0",
            "      SC_MANAGEMENT_PORT: \"8081\"",
            "      SC_MITMPROXY_HOST: 0.0.0.0",
            "      SC_MITMPROXY_PORT: \"8080\"",
            "      SC_MITMPROXY_CONFDIR: /tmp/mitmproxy",
            "    expose:",
            "      - \"8080\"",
            "      - \"8081\"",
            "    networks:",
            "      - proxy",
            "",
            "  proxy-tunnel:",
            f"    image: {image}",
            "    command: [\"concrete-security-proxy-tunnel\"]",
            "    read_only: true",
            "    tmpfs:",
            "      - /tmp",
            "      - /run",
            "    cap_drop:",
            "      - ALL",
            "    security_opt:",
            "      - no-new-privileges:true",
            "    environment:",
            "      SC_PROXY_TUNNEL_HOST: 0.0.0.0",
            "      SC_PROXY_TUNNEL_PORT: \"8082\"",
            "      SC_PROXY_TUNNEL_UPSTREAM_HOST: mitmproxy",
            "      SC_PROXY_TUNNEL_UPSTREAM_PORT: \"8080\"",
            "      SC_PROXY_TUNNEL_PATH: /concrete/proxy",
            "      SC_PROXY_TUNNEL_UPGRADE: concrete-proxy",
            "    expose:",
            "      - \"8082\"",
            "    networks:",
            "      - proxy",
            "",
            "networks:",
            "  proxy:",
            "    driver: bridge",
            "",
        ]
    )


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
    if resource == "dev_cvms":
        return await conn.fetchval(
            """
            SELECT count(*)
            FROM cvms
            WHERE entity_id = $1
              AND deleted_at IS NULL
              AND state <> 'TERMINATED'
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
    if resource == "dev_cvms":
        return await conn.fetchval(
            """
            SELECT count(*)
            FROM cvms
            WHERE owner_id = $1
              AND deleted_at IS NULL
              AND state <> 'TERMINATED'
            """,
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
            (
                SELECT COALESCE(
                    jsonb_agg(jsonb_build_object('id', ep.id, 'name', ep.name) ORDER BY ep.name),
                    '[]'::jsonb
                )
                FROM profile_users pu
                JOIN entity_profiles ep ON ep.id = pu.profile_id
                WHERE pu.user_id = u.id
                  AND ep.deleted_at IS NULL
            ) AS profiles,
            (
                SELECT max(oi.last_login_at)
                FROM oauth_identities oi
                WHERE oi.user_id = u.id
                  AND oi.deleted_at IS NULL
            ) AS last_login_at,
            u.created_at,
            u.deactivated_at,
            u.deleted_at
        FROM users u
        JOIN entities e ON e.id = u.entity_id
        WHERE u.id = $1
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
    return user_resource(row)


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
    next_cursor = ssh_key_cursor(rows[limit - 1]) if len(rows) > limit else None
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


@router.get("/entities")
async def list_entities(
    limit: int = Query(default=100, ge=1, le=500),
    cursor: str | None = Query(default=None, max_length=80),
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_permission("PLATFORM_OPERATOR")
    cursor_anchor = parse_entity_cursor(cursor)
    values: list[object] = []
    clauses: list[str] = []
    if cursor_anchor is not None:
        values.extend([cursor_anchor[0], cursor_anchor[1]])
        clauses.append("(created_at, id) < ($1, $2)")
    values.append(limit + 1)
    where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    query = f"""
        SELECT id, name, domain, created_at
        FROM entities
        {where_clause}
        ORDER BY created_at DESC, id DESC
        LIMIT ${len(values)}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *values)
    next_cursor = entity_cursor(rows[limit - 1]) if len(rows) > limit else None
    return list_page([entity_resource(row) for row in rows[:limit]], next_cursor=next_cursor)


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
    status: UserStatusFilter | None = None,
    assigned: AssignedFilter | None = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_entity(entity_id)
    current_user.require_permission("USER_MANAGE")
    # --status replaces the base live-row clause (so `erased` can match deleted
    # rows); --assigned adds a membership predicate. Neither binds a value.
    clauses = ["u.entity_id = $1"]
    clauses.extend(user_list_status_clauses(status))
    clauses.extend(user_list_assigned_clauses(assigned))
    where_clause = " AND ".join(clauses)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
            SELECT
                u.id,
                u.email,
                u.name,
                u.entity_id,
                e.name AS entity_name,
                COALESCE(array_agg(up.permission::text ORDER BY up.permission::text)
                    FILTER (WHERE up.permission IS NOT NULL), ARRAY[]::text[]) AS permissions,
                (
                    SELECT COALESCE(
                        jsonb_agg(jsonb_build_object('id', ep.id, 'name', ep.name) ORDER BY ep.name),
                        '[]'::jsonb
                    )
                    FROM profile_users pu
                    JOIN entity_profiles ep ON ep.id = pu.profile_id
                    WHERE pu.user_id = u.id
                      AND ep.deleted_at IS NULL
                ) AS profiles,
                (
                    SELECT max(oi.last_login_at)
                    FROM oauth_identities oi
                    WHERE oi.user_id = u.id
                      AND oi.deleted_at IS NULL
                ) AS last_login_at,
                u.created_at,
                u.deactivated_at,
                u.deleted_at
            FROM users u
            JOIN entities e ON e.id = u.entity_id
            LEFT JOIN user_permissions up ON up.user_id = u.id
            WHERE {where_clause}
            GROUP BY u.id, e.name
            ORDER BY u.email
            """,
            entity_id,
        )
    return list_page([user_resource(row) for row in rows])


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
    return user_resource(row)


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
    assigned: AssignedFilter | None = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_entity(entity_id)
    can_manage = "USER_MANAGE" in current_user.permissions
    # The --assigned clauses use only `pu.user_id` (no bind values), so they are
    # AND-ed straight into the WHERE; the Console does the filtering.
    clauses = ["ep.entity_id = $1", "ep.deleted_at IS NULL", "($3 OR pu.user_id IS NOT NULL)"]
    clauses.extend(profile_list_assigned_clauses(assigned))
    where_clause = " AND ".join(clauses)
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            f"""
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
            WHERE {where_clause}
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
            policy_provided = "policy" in body.model_fields_set
            if policy_provided:
                validate_profile_policy(body.policy)
                next_policy, next_secret_values = split_profile_policy_secret_values(body.policy)
            else:
                next_policy = old_policy
                next_secret_values = None
            changed = (
                next_name != profile["name"]
                or next_description != profile["description"]
                or next_policy != old_policy
                or bool(next_secret_values)
            )
            if changed:
                policy_changed = next_policy != old_policy or bool(next_secret_values)
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
                    if policy_provided:
                        await replace_profile_secret_material(
                            conn,
                            profile_id=profile_id,
                            secret_values=next_secret_values,
                        )
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


@router.post("/admin/reconcile")
async def reconcile_admin(
    body: AdminReconcile | None = None,
    current_user: CurrentUser = Depends(require_current_user),
) -> dict:
    current_user.require_permission("PLATFORM_OPERATOR")
    body = body or AdminReconcile()
    validate_reconcile_dependencies(include_orphans=body.include_orphans)
    summary = await run_reconciliation_pass(include_orphans=body.include_orphans)
    return {
        "cvms_advanced": summary.cvms_advanced,
        "security_cvms_advanced": summary.security_cvms_advanced,
        "orphans_cleaned": summary.orphans_cleaned,
    }


def validate_reconcile_dependencies(*, include_orphans: bool) -> None:
    raw = load_settings().raw
    if not raw.get("PHALA_API_TOKEN", "").strip():
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "CVM provider adapter is not configured",
            {"component": "cvm_provider_adapter"},
        )
    if include_orphans and (
        not raw.get("CLOUDFLARE_API_TOKEN", "").strip()
        or not raw.get("CLOUDFLARE_ZONE_ID", "").strip()
        or not raw.get("SECURITY_CVM_ZONE_ID", "").strip()
    ):
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Cloudflare adapter is not configured",
            {"component": "cloudflare_adapter"},
        )


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
        clauses.append(f"seq < {bind(after_seq)}")

    values.append(limit + 1)
    query = f"""
        SELECT
            seq, id, entity_id, actor_id, actor_email, action, target_type, target_id,
            before, after, ip_address, description, request_id, timestamp, prev_hash, row_hash
        FROM audit_events
        WHERE {' AND '.join(clauses)}
        ORDER BY seq DESC
        LIMIT ${len(values)}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *values)
    next_cursor = str(rows[limit - 1]["seq"]) if len(rows) > limit else None
    return list_page([audit_event_resource(row) for row in rows[:limit]], next_cursor=next_cursor)


@router.post("/audit/export", status_code=202)
async def create_audit_export(
    request: Request,
    body: AuditExportCreate,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    idempotency_key_value = require_idempotency_key(idempotency_key)
    current_user.require_permission("AUDIT_EXPORT")
    validate_audit_export_request(body)
    settings = load_settings()
    bucket_uri = settings.raw.get("AUDIT_EXPORT_BUCKET", "").strip()
    if not bucket_uri:
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "audit export bucket is not configured",
            {"component": "audit_export_bucket"},
        )

    body_sha256 = request_body_sha256(await request.body())
    operation_id = uuid4()
    filters_payload = audit_export_filters_payload(body)

    async with pool.acquire() as conn:
        async with conn.transaction():
            await acquire_idempotency_lock(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=AUDIT_EXPORT_ROUTE,
            )
            cached = await lookup_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=AUDIT_EXPORT_ROUTE,
                body_sha256=body_sha256,
            )
            if cached is not None:
                return JSONResponse(status_code=cached.status_code, content=cached.body, headers=cached.headers)

            export_count = await audit_export_daily_count(conn, current_user.id)
            if export_count >= 10:
                raise api_error(
                    429,
                    "RATE_LIMITED",
                    "daily audit export quota exhausted",
                    {"limit": "audit_export_daily"},
                )

            row = await conn.fetchrow(
                """
                INSERT INTO operations (
                    id,
                    kind,
                    status,
                    actor_id,
                    actor_email,
                    target_type,
                    target_id,
                    idempotency_key,
                    request_body_sha256,
                    progress_step,
                    progress_percent,
                    expires_at
                )
                VALUES (
                    $1, 'audit.export', 'pending', $2, $3, 'audit_export', $1, $4, $5,
                    'queued', 0, NULL
                )
                RETURNING
                    id,
                    kind,
                    status::text AS status,
                    actor_id,
                    actor_email,
                    target_type,
                    target_id,
                    progress_step,
                    progress_percent,
                    result,
                    error,
                    result_disclosed_at,
                    created_at,
                    updated_at,
                    expires_at
                """,
                operation_id,
                current_user.id,
                current_user.email,
                idempotency_key_value,
                body_sha256,
            )
            await conn.execute(
                """
                INSERT INTO audit_export_requests (
                    operation_id,
                    entity_id,
                    filters
                )
                VALUES ($1, $2, $3::jsonb)
                """,
                operation_id,
                current_user.entity_id,
                json.dumps(filters_payload),
            )
            await insert_audit_event(
                conn,
                entity_id=current_user.entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="AUDIT_EXPORT_REQUESTED",
                target_type="audit_export",
                target_id=operation_id,
                after=filters_payload,
            )
            response_body = operation_resource(row)
            await store_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=AUDIT_EXPORT_ROUTE,
                body_sha256=body_sha256,
                status_code=202,
                response_body=response_body,
            )
            return response_body


@router.get("/audit/exports/{download_token}")
async def download_audit_export(
    download_token: str,
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    if not AUDIT_EXPORT_DOWNLOAD_TOKEN_RE.fullmatch(download_token):
        raise api_error(404, "NOT_FOUND", "resource not found")
    token_hash = hashlib.sha256(download_token.encode("utf-8")).hexdigest()
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT
                    id,
                    operation_id,
                    storage_uri,
                    content_type,
                    sha256,
                    expires_at,
                    redeemed_at
                FROM audit_export_artifacts
                WHERE download_token_hash = $1
                FOR UPDATE
                """,
                token_hash,
            )
            now = datetime.now(timezone.utc)
            if row is None or row["expires_at"] <= now or row["redeemed_at"] is not None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            try:
                bucket_uri = load_settings().raw.get("AUDIT_EXPORT_BUCKET", "").strip()
                content = await read_audit_export_artifact(bucket_uri, row["storage_uri"])
            except AuditExportStorageError as exc:
                raise api_error(
                    503,
                    "SERVICE_UNAVAILABLE",
                    "audit export storage backend failed",
                    {"component": "audit_export_store"},
                ) from exc
            if hashlib.sha256(content).hexdigest() != row["sha256"]:
                raise api_error(
                    503,
                    "SERVICE_UNAVAILABLE",
                    "audit export artifact integrity check failed",
                    {"component": "audit_export_store"},
                )
            redeemed_at = timestamp(now)
            await conn.execute(
                """
                UPDATE audit_export_artifacts
                SET redeemed_at = $2
                WHERE id = $1
                """,
                row["id"],
                now,
            )
            await conn.execute(
                """
                UPDATE operations
                SET result = jsonb_set(COALESCE(result, '{}'::jsonb), '{redeemed_at}', to_jsonb($2::text), true),
                    updated_at = now()
                WHERE id = $1
                """,
                row["operation_id"],
                redeemed_at,
            )
    extension = "csv" if row["content_type"].startswith("text/csv") else "ndjson"
    return Response(
        content=content,
        media_type=row["content_type"],
        headers={
            "Content-Disposition": f'attachment; filename="audit-export-{row["operation_id"]}.{extension}"',
            "Cache-Control": "no-store",
        },
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


async def audit_export_daily_count(conn: asyncpg.Connection, actor_id: UUID) -> int:
    return await conn.fetchval(
        """
        SELECT count(*)
        FROM operations
        WHERE kind = 'audit.export'
          AND actor_id = $1
          AND created_at >= date_trunc('day', now())
        """,
        actor_id,
    )


def audit_export_filters_payload(body: AuditExportCreate) -> dict[str, Any]:
    return {
        "format": body.format,
        "actor_id": str(body.actor_id) if body.actor_id else None,
        "target_type": body.target_type,
        "target_id": body.target_id,
        "action": body.action,
        "from": timestamp(body.from_) if body.from_ else None,
        "to": timestamp(body.to) if body.to else None,
    }


class CvmStateFilter(str, Enum):
    """Lifecycle-state values accepted by ``cvm list --state`` / ``GET /cvms?state=``."""

    alive = "alive"
    all = "all"
    provisioning = "provisioning"
    running = "running"
    stopped = "stopped"
    failed = "failed"
    terminated = "terminated"


def cvm_list_state_clauses(
    state: CvmStateFilter | None,
    *,
    next_param_index: int,
) -> tuple[list[str], list[object]]:
    """Return the ``(clauses, values)`` for the ``state`` filter, to AND into the
    ``GET /cvms`` query (``values`` bind from ``$next_param_index``).

    - ``None`` / ``alive``: keep ``c.deleted_at IS NULL``; no state predicate.
    - ``all``: drop the ``deleted_at`` clause (includes terminated rows).
    - ``terminated``: drop the ``deleted_at`` clause and match
      ``c.state = 'TERMINATED'`` (terminate sets both, so keeping it returns nothing).
    - a concrete state: keep ``deleted_at`` and match ``c.state = $N`` (uppercased).
    """
    if state is None or state is CvmStateFilter.alive:
        return ["c.deleted_at IS NULL"], []
    if state is CvmStateFilter.all:
        return [], []
    if state is CvmStateFilter.terminated:
        return [f"c.state = ${next_param_index}"], ["TERMINATED"]
    # A concrete state: keep live rows and match exactly that state.
    return (
        ["c.deleted_at IS NULL", f"c.state = ${next_param_index}"],
        [state.value.upper()],
    )


class AssignedFilter(str, Enum):
    """Membership values accepted by ``--assigned`` on ``profile list`` / ``user list``."""

    yes = "yes"
    no = "no"


class UserStatusFilter(str, Enum):
    """Account-status values accepted by ``user list --status`` / ``GET .../users?status=``."""

    active = "active"
    deactivated = "deactivated"
    erased = "erased"


def profile_list_assigned_clauses(assigned: AssignedFilter | None) -> list[str]:
    """Return the clauses for the ``assigned`` filter, to AND into the
    ``GET /profiles`` query. The membership LEFT JOIN exposes ``pu.user_id`` for
    the current user (``NULL`` when they are not a member).

    - ``None``: no membership predicate (every visible profile).
    - ``yes``: ``pu.user_id IS NOT NULL`` (you are a member).
    - ``no``: ``pu.user_id IS NULL`` (you are not a member).

    Note: for a non-manager the base visibility clause already restricts the
    result to profiles they belong to (``$N OR pu.user_id IS NOT NULL``), so
    ``--assigned no`` AND-s an unsatisfiable predicate and returns zero rows by
    design. Only managers (who can see profiles they are not members of) get a
    meaningful ``--assigned no`` result.
    """
    if assigned is None:
        return []
    if assigned is AssignedFilter.yes:
        return ["pu.user_id IS NOT NULL"]
    return ["pu.user_id IS NULL"]


def user_list_status_clauses(status: UserStatusFilter | None) -> list[str]:
    """Return the clauses for the ``status`` filter, to AND into the users-list
    query. Account status is derived from ``u.deactivated_at`` / ``u.deleted_at``.

    - ``None``: keep ``u.deleted_at IS NULL`` (all non-erased users, the default).
    - ``active``: ``u.deactivated_at IS NULL AND u.deleted_at IS NULL``.
    - ``deactivated``: ``u.deactivated_at IS NOT NULL AND u.deleted_at IS NULL``.
    - ``erased``: ``u.deleted_at IS NOT NULL`` (drops the base live-row clause,
      which would otherwise return nothing).
    """
    if status is None:
        return ["u.deleted_at IS NULL"]
    if status is UserStatusFilter.active:
        return ["u.deactivated_at IS NULL", "u.deleted_at IS NULL"]
    if status is UserStatusFilter.deactivated:
        return ["u.deactivated_at IS NOT NULL", "u.deleted_at IS NULL"]
    # erased: the row is soft-deleted, so drop the base live-row clause.
    return ["u.deleted_at IS NOT NULL"]


def user_list_assigned_clauses(assigned: AssignedFilter | None) -> list[str]:
    """Return the clauses for the ``assigned`` filter, to AND into the users-list
    query. Membership is tested against ``profile_users`` for the user, joined to
    ``entity_profiles`` so soft-deleted profiles do not count as a membership —
    this keeps the filter consistent with the displayed ``profiles`` subquery,
    which also drops ``ep.deleted_at IS NOT NULL`` rows.

    - ``None``: no membership predicate (any membership).
    - ``yes``: belongs to at least one live profile (``EXISTS (...)``).
    - ``no``: belongs to no live profile (``NOT EXISTS (...)``).
    """
    if assigned is None:
        return []
    exists = (
        "EXISTS (SELECT 1 FROM profile_users pu "
        "JOIN entity_profiles ep ON ep.id = pu.profile_id "
        "WHERE pu.user_id = u.id AND ep.deleted_at IS NULL)"
    )
    if assigned is AssignedFilter.yes:
        return [exists]
    return [f"NOT {exists}"]


@router.get("/cvms")
async def list_cvms(
    profile_id: UUID | None = None,
    state: CvmStateFilter | None = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    clauses = ["c.entity_id = $1"]
    values: list[object] = [current_user.entity_id]
    state_clauses, state_values = cvm_list_state_clauses(state, next_param_index=len(values) + 1)
    clauses.extend(state_clauses)
    values.extend(state_values)
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


@router.post("/cvms", status_code=202)
async def create_cvm(
    request: Request,
    body: CVMCreate,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    idempotency_key_value = require_idempotency_key(idempotency_key)
    current_user.require_permission("CVM_LAUNCH")
    body_sha256 = request_body_sha256(await request.body())
    operation_id = uuid4()
    cvm_id = uuid4()
    async with pool.acquire() as conn:
        async with conn.transaction():
            await acquire_idempotency_lock(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=CREATE_CVM_ROUTE,
            )
            cached = await lookup_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=CREATE_CVM_ROUTE,
                body_sha256=body_sha256,
            )
            if cached is not None:
                return JSONResponse(status_code=cached.status_code, content=cached.body, headers=cached.headers)

            resolved = resolve_cvm_launch_config(body)
            profile_rows = await fetch_cvm_launch_profiles(conn, body.profile_ids, current_user)
            await ensure_cvm_launch_profile_memberships(conn, body.profile_ids, current_user)
            ensure_no_sandbox_env_conflict(profile_rows)
            await ensure_cvm_launch_ssh_keys(conn, body.ssh_key_ids, current_user)
            security_cvm_id = await fetch_live_security_cvm_id(conn, current_user.entity_id)
            await enforce_user_quota(conn, current_user.id, "dev_cvms")
            await enforce_entity_quota(conn, current_user.entity_id, "dev_cvms")
            fqdn = generated_cvm_fqdn(DEV_CVM_FQDN_PREFIX, resolved["base_domain"])
            compose_config = render_dev_cvm_compose_config(resolved)
            await conn.execute(
                """
                INSERT INTO cvms (
                    id,
                    entity_id,
                    state,
                    fqdn,
                    instance_type,
                    region,
                    compose_config,
                    expected_image_measurement,
                    owner_id,
                    security_cvm_id
                )
                VALUES ($1, $2, 'PROVISIONING', $3, $4, $5, $6, $7, $8, $9)
                """,
                cvm_id,
                current_user.entity_id,
                fqdn,
                resolved["instance_type"],
                resolved["region"],
                compose_config,
                resolved["expected_image_measurement"],
                current_user.id,
                security_cvm_id,
            )
            await conn.executemany(
                """
                INSERT INTO cvm_profiles (cvm_id, profile_id, attached_by)
                VALUES ($1, $2, $3)
                """,
                [(cvm_id, profile_id, current_user.id) for profile_id in body.profile_ids],
            )
            await conn.executemany(
                """
                INSERT INTO cvm_ssh_keys (cvm_id, ssh_key_id)
                VALUES ($1, $2)
                """,
                [(cvm_id, ssh_key_id) for ssh_key_id in body.ssh_key_ids],
            )
            row = await conn.fetchrow(
                """
                INSERT INTO operations (
                    id,
                    kind,
                    status,
                    actor_id,
                    actor_email,
                    target_type,
                    target_id,
                    idempotency_key,
                    request_body_sha256,
                    progress_step,
                    progress_percent
                )
                VALUES ($1, 'cvm.launch', 'pending', $2, $3, 'cvm', $4, $5, $6, 'persist_stub', 10)
                RETURNING
                    id,
                    kind,
                    status::text AS status,
                    actor_id,
                    actor_email,
                    target_type,
                    target_id,
                    progress_step,
                    progress_percent,
                    result,
                    error,
                    result_disclosed_at,
                    created_at,
                    updated_at,
                    expires_at
                """,
                operation_id,
                current_user.id,
                current_user.email,
                cvm_id,
                idempotency_key_value,
                body_sha256,
            )
            response_body = operation_resource(row)
            await store_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=CREATE_CVM_ROUTE,
                body_sha256=body_sha256,
                status_code=202,
                response_body=response_body,
            )
            return response_body


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


@router.get("/cvms/{cvm_id}/policy-bundle")
async def get_cvm_policy_bundle(
    cvm_id: UUID,
    response: Response,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    async with pool.acquire() as conn:
        cvm = await conn.fetchrow(
            """
            SELECT id, owner_id, state::text AS state, atls_policy_bundle
            FROM cvms
            WHERE id = $1
              AND entity_id = $2
              AND deleted_at IS NULL
            """,
            cvm_id,
            current_user.entity_id,
        )
        if cvm is None:
            raise api_error(404, "NOT_FOUND", "resource not found")
        if cvm["owner_id"] != current_user.id and "CVM_MANAGE" not in current_user.permissions:
            raise api_error(404, "NOT_FOUND", "resource not found")
        if cvm["state"] == "TERMINATED":
            raise api_error(
                409,
                "CONFLICT",
                "policy bundle is unavailable for terminated CVM",
                {"state": "cvm_terminated"},
            )
        bundle = cvm["atls_policy_bundle"]
    if bundle is None:
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "CVM policy bundle has not been materialized",
            {"component": "policy_bundle"},
        )
    response.headers["Cache-Control"] = "no-store"
    return json_payload(bundle)


@router.post("/cvms/{cvm_id}/actions/start")
async def start_cvm(
    cvm_id: UUID,
    response: Response,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    optional_idempotency_key(idempotency_key)
    return await apply_cvm_state_action(
        pool,
        cvm_id=cvm_id,
        action="start",
        source_state="STOPPED",
        target_state="RUNNING",
        audit_action="CVM_STARTED",
        if_match=if_match,
        current_user=current_user,
        response=response,
    )


@router.post("/cvms/{cvm_id}/actions/stop")
async def stop_cvm(
    cvm_id: UUID,
    response: Response,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    optional_idempotency_key(idempotency_key)
    return await apply_cvm_state_action(
        pool,
        cvm_id=cvm_id,
        action="stop",
        source_state="RUNNING",
        target_state="STOPPED",
        audit_action="CVM_STOPPED",
        if_match=if_match,
        current_user=current_user,
        response=response,
    )


@router.post("/cvms/{cvm_id}/actions/update", status_code=202)
async def update_cvm(
    cvm_id: UUID,
    request: Request,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    idempotency_key_value = optional_idempotency_key(idempotency_key)
    route = f"POST /api/v1/cvms/{cvm_id}/actions/update"
    body_sha256 = request_body_sha256(await request.body())
    operation_id = uuid4()
    async with pool.acquire() as conn:
        async with conn.transaction():
            if idempotency_key_value is not None:
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

            cvm = await lock_cvm_for_lifecycle_action(conn, cvm_id=cvm_id, current_user=current_user)
            require_cvm_owner_or_manager(cvm, current_user)
            if if_match is not None:
                require_matching_etag(cvm_etag(cvm), if_match)
            await ensure_no_active_operation(conn, target_id=cvm_id, state=cvm["state"])
            if cvm["state"] not in {"RUNNING", "STOPPED", "FAILED"}:
                raise api_error(
                    409,
                    "CONFLICT",
                    "cannot update CVM from current state",
                    {"state": cvm["state"]},
                )
            if cvm_provider_deployment_id(cvm) is None:
                raise api_error(
                    409,
                    "CONFLICT",
                    "CVM has no provider deployment to update",
                    {"state": "provider_deployment_missing"},
                )
            row = await conn.fetchrow(
                """
                INSERT INTO operations (
                    id,
                    kind,
                    status,
                    actor_id,
                    actor_email,
                    target_type,
                    target_id,
                    idempotency_key,
                    request_body_sha256,
                    progress_step,
                    progress_percent
                )
                VALUES ($1, 'cvm.update', 'pending', $2, $3, 'cvm', $4, $5, $6, 'queued', 0)
                RETURNING
                    id,
                    kind,
                    status::text AS status,
                    actor_id,
                    actor_email,
                    target_type,
                    target_id,
                    progress_step,
                    progress_percent,
                    result,
                    error,
                    result_disclosed_at,
                    created_at,
                    updated_at,
                    expires_at
                """,
                operation_id,
                current_user.id,
                current_user.email,
                cvm_id,
                idempotency_key_value,
                body_sha256 if idempotency_key_value is not None else None,
            )
            response_body = operation_resource(row)
            if idempotency_key_value is not None:
                await store_idempotency_response(
                    conn,
                    credential_id=str(current_user.id),
                    idempotency_key=idempotency_key_value,
                    route=route,
                    body_sha256=body_sha256,
                    status_code=202,
                    response_body=response_body,
                )
            return response_body


@router.post("/cvms/{cvm_id}/actions/terminate", status_code=202)
async def terminate_cvm(
    cvm_id: UUID,
    request: Request,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    idempotency_key_value = optional_idempotency_key(idempotency_key)
    route = f"POST /api/v1/cvms/{cvm_id}/actions/terminate"
    body_sha256 = request_body_sha256(await request.body())
    operation_id = uuid4()
    async with pool.acquire() as conn:
        async with conn.transaction():
            if idempotency_key_value is not None:
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

            cvm = await lock_cvm_for_lifecycle_action(conn, cvm_id=cvm_id, current_user=current_user)
            require_cvm_owner_or_manager(cvm, current_user)
            if if_match is not None:
                require_matching_etag(cvm_etag(cvm), if_match)
            if cvm["state"] == "TERMINATED":
                cvm_payload = await fetch_cvm_resource_for_operation(conn, cvm_id)
                operation_status = "succeeded"
                operation_result = json.dumps(cvm_payload)
                progress_step = "finalise"
                progress_percent = 100
            else:
                if cvm["state"] not in {"RUNNING", "STOPPED", "FAILED"}:
                    raise api_error(
                        409,
                        "CONFLICT",
                        "illegal CVM lifecycle transition",
                        {"state": cvm["state"]},
                    )
                if cvm_provider_app_id(cvm) is not None:
                    operation_status = "pending"
                    operation_result = None
                    progress_step = "queued"
                    progress_percent = 0
                else:
                    await conn.execute(
                        """
                        UPDATE service_principal_tokens
                        SET deleted_at = now(),
                            deleted_by = $1
                        WHERE principal_type = 'dev_cvm'
                          AND principal_id = $2
                          AND deleted_at IS NULL
                        """,
                        current_user.id,
                        cvm_id,
                    )
                    await conn.execute(
                        """
                        UPDATE cvms
                        SET state = 'TERMINATED',
                            deleted_at = now(),
                            deleted_by = $1,
                            updated_at = now(),
                            txt_dns_record_id = NULL,
                            cname_dns_record_id = NULL
                        WHERE id = $2
                        """,
                        current_user.id,
                        cvm_id,
                    )
                    cvm_payload = await fetch_cvm_resource_for_operation(conn, cvm_id)
                    await insert_audit_event(
                        conn,
                        entity_id=current_user.entity_id,
                        actor_id=current_user.id,
                        actor_email=current_user.email,
                        action="CVM_TERMINATED",
                        target_type="cvm",
                        target_id=cvm_id,
                        before={"state": cvm["state"]},
                        after={"state": "TERMINATED"},
                    )
                    operation_status = "succeeded"
                    operation_result = json.dumps(cvm_payload)
                    progress_step = "finalise"
                    progress_percent = 100
            row = await conn.fetchrow(
                """
                INSERT INTO operations (
                    id,
                    kind,
                    status,
                    actor_id,
                    actor_email,
                    target_type,
                    target_id,
                    idempotency_key,
                    request_body_sha256,
                    result,
                    progress_step,
                    progress_percent
                )
                VALUES ($1, 'cvm.terminate', $2::operation_status, $3, $4, 'cvm', $5, $6, $7, $8::jsonb, $9, $10)
                RETURNING
                    id,
                    kind,
                    status::text AS status,
                    actor_id,
                    actor_email,
                    target_type,
                    target_id,
                    progress_step,
                    progress_percent,
                    result,
                    error,
                    result_disclosed_at,
                    created_at,
                    updated_at,
                    expires_at
                """,
                operation_id,
                operation_status,
                current_user.id,
                current_user.email,
                cvm_id,
                idempotency_key_value,
                body_sha256 if idempotency_key_value is not None else None,
                operation_result,
                progress_step,
                progress_percent,
            )
            response_body = operation_resource(row)
            if idempotency_key_value is not None:
                await store_idempotency_response(
                    conn,
                    credential_id=str(current_user.id),
                    idempotency_key=idempotency_key_value,
                    route=route,
                    body_sha256=body_sha256,
                    status_code=202,
                    response_body=response_body,
                )
            return response_body


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


async def lock_cvm_for_lifecycle_action(
    conn: asyncpg.Connection,
    *,
    cvm_id: UUID,
    current_user: CurrentUser,
) -> asyncpg.Record:
    row = await conn.fetchrow(
        """
        SELECT id, entity_id, owner_id, state::text AS state, metadata, policy_version, updated_at
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


def cvm_provider_app_id(row: asyncpg.Record | dict) -> str | None:
    metadata = json_payload(dict(row).get("metadata", {}))
    if not isinstance(metadata, dict):
        return None
    app_id = metadata.get("app_id")
    return app_id if isinstance(app_id, str) and app_id else None


def cvm_provider_deployment_id(row: asyncpg.Record | dict) -> str | None:
    metadata = json_payload(dict(row).get("metadata", {}))
    if not isinstance(metadata, dict):
        return None
    deployment_id = metadata.get("deployment_id") or metadata.get("app_id")
    return deployment_id if isinstance(deployment_id, str) and deployment_id else None


async def apply_provider_cvm_lifecycle_action(*, app_id: str, action: str) -> None:
    from concrete_console.tee_provider import CvmProviderError, cvm_provider_from_settings

    try:
        client = cvm_provider_from_settings(timeout_seconds=PROVIDER_CVM_SYNC_ACTION_TIMEOUT_SECONDS)
        if action == "start":
            await client.start(app_id)
        elif action == "stop":
            await client.stop(app_id)
        else:
            raise RuntimeError(f"unsupported provider CVM action: {action}")
    except CvmProviderError as exc:
        raise api_error(
            502,
            "UPSTREAM_ERROR",
            "Dev CVM provider lifecycle action failed",
            {"adapter": "cvm_provider", "reason": exc.code},
        ) from exc


async def apply_cvm_state_action(
    pool: asyncpg.Pool,
    *,
    cvm_id: UUID,
    action: str,
    source_state: str,
    target_state: str,
    audit_action: str,
    if_match: str | None,
    current_user: CurrentUser,
    response: Response,
) -> dict:
    async with pool.acquire() as conn:
        async with conn.transaction():
            cvm = await lock_cvm_for_lifecycle_action(conn, cvm_id=cvm_id, current_user=current_user)
            require_cvm_owner_or_manager(cvm, current_user)
            if if_match is not None:
                require_matching_etag(cvm_etag(cvm), if_match)
            if cvm["state"] == target_state:
                return await fetch_cvm_resource_for_operation(conn, cvm_id)
            if cvm["state"] != source_state:
                raise api_error(
                    409,
                    "CONFLICT",
                    f"cannot {action} CVM from current state",
                    {"state": cvm["state"]},
                )
            app_id = cvm_provider_app_id(cvm)
            if app_id is not None:
                await apply_provider_cvm_lifecycle_action(app_id=app_id, action=action)
            await conn.execute(
                """
                UPDATE cvms
                SET state = $1,
                    updated_at = now()
                WHERE id = $2
                """,
                target_state,
                cvm_id,
            )
            await insert_audit_event(
                conn,
                entity_id=current_user.entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action=audit_action,
                target_type="cvm",
                target_id=cvm_id,
                before={"state": cvm["state"]},
                after={"state": target_state},
            )
    return await fetch_visible_cvm_resource(pool, cvm_id=cvm_id, current_user=current_user, response=response)


async def ensure_no_active_operation(conn: asyncpg.Connection, *, target_id: UUID, state: str) -> None:
    active_operation = await conn.fetchrow(
        """
        SELECT id, kind
        FROM operations
        WHERE target_id = $1
          AND status IN ('pending', 'running')
        ORDER BY created_at DESC
        LIMIT 1
        """,
        target_id,
    )
    if active_operation is not None:
        raise api_error(
            409,
            "CONFLICT",
            "resource already has an active operation",
            {
                "state": state,
                "operation_id": str(active_operation["id"]),
                "operation_kind": active_operation["kind"],
            },
        )


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


async def replace_profile_secret_material(
    conn: asyncpg.Connection,
    *,
    profile_id: UUID,
    secret_values: dict[str, str],
) -> None:
    injection_ids = sorted(secret_values)
    await conn.execute(
        """
        DELETE FROM profile_secret_material
        WHERE profile_id = $1
          AND NOT (injection_id = ANY($2::text[]))
        """,
        profile_id,
        injection_ids,
    )
    for injection_id in injection_ids:
        ciphertext = encrypt_profile_secret_value(
            profile_id=profile_id,
            injection_id=injection_id,
            value=secret_values[injection_id],
        )
        await conn.execute(
            """
            INSERT INTO profile_secret_material (profile_id, injection_id, ciphertext)
            VALUES ($1, $2, $3)
            ON CONFLICT (profile_id, injection_id)
            DO UPDATE SET ciphertext = EXCLUDED.ciphertext,
                          updated_at = now()
            """,
            profile_id,
            injection_id,
            ciphertext,
        )


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


async def fetch_cvm_launch_profiles(
    conn: asyncpg.Connection,
    profile_ids: list[UUID],
    current_user: CurrentUser,
) -> list[asyncpg.Record]:
    rows = await conn.fetch(
        """
        SELECT id AS profile_id, entity_id, name, policy
        FROM entity_profiles
        WHERE id = ANY($1::uuid[])
          AND entity_id = $2
          AND deleted_at IS NULL
        ORDER BY name, id
        """,
        profile_ids,
        current_user.entity_id,
    )
    if len(rows) != len(profile_ids):
        raise api_error(404, "NOT_FOUND", "resource not found")
    return list(rows)


async def ensure_cvm_launch_profile_memberships(
    conn: asyncpg.Connection,
    profile_ids: list[UUID],
    current_user: CurrentUser,
) -> None:
    rows = await conn.fetch(
        """
        SELECT profile_id
        FROM profile_users
        WHERE profile_id = ANY($1::uuid[])
          AND user_id = $2
        """,
        profile_ids,
        current_user.id,
    )
    member_profile_ids = {row["profile_id"] for row in rows}
    for profile_id in profile_ids:
        if profile_id not in member_profile_ids:
            raise api_error(
                403,
                "FORBIDDEN",
                "profile membership is required",
                {"required": "profile_member", "profile_id": str(profile_id)},
            )


async def ensure_cvm_launch_ssh_keys(
    conn: asyncpg.Connection,
    ssh_key_ids: list[UUID],
    current_user: CurrentUser,
) -> None:
    rows = await conn.fetch(
        """
        SELECT id
        FROM ssh_keys
        WHERE id = ANY($1::uuid[])
          AND user_id = $2
          AND deleted_at IS NULL
        """,
        ssh_key_ids,
        current_user.id,
    )
    if len(rows) != len(ssh_key_ids):
        raise api_error(404, "NOT_FOUND", "resource not found")


async def fetch_live_security_cvm_id(conn: asyncpg.Connection, entity_id: UUID) -> UUID:
    security_cvm_id = await conn.fetchval(
        """
        SELECT id
        FROM security_cvms
        WHERE entity_id = $1
          AND state = 'RUNNING'
          AND deleted_at IS NULL
          AND ca_cert_pem IS NOT NULL
        ORDER BY created_at DESC
        LIMIT 1
        """,
        entity_id,
    )
    if security_cvm_id is None:
        raise api_error(
            409,
            "CONFLICT",
            "entity has no live Security CVM",
            {"state": "no_security_cvm"},
        )
    return security_cvm_id


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
    async with pool.acquire() as conn:
        return await fetch_cvm_rows_from_conn(conn, where_clause=where_clause, values=values)


async def fetch_cvm_resource_for_operation(conn: asyncpg.Connection, cvm_id: UUID) -> dict:
    rows = await fetch_cvm_rows_from_conn(conn, where_clause="c.id = $1", values=[cvm_id])
    if not rows:
        raise api_error(404, "NOT_FOUND", "resource not found")
    return cvm_resource(rows[0])


async def fetch_cvm_rows_from_conn(
    conn: asyncpg.Connection,
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
    return await conn.fetch(query, *values)


@router.post("/entities/{entity_id}/security-cvm", status_code=202)
async def create_security_cvm(
    entity_id: UUID,
    request: Request,
    body: SecurityCVMCreate,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    idempotency_key_value = require_idempotency_key(idempotency_key)
    current_user.require_entity(entity_id)
    current_user.require_permission("SECURITY_CVM_CONFIGURE")
    route = f"POST /api/v1/entities/{entity_id}/security-cvm"
    body_sha256 = request_body_sha256(await request.body())
    operation_id = uuid4()
    security_cvm_id = uuid4()
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

            existing = await fetch_security_cvm_row(conn, entity_id)
            if existing is not None:
                raise api_error(
                    409,
                    "CONFLICT",
                    "Security CVM already exists for entity",
                    {"state": "security_cvm_already_live"},
                )
            resolved = resolve_security_cvm_provision_config(body)
            fqdn = generated_cvm_fqdn(SECURITY_CVM_FQDN_PREFIX, resolved["base_domain"])
            compose_config = render_security_cvm_compose_config(resolved)
            try:
                await conn.execute(
                    """
                    INSERT INTO security_cvms (
                        id,
                        entity_id,
                        state,
                        fqdn,
                        instance_type,
                        region,
                        proxy_port,
                        expected_image_measurement,
                        compose_config
                    )
                    VALUES ($1, $2, 'PROVISIONING', $3, $4, $5, 8080, $6, $7)
                    """,
                    security_cvm_id,
                    entity_id,
                    fqdn,
                    resolved["instance_type"],
                    resolved["region"],
                    resolved["expected_image_measurement"],
                    compose_config,
                )
            except asyncpg.UniqueViolationError:
                raise api_error(
                    409,
                    "CONFLICT",
                    "Security CVM already exists for entity",
                    {"state": "security_cvm_already_live"},
                ) from None
            row = await conn.fetchrow(
                """
                INSERT INTO operations (
                    id,
                    kind,
                    status,
                    actor_id,
                    actor_email,
                    target_type,
                    target_id,
                    idempotency_key,
                    request_body_sha256,
                    progress_step,
                    progress_percent
                )
                VALUES ($1, $2, 'pending', $3, $4, 'security_cvm', $5, $6, $7, 'persist_tokens_and_stub', 10)
                RETURNING
                    id,
                    kind,
                    status::text AS status,
                    actor_id,
                    actor_email,
                    target_type,
                    target_id,
                    progress_step,
                    progress_percent,
                    result,
                    error,
                    result_disclosed_at,
                    created_at,
                    updated_at,
                    expires_at
                """,
                operation_id,
                SECURITY_CVM_PROVISION_KIND,
                current_user.id,
                current_user.email,
                security_cvm_id,
                idempotency_key_value,
                body_sha256,
            )
            response_body = operation_resource(row)
            await store_idempotency_response(
                conn,
                credential_id=str(current_user.id),
                idempotency_key=idempotency_key_value,
                route=route,
                body_sha256=body_sha256,
                status_code=202,
                response_body=response_body,
            )
            return response_body


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


def security_cvm_provider_app_id(row: asyncpg.Record | dict) -> str | None:
    metadata = json_payload(dict(row).get("metadata", {}))
    if not isinstance(metadata, dict):
        return None
    app_id = metadata.get("app_id")
    return app_id if isinstance(app_id, str) and app_id else None


def security_cvm_provider_deployment_id(row: asyncpg.Record | dict) -> str | None:
    metadata = json_payload(dict(row).get("metadata", {}))
    if not isinstance(metadata, dict):
        return None
    deployment_id = metadata.get("deployment_id") or metadata.get("app_id")
    return deployment_id if isinstance(deployment_id, str) and deployment_id else None


async def terminate_provider_security_cvm(*, app_id: str) -> None:
    from concrete_console.tee_provider import CvmProviderError, cvm_provider_from_settings

    try:
        await cvm_provider_from_settings().delete(app_id)
    except CvmProviderError as exc:
        raise api_error(
            502,
            "UPSTREAM_ERROR",
            "Security CVM provider termination failed",
            {"adapter": "cvm_provider", "reason": exc.code},
        ) from exc


async def deprovision_security_cvm_dns_records(row: asyncpg.Record | dict) -> set[str]:
    from concrete_console.dns_provider.cloudflare import CloudflareClient, CloudflareError

    record_fields = (
        ("txt_dns_record_id", dict(row).get("txt_dns_record_id")),
        ("cname_dns_record_id", dict(row).get("cname_dns_record_id")),
    )
    record_fields = tuple(
        (field, record_id) for field, record_id in record_fields if isinstance(record_id, str) and record_id
    )
    if not record_fields:
        return set()
    try:
        client = CloudflareClient.from_settings(zone_id_key="SECURITY_CVM_ZONE_ID")
    except CloudflareError as exc:
        log.warning(
            "security_cvm_dns_deprovision_skipped",
            security_cvm_id=str(dict(row).get("id")),
            reason=exc.code,
        )
        return set()
    deleted_fields: set[str] = set()
    for field, record_id in record_fields:
        try:
            await client.delete_record(record_id)
            deleted_fields.add(field)
        except CloudflareError as exc:
            log.warning(
                "security_cvm_dns_deprovision_failed",
                security_cvm_id=str(dict(row).get("id")),
                record_id=record_id,
                reason=exc.code,
            )
    return deleted_fields


@router.delete("/entities/{entity_id}/security-cvm")
async def delete_security_cvm(
    entity_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_entity(entity_id)
    current_user.require_permission("SECURITY_CVM_CONFIGURE")
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await lock_security_cvm_for_decommission(conn, entity_id)
            live_dev_cvm_count = await conn.fetchval(
                """
                SELECT count(*)
                FROM cvms
                WHERE entity_id = $1
                  AND deleted_at IS NULL
                  AND state <> 'TERMINATED'
                """,
                entity_id,
            )
            if live_dev_cvm_count:
                raise api_error(
                    409,
                    "CONFLICT",
                    "cannot decommission Security CVM while Dev CVMs exist",
                    {"state": "dev_cvms_in_entity", "dev_cvm_count": live_dev_cvm_count},
                )
            app_id = security_cvm_provider_app_id(row)
            if app_id is not None:
                await terminate_provider_security_cvm(app_id=app_id)
            deleted_dns_fields = await deprovision_security_cvm_dns_records(row)
            await conn.execute(
                """
                UPDATE service_principal_tokens
                SET deleted_at = now(),
                    deleted_by = $1
                WHERE principal_type = 'security_cvm'
                  AND principal_id = $2
                  AND deleted_at IS NULL
                """,
                current_user.id,
                row["id"],
            )
            terminated = await conn.fetchrow(
                """
                UPDATE security_cvms
                SET state = 'TERMINATED',
                    deleted_at = now(),
                    deleted_by = $1,
                    updated_at = now(),
                    txt_dns_record_id = CASE WHEN $3 THEN NULL ELSE txt_dns_record_id END,
                    cname_dns_record_id = CASE WHEN $4 THEN NULL ELSE cname_dns_record_id END
                WHERE id = $2
                RETURNING
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
                """,
                current_user.id,
                row["id"],
                "txt_dns_record_id" in deleted_dns_fields,
                "cname_dns_record_id" in deleted_dns_fields,
            )
            await insert_audit_event(
                conn,
                entity_id=entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="SECURITY_CVM_DECOMMISSIONED",
                target_type="security_cvm",
                target_id=row["id"],
                before={"state": row["state"]},
                after={"state": "TERMINATED"},
            )
            if deleted_dns_fields:
                await insert_audit_event(
                    conn,
                    entity_id=entity_id,
                    actor_id=current_user.id,
                    actor_email=current_user.email,
                    action="SUBDOMAIN_DEPROVISIONED",
                    target_type="security_cvm",
                    target_id=row["id"],
                    before={
                        "txt_dns_record_id": row["txt_dns_record_id"],
                        "cname_dns_record_id": row["cname_dns_record_id"],
                    },
                    after={
                        "txt_dns_record_id": None
                        if "txt_dns_record_id" in deleted_dns_fields
                        else row["txt_dns_record_id"],
                        "cname_dns_record_id": None
                        if "cname_dns_record_id" in deleted_dns_fields
                        else row["cname_dns_record_id"],
                    },
                )
    return security_cvm_resource(terminated)


@router.post("/entities/{entity_id}/security-cvm/actions/update", status_code=202)
async def update_security_cvm(
    entity_id: UUID,
    request: Request,
    idempotency_key: Annotated[str | None, Header(alias="Idempotency-Key")] = None,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Any:
    current_user.require_entity(entity_id)
    current_user.require_permission("SECURITY_CVM_CONFIGURE")
    idempotency_key_value = optional_idempotency_key(idempotency_key)
    route = f"POST /api/v1/entities/{entity_id}/security-cvm/actions/update"
    body_sha256 = request_body_sha256(await request.body())
    operation_id = uuid4()
    async with pool.acquire() as conn:
        async with conn.transaction():
            if idempotency_key_value is not None:
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

            row = await lock_security_cvm_for_decommission(conn, entity_id)
            await ensure_no_active_operation(conn, target_id=row["id"], state=row["state"])
            if row["state"] not in {"RUNNING", "STOPPED", "FAILED"}:
                raise api_error(
                    409,
                    "CONFLICT",
                    "cannot update Security CVM from current state",
                    {"state": row["state"]},
                )
            if security_cvm_provider_deployment_id(row) is None:
                raise api_error(
                    409,
                    "CONFLICT",
                    "Security CVM has no provider deployment to update",
                    {"state": "provider_deployment_missing"},
                )
            op_row = await conn.fetchrow(
                """
                INSERT INTO operations (
                    id,
                    kind,
                    status,
                    actor_id,
                    actor_email,
                    target_type,
                    target_id,
                    idempotency_key,
                    request_body_sha256,
                    progress_step,
                    progress_percent
                )
                VALUES ($1, 'security_cvm.update', 'pending', $2, $3, 'security_cvm', $4, $5, $6, 'queued', 0)
                RETURNING
                    id,
                    kind,
                    status::text AS status,
                    actor_id,
                    actor_email,
                    target_type,
                    target_id,
                    progress_step,
                    progress_percent,
                    result,
                    error,
                    result_disclosed_at,
                    created_at,
                    updated_at,
                    expires_at
                """,
                operation_id,
                current_user.id,
                current_user.email,
                row["id"],
                idempotency_key_value,
                body_sha256 if idempotency_key_value is not None else None,
            )
            response_body = operation_resource(op_row)
            if idempotency_key_value is not None:
                await store_idempotency_response(
                    conn,
                    credential_id=str(current_user.id),
                    idempotency_key=idempotency_key_value,
                    route=route,
                    body_sha256=body_sha256,
                    status_code=202,
                    response_body=response_body,
                )
            return response_body


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
        async with pool.acquire() as conn:
            return await run_security_cvm_attestation_probe(conn, row, current_user=current_user)
    return security_cvm_attestation_resource(row)


async def run_security_cvm_attestation_probe(conn: asyncpg.Connection, row: Any, *, current_user: CurrentUser) -> dict[str, Any]:
    from concrete_console.attestation import (
        AtlasVerifierClient,
        AttestationVerifierError,
        AttestationVerifierUnavailable,
        build_security_cvm_attestation_request,
    )

    try:
        verifier = AtlasVerifierClient.from_settings()
    except AttestationVerifierUnavailable:
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "security CVM attestation probe is not configured",
            {"component": "security_cvm_attestation_probe"},
        ) from None
    except AttestationVerifierError as exc:
        raise api_error(
            502,
            "UPSTREAM_ERROR",
            "security CVM attestation verifier is unavailable",
            {"adapter": "security_cvm", "attestation_error_code": exc.code, **exc.details},
        ) from exc

    from concrete_console.scheduler import (
        attestation_drift_kind,
        fetch_security_cvm_token_hashes,
        materialize_security_cvm_shade_policy_for_attestation,
    )
    from concrete_console.shade_provider.shade import ShadeError

    token_hashes = await fetch_security_cvm_token_hashes(conn, row_value(row, "id"))
    try:
        # Full runtime verification (never dev()): regenerate the shade policy so the probe
        # exercises compose-hash + bootchain + RTMR3 against the live quote, like provisioning.
        shade_policy = await materialize_security_cvm_shade_policy_for_attestation(row)
        request = build_security_cvm_attestation_request(
            row,
            token_hashes=token_hashes,
            console_url=load_settings().raw.get("CONSOLE_URL", "http://localhost:8000"),
            shade_policy=shade_policy,
        )
        report = await verifier.verify(request, timeout_seconds=30)
    except ShadeError as exc:
        raise api_error(
            502,
            "UPSTREAM_ERROR",
            "security CVM attestation probe failed",
            {"adapter": "shade", "reason": exc.code},
        ) from exc
    except AttestationVerifierError as exc:
        raise api_error(
            502,
            "UPSTREAM_ERROR",
            "security CVM attestation probe failed",
            {"adapter": "security_cvm", "attestation_error_code": exc.code, **exc.details},
        ) from exc

    drift_kind = attestation_drift_kind(
        expected_image_measurement=row_value(row, "expected_image_measurement"),
        persisted_image_measurement=row_value(row, "image_measurement"),
        persisted_rtmr3_digest=row_value(row, "rtmr3_digest"),
        reported_image_measurement=report.image_measurement,
        reported_rtmr3_digest=report.rtmr3_digest,
    )
    if drift_kind is not None:
        await record_security_cvm_attestation_drift(conn, row, report, drift_kind=drift_kind, current_user=current_user)
        raise api_error(
            409,
            "CONFLICT",
            "Security CVM attestation drift detected",
            {
                "state": "attestation_drift",
                "console_verdict": security_cvm_attestation_resource(row),
                "fresh_report": {
                    "image_measurement_seen": report.image_measurement,
                    "rtmr3_digest_seen": report.rtmr3_digest,
                    "drift_kind": drift_kind,
                },
            },
        )
    return await persist_security_cvm_attestation_probe(conn, row, report, current_user=current_user)


def row_value(row: Any, key: str) -> Any:
    return row[key]


async def record_security_cvm_attestation_drift(
    conn: asyncpg.Connection,
    row: Any,
    report: Any,
    *,
    drift_kind: str,
    current_user: CurrentUser,
) -> None:
    async with conn.transaction():
        await insert_audit_event(
            conn,
            entity_id=row_value(row, "entity_id"),
            actor_id=current_user.id,
            actor_email=current_user.email,
            action="SECURITY_CVM_ATTESTATION_DRIFT",
            target_type="security_cvm",
            target_id=row_value(row, "id"),
            before={
                "image_measurement": row_value(row, "image_measurement"),
                "rtmr3_digest": row_value(row, "rtmr3_digest"),
            },
            after={
                "image_measurement": report.image_measurement,
                "rtmr3_digest": report.rtmr3_digest,
                "drift_kind": drift_kind,
                "source": "on_demand",
            },
        )


async def persist_security_cvm_attestation_probe(
    conn: asyncpg.Connection,
    row: Any,
    report: Any,
    *,
    current_user: CurrentUser,
) -> dict[str, Any]:
    verified_at = datetime.now(timezone.utc)
    async with conn.transaction():
        await conn.execute(
            """
            UPDATE security_cvms
            SET image_measurement = $2,
                rtmr3_digest = $3,
                attestation_verified_at = $4,
                error_reason = NULL,
                updated_at = now()
            WHERE id = $1
              AND deleted_at IS NULL
            """,
            row_value(row, "id"),
            report.image_measurement,
            report.rtmr3_digest,
            verified_at,
        )
        await insert_audit_event(
            conn,
            entity_id=row_value(row, "entity_id"),
            actor_id=current_user.id,
            actor_email=current_user.email,
            action="SECURITY_CVM_ATTESTATION_VERIFIED",
            target_type="security_cvm",
            target_id=row_value(row, "id"),
            before={
                "image_measurement": row_value(row, "image_measurement"),
                "rtmr3_digest": row_value(row, "rtmr3_digest"),
            },
            after={
                "image_measurement": report.image_measurement,
                "rtmr3_digest": report.rtmr3_digest,
                "attestation_verified_at": verified_at.isoformat().replace("+00:00", "Z"),
                "source": "on_demand",
            },
        )
    updated = dict(row)
    updated["image_measurement"] = report.image_measurement
    updated["rtmr3_digest"] = report.rtmr3_digest
    updated["attestation_verified_at"] = verified_at
    updated["error_reason"] = None
    return security_cvm_attestation_resource(updated)


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
            metadata,
            compose_config,
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


async def lock_security_cvm_for_decommission(conn: asyncpg.Connection, entity_id: UUID) -> asyncpg.Record:
    row = await conn.fetchrow(
        """
        SELECT
            id,
            entity_id,
            state::text AS state,
            fqdn,
            metadata,
            txt_dns_record_id,
            cname_dns_record_id,
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
        FOR UPDATE
        """,
        entity_id,
    )
    if row is None:
        raise api_error(404, "NOT_FOUND", "resource not found")
    return row


@router.get("/traffic-logs")
async def list_traffic_logs(
    cvm_id: UUID | None = None,
    security_cvm_id: UUID | None = None,
    destination_host: str | None = Query(default=None, max_length=255),
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
    if destination_host is not None:
        clauses.append(f"tl.destination_host = {bind(destination_host)}")
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
            tl.bytes_transferred,
            tl.attributes
        FROM traffic_logs tl
        JOIN security_cvms sc ON sc.id = tl.security_cvm_id
        WHERE {' AND '.join(clauses)}
        ORDER BY tl.timestamp DESC, tl.id DESC
        LIMIT ${len(values)}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *values)
    next_cursor = traffic_log_cursor(rows[limit - 1]) if len(rows) > limit else None
    return list_page([traffic_log_resource(row) for row in rows[:limit]], next_cursor=next_cursor)


@router.get("/traffic-logs/summary")
async def list_traffic_log_host_summary(
    cvm_id: UUID | None = None,
    security_cvm_id: UUID | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_permission("TRAFFIC_LOGS_VIEW")
    clauses = ["sc.entity_id = $1", "tl.destination_host IS NOT NULL"]
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

    values.append(limit)
    query = f"""
        SELECT tl.destination_host AS host, count(*)::int AS count
        FROM traffic_logs tl
        JOIN security_cvms sc ON sc.id = tl.security_cvm_id
        WHERE {' AND '.join(clauses)}
        GROUP BY tl.destination_host
        ORDER BY count DESC, tl.destination_host ASC
        LIMIT ${len(values)}
    """
    async with pool.acquire() as conn:
        rows = await conn.fetch(query, *values)
    return {"hosts": [{"host": row["host"], "count": row["count"]} for row in rows]}


@router.get("/traffic-logs/timeseries")
async def list_traffic_log_timeseries(
    cvm_id: UUID | None = None,
    security_cvm_id: UUID | None = None,
    destination_host: str | None = Query(default=None, max_length=255),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    buckets: int = Query(default=TRAFFIC_TIMESERIES_DEFAULT_BUCKETS, ge=1, le=TRAFFIC_TIMESERIES_MAX_BUCKETS),
    granularity: str | None = Query(default=None, max_length=8),
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_permission("TRAFFIC_LOGS_VIEW")
    plan = resolve_traffic_timeseries(from_, to, buckets, granularity, now=datetime.now(timezone.utc))
    clauses = ["sc.entity_id = $1"]
    values: list[object] = [current_user.entity_id]

    def bind(value: object) -> str:
        values.append(value)
        return f"${len(values)}"

    clauses.append(f"tl.timestamp >= {bind(plan['lo'])}")
    clauses.append(f"tl.timestamp <= {bind(plan['hi'])}")
    if cvm_id is not None:
        clauses.append(f"tl.cvm_id = {bind(cvm_id)}")
    if security_cvm_id is not None:
        clauses.append(f"tl.security_cvm_id = {bind(security_cvm_id)}")
    if destination_host is not None:
        clauses.append(f"tl.destination_host = {bind(destination_host)}")

    rows = await fetch_traffic_timeseries_rows(pool, clauses, values, plan)
    return traffic_timeseries_payload(rows, plan)


async def fetch_traffic_timeseries_rows(
    pool: asyncpg.Pool,
    clauses: list[str],
    values: list[object],
    plan: dict,
) -> list[asyncpg.Record]:
    """Group traffic_logs into the plan's buckets with allowed/blocked counts.

    Calendar plans truncate to UTC ``date_trunc`` boundaries; the ``auto`` plan
    uses fixed ``bucket_seconds``-wide epoch buckets. Blocked is the SC policy
    convention HTTP 403; everything else (including an unset code) counts allowed.
    """
    params = list(values)
    params.append(TRAFFIC_BLOCK_CODE)
    block_param = f"${len(params)}"
    if plan["unit"] is not None:
        params.append(plan["unit"])
        # date_trunc on the UTC wall-clock so day/week/month align to UTC boundaries.
        bucket_expr = f"date_trunc(${len(params)}, tl.timestamp AT TIME ZONE 'UTC')"
    else:
        params.append(plan["bucket_seconds"])
        width_param = f"${len(params)}"
        bucket_expr = f"to_timestamp(floor(extract(epoch FROM tl.timestamp) / {width_param}) * {width_param})"
    query = f"""
        SELECT
            {bucket_expr} AS bucket,
            count(*) FILTER (WHERE tl.response_code IS DISTINCT FROM {block_param})::int AS allowed,
            count(*) FILTER (WHERE tl.response_code = {block_param})::int AS blocked
        FROM traffic_logs tl
        JOIN security_cvms sc ON sc.id = tl.security_cvm_id
        WHERE {' AND '.join(clauses)}
        GROUP BY bucket
        ORDER BY bucket
    """
    async with pool.acquire() as conn:
        return await conn.fetch(query, *params)


@router.get("/operations/{operation_id}")
async def get_operation(
    operation_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    async with pool.acquire() as conn:
        row = await fetch_operation_for_read(conn, operation_id)
    if row is None:
        raise api_error(404, "NOT_FOUND", "resource not found")
    authorize_operation_read(row, current_user)
    return await operation_resource_for_read(pool, row, current_user)


async def fetch_operation_for_read(
    conn: asyncpg.Connection,
    operation_id: UUID,
    *,
    lock: bool = False,
) -> asyncpg.Record | None:
    query = OPERATION_READ_SELECT
    if lock:
        query = f"{query}\nFOR UPDATE OF o"
    return await conn.fetchrow(query, operation_id)


def authorize_operation_read(row: Any, current_user: CurrentUser) -> None:
    if row["actor_id"] == current_user.id:
        return
    if "PLATFORM_OPERATOR" not in current_user.permissions and row["actor_entity_id"] != current_user.entity_id:
        raise api_error(404, "NOT_FOUND", "resource not found")
    required_permission = OPERATION_KIND_PERMISSIONS.get(row["kind"])
    if required_permission is None:
        raise api_error(404, "NOT_FOUND", "resource not found")
    current_user.require_permission(required_permission)


async def operation_resource_for_read(pool: asyncpg.Pool, row: Any, current_user: CurrentUser) -> dict:
    if not operation_has_security_cvm_provision_result(row):
        return operation_resource(row)
    if row["actor_id"] == current_user.id and row["result_disclosed_at"] is None:
        async with pool.acquire() as conn:
            async with conn.transaction():
                locked = await fetch_operation_for_read(conn, row["id"], lock=True)
                if locked is None:
                    raise api_error(404, "NOT_FOUND", "resource not found")
                authorize_operation_read(locked, current_user)
                if locked["actor_id"] == current_user.id and locked["result_disclosed_at"] is None:
                    # One-time disclosure: hand the full result (incl. the CA-export
                    # token) to the initiating actor, then scrub the plaintext secrets
                    # from the STORED result so they don't linger at rest in the
                    # operations table after this single read. Subsequent reads already
                    # redact in the response (below); this also redacts in the DB.
                    disclosed = operation_resource(locked)
                    await conn.execute(
                        "UPDATE operations SET result_disclosed_at = now(), result = $2::jsonb WHERE id = $1",
                        locked["id"],
                        json.dumps(redacted_security_cvm_provision_result(locked["result"])),
                    )
                    await insert_audit_event(
                        conn,
                        entity_id=current_user.entity_id,
                        actor_id=current_user.id,
                        actor_email=current_user.email,
                        action="OPERATION_RESULT_DISCLOSED",
                        target_type="operation",
                        target_id=locked["id"],
                        after=operation_result_disclosed_audit_payload(locked),
                    )
                    return disclosed
                row = locked
    return operation_resource(operation_row_with_result(row, redacted_security_cvm_provision_result(row["result"])))


def operation_has_security_cvm_provision_result(row: Any) -> bool:
    return row["kind"] == SECURITY_CVM_PROVISION_KIND and row["status"] == "succeeded" and row["result"] is not None


def redacted_security_cvm_provision_result(result: Any) -> Any:
    result = json_payload(result)
    if not isinstance(result, dict):
        return result
    redacted = dict(result)
    for field in SECURITY_CVM_PROVISION_SECRET_FIELDS:
        if field in redacted:
            redacted[field] = SECURITY_CVM_PROVISION_REDACTION
    return redacted


def operation_row_with_result(row: Any, result: Any) -> dict[str, Any]:
    updated = dict(row)
    updated["result"] = result
    return updated


def operation_result_disclosed_audit_payload(row: Any) -> dict[str, Any]:
    return {
        "operation_id": str(row["id"]),
        "kind": row["kind"],
        "target_type": row["target_type"],
        "target_id": str(row["target_id"]) if row["target_id"] else None,
        "redacted_after_first_read": list(SECURITY_CVM_PROVISION_SECRET_FIELDS),
    }


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


def entity_cursor(row: asyncpg.Record) -> str:
    return f"{timestamp(row['created_at'])}|{row['id']}"


def parse_entity_cursor(cursor: str | None) -> tuple[datetime, UUID] | None:
    if cursor is None:
        return None
    try:
        created_at_raw, entity_id_raw = cursor.split("|", 1)
        created_at = datetime.fromisoformat(created_at_raw.replace("Z", "+00:00"))
        entity_id = UUID(entity_id_raw)
    except (ValueError, TypeError):
        raise api_error(
            422,
            "VALIDATION_ERROR",
            "invalid cursor",
            {"errors": [{"type": "invalid_cursor", "field": "cursor"}]},
        ) from None
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return created_at, entity_id


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
