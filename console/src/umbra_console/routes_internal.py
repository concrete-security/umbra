from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
from typing import Annotated, Any
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Depends, Header, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from umbra_console.db import get_pool
from umbra_console.errors import api_error
from umbra_console.crypto import sha256_hex
from umbra_console.idempotency import advisory_lock_key, request_body_sha256
from umbra_console.internal_auth import (
    CurrentServicePrincipal,
    require_dev_cvm_control_principal,
    require_security_cvm_ingest_principal,
)
from umbra_console.log_config import logger
from umbra_console.profile_secrets import expand_policy_secret_values_for_owner
from umbra_console.resources import json_payload, timestamp

log = logger()

router = APIRouter(prefix="/internal")

TRAFFIC_LOG_IDEMPOTENCY_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
TRAFFIC_LOG_ROUTE = "POST /internal/traffic-logs"
TRAFFIC_LOG_MAX_BODY_BYTES = 4 * 1024 * 1024
TRAFFIC_LOG_TIMESTAMP_SKEW = timedelta(minutes=10)
TRAFFIC_LOG_PRINCIPAL_LOGS_PER_MINUTE = 5000
TRAFFIC_LOG_VOLUME_LOCK_KEY = "traffic-log-volume"
TRAFFIC_LOG_ATTRIBUTES_MAX_KEYS = 4
TRAFFIC_LOG_ATTRIBUTE_VALUE_MAX_LEN = 256
TRAFFIC_LOG_ATTRIBUTE_NAME_RE = re.compile(r"^[a-z_]{1,32}$")
TRAFFIC_LOG_PATH_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


class TrafficLogIn(BaseModel):
    # `ignore` (not `forbid`) on this internal SC->Console producer/consumer
    # contract: a newer SC image MAY ship traffic fields this Console does not
    # model yet, and ingest must tolerate them rather than 422-rejecting whole
    # batches during an SC-before-Console rollout. Unknown fields are dropped.
    model_config = ConfigDict(extra="ignore")

    timestamp: datetime
    cvm_id: UUID | None = None
    source_ip: str = Field(min_length=1, max_length=45)
    destination_ip: str = Field(min_length=1, max_length=45)
    destination_host: str | None = Field(default=None, max_length=255)
    protocol: str = Field(min_length=1, max_length=20)
    port: int = Field(ge=0, le=65535)
    method: str | None = Field(default=None, max_length=20)
    path: str | None = Field(default=None, max_length=2000)
    response_code: int | None = Field(default=None, ge=0, le=599)
    # SC enforcement decision ("allowed", a block reason, "websocket_frame_dropped").
    # Optional so an older SC that predates it still ingests (decision stays NULL).
    decision: str | None = Field(default=None, max_length=64)
    bytes_transferred: int = Field(ge=0)
    attributes: dict[str, str] = Field(default_factory=dict)

    @field_validator("attributes")
    @classmethod
    def _validate_attributes(cls, value: dict[str, str]) -> dict[str, str]:
        if not isinstance(value, dict):
            raise ValueError("attributes must be a mapping")
        if len(value) > TRAFFIC_LOG_ATTRIBUTES_MAX_KEYS:
            raise ValueError(
                f"attributes contains more than {TRAFFIC_LOG_ATTRIBUTES_MAX_KEYS} entries"
            )
        for name, attribute_value in value.items():
            if not isinstance(name, str) or not TRAFFIC_LOG_ATTRIBUTE_NAME_RE.fullmatch(name):
                raise ValueError(f"invalid attribute name: {name!r}")
            if not isinstance(attribute_value, str) or len(attribute_value) > TRAFFIC_LOG_ATTRIBUTE_VALUE_MAX_LEN:
                raise ValueError(f"invalid attribute value for {name!r}")
        return value

    @field_validator("path")
    @classmethod
    def _validate_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if (
            not value.startswith("/")
            or "?" in value
            or "#" in value
            or "\\" in value
            or TRAFFIC_LOG_PATH_CONTROL_RE.search(value)
        ):
            raise ValueError("path must be a path-only origin-form value")
        return value


class TrafficLogBatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idempotency_key: str = Field(min_length=1, max_length=128)
    logs: list[TrafficLogIn] = Field(min_length=1, max_length=1000)


@router.get("/sc-control/cvms", response_model=None)
async def list_sc_control_cvms(
    response: Response,
    if_none_match: Annotated[str | None, Header(alias="If-None-Match")] = None,
    current_principal: CurrentServicePrincipal = Depends(require_security_cvm_ingest_principal),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict[str, Any] | Response:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT
                c.id,
                c.fqdn,
                c.policy_version,
                c.updated_at,
                c.owner_id,
                spt.token_hash AS proxy_token_hash,
                COALESCE(
                    (
                        SELECT jsonb_object_agg(
                                   usm.name,
                                   jsonb_build_object(
                                       'ciphertext', usm.ciphertext,
                                       'allowed_hosts', usm.allowed_hosts
                                   )
                               )
                        FROM user_secret_material usm
                        WHERE usm.user_id = c.owner_id
                    ),
                    '{}'::jsonb
                ) AS owner_secret_material,
                COALESCE(
                    jsonb_agg(
                        jsonb_build_object(
                            'profile_id', ep.id,
                            'policy', ep.policy,
                            'secret_material', COALESCE(
                                (
                                    SELECT jsonb_object_agg(psm.injection_id, psm.ciphertext ORDER BY psm.injection_id)
                                    FROM profile_secret_material psm
                                    WHERE psm.profile_id = ep.id
                                ),
                                '{}'::jsonb
                            )
                        )
                        ORDER BY cp.attached_at, cp.profile_id
                    ) FILTER (WHERE ep.id IS NOT NULL),
                    '[]'::jsonb
                ) AS profile_policies
            FROM cvms c
            JOIN service_principal_tokens spt
              ON spt.principal_type = 'dev_cvm'
             AND spt.principal_id = c.id
             AND spt.purpose = 'PROXY_AUTH'
             AND spt.deleted_at IS NULL
             AND (spt.expires_at IS NULL OR spt.expires_at > now())
            LEFT JOIN cvm_profiles cp ON cp.cvm_id = c.id
            LEFT JOIN entity_profiles ep
              ON ep.id = cp.profile_id
             AND ep.entity_id = c.entity_id
             AND ep.deleted_at IS NULL
            WHERE c.entity_id = $1
              AND c.deleted_at IS NULL
              AND c.state IN ('RUNNING', 'PROVISIONING')
            GROUP BY c.id, c.fqdn, c.policy_version, c.updated_at, c.owner_id, spt.token_hash
            ORDER BY c.updated_at, c.id
            """,
            current_principal.entity_id,
        )
    body = {
        "entries": [
            {
                "cvm_id": str(row["id"]),
                "fqdn": row["fqdn"],
                "proxy_token_hash": row["proxy_token_hash"],
                "merged_policy": merge_profile_policies(
                    json_payload(row["profile_policies"]),
                    owner_id=row["owner_id"],
                    owner_secrets=json_payload(row["owner_secret_material"]),
                    cvm_id=row["id"],
                ),
                "policy_version": row["policy_version"],
                "updated_at": timestamp(row["updated_at"]),
            }
            for row in rows
        ]
    }
    etag = sc_control_etag(body)
    async with pool.acquire() as conn:
        await record_sc_control_pull_observation(
            conn,
            security_cvm_id=current_principal.principal_id,
            entity_id=current_principal.entity_id,
            etag=etag,
            entry_count=len(rows),
        )
    if etag_matches(if_none_match, etag):
        return Response(status_code=304, headers={"ETag": etag})
    response.headers["ETag"] = etag
    return body


@router.get("/dev-control/security-cvm-atls-policy", response_model=None)
async def get_dev_security_cvm_atls_policy(
    response: Response,
    current_principal: CurrentServicePrincipal = Depends(require_dev_cvm_control_principal),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict[str, Any]:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                c.id AS cvm_id,
                c.security_cvm_id,
                sc.fqdn AS security_cvm_fqdn,
                sc.ca_cert_pem,
                sc.metadata,
                sc.expected_image_measurement,
                sc.image_measurement,
                sc.attestation_verified_at,
                sc.error_reason
            FROM cvms c
            JOIN security_cvms sc
              ON sc.id = c.security_cvm_id
             AND sc.entity_id = c.entity_id
            WHERE c.id = $1
              AND c.entity_id = $2
              AND c.deleted_at IS NULL
              AND c.state IN ('PROVISIONING', 'RUNNING')
              AND sc.deleted_at IS NULL
              AND sc.state = 'RUNNING'
            """,
            current_principal.principal_id,
            current_principal.entity_id,
        )
    if row is None:
        raise api_error(409, "CONFLICT", "Security CVM policy is unavailable", {"state": "security_cvm_unavailable"})
    metadata = json_payload(row["metadata"] or {})
    policy = metadata.get("atls_policy") if isinstance(metadata, dict) else None
    if not isinstance(policy, dict):
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Security CVM aTLS policy has not been materialized",
            {"component": "security_cvm_atls_policy"},
        )
    ca_cert_pem = row["ca_cert_pem"]
    if not isinstance(ca_cert_pem, str) or not ca_cert_pem:
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Security CVM CA certificate is unavailable",
            {"component": "security_cvm_ca"},
        )
    expected = row["expected_image_measurement"]
    actual = row["image_measurement"]
    if (
        expected is None
        or actual != expected
        or row["attestation_verified_at"] is None
        or row["error_reason"] == "ATTESTATION_DRIFT"
    ):
        raise api_error(
            409,
            "CONFLICT",
            "Security CVM attestation is not currently verified",
            {"state": "security_cvm_attestation_unverified"},
        )
    response.headers["Cache-Control"] = "no-store"
    return {
        "cvm_id": str(row["cvm_id"]),
        "security_cvm_id": str(row["security_cvm_id"]),
        "security_cvm_fqdn": row["security_cvm_fqdn"],
        "ca_cert_sha256": sha256_hex(ca_cert_pem),
        "atls_policy": policy,
        "image_measurement": actual,
        "attestation_verified_at": timestamp(row["attestation_verified_at"]),
    }


@router.get("/dev-control/security-cvm-ca", response_model=None)
async def get_dev_security_cvm_ca(
    response: Response,
    current_principal: CurrentServicePrincipal = Depends(require_dev_cvm_control_principal),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict[str, Any]:
    """Serve the current SC mitmproxy CA to an attached Dev CVM for runtime re-install.

    The Dev egress forwarder polls this so the sandbox can follow SC CA rotation without a
    fleet-wide ``cvm.update``. Returns the *public* CA cert only (already delivered to the Dev
    CVM as launch material); gated identically to the SC aTLS policy route — same control-token
    principal, same verified-attestation requirement.
    """
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            """
            SELECT
                c.id AS cvm_id,
                c.security_cvm_id,
                sc.fqdn AS security_cvm_fqdn,
                sc.ca_cert_pem,
                sc.expected_image_measurement,
                sc.image_measurement,
                sc.attestation_verified_at,
                sc.error_reason
            FROM cvms c
            JOIN security_cvms sc
              ON sc.id = c.security_cvm_id
             AND sc.entity_id = c.entity_id
            WHERE c.id = $1
              AND c.entity_id = $2
              AND c.deleted_at IS NULL
              AND c.state IN ('PROVISIONING', 'RUNNING')
              AND sc.deleted_at IS NULL
              AND sc.state = 'RUNNING'
            """,
            current_principal.principal_id,
            current_principal.entity_id,
        )
    if row is None:
        raise api_error(409, "CONFLICT", "Security CVM CA is unavailable", {"state": "security_cvm_unavailable"})
    ca_cert_pem = row["ca_cert_pem"]
    if not isinstance(ca_cert_pem, str) or not ca_cert_pem:
        raise api_error(
            503,
            "SERVICE_UNAVAILABLE",
            "Security CVM CA certificate is unavailable",
            {"component": "security_cvm_ca"},
        )
    expected = row["expected_image_measurement"]
    actual = row["image_measurement"]
    if (
        expected is None
        or actual != expected
        or row["attestation_verified_at"] is None
        or row["error_reason"] == "ATTESTATION_DRIFT"
    ):
        raise api_error(
            409,
            "CONFLICT",
            "Security CVM attestation is not currently verified",
            {"state": "security_cvm_attestation_unverified"},
        )
    response.headers["Cache-Control"] = "no-store"
    return {
        "cvm_id": str(row["cvm_id"]),
        "security_cvm_id": str(row["security_cvm_id"]),
        "security_cvm_fqdn": row["security_cvm_fqdn"],
        "ca_cert_sha256": sha256_hex(ca_cert_pem),
        "ca_cert_pem": ca_cert_pem,
        "attestation_verified_at": timestamp(row["attestation_verified_at"]),
    }


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
            await enforce_traffic_log_volume_limit(
                conn,
                security_cvm_id=current_principal.principal_id,
                row_count=len(body.logs),
            )
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
                    bytes_transferred,
                    attributes,
                    decision
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::jsonb, $15)
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
                        json.dumps(log.attributes, sort_keys=True),
                        log.decision,
                    )
                    for log in body.logs
                ],
            )
    return {"accepted": len(body.logs), "deduplicated": False}


def merge_profile_policies(
    profile_rows: list[dict[str, Any]],
    *,
    owner_id: Any = None,
    owner_secrets: dict[str, Any] | None = None,
    cvm_id: Any = None,
) -> dict[str, Any]:
    policies: list[dict[str, Any]] = []
    for row in profile_rows:
        policy = json_payload(row.get("policy", {}))
        if isinstance(policy, dict):
            secret_material = json_payload(row.get("secret_material", {}))
            if not isinstance(secret_material, dict):
                secret_material = {}
            profile_id = row.get("profile_id", "")

            def on_unresolved(
                reason: str,
                outcome: str,
                injection_id: str,
                secret_name: str,
                profile_id: Any = profile_id,
            ) -> None:
                log.warning(
                    "user_secret_injection_unresolved",
                    cvm_id=str(cvm_id) if cvm_id else None,
                    owner_id=str(owner_id) if owner_id else None,
                    profile_id=str(profile_id),
                    injection_id=injection_id,
                    secret_name=secret_name,
                    reason=reason,
                    outcome=outcome,
                )

            policies.append(
                expand_policy_secret_values_for_owner(
                    profile_id=profile_id,
                    policy=policy,
                    secret_material=secret_material,
                    owner_id=owner_id,
                    owner_secrets=owner_secrets if isinstance(owner_secrets, dict) else None,
                    on_unresolved=on_unresolved,
                )
            )
    egress_boundary_policies = [policy for policy in policies if policy.get("egress_boundary") is True]
    allowed_destination_policies = egress_boundary_policies or policies
    merged = {
        "allowed_destinations": merge_union_lists(allowed_destination_policies, "allowed_destinations"),
        "blocked_destinations": merge_intersection_lists(policies, "blocked_destinations"),
        "secret_patterns": merge_union_lists(policies, "secret_patterns"),
        "secret_injections": merge_union_lists(policies, "secret_injections"),
        "sandbox_env": merge_sandbox_env(policies),
    }
    # Only surface the key when a marker exists: keeps merged_policy (and its
    # content-derived ETag) byte-identical for the common case, and bounds the
    # blast radius if an old SC image that predates the field is polled before
    # it is upgraded (SC-image-before-Console rollout — see security-cvm spec).
    unfulfilled = merge_union_lists(policies, "unfulfilled_secret_injections")
    if unfulfilled:
        merged["unfulfilled_secret_injections"] = unfulfilled
    return merged


def merge_union_lists(policies: list[dict[str, Any]], field: str) -> list[Any]:
    merged: list[Any] = []
    seen: set[str] = set()
    for policy in policies:
        value = policy.get(field, [])
        if not isinstance(value, list):
            continue
        for item in value:
            key = canonical_json(item)
            if key not in seen:
                seen.add(key)
                merged.append(item)
    return merged


def merge_intersection_lists(policies: list[dict[str, Any]], field: str) -> list[Any]:
    if not policies:
        return []
    first_items = policies[0].get(field, [])
    if not isinstance(first_items, list):
        first_items = []
    common = {canonical_json(item) for item in first_items}
    for policy in policies[1:]:
        items = policy.get(field, [])
        if not isinstance(items, list):
            items = []
        common &= {canonical_json(item) for item in items}
    merged: list[Any] = []
    seen: set[str] = set()
    for item in first_items:
        key = canonical_json(item)
        if key in common and key not in seen:
            seen.add(key)
            merged.append(item)
    return merged


def merge_sandbox_env(policies: list[dict[str, Any]]) -> list[dict[str, str]]:
    merged: dict[str, str] = {}
    conflicts: list[str] = []
    for policy in policies:
        sandbox_env = policy.get("sandbox_env", {})
        if not isinstance(sandbox_env, dict):
            continue
        for name, value in sandbox_env.items():
            if not isinstance(name, str) or not isinstance(value, str):
                continue
            existing = merged.get(name)
            if existing is not None and existing != value:
                conflicts.append(name)
                continue
            merged[name] = value
    if conflicts:
        raise api_error(
            409,
            "CONFLICT",
            "attached profiles contain conflicting sandbox_env values",
            {"state": "sandbox_env_conflict", "names": sorted(set(conflicts))},
        )
    return [{"name": name, "value": merged[name]} for name in sorted(merged)]


def sc_control_etag(body: dict[str, Any]) -> str:
    return f'"{hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()}"'


async def record_sc_control_pull_observation(
    conn: asyncpg.Connection,
    *,
    security_cvm_id: UUID,
    entity_id: UUID,
    etag: str,
    entry_count: int,
) -> None:
    await conn.execute(
        """
        UPDATE security_cvms
        SET last_policy_pull_at = now(),
            last_policy_pull_etag = $3,
            last_policy_pull_entry_count = $4
        WHERE id = $1
          AND entity_id = $2
          AND deleted_at IS NULL
        """,
        security_cvm_id,
        entity_id,
        etag,
        entry_count,
    )


def etag_matches(if_none_match: str | None, etag: str) -> bool:
    if if_none_match is None:
        return False
    candidates = {candidate.strip() for candidate in if_none_match.split(",")}
    return "*" in candidates or etag in candidates or etag.strip('"') in candidates


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


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


async def enforce_traffic_log_volume_limit(
    conn: asyncpg.Connection,
    *,
    security_cvm_id: UUID,
    row_count: int,
) -> None:
    await conn.execute(
        "SELECT pg_advisory_xact_lock($1)",
        advisory_lock_key(
            credential_id=str(security_cvm_id),
            idempotency_key=TRAFFIC_LOG_VOLUME_LOCK_KEY,
            route=TRAFFIC_LOG_ROUTE,
        ),
    )
    current_count = await conn.fetchval(
        """
        SELECT COALESCE(sum(row_count), 0)::int
        FROM traffic_log_batches
        WHERE security_cvm_id = $1
          AND accepted_at > now() - INTERVAL '1 minute'
        """,
        security_cvm_id,
    )
    if (current_count or 0) + row_count > TRAFFIC_LOG_PRINCIPAL_LOGS_PER_MINUTE:
        raise api_error(
            429,
            "RATE_LIMITED",
            "traffic log volume rate limit exceeded",
            {"retry_after_seconds": 60, "limit": "traffic_log_principal_logs"},
            headers={"Retry-After": "60"},
        )


def ensure_aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
