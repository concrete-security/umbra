"""User-authorized local workspaces. Enrollment does not attest the laptop."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import secrets
from typing import Any
from uuid import UUID, uuid4

import asyncpg
from fastapi import APIRouter, Depends, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator

from umbra_console.audit import insert_audit_event
from umbra_console.auth import CurrentUser, require_current_user
from umbra_console.crypto import sha256_hex
from umbra_console.db import get_pool
from umbra_console.errors import api_error
from umbra_console.resources import json_payload, timestamp
from umbra_console.routes import fetch_cvm_launch_profiles, ensure_cvm_launch_profile_memberships, ensure_user_secret_references

router = APIRouter(prefix="/api/v1/local-workspaces")
LEASE_SECONDS = 300


class LocalWorkspaceCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    profile_ids: list[UUID] = Field(min_length=1, max_length=16)

    @field_validator("profile_ids")
    @classmethod
    def distinct_profiles(cls, values: list[UUID]) -> list[UUID]:
        if len(set(values)) != len(values):
            raise ValueError("profile IDs must be distinct")
        return values


def security_bundle(row: Any) -> dict:
    metadata = json_payload(row["metadata"] or {})
    policy = metadata.get("atls_policy") if isinstance(metadata, dict) else None
    if (row["state"] != "RUNNING" or row["deleted_at"] is not None
        or not row["expected_image_measurement"] or row["image_measurement"] != row["expected_image_measurement"]
        or row["attestation_verified_at"] is None or row["error_reason"] == "ATTESTATION_DRIFT"
        or not isinstance(policy, dict) or policy.get("disable_runtime_verification", False)
        or any(not policy.get(key) for key in ("expected_bootchain", "app_compose", "os_image_hash"))
        or not row["fqdn"] or not row["ca_cert_pem"]):
        raise api_error(409, "CONFLICT", "verified Security CVM material is unavailable")
    return {"security_cvm_id": str(row["id"]), "security_cvm_fqdn": row["fqdn"],
            "atls_policy": policy, "ca_pem": row["ca_cert_pem"], "ca_sha256": sha256_hex(row["ca_cert_pem"])}


async def authorize_profiles(conn: asyncpg.Connection, ids: list[UUID], user: CurrentUser) -> None:
    user.require_permission("CVM_LAUNCH")
    rows = await fetch_cvm_launch_profiles(conn, ids, user)
    await ensure_cvm_launch_profile_memberships(conn, ids, user)
    await ensure_user_secret_references(conn, profile_rows=rows, user_id=user.id, context="launcher")


async def current_security(conn: asyncpg.Connection, entity_id: UUID, sc_id: UUID | None = None) -> dict:
    row = await conn.fetchrow("""
        SELECT * FROM security_cvms WHERE entity_id = $1 AND deleted_at IS NULL
          AND ($2::uuid IS NULL OR id = $2) ORDER BY created_at DESC LIMIT 1
    """, entity_id, sc_id)
    if row is None:
        raise api_error(409, "CONFLICT", "a running Security CVM is required")
    return security_bundle(row)


@router.post("", status_code=201)
async def create_local_workspace(
    body: LocalWorkspaceCreate, response: Response,
    current_user: CurrentUser = Depends(require_current_user), pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    async with pool.acquire() as conn:
        async with conn.transaction():
            await authorize_profiles(conn, body.profile_ids, current_user)
            # Serialize admission per owner, including concurrent starts in different folders.
            await conn.fetchval("SELECT id FROM users WHERE id = $1 FOR UPDATE", current_user.id)
            count = await conn.fetchval("""SELECT count(*) FROM local_workspaces
                WHERE owner_id = $1 AND revoked_at IS NULL AND expires_at > now()""", current_user.id)
            if count >= 16:
                raise api_error(409, "CONFLICT", "maximum active local workspaces reached")
            bundle = await current_security(conn, current_user.entity_id)
            workspace_id, token = uuid4(), secrets.token_urlsafe(32)
            expires = datetime.now(timezone.utc) + timedelta(seconds=LEASE_SECONDS)
            await conn.execute("""INSERT INTO local_workspaces
                (id, entity_id, owner_id, security_cvm_id, profile_ids, proxy_token_hash, expires_at)
                VALUES ($1,$2,$3,$4,$5,$6,$7)""", workspace_id, current_user.entity_id, current_user.id,
                UUID(bundle["security_cvm_id"]), body.profile_ids, sha256_hex(token), expires)
            await insert_audit_event(conn, entity_id=current_user.entity_id, actor_id=current_user.id,
                actor_email=current_user.email, action="LOCAL_WORKSPACE_STARTED", target_type="local_workspace",
                target_id=workspace_id, after={"profile_ids": [str(v) for v in body.profile_ids],
                "security_cvm_id": bundle["security_cvm_id"], "assurance": "local-preview"})
    response.headers["Cache-Control"] = "no-store"
    return {**bundle, "id": str(workspace_id), "proxy_token": token, "expires_at": timestamp(expires)}


@router.post("/{workspace_id}/renew")
async def renew_local_workspace(
    workspace_id: UUID, response: Response,
    current_user: CurrentUser = Depends(require_current_user), pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow("""SELECT * FROM local_workspaces WHERE id=$1 AND owner_id=$2
                AND entity_id=$3 AND revoked_at IS NULL AND expires_at > now() FOR UPDATE""",
                workspace_id, current_user.id, current_user.entity_id)
            if row is None:
                raise api_error(404, "NOT_FOUND", "active local workspace not found")
            await authorize_profiles(conn, list(row["profile_ids"]), current_user)
            bundle = await current_security(conn, current_user.entity_id, row["security_cvm_id"])
            expires = datetime.now(timezone.utc) + timedelta(seconds=LEASE_SECONDS)
            await conn.execute("UPDATE local_workspaces SET expires_at=$2, updated_at=now() WHERE id=$1", workspace_id, expires)
    response.headers["Cache-Control"] = "no-store"
    return {**bundle, "id": str(workspace_id), "expires_at": timestamp(expires)}


@router.delete("/{workspace_id}", status_code=204)
async def revoke_local_workspace(
    workspace_id: UUID, current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow("""UPDATE local_workspaces SET revoked_at=now(), updated_at=now()
                WHERE id=$1 AND owner_id=$2 AND entity_id=$3 AND revoked_at IS NULL RETURNING id""",
                workspace_id, current_user.id, current_user.entity_id)
            if row:
                await insert_audit_event(conn, entity_id=current_user.entity_id, actor_id=current_user.id,
                    actor_email=current_user.email, action="LOCAL_WORKSPACE_STOPPED", target_type="local_workspace",
                    target_id=workspace_id)
    return Response(status_code=204)


async def local_control_entries(conn: asyncpg.Connection, entity_id: UUID, security_cvm_id: UUID) -> list[dict]:
    # The all-profile membership check prevents removals from yielding a weaker partial policy.
    rows = await conn.fetch("""
        SELECT l.*, COALESCE((SELECT jsonb_object_agg(us.name, jsonb_build_object(
            'ciphertext',us.ciphertext,'allowed_hosts',us.allowed_hosts))
            FROM user_secret_material us WHERE us.user_id=l.owner_id), '{}'::jsonb) AS owner_secret_material,
            (SELECT jsonb_agg(jsonb_build_object('profile_id',ep.id,'policy',ep.policy,
                'secret_material',COALESCE((SELECT jsonb_object_agg(ps.injection_id,ps.ciphertext)
                    FROM profile_secret_material ps WHERE ps.profile_id=ep.id),'{}'::jsonb)) ORDER BY ep.id)
             FROM entity_profiles ep WHERE ep.id=ANY(l.profile_ids)) AS profile_policies
        FROM local_workspaces l JOIN users u ON u.id=l.owner_id
        WHERE l.entity_id=$1 AND l.security_cvm_id=$2 AND l.revoked_at IS NULL AND l.expires_at > now()
          AND u.entity_id=l.entity_id AND u.deleted_at IS NULL AND u.deactivated_at IS NULL
          AND EXISTS (SELECT 1 FROM user_permissions up WHERE up.user_id=u.id AND up.permission='CVM_LAUNCH')
          AND cardinality(l.profile_ids)=(SELECT count(*) FROM entity_profiles ep
            JOIN profile_users pu ON pu.profile_id=ep.id AND pu.user_id=l.owner_id
            WHERE ep.id=ANY(l.profile_ids) AND ep.entity_id=l.entity_id AND ep.deleted_at IS NULL)
        ORDER BY l.id
    """, entity_id, security_cvm_id)
    # Deferred import avoids a router cycle.
    from umbra_console.routes_internal import merge_profile_policies
    return [{"local_workspace_id": str(row["id"]), "proxy_token_hash": row["proxy_token_hash"],
             "expires_at": timestamp(row["expires_at"]), "updated_at": timestamp(row["updated_at"]),
             "policy_version": 1, "merged_policy": merge_profile_policies(json_payload(row["profile_policies"]),
                 owner_id=row["owner_id"], owner_secrets=json_payload(row["owner_secret_material"]))}
            for row in rows]
