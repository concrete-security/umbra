"""Self-serve OAuth onboarding API behind `{CONSOLE_URL}/connect/{integration}`.

An admin posts one durable link in a shared channel; any developer holding
`CVM_LAUNCH` self-serves end to end: Google sign-in, a per-dev profile
cloned from the integration's stored template, the provider Allow page, and
binding the profile to their own CVM. The caller never chooses profile or
injection ids — both derive server-side from the linking table
(`integration_profiles`) and the integration row, and every mutation runs
under Console authority with the developer as the audited actor.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from uuid import UUID, uuid4

import asyncpg
from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict

from umbra_console.audit import insert_audit_event
from umbra_console.auth import CurrentUser, require_current_user
from umbra_console.db import get_pool
from umbra_console.errors import api_error
from umbra_console.log_config import logger
from umbra_console.resources import json_payload, timestamp
from umbra_console.routes_oauth import build_connect_url, create_connection_state

log = logger()

connect_router = APIRouter(prefix="/api/v1/connect")

CONNECT_INTEGRATION_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
CONNECT_PROFILE_NAME_MAX = 100


class ConnectAttach(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cvm_id: UUID


def require_integration_slug(integration: str) -> None:
    if not CONNECT_INTEGRATION_RE.fullmatch(integration):
        raise api_error(404, "NOT_FOUND", "resource not found")


async def fetch_integration(conn: asyncpg.Connection, entity_id: UUID, name: str) -> Any:
    return await conn.fetchrow(
        """
        SELECT entity_id, name, authorize_url, token_url, client_id, scopes,
               token_pointer, profile_policy_template
        FROM oauth_integrations
        WHERE entity_id = $1
          AND name = $2
        """,
        entity_id,
        name,
    )


async def fetch_link_row(
    conn: asyncpg.Connection, entity_id: UUID, integration: str, user_id: UUID
) -> Any:
    """The caller's per-integration profile, via the linking table.

    Reports current `profile_users` membership (`member`) alongside the link:
    an admin removing the user from the profile must revoke the persistent
    link's power, so callers treat a link with `member = False` as revoked
    rather than trusting the linking-table row alone.
    """
    return await conn.fetchrow(
        """
        SELECT ip.profile_id, ip.template_sha256, ep.name, ep.policy, ep.created_at,
               (ep.deleted_at IS NOT NULL) AS profile_deleted,
               (pu.user_id IS NOT NULL) AS member
        FROM integration_profiles ip
        JOIN entity_profiles ep ON ep.id = ip.profile_id
        LEFT JOIN profile_users pu
          ON pu.profile_id = ip.profile_id AND pu.user_id = ip.user_id
        WHERE ip.entity_id = $1
          AND ip.integration_name = $2
          AND ip.user_id = $3
        """,
        entity_id,
        integration,
        user_id,
    )


def link_is_usable(link: Any) -> bool:
    """A link backs a usable profile only while it is live and the caller is
    still a member."""
    return link is not None and not link["profile_deleted"] and link["member"]


def connect_profile_name(integration: str, email: str) -> str:
    localpart = email.split("@", 1)[0].lower()
    sanitized = re.sub(r"[^a-z0-9-]+", "-", localpart).strip("-") or "dev"
    return f"conn-{integration}-{sanitized}"[:CONNECT_PROFILE_NAME_MAX]


def connect_provision_lock_keys(entity_id: Any, integration: str, user_id: Any) -> tuple[int, int]:
    """Two signed int32 advisory-lock keys for one (entity, integration, user)."""
    digest = hashlib.sha256(f"{entity_id}:{integration}:{user_id}".encode("utf-8")).digest()
    return (
        int.from_bytes(digest[0:4], "big", signed=True),
        int.from_bytes(digest[4:8], "big", signed=True),
    )


@connect_router.get("/{integration}")
async def connect_status(
    integration: str,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    """Everything the wizard page needs; `entitled=false` is a 200, not a 403."""
    from umbra_console.routes import material_backed_secret_injection_ids

    require_integration_slug(integration)
    async with pool.acquire() as conn:
        integration_row = await fetch_integration(conn, current_user.entity_id, integration)
        if integration_row is None:
            raise api_error(404, "NOT_FOUND", "resource not found")
        link = await fetch_link_row(conn, current_user.entity_id, integration, current_user.id)
        profile = None
        required: list[str] = []
        minted: list[str] = []
        connection: dict[str, Any] = {"last_connected_at": None, "last_error": None}
        cvms: list[dict[str, Any]] = []
        # A link whose membership was revoked reads as "no profile" — the page
        # then routes the dev back through provision, which refuses to
        # self-restore (an admin must re-add them).
        if link_is_usable(link):
            profile = {
                "id": str(link["profile_id"]),
                "name": link["name"],
                "created_at": timestamp(link["created_at"]),
            }
            # Only inline-value (material-backed) injections are minted via the
            # connect flow; value_from injections are satisfied by the CVM
            # owner's user secret and must not block `secrets.complete`.
            required = material_backed_secret_injection_ids(json_payload(link["policy"]))
            material = await conn.fetch(
                """
                SELECT injection_id
                FROM profile_secret_material
                WHERE profile_id = $1
                """,
                link["profile_id"],
            )
            minted_set = {row["injection_id"] for row in material}
            minted = [injection_id for injection_id in required if injection_id in minted_set]
            last_state = await conn.fetchrow(
                """
                SELECT completed_at, error
                FROM oauth_connection_states
                WHERE profile_id = $1
                ORDER BY created_at DESC
                LIMIT 1
                """,
                link["profile_id"],
            )
            if last_state is not None:
                if last_state["error"]:
                    connection["last_error"] = last_state["error"]
                elif last_state["completed_at"] is not None:
                    connection["last_connected_at"] = timestamp(last_state["completed_at"])
            cvm_rows = await conn.fetch(
                """
                SELECT c.id, c.fqdn, c.state::text AS state,
                       (cp.profile_id IS NOT NULL) AS attached
                FROM cvms c
                LEFT JOIN cvm_profiles cp
                  ON cp.cvm_id = c.id
                 AND cp.profile_id = $3
                WHERE c.entity_id = $1
                  AND c.owner_id = $2
                  AND c.deleted_at IS NULL
                  AND c.state <> 'TERMINATED'
                ORDER BY c.created_at DESC
                """,
                current_user.entity_id,
                current_user.id,
                link["profile_id"],
            )
            cvms = [
                {
                    "id": str(row["id"]),
                    "fqdn": row["fqdn"],
                    "state": row["state"],
                    "attached": row["attached"],
                }
                for row in cvm_rows
            ]
    return {
        "integration": {"name": integration},
        "entitled": "CVM_LAUNCH" in current_user.permissions,
        "profile": profile,
        "secrets": {
            "required": required,
            "minted": minted,
            "complete": bool(required) and set(required) == set(minted),
        },
        "connection": connection,
        "cvms": cvms,
    }


@connect_router.post("/{integration}/profile")
async def connect_provision_profile(
    integration: str,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    """Idempotent per-dev profile provisioning from the stored template.

    Runs under Console authority (profile create + membership are otherwise
    USER_MANAGE): the CVM_LAUNCH gate is the blast radius the entity admin
    accepted by granting launch rights.
    """
    from umbra_console.routes import (
        enforce_entity_quota,
        material_backed_secret_injection_ids,
        policy_sha256,
        validate_profile_policy,
    )

    require_integration_slug(integration)
    current_user.require_permission("CVM_LAUNCH")
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Serialize concurrent first-visits for the same (entity,
            # integration, user) so two racing requests can't create orphaned
            # profiles or clobber each other's link row.
            k1, k2 = connect_provision_lock_keys(current_user.entity_id, integration, current_user.id)
            await conn.execute("SELECT pg_advisory_xact_lock($1, $2)", k1, k2)
            integration_row = await fetch_integration(conn, current_user.entity_id, integration)
            if integration_row is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            link = await fetch_link_row(conn, current_user.entity_id, integration, current_user.id)
            if link is not None and not link["profile_deleted"]:
                if not link["member"]:
                    # An admin removed the dev from the keyed profile. The
                    # self-service flow must not silently re-grant membership;
                    # an admin has to re-add them.
                    raise api_error(
                        409,
                        "CONFLICT",
                        "profile membership was revoked; ask your admin to restore access",
                        {"state": "membership_revoked"},
                    )
                return {
                    "profile_id": str(link["profile_id"]),
                    "name": link["name"],
                    "created": False,
                }
            template = json_payload(integration_row["profile_policy_template"])
            if not template:
                raise api_error(
                    409,
                    "CONFLICT",
                    "integration has no profile policy template",
                    {"state": "template_missing"},
                )
            # Defensive re-run: templates were validated on PUT, but they are
            # the only path that writes policy without inline secret values.
            # Require a material-backed (inline-value) injection, not merely any
            # declared one: a connect link mints a provider token into an
            # inline-value slot, so a value_from-only template would provision a
            # profile the connect flow can never complete (connect_status reads
            # required=[] and connect create 409s profile_not_provisioned).
            validate_profile_policy(template, require_injection_values=False)
            if not material_backed_secret_injection_ids(template):
                raise api_error(
                    409,
                    "CONFLICT",
                    "integration template declares no mintable secret injection",
                    {"state": "template_missing"},
                )
            await enforce_entity_quota(conn, current_user.entity_id, "profiles")
            profile_id = uuid4()
            name = connect_profile_name(integration, current_user.email)
            description = f"self-serve {integration} profile"
            try:
                # Savepoint: a name collision aborts only this INSERT, not the
                # whole transaction, so the suffixed retry can proceed.
                async with conn.transaction():
                    await conn.execute(
                        """
                        INSERT INTO entity_profiles (id, entity_id, name, description, policy)
                        VALUES ($1, $2, $3, $4, $5::jsonb)
                        """,
                        profile_id,
                        current_user.entity_id,
                        name,
                        description,
                        json.dumps(template),
                    )
            except asyncpg.UniqueViolationError:
                name = f"{name[: CONNECT_PROFILE_NAME_MAX - 7]}-{str(profile_id)[:6]}"
                await conn.execute(
                    """
                    INSERT INTO entity_profiles (id, entity_id, name, description, policy)
                    VALUES ($1, $2, $3, $4, $5::jsonb)
                    """,
                    profile_id,
                    current_user.entity_id,
                    name,
                    description,
                    json.dumps(template),
                )
            await conn.execute(
                """
                INSERT INTO profile_users (profile_id, user_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                """,
                profile_id,
                current_user.id,
            )
            await conn.execute(
                """
                INSERT INTO integration_profiles (
                    entity_id, integration_name, user_id, profile_id, template_sha256
                )
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (entity_id, integration_name, user_id)
                DO UPDATE SET profile_id = EXCLUDED.profile_id,
                              template_sha256 = EXCLUDED.template_sha256,
                              updated_at = now()
                """,
                current_user.entity_id,
                integration,
                current_user.id,
                profile_id,
                policy_sha256(template),
            )
            await insert_audit_event(
                conn,
                entity_id=current_user.entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="PROFILE_CREATED",
                target_type="profile",
                target_id=profile_id,
                after={"name": name, "via": "connect", "integration": integration},
            )
            await insert_audit_event(
                conn,
                entity_id=current_user.entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="PROFILE_USER_ASSIGNED",
                target_type="profile",
                target_id=profile_id,
                after={"user_id": str(current_user.id), "via": "connect"},
            )
    return {"profile_id": str(profile_id), "name": name, "created": True}


@connect_router.post("/{integration}/connections", status_code=201)
async def connect_create_connection(
    integration: str,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    """Self-serve connect link for the caller's OWN keyed profile only."""
    from umbra_console.routes import material_backed_secret_injection_ids

    require_integration_slug(integration)
    current_user.require_permission("CVM_LAUNCH")
    async with pool.acquire() as conn:
        async with conn.transaction():
            integration_row = await fetch_integration(conn, current_user.entity_id, integration)
            if integration_row is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            link = await fetch_link_row(conn, current_user.entity_id, integration, current_user.id)
            if not link_is_usable(link):
                raise api_error(
                    409,
                    "CONFLICT",
                    "provision the integration profile first",
                    {"state": "profile_not_provisioned"},
                )
            injection_ids = material_backed_secret_injection_ids(json_payload(link["policy"]))
            if not injection_ids:
                raise api_error(
                    409,
                    "CONFLICT",
                    "profile declares no mintable secret injections",
                    {"state": "profile_not_provisioned"},
                )
            state, expires_at = await create_connection_state(
                conn,
                entity_id=current_user.entity_id,
                integration_name=integration,
                profile_id=link["profile_id"],
                injection_ids=sorted(set(injection_ids)),
                created_by=current_user.id,
            )
            await insert_audit_event(
                conn,
                entity_id=current_user.entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="PROFILE_CONNECTION_LINK_CREATED",
                target_type="profile",
                target_id=link["profile_id"],
                after={
                    "integration": integration,
                    "injection_ids": sorted(set(injection_ids)),
                    "expires_at": timestamp(expires_at),
                    "via": "connect",
                },
            )
    return {
        "authorize_url": build_connect_url(integration_row, state),
        "expires_at": timestamp(expires_at),
    }


@connect_router.post("/{integration}/attach")
async def connect_attach_cvm(
    integration: str,
    body: ConnectAttach,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    """Owner self-attach: bind the caller's keyed profile to a CVM they own.

    Replaces the CVM_MANAGE requirement of the generic attach with the rule
    "caller launched the CVM (cvms.owner_id) AND is a member of the linked
    profile AND every declared injection is minted" — the same mint-complete
    gate that protects the generic routes.
    """
    from umbra_console.routes import (
        bump_cvm_policy_version,
        ensure_no_sandbox_env_conflict,
        ensure_profile_secret_material_complete,
        ensure_user_secret_references,
        require_cvm_profile_mutable,
    )

    require_integration_slug(integration)
    current_user.require_permission("CVM_LAUNCH")
    async with pool.acquire() as conn:
        async with conn.transaction():
            link = await fetch_link_row(conn, current_user.entity_id, integration, current_user.id)
            if not link_is_usable(link):
                raise api_error(
                    409,
                    "CONFLICT",
                    "provision the integration profile first",
                    {"state": "profile_not_provisioned"},
                )
            cvm = await conn.fetchrow(
                """
                SELECT id, entity_id, owner_id, state::text AS state, policy_version
                FROM cvms
                WHERE id = $1
                  AND entity_id = $2
                  AND deleted_at IS NULL
                FOR UPDATE
                """,
                body.cvm_id,
                current_user.entity_id,
            )
            # Owner-only, deliberately without a CVM_MANAGE bypass: managers
            # keep the generic attach route with its ETag ceremony. 404 (not
            # 403) so foreign CVMs are indistinguishable from absent ones.
            if cvm is None or cvm["owner_id"] != current_user.id:
                raise api_error(404, "NOT_FOUND", "resource not found")
            require_cvm_profile_mutable(cvm, action="attach")
            membership = await conn.fetchval(
                """
                SELECT 1
                FROM profile_users
                WHERE profile_id = $1
                  AND user_id = $2
                LIMIT 1
                """,
                link["profile_id"],
                current_user.id,
            )
            if membership is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            attach_profile_rows = [{"profile_id": link["profile_id"], "policy": link["policy"]}]
            # `value_from` user-secret injections carry no profile-side material,
            # so the material-complete gate skips them; preflight them against
            # the CVM owner's secrets exactly as the generic attach route does,
            # or an attach could succeed with a missing/unauthorized user secret
            # (the SC then fail-closes that destination with an
            # `unfulfilled_secret_injections` marker — a silent per-destination
            # breakage the caller never chose).
            await ensure_user_secret_references(
                conn,
                profile_rows=attach_profile_rows,
                user_id=cvm["owner_id"],
                context="cvm_owner",
            )
            await ensure_profile_secret_material_complete(
                conn,
                attach_profile_rows,
                status_code=409,
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
                body.cvm_id,
            )
            ensure_no_sandbox_env_conflict(
                [*existing_policies, {"profile_id": link["profile_id"], "policy": link["policy"]}]
            )
            result = await conn.execute(
                """
                INSERT INTO cvm_profiles (cvm_id, profile_id, attached_by)
                VALUES ($1, $2, $3)
                ON CONFLICT DO NOTHING
                """,
                body.cvm_id,
                link["profile_id"],
                current_user.id,
            )
            attached = result == "INSERT 0 1"
            if attached:
                await bump_cvm_policy_version(conn, body.cvm_id)
                await insert_audit_event(
                    conn,
                    entity_id=current_user.entity_id,
                    actor_id=current_user.id,
                    actor_email=current_user.email,
                    action="CVM_PROFILE_ATTACHED",
                    target_type="cvm",
                    target_id=body.cvm_id,
                    after={
                        "cvm_id": str(body.cvm_id),
                        "profile_id": str(link["profile_id"]),
                        "via": "connect",
                    },
                )
    # The cvm_profiles row exists either way once every gate passed.
    return {"attached": True, "already_attached": not attached}
