"""Entity OAuth integrations and connect links (docs/specs/oauth-connections.md).

A connect link lets a developer authorize a third-party OAuth app in their
browser while the Console — which holds the integration's client secret and
serves the redirect URI — exchanges the authorization code and mints the
resulting token straight into the profile's secret injections. No
port-forward out of a CVM, no manual code-shuttling, and the token never
transits a laptop or sandbox.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import html
import json
import re
from typing import Any
from urllib.parse import urlencode, urlsplit, urlunsplit
from uuid import UUID, uuid4

import asyncpg
import httpx
from fastapi import APIRouter, Depends, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from umbra_console.audit import insert_audit_event
from umbra_console.auth import CurrentUser, require_current_user
from umbra_console.config import load_settings
from umbra_console.crypto import random_token_urlsafe, sha256_hex
from umbra_console.db import get_pool
from umbra_console.errors import api_error
from umbra_console.log_config import logger
from umbra_console.oauth_endpoints import (
    TokenEndpointError,
    assert_token_url_egress_allowed,
    normalize_token_url,
    sanitize_provider_error_code,
)
from umbra_console.profile_secrets import (
    decrypt_oauth_client_secret,
    encrypt_managed_secret_value,
    encrypt_oauth_client_secret,
)
from umbra_console.resources import json_payload, timestamp
from pydantic import BaseModel, ConfigDict, Field, field_validator

log = logger()

oauth_router = APIRouter(prefix="/api/v1")
public_oauth_router = APIRouter()

OAUTH_INTEGRATION_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
OAUTH_POINTER_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
OAUTH_CONNECTION_STATE_TTL_SECONDS = 15 * 60
OAUTH_TOKEN_EXCHANGE_TIMEOUT_SECONDS = 10.0
OAUTH_CONNECTION_ERROR_MAX_LEN = 300


def console_public_url() -> str:
    return load_settings().raw.get("CONSOLE_URL", "http://localhost:8000").rstrip("/")


def oauth_callback_url() -> str:
    return f"{console_public_url()}/oauth/callback"


class OAuthIntegrationUpsert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authorize_url: str = Field(min_length=12, max_length=2048)
    token_url: str = Field(min_length=12, max_length=2048)
    client_id: str = Field(min_length=1, max_length=512)
    # Optional on update: omit to preserve the stored (write-only) secret;
    # required when creating a new integration (enforced in the handler).
    client_secret: str | None = Field(default=None, min_length=1, max_length=4096)
    scopes: str = Field(default="", max_length=2048)
    token_pointer: str = Field(min_length=2, max_length=512)
    profile_policy_template: dict[str, Any] | None = None

    @field_validator("authorize_url")
    @classmethod
    def absolute_https(cls, value: str) -> str:
        value = value.strip()
        parts = urlsplit(value)
        if parts.scheme != "https" or not parts.netloc:
            raise ValueError("must be an absolute https:// URL")
        if parts.fragment:
            raise ValueError("must not carry a fragment")
        return value

    @field_validator("token_url")
    @classmethod
    def allowlisted_token_url(cls, value: str) -> str:
        # Server-side fetch target: scheme + host allowlist (the resolved-IP
        # check runs again at exchange time).
        try:
            return normalize_token_url(value)
        except TokenEndpointError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("client_id", "client_secret", "scopes")
    @classmethod
    def printable(cls, value: str | None) -> str | None:
        if value is None:
            return value
        value = value.strip()
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
            raise ValueError("must not contain control characters")
        return value

    @field_validator("token_pointer")
    @classmethod
    def json_pointer(cls, value: str) -> str:
        value = value.strip()
        if not value.startswith("/"):
            raise ValueError("must be a JSON pointer starting with /")
        segments = value[1:].split("/")
        if not 1 <= len(segments) <= 8 or any(
            not OAUTH_POINTER_SEGMENT_RE.fullmatch(segment) for segment in segments
        ):
            raise ValueError("must have 1..8 segments of [A-Za-z0-9_.-]{1,128}")
        return value


class ProfileConnectionCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    integration: str = Field(min_length=1, max_length=64)
    injection_ids: list[str] | None = Field(default=None, max_length=16)


def oauth_integration_resource(row: Any) -> dict[str, Any]:
    # client_secret_ciphertext is deliberately absent: the secret is write-only.
    return {
        "entity_id": str(row["entity_id"]),
        "name": row["name"],
        "authorize_url": row["authorize_url"],
        "token_url": row["token_url"],
        "client_id": row["client_id"],
        "scopes": row["scopes"],
        "token_pointer": row["token_pointer"],
        "has_profile_policy_template": row["profile_policy_template"] is not None,
        "created_at": timestamp(row["created_at"]),
        "updated_at": timestamp(row["updated_at"]),
    }


@oauth_router.put("/entities/{entity_id}/oauth-integrations/{name}")
async def upsert_oauth_integration(
    entity_id: UUID,
    name: str,
    body: OAuthIntegrationUpsert,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_entity(entity_id)
    current_user.require_permission("USER_MANAGE")
    if not OAUTH_INTEGRATION_NAME_RE.fullmatch(name):
        raise api_error(422, "VALIDATION_ERROR", "invalid integration name", {"field": "name"})
    template = body.profile_policy_template
    if template is not None:
        # Deferred import: routes.py imports the scheduler at module load;
        # importing it lazily here keeps this module import-light for tests.
        from umbra_console.routes import (
            material_backed_secret_injection_ids,
            validate_profile_policy,
        )

        validate_profile_policy(template, require_injection_values=False)
        # Require a material-backed (inline-value) injection: the connect flow
        # mints a provider token into an inline-value slot, so a value_from-only
        # template is not connectable and would dead-end the wizard.
        if not material_backed_secret_injection_ids(template):
            raise api_error(
                422,
                "VALIDATION_ERROR",
                "template must declare at least one mintable secret injection",
                {"field": "profile_policy_template"},
            )
    ciphertext = (
        encrypt_oauth_client_secret(entity_id=entity_id, name=name, value=body.client_secret)
        if body.client_secret is not None
        else None
    )
    async with pool.acquire() as conn:
        async with conn.transaction():
            if ciphertext is None:
                exists = await conn.fetchval(
                    "SELECT 1 FROM oauth_integrations WHERE entity_id = $1 AND name = $2",
                    entity_id,
                    name,
                )
                if not exists:
                    raise api_error(
                        422,
                        "VALIDATION_ERROR",
                        "client_secret is required when creating an integration",
                        {"field": "client_secret"},
                    )
            row = await conn.fetchrow(
                """
                INSERT INTO oauth_integrations (
                    entity_id, name, authorize_url, token_url, client_id,
                    client_secret_ciphertext, scopes, token_pointer, profile_policy_template
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb)
                ON CONFLICT (entity_id, name)
                DO UPDATE SET authorize_url = EXCLUDED.authorize_url,
                              token_url = EXCLUDED.token_url,
                              client_id = EXCLUDED.client_id,
                              -- Preserve the stored write-only secret when the
                              -- update omits it.
                              client_secret_ciphertext = COALESCE(
                                  EXCLUDED.client_secret_ciphertext,
                                  oauth_integrations.client_secret_ciphertext
                              ),
                              scopes = EXCLUDED.scopes,
                              token_pointer = EXCLUDED.token_pointer,
                              -- Preserve the stored template when the update
                              -- omits it (same omit-to-preserve rule as the
                              -- client secret), so a secret-rotation PUT can't
                              -- silently break the /connect self-serve flow.
                              profile_policy_template = COALESCE(
                                  EXCLUDED.profile_policy_template,
                                  oauth_integrations.profile_policy_template
                              ),
                              updated_at = now()
                RETURNING entity_id, name, authorize_url, token_url, client_id, scopes,
                          token_pointer, profile_policy_template, created_at, updated_at
                """,
                entity_id,
                name,
                body.authorize_url,
                body.token_url,
                body.client_id,
                ciphertext,
                body.scopes,
                body.token_pointer,
                json.dumps(template) if template is not None else None,
            )
            await insert_audit_event(
                conn,
                entity_id=entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="OAUTH_INTEGRATION_CONFIGURED",
                target_type="oauth_integration",
                target_id=f"{entity_id}:{name}",
                after={
                    "name": name,
                    "client_id": body.client_id,
                    "has_profile_policy_template": template is not None,
                },
            )
    return oauth_integration_resource(row)


@oauth_router.get("/entities/{entity_id}/oauth-integrations")
async def list_oauth_integrations(
    entity_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_entity(entity_id)
    current_user.require_permission("USER_MANAGE")
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT entity_id, name, authorize_url, token_url, client_id, scopes,
                   token_pointer, profile_policy_template, created_at, updated_at
            FROM oauth_integrations
            WHERE entity_id = $1
            ORDER BY name
            """,
            entity_id,
        )
    return {"integrations": [oauth_integration_resource(row) for row in rows]}


@oauth_router.delete("/entities/{entity_id}/oauth-integrations/{name}", status_code=204)
async def delete_oauth_integration(
    entity_id: UUID,
    name: str,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    """Decommission an integration and purge its stored client-secret ciphertext.

    Cascades drop `oauth_connection_states` and `integration_profiles` rows;
    the per-dev profiles those linked to survive (an admin deletes them
    separately).
    """
    current_user.require_entity(entity_id)
    current_user.require_permission("USER_MANAGE")
    async with pool.acquire() as conn:
        async with conn.transaction():
            result = await conn.execute(
                "DELETE FROM oauth_integrations WHERE entity_id = $1 AND name = $2",
                entity_id,
                name,
            )
            if result != "DELETE 1":
                raise api_error(404, "NOT_FOUND", "resource not found")
            await insert_audit_event(
                conn,
                entity_id=entity_id,
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="OAUTH_INTEGRATION_DELETED",
                target_type="oauth_integration",
                target_id=f"{entity_id}:{name}",
                before={"name": name},
            )
    return Response(status_code=204)


async def create_connection_state(
    conn: asyncpg.Connection,
    *,
    entity_id: UUID,
    integration_name: str,
    profile_id: UUID,
    injection_ids: list[str],
    created_by: UUID | None,
) -> tuple[str, datetime]:
    """Mint a single-use connection state row; returns (raw state, expiry).

    The raw state appears exactly once (in the connect URL); the DB stores
    only its sha256. Shared by the admin connect-link route and the
    self-serve /connect flow so state semantics cannot drift.
    """
    state = random_token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(
        seconds=OAUTH_CONNECTION_STATE_TTL_SECONDS
    )
    await conn.execute(
        """
        INSERT INTO oauth_connection_states (
            id, entity_id, integration_name, state_token_hash,
            profile_id, injection_ids, created_by, expires_at
        )
        VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7, $8)
        """,
        uuid4(),
        entity_id,
        integration_name,
        sha256_hex(state),
        profile_id,
        json.dumps(injection_ids),
        created_by,
        expires_at,
    )
    return state, expires_at


def build_connect_url(integration: Any, state: str) -> str:
    parts = urlsplit(integration["authorize_url"])
    params = [
        ("response_type", "code"),
        ("client_id", integration["client_id"]),
        ("redirect_uri", oauth_callback_url()),
        ("state", state),
    ]
    scopes = integration["scopes"]
    if scopes:
        params.append(("scope", scopes))
    # Provider-specific extras (e.g. Slack's user_scope) live as query params
    # already present on the configured authorize_url; merge, never replace.
    query = "&".join(part for part in (parts.query, urlencode(params)) if part)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


@oauth_router.post("/profiles/{profile_id}/connections", status_code=201)
async def create_profile_connection(
    profile_id: UUID,
    body: ProfileConnectionCreate,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    current_user.require_permission("USER_MANAGE")
    if not OAUTH_INTEGRATION_NAME_RE.fullmatch(body.integration):
        raise api_error(422, "VALIDATION_ERROR", "invalid integration name", {"field": "integration"})
    from umbra_console.routes import material_backed_secret_injection_ids

    async with pool.acquire() as conn:
        async with conn.transaction():
            profile = await conn.fetchrow(
                """
                SELECT id, entity_id, policy
                FROM entity_profiles
                WHERE id = $1
                  AND deleted_at IS NULL
                """,
                profile_id,
            )
            if profile is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            current_user.require_entity(profile["entity_id"])
            integration = await conn.fetchrow(
                """
                SELECT entity_id, name, authorize_url, token_url, client_id, scopes, token_pointer
                FROM oauth_integrations
                WHERE entity_id = $1
                  AND name = $2
                """,
                profile["entity_id"],
                body.integration,
            )
            if integration is None:
                raise api_error(404, "NOT_FOUND", "resource not found")
            policy = json_payload(profile["policy"])
            # The OAuth callback mints a provider token into these injections;
            # only inline-value (material-backed) slots are ever read by the
            # SC, so value_from injections are not valid targets.
            material_backed = material_backed_secret_injection_ids(policy)
            injection_ids = body.injection_ids if body.injection_ids is not None else material_backed
            if not injection_ids:
                raise api_error(
                    422,
                    "VALIDATION_ERROR",
                    "profile declares no mintable secret injections",
                    {"field": "injection_ids"},
                )
            unknown = sorted(set(injection_ids) - set(material_backed))
            if unknown:
                raise api_error(
                    422,
                    "VALIDATION_ERROR",
                    "injection ids are not mintable (undeclared, or per-user value_from)",
                    {"field": "injection_ids", "state": "unknown_injection", "unknown": unknown},
                )
            state, expires_at = await create_connection_state(
                conn,
                entity_id=profile["entity_id"],
                integration_name=body.integration,
                profile_id=profile_id,
                injection_ids=sorted(set(injection_ids)),
                created_by=current_user.id,
            )
            await insert_audit_event(
                conn,
                entity_id=profile["entity_id"],
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="PROFILE_CONNECTION_LINK_CREATED",
                target_type="profile",
                target_id=profile_id,
                after={
                    "integration": body.integration,
                    "injection_ids": sorted(set(injection_ids)),
                    "expires_at": timestamp(expires_at),
                },
            )
    return {
        "connect_url": build_connect_url(integration, state),
        "expires_at": timestamp(expires_at),
    }


class ManagedSecretUpsert(BaseModel):
    model_config = ConfigDict(extra="forbid")

    token_url: str = Field(min_length=12, max_length=2048)
    client_id: str = Field(min_length=1, max_length=512)
    refresh_token: str = Field(min_length=1, max_length=8192)
    account_id: str | None = Field(default=None, max_length=256)
    access_token_expires_at: datetime | None = None

    @field_validator("token_url")
    @classmethod
    def allowlisted_token_url(cls, value: str) -> str:
        try:
            return normalize_token_url(value)
        except TokenEndpointError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("client_id", "refresh_token", "account_id")
    @classmethod
    def printable(cls, value: str | None) -> str | None:
        if value is None:
            return value
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
            raise ValueError("must not contain control characters")
        return value


def managed_secret_resource(row: Any) -> dict[str, Any]:
    # refresh_token_ciphertext is deliberately absent: write-only, no read path.
    return {
        "profile_id": str(row["profile_id"]),
        "injection_id": row["injection_id"],
        "provider": row["provider"],
        "token_url": row["token_url"],
        "client_id": row["client_id"],
        "account_id": row["account_id"],
        "access_token_expires_at": (
            timestamp(row["access_token_expires_at"]) if row["access_token_expires_at"] else None
        ),
        "last_rotated_at": timestamp(row["last_rotated_at"]) if row["last_rotated_at"] else None,
        "last_attempt_at": timestamp(row["last_attempt_at"]) if row["last_attempt_at"] else None,
        "last_error": row["last_error"],
        "created_at": timestamp(row["created_at"]),
        "updated_at": timestamp(row["updated_at"]),
    }


@oauth_router.put("/profiles/{profile_id}/managed-secrets/{injection_id}")
async def upsert_profile_managed_secret(
    profile_id: UUID,
    injection_id: str,
    body: ManagedSecretUpsert,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    """Configure a Console-managed rotating OAuth secret for one injection.

    The Console becomes the sole holder and sole refresher of the uploaded
    refresh token; a scheduler pass keeps a fresh access token in the
    injection slot. The PUT triggers an immediate first rotation so the
    caller learns right away whether the grant works.
    """
    from umbra_console.routes import (
        POLICY_ID_RE,
        declared_secret_injection_ids,
        fetch_profile_for_secret_write,
        material_backed_secret_injection_ids,
    )
    from umbra_console.scheduler import rotate_managed_secret_now

    if not POLICY_ID_RE.fullmatch(injection_id):
        raise api_error(422, "VALIDATION_ERROR", "invalid injection id", {"field": "injection_id"})
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await fetch_profile_for_secret_write(
                conn, profile_id=profile_id, current_user=current_user
            )
            policy = json_payload(row["policy"])
            if injection_id not in declared_secret_injection_ids(policy):
                raise api_error(
                    422,
                    "VALIDATION_ERROR",
                    "injection id is not declared in the profile policy",
                    {"field": "injection_id", "state": "unknown_injection"},
                )
            if injection_id not in material_backed_secret_injection_ids(policy):
                # value_from injections are resolved from the CVM owner's user
                # secret; the SC never reads managed/profile material for them,
                # so rotation here would silently never be injected.
                raise api_error(
                    422,
                    "VALIDATION_ERROR",
                    "injection sources its value from a per-user secret; managed rotation does not apply",
                    {"field": "injection_id", "state": "not_material_backed"},
                )
            ciphertext = encrypt_managed_secret_value(
                profile_id=profile_id, injection_id=injection_id, value=body.refresh_token
            )
            await conn.execute(
                """
                INSERT INTO profile_managed_secrets (
                    profile_id, injection_id, token_url, client_id,
                    refresh_token_ciphertext, account_id, access_token_expires_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (profile_id, injection_id)
                DO UPDATE SET token_url = EXCLUDED.token_url,
                              client_id = EXCLUDED.client_id,
                              refresh_token_ciphertext = EXCLUDED.refresh_token_ciphertext,
                              account_id = EXCLUDED.account_id,
                              access_token_expires_at = EXCLUDED.access_token_expires_at,
                              last_error = NULL,
                              updated_at = now()
                """,
                profile_id,
                injection_id,
                body.token_url,
                body.client_id,
                ciphertext,
                body.account_id,
                body.access_token_expires_at,
            )
            await insert_audit_event(
                conn,
                entity_id=row["entity_id"],
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="PROFILE_MANAGED_SECRET_CONFIGURED",
                target_type="profile",
                target_id=profile_id,
                after={
                    "injection_id": injection_id,
                    "token_url": body.token_url,
                    "client_id": body.client_id,
                },
            )
    async with pool.acquire() as conn:
        rotated, rotation_error = await rotate_managed_secret_now(
            conn, profile_id=profile_id, injection_id=injection_id
        )
        managed = await fetch_managed_secret_full_row(conn, profile_id, injection_id)
    payload = managed_secret_resource(managed)
    payload["rotated"] = rotated
    if rotation_error:
        payload["rotation_error"] = rotation_error
    return payload


async def fetch_managed_secret_full_row(
    conn: asyncpg.Connection, profile_id: UUID, injection_id: str
) -> Any:
    return await conn.fetchrow(
        """
        SELECT profile_id, injection_id, provider, token_url, client_id, account_id,
               access_token_expires_at, last_rotated_at, last_attempt_at, last_error,
               created_at, updated_at
        FROM profile_managed_secrets
        WHERE profile_id = $1
          AND injection_id = $2
        """,
        profile_id,
        injection_id,
    )


@oauth_router.get("/profiles/{profile_id}/managed-secrets")
async def list_profile_managed_secrets(
    profile_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    async with pool.acquire() as conn:
        profile = await conn.fetchrow(
            """
            SELECT ep.entity_id, (pu.user_id IS NOT NULL) AS assigned
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
            SELECT profile_id, injection_id, provider, token_url, client_id, account_id,
                   access_token_expires_at, last_rotated_at, last_attempt_at, last_error,
                   created_at, updated_at
            FROM profile_managed_secrets
            WHERE profile_id = $1
            ORDER BY injection_id
            """,
            profile_id,
        )
    return {"managed_secrets": [managed_secret_resource(row) for row in rows]}


@oauth_router.get("/profiles/{profile_id}/secrets-status")
async def profile_secrets_status(
    profile_id: UUID,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
) -> dict:
    """Grant observability: which declared injections have material, how the
    managed rotation is doing, and how the last connect attempt ended —
    always redacted, never any secret value."""
    from umbra_console.routes import declared_secret_injection_ids

    async with pool.acquire() as conn:
        profile = await conn.fetchrow(
            """
            SELECT ep.entity_id, ep.policy, (pu.user_id IS NOT NULL) AS assigned
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
        declared = declared_secret_injection_ids(json_payload(profile["policy"]))
        material_rows = await conn.fetch(
            """
            SELECT injection_id, updated_at
            FROM profile_secret_material
            WHERE profile_id = $1
            """,
            profile_id,
        )
        managed_rows = await conn.fetch(
            """
            SELECT injection_id, account_id, access_token_expires_at,
                   last_rotated_at, last_attempt_at, last_error
            FROM profile_managed_secrets
            WHERE profile_id = $1
            """,
            profile_id,
        )
        last_state = await conn.fetchrow(
            """
            SELECT integration_name, completed_at, error
            FROM oauth_connection_states
            WHERE profile_id = $1
            ORDER BY created_at DESC
            LIMIT 1
            """,
            profile_id,
        )
    material = {row["injection_id"]: row["updated_at"] for row in material_rows}
    managed = {row["injection_id"]: row for row in managed_rows}
    injections = []
    for injection_id in declared:
        managed_row = managed.get(injection_id)
        injections.append(
            {
                "injection_id": injection_id,
                "material_present": injection_id in material,
                "updated_at": timestamp(material[injection_id]) if injection_id in material else None,
                "managed": (
                    {
                        "access_token_expires_at": (
                            timestamp(managed_row["access_token_expires_at"])
                            if managed_row["access_token_expires_at"]
                            else None
                        ),
                        "last_rotated_at": (
                            timestamp(managed_row["last_rotated_at"])
                            if managed_row["last_rotated_at"]
                            else None
                        ),
                        "last_attempt_at": (
                            timestamp(managed_row["last_attempt_at"])
                            if managed_row["last_attempt_at"]
                            else None
                        ),
                        "last_error": managed_row["last_error"],
                    }
                    if managed_row is not None
                    else None
                ),
            }
        )
    connection = {"integration": None, "connected_at": None, "error": None}
    if last_state is not None:
        connection["integration"] = last_state["integration_name"]
        connection["error"] = last_state["error"]
        if last_state["error"] is None and last_state["completed_at"] is not None:
            connection["connected_at"] = timestamp(last_state["completed_at"])
    return {
        "profile_id": str(profile_id),
        "injections": injections,
        "last_connection": connection,
    }


@oauth_router.delete("/profiles/{profile_id}/managed-secrets/{injection_id}", status_code=204)
async def delete_profile_managed_secret(
    profile_id: UUID,
    injection_id: str,
    current_user: CurrentUser = Depends(require_current_user),
    pool: asyncpg.Pool = Depends(get_pool),
):
    """Stop Console-managed rotation for one injection.

    The stored injection material is left intact (the last injected access
    token keeps working until it expires, and the CVM never fail-closes);
    the upstream grant is NOT revoked at the provider.
    """
    from umbra_console.routes import fetch_profile_for_secret_write

    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await fetch_profile_for_secret_write(
                conn, profile_id=profile_id, current_user=current_user
            )
            result = await conn.execute(
                """
                DELETE FROM profile_managed_secrets
                WHERE profile_id = $1
                  AND injection_id = $2
                """,
                profile_id,
                injection_id,
            )
            if result != "DELETE 1":
                raise api_error(404, "NOT_FOUND", "resource not found")
            await insert_audit_event(
                conn,
                entity_id=row["entity_id"],
                actor_id=current_user.id,
                actor_email=current_user.email,
                action="PROFILE_MANAGED_SECRET_DELETED",
                target_type="profile",
                target_id=profile_id,
                after={"injection_id": injection_id},
            )
    return Response(status_code=204)


def callback_page(status_code: int, message: str) -> HTMLResponse:
    body = (
        "<!doctype html>\n"
        '<html><head><meta charset="utf-8"><title>Concrete</title></head>\n'
        f"<body><h1>Concrete</h1><p>{html.escape(message)}</p></body></html>\n"
    )
    return HTMLResponse(content=body, status_code=status_code)


def safe_provider_error_code(value: Any) -> str:
    return sanitize_provider_error_code(value)


def resolve_json_pointer(payload: Any, pointer: str) -> Any:
    value = payload
    for raw_segment in pointer.lstrip("/").split("/"):
        segment = raw_segment.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict) and segment in value:
            value = value[segment]
        elif isinstance(value, list) and segment.isdigit() and int(segment) < len(value):
            value = value[int(segment)]
        else:
            return None
    return value


async def exchange_authorization_code(
    integration: Any, *, client_secret: str, code: str
) -> tuple[str | None, str | None]:
    """Exchange the provider code for a token. Returns (token, error_code).

    The HTTP call happens outside any DB transaction. Error codes are safe
    short strings for the connection state's `error` column — never token or
    secret material.
    """
    try:
        # Re-check host + resolved IPs immediately before the fetch (covers
        # rows configured before an allowlist change and DNS rebinding).
        await run_in_threadpool(assert_token_url_egress_allowed, integration["token_url"])
    except TokenEndpointError:
        return None, "token_url_not_allowed"
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": oauth_callback_url(),
        "client_id": integration["client_id"],
        "client_secret": client_secret,
    }
    try:
        async with httpx.AsyncClient(timeout=OAUTH_TOKEN_EXCHANGE_TIMEOUT_SECONDS) as client:
            response = await client.post(
                integration["token_url"], data=data, headers={"Accept": "application/json"}
            )
    except httpx.HTTPError as exc:
        return None, f"exchange_transport:{type(exc).__name__}"
    if response.status_code != 200:
        return None, f"exchange_status:{response.status_code}"
    try:
        payload = response.json()
    except ValueError:
        return None, "exchange_malformed_response"
    if not isinstance(payload, dict):
        return None, "exchange_malformed_response"
    if payload.get("error") or payload.get("ok") is False:
        return None, f"exchange_error:{safe_provider_error_code(payload.get('error'))}"
    token = resolve_json_pointer(payload, integration["token_pointer"])
    if not isinstance(token, str) or not token.strip():
        return None, "token_pointer_miss"
    token = token.strip()
    if len(token) > 8192 or any(ord(char) < 0x20 or ord(char) == 0x7F for char in token):
        return None, "token_shape_invalid"
    return token, None


async def record_connection_error(pool: asyncpg.Pool, state_id: UUID, error: str) -> None:
    async with pool.acquire() as conn:
        await conn.execute(
            """
            UPDATE oauth_connection_states
            SET error = $2
            WHERE id = $1
            """,
            state_id,
            error[:OAUTH_CONNECTION_ERROR_MAX_LEN],
        )


def connect_page_redirect(integration_name: str, outcome_query: str) -> RedirectResponse:
    # The target is built from the DB-validated integration slug of the
    # consumed state row plus a fixed query — never from request params, so
    # there is no open-redirect surface. Display hints only: the /connect
    # page always re-fetches status before enabling anything.
    return RedirectResponse(
        f"{console_public_url()}/connect/{integration_name}?{outcome_query}",
        status_code=303,
    )


async def _connection_authorization(
    conn: asyncpg.Connection, *, profile_id: UUID, created_by: Any, lock: bool
) -> Any:
    """Row for the callback's initiator-authorization check.

    `lock=True` takes `FOR UPDATE OF ep` so the re-check inside the mint
    transaction and the write are atomic against a concurrent membership
    revocation / profile delete.
    """
    return await conn.fetchrow(
        f"""
        SELECT ep.policy,
               u.email AS actor_email,
               (pu.user_id IS NOT NULL) AS member,
               EXISTS (
                   SELECT 1 FROM user_permissions up
                   WHERE up.user_id = $2 AND up.permission = 'USER_MANAGE'
               ) AS is_manager
        FROM entity_profiles ep
        LEFT JOIN users u ON u.id = $2 AND u.deleted_at IS NULL
        LEFT JOIN profile_users pu
          ON pu.profile_id = ep.id AND pu.user_id = $2
        WHERE ep.id = $1
          AND ep.deleted_at IS NULL
        {"FOR UPDATE OF ep" if lock else ""}
        """,
        profile_id,
        created_by,
    )


def _connection_authorized(row: Any, created_by: Any) -> bool:
    # actor_email is NULL when the initiator no longer exists as an active user
    # (the `u.deleted_at IS NULL` join misses) — a soft-deleted initiator with a
    # lingering profile_users row must not still mint.
    return not (
        row is None
        or created_by is None
        or row["actor_email"] is None
        or (not row["member"] and not row["is_manager"])
    )


@public_oauth_router.get("/oauth/callback", include_in_schema=False)
async def oauth_connection_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    if not state:
        return callback_page(400, "Missing state parameter.")
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                UPDATE oauth_connection_states
                SET used_at = now()
                WHERE state_token_hash = $1
                  AND used_at IS NULL
                  AND expires_at > now()
                RETURNING id, entity_id, integration_name, profile_id, injection_ids, created_by
                """,
                sha256_hex(state),
            )
    if row is None:
        return callback_page(400, "This connect link is invalid, expired, or already used.")
    if error:
        await record_connection_error(pool, row["id"], f"provider:{safe_provider_error_code(error)}")
        return connect_page_redirect(row["integration_name"], "connect_error=provider_denied")
    if not code:
        await record_connection_error(pool, row["id"], "missing_code")
        return connect_page_redirect(row["integration_name"], "connect_error=missing_code")
    # Re-check authorization at consume time: an admin may have removed the
    # initiator's membership (or deleted the profile) after the link was
    # minted. The stored state must not outlive that authorization. This is a
    # cheap early reject before the provider exchange; it is re-run under a
    # row lock inside the mint transaction below to close the race where the
    # revocation lands mid-exchange.
    async with pool.acquire() as conn:
        profile = await _connection_authorization(
            conn, profile_id=row["profile_id"], created_by=row["created_by"], lock=False
        )
    if not _connection_authorized(profile, row["created_by"]):
        await record_connection_error(pool, row["id"], "authorization_revoked")
        return connect_page_redirect(row["integration_name"], "connect_error=authorization_revoked")
    async with pool.acquire() as conn:
        integration = await conn.fetchrow(
            """
            SELECT entity_id, name, authorize_url, token_url, client_id,
                   client_secret_ciphertext, scopes, token_pointer
            FROM oauth_integrations
            WHERE entity_id = $1
              AND name = $2
            """,
            row["entity_id"],
            row["integration_name"],
        )
    if integration is None:
        await record_connection_error(pool, row["id"], "integration_deleted")
        return connect_page_redirect(row["integration_name"], "connect_error=integration_deleted")
    client_secret = decrypt_oauth_client_secret(
        entity_id=integration["entity_id"],
        name=integration["name"],
        ciphertext=integration["client_secret_ciphertext"],
    )
    token, exchange_error = await exchange_authorization_code(
        integration, client_secret=client_secret, code=code
    )
    if exchange_error:
        log.warning(
            "oauth_connection_exchange_failed",
            integration=row["integration_name"],
            profile_id=str(row["profile_id"]),
            error=exchange_error,
        )
        await record_connection_error(pool, row["id"], exchange_error)
        return connect_page_redirect(row["integration_name"], "connect_error=exchange_failed")
    injection_ids = [
        injection_id
        for injection_id in json_payload(row["injection_ids"])
        if isinstance(injection_id, str)
    ]
    from umbra_console.routes import (
        POLICY_MAX_RENDERED_SECRET_LEN,
        bump_attached_cvm_policy_versions,
        rendered_injection_value_length,
        upsert_profile_secret_material,
    )

    abort_reason: str | None = None
    async with pool.acquire() as conn:
        async with conn.transaction():
            # Re-check authorization AND rendered length under a row lock, inside
            # the mint transaction. The pre-exchange checks above race anything
            # that lands during the provider round-trip: a revocation
            # (membership-removal / profile-delete) or a `profile configure` that
            # lengthens the value_template past the rendered-length bound.
            # `FOR UPDATE OF ep` serializes both against those writers so the
            # mint, its authorization, and the length bound all observe one
            # consistent policy snapshot (reading the fresh `ep.policy` the lock
            # returned, not the pre-exchange copy).
            authz = await _connection_authorization(
                conn, profile_id=row["profile_id"], created_by=row["created_by"], lock=True
            )
            if not _connection_authorized(authz, row["created_by"]):
                abort_reason = "authorization_revoked"
            else:
                policy = json_payload(authz["policy"])
                over_long = any(
                    rendered_injection_value_length(policy, injection_id, token)
                    > POLICY_MAX_RENDERED_SECRET_LEN
                    for injection_id in injection_ids
                )
                if over_long:
                    abort_reason = "rendered_value_too_long"
                else:
                    await upsert_profile_secret_material(
                        conn,
                        profile_id=row["profile_id"],
                        secret_values={injection_id: token for injection_id in injection_ids},
                    )
                    await bump_attached_cvm_policy_versions(conn, row["profile_id"])
                    # completed_at is the sole "connected" signal — set only here,
                    # in the same transaction as the mint, so a crash between
                    # used_at and this point never reads as a successful
                    # connection.
                    await conn.execute(
                        "UPDATE oauth_connection_states SET completed_at = now() WHERE id = $1",
                        row["id"],
                    )
                    await insert_audit_event(
                        conn,
                        entity_id=row["entity_id"],
                        actor_id=row["created_by"],
                        actor_email=authz["actor_email"],
                        action="PROFILE_SECRET_MINTED",
                        target_type="profile",
                        target_id=row["profile_id"],
                        after={
                            "injection_ids": injection_ids,
                            "via": "oauth_connection",
                            "integration": row["integration_name"],
                        },
                    )
    if abort_reason == "authorization_revoked":
        await record_connection_error(pool, row["id"], "authorization_revoked")
        return connect_page_redirect(row["integration_name"], "connect_error=authorization_revoked")
    if abort_reason == "rendered_value_too_long":
        await record_connection_error(pool, row["id"], "rendered_value_too_long")
        return connect_page_redirect(row["integration_name"], "connect_error=token_too_long")
    return connect_page_redirect(row["integration_name"], "connected=1")
