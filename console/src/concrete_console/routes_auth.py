from __future__ import annotations

from datetime import datetime, timezone
import hmac
import re
from typing import Annotated
from uuid import UUID

import asyncpg
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
import httpx
import jwt
from pydantic import BaseModel, ConfigDict, Field

from concrete_console.account_resolution import resolve_oidc_user
from concrete_console.audit import insert_audit_event
from concrete_console.crypto import pkce_s256, random_token_urlsafe, sha256_hex
from concrete_console.db import get_pool
from concrete_console.errors import api_error
from concrete_console.jwt_keys import get_jwt_manager
from concrete_console.oidc import (
    IdpOAuthError,
    exchange_authorization_code,
    google_authorize_redirect,
    oidc_settings,
    poll_device_code,
    start_device_flow,
    verify_google_id_token,
)
from concrete_console.sessions import issue_token_pair

router = APIRouter(prefix="/api/v1/auth")

REDIRECT_URI_RE = re.compile(r"^http://127\.0\.0\.1:[0-9]{1,5}/callback$")
PKCE_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")


class TokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    grant_type: str
    code: str = Field(min_length=1, max_length=255)
    code_verifier: str = Field(min_length=43, max_length=128)
    redirect_uri: str = Field(min_length=1, max_length=255)
    client_id: str = Field(min_length=1, max_length=255)


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=20, max_length=512)


class LogoutRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str | None = Field(default=None, max_length=512)


class DevicePollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_code: str = Field(min_length=1, max_length=255)
    polling_secret: str = Field(min_length=20, max_length=512)


class DeviceStartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str | None = Field(default=None, max_length=64)


def oauth_error(error: str) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": error})


def browser_error() -> HTMLResponse:
    return HTMLResponse(
        status_code=400,
        content=(
            "<!doctype html><html><head><meta charset=\"utf-8\"><title>Authentication failed</title>"
            "</head><body><h1>Authentication failed</h1><p>Return to the CLI and try again.</p></body></html>"
        ),
        headers={"Cache-Control": "no-store"},
    )


async def prune_expired_auth_rows(conn: asyncpg.Connection) -> None:
    await conn.execute("DELETE FROM loopback_auth_pending WHERE expires_at < now()")
    await conn.execute("DELETE FROM device_flow_pending WHERE expires_at < now()")


def request_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def request_id(request: Request) -> str | None:
    value = request.headers.get("x-request-id")
    return value[:128] if value else None


@router.post("/device/start")
async def device_start(
    body: DeviceStartRequest | None = Body(default=None),
    pool: asyncpg.Pool = Depends(get_pool),
):
    provider = (body.provider if body else None) or "google"
    if provider != "google":
        raise api_error(400, "BAD_REQUEST", "unsupported OIDC provider")
    try:
        idp_response = await start_device_flow()
    except (httpx.HTTPError, ValueError):
        raise api_error(502, "UPSTREAM_ERROR", "OIDC device authorization failed") from None

    device_code = idp_response.get("device_code")
    user_code = idp_response.get("user_code")
    verification_url = idp_response.get("verification_url") or idp_response.get("verification_uri")
    expires_in = int(idp_response.get("expires_in", 0))
    interval = int(idp_response.get("interval", 5))
    if not all(isinstance(value, str) and value for value in (device_code, user_code, verification_url)):
        raise api_error(502, "UPSTREAM_ERROR", "OIDC device authorization response was incomplete")
    if expires_in <= 0:
        raise api_error(502, "UPSTREAM_ERROR", "OIDC device authorization response was incomplete")

    polling_secret = random_token_urlsafe()
    async with pool.acquire() as conn:
        await prune_expired_auth_rows(conn)
        await conn.execute(
            """
            INSERT INTO device_flow_pending (
                device_code,
                polling_secret_hash,
                provider,
                expires_at,
                interval_seconds
            )
            VALUES ($1, $2, 'google', now() + ($3::int * interval '1 second'), $4)
            """,
            device_code,
            sha256_hex(polling_secret),
            expires_in,
            max(interval, 1),
        )
    return {
        "user_code": user_code,
        "verification_url": verification_url,
        "device_code": device_code,
        "polling_secret": polling_secret,
        "expires_in": expires_in,
        "interval": max(interval, 1),
    }


@router.post("/device/poll")
async def device_poll(
    body: DevicePollRequest,
    request: Request,
    pool: asyncpg.Pool = Depends(get_pool),
):
    now = datetime.now(timezone.utc)
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT device_code, polling_secret_hash, expires_at, interval_seconds, last_polled_at
                FROM device_flow_pending
                WHERE device_code = $1
                FOR UPDATE
                """,
                body.device_code,
            )
            if row is None:
                return oauth_error("access_denied")
            if not hmac.compare_digest(row["polling_secret_hash"], sha256_hex(body.polling_secret)):
                raise api_error(401, "UNAUTHORIZED", "invalid polling secret")
            if row["expires_at"] <= now:
                await conn.execute("DELETE FROM device_flow_pending WHERE device_code = $1", body.device_code)
                return oauth_error("expired_token")
            if row["last_polled_at"] is not None:
                earliest = row["last_polled_at"].timestamp() + max(row["interval_seconds"] - 1, 0)
                if now.timestamp() < earliest:
                    return oauth_error("slow_down")
            await conn.execute(
                "UPDATE device_flow_pending SET last_polled_at = now() WHERE device_code = $1",
                body.device_code,
            )

    try:
        idp_tokens = await poll_device_code(body.device_code)
    except IdpOAuthError as exc:
        if exc.error in {"authorization_pending", "slow_down"}:
            return oauth_error(exc.error)
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM device_flow_pending WHERE device_code = $1", body.device_code)
        return oauth_error(exc.error)
    except (httpx.HTTPError, jwt.PyJWTError, ValueError):
        raise api_error(502, "UPSTREAM_ERROR", "OIDC device token exchange failed") from None

    try:
        claims = await verify_google_id_token(idp_tokens.id_token, nonce=None, access_token=idp_tokens.access_token)
    except (jwt.PyJWTError, ValueError):
        raise api_error(502, "UPSTREAM_ERROR", "OIDC id_token verification failed") from None

    async with pool.acquire() as conn:
        async with conn.transaction():
            pending = await conn.fetchrow(
                """
                SELECT device_code
                FROM device_flow_pending
                WHERE device_code = $1
                FOR UPDATE
                """,
                body.device_code,
            )
            if pending is None:
                return oauth_error("access_denied")
            user_id = await resolve_oidc_user(conn, provider="google", claims=claims)
            await conn.execute("DELETE FROM device_flow_pending WHERE device_code = $1", body.device_code)
            token_pair = await issue_token_pair(
                conn,
                user_id=user_id,
                ip_address=request_ip(request),
                request_id=request_id(request),
            )
            await insert_audit_event(
                conn,
                entity_id=token_pair.entity_id,
                actor_id=token_pair.user_id,
                actor_email=token_pair.actor_email,
                action="AUTH_SESSION_ISSUED",
                target_type="user",
                target_id=token_pair.user_id,
                after={"refresh_jti": str(token_pair.refresh_jti), "flow": "device"},
            )
            return token_pair.response


@router.get("/authorize")
async def authorize(
    client_id: str,
    redirect_uri: str,
    response_type: str,
    code_challenge: str,
    code_challenge_method: str,
    state: str,
    scope: str,
    pool: asyncpg.Pool = Depends(get_pool),
) -> RedirectResponse:
    settings = oidc_settings()
    if client_id not in settings.client_allowlist:
        raise api_error(400, "BAD_REQUEST", "client_id is not allowed")
    if response_type != "code":
        raise api_error(400, "BAD_REQUEST", "response_type must be code")
    if not REDIRECT_URI_RE.fullmatch(redirect_uri):
        raise api_error(400, "BAD_REQUEST", "redirect_uri is not allowed")
    if code_challenge_method != "S256" or not PKCE_RE.fullmatch(code_challenge):
        raise api_error(400, "BAD_REQUEST", "invalid PKCE challenge")
    if len(state) < 32:
        raise api_error(400, "BAD_REQUEST", "state is too short")
    if "openid" not in set(scope.split()):
        raise api_error(400, "BAD_REQUEST", "scope must include openid")

    idp_state = random_token_urlsafe()
    idp_nonce = random_token_urlsafe()
    async with pool.acquire() as conn:
        await prune_expired_auth_rows(conn)
        try:
            await conn.execute(
                """
                INSERT INTO loopback_auth_pending (
                    state,
                    client_id,
                    code_challenge,
                    redirect_uri,
                    idp_state,
                    idp_nonce,
                    expires_at
                )
                VALUES ($1, $2, $3, $4, $5, $6, now() + interval '10 minutes')
                """,
                state,
                client_id,
                code_challenge,
                redirect_uri,
                idp_state,
                idp_nonce,
            )
        except asyncpg.UniqueViolationError:
            raise api_error(400, "BAD_REQUEST", "state is already in use") from None
    return RedirectResponse(google_authorize_redirect(idp_state=idp_state, nonce=idp_nonce, settings=settings), status_code=303)


@router.get("/oidc/callback")
async def oidc_callback(
    code: str,
    state: str,
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    async with pool.acquire() as conn:
        await prune_expired_auth_rows(conn)
        pending = await conn.fetchrow(
            """
            SELECT state, idp_nonce, redirect_uri
            FROM loopback_auth_pending
            WHERE idp_state = $1
            """,
            state,
        )
    if pending is None:
        return browser_error()

    try:
        idp_tokens = await exchange_authorization_code(code)
        claims = await verify_google_id_token(
            idp_tokens.id_token,
            nonce=pending["idp_nonce"],
            access_token=idp_tokens.access_token,
        )
        console_authz_code = random_token_urlsafe()
        async with pool.acquire() as conn:
            async with conn.transaction():
                locked = await conn.fetchrow(
                    """
                    SELECT state
                    FROM loopback_auth_pending
                    WHERE state = $1
                      AND expires_at > now()
                    FOR UPDATE
                    """,
                    pending["state"],
                )
                if locked is None:
                    return browser_error()
                user_id = await resolve_oidc_user(conn, provider="google", claims=claims)
                await conn.execute(
                    """
                    UPDATE loopback_auth_pending
                    SET console_authz_code_hash = $2,
                        user_id = $3
                    WHERE state = $1
                    """,
                    pending["state"],
                    sha256_hex(console_authz_code),
                    user_id,
                )
    except (httpx.HTTPError, jwt.PyJWTError, ValueError, HTTPException):
        async with pool.acquire() as conn:
            await conn.execute("DELETE FROM loopback_auth_pending WHERE state = $1", pending["state"])
        return browser_error()

    separator = "&" if "?" in pending["redirect_uri"] else "?"
    return RedirectResponse(
        f"{pending['redirect_uri']}{separator}code={console_authz_code}&state={pending['state']}",
        status_code=303,
    )


@router.post("/token")
async def token(
    body: TokenRequest,
    request: Request,
    pool: asyncpg.Pool = Depends(get_pool),
):
    if body.grant_type != "authorization_code":
        return oauth_error("invalid_request")
    if not PKCE_RE.fullmatch(body.code_verifier):
        return oauth_error("invalid_grant")

    async with pool.acquire() as conn:
        async with conn.transaction():
            await prune_expired_auth_rows(conn)
            pending = await conn.fetchrow(
                """
                SELECT state, client_id, code_challenge, redirect_uri, user_id
                FROM loopback_auth_pending
                WHERE console_authz_code_hash = $1
                FOR UPDATE
                """,
                sha256_hex(body.code),
            )
            if pending is None or pending["user_id"] is None:
                return oauth_error("invalid_grant")
            if pending["client_id"] != body.client_id or pending["redirect_uri"] != body.redirect_uri:
                return oauth_error("invalid_request")
            if pkce_s256(body.code_verifier) != pending["code_challenge"]:
                return oauth_error("invalid_grant")

            await conn.execute("DELETE FROM loopback_auth_pending WHERE state = $1", pending["state"])
            token_pair = await issue_token_pair(
                conn,
                user_id=pending["user_id"],
                ip_address=request_ip(request),
                request_id=request_id(request),
            )
            await insert_audit_event(
                conn,
                entity_id=token_pair.entity_id,
                actor_id=token_pair.user_id,
                actor_email=token_pair.actor_email,
                action="AUTH_SESSION_ISSUED",
                target_type="user",
                target_id=token_pair.user_id,
                after={"refresh_jti": str(token_pair.refresh_jti)},
            )
            return token_pair.response


@router.post("/refresh")
async def refresh(
    body: RefreshRequest,
    request: Request,
    pool: asyncpg.Pool = Depends(get_pool),
):
    async with pool.acquire() as conn:
        async with conn.transaction():
            row = await conn.fetchrow(
                """
                SELECT
                    rt.*,
                    u.email AS actor_email,
                    u.entity_id
                FROM refresh_tokens rt
                JOIN users u ON u.id = rt.user_id
                WHERE rt.token_hash = $1
                FOR UPDATE
                """,
                sha256_hex(body.refresh_token),
            )
            if row is None:
                raise api_error(401, "UNAUTHORIZED", "invalid refresh token")
            if row["redeemed_at"] is not None:
                revoked_rows = await conn.fetch(
                    """
                    UPDATE refresh_tokens
                    SET revoked_at = COALESCE(revoked_at, now())
                    WHERE family_id = $1
                    RETURNING access_jti, access_expires_at
                    """,
                    row["family_id"],
                )
                for revoked in revoked_rows:
                    await conn.execute(
                        """
                        INSERT INTO revoked_tokens (jti, expires_at)
                        VALUES ($1, $2)
                        ON CONFLICT (jti) DO NOTHING
                        """,
                        revoked["access_jti"],
                        revoked["access_expires_at"],
                    )
                await insert_audit_event(
                    conn,
                    entity_id=row["entity_id"],
                    actor_id=row["user_id"],
                    actor_email=row["actor_email"],
                    action="AUTH_REFRESH_REUSE_DETECTED",
                    target_type="user",
                    target_id=row["user_id"],
                    before={"family_root_jti": str(row["family_id"]), "replayed_jti": str(row["jti"])},
                    after={"revoked_refresh_token_count": len(revoked_rows)},
                )
                return JSONResponse(
                    status_code=401,
                    content={"error": {"code": "UNAUTHORIZED", "message": "invalid refresh token", "details": {}}},
                )
            if row["revoked_at"] is not None or row["expires_at"] <= datetime.now(timezone.utc):
                raise api_error(401, "UNAUTHORIZED", "invalid refresh token")

            await conn.execute("UPDATE refresh_tokens SET redeemed_at = now() WHERE jti = $1", row["jti"])
            token_pair = await issue_token_pair(
                conn,
                user_id=row["user_id"],
                family_id=row["family_id"],
                parent_jti=row["jti"],
                ip_address=request_ip(request),
                request_id=request_id(request),
            )
            await insert_audit_event(
                conn,
                entity_id=token_pair.entity_id,
                actor_id=token_pair.user_id,
                actor_email=token_pair.actor_email,
                action="AUTH_SESSION_REFRESHED",
                target_type="user",
                target_id=token_pair.user_id,
                after={"refresh_jti": str(token_pair.refresh_jti), "parent_jti": str(row["jti"])},
            )
            return token_pair.response


@router.post("/logout", status_code=204)
async def logout(
    body: LogoutRequest,
    authorization: Annotated[str | None, Header()] = None,
    pool: asyncpg.Pool = Depends(get_pool),
) -> Response:
    access_jti = None
    access_exp = None
    user_id = None
    try:
        if authorization is not None and authorization.startswith("Bearer "):
            claims = get_jwt_manager().verify_access_token(authorization.removeprefix("Bearer "))
            access_jti = UUID(str(claims.get("jti")))
            access_exp = claims.get("exp")
            user_id = UUID(str(claims.get("sub")))
    except (jwt.PyJWTError, ValueError):
        access_jti = None
        access_exp = None
        user_id = None

    async with pool.acquire() as conn:
        async with conn.transaction():
            actor = None
            if user_id is not None:
                actor = await conn.fetchrow("SELECT id, email, entity_id FROM users WHERE id = $1", user_id)
            if access_jti is not None and access_exp is not None:
                await conn.execute(
                    """
                    INSERT INTO revoked_tokens (jti, expires_at, revoked_by)
                    VALUES ($1, to_timestamp($2), $3)
                    ON CONFLICT (jti) DO NOTHING
                    """,
                    access_jti,
                    access_exp,
                    actor["id"] if actor else None,
                )
            if body.refresh_token:
                await conn.execute(
                    """
                    UPDATE refresh_tokens
                    SET revoked_at = COALESCE(revoked_at, now())
                    WHERE token_hash = $1
                    """,
                    sha256_hex(body.refresh_token),
                )
            if actor:
                await insert_audit_event(
                    conn,
                    entity_id=actor["entity_id"],
                    actor_id=actor["id"],
                    actor_email=actor["email"],
                    action="AUTH_SESSION_REVOKED",
                    target_type="user",
                    target_id=actor["id"],
                )
    return Response(status_code=204)
