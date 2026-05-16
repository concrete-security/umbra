from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import re
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

from concrete_console.config import load_settings
from concrete_console.crypto import b64url

FORBIDDEN_KEY_HEADERS = {"jku", "jwk", "x5u", "x5c"}
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_DEVICE_CODE_URL = "https://oauth2.googleapis.com/device/code"
GOOGLE_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"
GOOGLE_ISSUERS = {"https://accounts.google.com", "accounts.google.com"}
GOOGLE_KID_RE = re.compile(r"^[a-f0-9]{40}$")


@dataclass(frozen=True)
class OidcSettings:
    google_client_id: str
    google_client_secret: str
    console_url: str
    client_allowlist: frozenset[str]
    authorize_url: str
    token_url: str
    device_code_url: str
    jwks_url: str


@dataclass(frozen=True)
class IdpTokenResponse:
    id_token: str
    access_token: str | None


class IdpOAuthError(Exception):
    def __init__(self, error: str):
        super().__init__(error)
        self.error = error


@dataclass
class JwksCache:
    keys: dict[str, dict[str, Any]]
    expires_at: datetime


_jwks_cache: JwksCache | None = None


def _truthy(value: str | None) -> bool:
    return value is not None and value.strip().lower() in {"1", "true", "yes", "on"}


def _endpoint(raw: dict[str, str], name: str, default: str) -> str:
    value = raw.get(name, "").strip()
    if not value:
        return default
    if not (_truthy(raw.get("OIDC_OVERRIDES_ALLOWED")) and raw.get("LOG_LEVEL", "").lower() == "debug"):
        raise ValueError(f"{name} override requires OIDC_OVERRIDES_ALLOWED=true and LOG_LEVEL=debug")
    return value


def oidc_settings() -> OidcSettings:
    raw = load_settings().raw
    allowlist = frozenset(item.strip() for item in raw.get("OIDC_CLIENT_ALLOWLIST", "").split(",") if item.strip())
    return OidcSettings(
        google_client_id=raw["GOOGLE_OIDC_CLIENT_ID"],
        google_client_secret=raw["GOOGLE_OIDC_CLIENT_SECRET"],
        console_url=raw["CONSOLE_URL"].rstrip("/"),
        client_allowlist=allowlist,
        authorize_url=GOOGLE_AUTH_URL,
        token_url=_endpoint(raw, "GOOGLE_TOKEN_URL", GOOGLE_TOKEN_URL),
        device_code_url=_endpoint(raw, "GOOGLE_DEVICE_CODE_URL", GOOGLE_DEVICE_CODE_URL),
        jwks_url=_endpoint(raw, "GOOGLE_JWKS_URL", GOOGLE_JWKS_URL),
    )


def google_authorize_redirect(*, idp_state: str, nonce: str, settings: OidcSettings | None = None) -> str:
    settings = settings or oidc_settings()
    query = urlencode(
        {
            "client_id": settings.google_client_id,
            "redirect_uri": f"{settings.console_url}/api/v1/auth/oidc/callback",
            "response_type": "code",
            "scope": "openid email profile",
            "state": idp_state,
            "nonce": nonce,
            "prompt": "consent",
        }
    )
    return f"{settings.authorize_url}?{query}"


async def exchange_authorization_code(code: str, *, settings: OidcSettings | None = None) -> IdpTokenResponse:
    settings = settings or oidc_settings()
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            settings.token_url,
            data={
                "code": code,
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "redirect_uri": f"{settings.console_url}/api/v1/auth/oidc/callback",
                "grant_type": "authorization_code",
            },
        )
    response.raise_for_status()
    body = response.json()
    id_token = body.get("id_token")
    if not isinstance(id_token, str):
        raise ValueError("token endpoint did not return id_token")
    access_token = body.get("access_token")
    return IdpTokenResponse(
        id_token=id_token,
        access_token=access_token if isinstance(access_token, str) else None,
    )


async def start_device_flow(*, settings: OidcSettings | None = None) -> dict[str, Any]:
    settings = settings or oidc_settings()
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            settings.device_code_url,
            data={
                "client_id": settings.google_client_id,
                "scope": "openid email profile",
            },
        )
    response.raise_for_status()
    return response.json()


async def poll_device_code(device_code: str, *, settings: OidcSettings | None = None) -> IdpTokenResponse:
    settings = settings or oidc_settings()
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(
            settings.token_url,
            data={
                "client_id": settings.google_client_id,
                "client_secret": settings.google_client_secret,
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            },
        )
    if response.status_code >= 400:
        try:
            error = response.json().get("error")
        except ValueError:
            error = None
        if isinstance(error, str) and error:
            raise IdpOAuthError(error)
        response.raise_for_status()

    body = response.json()
    id_token = body.get("id_token")
    if not isinstance(id_token, str):
        raise ValueError("token endpoint did not return id_token")
    access_token = body.get("access_token")
    return IdpTokenResponse(
        id_token=id_token,
        access_token=access_token if isinstance(access_token, str) else None,
    )


def _decode_header(token: str) -> dict[str, Any]:
    if token.count(".") != 2:
        raise jwt.InvalidTokenError("invalid token shape")
    header_segment = token.split(".", 1)[0]
    try:
        header_bytes = base64.urlsafe_b64decode(header_segment + "=" * (-len(header_segment) % 4))
        header = json.loads(header_bytes)
    except Exception as exc:  # noqa: BLE001
        raise jwt.InvalidTokenError("invalid token header") from exc
    if not isinstance(header, dict):
        raise jwt.InvalidTokenError("invalid token header")
    return header


async def _load_jwks(settings: OidcSettings, *, force: bool = False) -> dict[str, dict[str, Any]]:
    global _jwks_cache
    now = datetime.now(timezone.utc)
    if not force and _jwks_cache is not None and _jwks_cache.expires_at > now:
        return _jwks_cache.keys

    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(settings.jwks_url)
    response.raise_for_status()
    body = response.json()
    keys: dict[str, dict[str, Any]] = {}
    for jwk in body.get("keys", []):
        kid = jwk.get("kid")
        if isinstance(kid, str):
            keys[kid] = jwk
    _jwks_cache = JwksCache(keys=keys, expires_at=now + timedelta(minutes=5))
    return keys


async def load_google_jwks(*, settings: OidcSettings | None = None, force: bool = False) -> dict[str, dict[str, Any]]:
    return await _load_jwks(settings or oidc_settings(), force=force)


def _at_hash(access_token: str) -> str:
    digest = jwt.algorithms.get_default_algorithms()["RS256"].compute_hash_digest(access_token.encode("ascii"))
    return b64url(digest[: len(digest) // 2])


async def verify_google_id_token(
    id_token: str,
    *,
    nonce: str | None,
    access_token: str | None,
    settings: OidcSettings | None = None,
) -> dict[str, Any]:
    settings = settings or oidc_settings()
    header = _decode_header(id_token)
    if FORBIDDEN_KEY_HEADERS.intersection(header):
        raise jwt.InvalidTokenError("caller-supplied key headers are forbidden")
    if header.get("alg") != "RS256":
        raise jwt.InvalidTokenError("unsupported id_token algorithm")
    if header.get("typ") == "at+JWT":
        raise jwt.InvalidTokenError("wrong token type")
    kid = header.get("kid")
    if not isinstance(kid, str) or not GOOGLE_KID_RE.fullmatch(kid):
        raise jwt.InvalidTokenError("invalid id_token kid")

    keys = await load_google_jwks(settings=settings)
    jwk = keys.get(kid)
    if jwk is None:
        keys = await load_google_jwks(settings=settings, force=True)
        jwk = keys.get(kid)
    if jwk is None:
        raise jwt.InvalidTokenError("unknown id_token kid")
    if jwk.get("alg", "RS256") != "RS256":
        raise jwt.InvalidTokenError("algorithm mismatch")

    claims = jwt.decode(
        id_token,
        jwt.PyJWK.from_dict({**jwk, "alg": "RS256"}).key,
        algorithms=["RS256"],
        audience=settings.google_client_id,
        options={"require": ["exp", "iat", "sub", "email"]},
        leeway=300,
    )
    if claims.get("iss") not in GOOGLE_ISSUERS:
        raise jwt.InvalidTokenError("invalid issuer")
    audience = claims.get("aud")
    if isinstance(audience, list):
        if any(item != settings.google_client_id for item in audience):
            raise jwt.InvalidTokenError("invalid audience")
        if claims.get("azp") != settings.google_client_id:
            raise jwt.InvalidTokenError("invalid authorized party")
    elif claims.get("azp") not in {None, settings.google_client_id}:
        raise jwt.InvalidTokenError("invalid authorized party")
    if claims.get("email_verified") is not True:
        raise jwt.InvalidTokenError("email is not verified")
    if nonce is not None and claims.get("nonce") != nonce:
        raise jwt.InvalidTokenError("invalid nonce")
    if access_token is not None:
        at_hash = claims.get("at_hash")
        if not isinstance(at_hash, str) or at_hash != _at_hash(access_token):
            raise jwt.InvalidTokenError("invalid at_hash")
    return claims


def reset_jwks_cache_for_tests() -> None:
    global _jwks_cache
    _jwks_cache = None
