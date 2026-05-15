from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from typing import Any
from uuid import UUID, uuid4

import jwt

from concrete_console.config import load_settings

KID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
FORBIDDEN_KEY_HEADERS = {"jku", "jwk", "x5u", "x5c"}


@dataclass(frozen=True)
class SigningResult:
    access_token: str
    jti: UUID
    expires_at: datetime


@dataclass(frozen=True)
class JwtSettings:
    algorithm: str
    private_key_ref: str
    public_keys_ref: str
    active_kid: str
    issuer: str
    audience: str
    access_ttl_seconds: int
    leeway_seconds: int


@dataclass(frozen=True)
class VerifyingKey:
    kid: str
    alg: str
    key: Any


def _file_ref_path(ref: str) -> Path:
    if not ref.startswith("file://"):
        raise ValueError(f"unsupported key reference: {ref.split(':', 1)[0]}")
    return Path(ref.removeprefix("file://"))


def _settings() -> JwtSettings:
    raw = load_settings().raw
    return JwtSettings(
        algorithm=raw.get("JWT_ALGORITHM", "EdDSA"),
        private_key_ref=raw["JWT_PRIVATE_KEY_REF"],
        public_keys_ref=raw["JWT_PUBLIC_KEYS_REF"],
        active_kid=raw["JWT_ACTIVE_KID"],
        issuer=raw.get("JWT_ISSUER", "concrete-console"),
        audience=raw.get("JWT_AUDIENCE", "concrete-console"),
        access_ttl_seconds=int(raw.get("JWT_ACCESS_TOKEN_TTL_SECONDS", "3600")),
        leeway_seconds=int(raw.get("JWT_LEEWAY_SECONDS", "30")),
    )


def _jwk_to_key(jwk: dict[str, Any]) -> Any:
    return jwt.PyJWK.from_dict(jwk).key


class JwtManager:
    def __init__(self, settings: JwtSettings):
        if settings.algorithm not in {"EdDSA", "RS256"}:
            raise ValueError("JWT_ALGORITHM must be EdDSA or RS256")
        if not KID_RE.fullmatch(settings.active_kid):
            raise ValueError("JWT_ACTIVE_KID has invalid characters")

        self.settings = settings
        self.private_key = _file_ref_path(settings.private_key_ref).read_text()
        jwks = json.loads(_file_ref_path(settings.public_keys_ref).read_text())
        keys: dict[str, VerifyingKey] = {}
        for jwk in jwks.get("keys", []):
            kid = jwk.get("kid")
            if not isinstance(kid, str) or not KID_RE.fullmatch(kid):
                raise ValueError("JWKS entry has invalid kid")
            alg = jwk.get("alg") or settings.algorithm
            if alg not in {"EdDSA", "RS256"}:
                raise ValueError("JWKS entry has unsupported alg")
            keys[kid] = VerifyingKey(kid=kid, alg=alg, key=_jwk_to_key({**jwk, "alg": alg}))
        if settings.active_kid not in keys:
            raise ValueError("JWT_ACTIVE_KID must appear in JWT_PUBLIC_KEYS_REF")
        self.verifying_keys = keys

    def issue_access_token(self, *, user_id: UUID, entity_id: UUID) -> SigningResult:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=self.settings.access_ttl_seconds)
        jti = uuid4()
        payload = {
            "iss": self.settings.issuer,
            "aud": self.settings.audience,
            "sub": str(user_id),
            "entity_id": str(entity_id),
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": str(jti),
        }
        token = jwt.encode(
            payload,
            self.private_key,
            algorithm=self.settings.algorithm,
            headers={
                "kid": self.settings.active_kid,
                "typ": "at+JWT",
                "alg": self.settings.algorithm,
            },
        )
        return SigningResult(access_token=token, jti=jti, expires_at=expires_at)

    def verify_access_token(self, token: str) -> dict[str, Any]:
        if token.count(".") != 2 or any(not part for part in token.split(".")):
            raise jwt.InvalidTokenError("invalid token shape")

        header_segment = token.split(".", 1)[0]
        try:
            header_bytes = base64.urlsafe_b64decode(header_segment + "=" * (-len(header_segment) % 4))
            header = json.loads(header_bytes)
        except Exception as exc:  # noqa: BLE001
            raise jwt.InvalidTokenError("invalid token header") from exc

        if FORBIDDEN_KEY_HEADERS.intersection(header):
            raise jwt.InvalidTokenError("caller-supplied key headers are forbidden")
        kid = header.get("kid")
        if not isinstance(kid, str) or not KID_RE.fullmatch(kid):
            raise jwt.InvalidTokenError("invalid kid")
        verifying_key = self.verifying_keys.get(kid)
        if verifying_key is None:
            raise jwt.InvalidTokenError("unknown kid")
        if header.get("alg") != verifying_key.alg:
            raise jwt.InvalidTokenError("algorithm mismatch")
        if header.get("typ") not in {None, "at+JWT"}:
            raise jwt.InvalidTokenError("invalid token type")

        return jwt.decode(
            token,
            verifying_key.key,
            algorithms=[verifying_key.alg],
            issuer=self.settings.issuer,
            audience=self.settings.audience,
            leeway=self.settings.leeway_seconds,
        )


_manager: JwtManager | None = None


def get_jwt_manager() -> JwtManager:
    global _manager
    if _manager is None:
        _manager = JwtManager(_settings())
    return _manager


def reset_jwt_manager_for_tests() -> None:
    global _manager
    _manager = None
