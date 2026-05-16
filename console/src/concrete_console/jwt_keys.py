from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
from threading import RLock
from typing import Any
from uuid import UUID, uuid4

import jwt

from concrete_console.config import load_settings

KID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
TOKEN_SEGMENT_RE = re.compile(r"^[A-Za-z0-9_-]+$")
FORBIDDEN_KEY_HEADERS = {"jku", "jwk", "x5u", "x5c"}
FORBIDDEN_ACCESS_TOKEN_CLAIMS = {"email", "permissions", "profiles"}
ALLOWED_ALGORITHMS = {"EdDSA", "RS256"}


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


@dataclass(frozen=True)
class RotationResult:
    old_active_kid: str
    active_kid: str
    retiring_kids: tuple[str, ...]


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


def _load_key_material(settings: JwtSettings, *, active_kid: str) -> tuple[str, dict[str, VerifyingKey]]:
    if settings.algorithm not in ALLOWED_ALGORITHMS:
        raise ValueError("JWT_ALGORITHM must be EdDSA or RS256")
    if not KID_RE.fullmatch(active_kid):
        raise ValueError("JWT active kid has invalid characters")

    private_key = _file_ref_path(settings.private_key_ref).read_text()
    jwks = json.loads(_file_ref_path(settings.public_keys_ref).read_text())
    keys: dict[str, VerifyingKey] = {}
    for jwk in jwks.get("keys", []):
        kid = jwk.get("kid")
        if not isinstance(kid, str) or not KID_RE.fullmatch(kid):
            raise ValueError("JWKS entry has invalid kid")
        alg = jwk.get("alg") or settings.algorithm
        if alg not in ALLOWED_ALGORITHMS:
            raise ValueError("JWKS entry has unsupported alg")
        keys[kid] = VerifyingKey(kid=kid, alg=alg, key=_jwk_to_key({**jwk, "alg": alg}))
    if active_kid not in keys:
        raise ValueError("active kid must appear in JWT_PUBLIC_KEYS_REF")
    if keys[active_kid].alg != settings.algorithm:
        raise ValueError("active kid algorithm must match JWT_ALGORITHM")
    _self_test_active_key(private_key, keys[active_kid], algorithm=settings.algorithm)
    return private_key, keys


def _self_test_active_key(private_key: str, verifying_key: VerifyingKey, *, algorithm: str) -> None:
    token = jwt.encode(
        {"probe": "jwt-key-self-test"},
        private_key,
        algorithm=algorithm,
        headers={"kid": verifying_key.kid, "typ": "at+JWT", "alg": algorithm},
    )
    jwt.decode(token, verifying_key.key, algorithms=[verifying_key.alg], options={"verify_aud": False})


class JwtManager:
    def __init__(self, settings: JwtSettings):
        self.settings = settings
        self.active_kid = settings.active_kid
        self.private_key, keys = _load_key_material(settings, active_kid=settings.active_kid)
        self.verifying_keys = keys
        self._retiring_deadlines: dict[str, datetime] = {}
        self._lock = RLock()

    def issue_access_token(self, *, user_id: UUID, entity_id: UUID) -> SigningResult:
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=self.settings.access_ttl_seconds)
        jti = uuid4()
        with self._lock:
            private_key = self.private_key
            active_kid = self.active_kid
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
            private_key,
            algorithm=self.settings.algorithm,
            headers={
                "kid": active_kid,
                "typ": "at+JWT",
                "alg": self.settings.algorithm,
            },
        )
        return SigningResult(access_token=token, jti=jti, expires_at=expires_at)

    def rotate(self, *, new_kid: str, retire_old_after_seconds: int) -> RotationResult:
        if not KID_RE.fullmatch(new_kid):
            raise ValueError("new_kid has invalid characters")
        if retire_old_after_seconds < 0 or retire_old_after_seconds > 86_400:
            raise ValueError("retire_old_after_seconds is out of range")

        with self._lock:
            now = datetime.now(timezone.utc)
            self._prune_retired_keys(now)
            old_active_kid = self.active_kid
            old_keys = dict(self.verifying_keys)
            old_kids = tuple(sorted(kid for kid in old_keys if kid != new_kid))
            private_key, new_keys = _load_key_material(self.settings, active_kid=new_kid)

            retiring_kids: tuple[str, ...] = ()
            if retire_old_after_seconds > 0:
                deadline = now + timedelta(seconds=retire_old_after_seconds)
                for kid in old_kids:
                    new_keys[kid] = old_keys[kid]
                    self._retiring_deadlines[kid] = deadline
                retiring_kids = old_kids
            else:
                for kid in old_kids:
                    new_keys.pop(kid, None)

            self.private_key = private_key
            self.verifying_keys = new_keys
            self.active_kid = new_kid
            self._retiring_deadlines.pop(new_kid, None)
            self._retiring_deadlines = {
                kid: deadline
                for kid, deadline in self._retiring_deadlines.items()
                if kid in self.verifying_keys and kid != self.active_kid
            }
            return RotationResult(
                old_active_kid=old_active_kid,
                active_kid=new_kid,
                retiring_kids=retiring_kids,
            )

    def verify_access_token(self, token: str) -> dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3 or any(not part or not TOKEN_SEGMENT_RE.fullmatch(part) for part in parts):
            raise jwt.InvalidTokenError("invalid token shape")

        header_segment = parts[0]
        try:
            header_bytes = base64.urlsafe_b64decode(header_segment + "=" * (-len(header_segment) % 4))
            header = json.loads(header_bytes)
        except Exception as exc:  # noqa: BLE001
            raise jwt.InvalidTokenError("invalid token header") from exc
        if not isinstance(header, dict):
            raise jwt.InvalidTokenError("invalid token header")

        if FORBIDDEN_KEY_HEADERS.intersection(header):
            raise jwt.InvalidTokenError("caller-supplied key headers are forbidden")
        alg = header.get("alg")
        if not isinstance(alg, str) or alg.lower() == "none" or alg not in ALLOWED_ALGORITHMS:
            raise jwt.InvalidTokenError("unsupported algorithm")
        if header.get("typ") not in {None, "at+JWT"}:
            raise jwt.InvalidTokenError("invalid token type")
        kid = header.get("kid")
        if not isinstance(kid, str) or not KID_RE.fullmatch(kid):
            raise jwt.InvalidTokenError("invalid kid")
        with self._lock:
            self._prune_retired_keys(datetime.now(timezone.utc))
            verifying_key = self.verifying_keys.get(kid)
        if verifying_key is None:
            raise jwt.InvalidTokenError("unknown kid")
        if alg != verifying_key.alg:
            raise jwt.InvalidTokenError("algorithm mismatch")

        claims = jwt.decode(
            token,
            verifying_key.key,
            algorithms=[verifying_key.alg],
            issuer=self.settings.issuer,
            audience=self.settings.audience,
            leeway=self.settings.leeway_seconds,
            options={"require": ["iss", "aud", "sub", "entity_id", "iat", "nbf", "exp", "jti"]},
        )
        if FORBIDDEN_ACCESS_TOKEN_CLAIMS.intersection(claims):
            raise jwt.InvalidTokenError("forbidden access token claims")
        return claims

    def _prune_retired_keys(self, now: datetime) -> None:
        expired = [kid for kid, deadline in self._retiring_deadlines.items() if deadline <= now]
        for kid in expired:
            if kid != self.active_kid:
                self.verifying_keys.pop(kid, None)
            self._retiring_deadlines.pop(kid, None)


_manager: JwtManager | None = None


def get_jwt_manager() -> JwtManager:
    global _manager
    if _manager is None:
        _manager = JwtManager(_settings())
    return _manager


def reset_jwt_manager_for_tests() -> None:
    global _manager
    _manager = None
