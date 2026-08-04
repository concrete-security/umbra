from __future__ import annotations

import base64
import hashlib
import secrets


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def random_token_urlsafe(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def pkce_s256(code_verifier: str) -> str:
    return b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())
