from __future__ import annotations

import base64
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from concrete_console.config import load_settings

SECRET_INJECTION_KEK_ENV = "SECRET_INJECTION_KEK_B64"
SECRET_INJECTION_ENVELOPE_VERSION = "v1"
SECRET_INJECTION_NONCE_BYTES = 12
SECRET_INJECTION_KEY_BYTES = 32
PUBLIC_SECRET_INJECTION_FIELDS = {"id", "match", "type", "header", "value_template"}


def load_secret_injection_kek() -> bytes:
    raw = load_settings().raw.get(SECRET_INJECTION_KEK_ENV, "").strip()
    if not raw:
        raise ValueError(f"{SECRET_INJECTION_KEK_ENV} is required")
    try:
        padded = raw + "=" * (-len(raw) % 4)
        key = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{SECRET_INJECTION_KEK_ENV} must be base64") from exc
    if len(key) != SECRET_INJECTION_KEY_BYTES:
        raise ValueError(f"{SECRET_INJECTION_KEK_ENV} must decode to 32 bytes")
    return key


def check_secret_injection_kek() -> None:
    load_secret_injection_kek()


def encrypt_profile_secret_value(*, profile_id: Any, injection_id: str, value: str) -> str:
    nonce = os.urandom(SECRET_INJECTION_NONCE_BYTES)
    encrypted = AESGCM(load_secret_injection_kek()).encrypt(
        nonce,
        value.encode("utf-8"),
        _secret_aad(profile_id, injection_id),
    )
    payload = base64.urlsafe_b64encode(nonce + encrypted).decode("ascii").rstrip("=")
    return f"{SECRET_INJECTION_ENVELOPE_VERSION}:{payload}"


def decrypt_profile_secret_value(*, profile_id: Any, injection_id: str, ciphertext: str) -> str:
    prefix = f"{SECRET_INJECTION_ENVELOPE_VERSION}:"
    if not ciphertext.startswith(prefix):
        raise ValueError("unsupported profile secret ciphertext envelope")
    encoded = ciphertext.removeprefix(prefix)
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("invalid profile secret ciphertext envelope") from exc
    if len(payload) <= SECRET_INJECTION_NONCE_BYTES:
        raise ValueError("invalid profile secret ciphertext payload")
    nonce = payload[:SECRET_INJECTION_NONCE_BYTES]
    encrypted = payload[SECRET_INJECTION_NONCE_BYTES:]
    plaintext = AESGCM(load_secret_injection_kek()).decrypt(
        nonce,
        encrypted,
        _secret_aad(profile_id, injection_id),
    )
    return plaintext.decode("utf-8")


def split_profile_policy_secret_values(policy: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    public_policy = dict(policy)
    secret_values: dict[str, str] = {}
    secret_injections = public_policy.get("secret_injections")
    if not isinstance(secret_injections, list):
        return public_policy, secret_values
    public_injections: list[dict[str, Any]] = []
    for injection in secret_injections:
        if not isinstance(injection, dict):
            continue
        injection_id = injection.get("id")
        if isinstance(injection_id, str) and isinstance(injection.get("value"), str):
            secret_values[injection_id] = injection["value"]
        public_injections.append(public_secret_injection(injection))
    public_policy["secret_injections"] = public_injections
    return public_policy, secret_values


def redacted_profile_policy(policy: Any) -> Any:
    if not isinstance(policy, dict):
        return {}
    public_policy, _ = split_profile_policy_secret_values(policy)
    return public_policy


def expand_profile_policy_secret_values(
    *,
    profile_id: Any,
    policy: dict[str, Any],
    secret_material: dict[str, Any],
) -> dict[str, Any]:
    public_policy = redacted_profile_policy(policy)
    secret_injections = public_policy.get("secret_injections")
    if not isinstance(secret_injections, list):
        return public_policy
    expanded: list[dict[str, Any]] = []
    for injection in secret_injections:
        if not isinstance(injection, dict):
            continue
        injection_id = injection.get("id")
        if not isinstance(injection_id, str):
            expanded.append(injection)
            continue
        ciphertext = secret_material.get(injection_id)
        if isinstance(ciphertext, str):
            injection = {
                **injection,
                "value": decrypt_profile_secret_value(
                    profile_id=profile_id,
                    injection_id=injection_id,
                    ciphertext=ciphertext,
                ),
            }
        expanded.append(injection)
    public_policy["secret_injections"] = expanded
    return public_policy


def public_secret_injection(injection: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in injection.items() if key in PUBLIC_SECRET_INJECTION_FIELDS}


def _secret_aad(profile_id: Any, injection_id: str) -> bytes:
    return f"concrete.profile_secret_material.{SECRET_INJECTION_ENVELOPE_VERSION}:{profile_id}:{injection_id}".encode(
        "utf-8"
    )
