from __future__ import annotations

import base64
import os
import re
from typing import Any, Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from concrete_console.config import load_settings

SECRET_INJECTION_KEK_ENV = "SECRET_INJECTION_KEK_B64"
SECRET_INJECTION_ENVELOPE_VERSION = "v1"
SECRET_INJECTION_NONCE_BYTES = 12
SECRET_INJECTION_KEY_BYTES = 32
SECRET_INJECTION_RENDERED_MAX_LEN = 8192
PUBLIC_SECRET_INJECTION_FIELDS = {"id", "match", "type", "header", "value_from", "value_template"}
SECRET_HOST_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


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
    return _encrypt_secret_value(aad=_secret_aad(profile_id, injection_id), value=value)


def decrypt_profile_secret_value(*, profile_id: Any, injection_id: str, ciphertext: str) -> str:
    return _decrypt_secret_value(aad=_secret_aad(profile_id, injection_id), ciphertext=ciphertext)


def encrypt_user_secret_value(*, user_id: Any, name: str, value: str) -> str:
    return _encrypt_secret_value(aad=_user_secret_aad(user_id, name), value=value)


def decrypt_user_secret_value(*, user_id: Any, name: str, ciphertext: str) -> str:
    return _decrypt_secret_value(aad=_user_secret_aad(user_id, name), ciphertext=ciphertext)


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
    return expand_policy_secret_values_for_owner(
        profile_id=profile_id,
        policy=policy,
        secret_material=secret_material,
    )


def expand_policy_secret_values_for_owner(
    *,
    profile_id: Any,
    policy: dict[str, Any],
    secret_material: dict[str, Any],
    owner_id: Any = None,
    owner_secrets: dict[str, Any] | None = None,
    on_omit: Callable[[str, str, str], None] | None = None,
) -> dict[str, Any]:
    """Hydrate secret injections for the Security CVM control payload.

    Inline (`value`) injections keep their historical behavior. `value_from`
    injections resolve against the CVM owner's secret material and are OMITTED
    on any failure (missing secret, non-https match, host binding not covering
    the match, undecryptable material, oversized render): the SC rejects
    unknown injection fields and fail-closes the whole CVM on a policy error,
    so an unresolved reference must never reach the wire. `on_omit(reason,
    injection_id, secret_name)` receives identifiers only, never values.
    """
    public_policy = redacted_profile_policy(policy)
    secret_injections = public_policy.get("secret_injections")
    if not isinstance(secret_injections, list):
        return public_policy
    expanded: list[dict[str, Any]] = []
    for injection in secret_injections:
        if not isinstance(injection, dict):
            continue
        if "value_from" in injection:
            resolved = _resolve_user_secret_injection(
                injection,
                owner_id=owner_id,
                owner_secrets=owner_secrets,
                on_omit=on_omit,
            )
            if resolved is not None:
                expanded.append(resolved)
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
    guarded: list[dict[str, Any]] = []
    for injection in expanded:
        if isinstance(injection, dict) and "value_from" in injection:
            _emit_omit(on_omit, "leak_guard", injection)
            continue
        guarded.append(injection)
    public_policy["secret_injections"] = guarded
    return public_policy


def user_secret_references(policy: Any) -> list[dict[str, Any]]:
    """List the `value_from` references declared by a profile policy.

    Tolerates malformed entries (skipped); returned dicts carry identifiers
    only: injection_id, secret_name, match_host, match_scheme.
    """
    if not isinstance(policy, dict):
        return []
    secret_injections = policy.get("secret_injections")
    if not isinstance(secret_injections, list):
        return []
    references: list[dict[str, Any]] = []
    for injection in secret_injections:
        if not isinstance(injection, dict):
            continue
        value_from = injection.get("value_from")
        if not isinstance(value_from, dict):
            continue
        name = value_from.get("user_secret")
        if not isinstance(name, str):
            continue
        match = injection.get("match")
        match = match if isinstance(match, dict) else {}
        injection_id = injection.get("id")
        host = match.get("host")
        scheme = match.get("scheme")
        references.append(
            {
                "injection_id": injection_id if isinstance(injection_id, str) else "",
                "secret_name": name,
                "match_host": host if isinstance(host, str) else "",
                "match_scheme": scheme if isinstance(scheme, str) else "",
            }
        )
    return references


def valid_secret_host_pattern(host: str) -> bool:
    if host == "*":
        return True
    if host != host.lower() or host.endswith(".") or len(host) > 253:
        return False
    if host.startswith("*."):
        suffix = host[2:]
        return "." in suffix and _valid_dns_name(suffix)
    return _valid_dns_name(host)


def host_pattern_covers(secret_pattern: str, injection_host: str) -> bool:
    """True iff every host the injection pattern matches (Security CVM
    DestinationRule semantics: `*`, `*.suffix` strict subdomains, exact) is
    also matched by the owner's secret pattern. Apex stays excluded from
    `*.suffix` on both sides, mirroring the SC.
    """
    if secret_pattern == "*":
        return True
    if secret_pattern == injection_host:
        return True
    if secret_pattern.startswith("*."):
        suffix = secret_pattern[2:]
        if injection_host == "*" or not injection_host:
            return False
        if injection_host.startswith("*."):
            inner = injection_host[2:]
            return inner == suffix or inner.endswith(f".{suffix}")
        return injection_host.endswith(f".{suffix}") and injection_host != suffix
    return False


def secret_hosts_cover(allowed_hosts: Any, injection_host: str) -> bool:
    if not isinstance(allowed_hosts, list):
        return False
    return any(
        isinstance(pattern, str) and host_pattern_covers(pattern, injection_host)
        for pattern in allowed_hosts
    )


def public_secret_injection(injection: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in injection.items() if key in PUBLIC_SECRET_INJECTION_FIELDS}


def _resolve_user_secret_injection(
    injection: dict[str, Any],
    *,
    owner_id: Any,
    owner_secrets: dict[str, Any] | None,
    on_omit: Callable[[str, str, str], None] | None,
) -> dict[str, Any] | None:
    value_from = injection.get("value_from")
    name = value_from.get("user_secret") if isinstance(value_from, dict) else None
    if not isinstance(name, str) or owner_id is None or not isinstance(owner_secrets, dict):
        _emit_omit(on_omit, "missing", injection)
        return None
    entry = owner_secrets.get(name)
    ciphertext = entry.get("ciphertext") if isinstance(entry, dict) else None
    if not isinstance(ciphertext, str):
        _emit_omit(on_omit, "missing", injection)
        return None
    match = injection.get("match")
    match = match if isinstance(match, dict) else {}
    if match.get("scheme") != "https":
        _emit_omit(on_omit, "scheme", injection)
        return None
    host = match.get("host")
    if not isinstance(host, str) or not secret_hosts_cover(entry.get("allowed_hosts"), host):
        _emit_omit(on_omit, "host_binding", injection)
        return None
    try:
        value = decrypt_user_secret_value(user_id=owner_id, name=name, ciphertext=ciphertext)
    except (ValueError, InvalidTag):
        _emit_omit(on_omit, "decrypt", injection)
        return None
    template = injection.get("value_template")
    if not isinstance(template, str) or template.count("${secret}") != 1:
        _emit_omit(on_omit, "invalid_template", injection)
        return None
    if len(template.replace("${secret}", value)) > SECRET_INJECTION_RENDERED_MAX_LEN:
        _emit_omit(on_omit, "rendered_too_long", injection)
        return None
    hydrated = {key: item for key, item in injection.items() if key != "value_from"}
    hydrated["value"] = value
    return hydrated


def _emit_omit(
    on_omit: Callable[[str, str, str], None] | None,
    reason: str,
    injection: dict[str, Any],
) -> None:
    if on_omit is None:
        return
    injection_id = injection.get("id")
    value_from = injection.get("value_from")
    name = value_from.get("user_secret") if isinstance(value_from, dict) else None
    on_omit(
        reason,
        injection_id if isinstance(injection_id, str) else "",
        name if isinstance(name, str) else "",
    )


def _encrypt_secret_value(*, aad: bytes, value: str) -> str:
    nonce = os.urandom(SECRET_INJECTION_NONCE_BYTES)
    encrypted = AESGCM(load_secret_injection_kek()).encrypt(nonce, value.encode("utf-8"), aad)
    payload = base64.urlsafe_b64encode(nonce + encrypted).decode("ascii").rstrip("=")
    return f"{SECRET_INJECTION_ENVELOPE_VERSION}:{payload}"


def _decrypt_secret_value(*, aad: bytes, ciphertext: str) -> str:
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
    plaintext = AESGCM(load_secret_injection_kek()).decrypt(nonce, encrypted, aad)
    return plaintext.decode("utf-8")


def _valid_dns_name(host: str) -> bool:
    labels = host.split(".")
    return len(labels) >= 2 and all(SECRET_HOST_DNS_LABEL_RE.fullmatch(label) for label in labels)


def _secret_aad(profile_id: Any, injection_id: str) -> bytes:
    return f"concrete.profile_secret_material.{SECRET_INJECTION_ENVELOPE_VERSION}:{profile_id}:{injection_id}".encode(
        "utf-8"
    )


def _user_secret_aad(user_id: Any, name: str) -> bytes:
    return f"concrete.user_secret_material.{SECRET_INJECTION_ENVELOPE_VERSION}:{user_id}:{name}".encode("utf-8")
