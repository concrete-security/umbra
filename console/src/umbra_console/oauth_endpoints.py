"""Egress guard for Console-initiated OAuth token-endpoint requests.

Both admin-configured integration token endpoints and member-configured
managed-secret token endpoints trigger *server-side* HTTP requests (code
exchange, refresh rotation). Without a guard, a caller could point those at
loopback, private, link-local, or cloud-metadata addresses and turn the
Console into an SSRF pivot. The host allowlist is the primary guard. As
defense in depth we also re-resolve the host at request time and refuse any
non-public address; note this narrows — but does not fully close — a
DNS-rebinding window, since httpx resolves independently of this check
(TOCTOU). The allowlist is what makes rebinding irrelevant in practice.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

from umbra_console.config import load_settings

# Provider-supplied error identifiers are echoed into the connection-state
# `error` column and printed by the CLI, so strip them to a conservative
# printable set before storing.
_SAFE_ERROR_CHARS_RE = re.compile(r"[^A-Za-z0-9_.:-]")
SAFE_ERROR_CODE_MAX_LEN = 64


def sanitize_provider_error_code(value: object) -> str:
    """Reduce a provider error (string or nested dict) to a safe short code."""
    raw: str | None = None
    if isinstance(value, str) and value:
        raw = value
    elif isinstance(value, dict):
        for key in ("code", "error", "message"):
            nested = value.get(key)
            if isinstance(nested, str) and nested:
                raw = nested
                break
    if not raw:
        return "provider_error"
    cleaned = _SAFE_ERROR_CHARS_RE.sub("_", raw)[:SAFE_ERROR_CODE_MAX_LEN]
    return cleaned or "provider_error"

# Env-overridable comma-separated allowlists. Defaults cover the providers this
# release wires; operators extend them per deployment.
TOKEN_URL_HOST_ALLOWLIST_ENV = "OAUTH_TOKEN_URL_HOSTS"
DEFAULT_TOKEN_URL_HOSTS = ("auth.openai.com", "slack.com")


class TokenEndpointError(ValueError):
    """Raised when a token endpoint URL is malformed or disallowed."""


def _allowed_hosts() -> frozenset[str]:
    raw = load_settings().raw.get(TOKEN_URL_HOST_ALLOWLIST_ENV)
    if raw is None:
        return frozenset(DEFAULT_TOKEN_URL_HOSTS)
    return frozenset(host.strip().lower() for host in raw.split(",") if host.strip())


def normalize_token_url(value: str) -> str:
    """Validate scheme/host of a token endpoint against the allowlist.

    Cheap, DNS-free: run at configuration time (PUT). Raises
    TokenEndpointError on a non-https, fragment-bearing, or non-allowlisted
    URL. The resolved-IP check (`assert_token_url_egress_allowed`) runs
    separately, at request time.
    """
    value = value.strip()
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname:
        raise TokenEndpointError("must be an absolute https:// URL")
    if parts.fragment:
        raise TokenEndpointError("must not carry a fragment")
    host = parts.hostname.lower()
    if host not in _allowed_hosts():
        raise TokenEndpointError(f"token endpoint host {host!r} is not on the allowlist")
    return value


def _is_public_address(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    # Reject every non-public range, incl. loopback, private, link-local
    # (169.254/16 covers the cloud-metadata 169.254.169.254), unique-local,
    # multicast, and reserved.
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def assert_token_url_egress_allowed(value: str) -> None:
    """Re-validate at request time, including resolved IPs (rebinding defense-in-depth).

    Must be called immediately before every server-side token-endpoint fetch,
    covering rows configured before an allowlist change and DNS that resolved
    to a public address at PUT time but a private one now.
    """
    normalize_token_url(value)
    host = urlsplit(value.strip()).hostname
    assert host is not None  # normalize_token_url guarantees it
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise TokenEndpointError(f"token endpoint host {host!r} did not resolve") from exc
    resolved = {info[4][0] for info in infos}
    if not resolved:
        raise TokenEndpointError(f"token endpoint host {host!r} did not resolve")
    bad = sorted(addr for addr in resolved if not _is_public_address(addr))
    if bad:
        raise TokenEndpointError(
            f"token endpoint host {host!r} resolves to non-public address(es): {', '.join(bad)}"
        )
