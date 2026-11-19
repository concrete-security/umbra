from __future__ import annotations

import ipaddress

import httpx


_INVALID_URL = "CONSOLE_URL must be an absolute base URL without credentials, query or fragment"


def validate_console_base(value: str) -> str:
    """Validate the HTTPX base before a bearer or traffic log can leave the CVM."""
    if not value:
        raise ValueError("CONSOLE_URL is required")
    _, separator, remainder = value.partition("://")
    authority = remainder.partition("/")[0]
    if (
        not separator
        or not authority
        or "@" in authority
        or any(character in value for character in "?#\\")
        or any(ord(character) <= 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(_INVALID_URL)
    try:
        parsed = httpx.URL(value)
    except (httpx.InvalidURL, UnicodeError):
        raise ValueError(_INVALID_URL) from None
    if not parsed.host or parsed.userinfo or (parsed.port is not None and not 1 <= parsed.port <= 65535):
        raise ValueError(_INVALID_URL)
    if parsed.scheme != "https" and not (parsed.scheme == "http" and _is_loopback(parsed.host)):
        raise ValueError("CONSOLE_URL must use HTTPS except for loopback HTTP")
    return str(parsed).rstrip("/")


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    if "%" in host:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return address.is_loopback
    return address == ipaddress.IPv6Address("::1")
