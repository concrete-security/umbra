from __future__ import annotations

from typing import Any
import ipaddress

from concrete_console.config import load_settings
from concrete_console.log_config import logger

log = logger()


def resolved_client_ip(request: Any) -> str:
    direct = request.client.host if request.client else "unknown"
    if settings_bool("TRUST_FORWARDED_HEADERS"):
        forwarded = request.headers.get("x-forwarded-for", "")
        public_ip = first_public_forwarded_ip(forwarded)
        if public_ip is not None:
            return public_ip
        if forwarded:
            log.warning("forwarded_for_no_public_ip", forwarded_for=forwarded[:256])
    return direct


def settings_bool(name: str) -> bool:
    return load_settings().raw.get(name, "false").strip().lower() in {"1", "true", "yes", "on"}


def first_public_forwarded_ip(value: str) -> str | None:
    for part in value.split(","):
        candidate = part.strip()
        if not candidate:
            continue
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
            return str(ip)
    return None
