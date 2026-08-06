#!/usr/bin/env python3
"""Ensure INSTALL_HOST points at this VM before the reverse proxy asks for TLS."""

from __future__ import annotations

import json
import os
import re
import sys
from urllib import error, parse, request


CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"
HOST_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")
IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def fail(message: str) -> None:
    print(f"provision-install-host-dns: {message}", file=sys.stderr)
    raise SystemExit(1)


def info(message: str) -> None:
    print(f"provision-install-host-dns: {message}", file=sys.stderr)


def env(name: str) -> str:
    return os.environ.get(name, "").strip()


def cloudflare_request(method: str, path: str, *, token: str, payload: dict | None = None) -> dict:
    base = env("CLOUDFLARE_API_BASE") or CLOUDFLARE_API_BASE
    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with request.urlopen(req, timeout=20) as resp:
            response_body = resp.read().decode("utf-8")
    except error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="replace")
        fail(f"Cloudflare {method} {path} failed with HTTP {exc.code}: {response_body[:500]}")
    except error.URLError as exc:
        fail(f"Cloudflare {method} {path} failed: {exc.reason}")

    try:
        parsed = json.loads(response_body)
    except json.JSONDecodeError as exc:
        fail(f"Cloudflare returned invalid JSON: {exc}")
    if parsed.get("success") is not True:
        fail(f"Cloudflare {method} {path} returned unsuccessful response: {response_body[:500]}")
    return parsed


def validate_ipv4(address: str) -> None:
    if not IPV4_RE.fullmatch(address):
        fail(f"VM_PUBLIC_IP must be an IPv4 address, got {address!r}")
    octets = [int(part) for part in address.split(".")]
    if any(part > 255 for part in octets):
        fail(f"VM_PUBLIC_IP must be an IPv4 address, got {address!r}")


def main() -> None:
    install_host = env("INSTALL_HOST")
    if not install_host:
        return
    install_host = install_host.rstrip(".").lower()
    if not HOST_RE.fullmatch(install_host):
        fail(f"INSTALL_HOST must be a DNS hostname, got {install_host!r}")

    token = env("CLOUDFLARE_API_TOKEN")
    if not token:
        fail("CLOUDFLARE_API_TOKEN is required when INSTALL_HOST is set")
    zone_id = env("INSTALL_HOST_ZONE_ID") or env("CLOUDFLARE_ZONE_ID")
    if not zone_id:
        fail("INSTALL_HOST_ZONE_ID or CLOUDFLARE_ZONE_ID is required when INSTALL_HOST is set")
    vm_public_ip = env("VM_PUBLIC_IP")
    if not vm_public_ip:
        fail("VM_PUBLIC_IP is required when INSTALL_HOST is set")
    validate_ipv4(vm_public_ip)

    encoded_host = parse.quote(install_host, safe="")
    payload = cloudflare_request(
        "GET",
        f"zones/{zone_id}/dns_records?type=A&name={encoded_host}",
        token=token,
    )
    records = payload.get("result")
    if not isinstance(records, list):
        fail("Cloudflare response did not contain a result list")

    for record in records:
        if record.get("content") == vm_public_ip:
            info(f"{install_host} already points at {vm_public_ip}")
            return

    if records:
        existing = ", ".join(str(record.get("content", "<unknown>")) for record in records)
        fail(f"{install_host} already has conflicting A record(s): {existing}")

    cloudflare_request(
        "POST",
        f"zones/{zone_id}/dns_records",
        token=token,
        payload={
            "type": "A",
            "name": install_host,
            "content": vm_public_ip,
            "ttl": 1,
            "proxied": False,
        },
    )
    info(f"created A record {install_host} -> {vm_public_ip}")


if __name__ == "__main__":
    main()
