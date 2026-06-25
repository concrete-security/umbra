#!/usr/bin/env python3
"""Runtime Security CVM mitmproxy CA refresher for the Dev CVM sandbox.

The Dev egress forwarder publishes the current SC CA to a shared volume (it fetches it from the
RTMR3-bound Console and validates fqdn + sha256). This watcher, running as root inside
``user-sandbox``, picks up that file and atomically rebuilds the single trust bundle that every
sandbox tool reads (``REQUESTS_CA_BUNDLE`` / ``SSL_CERT_FILE`` / ``CURL_CA_BUNDLE`` /
``GIT_SSL_CAINFO`` / ``NODE_EXTRA_CA_CERTS`` all point at ``/run/concrete/ca-bundle.pem``). This
lets the sandbox follow SC CA rotation without a fleet-wide ``cvm.update``.

The forwarder is the authoritative validator; this watcher does a structural PEM check and
*replaces* (never appends) the SC CA in the bundle, so a rotated or compromised CA stops being
trusted. Already-running processes that cached the bundle at startup (e.g. Node) need a restart
to pick up the new CA; path-based verifiers (curl, git, requests) recover on their next call.
"""
from __future__ import annotations

import os
import stat
import sys
import time
from dataclasses import dataclass
from pathlib import Path

PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
PEM_END = "-----END CERTIFICATE-----"


@dataclass(frozen=True)
class RefreshConfig:
    source_path: Path  # forwarder-published SC CA on the shared volume
    bundle_path: Path  # combined trust bundle every sandbox tool reads
    sc_cert_path: Path  # installed SC CA copy
    system_roots_path: Path  # distro root bundle
    interval_seconds: float


def log(message: str) -> None:
    print(f"concrete-ca-refresh: {message}", file=sys.stderr, flush=True)


def load_config() -> RefreshConfig:
    return RefreshConfig(
        source_path=Path(os.environ.get("CONCRETE_CA_SOURCE", "/var/lib/concrete-ca/security-cvm-ca.pem")),
        bundle_path=Path(os.environ.get("CONCRETE_CA_BUNDLE", "/run/concrete/ca-bundle.pem")),
        sc_cert_path=Path(os.environ.get("CONCRETE_CA_SC_CERT", "/run/concrete/security-cvm-ca.pem")),
        system_roots_path=Path(os.environ.get("CONCRETE_CA_SYSTEM_ROOTS", "/etc/ssl/certs/ca-certificates.crt")),
        interval_seconds=float(os.environ.get("CONCRETE_CA_REFRESH_INTERVAL_SECONDS", "30")),
    )


def is_valid_ca_pem(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return PEM_BEGIN in text and PEM_END in text


def compose_bundle(system_roots: bytes, sc_ca: bytes) -> bytes:
    roots = system_roots if system_roots.endswith(b"\n") else system_roots + b"\n"
    return roots + sc_ca


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def install_ca(config: RefreshConfig, sc_ca: bytes) -> None:
    """Rebuild the trust bundle as ``system roots + sc_ca`` (replace, not append) and the SC copy."""
    system_roots = config.system_roots_path.read_bytes()
    atomic_write(
        config.bundle_path,
        compose_bundle(system_roots, sc_ca),
        stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH,
    )
    atomic_write(config.sc_cert_path, sc_ca, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)


def refresh_once(config: RefreshConfig) -> bool:
    """Install the published SC CA if it is valid and differs from the installed one.

    Returns True if a new CA was installed.
    """
    try:
        sc_ca = config.source_path.read_bytes()
    except OSError:
        return False
    if not is_valid_ca_pem(sc_ca):
        log("ignored published CA: not a PEM certificate")
        return False
    try:
        current = config.sc_cert_path.read_bytes()
    except OSError:
        current = b""
    if sc_ca == current:
        return False
    install_ca(config, sc_ca)
    log("installed rotated Security CVM CA")
    return True


def main() -> None:
    config = load_config()
    log(f"watching {config.source_path} (interval={config.interval_seconds}s)")
    while True:
        try:
            refresh_once(config)
        except OSError as exc:
            log(f"refresh error: {exc}")
        time.sleep(config.interval_seconds)


if __name__ == "__main__":
    main()
