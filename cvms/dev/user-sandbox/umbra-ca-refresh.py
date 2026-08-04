#!/usr/bin/env python3
"""Runtime Security CVM mitmproxy CA refresher for the Dev CVM sandbox.

The Dev egress forwarder publishes the current SC CA to a shared volume (it fetches it from the
RTMR3-bound Console and validates fqdn + sha256). This watcher, running as root inside
``user-sandbox``, picks up that file and atomically rebuilds the single trust bundle that every
sandbox tool reads (``REQUESTS_CA_BUNDLE`` / ``SSL_CERT_FILE`` / ``CURL_CA_BUNDLE`` /
``GIT_SSL_CAINFO`` / ``NODE_EXTRA_CA_CERTS`` all point at ``/run/umbra/ca-bundle.pem``). This
lets the sandbox follow SC CA rotation without a fleet-wide ``cvm.update``.

The forwarder is the authoritative validator; this watcher does a structural PEM check and
*replaces* (never appends) the SC CA in the bundle, so a rotated or compromised CA stops being
trusted. Already-running processes that cached the bundle at startup (e.g. Node) need a restart
to pick up the new CA; path-based verifiers (curl, git, requests) recover on their next call.
"""
from __future__ import annotations

import hashlib
import json
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
    binding_path: Path  # forwarder-owned FQDN + CA digest sidecar
    launch_ca_path: Path  # immutable CA delivered in this launch binding
    bundle_path: Path  # combined trust bundle every sandbox tool reads
    sc_cert_path: Path  # installed SC CA copy
    system_roots_path: Path  # distro root bundle
    security_cvm_fqdn: str  # current launch-bound Security CVM identity
    interval_seconds: float
    bootstrap_timeout_seconds: float


def log(message: str) -> None:
    print(f"umbra-ca-refresh: {message}", file=sys.stderr, flush=True)


def load_config() -> RefreshConfig:
    security_cvm_fqdn = os.environ.get("SECURITY_CVM_FQDN", "").strip()
    if not security_cvm_fqdn:
        raise RuntimeError("missing required env SECURITY_CVM_FQDN")
    return RefreshConfig(
        source_path=Path(os.environ.get("UMBRA_CA_SOURCE", "/var/lib/umbra-ca/security-cvm-ca.pem")),
        binding_path=Path(os.environ.get("UMBRA_CA_BINDING", "/var/lib/umbra-ca/security-cvm-ca.json")),
        launch_ca_path=Path(os.environ.get("UMBRA_CA_LAUNCH", "/run/umbra/security-cvm-ca.launch.pem")),
        bundle_path=Path(os.environ.get("UMBRA_CA_BUNDLE", "/run/umbra/ca-bundle.pem")),
        sc_cert_path=Path(os.environ.get("UMBRA_CA_SC_CERT", "/run/umbra/security-cvm-ca.pem")),
        system_roots_path=Path(os.environ.get("UMBRA_CA_SYSTEM_ROOTS", "/etc/ssl/certs/ca-certificates.crt")),
        security_cvm_fqdn=security_cvm_fqdn,
        interval_seconds=float(os.environ.get("UMBRA_CA_REFRESH_INTERVAL_SECONDS", "30")),
        bootstrap_timeout_seconds=float(os.environ.get("UMBRA_CA_BOOTSTRAP_TIMEOUT_SECONDS", "120")),
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


def path_presence(path: Path) -> bool | None:
    """Return existence without treating permission or I/O errors as absence."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return None
    return True if stat.S_ISREG(metadata.st_mode) else None


def launch_ca_digest(config: RefreshConfig, launch_ca_path: Path | None = None) -> str | None:
    try:
        launch_ca = (launch_ca_path or config.launch_ca_path).read_bytes()
    except OSError:
        return None
    if not is_valid_ca_pem(launch_ca):
        return None
    return hashlib.sha256(launch_ca).hexdigest()


def read_published_ca(
    config: RefreshConfig, launch_ca_path: Path | None = None
) -> tuple[str, bytes | None]:
    """Read a CA only when the forwarder sidecar binds its digest and SC FQDN."""
    source_exists = path_presence(config.source_path)
    binding_exists = path_presence(config.binding_path)
    if source_exists is None or binding_exists is None:
        return "invalid", None
    if not source_exists and not binding_exists:
        return "missing", None
    if not source_exists or not binding_exists:
        return "invalid", None
    try:
        sc_ca = config.source_path.read_bytes()
        binding = json.loads(config.binding_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return "invalid", None
    if not is_valid_ca_pem(sc_ca) or not isinstance(binding, dict):
        return "invalid", None
    if binding.get("ca_cert_sha256") != hashlib.sha256(sc_ca).hexdigest():
        return "invalid", None
    current_launch_digest = launch_ca_digest(config, launch_ca_path)
    if current_launch_digest is None:
        return "invalid", None
    if (
        binding.get("security_cvm_fqdn") != config.security_cvm_fqdn
        or binding.get("launch_ca_cert_sha256") != current_launch_digest
    ):
        return "foreign", None
    return "valid", sc_ca


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
    state, sc_ca = read_published_ca(config)
    if state == "missing":
        return False
    if state != "valid" or sc_ca is None:
        log(f"ignored published CA: distribution is {state}")
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


def select_bootstrap_ca(config: RefreshConfig, launch_ca_path: Path) -> tuple[str, bytes] | None:
    """Select restart trust without rolling an authenticated persisted CA back.

    A valid current-binding distribution wins. An empty volume or a distribution
    validly bound to another FQDN or launch-CA baseline uses the current attested
    launch CA. Partial or corrupt state returns ``None`` so startup stays
    fail-closed until the forwarder's authenticated refresh repairs it.
    """
    launch_ca = launch_ca_path.read_bytes()
    if not is_valid_ca_pem(launch_ca):
        raise RuntimeError("launch Security CVM CA is not a PEM certificate")
    state, published_ca = read_published_ca(config, launch_ca_path)
    if state == "valid" and published_ca is not None:
        return "persisted", published_ca
    if state in {"missing", "foreign"}:
        return "launch", launch_ca
    return None


def bootstrap(config: RefreshConfig, launch_ca_path: Path) -> None:
    deadline = time.monotonic() + config.bootstrap_timeout_seconds
    while True:
        selected = select_bootstrap_ca(config, launch_ca_path)
        if selected is not None:
            source, sc_ca = selected
            install_ca(config, sc_ca)
            log(f"installed {source} Security CVM CA at startup")
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "timed out waiting for the forwarder's authenticated CA distribution repair"
            )
        log("waiting for authenticated CA refresh: persisted distribution is invalid")
        time.sleep(min(1, max(0, deadline - time.monotonic())))


def main() -> None:
    config = load_config()
    if len(sys.argv) == 3 and sys.argv[1] == "--bootstrap":
        bootstrap(config, Path(sys.argv[2]))
        return
    if len(sys.argv) != 1:
        raise SystemExit("usage: umbra-ca-refresh [--bootstrap LAUNCH_CA_PATH]")
    log(f"watching {config.source_path} (interval={config.interval_seconds}s)")
    while True:
        try:
            refresh_once(config)
        except OSError as exc:
            log(f"refresh error: {exc}")
        time.sleep(config.interval_seconds)


if __name__ == "__main__":
    main()
