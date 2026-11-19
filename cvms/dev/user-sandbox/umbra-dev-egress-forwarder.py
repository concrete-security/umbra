#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import http.client
import json
import os
import shlex
import stat
import sys
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


MAX_HEADER_BYTES = 65536
READ_SIZE = 65536
ATLS_POLICY_FETCH_MAX_ATTEMPTS = 12
ATLS_POLICY_FETCH_RETRY_SECONDS = 1.0
ATLS_POLICY_FETCH_TIMEOUT_SECONDS = 5.0
ATLS_POLICY_FETCH_MIN_INTERVAL_SECONDS = 2.5
ATLS_POLICY_MAX_AGE_SECONDS = 60.0
ATLS_POLICY_REFRESH_SECONDS = 30.0
DEFAULT_SECURITY_CVM_PROXY_PATH = "/umbra/proxy"
DEFAULT_SECURITY_CVM_PROXY_UPGRADE = "umbra-proxy"
PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
PEM_END = "-----END CERTIFICATE-----"
HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}


@dataclass(frozen=True)
class AtlsPolicyCandidate:
    contents: bytes
    ca_sha256: str


class AtlsPolicyDenied(ConnectionError):
    pass


@dataclass
class AtlsAuthorization:
    policy: AtlsPolicyCandidate
    expires_at: float
    revoked: asyncio.Event = field(default_factory=asyncio.Event)

    def is_current(self) -> bool:
        return not self.revoked.is_set() and time.monotonic() < self.expires_at

    def require_current(self) -> None:
        if not self.is_current():
            raise AtlsPolicyDenied("Security CVM aTLS policy authorization expired or was revoked")

    async def wait_until_invalid(self) -> None:
        while self.is_current():
            try:
                await asyncio.wait_for(self.revoked.wait(), timeout=self.expires_at - time.monotonic())
            except (TimeoutError, asyncio.TimeoutError):
                # An unchanged policy may have renewed the lease while we waited.
                continue


@dataclass
class AtlsAuthorizationState:
    current: AtlsAuthorization | None = None
    next_fetch_at: float = 0.0

    def revoke(self) -> None:
        if self.current is not None:
            self.current.revoked.set()
            self.current = None


@dataclass(frozen=True)
class ForwarderConfig:
    listen_host: str
    listen_port: int
    security_cvm_fqdn: str
    security_cvm_public_port: int
    security_cvm_proxy_path: str
    security_cvm_proxy_upgrade: str
    proxy_token: str
    dev_control_token: str
    console_url: str | None
    atls_policy_path: Path
    atls_policy_fetch_lock: asyncio.Lock
    ca_cert_path: Path
    atls_connect_cmd: tuple[str, ...]
    atls_connect_timeout_seconds: float
    ca_distribution_path: Path
    ca_distribution_binding_path: Path
    ca_refresh_interval_seconds: float
    atls_authorization: AtlsAuthorizationState = field(default_factory=AtlsAuthorizationState)


@dataclass(frozen=True)
class ProxyRequest:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]


@dataclass
class VerifiedUpstream:
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    process: asyncio.subprocess.Process


@dataclass
class AuthorizedWriter:
    stream: asyncio.StreamWriter
    authorization: AtlsAuthorization
    started: bool = False

    def write(self, data: bytes) -> None:
        self.authorization.require_current()
        self.started = True
        self.stream.write(data)

    async def drain(self) -> None:
        self.authorization.require_current()
        await self.stream.drain()

    def write_eof(self) -> None:
        self.authorization.require_current()
        self.stream.write_eof()


def log(message: str) -> None:
    print(f"dev-egress-forwarder: {message}", file=sys.stderr, flush=True)


def required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"missing required env {name}")
    return value


def optional_path_env(name: str, default: str) -> str:
    value = os.environ.get(name, default).strip()
    if not value.startswith("/") or any(character in value for character in "\r\n\t\0"):
        raise RuntimeError(f"{name} must be an absolute path without control characters")
    return value


def optional_token_env(name: str, default: str) -> str:
    value = os.environ.get(name, default).strip()
    if not value or any(character in value for character in "\r\n\t\0"):
        raise RuntimeError(f"{name} must not be empty or contain control characters")
    return value


def optional_url_env(name: str) -> str | None:
    value = os.environ.get(name, "").strip().rstrip("/")
    if not value:
        return None
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or any(character in value for character in "\r\n\t\0")
    ):
        log(f"{name} ignored because policy refresh requires an https origin URL")
        return None
    return value


def decode_required_b64(name: str) -> bytes:
    raw = required_env(name)
    try:
        decoded = base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise RuntimeError(f"invalid base64 in {name}") from exc
    if not decoded:
        raise RuntimeError(f"{name} decoded to empty bytes")
    return decoded


def write_private_file(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


def create_private_file(path: Path, payload: bytes, mode: int) -> bool:
    """Create ``path`` without replacing concurrent or persisted state."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        return False
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
        os.chmod(path, mode)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return True


def materialize_runtime_files(runtime_dir: Path) -> tuple[Path, Path, str]:
    ca_cert = decode_required_b64("SECURITY_CVM_CA_CERT_B64")
    proxy_token = required_env("SECURITY_CVM_PROXY_TOKEN")
    ca_path = runtime_dir / "security-cvm-ca.pem"
    policy_path = runtime_dir / "security-cvm.atls-policy.json"
    token_path = runtime_dir / "proxy-token"
    write_private_file(ca_path, ca_cert, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    write_private_file(token_path, proxy_token.encode("utf-8"), stat.S_IRUSR)

    for name in ("SECURITY_CVM_CA_CERT_B64", "SECURITY_CVM_ATLS_POLICY_B64", "SECURITY_CVM_PROXY_TOKEN"):
        os.environ.pop(name, None)
    return policy_path, ca_path, proxy_token


def load_config(runtime_dir: Path = Path("/run/umbra")) -> ForwarderConfig:
    policy_path, ca_path, proxy_token = materialize_runtime_files(runtime_dir)
    dev_control_token = required_env("DEV_CVM_CONTROL_TOKEN")
    os.environ.pop("DEV_CVM_CONTROL_TOKEN", None)
    command = os.environ.get("DEV_EGRESS_ATLS_CONNECT_CMD", "/usr/local/bin/umbra-atls-connect")
    argv = tuple(shlex.split(command))
    if not argv:
        raise RuntimeError("DEV_EGRESS_ATLS_CONNECT_CMD is empty")
    int(required_env("SECURITY_CVM_PROXY_PORT"))
    return ForwarderConfig(
        listen_host=os.environ.get("DEV_EGRESS_LISTEN_HOST", "0.0.0.0"),
        listen_port=int(os.environ.get("DEV_EGRESS_LISTEN_PORT", "3128")),
        security_cvm_fqdn=required_env("SECURITY_CVM_FQDN"),
        security_cvm_public_port=int(os.environ.get("SECURITY_CVM_PUBLIC_PORT", "443")),
        security_cvm_proxy_path=optional_path_env("SECURITY_CVM_PROXY_PATH", DEFAULT_SECURITY_CVM_PROXY_PATH),
        security_cvm_proxy_upgrade=optional_token_env("SECURITY_CVM_PROXY_UPGRADE", DEFAULT_SECURITY_CVM_PROXY_UPGRADE),
        proxy_token=proxy_token,
        dev_control_token=dev_control_token,
        console_url=optional_url_env("CONSOLE_URL"),
        atls_policy_path=policy_path,
        atls_policy_fetch_lock=asyncio.Lock(),
        ca_cert_path=ca_path,
        atls_connect_cmd=argv,
        atls_connect_timeout_seconds=float(os.environ.get("DEV_EGRESS_ATLS_CONNECT_TIMEOUT_SECONDS", "10")),
        ca_distribution_path=Path(
            os.environ.get("DEV_EGRESS_CA_DISTRIBUTION_PATH", "/var/lib/umbra-ca/security-cvm-ca.pem")
        ),
        ca_distribution_binding_path=Path(
            os.environ.get("DEV_EGRESS_CA_BINDING_PATH", "/var/lib/umbra-ca/security-cvm-ca.json")
        ),
        ca_refresh_interval_seconds=float(os.environ.get("DEV_EGRESS_CA_REFRESH_INTERVAL_SECONDS", "60")),
    )


async def read_headers(reader: asyncio.StreamReader) -> ProxyRequest:
    try:
        data = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as exc:
        raise ValueError("client closed before headers") from exc
    except asyncio.LimitOverrunError as exc:
        raise ValueError("headers too large") from exc
    if len(data) > MAX_HEADER_BYTES:
        raise ValueError("headers too large")
    lines = data.removesuffix(b"\r\n\r\n").decode("iso-8859-1").split("\r\n")
    parts = lines[0].split()
    if len(parts) != 3:
        raise ValueError("invalid request line")
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers.append((name.strip(), value.strip()))
    return ProxyRequest(parts[0].upper(), parts[1], parts[2], headers)


def filtered_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(name, value) for name, value in headers if name.lower() not in HOP_BY_HOP_HEADERS]


def parse_connect_target(target: str) -> tuple[str, int]:
    host, separator, port_text = target.rpartition(":")
    if not separator or not host or not port_text.isdigit():
        raise ValueError("CONNECT target must be host:port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("CONNECT target port out of range")
    return host, port


def validate_absolute_target(target: str) -> None:
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("HTTP proxy requests must use absolute-form http(s) URLs")


def header_values(request: ProxyRequest, header_name: str) -> list[str]:
    wanted = header_name.lower()
    return [value for name, value in request.headers if name.lower() == wanted]


def single_header_value(request: ProxyRequest, header_name: str) -> str | None:
    values = header_values(request, header_name)
    if not values:
        return None
    if len(values) > 1:
        raise ValueError(f"multiple {header_name} headers are not supported")
    return values[0]


def parse_content_length(request: ProxyRequest) -> int:
    value = single_header_value(request, "content-length")
    if value is None:
        return 0
    if not value.isdigit():
        raise ValueError("invalid Content-Length header")
    length = int(value)
    if length < 0:
        raise ValueError("invalid Content-Length header")
    return length


def transfer_encoding_is_chunked(request: ProxyRequest) -> bool:
    values = header_values(request, "transfer-encoding")
    if not values:
        return False
    codings = ",".join(values).lower().split(",")
    return any(coding.strip() == "chunked" for coding in codings)


def encode_request_line_and_headers(request: ProxyRequest, proxy_token: str, *, close_after_response: bool = False) -> bytes:
    lines = [f"{request.method} {request.target} {request.version}"]
    host_seen = False
    for name, value in filtered_headers(request.headers):
        if name.lower() == "host":
            host_seen = True
        lines.append(f"{name}: {value}")
    if request.method == "CONNECT" and not host_seen:
        lines.append(f"Host: {request.target}")
    if close_after_response:
        lines.append("Connection: close")
    lines.append(f"Proxy-Authorization: Bearer {proxy_token}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")


async def open_verified_upstream_with_policy(
    config: ForwarderConfig,
    *,
    policy_path: Path,
) -> VerifiedUpstream:
    payload = {
        "fqdn": config.security_cvm_fqdn,
        "port": config.security_cvm_public_port,
        "policy_path": str(policy_path),
        "ca_cert_path": str(config.ca_cert_path),
    }
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")}
    process = await asyncio.create_subprocess_exec(
        *config.atls_connect_cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise ConnectionError("aTLS connect helper pipes unavailable")
    try:
        process.stdin.write(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
        await process.stdin.drain()
        process.stdin.close()
        await process.stdin.wait_closed()
        stdout_line = await asyncio.wait_for(process.stdout.readline(), timeout=config.atls_connect_timeout_seconds)
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise ConnectionError("aTLS connect helper timed out") from exc
    if not stdout_line:
        stderr = await process.stderr.read(4096)
        await process.wait()
        reason = stderr.decode("utf-8", errors="replace").strip().splitlines()[:1]
        raise ConnectionError(f"aTLS connect helper failed: {reason[0] if reason else 'no diagnostic'}")
    try:
        response = json.loads(stdout_line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        process.kill()
        await process.wait()
        raise ConnectionError("aTLS connect helper returned malformed JSON") from exc
    host = response.get("host")
    port = response.get("port")
    if not isinstance(host, str) or not host or not isinstance(port, int) or not 1 <= port <= 65535:
        process.kill()
        await process.wait()
        raise ConnectionError("aTLS connect helper returned invalid relay address")
    try:
        reader, writer = await asyncio.open_connection(host, port)
    except OSError:
        process.terminate()
        await process.wait()
        raise
    return VerifiedUpstream(reader=reader, writer=writer, process=process)


async def open_verified_upstream(config: ForwarderConfig) -> tuple[VerifiedUpstream, AtlsAuthorization]:
    authorization = await ensure_atls_policy(config)
    try:
        upstream = await open_verified_upstream_with_policy(config, policy_path=config.atls_policy_path)
    except (ConnectionError, OSError) as exc:
        log(f"atls_primary_failed reason={exc}")
        # A rollout can make a still-fresh policy fail. Retry only with a
        # freshly authenticated candidate, never a previously accepted file.
        async with config.atls_policy_fetch_lock:
            renewed = current_atls_policy(config)
            if renewed is authorization or renewed is None:
                await asyncio.sleep(max(0.0, config.atls_authorization.next_fetch_at - time.monotonic()))
                renewed = await refresh_atls_policy_locked(config)
        if renewed is None:
            raise ConnectionError("aTLS verification failed and refresh did not recover") from exc
        authorization = renewed
        authorization.require_current()
        upstream = await open_verified_upstream_with_policy(config, policy_path=config.atls_policy_path)
    if not authorization.is_current():
        await close_verified_upstream(upstream)
        authorization.require_current()
    return upstream, authorization


def fetch_refreshed_atls_policy(config: ForwarderConfig) -> AtlsPolicyCandidate | None:
    if config.console_url is None:
        return None
    parsed = urlsplit(config.console_url)
    path = "/internal/dev-control/security-cvm-atls-policy"
    connection = http.client.HTTPSConnection(
        parsed.hostname, parsed.port or 443, timeout=ATLS_POLICY_FETCH_TIMEOUT_SECONDS
    )
    try:
        connection.request(
            "GET",
            path,
            headers={
                "Authorization": f"Bearer {config.dev_control_token}",
                "Accept": "application/json",
            },
        )
        response = connection.getresponse()
        if response.status in {401, 403, 409}:
            raise AtlsPolicyDenied(f"Console refused Security CVM aTLS policy: HTTP {response.status}")
        if response.status != 200:
            log(f"atls_console_refresh_unavailable status={response.status}")
            return None
        body = response.read(1024 * 1024 + 1)
    except AtlsPolicyDenied:
        raise
    except (OSError, http.client.HTTPException) as exc:
        log(f"atls_console_refresh_fetch_failed reason={exc}")
        return None
    finally:
        connection.close()
    if len(body) > 1024 * 1024:
        log("atls_console_refresh_rejected reason=response_too_large")
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        log("atls_console_refresh_rejected reason=malformed_json")
        return None
    if not isinstance(payload, dict):
        log("atls_console_refresh_rejected reason=malformed_payload")
        return None
    if payload.get("security_cvm_fqdn") != config.security_cvm_fqdn:
        log("atls_console_refresh_rejected reason=fqdn_mismatch")
        return None
    distribution_state, distributed_ca = read_ca_distribution(config)
    if distribution_state != "valid" or distributed_ca is None:
        raise AtlsPolicyDenied(f"Security CVM CA distribution is {distribution_state}")
    # The persisted CA is replaced only by launch-bound seeding or after the
    # authenticated CA endpoint passes the bound-FQDN and digest checks. Binding
    # policy refresh to that same CA lets rotation converge without accepting an
    # unbound or stale file left by a different launch configuration.
    expected_ca_sha256 = hashlib.sha256(distributed_ca).hexdigest()
    if payload.get("ca_cert_sha256") != expected_ca_sha256:
        raise AtlsPolicyDenied("Console policy does not match the current Security CVM CA")
    policy = payload.get("atls_policy")
    if not isinstance(policy, dict) or policy.get("type") != "dstack_tdx":
        log("atls_console_refresh_rejected reason=invalid_policy")
        return None
    if policy.get("disable_runtime_verification", False) is not False:
        log("atls_console_refresh_rejected reason=runtime_verification_disabled")
        return None
    if not all(policy.get(field) for field in ("expected_bootchain", "app_compose", "os_image_hash")):
        log("atls_console_refresh_rejected reason=runtime_verification_fields_missing")
        return None
    data = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return AtlsPolicyCandidate(data, expected_ca_sha256)


def current_atls_policy(config: ForwarderConfig) -> AtlsAuthorization | None:
    current = config.atls_authorization.current
    if current is None or not current.is_current() or not config.atls_policy_path.is_file():
        return None
    state, ca = read_ca_distribution(config)
    if state != "valid" or ca is None or hashlib.sha256(ca).hexdigest() != current.policy.ca_sha256:
        config.atls_authorization.revoke()
        return None
    return current


async def refresh_atls_policy_locked(config: ForwarderConfig) -> AtlsAuthorization | None:
    # Count the authorization window from request start, so a slow response
    # cannot turn already aged Console evidence into a fresh local lease.
    started = time.monotonic()
    if started < config.atls_authorization.next_fetch_at:
        return None
    config.atls_authorization.next_fetch_at = started + ATLS_POLICY_FETCH_MIN_INTERVAL_SECONDS
    expires_at = started + ATLS_POLICY_MAX_AGE_SECONDS
    try:
        candidate = await asyncio.wait_for(
            asyncio.to_thread(fetch_refreshed_atls_policy, config), timeout=ATLS_POLICY_FETCH_TIMEOUT_SECONDS
        )
    except AtlsPolicyDenied:
        config.atls_authorization.revoke()
        raise
    except (TimeoutError, asyncio.TimeoutError):
        log("atls_console_refresh_timed_out")
        return None
    if candidate is None or time.monotonic() >= expires_at:
        return None
    current = config.atls_authorization.current
    if current is not None and current.is_current() and current.policy == candidate:
        if not config.atls_policy_path.is_file():
            write_private_file(config.atls_policy_path, candidate.contents, 0o444)
        current.expires_at = expires_at
        return current
    config.atls_authorization.revoke()
    write_private_file(config.atls_policy_path, candidate.contents, 0o444)
    authorization = AtlsAuthorization(candidate, expires_at)
    config.atls_authorization.current = authorization
    log("atls_console_policy_installed")
    return authorization


async def ensure_atls_policy(config: ForwarderConfig) -> AtlsAuthorization:
    """Require a current process-local authorization before opening an upstream."""
    if (current := current_atls_policy(config)) is not None:
        return current
    if config.console_url is None:
        raise ConnectionError("Security CVM aTLS policy fetch requires CONSOLE_URL")
    async with config.atls_policy_fetch_lock:
        if (current := current_atls_policy(config)) is not None:
            return current
        if time.monotonic() < config.atls_authorization.next_fetch_at:
            raise ConnectionError("Security CVM aTLS policy fetch is backing off")
        for attempt in range(1, ATLS_POLICY_FETCH_MAX_ATTEMPTS + 1):
            if (current := await refresh_atls_policy_locked(config)) is not None:
                return current
            if attempt < ATLS_POLICY_FETCH_MAX_ATTEMPTS:
                log(f"atls_console_policy_fetch_retry attempt={attempt}")
                await asyncio.sleep(max(
                    ATLS_POLICY_FETCH_RETRY_SECONDS, config.atls_authorization.next_fetch_at - time.monotonic()
                ))
    raise ConnectionError("Security CVM aTLS policy fetch exhausted its bounded retries")


async def atls_policy_refresh_loop(config: ForwarderConfig) -> None:
    while True:
        await asyncio.sleep(ATLS_POLICY_REFRESH_SECONDS)
        async with config.atls_policy_fetch_lock:
            # Leave bootstrap to the first client. After that, renew even
            # during a single long-lived CONNECT with no new requests.
            if config.atls_authorization.current is not None:
                try:
                    await refresh_atls_policy_locked(config)
                except (AtlsPolicyDenied, OSError) as exc:
                    log(f"atls_console_refresh_failed reason={exc}")


def extract_validated_ca(payload: object, expected_fqdn: str) -> str | None:
    """Validate a /dev-control/security-cvm-ca payload and return its CA PEM, or None.

    Pure (no I/O) so it can be unit-tested. Confirms the CA is for the launch-bound SC FQDN,
    is a PEM certificate, and is self-consistent with the response's own sha256.
    """
    if not isinstance(payload, dict):
        log("ca_fetch_rejected reason=malformed_payload")
        return None
    if payload.get("security_cvm_fqdn") != expected_fqdn:
        log("ca_fetch_rejected reason=fqdn_mismatch")
        return None
    ca_pem = payload.get("ca_cert_pem")
    if not isinstance(ca_pem, str) or not is_valid_ca_pem(ca_pem.encode("utf-8")):
        log("ca_fetch_rejected reason=invalid_ca")
        return None
    expected_sha = payload.get("ca_cert_sha256")
    if not isinstance(expected_sha, str) or hashlib.sha256(ca_pem.encode("utf-8")).hexdigest() != expected_sha:
        log("ca_fetch_rejected reason=ca_sha_mismatch")
        return None
    return ca_pem


def fetch_security_cvm_ca(config: ForwarderConfig) -> str | None:
    """Fetch the current SC mitmproxy CA from the RTMR3-bound Console origin.

    Reaches the Console directly over the egress uplink (not through the SC proxy), so it works
    even while the sandbox's currently-trusted SC CA is stale after a rotation.
    """
    if config.console_url is None:
        return None
    parsed = urlsplit(config.console_url)
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=5)
    try:
        connection.request(
            "GET",
            "/internal/dev-control/security-cvm-ca",
            headers={
                "Authorization": f"Bearer {config.dev_control_token}",
                "Accept": "application/json",
            },
        )
        response = connection.getresponse()
        if response.status in {401, 403, 409}:
            raise AtlsPolicyDenied(f"Console refused Security CVM CA: HTTP {response.status}")
        if response.status != 200:
            log(f"ca_fetch_unavailable status={response.status}")
            return None
        body = response.read(1024 * 1024 + 1)
    except AtlsPolicyDenied:
        raise
    except (OSError, http.client.HTTPException) as exc:
        log(f"ca_fetch_failed reason={exc}")
        return None
    finally:
        connection.close()
    if len(body) > 1024 * 1024:
        log("ca_fetch_rejected reason=response_too_large")
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        log("ca_fetch_rejected reason=malformed_json")
        return None
    return extract_validated_ca(payload, config.security_cvm_fqdn)


def is_valid_ca_pem(data: bytes) -> bool:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return PEM_BEGIN in text and PEM_END in text


def launch_ca_digest(config: ForwarderConfig) -> str | None:
    try:
        launch_ca = config.ca_cert_path.read_bytes()
    except OSError:
        return None
    if not is_valid_ca_pem(launch_ca):
        return None
    return hashlib.sha256(launch_ca).hexdigest()


def ca_distribution_binding(config: ForwarderConfig, ca_data: bytes) -> bytes:
    launch_digest = launch_ca_digest(config)
    if launch_digest is None:
        raise ValueError("launch Security CVM CA is unavailable or invalid")
    return (
        json.dumps(
            {
                "security_cvm_fqdn": config.security_cvm_fqdn,
                "ca_cert_sha256": hashlib.sha256(ca_data).hexdigest(),
                "launch_ca_cert_sha256": launch_digest,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def path_presence(path: Path) -> bool | None:
    """Return existence without collapsing probe errors into absence."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        return None
    return True if stat.S_ISREG(metadata.st_mode) else None


def read_ca_distribution(config: ForwarderConfig) -> tuple[str, bytes | None]:
    """Return ``(state, CA)`` for the forwarder-owned persisted distribution.

    ``missing`` means both files are absent and first-boot seeding is safe.
    ``foreign`` is a valid distribution for a different launch-bound SC FQDN
    or launch-CA baseline.
    Any partial, unreadable, malformed, or digest-mismatched pair is ``invalid``.
    """
    ca_exists = path_presence(config.ca_distribution_path)
    binding_exists = path_presence(config.ca_distribution_binding_path)
    if ca_exists is None or binding_exists is None:
        return "invalid", None
    if not ca_exists and not binding_exists:
        return "missing", None
    if not ca_exists or not binding_exists:
        return "invalid", None
    try:
        ca_data = config.ca_distribution_path.read_bytes()
        binding = json.loads(config.ca_distribution_binding_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return "invalid", None
    if not is_valid_ca_pem(ca_data) or not isinstance(binding, dict):
        return "invalid", None
    if binding.get("ca_cert_sha256") != hashlib.sha256(ca_data).hexdigest():
        return "invalid", None
    current_launch_digest = launch_ca_digest(config)
    if current_launch_digest is None:
        return "invalid", None
    if (
        binding.get("security_cvm_fqdn") != config.security_cvm_fqdn
        or binding.get("launch_ca_cert_sha256") != current_launch_digest
    ):
        return "foreign", None
    return "valid", ca_data


def write_ca_distribution(config: ForwarderConfig, ca_pem: str) -> bool:
    """Publish an authenticated SC CA plus its FQDN/digest binding."""
    data = ca_pem.encode("utf-8")
    if not is_valid_ca_pem(data):
        raise ValueError("Security CVM CA is not a PEM certificate")
    binding = ca_distribution_binding(config, data)
    ca_changed = True
    binding_changed = True
    try:
        ca_changed = config.ca_distribution_path.read_bytes() != data
    except OSError:
        pass
    try:
        binding_changed = config.ca_distribution_binding_path.read_bytes() != binding
    except OSError:
        pass
    if not ca_changed and not binding_changed:
        return False
    mode = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    if ca_changed:
        write_private_file(config.ca_distribution_path, data, mode)
    if binding_changed:
        write_private_file(config.ca_distribution_binding_path, binding, mode)
    log("ca_distribution_updated")
    return True


def seed_ca_distribution(config: ForwarderConfig) -> None:
    """Seed first boot without rolling a persisted rotated CA back on restart."""
    try:
        ca_data = config.ca_cert_path.read_bytes()
    except OSError as exc:
        log(f"ca_distribution_seed_skipped reason={exc}")
        return
    if not is_valid_ca_pem(ca_data):
        log("ca_distribution_seed_skipped reason=invalid_launch_ca")
        return

    state, _persisted_ca = read_ca_distribution(config)
    if state == "valid":
        log("ca_distribution_seed_preserved")
        return
    if state == "foreign":
        # A full Dev CVM update can retain the named volume while changing the
        # launch-bound SC FQDN or launch CA baseline. The new compose material
        # is attested, so replace the foreign distribution with its launch CA.
        write_ca_distribution(config, ca_data.decode("utf-8"))
        log("ca_distribution_seed_rebound")
        return
    if state == "invalid":
        # Never repair partial/corrupt state from the immutable launch baseline:
        # only a fresh authenticated Console response may replace it.
        log("ca_distribution_seed_skipped reason=invalid_existing_state")
        return

    mode = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    if not create_private_file(config.ca_distribution_path, ca_data, mode):
        log("ca_distribution_seed_skipped reason=concurrent_state")
        return
    binding = ca_distribution_binding(config, ca_data)
    if not create_private_file(config.ca_distribution_binding_path, binding, mode):
        log("ca_distribution_seed_skipped reason=concurrent_binding")
        return
    log("ca_distribution_seeded")


async def ca_distribution_loop(config: ForwarderConfig) -> None:
    """Poll the Console for the current SC CA and republish it for the sandbox to re-install."""
    if config.console_url is None:
        log("ca_distribution_disabled reason=no_console_url")
        return
    while True:
        try:
            async with config.atls_policy_fetch_lock:
                try:
                    ca_pem = await asyncio.wait_for(
                        asyncio.to_thread(fetch_security_cvm_ca, config), timeout=ATLS_POLICY_FETCH_TIMEOUT_SECONDS
                    )
                except AtlsPolicyDenied:
                    config.atls_authorization.revoke()
                    raise
                if ca_pem is not None:
                    current = config.atls_authorization.current
                    if current is not None and hashlib.sha256(ca_pem.encode("utf-8")).hexdigest() != current.policy.ca_sha256:
                        config.atls_authorization.revoke()
                    await asyncio.to_thread(write_ca_distribution, config, ca_pem)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # keep the proxy serving even if CA refresh fails
            log(f"ca_distribution_error reason={exc}")
        await asyncio.sleep(config.ca_refresh_interval_seconds)


async def open_security_proxy_tunnel(upstream: VerifiedUpstream, config: ForwarderConfig) -> None:
    host = config.security_cvm_fqdn
    if config.security_cvm_public_port != 443:
        host = f"{host}:{config.security_cvm_public_port}"
    request = (
        f"GET {config.security_cvm_proxy_path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Connection: Upgrade\r\n"
        f"Upgrade: {config.security_cvm_proxy_upgrade}\r\n"
        "\r\n"
    )
    upstream.writer.write(request.encode("ascii"))
    await upstream.writer.drain()
    response = await read_response_headers(upstream.reader)
    status_line = response.split(b"\r\n", 1)[0].split()
    status = status_line[1] if len(status_line) >= 2 and response.startswith(b"HTTP/") else b"000"
    if status != b"101":
        raise ConnectionError(f"Security CVM proxy tunnel upgrade failed: HTTP {status.decode('ascii', errors='replace')}")


async def read_response_headers(reader: asyncio.StreamReader) -> bytes:
    try:
        response = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as exc:
        raise ConnectionError("upstream closed before response headers") from exc
    except asyncio.LimitOverrunError as exc:
        raise ConnectionError("upstream response headers too large") from exc
    if len(response) > MAX_HEADER_BYTES:
        raise ConnectionError("upstream response headers too large")
    return response


async def close_verified_upstream(upstream: VerifiedUpstream) -> None:
    upstream.writer.close()
    with suppress(OSError):
        await upstream.writer.wait_closed()
    if upstream.process.returncode is None:
        upstream.process.terminate()
        try:
            await asyncio.wait_for(upstream.process.wait(), timeout=2)
        except TimeoutError:
            upstream.process.kill()
            await upstream.process.wait()


async def write_response(writer: asyncio.StreamWriter, status: str, body: bytes = b"") -> None:
    writer.write(
        b"HTTP/1.1 "
        + status.encode("ascii")
        + b"\r\nConnection: close\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\n\r\n"
        + body
    )
    await writer.drain()


async def copy_stream(reader: asyncio.StreamReader, writer: AuthorizedWriter, counter: dict[str, int]) -> None:
    while True:
        data = await reader.read(READ_SIZE)
        if not data:
            break
        counter["bytes"] += len(data)
        writer.write(data)
        await writer.drain()
    try:
        writer.write_eof()
    except (OSError, RuntimeError):
        pass


async def relay_fixed_request_body(
    reader: asyncio.StreamReader, writer: AuthorizedWriter, request: ProxyRequest
) -> int:
    content_length = parse_content_length(request)
    if content_length > 0 and transfer_encoding_is_chunked(request):
        raise ValueError("request must not use both Content-Length and chunked Transfer-Encoding")
    if content_length > 0:
        body = await reader.readexactly(content_length)
        writer.write(body)
        await writer.drain()
        return len(body)
    if transfer_encoding_is_chunked(request):
        relayed = 0
        while True:
            line = await reader.readuntil(b"\r\n")
            writer.write(line)
            relayed += len(line)
            size_text = line.split(b";", 1)[0].strip()
            try:
                chunk_size = int(size_text, 16)
            except ValueError as exc:
                raise ValueError("invalid chunked request body") from exc
            if chunk_size == 0:
                while True:
                    trailer = await reader.readuntil(b"\r\n")
                    writer.write(trailer)
                    relayed += len(trailer)
                    if trailer == b"\r\n":
                        await writer.drain()
                        return relayed
            chunk = await reader.readexactly(chunk_size + 2)
            writer.write(chunk)
            relayed += len(chunk)
            await writer.drain()
    return 0


async def relay_response_until_close(reader: asyncio.StreamReader, writer: AuthorizedWriter) -> int:
    total = 0
    while True:
        data = await reader.read(READ_SIZE)
        if not data:
            return total
        total += len(data)
        writer.write(data)
        await writer.drain()


def response_header_values(response_headers: bytes, header_name: str) -> list[str]:
    wanted = header_name.lower()
    lines = response_headers.removesuffix(b"\r\n\r\n").decode("iso-8859-1").split("\r\n")
    values: list[str] = []
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        if name.strip().lower() == wanted:
            values.append(value.strip())
    return values


def response_content_length(response_headers: bytes) -> int | None:
    values = response_header_values(response_headers, "content-length")
    if not values:
        return None
    if len(set(values)) != 1 or not values[0].isdigit():
        raise ConnectionError("invalid upstream Content-Length header")
    return int(values[0])


def response_transfer_encoding_is_chunked(response_headers: bytes) -> bool:
    values = response_header_values(response_headers, "transfer-encoding")
    if not values:
        return False
    codings = ",".join(values).lower().split(",")
    return any(coding.strip() == "chunked" for coding in codings)


async def relay_chunked_response_body(reader: asyncio.StreamReader, writer: AuthorizedWriter) -> int:
    relayed = 0
    while True:
        line = await reader.readuntil(b"\r\n")
        writer.write(line)
        relayed += len(line)
        size_text = line.split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_text, 16)
        except ValueError as exc:
            raise ConnectionError("invalid chunked upstream response body") from exc
        if chunk_size == 0:
            while True:
                trailer = await reader.readuntil(b"\r\n")
                writer.write(trailer)
                relayed += len(trailer)
                if trailer == b"\r\n":
                    await writer.drain()
                    return relayed
        chunk = await reader.readexactly(chunk_size + 2)
        writer.write(chunk)
        relayed += len(chunk)
        await writer.drain()


async def relay_response_body(
    reader: asyncio.StreamReader,
    writer: AuthorizedWriter,
    response_headers: bytes,
) -> int:
    if response_transfer_encoding_is_chunked(response_headers):
        return await relay_chunked_response_body(reader, writer)
    content_length = response_content_length(response_headers)
    if content_length is None or content_length == 0:
        return 0
    body = await reader.readexactly(content_length)
    writer.write(body)
    await writer.drain()
    return len(body)


async def bridge(
    left_reader: asyncio.StreamReader,
    left_writer: AuthorizedWriter,
    right_reader: asyncio.StreamReader,
    right_writer: AuthorizedWriter,
) -> tuple[int, int]:
    left_count = {"bytes": 0}
    right_count = {"bytes": 0}
    left_to_right = asyncio.create_task(copy_stream(left_reader, right_writer, left_count))
    right_to_left = asyncio.create_task(copy_stream(right_reader, left_writer, right_count))
    tasks = (left_to_right, right_to_left)
    try:
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return left_count["bytes"], right_count["bytes"]


async def forward_request(
    reader: asyncio.StreamReader,
    downstream: AuthorizedWriter,
    upstream: VerifiedUpstream,
    request: ProxyRequest,
    config: ForwarderConfig,
) -> tuple[int, int]:
    authorization = downstream.authorization
    authorization.require_current()
    await open_security_proxy_tunnel(upstream, config)
    upstream_writer = AuthorizedWriter(upstream.writer, authorization)
    upstream_writer.write(
        encode_request_line_and_headers(request, config.proxy_token, close_after_response=request.method != "CONNECT")
    )
    await upstream_writer.drain()

    if request.method == "CONNECT":
        response = await read_response_headers(upstream.reader)
        downstream.write(response)
        await downstream.drain()
        status_parts = response.split(b"\r\n", 1)[0].split()
        status_code = status_parts[1] if len(status_parts) >= 2 and response.startswith(b"HTTP/") else b"000"
        if status_code != b"200":
            return 0, await relay_response_body(upstream.reader, downstream, response)
        return await bridge(reader, downstream, upstream.reader, upstream_writer)

    client_bytes = await relay_fixed_request_body(reader, upstream_writer, request)
    upstream_bytes = await relay_response_until_close(upstream.reader, downstream)
    return client_bytes, upstream_bytes


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: ForwarderConfig) -> None:
    peer = writer.get_extra_info("peername")
    started = time.monotonic()
    destination = "-"
    upstream: VerifiedUpstream | None = None
    downstream: AuthorizedWriter | None = None
    client_bytes = 0
    upstream_bytes = 0
    try:
        request = await read_headers(reader)
        if request.version not in {"HTTP/1.0", "HTTP/1.1"}:
            await write_response(writer, "400 Bad Request", b"unsupported HTTP version\n")
            return
        if request.method == "CONNECT":
            host, port = parse_connect_target(request.target)
            destination = f"{host}:{port}"
        else:
            validate_absolute_target(request.target)
            destination = request.target

        upstream, authorization = await open_verified_upstream(config)
        downstream = AuthorizedWriter(writer, authorization)
        relaying = asyncio.create_task(forward_request(reader, downstream, upstream, request, config))
        watching = asyncio.create_task(authorization.wait_until_invalid())
        try:
            done, _ = await asyncio.wait((relaying, watching), return_when=asyncio.FIRST_COMPLETED)
            if watching in done:
                authorization.require_current()
            client_bytes, upstream_bytes = relaying.result()
        finally:
            for task in (relaying, watching):
                task.cancel()
            await asyncio.gather(relaying, watching, return_exceptions=True)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, ValueError, OSError) as exc:
        log(f"connection_error peer={peer!r} destination={destination!r} reason={exc}")
        if isinstance(exc, AtlsPolicyDenied):
            if upstream is not None:
                upstream.writer.transport.abort()
            if downstream is not None and downstream.started:
                writer.transport.abort()
        if not writer.is_closing() and (downstream is None or not downstream.started):
            await write_response(writer, "502 Bad Gateway", b"egress forwarder failed closed\n")
    finally:
        if upstream is not None:
            await close_verified_upstream(upstream)
        writer.close()
        with suppress(OSError):
            await writer.wait_closed()
        duration_ms = int((time.monotonic() - started) * 1000)
        log(
            "connection_closed "
            f"peer={peer!r} destination={destination!r} duration_ms={duration_ms} "
            f"client_bytes={client_bytes} upstream_bytes={upstream_bytes}"
        )


async def main() -> None:
    config = load_config()
    seed_ca_distribution(config)
    ca_task = asyncio.create_task(ca_distribution_loop(config))
    policy_task = asyncio.create_task(atls_policy_refresh_loop(config))
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, config), config.listen_host, config.listen_port)
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    log(f"listening on {sockets}")
    try:
        async with server:
            await server.serve_forever()
    finally:
        ca_task.cancel()
        policy_task.cancel()
        await asyncio.gather(ca_task, policy_task, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
