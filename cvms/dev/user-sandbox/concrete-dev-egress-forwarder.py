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
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


MAX_HEADER_BYTES = 65536
READ_SIZE = 65536
DEFAULT_SECURITY_CVM_PROXY_PATH = "/concrete/proxy"
DEFAULT_SECURITY_CVM_PROXY_UPGRADE = "concrete-proxy"
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
    atls_policy_refresh_path: Path
    ca_cert_path: Path
    atls_connect_cmd: tuple[str, ...]
    atls_connect_timeout_seconds: float
    ca_distribution_path: Path
    ca_refresh_interval_seconds: float


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


@dataclass(frozen=True)
class RefreshedAtlsPolicy:
    policy_path: Path


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
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
    os.chmod(path, mode)


def materialize_runtime_files(runtime_dir: Path) -> tuple[Path, Path, str]:
    ca_cert = decode_required_b64("SECURITY_CVM_CA_CERT_B64")
    atls_policy = decode_required_b64("SECURITY_CVM_ATLS_POLICY_B64")
    try:
        parsed_policy = json.loads(atls_policy.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("SECURITY_CVM_ATLS_POLICY_B64 must decode to JSON") from exc
    if not isinstance(parsed_policy, dict):
        raise RuntimeError("SECURITY_CVM_ATLS_POLICY_B64 must decode to a JSON object")

    proxy_token = required_env("SECURITY_CVM_PROXY_TOKEN")
    ca_path = runtime_dir / "security-cvm-ca.pem"
    policy_path = runtime_dir / "security-cvm.atls-policy.json"
    token_path = runtime_dir / "proxy-token"
    write_private_file(ca_path, ca_cert, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    write_private_file(policy_path, atls_policy, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    write_private_file(token_path, proxy_token.encode("utf-8"), stat.S_IRUSR)

    for name in ("SECURITY_CVM_CA_CERT_B64", "SECURITY_CVM_ATLS_POLICY_B64", "SECURITY_CVM_PROXY_TOKEN"):
        os.environ.pop(name, None)
    return policy_path, ca_path, proxy_token


def load_config(runtime_dir: Path = Path("/run/concrete")) -> ForwarderConfig:
    policy_path, ca_path, proxy_token = materialize_runtime_files(runtime_dir)
    dev_control_token = required_env("DEV_CVM_CONTROL_TOKEN")
    os.environ.pop("DEV_CVM_CONTROL_TOKEN", None)
    command = os.environ.get("DEV_EGRESS_ATLS_CONNECT_CMD", "/usr/local/bin/concrete-atls-connect")
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
        atls_policy_refresh_path=runtime_dir / "security-cvm.atls-policy.refresh.json",
        ca_cert_path=ca_path,
        atls_connect_cmd=argv,
        atls_connect_timeout_seconds=float(os.environ.get("DEV_EGRESS_ATLS_CONNECT_TIMEOUT_SECONDS", "10")),
        ca_distribution_path=Path(
            os.environ.get("DEV_EGRESS_CA_DISTRIBUTION_PATH", "/var/lib/concrete-ca/security-cvm-ca.pem")
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


async def open_verified_upstream(config: ForwarderConfig) -> VerifiedUpstream:
    primary_error: Exception | None = None
    if config.atls_policy_refresh_path.exists():
        try:
            return await open_verified_upstream_with_policy(
                config,
                policy_path=config.atls_policy_refresh_path,
            )
        except (ConnectionError, OSError) as exc:
            log(f"atls_cached_refresh_failed reason={exc}")

    try:
        return await open_verified_upstream_with_policy(
            config,
            policy_path=config.atls_policy_path,
        )
    except (ConnectionError, OSError) as exc:
        primary_error = exc
        log(f"atls_primary_failed reason={exc}")

    refreshed = await asyncio.to_thread(fetch_refreshed_atls_policy, config)
    if refreshed is not None:
        try:
            return await open_verified_upstream_with_policy(
                config,
                policy_path=refreshed.policy_path,
            )
        except (ConnectionError, OSError) as exc:
            log(f"atls_console_refresh_failed reason={exc}")

    if primary_error is not None:
        raise ConnectionError(f"aTLS verification failed and refresh did not recover: {primary_error}") from primary_error
    raise ConnectionError("aTLS verification failed and refresh did not recover")


def fetch_refreshed_atls_policy(config: ForwarderConfig) -> RefreshedAtlsPolicy | None:
    if config.console_url is None:
        return None
    parsed = urlsplit(config.console_url)
    path = "/internal/dev-control/security-cvm-atls-policy"
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443, timeout=5)
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
        body = response.read(1024 * 1024 + 1)
    except OSError as exc:
        log(f"atls_console_refresh_fetch_failed reason={exc}")
        return None
    finally:
        connection.close()
    if response.status != 200:
        log(f"atls_console_refresh_unavailable status={response.status}")
        return None
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
    try:
        expected_ca_sha256 = hashlib.sha256(config.ca_cert_path.read_bytes()).hexdigest()
    except OSError as exc:
        log(f"atls_console_refresh_rejected reason=ca_unreadable detail={exc}")
        return None
    if payload.get("ca_cert_sha256") != expected_ca_sha256:
        log("atls_console_refresh_rejected reason=ca_changed")
        return None
    policy = payload.get("atls_policy")
    if not isinstance(policy, dict) or policy.get("type") != "dstack_tdx":
        log("atls_console_refresh_rejected reason=invalid_policy")
        return None
    if policy.get("disable_runtime_verification") is True:
        log("atls_console_refresh_rejected reason=runtime_verification_disabled")
        return None
    if not all(policy.get(field) for field in ("expected_bootchain", "app_compose", "os_image_hash")):
        log("atls_console_refresh_rejected reason=runtime_verification_fields_missing")
        return None
    data = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    write_private_file(config.atls_policy_refresh_path, data, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
    log("atls_console_refresh_installed")
    return RefreshedAtlsPolicy(policy_path=config.atls_policy_refresh_path)


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
    if not isinstance(ca_pem, str) or "-----BEGIN CERTIFICATE-----" not in ca_pem:
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
        body = response.read(1024 * 1024 + 1)
    except OSError as exc:
        log(f"ca_fetch_failed reason={exc}")
        return None
    finally:
        connection.close()
    if response.status != 200:
        log(f"ca_fetch_unavailable status={response.status}")
        return None
    if len(body) > 1024 * 1024:
        log("ca_fetch_rejected reason=response_too_large")
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        log("ca_fetch_rejected reason=malformed_json")
        return None
    return extract_validated_ca(payload, config.security_cvm_fqdn)


def write_ca_distribution(config: ForwarderConfig, ca_pem: str) -> bool:
    """Atomically publish the SC CA to the sandbox-shared path. Returns True if it changed."""
    data = ca_pem.encode("utf-8")
    path = config.ca_distribution_path
    try:
        if path.read_bytes() == data:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    log("ca_distribution_updated")
    return True


def seed_ca_distribution(config: ForwarderConfig) -> None:
    """Publish the launch-material CA at startup so the sandbox has a baseline before polling."""
    try:
        ca_pem = config.ca_cert_path.read_text(encoding="utf-8")
        write_ca_distribution(config, ca_pem)
    except OSError as exc:
        log(f"ca_distribution_seed_skipped reason={exc}")


async def ca_distribution_loop(config: ForwarderConfig) -> None:
    """Poll the Console for the current SC CA and republish it for the sandbox to re-install."""
    if config.console_url is None:
        log("ca_distribution_disabled reason=no_console_url")
        return
    while True:
        try:
            await asyncio.sleep(config.ca_refresh_interval_seconds)
            ca_pem = await asyncio.to_thread(fetch_security_cvm_ca, config)
            if ca_pem is not None:
                await asyncio.to_thread(write_ca_distribution, config, ca_pem)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # keep the proxy serving even if CA refresh fails
            log(f"ca_distribution_error reason={exc}")


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


async def copy_stream(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, counter: dict[str, int]) -> None:
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
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter, request: ProxyRequest
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


async def relay_response_until_close(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> int:
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


async def relay_chunked_response_body(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> int:
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
    writer: asyncio.StreamWriter,
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
    left_writer: asyncio.StreamWriter,
    right_reader: asyncio.StreamReader,
    right_writer: asyncio.StreamWriter,
) -> tuple[int, int]:
    left_count = {"bytes": 0}
    right_count = {"bytes": 0}
    left_to_right = asyncio.create_task(copy_stream(left_reader, right_writer, left_count))
    right_to_left = asyncio.create_task(copy_stream(right_reader, left_writer, right_count))
    done, pending = await asyncio.wait({left_to_right, right_to_left}, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for task in done:
        task.result()
    return left_count["bytes"], right_count["bytes"]


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: ForwarderConfig) -> None:
    peer = writer.get_extra_info("peername")
    started = time.monotonic()
    destination = "-"
    upstream: VerifiedUpstream | None = None
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

        upstream = await open_verified_upstream(config)
        await open_security_proxy_tunnel(upstream, config)
        upstream.writer.write(
            encode_request_line_and_headers(
                request,
                config.proxy_token,
                close_after_response=request.method != "CONNECT",
            )
        )
        await upstream.writer.drain()

        if request.method == "CONNECT":
            response = await read_response_headers(upstream.reader)
            writer.write(response)
            await writer.drain()
            status_parts = response.split(b"\r\n", 1)[0].split()
            status_code = status_parts[1] if len(status_parts) >= 2 and response.startswith(b"HTTP/") else b"000"
            if status_code != b"200":
                upstream_bytes = await relay_response_body(upstream.reader, writer, response)
                return
            client_bytes, upstream_bytes = await bridge(reader, writer, upstream.reader, upstream.writer)
        else:
            client_bytes = await relay_fixed_request_body(reader, upstream.writer, request)
            upstream_bytes = await relay_response_until_close(upstream.reader, writer)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, ValueError, OSError) as exc:
        log(f"connection_error peer={peer!r} destination={destination!r} reason={exc}")
        if not writer.is_closing():
            await write_response(writer, "502 Bad Gateway", b"egress forwarder failed closed\n")
    finally:
        if upstream is not None:
            await close_verified_upstream(upstream)
        writer.close()
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
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, config), config.listen_host, config.listen_port)
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    log(f"listening on {sockets}")
    try:
        async with server:
            await server.serve_forever()
    finally:
        ca_task.cancel()


if __name__ == "__main__":
    asyncio.run(main())
