#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import binascii
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
    proxy_token: str
    atls_policy_path: Path
    ca_cert_path: Path
    atls_connect_cmd: tuple[str, ...]
    atls_connect_timeout_seconds: float


@dataclass(frozen=True)
class ProxyRequest:
    method: str
    target: str
    version: str
    headers: list[tuple[str, str]]


def log(message: str) -> None:
    print(f"dev-egress-forwarder: {message}", file=sys.stderr, flush=True)


def required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"missing required env {name}")
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
        proxy_token=proxy_token,
        atls_policy_path=policy_path,
        ca_cert_path=ca_path,
        atls_connect_cmd=argv,
        atls_connect_timeout_seconds=float(os.environ.get("DEV_EGRESS_ATLS_CONNECT_TIMEOUT_SECONDS", "10")),
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


def encode_request_line_and_headers(request: ProxyRequest, proxy_token: str) -> bytes:
    lines = [f"{request.method} {request.target} {request.version}"]
    host_seen = False
    for name, value in filtered_headers(request.headers):
        if name.lower() == "host":
            host_seen = True
        lines.append(f"{name}: {value}")
    if request.method == "CONNECT" and not host_seen:
        lines.append(f"Host: {request.target}")
    lines.append(f"Proxy-Authorization: Bearer {proxy_token}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1")


async def open_verified_upstream(config: ForwarderConfig) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    payload = {
        "fqdn": config.security_cvm_fqdn,
        "port": config.security_cvm_public_port,
        "policy_path": str(config.atls_policy_path),
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
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(json.dumps(payload, separators=(",", ":")).encode("utf-8")),
            timeout=config.atls_connect_timeout_seconds,
        )
    except TimeoutError as exc:
        process.kill()
        await process.wait()
        raise ConnectionError("aTLS connect helper timed out") from exc
    if process.returncode != 0:
        reason = stderr.decode("utf-8", errors="replace").strip().splitlines()[:1]
        raise ConnectionError(f"aTLS connect helper failed: {reason[0] if reason else 'no diagnostic'}")
    try:
        response = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConnectionError("aTLS connect helper returned malformed JSON") from exc
    host = response.get("host")
    port = response.get("port")
    if not isinstance(host, str) or not host or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ConnectionError("aTLS connect helper returned invalid relay address")
    return await asyncio.open_connection(host, port)


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
    upstream_writer: asyncio.StreamWriter | None = None
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

        upstream_reader, upstream_writer = await open_verified_upstream(config)
        upstream_writer.write(encode_request_line_and_headers(request, config.proxy_token))
        await upstream_writer.drain()

        if request.method == "CONNECT":
            response = await upstream_reader.readuntil(b"\r\n\r\n")
            writer.write(response)
            await writer.drain()
            status_parts = response.split(b"\r\n", 1)[0].split()
            status_code = status_parts[1] if len(status_parts) >= 2 and response.startswith(b"HTTP/") else b"000"
            if status_code != b"200":
                return
        client_bytes, upstream_bytes = await bridge(reader, writer, upstream_reader, upstream_writer)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ConnectionError, ValueError, OSError) as exc:
        log(f"connection_error peer={peer!r} destination={destination!r} reason={exc}")
        if not writer.is_closing():
            await write_response(writer, "502 Bad Gateway", b"egress forwarder failed closed\n")
    finally:
        if upstream_writer is not None:
            upstream_writer.close()
            await upstream_writer.wait_closed()
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
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, config), config.listen_host, config.listen_port)
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    log(f"listening on {sockets}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
