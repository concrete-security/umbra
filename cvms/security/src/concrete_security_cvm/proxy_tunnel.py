from __future__ import annotations

import asyncio
from dataclasses import dataclass
import logging
import os
import time
from urllib.parse import urlsplit


DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_LISTEN_PORT = 8082
DEFAULT_UPSTREAM_HOST = "mitmproxy"
DEFAULT_UPSTREAM_PORT = 8080
DEFAULT_PATH = "/concrete/proxy"
DEFAULT_UPGRADE_TOKEN = "concrete-proxy"
MAX_HEADER_BYTES = 16384
READ_SIZE = 65536


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProxyTunnelConfig:
    listen_host: str = DEFAULT_LISTEN_HOST
    listen_port: int = DEFAULT_LISTEN_PORT
    upstream_host: str = DEFAULT_UPSTREAM_HOST
    upstream_port: int = DEFAULT_UPSTREAM_PORT
    path: str = DEFAULT_PATH
    upgrade_token: str = DEFAULT_UPGRADE_TOKEN

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> ProxyTunnelConfig:
        source = os.environ if env is None else env
        path = source.get("SC_PROXY_TUNNEL_PATH", DEFAULT_PATH).strip()
        if not path.startswith("/") or any(character in path for character in "\r\n\t\0"):
            raise ValueError("SC_PROXY_TUNNEL_PATH must be an absolute path without control characters")
        upgrade_token = source.get("SC_PROXY_TUNNEL_UPGRADE", DEFAULT_UPGRADE_TOKEN).strip()
        if not upgrade_token or any(character in upgrade_token for character in "\r\n\t\0"):
            raise ValueError("SC_PROXY_TUNNEL_UPGRADE must not be empty or contain control characters")
        return cls(
            listen_host=source.get("SC_PROXY_TUNNEL_HOST", DEFAULT_LISTEN_HOST),
            listen_port=_parse_port(source.get("SC_PROXY_TUNNEL_PORT", str(DEFAULT_LISTEN_PORT)), "SC_PROXY_TUNNEL_PORT"),
            upstream_host=source.get("SC_PROXY_TUNNEL_UPSTREAM_HOST", DEFAULT_UPSTREAM_HOST),
            upstream_port=_parse_port(
                source.get("SC_PROXY_TUNNEL_UPSTREAM_PORT", str(DEFAULT_UPSTREAM_PORT)),
                "SC_PROXY_TUNNEL_UPSTREAM_PORT",
            ),
            path=path,
            upgrade_token=upgrade_token,
        )


@dataclass(frozen=True)
class UpgradeRequest:
    method: str
    target: str
    version: str
    headers: dict[str, str]


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: ProxyTunnelConfig) -> None:
    peer = writer.get_extra_info("peername")
    started = time.monotonic()
    upstream_reader: asyncio.StreamReader | None = None
    upstream_writer: asyncio.StreamWriter | None = None
    client_bytes = 0
    upstream_bytes = 0
    try:
        request = await read_upgrade_request(reader)
        validate_upgrade_request(request, config)
        upstream_reader, upstream_writer = await asyncio.open_connection(config.upstream_host, config.upstream_port)
        writer.write(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                f"Upgrade: {config.upgrade_token}\r\n"
                "Connection: Upgrade\r\n"
                "\r\n"
            ).encode("ascii")
        )
        await writer.drain()
        client_bytes, upstream_bytes = await bridge(reader, writer, upstream_reader, upstream_writer)
    except UpgradeError as exc:
        logger.info("proxy_tunnel_upgrade_rejected", extra={"reason": exc.reason})
        if not writer.is_closing():
            await write_response(writer, exc.status, exc.body)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, OSError) as exc:
        logger.info("proxy_tunnel_connection_error", extra={"reason": exc.__class__.__name__})
        if not writer.is_closing():
            await write_response(writer, "502 Bad Gateway", b"proxy tunnel failed closed\n")
    finally:
        if upstream_writer is not None:
            upstream_writer.close()
            await upstream_writer.wait_closed()
        writer.close()
        await writer.wait_closed()
        logger.info(
            "proxy_tunnel_closed",
            extra={
                "peer": repr(peer),
                "duration_ms": int((time.monotonic() - started) * 1000),
                "client_bytes": client_bytes,
                "upstream_bytes": upstream_bytes,
            },
        )


async def read_upgrade_request(reader: asyncio.StreamReader) -> UpgradeRequest:
    data = await reader.readuntil(b"\r\n\r\n")
    if len(data) > MAX_HEADER_BYTES:
        raise UpgradeError("431 Request Header Fields Too Large", b"headers too large\n", "headers_too_large")
    lines = data.removesuffix(b"\r\n\r\n").decode("iso-8859-1").split("\r\n")
    parts = lines[0].split()
    if len(parts) != 3:
        raise UpgradeError("400 Bad Request", b"invalid request line\n", "invalid_request_line")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        lower_name = name.strip().lower()
        existing = headers.get(lower_name)
        headers[lower_name] = f"{existing}, {value.strip()}" if existing else value.strip()
    return UpgradeRequest(method=parts[0].upper(), target=parts[1], version=parts[2], headers=headers)


def validate_upgrade_request(request: UpgradeRequest, config: ProxyTunnelConfig) -> None:
    if request.method != "GET":
        raise UpgradeError("405 Method Not Allowed", b"method not allowed\n", "method_not_allowed")
    if request.version != "HTTP/1.1":
        raise UpgradeError("400 Bad Request", b"HTTP/1.1 required\n", "unsupported_http_version")
    if urlsplit(request.target).path != config.path:
        raise UpgradeError("404 Not Found", b"not found\n", "path_not_found")
    if not _header_has_token(request.headers.get("connection", ""), "upgrade"):
        raise UpgradeError("426 Upgrade Required", b"upgrade required\n", "connection_upgrade_missing")
    if not _header_has_token(request.headers.get("upgrade", ""), config.upgrade_token):
        raise UpgradeError("426 Upgrade Required", b"upgrade required\n", "upgrade_token_missing")


async def write_response(writer: asyncio.StreamWriter, status: str, body: bytes) -> None:
    writer.write(
        b"HTTP/1.1 "
        + status.encode("ascii")
        + b"\r\nConnection: close\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n"
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
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    upstream_reader: asyncio.StreamReader,
    upstream_writer: asyncio.StreamWriter,
) -> tuple[int, int]:
    client_count = {"bytes": 0}
    upstream_count = {"bytes": 0}
    client_to_upstream = asyncio.create_task(copy_stream(client_reader, upstream_writer, client_count))
    upstream_to_client = asyncio.create_task(copy_stream(upstream_reader, client_writer, upstream_count))
    done, pending = await asyncio.wait({client_to_upstream, upstream_to_client}, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for task in done:
        task.result()
    return client_count["bytes"], upstream_count["bytes"]


class UpgradeError(ValueError):
    def __init__(self, status: str, body: bytes, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.body = body
        self.reason = reason


def _header_has_token(value: str, token: str) -> bool:
    token_lower = token.lower()
    return any(part.strip().lower() == token_lower for part in value.split(","))


def _parse_port(raw: str, name: str) -> int:
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"{name} must be 1..65535")
    return port


async def serve(config: ProxyTunnelConfig) -> None:
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, config), config.listen_host, config.listen_port)
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    logger.info("proxy_tunnel_listening", extra={"sockets": sockets})
    async with server:
        await server.serve_forever()


def main() -> None:
    logging.basicConfig(level=os.environ.get("SC_LOG_LEVEL", "INFO"))
    asyncio.run(serve(ProxyTunnelConfig.from_env()))


if __name__ == "__main__":
    main()
