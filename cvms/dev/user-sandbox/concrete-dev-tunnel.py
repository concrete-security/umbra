#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import os
import signal
import sys
import time
from dataclasses import dataclass


MAX_HEADER_BYTES = 65536
READ_SIZE = 65536
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


@dataclass(frozen=True)
class TunnelConfig:
    listen_host: str
    listen_port: int
    ssh_host: str
    ssh_port: int
    path: str


def load_config() -> TunnelConfig:
    return TunnelConfig(
        listen_host=os.environ.get("DEV_TUNNEL_HOST", "0.0.0.0"),
        listen_port=int(os.environ.get("DEV_TUNNEL_PORT", "8090")),
        ssh_host=os.environ.get("DEV_CVM_SSH_HOST", "user-sandbox"),
        ssh_port=int(os.environ.get("DEV_CVM_SSH_PORT", "22")),
        path=os.environ.get("DEV_TUNNEL_PATH", "/concrete/tunnel"),
    )


def log(message: str) -> None:
    print(f"dev-tunnel: {message}", file=sys.stderr, flush=True)


async def read_http_headers(reader: asyncio.StreamReader) -> tuple[str, dict[str, str]]:
    try:
        data = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError as exc:
        raise ValueError("client closed before headers") from exc
    except asyncio.LimitOverrunError as exc:
        raise ValueError("headers too large") from exc
    if len(data) > MAX_HEADER_BYTES:
        raise ValueError("headers too large")
    head = data.removesuffix(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    request_line = lines[0]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip().lower()] = value.strip()
    return request_line, headers


def websocket_accept(key: str) -> str:
    digest = hashlib.sha1(f"{key}{WS_GUID}".encode("ascii")).digest()
    return base64.b64encode(digest).decode("ascii")


def valid_websocket_key(key: str) -> bool:
    try:
        decoded = base64.b64decode(key, validate=True)
    except (ValueError, binascii.Error):
        return False
    return len(decoded) == 16


async def write_http_response(writer: asyncio.StreamWriter, status: str, body: bytes = b"") -> None:
    writer.write(
        b"HTTP/1.1 "
        + status.encode("ascii")
        + b"\r\nConnection: close\r\nContent-Length: "
        + str(len(body)).encode("ascii")
        + b"\r\n\r\n"
        + body
    )
    await writer.drain()


async def write_ws_frame(writer: asyncio.StreamWriter, opcode: int, payload: bytes = b"") -> None:
    header = bytearray([0x80 | opcode])
    length = len(payload)
    if length < 126:
        header.append(length)
    elif length <= 0xFFFF:
        header.extend((126, *length.to_bytes(2, "big")))
    else:
        header.extend((127, *length.to_bytes(8, "big")))
    writer.write(bytes(header) + payload)
    await writer.drain()


async def read_ws_frame(reader: asyncio.StreamReader) -> tuple[int, bytes]:
    first_two = await reader.readexactly(2)
    opcode = first_two[0] & 0x0F
    masked = bool(first_two[1] & 0x80)
    length = first_two[1] & 0x7F
    if length == 126:
        length = int.from_bytes(await reader.readexactly(2), "big")
    elif length == 127:
        length = int.from_bytes(await reader.readexactly(8), "big")
    if not masked:
        raise ValueError("client websocket frames must be masked")
    mask = await reader.readexactly(4)
    payload = bytearray(await reader.readexactly(length))
    for index, byte in enumerate(payload):
        payload[index] = byte ^ mask[index % 4]
    return opcode, bytes(payload)


async def websocket_to_tcp(ws_reader: asyncio.StreamReader, ws_writer: asyncio.StreamWriter, tcp_writer: asyncio.StreamWriter) -> None:
    while True:
        opcode, payload = await read_ws_frame(ws_reader)
        if opcode == 0x8:
            break
        if opcode == 0x9:
            await write_ws_frame(ws_writer, 0xA, payload)
            continue
        if opcode in {0x0, 0x1, 0x2}:
            tcp_writer.write(payload)
            await tcp_writer.drain()
            continue
        if opcode == 0xA:
            continue
        raise ValueError(f"unsupported websocket opcode {opcode}")


async def tcp_to_websocket(tcp_reader: asyncio.StreamReader, ws_writer: asyncio.StreamWriter) -> None:
    while True:
        data = await tcp_reader.read(READ_SIZE)
        if not data:
            break
        await write_ws_frame(ws_writer, 0x2, data)


async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: TunnelConfig) -> None:
    peer = writer.get_extra_info("peername")
    started = time.monotonic()
    tcp_writer: asyncio.StreamWriter | None = None
    try:
        request_line, headers = await read_http_headers(reader)
        parts = request_line.split()
        if len(parts) != 3 or parts[0] != "GET" or parts[1].split("?", 1)[0] != config.path:
            await write_http_response(writer, "404 Not Found", b"not found\n")
            return
        if headers.get("upgrade", "").lower() != "websocket":
            await write_http_response(writer, "400 Bad Request", b"missing websocket upgrade\n")
            return
        key = headers.get("sec-websocket-key", "")
        if not key:
            await write_http_response(writer, "400 Bad Request", b"missing websocket key\n")
            return
        if headers.get("sec-websocket-version") != "13" or not valid_websocket_key(key):
            await write_http_response(writer, "400 Bad Request", b"invalid websocket handshake\n")
            return
        writer.write(
            (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {websocket_accept(key)}\r\n"
                "\r\n"
            ).encode("ascii")
        )
        await writer.drain()

        tcp_reader, tcp_writer = await asyncio.open_connection(config.ssh_host, config.ssh_port)
        tasks = {
            asyncio.create_task(websocket_to_tcp(reader, writer, tcp_writer)),
            asyncio.create_task(tcp_to_websocket(tcp_reader, writer)),
        }
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        for task in done:
            task.result()
    except (asyncio.IncompleteReadError, ConnectionError, ValueError) as exc:
        log(f"connection_error peer={peer!r} reason={exc}")
    finally:
        if tcp_writer is not None:
            tcp_writer.close()
            await tcp_writer.wait_closed()
        writer.close()
        await writer.wait_closed()
        duration_ms = int((time.monotonic() - started) * 1000)
        log(f"connection_closed peer={peer!r} duration_ms={duration_ms}")


async def main() -> None:
    config = load_config()
    server = await asyncio.start_server(lambda r, w: handle_client(r, w, config), config.listen_host, config.listen_port)
    sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
    log(f"listening on {sockets}")

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    async with server:
        await stop.wait()
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
