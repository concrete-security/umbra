#!/usr/bin/env python3
"""No-NIC Linux guest plumbing. Only public bootstrap data crosses from the host."""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import tempfile

HOST_CID = 2
EGRESS_PORT = 4050
BOOT_PORT = 4051
MAX_BOOT = 65536


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".umbra-")
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(data)
        os.replace(name, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name)


def validate_bootstrap(payload: bytes) -> tuple[bytes, bytes]:
    value = json.loads(payload)
    if not isinstance(value, dict) or set(value) != {"ca_pem", "authorized_key"}:
        raise ValueError("invalid bootstrap fields")
    ca, key = value["ca_pem"], value["authorized_key"]
    if not isinstance(ca, str) or not isinstance(key, str) or len(ca) > 32768:
        raise ValueError("invalid bootstrap types")
    if not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{40,200}={0,2}", key):
        raise ValueError("invalid public key")
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=ca)
    except (ssl.SSLError, UnicodeError) as error:
        raise ValueError("invalid public CA") from error
    return ca.encode("ascii"), key.encode("ascii") + b"\n"


async def splice(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 other_reader: asyncio.StreamReader, other_writer: asyncio.StreamWriter) -> None:
    async def pump(source, target):
        while payload := await source.read(65536):
            target.write(payload)
            await target.drain()
        if target.can_write_eof():
            target.write_eof()
            await target.drain()
    tasks = [asyncio.create_task(pump(reader, other_writer)), asyncio.create_task(pump(other_reader, writer))]
    try:
        await asyncio.gather(*tasks)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        other_writer.close()


def vsock_listener(port: int) -> socket.socket:
    listener = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    listener.bind((socket.VMADDR_CID_ANY, port))
    listener.listen(32)
    listener.setblocking(False)
    return listener


async def bootstrap(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        peer = writer.get_extra_info("peername")
        if not peer or peer[0] != HOST_CID:
            return
        payload = await asyncio.wait_for(reader.readuntil(b"\n"), 10)
        if len(payload) > MAX_BOOT:
            return
        ca, key = validate_bootstrap(payload)
        # The CA is replaced, never appended to an old intercepted trust root.
        roots = Path("/etc/ssl/certs/ca-certificates.crt").read_bytes()
        atomic_write(Path("/run/umbra/ca-bundle.pem"), roots + b"\n" + ca, 0o644)
        atomic_write(Path("/run/umbra/security-cvm-ca.pem"), ca, 0o644)
        ssh_dir = Path("/home/dev/.ssh")
        ssh_dir.mkdir(mode=0o700, exist_ok=True)
        atomic_write(ssh_dir / "authorized_keys", key, 0o600)
        os.chown(ssh_dir, 1001, 1001)
        os.chown(ssh_dir / "authorized_keys", 1001, 1001)
        host_key = Path("/etc/ssh/ssh_host_ed25519_key.pub").read_text().split()
        response = {"host_key": " ".join(host_key[:2])}
        writer.write(json.dumps(response).encode() + b"\n")
        await writer.drain()
    except (OSError, ValueError, ssl.SSLError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        pass
    finally:
        writer.close()


async def egress(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    peer.setblocking(False)
    try:
        await asyncio.wait_for(asyncio.get_running_loop().sock_connect(peer, (HOST_CID, EGRESS_PORT)), 10)
        remote_reader, remote_writer = await asyncio.open_connection(sock=peer)
        await splice(reader, writer, remote_reader, remote_writer)
    except (OSError, ConnectionError, TimeoutError):
        peer.close()
        writer.close()


async def ssh(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        peer = writer.get_extra_info("peername")
        if not peer or peer[0] != HOST_CID:
            return
        remote_reader, remote_writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", 22), 10)
        await splice(reader, writer, remote_reader, remote_writer)
    except (OSError, ConnectionError, TimeoutError):
        pass
    finally:
        writer.close()


async def main() -> None:
    processes = []
    process = await asyncio.create_subprocess_exec("/usr/bin/ssh-keygen", "-A")
    if await process.wait() != 0:
        raise RuntimeError("cannot initialize SSH host identity")
    Path("/run/sshd").mkdir(exist_ok=True)
    processes.append(await asyncio.create_subprocess_exec("/usr/sbin/sshd", "-D", "-e"))
    servers = [
        await asyncio.start_server(egress, "127.0.0.1", 3128),
        await asyncio.start_server(bootstrap, sock=vsock_listener(BOOT_PORT), limit=MAX_BOOT),
        await asyncio.start_server(ssh, sock=vsock_listener(22)),
    ]
    tasks = [asyncio.create_task(server.serve_forever()) for server in servers]
    tasks += [asyncio.create_task(process.wait()) for process in processes]
    try:
        await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    finally:
        for task in tasks:
            task.cancel()
        for server in servers:
            server.close()
        for process in processes:
            if process.returncode is None:
                process.terminate()
        await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(main())
