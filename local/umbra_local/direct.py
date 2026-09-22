"""Host-only local lease and direct attested proxy transport. No guest credentials."""
from __future__ import annotations

import asyncio
import contextlib
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import ssl
from urllib.parse import urlsplit
from uuid import UUID

from .state import LocalError

MAX_CLIENTS = 64
MAX_HEADERS = 65536


async def close_process(process) -> None:
    if process.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), 3)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await process.wait()


def validate_lease(value: dict, previous: dict | None = None) -> dict:
    try:
        UUID(value["id"])
        UUID(value["security_cvm_id"])
        expires = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
        remaining = (expires - datetime.now(timezone.utc)).total_seconds()
        if not 0 < remaining <= 330:
            raise ValueError
        if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", value["security_cvm_fqdn"]):
            raise ValueError
        ca = value["ca_pem"]
        if len(ca) > 32768 or hashlib.sha256(ca.encode("ascii")).hexdigest() != value["ca_sha256"]:
            raise ValueError
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cadata=ca)
        if not isinstance(value["atls_policy"], dict):
            raise ValueError
        result = dict(value)
        if previous:
            if value["id"] != previous["id"] or value["security_cvm_id"] != previous["security_cvm_id"]:
                raise ValueError
            result["proxy_token"] = previous["proxy_token"]
        if not re.fullmatch(r"[A-Za-z0-9_-]{40,128}", result["proxy_token"]):
            raise ValueError
        return result
    except (KeyError, ValueError, TypeError, UnicodeError, ssl.SSLError) as error:
        raise LocalError("Console returned invalid local authorization or Security CVM trust material") from error


def proxy_header(data: bytes, token: str) -> tuple[bytes, bool, int]:
    """One outer request per connection; CONNECT carries subsequent TLS requests."""
    if len(data) > MAX_HEADERS or not data.endswith(b"\r\n\r\n"):
        raise LocalError("invalid proxy headers")
    lines = data[:-4].decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or parts[2] != "HTTP/1.1" or not re.fullmatch(r"[A-Z]+", parts[0]):
        raise LocalError("invalid proxy request")
    method, target, _ = parts
    if any(ord(c) <= 32 or ord(c) == 127 for c in target):
        raise LocalError("invalid proxy target")
    connect = method == "CONNECT"
    if connect:
        host, separator, port = target.rpartition(":")
        if not separator or not host or not port.isascii() or not port.isdigit() or not 1 <= int(port) <= 65535:
            raise LocalError("invalid CONNECT target")
    else:
        parsed = urlsplit(target)
        if parsed.scheme != "http" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise LocalError("use absolute HTTP URLs or CONNECT for HTTPS")
    headers = []
    length = None
    hop = {"proxy-authorization", "proxy-connection", "connection", "keep-alive", "upgrade", "te", "trailer"}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if not separator or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in value):
            raise LocalError("invalid proxy header")
        name_lower = name.lower()
        if name_lower == "transfer-encoding":
            raise LocalError("chunked outer proxy requests are unsupported; use HTTPS")
        if name_lower == "content-length":
            value = value.strip()
            if length is not None or not value.isascii() or not value.isdigit() or len(value) > 10:
                raise LocalError("invalid content length")
            length = int(value)
            if length > 10 * 1024 * 1024:
                raise LocalError("proxy body exceeds limit")
        if name_lower not in hop:
            headers.append(f"{name}: {value.strip()}")
    if connect and length:
        raise LocalError("CONNECT must not have a body")
    if not connect:
        headers.append("Connection: close")
    headers.append(f"Proxy-Authorization: Bearer {token}")
    return ("\r\n".join([lines[0], *headers]) + "\r\n\r\n").encode("iso-8859-1"), connect, length or 0


class DirectBroker:
    def __init__(self, config: dict, config_dir):
        self.config = config
        self.config_dir = config_dir
        self.lease = None
        self.clients = set()
        self.processes = set()
        self.closed = False

    def command(self, verb):
        return [self.config["umbra"], "--config", str(self.config_dir), verb]

    def environment(self):
        value = dict(os.environ, UMBRA_NO_UPDATE_CHECK="1", NO_COLOR="1", UMBRA_OUTPUT="text")
        if self.config.get("console_url"):
            value["UMBRA_CONSOLE_URL"] = self.config["console_url"]
        return value

    async def control(self, payload):
        process = await asyncio.create_subprocess_exec(*self.command("local-control"),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, env=self.environment())
        try:
            async with asyncio.timeout(30):
                output, _ = await process.communicate(json.dumps(payload).encode() + b"\n")
                if process.returncode or len(output) > 1024 * 1024:
                    raise LocalError("local workspace authorization failed; check Console access and profile membership")
                return json.loads(output)
        finally:
            await close_process(process)

    async def start(self):
        value = await self.control({"operation": "create", "profile_ids": self.config["profiles"]})
        self.lease = validate_lease(value)
        # Wait for the Security CVM's policy pull; unknown bearer never counts as readiness.
        async with asyncio.timeout(60):
            while True:
                process = await self.open()
                try:
                    request, _, _ = proxy_header(b"CONNECT umbra-local-health.invalid:443 HTTP/1.1\r\nHost: umbra-local-health.invalid:443\r\n\r\n", self.lease["proxy_token"])
                    process.stdin.write(request)
                    await process.stdin.drain()
                    response = await asyncio.wait_for(process.stdout.readuntil(b"\r\n\r\n"), 10)
                    code = response.split(b"\r\n", 1)[0].split()[1]
                    if code in {b"200", b"403"}:
                        return
                    if code != b"407":
                        raise LocalError("Security CVM did not confirm the local workspace identity")
                finally:
                    await self.release(process)
                await asyncio.sleep(2)

    async def renew(self):
        value = await self.control({"operation": "renew", "id": self.lease["id"]})
        self.lease = validate_lease(value, self.lease)

    async def open(self):
        if self.closed or not self.lease:
            raise LocalError("local workspace is not authorized")
        expires = datetime.fromisoformat(self.lease["expires_at"].replace("Z", "+00:00"))
        if expires <= datetime.now(timezone.utc):
            raise LocalError("local workspace authorization expired")
        process = await asyncio.create_subprocess_exec(*self.command("local-tunnel"),
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, env=self.environment(), limit=MAX_HEADERS)
        self.processes.add(process)
        try:
            async with asyncio.timeout(30):
                process.stdin.write(json.dumps({"fqdn": self.lease["security_cvm_fqdn"], "atls_policy": self.lease["atls_policy"]}).encode() + b"\n")
                await process.stdin.drain()
                if await process.stdout.readline() != b'{"ready":true}\n':
                    raise LocalError("attested Security CVM connection failed")
            return process
        except BaseException:
            await self.release(process)
            raise

    async def release(self, process):
        self.processes.discard(process)
        await close_process(process)

    async def attach(self, reader, writer):
        task = asyncio.current_task()
        if self.closed or len(self.clients) >= MAX_CLIENTS:
            writer.close()
            return
        self.clients.add(task)
        process = None
        pumps = []
        try:
            async with asyncio.timeout(15):
                data = await reader.readuntil(b"\r\n\r\n")
                header, connect, length = proxy_header(data, self.lease["proxy_token"])
            process = await self.open()
            process.stdin.write(header)
            await process.stdin.drain()

            async def upload():
                remaining = length
                while connect or remaining:
                    data = await reader.read(65536 if connect else min(remaining, 65536))
                    if not data:
                        if remaining:
                            raise LocalError("incomplete proxy body")
                        return
                    process.stdin.write(data)
                    await process.stdin.drain()
                    remaining -= len(data)
                # No additional request, pipelining, or guest bearer crosses this connection.
                await asyncio.Future()

            async def download():
                while data := await process.stdout.read(65536):
                    writer.write(data)
                    await writer.drain()

            pumps = [asyncio.create_task(upload()), asyncio.create_task(download())]
            done, _ = await asyncio.wait(pumps, return_when=asyncio.FIRST_COMPLETED)
            for completed in done:
                completed.result()
        except (OSError, ValueError, LocalError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            # Never send exception text, attestation material or host credentials to the guest.
            pass
        finally:
            for pump in pumps:
                pump.cancel()
            await asyncio.gather(*pumps, return_exceptions=True)
            if process:
                await self.release(process)
            writer.close()
            self.clients.discard(task)

    async def close(self):
        self.closed = True
        for task in list(self.clients):
            task.cancel()
        await asyncio.gather(*list(self.clients), return_exceptions=True)
        await asyncio.gather(*(self.release(process) for process in list(self.processes)))
        if self.lease:
            with contextlib.suppress(Exception):
                await self.control({"operation": "revoke", "id": self.lease["id"]})
            self.lease = None
