"""Workspace supervisor. Loss of local authorization stops the VM."""
from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path
import re
import signal
import time

from .direct import DirectBroker
from .state import LocalError, lock, write_file, write_json


async def rpc(path: Path, operation: str, timeout: float = 2) -> dict:
    writer = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_unix_connection(str(path / "control.sock"), limit=4096)
            writer.write(json.dumps({"operation": operation}).encode() + b"\n")
            await writer.drain()
            result = json.loads(await reader.readuntil(b"\n"))
            if not isinstance(result, dict):
                raise ValueError
            return result
    finally:
        if writer:
            writer.close()


async def bootstrap(path: Path, ca: str, public_key: str) -> str:
    writer = None
    try:
        async with asyncio.timeout(5):
            reader, writer = await asyncio.open_unix_connection(str(path / "boot.sock"), limit=4096)
            writer.write(json.dumps({"ca_pem": ca, "authorized_key": public_key, "unix_time": int(time.time())}).encode() + b"\n")
            await writer.drain()
            value = json.loads(await reader.readuntil(b"\n"))
            if set(value) != {"host_key"} or not re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/]{40,200}={0,2}", value["host_key"]):
                raise LocalError("guest returned an invalid public SSH identity")
            return value["host_key"]
    finally:
        if writer:
            writer.close()


async def stop_process(process) -> None:
    if process is not None and process.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), 18)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await process.wait()


async def serve(path: Path, config_dir: Path) -> None:
    with lock(path / "runtime.lock"):
        await _serve(path, config_dir)


async def _serve(path: Path, config_dir: Path) -> None:
    config = json.loads((path / "config.json").read_text())
    if config.get("assurance") != "local-preview":
        raise LocalError("managed-local mode is not implemented; this runtime is preview-only")
    broker = DirectBroker(config, config_dir)
    native = None
    servers = []
    tasks = []
    status = {"name": path.name, "state": "starting", "assurance": "local-preview", "profiles": config["profiles"]}
    stopping = asyncio.Event()
    public_key = " ".join((path / "id_ed25519.pub").read_text().split()[:2])
    current_ca = ""
    initial_key = None

    async def maintain_lease() -> None:
        nonlocal current_ca
        while True:
            await asyncio.sleep(60)
            await broker.renew()
            current_ca = broker.lease["ca_pem"]
            # Refresh wall time as well as public trust, including after Mac sleep.
            returned_key = await bootstrap(path, current_ca, public_key)
            if returned_key != initial_key:
                raise LocalError("guest SSH identity changed during bootstrap refresh")

    async def bounded_console(reader) -> None:
        # Guest root controls serial output; drain it without unbounded host disk growth.
        remaining = 1024 * 1024
        while payload := await reader.read(65536):
            if remaining:
                import sys
                sys.stderr.buffer.write(payload[:remaining])
                sys.stderr.buffer.flush()
                remaining = max(0, remaining - len(payload))

    async def control(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request = json.loads(await asyncio.wait_for(reader.readuntil(b"\n"), 2))
            if request == {"operation": "stop"}:
                stopping.set()
            elif request != {"operation": "status"}:
                return
            writer.write(json.dumps(status).encode() + b"\n")
            await writer.drain()
        except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        finally:
            writer.close()

    # Stale sockets are removed only under the exclusive workspace runtime lock.
    for name in ("control.sock", "proxy.sock", "ssh.sock", "boot.sock"):
        with contextlib.suppress(FileNotFoundError):
            (path / name).unlink()
    try:
        await broker.start()
        current_ca = broker.lease["ca_pem"]
        status.update(local_workspace_id=broker.lease["id"], security_cvm_id=broker.lease["security_cvm_id"])
        link_task = asyncio.create_task(maintain_lease())
        tasks.append(link_task)
        servers.append(await asyncio.start_unix_server(broker.attach, str(path / "proxy.sock"), limit=65536))
        native = await asyncio.create_subprocess_exec(str(Path(config["bundle"]) / "umbra-local-vm"), str(path / "vm.json"),
            stderr=asyncio.subprocess.PIPE)
        tasks.append(asyncio.create_task(bounded_console(native.stderr)))
        native_task = asyncio.create_task(native.wait())
        tasks.append(native_task)
        for _ in range(120):
            if native_task.done() or link_task.done():
                raise LocalError("VM or authorization stopped before bootstrap")
            try:
                initial_key = await bootstrap(path, current_ca, public_key)
                break
            except (OSError, TimeoutError, ValueError, asyncio.IncompleteReadError):
                await asyncio.sleep(0.5)
        else:
            raise LocalError("guest bootstrap timed out; inspect the private workspace service.log")
        write_file(path / "known_hosts", f"umbra-local-{path.name} {initial_key}\n".encode())
        status["state"] = "running"
        servers.append(await asyncio.start_unix_server(control, str(path / "control.sock"), limit=4096))
        for number in (signal.SIGTERM, signal.SIGINT):
            asyncio.get_running_loop().add_signal_handler(number, stopping.set)
        stop_task = asyncio.create_task(stopping.wait())
        tasks.append(stop_task)
        done, _ = await asyncio.wait([link_task, native_task, stop_task], return_when=asyncio.FIRST_COMPLETED)
        status["reason"] = "stopped" if stop_task in done else "authorization-or-vm-disconnected"
    finally:
        status["state"] = "stopping"
        # Only child process handles are signalled, never PIDs read from a stale file.
        await stop_process(native)
        await broker.close()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for server in servers:
            server.close()
        status["state"] = "stopped"
        write_json(path / "status.json", status)
        for name in ("control.sock", "proxy.sock", "ssh.sock", "boot.sock"):
            with contextlib.suppress(FileNotFoundError):
                (path / name).unlink()
