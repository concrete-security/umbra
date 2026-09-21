"""Private runtime worker, invoked by the Rust umbra CLI; no public executable."""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
from pathlib import Path
import platform
import select
import re
import shlex
import shutil
import socket
import subprocess
import sys
import time

from . import projects, service
from .state import LocalError, lock, private_dir, ssh_config, verify_bundle, workspace, write_file, write_json

DEFAULT_BUNDLE = Path("/Library/Application Support/Umbra/Local/preview-v1")


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="umbra (private local runtime)", description="Internal worker for the Umbra CLI.")
    root.add_argument("--config", type=Path, default=Path(os.environ.get("UMBRA_CONFIG_DIR", "~/.umbra")).expanduser())
    root.add_argument("--json", action="store_true", help="structured output for up, status, stop and doctor")
    root.add_argument("--umbra", type=Path, help=argparse.SUPPRESS)
    root.add_argument("--console-url", help=argparse.SUPPRESS)
    root.add_argument("--atls-policy", type=Path, help=argparse.SUPPRESS)
    commands = root.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="check platform, tools and installed guest bundle")
    doctor.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE)
    up = commands.add_parser("up", help="start or reuse a private local workspace")
    up.add_argument("name", nargs="?", default="dev")
    up.add_argument("--preview", action="store_true", help="acknowledge this is not managed-local or TEE-attested execution")
    up.add_argument("--profile", action="append", default=[])
    up.add_argument("--default-profile", action="append", default=[])
    up.add_argument("--bundle", type=Path)
    up.add_argument("--cpus", type=int)
    up.add_argument("--memory", type=int, help="memory in MiB")
    for verb in ("status", "shell", "ssh-config", "code", "cursor"):
        item = commands.add_parser(verb)
        item.add_argument("name", nargs="?", default="dev")
    stop = commands.add_parser("stop", help="stop a named workspace without deleting its disk")
    stop.add_argument("name")
    execute = commands.add_parser("exec", help="execute argv inside the local VM")
    execute.add_argument("name")
    execute.add_argument("argv", nargs=argparse.REMAINDER)
    for verb in ("_serve", "_connect"):
        item = commands.add_parser(verb, help=argparse.SUPPRESS)
        item.add_argument("name")
    start = commands.add_parser("project-start", help=argparse.SUPPRESS)
    start.add_argument("--path", type=Path, default=Path.cwd())
    start.add_argument("--preview", action="store_true")
    start.add_argument("--profile", action="append", default=[])
    start.add_argument("--default-profile", action="append", default=[])
    start.add_argument("--bundle", type=Path)
    start.add_argument("--cpus", type=int)
    start.add_argument("--memory", type=int)
    for verb in ("project-status", "project-stop"):
        item = commands.add_parser(verb, help=argparse.SUPPRESS)
        item.add_argument("--path", type=Path, default=Path.cwd())
    session = commands.add_parser("project-session", help=argparse.SUPPRESS)
    session.add_argument("--path", type=Path, default=Path.cwd())
    session.add_argument("--verb", choices=("ssh", "claude", "codex", "code", "cursor"), required=True)
    session.add_argument("--workspace")
    session.add_argument("--name")
    session.add_argument("--remote-command")
    session.add_argument("--editor-bin", type=Path)
    return root


def emit(args, payload: dict) -> None:
    if args.json:
        print(json.dumps(payload, sort_keys=True))
        return
    print(f"> {payload.get('name', 'Local preview')}")
    for key, value in payload.items():
        if key != "name":
            print(f"      {key:<12} {value}")


def check_platform() -> None:
    version = platform.mac_ver()[0].split(".")[0]
    if platform.system() != "Darwin" or platform.machine() != "arm64" or not version or int(version) < 14:
        raise LocalError("local execution requires an Apple-silicon Mac running macOS 14 or later")


def status(path: Path) -> dict:
    try:
        return asyncio.run(service.rpc(path, "status"))
    except (OSError, ValueError, TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
        value = {"name": path.name, "state": "stopped", "assurance": "local-preview"}
        if (path / "status.json").is_file():
            with contextlib.suppress(OSError, ValueError):
                stored = json.loads((path / "status.json").read_text())
                if isinstance(stored, dict):
                    value["reason"] = stored.get("reason", "not-running")
        return value


def require_running(path: Path) -> None:
    if status(path)["state"] != "running":
        raise LocalError(f"local workspace is stopped; run umbra start local from its project folder")


def prepare(args, path: Path) -> dict:
    previous = json.loads((path / "config.json").read_text()) if (path / "config.json").exists() else {}
    profiles = args.profile or previous.get("profiles") or args.default_profile
    from uuid import UUID
    try:
        if not profiles or len(profiles) > 16 or len(set(profiles)) != len(profiles):
            raise ValueError
        for profile in profiles:
            UUID(profile)
    except (ValueError, TypeError):
        raise LocalError("select assigned policy profiles with --profile UUID-or-alias; no Dev CVM is needed") from None
    bundle = (args.bundle or Path(previous.get("bundle", str(DEFAULT_BUNDLE)))).expanduser().resolve()
    binary = str(args.umbra) if getattr(args, "umbra", None) else shutil.which("umbra")
    if not binary:
        raise LocalError("umbra is not installed; install the existing Umbra CLI and log in first")
    cpus = args.cpus if args.cpus is not None else previous.get("cpus", 4)
    memory = args.memory if args.memory is not None else previous.get("memory", 4096)
    if not 2 <= cpus <= min(32, os.cpu_count() or 2) or not 1024 <= memory <= 65536:
        raise LocalError("CPU or memory setting is outside the supported range")
    config = {"profiles": profiles, "bundle": str(bundle), "umbra": str(Path(binary).resolve()), "cpus": cpus,
              "memory": memory, "assurance": "local-preview"}
    for key in ("source", "console_url", "atls_policy"):
        value = getattr(args, key, None) or previous.get(key)
        if value is not None:
            config[key] = str(value)
    if status(path)["state"] == "running":
        if previous != config:
            raise LocalError("workspace is running with different settings; stop it before changing them")
        return config
    manifest = verify_bundle(bundle)
    if previous and previous.get("bundle") != config["bundle"]:
        raise LocalError("changing guest bundles on an existing disk is not supported; use a new workspace name")
    if (path / "bundle.json").exists() and json.loads((path / "bundle.json").read_text()) != manifest:
        raise LocalError("the base guest bundle changed; use a new workspace to avoid an incompatible kernel/disk pair")
    if not (path / "disk.raw").exists():
        temporary = path / "disk.raw.pending"
        with contextlib.suppress(FileNotFoundError):
            temporary.unlink()
        try:
            # APFS clone avoids copying the full virtual disk at every launch.
            result = subprocess.run(["/bin/cp", "-c", str(bundle / "rootfs.raw"), str(temporary)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode:
                with contextlib.suppress(FileNotFoundError):
                    temporary.unlink()
                shutil.copyfile(bundle / "rootfs.raw", temporary)
            os.chmod(temporary, 0o600)
            os.replace(temporary, path / "disk.raw")
        finally:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()
    key = path / "id_ed25519"
    if not key.exists():
        result = subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "umbra-local", "-f", str(key)],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if result.returncode:
            raise LocalError("could not create workspace SSH identity")
    if not (path / "id_ed25519.pub").is_file():
        raise LocalError("workspace public SSH identity is missing; restore it before starting")
    write_json(path / "bundle.json", manifest)
    write_json(path / "config.json", config)
    write_json(path / "vm.json", {"kernel": str(bundle / "Image"), "initrd": str(bundle / "initrd"),
                                 "disk": str(path / "disk.raw"), "socketDirectory": str(path),
                                 "cpus": cpus, "memoryMiB": memory})
    write_file(path / "ssh.conf", ssh_config(path, path.name, args.config, sys.executable).encode())
    write_file(path / "ssh-editor.conf", ssh_config(path, path.name, args.config, sys.executable, editor=True).encode())
    return config


def up(args, path: Path) -> dict:
    check_platform()
    previously_accepted = False
    if (path / "config.json").is_file():
        previously_accepted = json.loads((path / "config.json").read_text()).get("assurance") == "local-preview"
    if not args.preview and not previously_accepted:
        raise LocalError("this is a local preview, not managed-local; use umbra start local --preview on first launch after reading local/README.md")
    private_dir(args.config / "local")
    private_dir(path)
    with lock(path / "operation.lock"):
        prepare(args, path)
        current = status(path)
        if current["state"] == "running":
            return current
        print("Starting private VM with direct attested Security CVM egress...", file=sys.stderr)
        print("[WARN] local-preview trusts this Mac; Console authorizes a distinct local workspace identity.", file=sys.stderr)
        fd = os.open(path / "service.log", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as log:
            process = subprocess.Popen([sys.executable, "-I", "-m", "umbra_local.cli", "--config", str(args.config), "_serve", path.name],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        try:
            for _ in range(180):
                current = status(path)
                if current["state"] == "running":
                    return current
                if process.poll() is not None:
                    raise LocalError("workspace could not start; inspect its private service.log and check Console local-workspace support")
                time.sleep(0.5)
            raise LocalError("workspace startup timed out; no direct-network fallback was enabled")
        except BaseException:
            # Cancellation must not leave an undisclosed startup in progress.
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=25)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            raise



def connect(path: Path) -> int:
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        peer.connect(str(path / "ssh.sock"))
        incoming = [peer, sys.stdin.buffer]
        while incoming:
            readable, _, _ = select.select(incoming, [], [])
            for stream in readable:
                payload = peer.recv(65536) if stream is peer else os.read(sys.stdin.fileno(), 65536)
                if not payload:
                    incoming.remove(stream)
                    if stream is not peer:
                        peer.shutdown(socket.SHUT_WR)
                    else:
                        return 0
                elif stream is peer:
                    sys.stdout.buffer.write(payload)
                    sys.stdout.buffer.flush()
                else:
                    peer.sendall(payload)
        return 0
    finally:
        peer.close()



def project_payload(path: Path, binding: dict, directory: Path) -> dict:
    return dict(status(path), backend="local", project=binding["root"],
                guest_workspace=projects.guest_directory(binding, directory))


def project_command(args) -> int:
    directory = args.path.expanduser().resolve(strict=True)
    if args.command == "project-start":
        check_platform()
        selected = projects.select(args.config, directory)
        if selected is None and not args.preview:
            raise LocalError("local preview requires --preview on first launch; this is not a managed-local installation")
        # Detect unsupported files before starting a VM. Do not execute Git hooks
        # or ignore untracked/dotfiles: this is the caller's whole folder.
        source = Path(selected["root"]) if selected else directory
        projects.project_files.scan(source)
        binding = projects.bind(args.config, directory)
        args.name = binding["name"]
        args.source = binding["root"]
        path = workspace(args.config, args.name)
        up(args, path)
        print("Copying project changes into the sandbox...", file=sys.stderr)
        summary = projects.sync(path, binding)
        payload = project_payload(path, binding, directory)
        payload.update(imported_files=summary["files"], changed_files=summary["changed"])
        emit(args, payload)
        return 0
    binding = projects.select(args.config, directory)
    if binding is None:
        raise LocalError("this folder has no local workspace; run umbra start local here first")
    path = workspace(args.config, binding["name"])
    if args.command == "project-status":
        emit(args, project_payload(path, binding, directory))
        return 0
    if args.command == "project-stop":
        if status(path)["state"] == "running":
            asyncio.run(service.rpc(path, "stop"))
            for _ in range(50):
                if status(path)["state"] == "stopped":
                    break
                time.sleep(0.5)
            else:
                raise LocalError("local stop is still in progress; use umbra status before restarting")
        emit(args, project_payload(path, binding, directory))
        return 0
    if args.json:
        raise LocalError("--json is not supported for interactive or raw session output")
    require_running(path)
    try:
        summary = projects.sync(path, binding)
        if summary["changed"]:
            print(f"Copied {summary['changed']} project changes into the sandbox.", file=sys.stderr)
    except projects.ProjectConflict:
        # Keep access to the VM so the user can resolve the conflict. Neither
        # side is overwritten and the last successful merge base is retained.
        print("[WARN] Conflicting host and sandbox edits were not copied. Opening existing sandbox files so you can resolve them.", file=sys.stderr)
    guest = projects.guest_directory(binding, directory, args.workspace)
    if args.verb in {"code", "cursor"}:
        return project_editor(args, path, guest)
    script = session_script(args.verb, guest, args.name, args.remote_command)
    command = ["/usr/bin/ssh", "-F", str(path / "ssh.conf")]
    if args.remote_command is None:
        command.append("-t")
    command.extend([f"umbra-local-{path.name}", script])
    return subprocess.call(command)


def session_script(verb: str, guest: str, name: str | None, remote_command: str | None) -> str:
    if name and remote_command is not None:
        raise LocalError("--name cannot be combined with --command")
    if name is not None and not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", name):
        raise LocalError("invalid local session name")
    if remote_command is not None:
        launch = shlex.join(["bash", "-lc", remote_command])
    elif verb == "ssh":
        launch = "bash -l"
    else:
        launch = shlex.quote(verb)
    prefix = "cd -- " + shlex.quote(guest) + " && "
    if name is not None:
        return prefix + "mkdir -p /home/dev/.umbra-sessions && chmod 700 /home/dev/.umbra-sessions && exec dtach -A " + shlex.quote("/home/dev/.umbra-sessions/" + name) + " bash -lc " + shlex.quote(launch)
    return prefix + "exec " + launch


def project_editor(args, path: Path, guest: str) -> int:
    binary = str(args.editor_bin) if args.editor_bin else shutil.which(args.verb)
    if not binary:
        raise LocalError(f"install the {args.verb} command and Remote SSH extension first")
    profile = path / (args.verb + "-client")
    (profile / "User").mkdir(parents=True, exist_ok=True)
    write_json(profile / "User" / "settings.json", {"remote.SSH.configFile": str(path / "ssh-editor.conf"), "remote.SSH.enableAgentForwarding": False})
    print("[WARN] Editor-hosted tools are outside the VM boundary; run agents and MCP servers inside the VM.", file=sys.stderr)
    return subprocess.call([binary, "--user-data-dir", str(profile), "--remote", f"ssh-remote+umbra-local-{path.name}", guest])

def main() -> int:
    args = parser().parse_args()
    args.config = args.config.expanduser().resolve()
    try:
        if args.command.startswith("project-"):
            return project_command(args)
        if args.command == "doctor":
            check_platform()
            if not shutil.which("umbra") or not shutil.which("ssh"):
                raise LocalError("install the Umbra CLI and OpenSSH first")
            verify_bundle(args.bundle.expanduser().resolve())
            emit(args, {"state": "ready-for-preview", "assurance": "local-preview", "managed_device_admission": "not implemented"})
            return 0
        path = workspace(args.config, args.name)
        if args.command == "_serve":
            asyncio.run(service.serve(path, args.config))
        elif args.command == "_connect":
            return connect(path)
        elif args.command == "up":
            emit(args, up(args, path))
        elif args.command == "status":
            emit(args, status(path))
        elif args.command == "stop":
            if status(path)["state"] == "running":
                asyncio.run(service.rpc(path, "stop"))
                for _ in range(50):
                    if status(path)["state"] == "stopped":
                        break
                    time.sleep(0.5)
                else:
                    raise LocalError("stop is still in progress; check status before restarting")
            emit(args, status(path))
        elif args.command == "ssh-config":
            if args.json:
                raise LocalError("--json is not supported for ssh-config")
            require_running(path)
            print((path / "ssh.conf").read_text(), end="")
        elif args.command in {"shell", "exec"}:
            if args.json:
                raise LocalError("--json is not supported for interactive or raw command output")
            require_running(path)
            command = ["/usr/bin/ssh", "-F", str(path / "ssh.conf"), f"umbra-local-{path.name}"]
            if args.command == "exec":
                argv = args.argv[1:] if args.argv and args.argv[0] == "--" else args.argv
                if not argv:
                    raise LocalError("exec requires a command after --")
                command.append(shlex.join(argv))
            return subprocess.call(command)
        elif args.command in {"code", "cursor"}:
            if args.json:
                raise LocalError("--json is not supported for editor launch")
            require_running(path)
            binary = shutil.which(args.command)
            if not binary:
                raise LocalError(f"install the {args.command} command and the Remote SSH extension first")
            profile = path / (args.command + "-client")
            (profile / "User").mkdir(parents=True, exist_ok=True)
            write_json(profile / "User" / "settings.json", {"remote.SSH.configFile": str(path / "ssh-editor.conf"), "remote.SSH.enableAgentForwarding": False})
            print("[WARN] editor-hosted tools are outside the VM boundary; run agents and MCP servers inside the VM.", file=sys.stderr)
            return subprocess.call([binary, "--user-data-dir", str(profile), "--remote", f"ssh-remote+umbra-local-{path.name}", "/home/dev/workspaces"])
        return 0
    except (LocalError, OSError, ValueError, TimeoutError) as error:
        message = str(error) if isinstance(error, LocalError) else "local operation failed; inspect the private workspace log and configuration"
        print(f"[error] {message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("[cancelled] local operation interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
