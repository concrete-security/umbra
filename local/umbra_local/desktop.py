"""Desktop SSH registration; never open the host project as a local session."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess

from .state import LocalError, lock, private_dir, write_file

APPS = {"codex": "com.openai.codex", "claude": "com.anthropic.claudefordesktop"}


def read_settings(path: Path) -> bytes:
    """Read user settings without following symlinks or accepting shared writes."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return b""
    except OSError as error:
        raise LocalError(f"cannot safely read desktop settings: {path}") from error
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022 or info.st_size > 1024 * 1024:
            raise LocalError(f"unsafe desktop settings: {path}")
        with os.fdopen(fd, "rb", closefd=False) as source:
            data = source.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise LocalError("desktop settings exceed the size limit")
        return data
    finally:
        os.close(fd)


def replace_settings(path: Path, before: bytes, after: bytes) -> None:
    if before == after:
        return
    if read_settings(path) != before:
        raise LocalError("desktop settings changed concurrently; retry the launch")
    if before:
        backup = path.with_name(path.name + ".umbra-backup-" + hashlib.sha256(before).hexdigest()[:12])
        if not backup.exists():
            write_file(backup, before)
    write_file(path, after)


def install_ssh_include(folder: Path) -> None:
    """Prepend the managed Include; callers hold the SSH registration lock."""
    config = folder / "config"
    before = read_settings(config)
    # Tilde expansion belongs to OpenSSH. Reset stanza scope after Include so
    # pre-existing top-level options still apply to their original hosts.
    include = b'Include ~/.ssh/umbra-local/*.conf\n'
    marker = b'# Umbra local desktop workspaces\n' + include + b'Host *\n# End Umbra local desktop workspaces\n'
    if not before.startswith(marker):
        replace_settings(config, before, marker + before)


def register_ssh(path: Path, binding: dict, home: Path) -> str:
    """Expose only explicitly registered workspaces, preserving existing SSH text."""
    folder = home / ".ssh"
    private_dir(folder)
    entries = folder / "umbra-local"
    private_dir(entries)
    slug = re.sub(r"[^a-z0-9]+", "-", Path(binding["root"]).name.lower()).strip("-")[:24] or "project"
    alias = f"umbra-{slug}-{binding['name'].removeprefix('p-')[:12]}"
    source = read_settings(path / "ssh-editor.conf").decode()
    expected = f"Host umbra-local-{binding['name']}\n"
    if not source.startswith(expected):
        raise LocalError("workspace SSH configuration is missing or invalid")
    # Keep the original HostKeyAlias and ProxyCommand; only discovery gets a friendly name.
    source = f"Host {alias}\n" + source[len(expected):]
    with lock(folder / ".umbra-local.lock"):
        write_file(entries / f"{alias}.conf", source.encode())
        install_ssh_include(folder)
    return alias


def register_claude(alias: str, binding: dict, home: Path) -> None:
    folder = home / ".claude"
    # Claude commonly creates a readable settings directory; require ownership
    # and no shared writes, without changing its existing permissions.
    folder.mkdir(mode=0o700, exist_ok=True)
    info = folder.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022:
        raise LocalError("unsafe Claude settings directory")
    with lock(folder / ".umbra-local.lock"):
        path = folder / "settings.json"
        before = read_settings(path)
        try:
            settings = json.loads(before) if before else {}
            if not isinstance(settings, dict):
                raise ValueError
            entries = settings.setdefault("sshConfigs", [])
            if not isinstance(entries, list) or any(not isinstance(entry, dict) for entry in entries):
                raise ValueError
        except (ValueError, TypeError) as error:
            raise LocalError("invalid Claude settings; existing configuration was preserved") from error
        item = {"id": alias, "name": f"Umbra: {Path(binding['root']).name}", "sshHost": alias}
        existing = next((entry for entry in entries if entry.get("id") == alias), None)
        if existing is not None and existing.get("sshHost") != alias:
            raise LocalError("Claude SSH connection name is already used; existing configuration was preserved")
        if existing is None:
            entries.append(item)
            replace_settings(path, before, (json.dumps(settings, indent=2) + "\n").encode())


def check_guest(app: str, path: Path, binding: dict, guest: str) -> None:
    if app not in APPS:
        raise LocalError("unsupported desktop app")
    # SSH is exercised before app launch, including the login-shell proxy/CA
    # environment used by remote agent backends. Do not print guest output.
    script = 'test "$HTTPS_PROXY" = http://127.0.0.1:3128 && test -r "$SSL_CERT_FILE" && test -d ' + shlex.quote(guest)
    if app == "codex":
        script += " && command -v codex >/dev/null"
    result = subprocess.run(["/usr/bin/ssh", "-F", str(path / "ssh-editor.conf"),
        f"umbra-local-{binding['name']}", "bash -lc " + shlex.quote(script)],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    if result.returncode:
        raise LocalError("desktop guest readiness failed; run umbra ssh to check the agent, proxy environment and CA")


def launch(app: str, path: Path, binding: dict, guest: str) -> dict:
    check_guest(app, path, binding, guest)
    home = Path.home()
    alias = register_ssh(path, binding, home)
    if app == "claude":
        register_claude(alias, binding, home)
    result = subprocess.run(["/usr/bin/open", "-b", APPS[app]],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    if result.returncode:
        raise LocalError("desktop app could not open; sandbox and SSH connection are ready, so open the installed app manually")
    place = "Settings > Connections" if app == "codex" else "Code > environment"
    return {"desktop_app": app, "ssh_host": alias,
        "next_step": f"Select {alias} in {place}, then open {guest}. SSH workspace required; agent not started yet."}
