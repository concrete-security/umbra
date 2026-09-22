"""Private, locked preview state. Hash checks detect drift, not hostile-host tampering."""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")
BUNDLE_FILES = {"Image", "initrd", "rootfs.raw", "umbra-local-vm"}


class LocalError(Exception):
    """Safe, actionable diagnostic; never include raw remote payloads or secrets."""


def workspace(config: Path, name: str) -> Path:
    if not NAME.fullmatch(name):
        raise LocalError("name must start with a lowercase letter and contain at most 32 lowercase letters, digits or hyphens")
    path = config / "local" / name
    if len(os.fsencode(str(path / "control.sock"))) >= 104:
        raise LocalError("local state path is too long for macOS sockets; use --config with a shorter path")
    return path


def private_dir(path: Path) -> None:
    if path.is_symlink():
        raise LocalError("local state directory must not be a symlink")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise LocalError("local state directory must be owned by the current user with permissions 0700")


def write_json(path: Path, value: object) -> None:
    write_file(path, json.dumps(value, sort_keys=True, indent=2).encode() + b"\n")


def write_file(path: Path, payload: bytes, mode: int = 0o600) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".umbra-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


@contextlib.contextmanager
def lock(path: Path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise LocalError("unsafe local lock file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    except BlockingIOError as error:
        raise LocalError("another operation is using this workspace; retry after it finishes") from error
    finally:
        os.close(fd)


def digest_file(path: Path) -> str:
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verify_bundle(path: Path) -> dict:
    try:
        if path.is_symlink():
            raise ValueError
        manifest = json.loads((path / "manifest.json").read_text())
        if set(manifest) != {"version", "architecture", "files"} or manifest["version"] != 2:
            raise ValueError
        if manifest["architecture"] != "aarch64" or set(manifest["files"]) != BUNDLE_FILES:
            raise ValueError
        for name, expected in manifest["files"].items():
            artifact = path / name
            if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError
            if artifact.is_symlink() or not artifact.is_file() or digest_file(artifact) != expected:
                raise ValueError
        if not os.access(path / "umbra-local-vm", os.X_OK):
            raise ValueError
        return manifest
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        raise LocalError("guest bundle is absent, incompatible, incomplete or changed; build/install the preview bundle described in local/README.md") from error


def ssh_config(path: Path, name: str, config: Path, python: str, *, editor: bool = False) -> str:
    import shlex

    def value(raw: str) -> str:
        if any(ord(c) < 32 or ord(c) == 127 for c in raw):
            raise LocalError("control characters are not allowed in SSH paths")
        return '"' + raw.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"') + '"'

    proxy = shlex.join([python, "-I", "-m", "umbra_local.cli", "--config", str(config), "_connect", name])
    if any(ord(c) < 32 or ord(c) == 127 for c in proxy):
        raise LocalError("invalid SSH proxy command")
    return (
        f"Host umbra-local-{name}\n"
        "    HostName localhost\n    User dev\n    Port 22\n"
        f"    HostKeyAlias umbra-local-{name}\n"
        f"    IdentityFile {value(str(path / 'id_ed25519'))}\n"
        f"    UserKnownHostsFile {value(str(path / 'known_hosts'))}\n"
        "    GlobalKnownHostsFile /dev/null\n    StrictHostKeyChecking yes\n"
        "    IdentitiesOnly yes\n    ForwardAgent no\n    ForwardX11 no\n"
        f"    ClearAllForwardings {'no' if editor else 'yes'}\n"
        "    PermitLocalCommand no\n    ControlMaster no\n"
        "    EscapeChar none\n"
        f"    ProxyCommand {proxy.replace('%', '%%')}\n"
    )
