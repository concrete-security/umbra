"""Content-based, one-way project transfer. Also executed inside the guest.

No Git commands, host hooks, host mounts, or symlink dereferencing. The saved
manifest is a merge base: host edits never silently overwrite different VM edits.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import struct
import sys
import tarfile
import tempfile

MAX_MANIFEST = 16 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_RESPONSE = 4096


class TransferError(Exception):
    """A diagnostic safe to display without exposing file contents."""


def valid_path(name: str) -> bool:
    return (isinstance(name, str) and bool(name) and len(name.encode()) <= 4096
            and not any(ord(c) < 32 or ord(c) == 127 for c in name)
            and not name.startswith("/") and all(c not in {"", ".", ".."} for c in name.split("/")))


def safe_link(name: str, target: str) -> bool:
    if not target or target.startswith("/") or any(ord(c) < 32 or ord(c) == 127 for c in target):
        return False
    parts = list(PurePosixPath(name).parent.parts)
    for part in target.split("/"):
        if part == "..":
            if not parts:
                return False
            parts.pop()
        elif part not in {"", "."}:
            parts.append(part)
    return True


def validate_manifest(value: object) -> dict:
    if not isinstance(value, dict) or len(value) > MAX_ENTRIES:
        raise TransferError("project manifest is invalid or too large")
    for name, entry in value.items():
        if not valid_path(name) or not isinstance(entry, dict):
            raise TransferError("project contains an unsupported filename")
        kind = entry.get("kind")
        expected = {"kind", "mode", "sha256", "size"} if kind == "file" else {"kind", "target"} if kind == "link" else {"kind", "mode"}
        if set(entry) != expected or kind not in {"file", "dir", "link"}:
            raise TransferError("project manifest entry is invalid")
        if kind != "link" and (type(entry["mode"]) is not int or not 0 <= entry["mode"] <= 0o777):
            raise TransferError("project mode is invalid")
        if kind == "file":
            digest = entry["sha256"]
            if (not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest)
                    or type(entry["size"]) is not int or entry["size"] < 0):
                raise TransferError("project file metadata is invalid")
        if kind == "link" and (not isinstance(entry["target"], str) or not safe_link(name, entry["target"])):
            raise TransferError("project symlinks must be relative and stay inside the project")
        for parent in PurePosixPath(name).parents:
            if str(parent) != "." and value.get(str(parent), {}).get("kind") != "dir":
                raise TransferError("project manifest has an invalid parent directory")
    return value


@contextlib.contextmanager
def parent_fd(root: Path, name: str):
    """Open each path component without following symlinks, even during races."""
    if not valid_path(name):
        raise TransferError("invalid project path")
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in name.split("/")[:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd, name.split("/")[-1]
    finally:
        os.close(fd)


@contextlib.contextmanager
def open_file(root: Path, name: str):
    with parent_fd(root, name) as (parent, leaf):
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise TransferError("project file changed type during transfer")
            with os.fdopen(fd, "rb", closefd=False) as source:
                yield source
        finally:
            os.close(fd)


def validate_exclusions(value) -> list[str]:
    if not isinstance(value, (list, tuple)) or len(value) > 128 or any(not valid_path(item) or any(c in item for c in '*?[') for item in value):
        raise TransferError('exclusions must be relative names or paths without globs, dot components or control characters')
    return sorted(set(value))


def excluded(name: str, rules) -> bool:
    return any((rule in name.split('/')) if '/' not in rule else (name == rule or name.startswith(rule + '/')) for rule in rules)


def scan(root: Path, *, guest: bool = False, excludes=()) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise TransferError("project root is absent or was replaced by a symlink")
    result = {}
    rules = validate_exclusions(excludes)

    def scan_error(error: OSError) -> None:
        raise error
    # fwalk pins directory descriptors; a concurrent symlink replacement cannot
    # redirect the scan into the employee's home or credential directories.
    for directory, directories, files, fd in os.fwalk(root, follow_symlinks=False, onerror=scan_error):
        prefix = Path(directory).relative_to(root)
        if not guest:
            directories[:] = [leaf for leaf in directories if not excluded((prefix / leaf).as_posix(), rules)]
        for leaf in sorted(directories + files):
            name = (prefix / leaf).as_posix()
            if not guest and excluded(name, rules):
                continue
            if not guest and not valid_path(name):
                raise TransferError("project contains a filename with control characters or an unsupported path")
            info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
            mode = stat.S_IMODE(info.st_mode) & 0o777
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(leaf, dir_fd=fd)
                if not guest and not safe_link(name, target):
                    raise TransferError(f"project symlink {ascii(name)} is external or absolute; keep its target inside the project or exclude its generated folder with --exclude")
                # Also catch chains that escape through another in-tree symlink.
                if not guest and not (root / name).resolve().is_relative_to(root.resolve()):
                    raise TransferError(f"project symlink {ascii(name)} resolves outside the project; exclude its generated folder with --exclude")
                result[name] = {"kind": "link", "target": target}
            elif stat.S_ISDIR(info.st_mode):
                result[name] = {"kind": "dir", "mode": mode}
            elif stat.S_ISREG(info.st_mode):
                with open_file(root, name) as source:
                    before = os.fstat(source.fileno())
                    digest = hashlib.file_digest(source, "sha256").hexdigest()
                    after = os.fstat(source.fileno())
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise TransferError("a project file changed while copying; retry after the write completes")
                result[name] = {"kind": "file", "mode": mode, "sha256": digest, "size": before.st_size}
            elif guest:
                result[name] = {"kind": "guest-special"}
            else:
                raise TransferError("project contains a socket, device or FIFO; remove it before importing the folder")
            if len(result) > MAX_ENTRIES:
                raise TransferError("project has too many files for this preview")
    return result if guest else validate_manifest(result)


def changes(base: dict, desired: dict) -> set[str]:
    return {name for name in base.keys() | desired.keys() if base.get(name) != desired.get(name)}


def conflict_count(base: dict, desired: dict, current: dict) -> int:
    changed = changes(base, desired)
    conflicts = set()
    for name in changed:
        previous, new, live = base.get(name), desired.get(name), current.get(name)
        if live != previous and live != new:
            conflicts.add(name)
        # Directory-to-file replacements and removals may otherwise erase files
        # created only inside the sandbox. Never recursively delete such content.
        if live and live["kind"] == "dir" and (not new or new["kind"] != "dir"):
            if new:
                conflicts.add(name)
            for child in current:
                if child.startswith(name + "/") and (child not in changed or child in desired):
                    conflicts.add(name)
        if live and new and live["kind"] != new["kind"] and "dir" in {live["kind"], new["kind"]}:
            conflicts.add(name)
    return len(conflicts)


def make_archive(root: Path, base: dict, desired: dict, output) -> None:
    """Write only changed payloads. Headers/filenames never become shell text."""
    with tarfile.open(fileobj=output, mode="w|", format=tarfile.PAX_FORMAT) as archive:
        for name in sorted(changes(base, desired)):
            entry = desired.get(name)
            if not entry or entry["kind"] != "file":
                continue
            with open_file(root, name) as source:
                # Verify the opened inode before exposing any bytes to the VM.
                if hashlib.file_digest(source, "sha256").hexdigest() != entry["sha256"]:
                    raise TransferError("a project file changed while copying; retry after the write completes")
                source.seek(0)
                item = tarfile.TarInfo(name)
                item.mode = entry["mode"]
                item.size = entry["size"]
                archive.addfile(item, source)


def stage_archive(stream, staging: Path, base: dict, desired: dict) -> None:
    expected = {name for name in changes(base, desired) if desired.get(name, {}).get("kind") == "file"}
    seen = set()
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for item in archive:
            if item.name not in expected or item.name in seen or not item.isfile() or item.size != desired[item.name]["size"]:
                raise TransferError("project archive does not match the manifest")
            seen.add(item.name)
            destination = staging / item.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.extractfile(item) as source, destination.open("xb") as output:
                shutil.copyfileobj(source, output, 65536)
            with destination.open("rb") as source:
                if hashlib.file_digest(source, "sha256").hexdigest() != desired[item.name]["sha256"]:
                    raise TransferError("project contents changed in transit")
    if seen != expected:
        raise TransferError("project archive is incomplete")


def apply_snapshot(root: Path, staging: Path, base: dict, desired: dict) -> None:
    """Guest-side only. Host receives no files and executes no project hooks."""
    current = scan(root, guest=True)
    conflicts = conflict_count(base, desired, current)
    if conflicts:
        raise TransferError(f"{conflicts} project conflicts; host and sandbox edits were left unchanged")
    changed = changes(base, desired)
    # Delete files before their parent directories. rmdir, never recursive erase.
    for name in sorted((n for n in changed if n not in desired), key=lambda n: (-n.count("/"), n)):
        if name not in current:
            continue
        with parent_fd(root, name) as (parent, leaf):
            if current[name]["kind"] == "dir":
                os.rmdir(leaf, dir_fd=parent)
            else:
                os.unlink(leaf, dir_fd=parent)
    for name in sorted((n for n in changed if n in desired), key=lambda n: (n.count("/"), n)):
        entry = desired[name]
        with parent_fd(root, name) as (parent, leaf):
            if entry["kind"] == "dir":
                try:
                    os.mkdir(leaf, 0o700, dir_fd=parent)
                except FileExistsError:
                    pass
                directory = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
                os.close(directory)
            elif entry["kind"] == "file":
                # An atomic rename cannot follow a guest-supplied destination symlink.
                os.chmod(staging / name, entry["mode"])
                os.replace(staging / name, leaf, dst_dir_fd=parent)
            else:
                temporary = ".umbra-link-" + os.urandom(16).hex()
                try:
                    os.symlink(entry["target"], temporary, dir_fd=parent)
                    os.replace(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent)
                finally:
                    with contextlib.suppress(FileNotFoundError):
                        os.unlink(temporary, dir_fd=parent)
    for name in sorted((n for n in changed if desired.get(n, {}).get("kind") == "dir"), key=lambda n: -n.count("/")):
        with parent_fd(root, name) as (parent, leaf):
            fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            try:
                os.fchmod(fd, desired[name]["mode"])
            finally:
                os.close(fd)


def receive(stream, root: Path) -> dict:
    header = stream.read(4)
    if len(header) != 4 or not 0 < (size := struct.unpack("!I", header)[0]) <= MAX_MANIFEST:
        raise TransferError("invalid project transfer header")
    payload = stream.read(size)
    if len(payload) != size:
        raise TransferError("incomplete project manifest")
    envelope = json.loads(payload)
    if set(envelope) != {"version", "base", "desired"} or envelope["version"] != 1:
        raise TransferError("invalid project transfer envelope")
    base, desired = validate_manifest(envelope["base"]), validate_manifest(envelope["desired"])
    root.mkdir(parents=True, exist_ok=True)
    if root.is_symlink():
        raise TransferError("sandbox project directory must not be a symlink")
    with tempfile.TemporaryDirectory(prefix=".umbra-import-", dir=root.parent) as temporary:
        staging = Path(temporary)
        stage_archive(stream, staging, base, desired)
        apply_snapshot(root, staging, base, desired)
    return {"ok": True, "changed": len(changes(base, desired))}


async def bounded_run(command: list[str], source) -> dict:
    process = await asyncio.create_subprocess_exec(*command, stdin=source, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    try:
        async with asyncio.timeout(600):
            response = bytearray()
            while chunk := await process.stdout.read(min(1024, MAX_RESPONSE + 1 - len(response))):
                response.extend(chunk)
                if len(response) > MAX_RESPONSE:
                    raise TransferError("sandbox returned an oversized transfer response")
            code = await process.wait()
        value = json.loads(response)
        if not isinstance(value, dict) or value.get("ok") is not True or code != 0:
            # Do not display arbitrary content returned by an untrusted VM.
            if isinstance(value, dict) and value.get("error") == "conflict":
                raise TransferError("host and sandbox both changed a file; no automatic overwrite was performed; resolve the conflict inside the sandbox")
            raise TransferError("project transfer failed; files already in the sandbox were not reset")
        return value
    except (ValueError, TimeoutError) as error:
        raise TransferError("project transfer did not complete; retry after checking the sandbox") from error
    finally:
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
            await process.wait()


if __name__ == "__main__":
    try:
        result = receive(sys.stdin.buffer, Path("/home/dev/workspaces/project"))
    except Exception as error:
        result = {"ok": False, "error": "conflict" if isinstance(error, TransferError) and "conflicts" in str(error) else "transfer"}
    print(json.dumps(result), flush=True)
    raise SystemExit(0 if result["ok"] else 1)
