"""Folder-local selection, kept outside the checkout and its imported files."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import shlex
import stat
import struct
import tempfile

from . import project_files
from .state import LocalError, lock, private_dir, workspace, write_json

REGISTRY = "local-projects.json"
GUEST_ROOT = "/home/dev/workspaces/project"


def read_registry(config: Path) -> dict:
    path = config / REGISTRY
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return {"version": 1, "projects": []}
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077 or info.st_size > 1024 * 1024:
            raise LocalError("unsafe local project registry; refusing to fall back to a cloud workspace")
        with os.fdopen(fd, "rb", closefd=False) as source:
            value = json.loads(source.read(1024 * 1024 + 1))
        return validate_registry(value)
    except (OSError, ValueError, TypeError) as error:
        raise LocalError("invalid local project registry; refusing to fall back to a cloud workspace") from error
    finally:
        os.close(fd)


def validate_registry(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {"version", "projects"} or value["version"] != 1 or not isinstance(value["projects"], list):
        raise ValueError("invalid registry")
    roots, names = set(), set()
    for binding in value["projects"]:
        if not isinstance(binding, dict) or set(binding) != {"root", "name"}:
            raise ValueError("invalid binding")
        root, name = binding["root"], binding["name"]
        if not isinstance(root, str) or not Path(root).is_absolute() or str(Path(root)) != root or ".." in Path(root).parts or any(ord(c) < 32 or ord(c) == 127 for c in root):
            raise ValueError("invalid project root")
        # Reuse the runtime's path/name constraints without creating state.
        workspace(Path("/tmp/umbra"), name)
        if root in roots or name in names:
            raise ValueError("duplicate project binding")
        roots.add(root)
        names.add(name)
    return value


def select(config: Path, directory: Path) -> dict | None:
    directory = directory.resolve(strict=True)
    matches = [item for item in read_registry(config)["projects"] if directory.is_relative_to(Path(item["root"]))]
    return max(matches, key=lambda item: len(Path(item["root"]).parts)) if matches else None


def bind(config: Path, directory: Path) -> dict:
    root = directory.resolve(strict=True)
    config = config.resolve()
    if not root.is_dir() or root == Path(root.anchor) or root == Path.home().resolve():
        raise LocalError("start inside a project folder, not the filesystem root or your home directory")
    if root.is_relative_to(config) or config.is_relative_to(root):
        raise LocalError("project and Umbra configuration directories must not contain each other")
    if any(ord(c) < 32 or ord(c) == 127 for c in str(root)):
        raise LocalError("project path must not contain control characters")
    private_dir(config)
    with lock(config / "local-projects.lock"):
        registry = read_registry(config)
        matches = [item for item in registry["projects"] if root.is_relative_to(Path(item["root"]))]
        if matches:
            return max(matches, key=lambda item: len(Path(item["root"]).parts))
        binding = {"root": str(root), "name": "p-" + hashlib.sha256(os.fsencode(root)).hexdigest()[:20]}
        registry["projects"].append(binding)
        validate_registry(registry)
        write_json(config / REGISTRY, registry)
        return binding


def guest_directory(binding: dict, directory: Path, override: str | None = None) -> str:
    root = Path(binding["root"])
    relative = directory.resolve(strict=True).relative_to(root)
    if override is not None:
        raw = Path(override)
        if raw.is_absolute():
            try:
                relative = raw.relative_to(GUEST_ROOT)
            except ValueError as error:
                raise LocalError("local --workspace must stay inside the imported sandbox project") from error
        else:
            relative = relative / raw
    parts = []
    for component in relative.parts:
        if component == "..":
            if not parts:
                raise LocalError("local --workspace must stay inside the imported sandbox project")
            parts.pop()
        elif component not in {"", "."}:
            parts.append(component)
    result = str(Path(GUEST_ROOT).joinpath(*parts))
    if any(ord(c) < 32 or ord(c) == 127 for c in result):
        raise LocalError("workspace path contains control characters")
    return result


def sync(path: Path, binding: dict) -> dict:
    """Push changed host files; retain VM-only edits and never write host files."""
    root = Path(binding["root"])
    try:
        with lock(path / "import.lock"):
            manifest_path = path / "host-manifest.json"
            base = project_files.validate_manifest(json.loads(manifest_path.read_text())) if manifest_path.exists() else {}
            desired = project_files.scan(root)
            # Still initialize an empty project on its first import.
            if manifest_path.exists() and desired == base:
                return {"changed": 0, "files": len(desired)}
            envelope = json.dumps({"version": 1, "base": base, "desired": desired}, separators=(",", ":")).encode()
            if len(envelope) > project_files.MAX_MANIFEST:
                raise LocalError("project metadata exceeds the preview import limit")
            source = Path(project_files.__file__).read_text()
            command = ["/usr/bin/ssh", "-F", str(path / "ssh.conf"), f"umbra-local-{path.name}", shlex.join(["python3", "-u", "-c", source])]
            with tempfile.TemporaryFile() as request:
                request.write(struct.pack("!I", len(envelope)))
                request.write(envelope)
                project_files.make_archive(root, base, desired, request)
                request.seek(0)
                result = asyncio.run(project_files.bounded_run(command, request))
            write_json(manifest_path, desired)
            return {"changed": result.get("changed", 0), "files": len(desired)}
    except project_files.TransferError as error:
        if "host and sandbox both changed" in str(error):
            raise ProjectConflict(str(error)) from error
        raise LocalError(str(error)) from error


class ProjectConflict(LocalError):
    """The session can still open existing sandbox work to resolve the conflict."""
