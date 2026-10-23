#!/usr/bin/env python3
"""Check the absent-code guarantees behind two scoped Trivy pip SBOM exceptions."""

from __future__ import annotations

import ast
from email.parser import Parser
import json
import os
from pathlib import Path
import sys
import zipfile

PINNED = {"pip": "26.2.2", "msgpack": "1.1.2", "setuptools": "70.3.0", "urllib3": "2.8.0"}
IGNORED = {"msgpack": "1.1.2", "setuptools": "70.3.0"}
MSGPACK_FILES = {"COPYING", "__init__.py", "exceptions.py", "ext.py", "fallback.py"}
MAX_ENTRIES = 500_000
MAX_BYTES = 16 * 1024 * 1024


def fail(message: str) -> None:
    raise ValueError(message)


def read(path: Path) -> bytes:
    if path.stat().st_size > MAX_BYTES:
        fail(f"oversized file: {path}")
    return path.read_bytes()


def walk(root: Path, *, followlinks: bool = False):
    """Bound traversal and fail closed on unreadable image inventory."""
    count = 0
    visited = set()
    def onerror(error):
        raise error
    for directory, directories, files in os.walk(root, onerror=onerror, followlinks=followlinks):
        count += len(directories) + len(files)
        if count > MAX_ENTRIES:
            fail(f"inventory limit exceeded: {root}")
        if followlinks:
            info = Path(directory).stat()
            identity = (info.st_dev, info.st_ino)
            if identity in visited:
                directories.clear()
                # An alias can give an existing directory a dist-info name.
                yield Path(directory), directories, files
                continue
            visited.add(identity)
        yield Path(directory), directories, files


def version(source: bytes) -> str:
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            return ast.literal_eval(node.value)
    fail("missing literal package version")


def check_vendor(files: dict[str, bytes]) -> None:
    if version(files["pip/__init__.py"]) != PINNED["pip"]:
        fail("reassess exceptions after pip version drift")
    manifest = files["pip/_vendor/vendor.txt"].decode().splitlines()
    for name in ("msgpack", "setuptools", "urllib3"):
        if sum(line.split("#", 1)[0].strip() == f"{name}=={PINNED[name]}" for line in manifest) != 1:
            fail(f"reassess exceptions after {name} vendor version drift")
        components = [item for item in json.loads(files["pip/_vendor/bom.cdx.json"])["components"] if item["name"] == name]
        if len(components) != 1 or components[0]["version"] != PINNED[name]:
            fail(f"unexpected {name} vendor SBOM")
    prefix = "pip/_vendor/msgpack/"
    names = {name[len(prefix):] for name in files if name.startswith(prefix)}
    if names != MSGPACK_FILES or version(files[prefix + "__init__.py"]) != PINNED["msgpack"]:
        fail("pip msgpack must contain only the reviewed pure-Python subset")
    if "pip/_vendor/pkg_resources/__init__.py" not in files:
        fail("unexpected setuptools vendor subset")
    for name, data in files.items():
        if name.startswith("pip/_vendor/"):
            if name.startswith("pip/_vendor/setuptools/") or Path(name).stem.startswith("package_index"):
                fail(f"PackageIndex implementation present: {name}")
            if name.endswith(".py") and any(
                isinstance(node, ast.ClassDef) and node.name == "PackageIndex"
                for node in ast.walk(ast.parse(data))
            ):
                fail(f"PackageIndex implementation present: {name}")


def check_metadata(data: bytes, location: Path) -> tuple[str, str]:
    metadata = Parser().parsestr(data.decode())
    if len(metadata.get_all("Name", [])) != 1 or len(metadata.get_all("Version", [])) != 1:
        fail(f"incomplete package metadata: {location}")
    name = metadata["Name"].lower().replace("_", "-").replace(".", "-")
    package_version = metadata["Version"]
    if IGNORED.get(name) == package_version:
        fail(f"real installed {name} {package_version} is not a pip vendor exception: {location}")
    return name, package_version


def check_image(root: Path) -> None:
    bundled = []
    pip_roots = set()
    for directory, directories, files in walk(root, followlinks=True):
        if directory == root:
            directories[:] = [name for name in directories if name not in {"proc", "sys", "dev", "run"}]
        if directory.name == "_bundled" and directory.parent.name == "ensurepip":
            bundled.extend(directory / name for name in files if name.startswith("pip-") and name.endswith(".whl"))
        metadata = None
        if directory.name.endswith(".dist-info"):
            metadata = directory / "METADATA"
        elif directory.name.endswith(".egg-info") or directory.name == "EGG-INFO":
            metadata = directory / "PKG-INFO"
        if metadata is not None:
            name, package_version = check_metadata(read(metadata), metadata)
            if name == "pip":
                if package_version != PINNED["pip"]:
                    fail("reassess exceptions after installed pip version drift")
                pip_roots.add(directory.parent / "pip")
        for name in files:
            if name.endswith(".egg-info"):
                check_metadata(read(directory / name), directory / name)
            elif name.endswith(".egg"):
                with zipfile.ZipFile(directory / name) as archive:
                    if archive.getinfo("EGG-INFO/PKG-INFO").file_size > MAX_BYTES:
                        fail("oversized egg metadata")
                    check_metadata(archive.read("EGG-INFO/PKG-INFO"), directory / name)
    if not pip_roots:
        fail("no installed pip metadata found")
    for pip_root in pip_roots:
        files = {}
        for directory, _, names in walk(pip_root, followlinks=True):
            for name in names:
                path = directory / name
                relative = "pip/" + path.relative_to(pip_root).as_posix()
                if path.stem.lower().startswith("package_index"):
                    fail(f"PackageIndex implementation present: {relative}")
                if path.suffix == ".pyc":
                    source = path.with_suffix(".py")
                    if path.parent.name == "__pycache__":
                        source = path.parent.parent / (path.name.split(".", 1)[0] + ".py")
                    if not source.is_file():
                        fail(f"sourceless pip bytecode present: {relative}")
                    continue
                if relative.startswith("pip/_vendor/") and path.suffix in {".so", ".pyd", ".dll", ".dylib"}:
                    fail(f"native pip vendor module present: {relative}")
                if path.suffix == ".py" or relative.endswith(("/vendor.txt", "/bom.cdx.json")) or relative.startswith("pip/_vendor/msgpack/"):
                    files[relative] = read(path)
        check_vendor(files)
    for wheel in bundled:
        if wheel.stat().st_size > MAX_BYTES:
            fail(f"oversized ensurepip wheel: {wheel}")
        with zipfile.ZipFile(wheel) as archive:
            if sum(item.file_size for item in archive.infolist()) > MAX_BYTES:
                fail(f"oversized ensurepip wheel contents: {wheel}")
            check_vendor({name: archive.read(name) for name in archive.namelist() if not name.endswith("/")})


if __name__ == "__main__":
    try:
        check_image(Path("/"))
    except (ValueError, OSError, KeyError, SyntaxError, zipfile.BadZipFile) as error:
        print(f"pip vendor exception guard failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    print("pip vendor exception guarantees hold")
