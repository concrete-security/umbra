#!/usr/bin/env python3
"""Publish a legacy channel from an already SLSA-verified, extracted release tree."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import os
import re
import shutil
import tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("release_tree", Path(__file__).with_name("extract-cli-release-tree.py"))
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load release-tree contract")
release_tree = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release_tree)
TARGETS = release_tree.TARGETS


def prepare(source: Path, release_directory: Path, version: str) -> None:
    metadata = source / version / "concrete-update-version"
    if not metadata.is_file():
        return
    bridge_version = metadata.read_text().strip()
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", bridge_version):
        raise ValueError("invalid Concrete bridge version")
    channel = release_directory / "concrete-updates"
    channel.mkdir(parents=True, exist_ok=True)
    if channel.is_symlink():
        raise ValueError("Concrete channel must be a real directory")
    channel.chmod(0o755)
    descriptor = os.open(channel / ".publish.lock", os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with tempfile.TemporaryDirectory(prefix=".stage-", dir=channel) as stage_name:
            stage = Path(stage_name)
            candidate = stage / bridge_version
            candidate.mkdir()
            candidate.chmod(0o755)
            (candidate / "version").write_text(bridge_version + "\n")
            (candidate / "version").chmod(0o644)
            for target in sorted(TARGETS):
                original = source / version / target / "concrete-update-bridge"
                checksum = original.with_suffix(".sha256")
                digest = hashlib.sha256(original.read_bytes()).hexdigest()
                if checksum.read_text() != digest + "  concrete-update-bridge\n":
                    raise ValueError("Concrete bridge checksum mismatch")
                folder = candidate / target
                folder.mkdir()
                folder.chmod(0o755)
                shutil.copyfile(original, folder / "concrete")
                (folder / "concrete").chmod(0o755)
                (folder / "concrete.sha256").write_text(digest + "  concrete\n")
                (folder / "concrete.sha256").chmod(0o644)
            destination = channel / bridge_version
            if destination.exists() or destination.is_symlink():
                if destination.is_symlink() or not destination.is_dir():
                    raise ValueError("immutable Concrete release must be a real directory")
                existing = {file.relative_to(destination): file for file in destination.rglob("*") if file.is_file()}
                expected = {file.relative_to(candidate): file for file in candidate.rglob("*") if file.is_file()}
                if existing.keys() != expected.keys() or any(
                    existing[name].is_symlink() or existing[name].read_bytes() != expected[name].read_bytes()
                    for name in expected
                ):
                    raise ValueError("immutable Concrete release already exists with different contents")
            else:
                os.rename(candidate, destination)
            latest = channel / "latest"
            if latest.exists() and not latest.is_symlink():
                raise ValueError("Concrete latest must be an operator-managed symlink")
            if latest.is_symlink():
                previous = os.readlink(latest)
                if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", previous) and tuple(map(int, previous.split('.'))) > tuple(map(int, bridge_version.split('.'))):
                    raise ValueError("refusing to downgrade the Concrete update channel")
            os.symlink(bridge_version, stage / "latest")
            os.replace(stage / "latest", latest)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("verified_tree", type=Path)
    parser.add_argument("release_directory", type=Path)
    parser.add_argument("version")
    args = parser.parse_args()
    prepare(args.verified_tree, args.release_directory, args.version)


if __name__ == "__main__":
    main()
