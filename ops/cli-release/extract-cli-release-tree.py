#!/usr/bin/env python3
"""Validate and safely extract a SLSA-verified Umbra CLI release tree."""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import tarfile
from pathlib import Path, PurePosixPath


TARGETS = {
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
}
MAX_MEMBERS = 64
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
SHA256_LINE = re.compile(r"^([0-9a-f]{64})  umbra\n?$")


def fail(message: str) -> None:
    raise SystemExit(f"extract-cli-release-tree: {message}")


def normalized_parts(name: str) -> tuple[str, ...]:
    if not name or name.startswith("/") or "\\" in name:
        fail(f"unsafe archive path: {name!r}")
    path = PurePosixPath(name)
    parts = tuple(part for part in path.parts if part != ".")
    if any(part in {"", ".."} for part in parts):
        fail(f"unsafe archive path: {name!r}")
    return parts


def allowed_member(parts: tuple[str, ...], version: str, is_dir: bool) -> bool:
    channels = {version, "latest"}
    if not parts:
        return is_dir
    if parts[0] not in channels:
        return False
    if is_dir:
        return len(parts) == 1 or (len(parts) == 2 and parts[1] in TARGETS)
    return (len(parts) == 2 and parts[1] in {"version", "concrete-update-version"}) or (
        len(parts) == 3
        and parts[1] in TARGETS
        and parts[2] in {"umbra", "umbra.sha256", "concrete-update-bridge", "concrete-update-bridge.sha256"}
    )


def extract(archive_path: Path, destination: Path, version: str) -> None:
    seen: set[tuple[str, ...]] = set()
    files: dict[tuple[str, ...], tarfile.TarInfo] = {}
    directories: set[tuple[str, ...]] = set()
    total_size = 0

    try:
        archive = tarfile.open(archive_path, mode="r:gz")
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot read release archive: {exc}")

    with archive:
        members = archive.getmembers()
        if len(members) > MAX_MEMBERS:
            fail(f"archive has too many entries ({len(members)} > {MAX_MEMBERS})")
        for member in members:
            parts = normalized_parts(member.name)
            if parts in seen:
                fail(f"archive contains duplicate path: {member.name}")
            seen.add(parts)
            if not (member.isdir() or member.isreg()):
                fail(f"archive contains link or special entry: {member.name}")
            if not allowed_member(parts, version, member.isdir()):
                fail(f"archive path is outside the release allowlist: {member.name}")
            if member.isdir():
                directories.add(parts)
                continue
            if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                fail(f"archive member has unsafe size: {member.name}")
            total_size += member.size
            if total_size > MAX_TOTAL_BYTES:
                fail("archive expands beyond the total size limit")
            files[parts] = member

        required_files = {
            (channel, "version") for channel in (version, "latest")
        } | {
            (channel, target, filename)
            for channel in (version, "latest")
            for target in TARGETS
            for filename in ("umbra", "umbra.sha256")
        }
        bridge_members = {parts for parts in files if parts[-1].startswith("concrete-update-")}
        if bridge_members:
            required_files |= {
                (channel, "concrete-update-version") for channel in (version, "latest")
            } | {
                (channel, target, filename)
                for channel in (version, "latest")
                for target in TARGETS
                for filename in ("concrete-update-bridge", "concrete-update-bridge.sha256")
            }
        missing = required_files - files.keys()
        if missing:
            fail(f"archive is incomplete; missing {sorted('/'.join(path) for path in missing)}")

        destination.mkdir(parents=True, exist_ok=False)
        for parts in sorted(directories, key=lambda value: (len(value), value)):
            if parts:
                destination.joinpath(*parts).mkdir(parents=True, exist_ok=True)
        for parts, member in files.items():
            output = destination.joinpath(*parts)
            output.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                fail(f"cannot read archive member: {member.name}")
            with source, output.open("xb") as target:
                shutil.copyfileobj(source, target)
            output.chmod(0o755 if parts[-1] in {"umbra", "concrete-update-bridge"} else 0o644)

    for channel in (version, "latest"):
        version_path = destination / channel / "version"
        if version_path.read_text(encoding="utf-8") != f"{version}\n":
            fail(f"{channel}/version does not contain exactly {version!r}")
        for target in TARGETS:
            binary = destination / channel / target / "umbra"
            checksum = destination / channel / target / "umbra.sha256"
            match = SHA256_LINE.fullmatch(checksum.read_text(encoding="utf-8"))
            if not match:
                fail(f"malformed checksum: {checksum.relative_to(destination)}")
            if hashlib.sha256(binary.read_bytes()).hexdigest() != match.group(1):
                fail(f"checksum mismatch: {binary.relative_to(destination)}")
        if bridge_members:
            bridge_version = (destination / channel / "concrete-update-version").read_text(encoding="utf-8")
            if not re.fullmatch(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\n", bridge_version):
                fail("invalid Concrete bridge version")
            if bridge_version != (destination / version / "concrete-update-version").read_text(encoding="utf-8"):
                fail("Concrete bridge version differs between channels")
            for target in TARGETS:
                binary = destination / channel / target / "concrete-update-bridge"
                checksum = destination / channel / target / "concrete-update-bridge.sha256"
                match = re.fullmatch(r"([0-9a-f]{64})  concrete-update-bridge\n?", checksum.read_text(encoding="utf-8"))
                if not match or hashlib.sha256(binary.read_bytes()).hexdigest() != match.group(1):
                    fail(f"invalid Concrete bridge checksum for {channel}/{target}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("version")
    args = parser.parse_args()
    extract(args.archive, args.destination, args.version)


if __name__ == "__main__":
    main()
