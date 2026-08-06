#!/usr/bin/env python3
"""Bind canonical CLI release assets to one selected SemVer manifest."""

from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path


TARGETS = {
    "aarch64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
}
LINE = re.compile(r"^([0-9a-f]{64})  ([^\n]+)\n?$")


def fail(message: str) -> None:
    raise SystemExit(f"verify-cli-release-manifest: {message}")


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    parser.add_argument("version")
    parser.add_argument("assets", nargs="+", type=Path)
    args = parser.parse_args()

    entries: dict[str, str] = {}
    with args.manifest.open(encoding="utf-8") as source:
        for line in source:
            match = LINE.fullmatch(line)
            if not match:
                fail("manifest contains a malformed line")
            checksum, name = match.groups()
            if name in entries:
                fail(f"manifest contains duplicate path: {name}")
            if name.startswith("/") or "\\" in name or ".." in Path(name).parts:
                fail(f"manifest contains unsafe path: {name}")
            entries[name] = checksum

    for asset in args.assets:
        expected = entries.get(asset.name)
        if expected is None:
            fail(f"manifest does not bind {asset.name}")
        if digest(asset) != expected:
            fail(f"digest mismatch for {asset.name}")

    missing = [
        f"{args.version}/{target}/umbra"
        for target in sorted(TARGETS)
        if f"{args.version}/{target}/umbra" not in entries
    ]
    if missing:
        fail(f"manifest is not bound to the selected version: {missing}")


if __name__ == "__main__":
    main()
