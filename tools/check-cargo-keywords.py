#!/usr/bin/env python3
"""Validate crates.io keyword constraints for publishable workspace packages."""

from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys


REPO_ROOT = Path(__file__).resolve().parent.parent
MAX_KEYWORDS = 5
MAX_KEYWORD_LENGTH = 20
KEYWORD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_+\-]*$")


def keyword_failures(package: dict[str, object]) -> list[str]:
    """Return crates.io keyword-policy failures for one Cargo package."""
    name = package.get("name")
    package_name = name if isinstance(name, str) else "<unknown>"
    keywords = package.get("keywords")
    if not isinstance(keywords, list):
        return [f"{package_name}: keywords must be a list"]

    failures: list[str] = []
    if len(keywords) > MAX_KEYWORDS:
        failures.append(
            f"{package_name}: has {len(keywords)} keywords; crates.io permits "
            f"at most {MAX_KEYWORDS}"
        )

    for keyword in keywords:
        if not isinstance(keyword, str):
            failures.append(f"{package_name}: keyword values must be strings")
            continue
        if not keyword.isascii():
            failures.append(f"{package_name}: keyword {keyword!r} must be ASCII")
            continue
        if len(keyword) > MAX_KEYWORD_LENGTH:
            failures.append(
                f"{package_name}: keyword {keyword!r} has {len(keyword)} characters; "
                f"crates.io permits at most {MAX_KEYWORD_LENGTH}"
            )
            continue
        if KEYWORD_RE.fullmatch(keyword) is None:
            failures.append(
                f"{package_name}: keyword {keyword!r} must start with an ASCII "
                "alphanumeric and contain only ASCII letters, numbers, _, -, or +"
            )
    return failures


def publishable_keyword_failures(metadata: object) -> list[str]:
    """Return keyword failures for every publishable workspace package."""
    if not isinstance(metadata, dict):
        raise ValueError("cargo metadata output must be an object")
    packages = metadata.get("packages")
    if not isinstance(packages, list):
        raise ValueError("cargo metadata packages must be a list")

    failures: list[str] = []
    for package in packages:
        if not isinstance(package, dict):
            raise ValueError("cargo metadata package entries must be objects")
        if package.get("publish") != []:
            failures.extend(keyword_failures(package))
    return failures


def load_cargo_metadata(root: Path = REPO_ROOT) -> object:
    """Load resolved Cargo metadata from the locked workspace."""
    result = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
        ],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return json.loads(result.stdout)


def main() -> int:
    """Validate publishable workspace packages against crates.io keyword policy."""
    try:
        failures = publishable_keyword_failures(load_cargo_metadata())
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"check-cargo-keywords: {exc}", file=sys.stderr)
        return 1

    for failure in failures:
        print(f"check-cargo-keywords: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
