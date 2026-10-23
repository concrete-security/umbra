#!/usr/bin/env python3
"""Select immutable runner-test images from one source-bound release candidate.

This validates the publisher/private deployment lock format. It does not verify
registry provenance, run containers, or establish hardware attestation. Consumers
must parse the JSON output as data; no shell commands or environment files are
accepted or generated.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any


SOURCE_REPOSITORY = "concrete-security/umbra"
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
MEASUREMENT_RE = re.compile(r"[0-9a-f]{96}")
MAX_LOCK_BYTES = 64 * 1024
COMPONENT_REPOSITORIES = {
    "dev_cvm": "ghcr.io/concrete-security/umbra-dev-cvm",
    "security_cvm": "ghcr.io/concrete-security/umbra-security-cvm",
}


class ReleaseTestImagesError(ValueError):
    """The candidate cannot select images for the requested source commit."""


def _without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ReleaseTestImagesError("lock contains duplicate JSON keys")
        value[key] = item
    return value


def _invalid_constant(_value: str) -> None:
    raise ReleaseTestImagesError("lock contains a non-JSON number")


def _exact_object(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ReleaseTestImagesError(f"{context} has an invalid object shape")
    return value


def _digest_ref(value: Any, repository: str, context: str) -> str:
    pattern = re.escape(repository) + r"@sha256:[0-9a-f]{64}"
    if not isinstance(value, str) or re.fullmatch(pattern, value) is None:
        raise ReleaseTestImagesError(f"{context} must name its canonical repository by digest")
    return value


def select_images(raw_lock: bytes, expected_commit: str) -> dict[str, str]:
    """Validate one raw lock and return only allowlisted image/source identifiers.

    Null guest measurements are valid publisher output. When measurements exist,
    both components must name the same shared guest MRTD. No measurement in this
    format establishes that a runner can verify a live TEE.
    """
    if not isinstance(expected_commit, str) or COMMIT_RE.fullmatch(expected_commit) is None:
        raise ReleaseTestImagesError("expected commit must be 40 lowercase hexadecimal characters")
    if not isinstance(raw_lock, bytes) or not raw_lock or len(raw_lock) > MAX_LOCK_BYTES:
        raise ReleaseTestImagesError("lock must contain between 1 and 65536 bytes")
    try:
        decoded = json.loads(
            raw_lock.decode("utf-8"),
            object_pairs_hook=_without_duplicates,
            parse_constant=_invalid_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ReleaseTestImagesError("lock is not valid UTF-8 JSON") from None

    lock = _exact_object(decoded, {"schema_version", "source", "artifacts"}, "lock")
    if type(lock["schema_version"]) is not int or lock["schema_version"] != 1:
        raise ReleaseTestImagesError("lock schema_version must be 1")
    source = _exact_object(lock["source"], {"repository", "commit"}, "source")
    if source["repository"] != SOURCE_REPOSITORY:
        raise ReleaseTestImagesError("lock source repository is not canonical")
    if source["commit"] != expected_commit:
        raise ReleaseTestImagesError("lock source commit does not match the requested commit")

    artifacts = _exact_object(lock["artifacts"], set(COMPONENT_REPOSITORIES), "artifacts")
    images: dict[str, str] = {}
    measurements: list[str | None] = []
    for component, repository in COMPONENT_REPOSITORIES.items():
        artifact = _exact_object(
            artifacts[component],
            {"image", "measurement", "source_commit", "provenance"},
            component,
        )
        images[component] = _digest_ref(artifact["image"], repository, f"{component}.image")
        _digest_ref(artifact["provenance"], repository, f"{component}.provenance")
        if artifact["source_commit"] != expected_commit:
            raise ReleaseTestImagesError(f"{component}.source_commit does not match the requested commit")
        measurement = artifact["measurement"]
        if measurement is not None and (
            not isinstance(measurement, str) or MEASUREMENT_RE.fullmatch(measurement) is None
        ):
            raise ReleaseTestImagesError(f"{component}.measurement must be null or 96 lowercase hexadecimal characters")
        measurements.append(measurement)
    if measurements[0] != measurements[1]:
        raise ReleaseTestImagesError("component guest measurements must both be null or equal")

    return {
        "UMBRA_TEST_DEV_IMAGE": images["dev_cvm"],
        "UMBRA_TEST_SECURITY_IMAGE": images["security_cvm"],
        "source_commit": expected_commit,
        "lock_sha256": hashlib.sha256(raw_lock).hexdigest(),
    }


def main() -> int:
    """Print safe JSON identifiers, leaving stdout empty on every failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    args = parser.parse_args()
    try:
        with args.lock.open("rb") as handle:
            raw_lock = handle.read(MAX_LOCK_BYTES + 1)
        result = select_images(raw_lock, args.expected_commit)
    except OSError:
        print("select-release-test-images: cannot read lock file", file=sys.stderr)
        return 1
    except ReleaseTestImagesError as exc:
        print(f"select-release-test-images: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
