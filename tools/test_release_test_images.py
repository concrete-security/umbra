"""Release-image selection rejects source confusion and mutable artifacts."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest


SELECTOR_PATH = Path(__file__).resolve().parents[1] / "ops/verify/select-release-test-images.py"
SPEC = importlib.util.spec_from_file_location("select_release_test_images", SELECTOR_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load release-image selector")
selector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(selector)
COMMIT = "a" * 40
DEV_REPOSITORY = "ghcr.io/concrete-security/umbra-dev-cvm"
SECURITY_REPOSITORY = "ghcr.io/concrete-security/umbra-security-cvm"


@pytest.fixture
def candidate() -> dict[str, Any]:
    return {
        "schema_version": 1,
        "source": {"repository": "concrete-security/umbra", "commit": COMMIT},
        "artifacts": {
            "dev_cvm": {
                "image": DEV_REPOSITORY + "@sha256:" + "b" * 64,
                "measurement": None,
                "source_commit": COMMIT,
                "provenance": DEV_REPOSITORY + "@sha256:" + "c" * 64,
            },
            "security_cvm": {
                "image": SECURITY_REPOSITORY + "@sha256:" + "d" * 64,
                "measurement": None,
                "source_commit": COMMIT,
                "provenance": SECURITY_REPOSITORY + "@sha256:" + "e" * 64,
            },
        },
    }


@pytest.mark.parametrize("measurement", [None, "1" * 96], ids=["publisher-candidate", "private-lock"])
def test_select_release_images_source_bound_success(candidate: dict[str, Any], measurement: str | None) -> None:
    """A source-bound candidate or reviewed lock selects its exact runtime digests."""
    for artifact in candidate["artifacts"].values():
        artifact["measurement"] = measurement
    raw = json.dumps(candidate, indent=2).encode()
    assert selector.select_images(raw, COMMIT) == {
        "UMBRA_TEST_DEV_IMAGE": candidate["artifacts"]["dev_cvm"]["image"],
        "UMBRA_TEST_SECURITY_IMAGE": candidate["artifacts"]["security_cvm"]["image"],
        "source_commit": COMMIT,
        "lock_sha256": hashlib.sha256(raw).hexdigest(),
    }


def test_select_release_images_raw_lock_binding_success(candidate: dict[str, Any]) -> None:
    """Evidence identifies the actual lock bytes rather than a reserialized object."""
    raw = json.dumps(candidate).encode()
    different_bytes = b" \n" + raw + b"\n"
    assert selector.select_images(raw, COMMIT)["lock_sha256"] != selector.select_images(
        different_bytes, COMMIT
    )["lock_sha256"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        pytest.param("image", None, id="missing-image"),
        pytest.param("image", DEV_REPOSITORY + ":latest", id="mutable-tag"),
        pytest.param("image", DEV_REPOSITORY + ":v1@sha256:" + "b" * 64, id="tag-and-digest"),
        pytest.param("image", DEV_REPOSITORY + "@sha256:" + "b" * 63, id="short-digest"),
        pytest.param("image", DEV_REPOSITORY + "@sha256:" + "B" * 64, id="uppercase-digest"),
        pytest.param("image", "ghcr.io/other/umbra-dev-cvm@sha256:" + "b" * 64, id="foreign-image"),
        pytest.param("image", SECURITY_REPOSITORY + "@sha256:" + "b" * 64, id="swapped-component"),
        pytest.param("image", DEV_REPOSITORY + "@sha256:" + "b" * 64 + "\n", id="newline-image"),
        pytest.param("image", DEV_REPOSITORY + "@sha256:" + "b" * 64 + "$(id)", id="shell-suffix"),
        pytest.param("provenance", None, id="missing-provenance"),
        pytest.param("provenance", DEV_REPOSITORY + ":proof", id="mutable-provenance"),
        pytest.param("provenance", SECURITY_REPOSITORY + "@sha256:" + "c" * 64, id="foreign-provenance"),
        pytest.param("source_commit", "f" * 40, id="artifact-source-mismatch"),
        pytest.param("source_commit", None, id="missing-artifact-source"),
        pytest.param("measurement", "1" * 95, id="short-measurement"),
        pytest.param("measurement", "A" * 96, id="uppercase-measurement"),
        pytest.param("measurement", 1, id="numeric-measurement"),
    ],
)
def test_select_release_images_artifact_contract_failure(
    candidate: dict[str, Any], field: str, value: Any
) -> None:
    """An incomplete or changed artifact cannot become a runner image reference."""
    candidate["artifacts"]["dev_cvm"][field] = value
    with pytest.raises(selector.ReleaseTestImagesError):
        selector.select_images(json.dumps(candidate).encode(), COMMIT)


@pytest.mark.parametrize(
    ("dev_measurement", "security_measurement"),
    [
        pytest.param("1" * 96, None, id="partial-guest-baseline"),
        pytest.param("1" * 96, "2" * 96, id="different-guest-baselines"),
    ],
)
def test_select_release_images_shared_guest_pin_failure(
    candidate: dict[str, Any], dev_measurement: str, security_measurement: str | None
) -> None:
    """Guest pins, when supplied, must describe one shared dstack guest baseline."""
    candidate["artifacts"]["dev_cvm"]["measurement"] = dev_measurement
    candidate["artifacts"]["security_cvm"]["measurement"] = security_measurement
    with pytest.raises(selector.ReleaseTestImagesError, match="guest measurements"):
        selector.select_images(json.dumps(candidate).encode(), COMMIT)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        pytest.param(("schema_version",), 2, id="unsupported-schema"),
        pytest.param(("schema_version",), True, id="boolean-schema"),
        pytest.param(("source", "repository"), "other/umbra", id="foreign-source"),
        pytest.param(("source", "commit"), "f" * 40, id="source-mismatch"),
        pytest.param(("source", "commit"), None, id="missing-source"),
        pytest.param(("extra",), "unexpected", id="unknown-top-level-field"),
        pytest.param(("source", "extra"), "unexpected", id="unknown-source-field"),
        pytest.param(("artifacts", "extra"), {}, id="extra-component"),
        pytest.param(("artifacts", "dev_cvm", "extra"), "unexpected", id="unknown-artifact-field"),
        pytest.param(("artifacts", "security_cvm"), None, id="missing-component"),
    ],
)
def test_select_release_images_lock_contract_failure(
    candidate: dict[str, Any], path: tuple[str, ...], value: Any
) -> None:
    """Only the complete known lock schema can select a canonical source release."""
    target = candidate
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises(selector.ReleaseTestImagesError):
        selector.select_images(json.dumps(candidate).encode(), COMMIT)


@pytest.mark.parametrize(
    "expected_commit",
    ["a" * 39, "A" * 40, "a" * 40 + "\n", "refs/heads/dev"],
    ids=["abbreviated", "uppercase", "newline", "branch-name"],
)
def test_select_release_images_expected_commit_failure(candidate: dict[str, Any], expected_commit: str) -> None:
    """Source authority must be one explicit lowercase full commit hash."""
    with pytest.raises(selector.ReleaseTestImagesError, match="expected commit"):
        selector.select_images(json.dumps(candidate).encode(), expected_commit)


@pytest.mark.parametrize(
    "raw",
    [
        pytest.param(b'{"source":{},"source":{}}', id="duplicate-top-level"),
        pytest.param(b'{"source":{"commit":"a","commit":"b"}}', id="duplicate-nested"),
        pytest.param(b'{"schema_version":NaN}', id="non-json-number"),
        pytest.param(b'{"schema_version":Infinity}', id="infinity"),
        pytest.param(b'\xff', id="invalid-utf8"),
        pytest.param(b'{', id="invalid-json"),
        pytest.param(b'[]', id="array-root"),
        pytest.param(b'', id="empty-lock"),
        pytest.param(b' ' * (selector.MAX_LOCK_BYTES + 1), id="oversized-lock"),
    ],
)
def test_select_release_images_raw_json_failure(raw: bytes) -> None:
    """Ambiguous, invalid, or oversized JSON fails before producing identifiers."""
    with pytest.raises(selector.ReleaseTestImagesError):
        selector.select_images(raw, COMMIT)


def test_release_image_selector_cli_success(tmp_path: Path, candidate: dict[str, Any]) -> None:
    """The standalone selector emits only JSON data usable by workflow parsers."""
    lock = tmp_path / "candidate.json"
    raw = json.dumps(candidate).encode()
    lock.write_bytes(raw)
    result = subprocess.run(
        [sys.executable, str(SELECTOR_PATH), "--lock", str(lock), "--expected-commit", COMMIT],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0 and not result.stderr and json.loads(result.stdout) == selector.select_images(raw, COMMIT)


def test_release_image_selector_cli_secret_output_failure(tmp_path: Path, candidate: dict[str, Any]) -> None:
    """Malformed input cannot leak arbitrary lock values into retained workflow logs."""
    sentinel = "PRIVATE_SENTINEL_DO_NOT_LOG"
    candidate["artifacts"]["dev_cvm"]["image"] = sentinel
    lock = tmp_path / "candidate.json"
    lock.write_text(json.dumps(candidate), encoding="utf-8")
    result = subprocess.run(
        [sys.executable, str(SELECTOR_PATH), "--lock", str(lock), "--expected-commit", COMMIT],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0 and result.stdout == "" and sentinel not in result.stderr


def test_release_image_selector_cli_missing_file_failure(tmp_path: Path) -> None:
    """Unreadable lock paths fail without printing identifiers or file contents."""
    result = subprocess.run(
        [sys.executable, str(SELECTOR_PATH), "--lock", str(tmp_path / "missing"), "--expected-commit", COMMIT],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0 and result.stdout == "" and "cannot read lock file" in result.stderr
