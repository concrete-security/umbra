"""Exercise release-image artifact selection without GitHub or registry access."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/verify-release-images.yml"
SOURCE_SHA = "a" * 40
DEV_IMAGE = "ghcr.io/concrete-security/umbra-dev-cvm@sha256:" + "b" * 64
SECURITY_IMAGE = "ghcr.io/concrete-security/umbra-security-cvm@sha256:" + "c" * 64


def _candidate() -> dict[str, Any]:
    artifacts = {}
    for component, image in (("dev_cvm", DEV_IMAGE), ("security_cvm", SECURITY_IMAGE)):
        artifacts[component] = {
            "image": image,
            "measurement": None,
            "source_commit": SOURCE_SHA,
            "provenance": image.split("@", 1)[0] + "@sha256:" + "d" * 64,
        }
    return {
        "schema_version": 1,
        "source": {"repository": "concrete-security/umbra", "commit": SOURCE_SHA},
        "artifacts": artifacts,
    }


def _run_selection(
    tmp_path: Path,
    *,
    env_updates: dict[str, str] | None = None,
    run_updates: dict[str, Any] | None = None,
    lock_change: tuple[tuple[str, ...], Any] | None = None,
) -> tuple[subprocess.CompletedProcess[str], Path, str]:
    workflow = yaml.load(WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    script = next(
        step["run"]
        for step in workflow["jobs"]["select"]["steps"]
        if step.get("id") == "images"
    )
    run = {
        "repository": {"full_name": "concrete-security/umbra"},
        "head_repository": {"full_name": "concrete-security/umbra"},
        "path": ".github/workflows/publish-cvm-images.yml",
        "event": "push",
        "head_branch": "dev",
        "status": "completed",
        "conclusion": "success",
        "head_sha": SOURCE_SHA,
    }
    run.update(run_updates or {})
    run_path = tmp_path / "run.json"
    run_path.write_text(json.dumps(run), encoding="utf-8")
    lock = _candidate()
    if lock_change is not None:
        path, value = lock_change
        destination = lock
        for key in path[:-1]:
            destination = destination[key]
        destination[path[-1]] = value
    raw_lock = json.dumps(lock).encode()
    lock_path = tmp_path / "candidate.json"
    lock_path.write_bytes(raw_lock)
    lock_hash = hashlib.sha256(raw_lock).hexdigest()
    binaries = tmp_path / "bin"
    binaries.mkdir()
    gh = binaries / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        "import os, pathlib, shutil, sys\n"
        "args = sys.argv[1:]\n"
        "if args[0] == 'api':\n"
        "    print(pathlib.Path(os.environ['MOCK_RUN']).read_text())\n"
        "elif args[:2] == ['run', 'download']:\n"
        "    directory = pathlib.Path(args[args.index('--dir') + 1])\n"
        "    directory.mkdir(parents=True)\n"
        "    shutil.copyfile(os.environ['MOCK_LOCK'], directory / 'deployment-lock.candidate.json')\n"
        "else:\n"
        "    raise SystemExit('unexpected gh command')\n",
        encoding="utf-8",
    )
    gh.chmod(0o700)
    output_path = tmp_path / "output"
    env = {
        **os.environ,
        "PATH": str(binaries) + os.pathsep + os.environ["PATH"],
        "GH_TOKEN": "synthetic-read-token",
        "INPUT_SOURCE_SHA": "",
        "INPUT_LOCK_SHA256": "",
        "PUBLICATION_RUN_ID": "123",
        "SELECTED_DEV_IMAGE": DEV_IMAGE,
        "SELECTED_SECURITY_IMAGE": SECURITY_IMAGE,
        "GITHUB_REF": "refs/heads/dev",
        "GITHUB_REPOSITORY": "concrete-security/umbra",
        "MOCK_RUN": str(run_path),
        "MOCK_LOCK": str(lock_path),
        "RUNNER_TEMP": str(tmp_path),
        "GITHUB_OUTPUT": str(output_path),
        **(env_updates or {}),
    }
    if env["INPUT_SOURCE_SHA"] and "INPUT_LOCK_SHA256" not in (env_updates or {}):
        env["INPUT_LOCK_SHA256"] = lock_hash
    result = subprocess.run(
        ["bash", "-c", script], cwd=ROOT, env=env,
        text=True, capture_output=True, timeout=20, check=False,
    )
    return result, output_path, lock_hash


@pytest.mark.parametrize(
    "env_updates,run_updates",
    [
        pytest.param({}, {}, id="manual-dev-push"),
        pytest.param(
            {"GITHUB_REF": "refs/heads/main"},
            {"head_branch": "main", "event": "workflow_dispatch"},
            id="manual-main-dispatch",
        ),
        pytest.param(
            {"INPUT_SOURCE_SHA": SOURCE_SHA, "PUBLICATION_RUN_ID": ""},
            {},
            id="publisher-output",
        ),
    ],
)
def test_release_image_selection_exact_candidate_success(
    tmp_path: Path, env_updates: dict[str, str], run_updates: dict[str, Any],
) -> None:
    """Accepted selections preserve both runtime refs, source and raw candidate hash."""
    result, output_path, lock_hash = _run_selection(
        tmp_path, env_updates=env_updates, run_updates=run_updates,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert output_path.read_text(encoding="utf-8").splitlines() == [
        f"source_sha={SOURCE_SHA}", f"dev_image={DEV_IMAGE}",
        f"security_image={SECURITY_IMAGE}", f"lock_sha256={lock_hash}",
    ]


@pytest.mark.parametrize(
    "env_updates,run_updates,lock_change",
    [
        pytest.param({}, {"repository": {"full_name": "outsider/fork"}}, None, id="fork-repository"),
        pytest.param({}, {"head_repository": {"full_name": "outsider/fork"}}, None, id="fork-head-repository"),
        pytest.param({}, {"event": "pull_request"}, None, id="pull-request-event"),
        pytest.param({}, {"conclusion": "failure"}, None, id="failed-run"),
        pytest.param({}, {"status": "in_progress"}, None, id="incomplete-run"),
        pytest.param({}, {"path": ".github/workflows/other.yml"}, None, id="other-workflow"),
        pytest.param({}, {"head_branch": "feature"}, None, id="publication-feature-branch"),
        pytest.param({}, {"head_sha": SOURCE_SHA[:12]}, None, id="short-publication-source"),
        pytest.param({"GITHUB_REF": "refs/heads/feature"}, {}, None, id="manual-feature-branch"),
        pytest.param({"PUBLICATION_RUN_ID": "../123"}, {}, None, id="invalid-run-id"),
        pytest.param({"SELECTED_DEV_IMAGE": DEV_IMAGE[:-1] + "e"}, {}, None, id="selected-dev-mismatch"),
        pytest.param({"SELECTED_SECURITY_IMAGE": SECURITY_IMAGE[:-1] + "e"}, {}, None, id="selected-security-mismatch"),
        pytest.param({"SELECTED_DEV_IMAGE": "ghcr.io/concrete-security/umbra-dev-cvm:latest"}, {}, None, id="mutable-ref"),
        pytest.param({}, {}, (("source", "commit"), "e" * 40), id="candidate-source-mismatch"),
        pytest.param({}, {}, (("artifacts", "dev_cvm", "image"), DEV_IMAGE[:-1] + "e"), id="candidate-image-mismatch"),
        pytest.param({"INPUT_SOURCE_SHA": SOURCE_SHA[:12], "PUBLICATION_RUN_ID": ""}, {}, None, id="short-publisher-source"),
        pytest.param({"INPUT_SOURCE_SHA": SOURCE_SHA, "INPUT_LOCK_SHA256": "", "PUBLICATION_RUN_ID": ""}, {}, None, id="missing-publisher-hash"),
        pytest.param({"INPUT_SOURCE_SHA": SOURCE_SHA, "INPUT_LOCK_SHA256": "d" * 12, "PUBLICATION_RUN_ID": ""}, {}, None, id="malformed-publisher-hash"),
    ],
)
def test_release_image_selection_untrusted_candidate_failure(
    tmp_path: Path,
    env_updates: dict[str, str],
    run_updates: dict[str, Any],
    lock_change: tuple[tuple[str, ...], Any] | None,
) -> None:
    """Untrusted runs or mismatched candidate identities emit no selected image outputs."""
    result, output_path, _ = _run_selection(
        tmp_path, env_updates=env_updates, run_updates=run_updates, lock_change=lock_change,
    )
    assert result.returncode != 0, result.stdout + result.stderr
    assert not output_path.exists() or not output_path.read_text(encoding="utf-8")
