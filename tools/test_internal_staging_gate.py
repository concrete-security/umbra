"""Bind the migration staging exception to its operator-approved PR and revision."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
REPO = "concrete-security/umbra"
HEAD = "a" * 40
BRANCH = "codex/concrete-to-umbra-migration"


def run_gate(tmp_path: Path, approval: str, head_repo: str = REPO, head_ref: str = BRANCH, number: str = "18"):
    workflow = yaml.load(
        (ROOT / ".github/workflows/internal-staging-gate.yml").read_text(),
        Loader=yaml.BaseLoader,
    )
    script = workflow["jobs"]["require-verified-staging-lock"]["steps"][0]["run"]
    gh = tmp_path / "gh"
    gh.write_text(
        '#!/bin/sh\n'
        'case "$2" in\n'
        '  */git/ref/heads/dev) printf "%s\\n" "$HEAD_SHA" ;;\n'
        '  */statuses*) printf "%s\\n" "$FIXTURE_STATUS" ;;\n'
        '  *) exit 99 ;;\n'
        'esac\n'
    )
    gh.chmod(0o755)
    env = {
        "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
        "GITHUB_REPOSITORY": REPO,
        "HEAD_REPO": head_repo,
        "HEAD_REF": head_ref,
        "HEAD_SHA": HEAD,
        "DIRECT_PRODUCTION_SHA": approval,
        "PR_NUMBER": number,
        "EXPECTED_ACTOR": "trusted-bot",
        "FIXTURE_STATUS": (
            '{"state":"success","creator":{"login":"trusted-bot"},'
            '"target_url":"https://github.com/concrete-security/umbra-internal/actions/runs/1",'
            '"description":"success lock sha256:aaaaaaaaaaaa"}'
        ),
    }
    return subprocess.run(["bash", "-c", script], env=env, text=True, capture_output=True, timeout=10)


def test_exact_migration_approval_success(tmp_path: Path) -> None:
    """Only the approved same-repository migration PR and revision skip staging."""
    assert run_gate(tmp_path, HEAD).returncode == 0


@pytest.mark.parametrize(
    ("approval", "repo", "branch", "number"),
    [
        pytest.param("", REPO, BRANCH, "18", id="absent-approval"),
        pytest.param("b" * 40, REPO, BRANCH, "18", id="different-revision"),
        pytest.param("not-a-sha", REPO, BRANCH, "18", id="malformed-approval"),
        pytest.param(HEAD, "outsider/umbra", BRANCH, "18", id="fork"),
        pytest.param(HEAD, REPO, BRANCH, "19", id="other-pr"),
        pytest.param(HEAD, REPO, "other-branch", "18", id="other-branch"),
    ],
)
def test_unapproved_direct_promotion_failure(tmp_path: Path, approval: str, repo: str, branch: str, number: str) -> None:
    """Missing, stale, malformed, fork, branch, and PR mismatches retain staging."""
    assert run_gate(tmp_path, approval, repo, branch, number).returncode != 0


def test_normal_verified_staging_success(tmp_path: Path) -> None:
    """A verified dev promotion still uses the original actor and lock checks."""
    assert run_gate(tmp_path, "", head_ref="dev").returncode == 0
