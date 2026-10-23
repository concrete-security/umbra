"""The runner qualifies selected container bytes without rebuilding or cloud access."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "ops/verify/test-release-images.py"
SPEC = importlib.util.spec_from_file_location("release_image_runner", SCRIPT)
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)
COMMIT = "a" * 40
DEV = "ghcr.io/concrete-security/umbra-dev-cvm@sha256:" + "b" * 64
SECURITY = "ghcr.io/concrete-security/umbra-security-cvm@sha256:" + "c" * 64
ENV = {"UMBRA_TEST_DEV_IMAGE": DEV, "UMBRA_TEST_SECURITY_IMAGE": SECURITY, "UMBRA_TEST_SOURCE_SHA": COMMIT}


def inspection(image: str) -> list[dict]:
    return [{
        "Os": "linux", "Architecture": "amd64", "Id": "sha256:" + "d" * 64, "RepoDigests": [image],
        "Config": {"Labels": {"org.opencontainers.image.source": runner.SOURCE_URL,
                               "org.opencontainers.image.revision": COMMIT}},
    }]


@pytest.mark.parametrize("field,value", [
    ("UMBRA_TEST_DEV_IMAGE", "ghcr.io/example/dev:latest"),
    ("UMBRA_TEST_SECURITY_IMAGE", "ghcr.io/example/security:release"),
    ("UMBRA_TEST_SOURCE_SHA", "main"),
    ("UMBRA_TEST_LOCK_SHA256", "invalid"),
])
def test_mutable_or_unbound_selection_failure(field, value):
    """Mutable image refs and incomplete commit/digest identities are rejected."""
    with pytest.raises(runner.VerificationError):
        runner.selected_images({**ENV, field: value})


@pytest.mark.parametrize("change", ["platform", "digest", "repository", "revision", "missing-labels", "config-only"])
def test_pulled_image_identity_mismatch_failure(change):
    """Docker must resolve the exact runtime digest and matching immutable source."""
    data = inspection(DEV)
    if change == "platform":
        data[0]["Architecture"] = "arm64"
    elif change == "digest":
        data[0]["RepoDigests"] = [SECURITY]
    elif change == "repository":
        data[0]["Config"]["Labels"]["org.opencontainers.image.source"] = "https://example.test/fork"
    elif change == "revision":
        data[0]["Config"]["Labels"]["org.opencontainers.image.revision"] = "e" * 40
    elif change == "missing-labels":
        data[0]["Config"]["Labels"] = None
    else:
        data[0]["RepoDigests"] = None
    with pytest.raises(runner.VerificationError):
        runner.validate_image_inspection(DEV, COMMIT, json.dumps(data))


def test_release_checks_preserve_selected_images_without_building_success(monkeypatch):
    """Only pulled digests reach runtime tests, with no inherited deployment state."""
    calls = []
    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    def command(args, env, **kwargs):
        calls.append((args, dict(env)))
        if args[:3] == ["docker", "context", "inspect"]:
            return "unix:///var/run/docker.sock\n"
        if args[:2] == ["docker", "info"]:
            return "linux\n"
        if args[:3] == ["docker", "image", "inspect"]:
            return json.dumps(inspection(args[-1]))
        return ""
    monkeypatch.setattr(runner, "command", command)
    result = runner.verify({**ENV, "PHALA_API_TOKEN": "private", "CONSOLE_URL": "https://production.example.test",
                            "PYTEST_ADDOPTS": "--ignore=everything", "UMBRA_VERIFY_IMAGE_REPRODUCIBILITY": "1"})
    assert result["status"] == "passed"
    assert result["source_commit"] == COMMIT
    assert result["images"]["dev_cvm"]["reference"] == DEV
    assert "TDX hardware attestation" in result["not_exercised"]
    assert not any("build" in args or "buildx" in args for args, _ in calls)
    for _, env in calls:
        assert not {"PHALA_API_TOKEN", "CONSOLE_URL", "PYTEST_ADDOPTS", "UMBRA_VERIFY_IMAGE_REPRODUCIBILITY"} & env.keys()
    test_env = calls[-1][1]
    assert test_env["DEV_CVM_IMAGE_SMOKE_IMAGE"] == test_env["DEV_CVM_COMPOSE_SMOKE_IMAGE"] == DEV
    assert test_env["UMBRA_TEST_SECURITY_IMAGE"] == SECURITY
    assert test_env["UMBRA_E2E_REQUIRED"] == "1"


@pytest.mark.parametrize("endpoint", ["ssh://operator@staging", "tcp://staging.example.test:2376"])
def test_remote_docker_context_creates_no_resources_failure(monkeypatch, endpoint):
    """Runner-only checks never provision containers on a remote Docker host."""
    calls = []
    monkeypatch.setattr(runner.platform, "system", lambda: "Linux")
    def command(args, env, **kwargs):
        calls.append(args)
        return endpoint
    monkeypatch.setattr(runner, "command", command)
    with pytest.raises(runner.VerificationError, match="refuse remote"):
        runner.verify(ENV)
    assert len(calls) == 1 and calls[0][:3] == ["docker", "context", "inspect"]


def test_failed_rerun_removes_old_success_receipt_failure(tmp_path, monkeypatch):
    """Failure cannot leave a stale success artifact for a later consumer."""
    receipt = tmp_path / "receipt.json"
    receipt.write_text('{"status":"passed"}')
    monkeypatch.setenv("UMBRA_TEST_RECEIPT", str(receipt))
    def fail(_):
        raise runner.VerificationError("test failure")
    monkeypatch.setattr(runner, "verify", fail)
    assert runner.main() == 1
    assert not receipt.exists()


@pytest.mark.parametrize("diagnostics", [False, True], ids=["private-docker-step", "controlled-runtime-step"])
def test_failed_subprocess_diagnostic_visibility_success(capsys, diagnostics):
    """Only runtime failures expose child output, with fixture credentials redacted."""
    values = (
        "e2e-proxy-bearer", "e2e-ingest-bearer", "e2e-export-bearer", "e2e-injected-credential",
        "E2E_DLP_SENTINEL_ABC123", "e2e-query-must-not-be-logged", "compose-smoke-token",
        "compose-smoke-dev-control-token", "generated-fixture-control-value",
    )
    args = [sys.executable, "-c", (
        "import os, sys\n"
        "print('fixture stdout: ' + os.environ['FIXTURE_VALUES'])\n"
        "print('fixture stderr: policy was not installed', file=sys.stderr)\n"
        "print('Authorization: Bearer ' + os.environ['FIXTURE_CONTROL'], file=sys.stderr)\n"
        "raise SystemExit(7)\n"
    )]
    with pytest.raises(runner.VerificationError):
        runner.command(args, {"FIXTURE_VALUES": " ".join(values[:-1]), "FIXTURE_CONTROL": values[-1]},
                       **({"diagnostics": True} if diagnostics else {}))
    captured = capsys.readouterr()
    assert captured.out == ""
    assert not any(value in captured.err for value in values)
    if diagnostics:
        assert "fixture stdout:" in captured.err
        assert "fixture stderr: policy was not installed" in captured.err
    else:
        assert captured.err == ""


def test_failed_subprocess_diagnostic_bound_success(capsys):
    """A large failure keeps its final useful line within a bounded diagnostic."""
    args = [sys.executable, "-c", (
        "import sys\n"
        "print('x' * 100000)\n"
        "print('final assertion: expected 403, received 200', file=sys.stderr)\n"
        "raise SystemExit(1)\n"
    )]
    with pytest.raises(runner.VerificationError):
        runner.command(args, {}, diagnostics=True)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "final assertion: expected 403, received 200" in captured.err
    assert len(captured.err) < 10000


def test_timed_out_subprocess_diagnostic_visibility_success(capsys):
    """A runtime timeout retains flushed failure context without bearer material."""
    args = [sys.executable, "-c", (
        "import sys, time\n"
        "print('waiting for Security CVM listener', file=sys.stderr, flush=True)\n"
        "print('Authorization: Bearer generated-fixture-value', file=sys.stderr, flush=True)\n"
        "time.sleep(10)\n"
    )]
    with pytest.raises(runner.VerificationError, match="could not complete"):
        runner.command(args, {}, timeout=1, diagnostics=True)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "waiting for Security CVM listener" in captured.err
    assert "generated-fixture-value" not in captured.err
