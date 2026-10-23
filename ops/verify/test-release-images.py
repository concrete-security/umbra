#!/usr/bin/env python3
"""Exercise immutable published CVM images entirely on a Linux Docker runner."""

from __future__ import annotations

import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parents[2]
SOURCE_URL = "https://github.com/concrete-security/umbra"
IMAGE_RE = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[0-9]+)?/(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*@sha256:[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
DIGEST_RE = re.compile(r"[0-9a-f]{64}")
RUNTIME_DIAGNOSTIC_LIMIT = 8192


class VerificationError(RuntimeError):
    pass


def selected_images(env: dict[str, str]) -> tuple[str, str, str]:
    refs = []
    for name in ("UMBRA_TEST_DEV_IMAGE", "UMBRA_TEST_SECURITY_IMAGE"):
        value = env.get(name, "")
        if not IMAGE_RE.fullmatch(value):
            raise VerificationError(f"{name} must be a repository@sha256 runtime-manifest reference")
        refs.append(value)
    commit = env.get("UMBRA_TEST_SOURCE_SHA", "")
    if not COMMIT_RE.fullmatch(commit):
        raise VerificationError("UMBRA_TEST_SOURCE_SHA must be a full lowercase source commit")
    lock_hash = env.get("UMBRA_TEST_LOCK_SHA256")
    if lock_hash is not None and not DIGEST_RE.fullmatch(lock_hash):
        raise VerificationError("UMBRA_TEST_LOCK_SHA256 must be the raw candidate's SHA-256")
    return refs[0], refs[1], commit


def runner_env(env: dict[str, str]) -> dict[str, str]:
    """Keep Docker pull settings, not cloud credentials or application settings."""
    allowed = (
        "PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "UV_CACHE_DIR", "UV_PYTHON",
        "DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT", "XDG_RUNTIME_DIR",
    )
    return {name: env[name] for name in allowed if name in env}


def runtime_diagnostics(stdout: str | bytes | None, stderr: str | bytes | None) -> None:
    """Expose only controlled test output, after redacting its synthetic material."""
    output = "\n".join(
        part.decode("utf-8", errors="replace") if isinstance(part, bytes) else part
        for part in (stdout, stderr) if part
    )
    # Match the fixtures' own sanitization, including arbitrary bearer values
    # from generated fixture-control credentials, before taking the output tail.
    output = re.sub(r"(?i)(\bBearer[ \t]+)[^\s'\"\\,;}\]]+", r"\1[fixture value redacted]", output)
    for value in (
        "e2e-proxy-bearer", "e2e-ingest-bearer", "e2e-export-bearer", "e2e-injected-credential",
        "E2E_DLP_SENTINEL_ABC123", "e2e-query-must-not-be-logged", "compose-smoke-token",
        "compose-smoke-dev-control-token",
    ):
        output = output.replace(value, "[fixture value redacted]")
    if output.strip():
        print("release-images: runtime diagnostics:\n" + output[-RUNTIME_DIAGNOSTIC_LIMIT:],
              file=sys.stderr, flush=True)


def command(args: list[str], env: dict[str, str], *, timeout: int = 600, diagnostics: bool = False) -> str:
    try:
        result = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        if diagnostics:
            runtime_diagnostics(exc.stdout, exc.stderr)
        raise VerificationError(f"{Path(args[0]).name} could not complete") from exc
    except OSError as exc:
        raise VerificationError(f"{Path(args[0]).name} could not complete") from exc
    if result.returncode != 0:
        # Pulls and metadata calls retain private daemon/registry diagnostics.
        # Only synthetic smoke/pytest steps opt into the bounded failure output.
        if diagnostics:
            runtime_diagnostics(result.stdout, result.stderr)
        raise VerificationError(f"{Path(args[0]).name} failed during release-image verification")
    return result.stdout


def validate_image_inspection(image: str, commit: str, output: str) -> dict[str, str]:
    try:
        entries = json.loads(output)
        if not isinstance(entries, list) or len(entries) != 1:
            raise ValueError
        info = entries[0]
        labels = info["Config"]["Labels"]
        if info["Os"] != "linux" or info["Architecture"] != "amd64":
            raise VerificationError("release image must be linux/amd64")
        if image not in info["RepoDigests"]:
            raise VerificationError("pulled image does not retain the selected runtime digest")
        if labels.get("org.opencontainers.image.source") != SOURCE_URL:
            raise VerificationError("release image has the wrong source repository label")
        if labels.get("org.opencontainers.image.revision") != commit:
            raise VerificationError("release image has the wrong source commit label")
        image_id = info["Id"]
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            raise ValueError
        return {"reference": image, "image_id": image_id}
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise VerificationError("Docker returned incomplete release-image metadata") from exc


def verify(env: dict[str, str]) -> dict:
    dev_image, security_image, commit = selected_images(env)
    if platform.system() != "Linux":
        raise VerificationError("release-image tests require a Linux Docker runner")
    child_env = runner_env(env)
    endpoint = child_env.get("DOCKER_HOST") if not child_env.get("DOCKER_CONTEXT") else None
    if not endpoint:
        endpoint = command(
            ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"], child_env, timeout=30,
        ).strip()
    if not endpoint.startswith("unix:///"):
        raise VerificationError("runner-only tests refuse remote Docker engines")
    server = command(["docker", "info", "--format", "{{.OSType}}"], child_env, timeout=30)
    if server.strip() != "linux":
        raise VerificationError("release-image tests require a Linux Docker engine")
    evidence = {}
    for component, image in (("dev_cvm", dev_image), ("security_cvm", security_image)):
        print(f"release-images: pulling and checking {component}", file=sys.stderr, flush=True)
        command(["docker", "pull", "--platform", "linux/amd64", image], child_env)
        evidence[component] = validate_image_inspection(
            image, commit, command(["docker", "image", "inspect", image], child_env, timeout=30),
        )
    child_env.update({
        "DEV_CVM_IMAGE_SMOKE_IMAGE": dev_image,
        "DEV_CVM_COMPOSE_SMOKE_IMAGE": dev_image,
        "UMBRA_TEST_SECURITY_IMAGE": security_image,
        "UMBRA_E2E_REQUIRED": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    })
    steps = (
        ("Dev image contents", ["bash", "cvms/dev/tests/user_sandbox_image_smoke.sh"]),
        ("Dev topology and fail-closed egress", ["bash", "cvms/dev/tests/compose_smoke.sh"]),
        ("Security image wire journeys", [
            "uv", "run", "--locked", "--project", "cvms/security", "python",
            "ops/verify/run-required-pytest.py", "-q", "cvms/security/tests/test_egress_e2e.py",
        ]),
    )
    for name, args in steps:
        print(f"release-images: {name}", file=sys.stderr, flush=True)
        try:
            command(args, child_env, timeout=900, diagnostics=True)
        except VerificationError as exc:
            raise VerificationError(f"{name} failed; release images are not qualified") from exc
    return {
        "schema_version": 1,
        "status": "passed",
        "source_commit": commit,
        "lock_sha256": env.get("UMBRA_TEST_LOCK_SHA256"),
        "images": evidence,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "checks": [name for name, _ in steps],
        "not_exercised": [
            "TDX hardware attestation", "provider orchestration", "Google OIDC",
            "Sysbox isolation", "Dev-to-Security positive aTLS path", "production TLS termination",
        ],
    }


def main() -> int:
    receipt_path = Path(os.environ.get("UMBRA_TEST_RECEIPT", ROOT / "artifacts/release-image-tests.json"))
    try:
        # A failed rerun must never leave an earlier successful receipt behind.
        receipt_path.unlink(missing_ok=True)
        receipt = verify(dict(os.environ))
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", dir=receipt_path.parent, delete=False) as output:
            temporary = Path(output.name)
            json.dump(receipt, output, indent=2)
            output.write("\n")
        try:
            temporary.replace(receipt_path)
        finally:
            temporary.unlink(missing_ok=True)
    except (VerificationError, OSError) as exc:
        message = str(exc) if isinstance(exc, VerificationError) else "could not write release-image test receipt"
        print(f"release-images: {message}", file=sys.stderr)
        return 1
    print("release-images: runner checks passed; hardware attestation remains unverified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
