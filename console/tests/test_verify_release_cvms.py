"""Unit tests for strict deployment qualification evidence."""

import asyncio
import importlib.util
import json
from pathlib import Path

import pytest
import yaml


_spec = importlib.util.spec_from_file_location(
    "verify_release_cvms",
    Path(__file__).resolve().parents[2] / "ops/verify/verify-release-cvms.py",
)
verify = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(verify)

SECURITY_IMAGE = "ghcr.io/concrete-security/umbra-security-cvm@sha256:" + "a" * 64
DEV_IMAGE = "ghcr.io/concrete-security/umbra-dev-cvm@sha256:" + "b" * 64
MRTD = "c" * 96
RTMR3 = "d" * 96
ENTITY_ID = "11111111-1111-4111-8111-111111111111"


@pytest.fixture
def pins(monkeypatch):
    values = (SECURITY_IMAGE, MRTD, DEV_IMAGE, MRTD)
    for name, value in zip(verify.PIN_NAMES, values, strict=True):
        monkeypatch.setenv(name, value)
    return values


def test_running_console_uses_exact_pins_success(pins):
    """A Console configured with the locked pins qualifies for the journey."""
    assert verify.main(["pins", *pins]) == 0


@pytest.mark.parametrize("pos", range(4), ids=verify.PIN_NAMES)
def test_running_console_changed_pin_failure(pins, monkeypatch, pos):
    """A mismatch in any running image or boot measurement stops qualification."""
    monkeypatch.setenv(verify.PIN_NAMES[pos], "different")
    assert verify.main(["pins", *pins]) == 1


def cvm_evidence(role, image, *, changed_service=None, compose_mismatch=False, measurement=MRTD):
    compose = yaml.safe_dump({
        "services": {
            name: {"image": DEV_IMAGE if changed_service == name else image}
            for name in verify.SERVICES[role]
        },
    })
    app_compose = {"docker_compose_file": compose}
    deployed = "different" if compose_mismatch else compose
    if role == "security":
        evidence = {"atls_policy": {"app_compose": app_compose}, "deploy_compose_yaml": deployed}
    else:
        evidence = {
            "app_compose": app_compose,
            "app_compose_json": json.dumps(app_compose),
            "deploy_compose_yaml": deployed,
            "compose_template": compose,
        }
    return {
        "expected_image_measurement": MRTD,
        "image_measurement": measurement,
        "rtmr3_digest": RTMR3,
        "attestation_verified_at": "2026-11-19T00:00:00Z",
        "error_reason": None,
        "evidence": json.dumps(evidence),
    }


@pytest.mark.parametrize("role,image", [
    pytest.param("security", SECURITY_IMAGE, id="security"),
    pytest.param("dev", DEV_IMAGE, id="dev"),
])
def test_exact_attested_image_and_measurement_success(role, image):
    """Both roles require the pinned image in every product service."""
    assert verify.check_cvm(cvm_evidence(role, image), role, image, MRTD, RTMR3) is None


@pytest.mark.parametrize(("overrides", "rtmr3"), [
    pytest.param({"changed_service": "proxy-tunnel"}, RTMR3, id="other-image"),
    pytest.param({"compose_mismatch": True}, RTMR3, id="other-compose"),
    pytest.param({"measurement": "e" * 96}, RTMR3, id="other-mrtd"),
    pytest.param({}, "e" * 96, id="other-rtmr3"),
])
def test_different_attested_release_evidence_failure(overrides, rtmr3):
    """A successful quote for changed Compose, image, MRTD, or RTMR3 cannot qualify."""
    row = cvm_evidence("security", SECURITY_IMAGE, **overrides)
    with pytest.raises(verify.EvidenceError):
        verify.check_cvm(row, "security", SECURITY_IMAGE, MRTD, rtmr3)


def test_occupied_entity_refused_without_writing_failure(monkeypatch):
    """Fresh staging refuses any existing CVM and uses a read-only transaction."""
    class Transaction:
        async def __aenter__(self):
            pass

        async def __aexit__(self, *args):
            pass

    class Connection:
        def transaction(self, *, readonly):
            assert readonly is True
            return Transaction()

        async def fetchval(self, query, _):
            assert "SELECT 1 FROM security_cvms" in query
            assert "SELECT 1 FROM cvms" in query
            return True

        async def close(self):
            pass

    async def connect(*args, **kwargs):
        return Connection()

    monkeypatch.setattr(verify.asyncpg, "connect", connect)
    with pytest.raises(verify.EvidenceError, match="already has"):
        asyncio.run(verify.check_database(["fresh", ENTITY_ID]))
