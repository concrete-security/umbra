import asyncio
import json
import sys
from uuid import UUID

import pytest

from umbra_console.attestation import (
    AtlasVerifierClient,
    ATLAS_VERIFIER_CMD_ENV,
    AttestationVerifierError,
    build_dev_cvm_attestation_request,
    build_security_cvm_attestation_request,
    parse_attestation_report,
    verifier_error_from_output,
    verify_with_fetch_retries,
)


def test_parse_attestation_report_accepts_measurements() -> None:
    report = parse_attestation_report(
        json.dumps({"image_measurement": "A" * 96, "rtmr3_digest": "B" * 96}).encode("utf-8")
    )

    assert report.image_measurement == "a" * 96
    assert report.rtmr3_digest == "b" * 96


def test_parse_attestation_report_rejects_malformed_measurement() -> None:
    with pytest.raises(AttestationVerifierError) as exc:
        parse_attestation_report(json.dumps({"image_measurement": "not-hex", "rtmr3_digest": "b" * 96}).encode("utf-8"))

    assert exc.value.code == "ATTESTATION_QUOTE_INVALID"
    assert exc.value.details["reason"] == "invalid_image_measurement"


def test_verifier_error_from_output_preserves_known_code() -> None:
    error = verifier_error_from_output(
        json.dumps(
            {
                "error": {
                    "code": "ATTESTATION_IMAGE_MISMATCH",
                    "details": {"reported_image_measurement": "b" * 96},
                }
            }
        ).encode("utf-8")
    )

    assert error.code == "ATTESTATION_IMAGE_MISMATCH"
    assert error.details == {"reported_image_measurement": "b" * 96}


def test_build_dev_cvm_attestation_request_uses_policy_bundle() -> None:
    request = build_dev_cvm_attestation_request(
        {
            "fqdn": "cvm.example.com",
            "expected_image_measurement": "a" * 96,
            "metadata": {
                "policy_bundle": {
                    "compose_template": "services: {}\n",
                    "expected_bootchain": {"mrtd": "b" * 96},
                    "os_image_hash": "c" * 64,
                    "rtmr3_binding": {"cvm_id": str(UUID("00000000-0000-4000-8000-000000000031"))},
                }
            },
        }
    )

    assert request == {
        "kind": "dev_cvm",
        "fqdn": "cvm.example.com",
        "policy": {
            "type": "dstack_tdx",
            "expected_image_measurement": "a" * 96,
            "expected_bootchain": {"mrtd": "b" * 96},
            "os_image_hash": "c" * 64,
            "app_compose": {"docker_compose_file": "services: {}\n"},
            "rtmr3_binding": {"cvm_id": "00000000-0000-4000-8000-000000000031"},
        },
    }


def test_build_dev_cvm_attestation_request_preserves_full_app_compose() -> None:
    request = build_dev_cvm_attestation_request(
        {
            "fqdn": "cvm.example.com",
            "expected_image_measurement": "a" * 96,
            "metadata": {
                "policy_bundle": {
                    "compose_template": "services: {}\n",
                    "app_compose_json": (
                        '{"allowed_envs":[],"docker_compose_file":"stale",'
                        '"features":["kms","tproxy-net"],"runner":"docker-compose"}'
                    ),
                    "app_compose": {
                        "allowed_envs": ["wrong"],
                        "docker_compose_file": "stale",
                        "features": ["wrong"],
                        "runner": "docker-compose",
                    },
                    "expected_bootchain": {"mrtd": "b" * 96},
                    "os_image_hash": "c" * 64,
                    "rtmr3_binding": {"cvm_id": str(UUID("00000000-0000-4000-8000-000000000031"))},
                }
            },
        }
    )

    assert request["policy"]["app_compose"] == {
        "allowed_envs": [],
        "docker_compose_file": "services: {}\n",
        "features": ["kms", "tproxy-net"],
        "runner": "docker-compose",
    }


@pytest.mark.parametrize(
    "policy_bundle, reason",
    [
        (
            {
                "compose_template": "services: {}\n",
                "os_image_hash": "c" * 64,
                "rtmr3_binding": {"cvm_id": "00000000-0000-4000-8000-000000000031"},
            },
            "dev_cvm_expected_bootchain_missing",
        ),
        (
            {
                "compose_template": "services: {}\n",
                "expected_bootchain": {"mrtd": "b" * 96},
                "rtmr3_binding": {"cvm_id": "00000000-0000-4000-8000-000000000031"},
            },
            "dev_cvm_os_image_hash_missing",
        ),
    ],
)
def test_build_dev_cvm_attestation_request_rejects_incomplete_bundle(policy_bundle, reason) -> None:
    # FULL runtime verification, symmetric with the SC: a Dev CVM bundle missing the bootchain or
    # os_image_hash MUST fail closed, never fall through to an MRTD-only / dev() verification.
    with pytest.raises(AttestationVerifierError) as excinfo:
        build_dev_cvm_attestation_request(
            {
                "fqdn": "cvm.example.com",
                "expected_image_measurement": "a" * 96,
                "metadata": {"policy_bundle": policy_bundle},
            }
        )
    assert excinfo.value.code == "ATTESTATION_QUOTE_INVALID"
    assert excinfo.value.details["reason"] == reason


_SC_SNAPSHOT = {
    "id": UUID("00000000-0000-4000-8000-000000000041"),
    "entity_id": UUID("00000000-0000-4000-8000-000000000001"),
    "fqdn": "sc.example.com",
    "expected_image_measurement": "a" * 96,
    "compose_config": "services: {}\n",
    "metadata": {"provider": "phala"},
}
_SC_SHADE_POLICY = {
    "app_compose": {
        "manifest_version": 2,
        "runner": "docker-compose",
        "docker_compose_file": "services: {}\n",
        "kms_enabled": True,
    },
    "expected_bootchain": {"mrtd": "e" * 96, "rtmr0": "f" * 96},
    "os_image_hash": "d" * 64,
}


def test_build_security_cvm_attestation_request_uses_full_runtime_policy() -> None:
    # The SC is verified exactly like the Dev CVM — never dev()/disable_runtime_verification.
    # The shade-generated policy carries the AUTHORITATIVE complete app_compose +
    # expected_bootchain + os_image_hash, all of which MUST appear in the policy so the atlas
    # verifier runs compose-hash + bootchain + os-image + RTMR replay (not just MRTD).
    request = build_security_cvm_attestation_request(
        _SC_SNAPSHOT,
        token_hashes={"INGEST": "B" * 64, "CA_EXPORT": "C" * 64},
        console_url="https://console.example.com",
        shade_policy=_SC_SHADE_POLICY,
    )

    assert request == {
        "kind": "security_cvm",
        "fqdn": "sc.example.com",
        "policy": {
            "type": "dstack_tdx",
            "expected_image_measurement": "a" * 96,
            "app_compose": {
                "manifest_version": 2,
                "runner": "docker-compose",
                "docker_compose_file": "services: {}\n",
                "kms_enabled": True,
            },
            "expected_bootchain": {"mrtd": "e" * 96, "rtmr0": "f" * 96},
            "os_image_hash": "d" * 64,
            "rtmr3_binding": {
                "CONSOLE_URL": "https://console.example.com",
                "entity_id": "00000000-0000-4000-8000-000000000001",
                "sc_id": "00000000-0000-4000-8000-000000000041",
                "ingest_token_sha256": "b" * 64,
                "ca_export_token_sha256": "c" * 64,
            },
        },
    }


def test_build_security_cvm_attestation_request_prefers_authoritative_app_compose_json() -> None:
    # When shade carries the compact app_compose_json (hash-sensitive key order), it wins over
    # the round-tripped app_compose object so the compose-hash matches the measured quote.
    request = build_security_cvm_attestation_request(
        _SC_SNAPSHOT,
        token_hashes={"INGEST": "B" * 64, "CA_EXPORT": "C" * 64},
        console_url="https://console.example.com",
        shade_policy={
            **_SC_SHADE_POLICY,
            "app_compose": {"docker_compose_file": "stale", "runner": "wrong"},
            "app_compose_json": (
                '{"docker_compose_file":"services: {}\\n","kms_enabled":true,'
                '"manifest_version":2,"runner":"docker-compose"}'
            ),
        },
    )

    assert request["policy"]["app_compose"] == {
        "docker_compose_file": "services: {}\n",
        "kms_enabled": True,
        "manifest_version": 2,
        "runner": "docker-compose",
    }


@pytest.mark.parametrize(
    "shade_policy, reason",
    [
        (None, "security_cvm_shade_policy_missing"),
        ({"expected_bootchain": {"mrtd": "e" * 96}, "os_image_hash": "d" * 64}, "security_cvm_app_compose_missing"),
        ({"app_compose": {"runner": "docker-compose"}, "os_image_hash": "d" * 64}, "security_cvm_expected_bootchain_missing"),
        ({"app_compose": {"runner": "docker-compose"}, "expected_bootchain": {"mrtd": "e" * 96}}, "security_cvm_os_image_hash_missing"),
    ],
)
def test_build_security_cvm_attestation_request_rejects_incomplete_shade_policy(shade_policy, reason) -> None:
    # Never fall back to a dev()/disable_runtime_verification policy: an absent or incomplete
    # shade policy MUST raise rather than emit a bare policy that the verifier would relax.
    with pytest.raises(AttestationVerifierError) as exc:
        build_security_cvm_attestation_request(
            _SC_SNAPSHOT,
            token_hashes={"INGEST": "B" * 64, "CA_EXPORT": "C" * 64},
            console_url="https://console.example.com",
            shade_policy=shade_policy,
        )

    assert exc.value.code == "ATTESTATION_QUOTE_INVALID"
    assert exc.value.details["reason"] == reason


def test_atlas_verifier_client_uses_stdin_stdout_contract(tmp_path) -> None:
    verifier = tmp_path / "verifier.py"
    verifier.write_text(
        "import json, sys\n"
        "request = json.loads(sys.stdin.read())\n"
        "assert request['kind'] == 'dev_cvm'\n"
        "print(json.dumps({'image_measurement': 'a' * 96, 'rtmr3_digest': 'b' * 96}))\n"
    )

    report = asyncio.run(
        AtlasVerifierClient([sys.executable, str(verifier)]).verify(
            {"kind": "dev_cvm"},
            timeout_seconds=30,
        )
    )

    assert report.image_measurement == "a" * 96
    assert report.rtmr3_digest == "b" * 96


def test_verify_with_fetch_retries_retries_transient_fetch_failure(monkeypatch) -> None:
    attempts: list[int] = []

    class FakeVerifier:
        async def verify(self, request, *, timeout_seconds):
            attempts.append(timeout_seconds)
            if len(attempts) == 1:
                raise AttestationVerifierError(
                    "ATTESTATION_FETCH_FAILED",
                    {"reason": "tls_handshake_failed"},
                )
            return parse_attestation_report(
                json.dumps({"image_measurement": "a" * 96, "rtmr3_digest": "b" * 96}).encode("utf-8")
            )

    async def fake_sleep(_delay):
        return None

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)

    report = asyncio.run(
        verify_with_fetch_retries(
            FakeVerifier(),
            {"kind": "security_cvm"},
            timeout_seconds=30,
            initial_delay_seconds=0,
            max_delay_seconds=0,
        )
    )

    assert report.image_measurement == "a" * 96
    assert len(attempts) == 2


def test_verify_with_fetch_retries_does_not_retry_attestation_content_errors(monkeypatch) -> None:
    attempts = 0

    class FakeVerifier:
        async def verify(self, request, *, timeout_seconds):
            nonlocal attempts
            attempts += 1
            raise AttestationVerifierError(
                "ATTESTATION_RTMR_MISMATCH",
                {"reason": "rtmr_mismatch"},
            )

    async def fail_sleep(_delay):
        raise AssertionError("content errors must not sleep for retry")

    monkeypatch.setattr(asyncio, "sleep", fail_sleep)

    with pytest.raises(AttestationVerifierError) as exc:
        asyncio.run(
            verify_with_fetch_retries(
                FakeVerifier(),
                {"kind": "security_cvm"},
                timeout_seconds=30,
            )
        )

    assert exc.value.code == "ATTESTATION_RTMR_MISMATCH"
    assert attempts == 1


def test_atlas_verifier_client_rejects_malformed_command(monkeypatch) -> None:
    monkeypatch.setenv(ATLAS_VERIFIER_CMD_ENV, "'unterminated")

    with pytest.raises(AttestationVerifierError) as exc:
        AtlasVerifierClient.from_settings()

    assert exc.value.code == "ATTESTATION_FETCH_FAILED"
    assert exc.value.details == {"reason": "verifier_command_invalid"}
