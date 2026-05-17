import asyncio
import json
import sys
from uuid import UUID

import pytest

from concrete_console.attestation import (
    AtlasVerifierClient,
    ATLAS_VERIFIER_CMD_ENV,
    AttestationVerifierError,
    build_dev_cvm_attestation_request,
    build_security_cvm_attestation_request,
    parse_attestation_report,
    verifier_error_from_output,
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
                "passthrough_host": "app-443s.dstack.example.com",
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
        "connect_host": "app-443s.dstack.example.com",
        "policy": {
            "type": "dstack_tdx",
            "expected_image_measurement": "a" * 96,
            "expected_bootchain": {"mrtd": "b" * 96},
            "os_image_hash": "c" * 64,
            "app_compose": {"docker_compose_file": "services: {}\n"},
            "rtmr3_binding": {"cvm_id": "00000000-0000-4000-8000-000000000031"},
        },
    }


def test_build_security_cvm_attestation_request_uses_token_hashes() -> None:
    request = build_security_cvm_attestation_request(
        {
            "id": UUID("00000000-0000-4000-8000-000000000041"),
            "entity_id": UUID("00000000-0000-4000-8000-000000000001"),
            "fqdn": "sc.example.com",
            "expected_image_measurement": "a" * 96,
            "compose_config": "services: {}\n",
            "metadata": {"passthrough_host": "sc-app-443s.dstack.example.com"},
        },
        token_hashes={"INGEST": "B" * 64, "CA_EXPORT": "C" * 64},
        console_url="https://console.example.com",
    )

    assert request == {
        "kind": "security_cvm",
        "fqdn": "sc.example.com",
        "connect_host": "sc-app-443s.dstack.example.com",
        "policy": {
            "type": "dstack_tdx",
            "expected_image_measurement": "a" * 96,
            "app_compose": {"docker_compose_file": "services: {}\n"},
            "rtmr3_binding": {
                "CONSOLE_URL": "https://console.example.com",
                "entity_id": "00000000-0000-4000-8000-000000000001",
                "sc_id": "00000000-0000-4000-8000-000000000041",
                "ingest_token_sha256": "b" * 64,
                "ca_export_token_sha256": "c" * 64,
            },
        },
    }


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


def test_atlas_verifier_client_rejects_malformed_command(monkeypatch) -> None:
    monkeypatch.setenv(ATLAS_VERIFIER_CMD_ENV, "'unterminated")

    with pytest.raises(AttestationVerifierError) as exc:
        AtlasVerifierClient.from_settings()

    assert exc.value.code == "ATTESTATION_FETCH_FAILED"
    assert exc.value.details == {"reason": "verifier_command_invalid"}
