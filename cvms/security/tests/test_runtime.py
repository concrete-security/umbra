from __future__ import annotations

import hashlib

import pytest

from umbra_security_cvm.runtime import SecurityCVMRuntime, SecurityCVMRuntimeConfig


def env() -> dict[str, str]:
    return {
        "CONSOLE_URL": "https://console.example.com",
        "ENTITY_ID": "00000000-0000-4000-8000-000000000001",
        "SC_ID": "00000000-0000-4000-8000-000000000002",
        "CONSOLE_INGEST_TOKEN": "ingest-plaintext",
        "CA_EXPORT_TOKEN": "ca-export-plaintext",
        "SC_MANAGEMENT_HOST": "127.0.0.1",
        "SC_MANAGEMENT_PORT": "18081",
        "SC_CONTROL_INTERVAL_SECONDS": "2.5",
        "SC_CONTROL_JITTER_SECONDS": "0.5",
        "SC_TRAFFIC_FLUSH_INTERVAL_SECONDS": "0.25",
    }


def test_runtime_config_consumes_plaintext_token_env_and_hides_repr() -> None:
    source = env()

    config = SecurityCVMRuntimeConfig.from_env(source, consume_secrets=True)

    assert "CONSOLE_INGEST_TOKEN" not in source
    assert "CA_EXPORT_TOKEN" not in source
    assert config.console_url == "https://console.example.com"
    assert config.management_host == "127.0.0.1"
    assert config.management_port == 18081
    assert config.control_interval_seconds == 2.5
    assert config.control_jitter_seconds == 0.5
    assert config.traffic_flush_interval_seconds == 0.25
    assert "ingest-plaintext" not in repr(config)
    assert "ca-export-plaintext" not in repr(config)


def test_runtime_config_builds_boot_binding_from_plaintexts() -> None:
    config = SecurityCVMRuntimeConfig.from_env(env())
    binding = config.boot_binding()

    assert binding.payload()["CONSOLE_URL"] == "https://console.example.com"
    assert binding.payload()["ingest_token_sha256"] == hashlib.sha256(b"ingest-plaintext").hexdigest()
    assert binding.payload()["ca_export_token_sha256"] == hashlib.sha256(b"ca-export-plaintext").hexdigest()
    assert "ingest-plaintext" not in binding.canonical_json()
    assert "ca-export-plaintext" not in binding.canonical_json()


def test_runtime_build_wires_ca_control_state_and_traffic_clients_without_persisting_ca_key() -> None:
    config = SecurityCVMRuntimeConfig.from_env(env())

    runtime = SecurityCVMRuntime.build(config)

    assert b"BEGIN CERTIFICATE" in runtime.ca.ca_pem
    assert b"PRIVATE KEY" not in runtime.ca.ca_pem
    assert len(runtime.control_state.snapshot().control_map.entries_by_proxy_token_hash) == 0
    assert runtime.control_client.console_url == "https://console.example.com"
    assert runtime.traffic_emitter.client.console_url == "https://console.example.com"
    assert runtime.traffic_emitter.flush_interval_seconds == 0.25


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("SC_MANAGEMENT_PORT", "0", "SC_MANAGEMENT_PORT must be 1..65535"),
        ("SC_CONTROL_INTERVAL_SECONDS", "0", "SC_CONTROL_INTERVAL_SECONDS must be positive"),
        ("SC_CONTROL_JITTER_SECONDS", "-1", "SC_CONTROL_JITTER_SECONDS must be non-negative"),
        ("SC_TRAFFIC_FLUSH_INTERVAL_SECONDS", "0", "SC_TRAFFIC_FLUSH_INTERVAL_SECONDS must be positive"),
    ],
)
def test_runtime_config_rejects_invalid_numeric_env(key: str, value: str, message: str) -> None:
    source = env()
    source[key] = value

    with pytest.raises(ValueError, match=message):
        SecurityCVMRuntimeConfig.from_env(source)
