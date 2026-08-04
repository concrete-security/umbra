from __future__ import annotations

import os

from umbra_security_cvm.mitmproxy_runtime import (
    MITMPROXY_SCRIPT_ENV,
    build_runtime_addon_from_env,
    mitmdump_args,
)


def env(tmp_path) -> dict[str, str]:
    return {
        "CONSOLE_URL": "https://console.example.com",
        "ENTITY_ID": "00000000-0000-4000-8000-000000000001",
        "SC_ID": "00000000-0000-4000-8000-000000000002",
        "CONSOLE_INGEST_TOKEN": "ingest-plaintext",
        "CA_EXPORT_TOKEN": "ca-export-plaintext",
        "SC_MITMPROXY_CONFDIR": str(tmp_path / "mitmproxy"),
    }


def test_build_runtime_addon_materializes_same_ca_mitmproxy_uses(tmp_path) -> None:
    addon = build_runtime_addon_from_env(env(tmp_path))

    confdir = tmp_path / "mitmproxy"
    assert (confdir / "mitmproxy-ca.pem").read_bytes() == addon.runtime.ca.private_key_pem + addon.runtime.ca.ca_pem
    assert (confdir / "mitmproxy-ca-cert.pem").read_bytes() == addon.runtime.ca.ca_pem


def test_build_runtime_addon_consumes_os_environ_plaintext_tokens(monkeypatch, tmp_path) -> None:
    for name, value in env(tmp_path).items():
        monkeypatch.setenv(name, value)

    addon = build_runtime_addon_from_env()

    assert addon.runtime.config.ingest_token == "ingest-plaintext"
    assert addon.runtime.config.ca_export_token == "ca-export-plaintext"
    assert "CONSOLE_INGEST_TOKEN" not in os.environ
    assert "CA_EXPORT_TOKEN" not in os.environ


def test_mitmdump_args_pin_internal_listener_and_tmpfs_confdir(tmp_path) -> None:
    args = mitmdump_args(script_path="/app/addon.py", env={"SC_MITMPROXY_CONFDIR": str(tmp_path), "SC_MITMPROXY_PORT": "8181"})

    assert args[:7] == ["mitmdump", "--mode", "regular", "--listen-host", "0.0.0.0", "--listen-port", "8181"]
    assert f"confdir={tmp_path}" in args
    assert "ssl_insecure=false" in args
    assert "flow_detail=0" in args
    assert args[-2:] == ["-s", "/app/addon.py"]


def test_module_import_does_not_build_addon_without_mitmproxy_script_env() -> None:
    from umbra_security_cvm import mitmproxy_runtime

    assert os.environ.get(MITMPROXY_SCRIPT_ENV) != "1"
    assert mitmproxy_runtime.addons == []
