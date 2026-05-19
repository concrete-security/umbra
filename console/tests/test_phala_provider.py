import asyncio
import json
from pathlib import Path
import textwrap

import pytest

from concrete_console.tee_provider.phala import (
    PhalaClient,
    PhalaError,
    PhalaNotFound,
    compile_redaction_patterns,
    normalize_status,
    phala_subprocess_env,
    render_env_file,
    scrub_output,
)


TEST_CLI_TIMEOUT_SECONDS = 30


def write_fake_cli(tmp_path: Path, source: str) -> Path:
    cli = tmp_path / "fake-phala.py"
    cli.write_text("#!/usr/bin/env python3\n" + textwrap.dedent(source))
    cli.chmod(0o755)
    return cli


def run(awaitable):
    return asyncio.run(awaitable)


def test_normalize_status_maps_known_values() -> None:
    assert normalize_status("running") == "RUNNING"
    assert normalize_status("Booting") == "PENDING"
    assert normalize_status("crashed") == "FAILED"
    assert normalize_status("removed") == "TERMINATED"
    assert normalize_status("surprising") == "UNKNOWN"


def test_phala_subprocess_env_is_allowlisted(monkeypatch) -> None:
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("HOME", "/tmp/home")
    monkeypatch.setenv("PHALA_API_TOKEN", "must-not-pass")
    monkeypatch.setenv("GOOGLE_OIDC_CLIENT_SECRET", "must-not-pass")

    env = phala_subprocess_env("phala-token")

    assert env["PATH"] == "/usr/bin"
    assert env["HOME"] == "/tmp/home"
    assert env["PHALA_CLOUD_API_KEY"] == "phala-token"
    assert set(env).issubset({"PATH", "HOME", "LANG", "LC_ALL", "PHALA_CLOUD_API_KEY"})
    assert "PHALA_API_TOKEN" not in env
    assert "GOOGLE_OIDC_CLIENT_SECRET" not in env


def test_from_settings_accepts_timeout_override(monkeypatch) -> None:
    monkeypatch.setenv("PHALA_API_TOKEN", "phala-token")
    monkeypatch.setenv("PHALA_CLI_PATH", "/tmp/phala")

    client = PhalaClient.from_settings(timeout_seconds=30.0)

    assert client.timeout_seconds == 30.0
    assert client.cli_path == "/tmp/phala"


def test_render_env_file_rejects_smuggleable_values() -> None:
    with pytest.raises(PhalaError) as exc:
        render_env_file({"SECURITY_CVM_PROXY_TOKEN": "line1\nline2"})

    assert exc.value.code == "invalid_env_value"


def test_scrub_output_redacts_api_token_and_configured_patterns() -> None:
    patterns = compile_redaction_patterns(r"secret-[0-9]+")

    scrubbed = scrub_output("token phala-token and secret-123", "phala-token", patterns)

    assert scrubbed == "token [redacted] and [redacted]"


def test_deploy_stages_files_with_private_modes_and_cleans(tmp_path) -> None:
    marker = tmp_path / "seen.json"
    cli = write_fake_cli(
        tmp_path,
        f"""
        import json
        import os
        import stat
        import sys

        assert "PHALA_API_TOKEN" not in os.environ
        assert os.environ["PHALA_CLOUD_API_KEY"] == "phala-token"
        assert sys.argv[1:4] == ["deploy", "--name", "concrete-v0-cvm-smoke"]
        assert sys.argv[sys.argv.index("--instance-type") + 1] == "tdx.small"
        assert sys.argv[sys.argv.index("--region") + 1] == "FR-PARIS-1"
        compose_path = sys.argv[sys.argv.index("--compose") + 1]
        env_path = sys.argv[sys.argv.index("-e") + 1]
        assert stat.S_IMODE(os.stat(compose_path).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(env_path).st_mode) == 0o600
        assert open(compose_path).read() == "services: {{}}\\n"
        assert "SECURITY_CVM_PROXY_TOKEN=proxy-token\\n" in open(env_path).read()
        open({str(marker)!r}, "w").write(json.dumps({{"compose": compose_path, "env": env_path}}))
        print(json.dumps({{"app_id": "app-123", "gateway_host": "gateway.example.com", "status": "running"}}))
        """,
    )
    client = PhalaClient(cli_path=str(cli), api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS)

    result = run(
        client.deploy(
            name="concrete-v0-cvm-smoke",
            compose_yaml="services: {}\n",
            env={"SECURITY_CVM_PROXY_TOKEN": "proxy-token"},
            instance_type="tdx.small",
            region="FR-PARIS-1",
        )
    )

    seen = json.loads(marker.read_text())
    assert result.app_id == "app-123"
    assert result.gateway_host == "gateway.example.com"
    assert result.status == "RUNNING"
    assert not Path(seen["compose"]).exists()
    assert not Path(seen["env"]).exists()


def test_deploy_falls_back_to_cvms_get_when_cli_stdout_is_empty(tmp_path) -> None:
    marker = tmp_path / "argv.json"
    cli = write_fake_cli(
        tmp_path,
        f"""
        import json
        import sys

        if sys.argv[1:3] == ["cvms", "get"]:
            print(json.dumps({{
                "app_id": "app-123",
                "gateway": {{"base_domain": "dstack.example.com", "cname": "_.dstack.example.com"}},
                "status": "stopped"
            }}))
            raise SystemExit(0)

        open({str(marker)!r}, "w").write(json.dumps(sys.argv[1:]))
        """,
    )
    client = PhalaClient(cli_path=str(cli), api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS)

    result = run(client.deploy(name="concrete-v0-cvm-smoke", compose_yaml="services: {}\n", env={}))

    argv = json.loads(marker.read_text())
    assert argv[:3] == ["deploy", "--name", "concrete-v0-cvm-smoke"]
    assert "--wait" in argv
    assert result.app_id == "app-123"
    assert result.gateway_host == "dstack.example.com"
    assert result.status == "STOPPED"


def test_deploy_parses_progress_prefixed_json_and_fetches_gateway(tmp_path) -> None:
    marker = tmp_path / "argv.json"
    cli = write_fake_cli(
        tmp_path,
        f"""
        import json
        import sys

        if sys.argv[1:3] == ["cvms", "get"]:
            open({str(marker)!r}, "w").write(json.dumps(sys.argv[1:]))
            print(json.dumps({{
                "app_id": "app-123",
                "gateway": {{"base_domain": "dstack.example.com"}},
                "status": "running"
            }}))
            raise SystemExit(0)

        print("Provisioning CVM concrete-v0-cvm-smoke...")
        print(json.dumps({{"success": True, "app_id": "app-123", "name": "concrete-v0-cvm-smoke"}}))
        """,
    )
    client = PhalaClient(cli_path=str(cli), api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS)

    result = run(client.deploy(name="concrete-v0-cvm-smoke", compose_yaml="services: {}\n", env={}))

    assert json.loads(marker.read_text()) == ["cvms", "get", "app-123", "--json"]
    assert result.app_id == "app-123"
    assert result.gateway_host == "dstack.example.com"
    assert result.status == "RUNNING"


def test_update_uses_phala_deploy_with_cvm_id(tmp_path) -> None:
    marker = tmp_path / "argv.json"
    cli = write_fake_cli(
        tmp_path,
        f"""
        import json
        import sys

        open({str(marker)!r}, "w").write(json.dumps(sys.argv[1:]))
        print(json.dumps({{"app_id": "app-123", "gateway_host": "gateway.example.com", "status": "active"}}))
        """,
    )
    client = PhalaClient(cli_path=str(cli), api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS)

    result = run(client.update(app_id="app-123", compose_yaml="services: {}\n", env={}))

    argv = json.loads(marker.read_text())
    assert argv[:3] == ["deploy", "--cvm-id", "app-123"]
    assert "--compose" in argv
    assert "-e" in argv
    assert "--wait" in argv
    assert "--json" in argv
    assert result.status == "RUNNING"


def test_deploy_rejects_non_concrete_name(tmp_path) -> None:
    cli = write_fake_cli(tmp_path, "raise SystemExit('should not run')\n")
    client = PhalaClient(cli_path=str(cli), api_token="phala-token")

    with pytest.raises(PhalaError) as exc:
        run(client.deploy(name="other-system", compose_yaml="", env={}))

    assert exc.value.code == "invalid_name"


def test_nonzero_cli_output_is_redacted(tmp_path) -> None:
    cli = write_fake_cli(
        tmp_path,
        """
        import os
        import sys

        print("stdout has " + os.environ["PHALA_CLOUD_API_KEY"])
        print("stderr has secret-999", file=sys.stderr)
        raise SystemExit(2)
        """,
    )
    client = PhalaClient(
        cli_path=str(cli),
        api_token="phala-token",
        redaction_patterns=compile_redaction_patterns(r"secret-[0-9]+"),
        timeout_seconds=TEST_CLI_TIMEOUT_SECONDS,
    )

    with pytest.raises(PhalaError) as exc:
        run(client.logs("app-123"))

    assert exc.value.code == "cli_failed"
    assert "phala-token" not in exc.value.output
    assert "secret-999" not in exc.value.output
    assert exc.value.output.count("[redacted]") == 2


def test_info_validates_response_fields(tmp_path) -> None:
    cli = write_fake_cli(
        tmp_path,
        """
        import json

        print(json.dumps({"app_id": "bad app id", "gateway_host": "gateway.example.com"}))
        """,
    )
    client = PhalaClient(cli_path=str(cli), api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS)

    with pytest.raises(PhalaError) as exc:
        run(client.info("app-123"))

    assert exc.value.code == "invalid_response"
    assert exc.value.field == "app_id"


def test_delete_tolerates_not_found(tmp_path) -> None:
    cli = write_fake_cli(
        tmp_path,
        """
        import sys

        print("not found", file=sys.stderr)
        raise SystemExit(1)
        """,
    )
    client = PhalaClient(cli_path=str(cli), api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS)

    run(client.delete("app-123"))


def test_get_raises_not_found(tmp_path) -> None:
    cli = write_fake_cli(
        tmp_path,
        """
        import sys

        print("not found", file=sys.stderr)
        raise SystemExit(1)
        """,
    )
    client = PhalaClient(cli_path=str(cli), api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS)

    with pytest.raises(PhalaNotFound):
        run(client.info("app-123"))


def test_list_filters_to_concrete_v0_names(tmp_path) -> None:
    cli = write_fake_cli(
        tmp_path,
        """
        import json

        print(json.dumps({
            "cvms": [
                {"name": "concrete-v0-cvm-owned", "id": "app-1"},
                {"name": "teammate-prod", "id": "app-2"},
                {"name": "concrete-v0-sc-owned", "id": "app-3"}
            ]
        }))
        """,
    )
    client = PhalaClient(cli_path=str(cli), api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS)

    rows = run(client.list())

    assert [row["id"] for row in rows] == ["app-1", "app-3"]
