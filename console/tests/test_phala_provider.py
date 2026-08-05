import asyncio
import json
from pathlib import Path
import textwrap

import pytest

from umbra_console.tee_provider import (
    MAX_INSTANCE_TYPES_RESPONSE_BYTES,
    CvmProvider,
    CvmProviderError,
)
from umbra_console.tee_provider.phala import (
    PHALA_COMPOSE_FILE_HASH_HELPER,
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
    assert normalize_status("updating") == "PENDING"
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


def test_scrub_output_redacts_sensitive_assignments_and_configured_secrets(monkeypatch) -> None:
    monkeypatch.setenv("GHCR_TOKEN", "ghp_configuredsecret1234567890")

    scrubbed = scrub_output(
        'SECURITY_CVM_PROXY_TOKEN=proxy-token\n{"CA_EXPORT_TOKEN":"ca-token","image":"unchanged"}\n'
        "configured ghp_configuredsecret1234567890",
        "phala-token",
        (),
    )

    assert "proxy-token" not in scrubbed
    assert "ca-token" not in scrubbed
    assert "ghp_configuredsecret1234567890" not in scrubbed
    assert "SECURITY_CVM_PROXY_TOKEN=[redacted]" in scrubbed
    assert '"CA_EXPORT_TOKEN":"[redacted]"' in scrubbed
    assert '"image":"unchanged"' in scrubbed


def test_provider_adapter_preserves_scrubbed_phala_output() -> None:
    class FailingClient:
        async def update(self, **_kwargs):
            raise PhalaError("cli_failed", output="image pull denied")

    provider = CvmProvider(provider="phala", client=FailingClient())

    with pytest.raises(CvmProviderError) as exc:
        run(provider.update_deployment(deployment_id="app-123", compose_yaml="services: {}\n", env={}))

    assert exc.value.code == "cli_failed"
    assert exc.value.provider == "phala"
    assert exc.value.output == "image pull denied"


def test_provider_adapter_reads_deployment_compose_hash() -> None:
    class HashClient:
        async def compose_file_sha256(self, app_id):
            assert app_id == "app-123"
            return "a" * 64

    provider = CvmProvider(provider="phala", client=HashClient())

    assert run(provider.deployment_compose_sha256("app-123")) == "a" * 64


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
        assert sys.argv[1:4] == ["deploy", "--name", "umbra-v0-cvm-smoke"]
        assert sys.argv[sys.argv.index("--instance-type") + 1] == "tdx.small"
        assert sys.argv[sys.argv.index("--region") + 1] == "FR-PARIS-1"
        assert "--no-dev-os" in sys.argv
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
            name="umbra-v0-cvm-smoke",
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


def test_deploy_appends_disk_size_with_unit(tmp_path) -> None:
    # `phala deploy --disk-size` wants a size *with unit* (e.g. "50G"), not a
    # bare integer.
    cli = write_fake_cli(
        tmp_path,
        """
        import json
        import sys

        assert sys.argv[sys.argv.index("--disk-size") + 1] == "50G"
        print(json.dumps({"app_id": "app-123", "gateway_host": "gateway.example.com", "status": "running"}))
        """,
    )
    client = PhalaClient(cli_path=str(cli), api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS)

    result = run(
        client.deploy(
            name="umbra-v0-cvm-smoke",
            compose_yaml="services: {}\n",
            env={},
            instance_type="tdx.small",
            region="FR-PARIS-1",
            disk_size_gb=50,
        )
    )

    assert result.app_id == "app-123"


def test_deploy_omits_disk_size_when_absent(tmp_path) -> None:
    cli = write_fake_cli(
        tmp_path,
        """
        import json
        import sys

        assert "--disk-size" not in sys.argv
        print(json.dumps({"app_id": "app-123", "gateway_host": "gateway.example.com", "status": "running"}))
        """,
    )
    client = PhalaClient(cli_path=str(cli), api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS)

    result = run(
        client.deploy(
            name="umbra-v0-cvm-smoke",
            compose_yaml="services: {}\n",
            env={},
        )
    )

    assert result.app_id == "app-123"


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

    result = run(client.deploy(name="umbra-v0-cvm-smoke", compose_yaml="services: {}\n", env={}))

    argv = json.loads(marker.read_text())
    assert argv[:3] == ["deploy", "--name", "umbra-v0-cvm-smoke"]
    assert "--no-dev-os" in argv
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

        print("Provisioning CVM umbra-v0-cvm-smoke...")
        print(json.dumps({{"success": True, "app_id": "app-123", "name": "umbra-v0-cvm-smoke"}}))
        """,
    )
    client = PhalaClient(cli_path=str(cli), api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS)

    result = run(client.deploy(name="umbra-v0-cvm-smoke", compose_yaml="services: {}\n", env={}))

    assert json.loads(marker.read_text()) == ["cvms", "get", "app-123", "--json"]
    assert result.app_id == "app-123"
    assert result.gateway_host == "dstack.example.com"
    assert result.status == "RUNNING"


def test_update_uses_phala_deploy_cvm_id(tmp_path) -> None:
    marker = tmp_path / "argv.json"
    cli = write_fake_cli(
        tmp_path,
        f"""
        import json
        import sys

        if sys.argv[1:3] == ["cvms", "get"]:
            print(json.dumps({{
                "app_id": "app-123",
                "vm_uuid": "a8dcb43d-7c46-4d5d-b026-192409368bbc",
                "gateway": {{"base_domain": "dstack.example.com"}},
                "status": "running"
            }}))
            raise SystemExit(0)

        compose_path = sys.argv[sys.argv.index("--compose") + 1]
        env_path = sys.argv[sys.argv.index("-e") + 1]
        open({str(marker)!r}, "w").write(json.dumps({{
            "argv": sys.argv[1:],
            "compose": open(compose_path).read(),
            "env": open(env_path).read(),
        }}))
        print(json.dumps({{"app_id": "app-123", "gateway_host": "gateway.example.com", "status": "active"}}))
        """,
    )
    client = PhalaClient(
        cli_path=str(cli),
        api_token="phala-token",
        timeout_seconds=TEST_CLI_TIMEOUT_SECONDS,
    )

    result = run(client.update(app_id="app-123", compose_yaml="services: {}\n", env={"TOKEN": "value"}))

    seen = json.loads(marker.read_text())
    argv = seen["argv"]
    assert argv[:3] == ["deploy", "--cvm-id", "a8dcb43d-7c46-4d5d-b026-192409368bbc"]
    assert "--no-dev-os" in argv
    assert "--wait" not in argv
    assert "--json" in argv
    assert seen["compose"] == "services: {}\n"
    assert "TOKEN=value\n" in seen["env"]
    assert result.status == "RUNNING"


def test_compose_file_sha256_uses_node_helper(tmp_path) -> None:
    marker = tmp_path / "argv.json"
    node = write_fake_cli(
        tmp_path,
        f"""
        import json
        import sys

        open({str(marker)!r}, "w").write(json.dumps({{"argv": sys.argv[1:], "app_id": sys.argv[-1]}}))
        print(json.dumps({{"sha256": {"b" * 64!r}}}))
        """,
    )
    client = PhalaClient(
        cli_path="/unused/phala",
        api_token="phala-token",
        node_path=str(node),
        timeout_seconds=TEST_CLI_TIMEOUT_SECONDS,
    )

    assert run(client.compose_file_sha256("app-123")) == "b" * 64
    seen = json.loads(marker.read_text())
    assert seen["argv"][:2] == ["--input-type=module", "-e"]
    assert seen["app_id"] == "app-123"


def test_compose_file_hash_helper_reads_provider_compose_file() -> None:
    assert "getCvmComposeFile" in PHALA_COMPOSE_FILE_HASH_HELPER
    assert "docker_compose_file" in PHALA_COMPOSE_FILE_HASH_HELPER


def test_deploy_rejects_non_managed_name(tmp_path) -> None:
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


def test_list_filters_managed_v0_names_success(tmp_path) -> None:
    """Only fully validated Umbra resource names enter managed inventory."""

    cli = write_fake_cli(
        tmp_path,
        """
        import json

        print(json.dumps({
            "cvms": [
                {"name": "umbra-v0-cvm-owned", "id": "app-1"},
                {"name": "teammate-prod", "id": "app-2"},
                {"name": "umbra-v0-sc-owned", "id": "app-3"},
                {"name": "umbra-v0-cvm-owned\\nprovider-secret", "id": "app-4"},
                {"name": "umbra-v0-unrecognized", "id": "app-5"}
            ]
        }))
        """,
    )
    client = PhalaClient(cli_path=str(cli), api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS)

    rows = run(client.list())

    assert [row["id"] for row in rows] == ["app-1", "app-3"]


# -- instance-type adapter: PhalaClient subprocess error handling ---------------
# The happy path runs the real `phala` binary in test_instance_types.py
# (test_list_instance_types_contract[real]), where the parser also lives. These
# cover the failure translations, none of which needs a fake binary.


def test_run_command_translates_missing_binary_to_phala_error(tmp_path) -> None:
    client = PhalaClient(
        cli_path=str(tmp_path / "does-not-exist"), api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS
    )

    with pytest.raises(PhalaError) as exc:
        run(client.list_instance_types())

    assert exc.value.code == "cli_failed"


@pytest.mark.parametrize(
    ("make_output", "kwargs"),
    [
        # Deeply-nested payload: json.loads raises RecursionError, which must be caught
        # and degraded rather than escaping.
        (lambda: "[" * 200000 + "]" * 200000, {}),
        # Over-cap but VALID JSON: rejected on size before json.loads runs. It is valid
        # JSON on purpose -- without the size guard _run_json would parse it and NOT
        # raise, so this scenario actually pins the guard.
        (
            lambda: '"' + "a" * MAX_INSTANCE_TYPES_RESPONSE_BYTES + '"',
            {"max_bytes": MAX_INSTANCE_TYPES_RESPONSE_BYTES},
        ),
    ],
    ids=["deeply_nested", "oversize"],
)
def test_run_json_translates_hostile_output_to_invalid_json(make_output, kwargs, monkeypatch) -> None:
    """_run_json degrades hostile output to a normal invalid_json error instead of
    letting it escape or allocate an unbounded object: a deeply-nested payload (caught
    RecursionError) and an over-cap response (rejected on size before json.loads) both
    surface as invalid_json."""
    client = PhalaClient(cli_path="phala", api_token="phala-token", timeout_seconds=TEST_CLI_TIMEOUT_SECONDS)

    async def hostile(self, args):
        return make_output()

    # PhalaClient is a frozen dataclass, so patch the method on the class.
    monkeypatch.setattr(PhalaClient, "_run_text", hostile)

    with pytest.raises(PhalaError) as exc:
        run(client._run_json(["instance-types", "--json"], **kwargs))

    assert exc.value.code == "invalid_json"
