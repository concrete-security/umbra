import asyncio
import hashlib
import json
from pathlib import Path
import ssl
import sys

import pytest

from umbra_local import cli, direct, service, state


def test_stop_requires_target_failure():
    """Stop never silently uses a default workspace."""
    with pytest.raises(SystemExit) as result:
        cli.parser().parse_args(["stop"])
    assert result.value.code == 2


def test_up_requires_explicit_preview_failure(monkeypatch, tmp_path):
    """An unqualified launch cannot masquerade as a managed installation."""
    monkeypatch.setattr(cli, "check_platform", lambda: None)
    args = cli.parser().parse_args(["up"])
    with pytest.raises(state.LocalError, match="preview"):
        cli.up(args, tmp_path)


def test_nonzero_structured_stdout_empty_failure(monkeypatch, capsys):
    """A failed structured command prints only a diagnostic, never a success payload."""
    monkeypatch.setattr(sys, "argv", ["umbra-local", "--json", "doctor"])
    monkeypatch.setattr(cli, "check_platform", lambda: (_ for _ in ()).throw(state.LocalError("unsupported platform")))
    result = cli.main()
    captured = capsys.readouterr()
    assert (result, captured.out) == (1, "")


def test_unknown_workspace_status_success(monkeypatch, capsys, tmp_path):
    """Status is useful before first launch and does not require cloud credentials."""
    # macOS Unix socket lengths are deliberately enforced on every test platform.
    monkeypatch.setattr(sys, "argv", ["umbra-local", "--config", "/tmp/umbra-test-missing", "--json", "status"])
    assert cli.main() == 0
    assert json.loads(capsys.readouterr().out)["state"] == "stopped"


@pytest.mark.parametrize("payload", [b"{}", b"[]", b"not json", b'{"version":1,"ca_pem":"bad","sha256":"bad"}'])
def test_untrusted_ca_metadata_failure(payload):
    """Malformed or mismatched CA metadata cannot bootstrap guest trust."""
    with pytest.raises((state.LocalError, ValueError)):
        direct.validate_lease(json.loads(payload))


def test_managed_assurance_gate_failure(tmp_path):
    """Even the private worker refuses a config labelled managed-local."""
    (tmp_path / "config.json").write_text(json.dumps({"assurance": "managed-local"}))
    with pytest.raises(state.LocalError, match="not implemented"):
        asyncio.run(service._serve(tmp_path, tmp_path))


def test_native_no_nic_boundary_success():
    """The native source has one fixed vsock path and does not configure an IP attachment."""
    # This guards source drift, not hardware behavior or remote attestation.
    source = (Path(__file__).parents[1] / "native/Sources/UmbraLocalVM/main.swift").read_text()
    assert "config.networkDevices = []" in source and "VZNATNetworkDeviceAttachment(" not in source and "VZBridgedNetworkDeviceAttachment(" not in source


def test_no_host_directory_sharing_success():
    """The runtime never offers writable host workspaces to guest root."""
    source = (Path(__file__).parents[1] / "native/Sources/UmbraLocalVM/main.swift").read_text()
    assert "config.directorySharingDevices = []" in source


def test_remembered_profiles_precede_defaults_success(monkeypatch, tmp_path):
    """A plain restart preserves the project's selected policy over global defaults."""
    from pathlib import Path
    first = "11111111-1111-4111-8111-111111111111"
    default = "22222222-2222-4222-8222-222222222222"
    config = {"profiles":[first], "bundle":str(tmp_path), "umbra":str(Path("/usr/bin/true").resolve()),
        "cpus":2, "memory":4096, "assurance":"local-preview"}
    (tmp_path / "config.json").write_text(json.dumps(config))
    args = cli.parser().parse_args(["--umbra","/usr/bin/true","project-start","--default-profile",default])
    monkeypatch.setattr(cli,"status",lambda _: {"state":"running"})
    assert cli.prepare(args,tmp_path)["profiles"] == [first]
