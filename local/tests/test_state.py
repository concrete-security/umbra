import json
import os
from pathlib import Path
import stat

import pytest

from umbra_local import state


@pytest.fixture
def bundle(tmp_path):
    folder = tmp_path / "bundle"
    folder.mkdir()
    files = {}
    for name in state.BUNDLE_FILES:
        path = folder / name
        path.write_bytes(b"test artifact " + name.encode())
        path.chmod(0o700)
        files[name] = state.digest_file(path)
    (folder / "manifest.json").write_text(json.dumps({"version": 2, "architecture": "aarch64", "files": files}))
    return folder


def test_verified_bundle_success(bundle):
    """A complete, matching preview bundle passes drift checks."""
    assert state.verify_bundle(bundle)["architecture"] == "aarch64"


@pytest.mark.parametrize("name", sorted(state.BUNDLE_FILES))
def test_modified_artifact_failure(bundle, name):
    """Every boot input and the native helper is covered by the manifest."""
    (bundle / name).write_text("changed")
    with pytest.raises(state.LocalError):
        state.verify_bundle(bundle)


@pytest.mark.parametrize("name", ["../escape", "", "Upper", "two words", "a" * 33, "a\ncontrol"])
def test_invalid_workspace_name_failure(name):
    """Workspace names cannot escape their own private state directory."""
    with pytest.raises(state.LocalError):
        state.workspace(Path("/tmp/umbra"), name)


def test_state_permissions_success(tmp_path):
    """Persisted metadata is owner-only and writes are atomic replacements."""
    folder = tmp_path / "state"
    state.private_dir(folder)
    state.write_json(folder / "state.json", {"version": 1})
    assert stat.S_IMODE((folder / "state.json").stat().st_mode) == 0o600


def test_control_socket_path_limit_failure():
    """Reject paths where proxy.sock fits but the longer control.sock does not."""
    config = Path("/" + "a" * 80)
    with pytest.raises(state.LocalError, match="too long"):
        state.workspace(config, "dev")


def test_world_readable_state_failure(tmp_path):
    """Unsafe existing directories are rejected rather than silently trusted."""
    tmp_path.chmod(0o755)
    with pytest.raises(state.LocalError):
        state.private_dir(tmp_path)


def test_symlink_state_failure(tmp_path):
    """Symlinked state directories are not adopted."""
    link = tmp_path / "link"
    link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(state.LocalError):
        state.private_dir(link)


def test_duplicate_operation_failure(tmp_path):
    """Concurrent start operations cannot both own the workspace lock."""
    with state.lock(tmp_path / "lock"):
        with pytest.raises(state.LocalError):
            with state.lock(tmp_path / "lock"):
                pass


def test_ssh_no_host_forwarding_success(tmp_path):
    """SSH enables strict per-VM host-key checking and disables host authority forwarding."""
    config = state.ssh_config(tmp_path, "dev", tmp_path, "/usr/bin/python3")
    assert all(item in config for item in ["StrictHostKeyChecking yes", "ForwardAgent no", "ClearAllForwardings yes", "PermitLocalCommand no"])


def test_ssh_path_quoting_success():
    """Spaces, quotes and percent signs cannot become OpenSSH expansion tokens."""
    config = state.ssh_config(Path('/tmp/a "quoted" %d'), "dev", Path("/tmp/space here"), "/usr/bin/python3")
    assert '%%d' in config and '\\"quoted\\"' in config


def test_ssh_control_character_failure():
    """A crafted path cannot append a second SSH configuration directive."""
    with pytest.raises(state.LocalError):
        state.ssh_config(Path("/tmp/a\nForwardAgent yes"), "dev", Path("/tmp"), "/usr/bin/python3")


def test_editor_guest_loopback_forwarding_success():
    """The editor may reach its guest backend without enabling agent forwarding."""
    config = state.ssh_config(Path("/tmp/umbra"), "dev", Path("/tmp/umbra"), "/usr/bin/python3", editor=True)
    assert "ClearAllForwardings no" in config and "ForwardAgent no" in config


def test_legacy_bootstrap_bundle_failure(bundle):
    """A guest without clock bootstrap support fails before VM launch."""
    path = bundle / "manifest.json"
    value = json.loads(path.read_text())
    value["version"] = 1
    path.write_text(json.dumps(value))
    with pytest.raises(state.LocalError):
        state.verify_bundle(bundle)
