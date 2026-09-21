import asyncio
import io
import json
import os
from pathlib import Path
import shlex
import struct
import sys
import tarfile
import tempfile
from types import SimpleNamespace

import pytest

from umbra_local import cli, project_files as files, projects, state


@pytest.fixture
def tree():
    # Keep paths below macOS's Unix-domain socket limit.
    with tempfile.TemporaryDirectory(prefix="up-", dir="/tmp") as temporary:
        root = Path(temporary)
        (root / "config").mkdir(mode=0o700)
        (root / "project").mkdir()
        yield root / "config", root / "project"


def transfer(host, guest, base):
    desired = files.scan(host)
    request = io.BytesIO()
    payload = json.dumps({"version": 1, "base": base, "desired": desired}).encode()
    request.write(struct.pack("!I", len(payload)))
    request.write(payload)
    files.make_archive(host, base, desired, request)
    request.seek(0)
    result = files.receive(request, guest)
    assert result["ok"]
    return desired


def test_folder_binding_is_private_success(tree):
    """A checkout need not contain a config file or a committed binding."""
    config, root = tree
    projects.bind(config, root)
    assert list(root.iterdir()) == [] and (config / projects.REGISTRY).stat().st_mode & 0o077 == 0


def test_subdirectory_reuses_workspace_success(tree):
    """Running inside src picks the same VM without a project or CVM argument."""
    config, root = tree
    binding = projects.bind(config, root)
    (root / "src").mkdir()
    assert projects.select(config, root / "src") == binding


def test_subdirectory_start_is_idempotent_success(tree):
    """A second start inside the project does not allocate a second workspace."""
    config, root = tree
    binding = projects.bind(config, root)
    (root / "src").mkdir()
    assert projects.bind(config, root / "src") == binding and len(projects.read_registry(config)["projects"]) == 1


def test_sibling_prefix_does_not_match_success(tree):
    """A pathname prefix alone is not a project ancestor."""
    config, root = tree
    projects.bind(config, root)
    sibling = root.with_name(root.name + "-other")
    sibling.mkdir()
    assert projects.select(config, sibling) is None


def test_guest_cwd_preserved_success(tree):
    """Shells and agents start at the same relative path inside the copied tree."""
    config, root = tree
    binding = projects.bind(config, root)
    (root / "src").mkdir()
    assert projects.guest_directory(binding, root / "src") == projects.GUEST_ROOT + "/src"


@pytest.mark.parametrize("override", ["../../outside", "/etc", "/home/dev/workspaces/project-other"])
def test_guest_workspace_escape_failure(tree, override):
    """An override cannot switch a bound project to an unrelated guest directory."""
    config, root = tree
    binding = projects.bind(config, root)
    with pytest.raises(state.LocalError):
        projects.guest_directory(binding, root, override)


def test_registry_corruption_failure(tree):
    """Corrupt local context fails rather than selecting the cloud default."""
    config, root = tree
    state.write_file(config / projects.REGISTRY, b"not json")
    with pytest.raises(state.LocalError, match="fall back"):
        projects.select(config, root)


def test_registry_symlink_failure(tree):
    """A checkout cannot redirect the private registry through a symlink."""
    config, root = tree
    (root / "fake").write_text('{}')
    (config / projects.REGISTRY).symlink_to(root / "fake")
    with pytest.raises((state.LocalError, OSError)):
        projects.select(config, root)


@pytest.mark.parametrize("aliased", [False, True], ids=["direct", "symlink-parent"])
def test_import_of_umbra_credentials_failure(tree, aliased):
    """A project containing Umbra's private configuration is not imported."""
    config, root = tree
    if aliased:
        alias = root / "config-parent"
        alias.symlink_to(config.parent, target_is_directory=True)
        config = alias / "config"
    with pytest.raises(state.LocalError, match="must not contain"):
        projects.bind(config, root.parent)


def test_copy_dotfiles_untracked_and_git_success(tree):
    """Initial import copies the folder, not git ls-files or a clean checkout."""
    config, root = tree
    (root / ".git").mkdir()
    (root / ".git/config").write_text("fixture")
    (root / ".env").write_text("NON_SECRET_FIXTURE=true")
    (root / "new-untracked.txt").write_text("uncommitted content")
    guest = root.parent / "guest"
    base = transfer(root, guest, {})
    assert set(files.scan(guest)) == set(base) and (guest / "new-untracked.txt").read_text() == "uncommitted content"


def test_host_edit_sync_success(tree):
    """Later host edits update the guest when the guest file is unchanged."""
    _, root = tree
    (root / "a").write_text("first")
    guest = root.parent / "guest"
    base = transfer(root, guest, {})
    (root / "a").write_text("second")
    transfer(root, guest, base)
    assert (guest / "a").read_text() == "second"


def test_guest_only_edits_preserved_success(tree):
    """Adding another host file never resets work performed by the agent."""
    _, root = tree
    (root / "a").write_text("first")
    guest = root.parent / "guest"
    base = transfer(root, guest, {})
    (guest / "a").write_text("agent change")
    (guest / "agent-new").write_text("new")
    (root / "host-new").write_text("host new")
    transfer(root, guest, base)
    assert (guest / "a").read_text() == "agent change" and (guest / "agent-new").exists()


def test_conflicting_edits_failure(tree):
    """A divergent host and agent edit leaves both copies untouched."""
    _, root = tree
    (root / "a").write_text("first")
    guest = root.parent / "guest"
    base = transfer(root, guest, {})
    (root / "a").write_text("host edit")
    (guest / "a").write_text("agent edit")
    with pytest.raises(files.TransferError, match="conflicts"):
        transfer(root, guest, base)
    assert ((root / "a").read_text(), (guest / "a").read_text()) == ("host edit", "agent edit")


def test_matching_edits_do_not_conflict_success(tree):
    """A resolved conflict can be retried without discarding either tree."""
    _, root = tree
    (root / "a").write_text("first")
    guest = root.parent / "guest"
    base = transfer(root, guest, {})
    (root / "a").write_text("resolved")
    (guest / "a").write_text("resolved")
    transfer(root, guest, base)
    assert (guest / "a").read_text() == "resolved"


def test_host_deletion_of_unchanged_file_success(tree):
    """Deleting a host file removes its unchanged copy, not unrelated guest files."""
    _, root = tree
    (root / "a").write_text("first")
    guest = root.parent / "guest"
    base = transfer(root, guest, {})
    (root / "a").unlink()
    transfer(root, guest, base)
    assert not (guest / "a").exists()


def test_guest_files_block_parent_deletion_failure(tree):
    """A host directory removal cannot recursively erase guest-created work."""
    _, root = tree
    (root / "sub").mkdir()
    guest = root.parent / "guest"
    base = transfer(root, guest, {})
    (guest / "sub/agent").write_text("retain")
    (root / "sub").rmdir()
    with pytest.raises(files.TransferError, match="conflicts"):
        transfer(root, guest, base)
    assert (guest / "sub/agent").read_text() == "retain"


def test_internal_symlink_preserved_success(tree):
    """A relative in-project symlink remains a symlink, not a copied target."""
    _, root = tree
    (root / "target").write_text("content")
    (root / "link").symlink_to("target")
    guest = root.parent / "guest"
    transfer(root, guest, {})
    assert os.readlink(guest / "link") == "target"


@pytest.mark.parametrize("target", ["../outside", "/etc/passwd", "sub/../../outside"])
def test_external_symlink_failure(tree, target):
    """Imports never follow links out of the project into host credentials."""
    _, root = tree
    (root / "link").symlink_to(target)
    with pytest.raises(files.TransferError, match="symlink"):
        files.scan(root)


def test_fifo_is_not_opened_failure(tree):
    """A project FIFO is rejected without a blocking read."""
    _, root = tree
    os.mkfifo(root / "pipe")
    with pytest.raises(files.TransferError, match="FIFO"):
        files.scan(root)


def test_archive_traversal_failure(tree):
    """Tar extraction does not trust a filename supplied outside the manifest."""
    _, root = tree
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        member = tarfile.TarInfo("../escape")
        member.size = 1
        archive.addfile(member, io.BytesIO(b"x"))
    stream.seek(0)
    with pytest.raises(files.TransferError, match="manifest"):
        files.stage_archive(stream, root, {}, {})


def test_source_changed_during_archive_failure(tree):
    """A changed host inode cannot be sent under a stale content digest."""
    _, root = tree
    (root / "a").write_text("first")
    desired = files.scan(root)
    (root / "a").write_text("changed")
    with pytest.raises(files.TransferError, match="changed"):
        files.make_archive(root, {}, desired, io.BytesIO())


def test_fragmented_guest_response_success():
    """A JSON response arriving in several reads is assembled before decoding."""
    command = [sys.executable, "-c", 'import sys,time;sys.stdout.write(\'{"ok":\');sys.stdout.flush();time.sleep(.01);print("true}")']
    with tempfile.TemporaryFile() as source:
        assert asyncio.run(files.bounded_run(command, source))["ok"] is True


def test_oversized_guest_response_failure():
    """An untrusted guest cannot allocate unlimited output in the host importer."""
    with tempfile.TemporaryFile() as source:
        with pytest.raises(files.TransferError, match="oversized"):
            asyncio.run(files.bounded_run([sys.executable, "-c", 'print("x" * 10000)'], source))


def test_no_public_companion_entry_point_success():
    """Installing the runtime does not add another user-facing command."""
    manifest = (Path(__file__).parents[1] / "pyproject.toml").read_text()
    assert "[project.scripts]" not in manifest


def test_named_session_script_success():
    """Named local sessions use a guest-side persistent terminal."""
    command = cli.session_script("claude", projects.GUEST_ROOT + "/some space", "review", None)
    assert "dtach -A" in command and "'" + projects.GUEST_ROOT + "/some space'" in command


def test_command_shell_quoting_success():
    """Explicit shell commands and project paths remain separate quoted arguments."""
    command = cli.session_script("ssh", projects.GUEST_ROOT + "/some space", None, "printf '%s' 'a; b'")
    assert command.endswith(shlex.join(["bash", "-lc", "printf '%s' 'a; b'"]))


def test_local_stop_retains_binding_and_files_success(tree, monkeypatch, capsys):
    """Stopping a project never deletes its folder registration or guest disk."""
    config, root = tree
    binding = projects.bind(config, root)
    path = state.workspace(config, binding["name"])
    path.mkdir(parents=True)
    (path / "disk.raw").write_bytes(b"disk fixture")
    monkeypatch.setattr(cli, "status", lambda path: {"state": "stopped"})
    args = cli.parser().parse_args(["--config", str(config), "--json", "project-stop", "--path", str(root)])
    assert cli.project_command(args) == 0
    assert projects.select(config, root) == binding and (path / "disk.raw").read_bytes() == b"disk fixture"


def test_session_conflict_still_opens_guest_success(tree, monkeypatch, capsys):
    """A sync conflict does not lock the user out of the guest needed to resolve it."""
    config, root = tree
    binding = projects.bind(config, root)
    monkeypatch.setattr(cli, "require_running", lambda path: None)
    monkeypatch.setattr(projects, "sync", lambda *args: (_ for _ in ()).throw(projects.ProjectConflict("conflict")))
    commands = []
    monkeypatch.setattr(cli.subprocess, "call", lambda args: commands.append(args) or 0)
    args = cli.parser().parse_args(["--config", str(config), "project-session", "--verb", "ssh", "--path", str(root)])
    assert cli.project_command(args) == 0
    assert projects.GUEST_ROOT in commands[0][-1] and "Conflicting" in capsys.readouterr().err


def test_stopped_project_refuses_cloud_fallback_failure(tree, monkeypatch):
    """A folder binding survives stop and errors before opening any session."""
    config, root = tree
    projects.bind(config, root)
    monkeypatch.setattr(cli, "status", lambda path: {"state": "stopped"})
    args = cli.parser().parse_args(["--config", str(config), "project-session", "--verb", "codex", "--path", str(root)])
    with pytest.raises(state.LocalError, match="umbra start local"):
        cli.project_command(args)


@pytest.mark.parametrize("kind", ["venv", "fifo"])
def test_guest_generated_special_entries_preserved_success(tmp_path, kind):
    """Unrelated host edits survive guest-only virtualenv links or named pipes."""
    host, guest = tmp_path / "host", tmp_path / "guest"
    host.mkdir(); guest.mkdir()
    (host / "source").write_text("old")
    base = transfer(host, guest, {})
    if kind == "venv":
        (guest / ".venv").mkdir()
        (guest / ".venv/python").symlink_to("/usr/bin/python3")
    else:
        os.mkfifo(guest / "pipe")
    (host / "source").write_text("new")
    transfer(host, guest, base)
    assert (guest / "source").read_text() == "new"
