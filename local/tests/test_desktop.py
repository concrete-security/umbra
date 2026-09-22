"""Desktop registration exercises real OpenSSH resolution without opening apps."""
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from umbra_local import agent, desktop, state


@pytest.fixture
def setup(tmp_path):
    home = tmp_path / "home"
    home.mkdir(mode=0o700)
    path = tmp_path / "workspace"
    path.mkdir(mode=0o700)
    binding = {"root": str(tmp_path / "project with spaces"), "name": "p-12345678901234567890"}
    (path / "ssh-editor.conf").write_text(state.ssh_config(path, binding['name'], tmp_path, "/usr/bin/python3", editor=True))
    return home, path, binding


def test_existing_ssh_settings_preserved_success(setup):
    """Repeated registration preserves user bytes and unrelated hosts' effective options."""
    home, path, binding = setup
    (home / '.ssh').mkdir(mode=0o700)
    original = b'ForwardAgent yes\nHost ordinary\n    HostName example.invalid\n    User original\n'
    (home / '.ssh/config').write_bytes(original)
    alias = desktop.register_ssh(path, binding, home)
    desktop.register_ssh(path, binding, home)
    result = (home / '.ssh/config').read_bytes()
    assert result.endswith(original) and result.count(b'# Umbra local desktop workspaces\n') == 1
    assert next((home / '.ssh').glob('config.umbra-backup-*')).read_bytes() == original
    # Resolve the fixture Include under its temporary home; ssh expands ~ from passwd.
    test_config = home / 'resolved.conf'
    test_config.write_bytes(result.replace(b'~/.ssh', str(home / '.ssh').encode()))
    own = subprocess.check_output(['/usr/bin/ssh', '-G', '-F', str(test_config), alias], text=True)
    other = subprocess.check_output(['/usr/bin/ssh', '-G', '-F', str(test_config), 'ordinary'], text=True)
    assert 'forwardagent no\n' in own and f'hostkeyalias umbra-local-{binding["name"]}\n' in own
    assert 'user original\n' in other and 'forwardagent yes\n' in other


def test_claude_settings_preserved_success(setup):
    """Registration retains every unrelated setting and connection and is idempotent."""
    home, _, binding = setup
    (home / '.claude').mkdir()
    settings = home / '.claude/settings.json'
    original = {'env':{'EXAMPLE':'keep'}, 'sshConfigs':[{'id':'other','sshHost':'other'}]}
    settings.write_text(json.dumps(original))
    desktop.register_claude('umbra-test', binding, home)
    desktop.register_claude('umbra-test', binding, home)
    result = json.loads(settings.read_text())
    assert result['env'] == original['env'] and result['sshConfigs'] == [*original['sshConfigs'],
        {'id':'umbra-test','name':'Umbra: project with spaces','sshHost':'umbra-test'}]


@pytest.mark.parametrize('kind', ['symlink', 'malformed'])
def test_unsafe_claude_settings_failure(setup, kind):
    """Unsafe or malformed user settings are never replaced with defaults."""
    home, _, binding = setup
    (home / '.claude').mkdir()
    path = home / '.claude/settings.json'
    if kind == 'symlink':
        target = home / 'original'
        target.write_text('{}')
        path.symlink_to(target)
    else:
        path.write_text('broken JSON')
    before = path.read_bytes()
    with pytest.raises(state.LocalError):
        desktop.register_claude('umbra-test', binding, home)
    assert path.read_bytes() == before


@pytest.mark.parametrize('app', ['codex', 'claude'])
def test_desktop_handoff_success(setup, monkeypatch, app):
    """Only the desktop app opens; a host project path is never passed as a local folder."""
    home, path, binding = setup
    monkeypatch.setattr(Path, 'home', lambda: home)
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr(subprocess, 'run', run)
    result = desktop.launch(app, path, binding, '/home/dev/workspaces/project/src')
    assert calls[-1] == ['/usr/bin/open', '-b', desktop.APPS[app]]
    assert 'agent not started yet' in result['next_step']


@pytest.mark.parametrize('failed_step,diagnostic', [(1, 'readiness'), (2, 'agent settings')])
def test_guest_preparation_blocks_desktop_failure(setup, monkeypatch, failed_step, diagnostic):
    """Guest readiness or auth setup failure prevents desktop opening."""
    _, path, binding = setup
    calls = []
    def run(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=int(len(calls) == failed_step))
    monkeypatch.setattr(subprocess, 'run', run)
    with pytest.raises(state.LocalError, match=diagnostic):
        desktop.launch('codex', path, binding, '/home/dev/workspaces/project')
    assert len(calls) == failed_step and all(call[0] == '/usr/bin/ssh' for call in calls)


@pytest.mark.parametrize('app', ['codex', 'claude'])
def test_guest_placeholder_setup_success(tmp_path, app):
    """Fresh guest authentication contains only dummy tokens and is idempotent."""
    command = [sys.executable, '-c', agent.GUEST_SETUP, app]
    environment = dict(os.environ, HOME=str(tmp_path))
    subprocess.run(command, env=environment, check=True)
    path = tmp_path / ('.codex/auth.json' if app == 'codex' else '.claude/settings.json')
    before = path.read_bytes()
    subprocess.run(command, env=environment, check=True)
    value = json.loads(before)
    token = value['tokens']['refresh_token'] if app == 'codex' else value['env']['CLAUDE_CODE_OAUTH_TOKEN']
    assert token == 'umbra-proxy-injected' and path.read_bytes() == before and path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('app', ['codex', 'claude'])
def test_existing_guest_auth_preserved_success(tmp_path, app):
    """Existing guest provider authentication is never replaced by dummy auth."""
    path = tmp_path / ('.codex/auth.json' if app == 'codex' else '.claude/settings.json')
    path.parent.mkdir()
    original = {'custom': 'keep', 'env': {'ANTHROPIC_API_KEY': 'synthetic-existing'}}
    path.write_text(json.dumps(original))
    before = path.read_bytes()
    subprocess.run([sys.executable, '-c', agent.GUEST_SETUP, app], env=dict(os.environ, HOME=str(tmp_path)), check=True)
    assert path.read_bytes() == before


def test_guest_claude_settings_retained_success(tmp_path):
    """Adding the placeholder retains unrelated Claude settings and a private backup."""
    folder = tmp_path / '.claude'
    folder.mkdir()
    path = folder / 'settings.json'
    path.write_text('{"env":{"EXAMPLE":"keep"},"custom":true}')
    before = path.read_bytes()
    subprocess.run([sys.executable, '-c', agent.GUEST_SETUP, 'claude'], env=dict(os.environ, HOME=str(tmp_path)), check=True)
    result = json.loads(path.read_text())
    assert result['env']['EXAMPLE'] == 'keep' and result['custom'] is True and (folder / 'settings.before-umbra-agent.json').read_bytes() == before


@pytest.mark.parametrize('app', ['codex', 'claude'])
@pytest.mark.parametrize('kind', ['folder', 'file'])
def test_guest_settings_symlink_failure(tmp_path, app, kind):
    """Guest setup never follows settings links to unrelated files or directories."""
    folder = tmp_path / ('.codex' if app == 'codex' else '.claude')
    target = tmp_path / 'untouched'
    if kind == 'folder':
        target.mkdir()
        folder.symlink_to(target)
    else:
        folder.mkdir()
        target.write_text('{}')
        (folder / ('auth.json' if app == 'codex' else 'settings.json')).symlink_to(target)
    result = subprocess.run([sys.executable, '-c', agent.GUEST_SETUP, app], env=dict(os.environ, HOME=str(tmp_path)))
    assert result.returncode != 0 and (not list(target.iterdir()) if target.is_dir() else target.read_text() == '{}')
