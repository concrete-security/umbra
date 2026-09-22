"""Prepare non-secret guest authentication for Security CVM injection."""
from __future__ import annotations

from pathlib import Path
import shlex
import subprocess

from .state import LocalError

# Runs only inside the guest. Never reads the Mac's provider credentials.
GUEST_SETUP = r'''
import base64, datetime, json, os, pathlib, sys
app = sys.argv[1]
if app not in ('codex', 'claude'):
    raise SystemExit(1)
folder = pathlib.Path.home() / ('.codex' if app == 'codex' else '.claude')
if folder.is_symlink():
    raise SystemExit(1)
folder.mkdir(mode=0o700, exist_ok=True)
target = folder / ('auth.json' if app == 'codex' else 'settings.json')
if target.is_symlink():
    raise SystemExit(1)
if app == 'codex':
    if target.exists():
        raise SystemExit(0)
    def jwt(body):
        def encode(value):
            return base64.urlsafe_b64encode(json.dumps(value, separators=(',', ':')).encode()).decode().rstrip('=')
        return encode({'alg': 'none'}) + '.' + encode(body) + '.unsigned'
    value = {'auth_mode': 'chatgpt', 'tokens': {'id_token': jwt({}),
        'access_token': jwt({'exp': 4102444800}), 'refresh_token': 'umbra-proxy-injected',
        'account_id': None}, 'last_refresh': datetime.datetime.now(datetime.timezone.utc).isoformat()}
else:
    value = json.loads(target.read_text()) if target.exists() else {}
    env = value.setdefault('env', {})
    if any(key in env for key in ('ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN')):
        raise SystemExit(0)
    env['CLAUDE_CODE_OAUTH_TOKEN'] = 'umbra-proxy-injected'
    if target.exists():
        backup = folder / 'settings.before-umbra-agent.json'
        fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as output:
            output.write(target.read_text())
pending = target.with_name(target.name + '.umbra-pending')
fd = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as output:
    json.dump(value, output)
    output.write('\n')
os.replace(pending, target)
'''


def prepare(app: str, path: Path, binding: dict) -> None:
    """Install dummy auth once, retaining existing guest agent settings."""
    if app not in {'codex', 'claude'}:
        raise LocalError('unsupported local agent')
    result = subprocess.run(['/usr/bin/ssh', '-F', str(path / 'ssh.conf'),
        f"umbra-local-{binding['name']}", shlex.join(['python3', '-c', GUEST_SETUP, app])],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    if result.returncode:
        raise LocalError('could not prepare guest agent settings; existing authentication was preserved')
