#!/usr/bin/env python3
"""Opt-in real Apple VM acceptance test with a synthetic Console/transport workers.

Exercises native boot, SSH, folder imports, persistence and fail-closed shutdown.
Does not authenticate to a Console or prove production attestation or Security CVM policy enforcement.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import platform
import shlex
import signal
import subprocess
import tempfile
import threading
import time


def run(argv, *, cwd=None, env=None, timeout=180):
    result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {result.stderr[-4000:]}")
    return result


class Proxy(http.server.BaseHTTPRequestHandler):
    def do_CONNECT(self):
        self.send_response(403 if self.headers.get("Proxy-Authorization") == "Bearer " + "t" * 43 else 407)
        self.end_headers()

    def do_GET(self):
        if self.headers.get("Proxy-Authorization") != "Bearer " + "t" * 43:
            self.send_error(407)
            return
        if self.path.endswith("/blocked"):
            self.send_error(403)
            return
        payload = b"umbra-vsock-smoke\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def check(args, temporary):
    root = Path(temporary).resolve()
    config = root / "config"
    source = root / "project"
    source.mkdir()
    (source / "src").mkdir()
    (source / ".git").mkdir()
    (source / ".git/config").write_text("# smoke fixture\n")
    (source / ".env").write_text("SMOKE_FIXTURE=not-a-secret\n")
    (source / "untracked").write_text("initial\n")
    (source / "executable").write_text("#!/bin/sh\nprintf executable-ok\\n\n")
    (source / "executable").chmod(0o755)
    (source / "relative-link").symlink_to("untracked")
    environment = {k: v for k, v in os.environ.items() if not k.startswith("UMBRA_")}
    environment["UMBRA_NO_UPDATE_CHECK"] = "1"
    run([str(Path(__file__).parent / "install-runtime.sh"), "--config", str(config)], env=environment)
    python = config / "local-tools/bin/python3"
    run(["/usr/bin/openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=Umbra local smoke fixture", "-keyout", str(root / "ca.key"), "-out", str(root / "ca.pem")])
    proxy = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    fixture = root / "fixture"
    fixture.write_text(f'''#!{python} -I
import datetime, hashlib, json, os, select, socket, sys
from pathlib import Path
request = json.loads(sys.stdin.buffer.readline())
if sys.argv[-1] == "local-control":
    if Path({str(root / 'fail-authorization')!r}).exists() and request["operation"] == "renew":
        sys.exit(1)
    if request["operation"] == "revoke":
        print('{{"revoked":true}}')
    else:
        ca = Path({str(root / 'ca.pem')!r}).read_text()
        result = {{"id":"11111111-1111-4111-8111-111111111111", "security_cvm_id":"22222222-2222-4222-8222-222222222222",
            "security_cvm_fqdn":"fixture.invalid", "atls_policy":{{"fixture":True}}, "ca_pem":ca,
            "ca_sha256":hashlib.sha256(ca.encode()).hexdigest(),
            "expires_at":(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(seconds=300)).isoformat()}}
        if request["operation"] == "create": result["proxy_token"] = "t" * 43
        print(json.dumps(result))
else:
    peer = socket.create_connection(("127.0.0.1", {proxy.server_port}))
    print('{{"ready":true}}', flush=True)
    while True:
        readable, _, _ = select.select([peer, sys.stdin.buffer], [], [])
        for item in readable:
            data = peer.recv(65536) if item is peer else os.read(sys.stdin.fileno(),65536)
            if not data: sys.exit(0)
            if item is peer:
                sys.stdout.buffer.write(data); sys.stdout.buffer.flush()
            else: peer.sendall(data)
''')
    fixture.chmod(0o700)
    cli = [str(args.umbra), "--config", str(config)]
    worker = [str(python), "-I", "-m", "umbra_local.cli", "--config", str(config), "--umbra", str(fixture), "--json"]

    def command(script, *, cwd=source):
        return run(cli + ["ssh", "--command", script], cwd=cwd, env=environment).stdout.strip()

    def start():
        return json.loads(run(worker + ["project-start", "--path", str(source), "--preview", "--profile", "33333333-3333-4333-8333-333333333333",
                                       "--bundle", str(args.bundle)], env=environment).stdout)

    def status():
        return json.loads(run(cli + ["--json", "status"], cwd=source, env=environment).stdout)

    try:
        print("Booting real Virtualization.framework VM with synthetic Console and attested-transport fixtures...", flush=True)
        assert start()["state"] == "running"
        assert status()["assurance"] == "local-preview"
        assert command("uname -m") == "aarch64"
        assert command("codex --version").startswith("codex-cli ")
        # Exercise the desktop's SSH login environment and named connection,
        # without opening apps or modifying the real user's SSH/Claude settings.
        desktop_check = """
from pathlib import Path
import json, subprocess, sys
from umbra_local import desktop
config, home = map(Path, sys.argv[1:])
home.mkdir(mode=0o700)
binding = json.loads((config / 'local-projects.json').read_text())['projects'][0]
path = config / 'local' / binding['name']
desktop.check_guest('codex', path, binding, '/home/dev/workspaces/project')
alias = desktop.register_ssh(path, binding, home)
settings = home / '.ssh/config'
settings.write_text(settings.read_text().replace('~/.ssh', str(home / '.ssh')))
result = subprocess.check_output(['/usr/bin/ssh', '-F', str(settings), alias, 'uname -m'], text=True)
assert result.strip() == 'aarch64'
"""
        run([str(python), '-I', '-c', desktop_check, str(config), str(root / 'desktop-home')], env=environment)
        print("Verified desktop SSH alias and guest login proxy/CA environment (apps not opened).", flush=True)
        assert command("pwd", cwd=source / "src") == "/home/dev/workspaces/project/src"
        assert command("test -x executable && test -f .git/config && test -f .env && cat relative-link") == "initial"
        assert command("ls /sys/class/net") == "lo"
        assert command("curl --fail --silent --max-time 10 http://fixture.invalid/") == "umbra-vsock-smoke"
        assert command("curl --silent --output /dev/null --write-out '%{http_code}' http://fixture.invalid/blocked") == "403"
        command("mkdir -p .venv/bin && ln -s /usr/bin/python3 .venv/bin/python3")
        command("if curl --noproxy '*' --silent --connect-timeout 2 http://192.0.2.1/; then exit 1; fi")
        print("Verified guest boot, no NIC, SSH, whole-folder import, and vsock proxy.", flush=True)
        (source / "untracked").write_text("host-update\n")
        assert command("cat untracked") == "host-update"
        command("printf 'guest-edit\\n' > untracked; printf 'guest-only\\n' > guest-only")
        assert command("cat untracked") == "guest-edit"
        (source / "untracked").write_text("host-conflict\n")
        assert command("cat untracked") == "guest-edit"
        assert (source / "untracked").read_text() == "host-conflict\n"
        assert not (source / "guest-only").exists()
        (source / "untracked").write_text("guest-edit\n")
        assert command("cat untracked") == "guest-edit"
        run(cli + ["--json", "stop", "local"], cwd=source, env=environment)
        assert status()["state"] == "stopped"
        assert start()["state"] == "running"
        assert command("cat guest-only") == "guest-only"
        print("Verified host updates, conflict preservation, and stop/resume persistence.", flush=True)
        # A bounded payload verifies guest console logging cannot grow without limit.
        command("sudo python3 -c \"open('/dev/hvc0','wb').write(b'x' * 1572864)\"")
        time.sleep(1)
        assert all(p.stat().st_size < 1100000 for p in (config / "local").glob("*/service.log"))
        (root / "fail-authorization").touch()
        for _ in range(150):
            if status()["state"] == "stopped":
                break
            time.sleep(0.5)
        else:
            raise RuntimeError("VM remained running after authorization renewal failed")
        assert status()["reason"] == "authorization-or-vm-disconnected"
        print("PASS: failed authorization stopped the VM; no live Console or Security CVM was used.", flush=True)
    except BaseException:
        for path in (config / "local").glob("*/service.log"):
            print(path.read_text(errors="replace")[-6000:], flush=True)
        raise
    finally:
        # Stop through the authenticated local control socket before removing test files.
        result = subprocess.run(cli + ["stop", "local"], cwd=source, env=environment,
                                capture_output=True, timeout=60)
        proxy.shutdown()
        proxy.server_close()
        thread.join(timeout=5)
        if result.returncode:
            print("Test cleanup could not confirm VM stop; inspect " + str(config), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--umbra", required=True, type=Path)
    parser.add_argument("--bundle", required=True, type=Path)
    args = parser.parse_args()
    args.umbra = args.umbra.resolve(strict=True)
    args.bundle = args.bundle.resolve(strict=True)
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        parser.error("requires an Apple-silicon Mac")
    with tempfile.TemporaryDirectory(prefix="ul-smoke-", dir="/tmp") as temporary:
        check(args, temporary)


if __name__ == "__main__":
    main()
