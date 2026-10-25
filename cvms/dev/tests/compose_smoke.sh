#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
smoke_tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/umbra-dev-compose-smoke.XXXXXX")"
PROJECT="umbra-dev-compose-smoke-$(printf '%s' "${smoke_tmpdir##*.}" | tr '[:upper:]' '[:lower:]')"
compose_started=0
SMOKE_RUNTIME="${DEV_CVM_COMPOSE_SMOKE_RUNTIME:-runc}"
case "$SMOKE_RUNTIME" in
  runc) smoke_wait=60 ;;
  sysbox-runc)
    smoke_wait=180
    if [[ "${UMBRA_SYSBOX_QUALIFICATION_ARM:-}" = no-rootfs-cloning ]]; then smoke_wait=600; fi ;;
  *) echo "compose smoke: unsupported runtime" >&2; exit 2 ;;
esac
explicit_image=0
if [ "${DEV_CVM_COMPOSE_SMOKE_IMAGE+x}" = x ]; then
  IMAGE_TAG="$DEV_CVM_COMPOSE_SMOKE_IMAGE"
  explicit_image=1
else
  IMAGE_TAG="umbra-dev-sandbox-smoke:check"
fi

compose() {
  docker compose --env-file "$smoke_tmpdir/test.env" -p "$PROJECT" \
    -f "$ROOT/cvms/dev/docker-compose.yml" -f "$smoke_tmpdir/compose.override.yml" "$@"
}

free_port() {
  python3 - <<'PY'
import socket

sock = socket.socket()
sock.bind(("127.0.0.1", 0))
print(sock.getsockname()[1])
sock.close()
PY
}

cleanup() {
  local status="$1"
  local cleanup_status=0
  if [ "$compose_started" -eq 1 ]; then
    if [ "$status" -ne 0 ]; then
      compose ps >&2 || true
      compose logs --tail=120 >&2 || true
    fi
    if ! compose down -v --remove-orphans >/dev/null 2>&1; then
      echo "compose smoke: could not remove its test project" >&2
      cleanup_status=1
    fi
  fi
  if ! rm -rf -- "$smoke_tmpdir"; then
    cleanup_status=1
  fi
  return "$cleanup_status"
}

finish() {
  local status=$?
  trap - EXIT
  if ! cleanup "$status"; then
    status=1
  fi
  exit "$status"
}

trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if ! [[ "$IMAGE_TAG" =~ ^[A-Za-z0-9][A-Za-z0-9._:/@-]+$ ]]; then
  echo "compose smoke: invalid selected image reference" >&2
  exit 1
fi

if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  if [ "$explicit_image" -eq 1 ]; then
    echo "compose smoke: selected image is absent; pull the exact image before testing" >&2
    exit 1
  fi
  "$ROOT/cvms/dev/tests/user_sandbox_image_smoke.sh"
fi

tunnel_port="$(free_port)"
ssh-keygen -q -t ed25519 -N '' -f "$smoke_tmpdir/id_ed25519"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=umbra-compose-smoke-test-ca \
  -keyout "$smoke_tmpdir/ca.key" -out "$smoke_tmpdir/ca.pem" >/dev/null 2>&1
printf 'VERIFY_PLACEHOLDER=compose-smoke\n' >"$smoke_tmpdir/placeholders"

# Most developer hosts do not have sysbox-runc registered. This local smoke keeps
# production networking and service entrypoints, but swaps only the sandbox OCI
# runtime so SSH/tunnel boot can be checked outside a dstack guest. The opt-in
# Sysbox CI experiment keeps sysbox-runc and tests nested Docker below. Neither
# mode verifies TDX attestation.
# The production compose file must stay byte-identical (its shade app_compose
# hash feeds CVM measurements), so the test-only listener healthchecks live
# here: compose >= 2.40 fails `up --wait` for containers without a healthcheck,
# and waiting on the listeners also keeps the probes below from racing boot.
cat >"$smoke_tmpdir/compose.override.yml" <<YAML
services:
  user-sandbox:
    runtime: $SMOKE_RUNTIME
  dev-egress-forwarder:
    healthcheck:
      disable: false
      test: ["CMD", "python3", "-c", "import socket; socket.create_connection(('127.0.0.1', 3128), 1).close()"]
      interval: 500ms
      timeout: 2s
      start_period: 3s
      retries: 10
  dev-tunnel:
    ports:
      - "127.0.0.1:${tunnel_port}:8090"
    healthcheck:
      disable: false
      test: ["CMD", "python3", "-c", "import socket; socket.create_connection(('127.0.0.1', 8090), 1).close()"]
      interval: 500ms
      timeout: 2s
      start_period: 3s
      retries: 10
  smoke-origin:
    image: "$IMAGE_TAG"
    entrypoint: ["python3", "-u", "/opt/compose-smoke-origin.py"]
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    healthcheck:
      test: ["CMD", "python3", "-c", "import socket; socket.create_connection(('127.0.0.1', 18080), 1).close()"]
      interval: 500ms
      timeout: 2s
      start_period: 3s
      retries: 10
    volumes:
      - "$smoke_tmpdir/origin.py:/opt/compose-smoke-origin.py:ro"
    networks: [egress-uplink]
YAML

# Compose shell variables override --env-file values. Set every interpolation
# input explicitly, including the empty Console origin, before invoking it.
export DEV_CVM_IMAGE="$IMAGE_TAG"
export SECURITY_CVM_CA_CERT_B64
SECURITY_CVM_CA_CERT_B64="$(python3 -c 'import base64,sys; print(base64.b64encode(open(sys.argv[1], "rb").read()).decode())' "$smoke_tmpdir/ca.pem")"
export AUTHORIZED_SSH_KEYS_B64
AUTHORIZED_SSH_KEYS_B64="$(python3 -c 'import base64,sys; print(base64.b64encode(open(sys.argv[1], "rb").read()).decode())' "$smoke_tmpdir/id_ed25519.pub")"
export SANDBOX_ENV_PLACEHOLDERS_B64
SANDBOX_ENV_PLACEHOLDERS_B64="$(python3 -c 'import base64,sys; print(base64.b64encode(open(sys.argv[1], "rb").read()).decode())' "$smoke_tmpdir/placeholders")"
export SECURITY_CVM_FQDN="sc.invalid"
export SECURITY_CVM_PROXY_PORT="8080"
export SECURITY_CVM_PROXY_TOKEN="compose-smoke-token"
export DEV_CVM_CONTROL_TOKEN="compose-smoke-dev-control-token"
export DEV_TUNNEL_PATH="/umbra/tunnel,/legacy-cli/tunnel"
export CONSOLE_URL=""

# This explicit, test-only env file prevents Compose from loading the checkout's
# filled .env. No production credential or local CLI session enters the project.
python3 - "$smoke_tmpdir/test.env" <<'PY'
import os
import sys

names = (
    "DEV_CVM_IMAGE", "SECURITY_CVM_CA_CERT_B64", "AUTHORIZED_SSH_KEYS_B64",
    "SANDBOX_ENV_PLACEHOLDERS_B64", "SECURITY_CVM_FQDN", "SECURITY_CVM_PROXY_PORT",
    "SECURITY_CVM_PROXY_TOKEN", "DEV_CVM_CONTROL_TOKEN", "DEV_TUNNEL_PATH", "CONSOLE_URL",
)
with open(sys.argv[1], "x", encoding="utf-8") as handle:
    for name in names:
        handle.write(f"{name}={os.environ[name]}\n")
PY

cat >"$smoke_tmpdir/origin.py" <<'PY'
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

received = {}

class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/counter":
            body = json.dumps(received).encode()
        else:
            received[self.path] = received.get(self.path, 0) + 1
            body = b"compose-smoke-origin"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass

HTTPServer(("0.0.0.0", 18080), Origin).serve_forever()
PY
# The release job keeps a private umask; this public fixture must be readable
# by the image process after its capabilities are dropped.
chmod 0644 "$smoke_tmpdir/origin.py"

rendered_compose="$(
  compose config
)"
if [[ "$rendered_compose" == *SECURITY_CVM_ATLS_POLICY_B64* \
  || "$rendered_compose" == *SECURITY_CVM_ATLS_POLICY_GZIP_B64* ]]; then
  echo "compose smoke: full Security CVM policy must not be injected into any service" >&2
  exit 1
fi

compose_started=1
compose up -d --pull never --wait --wait-timeout "$smoke_wait"

if [[ "$SMOKE_RUNTIME" = sysbox-runc ]]; then
  # Exercise Sysbox's stop/start and exec paths with an owned persistent volume.
  compose exec -T --user dev user-sandbox sh -c \
    'umask 077; printf umbra-sysbox-restart > /home/dev/.umbra-sysbox-restart'
  compose restart --timeout 20 user-sandbox
  compose up -d --no-recreate --pull never --wait --wait-timeout "$smoke_wait"
  # shellcheck disable=SC2016 # Expand inside the restarted sandbox.
  compose exec -T --user dev user-sandbox sh -c \
    'test "$(cat /home/dev/.umbra-sysbox-restart)" = umbra-sysbox-restart && rm /home/dev/.umbra-sysbox-restart'
fi

run_checks() {
# The inner SSH command expands inside the sandbox, not in this script.
# shellcheck disable=SC2016
compose exec -T dev-tunnel bash -lc '
    set -euo pipefail
    umask 077
    cat >/tmp/id_ed25519
    ssh -i /tmp/id_ed25519 \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o IdentitiesOnly=yes \
      -o PasswordAuthentication=no \
      dev@user-sandbox '"'"'test "$(id -u)" = 1001 && test "$VERIFY_PLACEHOLDER" = compose-smoke && test -L /home/dev/.claude.json && python3 -m json.tool /home/dev/.claude.json >/dev/null'"'"'
  ' <"$smoke_tmpdir/id_ed25519"

# The origin has exactly one interface, on the forwarder's external bridge. Use
# its IP so a failed DNS lookup cannot masquerade as a blocked direct request.
origin_id="$(compose ps -q smoke-origin)"
origin_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$origin_id")"
python3 - "$origin_ip" <<'PY'
import ipaddress
import sys

ipaddress.IPv4Address(sys.argv[1])
PY

origin_control() {
  compose exec -T dev-egress-forwarder python3 - "$origin_ip" "$1" <<'PY'
import http.client
import json
import sys

host, phase = sys.argv[1:]
connection = http.client.HTTPConnection(host, 18080, timeout=5)
connection.request("GET", "/control")
response = connection.getresponse()
if response.status != 200 or response.read() != b"compose-smoke-origin":
    raise SystemExit("compose smoke: origin positive control failed")
connection.close()
if phase == "after":
    connection = http.client.HTTPConnection(host, 18080, timeout=5)
    connection.request("GET", "/counter")
    response = connection.getresponse()
    counts = json.loads(response.read())
    if response.status != 200 or counts != {"/control": 2}:
        raise SystemExit("compose smoke: a blocked request reached the controlled origin")
    connection.close()
PY
}

origin_control before

for sandbox_user in dev 0; do
  compose exec -T --user "$sandbox_user" user-sandbox python3 - "$origin_ip" "$sandbox_user" <<'PY'
import os
from pathlib import Path
import sys
import urllib.error
import urllib.request

host, role = sys.argv[1:]
for name in (
    "SECURITY_CVM_PROXY_TOKEN", "DEV_CVM_CONTROL_TOKEN", "SECURITY_CVM_ATLS_POLICY_B64",
    "SECURITY_CVM_ATLS_POLICY_GZIP_B64", "DEV_EGRESS_ATLS_CONNECT_CMD",
):
    if name in os.environ:
        raise SystemExit("compose smoke: forwarder-only environment reached the sandbox")
for path in (
    "/run/umbra/proxy-token", "/run/umbra/security-cvm.atls-policy.json",
    "/run/umbra/security-cvm.atls-policy.refresh.json", "/var/run/dstack.sock",
):
    if Path(path).exists():
        raise SystemExit("compose smoke: forwarder-only material reached the sandbox")

# ProxyHandler({}) suppresses every inherited proxy variable for this request.
direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
try:
    with direct.open(f"http://{host}:18080/denied-{role}", timeout=3):
        pass
except urllib.error.HTTPError:
    # An HTTP denial still proves direct contact with the controlled origin.
    raise SystemExit("compose smoke: direct sandbox request received an HTTP response")
except (urllib.error.URLError, OSError):
    pass
else:
    raise SystemExit("compose smoke: sandbox bypassed the forwarder")
PY
done

# Exercise the real forwarder listener without a helper substitute or a supplied
# policy. A missing authenticated bootstrap must deny CONNECT before success or
# application-byte delivery. CONSOLE_URL is deliberately empty in this project.
compose exec -T --user dev user-sandbox python3 - "$origin_ip" <<'PY'
import socket
import sys

target = f"{sys.argv[1]}:18080"
with socket.create_connection(("dev-egress-forwarder", 3128), timeout=5) as connection:
    connection.sendall(
        (f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n"
         f"GET /denied-connect HTTP/1.1\r\nHost: {target}\r\n\r\n").encode("ascii")
    )
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = connection.recv(4096)
        if not chunk:
            raise SystemExit("compose smoke: forwarder closed without its fail-closed response")
        response += chunk
        if len(response) > 65536:
            raise SystemExit("compose smoke: oversized forwarder response")
    if response.split(b"\r\n", 1)[0] != b"HTTP/1.1 502 Bad Gateway":
        raise SystemExit("compose smoke: missing attestation policy did not deny CONNECT with 502")
PY

# Correlate the denial with the bootstrap check: an unreachable SC can also
# return 502, without proving that policy bootstrap stopped this CONNECT.
compose logs --no-log-prefix --no-color dev-egress-forwarder | python3 -c '
import sys

target = f"{sys.argv[1]}:18080"
expected = (
    f" destination={target!r}"
    " reason=Security CVM aTLS policy fetch requires CONSOLE_URL"
)
lines = sys.stdin.read().splitlines()
if not any(" connection_error " in line and line.rstrip().endswith(expected) for line in lines):
    raise SystemExit("compose smoke: CONNECT denial did not come from the missing-policy bootstrap check")
' "$origin_ip"

if [ "$SMOKE_RUNTIME" = sysbox-runc ]; then
  python3 "$ROOT/cvms/dev/tests/nested_docker_smoke.py" \
    --sandbox "$(compose ps -q user-sandbox)" \
    --image "${UMBRA_NESTED_TEST_IMAGE:?set a pre-pulled nested image digest}" \
    --expect "${UMBRA_NESTED_EXPECT:?set success or unsafe-procfs}" \
    --origin "$origin_ip" \
    --control "$(compose exec -T user-sandbox getent ahostsv4 dev-egress-forwarder | awk 'NR == 1 { print $1 }')" \
    --receipt "${UMBRA_NESTED_RECEIPT:?set a fresh receipt path}"
fi

origin_control after

# The canonical path and a configured alias must both relay.
for tunnel_path in /umbra/tunnel /legacy-cli/tunnel; do
python3 - "$tunnel_port" "$tunnel_path" <<'PY'
import base64
import os
import socket
import sys

port = int(sys.argv[1])
path = sys.argv[2]
key = base64.b64encode(os.urandom(16)).decode("ascii")
with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
    sock.sendall(
        (
            f"GET {path} HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        ).encode("ascii")
    )
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            raise SystemExit("websocket closed before handshake")
        response += chunk
    if b"101 Switching Protocols" not in response:
        raise SystemExit(f"unexpected websocket response: {response!r}")

    header = sock.recv(2)
    if len(header) != 2 or header[0] & 0x0F != 2:
        raise SystemExit("did not receive binary SSH banner frame")
    length = header[1] & 0x7F
    if length == 126:
        length = int.from_bytes(sock.recv(2), "big")
    elif length == 127:
        length = int.from_bytes(sock.recv(8), "big")
    payload = b""
    while len(payload) < length:
        chunk = sock.recv(length - len(payload))
        if not chunk:
            raise SystemExit("websocket closed before SSH banner")
        payload += chunk
    if not payload.startswith(b"SSH-"):
        raise SystemExit(f"unexpected tunnel payload: {payload!r}")
PY
done

}

run_checks

if [[ -n "${UMBRA_SYSBOX_HANDOVER_DIR:-}" ]]; then
  # Only the disposable qualification runner may cold-stop the host runtime.
  [[ "${GITHUB_ACTIONS:-}" = true && "${RUNNER_ENVIRONMENT:-}" = github-hosted \
    && "$(uname -s)" = Linux && "$(uname -m)" = x86_64 && "$SMOKE_RUNTIME" = sysbox-runc \
    && "$UMBRA_SYSBOX_HANDOVER_DIR" = "${RUNNER_TEMP:?}/sysbox-compatibility/${UMBRA_SYSBOX_QUALIFICATION_ARM:?}/handover" ]]
  case "${UMBRA_SYSBOX_QUALIFICATION_ARM}:${UMBRA_SYSBOX_HANDOVER_EXPECT:-}" in
    default-clone:rootfs-loss|no-rootfs-cloning:preserved) ;;
    *) echo 'unsupported Sysbox handover expectation' >&2; exit 2 ;;
  esac
  mkdir "$UMBRA_SYSBOX_HANDOVER_DIR"
  printf 'passed\n' > "$UMBRA_SYSBOX_HANDOVER_DIR/baseline-passed"

  # One collector seeds only the old runtime. The candidate path only reads;
  # state loss must fail before the ordinary nested smoke can reload its image.
  cat > "$smoke_tmpdir/handover-state.py" <<'PY'
import json
from pathlib import Path
import subprocess
import sys
import time

phase, project, output, baseline, expectation = sys.argv[1:]
if phase not in ("before", "after"):
    raise SystemExit("invalid handover phase")
if expectation not in ("preserved", "rootfs-loss"):
    raise SystemExit("invalid handover expectation")

def run(args, **kwargs):
    try:
        return subprocess.run(args, check=True, capture_output=True, text=True, timeout=30, **kwargs).stdout
    except subprocess.CalledProcessError as error:
        # This project contains only synthetic runner fixtures. Retain a bounded
        # diagnostic before cleanup removes the failed container and its data.
        diagnostic = (error.stderr or "")[-4096:]
        with Path(output, "failed-command-" + phase + ".txt").open("x") as handle:
            handle.write(diagnostic)
        print(diagnostic, file=sys.stderr)
        raise

ids = run(["docker", "ps", "-aq", "--no-trunc", "--filter", f"label=com.docker.compose.project={project}"]).split()
if len(ids) != 4:
    raise SystemExit("handover requires all four existing containers")
deadline = time.monotonic() + 600
while True:
    rows = json.loads(run(["docker", "inspect", *ids]))
    if all(row["State"]["Status"] == "running" and
           row["State"].get("Health", {}).get("Status") == "healthy" for row in rows):
        break
    if any(row["State"]["Status"] in ("dead", "exited") or
           row["State"].get("Health", {}).get("Status") == "unhealthy" for row in rows):
        raise SystemExit("handover service failed to become healthy")
    if time.monotonic() >= deadline:
        raise SystemExit("handover services did not become healthy within 600 seconds")
    time.sleep(1)
services = {}
sandbox = None
for row in rows:
    service = row["Config"]["Labels"]["com.docker.compose.service"]
    if service in services or row["State"]["Status"] != "running":
        raise SystemExit("handover requires distinct running services")
    services[service] = {
        "id": row["Id"], "image_id": row["Image"], "runtime": row["HostConfig"]["Runtime"],
        "named_volumes": sorted([
            {key: mount[key] for key in ("Name", "Destination", "RW")}
            for mount in row["Mounts"] if mount["Type"] == "volume"
        ], key=lambda item: item["Destination"]),
    }
    if service == "user-sandbox":
        sandbox = row
if set(services) != {"user-sandbox", "dev-egress-forwarder", "dev-tunnel", "smoke-origin"}:
    raise SystemExit("unexpected handover service set")
rootfs_marker = "/usr/local/share/umbra-sysbox-handover"
if any(rootfs_marker == m["Destination"] or rootfs_marker.startswith(m["Destination"].rstrip("/") + "/")
       for m in sandbox["Mounts"]):
    raise SystemExit("rootfs fixture must be outside every mounted volume and tmpfs")
volumes = {m["Destination"]: m for m in sandbox["Mounts"] if m["Type"] == "volume"}
if any(path not in volumes or volumes[path]["RW"] is not True
       for path in ("/home/dev", "/home/dev/workspaces", "/var/lib/docker")):
    raise SystemExit("handover requires the production writable named volumes")
if phase == "after":
    previous = json.loads(Path(output, "before.json").read_text())
    if services != previous["services"]:
        raise SystemExit("cold handover recreated containers or changed image/runtime/volume bindings")
pid = sandbox["State"]["Pid"]
root_mounts = [line for line in run(["sudo", "cat", f"/proc/{pid}/mountinfo"]).splitlines()
               if line.split()[4] == "/"]
if len(root_mounts) != 1 or len(root_mounts[0]) > 16384:
    raise SystemExit("missing or oversized init root mount evidence")
# Retain the actual backing mount even if the fixture check below finds loss.
with Path(output, "init-root-" + phase + ".txt").open("x") as handle:
    handle.write(root_mounts[0] + "\n")
clone_upper = f"upperdir=/var/lib/sysbox/rootfs/{sandbox['Id']}/"
if ("upperdir=/var/lib/sysbox/rootfs/" in root_mounts[0]) != (expectation == "rootfs-loss"):
    raise SystemExit("actual rootfs backing does not match the selected cloning arm")
if expectation == "rootfs-loss" and clone_upper not in root_mounts[0]:
    raise SystemExit("cloned rootfs does not belong to the retained sandbox")

script = r'''
import hashlib, json, os, stat, sys
files = {
    "/usr/local/share/umbra-sysbox-handover": ("rootfs", 0, 0, 0o600),
    "/home/dev/.umbra-sysbox-handover": ("home", 1001, 1001, 0o600),
    "/home/dev/workspaces/.umbra-sysbox-handover": ("workspaces", 1001, 1001, 0o640),
    "/var/lib/docker/.umbra-sysbox-handover": ("docker-data", 0, 0, 0o600),
}
result = {}
for path, (label, uid, gid, mode) in files.items():
    content = ("umbra-cold-handover-" + label + "\n").encode()
    if sys.argv[1] == "before":
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fchown(handle.fileno(), uid, gid)
            os.fchmod(handle.fileno(), mode)
            os.fsync(handle.fileno())
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError as error:
        if sys.argv[1:] == ["after", "rootfs-loss"] and label == "rootfs":
            result[path] = {"missing": True, "error": str(error), "errno": error.errno}
            continue
        raise
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        actual = handle.read(1024)
    if not stat.S_ISREG(info.st_mode) or actual != content or (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) != (uid, gid, mode):
        raise SystemExit("cold handover fixture changed: " + label)
    result[path] = {"sha256": hashlib.sha256(actual).hexdigest(), "uid": info.st_uid,
                    "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode), "size": info.st_size}
print(json.dumps(result, sort_keys=True))
'''
fixtures = json.loads(run(["docker", "exec", "-i", "--user", "0", sandbox["Id"], "python3", "-", phase, expectation], input=script))
if phase == "after":
    missing = [path for path, record in fixtures.items() if record.get("missing")]
    if missing != ([rootfs_marker] if expectation == "rootfs-loss" else []):
        raise SystemExit("handover did not reproduce exactly the expected rootfs outcome")
    if missing:
        Path(output, "expected-rootfs-loss.txt").write_text(fixtures[rootfs_marker]["error"] + "\n")
# This records the actual overlay upperdir/clone backing, not an inference from
# the manager option. Kernel paths contain only this disposable runner's state.
inner = ["docker", "exec", "--user", "dev", sandbox["Id"], "docker"]
for attempt in range(60):
    if subprocess.run([*inner, "info"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                      timeout=10, check=False).returncode == 0:
        break
    time.sleep(1)
else:
    raise SystemExit("inner Docker did not become ready after cold handover")
expected_image = json.loads(Path(baseline).read_text())["nested_image_id"]
loaded = json.loads(run([*inner, "image", "inspect", expected_image]))
if len(loaded) != 1 or loaded[0]["Id"] != expected_image:
    raise SystemExit("cold handover lost the previously imported inner image")
# Read every retained layer before run_checks can import the image again.
# Metadata alone would miss lost content that the later load could repair.
subprocess.run([*inner, "image", "save", expected_image], stdout=subprocess.DEVNULL,
               stderr=subprocess.PIPE, timeout=120, check=True)
state = {"services": services, "fixtures": fixtures, "inner_image_id": loaded[0]["Id"],
         "inner_image_content_readable": True,
         "init_root_mount": root_mounts[0], "init_pid": pid, "expectation": expectation}
if phase == "after":
    retained_paths = set(fixtures) - ({rootfs_marker} if expectation == "rootfs-loss" else set())
    if any(fixtures[path] != previous["fixtures"][path] for path in retained_paths) or loaded[0]["Id"] != previous["inner_image_id"]:
        raise SystemExit("cold handover changed populated state")
with Path(output, phase + ".json").open("x") as handle:
    json.dump(state, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
  python3 "$smoke_tmpdir/handover-state.py" before "$PROJECT" "$UMBRA_SYSBOX_HANDOVER_DIR" "$UMBRA_NESTED_RECEIPT" "$UMBRA_SYSBOX_HANDOVER_EXPECT"
  compose stop --timeout 20
  bash "$ROOT/ops/verify/sysbox-compatibility.sh" switch-runtime "$PROJECT"
  # start cannot recreate a container. Do not use up, restore, or reseed here.
  compose start
  python3 "$smoke_tmpdir/handover-state.py" after "$PROJECT" "$UMBRA_SYSBOX_HANDOVER_DIR" "$UMBRA_NESTED_RECEIPT" "$UMBRA_SYSBOX_HANDOVER_EXPECT"
  export UMBRA_NESTED_EXPECT=success
  export UMBRA_NESTED_RECEIPT="$UMBRA_SYSBOX_HANDOVER_DIR/nested-candidate.json"
  run_checks
  python3 - "$UMBRA_SYSBOX_HANDOVER_DIR" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
before = json.loads((root / "before.json").read_text())
after = json.loads((root / "after.json").read_text())
receipt = {
    "status": "passed", "same_container_ids": {key: value["id"] for key, value in before["services"].items()},
    "rootfs_outcome": after["expectation"],
    "same_image_runtime_and_named_volume_bindings": before["services"] == after["services"],
    "preserved_files": after["fixtures"], "preserved_inner_image_id": after["inner_image_id"],
    "inner_image_content_readable_before_reload": before["inner_image_content_readable"] and after["inner_image_content_readable"],
    "old_init_root_mount": before["init_root_mount"], "candidate_init_root_mount": after["init_root_mount"],
    "baseline_nested_container_start": "unsafe-procfs control" if after["expectation"] == "rootfs-loss" else "none and bridge passed",
    "candidate_fresh_nested_containers": "none and bridge passed; direct bridge egress denied",
    "not_exercised": ["migration of already-cloned rootfs", "running nested container migration", "arbitrary user data recovery", "dstack boot", "TDX attestation", "KMS key continuity"],
}
with (root / "handover.json").open("x") as handle:
    json.dump(receipt, handle, indent=2)
    handle.write("\n")
PY
fi

echo "dev_compose_smoke: ok"
