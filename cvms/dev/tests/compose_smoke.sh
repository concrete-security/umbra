#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
smoke_tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/umbra-dev-compose-smoke.XXXXXX")"
PROJECT="umbra-dev-compose-smoke-$(printf '%s' "${smoke_tmpdir##*.}" | tr '[:upper:]' '[:lower:]')"
compose_started=0
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
# runtime so SSH/tunnel boot can be checked outside a dstack guest. Sysbox's
# user-namespace isolation and TDX attestation are not verified by this test.
# The production compose file must stay byte-identical (its shade app_compose
# hash feeds CVM measurements), so the test-only listener healthchecks live
# here: compose >= 2.40 fails `up --wait` for containers without a healthcheck,
# and waiting on the listeners also keeps the probes below from racing boot.
cat >"$smoke_tmpdir/compose.override.yml" <<YAML
services:
  user-sandbox:
    runtime: runc
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
compose up -d --pull never --wait --wait-timeout 60

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

echo "dev_compose_smoke: ok"
