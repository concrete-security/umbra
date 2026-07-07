#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROJECT="concrete-dev-compose-smoke"
IMAGE_TAG="${DEV_CVM_COMPOSE_SMOKE_IMAGE:-concrete-dev-sandbox-smoke:check}"
TMPDIR="$(mktemp -d)"
STATUS=0

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
  if [ "$STATUS" -ne 0 ]; then
    docker compose -p "$PROJECT" -f "$ROOT/cvms/dev/docker-compose.yml" -f "$TMPDIR/compose.override.yml" ps >&2 || true
    docker compose -p "$PROJECT" -f "$ROOT/cvms/dev/docker-compose.yml" -f "$TMPDIR/compose.override.yml" logs --tail=120 >&2 || true
  fi
  docker compose -p "$PROJECT" -f "$ROOT/cvms/dev/docker-compose.yml" -f "$TMPDIR/compose.override.yml" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$TMPDIR"
}

trap 'STATUS=$?; cleanup; exit "$STATUS"' EXIT

if ! docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  "$ROOT/cvms/dev/tests/user_sandbox_image_smoke.sh"
fi

tunnel_port="$(free_port)"
ssh-keygen -q -t ed25519 -N '' -f "$TMPDIR/id_ed25519"
awk 'BEGIN{p=0}/BEGIN CERTIFICATE/{p=1}p{print}/END CERTIFICATE/{exit}' \
  /etc/ssl/certs/ca-certificates.crt >"$TMPDIR/ca.pem"
printf '{}\n' >"$TMPDIR/policy.json"
printf 'VERIFY_PLACEHOLDER=compose-smoke\n' >"$TMPDIR/placeholders"

# Most developer hosts do not have sysbox-runc registered. This local smoke keeps
# production networking and service entrypoints, but swaps only the sandbox OCI
# runtime so SSH/tunnel boot can be checked outside a dstack guest.
# The production compose file must stay byte-identical (its shade app_compose
# hash feeds CVM measurements), so the test-only listener healthchecks live
# here: compose >= 2.40 fails `up --wait` for containers without a healthcheck,
# and waiting on the listeners also keeps the probes below from racing boot.
cat >"$TMPDIR/compose.override.yml" <<YAML
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
YAML

export DEV_CVM_IMAGE="$IMAGE_TAG"
export SECURITY_CVM_CA_CERT_B64
SECURITY_CVM_CA_CERT_B64="$(base64 -w0 "$TMPDIR/ca.pem")"
export AUTHORIZED_SSH_KEYS_B64
AUTHORIZED_SSH_KEYS_B64="$(base64 -w0 "$TMPDIR/id_ed25519.pub")"
export SANDBOX_ENV_PLACEHOLDERS_B64
SANDBOX_ENV_PLACEHOLDERS_B64="$(base64 -w0 "$TMPDIR/placeholders")"
export SECURITY_CVM_FQDN="sc.example.com"
export SECURITY_CVM_PROXY_PORT="8080"
export SECURITY_CVM_ATLS_POLICY_B64
SECURITY_CVM_ATLS_POLICY_B64="$(base64 -w0 "$TMPDIR/policy.json")"
export SECURITY_CVM_PROXY_TOKEN="compose-smoke-token"
export DEV_CVM_CONTROL_TOKEN="compose-smoke-dev-control-token"

docker compose -p "$PROJECT" -f "$ROOT/cvms/dev/docker-compose.yml" -f "$TMPDIR/compose.override.yml" \
  up -d --wait --wait-timeout 60

docker compose -p "$PROJECT" -f "$ROOT/cvms/dev/docker-compose.yml" -f "$TMPDIR/compose.override.yml" \
  exec -T dev-tunnel bash -lc '
    set -euo pipefail
    umask 077
    cat >/tmp/id_ed25519
    ssh -i /tmp/id_ed25519 \
      -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null \
      -o IdentitiesOnly=yes \
      -o PasswordAuthentication=no \
      dev@user-sandbox '"'"'test "$(id -u)" = 1001 && test "$VERIFY_PLACEHOLDER" = compose-smoke && test -L /home/dev/.claude.json && python3 -m json.tool /home/dev/.claude.json >/dev/null'"'"'
  ' <"$TMPDIR/id_ed25519"

python3 - "$tunnel_port" <<'PY'
import base64
import os
import socket
import sys

port = int(sys.argv[1])
key = base64.b64encode(os.urandom(16)).decode("ascii")
with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
    sock.sendall(
        (
            "GET /concrete/tunnel HTTP/1.1\r\n"
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

echo "dev_compose_smoke: ok"
