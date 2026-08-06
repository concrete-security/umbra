#!/usr/bin/env bash
set -euo pipefail

# Runs the opt-in real-Postgres integration tests against a throwaway Postgres
# container. The console pytest suite is otherwise DB-less (fake connections), so
# these tests skip unless UMBRA_TEST_DATABASE_URL is set. This script boots an
# ephemeral server, points the tests at it, and tears it down — keeping the plain
# `make test` gate DB-free while making the migration/query coverage runnable in
# one command. The throwaway server is fully isolated; no existing data is touched.
#
# Usage: ops/db/run-console-db-tests.sh [pytest target ...]
#   defaults to console/tests/test_sc_control_integration_db.py

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${UMBRA_TEST_PG_IMAGE:-postgres:16@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20}"
NAME="umbra-console-db-tests-$$"

if [ "$#" -gt 0 ]; then
  TARGETS=("$@")
else
  TARGETS=("console/tests/test_sc_control_integration_db.py")
fi

command -v docker >/dev/null 2>&1 || {
  echo "docker is required to run the console DB integration tests" >&2
  exit 2
}

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "Starting ephemeral Postgres ($IMAGE) ..." >&2
docker run -d --rm --name "$NAME" \
  -e POSTGRES_USER=umbra -e POSTGRES_PASSWORD=umbra -e POSTGRES_DB=umbra \
  -p 127.0.0.1::5432 "$IMAGE" >/dev/null

HOST_PORT="$(docker port "$NAME" 5432/tcp | head -n1 | sed 's/.*://')"
[ -n "$HOST_PORT" ] || {
  echo "could not determine the mapped Postgres port" >&2
  exit 1
}

echo "Waiting for Postgres readiness ..." >&2
ready=""
for _ in $(seq 1 60); do
  if docker exec "$NAME" pg_isready -U umbra -d umbra >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
[ -n "$ready" ] || {
  echo "Postgres did not become ready in time" >&2
  exit 1
}

export UMBRA_TEST_DATABASE_URL="postgresql://umbra:umbra@127.0.0.1:${HOST_PORT}/umbra"
echo "Running pytest against $UMBRA_TEST_DATABASE_URL" >&2
cd "$ROOT"
uv run --locked --project console python -m pytest "${TARGETS[@]}"
