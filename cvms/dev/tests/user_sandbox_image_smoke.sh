#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
IMAGE_TAG="concrete-dev-sandbox-smoke:check"

docker build \
  --file "${ROOT}/cvms/dev/user-sandbox/Dockerfile" \
  --tag "${IMAGE_TAG}" \
  "${ROOT}"

docker run --rm --entrypoint bash "${IMAGE_TAG}" -lc '
  set -euo pipefail
  for cmd in claude codex node npm gh uv; do
    command -v "${cmd}" >/dev/null
  done
  test -x /usr/local/lib/concrete/claude.real
  test -f /usr/local/lib/node_modules/@openai/codex/bin/codex.js
  claude --version >/dev/null
  codex --version >/dev/null
  node --version | grep -q "^v22\\."
'

echo "user_sandbox_image_smoke: ok"
