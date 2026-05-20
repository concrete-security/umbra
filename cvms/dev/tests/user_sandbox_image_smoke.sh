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
  test -s /usr/local/lib/concrete/claude.version
  test -f /usr/local/lib/node_modules/@openai/codex/bin/codex.js
  shadow_password="$(getent shadow dev | cut -d: -f2)"
  case "${shadow_password}" in
    ""|!*)
      echo "dev account shadow password field must not be empty or locked" >&2
      exit 1
      ;;
  esac
  apt-config dump | grep -F '"'"'Acquire::http::Proxy "http://dev-egress-forwarder:3128";'"'"' >/dev/null
  apt-config dump | grep -F '"'"'Acquire::https::Proxy "http://dev-egress-forwarder:3128";'"'"' >/dev/null
  apt-config dump | grep -F '"'"'Acquire::https::CaInfo "/run/concrete/ca-bundle.pem";'"'"' >/dev/null
  sudo_env="$(
    su dev -c '"'"'HTTP_PROXY=http://proxy.local:3128 HTTPS_PROXY=http://proxy.local:3128 http_proxy=http://proxy.local:3128 https_proxy=http://proxy.local:3128 NO_PROXY=localhost no_proxy=localhost REQUESTS_CA_BUNDLE=/run/concrete/ca-bundle.pem SSL_CERT_FILE=/run/concrete/ca-bundle.pem CURL_CA_BUNDLE=/run/concrete/ca-bundle.pem GIT_SSL_CAINFO=/run/concrete/ca-bundle.pem NODE_EXTRA_CA_CERTS=/run/concrete/ca-bundle.pem sudo env'"'"'
  )"
  grep -Fx '"'"'HTTP_PROXY=http://proxy.local:3128'"'"' <<<"${sudo_env}" >/dev/null
  grep -Fx '"'"'HTTPS_PROXY=http://proxy.local:3128'"'"' <<<"${sudo_env}" >/dev/null
  grep -Fx '"'"'http_proxy=http://proxy.local:3128'"'"' <<<"${sudo_env}" >/dev/null
  grep -Fx '"'"'https_proxy=http://proxy.local:3128'"'"' <<<"${sudo_env}" >/dev/null
  grep -Fx '"'"'REQUESTS_CA_BUNDLE=/run/concrete/ca-bundle.pem'"'"' <<<"${sudo_env}" >/dev/null
  grep -Fx '"'"'SSL_CERT_FILE=/run/concrete/ca-bundle.pem'"'"' <<<"${sudo_env}" >/dev/null
  grep -Fx '"'"'CURL_CA_BUNDLE=/run/concrete/ca-bundle.pem'"'"' <<<"${sudo_env}" >/dev/null
  claude --version >/dev/null
  codex --version >/dev/null
  node --version | grep -q "^v22\\."
'

echo "user_sandbox_image_smoke: ok"
