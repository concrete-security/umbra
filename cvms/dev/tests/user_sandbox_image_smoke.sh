#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
if [ "${DEV_CVM_IMAGE_SMOKE_IMAGE+x}" = x ]; then
  IMAGE_TAG="$DEV_CVM_IMAGE_SMOKE_IMAGE"
  # A release-image test must exercise the selected bytes and never replace
  # a missing artifact with a fresh source build.
  if [ -z "$IMAGE_TAG" ]; then
    echo "release-image smoke requires a non-empty selected image" >&2
    exit 1
  fi
  docker image inspect "$IMAGE_TAG" >/dev/null
else
  IMAGE_TAG="umbra-dev-sandbox-smoke:check"
  docker build \
    --platform linux/amd64 \
    --file "${ROOT}/cvms/dev/user-sandbox/Dockerfile" \
    --tag "${IMAGE_TAG}" \
    "${ROOT}"
fi

docker run --rm --network none --platform linux/amd64 --entrypoint bash "${IMAGE_TAG}" -lc '
  set -euo pipefail
  for cmd in claude codex node npm gh uv docker dockerd containerd; do
    command -v "${cmd}" >/dev/null
  done
  read -r linux_headers_package linux_headers_version < <(dpkg-query --show linux-libc-dev)
  dpkg --compare-versions "$linux_headers_version" ge 6.8.0-142.142
  test -x /usr/local/lib/umbra/claude.real
  test -s /usr/local/lib/umbra/claude.version
  test -f /usr/local/lib/umbra/codex/node_modules/@openai/codex/bin/codex.js
  shadow_password="$(getent shadow dev | cut -d: -f2)"
  case "${shadow_password}" in
    ""|!*)
      echo "dev account shadow password field must not be empty or locked" >&2
      exit 1
      ;;
  esac
  test -z "$(getent shadow dev | cut -d: -f3)"
  test -z "$(getent shadow sshd | cut -d: -f3)"
  if compgen -G "/etc/ssh/ssh_host_*" >/dev/null; then
    echo "build-time SSH host keys must not be present in the image" >&2
    exit 1
  fi
  apt-config dump | grep -F '"'"'Acquire::http::Proxy "http://dev-egress-forwarder:3128";'"'"' >/dev/null
  apt-config dump | grep -F '"'"'Acquire::https::Proxy "http://dev-egress-forwarder:3128";'"'"' >/dev/null
  apt-config dump | grep -F '"'"'Acquire::https::CaInfo "/run/umbra/ca-bundle.pem";'"'"' >/dev/null
  sudo_env="$(
    su dev -c '"'"'HTTP_PROXY=http://proxy.local:3128 HTTPS_PROXY=http://proxy.local:3128 http_proxy=http://proxy.local:3128 https_proxy=http://proxy.local:3128 NO_PROXY=localhost no_proxy=localhost REQUESTS_CA_BUNDLE=/run/umbra/ca-bundle.pem SSL_CERT_FILE=/run/umbra/ca-bundle.pem CURL_CA_BUNDLE=/run/umbra/ca-bundle.pem GIT_SSL_CAINFO=/run/umbra/ca-bundle.pem NODE_EXTRA_CA_CERTS=/run/umbra/ca-bundle.pem sudo env'"'"'
  )"
  grep -Fx '"'"'HTTP_PROXY=http://proxy.local:3128'"'"' <<<"${sudo_env}" >/dev/null
  grep -Fx '"'"'HTTPS_PROXY=http://proxy.local:3128'"'"' <<<"${sudo_env}" >/dev/null
  grep -Fx '"'"'http_proxy=http://proxy.local:3128'"'"' <<<"${sudo_env}" >/dev/null
  grep -Fx '"'"'https_proxy=http://proxy.local:3128'"'"' <<<"${sudo_env}" >/dev/null
  grep -Fx '"'"'REQUESTS_CA_BUNDLE=/run/umbra/ca-bundle.pem'"'"' <<<"${sudo_env}" >/dev/null
  grep -Fx '"'"'SSL_CERT_FILE=/run/umbra/ca-bundle.pem'"'"' <<<"${sudo_env}" >/dev/null
  grep -Fx '"'"'CURL_CA_BUNDLE=/run/umbra/ca-bundle.pem'"'"' <<<"${sudo_env}" >/dev/null
  docker --version >/dev/null
  dockerd --version >/dev/null
  containerd --version >/dev/null
  docker buildx version >/dev/null
  docker compose version >/dev/null
  printf "services:\n  smoke:\n    image: scratch\n" | docker compose --project-name smoke -f - config --quiet
  gh --version >/dev/null
  claude --version >/dev/null
  codex --version >/dev/null
  node --version | grep -q "^v22\\."
'

echo "user_sandbox_image_smoke: ok"

if [ "${UMBRA_VERIFY_IMAGE_REPRODUCIBILITY:-0}" = 1 ]; then
  if [ -n "${DEV_CVM_IMAGE_SMOKE_IMAGE:-}" ]; then
    echo "release-image smoke cannot rebuild the selected artifact" >&2
    exit 1
  fi
  bash "${ROOT}/ops/verify/verify-image-reproducibility.sh" \
    dev-cvm cvms/dev/user-sandbox/Dockerfile .
fi
