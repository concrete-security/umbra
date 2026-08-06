#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "deploy: $1" >&2
  exit "${2:-1}"
}

info() {
  echo "deploy: $1" >&2
}

is_truthy() {
  case "${1:-}" in
    1 | true | TRUE | yes | YES | y | Y | on | ON)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

component_list() {
  printf '%s' "${UMBRA_DEPLOY_CVMS:-}"
}

validate_component_list() {
  local raw part
  raw="$(component_list)"
  raw="${raw// /}"
  if [ -z "$raw" ]; then
    return 0
  fi

  IFS=',' read -r -a parts <<< "$raw"
  for part in "${parts[@]}"; do
    part="${part,,}"
    case "$part" in
      "" | none | all | sc | security | security-cvm | dev | dev-cvm)
        ;;
      *)
        fail "unknown UMBRA_DEPLOY_CVMS component '${part}'; use security, dev, all, or none"
        ;;
    esac
  done
}

component_requested() {
  local want="$1"
  local raw part
  raw="$(component_list)"
  raw="${raw// /}"
  if [ -z "$raw" ]; then
    return 1
  fi

  IFS=',' read -r -a parts <<< "$raw"
  for part in "${parts[@]}"; do
    part="${part,,}"
    case "${want}:${part}" in
      security:all | security:sc | security:security | security:security-cvm)
        return 0
        ;;
      dev:all | dev:dev | dev:dev-cvm)
        return 0
        ;;
    esac
  done
  return 1
}

security_requested() {
  is_truthy "${UMBRA_DEPLOY_SECURITY_CVM:-}" \
    || component_requested security
}

dev_requested() {
  is_truthy "${UMBRA_DEPLOY_DEV_CVM:-}" \
    || component_requested dev
}

wait_for_url() {
  local name="$1"
  local url="$2"
  local timeout_seconds="$3"
  local start now elapsed

  start="$(date +%s)"
  while true; do
    if curl -fsS "$url" >/dev/null 2>&1; then
      info "${name} is ready at ${url}"
      return 0
    fi

    now="$(date +%s)"
    elapsed=$((now - start))
    if [ "$elapsed" -ge "$timeout_seconds" ]; then
      fail "${name} did not become ready at ${url} within ${timeout_seconds}s"
    fi
    sleep 5
  done
}

publish_env_names=(GHCR_USER GHCR_TOKEN GH_TOKEN)
declare -A preserved_publish_env=()
for name in "${publish_env_names[@]}"; do
  if [ "${!name+x}" ]; then
    preserved_publish_env["$name"]="${!name}"
  fi
done

if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

# Publishing credentials are one-shot process inputs, not runtime settings.
# Restore only values explicitly supplied by the caller and discard any stale
# legacy copies sourced from .env before invoking artifact or image publishers.
for name in "${publish_env_names[@]}"; do
  if [ "${preserved_publish_env[$name]+x}" ]; then
    export "$name=${preserved_publish_env[$name]}"
  else
    unset "$name"
  fi
done

command -v docker >/dev/null || fail "docker is required"
command -v curl >/dev/null || fail "curl is required"
docker compose version >/dev/null 2>&1 || fail "docker compose plugin is required"

validate_component_list

./ops/db/guard-console-state-cutover.sh

console_url="${CONSOLE_URL:-}"
if [ -z "$console_url" ] && [ -n "${CONSOLE_HOST:-}" ]; then
  console_url="https://${CONSOLE_HOST}"
fi
if [ -z "$console_url" ]; then
  fail "missing CONSOLE_URL or CONSOLE_HOST"
fi
console_url="${console_url%/}"

wait_seconds="${UMBRA_DEPLOY_CONSOLE_WAIT_SECONDS:-180}"
if ! [[ "$wait_seconds" =~ ^[0-9]+$ ]]; then
  fail "UMBRA_DEPLOY_CONSOLE_WAIT_SECONDS must be a non-negative integer"
fi

./ops/cli-release/prepare-cli-installer.sh

info "starting Console Compose stack"
docker volume create umbra_console_letsencrypt >/dev/null
docker compose up -d --build

info "waiting up to ${wait_seconds}s for the public Console endpoints"
wait_for_url "Console health" "${console_url}/healthz" "$wait_seconds"
wait_for_url "Console readiness" "${console_url}/readyz" "$wait_seconds"
info "Console deployed at ${console_url}"

if security_requested; then
  info "Security CVM deploy requested"
  ./ops/deploy/redeploy-security-cvm.sh
else
  info "Security CVM deploy not requested; set UMBRA_DEPLOY_SECURITY_CVM=1 or UMBRA_DEPLOY_CVMS=security to launch one"
fi

if dev_requested; then
  info "Dev CVM deploy requested"
  UMBRA_REDEPLOY_DEV_REQUIRE_LAUNCH="${UMBRA_REDEPLOY_DEV_REQUIRE_LAUNCH:-1}" ./ops/deploy/redeploy-dev-cvm.sh
else
  info "Dev CVM deploy not requested; set UMBRA_DEPLOY_DEV_CVM=1 or UMBRA_DEPLOY_CVMS=dev to launch one"
fi
