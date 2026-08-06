#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "measure-dev: $1" >&2
  exit "${2:-1}"
}

if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

image_ref="${1:-${DEV_CVM_MEASURE_IMAGE_REF:-}}"
[ -n "$image_ref" ] || fail "usage: DEV_CVM_MEASURE_IMAGE_REF=<digest-pinned-image> make measure-dev"

output="${DEV_CVM_MEASURE_OUTPUT:-}"
if [ -z "$output" ]; then
  safe_id="$(printf '%s' "$image_ref" | sed 's/[^A-Za-z0-9_.-]/_/g')"
  output="artifacts/dev-cvm-release-${safe_id}.json"
fi

args=(
  --image-ref "$image_ref"
  --output "$output"
)

if [ -n "${DEV_CVM_MEASURE_NAME:-}" ]; then
  args+=(--name "$DEV_CVM_MEASURE_NAME")
fi
if [ -n "${DEV_CVM_MEASURE_FQDN:-}" ]; then
  args+=(--fqdn "$DEV_CVM_MEASURE_FQDN")
fi
if [ -n "${DEV_CVM_MEASURE_INSTANCE_TYPE:-}" ]; then
  args+=(--instance-type "$DEV_CVM_MEASURE_INSTANCE_TYPE")
fi
if [ -n "${DEV_CVM_MEASURE_REGION:-}" ]; then
  args+=(--region "$DEV_CVM_MEASURE_REGION")
fi
if [ -n "${DEV_CVM_MEASURE_DEPLOY_TIMEOUT_SECONDS:-}" ]; then
  args+=(--deploy-timeout-seconds "$DEV_CVM_MEASURE_DEPLOY_TIMEOUT_SECONDS")
fi
if [ -n "${DEV_CVM_MEASURE_POLICY_TIMEOUT_SECONDS:-}" ]; then
  args+=(--policy-timeout-seconds "$DEV_CVM_MEASURE_POLICY_TIMEOUT_SECONDS")
fi
case "${DEV_CVM_MEASURE_KEEP:-}" in
  1 | true | TRUE | yes | YES | y | Y | on | ON)
    args+=(--keep)
    ;;
esac

PYTHONPATH="${PYTHONPATH:+${PYTHONPATH}:}console/src" \
  uv run --locked --project console python ops/deploy/measure-dev-cvm-image.py "${args[@]}"
