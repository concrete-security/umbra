#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=ops/deploy/cvm-redeploy-lib.sh
source "${ROOT}/ops/deploy/cvm-redeploy-lib.sh"

cvm_redeploy_init "redeploy-dev"
# A source-SHA image and its provenance must describe the exact release tree,
# including shared publisher/backend tooling rather than only Docker context.
cvm_redeploy_require_clean_tree "the release tree has" .
cvm_redeploy_require_env GHCR_USER GHCR_TOKEN DEV_CVM_IMAGE_REPOSITORY
cvm_redeploy_list_owned_cvms

cvm_redeploy_publish_image \
  "$DEV_CVM_IMAGE_REPOSITORY" \
  cvms/dev/user-sandbox/Dockerfile \
  . \
  "${DEV_CVM_IMAGE_PLATFORMS:-linux/amd64}"
image_ref="$CVM_REDEPLOY_IMAGE_REF"
printf 'DEV_CVM_IMAGE=%s\n' "$image_ref"

measurement=""
# Read the sha the image was actually tagged with. The original also called
# rev-parse only once; an intermediate version of this refactor called it twice,
# which a HEAD move during the multi-minute build would have desynchronised.
release_manifest="${UMBRA_REDEPLOY_DEV_RELEASE_OUTPUT:-artifacts/dev-cvm-release-${CVM_REDEPLOY_GIT_SHA}.json}"
if ! cvm_redeploy_is_falsey "${UMBRA_REDEPLOY_DEV_MEASURE:-true}"; then
  cvm_redeploy_info "measuring ${image_ref} with a direct Phala canary"
  measure_args=(--image-ref "$image_ref" --output "$release_manifest")
  measure_name="${UMBRA_REDEPLOY_DEV_MEASURE_NAME:-${DEV_CVM_MEASURE_NAME:-}}"
  measure_fqdn="${UMBRA_REDEPLOY_DEV_MEASURE_FQDN:-${DEV_CVM_MEASURE_FQDN:-}}"
  measure_instance_type="${UMBRA_REDEPLOY_DEV_MEASURE_INSTANCE_TYPE:-${DEV_CVM_MEASURE_INSTANCE_TYPE:-}}"
  measure_region="${UMBRA_REDEPLOY_DEV_MEASURE_REGION:-${DEV_CVM_MEASURE_REGION:-}}"
  measure_deploy_timeout="${UMBRA_REDEPLOY_DEV_MEASURE_DEPLOY_TIMEOUT_SECONDS:-${DEV_CVM_MEASURE_DEPLOY_TIMEOUT_SECONDS:-}}"
  measure_policy_timeout="${UMBRA_REDEPLOY_DEV_MEASURE_POLICY_TIMEOUT_SECONDS:-${DEV_CVM_MEASURE_POLICY_TIMEOUT_SECONDS:-}}"
  measure_keep="${UMBRA_REDEPLOY_DEV_MEASURE_KEEP:-${DEV_CVM_MEASURE_KEEP:-}}"
  if [ -n "$measure_name" ]; then
    measure_args+=(--name "$measure_name")
  fi
  if [ -n "$measure_fqdn" ]; then
    measure_args+=(--fqdn "$measure_fqdn")
  fi
  if [ -n "$measure_instance_type" ]; then
    measure_args+=(--instance-type "$measure_instance_type")
  fi
  if [ -n "$measure_region" ]; then
    measure_args+=(--region "$measure_region")
  fi
  if [ -n "$measure_deploy_timeout" ]; then
    measure_args+=(--deploy-timeout-seconds "$measure_deploy_timeout")
  fi
  if [ -n "$measure_policy_timeout" ]; then
    measure_args+=(--policy-timeout-seconds "$measure_policy_timeout")
  fi
  if [ -n "$measure_keep" ] && cvm_redeploy_is_truthy "$measure_keep"; then
    measure_args+=(--keep)
  fi
  PYTHONPATH="${PYTHONPATH:+${PYTHONPATH}:}console/src" \
    UV_CACHE_DIR="${UV_CACHE_DIR:-/tmp/uv-cache}" \
    uv run --locked --project console python ops/deploy/measure-dev-cvm-image.py "${measure_args[@]}" 1>&2
  # Guarded: without this a missing or malformed manifest aborts with jq's raw
  # error and its own exit code, never reaching the friendly message below (which
  # only fires when jq succeeds and returns empty).
  measurement="$(jq -r '.image_measurement // empty' "$release_manifest" 2>/dev/null)" \
    || cvm_redeploy_fail "could not read the private measurement manifest"
  if [ -z "$measurement" ]; then
    cvm_redeploy_fail "the private measurement manifest did not include image_measurement"
  fi
  # The manifest records which image it measured; prove it is this one. Otherwise a
  # stale manifest at a reused path yields an image/MRTD pair the operator is told
  # to apply together, and the mismatch only surfaces later as failed attestation.
  measured_ref="$(jq -r '.image_ref // empty' "$release_manifest" 2>/dev/null)" \
    || cvm_redeploy_fail "could not read image_ref from the private measurement manifest"
  if [ "$measured_ref" != "$image_ref" ]; then
    cvm_redeploy_fail "the private measurement manifest does not describe the image just published"
  fi
  printf '\n# Review and apply these together in .env.<MODE>.secrets, then run\n'
  printf '# make build-env MODE=<MODE> && make redeploy-console:\n'
  printf 'DEV_CVM_IMAGE=%s\n' "$image_ref"
  printf 'DEV_CVM_IMAGE_MEASUREMENT=%s\n\n' "$measurement"
fi

missing=()
# The image and its measurement must be applied as a pair: an image without its
# matching MRTD fails attestation. So the ref is reported first and alone, and
# the measurement only once the ref is already current.
if [ "${DEV_CVM_IMAGE:-}" != "$image_ref" ]; then
  missing+=("$(cvm_redeploy_mismatch DEV_CVM_IMAGE "${DEV_CVM_IMAGE:-}" "$image_ref")")
  if [ -n "$measurement" ]; then
    missing+=("apply DEV_CVM_IMAGE_MEASUREMENT=${measurement} in the same edit (review the private release manifest)")
  else
    # Measurement was skipped, so we cannot supply the value — but the pin is
    # still worthless without its matching MRTD, and saying so is the only way
    # the operator learns that from this run.
    missing+=("DEV_CVM_IMAGE_MEASUREMENT matching that image, in the same edit (re-run without UMBRA_REDEPLOY_DEV_MEASURE=0 to compute it)")
  fi
elif [ -n "$measurement" ] && [ "${DEV_CVM_IMAGE_MEASUREMENT:-}" != "$measurement" ]; then
  missing+=("$(cvm_redeploy_mismatch DEV_CVM_IMAGE_MEASUREMENT "${DEV_CVM_IMAGE_MEASUREMENT:-}" "$measurement")")
elif [ -z "${DEV_CVM_IMAGE_MEASUREMENT:-}" ]; then
  missing+=("DEV_CVM_IMAGE_MEASUREMENT")
fi
if [ ! -d "${SHADE_DIR:-}" ]; then
  missing+=("SHADE_DIR pointing to a pinned shade checkout")
fi
# umbra-atlas-verify is baked into the Console image (console/Dockerfile), so
# only the Console container needs it on PATH — do not check the operator host.
if [ -z "${ATLAS_VERIFIER_CMD:-}" ]; then
  missing+=("ATLAS_VERIFIER_CMD")
fi
if [ -z "${UMBRA_REDEPLOY_DEV_CONFIG_DIR:-${UMBRA_VERIFY_TENANT_ADMIN_CONFIG_DIR:-}}" ]; then
  missing+=("UMBRA_REDEPLOY_DEV_CONFIG_DIR or UMBRA_VERIFY_TENANT_ADMIN_CONFIG_DIR")
fi
if [ -z "${UMBRA_REDEPLOY_DEV_PROFILE_ID:-}" ]; then
  missing+=("UMBRA_REDEPLOY_DEV_PROFILE_ID")
fi
if [ -z "${UMBRA_REDEPLOY_DEV_SSH_KEY_ID:-}" ]; then
  missing+=("UMBRA_REDEPLOY_DEV_SSH_KEY_ID")
fi

if [ "${#missing[@]}" -gt 0 ]; then
  # Publishing without launching is a benign stop here, unless the caller demands
  # a launch (deploy.sh does). The verdict word must match the exit code.
  if cvm_redeploy_is_truthy "${UMBRA_REDEPLOY_DEV_REQUIRE_LAUNCH:-}"; then
    cvm_redeploy_report_blocked blocked "${missing[@]}"
    exit 1
  fi
  cvm_redeploy_report_blocked skipped "${missing[@]}"
  exit 0
fi

console_url="$(cvm_redeploy_console_url)"
config_dir="${UMBRA_REDEPLOY_DEV_CONFIG_DIR:-${UMBRA_VERIFY_TENANT_ADMIN_CONFIG_DIR:-}}"

cvm_redeploy_info "launching Dev CVM through Console"
cargo run --quiet -p umbra-cli -- \
  --config "$config_dir" \
  --console-url "$console_url" \
  --profile "$UMBRA_REDEPLOY_DEV_PROFILE_ID" \
  cvm launch \
  --ssh-key "$UMBRA_REDEPLOY_DEV_SSH_KEY_ID" \
  --wait-timeout-seconds "${UMBRA_REDEPLOY_DEV_WAIT_SECONDS:-900}"
