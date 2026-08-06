#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=ops/deploy/cvm-redeploy-lib.sh
source "${ROOT}/ops/deploy/cvm-redeploy-lib.sh"

cvm_redeploy_init "redeploy-sc"
cvm_redeploy_require_clean_tree "the release tree has" .
cvm_redeploy_require_env GHCR_USER GHCR_TOKEN SECURITY_CVM_IMAGE_REPOSITORY
cvm_redeploy_list_owned_cvms

cvm_redeploy_publish_image \
  "$SECURITY_CVM_IMAGE_REPOSITORY" \
  cvms/security/Dockerfile \
  cvms/security \
  "${SECURITY_CVM_IMAGE_PLATFORMS:-linux/amd64}"
image_ref="$CVM_REDEPLOY_IMAGE_REF"
printf 'SECURITY_CVM_IMAGE_REF=%s\n' "$image_ref"

missing=()
if [ "${SECURITY_CVM_IMAGE_REF:-}" != "$image_ref" ]; then
  missing+=("$(cvm_redeploy_mismatch SECURITY_CVM_IMAGE_REF "${SECURITY_CVM_IMAGE_REF:-}" "$image_ref")")
fi
# SECURITY_CVM_IMAGE_MEASUREMENT is the shared dstack-guest MRTD; it does not
# change with the app image, so it is only ever checked for presence.
if [ -z "${SECURITY_CVM_IMAGE_MEASUREMENT:-}" ]; then
  missing+=("SECURITY_CVM_IMAGE_MEASUREMENT")
fi
if [ ! -d "${SHADE_DIR:-}" ]; then
  missing+=("SHADE_DIR pointing to a pinned shade checkout")
fi
if [ -z "${ATLAS_VERIFIER_CMD:-}" ]; then
  missing+=("ATLAS_VERIFIER_CMD")
fi
if [ -z "${UMBRA_REDEPLOY_SC_CONFIG_DIR:-${UMBRA_VERIFY_TENANT_ADMIN_CONFIG_DIR:-}}" ]; then
  missing+=("UMBRA_REDEPLOY_SC_CONFIG_DIR or UMBRA_VERIFY_TENANT_ADMIN_CONFIG_DIR")
fi

if [ "${#missing[@]}" -gt 0 ]; then
  cvm_redeploy_report_blocked blocked "${missing[@]}"
  exit 1
fi

console_url="$(cvm_redeploy_console_url)"
config_dir="${UMBRA_REDEPLOY_SC_CONFIG_DIR:-${UMBRA_VERIFY_TENANT_ADMIN_CONFIG_DIR:-}}"

cvm_redeploy_info "launching Security CVM through Console"
cargo run --quiet -p umbra-cli -- \
  --config "$config_dir" \
  --console-url "$console_url" \
  security-cvm launch \
  --wait-timeout-seconds "${UMBRA_REDEPLOY_SC_WAIT_SECONDS:-900}"
