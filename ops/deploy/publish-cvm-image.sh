#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=ops/deploy/cvm-redeploy-lib.sh
source "${ROOT}/ops/deploy/cvm-redeploy-lib.sh"

if [ "$#" -ne 3 ]; then
  cvm_redeploy_fail \
    "usage: publish-cvm-image.sh <dev-cvm|security-cvm> <ghcr-repository> <artifact.json>"
fi

component="$1"
image_repository="$2"
output="$3"

case "$component" in
  dev-cvm)
    component_key=dev_cvm
    dockerfile=cvms/dev/user-sandbox/Dockerfile
    context=.
    ;;
  security-cvm)
    component_key=security_cvm
    dockerfile=cvms/security/Dockerfile
    context=cvms/security
    ;;
  *)
    cvm_redeploy_fail "component must be dev-cvm or security-cvm"
    ;;
esac
case "$output" in
  artifacts/*.json) ;;
  *) cvm_redeploy_fail "artifact output must be a JSON file below artifacts/" ;;
esac

cvm_redeploy_init "publish-cvm-image"
cvm_redeploy_require_clean_tree "the release tree has" .
cvm_redeploy_require_env GHCR_USER GHCR_TOKEN
cvm_redeploy_publish_image \
  "$image_repository" "$dockerfile" "$context" linux/amd64

[ -n "$CVM_REDEPLOY_IMAGE_REF" ] \
  || cvm_redeploy_fail "publisher did not return a runtime image reference"
[ -n "$CVM_REDEPLOY_PROVENANCE_REF" ] \
  || cvm_redeploy_fail "publisher did not return an attestation index reference"
source_repository="${UMBRA_BUILD_SOURCE_REPOSITORY_URL#https://github.com/}"
case "$source_repository" in
  */*) ;;
  *) cvm_redeploy_fail "source repository must be hosted on github.com" ;;
esac

mkdir -p -- "$(dirname -- "$output")"
jq -n \
  --arg repository "$source_repository" \
  --arg commit "$CVM_REDEPLOY_GIT_SHA" \
  --arg component "$component_key" \
  --arg image "$CVM_REDEPLOY_IMAGE_REF" \
  --arg provenance "$CVM_REDEPLOY_PROVENANCE_REF" \
  '{
    schema_version: 1,
    source: {
      repository: $repository,
      commit: $commit
    },
    artifact: {
      component: $component,
      image: $image,
      measurement: null,
      source_commit: $commit,
      provenance: $provenance
    }
  }' > "$output"

cat -- "$output"
