#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=ops/buildkit-version.sh
source "${ROOT}/ops/buildkit-version.sh"

fail() {
  echo "image-reproducibility: $1" >&2
  exit 1
}

if [ "$#" -ne 3 ]; then
  fail "usage: verify-image-reproducibility.sh <label> <dockerfile> <context>"
fi

label="$1"
dockerfile="$2"
context="$3"
[[ "$label" =~ ^[a-z0-9][a-z0-9-]{0,31}$ ]] \
  || fail "label must contain only lower-case letters, digits, and hyphens"
git_sha_before="$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
  || fail "could not capture the source commit"
worktree_status="$(git -C "$ROOT" status --porcelain --untracked-files=all 2>/dev/null)" \
  || fail "could not inspect the source worktree"
[ -z "$worktree_status" ] \
  || fail "verification requires a clean source worktree"
git_sha="$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" \
  || fail "could not recapture the source commit after the clean-tree check"
[ "$git_sha" = "$git_sha_before" ] \
  || fail "HEAD changed while checking the source worktree"
umbra_release_source_objects_valid "$ROOT" "$git_sha" "$dockerfile" "$context" \
  || fail "Dockerfile and context must be ordinary repository objects inside the captured commit"
configured_source_url="$(
  umbra_normalize_source_repository_url \
    "${UMBRA_BUILD_SOURCE_REPOSITORY_URL:-https://github.com/concrete-security/umbra}"
)" || fail "UMBRA_BUILD_SOURCE_REPOSITORY_URL must be an HTTPS repository URL without credentials, query, or fragment"
origin_url="$(git -C "$ROOT" remote get-url origin 2>/dev/null)" \
  || fail "the release checkout has no readable origin remote"
origin_source_url="$(umbra_normalize_source_repository_url "$origin_url")" \
  || fail "the origin remote cannot be normalized to an HTTPS source identity"
[ "$configured_source_url" = "$origin_source_url" ] \
  || fail "UMBRA_BUILD_SOURCE_REPOSITORY_URL must explicitly match this checkout's origin repository"
UMBRA_BUILD_SOURCE_REPOSITORY_URL="$configured_source_url"
source_date_epoch="$(git -C "$ROOT" show -s --format=%ct "$git_sha" 2>/dev/null)" \
  || fail "could not derive the source commit timestamp"

umbra_require_reproducible_builder \
  || fail "the digest-pinned ${UMBRA_BUILDKIT_BUILDER} builder is unavailable (${UMBRA_BUILDKIT_FAILURE})"
UMBRA_BUILD_SOURCE_REPOSITORY_URL="$configured_source_url"
umbra_prepare_reproducible_build_args "$git_sha" "$source_date_epoch" \
  || fail "could not derive valid reproducible-build metadata"

repro_dir="$(mktemp -d /tmp/umbra-image-repro.XXXXXX)" \
  || fail "could not create the isolated verification workspace"
first_worktree="${repro_dir}/first-worktree"
second_worktree="${repro_dir}/second-worktree"
cleanup_repro() {
  local status=$?
  git -C "$ROOT" worktree remove --force -- "$second_worktree" >/dev/null 2>&1 || true
  git -C "$ROOT" worktree remove --force -- "$first_worktree" >/dev/null 2>&1 || true
  case "$repro_dir" in
    /tmp/umbra-image-repro.*)
      command rm -rf -- "$repro_dir" >/dev/null 2>&1 || true
      ;;
  esac
  return "$status"
}
trap cleanup_repro EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

for worktree in "$first_worktree" "$second_worktree"; do
  git -C "$ROOT" worktree add --detach "$worktree" "$git_sha" >/dev/null 2>&1 \
    || fail "could not create an independent detached worktree"
  umbra_resolve_release_worktree_paths "$worktree" "$dockerfile" "$context" \
    || fail "a detached worktree resolved a build path outside its captured root"
  if [ "$worktree" = "$first_worktree" ]; then
    first_build_dockerfile="$UMBRA_RELEASE_DOCKERFILE_PATH"
    first_build_context="$UMBRA_RELEASE_CONTEXT_PATH"
  else
    second_build_dockerfile="$UMBRA_RELEASE_DOCKERFILE_PATH"
    second_build_context="$UMBRA_RELEASE_CONTEXT_PATH"
  fi
done

[ "$(git -C "$ROOT" rev-parse --verify 'HEAD^{commit}' 2>/dev/null)" = "$git_sha" ] \
  || fail "HEAD changed before the reproducibility builds"

for pass in first second; do
  if [ "$pass" = first ]; then
    build_context="$first_build_context"
    build_dockerfile="$first_build_dockerfile"
  else
    build_context="$second_build_context"
    build_dockerfile="$second_build_dockerfile"
  fi
  archive="${repro_dir}/${pass}.oci.tar"
  echo "image-reproducibility: ${label} ${pass} cache-disabled build" >&2
  docker buildx build \
    "${UMBRA_REPRODUCIBLE_BUILD_ARGS[@]}" \
    --no-cache \
    --platform linux/amd64 \
    --file "$build_dockerfile" \
    --output "type=oci,dest=${archive},rewrite-timestamp=true,compatibility-version=${UMBRA_BUILDKIT_COMPATIBILITY_VERSION},oci-mediatypes=true" \
    "$build_context" >"${repro_dir}/${pass}.build.log" 2>&1 \
    || fail "${label} ${pass} cache-disabled build failed; detailed build output was suppressed"
  runtime_digest="$(umbra_oci_layout_runtime_digest "$archive" "$git_sha" "$source_date_epoch")" \
    || fail "${label} ${pass} build did not produce the required attested OCI shape"
  if [ "$pass" = first ]; then
    first_runtime_digest="$runtime_digest"
  else
    second_runtime_digest="$runtime_digest"
  fi
done

[ "$first_runtime_digest" = "$second_runtime_digest" ] \
  || fail "${label} independent cache-disabled builds produced different runtime digests"

echo "image-reproducibility: ok (${label} ${first_runtime_digest})"
