#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "sync-cli-workflow-artifacts: $1" >&2
  exit "${2:-1}"
}

info() {
  echo "sync-cli-workflow-artifacts: $1" >&2
}

gh_token="${GH_TOKEN:-}"
unset GH_TOKEN
[ -n "$gh_token" ] \
  || fail "a dedicated one-shot GH_TOKEN is required to download GitHub workflow artifacts"

command -v gh >/dev/null || fail "gh is required"
command -v python3 >/dev/null || fail "python3 is required"

authenticated_gh() {
  GH_TOKEN="$gh_token" gh "$@"
}

repo="${UMBRA_CLI_RELEASE_GITHUB_REPO:-concrete-security/umbra}"
release_dir="${UMBRA_CLI_RELEASE_DIR:-/opt/umbra/cli-releases}"
workflow="${UMBRA_CLI_WORKFLOW_NAME:-Release Umbra CLI}"
branch="${UMBRA_CLI_WORKFLOW_BRANCH:-main}"
expected_version="${UMBRA_CLI_RELEASE_VERSION:-}"
provenance_artifact="umbra-cli.intoto.jsonl"
release_bundle_artifact="umbra-cli-release-tree"
release_tree_asset="umbra-cli-release-tree.tar.gz"
installer_asset="umbra-install.sh"
checksums_asset="SHA256SUMS"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
verify_artifact="${script_dir}/verify-cli-release-artifact.sh"
extract_release="${script_dir}/extract-cli-release-tree.py"
verify_manifest="${script_dir}/verify-cli-release-manifest.py"
"$verify_artifact" --check
[ -n "$expected_version" ] \
  || fail "workflow sync is an explicit short-lived debug path and requires UMBRA_CLI_RELEASE_VERSION"
if ! [[ "$expected_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+\.)*[0-9A-Za-z-]+)?$ ]]; then
  fail "UMBRA_CLI_RELEASE_VERSION is not a semantic version: ${expected_version}"
fi

validate_run() {
  local run_id="$1"
  local run_branch run_status run_conclusion
  run_branch="$(authenticated_gh api "repos/${repo}/actions/runs/${run_id}" --jq '.head_branch // empty')"
  [ "$run_branch" = "$branch" ] || fail "workflow run ${run_id} is on ${run_branch:-unknown}; expected ${branch}"
  run_status="$(authenticated_gh api "repos/${repo}/actions/runs/${run_id}" --jq '.status // empty')"
  run_conclusion="$(authenticated_gh api "repos/${repo}/actions/runs/${run_id}" --jq '.conclusion // empty')"
  [ "$run_status" = "completed" ] && [ "$run_conclusion" = "success" ] \
    || fail "workflow run ${run_id} is not a completed success"
}

resolve_run_id() {
  if [ -n "${UMBRA_CLI_WORKFLOW_RUN_ID:-}" ]; then
    validate_run "$UMBRA_CLI_WORKFLOW_RUN_ID"
    printf '%s\n' "$UMBRA_CLI_WORKFLOW_RUN_ID"
    return
  fi

  authenticated_gh run list \
    --repo "$repo" \
    --workflow "$workflow" \
    -b "$branch" \
    --limit 50 \
    --json databaseId,conclusion,status,headBranch \
    --jq '[.[] | select(.status == "completed") | select(.conclusion == "success")][0].databaseId // empty'
}

run_id="$(resolve_run_id)"
[ -n "$run_id" ] || fail "no successful ${workflow} run found on ${branch}; set UMBRA_CLI_WORKFLOW_RUN_ID"

provenance_count="$(authenticated_gh api "repos/${repo}/actions/runs/${run_id}/artifacts" --jq \
  "[.artifacts[] | select(.expired == false) | select(.name == \"${provenance_artifact}\")] | length")"
[ "$provenance_count" = "1" ] \
  || fail "run ${run_id} has ${provenance_count} unexpired ${provenance_artifact} artifacts; select a successful non-dry-run release workflow"
release_bundle_count="$(authenticated_gh api "repos/${repo}/actions/runs/${run_id}/artifacts" --jq \
  "[.artifacts[] | select(.expired == false) | select(.name == \"${release_bundle_artifact}\")] | length")"
[ "$release_bundle_count" = "1" ] \
  || fail "run ${run_id} has ${release_bundle_count} unexpired ${release_bundle_artifact} artifacts; select a complete release workflow"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/umbra-cli-workflow-sync.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

provenance_dir="${tmpdir}/provenance"
info "downloading ${provenance_artifact}"
authenticated_gh run download "$run_id" \
  --repo "$repo" \
  --name "$provenance_artifact" \
  --dir "$provenance_dir"
provenance_path="${provenance_dir}/${provenance_artifact}"
[ -s "$provenance_path" ] || fail "downloaded ${provenance_artifact} is empty"

release_bundle_dir="${tmpdir}/release-bundle"
info "downloading ${release_bundle_artifact}"
authenticated_gh run download "$run_id" \
  --repo "$repo" \
  --name "$release_bundle_artifact" \
  --dir "$release_bundle_dir"
gh_token=""
unset gh_token
unset -f authenticated_gh
installer_path="${release_bundle_dir}/${installer_asset}"
[ -s "$installer_path" ] || fail "downloaded ${release_bundle_artifact} does not contain ${installer_asset}"
release_tree_path="${release_bundle_dir}/${release_tree_asset}"
[ -s "$release_tree_path" ] || fail "downloaded ${release_bundle_artifact} does not contain ${release_tree_asset}"
checksums_path="${release_bundle_dir}/${checksums_asset}"
[ -s "$checksums_path" ] || fail "downloaded ${release_bundle_artifact} does not contain ${checksums_asset}"

"$verify_artifact" "$release_tree_path" "$provenance_path" "$repo"
"$verify_artifact" "$installer_path" "$provenance_path" "$repo"
"$verify_artifact" "$checksums_path" "$provenance_path" "$repo"
python3 "$verify_manifest" \
  "$checksums_path" "$expected_version" "$release_tree_path" "$installer_path"

staged_release_dir="${tmpdir}/release-tree"
python3 "$extract_release" "$release_tree_path" "$staged_release_dir" "$expected_version"
install -m 0644 "$provenance_path" \
  "${staged_release_dir}/${expected_version}/${provenance_artifact}"
install -m 0644 "$provenance_path" \
  "${staged_release_dir}/latest/${provenance_artifact}"
install -m 0755 "$installer_path" \
  "${staged_release_dir}/${expected_version}/${installer_asset}"
install -m 0755 "$installer_path" \
  "${staged_release_dir}/latest/${installer_asset}"

info "installing CLI artifacts and provenance into ${release_dir}"
mkdir -p "$release_dir"
rm -rf "${release_dir}/latest"
cp -a "${staged_release_dir}/." "$release_dir/"

find "$release_dir" -type f -name umbra -exec chmod 0755 {} +

info "synced CLI version ${expected_version} from verified workflow artifacts"
