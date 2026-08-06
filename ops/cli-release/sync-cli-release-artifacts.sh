#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "sync-cli-release-artifacts: $1" >&2
  exit "${2:-1}"
}

info() {
  echo "sync-cli-release-artifacts: $1" >&2
}

command -v curl >/dev/null || fail "curl is required"
command -v python3 >/dev/null || fail "python3 is required"

repo="${UMBRA_CLI_RELEASE_GITHUB_REPO:-concrete-security/umbra}"
if ! [[ "$repo" =~ ^[0-9A-Za-z_.-]+/[0-9A-Za-z_.-]+$ ]]; then
  fail "invalid GitHub repository: ${repo}"
fi

release_dir="${UMBRA_CLI_RELEASE_DIR:-/opt/umbra/cli-releases}"
asset="umbra-cli-release-tree.tar.gz"
provenance_asset="umbra-cli.intoto.jsonl"
installer_asset="umbra-install.sh"
checksums_asset="SHA256SUMS"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
verify_artifact="${script_dir}/verify-cli-release-artifact.sh"
extract_release="${script_dir}/extract-cli-release-tree.py"
verify_manifest="${script_dir}/verify-cli-release-manifest.py"
select_release="${script_dir}/select-public-cli-release.py"
"$verify_artifact" --check

api_url="${UMBRA_CLI_RELEASE_API_URL:-https://api.github.com/repos/${repo}/releases?per_page=100}"
allow_loopback_http=false
if [ -n "${UMBRA_CLI_RELEASE_API_URL:-}" ]; then
  if [[ "$api_url" =~ ^http://127\.0\.0\.1(:[0-9]{1,5})?/[^[:space:]#]*$ ]]; then
    allow_loopback_http=true
  else
    fail "UMBRA_CLI_RELEASE_API_URL is restricted to loopback HTTP for tests"
  fi
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/umbra-cli-release-sync.XXXXXX")"
publish_stage=""
previous_latest=""
cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ -n "$previous_latest" ] \
    && { [ -e "$previous_latest" ] || [ -L "$previous_latest" ]; } \
    && [ ! -e "${release_dir}/latest" ] \
    && [ ! -L "${release_dir}/latest" ]; then
    if ! mv -T -- "$previous_latest" "${release_dir}/latest"; then
      echo "sync-cli-release-artifacts: could not restore prior latest release from ${previous_latest}" >&2
      publish_stage=""
    fi
  fi
  if [ -n "$publish_stage" ]; then
    rm -rf -- "$publish_stage"
  fi
  rm -rf -- "$tmpdir"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

curl_common=(
  --disable
  --fail
  --silent
  --show-error
  --connect-timeout 20
  --max-time 300
)
if [ "$allow_loopback_http" = false ]; then
  curl_common+=(
    --location
    --max-redirs 5
    --proto '=https'
    --proto-redir '=https'
    --tlsv1.2
  )
fi

metadata="${tmpdir}/releases.json"
info "fetching public release metadata for ${repo}"
if ! curl "${curl_common[@]}" \
  --header 'Accept: application/vnd.github+json' \
  --header 'X-GitHub-Api-Version: 2022-11-28' \
  --user-agent 'umbra-cli-release-sync' \
  --max-filesize 16777216 \
  --output "$metadata" \
  "$api_url"; then
  fail "could not fetch public GitHub release metadata for ${repo}"
fi
[ -s "$metadata" ] || fail "GitHub returned empty release metadata for ${repo}"

requested_tag="${UMBRA_CLI_RELEASE_TAG:-}"
if [ -z "$requested_tag" ] && [ -n "${UMBRA_CLI_RELEASE_VERSION:-}" ]; then
  requested_tag="umbra-cli/${UMBRA_CLI_RELEASE_VERSION}"
fi
selector_args=("$metadata" "$repo")
if [ -n "$requested_tag" ]; then
  selector_args+=(--tag "$requested_tag")
fi
if [ "$allow_loopback_http" = true ]; then
  selector_args+=(--allow-loopback-http)
fi
selection="${tmpdir}/selection"
if ! python3 "$select_release" "${selector_args[@]}" > "$selection"; then
  fail "could not select a complete public CLI release"
fi
mapfile -t selected < "$selection"
[ "${#selected[@]}" -eq 6 ] || fail "release selector returned malformed output"
version="${selected[0]}"
tag="${selected[1]}"

asset_names=("$asset" "$provenance_asset" "$installer_asset" "$checksums_asset")
asset_limits=(536870912 67108864 4194304 16777216)
for index in "${!asset_names[@]}"; do
  release_asset="${asset_names[$index]}"
  asset_url="${selected[$((index + 2))]}"
  info "downloading ${release_asset} from ${repo} release ${tag}"
  if ! curl "${curl_common[@]}" \
    --max-filesize "${asset_limits[$index]}" \
    --output "${tmpdir}/${release_asset}" \
    "$asset_url"; then
    fail "could not download ${release_asset} from ${tag}; confirm the release asset exists"
  fi
  [ -s "${tmpdir}/${release_asset}" ] || fail "downloaded ${release_asset} is empty"
done

"$verify_artifact" "${tmpdir}/${asset}" "${tmpdir}/${provenance_asset}" "$repo"
"$verify_artifact" "${tmpdir}/${installer_asset}" "${tmpdir}/${provenance_asset}" "$repo"
"$verify_artifact" "${tmpdir}/${checksums_asset}" "${tmpdir}/${provenance_asset}" "$repo"
python3 "$verify_manifest" \
  "${tmpdir}/${checksums_asset}" "$version" \
  "${tmpdir}/${asset}" "${tmpdir}/${installer_asset}"

staged_release_dir="${tmpdir}/release-tree"
python3 "$extract_release" "${tmpdir}/${asset}" "$staged_release_dir" "$version"

latest_version_file="${staged_release_dir}/latest/version"
[ -f "$latest_version_file" ] || fail "release tree does not contain latest/version"

install -m 0644 "${tmpdir}/${provenance_asset}" \
  "${staged_release_dir}/${version}/${provenance_asset}"
install -m 0644 "${tmpdir}/${provenance_asset}" \
  "${staged_release_dir}/latest/${provenance_asset}"
install -m 0755 "${tmpdir}/${installer_asset}" \
  "${staged_release_dir}/${version}/${installer_asset}"
install -m 0755 "${tmpdir}/${installer_asset}" \
  "${staged_release_dir}/latest/${installer_asset}"
find "$staged_release_dir" -type f -name umbra -exec chmod 0755 {} +

info "installing CLI artifacts and provenance into ${release_dir}"
mkdir -p "$release_dir"
[ -d "$release_dir" ] && [ ! -L "$release_dir" ] \
  || fail "release directory must be a real directory: ${release_dir}"

# Copy the verified tree onto the destination filesystem before exposing it.
# Each complete channel directory is then published with one atomic rename.
publish_stage="$(mktemp -d "${release_dir%/}/.umbra-cli-publish.XXXXXX")"
cp -a "${staged_release_dir}/${version}" "${publish_stage}/${version}"
cp -a "${staged_release_dir}/latest" "${publish_stage}/latest"

version_destination="${release_dir}/${version}"
if [ -e "$version_destination" ] || [ -L "$version_destination" ]; then
  [ -d "$version_destination" ] && [ ! -L "$version_destination" ] \
    || fail "immutable release destination is not a real directory: ${version_destination}"
  if ! diff -qr -- "${publish_stage}/${version}" "$version_destination" >/dev/null; then
    fail "immutable release ${version} already exists with different contents"
  fi
  rm -rf -- "${publish_stage:?}/${version}"
else
  mv -T -- "${publish_stage}/${version}" "$version_destination"
fi

latest_destination="${release_dir}/latest"
if [ -e "$latest_destination" ] || [ -L "$latest_destination" ]; then
  [ -d "$latest_destination" ] && [ ! -L "$latest_destination" ] \
    || fail "latest release destination is not a real directory: ${latest_destination}"
  previous_latest="${publish_stage}/previous-latest"
  mv -T -- "$latest_destination" "$previous_latest"
fi
mv -T -- "${publish_stage}/latest" "$latest_destination"
if [ -n "$previous_latest" ]; then
  rm -rf -- "$previous_latest"
  previous_latest=""
fi

synced_versions="$(find "$release_dir" -mindepth 1 -maxdepth 1 -type d ! -name latest ! -name '.umbra-cli-publish.*' -printf '%f\n' 2>/dev/null | sort -V | tr '\n' ' ')"
info "synced CLI versions: ${synced_versions:-unknown}"
