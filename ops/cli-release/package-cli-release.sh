#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "package-cli-release: $1" >&2
  exit "${2:-1}"
}

info() {
  echo "package-cli-release: $1" >&2
}

command -v cargo >/dev/null || fail "cargo is required"
command -v rustc >/dev/null || fail "rustc is required"
command -v sha256sum >/dev/null || fail "sha256sum is required"

target="${UMBRA_CLI_RELEASE_TARGET:-}"
if [ -z "$target" ]; then
  target="$(rustc -vV | awk '/^host: / {print $2}')"
fi
[ -n "$target" ] || fail "could not determine Rust host target"

version="$(cargo pkgid -p umbra-cli | sed 's/.*@//')"
[ -n "$version" ] || fail "could not determine umbra-cli version"

release_dir="${UMBRA_CLI_RELEASE_DIR:-/opt/umbra/cli-releases}"
staging_dir="${UMBRA_CLI_RELEASE_STAGING_DIR:-}"
remote="${UMBRA_CLI_RELEASE_REMOTE:-}"
remote_dir="${UMBRA_CLI_RELEASE_REMOTE_DIR:-/opt/umbra/cli-releases}"
if [ -n "$remote" ]; then
  release_dir="${staging_dir:-$(mktemp -d "${TMPDIR:-/tmp}/umbra-cli-release.XXXXXX")}"
fi

info "building umbra-cli ${version} for ${target}"
cargo build --release -p umbra-cli --target "$target"

binary="target/${target}/release/umbra"
[ -x "$binary" ] || fail "expected release binary at ${binary}"

for channel in "$version" latest; do
  dest_dir="${release_dir}/${channel}/${target}"
  install -d "$dest_dir"
  install -m 0755 "$binary" "${dest_dir}/umbra"
  (
    cd "$dest_dir"
    sha256sum umbra > umbra.sha256
  )
  # Version metadata consumed by `umbra update` and its passive
  # new-version check: GET /releases/umbra-cli/latest/version.
  printf '%s\n' "$version" > "${release_dir}/${channel}/version"
  info "wrote ${dest_dir}/umbra"
done

if [ -n "$remote" ]; then
  command -v ssh >/dev/null || fail "ssh is required when UMBRA_CLI_RELEASE_REMOTE is set"
  command -v rsync >/dev/null || fail "rsync is required when UMBRA_CLI_RELEASE_REMOTE is set"
  info "publishing ${target} artifacts to ${remote}:${remote_dir}"
  ssh "$remote" "mkdir -p $(printf '%q' "$remote_dir")"
  rsync -a "${release_dir}/" "${remote}:${remote_dir%/}/"
fi
