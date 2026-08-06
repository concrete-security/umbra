#!/usr/bin/env sh
set -eu

program="umbra-install"
base_url="${UMBRA_INSTALL_BASE_URL:-__UMBRA_INSTALL_BASE_URL__}"
version="${UMBRA_INSTALL_VERSION:-latest}"
source_repo="${UMBRA_INSTALL_SOURCE_REPO:-__UMBRA_INSTALL_SOURCE_REPO__}"
source_branch="${UMBRA_INSTALL_SOURCE_BRANCH:-main}"
slsa_verifier="${UMBRA_INSTALL_SLSA_VERIFIER:-}"
slsa_builder_id="https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0"
tmp_dir=""

info() {
  printf '%s: %s\n' "$program" "$*" >&2
}

fail() {
  info "$1"
  exit "${2:-1}"
}

cleanup() {
  if [ -n "$tmp_dir" ]; then
    rm -rf "$tmp_dir"
  fi
}
trap cleanup EXIT HUP INT TERM

path_contains() {
  dir="$1"
  case ":${PATH:-}:" in
    *":${dir}:"*) return 0 ;;
    *) return 1 ;;
  esac
}

can_write_dir() {
  dir="$1"
  mkdir -p "$dir" 2>/dev/null || return 1
  [ -d "$dir" ] && [ -w "$dir" ]
}

install_dir() {
  if [ -n "${UMBRA_INSTALL_BIN_DIR:-}" ]; then
    can_write_dir "$UMBRA_INSTALL_BIN_DIR" || fail "cannot write UMBRA_INSTALL_BIN_DIR=${UMBRA_INSTALL_BIN_DIR}"
    printf '%s\n' "$UMBRA_INSTALL_BIN_DIR"
    return
  fi

  home_dir="${HOME:-}"
  for dir in "${home_dir}/.local/bin" "${home_dir}/bin" /usr/local/bin /opt/homebrew/bin; do
    if [ -n "$dir" ] && path_contains "$dir" && can_write_dir "$dir"; then
      printf '%s\n' "$dir"
      return
    fi
  done

  if [ -n "$home_dir" ] && can_write_dir "${home_dir}/.local/bin"; then
    info "installing to ${home_dir}/.local/bin; add it to PATH before running umbra"
    printf '%s\n' "${home_dir}/.local/bin"
    return
  fi

  for dir in /usr/local/bin /opt/homebrew/bin; do
    if can_write_dir "$dir"; then
      printf '%s\n' "$dir"
      return
    fi
  done

  fail "could not find a writable install directory; set UMBRA_INSTALL_BIN_DIR"
}

target_triple() {
  os="$(uname -s 2>/dev/null || true)"
  arch="$(uname -m 2>/dev/null || true)"

  case "$arch" in
    x86_64 | amd64) arch="x86_64" ;;
    arm64 | aarch64) arch="aarch64" ;;
    *) fail "unsupported CPU architecture: ${arch}" ;;
  esac

  case "$os" in
    Linux) printf '%s-unknown-linux-gnu\n' "$arch" ;;
    Darwin)
      [ "$arch" = "aarch64" ] \
        || fail "Intel macOS does not have a published Umbra CLI binary; use Apple Silicon or build from source"
      printf '%s-apple-darwin\n' "$arch"
      ;;
    *) fail "unsupported operating system: ${os}" ;;
  esac
}

download() {
  url="$1"
  output="$2"

  if command -v curl >/dev/null 2>&1; then
    case "$base_url" in
      https://*)
        curl --fail --silent --show-error --location \
          --proto '=https' --proto-redir '=https' \
          "$url" -o "$output" && return 0
        ;;
      *)
        # Loopback HTTP is a test/local-mirror carve-out. Do not follow its
        # redirects, which could otherwise escape to remote plaintext.
        curl --fail --silent --show-error "$url" -o "$output" && return 0
        ;;
    esac
    return 1
  fi
  if command -v wget >/dev/null 2>&1; then
    case "$base_url" in
      https://*) fail "curl is required for remote installation so redirects remain HTTPS-only" ;;
    esac
    wget -q -O "$output" "$url" && return 0
    return 1
  fi
  fail "curl or wget is required"
}

sha256_file() {
  file="$1"

  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
    return
  fi
  fail "sha256sum or shasum is required"
}

verify_checksum() {
  file="$1"
  checksum_file="$2"

  expected="$(awk '{print $1; exit}' "$checksum_file")"
  [ -n "$expected" ] || fail "empty checksum file"
  actual="$(sha256_file "$file")"
  [ "$actual" = "$expected" ] || fail "checksum mismatch for downloaded umbra binary"
}

validate_version() {
  candidate="$1"
  # Release paths and the authenticated binary's reported version must use one
  # canonical SemVer spelling. Build metadata is deliberately excluded: it has
  # no precedence and would allow multiple URLs for the same release identity.
  printf '%s\n' "$candidate" | awk '
    NR != 1 { exit 1 }
    {
      version = $0
      if (version == "" || version ~ /[^0-9A-Za-z.-]/) exit 1
      dash = index(version, "-")
      if (dash == 0) {
        core = version
        prerelease = ""
      } else {
        core = substr(version, 1, dash - 1)
        prerelease = substr(version, dash + 1)
        if (prerelease == "") exit 1
      }
      count = split(core, numbers, ".")
      if (count != 3) exit 1
      for (index_ = 1; index_ <= count; index_++) {
        number = numbers[index_]
        if (number !~ /^(0|[1-9][0-9]*)$/) exit 1
      }
      if (prerelease != "") {
        count = split(prerelease, identifiers, ".")
        for (index_ = 1; index_ <= count; index_++) {
          identifier = identifiers[index_]
          if (identifier == "" || identifier !~ /^[0-9A-Za-z-]+$/) exit 1
          if (identifier ~ /^[0-9]+$/ && identifier !~ /^(0|[1-9][0-9]*)$/) exit 1
        }
      }
    }
    END { if (NR != 1) exit 1 }
  ' || fail "invalid umbra release version: ${candidate}"
}

read_version() {
  version_file="$1"
  awk 'END { exit(NR == 1 ? 0 : 1) }' "$version_file" \
    || fail "latest version metadata must contain exactly one line"
  resolved="$(sed -n '1{s/\r$//;p;}' "$version_file")"
  validate_version "$resolved"
  printf '%s\n' "$resolved"
}

validate_source_repo() {
  repo="$1"
  case "$repo" in
    github.com/*/*) ;;
    *) fail "invalid SLSA source repository: ${repo}; expected github.com/OWNER/REPO" ;;
  esac
  case "$repo" in
    *[!0-9A-Za-z._/-]*) fail "invalid SLSA source repository: ${repo}; expected github.com/OWNER/REPO" ;;
  esac

  repo_path="${repo#github.com/}"
  owner="${repo_path%%/*}"
  name="${repo_path#*/}"
  [ -n "$owner" ] && [ -n "$name" ] && [ "${name#*/}" = "$name" ] \
    || fail "invalid SLSA source repository: ${repo}; expected github.com/OWNER/REPO"
}

require_slsa_verifier() {
  if [ -n "$slsa_verifier" ]; then
    case "$slsa_verifier" in
      /*) ;;
      *) fail "UMBRA_INSTALL_SLSA_VERIFIER must be an absolute executable path" ;;
    esac
    [ -x "$slsa_verifier" ] \
      || fail "slsa-verifier is required; install it first or set UMBRA_INSTALL_SLSA_VERIFIER to its absolute executable path"
    return
  fi

  # Do not use ordinary `command -v`: POSIX permits relative PATH entries, so
  # a repository-controlled `.` or `tools` directory could shadow the trusted
  # verifier. Walk PATH without word/glob expansion and accept absolute
  # directories only.
  remaining_path="${PATH:-}"
  while :; do
    case "$remaining_path" in
      *:*) verifier_dir="${remaining_path%%:*}"; remaining_path="${remaining_path#*:}"; more_path=true ;;
      *) verifier_dir="$remaining_path"; more_path=false ;;
    esac
    case "$verifier_dir" in
      /*)
        if [ -x "${verifier_dir%/}/slsa-verifier" ]; then
          slsa_verifier="${verifier_dir%/}/slsa-verifier"
          return
        fi
        ;;
    esac
    [ "$more_path" = true ] || break
  done
  fail "slsa-verifier is required; install it first or set UMBRA_INSTALL_SLSA_VERIFIER to its absolute executable path"
}

# TLS authenticates the release mirror, while signed SLSA provenance separately
# binds the downloaded binary to the expected GitHub source repository. Keep the
# transport check too: it protects version metadata and avoids downgrade or
# availability attacks on remote networks.
case "$base_url" in
  https://*) ;;
  http://127.0.0.1 | http://127.0.0.1[/:]* | http://localhost | http://localhost[/:]*) ;;
  "http://[::1]" | "http://[::1]"[/:]*) ;;
  http://*) fail "refusing plaintext http for a remote installer base URL: ${base_url}" ;;
  *) fail "invalid installer base URL: ${base_url}" ;;
esac

validate_source_repo "$source_repo"
case "$source_branch" in
  "" | *[!0-9A-Za-z._/-]*) fail "invalid SLSA source branch: ${source_branch}" ;;
esac
require_slsa_verifier

target="$(target_triple)"
tmp_parent="${TMPDIR:-/tmp}"
tmp_dir="$(mktemp -d "${tmp_parent%/}/umbra-install.XXXXXX")"
if [ "$version" = "latest" ]; then
  latest_version_path="${tmp_dir}/version"
  latest_version_url="${base_url%/}/releases/umbra-cli/latest/version"
  info "resolving latest umbra release"
  download "$latest_version_url" "$latest_version_path" \
    || fail "latest umbra release version is not available"
  resolved_version="$(read_version "$latest_version_path")"
else
  validate_version "$version"
  resolved_version="$version"
fi

artifact_dir="${tmp_dir}/${resolved_version}/${target}"
mkdir -p "$artifact_dir"
binary_path="${artifact_dir}/umbra"
checksum_path="${artifact_dir}/umbra.sha256"
provenance_path="${tmp_dir}/${resolved_version}/umbra-cli.intoto.jsonl"
artifact_url="${base_url%/}/releases/umbra-cli/${resolved_version}/${target}/umbra"
checksum_url="${artifact_url}.sha256"
provenance_url="${base_url%/}/releases/umbra-cli/${resolved_version}/umbra-cli.intoto.jsonl"

info "downloading umbra ${resolved_version} for ${target}"
download "$artifact_url" "$binary_path" || fail "no prebuilt umbra binary is available for ${target}"
download "$checksum_url" "$checksum_path" || fail "checksum is not available for ${target}"
download "$provenance_url" "$provenance_path" \
  || fail "SLSA provenance is not available for umbra ${resolved_version}"
verify_checksum "$binary_path" "$checksum_path"
info "verifying umbra ${resolved_version} SLSA provenance"
"$slsa_verifier" verify-artifact "$binary_path" \
  --provenance-path "$provenance_path" \
  --source-uri "$source_repo" \
  --source-branch "$source_branch" \
  --build-workflow-input dry_run=false \
  --builder-id "$slsa_builder_id" \
  || fail "SLSA provenance verification failed for umbra ${resolved_version}"

# Executing a binary is safe only after provenance succeeds. The provenance
# authenticates the artifact and build identity, but a mirror could otherwise
# replay an older genuinely signed Umbra binary under a newer version URL.
chmod 0755 "$binary_path"
reported_output="$("$binary_path" --version 2>/dev/null)" \
  || fail "verified umbra ${resolved_version} failed to execute on this machine"
reported_version="$(printf '%s\n' "$reported_output" | awk 'NF { value = $NF; lines += 1 } END { if (lines == 1) print value; else exit 1 }')" \
  || fail "verified umbra ${resolved_version} did not report a parseable version"
[ "$reported_version" = "$resolved_version" ] \
  || fail "verified binary reports umbra ${reported_version}, expected ${resolved_version}; refusing signed downgrade or mismatched release"

dest_dir="$(install_dir)"
dest_path="${dest_dir}/umbra"
tmp_dest="${dest_dir}/.umbra.tmp.$$"
cp "$binary_path" "$tmp_dest"
mv "$tmp_dest" "$dest_path"

if ! path_contains "$dest_dir"; then
  info "${dest_dir} is not on PATH"
fi

info "installed ${dest_path}"
"$dest_path" --version
