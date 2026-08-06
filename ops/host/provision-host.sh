#!/usr/bin/env bash
# Install the host tooling Umbra needs from already-trusted package managers
# plus the pinned Go module authenticated by the public Go checksum database.
#
# Supported:
# - macOS with Homebrew, for local development
# - Debian/Ubuntu with apt, for Console VMs
#
# Idempotent where practical:
# - CLI tools already on PATH are skipped.
# - system/dev packages are always passed to apt/brew because package managers are idempotent.
#
# Installs or verifies:
# - docker
# - git
# - make
# - jq
# - curl
# - wget
# - postgresql-client / libpq
# - build-essential / gcc
# - pkg-config
# - libssl-dev / openssl
# - ca-certificates
# - the repository-pinned Rust toolchain
# - uv
# - GitHub CLI
# - Go >=1.23.2 (a versioned signed apt package on Linux)
# - slsa-verifier at a repository-pinned version
# - optionally Node.js + the locked, digest-pinned Phala CLI when both
#   PHALA_CLI_VERSION and PHALA_CLI_SHA256 are set
#
# Does NOT create deployment secrets:
# - .env layers
# - generated .env
# - JWT keys
# - SECRET_INJECTION_KEK_B64
# - shade checkout
# - Phala / Cloudflare / OIDC / GHCR tokens
#
# Usage:
#   bash ops/host/provision-host.sh
#   PHALA_CLI_VERSION=X.Y.Z PHALA_CLI_SHA256=<64-hex> bash ops/host/provision-host.sh
#   DRY_RUN=1 PHALA_CLI_VERSION=X.Y.Z PHALA_CLI_SHA256=<64-hex> bash ops/host/provision-host.sh
#
# CI / tests:
#   bash -n ops/host/provision-host.sh
#   DRY_RUN=1 PROVISION_OS=linux PROVISION_PKG_MANAGER=apt SKIP_PACKAGE_MANAGER_CHECK=1 bash ops/host/provision-host.sh
#   DRY_RUN=1 PROVISION_OS=macos PROVISION_PKG_MANAGER=brew SKIP_PACKAGE_MANAGER_CHECK=1 bash ops/host/provision-host.sh

set -euo pipefail

# Provisioning never needs the provider credential. Drop either accepted token
# spelling before the first child process so no bootstrap or verification tool
# can inherit it from an operator shell.
unset PHALA_API_TOKEN PHALA_CLOUD_API_KEY

PHALA_CLI_VERSION="${PHALA_CLI_VERSION:-}"
PHALA_CLI_SHA256="${PHALA_CLI_SHA256:-}"
PHALA_CLI_PATH="${PHALA_CLI_PATH:-/usr/local/bin/phala}"
PHALA_CLI_INSTALL_ROOT="/usr/local/lib/umbra/phala-cli"
DRY_RUN="${DRY_RUN:-false}"
SKIP_PACKAGE_MANAGER_CHECK="${SKIP_PACKAGE_MANAGER_CHECK:-false}"
PROVISION_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=ops/buildkit-version.sh
source "${PROVISION_REPO_ROOT}/ops/buildkit-version.sh"
PHALA_CLI_PACKAGE_JSON="${PROVISION_REPO_ROOT}/console/package.json"
PHALA_CLI_PACKAGE_LOCK="${PROVISION_REPO_ROOT}/console/package-lock.json"
PHALA_NODE_BINARY=""
PHALA_NPM_BINARY=""
PHALA_CURL_BINARY=""
RUST_TOOLCHAIN_VERSION="$(
  awk -F '"' '/^[[:space:]]*channel[[:space:]]*=/{print $2; exit}' \
    "${PROVISION_REPO_ROOT}/rust-toolchain.toml"
)"
SLSA_VERIFIER_VERSION="2.7.1"
SLSA_VERIFIER_PATH="${UMBRA_INSTALL_SLSA_VERIFIER:-/usr/local/bin/slsa-verifier}"
SLSA_VERIFIER_MIN_GO_VERSION="1.23.2"
SLSA_VERIFIER_APT_GO_PACKAGE="golang-1.24-go"
SLSA_VERIFIER_APT_GO_BINARY="/usr/lib/go-1.24/bin/go"
SLSA_VERIFIER_GO_BINARY=""

OS=""
PKG_MANAGER=""

log() {
  echo "provision-host: $*" >&2
}

die() {
  log "$@"
  exit 1
}

have() {
  command -v "$1" >/dev/null 2>&1
}

is_dry_run() {
  [ "$DRY_RUN" = "true" ] || [ "$DRY_RUN" = "1" ]
}

skip_package_manager_check() {
  [ "$SKIP_PACKAGE_MANAGER_CHECK" = "true" ] || [ "$SKIP_PACKAGE_MANAGER_CHECK" = "1" ]
}

run() {
  if is_dry_run; then
    printf 'provision-host: dry-run:' >&2
    printf ' %s' "$@" >&2
    printf '\n' >&2
    return 0
  fi

  "$@"
}

validate_inputs() {
  case "$DRY_RUN" in
    true|false|1|0)
      ;;
    *)
      die "DRY_RUN must be true, false, 1, or 0; got '${DRY_RUN}'"
      ;;
  esac

  case "$SKIP_PACKAGE_MANAGER_CHECK" in
    true|false|1|0)
      ;;
    *)
      die "SKIP_PACKAGE_MANAGER_CHECK must be true, false, 1, or 0; got '${SKIP_PACKAGE_MANAGER_CHECK}'"
      ;;
  esac

  if [ -n "$PHALA_CLI_VERSION" ] || [ -n "$PHALA_CLI_SHA256" ]; then
    [ -n "$PHALA_CLI_VERSION" ] \
      || die "PHALA_CLI_VERSION is required when PHALA_CLI_SHA256 is set"
    [ -n "$PHALA_CLI_SHA256" ] \
      || die "PHALA_CLI_SHA256 is required when PHALA_CLI_VERSION is set"
    if ! printf '%s\n' "$PHALA_CLI_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
      die "invalid PHALA_CLI_VERSION='${PHALA_CLI_VERSION}' (expected X.Y.Z)"
    fi
    if ! printf '%s\n' "$PHALA_CLI_SHA256" | grep -Eq '^[0-9A-Fa-f]{64}$'; then
      die "invalid PHALA_CLI_SHA256 (expected exactly 64 hexadecimal characters)"
    fi
    PHALA_CLI_SHA256="$(printf '%s\n' "$PHALA_CLI_SHA256" | awk '{print tolower($0)}')"
  fi

  case "$PHALA_CLI_PATH" in
    /*) ;;
    *) die "PHALA_CLI_PATH must be an absolute path" ;;
  esac
  if ! printf '%s\n' "$RUST_TOOLCHAIN_VERSION" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    die "could not read a pinned X.Y.Z Rust channel from rust-toolchain.toml"
  fi

  case "$SLSA_VERIFIER_PATH" in
    /*) ;;
    *) die "UMBRA_INSTALL_SLSA_VERIFIER must be an absolute path" ;;
  esac
}

detect_os() {
  if [ -n "${PROVISION_OS:-}" ] || [ -n "${PROVISION_PKG_MANAGER:-}" ]; then
    [ -n "${PROVISION_OS:-}" ] || die "PROVISION_PKG_MANAGER also requires PROVISION_OS"
    [ -n "${PROVISION_PKG_MANAGER:-}" ] || die "PROVISION_OS also requires PROVISION_PKG_MANAGER"

    case "$PROVISION_OS" in
      linux|macos)
        OS="$PROVISION_OS"
        ;;
      *)
        die "invalid PROVISION_OS='${PROVISION_OS}' (expected: linux | macos)"
        ;;
    esac

    case "$PROVISION_PKG_MANAGER" in
      apt|brew)
        PKG_MANAGER="$PROVISION_PKG_MANAGER"
        ;;
      *)
        die "invalid PROVISION_PKG_MANAGER='${PROVISION_PKG_MANAGER}' (expected: apt | brew)"
        ;;
    esac

    case "${OS}:${PKG_MANAGER}" in
      linux:apt|macos:brew)
        ;;
      *)
        die "invalid forced OS/package-manager pair: ${OS}/${PKG_MANAGER}"
        ;;
    esac

    log "using forced OS=${OS}, package manager=${PKG_MANAGER}"
    return 0
  fi

  case "$(uname -s)" in
    Darwin)
      OS="macos"
      PKG_MANAGER="brew"
      ;;
    Linux)
      if have apt-get; then
        OS="linux"
        PKG_MANAGER="apt"
      else
        die "unsupported Linux: no apt-get; install tooling manually per docs/operator-setup.md"
      fi
      ;;
    *)
      die "unsupported OS '$(uname -s)'; see docs/operator-setup.md"
      ;;
  esac

  log "detected OS=${OS}, package manager=${PKG_MANAGER}"
}

require_package_manager_ready() {
  if skip_package_manager_check; then
    log "skipping package manager readiness check"
    return 0
  fi

  case "$PKG_MANAGER" in
    brew)
      have brew || die "Homebrew is required first: https://brew.sh"
      ;;
    apt)
      have sudo || die "sudo is required on Debian/Ubuntu"

      export DEBIAN_FRONTEND=noninteractive
      run sudo apt-get update -y
      ;;
    *)
      die "unsupported package manager: ${PKG_MANAGER}"
      ;;
  esac
}

tool_binary() {
  case "$1" in
    curl) echo "curl" ;;
    wget) echo "wget" ;;
    git) echo "git" ;;
    make) echo "make" ;;
    jq) echo "jq" ;;
    psql) echo "psql" ;;
    pkg-config) echo "pkg-config" ;;
    go) echo "go" ;;
    *)
      die "unknown CLI tool '${1}'"
      ;;
  esac
}

package_for_os() {
  package_name="$1"

  case "${PKG_MANAGER}:${package_name}" in
    brew:ca-certificates) echo "ca-certificates" ;;
    brew:build-essential) echo "gcc" ;;
    brew:openssl-dev) echo "openssl" ;;

    apt:ca-certificates) echo "ca-certificates" ;;
    apt:build-essential) echo "build-essential" ;;
    apt:openssl-dev) echo "libssl-dev" ;;

    *)
      die "no package-only mapping for '${package_name}' on package manager='${PKG_MANAGER}'"
      ;;
  esac
}

tool_package_for_os() {
  tool="$1"

  case "${PKG_MANAGER}:${tool}" in
    brew:curl) echo "curl" ;;
    brew:wget) echo "wget" ;;
    brew:git) echo "git" ;;
    brew:make) echo "make" ;;
    brew:jq) echo "jq" ;;
    brew:psql) echo "libpq" ;;
    brew:pkg-config) echo "pkg-config" ;;
    brew:go) echo "go" ;;

    apt:curl) echo "curl" ;;
    apt:wget) echo "wget" ;;
    apt:git) echo "git" ;;
    apt:make) echo "make" ;;
    apt:jq) echo "jq" ;;
    apt:psql) echo "postgresql-client" ;;
    apt:pkg-config) echo "pkg-config" ;;

    *)
      die "no CLI tool mapping for tool='${tool}' on package manager='${PKG_MANAGER}'"
      ;;
  esac
}

install_package() {
  local package="$1"

  case "$PKG_MANAGER" in
    brew)
      run brew install "$package"
      ;;
    apt)
      run sudo apt-get install -y --no-install-recommends "$package"
      ;;
    *)
      die "unsupported package manager: ${PKG_MANAGER}"
      ;;
  esac
}

apt_package_available() {
  apt-cache show "$1" >/dev/null 2>&1
}

install_first_available_apt_package() {
  local package
  local purpose="$1"
  shift

  if is_dry_run; then
    log "dry-run: install first available signed apt package for ${purpose}: $*"
    return 0
  fi

  for package in "$@"; do
    if apt_package_available "$package"; then
      install_package "$package"
      return 0
    fi
  done

  die "no signed apt package is available for ${purpose} (tried: $*); configure an organization-approved signed package source or preinstall it, then rerun"
}

apt_package_candidate_version() {
  apt-cache policy "$1" 2>/dev/null \
    | awk '$1 == "Candidate:" { print $2; exit }'
}

install_supported_buildx_apt_package() {
  local candidate package version

  if is_dry_run; then
    log "dry-run: install first signed apt package providing Buildx ${UMBRA_BUILDX_VERSION}: $*"
    return 0
  fi

  for package in "$@"; do
    apt_package_available "$package" || continue
    candidate="$(apt_package_candidate_version "$package")" || continue
    if [[ "$candidate" =~ ([0-9]+\.[0-9]+\.[0-9]+) ]]; then
      version="${BASH_REMATCH[1]}"
      if [ "$version" = "$UMBRA_BUILDX_VERSION" ]; then
        # Pin the candidate read above in the apt request itself. Otherwise an
        # index refresh between policy and install can silently select a newer
        # client than the reproducibility contract reviewed.
        install_package "${package}=${candidate}"
        return 0
      fi
    fi
  done

  die "no signed apt package provides Buildx ${UMBRA_BUILDX_VERSION} (tried: $*); configure an organization-approved signed package source or preinstall it, then rerun"
}

ensure_tool() {
  local tool
  local binary
  local package

  tool="$1"
  binary="$(tool_binary "$tool")"
  package="$(tool_package_for_os "$tool")"

  if have "$binary"; then
    log "${tool} already installed; found '${binary}' on PATH"
    return 0
  fi

  log "installing ${tool}: package='${package}', binary='${binary}'"
  install_package "$package"

  if is_dry_run; then
    return 0
  fi

  if ! have "$binary"; then
    die "${tool} installation finished, but '${binary}' is still not on PATH"
  fi
}

ensure_package_only() {
  local package_name
  local package

  package_name="$1"
  package="$(package_for_os "$package_name")"

  log "ensuring package ${package_name}: package='${package}'"
  install_package "$package"
}

ensure_common_tools() {
  # Real CLI tools: safe to gate on command -v.
  ensure_tool curl
  ensure_tool wget
  ensure_tool git
  ensure_tool make
  ensure_tool jq
  ensure_tool psql
  ensure_tool pkg-config

  # System/dev packages: do not gate on proxy binaries.
  # apt/brew are idempotent, so repeatedly ensuring them is OK.
  ensure_package_only ca-certificates
  ensure_package_only build-essential
  ensure_package_only openssl-dev
}

ensure_docker() {
  local current_user

  if have docker; then
    umbra_buildx_client_supported \
      || die "docker is installed but exact Buildx ${UMBRA_BUILDX_VERSION} is unavailable; install that signed docker-buildx or docker-buildx-plugin version, then rerun"
    docker compose version >/dev/null 2>&1 \
      || die "docker is installed but Compose v2 is missing; install a signed docker-compose-v2 or docker-compose-plugin package, then rerun"
    if is_dry_run; then
      log "docker, supported Buildx, and Compose v2 already installed; dry-run skipped live builder bootstrap"
      return 0
    fi
    umbra_require_reproducible_builder \
      || die "the digest-pinned ${UMBRA_BUILDKIT_BUILDER} builder is unavailable (${UMBRA_BUILDKIT_FAILURE}); start Docker, refresh docker-group access, or resolve a conflicting builder before rerunning"
    log "docker, Buildx, Compose v2, and the digest-pinned BuildKit ${UMBRA_BUILDKIT_VERSION} builder are ready"
    return 0
  fi

  case "$OS" in
    macos)
      log "Docker is not installed."
      log "Install Docker Desktop with:"
      log "  brew install --cask docker"
      log "then launch it once and rerun this script."
      if ! is_dry_run; then
        die "Docker Desktop must be installed and running before provisioning can continue"
      fi
      ;;
    linux)
      log "installing Docker from configured signed apt repositories"
      install_first_available_apt_package "Docker Engine" docker-ce docker.io
      install_supported_buildx_apt_package docker-buildx-plugin docker-buildx
      install_first_available_apt_package "Docker Compose v2" docker-compose-plugin docker-compose-v2

      if is_dry_run; then
        return 0
      fi

      umbra_buildx_client_supported \
        || die "signed Docker packages installed, but exact Buildx ${UMBRA_BUILDX_VERSION} is unavailable"
      docker compose version >/dev/null 2>&1 \
        || die "signed Docker packages installed, but 'docker compose version' still fails"

      current_user="$(id -un)"
      run sudo usermod -aG docker "$current_user"
      log "added ${current_user} to the docker group; re-login, then rerun this provisioner so it can create and verify the digest-pinned BuildKit builder before 'make up'"
      ;;
    *)
      die "unsupported OS for docker install: ${OS}"
      ;;
  esac
}

rust_toolchain_ready() {
  have cargo \
    && have rustc \
    && have rustfmt \
    && [ "$(rustc --version 2>/dev/null | awk '{print $2}')" = "$RUST_TOOLCHAIN_VERSION" ] \
    && cargo clippy --version >/dev/null 2>&1
}

ensure_rust() {
  local rustup_bin
  local rustup_path=""

  if rust_toolchain_ready; then
    log "Rust ${RUST_TOOLCHAIN_VERSION} with Cargo, rustfmt, and clippy already installed"
    return 0
  fi

  if ! have rustup; then
    case "$OS" in
      macos)
        log "installing rustup with Homebrew"
        install_package rustup
        ;;
      linux)
        if is_dry_run; then
          log "dry-run: install signed apt package rustup when available; otherwise fail closed with preinstallation guidance"
          install_package rustup
        elif apt_package_available rustup; then
          install_package rustup
        else
          die "Rust ${RUST_TOOLCHAIN_VERSION} is required and no signed rustup package is available from configured apt sources; preinstall rustup from a distro or organization-approved signed package source, then rerun"
        fi
        ;;
      *)
        die "unsupported OS for Rust install: ${OS}"
        ;;
    esac
  fi

  if is_dry_run; then
    log "dry-run: rustup toolchain install ${RUST_TOOLCHAIN_VERSION} --profile minimal --component rustfmt --component clippy"
    log "dry-run: rustup default ${RUST_TOOLCHAIN_VERSION}"
    return 0
  fi

  if [ "$OS" = "macos" ]; then
    rustup_path="$(brew --prefix rustup 2>/dev/null || true)"
    if [ -n "$rustup_path" ] && [ -x "${rustup_path}/bin/rustup" ]; then
      rustup_path="${rustup_path}/bin"
    else
      rustup_path=""
    fi
  fi

  if [ -n "$rustup_path" ]; then
    rustup_bin="${rustup_path}/rustup"
    export PATH="${rustup_path}:${PATH}"
    log "Homebrew rustup is keg-only; add ${rustup_path} to PATH in your shell profile"
  elif have rustup; then
    rustup_bin="$(command -v rustup)"
  else
    die "rustup installation finished, but 'rustup' is still not on PATH"
  fi

  "$rustup_bin" toolchain install "$RUST_TOOLCHAIN_VERSION" \
    --profile minimal --component rustfmt --component clippy
  "$rustup_bin" default "$RUST_TOOLCHAIN_VERSION"

  rust_toolchain_ready \
    || die "Rust provisioning finished, but the pinned ${RUST_TOOLCHAIN_VERSION} toolchain with rustfmt and clippy is unavailable"
}

ensure_uv() {
  if have uv; then
    log "uv already installed"
    return 0
  fi

  case "$OS" in
    macos)
      log "installing uv with Homebrew"
      install_package uv
      ;;
    linux)
      if is_dry_run; then
        log "dry-run: install signed apt package uv when available; otherwise fail closed with preinstallation guidance"
        install_package uv
      elif apt_package_available uv; then
        install_package uv
      else
        die "uv is required and no signed uv package is available from configured apt sources; preinstall uv from a distro or organization-approved signed package source, then rerun"
      fi
      ;;
    *)
      die "unsupported OS for uv install: ${OS}"
      ;;
  esac

  if ! is_dry_run && ! have uv; then
    die "uv installation finished, but 'uv' is still not on PATH"
  fi
}

ensure_gh() {
  if have gh; then
    log "gh already installed"
    return 0
  fi

  case "$OS" in
    macos)
      log "installing GitHub CLI with Homebrew"
      install_package gh
      ;;
    linux)
      log "installing GitHub CLI from configured signed apt repositories"
      install_first_available_apt_package "GitHub CLI" gh
      ;;
    *)
      die "unsupported OS for gh install: ${OS}"
      ;;
  esac

  if is_dry_run; then
    return 0
  fi

  if ! have gh; then
    die "GitHub CLI installation finished, but 'gh' is still not on PATH"
  fi
}

slsa_verifier_reports_pinned_version() {
  local verifier="$1"

  [ -x "$verifier" ] \
    && "$verifier" version 2>&1 \
      | grep -Eq "(^|[^0-9])v?${SLSA_VERIFIER_VERSION//./\\.}([^0-9]|$)"
}

go_binary_version() {
  local output
  local version

  output="$("$1" version 2>/dev/null)" || return 1
  version="$(printf '%s\n' "$output" | awk '$1 == "go" && $2 == "version" { sub(/^go/, "", $3); print $3; exit }')"
  [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  printf '%s\n' "$version"
}

ensure_slsa_verifier_go() {
  local actual_version
  local go_prefix

  case "$OS" in
    linux)
      if is_dry_run; then
        log "dry-run: install signed apt package ${SLSA_VERIFIER_APT_GO_PACKAGE} for Go >= ${SLSA_VERIFIER_MIN_GO_VERSION}"
        install_package "$SLSA_VERIFIER_APT_GO_PACKAGE"
      elif apt_package_available "$SLSA_VERIFIER_APT_GO_PACKAGE"; then
        install_package "$SLSA_VERIFIER_APT_GO_PACKAGE"
      else
        die "slsa-verifier ${SLSA_VERIFIER_VERSION} requires Go >= ${SLSA_VERIFIER_MIN_GO_VERSION}, but signed apt package ${SLSA_VERIFIER_APT_GO_PACKAGE} is unavailable; enable the Ubuntu updates/security universe source or configure an organization-approved signed apt source that provides it, then rerun"
      fi
      SLSA_VERIFIER_GO_BINARY="$SLSA_VERIFIER_APT_GO_BINARY"
      ;;
    macos)
      # Homebrew is the trusted package boundary on macOS. Install idempotently,
      # then use that package's absolute binary rather than another `go` on PATH.
      install_package go
      if is_dry_run; then
        SLSA_VERIFIER_GO_BINARY="go"
      else
        go_prefix="$(brew --prefix go 2>/dev/null)" \
          || die "Homebrew installed Go, but its package prefix is unavailable"
        SLSA_VERIFIER_GO_BINARY="${go_prefix}/bin/go"
      fi
      ;;
    *)
      die "unsupported OS for Go install: ${OS}"
      ;;
  esac

  if is_dry_run; then
    log "dry-run: use ${SLSA_VERIFIER_GO_BINARY} and require Go >= ${SLSA_VERIFIER_MIN_GO_VERSION}"
    return 0
  fi

  [ -x "$SLSA_VERIFIER_GO_BINARY" ] \
    || die "signed Go package did not provide the expected compiler at ${SLSA_VERIFIER_GO_BINARY}"
  actual_version="$(go_binary_version "$SLSA_VERIFIER_GO_BINARY")" \
    || die "could not determine the Go version at ${SLSA_VERIFIER_GO_BINARY}"
  umbra_version_at_least "$actual_version" "$SLSA_VERIFIER_MIN_GO_VERSION" \
    || die "Go ${actual_version} at ${SLSA_VERIFIER_GO_BINARY} is too old; slsa-verifier ${SLSA_VERIFIER_VERSION} requires Go >= ${SLSA_VERIFIER_MIN_GO_VERSION}"
  log "using Go ${actual_version} at ${SLSA_VERIFIER_GO_BINARY} for slsa-verifier"
}

ensure_slsa_verifier() {
  local install_dir
  local install_tmp
  local module

  ensure_slsa_verifier_go
  module="github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v${SLSA_VERIFIER_VERSION}"

  if is_dry_run; then
    log "dry-run: rebuild ${module} with an isolated Go environment, CGO_ENABLED=0, GOENV=off, GOFLAGS empty, GOWORK=off, GOTOOLCHAIN=local, GOPROXY=https://proxy.golang.org, and GOSUMDB=sum.golang.org"
    log "dry-run: install verified binary at ${SLSA_VERIFIER_PATH}"
    return 0
  fi

  install_tmp="$(mktemp -d "${TMPDIR:-/tmp}/umbra-slsa-verifier.XXXXXX")"
  mkdir -p \
    "${install_tmp}/cache" \
    "${install_tmp}/home" \
    "${install_tmp}/modcache" \
    "${install_tmp}/path" \
    "${install_tmp}/tmp"
  if ! env -i \
    PATH=/usr/bin:/bin \
    HOME="${install_tmp}/home" \
    TMPDIR="${install_tmp}/tmp" \
    CGO_ENABLED=0 \
    CC= \
    CXX= \
    GOBIN="$install_tmp" \
    GOCACHE="${install_tmp}/cache" \
    GOENV=off \
    GOFLAGS= \
    GOINSECURE= \
    GOMODCACHE="${install_tmp}/modcache" \
    GOPATH="${install_tmp}/path" \
    GOPRIVATE= \
    GONOSUMDB= \
    GONOPROXY= \
    GOPROXY=https://proxy.golang.org \
    GOSUMDB=sum.golang.org \
    GOTMPDIR="${install_tmp}/tmp" \
    GOTOOLCHAIN=local \
    GOVCS='*:off' \
    GOWORK=off \
      "$SLSA_VERIFIER_GO_BINARY" install "$module"; then
    rm -rf "$install_tmp"
    die "failed to install pinned slsa-verifier ${SLSA_VERIFIER_VERSION} through the public Go checksum service"
  fi

  [ -x "$install_tmp/slsa-verifier" ] || {
    rm -rf "$install_tmp"
    die "Go installation did not produce slsa-verifier"
  }
  slsa_verifier_reports_pinned_version "$install_tmp/slsa-verifier" || {
    rm -rf "$install_tmp"
    die "authenticated Go build did not produce slsa-verifier ${SLSA_VERIFIER_VERSION}"
  }
  install_dir="$(dirname "$SLSA_VERIFIER_PATH")"
  run sudo mkdir -p "$install_dir"
  run sudo install -m 0755 "$install_tmp/slsa-verifier" "$SLSA_VERIFIER_PATH"

  if ! cmp -s "$install_tmp/slsa-verifier" "$SLSA_VERIFIER_PATH"; then
    rm -rf "$install_tmp"
    die "installed slsa-verifier differs from the authenticated Go build"
  fi
  rm -rf "$install_tmp"

  slsa_verifier_reports_pinned_version "$SLSA_VERIFIER_PATH" \
    || die "installed slsa-verifier does not report pinned version ${SLSA_VERIFIER_VERSION}"
  log "installed slsa-verifier ${SLSA_VERIFIER_VERSION} at ${SLSA_VERIFIER_PATH}"
}

node_supported() {
  local node_binary
  local major
  local version

  node_binary="$(type -P node 2>/dev/null)" || return 1
  [ -x "$node_binary" ] || return 1
  version="$(env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C "$node_binary" --version 2>/dev/null)"
  version="${version#v}"
  major="${version%%.*}"
  case "$major" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$major" -ge 18 ]
}

resolve_phala_tool_binaries() {
  PHALA_NODE_BINARY="$(type -P node 2>/dev/null)" \
    || die "could not resolve the package-managed Node.js executable"
  PHALA_NPM_BINARY="$(type -P npm 2>/dev/null)" \
    || die "could not resolve the package-managed npm executable"
  PHALA_CURL_BINARY="$(type -P curl 2>/dev/null)" \
    || die "could not resolve the package-managed curl executable"
  case "${PHALA_NODE_BINARY}:${PHALA_NPM_BINARY}:${PHALA_CURL_BINARY}" in
    /*:/*:/*) ;;
    *) die "Node.js, npm, and curl must resolve to absolute executable paths" ;;
  esac
  [ -x "$PHALA_NODE_BINARY" ] && [ -x "$PHALA_NPM_BINARY" ] && [ -x "$PHALA_CURL_BINARY" ] \
    || die "Node.js, npm, or curl resolved to a non-executable path"
}

run_phala_node() {
  env -i \
    PATH=/usr/bin:/bin \
    LANG=C \
    LC_ALL=C \
      "$PHALA_NODE_BINARY" "$@"
}

run_phala_npm_ci() {
  local install_root="$1"
  local clean_path

  mkdir -p "${install_root}/npm-cache" "${install_root}/npm-home" "${install_root}/npm-tmp"
  : > "${install_root}/npm-globalconfig"
  : > "${install_root}/npm-userconfig"
  clean_path="$(dirname "$PHALA_NODE_BINARY"):/usr/bin:/bin"
  env -i \
    PATH="$clean_path" \
    HOME="${install_root}/npm-home" \
    TMPDIR="${install_root}/npm-tmp" \
    LANG=C \
    LC_ALL=C \
    NPM_CONFIG_AUDIT=false \
    NPM_CONFIG_CACHE="${install_root}/npm-cache" \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_GLOBALCONFIG="${install_root}/npm-globalconfig" \
    NPM_CONFIG_IGNORE_SCRIPTS=true \
    NPM_CONFIG_PACKAGE_LOCK=true \
    NPM_CONFIG_PACKAGE_LOCK_ONLY=false \
    NPM_CONFIG_PROVENANCE=false \
    NPM_CONFIG_REGISTRY=https://registry.npmjs.org \
    NPM_CONFIG_REPLACE_REGISTRY_HOST=never \
    NPM_CONFIG_STRICT_SSL=true \
    NPM_CONFIG_UPDATE_NOTIFIER=false \
    NPM_CONFIG_USERCONFIG="${install_root}/npm-userconfig" \
      "$PHALA_NPM_BINARY" ci \
        --prefix "$install_root" \
        --omit=dev \
        --ignore-scripts \
        --no-audit \
        --no-fund \
        --registry=https://registry.npmjs.org \
        --strict-ssl=true \
        --userconfig="${install_root}/npm-userconfig" \
        --globalconfig="${install_root}/npm-globalconfig"
}

ensure_node() {
  if node_supported && have npm; then
    if ! is_dry_run; then
      resolve_phala_tool_binaries
    fi
    log "supported Node.js and npm already installed"
    return 0
  fi

  case "$OS" in
    macos)
      log "installing Node.js with Homebrew"
      install_package node
      ;;
    linux)
      log "installing Node.js and npm from configured signed apt repositories"
      install_first_available_apt_package "Node.js" nodejs
      if is_dry_run; then
        log "dry-run: ensure npm is bundled with Node.js or install the signed apt package npm"
      elif ! have npm; then
        install_first_available_apt_package "npm" npm
      fi
      ;;
    *)
      die "unsupported OS for node install: ${OS}"
      ;;
  esac

  if is_dry_run; then
    return 0
  fi

  if ! node_supported || ! have npm; then
    die "Phala CLI requires Node.js >=18 with npm; install it from a distro, vendor, or organization-approved signed package source (this script will not add NodeSource), then rerun"
  fi
  resolve_phala_tool_binaries
}

sha256_file() {
  run_phala_node -e '
    const crypto = require("node:crypto");
    const fs = require("node:fs");
    const digest = crypto.createHash("sha256").update(fs.readFileSync(process.argv[1])).digest("hex");
    process.stdout.write(digest + "\n");
  ' "$1"
}

sha512_integrity_file() {
  run_phala_node -e '
    const crypto = require("node:crypto");
    const fs = require("node:fs");
    const digest = crypto.createHash("sha512").update(fs.readFileSync(process.argv[1])).digest("base64");
    process.stdout.write("sha512-" + digest + "\n");
  ' "$1"
}

phala_cli_version_output_matches() {
  local output="$1"
  local suffix

  case "$output" in
    "$PHALA_CLI_VERSION"|"v${PHALA_CLI_VERSION}")
      return 0
      ;;
    "${PHALA_CLI_VERSION}+"*|"v${PHALA_CLI_VERSION}+"*)
      suffix="${output#*+}"
      [ -n "$suffix" ] || return 1
      case "$suffix" in
        *[!0-9A-Za-z.-]*) return 1 ;;
      esac
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

phala_cli_version_ready() {
  local launcher="$1"
  local output

  [ -x "$launcher" ] || return 1
  output="$(run_phala_node "$launcher" --version 2>/dev/null)" || return 1
  phala_cli_version_output_matches "$output"
}

phala_package_identity_ready() {
  local package_json="$1"

  [ -f "$package_json" ] \
    && [ ! -L "$package_json" ] \
    && jq -e --arg version "$PHALA_CLI_VERSION" \
      '.name == "phala" and .version == $version and .bin.phala == "dist/index.js"' \
      "$package_json" >/dev/null
}

phala_install_tree_permissions_ready() {
  local install_dir="$1"
  local unsafe_path

  [ -d "$install_dir" ] && [ ! -L "$install_dir" ] || return 1
  unsafe_path="$(
    find -P "$install_dir" \
      \( ! -user root -o -perm -020 -o -perm -002 \) \
      -print -quit
  )" || return 1
  [ -z "$unsafe_path" ]
}

phala_path_resolves_to() {
  local candidate="$1"
  local expected="$2"

  [ -e "$candidate" ] && [ -e "$expected" ] \
    && run_phala_node -e '
      const fs = require("node:fs");
      process.exit(fs.realpathSync(process.argv[1]) === fs.realpathSync(process.argv[2]) ? 0 : 1);
    ' "$candidate" "$expected"
}

phala_lock_material() {
  local package_json="${1:-$PHALA_CLI_PACKAGE_JSON}"
  local package_lock="${2:-$PHALA_CLI_PACKAGE_LOCK}"
  local lock_fields
  local manifest_version
  local root_version
  local package_version
  local resolved
  local integrity
  local expected_url

  manifest_version="$(jq -er '.dependencies.phala | select(type == "string")' "$package_json")" \
    || die "could not read the pinned Phala version from ${package_json}"
  lock_fields="$(
    jq -er '
      [
        .packages[""].dependencies.phala,
        .packages["node_modules/phala"].version,
        .packages["node_modules/phala"].resolved,
        .packages["node_modules/phala"].integrity
      ]
      | if all(.[]; type == "string" and length > 0) then @tsv
        else error("incomplete locked phala package") end
    ' "$package_lock"
  )" || die "could not read locked Phala package material from ${package_lock}"
  jq -e '
    all(
      .packages | to_entries[];
      .key == ""
      or (
        (.value.version | type == "string" and length > 0)
        and (.value.resolved | type == "string" and startswith("https://registry.npmjs.org/"))
        and (.value.integrity | type == "string" and test("^sha512-[0-9A-Za-z+/]+={0,2}$"))
      )
    )
  ' "$package_lock" >/dev/null \
    || die "every npm dependency must have an exact version and canonical registry integrity pin"
  IFS=$'\t' read -r root_version package_version resolved integrity <<< "$lock_fields"

  [ "$manifest_version" = "$PHALA_CLI_VERSION" ] \
    || die "PHALA_CLI_VERSION=${PHALA_CLI_VERSION} does not match ${package_json} (${manifest_version})"
  [ "$root_version" = "$PHALA_CLI_VERSION" ] && [ "$package_version" = "$PHALA_CLI_VERSION" ] \
    || die "PHALA_CLI_VERSION=${PHALA_CLI_VERSION} does not match the committed npm lock"
  expected_url="https://registry.npmjs.org/phala/-/phala-${PHALA_CLI_VERSION}.tgz"
  [ "$resolved" = "$expected_url" ] \
    || die "locked Phala tarball URL is not the canonical npm registry URL for ${PHALA_CLI_VERSION}"
  printf '%s\n' "$integrity" | grep -Eq '^sha512-[0-9A-Za-z+/]+={0,2}$' \
    || die "locked Phala package is missing a valid sha512 integrity pin"

  printf '%s\t%s\n' "$resolved" "$integrity"
}

link_phala_cli() {
  local source="$1"
  local target="$PHALA_CLI_PATH"

  [ -x "$source" ] && [ ! -L "$source" ] \
    || die "verified Phala launcher is missing or is not a regular executable: ${source}"
  [ ! -d "$target" ] || die "PHALA_CLI_PATH names a directory: ${target}"

  if phala_path_resolves_to "$target" "$source"; then
    log "phala CLI already at ${target}"
    return 0
  fi

  log "linking ${target} directly to verified launcher ${source}"
  case "$OS" in
    macos|linux)
      run sudo mkdir -p "$(dirname "$target")"
      run sudo ln -sfn "$source" "$target"
      ;;
    *)
      die "unsupported OS for phala link: ${OS}"
      ;;
  esac

  phala_path_resolves_to "$target" "$source" \
    || die "PHALA_CLI_PATH does not resolve to the verified launcher after installation"
}

ensure_phala_cli() {
  local final_dir
  local final_launcher
  local install_tmp=""
  local publish_stage=""
  local lock_material
  local locked_integrity
  local tarball_url
  local tarball_path
  local actual_sha256
  local actual_integrity

  [ -n "$PHALA_CLI_VERSION" ] || return 0

  ensure_node

  if is_dry_run; then
    log "dry-run: verify phala@${PHALA_CLI_VERSION} against console/package.json and the complete console/package-lock.json dependency graph"
    log "dry-run: require tarball sha256 ${PHALA_CLI_SHA256} for https://registry.npmjs.org/phala/-/phala-${PHALA_CLI_VERSION}.tgz"
    log "dry-run: npm ci --omit=dev --ignore-scripts --no-audit --no-fund from the committed lock"
    log "dry-run: link ${PHALA_CLI_PATH} directly to the verified package launcher under ${PHALA_CLI_INSTALL_ROOT}"
    return 0
  fi

  (
    # shellcheck disable=SC2329 # Invoked indirectly by the EXIT trap below.
    cleanup_phala_install() {
      if [ -n "$install_tmp" ]; then
        rm -rf "$install_tmp"
      fi
      if [ -n "$publish_stage" ] && [ -e "$publish_stage" ]; then
        case "$OS" in
          macos|linux) sudo rm -rf "$publish_stage" ;;
        esac
      fi
    }
    trap cleanup_phala_install EXIT

    install_tmp="$(mktemp -d "${TMPDIR:-/tmp}/umbra-phala-cli.XXXXXX")"
    cp "$PHALA_CLI_PACKAGE_JSON" "${install_tmp}/package.json"
    cp "$PHALA_CLI_PACKAGE_LOCK" "${install_tmp}/package-lock.json"
    lock_material="$(phala_lock_material "${install_tmp}/package.json" "${install_tmp}/package-lock.json")"
    IFS=$'\t' read -r tarball_url locked_integrity <<< "$lock_material"
    tarball_path="${install_tmp}/phala-${PHALA_CLI_VERSION}.tgz"
    env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C \
      "$PHALA_CURL_BINARY" --disable \
      --fail --silent --show-error --location \
      --proto '=https' --proto-redir '=https' --tlsv1.2 \
      --noproxy '*' --max-redirs 3 --connect-timeout 20 --max-time 120 \
      --max-filesize 52428800 \
      --output "$tarball_path" "$tarball_url" \
      || die "failed to download the locked Phala CLI tarball"
    actual_sha256="$(sha256_file "$tarball_path")"
    [ "$actual_sha256" = "$PHALA_CLI_SHA256" ] \
      || die "Phala CLI tarball sha256 mismatch: expected ${PHALA_CLI_SHA256}, got ${actual_sha256}"
    actual_integrity="$(sha512_integrity_file "$tarball_path")"
    [ "$actual_integrity" = "$locked_integrity" ] \
      || die "Phala CLI tarball does not match the integrity in the committed npm lock"

    final_dir="${PHALA_CLI_INSTALL_ROOT}/${PHALA_CLI_VERSION}-${PHALA_CLI_SHA256}"
    final_launcher="${final_dir}/node_modules/phala/dist/index.js"
    sudo mkdir -p "$(dirname "$PHALA_CLI_INSTALL_ROOT")" "$PHALA_CLI_INSTALL_ROOT"
    sudo chown root "$(dirname "$PHALA_CLI_INSTALL_ROOT")" "$PHALA_CLI_INSTALL_ROOT"
    sudo chmod 0755 "$(dirname "$PHALA_CLI_INSTALL_ROOT")" "$PHALA_CLI_INSTALL_ROOT"
    if [ -e "$final_dir" ]; then
      if ! phala_install_tree_permissions_ready "$final_dir" \
        || ! phala_package_identity_ready "${final_dir}/node_modules/phala/package.json" \
        || [ ! -f "$final_launcher" ] || [ -L "$final_launcher" ] \
        || ! phala_cli_version_ready "$final_launcher"; then
        die "existing digest-addressed Phala install is invalid: ${final_dir}"
      fi
      link_phala_cli "$final_launcher"
      log "phala CLI ${PHALA_CLI_VERSION} already installed from the verified locked package"
      exit 0
    fi

    run_phala_npm_ci "$install_tmp" \
      || die "failed to install the committed Phala dependency graph with npm ci"
    phala_package_identity_ready "${install_tmp}/node_modules/phala/package.json" \
      || die "locked npm install did not produce exact phala@${PHALA_CLI_VERSION} package metadata"
    [ -f "${install_tmp}/node_modules/phala/dist/index.js" ] \
      && [ ! -L "${install_tmp}/node_modules/phala/dist/index.js" ] \
      || die "locked npm install did not produce the direct Phala launcher"
    phala_cli_version_ready "${install_tmp}/node_modules/phala/dist/index.js" \
      || die "installed Phala launcher does not report exact version ${PHALA_CLI_VERSION}"

    case "$OS" in
      macos|linux)
        publish_stage="$(sudo mktemp -d "${PHALA_CLI_INSTALL_ROOT}/.install.XXXXXX")"
        sudo cp -R "${install_tmp}/package.json" "${install_tmp}/package-lock.json" \
          "${install_tmp}/node_modules" "$publish_stage/"
        sudo chmod -R go-w "$publish_stage"
        sudo chmod 0755 "$publish_stage"
        [ ! -e "$final_dir" ] || die "Phala install appeared concurrently: ${final_dir}"
        sudo mv "$publish_stage" "$final_dir"
        ;;
      *)
        die "unsupported OS for phala install: ${OS}"
        ;;
    esac
    publish_stage=""

    if ! phala_install_tree_permissions_ready "$final_dir" \
      || ! phala_package_identity_ready "${final_dir}/node_modules/phala/package.json" \
      || ! phala_cli_version_ready "$final_launcher"; then
      die "published Phala CLI failed exact package/version verification"
    fi
    link_phala_cli "$final_launcher"
    log "installed locked phala CLI ${PHALA_CLI_VERSION} at ${PHALA_CLI_PATH}"
  )
}

print_next_steps() {
  if [ -n "$PHALA_CLI_VERSION" ]; then
    log "keep the verified Phala pins in the generated .env:"
    log "  PHALA_CLI_VERSION=${PHALA_CLI_VERSION}"
    log "  PHALA_CLI_SHA256=${PHALA_CLI_SHA256}"
  fi

  log "tooling done."
  log "remaining manual steps are documented in docs/operator-setup.md:"
  log "  clone repo"
  log "  author .env layers"
  log "  run make build-env MODE=<staging|prod>"
  log "  generate JWT keys"
  log "  set SECRET_INJECTION_KEK_B64"
  log "  configure SHADE_DIR"
  log "  configure DNS, OIDC redirect, Phala, Cloudflare, and GHCR tokens"
  log "then run the appropriate make target for this host."
}

main() {
  validate_inputs
  detect_os
  require_package_manager_ready

  ensure_common_tools
  ensure_docker
  ensure_rust
  ensure_uv
  ensure_gh
  ensure_slsa_verifier
  ensure_phala_cli

  print_next_steps
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
