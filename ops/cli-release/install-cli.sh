#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "install-cli: $1" >&2
  exit "${2:-1}"
}

info() {
  echo "install-cli: $1" >&2
}

path_contains() {
  local dir="$1"
  case ":${PATH}:" in
    *":${dir}:"*) return 0 ;;
    *) return 1 ;;
  esac
}

try_shim() {
  local dir="$1"
  local cargo_bin="$2"

  path_contains "$dir" || return 1
  mkdir -p "$dir"
  [ -w "$dir" ] || return 1
  ln -sf "$cargo_bin" "$dir/umbra"
  hash -r 2>/dev/null || true
  command -v umbra >/dev/null 2>&1
}

command -v cargo >/dev/null || fail "cargo is required"

cargo install --locked --profile cli-install --path cli

cargo_home="${CARGO_HOME:-${HOME}/.cargo}"
cargo_bin="${cargo_home}/bin/umbra"
[ -x "$cargo_bin" ] || fail "cargo did not install ${cargo_bin}"

on_path="$(command -v umbra 2>/dev/null || true)"
if [ "$on_path" = "$cargo_bin" ]; then
  info "umbra is available at $on_path"
  exit 0
fi

for dir in "${HOME}/.local/bin" "${HOME}/bin" /usr/local/bin /opt/homebrew/bin; do
  if try_shim "$dir" "$cargo_bin"; then
    info "created PATH-visible shim at ${dir}/umbra"
    info "umbra is available at $(command -v umbra)"
    exit 0
  fi
done

cat >&2 <<EOF
install-cli: installed ${cargo_bin}, but it is not on PATH and no writable PATH-visible shim directory was found.
install-cli: add Cargo's bin directory to your shell config, then open a new shell:
install-cli:   export PATH="\$HOME/.cargo/bin:\$PATH"
EOF
exit 1
