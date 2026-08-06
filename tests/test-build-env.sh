#!/usr/bin/env bash
# Behavioral tests for ops/host/build-env.sh.
#
# Each test runs in its own mktemp -d directory holding fake .env.* layers, so
# the script reads those fixtures (relative to CWD) and never touches the repo's
# real .env / secret files. Output goes to .env.generated via ENV_FILE_OUT.
set -euo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ops/host/build-env.sh"

fail() {
  echo "test failed: $*" >&2
  exit 1
}

assert_success() {
  if ! "$@"; then
    fail "expected success: $*"
  fi
}

assert_failure() {
  if "$@"; then
    fail "expected failure: $*"
  fi
}

make_valid_layers() {
  cat > .env.common <<'EOF'
COMMON_VALUE=hello
EOF

  cat > .env.staging <<'EOF'
ENV=staging
STAGING_VALUE=yes
EOF

  cat > .env.admin <<'EOF'
ADMIN_USER=alice
EOF

  cat > .env.staging.secrets <<'EOF'
SECRET_VALUE=fake-secret
EOF
}

run_build_env() {
  MODE=staging ENV_FILE_OUT=.env.generated "$SCRIPT"
}

test_valid_merge() {
  local tmp
  tmp="$(mktemp -d)"

  (
    cd "$tmp"
    make_valid_layers

    assert_success run_build_env

    grep -q '^COMMON_VALUE=hello$' .env.generated || fail "missing COMMON_VALUE"
    grep -q '^ENV=staging$' .env.generated || fail "missing ENV"
    grep -q '^ADMIN_USER=alice$' .env.generated || fail "missing ADMIN_USER"
    grep -q '^SECRET_VALUE=fake-secret$' .env.generated || fail "missing SECRET_VALUE"
  )

  rm -rf "$tmp"
}

test_missing_layer_fails() {
  local tmp
  tmp="$(mktemp -d)"

  (
    cd "$tmp"
    make_valid_layers
    rm .env.staging.secrets

    assert_failure run_build_env
  )

  rm -rf "$tmp"
}

test_invalid_lines_do_not_echo_values_failure() {
  local error line secret tmp
  secret="must-not-appear-in-public-logs"

  for line in "export COMMON_VALUE=${secret}" "malformed ${secret}"; do
    tmp="$(mktemp -d)"

    (
      cd "$tmp"
      make_valid_layers
      printf '%s\n' "$line" > .env.common

      if error="$(run_build_env 2>&1)"; then
        fail "expected malformed environment input to fail"
      fi
      case "$error" in
        *"$secret"*) fail "malformed environment value leaked to stderr" ;;
      esac
    )

    rm -rf "$tmp"
  done
}

test_duplicate_key_fails() {
  local tmp
  tmp="$(mktemp -d)"

  (
    cd "$tmp"
    make_valid_layers

    cat >> .env.admin <<'EOF'
ENV=duplicate
EOF

    assert_failure run_build_env
  )

  rm -rf "$tmp"
}

test_publish_credentials_fail() {
  local key tmp

  for key in GHCR_USER GHCR_TOKEN GH_TOKEN; do
    tmp="$(mktemp -d)"

    (
      cd "$tmp"
      make_valid_layers
      printf '%s=fake-publish-credential\n' "$key" >> .env.admin

      assert_failure run_build_env
    )

    rm -rf "$tmp"
  done
}

test_invalid_mode_fails() {
  local tmp
  tmp="$(mktemp -d)"

  (
    cd "$tmp"
    make_valid_layers

    # MODE is not one of dev|staging|prod -> validate_mode must abort
    # (before any layer is even read).
    assert_failure "$SCRIPT" dddd
  )

  rm -rf "$tmp"
}

test_valid_merge
test_missing_layer_fails
test_invalid_lines_do_not_echo_values_failure
test_duplicate_key_fails
test_publish_credentials_fail
test_invalid_mode_fails

echo "all build-env tests passed"
