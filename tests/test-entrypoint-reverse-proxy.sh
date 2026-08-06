#!/usr/bin/env bash
# Behavioral tests for ops/reverse-proxy/entrypoint.sh — specifically its startup
# guard clauses (CONSOLE_HOST required, LETSENCRYPT_STAGING must be exactly
# true/false). Those guards run before any privileged/external step, so we can
# exercise them without certbot/nginx/root.
#
# Each run executes the real entrypoint in a pristine environment (env -i) with
# stubbed certbot/nginx/envsubst on PATH, capturing stderr + exit code. For the
# accepted values (true/false) the script passes the guard and then fails later on
# the privileged steps (mkdir /var/www, write /etc/nginx) — that's expected; we
# only assert that the guard message is NOT emitted, i.e. the value was accepted.
set -euo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ops/reverse-proxy/entrypoint.sh"

CONSOLE_MSG="CONSOLE_HOST is required"
GUARD_MSG="LETSENCRYPT_STAGING must be exactly 'true' or 'false'"

fail() { echo "test failed: $*" >&2; exit 1; }
pass() { echo "entrypoint-reverse-proxy: ok: $*" >&2; }

# run_entrypoint VAR=val ...  -> sets RC + STDERR
run_entrypoint() {
  local tmp stubdir
  tmp="$(mktemp -d)"
  stubdir="$tmp/bin"
  mkdir -p "$stubdir"
  for c in certbot nginx envsubst; do
    printf '#!/bin/sh\nexit 0\n' > "$stubdir/$c"
    chmod +x "$stubdir/$c"
  done

  set +e
  STDERR="$(env -i PATH="$stubdir:/usr/bin:/bin" "$@" sh "$SCRIPT" 2>&1 >/dev/null)"
  RC=$?
  set -e

  rm -rf "$tmp"
}

contains() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac; }

# --- 1. missing CONSOLE_HOST aborts -----------------------------------------
run_entrypoint LETSENCRYPT_STAGING=true
[ "$RC" -ne 0 ] || fail "missing CONSOLE_HOST should exit non-zero"
contains "$CONSOLE_MSG" "$STDERR" || fail "expected CONSOLE_HOST message, got: $STDERR"
pass "missing CONSOLE_HOST aborts"

# --- 2. LETSENCRYPT_STAGING rejected: unset / empty / wrong-case / garbage ---
for bad in "__UNSET__" "" "TRUE" "1" "yes" "bogus"; do
  if [ "$bad" = "__UNSET__" ]; then
    run_entrypoint CONSOLE_HOST=example.com
  else
    run_entrypoint CONSOLE_HOST=example.com LETSENCRYPT_STAGING="$bad"
  fi
  [ "$RC" -ne 0 ] || fail "LETSENCRYPT_STAGING='$bad' should exit non-zero"
  contains "$GUARD_MSG" "$STDERR" || fail "LETSENCRYPT_STAGING='$bad' should hit the guard, got: $STDERR"
done
pass "LETSENCRYPT_STAGING rejects unset/empty/TRUE/1/yes/bogus"

# --- 3. LETSENCRYPT_STAGING accepted: true / false pass the guard -----------
for good in true false; do
  run_entrypoint CONSOLE_HOST=example.com LETSENCRYPT_STAGING="$good"
  if contains "$GUARD_MSG" "$STDERR"; then
    fail "LETSENCRYPT_STAGING='$good' must pass the guard, got: $STDERR"
  fi
done
pass "LETSENCRYPT_STAGING accepts true/false"

echo "all entrypoint-reverse-proxy tests passed"
