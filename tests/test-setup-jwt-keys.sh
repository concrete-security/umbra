#!/usr/bin/env bash
# Tests the 4 idempotency states of ops/host/setup-jwt-keys.sh:
#   priv + pub exist        -> no-op
#   priv exists, pub missing -> rebuild pub from priv
#   priv missing, pub exists -> abort (inconsistent state)
#   neither exists           -> generate both
#
# The script uses sudo and reads its key paths from JWT_*_REF. Each case points
# those refs at a user-writable tmp dir and puts a passthrough `sudo` (exec "$@")
# first on PATH, so the real script runs entirely as the test user — no
# privilege, no /etc writes.
set -euo pipefail

SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/ops/host/setup-jwt-keys.sh"

fail() { echo "test failed: $*" >&2; exit 1; }
pass() { echo "setup-jwt-keys: ok: $*" >&2; }
contains() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac; }

# Portable file permission bits: GNU stat (-c) with a BSD/macOS (-f) fallback.
file_mode() { stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"; }

# Safety net: clean up the most recent workdir even if a test aborts via fail().
trap 'rm -rf "${work:-}"' EXIT

setup_workdir() {
  work="$(mktemp -d)"
  mkdir -p "$work/bin" "$work/jwt"
  printf '#!/bin/sh\nexec "$@"\n' > "$work/bin/sudo"
  chmod +x "$work/bin/sudo"

  priv="$work/jwt/private.pem"
  pub="$work/jwt/public.jwks"
  envfile="$work/env"
  cat > "$envfile" <<EOF
JWT_PRIVATE_KEY_REF=file://$priv
JWT_PUBLIC_KEYS_REF=file://$pub
JWT_ACTIVE_KID=test-kid
EOF
}

run_setup() {
  set +e
  OUT="$(ENV_FILE="$envfile" PATH="$work/bin:$PATH" bash "$SCRIPT" 2>&1)"
  RC=$?
  set -e
}

make_priv() {
  openssl genpkey -algorithm ed25519 -out "$priv" 2>/dev/null
  chmod 400 "$priv"
}

# --- state: neither exists -> generate both ---------------------------------
setup_workdir
run_setup
[ "$RC" -eq 0 ] || fail "generate: rc=$RC: $OUT"
[ -s "$priv" ] || fail "generate: private key not created"
[ -s "$pub" ] || fail "generate: public JWKS not created"
contains '"kid":"test-kid"' "$(cat "$pub")" || fail "generate: JWKS missing kid: $(cat "$pub")"
[ "$(file_mode "$priv")" = "400" ] || fail "generate: priv perms != 400 (got $(file_mode "$priv"))"
[ "$(file_mode "$pub")" = "444" ] || fail "generate: pub perms != 444 (got $(file_mode "$pub"))"
rm -rf "$work"
pass "neither exists -> generates keypair (400/444, kid embedded)"

# --- state: both exist -> no-op ---------------------------------------------
setup_workdir
make_priv
printf '{"keys":[{"kid":"preexisting"}]}\n' > "$pub"
before="$(cat "$pub")"
run_setup
[ "$RC" -eq 0 ] || fail "no-op: rc=$RC: $OUT"
contains "already present" "$OUT" || fail "no-op: expected 'already present', got: $OUT"
[ "$(cat "$pub")" = "$before" ] || fail "no-op: public JWKS was modified"
rm -rf "$work"
pass "both exist -> no-op (public JWKS untouched)"

# --- state: priv exists, pub missing -> rebuild pub -------------------------
setup_workdir
make_priv
cp "$priv" "$work/priv.before"
run_setup
[ "$RC" -eq 0 ] || fail "rebuild: rc=$RC: $OUT"
cmp -s "$priv" "$work/priv.before" || fail "rebuild: private key was modified (must reuse the existing one)"
[ -s "$pub" ] || fail "rebuild: public JWKS not created"
contains '"kid":"test-kid"' "$(cat "$pub")" || fail "rebuild: JWKS missing kid"
contains "rebuilding" "$OUT" || fail "rebuild: expected 'rebuilding' message, got: $OUT"
rm -rf "$work"
pass "priv exists, pub missing -> rebuilds public JWKS from priv"

# --- state: priv missing, pub exists -> abort -------------------------------
setup_workdir
printf '{"keys":[]}\n' > "$pub"
run_setup
[ "$RC" -ne 0 ] || fail "inconsistent: should abort, got rc=0: $OUT"
contains "private key is missing" "$OUT" || fail "inconsistent: expected abort message, got: $OUT"
[ ! -f "$priv" ] || fail "inconsistent: must not generate a private key"
rm -rf "$work"
pass "pub exists, priv missing -> aborts (no key generated)"

echo "all setup-jwt-keys tests passed"
