#!/usr/bin/env bash
# Generate the Ed25519 JWT signing keypair this Console needs, if it is absent.
#
# This is a provisioning step: it may write under /etc/umbra/jwt and therefore
# may require sudo. It is idempotent:
# - private key + public JWKS exist: no-op
# - private key exists but public JWKS is missing: rebuild public JWKS from private key
# - public JWKS exists but private key is missing: abort (inconsistent state)
# - neither exists: generate both
#
# Usage:
#   ./ops/host/setup-jwt-keys.sh                  # reads .env
#   ENV_FILE=/path/to/env ./ops/host/setup-jwt-keys.sh

set -euo pipefail

ENV_FILE="${ENV_FILE:-.env}"

log() {
  echo "setup-jwt-keys: $*" >&2
}

die() {
  log "$@"
  exit 1
}

require_file_ref() {
  local name="$1"
  local value="$2"

  case "$value" in
    file://?*)
      printf '%s\n' "${value#file://}"
      ;;
    "")
      die "${name} must be set to a file:// path"
      ;;
    *)
      die "${name} must be a file:// path, got '${value}'"
      ;;
  esac
}

write_public_jwks() {
  local private_key="$1"
  local public_jwks="$2"
  local active_kid="$3"

  local x

  # Ed25519 SPKI DER is 44 bytes: 12-byte header + 32-byte raw public key.
  x="$(
    sudo openssl pkey -in "$private_key" -pubout -outform DER \
      | tail -c 32 \
      | openssl base64 -A \
      | tr '+/' '-_' \
      | tr -d '='
  )"

  printf '{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"%s","x":"%s"}]}\n' "$active_kid" "$x" \
    | sudo tee "$public_jwks" >/dev/null

  sudo chmod 444 "$public_jwks"
}

[ -f "$ENV_FILE" ] || die "${ENV_FILE} not found; run 'make build-env MODE=<staging|prod>' first"

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

priv="$(require_file_ref JWT_PRIVATE_KEY_REF "${JWT_PRIVATE_KEY_REF:-}")"
pub="$(require_file_ref JWT_PUBLIC_KEYS_REF "${JWT_PUBLIC_KEYS_REF:-}")"
kid="${JWT_ACTIVE_KID:-}"

[ -n "$kid" ] || die "JWT_ACTIVE_KID must be set; run 'make build-env MODE=<staging|prod>' first"

case "$kid" in
  *[!A-Za-z0-9_.-]*)
    die "JWT_ACTIVE_KID contains invalid characters; use only A-Z, a-z, 0-9, _, -, ."
    ;;
esac

# No-op and inconsistent-state checks come first, so an already-provisioned host
# needs no sudo at all.
if [ -f "$priv" ] && [ -f "$pub" ]; then
  log "keys already present (${priv}, ${pub}); leaving them untouched"
  exit 0
fi

if [ ! -f "$priv" ] && [ -f "$pub" ]; then
  die "public JWKS exists (${pub}) but private key is missing (${priv}); refusing to generate a mismatched keypair"
fi

sudo mkdir -p "$(dirname "$priv")" "$(dirname "$pub")"

if [ -f "$priv" ] && [ ! -f "$pub" ]; then
  log "private key exists but public JWKS is missing; rebuilding ${pub}"
  write_public_jwks "$priv" "$pub" "$kid"
  log "wrote ${pub} from existing private key (kid=${kid})"
  exit 0
fi

# Neither exists: generate both.
sudo openssl genpkey -algorithm ed25519 -out "$priv"
sudo chmod 400 "$priv"

write_public_jwks "$priv" "$pub" "$kid"

log "wrote ${priv} + ${pub} (kid=${kid})"
