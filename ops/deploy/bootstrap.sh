#!/usr/bin/env bash
set -euo pipefail

fail() {
  echo "bootstrap: $1" >&2
  exit "${2:-1}"
}

info() {
  echo "bootstrap: $1" >&2
}

bootstrap_container_session_dir=""
bootstrap_local_session_tmp=""
cleanup_bootstrap_session() {
  local status=$?
  if [ -n "${bootstrap_container_session_dir}" ]; then
    docker compose exec -T console rm -rf -- "${bootstrap_container_session_dir}" \
      >/dev/null 2>&1 || true
  fi
  if [ -n "${bootstrap_local_session_tmp}" ]; then
    command rm -f -- "${bootstrap_local_session_tmp}" >/dev/null 2>&1 || true
  fi
  exit "${status}"
}
trap cleanup_bootstrap_session EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    fail "missing ${name}; set it in .env"
  fi
}

find_user_id() {
  local entity_id="$1"
  local email="$2"

  docker compose exec -T \
    -e BOOTSTRAP_ENTITY_ID="$entity_id" \
    -e BOOTSTRAP_EMAIL="$email" \
    console python - 2>/dev/null <<'PY'
import asyncio
import os

import asyncpg


async def main() -> None:
    database_url = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://", 1)
    conn = await asyncpg.connect(database_url)
    try:
        user_id = await conn.fetchval(
            """
            SELECT id
            FROM users
            WHERE entity_id = $1::uuid
              AND lower(email) = lower($2)
              AND deleted_at IS NULL
            LIMIT 1
            """,
            os.environ["BOOTSTRAP_ENTITY_ID"],
            os.environ["BOOTSTRAP_EMAIL"],
        )
    finally:
        await conn.close()
    if user_id is not None:
        print(user_id)


asyncio.run(main())
PY
}

ensure_user_permission() {
  local user_id="$1"
  local permission="$2"

  docker compose exec -T \
    -e BOOTSTRAP_USER_ID="$user_id" \
    -e BOOTSTRAP_PERMISSION="$permission" \
    console python - >/dev/null 2>/dev/null <<'PY'
import asyncio
import os

import asyncpg


async def main() -> None:
    database_url = os.environ["DATABASE_URL"].replace("postgresql+asyncpg://", "postgresql://", 1)
    conn = await asyncpg.connect(database_url)
    try:
        await conn.execute(
            """
            INSERT INTO user_permissions (user_id, permission)
            VALUES ($1::uuid, $2::permission)
            ON CONFLICT DO NOTHING
            """,
            os.environ["BOOTSTRAP_USER_ID"],
            os.environ["BOOTSTRAP_PERMISSION"],
        )
    finally:
        await conn.close()


asyncio.run(main())
PY
}

if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

command -v docker >/dev/null || fail "docker is required"
command -v jq >/dev/null || fail "jq is required"
command -v cargo >/dev/null || fail "cargo is required"
docker compose version >/dev/null 2>&1 || fail "docker compose plugin is required"

docker compose ps --services --filter status=running | grep -qx "console" \
  || fail "console Compose service is not running; run make up first"
docker compose ps --services --filter status=running | grep -qx "console-db" \
  || fail "console-db Compose service is not running; run make up first"

require_env UMBRA_VERIFY_BOOTSTRAP_DOMAIN
require_env UMBRA_VERIFY_BOOTSTRAP_ADMIN_EMAIL
require_env UMBRA_VERIFY_TENANT_DOMAIN
require_env UMBRA_VERIFY_TENANT_NAME
require_env UMBRA_VERIFY_TENANT_ADMIN_EMAIL

if [ -z "${CONSOLE_URL:-}" ]; then
  if [ -n "${CONSOLE_HOST:-}" ]; then
    CONSOLE_URL="https://${CONSOLE_HOST}"
  else
    fail "missing CONSOLE_URL or CONSOLE_HOST"
  fi
fi
CONSOLE_URL="${CONSOLE_URL%/}"
PLATFORM_CONFIG="${UMBRA_VERIFY_CLI_CONFIG_DIR:-${UMBRA_CONFIG_DIR:-${HOME}/.umbra/platform}}"

info "bootstrapping platform entity and platform-operator session"
bootstrap_container_session_dir="/tmp/umbra-bootstrap-session-${RANDOM}-$$"
container_session_file="${bootstrap_container_session_dir}/session.json"

bootstrap_args=(
  python -m umbra_console.bootstrap
  --domain "${UMBRA_VERIFY_BOOTSTRAP_DOMAIN}"
  --admin-email "${UMBRA_VERIFY_BOOTSTRAP_ADMIN_EMAIL}"
  --session-file "${container_session_file}"
)
if [ -n "${UMBRA_VERIFY_BOOTSTRAP_ADMIN_NAME:-}" ]; then
  bootstrap_args+=(--admin-name "${UMBRA_VERIFY_BOOTSTRAP_ADMIN_NAME}")
fi
if [ -n "${UMBRA_VERIFY_BOOTSTRAP_ENTITY_NAME:-}" ]; then
  bootstrap_args+=(--entity-name "${UMBRA_VERIFY_BOOTSTRAP_ENTITY_NAME}")
fi
if [ -n "${UMBRA_VERIFY_BOOTSTRAP_DEFAULT_PROFILE:-}" ]; then
  bootstrap_args+=(--default-profile "${UMBRA_VERIFY_BOOTSTRAP_DEFAULT_PROFILE}")
fi

if ! docker compose exec -T console mkdir -p -- "${bootstrap_container_session_dir}" \
  >/dev/null 2>&1; then
  fail "could not prepare the private Console bootstrap session directory"
fi
if ! docker compose exec -T -e UMBRA_ALLOW_BOOTSTRAP=true console "${bootstrap_args[@]}" >/dev/null 2>/dev/null; then
  fail "Console bootstrap failed; detailed diagnostics were suppressed because they may contain configured identities or session paths"
fi
if ! install -d -m 700 -- "${PLATFORM_CONFIG}" >/dev/null 2>&1; then
  fail "could not prepare the private local CLI configuration directory"
fi
bootstrap_local_session_tmp="$(mktemp "${PLATFORM_CONFIG%/}/.session.json.bootstrap.XXXXXX" 2>/dev/null)" \
  || fail "could not create a private temporary local session file"
if ! docker compose cp "console:${container_session_file}" "${bootstrap_local_session_tmp}" \
  >/dev/null 2>&1; then
  fail "could not copy the private Console bootstrap session"
fi
if ! chmod 600 -- "${bootstrap_local_session_tmp}" >/dev/null 2>&1; then
  fail "could not secure the copied bootstrap session"
fi
if ! docker compose exec -T console rm -rf -- "${bootstrap_container_session_dir}" \
  >/dev/null 2>&1; then
  fail "could not remove the private Console bootstrap session"
fi
bootstrap_container_session_dir=""
if ! mv -f -- "${bootstrap_local_session_tmp}" "${PLATFORM_CONFIG%/}/session.json" \
  >/dev/null 2>&1; then
  fail "could not install the private local bootstrap session"
fi
bootstrap_local_session_tmp=""

cli=(
  cargo run --quiet -p umbra-cli --
  --config "${PLATFORM_CONFIG}"
  --console-url "${CONSOLE_URL}"
  --json
)

info "ensuring verifier tenant entity"
entities_json="$("${cli[@]}" entity list)" \
  || fail "could not list entities with the configured platform session"
entity_id="$(printf '%s\n' "${entities_json}" | jq -er --arg domain "${UMBRA_VERIFY_TENANT_DOMAIN}" \
  'first(.entities[]? | select((.domain | ascii_downcase) == ($domain | ascii_downcase)) | .id) // empty')" \
  || entity_id=""

if [ -z "${entity_id}" ]; then
  entity_json="$("${cli[@]}" entity add "${UMBRA_VERIFY_TENANT_DOMAIN}" --name "${UMBRA_VERIFY_TENANT_NAME}")" \
    || fail "could not create the verifier tenant entity"
  entity_id="$(printf '%s\n' "${entity_json}" | jq -er '.id')" \
    || fail "entity add did not return an entity id"
  info "created tenant entity ${entity_id}"
else
  info "reusing tenant entity ${entity_id}"
fi

info "ensuring verifier tenant admin"
tenant_admin_user_id="$(find_user_id "${entity_id}" "${UMBRA_VERIFY_TENANT_ADMIN_EMAIL}")" \
  || fail "could not query the verifier tenant admin"
if [ -z "${tenant_admin_user_id}" ]; then
  user_args=(
    user add "${UMBRA_VERIFY_TENANT_ADMIN_EMAIL}"
    --entity "${entity_id}"
    --permission USER_MANAGE
    --permission PERMISSION_MANAGE
    --permission SECURITY_CVM_CONFIGURE
    --permission AUDIT_VIEW
    --permission AUDIT_EXPORT
    --permission TRAFFIC_LOGS_VIEW
    --permission CVM_LAUNCH
  )
  if [ -n "${UMBRA_VERIFY_TENANT_ADMIN_NAME:-}" ]; then
    user_args+=(--name "${UMBRA_VERIFY_TENANT_ADMIN_NAME}")
  fi
  tenant_admin_json="$("${cli[@]}" "${user_args[@]}")" \
    || fail "could not create the verifier tenant admin"
  tenant_admin_user_id="$(printf '%s\n' "${tenant_admin_json}" | jq -er '.id')" \
    || fail "user add did not return a user id"
  info "created tenant admin ${tenant_admin_user_id}"
else
  info "reusing tenant admin ${tenant_admin_user_id}"
fi

for permission in USER_MANAGE PERMISSION_MANAGE SECURITY_CVM_CONFIGURE AUDIT_VIEW AUDIT_EXPORT TRAFFIC_LOGS_VIEW; do
  ensure_user_permission "${tenant_admin_user_id}" "${permission}" \
    || fail "could not ensure ${permission} for the verifier tenant admin"
done

cat <<EOF
bootstrap complete
console_url=${CONSOLE_URL}
tenant_entity_id=${entity_id}
tenant_admin_user_id=${tenant_admin_user_id}

tenant admin login:
  umbra --config "\${HOME}/.umbra/umbra-v0" --console-url "${CONSOLE_URL}" auth login
EOF
