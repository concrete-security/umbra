#!/usr/bin/env bash
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=ops/verify/verify-journey-lib.sh
source "${ROOT}/ops/verify/verify-journey-lib.sh"

fail() {
  echo "$1" >&2
  exit "${2:-1}"
}

step() {
  echo "journey step $1: $2" >&2
}

tmp_files=()
bootstrap_container_session_dir=""
# Dev CVM this run launched, set as soon as step 7 knows its id and cleared once
# step 11 confirms it TERMINATED. Anything still recorded here when the shell
# exits is a leak: a live Dev CVM makes the *next* run's `security-cvm terminate`
# fail with `dev_cvms_in_entity`, so one transient failure would otherwise cascade
# into every subsequent run. The EXIT trap terminates it whatever killed us.
launched_dev_cvm_id=""
# Filled by the step-7 reconcile (reconcile_journey_dev_cvms) and read by step 11.
# `swept_journey_dev_cvm_ids` are leftovers from PREVIOUS journeys this run
# terminated; `foreign_dev_cvms` are "<id> <state>" for Dev CVMs this run
# deliberately left alone because no journey created them.
swept_journey_dev_cvm_ids=()
foreign_dev_cvms=()
developer_cli=()
cleanup() {
  local status=$?
  local path
  if [ -n "${bootstrap_container_session_dir}" ]; then
    docker compose exec -T console rm -rf -- "${bootstrap_container_session_dir}" \
      >/dev/null 2>&1 || true
    bootstrap_container_session_dir=""
  fi
  if [ -n "${launched_dev_cvm_id}" ]; then
    echo "journey cleanup: terminating Dev CVM ${launched_dev_cvm_id} left live by an aborted journey" >&2
    if "${developer_cli[@]}" cvm terminate "${launched_dev_cvm_id}" \
      --wait-timeout-seconds "${UMBRA_VERIFY_DEV_CVM_TERMINATE_WAIT_TIMEOUT_SECONDS:-600}" >/dev/null; then
      echo "journey cleanup: terminated Dev CVM ${launched_dev_cvm_id}" >&2
    else
      echo "journey cleanup: FAILED to terminate Dev CVM ${launched_dev_cvm_id}; the next run reconciles it at step 7, or terminate it now with umbra cvm terminate ${launched_dev_cvm_id}" >&2
    fi
    launched_dev_cvm_id=""
  fi
  for path in "${tmp_files[@]}"; do
    rm -rf -- "${path}" >/dev/null 2>&1 || true
  done
  # Preserve the status that triggered the trap: the teardown above must never
  # turn a failed journey green, nor a passing one red.
  exit "${status}"
}
trap cleanup EXIT
# Bash skips the EXIT trap when an unhandled signal kills the shell, so route
# signals through `exit` to keep teardown running on a cancelled CI run.
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

require_env() {
  local name="$1"
  local step_no="$2"
  if [ -z "${!name:-}" ]; then
    fail "journey step ${step_no}: missing ${name}; set the verify bootstrap inputs in .env"
  fi
}

confirm_device_login_ready() {
  local step_no="$1"
  local role="$2"
  local tty_fd

  if ! { exec {tty_fd}<>/dev/tty; } 2>/dev/null; then
    fail "journey step ${step_no}: ${role} Google device login requires an interactive operator; rerun make verify from a terminal when the account owner can approve the code before expiry"
  fi

  {
    echo "journey step ${step_no}: ${role} Google approval is required"
    echo "journey step ${step_no}: press Enter only when the account owner is ready to approve the next displayed Google device code"
  } >&${tty_fd}
  IFS= read -r _ <&${tty_fd} \
    || fail "journey step ${step_no}: could not read operator confirmation before Google device login"
  exec {tty_fd}>&-
}

ensure_verify_session() {
  local step_no="$1"
  local role="$2"
  local expected_email="$3"
  local config_dir="$4"
  local -n session_cli="$5"
  local session_file="${config_dir%/}/session.json"
  local status_json session_email access_state remaining_seconds min_remaining
  min_remaining="${UMBRA_VERIFY_SESSION_MIN_REMAINING_SECONDS:-1200}"
  if ! [[ "${min_remaining}" =~ ^[0-9]+$ ]]; then
    fail "journey step ${step_no}: UMBRA_VERIFY_SESSION_MIN_REMAINING_SECONDS must be a non-negative integer"
  fi

  if [ -f "${session_file}" ]; then
    echo "journey step ${step_no}: checking cached ${role} session" >&2
    if status_json="$("${session_cli[@]}" auth status 2>/dev/null)"; then
      session_email="$(printf '%s\n' "${status_json}" | jq -r '.user.email // ""')" || session_email=""
      access_state="$(printf '%s\n' "${status_json}" | jq -r '.access_token.state // ""')" || access_state=""
      remaining_seconds="$(printf '%s\n' "${status_json}" | jq -r '.access_token.remaining_seconds // 0')" || remaining_seconds="0"
      if ! [[ "${remaining_seconds}" =~ ^-?[0-9]+$ ]]; then
        remaining_seconds=0
      fi
      if [ "${session_email,,}" = "${expected_email,,}" ]; then
        if [ "${access_state}" = "valid" ] && [ "${remaining_seconds}" -ge "${min_remaining}" ]; then
          if "${session_cli[@]}" key list >/dev/null 2>/dev/null; then
            echo "journey step ${step_no}: reusing cached ${role} session" >&2
            return 0
          fi
          echo "journey step ${step_no}: cached ${role} access token is not valid against the current Console; trying refresh" >&2
        elif [ "${access_state}" = "valid" ]; then
          echo "journey step ${step_no}: cached ${role} access token has ${remaining_seconds}s remaining; trying refresh before long verifier operations" >&2
        fi
        if "${session_cli[@]}" auth refresh >/dev/null 2>/dev/null; then
          if "${session_cli[@]}" key list >/dev/null 2>/dev/null; then
            echo "journey step ${step_no}: refreshed cached ${role} session" >&2
            return 0
          fi
          echo "journey step ${step_no}: refreshed cached ${role} session was not accepted by the current Console; starting Google device login" >&2
        else
          echo "journey step ${step_no}: cached ${role} session could not be refreshed; starting Google device login" >&2
        fi
      else
        echo "journey step ${step_no}: cached ${role} session belongs to another account; starting Google device login" >&2
      fi
    else
      echo "journey step ${step_no}: cached ${role} session is unreadable; starting Google device login" >&2
    fi
  else
    echo "journey step ${step_no}: no cached ${role} session; starting Google device login" >&2
  fi

  echo "journey step ${step_no}: starting ${role} Google device login; approve the displayed code before it expires" >&2
  confirm_device_login_ready "${step_no}" "${role}"
  "${session_cli[@]}" auth login --device >/dev/null
}

if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

if [ -z "${CONSOLE_URL:-}" ]; then
  if [ -n "${CONSOLE_HOST:-}" ]; then
    CONSOLE_URL="https://${CONSOLE_HOST}"
  else
    fail "journey preflight: missing CONSOLE_URL or CONSOLE_HOST"
  fi
fi

CONSOLE_URL="${CONSOLE_URL%/}"
UMBRA_VERIFY_CLI_CONFIG_DIR="${UMBRA_VERIFY_CLI_CONFIG_DIR:-${UMBRA_CONFIG_DIR:-${HOME}/.umbra}}"

step "preflight" "checking Console health"
command -v jq >/dev/null || fail "journey preflight: jq is required"
command -v ssh-keygen >/dev/null || fail "journey preflight: ssh-keygen is required"
curl -fsS "${CONSOLE_URL}/healthz" >/dev/null \
  || fail "journey preflight: Console health check failed at ${CONSOLE_URL}/healthz; run make up first"

# Live contract check for the instance-type catalog adapter: the Console parser
# only needs `result[].items[].id` to survive schema drift; assert the real
# provider still honors that shape so drift is caught here, not in production.
step "preflight" "checking phala instance-types contract"
phala_cli="${PHALA_CLI_PATH:-/usr/local/bin/phala}"
if [ -n "${PHALA_API_TOKEN:-}" ] && command -v "${phala_cli}" >/dev/null 2>&1; then
  instance_types_json="$(PHALA_CLOUD_API_KEY="${PHALA_API_TOKEN}" "${phala_cli}" instance-types --json 2>/dev/null)" \
    || fail "journey preflight: phala instance-types --json failed; provider diagnostics were suppressed because they may contain credentials"
  instance_type_id_count="$(printf '%s' "${instance_types_json}" \
    | jq -r '[.result[]?.items[]?.id | select(type == "string" and length > 0)] | length')" \
    || fail "journey preflight: phala instance-types output is not parseable JSON"
  [ "${instance_type_id_count:-0}" -gt 0 ] \
    || fail "journey preflight: phala instance-types returned no parseable result[].items[].id -- catalog adapter schema drift"
else
  echo "journey preflight: skipping phala instance-types contract check (phala CLI or PHALA_API_TOKEN unavailable)" >&2
fi

step "preflight" "checking the shade checkout against the pinned SHADE_REF"
[ -n "${SHADE_REF:-}" ] || fail "journey preflight: SHADE_REF is not set; rebuild .env with make build-env"
[ -n "${SHADE_DIR:-}" ] && [ -d "${SHADE_DIR}" ] \
  || fail "journey preflight: SHADE_DIR '${SHADE_DIR:-unset}' is not a directory"
shade_head="$(git -c "safe.directory=${SHADE_DIR}" -C "${SHADE_DIR}" rev-parse HEAD 2>/dev/null)" \
  || fail "journey preflight: could not read the shade checkout at ${SHADE_DIR}"
[ "${shade_head}" = "${SHADE_REF}" ] \
  || fail "journey preflight: shade checkout is at ${shade_head}, not pinned SHADE_REF ${SHADE_REF}; make deploy converges it"
[ -z "$(git -c "safe.directory=${SHADE_DIR}" -C "${SHADE_DIR}" status --porcelain)" ] \
  || fail "journey preflight: shade checkout at ${SHADE_DIR} has local modifications"

step 1 "platform bootstrap"
require_env UMBRA_VERIFY_BOOTSTRAP_DOMAIN 1
require_env UMBRA_VERIFY_BOOTSTRAP_ADMIN_EMAIL 1

docker compose ps --services --filter status=running | grep -qx "console" \
  || fail "journey step 1: console Compose service is not running; run make up first"

bootstrap_args=(
  python -m umbra_console.bootstrap
  --domain "${UMBRA_VERIFY_BOOTSTRAP_DOMAIN}"
  --admin-email "${UMBRA_VERIFY_BOOTSTRAP_ADMIN_EMAIL}"
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

bootstrap_container_session_dir="/tmp/umbra-bootstrap-session-${RANDOM}-$$"
container_session_file="${bootstrap_container_session_dir}/session.json"
bootstrap_args+=(--session-file "${container_session_file}")

if ! docker compose exec -T console mkdir -p -- "${bootstrap_container_session_dir}" \
  >/dev/null 2>&1; then
  fail "journey step 1: could not prepare the private Console bootstrap session directory"
fi
if ! docker compose exec -T -e UMBRA_ALLOW_BOOTSTRAP=true console "${bootstrap_args[@]}" >/dev/null 2>/dev/null; then
  fail "journey step 1: Console bootstrap failed; detailed diagnostics were suppressed because they may contain configured identities or session paths"
fi
if ! install -d -m 700 -- "${UMBRA_VERIFY_CLI_CONFIG_DIR}" >/dev/null 2>&1; then
  fail "journey step 1: could not prepare the private local CLI configuration directory"
fi
bootstrap_local_session_tmp="$(mktemp "${UMBRA_VERIFY_CLI_CONFIG_DIR%/}/.session.json.bootstrap.XXXXXX" 2>/dev/null)" \
  || fail "journey step 1: could not create a private temporary local session file"
tmp_files+=("${bootstrap_local_session_tmp}")
if ! docker compose cp "console:${container_session_file}" "${bootstrap_local_session_tmp}" \
  >/dev/null 2>&1; then
  fail "journey step 1: could not copy the private Console bootstrap session"
fi
if ! chmod 600 -- "${bootstrap_local_session_tmp}" >/dev/null 2>&1; then
  fail "journey step 1: could not secure the copied bootstrap session"
fi
if ! docker compose exec -T console rm -rf -- "${bootstrap_container_session_dir}" \
  >/dev/null 2>&1; then
  fail "journey step 1: could not remove the private Console bootstrap session"
fi
bootstrap_container_session_dir=""
if ! mv -f -- "${bootstrap_local_session_tmp}" "${UMBRA_VERIFY_CLI_CONFIG_DIR%/}/session.json" \
  >/dev/null 2>&1; then
  fail "journey step 1: could not install the private local bootstrap session"
fi

step 2 "entity onboarding"
require_env UMBRA_VERIFY_TENANT_DOMAIN 2
require_env UMBRA_VERIFY_TENANT_NAME 2
require_env UMBRA_VERIFY_TENANT_ADMIN_EMAIL 2

cli=(
  cargo run --quiet -p umbra-cli --
  --config "${UMBRA_VERIFY_CLI_CONFIG_DIR}"
  --console-url "${CONSOLE_URL}"
  --json
)

entities_json="$("${cli[@]}" entity list)" \
  || fail "journey step 2: umbra entity list failed; authenticate the configured platform-operator session"
entity_id="$(printf '%s\n' "${entities_json}" | jq -er --arg domain "${UMBRA_VERIFY_TENANT_DOMAIN}" \
  'first(.entities[]? | select((.domain | ascii_downcase) == ($domain | ascii_downcase)) | .id) // empty')" \
  || entity_id=""
tenant_admin_user_id=""

journey_created_entity=0
journey_created_developer=0
journey_assigned_profile_member=0
if [ -n "${entity_id}" ]; then
  echo "journey step 2: reusing existing verifier tenant entity ${entity_id}" >&2
else
  journey_created_entity=1
  entity_json="$("${cli[@]}" entity add "${UMBRA_VERIFY_TENANT_DOMAIN}" --name "${UMBRA_VERIFY_TENANT_NAME}")" \
    || fail "journey step 2: umbra entity add failed; authenticate the configured platform-operator session"
  entity_id="$(printf '%s\n' "${entity_json}" | jq -er '.id')" \
    || fail "journey step 2: umbra entity add did not return an entity id"

  user_args=(
    user add "${UMBRA_VERIFY_TENANT_ADMIN_EMAIL}"
    --entity "${entity_id}"
    --permission USER_MANAGE
    --permission PERMISSION_MANAGE
    --permission SECURITY_CVM_CONFIGURE
    --permission AUDIT_VIEW
    --permission AUDIT_EXPORT
    --permission TRAFFIC_LOGS_VIEW
  )
  if [ -n "${UMBRA_VERIFY_TENANT_ADMIN_NAME:-}" ]; then
    user_args+=(--name "${UMBRA_VERIFY_TENANT_ADMIN_NAME}")
  fi

  tenant_admin_json="$("${cli[@]}" "${user_args[@]}")" \
    || fail "journey step 2: umbra user add failed for the verifier tenant admin"
  tenant_admin_user_id="$(printf '%s\n' "${tenant_admin_json}" | jq -er '.id')" \
    || fail "journey step 2: umbra user add did not return a user id"
fi

step 3 "first entity-admin login"
require_env UMBRA_VERIFY_TENANT_ADMIN_CONFIG_DIR 3

admin_cli=(
  cargo run --quiet -p umbra-cli --
  --config "${UMBRA_VERIFY_TENANT_ADMIN_CONFIG_DIR}"
  --console-url "${CONSOLE_URL}"
  --json
)

ensure_verify_session 3 "tenant-admin" "${UMBRA_VERIFY_TENANT_ADMIN_EMAIL}" "${UMBRA_VERIFY_TENANT_ADMIN_CONFIG_DIR}" admin_cli
status_json="$("${admin_cli[@]}" status)" \
  || fail "journey step 3: tenant admin status check failed after authentication"
session_email="$(printf '%s\n' "${status_json}" | jq -er '.user.email')" \
  || fail "journey step 3: tenant admin status response did not include user.email"
if [ "${session_email,,}" != "${UMBRA_VERIFY_TENANT_ADMIN_EMAIL,,}" ]; then
  fail "journey step 3: logged-in account did not match the configured tenant admin"
fi
tenant_admin_user_id="$(printf '%s\n' "${status_json}" | jq -er '.user.id')" \
  || fail "journey step 3: tenant admin status response did not include user.id"
status_entity_id="$(printf '%s\n' "${status_json}" | jq -er '.entity.id')" \
  || fail "journey step 3: tenant admin status response did not include entity.id"
if [ "${status_entity_id}" != "${entity_id}" ]; then
  fail "journey step 3: logged-in entity ${status_entity_id} did not match onboarded entity ${entity_id}"
fi

step 4 "Security CVM launch"
require_env SECURITY_CVM_IMAGE_REF 4
require_env SECURITY_CVM_IMAGE_MEASUREMENT 4
require_env SHADE_DIR 4
require_env ATLAS_VERIFIER_CMD 4

security_cvm_args=(
  security-cvm launch
  --wait-timeout-seconds "${UMBRA_VERIFY_SECURITY_CVM_WAIT_TIMEOUT_SECONDS:-900}"
)
if [ -n "${UMBRA_VERIFY_SECURITY_CVM_INSTANCE_TYPE:-}" ]; then
  security_cvm_args+=(--instance-type "${UMBRA_VERIFY_SECURITY_CVM_INSTANCE_TYPE}")
fi
if [ -n "${UMBRA_VERIFY_SECURITY_CVM_REGION:-}" ]; then
  security_cvm_args+=(--region "${UMBRA_VERIFY_SECURITY_CVM_REGION}")
fi

security_cvm_json=""
if existing_security_cvm_json="$("${admin_cli[@]}" security-cvm show 2>/dev/null)"; then
  existing_security_cvm_state="$(printf '%s\n' "${existing_security_cvm_json}" | jq -r '.state // ""')" \
    || existing_security_cvm_state=""
  if [ "${existing_security_cvm_state}" = "RUNNING" ]; then
    security_cvm_json="${existing_security_cvm_json}"
    echo "journey step 4: reusing RUNNING Security CVM $(printf '%s\n' "${security_cvm_json}" | jq -r '.id')" >&2
  fi
fi

journey_created_security_cvm=0
if [ -z "${security_cvm_json}" ]; then
  journey_created_security_cvm=1
  if [ "${UMBRA_VERIFY_DEBUG_POLL:-0}" = "1" ]; then
    security_cvm_launch_json="$(UMBRA_DEBUG_POLL=1 "${admin_cli[@]}" "${security_cvm_args[@]}")" \
      || fail "journey step 4: umbra security-cvm launch failed"
  else
    security_cvm_launch_json="$("${admin_cli[@]}" "${security_cvm_args[@]}")" \
      || fail "journey step 4: umbra security-cvm launch failed"
  fi
  security_cvm_json="$(printf '%s\n' "${security_cvm_launch_json}" | jq -c '.security_cvm // .')" \
    || fail "journey step 4: Security CVM launch response was malformed"
fi
security_cvm_id="$(printf '%s\n' "${security_cvm_json}" | jq -er '.id')" \
  || fail "journey step 4: Security CVM response did not include id"
security_cvm_state="$(printf '%s\n' "${security_cvm_json}" | jq -er '.state')" \
  || fail "journey step 4: Security CVM response did not include state"
if [ "${security_cvm_state}" != "RUNNING" ]; then
  fail "journey step 4: Security CVM ${security_cvm_id} ended in state ${security_cvm_state}, expected RUNNING"
fi

attestation_json="$("${admin_cli[@]}" security-cvm attestation --probe)" \
  || fail "journey step 4: Security CVM attestation probe failed for ${security_cvm_id}"
attested_id="$(printf '%s\n' "${attestation_json}" | jq -er '.security_cvm_id')" \
  || fail "journey step 4: Security CVM attestation response did not include security_cvm_id"
if [ "${attested_id}" != "${security_cvm_id}" ]; then
  fail "journey step 4: attestation response for ${attested_id}, expected ${security_cvm_id}"
fi
verified="$(printf '%s\n' "${attestation_json}" | jq -er '.verdict.verified')" \
  || fail "journey step 4: Security CVM attestation response did not include verdict.verified"
if [ "${verified}" != "true" ]; then
  failure_reason="$(printf '%s\n' "${attestation_json}" | jq -r '.verdict.failure_reason // "unknown"')"
  fail "journey step 4: Security CVM attestation was not verified (${failure_reason})"
fi

step 5 "profile authoring"
profile_name="${UMBRA_VERIFY_PROFILE_NAME:-umbra-verify-egress}"
profiles_json="$("${admin_cli[@]}" profile list)" \
  || fail "journey step 5: umbra profile list failed"
profile_id="$(printf '%s\n' "${profiles_json}" | jq -er --arg name "${profile_name}" \
  'first(.[]? | select(.name == $name) | .id) // empty')" \
  || profile_id=""
journey_created_profile=0
if [ -n "${profile_id}" ]; then
  echo "journey step 5: reusing existing profile ${profile_id} named ${profile_name}" >&2
else
  journey_created_profile=1
  profile_json="$("${admin_cli[@]}" profile create "${profile_name}" --description "Umbra verify egress policy")" \
    || fail "journey step 5: umbra profile create failed"
  profile_id="$(printf '%s\n' "${profile_json}" | jq -er '.id')" \
    || fail "journey step 5: umbra profile create did not return a profile id"
fi
# Step 9 needs an upstream that echoes request headers back, so it can prove the
# SC's secret injection actually left the SC. Depending on ONE public echo service
# let a third-party outage fail the run and block `dev -> main` promotion with
# nothing wrong with the platform (httpbin.org served 503 through 2026-07-28), so
# the profile allows several interchangeable hosts and step 9 fails over between
# them. Resolution order, the de-dup rule and the pool itself all live in
# ops/verify/verify-journey-lib.sh, where tests/test-verify-journey.sh pins them.
allowed_hosts=()
resolve_verify_egress_hosts allowed_hosts
if [ "${#allowed_hosts[@]}" -eq 0 ]; then
  fail "journey step 5: no step-9 egress target configured; set UMBRA_VERIFY_ALLOWED_HOSTS to one or more httpbin-contract hosts"
fi
echo "journey step 5: step-9 egress targets, in preference order: ${allowed_hosts[*]}" >&2
blocked_host="${UMBRA_VERIFY_BLOCKED_HOST:-admin.example.com}"

policy_file="$(mktemp)"
tmp_files+=("${policy_file}")
verify_egress_policy_json allowed_hosts "${blocked_host}" >"${policy_file}" \
  || fail "journey step 5: could not author the verify profile policy"

configured_profile_json="$("${admin_cli[@]}" --profile "${profile_id}" profile configure --policy-file "${policy_file}")" \
  || fail "journey step 5: umbra profile configure failed for ${profile_id}"
configured_profile_id="$(printf '%s\n' "${configured_profile_json}" | jq -er '.id')" \
  || fail "journey step 5: umbra profile configure did not return a profile id"
if [ "${configured_profile_id}" != "${profile_id}" ]; then
  fail "journey step 5: configured profile ${configured_profile_id}, expected ${profile_id}"
fi
printf '%s\n' "${configured_profile_json}" | jq -e --argjson allowed_count "${#allowed_hosts[@]}" '
  (.policy.allowed_destinations | length) == $allowed_count and
  (.policy.blocked_destinations | length) == 1 and
  (.policy.secret_patterns | length) == 1 and
  (.policy.secret_injections | length) == $allowed_count and
  (.policy.sandbox_env.VERIFY_PLACEHOLDER == "non-secret-placeholder")
' >/dev/null || fail "journey step 5: configured profile policy is incomplete"

step 6 "membership grant"
require_env UMBRA_VERIFY_DEVELOPER_EMAIL 6

if [ "${UMBRA_VERIFY_DEVELOPER_EMAIL,,}" = "${UMBRA_VERIFY_TENANT_ADMIN_EMAIL,,}" ]; then
  developer_user_id="${tenant_admin_user_id}"
  "${admin_cli[@]}" user permissions grant "${developer_user_id}" CVM_LAUNCH >/dev/null \
    || fail "journey step 6: umbra user permissions grant failed for existing developer ${developer_user_id}"
else
  users_json="$("${admin_cli[@]}" user list)" \
    || fail "journey step 6: umbra user list failed"
  developer_user_id="$(printf '%s\n' "${users_json}" | jq -er --arg email "${UMBRA_VERIFY_DEVELOPER_EMAIL}" \
    'first(.[]? | select((.email | ascii_downcase) == ($email | ascii_downcase)) | .id) // empty')" \
    || developer_user_id=""
  if [ -n "${developer_user_id}" ]; then
    journey_created_developer=0
    echo "journey step 6: reusing existing verifier developer user ${developer_user_id}" >&2
    "${admin_cli[@]}" user permissions grant "${developer_user_id}" CVM_LAUNCH >/dev/null \
      || fail "journey step 6: umbra user permissions grant failed for existing developer ${developer_user_id}"
  else
    journey_created_developer=1
    developer_args=(
      user add "${UMBRA_VERIFY_DEVELOPER_EMAIL}"
      --permission CVM_LAUNCH
    )
    if [ -n "${UMBRA_VERIFY_DEVELOPER_NAME:-}" ]; then
      developer_args+=(--name "${UMBRA_VERIFY_DEVELOPER_NAME}")
    fi

    developer_json="$("${admin_cli[@]}" "${developer_args[@]}")" \
      || fail "journey step 6: umbra user add failed for the verifier developer"
    developer_user_id="$(printf '%s\n' "${developer_json}" | jq -er '.id')" \
      || fail "journey step 6: umbra user add did not return a developer user id"
  fi
fi

members_json="$("${admin_cli[@]}" --profile "${profile_id}" profile members list)" \
  || fail "journey step 6: umbra profile members list failed for profile ${profile_id}"
if printf '%s\n' "${members_json}" | jq -e --arg user_id "${developer_user_id}" \
  'any(.[]; .user_id == $user_id)' >/dev/null; then
  echo "journey step 6: developer ${developer_user_id} is already a profile member" >&2
  journey_assigned_profile_member=0
else
  journey_assigned_profile_member=1
  member_json="$("${admin_cli[@]}" --profile "${profile_id}" profile members add "${developer_user_id}")" \
    || fail "journey step 6: umbra profile members add failed for developer ${developer_user_id}"
  member_profile_id="$(printf '%s\n' "${member_json}" | jq -er '.profile_id')" \
    || fail "journey step 6: profile members add response did not include profile_id"
  member_user_id="$(printf '%s\n' "${member_json}" | jq -er '.user_id')" \
    || fail "journey step 6: profile members add response did not include user_id"
  if [ "${member_profile_id}" != "${profile_id}" ]; then
    fail "journey step 6: membership grant returned profile ${member_profile_id}, expected ${profile_id}"
  fi
  if [ "${member_user_id}" != "${developer_user_id}" ]; then
    fail "journey step 6: membership grant returned user ${member_user_id}, expected ${developer_user_id}"
  fi
  members_json="$("${admin_cli[@]}" --profile "${profile_id}" profile members list)" \
    || fail "journey step 6: umbra profile members list failed for profile ${profile_id}"
fi
printf '%s\n' "${members_json}" | jq -e --arg user_id "${developer_user_id}" \
  'any(.[]; .user_id == $user_id)' >/dev/null \
  || fail "journey step 6: developer ${developer_user_id} was not listed as a profile member"
users_json="$("${admin_cli[@]}" user list)" \
  || fail "journey step 6: umbra user list failed after permission grant"
printf '%s\n' "${users_json}" | jq -e --arg user_id "${developer_user_id}" \
  'any(.[]; .id == $user_id and any(.permissions[]?; . == "CVM_LAUNCH"))' >/dev/null \
  || fail "journey step 6: developer ${developer_user_id} does not have CVM_LAUNCH after grant"

step 7 "Dev CVM launch"
require_env UMBRA_VERIFY_DEVELOPER_CONFIG_DIR 7
require_env DEV_CVM_IMAGE 7
require_env DEV_CVM_IMAGE_MEASUREMENT 7
require_env SHADE_DIR 7
require_env ATLAS_VERIFIER_CMD 7

developer_cli=(
  cargo run --quiet -p umbra-cli --
  --config "${UMBRA_VERIFY_DEVELOPER_CONFIG_DIR}"
  --console-url "${CONSOLE_URL}"
  --json
)

developer_config_dir="${UMBRA_VERIFY_DEVELOPER_CONFIG_DIR}"
if [ "${UMBRA_VERIFY_DEVELOPER_EMAIL,,}" = "${UMBRA_VERIFY_TENANT_ADMIN_EMAIL,,}" ]; then
  developer_config_dir="${UMBRA_VERIFY_TENANT_ADMIN_CONFIG_DIR}"
  echo "journey step 7: developer account matches tenant admin; reusing tenant-admin session" >&2
  developer_cli=(
    cargo run --quiet -p umbra-cli --
    --config "${developer_config_dir}"
    --console-url "${CONSOLE_URL}"
    --json
  )
fi

ensure_verify_session 7 "developer" "${UMBRA_VERIFY_DEVELOPER_EMAIL}" "${developer_config_dir}" developer_cli
developer_status_json="$("${developer_cli[@]}" status)" \
  || fail "journey step 7: developer status check failed after authentication"
developer_session_email="$(printf '%s\n' "${developer_status_json}" | jq -er '.user.email')" \
  || fail "journey step 7: developer status response did not include user.email"
if [ "${developer_session_email,,}" != "${UMBRA_VERIFY_DEVELOPER_EMAIL,,}" ]; then
  fail "journey step 7: logged-in account did not match the configured developer"
fi
developer_entity_id="$(printf '%s\n' "${developer_status_json}" | jq -er '.entity.id')" \
  || fail "journey step 7: developer status response did not include entity.id"
if [ "${developer_entity_id}" != "${entity_id}" ]; then
  fail "journey step 7: logged-in developer entity ${developer_entity_id} did not match onboarded entity ${entity_id}"
fi

# Two bounds on the sweep, both required. The entity assertion above keeps it
# inside the verifier's own entity, and the verify-profile marker keeps it to Dev
# CVMs a journey created: the verifier identity is an ordinary user, so its own
# entity also holds production Dev CVMs (see reconcile_journey_dev_cvms).
reconcile_journey_dev_cvms 7 developer_cli "${profile_id}" "${profile_name}" \
  swept_journey_dev_cvm_ids foreign_dev_cvms \
  || fail "journey step 7: could not reconcile leftover journey Dev CVMs"

ssh_key_dir="$(mktemp -d)"
tmp_files+=("${ssh_key_dir}")
ssh_key_path="${ssh_key_dir}/umbra_verify_ed25519"
ssh-keygen -q -t ed25519 -N '' -C "umbra-verify-${developer_user_id}" -f "${ssh_key_path}" >/dev/null

ssh_key_json="$("${developer_cli[@]}" key add --label "${UMBRA_VERIFY_SSH_KEY_LABEL:-umbra-verify}" --file "${ssh_key_path}.pub")" \
  || fail "journey step 7: umbra key add failed for developer ${developer_user_id}"
ssh_key_id="$(printf '%s\n' "${ssh_key_json}" | jq -er '.id')" \
  || fail "journey step 7: umbra key add did not return key id"

cvm_launch_args=(
  --profile "${profile_id}"
  cvm launch
  --ssh-key "${ssh_key_id}"
  --wait-timeout-seconds "${UMBRA_VERIFY_DEV_CVM_WAIT_TIMEOUT_SECONDS:-900}"
)
if [ -n "${UMBRA_VERIFY_DEV_CVM_INSTANCE_TYPE:-}" ]; then
  cvm_launch_args+=(--instance-type "${UMBRA_VERIFY_DEV_CVM_INSTANCE_TYPE}")
fi
if [ -n "${UMBRA_VERIFY_DEV_CVM_REGION:-}" ]; then
  cvm_launch_args+=(--region "${UMBRA_VERIFY_DEV_CVM_REGION}")
fi

cvm_json="$("${developer_cli[@]}" "${cvm_launch_args[@]}")" \
  || fail "journey step 7: umbra cvm launch failed for developer ${developer_user_id}"
cvm_id="$(printf '%s\n' "${cvm_json}" | jq -er '.id')" \
  || fail "journey step 7: umbra cvm launch did not return cvm id"
# Hand the CVM to the EXIT trap before asserting anything about it: a launch that
# lands in FAILED still leaves a non-TERMINATED row that blocks decommission.
launched_dev_cvm_id="${cvm_id}"
cvm_state="$(printf '%s\n' "${cvm_json}" | jq -er '.state')" \
  || fail "journey step 7: umbra cvm launch did not return cvm state"
if [ "${cvm_state}" != "RUNNING" ]; then
  fail "journey step 7: Dev CVM ${cvm_id} ended in state ${cvm_state}, expected RUNNING"
fi
printf '%s\n' "${cvm_json}" | jq -e --arg profile_id "${profile_id}" \
  'any(.profiles[]?; .id == $profile_id)' >/dev/null \
  || fail "journey step 7: Dev CVM ${cvm_id} did not include profile ${profile_id}"
printf '%s\n' "${cvm_json}" | jq -e --arg ssh_key_id "${ssh_key_id}" \
  'any(.ssh_keys[]?; .id == $ssh_key_id)' >/dev/null \
  || fail "journey step 7: Dev CVM ${cvm_id} did not include SSH key ${ssh_key_id}"
printf '%s\n' "${cvm_json}" | jq -e '
  (.attestation_verified_at | type == "string") and
  (.image_measurement | type == "string") and
  (.rtmr3_digest | type == "string")
' >/dev/null || fail "journey step 7: Dev CVM ${cvm_id} missing attestation fields"
policy_file_path="$(printf '%s\n' "${cvm_json}" | jq -er '.policy_file_path')" \
  || fail "journey step 7: umbra cvm launch did not return policy_file_path"
if [ ! -s "${policy_file_path}" ]; then
  fail "journey step 7: aTLS policy file was not written"
fi
cvm_fqdn="$(printf '%s\n' "${cvm_json}" | jq -er '.fqdn')" \
  || fail "journey step 7: umbra cvm launch did not return fqdn"

step 8 "tunnel and SSH"
proxy_script="${ssh_key_dir}/umbra-tunnel-proxy.sh"
cat >"${proxy_script}" <<EOF
#!/usr/bin/env bash
set -euo pipefail
cd $(printf '%q' "$(pwd)")
exec cargo run --quiet -p umbra-cli -- --config $(printf '%q' "${developer_config_dir}") --console-url $(printf '%q' "${CONSOLE_URL}") --atls-policy $(printf '%q' "${policy_file_path}") tunnel $(printf '%q' "${cvm_fqdn}")
EOF
chmod 700 "${proxy_script}"

ssh_base=(
  ssh
  -i "${ssh_key_path}"
  -o "ProxyCommand=${proxy_script}"
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o LogLevel=ERROR
  -o ConnectTimeout=30
  -o BatchMode=yes
  -o IdentitiesOnly=yes
  dev@"${cvm_fqdn}"
)
# The tunnel serves as soon as the CVM attests, but the sandbox's sshd only
# accepts after Sysbox finishes registering the container (several minutes on
# first boot). The CLI's own guidance is to retry while the row is RUNNING,
# so poll within a bounded window instead of failing on the first attempt.
ssh_smoke=""
ssh_deadline=$((SECONDS + 420))
while true; do
  if ssh_smoke="$("${developer_cli[@]}" ssh "${cvm_id}" --identity-file "${ssh_key_path}" --command "printf umbra-ssh-ok")"; then
    break
  fi
  if [ "${SECONDS}" -ge "${ssh_deadline}" ]; then
    fail "journey step 8: umbra ssh failed for Dev CVM ${cvm_id} within the sandbox startup window"
  fi
  step 8 "sandbox sshd not accepting yet; retrying"
  sleep 15
done
if [ "${ssh_smoke}" != "umbra-ssh-ok" ]; then
  fail "journey step 8: SSH smoke returned an unexpected response"
fi

step 9 "sandbox behavior"
blocked_url="https://${blocked_host}/"

# Assert the sandbox_env placeholder on its own, BEFORE the egress loop below.
# Folding it into the echo request (as this once did) would let a genuine
# substitution defect look like an unreachable host and silently fail over.
sandbox_placeholder="$("${ssh_base[@]}" "printf '%s' \"\${VERIFY_PLACEHOLDER:-}\"")" \
  || fail "journey step 9: could not read VERIFY_PLACEHOLDER from the sandbox"
if [ "${sandbox_placeholder}" != "non-secret-placeholder" ]; then
  fail "journey step 9: sandbox VERIFY_PLACEHOLDER did not match the expected non-secret value"
fi

# Fail over only past a host that does not ANSWER. A host that answers but echoes
# the wrong headers is a platform defect and fails the run immediately — failing
# over there would let a broken SC hide behind the next candidate.
selected_host=""
egress_attempts=()
for candidate in "${allowed_hosts[@]}"; do
  echo "journey step 9: trying egress target ${candidate}" >&2
  if ! "${ssh_base[@]}" "curl -fsS --max-time 30 https://${candidate}/status/204 >/dev/null"; then
    egress_attempts+=("${candidate} (GET /status/204 unreachable)")
    continue
  fi
  if ! injection_json="$("${ssh_base[@]}" "curl -fsS --max-time 30 -H \"X-Verify-Placeholder: \${VERIFY_PLACEHOLDER}\" https://${candidate}/headers")"; then
    egress_attempts+=("${candidate} (GET /headers unreachable)")
    continue
  fi
  printf '%s\n' "${injection_json}" | jq -e "${VERIFY_EGRESS_HEADER_ASSERTIONS}" >/dev/null \
    || fail "journey step 9: ${candidate} answered but the injected authorization header or placeholder env header was not observed upstream"
  selected_host="${candidate}"
  break
done
if [ -z "${selected_host}" ]; then
  fail "journey step 9: no egress target answered from the sandbox — tried ${egress_attempts[*]}. These are third-party echo services, so confirm they are not all down before suspecting Umbra; set UMBRA_VERIFY_ALLOWED_HOSTS to a reachable httpbin-contract host to unblock the gate"
fi
echo "journey step 9: egress target ${selected_host} answered with the injected header and placeholder env observed upstream" >&2
dlp_url="https://${selected_host}/post"

if "${ssh_base[@]}" "curl -fsS --max-time 30 ${blocked_url} >/dev/null"; then
  fail "journey step 9: blocked destination ${blocked_url} unexpectedly succeeded"
fi

if "${ssh_base[@]}" "curl -fsS --max-time 30 -X POST --data UMBRA_VERIFY_SECRET_ABC123 ${dlp_url} >/dev/null"; then
  fail "journey step 9: DLP request to ${dlp_url} unexpectedly succeeded"
fi

udp_check='import socket,sys
query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
try:
    s.sendto(query,("1.1.1.1",53))
    s.recvfrom(512)
except (OSError, socket.timeout):
    sys.exit(0)
sys.exit(1)'
"${ssh_base[@]}" "python3 -c $(printf '%q' "${udp_check}")" \
  || fail "journey step 9: UDP egress unexpectedly reached a public resolver from the sandbox"

traffic_deadline=$((SECONDS + ${UMBRA_VERIFY_TRAFFIC_LOG_WAIT_SECONDS:-60}))
traffic_logs_ok=0
while [ "${SECONDS}" -lt "${traffic_deadline}" ]; do
  traffic_logs_json="$("${admin_cli[@]}" traffic-logs --cvm "${cvm_id}" --limit 100)" \
    || fail "journey step 9: umbra traffic-logs failed for Dev CVM ${cvm_id}"
  if printf '%s\n' "${traffic_logs_json}" | jq -e \
    --arg allowed_host "${selected_host}" \
    --arg blocked_host "${blocked_host}" '
      (.logs // []) as $logs |
      any($logs[]; .destination_host == $allowed_host and .method == "GET" and .path == "/status/204" and .response_code == 204) and
      any($logs[]; .destination_host == $allowed_host and .method == "GET" and .path == "/headers" and .response_code == 200) and
      any($logs[]; .destination_host == $allowed_host and .method == "POST" and .path == "/post" and .response_code == 403) and
      any($logs[]; .destination_host == $blocked_host and .response_code == 403)
    ' >/dev/null; then
    traffic_logs_ok=1
    break
  fi
  sleep 5
done
if [ "${traffic_logs_ok}" -ne 1 ]; then
  fail "journey step 9: traffic logs did not contain allowed, injected, blocked, and DLP outcomes for Dev CVM ${cvm_id}"
fi

step 10 "audit retrieval"
# The journey may run against a lived-in database (e.g. a migrated private
# deployment), so the expected events can sit thousands of rows deep. Page
# with cursors until the log is exhausted; every page passes the CLI's audit
# hash-chain verification.
audit_limit="${UMBRA_VERIFY_AUDIT_LIMIT:-500}"
audit_max_pages="${UMBRA_VERIFY_AUDIT_MAX_PAGES:-40}"
# UMBRA_VERIFY_AUDIT_FROM (RFC3339) bounds chain verification to rows written
# after a given instant. It exists ONLY to quarantine rows that predate a known
# canonicalization defect: the Console hashed with escaped non-ASCII while the
# spec and the CLI use JCS, so any historical row containing a non-ASCII byte
# is genuine but unverifiable. Never widen this window to silence a NEW
# mismatch — a post-fix failure is a real finding. Fresh deployments leave it
# unset and verify the whole chain.
audit_from_args=()
if [ -n "${UMBRA_VERIFY_AUDIT_FROM:-}" ]; then
  audit_from_args=(--from "${UMBRA_VERIFY_AUDIT_FROM}")
fi
audit_events_merged="[]"
audit_next_cursor=""
audit_page=0
while :; do
  audit_page=$((audit_page + 1))
  if [ "${audit_page}" -gt "${audit_max_pages}" ]; then
    fail "journey step 10: audit log exceeded ${audit_max_pages} pages of ${audit_limit} rows before all journey events could be verified; raise UMBRA_VERIFY_AUDIT_MAX_PAGES or archive the log"
  fi
  audit_cursor_args=()
  if [ -n "${audit_next_cursor}" ]; then
    audit_cursor_args=(--cursor "${audit_next_cursor}")
  fi
  audit_json="$("${admin_cli[@]}" audit events --limit "${audit_limit}" "${audit_from_args[@]}" "${audit_cursor_args[@]}")" \
    || fail "journey step 10: umbra audit events failed or audit hash-chain verification failed"
  audit_events_merged="$(printf '%s\n%s\n' "${audit_events_merged}" "${audit_json}" \
    | jq -cs '.[0] + (.[1].events // [])')" \
    || fail "journey step 10: failed to merge audit event pages"
  audit_next_cursor="$(printf '%s\n' "${audit_json}" | jq -r '.next_cursor // empty')" \
    || fail "journey step 10: audit events response did not include a valid next_cursor field"
  if [ -z "${audit_next_cursor}" ]; then
    break
  fi
done
audit_json="$(printf '%s\n' "${audit_events_merged}" | jq -c '{events: .}')" \
  || fail "journey step 10: failed to assemble merged audit events"

missing_audit_events="$(
  printf '%s\n' "${audit_json}" | jq -r \
    --arg tenant_admin_user_id "${tenant_admin_user_id}" \
    --arg security_cvm_id "${security_cvm_id}" \
    --arg profile_id "${profile_id}" \
    --arg developer_user_id "${developer_user_id}" \
    --arg ssh_key_id "${ssh_key_id}" \
    --arg cvm_id "${cvm_id}" \
    --arg created_entity "${journey_created_entity}" \
    --arg created_security_cvm "${journey_created_security_cvm}" \
    --arg created_profile "${journey_created_profile}" \
    --arg created_developer "${journey_created_developer}" \
    --arg assigned_member "${journey_assigned_profile_member}" '
      def has_event($action; $target_type; $target_id):
        any((.events // [])[]; .action == $action and .target_type == $target_type and .target_id == $target_id);
      def require($flag; $action; $target_type; $target_id; $message):
        if $flag != "1" or has_event($action; $target_type; $target_id) then empty else $message end;
      [
        require($created_entity; "USER_REGISTERED"; "user"; $tenant_admin_user_id; "USER_REGISTERED tenant-admin user"),
        require($created_security_cvm; "SECURITY_CVM_PROVISIONING_STARTED"; "security_cvm"; $security_cvm_id; "SECURITY_CVM_PROVISIONING_STARTED security-cvm"),
        # Unconditional: step 4 runs `security-cvm attestation --probe` on
        # every run (reused SC included) and asserts verdict.verified, and the
        # Console persists one SECURITY_CVM_ATTESTATION_VERIFIED per successful
        # probe. Gating this on create would stop the gate noticing a Console
        # that verifies attestation without recording it.
        (if has_event("SECURITY_CVM_ATTESTATION_VERIFIED"; "security_cvm"; $security_cvm_id) then empty else "SECURITY_CVM_ATTESTATION_VERIFIED security-cvm" end),
        require($created_security_cvm; "SECURITY_CVM_PROVISIONED"; "security_cvm"; $security_cvm_id; "SECURITY_CVM_PROVISIONED security-cvm"),
        require($created_profile; "PROFILE_CREATED"; "profile"; $profile_id; "PROFILE_CREATED profile"),
        (if has_event("PROFILE_POLICY_UPDATED"; "profile"; $profile_id) then empty else "PROFILE_POLICY_UPDATED profile" end),
        require($created_developer; "USER_REGISTERED"; "user"; $developer_user_id; "USER_REGISTERED developer user"),
        require($assigned_member; "PROFILE_USER_ASSIGNED"; "profile"; $profile_id; "PROFILE_USER_ASSIGNED profile"),
        (if has_event("SSH_KEY_ADDED"; "ssh_key"; $ssh_key_id) then empty else "SSH_KEY_ADDED ssh-key" end),
        (if has_event("CVM_ATTESTATION_VERIFIED"; "cvm"; $cvm_id) then empty else "CVM_ATTESTATION_VERIFIED dev-cvm" end),
        (if has_event("CVM_LAUNCHED"; "cvm"; $cvm_id) then empty else "CVM_LAUNCHED dev-cvm" end)
      ] | .[]
    '
)" || fail "journey step 10: failed to inspect audit events response"
if [ -n "${missing_audit_events}" ]; then
  missing_audit_summary="$(printf '%s\n' "${missing_audit_events}" | paste -sd, - | sed 's/,/, /g')"
  fail "journey step 10: audit events missing expected entries: ${missing_audit_summary}"
fi

step 11 "teardown"
terminated_cvm_json="$("${developer_cli[@]}" cvm terminate "${cvm_id}" --wait-timeout-seconds "${UMBRA_VERIFY_DEV_CVM_TERMINATE_WAIT_TIMEOUT_SECONDS:-600}")" \
  || fail "journey step 11: umbra cvm terminate failed for Dev CVM ${cvm_id}"
terminated_cvm_id="$(printf '%s\n' "${terminated_cvm_json}" | jq -er '.id')" \
  || fail "journey step 11: Dev CVM terminate response did not include id"
terminated_cvm_state="$(printf '%s\n' "${terminated_cvm_json}" | jq -er '.state')" \
  || fail "journey step 11: Dev CVM terminate response did not include state"
if [ "${terminated_cvm_id}" != "${cvm_id}" ]; then
  fail "journey step 11: terminated Dev CVM ${terminated_cvm_id}, expected ${cvm_id}"
fi
if [ "${terminated_cvm_state}" != "TERMINATED" ]; then
  fail "journey step 11: Dev CVM ${cvm_id} ended in state ${terminated_cvm_state}, expected TERMINATED"
fi
# Confirmed TERMINATED, so the EXIT trap has nothing left to reclaim.
launched_dev_cvm_id=""

# Decommission the Security CVM only if this run provisioned it AND nothing
# foreign blocks it; the helper reports and retains otherwise.
security_cvm_teardown_outcome="$(teardown_journey_security_cvm 11 admin_cli \
  "${security_cvm_id}" "${journey_created_security_cvm}" "${#foreign_dev_cvms[@]}")" \
  || fail "journey step 11: Security CVM teardown failed for ${security_cvm_id}"

teardown_audit_json="$("${admin_cli[@]}" audit events --limit "${audit_limit}")" \
  || fail "journey step 11: umbra audit events failed after teardown or audit hash-chain verification failed"
printf '%s\n' "${teardown_audit_json}" | jq -e \
  --arg cvm_id "${cvm_id}" '
    any((.events // [])[]; .action == "CVM_TERMINATED" and .target_type == "cvm" and .target_id == $cvm_id)
  ' >/dev/null || fail "journey step 11: audit events missing the Dev CVM termination row"
# Asserted only when the SC was actually decommissioned: a retained SC (reused, or
# blocked by a foreign Dev CVM) must NOT produce this row, and demanding it anyway
# would fail a run that behaved correctly.
if [ "${security_cvm_teardown_outcome}" = "terminated" ]; then
  printf '%s\n' "${teardown_audit_json}" | jq -e \
    --arg security_cvm_id "${security_cvm_id}" '
      any((.events // [])[]; .action == "SECURITY_CVM_DECOMMISSIONED" and .target_type == "security_cvm" and .target_id == $security_cvm_id)
    ' >/dev/null || fail "journey step 11: audit events missing the Security CVM decommission row"
fi

require_env PHALA_API_TOKEN 11
make down

compose_containers="$(docker ps -a --filter "label=com.docker.compose.project=umbra" --format '{{.Names}}' || true)"
if [ -n "${compose_containers}" ]; then
  fail "journey step 11: make down left Compose containers: $(printf '%s\n' "${compose_containers}" | paste -sd, - | sed 's/,/, /g')"
fi
compose_networks="$(docker network ls --filter "label=com.docker.compose.project=umbra" --format '{{.Name}}' || true)"
if [ -n "${compose_networks}" ]; then
  fail "journey step 11: make down left Compose networks: $(printf '%s\n' "${compose_networks}" | paste -sd, - | sed 's/,/, /g')"
fi
compose_volumes="$(docker volume ls --filter "label=com.docker.compose.project=umbra" --format '{{.Name}}' | grep -vx 'umbra_console_letsencrypt' | grep -v '_console_db_data$' || true)"
if [ -n "${compose_volumes}" ]; then
  fail "journey step 11: make down left unexpected Compose volumes: $(printf '%s\n' "${compose_volumes}" | paste -sd, - | sed 's/,/, /g')"
fi

phala_cvms="$(PHALA_CLOUD_API_KEY="${PHALA_API_TOKEN}" "${PHALA_CLI_PATH:-/usr/local/bin/phala}" cvms list 2>/dev/null)" \
  || fail "journey step 11: failed to list Phala CVMs after make down"
umbra_phala_cvm_names="$(printf '%s\n' "${phala_cvms}" \
  | awk -v prefix="${JOURNEY_PROVIDER_CVM_NAME_PREFIX}" 'index($1, prefix) == 1 {print $1}')"
# Every resource this run terminated must be gone at the provider too. Resources
# the run did NOT create are reported, not asserted absent — a lived-in deployment
# legitimately keeps its own Dev CVMs and Security CVM running through the gate.
must_be_absent_ids=("${cvm_id}" ${swept_journey_dev_cvm_ids[@]+"${swept_journey_dev_cvm_ids[@]}"})
if [ "${security_cvm_teardown_outcome}" = "terminated" ]; then
  must_be_absent_ids+=("${security_cvm_id}")
fi
leaked_provider_cvms="$(journey_provider_leaks "${umbra_phala_cvm_names}" "${must_be_absent_ids[@]}")" \
  || fail "journey step 11: could not attribute the Phala CVM listing to this run's resources"
if [ -n "${leaked_provider_cvms}" ]; then
  fail "journey step 11: teardown left provider CVM(s) for resources this run terminated: $(printf '%s\n' "${leaked_provider_cvms}" | paste -sd, - | sed 's/,/, /g')"
fi
retained_provider_cvms="$(printf '%s' "${umbra_phala_cvm_names}" | grep -c . || true)"
if [ "${retained_provider_cvms}" -gt 0 ]; then
  echo "journey step 11: leaving ${retained_provider_cvms} Umbra-managed Phala CVM(s) this run did not create: $(printf '%s\n' "${umbra_phala_cvm_names}" | paste -sd, - | sed 's/,/, /g')" >&2
fi

step "complete" "full journey passed"
