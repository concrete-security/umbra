#!/usr/bin/env bash
# Behavioral tests for the verifier's pure step-9 helpers and its private
# bootstrap-session transfer path (also shared in shape with bootstrap.sh).
#
# The journey itself only runs against live infra, so before this file its egress
# logic was covered by nothing but `bash -n`. Every case below pins a rule that is
# INVISIBLE to a green verify run: soften it and the journey still passes while
# proving strictly less. The three that matter, and the "simplification" each one
# guards against:
#
#   1. the legacy singular UMBRA_VERIFY_ALLOWED_HOST must stay a PREFERENCE.
#      Making it an exclusive pin again silently opts the promotion gate back into
#      the single third-party dependency the pool exists to remove.
#   2. the echoed-header comparison must reject a MULTI-value array rather than
#      picking an element. `.[0]` instead would turn exact equality into a
#      "contains" test, so an SC sending an extra Authorization value would pass.
#   3. the policy document must stay acceptable to the real Console validator.
#   4. cleanup must reach ONLY what a journey created. Widening it back to "every
#      Dev CVM the verifier can see" still leaves the journey green while it
#      destroys production CVMs (it did, on 2026-08-06), and terminating a REUSED
#      Security CVM at teardown takes every Dev CVM in the entity offline.
#
# Resolution cases run the library in a child shell with both knobs explicitly
# unset, so a developer's own exported UMBRA_VERIFY_* cannot skew the result.
set -euo pipefail

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="${ROOT}/ops/verify/verify-journey-lib.sh"
# shellcheck source=ops/verify/verify-journey-lib.sh
source "${LIB}"

fail() { echo "test failed: $*" >&2; exit 1; }
pass() { echo "verify-journey: ok: $*" >&2; }

POOL="postman-echo.com httpbin.dev httpbingo.org httpbin.org"

# --- 1. egress target resolution + de-duplication ----------------------------

# resolve_case <label> <expected> [VAR=val ...]
resolve_case() {
  local label="$1" expected="$2" got
  shift 2
  got="$(
    env -u UMBRA_VERIFY_ALLOWED_HOST -u UMBRA_VERIFY_ALLOWED_HOSTS "$@" \
      bash -c 'set -euo pipefail; source "$1"; resolve_verify_egress_hosts hosts; printf "%s" "${hosts[*]}"' \
      _ "${LIB}"
  )"
  [ "${got}" = "${expected}" ] || fail "resolve (${label}): expected [${expected}], got [${got}]"
}

resolve_case "neither knob set" "${POOL}"
# The migration case: a deployed .env still carrying the value operator-setup.md
# used to prescribe must gain the failover pool, not keep a single dependency.
resolve_case "legacy singular =httpbin.org" \
  "httpbin.org postman-echo.com httpbin.dev httpbingo.org" \
  UMBRA_VERIFY_ALLOWED_HOST=httpbin.org
resolve_case "legacy singular, host not in pool" \
  "my.echo.example ${POOL}" \
  UMBRA_VERIFY_ALLOWED_HOST=my.echo.example
resolve_case "plural runs against exactly one host" "only.example" \
  UMBRA_VERIFY_ALLOWED_HOSTS=only.example
resolve_case "plural, comma separated" "a.example b.example c.example" \
  UMBRA_VERIFY_ALLOWED_HOSTS=a.example,b.example,c.example
resolve_case "plural, comma and space mixed" "a.example b.example" \
  UMBRA_VERIFY_ALLOWED_HOSTS="a.example, b.example"
resolve_case "both knobs, singular wins and de-dups" "b.example a.example" \
  UMBRA_VERIFY_ALLOWED_HOST=b.example UMBRA_VERIFY_ALLOWED_HOSTS="a.example b.example"
resolve_case "both knobs empty falls back to pool" "${POOL}" \
  UMBRA_VERIFY_ALLOWED_HOST= UMBRA_VERIFY_ALLOWED_HOSTS=
pass "egress targets resolve in preference order, de-duplicated, space/comma separated"

# A repeated host must collapse: two policy rules sharing an id are rejected by the
# Console with duplicate_id, which would fail step 5 rather than step 9.
resolve_case "repeated host collapses" "dup.example" \
  UMBRA_VERIFY_ALLOWED_HOSTS="dup.example dup.example,dup.example"
pass "a repeated host cannot produce duplicate policy ids"

# --- 2. echoed-header comparison ---------------------------------------------

AUTH='Bearer verify-secret-placeholder'
PLACEHOLDER='non-secret-placeholder'

# header_case <expect: pass|fail> <label> <json>
header_case() {
  local expect="$1" label="$2" json="$3" got
  if printf '%s' "${json}" | jq -e "${VERIFY_EGRESS_HEADER_ASSERTIONS}" >/dev/null 2>&1; then
    got=pass
  else
    got=fail
  fi
  [ "${got}" = "${expect}" ] || fail "header (${label}): expected ${expect}, got ${got}"
}

# Accepted shapes: scalar (httpbin.org, postman-echo.com), single-element array
# (httpbingo.org, httpbin.dev), and either header casing.
header_case pass "scalar, title-case keys" \
  "{\"headers\":{\"Authorization\":\"${AUTH}\",\"X-Verify-Placeholder\":\"${PLACEHOLDER}\"}}"
header_case pass "scalar, lower-case keys" \
  "{\"headers\":{\"authorization\":\"${AUTH}\",\"x-verify-placeholder\":\"${PLACEHOLDER}\"}}"
header_case pass "single-element arrays" \
  "{\"headers\":{\"Authorization\":[\"${AUTH}\"],\"X-Verify-Placeholder\":[\"${PLACEHOLDER}\"]}}"
pass "accepts scalar and single-element-array header values, either casing"

# Rejected: anything that would let a broken SC through.
header_case fail "multi-value array is not narrowed to its first element" \
  "{\"headers\":{\"Authorization\":[\"${AUTH}\",\"Bearer other\"],\"X-Verify-Placeholder\":[\"${PLACEHOLDER}\"]}}"
header_case fail "empty array" \
  "{\"headers\":{\"Authorization\":[],\"X-Verify-Placeholder\":[\"${PLACEHOLDER}\"]}}"
header_case fail "wrong injected secret" \
  "{\"headers\":{\"Authorization\":\"Bearer wrong\",\"X-Verify-Placeholder\":\"${PLACEHOLDER}\"}}"
header_case fail "missing Authorization" \
  "{\"headers\":{\"X-Verify-Placeholder\":\"${PLACEHOLDER}\"}}"
header_case fail "missing placeholder" \
  "{\"headers\":{\"Authorization\":\"${AUTH}\"}}"
header_case fail "placeholder not substituted by the sandbox" \
  "{\"headers\":{\"Authorization\":\"${AUTH}\",\"X-Verify-Placeholder\":\"\$VERIFY_PLACEHOLDER\"}}"
header_case fail "no headers at all" '{}'
pass "rejects multi-value/empty arrays, wrong values, missing and unsubstituted headers"

# --- 3. policy document ------------------------------------------------------

policy_file="$(mktemp)"
session_fixture_root=""
cleanup_fixture_root=""
cleanup_test_files() {
  rm -f -- "${policy_file}"
  if [ -n "${session_fixture_root}" ]; then
    rm -rf -- "${session_fixture_root}"
  fi
  if [ -n "${cleanup_fixture_root}" ]; then
    rm -rf -- "${cleanup_fixture_root}"
  fi
}
trap cleanup_test_files EXIT

policy_hosts=(postman-echo.com httpbin.dev httpbingo.org httpbin.org)
verify_egress_policy_json policy_hosts admin.example.com >"${policy_file}" \
  || fail "verify_egress_policy_json failed for ${#policy_hosts[@]} hosts"

jq -e --argjson n "${#policy_hosts[@]}" '
  (.allowed_destinations | length) == $n and
  (.secret_injections | length) == $n and
  (.blocked_destinations | length) == 1 and
  (.secret_patterns | length) == 1 and
  ([.allowed_destinations[].id] | unique | length) == $n and
  ([.secret_injections[].id] | unique | length) == $n and
  ([.secret_injections[].match | has("id")] | any | not) and
  (.secret_injections[0].value_template == "Bearer ${secret}") and
  (.sandbox_env.VERIFY_PLACEHOLDER == "non-secret-placeholder")
' "${policy_file}" >/dev/null || fail "policy document has the wrong shape"

# Every generated id must satisfy the Console's POLICY_ID_RE.
if jq -r '(.allowed_destinations[].id, .secret_injections[].id, .blocked_destinations[].id)' "${policy_file}" \
  | grep -qvE '^[A-Za-z0-9._:-]{1,100}$'; then
  fail "policy contains an id that POLICY_ID_RE would reject"
fi
pass "policy emits one destination + one injection per host, with unique valid ids"

empty_hosts=()
if verify_egress_policy_json empty_hosts admin.example.com >/dev/null 2>&1; then
  fail "an empty host list must not yield a policy document"
fi
pass "empty host list is refused rather than emitting an empty policy"

# Shape assertions can drift from what the Console actually accepts, so assert
# against the real validator. The negative control proves it is engaged and not
# silently accepting everything.
#
# uv is a HARD requirement here, never an optional extra. This is the only
# assertion in the file that checks the policy against what the Console will
# actually accept rather than against a restatement of its rules, so skipping it
# would quietly downgrade this suite to shape checks — the exact drift it exists to
# catch. `make check` already requires uv for the Console and Security CVM compile
# steps, so this adds no new dependency; it only refuses to pass while pretending.
command -v uv >/dev/null 2>&1 \
  || fail "uv is required to validate the generated policy against the Console's validate_profile_policy"

uv run --locked --project "${ROOT}/console" python - "${policy_file}" "${ROOT}" <<'PY' \
  || fail "policy document rejected by the real Console validator"
import json, sys

sys.path.insert(0, sys.argv[2] + "/console/src")
from fastapi import HTTPException
from umbra_console.routes import validate_profile_policy

policy = json.load(open(sys.argv[1]))
try:
    validate_profile_policy(policy)
except HTTPException as exc:
    print("validator rejected the generated policy:", json.dumps(exc.detail)[:800], file=sys.stderr)
    raise SystemExit(1)

duplicated = json.loads(json.dumps(policy))
duplicated["secret_injections"][1]["id"] = duplicated["secret_injections"][0]["id"]
try:
    validate_profile_policy(duplicated)
except HTTPException as exc:
    errors = exc.detail.get("error", {}).get("details", {}).get("errors", [])
    if not any(item.get("type") == "duplicate_id" for item in errors):
        print("expected duplicate_id, got:", json.dumps(errors)[:800], file=sys.stderr)
        raise SystemExit(1)
else:
    print("validator accepted duplicate injection ids; it is not engaged", file=sys.stderr)
    raise SystemExit(1)
PY
pass "policy document accepted by the real Console validate_profile_policy"

# --- 4. private bootstrap-session transfer ----------------------------------

# Exercise the real scripts up to their session install boundary with every
# external command mocked. Each mock deliberately emits values that must stay
# private; the scripts must suppress that output, leave a pre-existing session
# untouched, remove their same-directory temporary file, and clean the remote
# session directory after any copy/chmod/mv failure.
session_fixture_root="$(mktemp -d)"
mock_bin="${session_fixture_root}/bin"
mkdir -p -- "${mock_bin}"

cat >"${mock_bin}/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = "compose" ] || exit 90
shift
case "${1:-}" in
  version)
    exit 0
    ;;
  ps)
    printf '%s\n' console console-db
    ;;
  cp)
    destination="${@: -1}"
    if [ "${MOCK_FAILURE}" = "cp" ]; then
      printf '%s\n' "${MOCK_HOSTILE_DIAGNOSTIC}" >&2
      exit 71
    fi
    printf '%s\n' "${MOCK_SESSION_PAYLOAD}" >"${destination}"
    ;;
  exec)
    if [[ " $* " == *" rm -rf "* ]]; then
      printf 'cleaned\n' >>"${MOCK_STATE_DIR}/remote-cleanup"
      exit 0
    fi
    if [[ " $* " == *" mkdir -p "* ]]; then
      exit 0
    fi
    # This simulates a noisy bootstrap command that echoes configured identity
    # data in both channels. The caller must discard both channels.
    printf '%s\n' "${MOCK_HOSTILE_DIAGNOSTIC}"
    printf '%s\n' "${MOCK_HOSTILE_DIAGNOSTIC}" >&2
    ;;
  *)
    exit 91
    ;;
esac
SH

cat >"${mock_bin}/cargo" <<'SH'
#!/usr/bin/env bash
exit 0
SH

cat >"${mock_bin}/curl" <<'SH'
#!/usr/bin/env bash
exit 0
SH

cat >"${mock_bin}/chmod" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [ "${MOCK_FAILURE}" = "chmod" ]; then
  printf '%s\n' "${MOCK_HOSTILE_DIAGNOSTIC}" >&2
  exit 72
fi
exec /usr/bin/chmod "$@"
SH

cat >"${mock_bin}/mv" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [ "${MOCK_FAILURE}" = "mv" ]; then
  printf '%s\n' "${MOCK_HOSTILE_DIAGNOSTIC}" >&2
  exit 73
fi
exec /usr/bin/mv "$@"
SH

chmod 755 -- "${mock_bin}"/*

session_transfer_case() {
  local script_label="$1"
  local script_path="$2"
  local failure="$3"
  local case_dir config_dir state_dir output_file identity_marker payload_marker path_marker
  local expected_error existing_session temp_file

  case_dir="${session_fixture_root}/${script_label}-${failure}"
  path_marker="private-config-${script_label}-${failure}-must-not-log"
  config_dir="${case_dir}/${path_marker}"
  state_dir="${case_dir}/state"
  output_file="${case_dir}/output"
  identity_marker="private-${script_label}-${failure}@must-not-log.example"
  payload_marker="session-payload-${script_label}-${failure}-must-not-log"
  existing_session="existing-session-${script_label}-${failure}"
  mkdir -p -- "${config_dir}" "${state_dir}" "${case_dir}/home"
  printf '%s\n' "${existing_session}" >"${config_dir}/session.json"

  case "${failure}" in
    cp) expected_error="could not copy the private Console bootstrap session" ;;
    chmod) expected_error="could not secure the copied bootstrap session" ;;
    mv) expected_error="could not install the private local bootstrap session" ;;
    *) fail "unknown session-transfer failure fixture" ;;
  esac

  if (
    cd -- "${case_dir}"
    env -i \
      PATH="${mock_bin}:/usr/bin:/bin" \
      HOME="${case_dir}/home" \
      CONSOLE_URL="https://console.invalid" \
      UMBRA_VERIFY_CLI_CONFIG_DIR="${config_dir}" \
      UMBRA_VERIFY_BOOTSTRAP_DOMAIN="${identity_marker}" \
      UMBRA_VERIFY_BOOTSTRAP_ADMIN_EMAIL="${identity_marker}" \
      UMBRA_VERIFY_TENANT_DOMAIN="tenant.must-not-log.example" \
      UMBRA_VERIFY_TENANT_NAME="Private Tenant Must Not Log" \
      UMBRA_VERIFY_TENANT_ADMIN_EMAIL="${identity_marker}" \
      MOCK_FAILURE="${failure}" \
      MOCK_HOSTILE_DIAGNOSTIC="${identity_marker} ${payload_marker} ${path_marker}" \
      MOCK_SESSION_PAYLOAD="${payload_marker}" \
      MOCK_STATE_DIR="${state_dir}" \
      bash "${script_path}"
  ) >"${output_file}" 2>&1; then
    fail "${script_label} unexpectedly succeeded when ${failure} failed"
  fi

  grep -Fq -- "${expected_error}" "${output_file}" \
    || fail "${script_label} ${failure} did not emit its safe failure diagnostic"
  for private_value in "${identity_marker}" "${payload_marker}" "${path_marker}" "umbra-bootstrap-session"; do
    if grep -Fq -- "${private_value}" "${output_file}"; then
      fail "${script_label} ${failure} reproduced a private value in diagnostics"
    fi
  done
  [ "$(cat -- "${config_dir}/session.json")" = "${existing_session}" ] \
    || fail "${script_label} ${failure} replaced the existing session"
  temp_file="$(find "${config_dir}" -maxdepth 1 -name '.session.json.bootstrap.*' -print -quit)"
  [ -z "${temp_file}" ] \
    || fail "${script_label} ${failure} left a temporary session file"
  [ -s "${state_dir}/remote-cleanup" ] \
    || fail "${script_label} ${failure} did not clean the remote session directory"
}

for failure in cp chmod mv; do
  session_transfer_case bootstrap "${ROOT}/ops/deploy/bootstrap.sh" "${failure}"
  session_transfer_case verifier "${ROOT}/ops/verify/verify-journey.sh" "${failure}"
done
pass "bootstrap session transfer is atomic, cleans up on failure, and redacts tool output"


# --- 5. cleanup scope: only what a journey created ---------------------------

# The invariant: the journey terminates its OWN leftovers and nothing else. Both
# helpers reach the Console through an injected CLI array, so the mock below both
# answers them and RECORDS every call — the assertions are about which
# terminations were issued, not only about what was returned.
cleanup_fixture_root="$(mktemp -d)"
mock_cli_path="${cleanup_fixture_root}/mock-umbra"

cat >"${mock_cli_path}" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${MOCK_CLI_LOG}"
case "${1:-} ${2:-}" in
  "cvm list")
    cat -- "${MOCK_CVM_LIST_FILE}"
    ;;
  "cvm terminate")
    case " ${MOCK_TERMINATE_FAIL_IDS:-} " in
      *" ${3} "*) exit 1 ;;
    esac
    printf '{"id":"%s","state":"TERMINATED"}\n' "${3}"
    ;;
  "security-cvm terminate")
    printf '{"id":"%s","state":"%s"}\n' "${MOCK_SC_ID}" "${MOCK_SC_STATE}"
    ;;
  *)
    # Any other Console call from a cleanup helper is out of contract.
    exit 90
    ;;
esac
SH
chmod 755 -- "${mock_cli_path}"

MARKER_PROFILE_ID="11111111-1111-4111-8111-111111111111"
MARKER_PROFILE_NAME="umbra-verify-egress"
JOURNEY_LEFTOVER_ID="aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa"
RECREATED_PROFILE_ID="22222222-2222-4222-8222-222222222222"
FOREIGN_CVM_ID="24485175-cef4-4a7a-93d7-3419477c87ae"
SC_ID="e2d63a73-3333-4333-8333-333333333333"

# The verify profile attaches the marker; a production CVM carries its own.
journey_cvm_json() {
  printf '{"id":"%s","state":"RUNNING","profiles":[{"id":"%s","name":"%s"}]}' \
    "$1" "$2" "$3"
}

# Elements are "<id>" (terminated) or "<id> <state>" (left alone); both reduce to
# the id, so one joiner serves both assertions.
join_ids() {
  local -n _join="$1"
  local item out=""
  for item in ${_join[@]+"${_join[@]}"}; do
    out+="${item%% *} "
  done
  printf '%s' "${out% }"
}

# sweep_case <label> <cvm-list-json> <expected-terminated-ids> <expected-untouched-ids>
sweep_case() {
  local label="$1" cvms="$2" expected_terminated="$3" expected_untouched="$4"
  local log="${cleanup_fixture_root}/${label}.log"
  local list_file="${cleanup_fixture_root}/${label}.json"
  local diag="${cleanup_fixture_root}/${label}.err"
  local -a swept=() untouched=() mock_cli
  local id got

  printf '%s\n' "${cvms}" >"${list_file}"
  : >"${log}"
  mock_cli=(env "MOCK_CLI_LOG=${log}" "MOCK_CVM_LIST_FILE=${list_file}" bash "${mock_cli_path}")
  reconcile_journey_dev_cvms 7 mock_cli "${MARKER_PROFILE_ID}" "${MARKER_PROFILE_NAME}" \
    swept untouched 2>"${diag}" \
    || fail "sweep (${label}): reconcile failed: $(cat -- "${diag}")"

  got="$(join_ids swept)"
  [ "${got}" = "${expected_terminated}" ] \
    || fail "sweep (${label}): terminated [${got}], expected [${expected_terminated}]"
  got="$(join_ids untouched)"
  [ "${got}" = "${expected_untouched}" ] \
    || fail "sweep (${label}): left [${got}], expected [${expected_untouched}]"

  for id in ${expected_untouched}; do
    if grep -Fq "cvm terminate ${id}" "${log}"; then
      fail "sweep (${label}): terminated Dev CVM ${id}, which no journey created"
    fi
    grep -Fq -- "${id}" "${diag}" \
      || fail "sweep (${label}): left Dev CVM ${id} unreported"
  done
  for id in ${expected_terminated}; do
    grep -Fq "cvm terminate ${id}" "${log}" \
      || fail "sweep (${label}): did not terminate its own leftover ${id}"
  done
}

sweep_case "marker-by-id" \
  "[$(journey_cvm_json "${JOURNEY_LEFTOVER_ID}" "${MARKER_PROFILE_ID}" "${MARKER_PROFILE_NAME}")]" \
  "${JOURNEY_LEFTOVER_ID}" ""
# A profile recreated between runs keeps the same NAME with a new id; the leftover
# still attached to the old id must stay recognisable.
sweep_case "marker-by-name" \
  "[$(journey_cvm_json "${JOURNEY_LEFTOVER_ID}" "${RECREATED_PROFILE_ID}" "${MARKER_PROFILE_NAME}")]" \
  "${JOURNEY_LEFTOVER_ID}" ""
pass "a markered leftover from a previous journey is terminated"

# The 2026-08-06 regression, pinned: a production Dev CVM in the verifier's own
# entity, owned by the verifier's own account, carrying another profile.
sweep_case "foreign-only" \
  "[$(journey_cvm_json "${FOREIGN_CVM_ID}" "33333333-3333-4333-8333-333333333333" "zami-coding")]" \
  "" "${FOREIGN_CVM_ID}"
sweep_case "foreign-and-leftover" \
  "[$(journey_cvm_json "${FOREIGN_CVM_ID}" "33333333-3333-4333-8333-333333333333" "zami-coding"),\
$(journey_cvm_json "${JOURNEY_LEFTOVER_ID}" "${MARKER_PROFILE_ID}" "${MARKER_PROFILE_NAME}")]" \
  "${JOURNEY_LEFTOVER_ID}" "${FOREIGN_CVM_ID}"
# No profile at all is still not a marker.
sweep_case "unattached" \
  '[{"id":"44444444-4444-4444-8444-444444444444","state":"STOPPED","profiles":[]}]' \
  "" "44444444-4444-4444-8444-444444444444"
pass "an unmarkered Dev CVM is reported and left alive, never terminated"

# Fail-closed: a leftover this journey CANNOT clear must fail the run there, so it
# cannot be silently carried into step 11's dev_cvms_in_entity conflict.
sweep_terminate_failure_log="${cleanup_fixture_root}/sweep-terminate-failure.log"
sweep_terminate_failure_list="${cleanup_fixture_root}/sweep-terminate-failure.json"
journey_cvm_json "${JOURNEY_LEFTOVER_ID}" "${MARKER_PROFILE_ID}" "${MARKER_PROFILE_NAME}" \
  | sed 's/^/[/; s/$/]/' >"${sweep_terminate_failure_list}"
: >"${sweep_terminate_failure_log}"
sweep_terminate_failure_cli=(
  env "MOCK_CLI_LOG=${sweep_terminate_failure_log}"
  "MOCK_CVM_LIST_FILE=${sweep_terminate_failure_list}"
  "MOCK_TERMINATE_FAIL_IDS=${JOURNEY_LEFTOVER_ID}"
  bash "${mock_cli_path}"
)
sweep_terminate_failure_swept=()
sweep_terminate_failure_untouched=()
if reconcile_journey_dev_cvms 7 sweep_terminate_failure_cli \
  "${MARKER_PROFILE_ID}" "${MARKER_PROFILE_NAME}" \
  sweep_terminate_failure_swept sweep_terminate_failure_untouched 2>/dev/null; then
  fail "sweep: a leftover that cannot be terminated must fail the run"
fi
pass "a leftover the journey cannot terminate fails the run instead of being ignored"

# sc_teardown_case <label> <created-flag> <foreign-count> <expected> [<terminate-state>]
#   <expected>: terminated | retained | error
sc_teardown_case() {
  local label="$1" created="$2" foreign_count="$3" expected="$4"
  local sc_state="${5:-TERMINATED}"
  local log="${cleanup_fixture_root}/sc-${label}.log"
  local diag="${cleanup_fixture_root}/sc-${label}.err"
  local -a mock_cli
  local outcome status=0

  : >"${log}"
  mock_cli=(env "MOCK_CLI_LOG=${log}" "MOCK_SC_ID=${SC_ID}" "MOCK_SC_STATE=${sc_state}" bash "${mock_cli_path}")
  outcome="$(teardown_journey_security_cvm 11 mock_cli "${SC_ID}" "${created}" "${foreign_count}" 2>"${diag}")" \
    || status=$?

  if [ "${expected}" = "error" ]; then
    [ "${status}" -ne 0 ] \
      || fail "sc teardown (${label}): expected a failure, got outcome [${outcome}]"
    return 0
  fi
  [ "${status}" -eq 0 ] \
    || fail "sc teardown (${label}): failed unexpectedly: $(cat -- "${diag}")"
  [ "${outcome}" = "${expected}" ] \
    || fail "sc teardown (${label}): outcome [${outcome}], expected [${expected}]"
  if [ "${expected}" = "terminated" ]; then
    grep -Fq "security-cvm terminate" "${log}" \
      || fail "sc teardown (${label}): did not decommission the Security CVM it provisioned"
  elif grep -Fq "security-cvm terminate" "${log}"; then
    fail "sc teardown (${label}): decommissioned a Security CVM it must have retained"
  fi
}

# Step 4 reused an already-RUNNING SC: terminating it would cut egress for every
# Dev CVM in the entity, including CVMs no journey created.
sc_teardown_case "reused" 0 0 retained
sc_teardown_case "reused-with-foreign-dev-cvms" 0 2 retained
grep -Fq "reused" "${cleanup_fixture_root}/sc-reused.err" \
  || fail "sc teardown: a retained reused Security CVM was not reported as reused"
pass "a Security CVM step 4 reused is never decommissioned at teardown"

sc_teardown_case "journey-created" 1 0 terminated
pass "a Security CVM this journey provisioned is decommissioned at teardown"

# `security-cvm terminate` fails 409 dev_cvms_in_entity while any Dev CVM lives,
# and clearing someone else's Dev CVM to get past it is the widening this whole
# section forbids: report and leave both.
sc_teardown_case "journey-created-blocked" 1 1 retained
grep -Fq "dev_cvms_in_entity" "${cleanup_fixture_root}/sc-journey-created-blocked.err" \
  || fail "sc teardown: a Security CVM blocked by a foreign Dev CVM was not explained"
pass "a journey-provisioned Security CVM blocked by a foreign Dev CVM is reported, not forced"

sc_teardown_case "state-mismatch" 1 0 error RUNNING
sc_teardown_case "bad-foreign-count" 1 "many" error
pass "teardown refuses a Security CVM that did not reach TERMINATED and a non-numeric count"

# --- 6. provider attribution -------------------------------------------------

# Step 11 asserts the provider no longer hosts what this run TERMINATED, and only
# that: asserting zero managed CVMs can never pass on a deployment that keeps its
# own CVMs running, which is how the gate became unrunnable in the first place.
provider_listing="$(printf '%s\n' \
  "umbra-v0-cvm-aaaaaaaa11114111 running" \
  "umbra-v0-cvm-24485175cef44a7a running" \
  "umbra-v0-sc-e2d63a7333334333 running" \
  "unrelated-tenant-cvm running")"

leaks="$(journey_provider_leaks "${provider_listing}" "${JOURNEY_LEFTOVER_ID}" "${SC_ID}" | paste -sd, -)"
[ "${leaks}" = "umbra-v0-cvm-aaaaaaaa11114111,umbra-v0-sc-e2d63a7333334333" ] \
  || fail "provider attribution: leaks [${leaks}] did not match the terminated resources"
leaks="$(journey_provider_leaks "${provider_listing}" "${SC_ID}")"
[ "${leaks}" = "umbra-v0-sc-e2d63a7333334333" ] \
  || fail "provider attribution: a retained Security CVM must not be attributed to a run that kept it"
leaks="$(journey_provider_leaks "${provider_listing}" "99999999-9999-4999-8999-999999999999")"
[ -z "${leaks}" ] \
  || fail "provider attribution: reported [${leaks}] for a resource with no provider CVM"
pass "provider leaks are attributed by resource id, never by counting managed CVMs"

echo "all verify-journey tests passed"
