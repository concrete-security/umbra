#!/usr/bin/env bash
# Helpers for ops/verify/verify-journey.sh: the step-9 ("sandbox behavior")
# egress checks and the journey's resource-ownership/cleanup rules.
#
# Sourced, not executed — like ops/deploy/cvm-redeploy-lib.sh.
#
# WHY THESE LIVE HERE. The journey only runs against live infra (a real Console,
# real Phala CVMs, real Google-issued sessions), so anything inline in it is
# covered by nothing but `bash -n`. Each piece below encodes a rule that is
# INVISIBLE to a green verify run — soften it and the journey still passes while
# proving strictly less:
#
#   1. the egress target list, where the legacy singular knob must stay a
#      preference and must not become an exclusive pin again;
#   2. the echoed-header comparison, which must not soften into a "contains" test;
#   3. the policy document, which must stay acceptable to the Console validator;
#   4. the cleanup scope, which must never reach a resource another owner created
#      (the sweep that ignored this destroyed two production Dev CVMs on
#      2026-08-06).
#
# The cleanup helpers reach the Console only through a CLI command array the
# caller injects, so tests/test-verify-journey.sh substitutes a recording mock
# and everything here stays exercised. Nothing opens a socket by itself.
# Functions return non-zero rather than calling the journey's fail(), so they
# stay usable from that harness.

# Interchangeable httpbin-contract hosts run by INDEPENDENT operators, so that no
# single third-party outage can fail the `dev -> main` promotion gate. Step 9 uses
# the first that answers.
#
# A candidate must serve `GET /status/204` -> 204, `GET /headers` -> JSON echoing
# the request headers, and accept `POST /post` (the SC's DLP blocks that one with
# 403 before it reaches upstream, so only the path has to exist).
VERIFY_EGRESS_HOST_POOL="postman-echo.com httpbin.dev httpbingo.org httpbin.org"

# jq program asserting that BOTH the injected Authorization header and the
# substituted sandbox_env placeholder were observed upstream.
#
# An echoed header value is a scalar on some services (httpbin.org,
# postman-echo.com) and a single-element array on others (httpbingo.org,
# httpbin.dev). `sole` normalizes both, but maps a MULTI-value array to null
# rather than picking an element, so this stays exact equality against the value
# the SC sent instead of softening into a "contains" test.
VERIFY_EGRESS_HEADER_ASSERTIONS='
  def sole: if type == "array" then (if length == 1 then .[0] else null end) else . end;
  (((.headers.Authorization // .headers.authorization) | sole) == "Bearer verify-secret-placeholder") and
  (((.headers["X-Verify-Placeholder"] // .headers["x-verify-placeholder"]) | sole) == "non-secret-placeholder")
'

# resolve_verify_egress_hosts <array-name>
#
# Fill the caller's array with the step-9 egress targets in preference order:
# UMBRA_VERIFY_ALLOWED_HOST (legacy, singular) first, then
# UMBRA_VERIFY_ALLOWED_HOSTS, then VERIFY_EGRESS_HOST_POOL. Both variables
# accept a space- or comma-separated list.
#
# The singular knob is a PREFERENCE, not an exclusive pin: docs/operator-setup.md
# used to prescribe `UMBRA_VERIFY_ALLOWED_HOST=httpbin.org`, so deployed .env
# layers still carry it, and honoring it as a pin would silently opt the promotion
# gate back into the single third-party dependency the pool exists to remove. To
# run against exactly one host, set UMBRA_VERIFY_ALLOWED_HOSTS to that host.
#
# The result is de-duplicated preserving order, because a host named by both
# variables would otherwise produce two policy rules sharing an id, which the
# Console rejects with duplicate_id.
resolve_verify_egress_hosts() {
  local -n _resolved="$1"
  local raw host
  local -a requested=()
  local -A seen=()

  raw="${UMBRA_VERIFY_ALLOWED_HOST:-} ${UMBRA_VERIFY_ALLOWED_HOSTS:-${VERIFY_EGRESS_HOST_POOL}}"
  read -r -a requested <<<"${raw//,/ }"

  _resolved=()
  for host in ${requested[@]+"${requested[@]}"}; do
    if [ -z "${seen[${host}]:-}" ]; then
      seen["${host}"]=1
      _resolved+=("${host}")
    fi
  done
}

# verify_egress_policy_json <hosts-array-name> <blocked-host>
#
# Print the verify profile policy document, or return non-zero. Emits one
# allowed_destinations rule and one matching secret_injections rule per egress
# host, so whichever host step 9 settles on is both reachable and injected into.
# Ids embed the host (the Console's POLICY_ID_RE permits dots) to stay unique and
# to name the offending host in a validation error.
verify_egress_policy_json() {
  local -n _hosts="$1"
  local blocked_host="$2"
  local hosts_json

  if [ "${#_hosts[@]}" -eq 0 ]; then
    return 1
  fi

  hosts_json="$(printf '%s\n' "${_hosts[@]}" | jq -R . | jq -s .)" || return 1
  jq -n --argjson allowed_hosts "${hosts_json}" --arg blocked_host "${blocked_host}" '
    def match_rule($host): {
      scheme: "https",
      host: $host,
      ports: [443],
      methods: ["GET", "POST"],
      path_prefixes: ["/"]
    };
    {
      allowed_destinations: [
        $allowed_hosts[] | match_rule(.) + { id: "verify-allowed-\(.)" }
      ],
      blocked_destinations: [
        match_rule($blocked_host) + { id: "verify-blocked-admin" }
      ],
      secret_patterns: [
        {
          id: "verify-dlp-token",
          name: "Verify token",
          pattern: "UMBRA_VERIFY_SECRET_[A-Za-z0-9]+",
          scan_headers: true,
          scan_body: true
        }
      ],
      secret_injections: [
        $allowed_hosts[] | {
          id: "verify-auth-header-\(.)",
          match: match_rule(.),
          type: "request_header",
          header: "authorization",
          value: "verify-secret-placeholder",
          value_template: "Bearer ${secret}"
        }
      ],
      sandbox_env: {
        VERIFY_PLACEHOLDER: "non-secret-placeholder"
      }
    }
  '
}

# --- journey resource ownership ----------------------------------------------
#
# THE INVARIANT: the journey cleans up only what THIS run created, plus genuine
# leftovers from PREVIOUS journeys — never a resource another owner created.
#
# The sweep this replaced terminated every non-TERMINATED Dev CVM the verifier
# session could see, on the theory that any of them had to be a leftover. That
# is false on any lived-in deployment: the verifier identity is an ordinary
# user/entity, so `cvm list` also returns production Dev CVMs owned by the same
# account. On 2026-08-06 it swept two live Zami channel CVMs.
#
# WHY THE MARKER IS THE VERIFY PROFILE. A leftover must be recognisable by a
# *fresh checkout on another machine* (CI runner, a second operator), so the
# marker has to be server-side state. The candidates:
#
#   * `umbra cvm launch --alias` is CLIENT-SIDE ONLY — it writes
#     `~/.umbra/aliases.toml` (cli/src/commands/alias.rs) and is never sent to
#     the Console, so a CI runner's fresh config dir sees no aliases at all.
#   * the CVM owner is NOT discriminating: the incident happened precisely
#     because the verifier account owns the production CVMs too.
#   * the Console persists no user-supplied label/metadata on `cvms`
#     (`cvm_resource`, console/src/umbra_console/resources.py), and adding one
#     would be a new schema + API field for a test-harness concern.
#
# What the Console DOES persist, and returns in `cvm list --json`, is the
# profile attachment (`cvm_profiles` -> `profiles: [{id, name}]`). Step 7 always
# launches with the verify profile, step 5 resolves that profile by NAME
# (`UMBRA_VERIFY_PROFILE_NAME`, default `umbra-verify-egress`), and the Console
# refuses to delete a profile attached to a live CVM (409 `cvms_attached`), so a
# live journey leftover always still carries it. That makes "attached to the
# verify profile" a deterministic, server-side, machine-checkable marker with no
# new API surface. Matching id OR name keeps a leftover recognisable across a
# profile that was recreated between runs.
#
# Anything unmarkered is reported and left alone, in every state. A marker that
# stops matching therefore leaks (the next run reports it) rather than deletes.
JOURNEY_DEV_CVM_PARTITION_JQ='
  .[]?
  | (if any(.profiles[]?; (.id == $marker_id) or (.name == $marker_name))
     then "own" else "foreign" end) as $bucket
  | "\($bucket) \(.id) \(.state)"
'

# Provider CVM names the Console mints: `umbra-v0-cvm-<token>` and
# `umbra-v0-sc-<token>`, where <token> is the resource UUID with its dashes
# removed and truncated (`cvm_launch_provider_name` / `security_cvm_provider_name`
# in console/src/umbra_console/scheduler.py, 16 chars; `routes_admin.py` uses 12).
# Kept here so the journey and the attribution below share one definition.
JOURNEY_PROVIDER_CVM_NAME_PREFIX="umbra-v0-"

# journey_partition_dev_cvms <list-json> <marker-profile-id> <marker-profile-name> \
#                            <own-array-name> <foreign-array-name>
#
# Split an `umbra cvm list --json` page into the CVMs a verify journey created
# (markered) and everything else. Each element is "<id> <state>".
journey_partition_dev_cvms() {
  local list_json="$1" marker_id="$2" marker_name="$3"
  local -n _journey_own="$4"
  local -n _journey_foreign="$5"
  local partitioned line

  _journey_own=()
  _journey_foreign=()
  partitioned="$(printf '%s\n' "${list_json}" | jq -r \
    --arg marker_id "${marker_id}" \
    --arg marker_name "${marker_name}" \
    "${JOURNEY_DEV_CVM_PARTITION_JQ}")" || return 1
  while IFS= read -r line; do
    case "${line}" in
      "own "*) _journey_own+=("${line#own }") ;;
      "foreign "*) _journey_foreign+=("${line#foreign }") ;;
    esac
  done <<<"${partitioned}"
}

# reconcile_journey_dev_cvms <step-no> <cli-array-name> <marker-profile-id> \
#                            <marker-profile-name> <terminated-array-name> \
#                            <foreign-array-name>
#
# Terminate the Dev CVMs a PREVIOUS journey left alive, so a run that died before
# its own teardown does not block this one, and leave every unmarkered Dev CVM in
# place. Two independent bounds apply: the caller asserts the verifier session and
# its entity, and the marker above scopes the sweep inside that entity to what a
# journey created.
#
# Fills <terminated-array-name> with the ids it removed (step 11 asserts those are
# gone at the provider) and <foreign-array-name> with "<id> <state>" for each CVM
# it deliberately left alone (step 11 needs the count: a foreign Dev CVM blocks
# `security-cvm terminate` with dev_cvms_in_entity).
#
# Termination goes through the API, not the DB, so each removal still emits its
# CVM_TERMINATED audit row and deprovisions DNS.
reconcile_journey_dev_cvms() {
  local step_no="$1"
  local -n _reconcile_cli="$2"
  local marker_id="$3" marker_name="$4"
  local -n _reconcile_terminated="$5"
  local -n _reconcile_foreign="$6"
  local list_json entry entry_id entry_state
  # Underscore-prefixed so a caller array named `own`/`foreign` cannot shadow the
  # namerefs above (bash resolves a nameref against the innermost binding).
  local -a _own=() _foreign=()

  _reconcile_terminated=()
  _reconcile_foreign=()
  if ! list_json="$("${_reconcile_cli[@]}" cvm list --state alive)"; then
    echo "journey step ${step_no}: umbra cvm list failed while reconciling leftover journey Dev CVMs" >&2
    return 1
  fi
  if ! journey_partition_dev_cvms "${list_json}" "${marker_id}" "${marker_name}" _own _foreign; then
    echo "journey step ${step_no}: could not parse the Dev CVM listing while reconciling leftovers" >&2
    return 1
  fi

  _reconcile_foreign=(${_foreign[@]+"${_foreign[@]}"})
  for entry in ${_foreign[@]+"${_foreign[@]}"}; do
    read -r entry_id entry_state <<<"${entry}"
    echo "journey step ${step_no}: leaving Dev CVM ${entry_id} (state ${entry_state}) untouched: it is not attached to the verify profile ${marker_name}, so no verify journey created it" >&2
  done
  if [ "${#_own[@]}" -eq 0 ]; then
    echo "journey step ${step_no}: no leftover journey Dev CVMs to reconcile" >&2
  fi
  for entry in ${_own[@]+"${_own[@]}"}; do
    read -r entry_id entry_state <<<"${entry}"
    echo "journey step ${step_no}: terminating leftover journey Dev CVM ${entry_id} (state ${entry_state}) from a previous journey" >&2
    if ! "${_reconcile_cli[@]}" cvm terminate "${entry_id}" \
      --wait-timeout-seconds "${UMBRA_VERIFY_DEV_CVM_TERMINATE_WAIT_TIMEOUT_SECONDS:-600}" >/dev/null; then
      echo "journey step ${step_no}: could not terminate leftover journey Dev CVM ${entry_id} in state ${entry_state}; it would block step 11 with dev_cvms_in_entity, so clear it with umbra cvm terminate ${entry_id} (a CVM stuck in PROVISIONING has no legal terminate transition and needs an operator)" >&2
      return 1
    fi
    _reconcile_terminated+=("${entry_id}")
    echo "journey step ${step_no}: terminated leftover journey Dev CVM ${entry_id}" >&2
  done
}

# teardown_journey_security_cvm <step-no> <cli-array-name> <security-cvm-id> \
#                               <journey-created-flag> <foreign-dev-cvm-count>
#
# Decommission the entity Security CVM only when this run provisioned it and
# nothing foreign stands in the way. Prints its decision on stdout — `terminated`
# or `retained` — so step 11 asserts the SECURITY_CVM_DECOMMISSIONED audit row and
# the provider deprovision exactly when they are expected.
#
# Two reasons to retain:
#
#   * step 4 REUSED an already-RUNNING Security CVM. Terminating it would destroy
#     the egress path of every Dev CVM in the entity — a resource this run did not
#     create.
#   * this run provisioned it, but a Dev CVM it did not create is still alive.
#     `security-cvm terminate` fails 409 `dev_cvms_in_entity` while any Dev CVM
#     lives, and terminating someone else's Dev CVM to clear the way is exactly the
#     widening this invariant forbids. So report both and leave both: the run is
#     honest about the SC it leaked instead of failing on a conflict it must not
#     resolve.
teardown_journey_security_cvm() {
  local step_no="$1"
  local -n _teardown_cli="$2"
  local security_cvm_id="$3" journey_created="$4" foreign_count="$5"
  local response terminated_id terminated_state

  if ! [[ "${foreign_count}" =~ ^[0-9]+$ ]]; then
    echo "journey step ${step_no}: foreign Dev CVM count must be a non-negative integer" >&2
    return 1
  fi
  if [ "${journey_created}" != "1" ]; then
    echo "journey step ${step_no}: leaving Security CVM ${security_cvm_id} in place: step 4 reused an already-RUNNING Security CVM, so this journey did not provision it" >&2
    printf '%s\n' "retained"
    return 0
  fi
  if [ "${foreign_count}" -gt 0 ]; then
    echo "journey step ${step_no}: leaving Security CVM ${security_cvm_id} in place even though this journey provisioned it: ${foreign_count} Dev CVM(s) this journey did not create are still alive in the entity, and security-cvm terminate fails with dev_cvms_in_entity while any Dev CVM lives. Terminating those Dev CVMs is their owner's call, not the verifier's, so decommission this Security CVM with umbra security-cvm terminate once they are gone" >&2
    printf '%s\n' "retained"
    return 0
  fi

  if ! response="$("${_teardown_cli[@]}" security-cvm terminate)"; then
    echo "journey step ${step_no}: umbra security-cvm terminate failed for Security CVM ${security_cvm_id}" >&2
    return 1
  fi
  if ! terminated_id="$(printf '%s\n' "${response}" | jq -er '.id')"; then
    echo "journey step ${step_no}: Security CVM terminate response did not include id" >&2
    return 1
  fi
  if ! terminated_state="$(printf '%s\n' "${response}" | jq -er '.state')"; then
    echo "journey step ${step_no}: Security CVM terminate response did not include state" >&2
    return 1
  fi
  if [ "${terminated_id}" != "${security_cvm_id}" ]; then
    echo "journey step ${step_no}: terminated Security CVM ${terminated_id}, expected ${security_cvm_id}" >&2
    return 1
  fi
  if [ "${terminated_state}" != "TERMINATED" ]; then
    echo "journey step ${step_no}: Security CVM ${security_cvm_id} ended in state ${terminated_state}, expected TERMINATED" >&2
    return 1
  fi
  printf '%s\n' "terminated"
}

# journey_provider_leaks <provider-cvm-name-listing> [<resource-uuid> ...]
#
# Print the provider CVM names still present that belong to one of the given
# resource ids — i.e. resources this run terminated whose provider CVM survived.
#
# Step 11 used to assert the provider hosts ZERO managed CVMs, which is another
# form of the same bug: on a deployment that legitimately runs Dev CVMs and a
# Security CVM the journey did not create, that assertion can only ever fail.
# Attribution by id is both runnable there and STRICTER for what it covers — it
# names the specific leaked resource instead of counting.
journey_provider_leaks() {
  local listing="$1"
  shift
  local name token compact id
  while IFS= read -r name; do
    name="${name%%[[:space:]]*}"
    [ -n "${name}" ] || continue
    # `umbra-v0-cvm-<token>` / `umbra-v0-sc-<token>`; the truncation length has
    # changed before, so match the token as a PREFIX of the compact uuid rather
    # than pinning a width.
    token="${name##*-}"
    token="${token,,}"
    [ -n "${token}" ] || continue
    for id in "$@"; do
      compact="${id//-/}"
      compact="${compact,,}"
      if [ "${compact#"${token}"}" != "${compact}" ]; then
        printf '%s\n' "${name}"
        break
      fi
    done
  done <<<"${listing}"
}
