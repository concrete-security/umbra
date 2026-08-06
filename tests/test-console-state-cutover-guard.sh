#!/usr/bin/env bash
# Behavioral tests for the explicit-selector Console state cutover guard.

set -euo pipefail

ROOT="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${ROOT}/ops/db/guard-console-state-cutover.sh"
TARGET="umbra_console_db_data"
SOURCE="precutover_console_db_data"
SOURCE_PROJECT="precutover-project"
SOURCE_PROJECT_SHA256="$(printf '%s' "$SOURCE_PROJECT" | sha256sum | awk '{print $1}')"

fail() {
  echo "test failed: $*" >&2
  exit 1
}

make_fake_docker() {
  local bin_dir="$1"
  mkdir -p "$bin_dir"
  cat >"${bin_dir}/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_DOCKER_LOG}"

if [ "${FAKE_DOCKER_LIST_FAILURE:-}" = "1" ] && [ "${1:-}" = "volume" ] && [ "${2:-}" = "ls" ]; then
  exit 1
fi

case "${1:-}:${2:-}" in
  volume:ls)
    printf '%s' "${FAKE_ALL_VOLUMES:-}"
    ;;
  volume:inspect)
    [ "${FAKE_DOCKER_INSPECT_FAILURE:-}" != "1" ] || exit 1
    volume_name="${*: -1}"
    printf '%s\n' "${FAKE_ALL_VOLUMES:-}" | grep -Fxq "$volume_name" || exit 1
    if [[ "$*" == *"com.docker.compose.volume"* ]]; then
      printf '%s\n' "${FAKE_SOURCE_VOLUME_LABEL:-console_db_data}"
    elif [[ "$*" == *"com.docker.compose.project"* ]]; then
      printf '%s\n' "${FAKE_SOURCE_PROJECT:-precutover-project}"
    fi
    ;;
  run:*)
    [ "${FAKE_MARKER_PRESENT:-}" = "1" ]
    ;;
  *)
    exit 1
    ;;
esac
SH
  chmod 755 "${bin_dir}/docker"
}

run_guard() {
  local tmp="$1"
  PATH="${tmp}/bin:${PATH}" \
  FAKE_DOCKER_LOG="${tmp}/docker.log" \
  UMBRA_STATE_CUTOVER_SOURCE_VOLUME="$SOURCE" \
  UMBRA_STATE_CUTOVER_SOURCE_PROJECT_SHA256="$SOURCE_PROJECT_SHA256" \
  "$SCRIPT"
}

expect_success() (
  local label="$1" all_volumes="$2" marker_present="$3" tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  make_fake_docker "${tmp}/bin"
  if ! FAKE_ALL_VOLUMES="$all_volumes" \
    FAKE_MARKER_PRESENT="$marker_present" \
    run_guard "$tmp"; then
    fail "${label}: expected guard success"
  fi
)

expect_failure() (
  local label="$1" all_volumes="$2" marker_present="$3" tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  make_fake_docker "${tmp}/bin"
  if FAKE_ALL_VOLUMES="$all_volumes" \
    FAKE_MARKER_PRESENT="$marker_present" \
    run_guard "$tmp" >/dev/null 2>&1; then
    fail "${label}: expected guard failure"
  fi
)

expect_success "fresh host" "" 0
expect_success "fresh Umbra state only" "$TARGET" 0
expect_success "unrelated Compose state" "unrelated_console_db_data" 0
expect_failure "source without target" "$SOURCE" 0
expect_failure "source plus unverified target" "$TARGET
$SOURCE" 0
expect_success "source plus verified target" "$TARGET
$SOURCE" 1

inspect_tmp="$(mktemp -d)"
trap 'rm -rf "$inspect_tmp"' EXIT
make_fake_docker "${inspect_tmp}/bin"
if FAKE_ALL_VOLUMES="$TARGET
$SOURCE" \
  FAKE_DOCKER_INSPECT_FAILURE=1 \
  run_guard "$inspect_tmp" >/dev/null 2>&1; then
  fail "source inspection failure was treated as an absent source"
fi

identity_tmp="$(mktemp -d)"
trap 'rm -rf "$identity_tmp"' EXIT
make_fake_docker "${identity_tmp}/bin"
if FAKE_ALL_VOLUMES="$SOURCE" \
  FAKE_SOURCE_PROJECT="different-project" \
  run_guard "$identity_tmp" >/dev/null 2>&1; then
  fail "unexpected source project identity was accepted"
fi

unconfigured_tmp="$(mktemp -d)"
trap 'rm -rf "$unconfigured_tmp"' EXIT
make_fake_docker "${unconfigured_tmp}/bin"
if ! PATH="${unconfigured_tmp}/bin:${PATH}" \
  FAKE_DOCKER_LOG="${unconfigured_tmp}/docker.log" \
  UMBRA_STATE_GUARD_CONFIG="${unconfigured_tmp}/absent.conf" \
  "$SCRIPT"; then
  fail "a public checkout without a private selector did not pass"
fi
[ ! -e "${unconfigured_tmp}/docker.log" ] \
  || fail "an unconfigured public guard queried Docker"

expect_selector_config_failure() (
  local label="$1" content="$2" tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  make_fake_docker "${tmp}/bin"
  printf '%s' "$content" >"${tmp}/selector.conf"
  if PATH="${tmp}/bin:${PATH}" \
    FAKE_DOCKER_LOG="${tmp}/docker.log" \
    UMBRA_STATE_GUARD_CONFIG="${tmp}/selector.conf" \
    "$SCRIPT" >/dev/null 2>&1; then
    fail "${label}: malformed selector was treated as an unconfigured public checkout"
  fi
)

expect_selector_config_failure "empty selector" ""
expect_selector_config_failure "unknown selector key" $'UNRELATED=value\n'
expect_selector_config_failure \
  "truncated selector" \
  $'UMBRA_STATE_CUTOVER_SOURCE_VOLUME=precutover_console_db_data\n'

config_read_tmp="$(mktemp -d)"
trap 'rm -rf "$config_read_tmp"' EXIT
make_fake_docker "${config_read_tmp}/bin"
printf '%s\n' 'UMBRA_STATE_CUTOVER_SOURCE_VOLUME=source' >"${config_read_tmp}/selector.conf"
cat >"${config_read_tmp}/bin/sed" <<'SH'
#!/usr/bin/env bash
exit 1
SH
chmod 755 "${config_read_tmp}/bin/sed"
if PATH="${config_read_tmp}/bin:${PATH}" \
  FAKE_DOCKER_LOG="${config_read_tmp}/docker.log" \
  UMBRA_STATE_GUARD_CONFIG="${config_read_tmp}/selector.conf" \
  "$SCRIPT" >/dev/null 2>&1; then
  fail "selector read failure was treated as an unconfigured public checkout"
fi

failure_tmp="$(mktemp -d)"
trap 'rm -rf "$failure_tmp"' EXIT
make_fake_docker "${failure_tmp}/bin"
if FAKE_DOCKER_LIST_FAILURE=1 run_guard "$failure_tmp" >/dev/null 2>&1; then
  fail "Docker listing failure was treated as an empty host"
fi

up_recipe="$(
  awk '
    /^up:/ { in_up = 1; next }
    in_up && /^[^[:space:]]/ { exit }
    in_up && /^\t/ { print }
  ' "${ROOT}/Makefile"
)"
first_up_command="$(printf '%s\n' "$up_recipe" | sed -n '1{s/^[[:space:]]*//;p;}')"
[ "$first_up_command" = './ops/db/guard-console-state-cutover.sh' ] \
  || fail "make up does not run the state guard before any startup side effect"

for guarded_target in up-env bootstrap-env; do
  target_recipe="$(
    awk -v target="${guarded_target}:" '
      $0 == target { in_target = 1; next }
      in_target && /^[^[:space:]]/ { exit }
      in_target && /^\t/ { print }
    ' "${ROOT}/Makefile"
  )"
  first_target_command="$(printf '%s\n' "$target_recipe" | sed -n '1{s/^[[:space:]]*//;p;}')"
  [ "$first_target_command" = './ops/db/guard-console-state-cutover.sh' ] \
    || fail "make ${guarded_target} does not run the state guard before any setup side effect"
done

deploy_guard_line="$(grep -n -m1 '^\./ops/db/guard-console-state-cutover\.sh$' "${ROOT}/ops/deploy/deploy.sh" | cut -d: -f1)"
deploy_volume_line="$(grep -n -m1 '^docker volume create umbra_console_letsencrypt ' "${ROOT}/ops/deploy/deploy.sh" | cut -d: -f1)"
[ -n "$deploy_guard_line" ] && [ -n "$deploy_volume_line" ] && [ "$deploy_guard_line" -lt "$deploy_volume_line" ] \
  || fail "deploy does not run the state guard before creating durable state"

documented_unit="${ROOT}/docs/ci-cd.md"
documented_exec_starts="$(
  awk '
    /^[[:space:]]*ExecStart=/ {
      sub(/^[[:space:]]*/, "")
      print
    }
  ' "$documented_unit"
)"
printf '%s\n' "$documented_exec_starts" | grep -Fxq 'ExecStart=/usr/bin/make up' \
  || fail "the documented reboot unit does not use the guarded make up entrypoint"
if printf '%s\n' "$documented_exec_starts" \
  | grep -Eq 'ExecStart=.*docker[[:space:]]+compose[[:space:]]+up'; then
  fail "the documented reboot unit bypasses the state guard with direct docker compose startup"
fi

echo "all Console state cutover guard tests passed"
