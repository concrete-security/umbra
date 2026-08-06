#!/usr/bin/env bash
# Refuse to initialize a fresh Umbra database while an explicitly configured
# pre-cutover Console database volume is present. The source identity lives in
# deployment-private configuration; a fresh public checkout has no source.

set -euo pipefail

TARGET_DB_VOLUME="umbra_console_db_data"
VERIFIED_MARKER=".umbra-console-state-verified-v1"
MARKER_IMAGE="${UMBRA_STATE_GUARD_IMAGE:-postgres:16@sha256:33f923b05f64ca54ac4401c01126a6b92afe839a0aa0a52bc5aeb5cc958e5f20}"
CONFIG_PATH="${UMBRA_STATE_GUARD_CONFIG:-ops/db/private-console-state-cutover.conf}"
SOURCE_DB_VOLUME="${UMBRA_STATE_CUTOVER_SOURCE_VOLUME:-}"
SOURCE_PROJECT_SHA256="${UMBRA_STATE_CUTOVER_SOURCE_PROJECT_SHA256:-}"
CONFIG_CONTENT=""
CONFIG_PRESENT=0

guard_fail() {
  echo "console-state-guard: $1" >&2
  exit "${2:-1}"
}

read_config_value() {
  local key="$1"
  local -a matches=()
  while IFS= read -r line; do
    case "$line" in
      "${key}="*) matches+=("${line#*=}") ;;
    esac
  done <<<"$CONFIG_CONTENT"
  [ "${#matches[@]}" -le 1 ] \
    || guard_fail "${CONFIG_PATH} defines ${key} more than once"
  if [ "${#matches[@]}" -eq 1 ]; then
    printf '%s' "${matches[0]}"
  fi
}

if [ -e "$CONFIG_PATH" ]; then
  CONFIG_PRESENT=1
  [ -f "$CONFIG_PATH" ] && [ -r "$CONFIG_PATH" ] \
    || guard_fail "the pre-cutover state selector is not a readable regular file"
  CONFIG_CONTENT="$(
    sed -n '/^UMBRA_STATE_CUTOVER_SOURCE_VOLUME=/p; /^UMBRA_STATE_CUTOVER_SOURCE_PROJECT_SHA256=/p' \
      "$CONFIG_PATH"
  )" || guard_fail "could not read the pre-cutover state selector"
  if [ -z "$SOURCE_DB_VOLUME" ]; then
    SOURCE_DB_VOLUME="$(read_config_value UMBRA_STATE_CUTOVER_SOURCE_VOLUME)"
  fi
  if [ -z "$SOURCE_PROJECT_SHA256" ]; then
    SOURCE_PROJECT_SHA256="$(read_config_value UMBRA_STATE_CUTOVER_SOURCE_PROJECT_SHA256)"
  fi
fi

if [ -z "$SOURCE_DB_VOLUME" ] && [ -z "$SOURCE_PROJECT_SHA256" ]; then
  if [ "$CONFIG_PRESENT" -eq 0 ]; then
    exit 0
  fi
  guard_fail "the pre-cutover state selector is empty or malformed"
fi
[ -n "$SOURCE_DB_VOLUME" ] && [ -n "$SOURCE_PROJECT_SHA256" ] \
  || guard_fail "the pre-cutover state selector is incomplete"

case "$SOURCE_DB_VOLUME" in
  *[!A-Za-z0-9_.-]* | "")
    guard_fail "UMBRA_STATE_CUTOVER_SOURCE_VOLUME is not a valid Docker volume name"
    ;;
esac
[ "$SOURCE_DB_VOLUME" != "$TARGET_DB_VOLUME" ] \
  || guard_fail "the configured source and target database volumes must differ"
[[ "$SOURCE_PROJECT_SHA256" =~ ^[0-9a-f]{64}$ ]] \
  || guard_fail "UMBRA_STATE_CUTOVER_SOURCE_PROJECT_SHA256 must be 64 lowercase hexadecimal characters"

for tool in docker sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || guard_fail "${tool} is required"
done
all_volumes="$(docker volume ls --format '{{.Name}}')" \
  || guard_fail "could not list Docker volumes; refusing to infer that no durable Console state exists"

if ! printf '%s\n' "$all_volumes" | grep -Fxq "$SOURCE_DB_VOLUME"; then
  exit 0
fi
if ! printf '%s\n' "$all_volumes" | grep -Fxq "$TARGET_DB_VOLUME"; then
  guard_fail "configured pre-cutover Console state was found, but ${TARGET_DB_VOLUME} is absent; complete a controlled state copy before startup"
fi

source_volume_label="$(
  docker volume inspect \
    --format '{{ index .Labels "com.docker.compose.volume" }}' \
    "$SOURCE_DB_VOLUME" 2>/dev/null
)" || guard_fail "could not inspect the configured pre-cutover state identity"
source_project_label="$(
  docker volume inspect \
    --format '{{ index .Labels "com.docker.compose.project" }}' \
    "$SOURCE_DB_VOLUME" 2>/dev/null
)" || guard_fail "could not inspect the configured pre-cutover state identity"
[ "$source_volume_label" = "console_db_data" ] \
  || guard_fail "the configured pre-cutover volume does not have the expected Console state label"
source_project_sha256="$(printf '%s' "$source_project_label" | sha256sum | awk '{print $1}')"
[ "$source_project_sha256" = "$SOURCE_PROJECT_SHA256" ] \
  || guard_fail "the configured pre-cutover volume has an unexpected project identity"

if ! docker run --rm --pull never \
  --entrypoint sh \
  -e UMBRA_STATE_MARKER="$VERIFIED_MARKER" \
  -v "${TARGET_DB_VOLUME}:/state:ro" \
  "$MARKER_IMAGE" \
  -c 'test -f "/state/${UMBRA_STATE_MARKER}"' \
  >/dev/null 2>&1; then
  guard_fail "configured pre-cutover Console state was found, and ${TARGET_DB_VOLUME} has no verified migration marker; refusing to select either volume"
fi
