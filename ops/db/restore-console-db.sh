#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=ops/db/console-db-guard.sh
source "${ROOT}/ops/db/console-db-guard.sh"

backup_path="${1:-}"
if [ -z "$backup_path" ]; then
  console_db_guard_fail "usage: $0 /path/to/console-YYYYMMDDTHHMMSSZ.sql.gz"
fi
if [ ! -f "$backup_path" ]; then
  console_db_guard_fail "backup file not found: ${backup_path}"
fi
if [ ! -s "$backup_path" ]; then
  console_db_guard_fail "backup file is empty: ${backup_path}"
fi

pre_restore_backup="$(console_db_guard_before_destructive "restore-from-${backup_path}")"
console_db_guard_info "proceeding with restore after pre-restore backup ${pre_restore_backup}"

restore_tmp="$(mktemp)"
if ! gunzip -c "$backup_path" >"$restore_tmp"; then
  rm -f "$restore_tmp"
  console_db_guard_fail "failed to decompress backup ${backup_path}"
fi
if ! docker compose exec -T console-db sh -c \
  'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' \
  <"$restore_tmp"; then
  rm -f "$restore_tmp"
  console_db_guard_fail "restore failed; current database may be inconsistent; pre-restore backup is ${pre_restore_backup}"
fi
rm -f "$restore_tmp"

echo "restore: database restored from ${backup_path}"
echo "restore: pre-restore backup retained at ${pre_restore_backup}"
