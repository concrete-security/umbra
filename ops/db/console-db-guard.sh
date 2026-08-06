#!/usr/bin/env bash

umask 077

CONSOLE_DB_GUARD_CONFIRM_PHRASE="erase-console-database"

console_db_guard_fail() {
  echo "console-db-guard: $1" >&2
  exit "${2:-1}"
}

console_db_guard_info() {
  echo "console-db-guard: $1" >&2
}

console_db_guard_require_running() {
  if ! docker compose ps --services --filter status=running | grep -qx 'console-db'; then
    console_db_guard_fail "console-db is not running; run make up first"
  fi
}

console_db_guard_backup_dir() {
  local dir="${UMBRA_DB_BACKUP_DIR:-${HOME}/.umbra/console-db-backups}"
  mkdir -p "$dir"
  if [ ! -d "$dir" ] || [ ! -w "$dir" ]; then
    console_db_guard_fail "backup directory is missing or not writable: ${dir}"
  fi
  printf '%s\n' "$dir"
}

console_db_guard_print_summary() {
  docker compose exec -T console-db sh -c \
    'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -At' <<'SQL'
SELECT format(
  '%s=%s',
  relname,
  COALESCE(n_live_tup::text, '?')
)
FROM pg_stat_user_tables
WHERE schemaname = 'public'
  AND relname NOT IN ('alembic_version', 'schema_migrations')
ORDER BY relname;
SQL
}

console_db_guard_backup() {
  local reason="${1:-manual}"
  local backup_dir timestamp backup_file meta_file alembic_version dump_tmp

  console_db_guard_require_running
  backup_dir="$(console_db_guard_backup_dir)"
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  backup_file="${backup_dir}/console-${timestamp}.sql.gz"
  meta_file="${backup_dir}/console-${timestamp}.meta"
  dump_tmp="$(mktemp)"

  console_db_guard_info "writing backup (${reason}) to ${backup_file}"

  if ! docker compose exec -T console-db sh -c \
    'exec pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-acl --clean --if-exists' \
    >"$dump_tmp"; then
    rm -f "$dump_tmp"
    console_db_guard_fail "pg_dump failed; backup was not written"
  fi
  if ! gzip -c "$dump_tmp" >"$backup_file"; then
    rm -f "$dump_tmp" "$backup_file"
    console_db_guard_fail "gzip failed; backup was not written"
  fi
  rm -f "$dump_tmp"
  if [ ! -s "$backup_file" ]; then
    rm -f "$backup_file"
    console_db_guard_fail "backup file is empty"
  fi

  alembic_version="$(
    docker compose exec -T console-db sh -c \
      'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -At' \
      2>/dev/null <<'SQL' || true
SELECT COALESCE(version_num, '') FROM alembic_version LIMIT 1;
SQL
  )"

  {
    echo "created_at_utc=${timestamp}"
    echo "reason=${reason}"
    echo "backup_file=${backup_file}"
    echo "alembic_version=${alembic_version}"
    echo "git_head=$(git rev-parse HEAD 2>/dev/null || echo unknown)"
    echo "table_row_estimates:"
    console_db_guard_print_summary || true
  } >"$meta_file"

  console_db_guard_info "backup complete: ${backup_file}"
  printf '%s\n' "$backup_file"
}

console_db_guard_require_allow_flag() {
  if [ "${UMBRA_ALLOW_DB_DESTRUCTIVE:-}" != "1" ]; then
    console_db_guard_fail \
      "refusing destructive database action; set UMBRA_ALLOW_DB_DESTRUCTIVE=1 to acknowledge data loss risk"
  fi
}

console_db_guard_require_confirmation() {
  local action="$1"

  if [ -t 0 ]; then
    console_db_guard_info "about to ${action}; this permanently deletes Console application data"
    console_db_guard_info "current table row estimates:"
    console_db_guard_print_summary >&2 || true
    printf 'console-db-guard: type %q to continue: ' "$CONSOLE_DB_GUARD_CONFIRM_PHRASE" >&2
    local reply=""
    IFS= read -r reply || true
    if [ "$reply" != "$CONSOLE_DB_GUARD_CONFIRM_PHRASE" ]; then
      console_db_guard_fail "confirmation phrase did not match; aborted ${action}"
    fi
    return 0
  fi

  if [ "${UMBRA_DB_DESTRUCTIVE_CONFIRM:-}" != "$CONSOLE_DB_GUARD_CONFIRM_PHRASE" ]; then
    console_db_guard_fail \
      "non-interactive ${action} requires UMBRA_DB_DESTRUCTIVE_CONFIRM=${CONSOLE_DB_GUARD_CONFIRM_PHRASE}"
  fi
}

console_db_guard_before_destructive() {
  local action="$1"
  console_db_guard_require_running
  console_db_guard_require_allow_flag
  console_db_guard_require_confirmation "$action"
  console_db_guard_backup "$action"
}
