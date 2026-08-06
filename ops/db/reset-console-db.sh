#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=ops/db/console-db-guard.sh
source "${ROOT}/ops/db/console-db-guard.sh"

backup_file="$(console_db_guard_before_destructive reset)"
console_db_guard_info "proceeding with reset after backup ${backup_file}"

docker compose exec -T console-db sh -c \
  'exec psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1' <<'SQL'
DO $$
DECLARE
  table_list text;
BEGIN
  SELECT string_agg(format('%I.%I', schemaname, tablename), ', ' ORDER BY tablename)
  INTO table_list
  FROM pg_tables
  WHERE schemaname = 'public'
    AND tablename NOT IN ('alembic_version', 'schema_migrations');

  IF table_list IS NOT NULL THEN
    EXECUTE 'TRUNCATE TABLE ' || table_list || ' RESTART IDENTITY CASCADE';
  END IF;
END $$;
SQL

echo "reset: console database truncated; migration table preserved"
echo "reset: pre-reset backup retained at ${backup_file}"
