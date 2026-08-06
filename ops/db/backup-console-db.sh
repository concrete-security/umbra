#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
# shellcheck source=ops/db/console-db-guard.sh
source "${ROOT}/ops/db/console-db-guard.sh"

reason="${1:-manual}"
console_db_guard_backup "$reason"
