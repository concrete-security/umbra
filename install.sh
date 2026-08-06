#!/usr/bin/env sh
set -eu

script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
if [ -z "${UMBRA_INSTALL_BASE_URL:-}" ]; then
  echo "umbra-install: set UMBRA_INSTALL_BASE_URL to an approved HTTPS install origin" >&2
  exit 2
fi
export UMBRA_INSTALL_BASE_URL
export UMBRA_INSTALL_SOURCE_REPO="${UMBRA_INSTALL_SOURCE_REPO:-github.com/concrete-security/umbra}"
exec sh "${script_dir}/ops/installer/install.sh" "$@"
