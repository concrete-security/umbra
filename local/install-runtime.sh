#!/usr/bin/env bash
set -euo pipefail
# Source-preview setup only. No public companion executable is installed.
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
config=${UMBRA_CONFIG_DIR:-"$HOME/.umbra"}
if [[ ${1:-} == --config && $# == 2 ]]; then
  config=$2
elif [[ $# != 0 ]]; then
  printf 'Usage: local/install-runtime.sh [--config DIRECTORY]\n' >&2
  exit 2
fi
umask 077
python3 - "$config" "$root/local" <<'PY'
import os
from pathlib import Path
import stat
import subprocess
import sys
import venv

if sys.version_info < (3, 12):
    raise SystemExit('Python 3.12 or later is required for the local runtime.')
config = Path(sys.argv[1]).expanduser().absolute()
if config.is_symlink():
    raise SystemExit('Umbra configuration directory must not be a symlink.')
config.mkdir(mode=0o700, parents=True, exist_ok=True)
info = config.stat()
if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
    raise SystemExit('Umbra configuration directory must be owned by you and mode 0700.')
tools = config / 'local-tools'
if tools.is_symlink():
    raise SystemExit('Private runtime directory must not be a symlink.')
venv.EnvBuilder(with_pip=True).create(tools)
subprocess.run([str(tools / 'bin/python3'), '-I', '-m', 'pip', 'install', '--disable-pip-version-check', sys.argv[2]], check=True)
print('Installed the private local runtime. Use umbra start local from a project folder.')
PY
