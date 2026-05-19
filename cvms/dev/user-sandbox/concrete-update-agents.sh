#!/bin/bash
_marker="/tmp/.concrete-agents-updated"
_cooldown=14400
if [[ -f "$_marker" ]] && [[ "$(uname -s)" == "Linux" ]]; then
  now=$(date +%s)
  mtime=$(stat -c '%Y' "$_marker" 2>/dev/null || echo 0)
  if [[ "$mtime" =~ ^[0-9]+$ ]] && (( now - mtime < _cooldown )); then
    return 0 2>/dev/null || exit 0
  fi
fi
touch "$_marker" 2>/dev/null || true
(
  nohup bash -c '
    set +e
    export NPM_CONFIG_IGNORE_SCRIPTS=true
    export NPM_CONFIG_AUDIT=false
    if command -v npm >/dev/null 2>&1; then
      npm install -g @openai/codex --prefix /home/dev/.local >/dev/null 2>&1 &
    fi
    if [ -x /usr/local/lib/concrete/claude.real ]; then
      /usr/local/lib/concrete/claude.real update >/dev/null 2>&1 &
    fi
    if command -v gh >/dev/null 2>&1; then
      gh upgrade >/dev/null 2>&1 &
    fi
    wait 2>/dev/null || true
  ' >/dev/null 2>&1 &
)
return 0 2>/dev/null || true
