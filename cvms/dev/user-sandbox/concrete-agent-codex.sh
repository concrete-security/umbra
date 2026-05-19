#!/bin/bash
. /usr/local/lib/concrete/concrete-update-agents.sh
if [ -x /home/dev/.local/bin/codex ]; then
  exec /home/dev/.local/bin/codex "$@"
fi
exec node /usr/local/lib/node_modules/@openai/codex/bin/codex.js "$@"
