#!/bin/bash
. /usr/local/lib/concrete/concrete-update-agents.sh
if [ -x /home/dev/.local/bin/codex ]; then
  exec /home/dev/.local/bin/codex --dangerously-bypass-approvals-and-sandbox "$@"
fi
exec node /usr/local/lib/concrete/codex/node_modules/@openai/codex/bin/codex.js \
  --dangerously-bypass-approvals-and-sandbox "$@"
