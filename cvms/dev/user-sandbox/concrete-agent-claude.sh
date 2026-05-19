#!/bin/bash
. /usr/local/lib/concrete/concrete-update-agents.sh
if [ -x /home/dev/.local/bin/claude ]; then
  exec /home/dev/.local/bin/claude "$@"
fi
exec /usr/local/lib/concrete/claude.real "$@"
