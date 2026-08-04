#!/bin/bash
. /usr/local/lib/umbra/umbra-update-agents.sh

mkdir -p /home/dev/.claude || exit 1
if [ -e /home/dev/.claude.json ] && [ ! -L /home/dev/.claude.json ]; then
  if [ ! -s /home/dev/.claude.json ]; then
    printf '{}\n' >/home/dev/.claude.json || exit 1
    chmod 0600 /home/dev/.claude.json || exit 1
  fi
else
  if [ ! -s /home/dev/.claude/.claude.json ]; then
    printf '{}\n' >/home/dev/.claude/.claude.json || exit 1
    chmod 0600 /home/dev/.claude/.claude.json || exit 1
  fi
  ln -sfn /home/dev/.claude/.claude.json /home/dev/.claude.json || exit 1
fi

if [ -x /home/dev/.local/bin/claude ]; then
  exec /home/dev/.local/bin/claude "$@"
fi
exec /usr/local/lib/umbra/claude.real "$@"
