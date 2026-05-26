[ -r /run/concrete-env.sh ] && . /run/concrete-env.sh
if [ -t 1 ]; then
  printf '\033[?25h\033[1 q'
fi
[ "$(id -u)" = "1001" ] && [ -r /usr/local/lib/concrete/concrete-update-agents.sh ] && . /usr/local/lib/concrete/concrete-update-agents.sh
