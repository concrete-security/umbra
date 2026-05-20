[ -r /run/concrete-env.sh ] && . /run/concrete-env.sh
[ "$(id -u)" = "1001" ] && [ -r /usr/local/lib/concrete/concrete-update-agents.sh ] && . /usr/local/lib/concrete/concrete-update-agents.sh
