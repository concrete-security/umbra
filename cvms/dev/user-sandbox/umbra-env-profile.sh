[ -r /run/umbra/env.sh ] && . /run/umbra/env.sh
[ "$(id -u)" = "1001" ] && [ -r /usr/local/lib/umbra/umbra-update-agents.sh ] && . /usr/local/lib/umbra/umbra-update-agents.sh
