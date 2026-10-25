#!/usr/bin/env bash
# Package installation and cold runtime replacement are confined to disposable CI.
set -euo pipefail
[[ "${GITHUB_ACTIONS:-}" = true && "${RUNNER_ENVIRONMENT:-}" = github-hosted \
   && "$(uname -s)" = Linux && "$(uname -m)" = x86_64 ]] \
  || { echo 'Sysbox comparison requires a disposable GitHub-hosted Linux amd64 runner' >&2; exit 2; }
unset DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
export DOCKER_HOST=unix:///var/run/docker.sock
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
: "${RUNNER_TEMP:?}"
: "${DEV_CVM_COMPOSE_SMOKE_IMAGE:?}"
: "${UMBRA_NESTED_TEST_IMAGE:?}"
receipt_dir="$RUNNER_TEMP/sysbox-compatibility"
candidate_dir="${UMBRA_SYSBOX_CANDIDATE_DIR:-}"

check_candidate() {
  [[ "$candidate_dir" = "$RUNNER_TEMP/sysbox-candidate" \
     || "$candidate_dir" = "$RUNNER_TEMP/sysbox-upstream-candidate" ]] \
    || { echo 'refuse candidate outside the disposable runner output' >&2; exit 2; }
  [[ ! -L "$candidate_dir" ]]
  for component in sysbox-runc sysbox-fs sysbox-mgr; do
    [[ -f "$candidate_dir/$component" && -x "$candidate_dir/$component" && ! -L "$candidate_dir/$component" ]] \
      || { echo 'candidate must contain three regular executable files' >&2; exit 2; }
  done
  (cd "$candidate_dir" && sha256sum --check --strict "$receipt_dir/candidate.sha256")
}

record_runtime() {
  local version="$1"
  for component in sysbox-runc sysbox-fs sysbox-mgr; do
    "$component" --version > "$receipt_dir/${component}-${version}.txt"
    sha256sum "$(command -v "$component")" >> "$receipt_dir/binaries-${version}.sha256"
  done
  docker version --format '{{json .Server}}' > "$receipt_dir/outer-${version}.json"
  systemctl show sysbox-mgr.service --property=ExecStart --value > "$receipt_dir/manager-${version}.txt"
  cmp "$receipt_dir/outer-before.json" "$receipt_dir/outer-${version}.json" \
    || { echo 'Sysbox installation changed the outer Docker components' >&2; exit 1; }
}

install_candidate() (
  local project="${1:-}"
  local containers
  local phase=fresh-candidate
  local status=0
  local ids=()
  check_candidate
  [[ "${UMBRA_SYSBOX_CANDIDATE_VERSION:-}" = 0.7.1 || "${UMBRA_SYSBOX_CANDIDATE_VERSION:-}" = 0.7.1+umbra.1 ]]
  containers="$(docker ps -aq --no-trunc)"
  if [[ -n "$containers" ]]; then
    mapfile -t ids <<< "$containers"
  fi
  if [[ -n "$project" ]]; then
    phase=handover-candidate
    # Only the four cold-stopped fixtures from the current smoke may survive.
    [[ "$project" =~ ^umbra-dev-compose-smoke-[a-z0-9]+$ && "${#ids[@]}" -eq 4 ]]
    docker inspect "${ids[@]}" | python3 -c '
import json, sys
rows = json.load(sys.stdin)
expected = {"user-sandbox", "dev-egress-forwarder", "dev-tunnel", "smoke-origin"}
if len(rows) != 4 or {r["Config"]["Labels"].get("com.docker.compose.service") for r in rows} != expected:
    raise SystemExit("handover requires exactly the owned Compose services")
if any(r["Config"]["Labels"].get("com.docker.compose.project") != sys.argv[1]
       or r["State"]["Status"] != "exited" or r["State"]["Pid"] != 0
       or r["HostConfig"]["RestartPolicy"]["Name"] not in ("", "no") for r in rows):
    raise SystemExit("refuse runtime replacement with running or foreign containers")
' "$project"
  else
    [[ "${#ids[@]}" -eq 0 ]] || { echo 'refuse runtime replacement with existing containers' >&2; exit 1; }
  fi
  # Restore daemon availability on failure so the caller can remove only its
  # fixtures. Never start/recreate containers or repair their data in this trap.
  trap 'status=$?; trap - EXIT; if [[ "$status" -ne 0 ]]; then sudo systemctl start sysbox.service containerd.service docker.service || true; fi; exit "$status"' EXIT
  # Keep the package, Docker metadata and Sysbox data root. Cold-stop the outer
  # daemons too: their memory must not conceal missing persistent runtime state.
  sudo systemctl stop docker.service docker.socket containerd.service
  sudo systemctl stop sysbox.service sysbox-fs.service sysbox-mgr.service
  for service in docker.service docker.socket containerd.service sysbox-fs.service sysbox-mgr.service; do
    systemctl show "$service" --property=ActiveState --property=SubState --property=Result \
      --property=ExecMainCode --property=ExecMainStatus --property=MainPID --property=ControlPID \
      > "$receipt_dir/${service}-stopped-${phase}.txt"
    python3 - "$receipt_dir/${service}-stopped-${phase}.txt" <<'PY'
from pathlib import Path
import sys
state = dict(line.split('=', 1) for line in Path(sys.argv[1]).read_text().splitlines())
if state.get('ActiveState') != 'inactive' or state.get('SubState') != 'dead' or state.get('Result') != 'success':
    raise SystemExit('daemon stop did not complete successfully')
if any(state.get(key, '0') != '0' for key in ('MainPID', 'ControlPID')):
    raise SystemExit('daemon stop retained a process')
PY
  done
  for component in sysbox-runc sysbox-fs sysbox-mgr; do
    if pgrep -x "$component" >/dev/null; then
      echo 'refuse replacement while a Sysbox process still exists' >&2; exit 1
    fi
  done
  for component in sysbox-runc sysbox-fs sysbox-mgr; do
    sudo install -m 0755 "$candidate_dir/$component" "$(command -v "$component")"
    cmp "$candidate_dir/$component" "$(command -v "$component")"
    "$component" --version | grep -F "$UMBRA_SYSBOX_CANDIDATE_VERSION" >/dev/null
  done
  sudo systemctl restart sysbox.service
  for service in sysbox-fs.service sysbox-mgr.service; do
    systemctl is-active --quiet "$service"
  done
  sudo systemctl start containerd.service docker.service
  for service in containerd.service docker.service; do
    systemctl is-active --quiet "$service"
  done
  # An outer-daemon restart must not replace or automatically run any fixture.
  docker ps -aq --no-trunc | sort > "$receipt_dir/containers-${phase}.txt"
  printf '%s\n' "${ids[@]}" | sed '/^$/d' | sort > "$receipt_dir/containers-before-${phase}.txt"
  cmp "$receipt_dir/containers-before-${phase}.txt" "$receipt_dir/containers-${phase}.txt"
  if [[ "${#ids[@]}" -gt 0 ]]; then
    docker inspect "${ids[@]}" | python3 -c '
import json, sys
if any(row["State"]["Status"] != "exited" or row["State"]["Pid"] != 0 for row in json.load(sys.stdin)):
    raise SystemExit("outer daemon restart automatically started a handover fixture")
'
  fi
)

case "${1:-compare}" in
  switch-runtime)
    [[ "$#" -eq 2 && -d "$receipt_dir/handover" ]]
    install_candidate "$2"
    record_runtime handover-candidate
    exit 0 ;;
  compare) [[ "$#" -eq 0 ]] ;;
  *) echo 'unsupported Sysbox qualification phase' >&2; exit 2 ;;
esac

mkdir "$receipt_dir"
containers="$(docker ps -aq)"
[[ -z "$containers" ]] || { echo 'refuse a runner with existing containers' >&2; exit 2; }
docker version --format '{{json .Server}}' > "$receipt_dir/outer-before.json"
uname -r > "$receipt_dir/kernel.txt"
printf '%s\n' "${ImageOS:-unknown}" "${ImageVersion:-unknown}" > "$receipt_dir/runner-image.txt"
docker info --format '{{json .}}' | jq '{Driver,CgroupDriver,CgroupVersion,SecurityOptions,KernelVersion,OperatingSystem,Architecture}' > "$receipt_dir/host.json"

# Fetch both pinned packages before installing either. No mutable installation URL
# or shell installer is trusted; release SHA-256 values are reviewed source pins.
for version in 0.6.7 0.7.1; do
  case "$version" in
    0.6.7) sha=b7ac389e5a19592cadf16e0ca30e40919516128f6e1b7f99e1cb4ff64554172e ;;
    0.7.1) sha=9d6d5484f980d0a17f86c492c1262015c2afb66280bdb97215b79fde6a0261c5 ;;
  esac
  package="$RUNNER_TEMP/sysbox-ce_${version}.linux_amd64.deb"
  curl --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 \
    --retry 3 --connect-timeout 10 --max-time 120 \
    "https://github.com/nestybox/sysbox/releases/download/v${version}/sysbox-ce_${version}.linux_amd64.deb" \
    --output "$package"
  printf '%s  %s\n' "$sha" "$package" | sha256sum --check --strict
  printf '%s\n' "$sha" > "$receipt_dir/package-${version}.sha256"
done

if [[ -n "$candidate_dir" ]]; then
  [[ "$candidate_dir" = "$RUNNER_TEMP/sysbox-candidate" ]]
  cp "$RUNNER_TEMP/sysbox-security/binaries.sha256" "$receipt_dir/candidate.sha256"
  export UMBRA_SYSBOX_CANDIDATE_VERSION=0.7.1+umbra.1
else
  candidate_dir="$RUNNER_TEMP/sysbox-upstream-candidate"
  mkdir "$candidate_dir"
  for component in sysbox-runc sysbox-fs sysbox-mgr; do
    dpkg-deb --fsys-tarfile "$RUNNER_TEMP/sysbox-ce_0.7.1.linux_amd64.deb" \
      | tar -xOf - "./usr/bin/$component" > "$candidate_dir/$component"
    chmod 0500 "$candidate_dir/$component"
    (cd "$candidate_dir" && sha256sum "$component") >> "$receipt_dir/candidate.sha256"
  done
  export UMBRA_SYSBOX_CANDIDATE_VERSION=0.7.1
fi
export UMBRA_SYSBOX_CANDIDATE_DIR="$candidate_dir"
check_candidate

sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends "$RUNNER_TEMP/sysbox-ce_0.6.7.linux_amd64.deb"
[[ "$(dpkg-query -W -f='${Version}' sysbox-ce)" = 0.6.7.linux ]] \
  || { echo 'unexpected installed Sysbox version' >&2; exit 1; }
# Match the 0.5.12 guest's manager setting before creating the test project.
sudo mkdir -p /etc/systemd/system/sysbox-mgr.service.d
printf '[Service]\nExecStart=\nExecStart=%s --data-root /var/lib/sysbox --disable-ovfs-on-idmapped-mount\n' \
  "$(command -v sysbox-mgr)" | sudo tee /etc/systemd/system/sysbox-mgr.service.d/umbra-ci.conf >/dev/null
sudo systemctl daemon-reload
sudo systemctl restart sysbox.service
for service in sysbox-fs.service sysbox-mgr.service; do
  systemctl is-active --quiet "$service"
done
record_runtime 0.6.7

export DEV_CVM_COMPOSE_SMOKE_RUNTIME=sysbox-runc
export UMBRA_NESTED_RECEIPT="$receipt_dir/nested-0.6.7.json"
export UMBRA_NESTED_EXPECT=unsafe-procfs
export UMBRA_SYSBOX_HANDOVER_DIR="$receipt_dir/handover"
if timeout --kill-after=30 1200 bash cvms/dev/tests/compose_smoke.sh; then
  printf 'passed\n' > "$receipt_dir/compose-handover.txt"
else
  printf 'failed\n' > "$receipt_dir/compose-handover.txt"
fi
if [[ -f "$receipt_dir/handover/baseline-passed" ]]; then
  printf 'passed\n' > "$receipt_dir/compose-0.6.7.txt"
else
  printf 'failed\n' > "$receipt_dir/compose-0.6.7.txt"
fi
unset UMBRA_SYSBOX_HANDOVER_DIR

# Always attempt the fresh candidate arm, even if the old arm or cold handover
# failed. Cleanup may remove only the just-finished disposable smoke project.
install_candidate
record_runtime 0.7.1
export UMBRA_NESTED_RECEIPT="$receipt_dir/nested-0.7.1.json"
export UMBRA_NESTED_EXPECT=success
if timeout --kill-after=30 600 bash cvms/dev/tests/compose_smoke.sh; then
  printf 'passed\n' > "$receipt_dir/compose-0.7.1.txt"
else
  printf 'failed\n' > "$receipt_dir/compose-0.7.1.txt"
fi

python3 - "$receipt_dir" <<'PY'
import json
import os
from pathlib import Path
import sys

root = Path(sys.argv[1])
outcomes = {version: (root / f'compose-{version}.txt').read_text().strip()
            for version in ('0.6.7', '0.7.1', 'handover')}
if any(value != 'passed' for value in outcomes.values()):
    result = {'status': 'failed',
              'baseline': 'reproduced' if outcomes['0.6.7'] == 'passed' else 'inconclusive',
              'candidate': 'passed' if outcomes['0.7.1'] == 'passed' else 'failed',
              'cold_handover': 'passed' if outcomes['handover'] == 'passed' else 'failed'}
    (root / 'comparison.json').write_text(json.dumps(result, indent=2) + '\n')
    raise SystemExit(f"Sysbox comparison failed: {result}")
baseline = json.loads((root / 'nested-0.6.7.json').read_text())
candidate = json.loads((root / 'nested-0.7.1.json').read_text())
handover = json.loads((root / 'handover/handover.json').read_text())
resumed = json.loads((root / 'handover/nested-candidate.json').read_text())
for field in ('dev_image_id', 'nested_image', 'nested_image_id', 'inner_versions'):
    if baseline[field] != candidate[field] or baseline[field] != resumed[field]:
        raise SystemExit(f'A/B input changed: {field}')
if baseline['expectation'] != 'unsafe-procfs' or candidate['expectation'] != 'success' or resumed['expectation'] != 'success':
    raise SystemExit('invalid A/B expectations')
if handover['status'] != 'passed' or not resumed['nested_bridge_direct_egress_denied']:
    raise SystemExit('cold handover did not preserve state and egress enforcement')
(root / 'comparison.json').write_text(json.dumps({
    'status': 'passed', 'baseline_sysbox': '0.6.7', 'candidate_sysbox': os.environ['UMBRA_SYSBOX_CANDIDATE_VERSION'],
    'dev_image_id': candidate['dev_image_id'], 'nested_image_id': candidate['nested_image_id'],
    'inner_versions': candidate['inner_versions'],
    'cold_handover': handover,
    'not_exercised': candidate['not_exercised'],
}, indent=2) + '\n')
print('Sysbox comparison: old procfs failure reproduced; populated cold handover and fresh candidate passed')
PY
