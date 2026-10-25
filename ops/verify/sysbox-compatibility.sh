#!/usr/bin/env bash
# Destructive package installation is confined to an empty disposable CI runner.
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
mkdir "$receipt_dir"
[[ -z "$(docker ps -aq)" ]] || { echo 'refuse a runner with existing containers' >&2; exit 2; }
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

sudo apt-get update -qq
for version in 0.6.7 0.7.1; do
  [[ -z "$(docker ps -aq)" ]] || { echo 'test cleanup left containers; refusing runtime switch' >&2; exit 1; }
  if [[ "$version" = 0.7.1 ]]; then
    # Upstream requires uninstall/reinstall; all baseline containers are gone.
    sudo apt-get remove -y sysbox-ce
  fi
  sudo apt-get install -y --no-install-recommends "$RUNNER_TEMP/sysbox-ce_${version}.linux_amd64.deb"
  installed="$(dpkg-query -W -f='${Version}' sysbox-ce)"
  [[ "$installed" = "$version.linux" ]] \
    || { echo 'unexpected installed Sysbox version' >&2; exit 1; }
  # Match the 0.5.12 guest's manager setting in both arms. This is safe only
  # before creating the isolated test project; never restart a live CVM here.
  sudo mkdir -p /etc/systemd/system/sysbox-mgr.service.d
  printf '[Service]\nExecStart=\nExecStart=%s --data-root /var/lib/sysbox --disable-ovfs-on-idmapped-mount\n' \
    "$(command -v sysbox-mgr)" | sudo tee /etc/systemd/system/sysbox-mgr.service.d/umbra-ci.conf >/dev/null
  sudo systemctl daemon-reload
  sudo systemctl restart sysbox.service
  systemctl is-active --quiet sysbox-fs.service sysbox-mgr.service
  for component in sysbox-runc sysbox-fs sysbox-mgr; do
    "$component" --version > "$receipt_dir/${component}-${version}.txt"
    sha256sum "$(command -v "$component")" >> "$receipt_dir/binaries-${version}.sha256"
  done
  docker version --format '{{json .Server}}' > "$receipt_dir/outer-${version}.json"
  cmp "$receipt_dir/outer-before.json" "$receipt_dir/outer-${version}.json" \
    || { echo 'Sysbox installation changed the outer Docker components' >&2; exit 1; }
  export DEV_CVM_COMPOSE_SMOKE_RUNTIME=sysbox-runc
  export UMBRA_NESTED_RECEIPT="$receipt_dir/nested-${version}.json"
  if [[ "$version" = 0.6.7 ]]; then
    export UMBRA_NESTED_EXPECT=unsafe-procfs
  else
    export UMBRA_NESTED_EXPECT=success
  fi
  # Attempt the candidate even if the old runtime cannot reproduce on this host.
  # The final comparison still fails unless BOTH arms have the expected outcome.
  if timeout --kill-after=30 600 bash cvms/dev/tests/compose_smoke.sh; then
    printf 'passed\n' > "$receipt_dir/compose-${version}.txt"
  else
    printf 'failed\n' > "$receipt_dir/compose-${version}.txt"
  fi
done

python3 - "$receipt_dir" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
outcomes = {version: (root / f'compose-{version}.txt').read_text().strip()
            for version in ('0.6.7', '0.7.1')}
if any(value != 'passed' for value in outcomes.values()):
    result = {'status': 'failed',
              'baseline': 'reproduced' if outcomes['0.6.7'] == 'passed' else 'inconclusive',
              'candidate': 'passed' if outcomes['0.7.1'] == 'passed' else 'failed'}
    (root / 'comparison.json').write_text(json.dumps(result, indent=2) + '\n')
    raise SystemExit(f"Sysbox comparison failed: baseline={result['baseline']}, candidate={result['candidate']}")
baseline = json.loads((root / 'nested-0.6.7.json').read_text())
candidate = json.loads((root / 'nested-0.7.1.json').read_text())
for field in ('dev_image_id', 'nested_image', 'nested_image_id', 'inner_versions'):
    if baseline[field] != candidate[field]:
        raise SystemExit(f'A/B input changed: {field}')
if baseline['expectation'] != 'unsafe-procfs' or candidate['expectation'] != 'success':
    raise SystemExit('invalid A/B expectations')
(root / 'comparison.json').write_text(json.dumps({
    'status': 'passed', 'baseline_sysbox': '0.6.7', 'candidate_sysbox': '0.7.1',
    'dev_image_id': candidate['dev_image_id'], 'nested_image_id': candidate['nested_image_id'],
    'inner_versions': candidate['inner_versions'],
    'not_exercised': candidate['not_exercised'],
}, indent=2) + '\n')
print('Sysbox comparison: exact procfs failure reproduced with 0.6.7; 0.7.1 passed')
PY
