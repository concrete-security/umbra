#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd "$(dirname "$0")/../.." && pwd)"
cd "$repo_root"

sh -n ops/installer/install.sh
sh -n ops/installer/entrypoint.sh

# Keep the documented trust bootstrap and the release workflow coupled to the
# executable contract. These are deliberately static checks: a future edit
# must not quietly reintroduce an unverified curl-to-shell path or mutable
# release selection that the functional fixture would not exercise.
installer_docs=(README.md docs/quick-start.md)
if [ -f ops/public-release/overlays/README.md ]; then
  installer_docs+=(ops/public-release/overlays/README.md)
fi
if grep -E 'curl[^|]*/install\.sh[^|]*\|[[:space:]]*(sh|bash)' \
  "${installer_docs[@]}" >/dev/null; then
  echo "installer smoke: documentation contains an unverified curl-to-shell path" >&2
  exit 1
fi
if grep -F 'gh release' docs/quick-start.md >/dev/null; then
  echo "installer smoke: clean bootstrap unexpectedly requires authenticated gh" >&2
  exit 1
fi
grep -F 'https://api.github.com/repos/concrete-security/umbra/releases?per_page=100' docs/quick-start.md >/dev/null
grep -F 'def semver_key(version):' docs/quick-start.md >/dev/null
grep -F 'max(candidates, key=lambda candidate: (candidate[0], candidate[1]))' docs/quick-start.md >/dev/null
grep -F 'GOPRIVATE= GONOSUMDB= GONOPROXY=' docs/quick-start.md >/dev/null
grep -F 'GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org' docs/quick-start.md >/dev/null
grep -F 'UMBRA_INSTALL_VERSION="$release_version"' docs/quick-start.md >/dev/null
grep -F 'export UMBRA_SLSA_VERIFIER="$slsa_verifier"' docs/quick-start.md >/dev/null
grep -F "sh -eu <<'UMBRA_BOOTSTRAP'" docs/quick-start.md >/dev/null
grep -F 'verify-artifact "$installer_dir/SHA256SUMS"' docs/quick-start.md >/dev/null
grep -F 'entries.get("umbra-install.sh") != installer_digest' docs/quick-start.md >/dev/null
grep -F 'sha256sum umbra-install.sh >> SHA256SUMS' .github/workflows/publish-cli.yml >/dev/null
grep -F 'uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0' .github/workflows/publish-cli.yml >/dev/null

installer_compose="$(sed -n '/^  installer:/,/^  reverse-proxy:/p' docker-compose.yml)"
if ! grep -F 'INSTALL_HOST: ${INSTALL_HOST:-}' <<<"$installer_compose" >/dev/null; then
  echo "installer smoke: Compose does not pass INSTALL_HOST to the installer" >&2
  exit 1
fi

# Remote transport remains HTTPS-only even though the binary is also checked
# against independently signed SLSA provenance. Rejection happens before any
# download, so these cases touch no network.
assert_base_url_rejected() {
  base_url="$1"
  expected="$2"
  output="$(UMBRA_INSTALL_BASE_URL="$base_url" sh ops/installer/install.sh 2>&1 || true)"
  case "$output" in
    *"$expected"*) ;;
    *)
      echo "installer smoke: install.sh did not refuse ${base_url} with '${expected}'; got: ${output}" >&2
      exit 1
      ;;
  esac
}
assert_base_url_rejected "http://install.example.com" "refusing plaintext http"
assert_base_url_rejected "http://127.0.0.1.evil.example.com" "refusing plaintext http"
assert_base_url_rejected "ftp://install.example.com" "invalid installer base URL"

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/umbra-installer-smoke.XXXXXX")"
trap 'rm -rf "$tmpdir"' EXIT

# The deployment environment contains Console/provider credentials needed by
# DNS setup. Release sync must receive only its explicit non-secret allowlist;
# workflow recovery additionally receives the caller's one-shot GH_TOKEN.
prepare_fixture="$tmpdir/prepare-env"
prepare_github_env_log="$prepare_fixture/github.env"
prepare_workflow_env_log="$prepare_fixture/workflow.env"
prepare_dns_marker="$prepare_fixture/dns-ran"
prepare_package_marker="$prepare_fixture/package-ran"
mkdir -p "$prepare_fixture/ops/cli-release" "$prepare_fixture/ops/host"
cp ops/cli-release/prepare-cli-installer.sh \
  "$prepare_fixture/ops/cli-release/prepare-cli-installer.sh"
cat > "$prepare_fixture/ops/host/provision-install-host-dns.py" <<'EOF'
#!/usr/bin/env python3
"""Record an invocation only when the local-source rejection test requests it."""
import os
from pathlib import Path

if marker := os.environ.get("PREPARE_DNS_MARKER"):
    Path(marker).touch()
EOF
cat > "$prepare_fixture/ops/cli-release/package-cli-release.sh" <<'EOF'
#!/bin/sh
set -eu
touch "$PREPARE_PACKAGE_MARKER"
EOF
cat > "$prepare_fixture/ops/cli-release/sync-cli-release-artifacts.sh" <<EOF
#!/bin/sh
set -eu
/usr/bin/env | /usr/bin/sort > "$prepare_github_env_log"
EOF
cat > "$prepare_fixture/ops/cli-release/sync-cli-workflow-artifacts.sh" <<EOF
#!/bin/sh
set -eu
: "\${GH_TOKEN:?workflow fixture requires GH_TOKEN}"
/usr/bin/env | /usr/bin/sort > "$prepare_workflow_env_log"
EOF
chmod 0755 \
  "$prepare_fixture/ops/cli-release/prepare-cli-installer.sh" \
  "$prepare_fixture/ops/cli-release/package-cli-release.sh" \
  "$prepare_fixture/ops/cli-release/sync-cli-release-artifacts.sh" \
  "$prepare_fixture/ops/cli-release/sync-cli-workflow-artifacts.sh"
cat > "$prepare_fixture/.env" <<'EOF'
INSTALL_HOST=install.fixture.example
DATABASE_URL=postgresql://deployment-secret
SECRET_INJECTION_KEK_B64=deployment-kek-secret
CLOUDFLARE_API_TOKEN=deployment-cloudflare-secret
DSTACK_DOCKER_PASSWORD=deployment-registry-secret
GOOGLE_OIDC_CLIENT_SECRET=deployment-oidc-secret
GH_TOKEN=legacy-env-token
EOF

assert_release_child_has_no_deployment_secrets() {
  child_env_log="$1"
  for secret_name in \
    AWS_SECRET_ACCESS_KEY \
    CLOUDFLARE_API_TOKEN \
    DATABASE_URL \
    DSTACK_DOCKER_PASSWORD \
    GOOGLE_OIDC_CLIENT_SECRET \
    SECRET_INJECTION_KEK_B64; do
    if grep -Eq "^${secret_name}=" "$child_env_log"; then
      echo "installer smoke: release child inherited ${secret_name}" >&2
      exit 1
    fi
  done
}

(
  cd "$prepare_fixture"
  PATH="$PATH" \
  GH_TOKEN=caller-token-that-github-must-not-inherit \
  AWS_SECRET_ACCESS_KEY=caller-aws-secret \
  UMBRA_CLI_RELEASE_SOURCE=github \
  UMBRA_CLI_RELEASE_DIR=/srv/releases \
  UMBRA_CLI_RELEASE_GITHUB_REPO=example/umbra \
  UMBRA_CLI_RELEASE_TAG=umbra-cli/1.2.3 \
  UMBRA_CLI_RELEASE_API_URL=http://127.0.0.1/releases \
  UMBRA_INSTALL_SLSA_VERIFIER=/usr/local/bin/slsa-verifier \
    bash ops/cli-release/prepare-cli-installer.sh >/dev/null
)
assert_release_child_has_no_deployment_secrets "$prepare_github_env_log"
if grep -q '^GH_TOKEN=' "$prepare_github_env_log"; then
  echo "installer smoke: anonymous GitHub release child inherited GH_TOKEN" >&2
  exit 1
fi
grep -Fx 'UMBRA_CLI_RELEASE_DIR=/srv/releases' "$prepare_github_env_log" >/dev/null
grep -Fx 'UMBRA_CLI_RELEASE_GITHUB_REPO=example/umbra' "$prepare_github_env_log" >/dev/null
grep -Fx 'UMBRA_CLI_RELEASE_TAG=umbra-cli/1.2.3' "$prepare_github_env_log" >/dev/null
grep -Fx 'UMBRA_CLI_RELEASE_API_URL=http://127.0.0.1/releases' "$prepare_github_env_log" >/dev/null
grep -Fx 'UMBRA_INSTALL_SLSA_VERIFIER=/usr/local/bin/slsa-verifier' "$prepare_github_env_log" >/dev/null

(
  cd "$prepare_fixture"
  PATH="$PATH" \
  GH_TOKEN=workflow-one-shot-token \
  AWS_SECRET_ACCESS_KEY=caller-aws-secret \
  UMBRA_CLI_RELEASE_SOURCE=workflow \
  UMBRA_CLI_RELEASE_DIR=/srv/releases \
  UMBRA_CLI_RELEASE_GITHUB_REPO=example/umbra \
  UMBRA_CLI_RELEASE_VERSION=1.2.3 \
  UMBRA_CLI_WORKFLOW_BRANCH=main \
  UMBRA_CLI_WORKFLOW_RUN_ID=4242 \
  UMBRA_INSTALL_SLSA_VERIFIER=/usr/local/bin/slsa-verifier \
    bash ops/cli-release/prepare-cli-installer.sh >/dev/null
)
assert_release_child_has_no_deployment_secrets "$prepare_workflow_env_log"
grep -Fx 'GH_TOKEN=workflow-one-shot-token' "$prepare_workflow_env_log" >/dev/null
grep -Fx 'GH_PROMPT_DISABLED=1' "$prepare_workflow_env_log" >/dev/null
grep -Fx 'UMBRA_CLI_WORKFLOW_BRANCH=main' "$prepare_workflow_env_log" >/dev/null
grep -Fx 'UMBRA_CLI_WORKFLOW_RUN_ID=4242' "$prepare_workflow_env_log" >/dev/null

rm -f "$prepare_workflow_env_log"
missing_workflow_token_output="$(
  cd "$prepare_fixture"
  PATH="$PATH" \
  UMBRA_CLI_RELEASE_SOURCE=workflow \
    env -u GH_TOKEN bash ops/cli-release/prepare-cli-installer.sh 2>&1 || true
)"
case "$missing_workflow_token_output" in
  *'workflow source requires an explicitly supplied one-shot GH_TOKEN'*) ;;
  *) echo "installer smoke: workflow source reused GH_TOKEN from .env" >&2; exit 1 ;;
esac
test ! -e "$prepare_workflow_env_log"

local_source_status=0
local_source_output="$(
  cd "$prepare_fixture"
  PATH="$PATH" \
  PREPARE_DNS_MARKER="$prepare_dns_marker" \
  PREPARE_PACKAGE_MARKER="$prepare_package_marker" \
  UMBRA_CLI_RELEASE_SOURCE=local \
    bash ops/cli-release/prepare-cli-installer.sh 2>&1
)" || local_source_status=$?
if [ "$local_source_status" -eq 0 ]; then
  echo "installer smoke: secret-bearing prepare accepted the local source" >&2
  exit 1
fi
case "$local_source_output" in
  *'UMBRA_CLI_RELEASE_SOURCE=local is forbidden'*'run make package-cli from a separate checkout'*) ;;
  *) echo "installer smoke: local-source rejection omitted secretless packaging guidance: $local_source_output" >&2; exit 1 ;;
esac
test ! -e "$prepare_dns_marker"
test ! -e "$prepare_package_marker"

# Execute the exact selector embedded in the public quick start. It must
# understand the project's prerelease line and compare numeric prerelease
# identifiers numerically (beta.10 > beta.3), independent of API ordering.
selector="$tmpdir/select-release.py"
awk '
  /^python3 - .*<<.PY.$/ { copying = 1; next }
  copying && /^PY$/ { exit }
  copying { print }
' docs/quick-start.md > "$selector"
selector_fixture="$tmpdir/releases.json"
cat > "$selector_fixture" <<'EOF'
[
  {"tag_name":"umbra-cli/0.3.0-beta.3","draft":false,"prerelease":true,"assets":[{"name":"umbra-install.sh","browser_download_url":"https://example/beta3/install"},{"name":"SHA256SUMS","browser_download_url":"https://example/beta3/checksums"},{"name":"umbra-cli.intoto.jsonl","browser_download_url":"https://example/beta3/provenance"}]},
  {"tag_name":"umbra-cli/0.2.9","draft":false,"prerelease":false,"assets":[{"name":"umbra-install.sh","browser_download_url":"https://example/stable/install"},{"name":"SHA256SUMS","browser_download_url":"https://example/stable/checksums"},{"name":"umbra-cli.intoto.jsonl","browser_download_url":"https://example/stable/provenance"}]},
  {"tag_name":"umbra-cli/0.3.0-beta.10","draft":false,"prerelease":true,"assets":[{"name":"umbra-install.sh","browser_download_url":"https://example/beta10/install"},{"name":"SHA256SUMS","browser_download_url":"https://example/beta10/checksums"},{"name":"umbra-cli.intoto.jsonl","browser_download_url":"https://example/beta10/provenance"}]},
  {"tag_name":"umbra-cli/9.0.0","draft":true,"prerelease":false,"assets":[{"name":"umbra-install.sh","browser_download_url":"https://example/draft/install"},{"name":"SHA256SUMS","browser_download_url":"https://example/draft/checksums"},{"name":"umbra-cli.intoto.jsonl","browser_download_url":"https://example/draft/provenance"}]},
  {"tag_name":"umbra-cli/0.3.0-01","draft":false,"prerelease":true,"assets":[{"name":"umbra-install.sh","browser_download_url":"https://example/invalid/install"},{"name":"SHA256SUMS","browser_download_url":"https://example/invalid/checksums"},{"name":"umbra-cli.intoto.jsonl","browser_download_url":"https://example/invalid/provenance"}]}
]
EOF
python3 "$selector" "$selector_fixture" > "$tmpdir/selected-release"
test "$(sed -n '1p' "$tmpdir/selected-release")" = "0.3.0-beta.10"
test "$(sed -n '2p' "$tmpdir/selected-release")" = "https://example/beta10/install"

mkdir -p "$tmpdir/shadow"
cat > "$tmpdir/shadow/slsa-verifier" <<'EOF'
#!/bin/sh
touch "$SHADOW_VERIFIER_MARKER"
exit 0
EOF
chmod 0755 "$tmpdir/shadow/slsa-verifier"
shadow_marker="$tmpdir/shadow-verifier-ran"
shadow_output="$(
  cd "$tmpdir"
  PATH="shadow:/usr/bin:/bin" \
  SHADOW_VERIFIER_MARKER="$shadow_marker" \
  UMBRA_INSTALL_BASE_URL="http://127.0.0.1" \
  UMBRA_INSTALL_SOURCE_REPO="github.com/example/umbra" \
    env -u UMBRA_INSTALL_SLSA_VERIFIER \
      sh "$repo_root/ops/installer/install.sh" 2>&1 || true
)"
case "$shadow_output" in
  *'slsa-verifier is required'*) ;;
  *) echo "installer smoke: relative PATH verifier shadow was not rejected" >&2; exit 1 ;;
esac
test ! -e "$shadow_marker"

relative_override_output="$(
  cd "$tmpdir"
  PATH="/usr/bin:/bin" \
  SHADOW_VERIFIER_MARKER="$shadow_marker" \
  UMBRA_INSTALL_BASE_URL="http://127.0.0.1" \
  UMBRA_INSTALL_SOURCE_REPO="github.com/example/umbra" \
  UMBRA_INSTALL_SLSA_VERIFIER="shadow/slsa-verifier" \
    sh "$repo_root/ops/installer/install.sh" 2>&1 || true
)"
case "$relative_override_output" in
  *'UMBRA_INSTALL_SLSA_VERIFIER must be an absolute executable path'*) ;;
  *) echo "installer smoke: relative verifier override was not rejected" >&2; exit 1 ;;
esac
test ! -e "$shadow_marker"

for invalid_version in \
  v1.2.3 \
  1.2 \
  01.2.3 \
  1.2.3+build.1 \
  1.2.3-01 \
  '1.2.3 '
do
  invalid_version_output="$(
    PATH="/usr/bin:/bin" \
    UMBRA_INSTALL_BASE_URL="http://127.0.0.1" \
    UMBRA_INSTALL_SOURCE_REPO="github.com/example/umbra" \
    UMBRA_INSTALL_SLSA_VERIFIER="$tmpdir/shadow/slsa-verifier" \
    UMBRA_INSTALL_VERSION="$invalid_version" \
      sh "$repo_root/ops/installer/install.sh" 2>&1 || true
  )"
  case "$invalid_version_output" in
    *"invalid umbra release version: ${invalid_version}"*) ;;
    *)
      echo "installer smoke: non-canonical version was not rejected: ${invalid_version}" >&2
      exit 1
      ;;
  esac
done

mkdir -p "$tmpdir/intel-macos"
cat > "$tmpdir/intel-macos/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -s) printf 'Darwin\n' ;;
  -m) printf 'x86_64\n' ;;
  *) exit 1 ;;
esac
EOF
chmod 0755 "$tmpdir/intel-macos/uname"
intel_macos_output="$(
  PATH="$tmpdir/intel-macos:/usr/bin:/bin" \
  UMBRA_INSTALL_BASE_URL="http://127.0.0.1" \
  UMBRA_INSTALL_SOURCE_REPO="github.com/example/umbra" \
  UMBRA_INSTALL_SLSA_VERIFIER="$tmpdir/shadow/slsa-verifier" \
  UMBRA_INSTALL_VERSION="1.2.3" \
    sh "$repo_root/ops/installer/install.sh" 2>&1 || true
)"
case "$intel_macos_output" in
  *'Intel macOS does not have a published Umbra CLI binary'*) ;;
  *) echo "installer smoke: Intel macOS support mismatch was not rejected" >&2; exit 1 ;;
esac

export INSTALL_HOST=install.example.com
export UMBRA_CLI_RELEASE_DIR="$tmpdir/releases"
release_version="0.0.1"
release_target="x86_64-unknown-linux-gnu"
for channel in "$release_version" latest; do
  channel_dir="$UMBRA_CLI_RELEASE_DIR/$channel/$release_target"
  mkdir -p "$channel_dir"
  printf '#!/bin/sh\nprintf "umbra %%s\\n" "%s"\n' "$release_version" \
    > "$channel_dir/umbra"
  chmod 0755 "$channel_dir/umbra"
  (cd "$channel_dir" && sha256sum umbra > umbra.sha256)
  printf '%s\n' "$release_version" > "$UMBRA_CLI_RELEASE_DIR/$channel/version"
  printf '{"fixture":"signed provenance"}\n' \
    > "$UMBRA_CLI_RELEASE_DIR/$channel/umbra-cli.intoto.jsonl"
done

# A newer immutable path carrying an older, genuinely signed binary exercises
# the installer's post-provenance version binding. The fake verifier accepts
# this fixture, so only the binary's authenticated --version can stop replay.
replayed_version="0.0.2"
replayed_dir="$UMBRA_CLI_RELEASE_DIR/$replayed_version/$release_target"
mkdir -p "$replayed_dir"
cp "$UMBRA_CLI_RELEASE_DIR/$release_version/$release_target/umbra" \
  "$replayed_dir/umbra"
(cd "$replayed_dir" && sha256sum umbra > umbra.sha256)
printf '{"fixture":"signed provenance"}\n' \
  > "$UMBRA_CLI_RELEASE_DIR/$replayed_version/umbra-cli.intoto.jsonl"

docker build -q -t umbra-installer-smoke ops/installer
container_id="$(docker run -d \
  -e INSTALL_HOST="$INSTALL_HOST" \
  -v "$UMBRA_CLI_RELEASE_DIR:/opt/umbra/cli-releases:ro" \
  umbra-installer-smoke)"
trap 'docker rm -f "$container_id" >/dev/null 2>&1 || true; rm -rf "$tmpdir"' EXIT

for _ in $(seq 1 30); do
  if docker exec "$container_id" wget -q -O - http://127.0.0.1:8080/healthz | grep -q ok; then
    break
  fi
  sleep 1
done

script="$(docker exec "$container_id" wget -q -O - http://127.0.0.1:8080/install.sh)"
case "$script" in
  *'base_url="${UMBRA_INSTALL_BASE_URL:-https://install.example.com}"'*) ;;
  *) echo "installer smoke: install.sh base_url missing expected default" >&2; exit 1 ;;
esac
case "$script" in
  *'source_repo="${UMBRA_INSTALL_SOURCE_REPO:-github.com/concrete-security/umbra}"'*) ;;
  *) echo "installer smoke: install.sh source_repo missing expected default" >&2; exit 1 ;;
esac

root_script="$(docker exec "$container_id" wget -q -O - http://127.0.0.1:8080/)"
test "$root_script" = "$script"

artifact="$(docker exec "$container_id" wget -q -O - http://127.0.0.1:8080/releases/umbra-cli/latest/x86_64-unknown-linux-gnu/umbra)"
test "$artifact" = "$(sed -n '1,$p' "$UMBRA_CLI_RELEASE_DIR/latest/$release_target/umbra")"

checksum="$(docker exec "$container_id" wget -q -O - http://127.0.0.1:8080/releases/umbra-cli/latest/x86_64-unknown-linux-gnu/umbra.sha256)"
test "$checksum" = "$(sha256sum "$UMBRA_CLI_RELEASE_DIR/latest/$release_target/umbra" | awk '{print $1}')  umbra"

latest_version="$(docker exec "$container_id" wget -q -O - http://127.0.0.1:8080/releases/umbra-cli/latest/version)"
test "$latest_version" = "$release_version"

provenance="$(docker exec "$container_id" wget -q -O - "http://127.0.0.1:8080/releases/umbra-cli/$release_version/umbra-cli.intoto.jsonl")"
test "$provenance" = '{"fixture":"signed provenance"}'

# Exercise the installer without trusting the fixture as real provenance. The
# configurable verifier path is a narrow test seam: this stub checks that the
# installer supplies the downloaded artifact, attestation, source repository,
# and canonical branch. Production fails closed unless a preinstalled
# slsa-verifier validates the real signed bundle.
fake_bin="$tmpdir/fake-bin"
mkdir -p "$fake_bin"

cat > "$fake_bin/uname" <<'EOF'
#!/bin/sh
case "${1:-}" in
  -s) printf 'Linux\n' ;;
  -m) printf 'x86_64\n' ;;
  *) exit 1 ;;
esac
EOF
chmod 0755 "$fake_bin/uname"

cat > "$fake_bin/curl" <<'EOF'
#!/bin/sh
set -eu
output=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      shift
      output="${1:-}"
      ;;
    -*) ;;
    *) url="$1" ;;
  esac
  shift
done
[ -n "$output" ] && [ -n "$url" ] || exit 2
prefix="http://127.0.0.1/releases/umbra-cli/"
relative="${url#"$prefix"}"
[ "$relative" != "$url" ] || exit 22
case "$relative" in
  latest/version) ;;
  latest/*) exit 22 ;;
esac
printf '%s\n' "$url" >> "$INSTALLER_DOWNLOAD_LOG"
cp "$INSTALLER_FIXTURE_ROOT/$relative" "$output"
EOF
chmod 0755 "$fake_bin/curl"

cat > "$fake_bin/slsa-verifier" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$@" > "$INSTALLER_VERIFIER_LOG"
[ "$#" -eq 12 ]
[ "$1" = verify-artifact ]
[ -s "$2" ]
[ "$3" = --provenance-path ]
[ -s "$4" ]
[ "$5" = --source-uri ]
[ "$6" = github.com/example/umbra ]
[ "$7" = --source-branch ]
[ "$8" = main ]
[ "$9" = --build-workflow-input ]
[ "${10}" = dry_run=false ]
[ "${11}" = --builder-id ]
[ "${12}" = 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0' ]
[ "${INSTALLER_VERIFIER_RESULT:-success}" = success ]
EOF
chmod 0755 "$fake_bin/slsa-verifier"

download_log="$tmpdir/download.log"
verifier_log="$tmpdir/verifier.log"
install_bin_dir="$tmpdir/install-success"
: > "$download_log"
PATH="$fake_bin:$PATH" \
INSTALLER_DOWNLOAD_LOG="$download_log" \
INSTALLER_FIXTURE_ROOT="$UMBRA_CLI_RELEASE_DIR" \
INSTALLER_VERIFIER_LOG="$verifier_log" \
UMBRA_INSTALL_BASE_URL="http://127.0.0.1" \
UMBRA_INSTALL_BIN_DIR="$install_bin_dir" \
UMBRA_INSTALL_SLSA_VERIFIER="$fake_bin/slsa-verifier" \
UMBRA_INSTALL_SOURCE_REPO="github.com/example/umbra" \
  sh ops/installer/install.sh >/dev/null

test -x "$install_bin_dir/umbra"
grep -Fx "http://127.0.0.1/releases/umbra-cli/latest/version" "$download_log" >/dev/null
grep -Fx "http://127.0.0.1/releases/umbra-cli/$release_version/$release_target/umbra" "$download_log" >/dev/null
grep -Fx "http://127.0.0.1/releases/umbra-cli/$release_version/$release_target/umbra.sha256" "$download_log" >/dev/null
grep -Fx "http://127.0.0.1/releases/umbra-cli/$release_version/umbra-cli.intoto.jsonl" "$download_log" >/dev/null
if grep -F "/latest/$release_target/" "$download_log" >/dev/null; then
  echo "installer smoke: latest channel was used for a mutable artifact download" >&2
  exit 1
fi
grep -Fx -- '--source-uri' "$verifier_log" >/dev/null
grep -Fx 'github.com/example/umbra' "$verifier_log" >/dev/null
grep -Fx -- '--source-branch' "$verifier_log" >/dev/null
grep -Fx 'main' "$verifier_log" >/dev/null
grep -Fx -- '--build-workflow-input' "$verifier_log" >/dev/null
grep -Fx 'dry_run=false' "$verifier_log" >/dev/null
grep -Fx -- '--builder-id' "$verifier_log" >/dev/null
grep -Fx 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0' "$verifier_log" >/dev/null

replayed_bin_dir="$tmpdir/install-replayed"
mkdir -p "$replayed_bin_dir"
printf '#!/bin/sh\nprintf "trusted existing umbra\\n"\n' \
  > "$replayed_bin_dir/umbra"
chmod 0755 "$replayed_bin_dir/umbra"
trusted_digest="$(sha256sum "$replayed_bin_dir/umbra" | awk '{print $1}')"
replayed_output="$(
  PATH="$fake_bin:$PATH" \
  INSTALLER_DOWNLOAD_LOG="$download_log" \
  INSTALLER_FIXTURE_ROOT="$UMBRA_CLI_RELEASE_DIR" \
  INSTALLER_VERIFIER_LOG="$verifier_log" \
  UMBRA_INSTALL_BASE_URL="http://127.0.0.1" \
  UMBRA_INSTALL_BIN_DIR="$replayed_bin_dir" \
  UMBRA_INSTALL_VERSION="$replayed_version" \
  UMBRA_INSTALL_SLSA_VERIFIER="$fake_bin/slsa-verifier" \
  UMBRA_INSTALL_SOURCE_REPO="github.com/example/umbra" \
    sh ops/installer/install.sh 2>&1 || true
)"
case "$replayed_output" in
  *"verified binary reports umbra ${release_version}, expected ${replayed_version}"*) ;;
  *) echo "installer smoke: signed older payload was not rejected: $replayed_output" >&2; exit 1 ;;
esac
test "$(sha256sum "$replayed_bin_dir/umbra" | awk '{print $1}')" = "$trusted_digest"

: > "$download_log"
missing_output="$(
  PATH="$fake_bin:$PATH" \
  INSTALLER_DOWNLOAD_LOG="$download_log" \
  INSTALLER_FIXTURE_ROOT="$UMBRA_CLI_RELEASE_DIR" \
  UMBRA_INSTALL_BASE_URL="http://127.0.0.1" \
  UMBRA_INSTALL_BIN_DIR="$tmpdir/install-missing" \
  UMBRA_INSTALL_SLSA_VERIFIER="$fake_bin/missing-slsa-verifier" \
  UMBRA_INSTALL_SOURCE_REPO="github.com/example/umbra" \
    sh ops/installer/install.sh 2>&1 || true
)"
case "$missing_output" in
  *'slsa-verifier is required'*) ;;
  *) echo "installer smoke: missing verifier did not fail closed" >&2; exit 1 ;;
esac
test ! -s "$download_log"
test ! -e "$tmpdir/install-missing/umbra"

: > "$download_log"
rejected_bin_dir="$tmpdir/install-rejected"
rejected_output="$(
  PATH="$fake_bin:$PATH" \
  INSTALLER_DOWNLOAD_LOG="$download_log" \
  INSTALLER_FIXTURE_ROOT="$UMBRA_CLI_RELEASE_DIR" \
  INSTALLER_VERIFIER_LOG="$verifier_log" \
  INSTALLER_VERIFIER_RESULT=reject \
  UMBRA_INSTALL_BASE_URL="http://127.0.0.1" \
  UMBRA_INSTALL_BIN_DIR="$rejected_bin_dir" \
  UMBRA_INSTALL_SLSA_VERIFIER="$fake_bin/slsa-verifier" \
  UMBRA_INSTALL_SOURCE_REPO="github.com/example/umbra" \
    sh ops/installer/install.sh 2>&1 || true
)"
case "$rejected_output" in
  *'SLSA provenance verification failed'*) ;;
  *) echo "installer smoke: rejected provenance did not fail closed" >&2; exit 1 ;;
esac
test ! -e "$rejected_bin_dir/umbra"

# Both artifact sync paths must carry the release workflow's exact provenance
# artifact beside the immutable and latest version files. The release path uses
# anonymous public HTTP fixtures; only the explicit workflow path uses fake gh.
sync_version="1.2.3"
sync_targets="x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu aarch64-apple-darwin"
sync_fixture="$tmpdir/sync-fixture"
release_assets="$sync_fixture/release-assets"
release_tree="$sync_fixture/release-tree"
workflow_artifacts="$sync_fixture/workflow-artifacts"
sync_fake_bin="$sync_fixture/bin"
sync_anonymous_bin="$sync_fixture/anonymous-bin"
mkdir -p \
  "$release_assets" \
  "$workflow_artifacts/umbra-cli-release-tree" \
  "$sync_fake_bin" \
  "$sync_anonymous_bin"
for channel in "$sync_version" latest; do
  for target in $sync_targets; do
    mkdir -p "$release_tree/$channel/$target"
    printf 'synced binary for %s\n' "$target" \
      > "$release_tree/$channel/$target/umbra"
    (cd "$release_tree/$channel/$target" && sha256sum umbra > umbra.sha256)
  done
  printf '%s\n' "$sync_version" > "$release_tree/$channel/version"
done
tar -C "$release_tree" -czf "$release_assets/umbra-cli-release-tree.tar.gz" .
printf '{"fixture":"release provenance"}\n' \
  > "$release_assets/umbra-cli.intoto.jsonl"
printf '#!/bin/sh\nexit 0\n' > "$release_assets/umbra-install.sh"
chmod 0755 "$release_assets/umbra-install.sh"
: > "$release_assets/SHA256SUMS"
(
  cd "$release_assets"
  sha256sum umbra-cli-release-tree.tar.gz umbra-install.sh > SHA256SUMS
)
for target in $sync_targets; do
  digest="$(sha256sum "$release_tree/$sync_version/$target/umbra" | awk '{print $1}')"
  printf '%s  %s/%s/umbra\n' "$digest" "$sync_version" "$target" \
    >> "$release_assets/SHA256SUMS"
done
cp "$release_assets/umbra-cli.intoto.jsonl" \
  "$workflow_artifacts/umbra-cli.intoto.jsonl"
cp "$release_assets/umbra-install.sh" \
  "$release_assets/umbra-cli-release-tree.tar.gz" \
  "$release_assets/SHA256SUMS" \
  "$workflow_artifacts/umbra-cli-release-tree/"

cat > "$sync_fake_bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[ "${GH_TOKEN:-}" = one-shot-fixture ] || {
  echo "workflow gh child did not receive only the one-shot token" >&2
  exit 2
}
case "${1:-} ${2:-}" in
  "api repos/example/umbra/actions/runs/4242")
    query=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --jq ]; then
        shift
        query="${1:-}"
        break
      fi
      shift
    done
    case "$query" in
      *head_branch*) printf 'main\n' ;;
      *status*) printf 'completed\n' ;;
      *conclusion*) printf 'success\n' ;;
      *) exit 2 ;;
    esac
    ;;
  "api repos/example/umbra/actions/runs/4242/artifacts")
    query=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = --jq ]; then
        shift
        query="${1:-}"
        break
      fi
      shift
    done
    case "$query" in
      *'umbra-cli.intoto.jsonl'*'length'*) printf '1\n' ;;
      *'umbra-cli-release-tree'*'length'*) printf '1\n' ;;
      *) exit 2 ;;
    esac
    ;;
  "run download")
    shift 2
    run_id="${1:-}"
    shift
    name=""
    dest=""
    while [ "$#" -gt 0 ]; do
      case "$1" in
        --name) shift; name="${1:-}" ;;
        --dir) shift; dest="${1:-}" ;;
      esac
      shift
    done
    [ "$run_id" = 4242 ]
    [ -n "$name" ] && [ -n "$dest" ]
    mkdir -p "$dest"
    if [ "$name" = umbra-cli.intoto.jsonl ]; then
      cp "$SYNC_WORKFLOW_ARTIFACTS/$name" "$dest/$name"
    else
      cp -a "$SYNC_WORKFLOW_ARTIFACTS/$name/." "$dest/"
    fi
    printf 'workflow:%s\n' "$name" >> "$SYNC_GH_LOG"
    ;;
  *)
    echo "unexpected fake gh invocation: $*" >&2
    exit 2
    ;;
esac
EOF
chmod 0755 "$sync_fake_bin/gh"

release_metadata="$sync_fixture/releases.json"
cat > "$release_metadata" <<'EOF'
[
  {
    "tag_name": "umbra-cli/1.2.4-01",
    "draft": false,
    "assets": [
      {"name":"umbra-cli-release-tree.tar.gz","browser_download_url":"http://127.0.0.1/assets/umbra-cli-release-tree.tar.gz"},
      {"name":"umbra-cli.intoto.jsonl","browser_download_url":"http://127.0.0.1/assets/umbra-cli.intoto.jsonl"},
      {"name":"umbra-install.sh","browser_download_url":"http://127.0.0.1/assets/umbra-install.sh"},
      {"name":"SHA256SUMS","browser_download_url":"http://127.0.0.1/assets/SHA256SUMS"}
    ]
  },
  {
    "tag_name": "umbra-cli/1.2.3",
    "draft": false,
    "assets": [
      {"name":"umbra-cli-release-tree.tar.gz","browser_download_url":"http://127.0.0.1/assets/umbra-cli-release-tree.tar.gz"},
      {"name":"umbra-cli.intoto.jsonl","browser_download_url":"http://127.0.0.1/assets/umbra-cli.intoto.jsonl"},
      {"name":"umbra-install.sh","browser_download_url":"http://127.0.0.1/assets/umbra-install.sh"},
      {"name":"SHA256SUMS","browser_download_url":"http://127.0.0.1/assets/SHA256SUMS"}
    ]
  },
  {
    "tag_name": "umbra-cli/9.0.0",
    "draft": true,
    "assets": []
  }
]
EOF

cat > "$sync_anonymous_bin/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
output=""
url=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      shift
      output="${1:-}"
      ;;
    --header)
      shift
      case "${1:-}" in
        [Aa]uthorization:*)
          echo "anonymous release sync supplied an authorization header" >&2
          exit 2
          ;;
      esac
      ;;
    --connect-timeout|--max-time|--max-filesize|--max-redirs|--proto|--proto-redir|--user-agent)
      shift
      ;;
    --disable|--fail|--silent|--show-error|--location|--tlsv1.2)
      ;;
    --*)
      echo "unexpected fake curl option: $1" >&2
      exit 2
      ;;
    *)
      [ -z "$url" ] || { echo "multiple fake curl URLs" >&2; exit 2; }
      url="$1"
      ;;
  esac
  shift
done
[ -n "$output" ] && [ -n "$url" ]
printf '%s\n' "$url" >> "$SYNC_CURL_LOG"
case "$url" in
  http://127.0.0.1/github/releases)
    cp "$SYNC_RELEASE_METADATA" "$output"
    ;;
  http://127.0.0.1/assets/umbra-cli-release-tree.tar.gz)
    cp "$SYNC_RELEASE_ASSETS/umbra-cli-release-tree.tar.gz" "$output"
    ;;
  http://127.0.0.1/assets/umbra-cli.intoto.jsonl)
    cp "$SYNC_RELEASE_ASSETS/umbra-cli.intoto.jsonl" "$output"
    ;;
  http://127.0.0.1/assets/umbra-install.sh)
    cp "$SYNC_RELEASE_ASSETS/umbra-install.sh" "$output"
    ;;
  http://127.0.0.1/assets/SHA256SUMS)
    cp "$SYNC_RELEASE_ASSETS/SHA256SUMS" "$output"
    ;;
  *)
    echo "unexpected fake curl URL: $url" >&2
    exit 2
    ;;
esac
EOF
chmod 0755 "$sync_anonymous_bin/curl"

cat > "$sync_anonymous_bin/gh" <<'EOF'
#!/bin/sh
set -eu
touch "$SYNC_GH_MARKER"
echo "anonymous release sync invoked gh" >&2
exit 2
EOF
chmod 0755 "$sync_anonymous_bin/gh"

cat > "$sync_fake_bin/slsa-verifier" <<'EOF'
#!/bin/sh
set -eu
if [ "${GH_TOKEN+x}" ]; then
  echo "workflow verifier inherited GH_TOKEN" >&2
  exit 2
fi
[ "$#" -eq 12 ]
[ "$1" = verify-artifact ]
[ -s "$2" ]
[ "$3" = --provenance-path ]
[ -s "$4" ]
[ "$5" = --source-uri ]
[ "$6" = github.com/example/umbra ]
[ "$7" = --source-branch ]
[ "$8" = main ]
[ "$9" = --build-workflow-input ]
[ "${10}" = dry_run=false ]
[ "${11}" = --builder-id ]
[ "${12}" = 'https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0' ]
printf 'verified:%s\n' "$(basename "$2")" >> "$SYNC_VERIFIER_LOG"
[ "${SYNC_VERIFIER_RESULT:-success}" = success ]
EOF
chmod 0755 "$sync_fake_bin/slsa-verifier"

sync_real_python3="$(command -v python3)"
cat > "$sync_fake_bin/python3" <<'EOF'
#!/bin/sh
set -eu
if [ "${GH_TOKEN+x}" ]; then
  echo "workflow Python child inherited GH_TOKEN" >&2
  exit 2
fi
printf 'python\n' >> "$SYNC_NON_GH_LOG"
exec "$SYNC_REAL_PYTHON3" "$@"
EOF
chmod 0755 "$sync_fake_bin/python3"

sync_gh_log="$sync_fixture/gh.log"
sync_gh_marker="$sync_fixture/anonymous-gh-ran"
sync_curl_log="$sync_fixture/curl.log"
sync_verifier_log="$sync_fixture/verifier.log"
release_sync_dir="$sync_fixture/release-sync"
: > "$sync_gh_log"
: > "$sync_curl_log"
: > "$sync_verifier_log"
PATH="$sync_anonymous_bin:$PATH" \
GHCR_TOKEN=legacy-registry-token \
SYNC_CURL_LOG="$sync_curl_log" \
SYNC_GH_MARKER="$sync_gh_marker" \
SYNC_VERIFIER_LOG="$sync_verifier_log" \
SYNC_RELEASE_ASSETS="$release_assets" \
SYNC_RELEASE_METADATA="$release_metadata" \
UMBRA_INSTALL_SLSA_VERIFIER="$sync_fake_bin/slsa-verifier" \
UMBRA_CLI_RELEASE_GITHUB_REPO=example/umbra \
UMBRA_CLI_RELEASE_API_URL=http://127.0.0.1/github/releases \
UMBRA_CLI_RELEASE_DIR="$release_sync_dir" \
  env -u GH_TOKEN bash ops/cli-release/sync-cli-release-artifacts.sh >/dev/null
cmp "$release_assets/umbra-cli.intoto.jsonl" \
  "$release_sync_dir/$sync_version/umbra-cli.intoto.jsonl"
cmp "$release_assets/umbra-cli.intoto.jsonl" \
  "$release_sync_dir/latest/umbra-cli.intoto.jsonl"
cmp "$release_assets/umbra-install.sh" \
  "$release_sync_dir/$sync_version/umbra-install.sh"
cmp "$release_assets/umbra-install.sh" \
  "$release_sync_dir/latest/umbra-install.sh"
test ! -e "$sync_gh_marker"
test "$(wc -l < "$sync_curl_log")" -eq 5
grep -Fx 'http://127.0.0.1/github/releases' "$sync_curl_log" >/dev/null
grep -Fx 'http://127.0.0.1/assets/umbra-cli-release-tree.tar.gz' "$sync_curl_log" >/dev/null
grep -Fx 'http://127.0.0.1/assets/umbra-cli.intoto.jsonl' "$sync_curl_log" >/dev/null
grep -Fx 'http://127.0.0.1/assets/umbra-install.sh' "$sync_curl_log" >/dev/null
grep -Fx 'http://127.0.0.1/assets/SHA256SUMS' "$sync_curl_log" >/dev/null
grep -Fx 'verified:umbra-cli-release-tree.tar.gz' "$sync_verifier_log" >/dev/null
grep -Fx 'verified:umbra-install.sh' "$sync_verifier_log" >/dev/null
grep -Fx 'verified:SHA256SUMS' "$sync_verifier_log" >/dev/null

rejected_sync_dir="$sync_fixture/rejected-sync"
rejected_sync_output="$(
  PATH="$sync_anonymous_bin:$PATH" \
  SYNC_CURL_LOG="$sync_curl_log" \
  SYNC_GH_MARKER="$sync_gh_marker" \
  SYNC_VERIFIER_LOG="$sync_verifier_log" \
  SYNC_VERIFIER_RESULT=reject \
  SYNC_RELEASE_ASSETS="$release_assets" \
  SYNC_RELEASE_METADATA="$release_metadata" \
  UMBRA_INSTALL_SLSA_VERIFIER="$sync_fake_bin/slsa-verifier" \
  UMBRA_CLI_RELEASE_GITHUB_REPO=example/umbra \
  UMBRA_CLI_RELEASE_API_URL=http://127.0.0.1/github/releases \
  UMBRA_CLI_RELEASE_TAG="umbra-cli/$sync_version" \
  UMBRA_CLI_RELEASE_DIR="$rejected_sync_dir" \
    env -u GH_TOKEN bash ops/cli-release/sync-cli-release-artifacts.sh 2>&1 || true
)"
case "$rejected_sync_output" in
  *'SLSA provenance verification failed'*) ;;
  *) echo "installer smoke: release sync did not fail closed on provenance rejection" >&2; exit 1 ;;
esac
test ! -e "$rejected_sync_dir"

: > "$sync_curl_log"
: > "$sync_verifier_log"
invalid_semver_sync_dir="$sync_fixture/invalid-semver-sync"
invalid_semver_sync_output="$(
  PATH="$sync_anonymous_bin:$PATH" \
  SYNC_CURL_LOG="$sync_curl_log" \
  SYNC_GH_MARKER="$sync_gh_marker" \
  SYNC_VERIFIER_LOG="$sync_verifier_log" \
  SYNC_RELEASE_ASSETS="$release_assets" \
  SYNC_RELEASE_METADATA="$release_metadata" \
  UMBRA_INSTALL_SLSA_VERIFIER="$sync_fake_bin/slsa-verifier" \
  UMBRA_CLI_RELEASE_GITHUB_REPO=example/umbra \
  UMBRA_CLI_RELEASE_API_URL=http://127.0.0.1/github/releases \
  UMBRA_CLI_RELEASE_TAG=umbra-cli/1.2.4-01 \
  UMBRA_CLI_RELEASE_DIR="$invalid_semver_sync_dir" \
    env -u GH_TOKEN bash ops/cli-release/sync-cli-release-artifacts.sh 2>&1 || true
)"
case "$invalid_semver_sync_output" in
  *'requested release tag is not canonical SemVer: umbra-cli/1.2.4-01'*) ;;
  *) echo "installer smoke: release sync accepted invalid numeric prerelease: $invalid_semver_sync_output" >&2; exit 1 ;;
esac
test "$(wc -l < "$sync_curl_log")" -eq 1
grep -Fx 'http://127.0.0.1/github/releases' "$sync_curl_log" >/dev/null
test ! -s "$sync_verifier_log"
test ! -e "$invalid_semver_sync_dir"
test ! -e "$sync_gh_marker"

hostile_tree="$sync_fixture/hostile-tree"
hostile_archive="$sync_fixture/hostile-release.tar.gz"
hostile_extract="$sync_fixture/hostile-extract"
mkdir -p "$hostile_tree"
ln -s /tmp "$hostile_tree/latest"
tar -C "$hostile_tree" -czf "$hostile_archive" .
hostile_output="$(
  python3 ops/cli-release/extract-cli-release-tree.py \
    "$hostile_archive" "$hostile_extract" "$sync_version" 2>&1 || true
)"
case "$hostile_output" in
  *'archive contains link or special entry'*) ;;
  *) echo "installer smoke: hostile release archive was not rejected" >&2; exit 1 ;;
esac
test ! -e "$hostile_extract"

workflow_sync_dir="$sync_fixture/workflow-sync"
sync_non_gh_log="$sync_fixture/non-gh.log"
: > "$sync_gh_log"
: > "$sync_non_gh_log"
: > "$sync_verifier_log"
PATH="$sync_fake_bin:$PATH" \
GH_TOKEN=one-shot-fixture \
SYNC_GH_LOG="$sync_gh_log" \
SYNC_NON_GH_LOG="$sync_non_gh_log" \
SYNC_REAL_PYTHON3="$sync_real_python3" \
SYNC_VERIFIER_LOG="$sync_verifier_log" \
SYNC_WORKFLOW_ARTIFACTS="$workflow_artifacts" \
UMBRA_INSTALL_SLSA_VERIFIER="$sync_fake_bin/slsa-verifier" \
UMBRA_CLI_RELEASE_GITHUB_REPO=example/umbra \
UMBRA_CLI_WORKFLOW_RUN_ID=4242 \
UMBRA_CLI_WORKFLOW_BRANCH=main \
UMBRA_CLI_RELEASE_VERSION="$sync_version" \
UMBRA_CLI_RELEASE_DIR="$workflow_sync_dir" \
  bash ops/cli-release/sync-cli-workflow-artifacts.sh >/dev/null
cmp "$workflow_artifacts/umbra-cli.intoto.jsonl" \
  "$workflow_sync_dir/$sync_version/umbra-cli.intoto.jsonl"
cmp "$workflow_artifacts/umbra-cli.intoto.jsonl" \
  "$workflow_sync_dir/latest/umbra-cli.intoto.jsonl"
cmp "$workflow_artifacts/umbra-cli-release-tree/umbra-install.sh" \
  "$workflow_sync_dir/$sync_version/umbra-install.sh"
cmp "$workflow_artifacts/umbra-cli-release-tree/umbra-install.sh" \
  "$workflow_sync_dir/latest/umbra-install.sh"
grep -Fx 'workflow:umbra-cli.intoto.jsonl' "$sync_gh_log" >/dev/null
grep -Fx 'workflow:umbra-cli-release-tree' "$sync_gh_log" >/dev/null
grep -Fx 'verified:umbra-cli-release-tree.tar.gz' "$sync_verifier_log" >/dev/null
grep -Fx 'verified:umbra-install.sh' "$sync_verifier_log" >/dev/null
grep -Fx 'verified:SHA256SUMS' "$sync_verifier_log" >/dev/null
test "$(wc -l < "$sync_non_gh_log")" -eq 2

echo "installer smoke: ok"
