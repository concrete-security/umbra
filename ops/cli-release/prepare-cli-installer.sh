#!/usr/bin/env bash
set -euo pipefail

info() {
  echo "prepare-cli-installer: $1" >&2
}

preserve_env_names=(
  INSTALL_HOST
  UMBRA_CLI_RELEASE_DIR
  UMBRA_CLI_RELEASE_SOURCE
  UMBRA_CLI_RELEASE_GITHUB_REPO
  UMBRA_CLI_WORKFLOW_NAME
  UMBRA_CLI_WORKFLOW_BRANCH
  UMBRA_CLI_WORKFLOW_RUN_ID
  UMBRA_CLI_RELEASE_TAG
  UMBRA_CLI_RELEASE_VERSION
  UMBRA_CLI_RELEASE_API_URL
  UMBRA_INSTALL_BASE_URL
  UMBRA_INSTALL_SLSA_VERIFIER
)
caller_supplied_gh_token=false
caller_gh_token=""
if [ "${GH_TOKEN+x}" ]; then
  caller_supplied_gh_token=true
  caller_gh_token="$GH_TOKEN"
fi
readonly caller_supplied_gh_token caller_gh_token
declare -A preserved_env=()
for name in "${preserve_env_names[@]}"; do
  if [ "${!name+x}" ]; then
    preserved_env["$name"]="${!name}"
  fi
done

if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

for name in "${!preserved_env[@]}"; do
  export "$name=${preserved_env[$name]}"
done
# A legacy .env may still contain a broad, long-lived publish token. Keep every
# token out of the parent deployment environment; the workflow recovery path
# receives only the explicitly captured one-shot token below.
unset GH_TOKEN

release_source="${UMBRA_CLI_RELEASE_SOURCE:-github}"
readonly release_source
case "$release_source" in
  github|workflow|skip) ;;
  local)
    echo "prepare-cli-installer: UMBRA_CLI_RELEASE_SOURCE=local is forbidden because this workflow loads deployment secrets; run make package-cli from a separate checkout with no .env or provider secrets" >&2
    exit 1
    ;;
  *)
    echo "prepare-cli-installer: UMBRA_CLI_RELEASE_SOURCE must be github, workflow, or skip" >&2
    exit 1
    ;;
esac

if [ -z "${INSTALL_HOST:-}" ]; then
  exit 0
fi

python3 ops/host/provision-install-host-dns.py

# Release verification needs only process tooling, temporary storage, public
# release selectors, and the fixed verifier path. In particular, none of the
# Console/provider secrets loaded from .env may reach curl, Python, or the SLSA
# verifier beneath either sync script.
release_sync_env=("PATH=${PATH:-/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin}")
for name in \
  TMPDIR \
  UMBRA_CLI_RELEASE_DIR \
  UMBRA_CLI_RELEASE_GITHUB_REPO \
  UMBRA_CLI_RELEASE_VERSION \
  UMBRA_INSTALL_SLSA_VERIFIER; do
  if [ "${!name+x}" ]; then
    release_sync_env+=("$name=${!name}")
  fi
done

case "$release_source" in
  github)
    info "syncing CLI artifacts from GitHub release"
    github_sync_env=("${release_sync_env[@]}")
    for name in UMBRA_CLI_RELEASE_TAG UMBRA_CLI_RELEASE_API_URL; do
      if [ "${!name+x}" ]; then
        github_sync_env+=("$name=${!name}")
      fi
    done
    /usr/bin/env -i "${github_sync_env[@]}" \
      ./ops/cli-release/sync-cli-release-artifacts.sh
    ;;
  workflow)
    info "syncing CLI artifacts from GitHub Actions workflow"
    if [ "$caller_supplied_gh_token" != true ] || [ -z "$caller_gh_token" ]; then
      echo "prepare-cli-installer: workflow source requires an explicitly supplied one-shot GH_TOKEN" >&2
      exit 1
    fi
    case "$caller_gh_token" in
      *$'\n'*|*$'\r'*)
        echo "prepare-cli-installer: one-shot GH_TOKEN must not contain newlines" >&2
        exit 1
        ;;
    esac
    workflow_sync_env=("${release_sync_env[@]}" "GH_PROMPT_DISABLED=1")
    for name in \
      UMBRA_CLI_WORKFLOW_NAME \
      UMBRA_CLI_WORKFLOW_BRANCH \
      UMBRA_CLI_WORKFLOW_RUN_ID; do
      if [ "${!name+x}" ]; then
        workflow_sync_env+=("$name=${!name}")
      fi
    done
    /usr/bin/env -i "${workflow_sync_env[@]}" \
      /bin/bash -c '
        IFS= read -r GH_TOKEN <&3 || exit 1
        exec 3<&-
        export GH_TOKEN
        exec "$@"
      ' prepare-cli-workflow ./ops/cli-release/sync-cli-workflow-artifacts.sh \
      3<<< "$caller_gh_token"
    ;;
  skip)
    info "skipping CLI artifact sync"
    ;;
esac
