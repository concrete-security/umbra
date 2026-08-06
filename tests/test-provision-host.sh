#!/usr/bin/env bash
# Behavioral tests for ops/host/provision-host.sh. Install paths use DRY_RUN;
# fail-closed paths use inert command stubs, so nothing is actually installed.
# Uses the script's test hooks:
#   DRY_RUN, PROVISION_OS, PROVISION_PKG_MANAGER, SKIP_PACKAGE_MANAGER_CHECK.
#
# Each run executes the real script in a pristine environment (env -i) with a
# minimal PATH that intentionally contains none of the provisioned tools,
# capturing stdout+stderr and the exit code.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${REPO_ROOT}/ops/host/provision-host.sh"
# shellcheck source=ops/buildkit-version.sh
source "${REPO_ROOT}/ops/buildkit-version.sh"
PINNED_RUST_VERSION="$(awk -F '"' '/^[[:space:]]*channel[[:space:]]*=/{print $2; exit}' "${REPO_ROOT}/rust-toolchain.toml")"
PINNED_PHALA_VERSION="$(awk -F '"' '/^[[:space:]]*"phala":[[:space:]]*"[0-9]/{print $4; exit}' "${REPO_ROOT}/console/package.json")"
PINNED_PHALA_SHA256="$(awk -F= '$1 == "PHALA_CLI_SHA256" {print $2; exit}' "${REPO_ROOT}/.env.common")"
TEST_BIN="$(mktemp -d "${TMPDIR:-/tmp}/umbra-provision-host.XXXXXX")"
TEST_COMMANDS=(awk bash dirname env grep mkdir)
FAIL_BIN="$(mktemp -d "${TMPDIR:-/tmp}/umbra-provision-host-fail.XXXXXX")"
FAIL_COMMANDS=(apt-cache awk bash cargo curl dirname docker gh git grep jq make pkg-config psql rustc rustfmt sudo uv wget)
VERIFIER_FIXTURE="$(mktemp -d "${TMPDIR:-/tmp}/umbra-provision-verifier.XXXXXX")"

cleanup() {
  local command_name
  for command_name in "${TEST_COMMANDS[@]}"; do
    rm -f "${TEST_BIN}/${command_name}"
  done
  rm -f "${TEST_BIN}/go-fixture"
  rmdir "$TEST_BIN"
  for command_name in "${FAIL_COMMANDS[@]}"; do
    rm -f "${FAIL_BIN}/${command_name}"
  done
  rmdir "$FAIL_BIN"
  rm -rf -- "${VERIFIER_FIXTURE:?}"
}
trap cleanup EXIT

for command_name in "${TEST_COMMANDS[@]}"; do
  ln -s "$(command -v "$command_name")" "${TEST_BIN}/${command_name}"
done

for command_name in awk bash dirname grep; do
  ln -s "$(command -v "$command_name")" "${FAIL_BIN}/${command_name}"
done
for command_name in curl git jq make pkg-config psql sudo wget; do
  ln -s "$(type -P true)" "${FAIL_BIN}/${command_name}"
done
ln -s "$(type -P false)" "${FAIL_BIN}/apt-cache"

fail() { echo "test failed: $*" >&2; exit 1; }
pass() { echo "provision-host: ok: $*" >&2; }
contains() { case "$2" in *"$1"*) return 0 ;; *) return 1 ;; esac; }

test_buildx_client_versions_success() {
  docker() { printf '%s\n' 'github.com/docker/buildx v0.34.0 fixture'; }
  umbra_buildx_client_supported \
    || fail "expected the exactly reviewed Buildx client to pass"
  unset -f docker
  pass "accepts the exactly reviewed Buildx client"
}

test_buildx_client_versions_failure() {
  local fixture

  for fixture in \
    'github.com/docker/buildx v0.33.9 fixture' \
    'github.com/docker/buildx v0.34.1 fixture' \
    'github.com/docker/buildx v0.34.0-rc1 fixture' \
    'github.com/docker/buildx v0.36.0 fixture' \
    'github.com/docker/buildx v0.34 fixture' \
    'unparseable buildx output'; do
    docker() { printf '%s\n' "$fixture"; }
    if umbra_buildx_client_supported; then
      fail "expected unsupported Buildx fixture to fail: $fixture"
    fi
    unset -f docker
  done
  pass "rejects old, prerelease, and unparseable Buildx clients"
}

test_buildkit_pinned_runtime_success() {
  local fixture

  fixture="$(cat <<EOF
Name:          ${UMBRA_BUILDKIT_BUILDER}
Driver:        docker-container

Nodes:
Name:                  ${UMBRA_BUILDKIT_BUILDER}0
Driver Options:        image="${UMBRA_BUILDKIT_IMAGE}"
Status:                running
BuildKit version:      v${UMBRA_BUILDKIT_VERSION}
EOF
)"
  umbra_builder_runtime_valid "$fixture" \
    || fail "expected the exact pinned one-node builder fixture to pass"
  pass "accepts only the running digest-pinned BuildKit runtime"
}

test_buildkit_pinned_runtime_failure() {
  local fixture healthy

  healthy="$(cat <<EOF
Name:          ${UMBRA_BUILDKIT_BUILDER}
Driver:        docker-container

Nodes:
Name:                  ${UMBRA_BUILDKIT_BUILDER}0
Driver Options:        image="${UMBRA_BUILDKIT_IMAGE}"
Status:                running
BuildKit version:      v${UMBRA_BUILDKIT_VERSION}
EOF
)"
  for fixture in \
    "${healthy/BuildKit version:      v${UMBRA_BUILDKIT_VERSION}/BuildKit version:      v0.32.2-rc1}" \
    "${healthy/Status:                running/Status:                inactive}" \
    "${healthy/${UMBRA_BUILDKIT_IMAGE}/moby\/buildkit:latest}" \
    "${healthy}"$'\nName:                  extra-node\nStatus:                error\nError:                 dial failed'; do
    if umbra_builder_runtime_valid "$fixture"; then
      fail "expected mismatched, inactive, mutable, or errored builder fixture to fail"
    fi
  done
  pass "rejects version drift, inactive nodes, mutable images, and partial multi-node failure"
}

test_dry_run_skips_builder_bootstrap() {
  local output rc

  set +e
  # shellcheck disable=SC2016 # The inner shell defines a deterministic Docker fixture.
  output="$(env -i PATH="$TEST_BIN" bash -c '
    source "$1"
    DRY_RUN=1
    OS=linux
    docker() {
      case "$*" in
        "buildx version")
          printf "%s\n" "github.com/docker/buildx v0.34.0 fixture"
          ;;
        "compose version")
          return 0
          ;;
        *)
          printf "unexpected Docker mutation during dry-run: %s\n" "$*" >&2
          return 97
          ;;
      esac
    }
    ensure_docker
  ' _ "$SCRIPT" 2>&1)"
  rc=$?
  set -e

  [ "$rc" -eq 0 ] || fail "dry-run must not bootstrap a builder, got: $output"
  contains "dry-run skipped live builder bootstrap" "$output" \
    || fail "dry-run must explain that builder bootstrap was skipped, got: $output"
  pass "does not bootstrap or mutate the Docker builder during dry-run"
}

test_buildx_apt_candidate_selection() {
  local selected

  selected="$(
    (
      # shellcheck source=ops/host/provision-host.sh
      source "$SCRIPT"
      DRY_RUN=0
      apt_package_available() { return 0; }
      apt_package_candidate_version() {
        case "$1" in
          docker-buildx) printf '%s\n' '0.36.0-0ubuntu1' ;;
          docker-buildx-plugin) printf '%s\n' '5:0.34.0-1~ubuntu.22.04~jammy' ;;
          *) return 1 ;;
        esac
      }
      install_package() { printf '%s\n' "$1"; }
      install_supported_buildx_apt_package docker-buildx docker-buildx-plugin
    )
  )"
  [ "$selected" = 'docker-buildx-plugin=5:0.34.0-1~ubuntu.22.04~jammy' ] \
    || fail "an available old Buildx package shadowed the compliant candidate: $selected"
  pass "selects only a signed package for the exactly pinned Buildx client"
}

test_attested_index_descriptors() {
  local attestation_digest attestation_manifest git_sha healthy image_config
  local output provenance_digest provenance_statement runtime_digest sbom_digest
  local sbom_statement source_date_epoch variant

  runtime_digest="sha256:$(printf '1%.0s' {1..64})"
  attestation_digest="sha256:$(printf '2%.0s' {1..64})"
  healthy="$(jq -cn \
    --arg runtime "$runtime_digest" \
    --arg attestation "$attestation_digest" '
      {
        schemaVersion: 2,
        mediaType: "application/vnd.oci.image.index.v1+json",
        manifests: [
          {
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: $runtime,
            platform: {os: "linux", architecture: "amd64"}
          },
          {
            mediaType: "application/vnd.oci.image.manifest.v1+json",
            digest: $attestation,
            platform: {os: "unknown", architecture: "unknown"},
            annotations: {
              "vnd.docker.reference.type": "attestation-manifest",
              "vnd.docker.reference.digest": $runtime
            }
          }
        ]
      }
    ')"
  output="$(printf '%s' "$healthy" | umbra_attested_index_descriptors)" \
    || fail "expected the pinned builder's attested index shape to pass"
  [ "$(printf '%s' "$output" | jq -r '.runtime_digest')" = "$runtime_digest" ] \
    || fail "attested index selector returned the wrong runtime digest"

  for variant in \
    "$(printf '%s' "$healthy" | jq -c 'del(.manifests[1])')" \
    "$(printf '%s' "$healthy" | jq -c '.manifests += [.manifests[0]]')" \
    "$(printf '%s' "$healthy" | jq -c '.manifests += [{mediaType:"application/vnd.oci.image.manifest.v1+json",digest:"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",platform:{os:"unknown",architecture:"unknown"}}]')" \
    "$(printf '%s' "$healthy" | jq -c '.manifests[1].annotations["vnd.docker.reference.digest"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"')" \
    "$(printf '%s' "$healthy" | jq -c '.mediaType = "application/vnd.docker.distribution.manifest.list.v2+json"')"; do
    if printf '%s' "$variant" | umbra_attested_index_descriptors >/dev/null 2>&1; then
      fail "expected a missing, ambiguous, detached, or non-OCI attested index to fail"
    fi
  done

  git_sha="$(printf '3%.0s' {1..40})"
  image_config="$(jq -cn \
    --arg git_sha "$git_sha" \
    --arg source "$UMBRA_BUILD_SOURCE_REPOSITORY_URL" '
      {
        architecture: "amd64",
        os: "linux",
        config: {Labels: {
          "org.opencontainers.image.revision": $git_sha,
          "org.opencontainers.image.source": $source
        }}
      }
    ')"
  printf '%s' "$image_config" | umbra_runtime_image_config_valid "$git_sha" \
    || fail "expected exact runtime source labels to pass"
  for variant in \
    "$(printf '%s' "$image_config" | jq -c 'del(.config.Labels["org.opencontainers.image.revision"])')" \
    "$(printf '%s' "$image_config" | jq -c '.config.Labels["org.opencontainers.image.source"] = "https://example.invalid/repository"')" \
    "$(printf '%s' "$image_config" | jq -c '.architecture = "arm64"')"; do
    if printf '%s' "$variant" | umbra_runtime_image_config_valid "$git_sha"; then
      fail "expected missing or mismatched runtime source metadata to fail"
    fi
  done

  provenance_digest="sha256:$(printf '8%.0s' {1..64})"
  sbom_digest="sha256:$(printf '9%.0s' {1..64})"
  attestation_manifest="$(jq -cn \
    --arg provenance "$provenance_digest" \
    --arg runtime "$runtime_digest" \
    --arg sbom "$sbom_digest" '
    {
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      artifactType: "application/vnd.docker.attestation.manifest.v1+json",
      subject: {digest: $runtime},
      layers: [
        {
          mediaType: "application/vnd.in-toto+json",
          digest: $sbom,
          annotations: {"in-toto.io/predicate-type": "https://spdx.dev/Document"}
        },
        {
          mediaType: "application/vnd.in-toto+json",
          digest: $provenance,
          annotations: {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"}
        }
      ]
    }
  ')"
  printf '%s' "$attestation_manifest" | umbra_attestation_manifest_valid "$runtime_digest" \
    || fail "expected subject-bound SBOM and provenance predicates to pass"
  for variant in \
    "$(printf '%s' "$attestation_manifest" | jq -c 'del(.layers[0])')" \
    "$(printf '%s' "$attestation_manifest" | jq -c '.subject.digest = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"')" \
    "$(printf '%s' "$attestation_manifest" | jq -c '.layers += [.layers[0]]')"; do
    if printf '%s' "$variant" | umbra_attestation_manifest_valid "$runtime_digest"; then
      fail "expected incomplete, detached, or ambiguous release attestations to fail"
    fi
  done

  source_date_epoch=1700000000
  provenance_statement="$(jq -cn \
    --arg compatibility "$UMBRA_BUILDKIT_COMPATIBILITY_VERSION" \
    --arg epoch "$source_date_epoch" \
    --arg frontend "$UMBRA_DOCKERFILE_FRONTEND_IMAGE" \
    --arg frontend_digest "$UMBRA_DOCKERFILE_FRONTEND_DIGEST" \
    --arg git_sha "$git_sha" \
    --arg sbom_digest "$UMBRA_SBOM_GENERATOR_DIGEST" \
    --arg source "$UMBRA_BUILD_SOURCE_REPOSITORY_URL" '
      {
        _type: "https://in-toto.io/Statement/v1",
        predicateType: "https://slsa.dev/provenance/v1",
        subject: [],
        predicate: {buildDefinition: {
          buildType: "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
          resolvedDependencies: [
            {digest: {sha256: $frontend_digest}},
            {digest: {sha256: $sbom_digest}}
          ],
          externalParameters: {request: {
            frontend: "gateway.v0",
            compatibilityVersion: ($compatibility | tonumber),
            args: {
              "build-arg:SOURCE_DATE_EPOCH": $epoch,
              "build-arg:HTTP_PROXY": "",
              "build-arg:HTTPS_PROXY": "",
              "build-arg:FTP_PROXY": "",
              "build-arg:NO_PROXY": "",
              "build-arg:ALL_PROXY": "",
              "build-arg:http_proxy": "",
              "build-arg:https_proxy": "",
              "build-arg:ftp_proxy": "",
              "build-arg:no_proxy": "",
              "build-arg:all_proxy": "",
              "label:org.opencontainers.image.revision": $git_sha,
              "label:org.opencontainers.image.source": $source,
              cmdline: $frontend
            }
          }}
        }}
      }
    ')"
  printf '%s' "$provenance_statement" \
    | umbra_provenance_statement_valid "$git_sha" "$source_date_epoch" \
    || fail "expected pinned provenance inputs with empty proxy args to pass"
  if printf '%s' "$provenance_statement" \
    | jq -c '.predicate.buildDefinition.externalParameters.request.args["build-arg:HTTPS_PROXY"] = "http://user:secret@proxy.invalid"' \
    | umbra_provenance_statement_valid "$git_sha" "$source_date_epoch"; then
    fail "credential-bearing proxy build args must fail provenance validation"
  fi

  sbom_statement='{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://spdx.dev/Document","subject":[],"predicate":{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","packages":[{"name":"fixture"}]}}'
  printf '%s' "$sbom_statement" | umbra_sbom_statement_valid \
    || fail "expected a non-empty SPDX 2.3 statement to pass"
  if printf '%s' "$sbom_statement" | jq -c '.predicate.packages = []' \
    | umbra_sbom_statement_valid; then
    fail "an empty published SPDX package inventory must fail"
  fi
  pass "requires one source-labelled runtime with subject-bound SBOM and provenance"
}

test_nested_oci_layout_resolution() {
  local archive attestation_digest config_digest git_sha layout provenance_digest
  local result_digest runtime_digest sbom_digest source_date_epoch

  layout="${VERIFIER_FIXTURE}/oci-layout"
  archive="${VERIFIER_FIXTURE}/oci-layout.tar"
  mkdir -p "${layout}/blobs/sha256"
  result_digest="sha256:$(printf 'a%.0s' {1..64})"
  runtime_digest="sha256:$(printf 'b%.0s' {1..64})"
  attestation_digest="sha256:$(printf 'c%.0s' {1..64})"
  config_digest="sha256:$(printf 'd%.0s' {1..64})"
  provenance_digest="sha256:$(printf 'e%.0s' {1..64})"
  sbom_digest="sha256:$(printf 'f%.0s' {1..64})"
  git_sha="$(printf '1%.0s' {1..40})"
  source_date_epoch=1700000000

  jq -cn --arg result "$result_digest" '{
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.index.v1+json",
    manifests: [{mediaType: "application/vnd.oci.image.index.v1+json", digest: $result}]
  }' > "${layout}/index.json"
  jq -cn \
    --arg attestation "$attestation_digest" \
    --arg runtime "$runtime_digest" '{
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.index.v1+json",
      manifests: [
        {
          mediaType: "application/vnd.oci.image.manifest.v1+json",
          digest: $runtime,
          platform: {os: "linux", architecture: "amd64"}
        },
        {
          mediaType: "application/vnd.oci.image.manifest.v1+json",
          digest: $attestation,
          platform: {os: "unknown", architecture: "unknown"},
          annotations: {
            "vnd.docker.reference.type": "attestation-manifest",
            "vnd.docker.reference.digest": $runtime
          }
        }
      ]
    }' > "${layout}/blobs/sha256/${result_digest#sha256:}"
  jq -cn \
    --arg provenance "$provenance_digest" \
    --arg runtime "$runtime_digest" \
    --arg sbom "$sbom_digest" '{
      schemaVersion: 2,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      artifactType: "application/vnd.docker.attestation.manifest.v1+json",
      subject: {digest: $runtime},
      layers: [
        {
          mediaType: "application/vnd.in-toto+json",
          digest: $sbom,
          annotations: {"in-toto.io/predicate-type": "https://spdx.dev/Document"}
        },
        {
          mediaType: "application/vnd.in-toto+json",
          digest: $provenance,
          annotations: {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"}
        }
      ]
    }' > "${layout}/blobs/sha256/${attestation_digest#sha256:}"
  jq -cn --arg config "$config_digest" '{
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    config: {digest: $config}
  }' > "${layout}/blobs/sha256/${runtime_digest#sha256:}"
  printf '{}\n' > "${layout}/blobs/sha256/${config_digest#sha256:}"
  printf '{}\n' > "${layout}/blobs/sha256/${provenance_digest#sha256:}"
  printf '{}\n' > "${layout}/blobs/sha256/${sbom_digest#sha256:}"
  tar -cf "$archive" -C "$layout" index.json blobs

  umbra_oci_layout_blob_valid() { return 0; }
  umbra_provenance_statement_valid() { cat >/dev/null; }
  umbra_sbom_statement_valid() { cat >/dev/null; }
  umbra_runtime_image_config_valid() { cat >/dev/null; }
  [ "$(umbra_oci_layout_result_digest "$archive")" = "$result_digest" ] \
    || fail "nested OCI layout did not return its full attested result digest"
  # shellcheck disable=SC2218 # The production definition comes from the sourced helper.
  [ "$(umbra_oci_layout_runtime_digest "$archive" "$git_sha" "$source_date_epoch")" = "$runtime_digest" ] \
    || fail "nested OCI layout did not resolve its attested linux/amd64 runtime"
  # Restore the actual content and metadata validators after isolating the layout seam.
  # shellcheck source=ops/buildkit-version.sh
  source "${REPO_ROOT}/ops/buildkit-version.sh"
  pass "resolves the pinned builder's nested attested OCI layout"
}

test_release_source_path_guards() {
  local git_sha path_fixture

  git_sha="$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')"
  umbra_release_source_objects_valid "$REPO_ROOT" "$git_sha" console/Dockerfile console \
    || fail "ordinary committed Dockerfile and context should pass"
  if umbra_release_source_objects_valid "$REPO_ROOT" "$git_sha" CLAUDE.md .; then
    fail "a committed Dockerfile symlink must be rejected"
  fi
  if umbra_release_source_objects_valid "$REPO_ROOT" "$git_sha" ../Dockerfile console; then
    fail "a repository-root escape must be rejected before checkout"
  fi

  path_fixture="${VERIFIER_FIXTURE}/path-guard"
  mkdir -p "${path_fixture}/root/context" "${path_fixture}/outside"
  printf 'FROM scratch\n' > "${path_fixture}/outside/Dockerfile"
  ln -s "${path_fixture}/outside/Dockerfile" "${path_fixture}/root/Dockerfile"
  if umbra_resolve_release_worktree_paths "${path_fixture}/root" Dockerfile context; then
    fail "a Dockerfile symlink escaping the detached root must be rejected"
  fi
  pass "rejects committed symlinks and paths escaping detached release roots"
}

test_publisher_credential_environment_boundary() {
  local helper

  # shellcheck source=ops/deploy/cvm-redeploy-lib.sh
  source "${REPO_ROOT}/ops/deploy/cvm-redeploy-lib.sh"
  (
    GHCR_USER=fixture-user
    GHCR_TOKEN=fixture-token
    export GHCR_USER GHCR_TOKEN
    cvm_redeploy_restore_publisher_credential GHCR_USER x "$GHCR_USER"
    cvm_redeploy_restore_publisher_credential GHCR_TOKEN x "$GHCR_TOKEN"
    [ "$GHCR_USER:$GHCR_TOKEN" = fixture-user:fixture-token ] \
      || fail "publisher credentials stopped being readable by the publisher shell"
    for helper in git phala builder; do
      HELPER_LABEL="$helper" bash -c '
        [ -z "${GHCR_USER:-}" ] && [ -z "${GHCR_TOKEN:-}" ]
      ' || fail "${helper} helper inherited a pre-login publisher credential"
    done
  )
  pass "keeps one-shot publisher credentials out of pre-login child environments"
}

test_release_publication_trust_boundary() {
  local ambient_config ambient_trap cleanup_dir cleanup_log default_builder git_sha
  local image_repo log_capture operation_log
  local output push_marker rc source_date_epoch source_url temporary_config_marker
  local valid_provenance_json valid_sbom_json

  # shellcheck source=ops/deploy/cvm-redeploy-lib.sh
  source "${REPO_ROOT}/ops/deploy/cvm-redeploy-lib.sh"
  git_sha="$(git -C "$REPO_ROOT" rev-parse --verify 'HEAD^{commit}')"
  source_date_epoch="$(git -C "$REPO_ROOT" show -s --format=%ct "$git_sha")"
  source_url="$(umbra_normalize_source_repository_url "$(git -C "$REPO_ROOT" remote get-url origin)")"
  UMBRA_BUILD_SOURCE_REPOSITORY_URL="$source_url"
  CVM_REDEPLOY_CLEAN_GIT_SHA="$git_sha"
  image_repo="ghcr.io/example/umbra"
  push_marker="${VERIFIER_FIXTURE}/registry-push"
  operation_log="${VERIFIER_FIXTURE}/publisher-operations"
  temporary_config_marker="${VERIFIER_FIXTURE}/publisher-docker-config"
  ambient_config="${VERIFIER_FIXTURE}/ambient-docker-config"
  mkdir -p "$ambient_config"
  printf 'ambient-config-must-not-change\n' > "${ambient_config}/config.json"
  export DOCKER_CONFIG="$ambient_config"
  FIXTURE_AMBIENT_DOCKER_CONFIG="$ambient_config"
  FIXTURE_LOCAL_RUNTIME_DIGEST="sha256:$(printf '4%.0s' {1..64})"
  FIXTURE_SECOND_RUNTIME_DIGEST="$FIXTURE_LOCAL_RUNTIME_DIGEST"
  FIXTURE_REMOTE_RUNTIME_DIGEST="$FIXTURE_LOCAL_RUNTIME_DIGEST"
  FIXTURE_ATTESTATION_DIGEST="sha256:$(printf '5%.0s' {1..64})"
  FIXTURE_INDEX_DIGEST="sha256:$(printf '6%.0s' {1..64})"
  FIXTURE_SECOND_INDEX_DIGEST="$FIXTURE_INDEX_DIGEST"
  FIXTURE_PUBLISHED_INDEX_DIGEST="$FIXTURE_INDEX_DIGEST"
  FIXTURE_PROVENANCE_DIGEST="sha256:$(printf '8%.0s' {1..64})"
  FIXTURE_SBOM_DIGEST="sha256:$(printf '9%.0s' {1..64})"
  FIXTURE_PUSH_MARKER="$push_marker"
  FIXTURE_OPERATION_LOG="$operation_log"
  FIXTURE_CONFIG_PATH_MARKER="$temporary_config_marker"
  FIXTURE_DOCKER_STDERR="fixture-provider-secret-and-private-path"
  FIXTURE_BUILD_FAILURE=0
  FIXTURE_IMAGETOOLS_FAILURE=0
  FIXTURE_LOGIN_FAILURE=0
  FIXTURE_CLEANUP_FAILURE=0
  FIXTURE_CREDENTIAL_LEAK_MARKER="${VERIFIER_FIXTURE}/credential-leak"
  FIXTURE_TAG_ARGUMENT_MARKER="${VERIFIER_FIXTURE}/tag-argument"
  FIXTURE_BUILD_ARGS_SOURCE=""
  FIXTURE_BUILD_ARGS_BUILDER=""
  FIXTURE_ORIGIN_ADVERTISES=1
  default_builder="$UMBRA_BUILDKIT_BUILDER"
  FIXTURE_IMAGE_CONFIG="$(jq -cn \
    --arg git_sha "$git_sha" \
    --arg source "$source_url" '{
      architecture: "amd64",
      os: "linux",
      config: {Labels: {
        "org.opencontainers.image.revision": $git_sha,
        "org.opencontainers.image.source": $source
      }}
    }')"
  FIXTURE_ATTESTATION_JSON="$(jq -cn \
    --arg provenance "$FIXTURE_PROVENANCE_DIGEST" \
    --arg runtime "$FIXTURE_LOCAL_RUNTIME_DIGEST" \
    --arg sbom "$FIXTURE_SBOM_DIGEST" '{
    schemaVersion: 2,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    artifactType: "application/vnd.docker.attestation.manifest.v1+json",
    subject: {digest: $runtime},
    layers: [
      {
        mediaType: "application/vnd.in-toto+json",
        digest: $sbom,
        annotations: {"in-toto.io/predicate-type": "https://spdx.dev/Document"}
      },
      {
        mediaType: "application/vnd.in-toto+json",
        digest: $provenance,
        annotations: {"in-toto.io/predicate-type": "https://slsa.dev/provenance/v1"}
      }
    ]
  }')"
  FIXTURE_PROVENANCE_JSON="$(jq -cn \
    --arg compatibility "$UMBRA_BUILDKIT_COMPATIBILITY_VERSION" \
    --arg epoch "$source_date_epoch" \
    --arg frontend "$UMBRA_DOCKERFILE_FRONTEND_IMAGE" \
    --arg frontend_digest "$UMBRA_DOCKERFILE_FRONTEND_DIGEST" \
    --arg git_sha "$git_sha" \
    --arg sbom_digest "$UMBRA_SBOM_GENERATOR_DIGEST" \
    --arg source "$source_url" '{
      "linux/amd64": {SLSA: {buildDefinition: {
        buildType: "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
        resolvedDependencies: [
          {digest: {sha256: $frontend_digest}},
          {digest: {sha256: $sbom_digest}}
        ],
        externalParameters: {request: {
          frontend: "gateway.v0",
          compatibilityVersion: ($compatibility | tonumber),
          args: {
            "build-arg:SOURCE_DATE_EPOCH": $epoch,
            "build-arg:HTTP_PROXY": "",
            "build-arg:HTTPS_PROXY": "",
            "build-arg:FTP_PROXY": "",
            "build-arg:NO_PROXY": "",
            "build-arg:ALL_PROXY": "",
            "build-arg:http_proxy": "",
            "build-arg:https_proxy": "",
            "build-arg:ftp_proxy": "",
            "build-arg:no_proxy": "",
            "build-arg:all_proxy": "",
            "label:org.opencontainers.image.revision": $git_sha,
            "label:org.opencontainers.image.source": $source,
            cmdline: $frontend
          }
        }}
      }}}
    }')"
  FIXTURE_SBOM_JSON='{"linux/amd64":{"SPDX":{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","packages":[{"name":"fixture"}]}}}'

  umbra_require_reproducible_builder() { return 0; }
  umbra_prepare_reproducible_build_args() {
    FIXTURE_BUILD_ARGS_SOURCE="$UMBRA_BUILD_SOURCE_REPOSITORY_URL"
    FIXTURE_BUILD_ARGS_BUILDER="$UMBRA_BUILDKIT_BUILDER"
    UMBRA_REPRODUCIBLE_BUILD_ARGS=(--builder "$UMBRA_BUILDKIT_BUILDER")
  }
  cvm_redeploy_origin_advertises_commit() {
    [ "$1" = "$git_sha" ] && [ "$FIXTURE_ORIGIN_ADVERTISES" -eq 1 ]
  }
  umbra_oci_layout_result_digest() {
    case "$1" in
      *second-release.oci.tar) printf '%s\n' "$FIXTURE_SECOND_INDEX_DIGEST" ;;
      *) printf '%s\n' "$FIXTURE_INDEX_DIGEST" ;;
    esac
  }
  umbra_oci_layout_runtime_digest() {
    [ "$2" = "$git_sha" ] && [ "$3" = "$source_date_epoch" ] || return 1
    case "$1" in
      *second-release.oci.tar) printf '%s\n' "$FIXTURE_SECOND_RUNTIME_DIGEST" ;;
      *) printf '%s\n' "$FIXTURE_LOCAL_RUNTIME_DIGEST" ;;
    esac
  }
  cvm_redeploy_info() { :; }
  docker() {
    local fixture_arg fixture_metadata_file="" fixture_no_cache=0
    local fixture_output="" fixture_password

    if [ "${DOCKER_CONFIG:-}" = "$FIXTURE_AMBIENT_DOCKER_CONFIG" ] \
      || [ -n "${GHCR_USER:-}" ] || [ -n "${GHCR_TOKEN:-}" ]; then
      : > "$FIXTURE_CREDENTIAL_LEAK_MARKER"
      return 91
    fi
    [ "$(stat -c '%a' "$DOCKER_CONFIG")" = 700 ] || return 92
    printf '%s\n' "$DOCKER_CONFIG" > "$FIXTURE_CONFIG_PATH_MARKER"
    if [ -n "$FIXTURE_DOCKER_STDERR" ]; then
      printf '%s\n' "$FIXTURE_DOCKER_STDERR" >&2
    fi
    case "$1 $2" in
      "login ghcr.io")
        printf '%s\n' login >> "$FIXTURE_OPERATION_LOG"
        fixture_password="$(cat)"
        [ "$fixture_password" = fixture-token ] || return 93
        [ "$FIXTURE_LOGIN_FAILURE" -eq 0 ] || return 1
        printf '%s\n' fixture-token > "${DOCKER_CONFIG}/config.json"
        return 0
        ;;
      "manifest inspect")
        return 1
        ;;
      "buildx rm")
        printf '%s\n' builder-cleanup >> "$FIXTURE_OPERATION_LOG"
        [ "$4" = "$FIXTURE_BUILD_ARGS_BUILDER" ] \
          && [ "$4" != "$default_builder" ] || return 98
        [ "$FIXTURE_CLEANUP_FAILURE" -eq 0 ]
        ;;
      "buildx build")
        for fixture_arg in "$@"; do
          [ "$fixture_arg" = --no-cache ] && fixture_no_cache=1
          case "$fixture_arg" in
            --tag | -t) : > "$FIXTURE_TAG_ARGUMENT_MARKER" ;;
            type=oci,*) fixture_output=oci ;;
            type=registry,*) fixture_output=registry ;;
          esac
        done
        [ "$fixture_no_cache" -eq 1 ] || return 94
        [ "$FIXTURE_BUILD_FAILURE" -eq 0 ] || return 1
        if [ "$fixture_output" = registry ]; then
          printf '%s\n' registry-build >> "$FIXTURE_OPERATION_LOG"
          contains "type=registry,name=${image_repo},push-by-digest=true" "$*" \
            || return 95
          while [ "$#" -gt 0 ]; do
            if [ "$1" = --metadata-file ]; then
              fixture_metadata_file="$2"
              break
            fi
            shift
          done
          [ -n "$fixture_metadata_file" ] || return 96
          jq -cn \
            --arg digest "$FIXTURE_PUBLISHED_INDEX_DIGEST" '{
              "containerimage.digest": $digest,
              "containerimage.descriptor": {
                mediaType: "application/vnd.oci.image.index.v1+json",
                digest: $digest
              }
            }' > "$fixture_metadata_file"
          : > "$FIXTURE_PUSH_MARKER"
        elif [ "$fixture_output" = oci ]; then
          printf '%s\n' local-build >> "$FIXTURE_OPERATION_LOG"
        else
          return 97
        fi
        ;;
      "buildx imagetools")
        [ "$FIXTURE_IMAGETOOLS_FAILURE" -eq 0 ] || return 1
        [ "$3" = inspect ] || return 1
        if [ "$4" = "${image_repo}@${FIXTURE_PUBLISHED_INDEX_DIGEST}" ] && [ "$5" = --raw ]; then
          jq -cn \
            --arg runtime "$FIXTURE_REMOTE_RUNTIME_DIGEST" \
            --arg attestation "$FIXTURE_ATTESTATION_DIGEST" '{
              schemaVersion: 2,
              mediaType: "application/vnd.oci.image.index.v1+json",
              manifests: [
                {
                  mediaType: "application/vnd.oci.image.manifest.v1+json",
                  digest: $runtime,
                  platform: {os: "linux", architecture: "amd64"}
                },
                {
                  mediaType: "application/vnd.oci.image.manifest.v1+json",
                  digest: $attestation,
                  platform: {os: "unknown", architecture: "unknown"},
                  annotations: {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": $runtime
                  }
                }
              ]
            }'
        elif [ "$4" = "${image_repo}@${FIXTURE_PUBLISHED_INDEX_DIGEST}" ] \
          && [ "$5" = --format ] && [ "$6" = '{{json .Provenance}}' ]; then
          printf '%s\n' "$FIXTURE_PROVENANCE_JSON"
        elif [ "$4" = "${image_repo}@${FIXTURE_PUBLISHED_INDEX_DIGEST}" ] \
          && [ "$5" = --format ] && [ "$6" = '{{json .SBOM}}' ]; then
          printf '%s\n' "$FIXTURE_SBOM_JSON"
        elif [ "$4" = "${image_repo}@${FIXTURE_REMOTE_RUNTIME_DIGEST}" ] \
          && [ "$5" = --format ]; then
          printf '%s\n' "$FIXTURE_IMAGE_CONFIG"
        elif [ "$4" = "${image_repo}@${FIXTURE_ATTESTATION_DIGEST}" ] \
          && [ "$5" = --raw ]; then
          printf '%s\n' "$FIXTURE_ATTESTATION_JSON"
        else
          return 1
        fi
        ;;
      *) return 1 ;;
    esac
  }

  log_capture="${VERIFIER_FIXTURE}/publisher.stderr"
  : > "$operation_log"
  ambient_trap="$(trap -p EXIT)"
  GHCR_USER=fixture-user GHCR_TOKEN=fixture-token \
    cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64 \
      2>"$log_capture"
  [ "$(trap -p EXIT)" = "$ambient_trap" ] \
    || fail "successful publication did not restore the preexisting EXIT trap"
  [ "$DOCKER_CONFIG" = "$ambient_config" ] \
    || fail "successful publication did not restore ambient DOCKER_CONFIG state"
  case "$(declare -p DOCKER_CONFIG 2>/dev/null || true)" in
    declare\ -x*) ;;
    *)
      fail "successful publication did not restore ambient DOCKER_CONFIG as exported"
      ;;
  esac
  bash -c 'test "${DOCKER_CONFIG-}" = "$1"' _ "$ambient_config" \
    || fail "successful publication did not preserve ambient DOCKER_CONFIG for child shells"
  [ "$UMBRA_BUILDKIT_BUILDER" = "$default_builder" ] \
    || fail "successful publication did not restore the configured builder name"
  [[ "$FIXTURE_BUILD_ARGS_BUILDER" =~ ^umbra-release-${git_sha:0:12}-[0-9]+$ ]] \
    || fail "publication did not use a unique per-run isolated builder"
  [ "$(<"${ambient_config}/config.json")" = ambient-config-must-not-change ] \
    || fail "publication read or modified the ambient Docker auth config"
  [ ! -e "$(<"$temporary_config_marker")" ] \
    || fail "successful publication left its credential-bearing Docker config"
  [ ! -e "$FIXTURE_CREDENTIAL_LEAK_MARKER" ] \
    || fail "a downstream Docker command inherited GHCR credentials or ambient config"
  [ ! -e "$FIXTURE_TAG_ARGUMENT_MARKER" ] \
    || fail "digest-only publication supplied a mutable tag argument"
  [ "$(grep -c '^local-build$' "$operation_log")" -eq 2 ] \
    || fail "an existing index must perform two independent local builds"
  [ "$(grep -c '^registry-build$' "$operation_log" || true)" -eq 1 ] \
    || fail "an existing index must still publish once by digest"
  [ "$FIXTURE_BUILD_ARGS_SOURCE" = "$source_url" ] \
    || fail "the explicit fork source identity was not captured for build labels"
  [ "$CVM_REDEPLOY_IMAGE_REF" = "${image_repo}@${FIXTURE_LOCAL_RUNTIME_DIGEST}" ] \
    || fail "publication selected a runtime other than the locally reproduced subject"
  if contains "$FIXTURE_DOCKER_STDERR" "$(<"$log_capture")"; then
    fail "provider-controlled Docker stderr reached successful publication output"
  fi

  : > "$operation_log"
  command rm -f -- "$push_marker" "$FIXTURE_TAG_ARGUMENT_MARKER"
  (
    # Bash reports an inherited EXIT trap inside a subshell but does not arm it,
    # so the publisher's restore/chain would re-arm this file's `cleanup` here and
    # delete VERIFIER_FIXTURE and TEST_BIN when this subshell exits. Every
    # subshell publication that reaches that restore/chain disarms it first.
    builtin trap - EXIT
    FIXTURE_DOCKER_STDERR=
    DOCKER_CONFIG="$ambient_config"
    export -n DOCKER_CONFIG
    GHCR_USER=fixture-user GHCR_TOKEN=fixture-token \
      cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64 >/dev/null
    [ "$DOCKER_CONFIG" = "$ambient_config" ] \
      || fail "successful publication did not restore unexported ambient DOCKER_CONFIG"
    case "$(declare -p DOCKER_CONFIG 2>/dev/null || true)" in
      declare\ -x*) fail "successful publication restored unexported DOCKER_CONFIG as exported";;
    esac
    bash -c 'test -z "${DOCKER_CONFIG+x}"' \
      || fail "unexported ambient DOCKER_CONFIG should not leak into child shells"
  )

  set +e
  output="$(
    CVM_REDEPLOY_CLEAN_GIT_SHA="$git_sha" \
      UMBRA_BUILD_SOURCE_REPOSITORY_URL="$source_url" \
      cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64 2>&1
  )"
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || fail "missing publisher credentials must fail"
  contains "provide publisher credentials through the process environment" "$output" \
    || fail "missing publisher credentials did not give process-scoped guidance: $output"
  if contains '.env' "$output"; then
    fail "missing publisher credentials must not direct users to persistent .env files"
  fi

  : > "$operation_log"
  set +e
  output="$(
    CVM_REDEPLOY_CLEAN_GIT_SHA="$(printf '0%.0s' {1..40})" \
      GHCR_USER=fixture-user GHCR_TOKEN=fixture-token \
      cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64 2>&1
  )"
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || fail "a HEAD different from the clean-tree capture must fail"
  contains "HEAD changed after the clean-tree guard" "$output" \
    || fail "moved HEAD did not report the atomic source-capture boundary: $output"
  [ ! -s "$operation_log" ] || fail "moved HEAD reached Docker or the registry"
  CVM_REDEPLOY_CLEAN_GIT_SHA="$git_sha"

  : > "$operation_log"
  set +e
  output="$(
    UMBRA_BUILD_SOURCE_REPOSITORY_URL=https://example.invalid/not-this-origin \
      GHCR_USER=fixture-user GHCR_TOKEN=fixture-token \
      cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64 2>&1
  )"
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || fail "a checkout labelled as another repository must fail"
  contains "must explicitly match this checkout's origin repository" "$output" \
    || fail "fork source mismatch did not report its source-identity boundary: $output"
  [ ! -s "$operation_log" ] || fail "a false canonical source label reached Docker"

  FIXTURE_ORIGIN_ADVERTISES=0
  : > "$operation_log"
  set +e
  output="$(
    builtin trap - EXIT
    GHCR_USER=fixture-user GHCR_TOKEN=fixture-token \
      cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64 2>&1
  )"
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || fail "an unadvertised local commit must not be published"
  contains "not advertised by an origin head or tag" "$output" \
    || fail "unadvertised source did not report its provenance boundary: $output"
  [ ! -s "$operation_log" ] \
    || fail "an unadvertised source commit reached Docker or the registry"
  FIXTURE_ORIGIN_ADVERTISES=1

  FIXTURE_SECOND_INDEX_DIGEST="sha256:$(printf 'a%.0s' {1..64})"
  : > "$operation_log"
  command rm -f -- "$push_marker" "$FIXTURE_TAG_ARGUMENT_MARKER"
  GHCR_USER=fixture-user GHCR_TOKEN=fixture-token \
    cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64
  [ "$(grep -c '^local-build$' "$operation_log")" -eq 2 ] \
    && [ "$(grep -c '^registry-build$' "$operation_log" || true)" -eq 1 ] \
    || fail "index-nondeterminism must only affect index digests, not publishability"
  [ "$(grep -c '^local-build$' "$operation_log")" -eq 2 ] \
    || fail "index-nondeterminism changed local reproducibility checkpoints"
  [ "$CVM_REDEPLOY_IMAGE_REF" = "${image_repo}@${FIXTURE_LOCAL_RUNTIME_DIGEST}" ] \
    || fail "publication selected an unexpected runtime with index-nondeterminism"
  FIXTURE_SECOND_INDEX_DIGEST="$FIXTURE_INDEX_DIGEST"
  FIXTURE_DOCKER_STDERR=""

  FIXTURE_SECOND_RUNTIME_DIGEST="sha256:$(printf 'e%.0s' {1..64})"
  : > "$operation_log"
  command rm -f -- "$push_marker" "$FIXTURE_TAG_ARGUMENT_MARKER"
  set +e
  output="$(
    builtin trap - EXIT
    GHCR_USER=fixture-user GHCR_TOKEN=fixture-token \
      cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64 2>&1
  )"
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || fail "different runtime subjects must fail publication"
  contains "independent cache-disabled release builds produced different runtime digests" "$output" \
    || fail "runtime-digest mismatch did not report its trust boundary: $output"
  [ "$(grep -c '^local-build$' "$operation_log")" -eq 2 ] \
    || fail "runtime nondeterminism was not observed after two local builds"
  [ "$(grep -c -E '^(login|registry-build)$' "$operation_log" || true)" -eq 0 ] \
    || fail "runtime mismatch reached the registry"
  FIXTURE_SECOND_RUNTIME_DIGEST="$FIXTURE_LOCAL_RUNTIME_DIGEST"

  FIXTURE_PUBLISHED_INDEX_DIGEST="sha256:$(printf 'b%.0s' {1..64})"
  : > "$operation_log"
  command rm -f -- "$push_marker"
  GHCR_USER=fixture-user GHCR_TOKEN=fixture-token \
    cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64
  [ -e "$push_marker" ] || fail "a differing published index digest was not used to upload a result index"
  [ "$(grep -c '^local-build$' "$operation_log")" -eq 2 ] \
    && [ "$(grep -c '^registry-build$' "$operation_log")" -eq 1 ] \
    || fail "an existing local subject must still publish one digest-only registry build"
  [ ! -e "$FIXTURE_TAG_ARGUMENT_MARKER" ] \
    || fail "a differing published index digest path created a mutable tag"
  FIXTURE_PUBLISHED_INDEX_DIGEST="$FIXTURE_INDEX_DIGEST"

  FIXTURE_REMOTE_RUNTIME_DIGEST="sha256:$(printf '7%.0s' {1..64})"
  set +e
  output="$(
    builtin trap - EXIT
    GHCR_USER=fixture-user GHCR_TOKEN=fixture-token \
      cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64 2>&1
  )"
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || fail "a remote index with a different runtime digest must fail"
  contains "does not match the local detached-worktree build" "$output" \
    || fail "runtime digest mismatch did not report the local-build trust boundary: $output"
  FIXTURE_REMOTE_RUNTIME_DIGEST="$FIXTURE_LOCAL_RUNTIME_DIGEST"

  valid_provenance_json="$FIXTURE_PROVENANCE_JSON"
  FIXTURE_PROVENANCE_JSON='{"linux/amd64":{"SLSA":{}}}'
  set +e
  output="$(
    builtin trap - EXIT
    GHCR_USER=fixture-user GHCR_TOKEN=fixture-token \
      cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64 2>&1
  )"
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || fail "malformed normalized registry provenance must fail"
  contains "published provenance does not match" "$output" \
    || fail "malformed provenance did not report the predicate boundary: $output"

  # imagetools omits the platform wrapper for single-platform indexes (the
  # real GHCR shape for linux/amd64-only publishes); both predicate shapes
  # must be accepted.
  FIXTURE_PROVENANCE_JSON="$(printf '%s' "$valid_provenance_json" | jq -c '."linux/amd64"')"
  flat_sbom_saved="$FIXTURE_SBOM_JSON"
  FIXTURE_SBOM_JSON="$(printf '%s' "$flat_sbom_saved" | jq -c '."linux/amd64"')"
  (
    builtin trap - EXIT
    GHCR_USER=fixture-user GHCR_TOKEN=fixture-token \
      cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64 >/dev/null \
      || fail "publication rejected the single-platform flat provenance/SBOM shape"
  )
  FIXTURE_SBOM_JSON="$flat_sbom_saved"
  FIXTURE_PROVENANCE_JSON="$valid_provenance_json"

  valid_sbom_json="$FIXTURE_SBOM_JSON"
  FIXTURE_SBOM_JSON='{"linux/amd64":{"SPDX":{"spdxVersion":"SPDX-2.3","dataLicense":"CC0-1.0","packages":[]}}}'
  set +e
  output="$(
    builtin trap - EXIT
    GHCR_USER=fixture-user GHCR_TOKEN=fixture-token \
      cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64 2>&1
  )"
  rc=$?
  set -e
  [ "$rc" -ne 0 ] || fail "empty normalized registry SBOM must fail"
  contains "published SBOM is not a non-empty SPDX 2.3 document" "$output" \
    || fail "empty registry SBOM did not report the predicate boundary: $output"
  FIXTURE_SBOM_JSON="$valid_sbom_json"

  FIXTURE_BUILD_FAILURE=1
  command rm -f -- "${VERIFIER_FIXTURE}/chained-exit-trap"
  set +e
  (
    trap 'printf "%s\n" chained > "${VERIFIER_FIXTURE}/chained-exit-trap"' EXIT
    GHCR_USER=fixture-user GHCR_TOKEN=fixture-token \
      cvm_redeploy_publish_image "$image_repo" console/Dockerfile console linux/amd64
  ) >/dev/null 2>&1
  rc=$?
  set -e
  [ "$rc" -ne 0 ] && [ -e "${VERIFIER_FIXTURE}/chained-exit-trap" ] \
    || fail "failed publication did not chain its preexisting EXIT trap"
  FIXTURE_BUILD_FAILURE=0

  cleanup_dir="$(mktemp -d /tmp/umbra-cvm-release.XXXXXX)"
  cleanup_log="${VERIFIER_FIXTURE}/aggregate-cleanup"
  mkdir -p "${cleanup_dir}/first-worktree" "${cleanup_dir}/second-worktree" \
    "${cleanup_dir}/docker-config"
  chmod 0700 "${cleanup_dir}/docker-config"
  : > "$cleanup_log"
  : > "$operation_log"
  CVM_REDEPLOY_RELEASE_DIR="$cleanup_dir"
  CVM_REDEPLOY_RELEASE_WORKTREE="${cleanup_dir}/first-worktree"
  CVM_REDEPLOY_RELEASE_SECOND_WORKTREE="${cleanup_dir}/second-worktree"
  CVM_REDEPLOY_RELEASE_DOCKER_CONFIG="${cleanup_dir}/docker-config"
  CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG="$ambient_config"
  CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG_SET=x
  CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG_EXPORTED=x
  CVM_REDEPLOY_RELEASE_PREVIOUS_BUILDER="$default_builder"
  UMBRA_BUILDKIT_BUILDER="umbra-release-cleanup-fixture"
  FIXTURE_BUILD_ARGS_BUILDER="$UMBRA_BUILDKIT_BUILDER"
  CVM_REDEPLOY_RELEASE_BUILDER_CLEANUP_REQUIRED=1
  export DOCKER_CONFIG="$CVM_REDEPLOY_RELEASE_DOCKER_CONFIG"
  FIXTURE_CLEANUP_FAILURE=1
  git() {
    if [ "$1 $2" = "worktree remove" ]; then
      printf '%s\n' "$5" >> "$cleanup_log"
      return 1
    fi
    command git "$@"
  }
  set +e
  cvm_redeploy_cleanup_release_workspace
  rc=$?
  set -e
  unset -f git
  [ "$rc" -ne 0 ] || fail "cleanup must aggregate resource-removal failures"
  [ "$(wc -l < "$cleanup_log")" -eq 2 ] \
    || fail "cleanup stopped before attempting both detached worktrees"
  [ "$(grep -c '^builder-cleanup$' "$operation_log")" -eq 1 ] \
    || fail "cleanup did not attempt the isolated builder removal"
  [ ! -e "$cleanup_dir" ] \
    || fail "cleanup did not attempt the release-directory removal after worktree failures"
  [ "$DOCKER_CONFIG" = "$ambient_config" ] \
    && [ "$UMBRA_BUILDKIT_BUILDER" = "$default_builder" ] \
    || fail "failed cleanup did not restore ambient Docker and builder state"
  FIXTURE_CLEANUP_FAILURE=0

  unset -f docker umbra_require_reproducible_builder umbra_prepare_reproducible_build_args
  unset -f cvm_redeploy_origin_advertises_commit
  unset -f umbra_oci_layout_result_digest umbra_oci_layout_runtime_digest
  unset DOCKER_CONFIG
  unset FIXTURE_AMBIENT_DOCKER_CONFIG FIXTURE_ATTESTATION_DIGEST FIXTURE_ATTESTATION_JSON
  unset FIXTURE_BUILD_ARGS_BUILDER FIXTURE_BUILD_ARGS_SOURCE FIXTURE_BUILD_FAILURE
  unset FIXTURE_CLEANUP_FAILURE
  unset FIXTURE_CONFIG_PATH_MARKER FIXTURE_CREDENTIAL_LEAK_MARKER
  unset FIXTURE_DOCKER_STDERR
  unset FIXTURE_IMAGE_CONFIG FIXTURE_IMAGETOOLS_FAILURE FIXTURE_INDEX_DIGEST
  unset FIXTURE_LOCAL_RUNTIME_DIGEST FIXTURE_LOGIN_FAILURE FIXTURE_OPERATION_LOG
  unset FIXTURE_ORIGIN_ADVERTISES
  unset FIXTURE_PROVENANCE_DIGEST FIXTURE_PROVENANCE_JSON FIXTURE_PUBLISHED_INDEX_DIGEST
  unset FIXTURE_PUSH_MARKER FIXTURE_REMOTE_RUNTIME_DIGEST FIXTURE_SBOM_DIGEST
  unset FIXTURE_SBOM_JSON FIXTURE_SECOND_INDEX_DIGEST FIXTURE_SECOND_RUNTIME_DIGEST
  unset FIXTURE_TAG_ARGUMENT_MARKER
  # Restore the real parser and pinned source default after fixture overrides.
  unset UMBRA_BUILD_SOURCE_REPOSITORY_URL
  # shellcheck source=ops/buildkit-version.sh
  source "${REPO_ROOT}/ops/buildkit-version.sh"
  # shellcheck source=ops/deploy/cvm-redeploy-lib.sh
  source "${REPO_ROOT}/ops/deploy/cvm-redeploy-lib.sh"
  pass "publishes runtime-reproduced digest subjects with isolated credentials"
}

# run_provision_from PATH VAR=val ...  -> sets RC + OUT
run_provision_from() {
  local provision_path="$1"
  shift
  set +e
  OUT="$(env -i PATH="$provision_path" "$@" bash "$SCRIPT" 2>&1)"
  RC=$?
  set -e
}

run_provision() {
  run_provision_from "$TEST_BIN" "$@"
}

cat > "${TEST_BIN}/go-fixture" <<'EOF'
#!/bin/sh
printf 'go version go%s linux/amd64\n' "$FAKE_GO_VERSION"
EOF
chmod 0755 "${TEST_BIN}/go-fixture"

run_go_version_check() {
  local version="$1"
  set +e
  # shellcheck disable=SC2016 # The inner shell expands product helper variables.
  OUT="$(env -i \
    PATH="$TEST_BIN" \
    FAKE_GO_VERSION="$version" \
      bash -c '
        source "$1"
        actual="$(go_binary_version "$2")" || exit 2
        umbra_version_at_least "$actual" "$SLSA_VERIFIER_MIN_GO_VERSION"
      ' _ "$SCRIPT" "${TEST_BIN}/go-fixture" 2>&1)"
  RC=$?
  set -e
}

run_phala_version_output_check() {
  local output="$1"
  set +e
  # shellcheck disable=SC2016 # The inner shell expands product helper arguments.
  OUT="$(env -i \
    PATH="$TEST_BIN" \
    PHALA_CLI_VERSION="$PINNED_PHALA_VERSION" \
      bash -c '
        source "$1"
        phala_cli_version_output_matches "$2"
      ' _ "$SCRIPT" "$output" 2>&1)"
  RC=$?
  set -e
}

test_buildx_client_versions_success
test_buildx_client_versions_failure
test_buildkit_pinned_runtime_success
test_buildkit_pinned_runtime_failure
test_dry_run_skips_builder_bootstrap
test_buildx_apt_candidate_selection
test_attested_index_descriptors
test_nested_oci_layout_resolution
test_release_source_path_guards
test_publisher_credential_environment_boundary
test_release_publication_trust_boundary

# --- bootstrap trust boundary ----------------------------------------------
for forbidden in \
  get.docker.com \
  sh.rustup.rs \
  astral.sh/uv \
  deb.nodesource.com \
  cli.github.com/packages \
  githubcli-archive-keyring \
  /etc/apt/keyrings \
  /etc/apt/sources.list.d \
  apt-key \
  'gpg --dearmor'; do
  if grep -Fq "$forbidden" "$SCRIPT"; then
    fail "provisioner must not reference untrusted bootstrap source '${forbidden}'"
  fi
done

if grep -Eq '(curl|wget)[^|]*\|[^#]*(sh|bash)([[:space:]]|$)' "$SCRIPT"; then
  fail "provisioner must not pipe downloaded content to a shell"
fi
if grep -Eq 'npm[[:space:]]+install[[:space:]]+-g' "$SCRIPT"; then
  fail "Phala provisioning must use the committed dependency lock, not npm install -g"
fi
if grep -Fq 'command -v phala' "$SCRIPT"; then
  fail "Phala provisioning must not derive the privileged launcher from PATH"
fi
pass "contains no remote shell bootstrap or ad-hoc repository key setup"

# These non-dry runs use only inert command stubs. They prove unavailable apt
# packages stop provisioning with actionable guidance before any fallback.
run_provision_from "$FAIL_BIN" DRY_RUN=0 PROVISION_OS=linux PROVISION_PKG_MANAGER=apt SKIP_PACKAGE_MANAGER_CHECK=1
[ "$RC" -ne 0 ] || fail "missing signed Docker package must fail closed"
contains "no signed apt package is available for Docker Engine" "$OUT" \
  || fail "missing Docker package must give signed-source guidance, got: $OUT"

cat > "${FAIL_BIN}/docker" <<EOF
#!/bin/sh
case "\$*" in
  'buildx version')
    printf '%s\n' 'github.com/docker/buildx v0.34.0 fixture'
    ;;
  'buildx inspect ${UMBRA_BUILDKIT_BUILDER}'|'buildx inspect ${UMBRA_BUILDKIT_BUILDER} --bootstrap')
    printf '%s\n' \
      'Name:          ${UMBRA_BUILDKIT_BUILDER}' \
      'Driver:        docker-container' \
      '' \
      'Nodes:' \
      'Name:                  ${UMBRA_BUILDKIT_BUILDER}0' \
      'Driver Options:        image="${UMBRA_BUILDKIT_IMAGE}"' \
      'Status:                running' \
      'BuildKit version:      v${UMBRA_BUILDKIT_VERSION}'
    ;;
esac
exit 0
EOF
chmod 0755 "${FAIL_BIN}/docker"
run_provision_from "$FAIL_BIN" DRY_RUN=0 PROVISION_OS=linux PROVISION_PKG_MANAGER=apt SKIP_PACKAGE_MANAGER_CHECK=1
[ "$RC" -ne 0 ] || fail "missing signed rustup package must fail closed"
contains "no signed rustup package is available from configured apt sources" "$OUT" \
  || fail "missing rustup package must give preinstallation guidance, got: $OUT"

for command_name in cargo gh rustfmt uv; do
  ln -s "$(type -P true)" "${FAIL_BIN}/${command_name}"
done
cat > "${FAIL_BIN}/rustc" <<EOF
#!/bin/sh
printf 'rustc %s (fixture)\n' '${PINNED_RUST_VERSION}'
EOF
chmod 0755 "${FAIL_BIN}/rustc"
run_provision_from "$FAIL_BIN" \
  UMBRA_INSTALL_SLSA_VERIFIER="${FAIL_BIN}/not-installed" \
  DRY_RUN=0 \
  PROVISION_OS=linux \
  PROVISION_PKG_MANAGER=apt \
  SKIP_PACKAGE_MANAGER_CHECK=1
[ "$RC" -ne 0 ] || fail "missing signed versioned Go package must fail closed"
contains "signed apt package golang-1.24-go is unavailable" "$OUT" \
  || fail "missing versioned Go package must give Ubuntu signed-source guidance, got: $OUT"
pass "fails closed when configured apt sources lack required packages"

# --- input validation -------------------------------------------------------
run_provision DRY_RUN=maybe
[ "$RC" -ne 0 ] || fail "invalid DRY_RUN should abort"
contains "DRY_RUN must be" "$OUT" || fail "expected DRY_RUN validation message, got: $OUT"

run_provision DRY_RUN=1 PHALA_CLI_VERSION=1.2 PHALA_CLI_SHA256="$PINNED_PHALA_SHA256" PROVISION_OS=linux PROVISION_PKG_MANAGER=apt SKIP_PACKAGE_MANAGER_CHECK=1
[ "$RC" -ne 0 ] || fail "invalid PHALA_CLI_VERSION should abort"
contains "invalid PHALA_CLI_VERSION" "$OUT" || fail "expected PHALA_CLI_VERSION message, got: $OUT"

run_provision DRY_RUN=1 PHALA_CLI_VERSION="$PINNED_PHALA_VERSION" PROVISION_OS=linux PROVISION_PKG_MANAGER=apt SKIP_PACKAGE_MANAGER_CHECK=1
[ "$RC" -ne 0 ] || fail "Phala version without digest should abort"
contains "PHALA_CLI_SHA256 is required" "$OUT" || fail "expected missing Phala digest message, got: $OUT"

run_provision DRY_RUN=1 PHALA_CLI_SHA256="$PINNED_PHALA_SHA256" PROVISION_OS=linux PROVISION_PKG_MANAGER=apt SKIP_PACKAGE_MANAGER_CHECK=1
[ "$RC" -ne 0 ] || fail "Phala digest without version should abort"
contains "PHALA_CLI_VERSION is required" "$OUT" || fail "expected missing Phala version message, got: $OUT"

run_provision DRY_RUN=1 PHALA_CLI_VERSION="$PINNED_PHALA_VERSION" PHALA_CLI_SHA256=not-a-digest PROVISION_OS=linux PROVISION_PKG_MANAGER=apt SKIP_PACKAGE_MANAGER_CHECK=1
[ "$RC" -ne 0 ] || fail "invalid Phala digest should abort"
contains "invalid PHALA_CLI_SHA256" "$OUT" || fail "expected invalid Phala digest message, got: $OUT"
pass "rejects invalid and partial pinned-tool inputs"

# --- Phala exact version identity ------------------------------------------
for supported_phala_output in "$PINNED_PHALA_VERSION" "v${PINNED_PHALA_VERSION}" "v${PINNED_PHALA_VERSION}+d2300dd"; do
  run_phala_version_output_check "$supported_phala_output"
  [ "$RC" -eq 0 ] || fail "exact Phala output '${supported_phala_output}' should pass, got: $OUT"
done
for hostile_phala_output in \
  "v${PINNED_PHALA_VERSION}0" \
  "prefix-${PINNED_PHALA_VERSION}" \
  "v${PINNED_PHALA_VERSION}+" \
  "v${PINNED_PHALA_VERSION}+valid suffix" \
  "v${PINNED_PHALA_VERSION}"$'\nv999.0.0'; do
  run_phala_version_output_check "$hostile_phala_output"
  [ "$RC" -ne 0 ] || fail "non-exact Phala output '${hostile_phala_output}' should fail"
done
pass "requires an anchored exact Phala CLI version identity"

# --- Phala Node/npm environment isolation ----------------------------------
phala_fixture="${VERIFIER_FIXTURE}/phala"
phala_install_root="${phala_fixture}/install"
phala_hostile_marker="${phala_fixture}/node-options-ran"
phala_launcher="${phala_fixture}/launcher.js"
phala_fake_npm="${phala_fixture}/npm"
mkdir -p "$phala_fixture"
cat > "${phala_fixture}/hostile.cjs" <<EOF
require("node:fs").writeFileSync("${phala_hostile_marker}", "ambient NODE_OPTIONS executed");
EOF
cat > "$phala_launcher" <<EOF
#!/usr/bin/env node
if (process.env.PHALA_API_TOKEN || process.env.PHALA_CLOUD_API_KEY) process.exit(2);
process.stdout.write("v${PINNED_PHALA_VERSION}+d2300dd\\n");
EOF
chmod 0755 "$phala_launcher"
cat > "$phala_fake_npm" <<'EOF'
#!/bin/sh
set -eu
[ "${NODE_OPTIONS+x}" != x ]
[ "${NODE_PATH+x}" != x ]
[ "${NODE_EXTRA_CA_CERTS+x}" != x ]
[ "${PHALA_API_TOKEN+x}" != x ]
[ "${PHALA_CLOUD_API_KEY+x}" != x ]
[ "${SSL_CERT_FILE+x}" != x ]
[ "${CURL_CA_BUNDLE+x}" != x ]
[ "${HTTPS_PROXY+x}" != x ]
[ "${HTTP_PROXY+x}" != x ]
[ "${ALL_PROXY+x}" != x ]
[ "${NO_PROXY+x}" != x ]
[ "${https_proxy+x}" != x ]
[ "${http_proxy+x}" != x ]
[ "${all_proxy+x}" != x ]
[ "${no_proxy+x}" != x ]
[ "${npm_config_registry+x}" != x ]
[ "${npm_config_userconfig+x}" != x ]
[ "${npm_config_proxy+x}" != x ]
[ "${NPM_CONFIG_PROXY+x}" != x ]
[ "${NPM_CONFIG_HTTPS_PROXY+x}" != x ]
[ "${NPM_CONFIG_NODE_OPTIONS+x}" != x ]
[ "$NPM_CONFIG_REGISTRY" = https://registry.npmjs.org ]
[ "$NPM_CONFIG_REPLACE_REGISTRY_HOST" = never ]
[ "$NPM_CONFIG_STRICT_SSL" = true ]
[ "$1" = ci ]
[ "$2" = --prefix ]
install_root="$3"
[ "$HOME" = "${install_root}/npm-home" ]
[ "$TMPDIR" = "${install_root}/npm-tmp" ]
[ "$NPM_CONFIG_CACHE" = "${install_root}/npm-cache" ]
[ "$NPM_CONFIG_USERCONFIG" = "${install_root}/npm-userconfig" ]
[ "$NPM_CONFIG_GLOBALCONFIG" = "${install_root}/npm-globalconfig" ]
[ "$PATH" = "${PATH%%:*}:/usr/bin:/bin" ]
: > "${install_root}/npm-was-clean"
EOF
chmod 0755 "$phala_fake_npm"

set +e
# shellcheck disable=SC2016 # The inner shell expands product helper arguments.
OUT="$(env -i \
  PATH="$TEST_BIN" \
  PHALA_API_TOKEN=hostile-secret-must-not-reach-tools \
  PHALA_CLOUD_API_KEY=hostile-secret-must-not-reach-tools \
  NODE_OPTIONS="--require=${phala_fixture}/hostile.cjs" \
  NODE_PATH="${phala_fixture}/hostile-node-path" \
  NODE_EXTRA_CA_CERTS="${phala_fixture}/hostile-ca.pem" \
  NPM_CONFIG_NODE_OPTIONS="--require=${phala_fixture}/hostile.cjs" \
  NPM_CONFIG_REGISTRY=https://registry.example.invalid \
  NPM_CONFIG_USERCONFIG="${phala_fixture}/hostile-uppercase.npmrc" \
  NPM_CONFIG_GLOBALCONFIG="${phala_fixture}/hostile-global.npmrc" \
  NPM_CONFIG_PROXY=http://proxy.example.invalid \
  NPM_CONFIG_HTTPS_PROXY=http://proxy.example.invalid \
  npm_config_registry=https://registry.example.invalid \
  npm_config_userconfig="${phala_fixture}/hostile.npmrc" \
  HOME="${phala_fixture}/hostile-home" \
  TMPDIR="${phala_fixture}/hostile-tmp" \
  SSL_CERT_FILE="${phala_fixture}/hostile-ca.pem" \
  CURL_CA_BUNDLE="${phala_fixture}/hostile-ca.pem" \
  HTTPS_PROXY=http://proxy.example.invalid \
  HTTP_PROXY=http://proxy.example.invalid \
  ALL_PROXY=http://proxy.example.invalid \
  NO_PROXY=registry.npmjs.org \
    bash -c '
      source "$1"
      PHALA_CLI_VERSION="$2"
      PHALA_NODE_BINARY="$3"
      PHALA_NPM_BINARY="$4"
      phala_cli_version_ready "$5"
      sha512_integrity_file "$5" >/dev/null
      phala_path_resolves_to "$5" "$5"
      run_phala_npm_ci "$6"
    ' _ "$SCRIPT" "$PINNED_PHALA_VERSION" "$(type -P node)" "$phala_fake_npm" \
      "$phala_launcher" "$phala_install_root" 2>&1)"
RC=$?
set -e
[ "$RC" -eq 0 ] || fail "Phala Node/npm clean environment should pass, got: $OUT"
[ ! -e "$phala_hostile_marker" ] || fail "ambient NODE_OPTIONS executed during Phala verification"
[ -f "${phala_install_root}/npm-was-clean" ] || fail "isolated npm fixture did not run"
pass "isolates Phala Node/npm verification from hostile ambient configuration"

# --- slsa-verifier Go version floor ----------------------------------------
for supported_go_version in 1.23.2 1.24.0 2.0.0; do
  run_go_version_check "$supported_go_version"
  [ "$RC" -eq 0 ] \
    || fail "Go ${supported_go_version} should meet the slsa-verifier minimum, got: $OUT"
done
for unsupported_go_version in 1.23.1 1.22.9 devel; do
  run_go_version_check "$unsupported_go_version"
  [ "$RC" -ne 0 ] \
    || fail "Go ${unsupported_go_version} should not meet the slsa-verifier minimum"
done
pass "enforces the slsa-verifier Go >=1.23.2 floor"

# --- slsa-verifier authenticated rebuild -----------------------------------
fake_go="${VERIFIER_FIXTURE}/fake-go"
preexisting_verifier="${VERIFIER_FIXTURE}/installed/slsa-verifier"
mkdir -p "$(dirname "$preexisting_verifier")"
cat > "$preexisting_verifier" <<'EOF'
#!/bin/sh
: > "${0}.was-run"
printf 'slsa-verifier version 2.7.1\n'
EOF
chmod 0755 "$preexisting_verifier"

cat > "$fake_go" <<'EOF'
#!/bin/sh
set -eu
[ "$#" -eq 2 ]
[ "$1" = install ]
[ "$2" = github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.7.1 ]
[ "$PATH" = /usr/bin:/bin ]
[ "$CGO_ENABLED" = 0 ]
[ "${CC+x}:$CC" = x: ]
[ "${CXX+x}:$CXX" = x: ]
[ "$GOENV" = off ]
[ "${GOFLAGS+x}:$GOFLAGS" = x: ]
[ "$GOINSECURE" = "" ]
[ "$GOPRIVATE" = "" ]
[ "$GONOSUMDB" = "" ]
[ "$GONOPROXY" = "" ]
[ "$GOPROXY" = https://proxy.golang.org ]
[ "$GOSUMDB" = sum.golang.org ]
[ "$GOTOOLCHAIN" = local ]
[ "$GOVCS" = '*:off' ]
[ "$GOWORK" = off ]
[ -n "$GOBIN" ]
[ -n "$GOCACHE" ]
[ -n "$GOMODCACHE" ]
[ -n "$GOPATH" ]
[ -n "$GOTMPDIR" ]
[ -n "$HOME" ]
[ -n "$TMPDIR" ]
[ -z "${GOROOT+x}" ]
[ -z "${SLSA_HOSTILE_MARKER+x}" ]
: > "${0}.ran"
printf '%s\n' \
  '#!/bin/sh' \
  '[ "$1" = version ]' \
  "printf 'slsa-verifier version 2.7.1\\n'" \
  > "$GOBIN/slsa-verifier"
chmod 0755 "$GOBIN/slsa-verifier"
EOF
chmod 0755 "$fake_go"

set +e
# shellcheck disable=SC2016 # The inner shell expands sourced helper variables.
OUT="$(env -i \
  PATH="$TEST_BIN:/usr/bin:/bin" \
  UMBRA_INSTALL_SLSA_VERIFIER="$preexisting_verifier" \
  GOFLAGS="-toolexec=${VERIFIER_FIXTURE}/hostile-toolexec" \
  GOENV="${VERIFIER_FIXTURE}/hostile-goenv" \
  GOWORK="${VERIFIER_FIXTURE}/hostile-work" \
  GOROOT="${VERIFIER_FIXTURE}/hostile-goroot" \
  CC="${VERIFIER_FIXTURE}/hostile-cc" \
  CXX="${VERIFIER_FIXTURE}/hostile-cxx" \
  SLSA_HOSTILE_MARKER=present \
    bash -c '
      source "$1"
      OS=linux
      test_go_binary="$2"
      ensure_slsa_verifier_go() {
        SLSA_VERIFIER_GO_BINARY="$test_go_binary"
      }
      run() {
        if [ "$1" = sudo ]; then
          shift
        fi
        "$@"
      }
      ensure_slsa_verifier
    ' _ "$SCRIPT" "$fake_go" 2>&1)"
RC=$?
set -e
[ "$RC" -eq 0 ] || fail "authenticated verifier rebuild should succeed, got: $OUT"
[ -f "${fake_go}.ran" ] || fail "preexisting verifier bypassed the authenticated Go rebuild"
[ ! -e "${preexisting_verifier}.was-run" ] \
  || fail "preexisting verifier was trusted before the authenticated rebuild"
"$preexisting_verifier" version 2>/dev/null | grep -F '2.7.1' >/dev/null \
  || fail "authenticated verifier candidate was not installed"
pass "rebuilds the verifier under an isolated Go environment"

# --- forced OS / package-manager pairing ------------------------------------
run_provision DRY_RUN=1 PROVISION_OS=linux SKIP_PACKAGE_MANAGER_CHECK=1
[ "$RC" -ne 0 ] || fail "partial PROVISION_OS (no PKG_MANAGER) should abort"

run_provision DRY_RUN=1 PROVISION_OS=windows PROVISION_PKG_MANAGER=apt SKIP_PACKAGE_MANAGER_CHECK=1
[ "$RC" -ne 0 ] || fail "invalid PROVISION_OS should abort"

run_provision DRY_RUN=1 PROVISION_OS=macos PROVISION_PKG_MANAGER=apt SKIP_PACKAGE_MANAGER_CHECK=1
[ "$RC" -ne 0 ] || fail "mismatched macos/apt pair should abort"
pass "rejects partial / invalid / mismatched OS-pkgmanager"

# --- linux/apt dry-run installs dev packages unconditionally ----------------
run_provision DRY_RUN=1 PROVISION_OS=linux PROVISION_PKG_MANAGER=apt SKIP_PACKAGE_MANAGER_CHECK=1
[ "$RC" -eq 0 ] || fail "linux/apt dry-run should succeed, got rc=$RC: $OUT"
for pkg in ca-certificates build-essential libssl-dev; do
  contains "apt-get install -y --no-install-recommends ${pkg}" "$OUT" \
    || fail "linux/apt must always install '${pkg}' (regression guard), got: $OUT"
done
contains "signed apt package for Docker Engine: docker-ce docker.io" "$OUT" \
  || fail "linux/apt must select a signed Docker Engine package, got: $OUT"
contains "signed apt package providing Buildx ${UMBRA_BUILDX_VERSION}: docker-buildx-plugin docker-buildx" "$OUT" \
  || fail "linux/apt must select a signed supported Buildx package, got: $OUT"
contains "signed apt package for Docker Compose v2: docker-compose-plugin docker-compose-v2" "$OUT" \
  || fail "linux/apt must select a signed Compose v2 package, got: $OUT"
contains "apt-get install -y --no-install-recommends rustup" "$OUT" \
  || fail "linux/apt must use the configured rustup package, got: $OUT"
contains "rustup toolchain install ${PINNED_RUST_VERSION} --profile minimal --component rustfmt --component clippy" "$OUT" \
  || fail "rustup must install the repository-pinned toolchain and components, got: $OUT"
contains "apt-get install -y --no-install-recommends uv" "$OUT" \
  || fail "linux/apt must use the configured uv package, got: $OUT"
contains "signed apt package for GitHub CLI: gh" "$OUT" \
  || fail "linux/apt must use a configured signed GitHub CLI package, got: $OUT"
contains "apt-get install -y --no-install-recommends golang-1.24-go" "$OUT" \
  || fail "linux/apt must install the signed versioned Go toolchain for slsa-verifier, got: $OUT"
contains "use /usr/lib/go-1.24/bin/go and require Go >= 1.23.2" "$OUT" \
  || fail "linux/apt must use the versioned Go binary rather than Jammy's Go 1.18 default, got: $OUT"
contains "rebuild github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.7.1 with an isolated Go environment, CGO_ENABLED=0, GOENV=off, GOFLAGS empty, GOWORK=off, GOTOOLCHAIN=local, GOPROXY=https://proxy.golang.org, and GOSUMDB=sum.golang.org" "$OUT" \
  || fail "linux/apt must pin and isolate the authenticated verifier build, got: $OUT"
contains "install verified binary at /usr/local/bin/slsa-verifier" "$OUT" \
  || fail "linux/apt must provision the absolute verifier path used by deploys, got: $OUT"
pass "linux/apt uses signed configured packages and the pinned Rust toolchain"

# --- optional Linux Phala path does not add NodeSource ----------------------
run_provision DRY_RUN=1 PHALA_CLI_VERSION="$PINNED_PHALA_VERSION" PHALA_CLI_SHA256="$PINNED_PHALA_SHA256" PROVISION_OS=linux PROVISION_PKG_MANAGER=apt SKIP_PACKAGE_MANAGER_CHECK=1
[ "$RC" -eq 0 ] || fail "linux/apt Phala dry-run should succeed, got rc=$RC: $OUT"
contains "signed apt package for Node.js: nodejs" "$OUT" \
  || fail "linux/apt must select Node.js from configured apt sources, got: $OUT"
contains "ensure npm is bundled with Node.js or install the signed apt package npm" "$OUT" \
  || fail "linux/apt must require package-managed npm, got: $OUT"
contains "verify phala@${PINNED_PHALA_VERSION} against console/package.json and the complete console/package-lock.json dependency graph" "$OUT" \
  || fail "Phala install must use the committed package manifest and full dependency lock, got: $OUT"
contains "require tarball sha256 ${PINNED_PHALA_SHA256}" "$OUT" \
  || fail "Phala install must require and verify the configured tarball digest, got: $OUT"
contains "npm ci --omit=dev --ignore-scripts --no-audit --no-fund from the committed lock" "$OUT" \
  || fail "Phala install must use npm ci with scripts disabled, got: $OUT"
contains "link /usr/local/bin/phala directly to the verified package launcher" "$OUT" \
  || fail "Phala install must publish the direct resolved launcher, got: $OUT"
pass "optional Linux Phala path uses a digest-pinned locked npm install"

# --- macos/brew dry-run maps the dev packages -------------------------------
run_provision DRY_RUN=1 PROVISION_OS=macos PROVISION_PKG_MANAGER=brew SKIP_PACKAGE_MANAGER_CHECK=1
[ "$RC" -eq 0 ] || fail "macos/brew dry-run should succeed, got rc=$RC: $OUT"
contains "brew install openssl" "$OUT" || fail "macos must map openssl-dev -> openssl, got: $OUT"
contains "brew install ca-certificates" "$OUT" || fail "macos must install ca-certificates, got: $OUT"
contains "brew install --cask docker" "$OUT" || fail "macos must give signed Docker Desktop install guidance, got: $OUT"
for package in rustup uv gh go; do
  contains "brew install ${package}" "$OUT" \
    || fail "macos must install '${package}' with Homebrew, got: $OUT"
done
contains "rebuild github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@v2.7.1 with an isolated Go environment, CGO_ENABLED=0, GOENV=off, GOFLAGS empty, GOWORK=off, GOTOOLCHAIN=local, GOPROXY=https://proxy.golang.org, and GOSUMDB=sum.golang.org" "$OUT" \
  || fail "macos must pin and isolate slsa-verifier behind the public Go checksum service, got: $OUT"
contains "rustup toolchain install ${PINNED_RUST_VERSION} --profile minimal --component rustfmt --component clippy" "$OUT" \
  || fail "macos must install the repository-pinned Rust toolchain, got: $OUT"
pass "macos/brew uses package-manager installs and the pinned Rust toolchain"

echo "all provision-host tests passed"
