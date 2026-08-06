#!/usr/bin/env bash
# Reproducible container-build inputs shared by host provisioning, CVM image
# publication, and the independent-worktree smoke. This file is sourced;
# callers own user-facing errors.

UMBRA_BUILDX_VERSION="0.34.0"
UMBRA_BUILDKIT_BUILDER="umbra-release"
UMBRA_BUILDKIT_VERSION="0.32.2"
UMBRA_BUILDKIT_IMAGE="moby/buildkit:v${UMBRA_BUILDKIT_VERSION}@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8"
UMBRA_BUILDKIT_COMPATIBILITY_VERSION="30"
UMBRA_BUILD_SOURCE_REPOSITORY_URL="${UMBRA_BUILD_SOURCE_REPOSITORY_URL:-https://github.com/concrete-security/umbra}"
UMBRA_DOCKERFILE_FRONTEND_DIGEST="ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32"
UMBRA_DOCKERFILE_FRONTEND_IMAGE="docker/dockerfile:1.26.0@sha256:${UMBRA_DOCKERFILE_FRONTEND_DIGEST}"
UMBRA_SBOM_GENERATOR_DIGEST="79e7b013cbec16bbb436f312819a49a4a57752b2270c1a9332ae1a10fcc82a68"
UMBRA_SBOM_GENERATOR_IMAGE="docker.io/docker/buildkit-syft-scanner:stable-1@sha256:${UMBRA_SBOM_GENERATOR_DIGEST}"
UMBRA_BUILDKIT_FAILURE=""
UMBRA_REPRODUCIBLE_BUILD_ARGS=()

umbra_version_at_least() {
  local actual_major actual_minor actual_patch
  local minimum_major minimum_minor minimum_patch

  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  [[ "$2" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
  IFS=. read -r actual_major actual_minor actual_patch <<<"$1"
  IFS=. read -r minimum_major minimum_minor minimum_patch <<<"$2"

  [ "$actual_major" -gt "$minimum_major" ] \
    || { [ "$actual_major" -eq "$minimum_major" ] \
      && [ "$actual_minor" -gt "$minimum_minor" ]; } \
    || { [ "$actual_major" -eq "$minimum_major" ] \
      && [ "$actual_minor" -eq "$minimum_minor" ] \
      && [ "$actual_patch" -ge "$minimum_patch" ]; }
}

umbra_buildx_client_supported() {
  local output token version=""

  output="$(docker buildx version 2>/dev/null)" || return 1
  for token in $output; do
    if [[ "$token" =~ ^v([0-9]+\.[0-9]+\.[0-9]+)$ ]]; then
      [ -z "$version" ] || return 1
      version="${BASH_REMATCH[1]}"
    fi
  done
  [ -n "$version" ] || return 1
  [ "$version" = "$UMBRA_BUILDX_VERSION" ]
}

# Prove that the requested Dockerfile and context are ordinary objects in the
# captured commit. Filesystem tests alone are insufficient: a committed symlink
# can resolve outside a detached worktree while still satisfying `-f`/`-d`.
umbra_release_source_objects_valid() {
  local context="$4" context_entry context_mode context_path context_type
  local dockerfile="$3" dockerfile_entry dockerfile_mode dockerfile_path
  local dockerfile_type git_sha="$2" repository="$1"

  [[ "$git_sha" =~ ^[0-9a-f]{40}$ ]] || return 1
  case "$dockerfile" in
    "" | /* | . | */./* | ./* | *//* | */../* | ../* | */.. | *[!A-Za-z0-9._/-]*)
      return 1
      ;;
  esac
  case "$context" in
    "" | /* | */./* | ./* | *//* | */../* | ../* | */.. | *[!A-Za-z0-9._/-]*)
      return 1
      ;;
  esac

  dockerfile_entry="$(git -C "$repository" ls-tree "$git_sha" -- "$dockerfile" 2>/dev/null)" \
    || return 1
  [ "$(printf '%s\n' "$dockerfile_entry" | wc -l)" -eq 1 ] || return 1
  IFS=$' \t' read -r dockerfile_mode dockerfile_type _ dockerfile_path \
    <<<"$dockerfile_entry"
  case "$dockerfile_mode:$dockerfile_type:$dockerfile_path" in
    100644:blob:"$dockerfile" | 100755:blob:"$dockerfile") ;;
    *) return 1 ;;
  esac

  if [ "$context" = . ]; then
    [ "$(git -C "$repository" cat-file -t "${git_sha}^{tree}" 2>/dev/null)" = tree ] \
      || return 1
  else
    context_entry="$(git -C "$repository" ls-tree "$git_sha" -- "$context" 2>/dev/null)" \
      || return 1
    [ "$(printf '%s\n' "$context_entry" | wc -l)" -eq 1 ] || return 1
    IFS=$' \t' read -r context_mode context_type _ context_path <<<"$context_entry"
    [ "$context_mode:$context_type:$context_path" = "040000:tree:${context}" ] \
      || return 1
  fi
}

# Resolve both paths after checkout and keep them below the detached root. This
# repeats the Git-object check at the filesystem boundary so neither a symlink
# nor a path-normalisation surprise can redirect BuildKit to ambient files.
umbra_resolve_release_worktree_paths() {
  local context="$3" dockerfile="$2" resolved_context resolved_dockerfile
  local resolved_root worktree="$1"

  resolved_root="$(realpath -e -- "$worktree" 2>/dev/null)" || return 1
  resolved_dockerfile="$(realpath -e -- "${worktree}/${dockerfile}" 2>/dev/null)" \
    || return 1
  resolved_context="$(realpath -e -- "${worktree}/${context}" 2>/dev/null)" \
    || return 1
  case "$resolved_dockerfile" in
    "$resolved_root"/*) ;;
    *) return 1 ;;
  esac
  case "$resolved_context" in
    "$resolved_root" | "$resolved_root"/*) ;;
    *) return 1 ;;
  esac
  [ -f "$resolved_dockerfile" ] && [ ! -L "${worktree}/${dockerfile}" ] \
    && [ -d "$resolved_context" ] && [ ! -L "${worktree}/${context}" ] \
    || return 1

  UMBRA_RELEASE_DOCKERFILE_PATH="$resolved_dockerfile"
  UMBRA_RELEASE_CONTEXT_PATH="$resolved_context"
}

umbra_normalize_source_repository_url() {
  local remote host path url="$1"

  case "$url" in
    https://*) ;;
    git@*:*)
      remote="${url#git@}"
      host="${remote%%:*}"
      path="${remote#*:}"
      [ -n "$host" ] && [ -n "$path" ] || return 1
      url="https://${host}/${path}"
      ;;
    ssh://git@*/*) url="https://${url#ssh://git@}" ;;
    *) return 1 ;;
  esac
  case "${url#https://}" in
    "" | */ | *@* | *\?* | *\#* | *[[:space:]]*) return 1 ;;
  esac
  case "${url#https://}" in
    */*) ;;
    *) return 1 ;;
  esac
  url="${url%/}"
  url="${url%.git}"
  printf '%s\n' "$url"
}

umbra_builder_node_count() {
  awk '
    /^Nodes:[[:space:]]*$/ { in_nodes = 1; next }
    in_nodes && /^Name:[[:space:]]+/ { count++ }
    END { print count + 0 }
  ' <<<"$1"
}

umbra_builder_configuration_valid() {
  local driver_options inspect_output="$1" node_count

  node_count="$(umbra_builder_node_count "$inspect_output")" || return 1
  [ "$node_count" -eq 1 ] || return 1
  grep -Eq '^Driver:[[:space:]]+docker-container[[:space:]]*$' <<<"$inspect_output" \
    || return 1
  driver_options="$(awk '
    /^Driver Options:[[:space:]]*/ {
      sub(/^Driver Options:[[:space:]]*/, "")
      print
    }
  ' <<<"$inspect_output")" || return 1
  [ "$driver_options" = "image=\"${UMBRA_BUILDKIT_IMAGE}\"" ] || return 1
  ! grep -Eq '^[[:space:]]*Error:[[:space:]]*' <<<"$inspect_output"
}

umbra_builder_runtime_valid() {
  local inspect_output="$1"

  umbra_builder_configuration_valid "$inspect_output" || return 1
  [ "$(grep -Ec '^Status:[[:space:]]+running[[:space:]]*$' <<<"$inspect_output")" -eq 1 ] \
    || return 1
  [ "$(grep -Ec "^BuildKit version:[[:space:]]+v${UMBRA_BUILDKIT_VERSION}[[:space:]]*$" <<<"$inspect_output")" -eq 1 ] \
    || return 1
}

umbra_clear_buildx_environment() {
  unset \
    BUILDKIT_HOST \
    BUILDX_BUILDER \
    BUILDX_CONFIG \
    BUILDX_GIT_CHECK_DIRTY \
    BUILDX_METADATA_PROVENANCE \
    BUILDX_NO_DEFAULT_ATTESTATIONS \
    EXPERIMENTAL_BUILDKIT_SOURCE_POLICY \
    SOURCE_DATE_EPOCH
  export BUILDX_GIT_INFO=false
  export BUILDX_GIT_LABELS=false
}

umbra_require_reproducible_builder() {
  local inspect_output

  UMBRA_BUILDKIT_FAILURE=""
  umbra_clear_buildx_environment
  if ! umbra_buildx_client_supported; then
    UMBRA_BUILDKIT_FAILURE="buildx_client_unsupported"
    return 1
  fi
  if ! docker info >/dev/null 2>&1; then
    UMBRA_BUILDKIT_FAILURE="docker_daemon_unavailable"
    return 1
  fi

  if ! inspect_output="$(docker buildx inspect "$UMBRA_BUILDKIT_BUILDER" 2>/dev/null)"; then
    docker buildx create \
      --name "$UMBRA_BUILDKIT_BUILDER" \
      --driver docker-container \
      --driver-opt "image=${UMBRA_BUILDKIT_IMAGE}" \
      >/dev/null 2>&1 || true
    if ! inspect_output="$(docker buildx inspect "$UMBRA_BUILDKIT_BUILDER" 2>/dev/null)"; then
      UMBRA_BUILDKIT_FAILURE="builder_create_failed"
      return 1
    fi
  fi
  if ! umbra_builder_configuration_valid "$inspect_output"; then
    UMBRA_BUILDKIT_FAILURE="builder_configuration_mismatch"
    return 1
  fi
  if ! inspect_output="$(docker buildx inspect "$UMBRA_BUILDKIT_BUILDER" --bootstrap 2>/dev/null)"; then
    UMBRA_BUILDKIT_FAILURE="builder_bootstrap_failed"
    return 1
  fi
  if ! umbra_builder_runtime_valid "$inspect_output"; then
    UMBRA_BUILDKIT_FAILURE="builder_runtime_mismatch"
    return 1
  fi
}

umbra_prepare_reproducible_build_args() {
  local git_sha="$1" source_date_epoch="$2"

  [[ "$git_sha" =~ ^([0-9a-f]{40}|[0-9a-f]{64})$ ]] || return 1
  [[ "$source_date_epoch" =~ ^[0-9]+$ ]] || return 1
  UMBRA_REPRODUCIBLE_BUILD_ARGS=(
    --builder "$UMBRA_BUILDKIT_BUILDER"
    --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}"
    # Docker otherwise imports proxy values (including credentials) from the
    # client config as predefined build args, and max-mode provenance records
    # their values. Release builds use daemon/network configuration instead.
    --build-arg HTTP_PROXY=
    --build-arg HTTPS_PROXY=
    --build-arg FTP_PROXY=
    --build-arg NO_PROXY=
    --build-arg ALL_PROXY=
    --build-arg http_proxy=
    --build-arg https_proxy=
    --build-arg ftp_proxy=
    --build-arg no_proxy=
    --build-arg all_proxy=
    --provenance=mode=max
    --attest "type=sbom,generator=${UMBRA_SBOM_GENERATOR_IMAGE}"
    --label "org.opencontainers.image.revision=${git_sha}"
    --label "org.opencontainers.image.source=${UMBRA_BUILD_SOURCE_REPOSITORY_URL}"
  )
}

# Validate the attested result index produced by the pinned builder and return
# both content-addressed descriptors. Keeping this selector shared prevents the
# publication path and the independent-worktree gate from silently choosing
# different subjects when BuildKit adds its attestation manifest.
umbra_attested_index_descriptors() {
  jq -cer '
    def valid_digest: type == "string" and test("^sha256:[0-9a-f]{64}$");
    [
      .manifests[]?
      | select(.mediaType == "application/vnd.oci.image.manifest.v1+json")
      | select(.platform.os == "linux" and .platform.architecture == "amd64")
      | select((.annotations["vnd.docker.reference.type"] // "") != "attestation-manifest")
    ] as $runtime
    | [
        .manifests[]?
        | select(.mediaType == "application/vnd.oci.image.manifest.v1+json")
        | select(.platform.os == "unknown" and .platform.architecture == "unknown")
        | select(.annotations["vnd.docker.reference.type"] == "attestation-manifest")
      ] as $attestation
    | if .mediaType == "application/vnd.oci.image.index.v1+json"
        and (.manifests | type == "array" and length == 2)
        and ($runtime | length) == 1
        and ($attestation | length) == 1
        and ($runtime[0].digest | valid_digest)
        and ($attestation[0].digest | valid_digest)
        and $attestation[0].annotations["vnd.docker.reference.digest"] == $runtime[0].digest
      then {
        runtime_digest: $runtime[0].digest,
        attestation_digest: $attestation[0].digest
      }
      else error("expected one attested linux/amd64 runtime manifest")
      end
  '
}

umbra_runtime_image_config_valid() {
  local git_sha="$1"

  jq -e \
    --arg git_sha "$git_sha" \
    --arg source "$UMBRA_BUILD_SOURCE_REPOSITORY_URL" '
      .architecture == "amd64"
        and .os == "linux"
        and .config.Labels["org.opencontainers.image.revision"] == $git_sha
        and .config.Labels["org.opencontainers.image.source"] == $source
    ' >/dev/null
}

umbra_attestation_manifest_valid() {
  local runtime_digest="$1"

  jq -e --arg runtime_digest "$runtime_digest" '
    .mediaType == "application/vnd.oci.image.manifest.v1+json"
      and .artifactType == "application/vnd.docker.attestation.manifest.v1+json"
      and .subject.digest == $runtime_digest
      and (.layers | type == "array" and length == 2)
      and ([
        .layers[]
        | select(
            .mediaType == "application/vnd.in-toto+json"
            and (.digest | type == "string" and test("^sha256:[0-9a-f]{64}$"))
          )
      ] | length) == 2
      and ([
        .layers[]
        | .annotations["in-toto.io/predicate-type"]
      ] | sort) == ([
        "https://spdx.dev/Document",
        "https://slsa.dev/provenance/v1"
      ] | sort)
  ' >/dev/null
}

umbra_provenance_statement_valid() {
  local git_sha="$1" source_date_epoch="$2"

  jq -e \
    --arg compatibility_version "$UMBRA_BUILDKIT_COMPATIBILITY_VERSION" \
    --arg frontend "$UMBRA_DOCKERFILE_FRONTEND_IMAGE" \
    --arg frontend_digest "$UMBRA_DOCKERFILE_FRONTEND_DIGEST" \
    --arg git_sha "$git_sha" \
    --arg sbom_digest "$UMBRA_SBOM_GENERATOR_DIGEST" \
    --arg source "$UMBRA_BUILD_SOURCE_REPOSITORY_URL" \
    --arg source_date_epoch "$source_date_epoch" '
      .predicate.buildDefinition.externalParameters.request.args as $request_args
      | ._type == "https://in-toto.io/Statement/v1"
        and .predicateType == "https://slsa.dev/provenance/v1"
        and .predicate.buildDefinition.buildType
          == "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md"
        and .predicate.buildDefinition.externalParameters.request.frontend == "gateway.v0"
        and .predicate.buildDefinition.externalParameters.request.args["build-arg:SOURCE_DATE_EPOCH"] == $source_date_epoch
        and .predicate.buildDefinition.externalParameters.request.args["label:org.opencontainers.image.revision"] == $git_sha
        and .predicate.buildDefinition.externalParameters.request.args["label:org.opencontainers.image.source"] == $source
        and .predicate.buildDefinition.externalParameters.request.args.cmdline == $frontend
        and ([
          "HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "NO_PROXY", "ALL_PROXY",
          "http_proxy", "https_proxy", "ftp_proxy", "no_proxy", "all_proxy"
        ] | all(. as $name | $request_args["build-arg:\($name)"] == ""))
        and (.predicate.buildDefinition.externalParameters.request.compatibilityVersion | tostring) == $compatibility_version
        and ([.predicate.buildDefinition.resolvedDependencies[]?.digest.sha256] | index($frontend_digest)) != null
        and ([.predicate.buildDefinition.resolvedDependencies[]?.digest.sha256] | index($sbom_digest)) != null
    ' >/dev/null
}

umbra_sbom_statement_valid() {
  jq -e '
    ._type == "https://in-toto.io/Statement/v1"
      and .predicateType == "https://spdx.dev/Document"
      and .predicate.spdxVersion == "SPDX-2.3"
      and .predicate.dataLicense == "CC0-1.0"
      and (.predicate.packages | type == "array" and length > 0)
  ' >/dev/null
}

umbra_oci_layout_blob_valid() {
  local archive="$1" digest="$2" actual

  [[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
  actual="$(
    tar -xOf "$archive" "blobs/sha256/${digest#sha256:}" \
      | sha256sum \
      | awk '{print "sha256:" $1}'
  )" || return 1
  [ "$actual" = "$digest" ]
}

# OCI layout exports wrap the attested result index in the layout's own index.
# Return that content address separately so a publisher can probe and push only
# the already-reproduced digest, without introducing a mutable staging tag.
umbra_oci_layout_result_digest() {
  local archive="$1" result_digest

  result_digest="$(
    tar -xOf "$archive" index.json \
      | jq -er '
          if .mediaType == "application/vnd.oci.image.index.v1+json"
              and (.manifests | length) == 1
              and .manifests[0].mediaType == "application/vnd.oci.image.index.v1+json"
              and (.manifests[0].digest | test("^sha256:[0-9a-f]{64}$"))
            then .manifests[0].digest
            else error("expected one attested result index in the OCI layout")
          end
        '
  )" || return 1
  umbra_oci_layout_blob_valid "$archive" "$result_digest" || return 1
  printf '%s\n' "$result_digest"
}

# Resolve the result index, prove the SBOM and provenance predicates are
# attached to the selected runtime subject, and print only the stable runtime
# digest used by the CVM deployment.
umbra_oci_layout_runtime_digest() {
  local archive="$1" git_sha="$2" source_date_epoch="$3"
  local attestation_digest attestation_json config_digest config_json descriptors
  local provenance_digest result_digest result_index runtime_digest runtime_manifest sbom_digest

  result_digest="$(umbra_oci_layout_result_digest "$archive")" || return 1
  result_index="$(
    tar -xOf "$archive" "blobs/sha256/${result_digest#sha256:}"
  )" || return 1
  descriptors="$(printf '%s' "$result_index" | umbra_attested_index_descriptors)" \
    || return 1
  runtime_digest="$(printf '%s' "$descriptors" | jq -er '.runtime_digest')" \
    || return 1
  attestation_digest="$(printf '%s' "$descriptors" | jq -er '.attestation_digest')" \
    || return 1
  umbra_oci_layout_blob_valid "$archive" "$attestation_digest" || return 1
  attestation_json="$(
    tar -xOf "$archive" "blobs/sha256/${attestation_digest#sha256:}"
  )" || return 1
  umbra_attestation_manifest_valid "$runtime_digest" <<<"$attestation_json" \
    || return 1
  provenance_digest="$(printf '%s' "$attestation_json" | jq -er '
    [.layers[]?
      | select(.annotations["in-toto.io/predicate-type"] == "https://slsa.dev/provenance/v1")
      | .digest
      | select(test("^sha256:[0-9a-f]{64}$"))
    ] | if length == 1 then .[0] else error("expected one provenance layer") end
  ')" || return 1
  sbom_digest="$(printf '%s' "$attestation_json" | jq -er '
    [.layers[]?
      | select(.annotations["in-toto.io/predicate-type"] == "https://spdx.dev/Document")
      | .digest
      | select(test("^sha256:[0-9a-f]{64}$"))
    ] | if length == 1 then .[0] else error("expected one SBOM layer") end
  ')" || return 1
  umbra_oci_layout_blob_valid "$archive" "$provenance_digest" || return 1
  tar -xOf "$archive" "blobs/sha256/${provenance_digest#sha256:}" \
    | umbra_provenance_statement_valid "$git_sha" "$source_date_epoch" \
    || return 1
  umbra_oci_layout_blob_valid "$archive" "$sbom_digest" || return 1
  tar -xOf "$archive" "blobs/sha256/${sbom_digest#sha256:}" \
    | umbra_sbom_statement_valid \
    || return 1
  umbra_oci_layout_blob_valid "$archive" "$runtime_digest" || return 1
  runtime_manifest="$(
    tar -xOf "$archive" "blobs/sha256/${runtime_digest#sha256:}"
  )" || return 1
  config_digest="$(printf '%s' "$runtime_manifest" | jq -er '
    if .mediaType == "application/vnd.oci.image.manifest.v1+json"
        and (.config.digest | test("^sha256:[0-9a-f]{64}$"))
      then .config.digest
      else error("expected an OCI runtime manifest with a content-addressed config")
    end
  ')" || return 1
  umbra_oci_layout_blob_valid "$archive" "$config_digest" || return 1
  config_json="$(
    tar -xOf "$archive" "blobs/sha256/${config_digest#sha256:}"
  )" || return 1
  umbra_runtime_image_config_valid "$git_sha" <<<"$config_json" || return 1

  printf '%s\n' "$runtime_digest"
}
