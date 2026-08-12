#!/usr/bin/env bash
# Shared preflight and image-publish steps for the CVM redeploy scripts
# (ops/deploy/redeploy-security-cvm.sh, ops/deploy/redeploy-dev-cvm.sh).
#
# Sourced, not executed — like ops/db/console-db-guard.sh.
#
# COMMAND SUBSTITUTION IS THE HAZARD IN THIS FILE. Two independent traps:
#
#   1. Bash strips errexit inside `$( )`. An ordinary failing command there is
#      ignored even under the caller's `set -e`.
#   2. cvm_redeploy_fail's `exit` terminates only the SUBSHELL. It reaches the
#      caller solely because errexit acts on the failed *assignment* in
#      `v="$(...)"`. In any other shape — `echo "$(guard)"`, `local v="$(guard)"`,
#      `if [ -n "$(guard)" ]` — the guard fires, prints, and execution CONTINUES.
#
# Trap 2 is not theoretical: `if [ -n "$(git status ...)" ]` is how the original
# clean-tree guard read a failed git as a clean tree and published anyway. Trap 1
# is what an earlier version of this refactor hit by running `docker login` inside
# a substituted function — the original ran it at top level and aborted correctly.
#
# So: every command inside a substitution must check its own status, and guards
# must be called as plain commands. cvm_redeploy_publish_image returns through a
# variable for exactly this reason.
#
# What stays in the callers: the watched source paths, the Dockerfile/context,
# the Dev CVM measurement step, the launch barrier's checks, and the final CLI
# command. The barrier's exit code differs by design — the SC always fails, the
# Dev CVM only fails under UMBRA_REDEPLOY_DEV_REQUIRE_LAUNCH — so each caller
# passes the matching verdict to cvm_redeploy_report_blocked.

# shellcheck source=ops/buildkit-version.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/../buildkit-version.sh"

CVM_REDEPLOY_LABEL="cvm-redeploy"

cvm_redeploy_fail() {
  echo "${CVM_REDEPLOY_LABEL}: $1" >&2
  exit "${2:-1}"
}

cvm_redeploy_info() {
  echo "${CVM_REDEPLOY_LABEL}: $1" >&2
}

cvm_redeploy_is_truthy() {
  case "${1:-}" in
    1 | true | TRUE | yes | YES | y | Y | on | ON)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

cvm_redeploy_is_falsey() {
  case "${1:-}" in
    0 | false | FALSE | no | NO | n | N | off | OFF)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

cvm_redeploy_require_env() {
  local name
  for name in "$@"; do
    if [ -z "${!name:-}" ]; then
      case "$name" in
        GHCR_USER | GHCR_TOKEN)
          cvm_redeploy_fail "missing ${name}; provide publisher credentials through the process environment"
          ;;
        *)
          cvm_redeploy_fail "missing ${name}; set it in .env"
          ;;
      esac
    fi
  done
}

cvm_redeploy_restore_publisher_credential() {
  local is_set="$2" name="$1" value="$3"

  case "$name" in
    GHCR_USER | GHCR_TOKEN) ;;
    *) cvm_redeploy_fail "internal publisher-credential name is invalid" ;;
  esac
  if [ -n "$is_set" ]; then
    builtin printf -v "$name" '%s' "$value"
    # Keep the one-shot value readable by require_env and the publisher shell,
    # but absent from git, Phala, builder setup, and every other pre-login child.
    builtin export -n "$name"
  else
    builtin unset "$name"
  fi
}

# Set the log prefix, export .env, and assert the tools every redeploy needs.
#
# Moves to the repo root first, because everything downstream is cwd-relative:
# `.env`, the `git status` guard, the Dockerfiles and build contexts, the measure
# script, and artifacts/. Derived from this file's own location, so it holds for
# any caller. Three specific failures it removes, in order of severity:
#   - `. ./.env` EXECUTES the file, so a run started from a shared directory
#     would source whatever .env sat there;
#   - git pathspecs are cwd-relative, so `git status -- cvms/security` from a
#     subdirectory returns empty with status 0 — the clean-tree guard read a
#     dirty tree as clean and would publish a mislabelled source-SHA image. The
#     capture-and-check in that guard cannot catch this; only being at the root
#     can;
#   - artifacts/ is root-anchored in .gitignore, so a manifest written from a
#     subdirectory landed outside the ignore rule.
# `CDPATH= ` matters: with CDPATH set and a relative path, `cd` both consults it
# and echoes the resolved directory on STDOUT, which is where these scripts' only
# machine-readable payload lives. Same guard as ops/installer/smoke_test.sh.
cvm_redeploy_init() {
  # A caller may have inherited xtrace or enabled it while debugging. Disable it
  # before copying one-shot publisher credentials into locals; otherwise bash
  # itself would print the values before any Docker redaction boundary applies.
  builtin set +x
  # Publishing credentials are one-shot process inputs. Preserve whether the
  # caller supplied them before sourcing the generated runtime environment, then
  # restore that state so a stale legacy .env can neither inject nor override a
  # registry publisher credential.
  local ambient_ghcr_user="${GHCR_USER-}"
  local ambient_ghcr_token="${GHCR_TOKEN-}"
  local ambient_ghcr_user_set="${GHCR_USER+x}"
  local ambient_ghcr_token_set="${GHCR_TOKEN+x}"
  local caller_exit_trap
  # From this point until the isolated `docker login`, no child process should
  # receive publisher credentials. Restore them later as non-exported shell
  # variables so the publisher can consume them without widening that boundary.
  builtin unset GHCR_USER GHCR_TOKEN
  caller_exit_trap="$(builtin trap -p EXIT)" || caller_exit_trap=""

  # Set first so the guards below carry the caller's label, not the module default;
  # re-set after the .env source so a .env cannot keep an override of its own.
  CVM_REDEPLOY_LABEL="$1"

  # `cd <existing>/../..` collapses `..` textually and so essentially cannot fail;
  # what it CAN do is succeed into the wrong tree (e.g. this file reached through
  # a symlink from outside the repo), which is silent and exactly the failure the
  # cd exists to prevent. So assert arrival rather than trusting cd's status.
  CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." \
    || cvm_redeploy_fail "cannot enter the repository root"
  { [ -e .git ] && [ -f Makefile ]; } \
    || cvm_redeploy_fail "the release script did not resolve to the repository root"

  if [ -f .env ]; then
    set -a
    . ./.env
    # `.env` is shell code and can turn xtrace back on. Disable it as the very
    # next statement, before restoring one-shot publisher credentials.
    builtin set +x
    builtin set +a
    # allexport made any legacy .env values inheritable while it was sourced;
    # discard them before the next external helper and restore only the captured
    # process-scoped values below.
    builtin unset GHCR_USER GHCR_TOKEN
  fi

  # `.env` is EXECUTED as bash, so everything below re-establishes the shell state
  # this library's guarantees rest on. THREAT MODEL: accidents, not a hostile
  # operator. The .env is 0600, gitignored and operator-authored; if it is hostile
  # the account is already lost and no guard here helps. What these lines defend
  # against is a stray `set +e` left in during debugging, an ambient GIT_* from a
  # git hook or `rebase --exec` (which needs no .env at all), and a helper function
  # accidentally shadowing something load-bearing.
  #
  # Order matters: restore the shell, then re-source this file so a .env definition
  # cannot stand in for one of our own functions, then re-check the root.
  # EVERY statement here is prefixed `builtin`, and that is load-bearing: each guard
  # is written with a builtin the .env could have shadowed, so without the prefix the
  # statement meant to undo the damage is itself the first casualty. Measured:
  # `unset() { :; }` disabled all three unsets at once and let a dirty tree publish
  # with rc=0; `.() { :; }` disabled the re-source below. The irreducible residue is
  # a function named `builtin` itself, which cannot be defended against from inside
  # bash — so this block is thorough, not total.
  builtin trap - EXIT
  builtin unset -f exit printf echo cd set unset type command read test dirname awk grep [ . source
  builtin set -euo pipefail
  # Root re-check BEFORE the re-source, so a `cd` in the .env reports our message
  # rather than a raw bash "No such file or directory".
  { [ -e .git ] && [ -f Makefile ]; } \
    || cvm_redeploy_fail "the environment file changed the release script's repository root"
  # The callers source this library BEFORE .env is read, so without this re-source a
  # .env could redefine any cvm_redeploy_* function and the guard it replaces would
  # simply not run. Measured: an `exit()` override made the barrier fall through to
  # the launch step. Re-sourcing only redefines functions; it does not recurse.
  # ${BASH_SOURCE[0]}, never a literal path: a relative literal would REPLACE this
  # file's recorded location, so a later cvm_redeploy_init would resolve its cd
  # against the cwd and could land in a different repository root.
  builtin . "${BASH_SOURCE[0]}"
  cvm_redeploy_restore_publisher_credential \
    GHCR_USER "$ambient_ghcr_user_set" "$ambient_ghcr_user"
  cvm_redeploy_restore_publisher_credential \
    GHCR_TOKEN "$ambient_ghcr_token_set" "$ambient_ghcr_token"
  # An ambient value here would point every git call in this library at a different
  # repository, hide files from the clean-tree guard, or corrupt what it captures:
  # GIT_DIR/GIT_WORK_TREE/GIT_INDEX_FILE redirect the repo, GIT_CONFIG_* can inject
  # core.excludesFile or core.hooksPath, and GIT_TRACE=/dev/stdout pollutes the
  # capture into a false failure. Clear the whole prefix rather than a hand-list.
  # BASH_ENV joins them: it injects functions and aliases into every child bash.
  builtin unset BASH_ENV 2>/dev/null || true
  local gitvar
  for gitvar in $(compgen -v GIT_ 2>/dev/null || true); do
    builtin unset "$gitvar" 2>/dev/null || true
  done
  # Same reason as the re-source, for the external tools: a `git() { ... }` in scope
  # intercepts every git call, and the clean-tree guard then passes on any tree. `uv`
  # and `cargo` are included because the Dev script drives the Phala measurement and
  # the live launch through them.
  builtin unset -f docker git jq uv cargo awk grep
  # After the source, so a .env defining CVM_REDEPLOY_LABEL cannot relabel every
  # message this run emits.
  CVM_REDEPLOY_LABEL="$1"

  # `type -P` not `command -v`: the latter also resolves shell functions, so with a
  # function in scope it would report success while no real binary exists.
  local tool
  for tool in docker git jq realpath; do
    type -P "$tool" >/dev/null || cvm_redeploy_fail "${tool} is required"
  done
  if [ -n "$caller_exit_trap" ]; then
    builtin eval "$caller_exit_trap"
  fi
}

# Published labels and provenance name the captured git SHA, so publishing from
# a dirty tree would produce content that misrepresents its source.
# `subject` is the full phrase including its verb ("cvms/security has", "Dev CVM
# source files have") — one argument, not two, so a caller can never leave the
# variadic pathspec list one element short and silently widen the scan.
cvm_redeploy_require_clean_tree() {
  local subject="$1"
  shift
  # With no pathspec left, `git status -- ` scans the WHOLE tree, which would make
  # this guard fire on unrelated dirt and look like a bug in the caller's list.
  [ "$#" -gt 0 ] || cvm_redeploy_fail "require_clean_tree needs at least one pathspec"
  # Repo health first, so that a repo-level failure (dubious ownership, a corrupt
  # index, a pruned worktree) is not reported as "your pathspec list is stale" —
  # a diagnosis whose only fix would be to weaken this guard.
  git rev-parse --git-dir >/dev/null \
    || cvm_redeploy_fail "git cannot read this repository; fix that before publishing"
  # A pathspec matching nothing makes `git status` return empty with status 0, so a
  # renamed or deleted watched path would drop out of this guard in silence. HEAD is
  # itself a file-moving refactor, so that is a live risk, not a hypothetical one.
  # stderr is NOT discarded: git names the offending path, this message cannot.
  git ls-files --error-unmatch -- "$@" >/dev/null \
    || cvm_redeploy_fail "a watched path is absent from the index; update the guard's pathspec list: $*"
  local dirty git_sha_after git_sha_before
  git_sha_before="$(git rev-parse --verify 'HEAD^{commit}')" \
    || cvm_redeploy_fail "git rev-parse HEAD failed; cannot capture the release commit"
  # Capture and check: `if [ -n "$(git status …)" ]` would read a failed git as a
  # clean tree, and this guard is the only thing keeping a dirty tree from being
  # published as though it came from the captured clean commit.
  dirty="$(git status --porcelain --untracked-files=all -- "$@")" \
    || cvm_redeploy_fail "git status failed; cannot confirm the tree is clean"
  if [ -n "$dirty" ]; then
    cvm_redeploy_fail "${subject} uncommitted changes; commit before publishing a digest-addressed image"
  fi
  git_sha_after="$(git rev-parse --verify 'HEAD^{commit}')" \
    || cvm_redeploy_fail "git rev-parse HEAD failed after the clean-tree check"
  [ "$git_sha_before" = "$git_sha_after" ] \
    || cvm_redeploy_fail "HEAD changed while checking the release tree; retry from a stable commit"
  CVM_REDEPLOY_CLEAN_GIT_SHA="$git_sha_after"
}

cvm_redeploy_list_owned_cvms() {
  if [ -z "${PHALA_API_TOKEN:-}" ]; then
    cvm_redeploy_info "PHALA_API_TOKEN is not set; skipping pre-redeploy Umbra-owned Phala CVM listing"
    return 0
  fi

  local listing owned_count
  # Reported, not fatal: this inventory is informational. But a missing binary or a
  # rejected token would otherwise render as zero rows, indistinguishable from an
  # empty fleet — and acting on "no CVMs exist" is how the one-SC-one-Dev cap gets
  # broken. `|| true` still absorbs grep's no-match.
  local rc=0
  listing="$(PHALA_CLOUD_API_KEY="$PHALA_API_TOKEN" "${PHALA_CLI_PATH:-/usr/local/bin/phala}" cvms list 2>/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    cvm_redeploy_info "listing incomplete (phala CLI exited ${rc}); treat the fleet as unknown, not empty"
    return 0
  fi
  # Provider list rows are not reproduced in retained deploy logs. A response
  # can contain arbitrary fields even when the CLI exits zero; only a derived
  # integer is needed for the one-SC-one-Dev operator check.
  owned_count="$(printf '%s\n' "$listing" | awk '/^umbra-v0-/{count++} END{print count + 0}')"
  cvm_redeploy_info "Umbra-owned Phala CVM count before redeploy: ${owned_count}"
}

# Temporary release state is always created under this exact prefix. The EXIT
# trap protects failed builds; the explicit call protects successful ones.
CVM_REDEPLOY_RELEASE_DIR=""
CVM_REDEPLOY_RELEASE_WORKTREE=""
CVM_REDEPLOY_RELEASE_SECOND_WORKTREE=""
CVM_REDEPLOY_RELEASE_DOCKER_CONFIG=""
CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG=""
CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG_SET=""
CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG_EXPORTED=""
CVM_REDEPLOY_RELEASE_PREVIOUS_EXIT_TRAP=""
CVM_REDEPLOY_RELEASE_BUILDER_CLEANUP_REQUIRED=""
CVM_REDEPLOY_RELEASE_PREVIOUS_BUILDER=""
CVM_REDEPLOY_CLEAN_GIT_SHA="${CVM_REDEPLOY_CLEAN_GIT_SHA:-}"

cvm_redeploy_cleanup_release_workspace() {
  local failed=0

  if [ -n "$CVM_REDEPLOY_RELEASE_BUILDER_CLEANUP_REQUIRED" ]; then
    docker buildx rm --force "$UMBRA_BUILDKIT_BUILDER" >/dev/null 2>&1 \
      || failed=1
  fi
  if [ -n "$CVM_REDEPLOY_RELEASE_SECOND_WORKTREE" ]; then
    git worktree remove --force -- "$CVM_REDEPLOY_RELEASE_SECOND_WORKTREE" \
      >/dev/null 2>&1 || failed=1
  fi
  if [ -n "$CVM_REDEPLOY_RELEASE_WORKTREE" ]; then
    git worktree remove --force -- "$CVM_REDEPLOY_RELEASE_WORKTREE" \
      >/dev/null 2>&1 || failed=1
  fi
  if [ -n "$CVM_REDEPLOY_RELEASE_DIR" ]; then
    case "$CVM_REDEPLOY_RELEASE_DIR" in
      /tmp/umbra-cvm-release.*)
        command rm -rf -- "$CVM_REDEPLOY_RELEASE_DIR" >/dev/null 2>&1 \
          || failed=1
        ;;
      *)
        failed=1
        ;;
    esac
  fi
  if [ -n "$CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG_SET" ]; then
    local previous_docker_config_decoration
    previous_docker_config_decoration="${CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG_EXPORTED}"
    builtin printf -v DOCKER_CONFIG '%s' "$CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG"
    if [ -n "$previous_docker_config_decoration" ]; then
      builtin export DOCKER_CONFIG
    else
      builtin export -n DOCKER_CONFIG
    fi
  else
    builtin unset DOCKER_CONFIG
  fi
  if [ -n "$CVM_REDEPLOY_RELEASE_PREVIOUS_BUILDER" ]; then
    UMBRA_BUILDKIT_BUILDER="$CVM_REDEPLOY_RELEASE_PREVIOUS_BUILDER"
  fi
  CVM_REDEPLOY_RELEASE_DIR=""
  CVM_REDEPLOY_RELEASE_WORKTREE=""
  CVM_REDEPLOY_RELEASE_SECOND_WORKTREE=""
  CVM_REDEPLOY_RELEASE_DOCKER_CONFIG=""
  CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG=""
  CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG_SET=""
  CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG_EXPORTED=""
  CVM_REDEPLOY_RELEASE_BUILDER_CLEANUP_REQUIRED=""
  CVM_REDEPLOY_RELEASE_PREVIOUS_BUILDER=""
  return "$failed"
}

# Both trap handlers reinstate whatever `trap -p EXIT` reported before the
# publisher replaced it — the only way Bash lets a sourced helper leave a caller's
# EXIT handler intact. Caller contract: inside a subshell Bash reports the
# inherited handler but has already disarmed it, and this restore cannot tell that
# apart from one installed in the current shell, so a caller invoking these
# functions in `( )`/`$( )` must `trap - EXIT` first or its outer cleanup runs at
# subshell exit.
cvm_redeploy_restore_release_exit_trap() {
  local previous_trap="$CVM_REDEPLOY_RELEASE_PREVIOUS_EXIT_TRAP"

  builtin trap - EXIT
  CVM_REDEPLOY_RELEASE_PREVIOUS_EXIT_TRAP=""
  if [ -n "$previous_trap" ]; then
    builtin eval "$previous_trap"
  fi
}

cvm_redeploy_release_exit_trap() {
  local cleanup_status=0 final_status="$1"
  local previous_trap="$CVM_REDEPLOY_RELEASE_PREVIOUS_EXIT_TRAP"

  builtin trap - EXIT
  CVM_REDEPLOY_RELEASE_PREVIOUS_EXIT_TRAP=""
  cvm_redeploy_cleanup_release_workspace || cleanup_status=$?
  if [ "$cleanup_status" -ne 0 ]; then
    cvm_redeploy_info "isolated release cleanup could not remove every temporary resource"
    if [ "$final_status" -eq 0 ]; then
      final_status="$cleanup_status"
    fi
  fi
  if [ -n "$previous_trap" ]; then
    # Installing the saved trap in a subshell and exiting with the pending status
    # reproduces Bash EXIT-trap semantics, including an explicit `exit` in the
    # caller's handler, without evaluating its body as our own cleanup code.
    (
      builtin trap - EXIT
      builtin eval "$previous_trap"
      builtin exit "$final_status"
    ) || final_status=$?
  fi
  builtin exit "$final_status"
}

cvm_redeploy_origin_advertises_commit() {
  local git_sha="$1" refs

  refs="$(GIT_TERMINAL_PROMPT=0 git ls-remote --heads --tags origin 2>/dev/null)" \
    || return 1
  printf '%s\n' "$refs" \
    | awk -v expected="$git_sha" '$1 == expected { found = 1 } END { exit !found }'
}

# Reproduce and publish an immutable result index from the given Dockerfile and
# build context, then set CVM_REDEPLOY_IMAGE_REF to its runnable
# <repo>@<runtime-digest> and CVM_REDEPLOY_PROVENANCE_REF to the immutable
# attestation index containing its subject-bound SBOM and SLSA provenance. No
# mutable or source-SHA tag is created. Two local OCI builds must agree on the
# runnable manifest before publishing; one cache-disabled tagless build publishes
# the result index by digest.
#
# The result comes back through that global, NOT through stdout, and it must stay
# that way. Bash strips errexit inside a command substitution, so capturing this
# function's stdout would let a rejected login or failed build fall through to a
# later digest lookup, potentially reporting an earlier call's subject as success.
# Returning through a global keeps every command here under the caller's `set -e`
# and keeps Docker CLI stdout chatter out of the ref.
cvm_redeploy_publish_image() {
  builtin set +x
  CVM_REDEPLOY_IMAGE_REF=""
  CVM_REDEPLOY_PROVENANCE_REF=""
  local image_repo="$1" dockerfile="$2" context="$3" platforms="$4"
  local attestation_digest attestation_json descriptors git_sha
  local index_json local_archive local_runtime_digest
  local provenance_json provenance_statement runtime_config runtime_digest sbom_json
  local sbom_statement second_archive second_runtime_digest
  local source_date_epoch
  local metadata_file published_index_digest registry_password registry_user
  local configured_source_url origin_source_url origin_url
  local second_worktree_context second_worktree_dockerfile
  local worktree_context worktree_dockerfile
  local current_git_sha
  local docker_config_declaration

  # Also guarded in the callers, which keeps the original failure ordering (GHCR
  # before the Phala inventory). Repeated here so a future caller cannot reach the
  # login with an unset value and get a raw `set -u` error instead of our message.
  cvm_redeploy_require_env GHCR_USER GHCR_TOKEN
  registry_user="$GHCR_USER"
  registry_password="$GHCR_TOKEN"
  # The caller may have passed these as exported environment assignments. Keep
  # only unexported locals until login so no Docker/build helper inherits them.
  builtin unset GHCR_USER GHCR_TOKEN
  case "$image_repo" in
    registry.example.com/*)
      cvm_redeploy_fail "${image_repo} is a reserved example registry; set an owned GHCR repository before publishing"
      ;;
    ghcr.io/*)
      ;;
    *)
      cvm_redeploy_fail "runtime image publication currently supports only owned ghcr.io repositories"
      ;;
  esac

  git_sha="$CVM_REDEPLOY_CLEAN_GIT_SHA"
  [[ "$git_sha" =~ ^[0-9a-f]{40}$ ]] \
    || cvm_redeploy_fail "the clean-tree guard did not capture a release commit"
  current_git_sha="$(git rev-parse --verify 'HEAD^{commit}')" \
    || cvm_redeploy_fail "git rev-parse HEAD failed; cannot recheck the release commit"
  [ "$current_git_sha" = "$git_sha" ] \
    || cvm_redeploy_fail "HEAD changed after the clean-tree guard; retry from a stable commit"
  if [ "$platforms" != "linux/amd64" ]; then
    cvm_redeploy_fail "CVM publication supports exactly linux/amd64; got ${platforms}"
  fi
  umbra_release_source_objects_valid . "$git_sha" "$dockerfile" "$context" \
    || cvm_redeploy_fail "CVM Dockerfile and context must be ordinary repository objects inside the captured commit"
  configured_source_url="$(
    umbra_normalize_source_repository_url \
      "${UMBRA_BUILD_SOURCE_REPOSITORY_URL:-https://github.com/concrete-security/umbra}"
  )" || cvm_redeploy_fail "UMBRA_BUILD_SOURCE_REPOSITORY_URL must be an HTTPS repository URL without credentials, query, or fragment"
  origin_url="$(git remote get-url origin 2>/dev/null)" \
    || cvm_redeploy_fail "the release checkout has no readable origin remote; set it to the repository named by UMBRA_BUILD_SOURCE_REPOSITORY_URL"
  origin_source_url="$(umbra_normalize_source_repository_url "$origin_url")" \
    || cvm_redeploy_fail "the origin remote cannot be normalized to an HTTPS source identity"
  [ "$configured_source_url" = "$origin_source_url" ] \
    || cvm_redeploy_fail "UMBRA_BUILD_SOURCE_REPOSITORY_URL must explicitly match this checkout's origin repository"
  cvm_redeploy_origin_advertises_commit "$git_sha" \
    || cvm_redeploy_fail "the captured release commit is not advertised by an origin head or tag; push the reviewed commit before publishing"
  # Capture this before builder setup clears build-affecting environment, then
  # restore the one reviewed value for labels and local/remote validation.
  UMBRA_BUILD_SOURCE_REPOSITORY_URL="$configured_source_url"
  # Published for callers that name artifacts after the same commit. Reading HEAD
  # a second time would let a mid-build HEAD move desynchronise those names from
  # the immutable subject this function actually published.
  CVM_REDEPLOY_GIT_SHA="$git_sha"

  source_date_epoch="$(git show -s --format=%ct "$git_sha")" \
    || cvm_redeploy_fail "could not derive SOURCE_DATE_EPOCH from ${git_sha}"

  CVM_REDEPLOY_RELEASE_PREVIOUS_EXIT_TRAP="$(builtin trap -p EXIT)" \
    || CVM_REDEPLOY_RELEASE_PREVIOUS_EXIT_TRAP=""
  CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG="${DOCKER_CONFIG-}"
  CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG_SET="${DOCKER_CONFIG+x}"
  docker_config_declaration="$(builtin declare -p DOCKER_CONFIG 2>/dev/null || true)"
  case "$docker_config_declaration" in
    declare\ -x* )
      CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG_EXPORTED=x
      ;;
    *)
      CVM_REDEPLOY_RELEASE_PREVIOUS_DOCKER_CONFIG_EXPORTED=
      ;;
  esac
  CVM_REDEPLOY_RELEASE_DIR="$(mktemp -d /tmp/umbra-cvm-release.XXXXXX)" \
    || cvm_redeploy_fail "could not create the isolated release workspace"
  builtin trap 'cvm_redeploy_release_exit_trap "$?"' EXIT
  CVM_REDEPLOY_RELEASE_WORKTREE="${CVM_REDEPLOY_RELEASE_DIR}/first-worktree"
  CVM_REDEPLOY_RELEASE_SECOND_WORKTREE="${CVM_REDEPLOY_RELEASE_DIR}/second-worktree"
  CVM_REDEPLOY_RELEASE_DOCKER_CONFIG="${CVM_REDEPLOY_RELEASE_DIR}/docker-config"
  command mkdir -m 0700 -- "$CVM_REDEPLOY_RELEASE_DOCKER_CONFIG" \
    || cvm_redeploy_fail "could not create the isolated Docker client configuration"
  builtin export DOCKER_CONFIG="$CVM_REDEPLOY_RELEASE_DOCKER_CONFIG"

  # The isolated Docker config intentionally has no ambient Buildx state. The
  # per-run builder is created/verified inside it and removed on every exit; a
  # unique name prevents collision with a maintainer's ambient named builder.
  CVM_REDEPLOY_RELEASE_PREVIOUS_BUILDER="$UMBRA_BUILDKIT_BUILDER"
  UMBRA_BUILDKIT_BUILDER="umbra-release-${git_sha:0:12}-${BASHPID}"
  CVM_REDEPLOY_RELEASE_BUILDER_CLEANUP_REQUIRED=1
  umbra_require_reproducible_builder \
    || cvm_redeploy_fail "the digest-pinned ${UMBRA_BUILDKIT_BUILDER} builder is unavailable (${UMBRA_BUILDKIT_FAILURE})"
  UMBRA_BUILD_SOURCE_REPOSITORY_URL="$configured_source_url"
  umbra_prepare_reproducible_build_args "$git_sha" "$source_date_epoch" \
    || cvm_redeploy_fail "git returned invalid reproducible-build metadata for ${git_sha}"

  git worktree add --detach "$CVM_REDEPLOY_RELEASE_WORKTREE" "$git_sha" \
    >/dev/null 2>&1 \
    || cvm_redeploy_fail "could not create the first detached worktree for the reviewed source commit"
  git worktree add --detach "$CVM_REDEPLOY_RELEASE_SECOND_WORKTREE" "$git_sha" \
    >/dev/null 2>&1 \
    || cvm_redeploy_fail "could not create the second detached worktree for the reviewed source commit"
  umbra_resolve_release_worktree_paths \
    "$CVM_REDEPLOY_RELEASE_WORKTREE" "$dockerfile" "$context" \
    || cvm_redeploy_fail "the first detached worktree resolved a build path outside its captured root"
  worktree_dockerfile="$UMBRA_RELEASE_DOCKERFILE_PATH"
  worktree_context="$UMBRA_RELEASE_CONTEXT_PATH"
  umbra_resolve_release_worktree_paths \
    "$CVM_REDEPLOY_RELEASE_SECOND_WORKTREE" "$dockerfile" "$context" \
    || cvm_redeploy_fail "the second detached worktree resolved a build path outside its captured root"
  second_worktree_dockerfile="$UMBRA_RELEASE_DOCKERFILE_PATH"
  second_worktree_context="$UMBRA_RELEASE_CONTEXT_PATH"
  current_git_sha="$(git rev-parse --verify 'HEAD^{commit}')" \
    || cvm_redeploy_fail "git rev-parse HEAD failed before the release builds"
  [ "$current_git_sha" = "$git_sha" ] \
    || cvm_redeploy_fail "HEAD changed before the release builds; retry from a stable commit"
  local_archive="${CVM_REDEPLOY_RELEASE_DIR}/release.oci.tar"
  second_archive="${CVM_REDEPLOY_RELEASE_DIR}/second-release.oci.tar"

  cvm_redeploy_info "building the first independent release subject from detached commit ${git_sha}"
  docker buildx build \
    "${UMBRA_REPRODUCIBLE_BUILD_ARGS[@]}" \
    --no-cache \
    --platform "$platforms" \
    --file "$worktree_dockerfile" \
    --output "type=oci,dest=${local_archive},rewrite-timestamp=true,compatibility-version=${UMBRA_BUILDKIT_COMPATIBILITY_VERSION},oci-mediatypes=true" \
    "$worktree_context" >"${CVM_REDEPLOY_RELEASE_DIR}/first-build.log" 2>&1 \
    || cvm_redeploy_fail "first local release build failed; nothing was published"
  local_runtime_digest="$(
    umbra_oci_layout_runtime_digest "$local_archive" "$git_sha" "$source_date_epoch"
  )" || cvm_redeploy_fail "local release output failed reproducibility and attestation validation"

  cvm_redeploy_info "building the second independent release subject from detached commit ${git_sha}"
  docker buildx build \
    "${UMBRA_REPRODUCIBLE_BUILD_ARGS[@]}" \
    --no-cache \
    --platform "$platforms" \
    --file "$second_worktree_dockerfile" \
    --output "type=oci,dest=${second_archive},rewrite-timestamp=true,compatibility-version=${UMBRA_BUILDKIT_COMPATIBILITY_VERSION},oci-mediatypes=true" \
    "$second_worktree_context" >"${CVM_REDEPLOY_RELEASE_DIR}/second-build.log" 2>&1 \
    || cvm_redeploy_fail "second independent local release build failed; nothing was published"
  second_runtime_digest="$(
    umbra_oci_layout_runtime_digest "$second_archive" "$git_sha" "$source_date_epoch"
  )" || cvm_redeploy_fail "second local release output failed reproducibility and attestation validation"
  [ "$second_runtime_digest" = "$local_runtime_digest" ] \
    || cvm_redeploy_fail "independent cache-disabled release builds produced different runtime digests"

  cvm_redeploy_info "logging in to ghcr.io with an isolated Docker client configuration"
  printf '%s' "$registry_password" \
    | docker login ghcr.io -u "$registry_user" --password-stdin >/dev/null 2>&1 \
    || cvm_redeploy_fail "docker login ghcr.io failed; verify the process-scoped publisher credential and package access"
  registry_user=""
  registry_password=""

  metadata_file="${CVM_REDEPLOY_RELEASE_DIR}/registry-build-metadata.json"
  cvm_redeploy_info "uploading one tagless attested result index by digest"
  docker buildx build \
    "${UMBRA_REPRODUCIBLE_BUILD_ARGS[@]}" \
    --no-cache \
    --platform "$platforms" \
    --file "$worktree_dockerfile" \
    --metadata-file "$metadata_file" \
    --output "type=registry,name=${image_repo},push-by-digest=true,rewrite-timestamp=true,compatibility-version=${UMBRA_BUILDKIT_COMPATIBILITY_VERSION},oci-mediatypes=true" \
    "$worktree_context" >"${CVM_REDEPLOY_RELEASE_DIR}/registry-build.log" 2>&1 \
    || cvm_redeploy_fail "content-addressed registry build failed; no tag was created"
  published_index_digest="$(jq -er '
    if .["containerimage.descriptor"].mediaType == "application/vnd.oci.image.index.v1+json"
        and (.["containerimage.descriptor"].digest | test("^sha256:[0-9a-f]{64}$"))
        and .["containerimage.digest"] == .["containerimage.descriptor"].digest
      then .["containerimage.digest"]
      else error("expected one content-addressed OCI result index")
    end
  ' "$metadata_file")" \
    || cvm_redeploy_fail "registry build metadata did not identify one OCI result index"

  index_json="$(docker buildx imagetools inspect "${image_repo}@${published_index_digest}" --raw 2>/dev/null)" \
    || cvm_redeploy_fail "could not inspect the immutable published image index"
  descriptors="$(printf '%s' "$index_json" | umbra_attested_index_descriptors)" \
    || cvm_redeploy_fail "could not resolve one attested linux/amd64 runtime manifest from the published index"
  runtime_digest="$(printf '%s' "$descriptors" | jq -er '.runtime_digest')" \
    || cvm_redeploy_fail "could not read the published runtime manifest digest"
  attestation_digest="$(printf '%s' "$descriptors" | jq -er '.attestation_digest')" \
    || cvm_redeploy_fail "could not read the published attestation manifest digest"
  if [[ ! "$runtime_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    cvm_redeploy_fail "registry returned an invalid runtime manifest digest"
  fi
  if [ "$runtime_digest" != "$local_runtime_digest" ]; then
    cvm_redeploy_fail "registry runtime digest does not match the local detached-worktree build"
  fi

  # Treat the registry as untrusted metadata: validate runtime config and every
  # attached predicate before selecting the deploy subject.
  runtime_config="$(
    docker buildx imagetools inspect \
      "${image_repo}@${runtime_digest}" \
      --format '{{json .Image}}' 2>/dev/null
  )" || cvm_redeploy_fail "could not inspect runtime image metadata"
  printf '%s' "$runtime_config" | umbra_runtime_image_config_valid "$git_sha" \
    || cvm_redeploy_fail "runtime image metadata does not match the reviewed source"
  attestation_json="$(
    docker buildx imagetools inspect "${image_repo}@${attestation_digest}" --raw 2>/dev/null
  )" || cvm_redeploy_fail "could not inspect the attestation manifest"
  printf '%s' "$attestation_json" | umbra_attestation_manifest_valid "$runtime_digest" \
    || cvm_redeploy_fail "image attestations do not bind the required SBOM/provenance descriptors to the runtime"
  provenance_json="$(
    docker buildx imagetools inspect \
      "${image_repo}@${published_index_digest}" \
      --format '{{json .Provenance}}' 2>/dev/null
  )" || cvm_redeploy_fail "could not inspect the published provenance"
  # imagetools keys the result by platform only for multi-platform indexes; a
  # single-platform (linux/amd64-only) index yields the flat {"SLSA": ...}
  # shape. Accept exactly those two shapes and nothing else.
  provenance_statement="$(printf '%s' "$provenance_json" | jq -cer '
    if keys == ["linux/amd64"]
        and (."linux/amd64" | keys) == ["SLSA"]
      then ."linux/amd64".SLSA
    elif keys == ["SLSA"]
      then .SLSA
    else error("expected one linux/amd64 SLSA predicate")
    end
    | {
        _type: "https://in-toto.io/Statement/v1",
        predicateType: "https://slsa.dev/provenance/v1",
        subject: [],
        predicate: .
      }
  ')" || cvm_redeploy_fail "published provenance has an unexpected platform or predicate shape"
  printf '%s' "$provenance_statement" \
    | umbra_provenance_statement_valid "$git_sha" "$source_date_epoch" \
    || cvm_redeploy_fail "published provenance does not match the reviewed release inputs"
  sbom_json="$(
    docker buildx imagetools inspect \
      "${image_repo}@${published_index_digest}" \
      --format '{{json .SBOM}}' 2>/dev/null
  )" || cvm_redeploy_fail "could not inspect the published SBOM"
  sbom_statement="$(printf '%s' "$sbom_json" | jq -cer '
    if keys == ["linux/amd64"] and (."linux/amd64" | has("SPDX"))
      then ."linux/amd64".SPDX
    elif keys == ["SPDX"]
      then .SPDX
    else error("expected one linux/amd64 SPDX predicate")
    end
    | {
        _type: "https://in-toto.io/Statement/v1",
        predicateType: "https://spdx.dev/Document",
        subject: [],
        predicate: .
      }
  ')" || cvm_redeploy_fail "published SBOM has an unexpected platform or predicate shape"
  printf '%s' "$sbom_statement" | umbra_sbom_statement_valid \
    || cvm_redeploy_fail "published SBOM is not a non-empty SPDX 2.3 document"

  CVM_REDEPLOY_IMAGE_REF="${image_repo}@${runtime_digest}"
  CVM_REDEPLOY_PROVENANCE_REF="${image_repo}@${published_index_digest}"
  cvm_redeploy_cleanup_release_workspace \
    || cvm_redeploy_fail "could not clean the isolated release workspace"
  cvm_redeploy_restore_release_exit_trap
}

# Render one barrier reason for a value the .env holds wrongly: what is there
# now, what it must become. Multi-line and column-aligned on purpose — two
# sha256 refs side by side on one line are unreadable.
#
# Non-secret, operator-pasteable values ONLY (image refs, measurements). This
# prints both values verbatim, and the barrier report lands in a retained CI log
# whenever deploy.sh runs it, so never pass a token, key, password or bearer.
# There is no legitimate secret use here anyway: the comparison is always against
# a value this script computed.
cvm_redeploy_mismatch() {
  local name="$1" current="$2" expected="$3"
  printf '%s mismatch\n' "$name"
  # %q, so a difference that is invisible as plain text — a CRLF from an edited
  # .env, a trailing space — is actually legible. This report is the operator's
  # only recourse at the safety-critical gate.
  if [ -n "$current" ]; then
    printf '    got:      %q\n' "$current"
  else
    printf '    got:      <unset>\n'
  fi
  printf '    expected: %q\n' "$expected"
  printf '    pin it in .env.<MODE>.secrets, then run:\n'
  printf '      make build-env MODE=<MODE> && make redeploy-console\n'
  printf '    editing the generated .env directly does not survive build-env, and\n'
  printf '    build-env is what propagates the layer into it'
}

# Report why the live launch cannot proceed. `verdict` is "blocked" when the
# caller will exit non-zero and "skipped" when it will exit 0 — the two read very
# differently to an operator, and docs/production-deploy.md documents the Dev
# skip as a benign stop, so only "blocked" gets a failure marker. The marker is
# ASCII per the docs/specs/cli-style.md registry ([OK]/[FAIL]/[WARN]). Reasons
# come as arguments and may span several lines; continuation lines stay indented
# under their reason.
cvm_redeploy_report_blocked() {
  local verdict="$1"
  shift
  local reason marker=""
  if [ "$verdict" = "blocked" ]; then
    marker="[FAIL] "
  fi
  echo "${CVM_REDEPLOY_LABEL}: ${marker}image is published, but live launch is ${verdict} until these are set:" >&2
  for reason in "$@"; do
    printf '%s: - %s\n' "${CVM_REDEPLOY_LABEL}" "$reason" >&2
  done
}

# Echo the Console base URL with any trailing slash removed.
cvm_redeploy_console_url() {
  local console_url="${CONSOLE_URL:-}"
  if [ -z "$console_url" ] && [ -n "${CONSOLE_HOST:-}" ]; then
    console_url="https://${CONSOLE_HOST}"
  fi
  if [ -z "$console_url" ]; then
    cvm_redeploy_fail "missing CONSOLE_URL or CONSOLE_HOST"
  fi
  printf '%s\n' "${console_url%/}"
}
