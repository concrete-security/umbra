#!/usr/bin/env sh
set -eu

program="verify-cli-release-artifact"
verifier="${UMBRA_INSTALL_SLSA_VERIFIER:-}"
builder_id="https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0"

fail() {
  printf '%s: %s\n' "$program" "$1" >&2
  exit 1
}

[ -n "$verifier" ] \
  || fail "UMBRA_INSTALL_SLSA_VERIFIER must name the trusted preinstalled verifier"
case "$verifier" in
  /*) ;;
  *) fail "UMBRA_INSTALL_SLSA_VERIFIER must be an absolute executable path" ;;
esac
[ -x "$verifier" ] || fail "trusted slsa-verifier is missing or not executable: ${verifier}"

if [ "${1:-}" = "--check" ] && [ "$#" -eq 1 ]; then
  exit 0
fi

[ "$#" -eq 3 ] \
  || fail "usage: $program ARTIFACT PROVENANCE OWNER/REPO"
artifact="$1"
provenance="$2"
repo="$3"
[ -f "$artifact" ] && [ -s "$artifact" ] || fail "artifact is missing or empty: ${artifact}"
[ -f "$provenance" ] && [ -s "$provenance" ] || fail "provenance is missing or empty: ${provenance}"
case "$repo" in
  */*) ;;
  *) fail "release repository must be OWNER/REPO, got ${repo}" ;;
esac
case "$repo" in
  *[!0-9A-Za-z._/-]* | */*/*) fail "release repository must be OWNER/REPO, got ${repo}" ;;
esac

"$verifier" verify-artifact "$artifact" \
  --provenance-path "$provenance" \
  --source-uri "github.com/${repo}" \
  --source-branch main \
  --build-workflow-input dry_run=false \
  --builder-id "$builder_id" \
  || fail "SLSA provenance verification failed for $(basename "$artifact")"
