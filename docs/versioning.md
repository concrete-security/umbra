# Versioning and compatibility

Umbra uses semantic versioning for published CLI releases. Before 1.0, a minor release may contain breaking changes and a patch release is intended to be backward compatible within that minor line. Release notes call out every known migration or compatibility break.

Only the latest pre-1.0 release is supported. The project will define a longer support window before declaring a stable 1.x line.

## Component compatibility

The CLI, Console, Dev CVM image, Security CVM image, installer, and deployment templates are released as one tested set. Operators should use the component versions and immutable image digests named by the same release. Mixing release sets is unsupported unless the release notes explicitly describe a rolling upgrade window.

The Console API may evolve before 1.0. A CLI should not be assumed compatible with a Console from another minor line. Attestation policies bind runtime material; changing a CVM image can require a Console rollout and CVM update rather than only replacing a container tag.

Database migrations are forward-only. Back up the Console database before an upgrade, read the release notes, and test the exact release set in a non-production environment. Rollback may require restoring that backup; do not assume an older Console can read a schema migrated by a newer release.

The initial public migration graph recognizes the exact deployed pre-Umbra head `0032_attn_unreachable` through lineage-only no-op revisions and merges it with the public secret-envelope branch at `0033_public_legacy_merge`. `0034_connect_oauth_schema` then installs Connect / OAuth / managed-secret schema on every database at that merge, including fresh Umbra installs. Always use complete revision IDs because both branches include an `0028...` revision. Downgrade across the merge is unsupported: restore the pre-upgrade backup.

## Release notes

Every release records:

- user-visible changes and fixed security issues;
- breaking changes and required operator action;
- supported platforms and known limitations;
- exact CLI and container versions or digests;
- database migration and rollback considerations;
- artifact checksums, signatures or attestations, provenance, and SBOM links;
- any temporary compatibility window between components.

Unreleased changes are collected in `CHANGELOG.md`. The GitHub release is the authoritative immutable note for a published version.

## Artifact retention and revocation

Published version tags, release notes, checksums, SBOMs, provenance, and image digests are permanent records. A version, tag, or versioned asset is never silently replaced or reused. GitHub Actions artifacts are temporary transport between jobs and are not the archival copy; the corresponding versioned GitHub release and container registry digest are the retention sources.

Versioned CLI assets and container manifests are retained for at least 24 months after they leave support. The mutable `latest` installer mirror is only a convenience pointer and has no retention guarantee. Source tags, release notes, integrity metadata, and any revocation notice are retained indefinitely.

When a release must be revoked, maintainers publish a security advisory or prominent release-note update, remove it from `latest`, yank the crate where appropriate, and publish a fixed new version. They do not move its tag or reuse its version. If an artifact itself is unsafe to keep downloadable, maintainers may remove that payload, but preserve its digest, provenance identity, reason for removal, and replacement version in the release record. Rollback always selects a separately published, still-trusted version; it never mutates an old release in place.
