# Changelog

Umbra follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and will use semantic versioning once a stable compatibility contract is declared.

## Unreleased

## [0.1.0] - 2026-08-19

First public release of `umbra-cli`.

### Added

- Initial public source release of the CLI, Console, Dev CVM, Security CVM, specifications, self-host templates, and CI/release definitions.
- Pinned Python 3.12 application/test and CI environments, exact-key pull-request caches, and documented release artifact retention and revocation.
- Snapshot-pinned Dev image OS packages and direct SHA-256-pinned Docker Engine, CLI, containerd, Buildx, and Compose packages.
- Snapshot-pinned Debian inputs for Console and Security CVM images, plus exact Alpine package closures for the installer and reverse proxy.
- Public CI diagnostics no longer reproduce malformed environment lines, raw provider stderr, malformed operation bodies, verifier identities, or private canary manifests.
- Rust and Python package metadata carries the Apache-2.0 license and the canonical `concrete-security/umbra` repository, documentation, and issue-tracker URLs.
- The Console migration graph now recognizes the exact deployed pre-Umbra database head, retains dormant legacy schema and data, applies the public secret-envelope migration, and converges fresh and migrated databases at one canonical head.

### Distribution transition

- Pre-public proprietary CLI artifacts are a separate, incompatible release line. They are not open-source releases or an update channel into Umbra. The first public release notes will identify the new license, verified reinstall path, artifact attestations, and compatibility expectations.

Until the first public version is cut, source and configuration compatibility may change without notice.
