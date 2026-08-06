# Contributing to Umbra

Thank you for helping improve Umbra. Bug reports, documentation fixes, tests, threat-model feedback, and focused code changes are welcome.

## Before opening a change

Open an issue first for large features, architecture changes, new external services, or changes to an attestation or enforcement boundary. Security vulnerabilities must follow `SECURITY.md` and must not be filed publicly.

Keep changes scoped. Specs under `docs/specs/` are the behavioral contract; a behavior change must update the relevant spec and module README in the same pull request. Never include credentials, tokens, production identifiers, private incident material, or personal data in code, fixtures, logs, or issue content.

## Local checks

The normal contributor path uses local toolchains and Docker. It does not need access to the maintainers' Google, GCP, Cloudflare, Phala, or GHCR accounts. Documented repository gates and project commands use `.python-version`; `uv` provisions the exact pinned Python 3.12 patch when it is not already installed.

```bash
make check
make test
```

Some live deployment and attestation tests require paid third-party services and maintainer credentials. Maintainers run those protected gates after review; external contributors are not expected to possess those credentials.

Follow the Rust and Python test conventions in `AGENTS.md`. Add or extend a test that proves the changed outcome, and state which commands you ran in the pull request.

## Developer Certificate of Origin

Umbra uses the [Developer Certificate of Origin 1.1](https://developercertificate.org/). Sign off every commit with:

```bash
git commit -s
```

The resulting commit message must contain a `Signed-off-by: Name <email>` line that matches the commit author. The sign-off certifies that you have the right to submit the work under the repository's license. It is not an assignment of copyright. Pull requests with unsigned commits do not pass the contribution gate.

Do not add agent attribution or `Co-Authored-By` trailers. Squash or amend commits as needed so every commit in the submitted history is signed off.

## Review

Maintainers may request changes for correctness, security, tests, documentation, compatibility, or project scope. Sensitive paths identified in `.github/CODEOWNERS` require review from their designated owners. A green CI run does not replace review of trust-boundary changes.

Unless a file says otherwise, contributions are made under the same license that applies to the repository (inbound equals outbound).
