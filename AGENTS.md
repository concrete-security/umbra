# AGENTS.md

Umbra runs coding agents in attested CVMs with governed network and secret access. `CLAUDE.md` is a symlink to this file; edit only `AGENTS.md`.

## Scope and completion

- Preserve user and concurrent work.
- Complete implementation requests through relevant verification, fixing failures caused by the change. Finish when the requested behavior works and affected contracts and docs agree, or report a concrete blocker. Local edits and checks need no repeated approval.
- Do not push, publish, deploy, open a PR, or mutate external systems without explicit authorization; continue authorized local preparation.
- Never log or commit credentials, OIDC device codes, private keys, secret values, or filled environment files. Do not accept secrets on argv. Handle vulnerabilities and private incident material through `SECURITY.md`.

## Context for the task

Specs under `docs/specs/` are the behavioral contract: treat an implementation mismatch as a bug unless the task explicitly changes the contract. Check a spec's status before treating a proposal as implemented behavior. Keep affected specs, implementation, tests, generated OpenAPI, and documentation aligned.

Consult module READMEs when component context is needed. Use these references for the corresponding task:

| Task | Reference |
| --- | --- |
| Architecture or trust boundaries | `docs/v0_plan.md` |
| Build or release trust boundaries | `docs/supply-chain-threat-model.md` |
| CLI implementation or output | `cli/README.md`, `docs/specs/cli-style.md` |
| Operating the CLI | `cli/assets/umbra-cli/SKILL.md` |
| Deployment | `docs/environments.md`, `docs/operator-setup.md`, `docs/production-deploy.md` |

## Verification and conventions

Run repository commands from the root using the invocations and toolchain pins in `Makefile`. `make check` and `make test` are the contributor gates in `CONTRIBUTING.md`; documentation-only changes need diff and reference checks. Repeat passing checks only for new edits or unresolved concerns.

- `make test` is DB-less unless `UMBRA_TEST_DATABASE_URL` is set. Never point tests at production.
- `make test-console-db` may create and clean up its own isolated Postgres container. Erasing existing database state through reset, restore, truncation, database drop, or volume deletion requires an explicit user request. Schema changes use Alembic migrations and normal startup.
- `make check` includes Docker-backed smoke checks. Image reproducibility is a separate opt-in gate: `make verify-cvm-images-repro`.
- `make up` and `make down` operate the configured stack; apply the external-system authorization boundary above.

Tests assert one success or failure outcome, have names ending in `_success` or `_failure`, and include a short intent docstring. Extend an existing test when it already owns the guarantee.

- Rust: use `rstest` with named `#[case::label(...)]` rows for parametrized cases; retain plain `#[test]` for single or heterogeneous cases.
- Python: use `pytest.mark.parametrize` when setup and assertions share a shape.

Use Conventional Commit subjects (`type(scope): subject`) and DCO sign-off (`git commit -s`) as described in `CONTRIBUTING.md`. Do not add agent attribution or `Co-Authored-By` trailers.

## Attestation pitfalls

- Console Security CVM verification needs shade's complete, current runtime policy; missing required fields fail closed. Regenerate the Dev-facing aTLS policy on provision, update, reconciliation, and probe. Details are in `docs/specs/console.md` §10.4 and `docs/specs/security-cvm.md` §2.
- `SECURITY_CVM_IMAGE_MEASUREMENT` is the dstack guest MRTD, not the app image version. A container digest change alone must not change it.
- The Dev-side SC runtime-policy exception and its removal criteria live in `docs/sc-policy-check-disabled.md`. Do not extend that exception to Console verification or disable the remaining checks.
