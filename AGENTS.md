# AGENTS.md

Guidance for coding agents working in this repository. `CLAUDE.md` is a symlink to this file; edit only `AGENTS.md`.

## Product

Umbra runs AI coding agents inside attested cloud sandboxes without giving them unconstrained network or secret access. The CLI is the user and operator surface. The Console owns auth, state, policy, audit, and orchestration. Dev CVMs host developer sandboxes. Security CVMs enforce every sandbox egress path.

## Read first

Before changing behavior, read:

- `README.md` and the affected module README;
- `docs/v0_plan.md` for architecture and trust boundaries;
- `docs/supply-chain-threat-model.md` for build and release trust boundaries;
- the relevant contract under `docs/specs/`;
- `docs/specs/cli-style.md` for human-readable CLI output;
- `skills/umbra-cli/SKILL.md` for CLI workflows and gotchas;
- `docs/environments.md`, `docs/operator-setup.md`, and `docs/production-deploy.md` when changing deployment behavior.

Specs are the contract. If a spec and implementation disagree, assume the implementation is wrong unless the task explicitly changes the contract. A spec change must ship with the implementation and documentation it motivates.

## Modules

| Module | Path | Owns |
| --- | --- | --- |
| CLI | `cli/` | Rust binary, command UX, local config/session state, Console API client, aTLS tunnel, and SSH/editor/agent wrappers. |
| Console | `console/` | FastAPI app, Postgres schema, auth/RBAC, profiles, quotas, CVM orchestration, audit, traffic logs, and provider adapters. |
| Dev CVM | `cvms/dev/` | Sandbox image, WebSocket SSH relay, fail-closed egress forwarder, atlas transport helper, and app compose. |
| Security CVM | `cvms/security/` | Egress proxy, policy pull, bearer identity, DLP, secret injection, CA export, traffic logging, and app compose. |

## Implementation map

| Area | Primary files |
| --- | --- |
| CLI tree and wiring | `cli/src/cli.rs`, `cli/src/lib.rs`, `cli/src/commands/` |
| CLI help and output | `cli/src/help.rs`, `cli/src/style.rs` |
| CLI Console client | `cli/src/console.rs`, `cli/src/operation.rs` |
| CLI local state | `cli/src/config.rs`, `cli/src/session.rs`, `cli/src/fsutil.rs` |
| CLI aTLS/SSH | `cli/src/commands/tunnel.rs`, `cli/src/commands/ssh.rs`, `cli/src/commands/cvm.rs` |
| Console routes | `console/src/umbra_console/app.py`, `routes.py`, `routes_auth.py`, `routes_internal.py` |
| Console providers | `console/src/umbra_console/tee_provider/`, `dns_provider/`, `shade_provider/` |
| Console scheduler | `console/src/umbra_console/scheduler.py` |
| Dev CVM runtime | `cvms/dev/docker-compose.yml`, `cvms/dev/shade.yml`, `cvms/dev/user-sandbox/` |
| Security CVM runtime | `cvms/security/docker-compose.yml`, `cvms/security/shade.yml`, `cvms/security/src/umbra_security_cvm/` |

## Common commands

```bash
make build
make test
make check
make fmt
make up
make down
make backup-console-db
```

Do not run reset, restore, table truncation, database drop, volume deletion, or another database-destructive command unless the user explicitly requests erasure. Schema changes use Alembic migrations and the normal startup path.

## Working rules

- Keep changes scoped and preserve unrelated user work.
- Fix root causes and reuse existing helpers before creating abstractions.
- Search the whole suite before adding a new test; extend a matching test when it already owns the guarantee.
- Keep specs, implementation, module READMEs, and operational guidance aligned.
- Never log or commit JWTs, refresh tokens, OIDC device codes, provider or registry credentials, service-principal bearers, private keys, CA export tokens, secret values, or filled environment files.
- Command payload goes to stdout; diagnostics go to stderr; non-zero CLI exits leave stdout empty.
- Do not accept secrets on argv.
- Do not push or publish unless the user explicitly asks.
- Use Conventional Commit subjects (`type(scope): subject`) and DCO sign-off as described in `CONTRIBUTING.md`; do not add agent attribution trailers.

## CLI conventions

- Rust 2021 on stable; use clap v4 derive APIs.
- Subcommands live under `cli/src/commands/` and are wired through `commands/mod.rs`, `cli.rs`, and `lib.rs`.
- Use `ExitStatus` from `cli/src/exit.rs`.
- Parametrized cases use `rstest` with named `#[case::label(...)]` rows. Keep a plain `#[test]` for a single or genuinely heterogeneous case.
- Test names end in `_success` or `_failure`, assert one outcome, and carry a short intent docstring.

## Python conventions

- Console uses `uv`, FastAPI, asyncpg, Alembic, structlog, and pytest.
- Security CVM uses Python 3.12, `uv`, httpx, google-re2, cryptography, pytest, and optional mitmproxy.
- Provider subprocess boundaries must be narrow and redact sensitive material.
- A test asserts one success or one failure outcome, with that outcome word last in its name and a one- or two-line intent docstring.
- Prefer `pytest.mark.parametrize` when setup and assertion shape are shared.

## Durable security invariants

- CVM updates are provider-neutral product flows: `umbra cvm update` and `umbra security-cvm update`. Provider-specific identifiers stay behind Console adapters.
- Security CVM attestation uses shade's complete authoritative `app_compose` plus `expected_bootchain`, `os_image_hash`, RTMR3 binding inputs, and MRTD. Missing runtime fields are an error; never relax Console verification to a development policy.
- Regenerate the Security CVM aTLS policy from current deployed compose on each provision, update, reconciliation, and probe. A stored stale policy can make Dev forwarders fail closed even when Console verification passes.
- `SECURITY_CVM_IMAGE_MEASUREMENT` is the dstack guest MRTD, not the app image version. Do not change it merely because an SC container digest changes.
- The Dev-side SC runtime-image check is temporarily disabled in clearly marked code. Genuine TEE, quote, TCB, certificate, EKM, and RTMR replay checks remain. Follow `docs/sc-policy-check-disabled.md` to remove the deviation.
- Dev forwarders poll for a rotated SC CA and the sandbox watcher replaces its CA bundle atomically. Already-running processes that cache trust may still need restart after rotation.
- Governed inbound WebSocket frames fail closed. Author separate assertions for each envelope and identity-path family; delivery is the union of matching assertions and JSON pointers are depth-limited.
- `profile configure` replaces the policy wholesale. Inline secret material not resupplied is removed; `value_from.user_secret` material is user-owned and is not stored with the profile.
- Browser/loopback and device OIDC flows require different Google client types. Configure separate clients for environments that support both.

Security vulnerabilities and sensitive incident material follow `SECURITY.md`, not public issues.
