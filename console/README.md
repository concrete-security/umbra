# Console

The Umbra Console is the HTTPS control plane. It runs with Postgres and a TLS reverse proxy and is not itself a TEE. Developers and administrators use it through the `umbra` CLI.

The Console owns authentication, authorization, multi-tenant resource state, CVM provisioning, policy management, audit, traffic logs, and reconciliation. Its authoritative contract is `docs/specs/console.md`.

## Responsibilities

- Verify Google OIDC and issue/revoke Console sessions.
- Enforce entity scoping, RBAC, quotas, and profile membership.
- Store entities, users, SSH keys, profiles, CVMs, operations, audit events, traffic logs, and service-principal metadata.
- Orchestrate Dev and Security CVMs through narrow provider adapters.
- Render per-CVM attestation and effective policy material.
- Serve authenticated internal policy, CA-refresh, and traffic-log endpoints.
- Maintain tamper-evident audit chains and scheduled exports.

```text
CLI users/admins
      |
      | HTTPS REST + OIDC sessions
      v
Console + Postgres
      |
      | shade, TDX provider, DNS, atlas verification
      v
Dev CVMs and Security CVMs
      ^
      | authenticated policy/CA reads and traffic-log ingest
      |
Security and Dev CVM control clients
```

The Console is trusted for control-plane policy and state. It is not in the developer-to-Dev-CVM aTLS data path; the CLI verifies that path locally.

## Run and test

From the repository root:

```bash
make up
make bootstrap
make down

uv run --locked --project console python -m pytest console/tests
make check
make test
```

The repository pins Python 3.12 in `.python-version`, matching the Console container. `uv` provisions it when necessary; newer Python minors are not part of the supported or release-tested runtime. The Console image restores the dated Debian snapshots recorded by its digest-pinned Rust and Python bases before installing system packages, so a later repository update cannot silently change the same source build.

The final image normalizes application-tree permissions before switching to unprivileged UID/GID 10001. A restrictive source-checkout umask therefore cannot make Alembic metadata or installed application files unreadable at startup, while the runtime user remains unable to modify the image contents.

`console/package.json` is a private build manifest, not a package intended for npm publication. Its pinned `phala` runtime dependency supplies the provider CLI and narrow compose-hash helper; the development-only `tailwindcss` dependency rebuilds the operator dashboard CSS. The container installs the lock with package scripts disabled and prunes development dependencies.

The ordinary Console suite uses fake asyncpg connections and needs no database. Database integration tests are opt-in through `UMBRA_TEST_DATABASE_URL` and must point at a role allowed to create a throwaway database. Never point them at a production database.

## Main entry points

| Area | Location |
| --- | --- |
| FastAPI app | `src/umbra_console/app.py` |
| Public REST routes | `src/umbra_console/routes.py` |
| Auth routes | `src/umbra_console/routes_auth.py` |
| OAuth / Connect | `src/umbra_console/routes_oauth.py`, `routes_connect.py`, `oauth_endpoints.py`, `static/connect/` |
| Internal routes | `src/umbra_console/routes_internal.py` |
| Bootstrap | `src/umbra_console/bootstrap.py` |
| Scheduler | `src/umbra_console/scheduler.py` |
| TDX provider adapter | `src/umbra_console/tee_provider/` |
| DNS provider adapter | `src/umbra_console/dns_provider/` |
| shade adapter | `src/umbra_console/shade_provider/` |
| Alembic migrations | `alembic/versions/` |
| Tests | `tests/` |

## Runtime notes

- Public routes live under `/api/v1`; authenticated CVM control routes live under `/internal`.
- Middleware owns request IDs, body/JSON guards, canonical UUID paths, security headers, rate limits, metrics, and normalized error envelopes.
- Provider subprocess adapters allowlist environment, stage private material at restrictive modes, avoid shell invocation, and redact errors.
- CVM update APIs are provider-neutral. Provider-specific IDs and commands stay inside adapters.
- After approved runtime images are published for anonymous reads, leaving every `DSTACK_DOCKER_*` value unset makes the Console forward no registry credential to the provider or CVM. Before that publication, and for any private registry, self-hosters must explicitly set the complete `DSTACK_DOCKER_REGISTRY`, `DSTACK_DOCKER_USERNAME`, and `DSTACK_DOCKER_PASSWORD` trio; partial configuration is rejected.
- `GHCR_USER`, `GHCR_TOKEN`, and `GH_TOKEN` are one-shot host process inputs. `build-env` rejects them from merged runtime layers, and Compose keeps legacy values out of the Console and installer containers.
- Attestation uses the bundled `umbra-atlas-verify` helper and complete shade runtime policy. Missing authoritative runtime fields fail closed.
- Profile inline values and user secrets are write-only. They are decrypted only while materializing authenticated Security CVM control policy.
- `SECRET_INJECTION_KEK_B64` must decode to 32 random bytes, remain stable with the database, and must not reuse JWT signing material.

## Data safety

Console state is durable. Schema changes require Alembic migrations and normal startup deployment. Do not drop or truncate tables, delete Compose volumes, reset the database, or run restore as a debugging technique. Use `make backup-console-db` before upgrades and follow `docs/versioning.md`.

The public migration graph contains a lineage-only compatibility branch for the exact deployed pre-Umbra head `0032_attn_unreachable`. Its no-op revisions let that durable database run the real public migrations and converge at `0033_public_legacy_merge`. `0034_connect_oauth_schema` then installs the public Connect / OAuth / managed-secret tables and audit actions (idempotent on a database that already has them). Use full revision IDs because both branches contain a revision beginning with `0028`. Downgrade across the merge is unsupported; restore the pre-upgrade database backup instead.

Generic self-host setup and deployment guidance lives in `docs/operator-setup.md` and `docs/production-deploy.md`.

## Scope

The v0 Console supports Google OIDC, one Security CVM per entity, provider-backed Dev CVMs, profile policy, OAuth Connect and managed-secret rotation, audit, traffic logs, and the operator dashboard. Additional identity providers, high availability, and connector/tool CVMs are outside the current v0 contract unless their specifications say otherwise.
