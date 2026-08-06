# Environments

Umbra supports three deployment modes with the same component shape and different isolation and availability expectations. This document intentionally uses reserved examples; it contains no maintainer topology or live values.

## Deployment topology

| Mode | Intended use | Example Console | Source branch | Expectations |
| --- | --- | --- | --- | --- |
| DEV | Local or disposable integration work | `console.dev.example.com` | feature branch | May use test certificates and local Postgres. Never share provider credentials with staging or production. |
| STAGING | Production-like release verification | `console.staging.example.com` | `dev` | Separate cloud identity, provider workspace, DNS namespace, database, keys, and OIDC clients. |
| PROD | User-serving deployment | `console.example.com` | `main` | Protected deployment environment, independent credentials and state, backups, monitoring, and reviewed promotion. |

Each deployed environment consists of:

```text
public DNS
  console.<environment-domain> ──> operator host
  cvm-*.<dev-cvm-domain>       ──> provider-managed Dev CVMs
  sc-*.<security-cvm-domain>   ──> provider-managed Security CVM

operator host
  reverse proxy + Console + Postgres
             |
             +── DNS provider
             +── TDX CVM provider
             +── container registry
             +── OIDC provider
```

The public workflows use GitHub-hosted runners and connect to an environment host with short-lived cloud federation. Repository and environment variables identify the provider, project, VM, zone, and checkout path. Credentials and runtime secrets remain in protected environment state or on the host; they are not committed and must not be printed by a workflow.

CLI publication uses a third GitHub environment, `release`. It has no deployment host or cloud identity: it gates the main-only publish job. Configure an independent required reviewer, prevent self-review, disable administrator bypass where supported, and restrict deployments to `main` before a non-dry-run release.

## Host bootstrap trust

After cloning the repository, provision host tools without `sudo`:

```bash
bash ops/host/provision-host.sh
```

The script never executes downloaded installer scripts or adds repository signing keys. Linux installs resolve only through already-configured signed `apt` sources; macOS installs use an existing trusted Homebrew installation. If Linux sources do not provide `rustup` or `uv`, or the optional Phala path cannot provide Node.js 18 or newer with npm, the script exits with precise preinstallation guidance. Configure an organization-approved signed package source or preinstall the missing tool, then rerun.

Rust follows the channel in `rust-toolchain.toml`, including `rustfmt` and `clippy`. Homebrew's `rustup` formula is keg-only, so macOS users must add `$(brew --prefix rustup)/bin` to their shell `PATH`. Docker Desktop remains an explicit macOS prerequisite; the script prints its Homebrew cask command when Docker is absent.

## Configuration layers

Build the runtime `.env` from four non-overlapping layers:

| Layer | Tracked | Contents |
| --- | --- | --- |
| `.env.common` | yes | Non-secret defaults shared by every mode. |
| `.env.<mode>` | yes | Neutral, non-secret environment template. |
| `.env.admin` | no | Host/operator paths and local account details. Start from `.env.admin.example`. |
| `.env.<mode>.secrets` | no | OIDC, DNS, provider, encryption, metrics, and immutable image material. Start from `.env.MODE.secrets.example`. |

```bash
cp .env.admin.example .env.admin
cp .env.MODE.secrets.example .env.staging.secrets
make build-env MODE=staging
```

Every key belongs to exactly one layer. `make build-env` rejects duplicates; do not rely on last-value-wins overrides. The generated `.env` is ignored and must never be copied into an issue, log, artifact, or commit.

The committed prod and staging values are examples, including RFC 5737 IP addresses and `example.com` hostnames. Replace them before deployment.

## Isolation requirements

- Use a separate TDX-provider workspace and API token per environment. Cleanup operates on Umbra-owned names visible to that token; sharing a workspace can cross environment boundaries.
- Use disjoint Dev and Security CVM DNS namespaces. They may be separate zones or visibly disjoint subdomains under one zone.
- Use separate databases, JWT signing keys, secret-injection encryption keys, OIDC clients, and Console session caches for staging and production.
- Use separate cloud federation identities and least-privilege deployers. Bind each identity to the exact repository, workflow, branch, and protected environment that needs it.
- Keep production deployment and CLI publication behind their separate required reviewers with self-approval disabled. A staging identity must not be able to reach production resources, and the `release` environment must grant no cloud deployment authority.
- Pin released containers by immutable digest. A tag is not deployment trust material.
- Back up durable Console data before migrations or upgrades. Never use reset or restore as an ordinary deploy step.

Google's browser/loopback and device authorization flows require different OAuth client types. Configure both when the environment supports interactive CLI login and headless verification.

## GitHub configuration

The staging and production environments supply these non-secret variables:

| Variable | Placeholder |
| --- | --- |
| `GCP_WORKLOAD_IDENTITY_PROVIDER` | `projects/<number>/locations/global/workloadIdentityPools/<pool>/providers/<provider>` |
| `GCP_SERVICE_ACCOUNT` | `<deployer>@<project>.iam.gserviceaccount.com` |
| `GCP_PROJECT` | `<project-id>` |
| `VM_INSTANCE` | `<instance-name>` |
| `VM_ZONE` | `<zone>` |
| `VM_REPO_DIR` | `/opt/umbra/umbra` |

The path must not depend on a human home directory because federated deployers may map to distinct host users.

See [operator setup](operator-setup.md) for external accounts and local material, [CI/CD](ci-cd.md) for federation and protections, and [production deploy](production-deploy.md) for the generic release flow.
