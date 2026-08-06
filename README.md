# Umbra

Umbra runs AI coding agents in attested cloud sandboxes with governed network and secret access. Developers use a CLI to create and enter Dev CVMs; all sandbox egress is forced through an entity Security CVM for policy enforcement, secret scanning, proxy-time credential injection, and traffic logging.

Umbra is an independent project. Its intended public home is `concrete-security/umbra` on GitHub; publication remains gated on maintainers proving control of that repository and its release identities.

> Umbra is pre-1.0 software. Interfaces, deployment requirements, and compatibility may change between minor releases. Only the latest pre-1.0 release is supported; see [versioning](docs/versioning.md).

## Architecture

```text
developer/admin machine
  umbra CLI
      |
      | HTTPS REST + OIDC
      v
operator environment
  Console + Postgres + TLS reverse proxy
      |
      | provisioning, DNS, and attestation
      v
attested CVMs
  Dev CVM ---- forced aTLS proxy ----> Security CVM ---- TLS ----> internet
```

| Module       | Path             | Role                                                                                                                        |
| ------------ | ---------------- | --------------------------------------------------------------------------------------------------------------------------- |
| CLI          | `cli/`           | Authentication, local state, CVM lifecycle, verified tunnels, SSH/editor/agent sessions, profiles, audit, and traffic logs. |
| Console      | `console/`       | HTTPS control plane for OIDC, sessions, RBAC, resource state, orchestration, policy, audit, and reconciliation.             |
| Dev CVM      | `cvms/dev/`      | Per-developer TDX sandbox with SSH, persistent sessions, Docker, and fail-closed egress forwarding.                         |
| Security CVM | `cvms/security/` | Per-entity egress proxy for policy, DLP, credential injection, CA export, and traffic-log emission.                         |

The Console is a conventional HTTPS control plane. The attested Dev and Security CVMs are the confidential-compute boundary. The trust model and component contracts are described in [the v0 plan](docs/v0_plan.md), the [supply-chain threat model](docs/supply-chain-threat-model.md), and the documents under [docs/specs/](docs/specs/).

## Try the CLI

If an operator has already provisioned your account and assigned a profile:

After the first approved release and its provenance are published, install the CLI with the SLSA-verified procedure in the [developer quick start](docs/quick-start.md#install). A source build is the documented path before that launch gate. Then:

```bash
umbra auth login https://console.example.com
umbra cvm launch
umbra ssh
```

See the [developer quick start](docs/quick-start.md) for SSH keys, editors, Claude Code, Codex, and common troubleshooting.

## Self-host

A live deployment currently requires a Linux host plus accounts or credentials for an OIDC provider, DNS, a supported TDX CVM provider, a container registry, and persistent Postgres. These services may be paid and their cost depends on region and instance size.

Start with:

- [environment model](docs/environments.md);
- [operator setup](docs/operator-setup.md);
- [deployment guide](docs/production-deploy.md);
- [CI/CD model](docs/ci-cd.md).

The committed environment files contain reserved examples only. Put secrets in the gitignored layers described by the setup guide, never in a tracked file.

## Develop

The normal contributor gates are local and do not require maintainer cloud credentials:

```bash
make build
make check
make test
```

Read the module README before changing a component:

- [CLI](cli/README.md)
- [Console](console/README.md)
- [Dev CVM](cvms/dev/README.md)
- [Security CVM](cvms/security/README.md)

Specs are the behavioral contract. A behavior change should update its spec, implementation, tests, and affected README together. See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md) for repository conventions.

## Security boundary

Umbra governs traffic opened by processes inside the Dev CVM network namespace. Local workstation tools and provider-hosted editor or browser tools may open their own network connections outside that boundary. Use an agent or shell running inside the Dev CVM when Security CVM egress enforcement is required.

Do not use an attestation bypass in a production or release-verification path. The temporary Security CVM image-policy deviation is documented openly in [docs/sc-policy-check-disabled.md](docs/sc-policy-check-disabled.md).

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

## Project information

- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [Versioning and compatibility](docs/versioning.md)
- [Governance](GOVERNANCE.md)
- [Support](SUPPORT.md)
- [Code of conduct](CODE_OF_CONDUCT.md)
- [Trademarks](TRADEMARKS.md)
- [Authors](AUTHORS.md)

Licensing terms are in [LICENSE.txt](LICENSE.txt).
