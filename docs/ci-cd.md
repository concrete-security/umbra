# CI/CD pipeline

Umbra separates public artifact production from private environment deployment:

```text
feature branch --PR--> dev --reviewed promotion--> main --tag/release--> immutable artifacts
                                                                        |
                                                   private deployment repo pins exact digests
```

| Stage | Trigger | Workflow | Purpose |
| --- | --- | --- | --- |
| PR gate | PR to `dev` | `.github/workflows/pr-gate.yml` | Run `make check` and `make test` without live credentials. |
| Security checks | repository security triggers | `.github/workflows/security.yml` | Run public dependency, source, and artifact security gates. |
| CLI release | manual | `.github/workflows/publish-cli.yml` | Package and publish one reviewed version and its installer tree. |

The public repository contains no staging or production deployment workflow. The maintainers' private deployment repository records the exact public commit, release tag, image digest, SBOM, and provenance selected for each environment, and owns all live deployment orchestration.

All third-party Actions references use full commit SHAs except the SLSA generator, whose reviewed exception is exactly `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.1.0`. The generator requires a semver tag for builder-identity reconstruction. The repository checker recognizes quoted and unquoted YAML keys and cross-checks this exception against the CLI updater and bootstrap installer's exact builder IDs; update those trust pins and their tests together.

## Contributor boundary

Pull-request jobs run on GitHub-hosted runners with read-only repository permissions and no deployment secrets. Fork pull requests must never receive cloud federation, registry publishing, OIDC clients, provider credentials, production environments, or caches containing private material.

The local contributor contract is:

```bash
make check
make test
```

Live verification uses the private deployment repository and maintainer infrastructure; it is not required from an external contributor's cloud account.

## Build-cache boundary

The pull-request gate caches only public Cargo inputs, Cargo build output, and uv downloads. Its exact cache keys include the Python pin, Rust toolchain, and all Rust and Python locks; there are no prefix fallback keys. A clean cache miss must pass the same locked gates.

Pull-request merge-ref caches do not flow into protected branches. Default-branch caches may flow into a pull request, but contain no credentials or local configuration. Release and deployment jobs restore no pull-request cache.

## Deployment boundary

The public repository is authoritative for source, tests, release artifacts, image digests, SBOMs, and provenance. It has no cloud deployment identity and receives no staging or production credentials.

The private deployment repository is authoritative for environment lock files, Workload Identity Federation conditions, service accounts, hosts, databases, provider workspaces, approval gates, session caches, rollback state, and recovery material. It consumes only immutable public artifacts and never rebuilds product source for deployment.

## Environment protection

Configure GitHub before accepting public contributions or publishing releases:

- protect `dev` with required PR review, `check`, and `test`;
- protect `main` with required PR review and the same source gates;
- create a separate `release` environment for `.github/workflows/publish-cli.yml`, restrict it to `main`, require an independent reviewer, prevent self-review, and disable administrator bypass where supported;
- disable force pushes and branch deletion;
- enable secret scanning, push protection, dependency review, and the DCO gate;
- restrict Actions to approved immutable references.

An `environment: release` declaration does not protect a publication by itself: GitHub will create an unprotected environment when the named environment is missing. Capture the `release` environment's deployment-branch policy and reviewer settings through the GitHub API before the first non-dry-run release.

## Host model

The maintainers' deployment hosts are managed only by the private deployment repository; the public workflows never connect to them. Self-hosters should keep SSH off the public internet, use short-lived host access, and keep environment layers, cryptographic material, OIDC sessions, and recovery state outside the public checkout.

See [operator setup](operator-setup.md) and [environments](environments.md) for the generic host and configuration shape.

### Reboot persistence

The Console Compose stack (`docker-compose.yml`) sets no `restart:` policy and no service manager wraps it, so a host reboot leaves the Console down until someone re-runs the deploy. Install a systemd **oneshot** unit per host that brings the stack up on boot from `VM_REPO_DIR`:

```ini
# /etc/systemd/system/umbra-console.service
[Unit]
Description=Umbra Console Compose stack
After=docker.service network-online.target
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/opt/umbra/umbra        # = VM_REPO_DIR
ExecStart=/usr/bin/make up
ExecStop=/usr/bin/make down

[Install]
WantedBy=multi-user.target
```

Enable with `sudo systemctl enable --now umbra-console.service`. The `make up` entrypoint is intentional: it runs the durable-state cutover guard before any Compose volume or container can be created, then returns after Compose starts the containers in detached mode; `Type=oneshot` + `RemainAfterExit=yes` records the detached stack as active. Do not point the unit at `docker compose up` directly — that would bypass the state guard.

## Log and command hygiene

Public workflow logs are permanent publication surfaces. Scripts and workflows must:

- avoid shell tracing around credentials;
- pass secrets through stdin, protected environment, or private files, never argv;
- never print bearer headers, OIDC codes or tokens, filled `.env` data, session JSON, private keys, or full provider deploy material;
- redact subprocess errors before forwarding them;
- keep uploaded artifacts limited to reviewed non-secret reports;
- pin third-party Actions and downloaded tools to reviewed immutable versions.

Review log behavior whenever deployment primitives, verification tooling, a workflow, or a provider adapter changes.

## Issue workflow

CI failures and ordinary bugs use public GitHub issues when their reproduction contains no sensitive data. Security vulnerabilities follow `SECURITY.md` and must not be filed publicly. Maintainers may keep deployment incidents private, then file a separate sanitized public bug when a source change is needed.

No external issue-tracker integration is required by this repository.

## Promotion procedure

1. Merge a reviewed, green PR into `dev`.
2. Open a reviewed `dev` to `main` PR after the public source gates pass for the exact candidate SHA.
3. Tag and publish immutable CLI and image artifacts with their SBOMs and provenance.
4. Update the private deployment repository to pin those exact public identifiers, verify them in staging, then promote the same digests to production under the private deployment gates.

No public-repository workflow deploys a maintainer-operated environment.
