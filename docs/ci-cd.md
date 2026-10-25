# CI/CD pipeline

Umbra separates public artifact production from private environment deployment:

```text
feature branch --PR--> dev --reviewed promotion--> main --tag/release--> immutable artifacts
                                                                        |
                                                   private deployment repo pins exact digests
```

| Stage | Trigger | Workflow | Purpose |
| --- | --- | --- | --- |
| PR gate | PR to `dev` or `main` | `.github/workflows/pr-gate.yml` | Run `make check` and `make test` without live credentials. |
| Security checks | repository security triggers | `.github/workflows/security.yml` | Run public dependency, source, and artifact security gates. |
| CVM image candidate | push to `dev`; manual after promotion | `.github/workflows/publish-cvm-images.yml` | Reproduce and publish digest-only Dev/Security images with SBOM and provenance, then test those exact runtime images. |
| Selected CVM image verification | manual | `.github/workflows/verify-release-images.yml` | Repeat runner tests for immutable images selected from a successful publication candidate. |
| CLI release | manual | `.github/workflows/publish-cli.yml` | Package and publish one reviewed version and its installer tree. |

Security analysis runs on pushes to `dev`, `main`, and `codex/security-*`, on pull requests to `dev` or `main`, and by manual dispatch. Use a security patch branch to rerun source and image scans without the `dev` push publisher. These branch scans do not refresh default-branch Dependabot alerts; those reflect the dependency manifests on `main`.

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

### Runner release-image gate

After both CVM images publish, `publish-cvm-images.yml` assembles
`deployment-lock.candidate.json` and validates it with
`ops/verify/select-release-test-images.py`. The selector rejects duplicate JSON
keys, noncanonical repositories, mutable refs, mismatched source commits, and
inconsistent guest measurements. Its source must equal the workflow's full
commit SHA. Null measurements remain valid because this job has no TDX hardware.

The downstream `release-images` job calls `verify-release-images.yml` with those
exact runtime digest refs. It checks out the image source commit and runs
`make test-release-images` on a Linux amd64 GitHub-hosted runner. The target
pulls the images, checks their source labels, and runs the release-image tests
without rebuilding either image. A test failure makes the publication workflow
fail, even though the immutable images and candidate already exist. Consumers
must require the complete publication workflow to succeed before selecting its
candidate.

After all tests pass, the job uploads only
`artifacts/release-image-tests.json`. This receipt binds the exact image refs,
inspected image config IDs, source commit, and SHA-256 of the raw candidate.
It also lists untested hardware, provider, OIDC, Sysbox, aTLS, and production
TLS boundaries. Failed tests produce no success receipt. Logs, credentials,
and private configuration are not uploaded.

This job has repository and package read permissions. Registry pulls use the
workflow token and a temporary Docker credential directory, removed after the
tests. It uses no deployment environment, cloud identity, provider credentials,
private state, or pull-request cache.

To repeat the gate manually, run **Verify release images** on `dev` or `main`.
Supply a successful **Publish CVM images** run ID and the two exact digest refs
from its candidate. The workflow authenticates the publication's repository,
workflow path, event, branch, conclusion, and full source SHA. It downloads that
run's candidate and rejects selected refs that differ from its contents.
Expired or missing candidate artifacts fail the manual selection.

If publication succeeded but its downstream release-image tests failed, rerun
the failed jobs in that publication workflow. Manual selection requires an
overall successful publication and cannot select a failed run's candidate.

For local verification of already approved runtime refs:

```bash
UMBRA_TEST_DEV_IMAGE=ghcr.io/concrete-security/umbra-dev-cvm@sha256:<runtime-digest> \
UMBRA_TEST_SECURITY_IMAGE=ghcr.io/concrete-security/umbra-security-cvm@sha256:<runtime-digest> \
UMBRA_TEST_SOURCE_SHA=<full-source-commit> \
  make test-release-images
```

Authenticate Docker separately if the images require pull access. This target
needs a local Linux amd64 Docker daemon; remote Docker contexts are refused.
CI supplies the validated candidate hash. Direct local runs record a null
`lock_sha256` unless the caller supplies `UMBRA_TEST_LOCK_SHA256`.
Image labels and a candidate's provenance
references do not independently authenticate registry provenance. The automatic
gate relies on the existing publisher's source and build-evidence checks; the
manual gate also authenticates the successful publication run.

Runner image tests do not establish genuine TDX attestation, provider lifecycle,
real OIDC login, or Sysbox behavior. Live staging must verify those properties
against the selected immutable artifacts before production promotion.

## Sysbox compatibility experiment

`Sysbox compatibility` runs on a disposable GitHub-hosted Ubuntu 24.04 runner.
It compares checksum-pinned upstream Sysbox 0.6.7 with a locked 0.7.1 source
candidate against the same fixed Dev release digest. All tests run on the same
host; installation must not change the outer Docker components. The workflow installs host runtime packages
and therefore must never run on a developer machine, self-hosted runner or CVM.

The existing Compose smoke keeps `runc` by default. This experiment opts into
`sysbox-runc`, retains the production Compose file, uses synthetic keys and CA
material, and checks SSH, tunnels, internal networking and missing-policy denial.
A pinned Ubuntu image is streamed into the inner Docker daemon without a pull or
host socket mount. Fresh nested containers exercise both `none` and `bridge`
networks; the candidate also checks blocked direct bridge egress.

The baseline must reproduce the exact `unsafe procfs` / `openat2` / cross-device
failure after the inner daemon is ready. An installation, startup or different
runtime error makes the comparison inconclusive. The candidate must run the
commands successfully in the retained control sandbox and a fresh no-clone
project, before and after its cold restart. The receipt records image IDs, runtime versions, host
kernel, user namespace mappings and package/binary hashes. The package source
pins come from the upstream [0.6.7](https://github.com/nestybox/sysbox/releases/tag/v0.6.7)
and [0.7.1](https://github.com/nestybox/sysbox/releases/tag/v0.7.1) releases.

A separate job scans all three exact candidate Go binaries with Trivy's `rootfs`
analyzer. Missing inventories, scanner errors and known HIGH/CRITICAL dependency
advisories fail the job; repository ignore exceptions do not apply. Manual runs
can set `run_compatibility=false` to repeat only this scan.

The default candidate compiles the coherent 0.7.1 source set with pinned Go
1.27.3, snapshot native build packages and committed dependency locks. A small
source patch adapts its cgroup device filter to the fixed eBPF library while
preserving raw kernel attachment semantics. Existing filter-generation tests
run during the build. A private runner cgroup checks allowed and denied device
opens, enforcement after the loader exits, explicit detach and invalid targets.
The candidate must
reproduce the reviewed binary checksums before scanning. Only after the scan and
inventory gates pass does the disposable runner install those exact bytes and
compare them against 0.6.7. The smoke also checks sandbox restart, exec and a
saved home-directory file.

Manual runs can select `dev_image=migration-baseline` to repeat qualification
against the unchanged older Dev image used by the migration canary. Both choices
map to reviewed immutable digests and their exact source-revision labels in the
workflow; pull requests keep the current release default. The nested smoke binds
the complete Engine, containerd, runc and docker-init version tuple to that digest
and rejects unreviewed images or component drift. A passing result for one image
does not qualify the other.

The populated-state qualification has two distinct arms. Both retain
`--data-root /var/lib/sysbox --disable-ovfs-on-idmapped-mount`; neither relaxes
procfs checks, device filters, user namespaces or sandbox networking.

- **Default clone loss control:** the original 0.6.7 manager configuration first
  reproduces the procfs failure. The smoke writes synthetic fixtures to the
  writable rootfs and the home, workspace and Docker-data named volumes, then
  cold-stops the containers, Docker, containerd and Sysbox before installing the
  candidate. The same containers must restart with only the rootfs marker
  missing. The gate accepts exactly `FileNotFoundError` for that path, while
  requiring every volume fixture, ownership/mode, container/image/runtime/volume
  binding, and the previously loaded inner image. Other failures remain failures.
  The receipt retains the raw missing-file diagnostic and actual clone mount.
- **Fresh no-clone candidate:** with no containers present, the manager adds
  `--disable-rootfs-cloning` before creating a fresh candidate baseline. This
  supported option uses ordinary rootfs chown instead of the disposable clone
  optimization. It can cost more startup I/O; readiness is bounded at 600 seconds.
  Nested Docker, SSH, tunnels and egress controls must work before data is seeded.
  All daemons then cold-stop; the same reviewed binaries and same container IDs
  restart. Every rootfs and volume fixture, ownership/mode and inner image must
  survive, and all workload/security checks must pass again.

Each arm checks completed daemon shutdown, retains Docker metadata and the
installed package, and uses `compose start`, never recreation, to resume its
containers. Inner `docker image save` reads every retained layer before the
nested smoke can import anything again. Actual init root mounts prove that the
control uses a clone and the preservation arm does not. Cleanup removes only
the owned synthetic project; an unrelated error cannot pass as expected loss.

This configuration **does not migrate an already-cloned rootfs**. Both upstream
versions [delete clone data during manager shutdown](https://github.com/nestybox/sysbox-mgr/blob/2d45af01bcfd8641e6641f76104c6003bf501cd7/mgr.go#L489)
and [clean the data root on startup](https://github.com/nestybox/sysbox-mgr/blob/2d45af01bcfd8641e6641f76104c6003bf501cd7/utils.go#L503).
Existing clone-backed data needs an explicit verified filesystem
checkpoint before the first runtime correction. A healthy fresh no-clone
baseline must precede any separate OS-upgrade qualification. CI does not restore
fixtures or silently change the source-pinned bootstrap manager flags.

Only a successful source build, security scan, device-filter test and complete
runtime comparison produce `sysbox-qualified-candidate-<run>-<attempt>`.
This 14-day CI artifact contains a tar archive of the three executable binaries,
binary/archive SHA-256 manifests and bounded `qualification.json` metadata.
The metadata identifies the checkout and workflow run, hashes source/build/test
inputs and the separate security/runtime receipts, and records the tested image
digests. These are diagnostic provenance records, not signed release attestations.
The metadata binds the required no-clone manager flags and explicitly excludes
migration of already-cloned data. Both arms must pass their exact outcomes.
Scan-only runs, upstream-package diagnostics and failed preservation checks produce no
qualified binary artifact. No build output is published as a release or installed on a CVM.

Manual `resolve_locks=true` adds a separate maintenance job that exports proposed
Go module locks. It builds no runtime and cannot feed the qualification job.
Review and commit those locks before rebuilding; a changed binary hash still
fails the mandatory checksum gate until its new pin is reviewed and committed.

Manual `rebuild_candidate=false` selects the checksum-pinned upstream package
for a separate diagnostic. It must pass the same unsuppressed binary scan;
compatibility success does not override known dependency advisories.

This is a diagnostic experiment, not a release or deployment approval. Upstream
packages share the 0.6.7 component source revisions with dstack, but the runner's
kernel, packaging and outer Docker differ. No result establishes dstack boot,
TDX attestation, KMS key continuity, existing-data recovery or a safe host runtime
upgrade. The handover covers only the synthetic files, named-volume bindings
and inner image on the recorded runner storage mode. Production migration needs
separate verification of these properties on the selected guest image and data.

## Build-cache boundary

The pull-request gate caches only public Cargo inputs, Cargo build output, and uv downloads. Its exact cache keys include the Python pin, Rust toolchain, and all Rust and Python locks; there are no prefix fallback keys. A clean cache miss must pass the same locked gates.

Pull-request merge-ref caches do not flow into protected branches. Default-branch caches may flow into a pull request, but contain no credentials or local configuration. Release and deployment jobs restore no pull-request cache.

## Deployment boundary

The public repository is authoritative for source, tests, release artifacts, image digests, SBOMs, and provenance. It has no cloud deployment identity and receives no staging or production credentials.

The CVM publisher receives only the workflow's package-scoped `GITHUB_TOKEN`.
It publishes tagless GHCR indexes, records their stable runtime subjects and
attestation-index references, and leaves both guest measurements null. The
private deployment authority measures the Dev image through its provider canary
and applies that shared dstack guest MRTD to both components before staging.

The private deployment repository is authoritative for environment lock files, Workload Identity Federation conditions, service accounts, hosts, databases, provider workspaces, approval gates, session caches, rollback state, and recovery material. It consumes only immutable public artifacts and never rebuilds product source for deployment.

## Environment protection

Configure GitHub before accepting public contributions or publishing releases:

- protect `dev` with required PR review, `check`, and `test`;
- protect `main` with required PR review and the same source gates;
- create a separate `release` environment for `.github/workflows/publish-cli.yml`, restrict it to `main`, require an independent reviewer, prevent self-review, and disable administrator bypass where supported;
- disable force pushes and branch deletion;
- enable secret scanning, push protection, dependency review, and the DCO gate;
- restrict Actions to approved immutable references.

Public repositories must also have GitHub's dependency graph enabled. The
dependency-review job deliberately fails when that repository prerequisite is
missing; do not weaken or skip the gate to compensate for incomplete settings.

The scoped Hickory DNSSEC advisory exception requires both locked Linux Cargo
feature graphs to exclude DNSSEC. `make check` enforces that condition and
requires reassessment when the resolver version changes. The exception expires
on 2026-11-08; remove it when the upstream dependency permits a patched resolver.

The Hickory CNAME advisory GHSA-6f2x-v7q7-m7m5 also has a scoped exception until 2026-11-08. In 0.25.2, the affected recursive implementation is in the separate `hickory-recursor` crate. Umbra's reqwest 0.12.28 calls the stub `TokioResolver::lookup_ip`, rather than that full-recursion implementation. Both lockfiles and all native release graphs exclude `hickory-recursor`. Controlled CNAME-only DNS fixtures in Atlas cover unrelated answer, authority and additional records, plus legitimate-chain controls. This exception addresses the advisory's recursive fan-out, without claiming general DNS response safety. `tools/check-cargo-dnssec.py` checks all CLI release targets and Console Linux; it rejects version, registry source, resolver caller and DNSSEC feature drift. The DNSSEC exception has its own independent condition. See the [advisory](https://github.com/advisories/GHSA-6f2x-v7q7-m7m5), [answer-section fix](https://github.com/hickory-dns/hickory-dns/commit/4689fc8d3ddd3e3f99ec1b7be4e2e9e78afd2e6b), and [chain fix](https://github.com/hickory-dns/hickory-dns/commit/ccd6952378f250c714fc2af0cb1053e1c179f832).

The two pip-vendor exceptions also expire on 2026-11-08. They match Trivy's Python target and exact affected package PURLs when present; Trivy also matches a missing PURL. Before applying them, the image gate runs `tools/check-pip-vendor.py` in a read-only container without network access. The guard checks the reviewed pip/vendor pins and rejects native msgpack, PackageIndex implementations, or actual installed distributions at the excepted vulnerable versions, including alternate Python environments. A guard failure stops the image gate and requires reassessment.

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

## One-time CLI 0.1.0 draft recovery

`recover-cli-0.1.0.yml` is the explicitly approved packaging recovery for the
unpublished GitHub 0.1.0 draft. It does not publish crates, move tags, or replace
release assets. It verifies the pinned original successful run and SLSA evidence,
removes only the accidentally included skill, and retains the original binary
bytes. The strict distribution extractor remains unchanged. A signed repair
receipt links the original binary source to the new packaging commit; original
archive, checksums and provenance are retained as separate evidence.

After independent verification of the new SLSA evidence, an authorized operator
may replace only the archive, checksum manifest and provenance while the release
remains a draft and its tag and original asset IDs/digests remain unchanged.
Preserve the original evidence and signed receipt alongside the release. Verify
the re-downloaded canonical assets and isolated installation before publishing.
This exception does not apply to public releases or change normal publication's
byte-identity checks. Production installer-mirror deployment is separate.
