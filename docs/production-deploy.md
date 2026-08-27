# Deployment guide

This guide deploys a prepared self-hosted environment from reviewed source and neutral templates. Complete [operator setup](operator-setup.md) first.

## 1. Preconditions

- The checkout is at the release commit and has no unrelated local changes.
- `.env` was generated with `make build-env MODE=<mode>` from the four layers in [environments](environments.md).
- `CONSOLE_HOST` resolves to the configured host and public TLS can terminate.
- DNS and TDX-provider credentials are scoped to this environment.
- Before Console starts, Dev and Security CVM images will be pinned by an approved immutable digest (use §3 when self-building).
- JWT keys, the secret-injection KEK, and durable Postgres are available.
- A real OIDC identity in the configured tenant domain is available for login.

Back up an existing Console database before upgrading:

```bash
make backup-console-db
```

Read [versioning and compatibility](versioning.md) and the release's [changelog](../CHANGELOG.md) before applying migrations.

## 2. Validate the release

```bash
git status --short --branch
make check
make test
```

Verify required external tools and non-secret configuration without dumping the environment:

```bash
set -a
. ./.env
set +a

command -v make git jq curl uv rustc cargo docker psql
docker info >/dev/null
docker buildx version  # must report exactly v0.34.0
docker buildx inspect umbra-release --bootstrap  # exact digest-pinned BuildKit 0.32.2
test -d "$SHADE_DIR"
test -n "$SHADE_REF"
test "$(git -c "safe.directory=${SHADE_DIR}" -C "$SHADE_DIR" rev-parse HEAD)" = "$SHADE_REF"
uv run --project "$SHADE_DIR" shade --help >/dev/null
test -n "$CONSOLE_HOST"
test -n "$VM_PUBLIC_IP"
test -n "$JWT_PRIVATE_KEY_REF"
test -n "$JWT_PUBLIC_KEYS_REF"
```

Validate DNS, provider, and registry access separately. Pass credentials on stdin or in environment variables; never place them on argv or print them.

## 3. Build and pin the runtime images

Skip this section only when you already have an approved release manifest with immutable Dev and Security image refs plus the shared dstack guest MRTD. The supported source-build publisher currently targets operator-owned GHCR repositories and `linux/amd64` only. Runtime pulls from other OCI registries are possible, but generic-registry publication is not implemented by these helpers.

Start from a clean, reviewed commit. The repository fixes the release inputs to:

```text
Buildx:              0.34.0 exactly
BuildKit:            moby/buildkit:v0.32.2@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8
Dockerfile frontend: docker/dockerfile:1.26.0@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32
SBOM generator:      docker.io/docker/buildkit-syft-scanner:stable-1@sha256:79e7b013cbec16bbb436f312819a49a4a57752b2270c1a9332ae1a10fcc82a68
Dev bases:           golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36
                     rust:1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa
                     ghcr.io/astral-sh/uv:0.12.1@sha256:cf4eedcaa81655197f625739489effcbe71b61ceb1506f332c3facae5deceded
                     ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
Security bases:      ghcr.io/astral-sh/uv:0.12.1@sha256:cf4eedcaa81655197f625739489effcbe71b61ceb1506f332c3facae5deceded
                     python:3.12-slim-trixie@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36
```

`ops/buildkit-version.sh` and the two Dockerfiles are authoritative for these values. The Dev image also fixes an Ubuntu snapshot and verifies exact Docker `.deb` digests; the Security image fixes a Debian snapshot. A pin change must be reviewed together with this guide. The host Docker Engine itself is not pinned by the repository: treat its daemon and root-equivalent socket as a trusted release-host boundary and record `docker version` with the build evidence.

Run both independent-worktree reproducibility gates before publication:

```bash
test -z "$(git status --porcelain --untracked-files=all)"
git rev-parse --verify 'HEAD^{commit}'
docker version
export UMBRA_BUILD_SOURCE_REPOSITORY_URL=https://github.com/YOUR_ORG/YOUR_REPOSITORY
git remote get-url origin  # must identify the same repository; SSH syntax is normalized
make verify-cvm-images-repro
```

Each gate performs two cache-disabled builds from separate detached worktrees, uses the source commit timestamp to normalize image layers, and compares the runnable OCI manifest digest. Each build's attested result index is separately validated for the expected subject binding, source labels, SPDX document, and max-mode SLSA inputs. BuildKit provenance includes per-invocation timestamps and an invocation ID, so those top-level index digests are expected to differ. The source URL becomes the OCI source label and provenance identity. The publisher also requires the captured commit to be advertised by an `origin` branch or tag, so push the reviewed release commit before publication. Select owned GHCR repositories in the committed mode layer, then regenerate `.env`:

In the canonical repository, `.github/workflows/publish-cvm-images.yml` runs the
same gate on every trusted `dev` push. It uploads a lock-shaped candidate whose
image fields are runnable manifest refs and whose provenance fields identify the
validated immutable attestation indexes. Measurements remain null because the
public publisher has no provider identity; the private deployment authority
fills them from the Dev canary before staging. The commands below remain the
self-hosted/operator publication path.

```text
SECURITY_CVM_IMAGE_REPOSITORY=ghcr.io/<owner>/umbra-security-cvm
DEV_CVM_IMAGE_REPOSITORY=ghcr.io/<owner>/umbra-dev-cvm
```

```bash
make build-env MODE=prod
set -a
. ./.env
set +a
```

Have a secret manager export one-shot `GHCR_USER` and `GHCR_TOKEN` values into this shell; never save them in an environment layer. Publish the Security image:

```bash
UMBRA_REDEPLOY_SC_CONFIG_DIR= \
UMBRA_VERIFY_TENANT_ADMIN_CONFIG_DIR= \
  make redeploy-sc
```

On a valid publication, this command performs one tagless registry build with push-by-digest, revalidates its remote runtime and attestations, prints `SECURITY_CVM_IMAGE_REF=ghcr.io/...@sha256:...`, and then deliberately exits non-zero at the environment-pin guard. Accept that stop only when the fixed diagnostic says publication succeeded and its blockers are applying the printed digest plus the deliberately omitted live-launch config; any earlier or different error is a failed build. The helper never creates a source-commit tag and never deploys the invocation-specific attestation-index digest.

Publish the Dev image and let the direct provider canary observe the guest MRTD:

```bash
UMBRA_REDEPLOY_DEV_CONFIG_DIR= \
UMBRA_VERIFY_TENANT_ADMIN_CONFIG_DIR= \
UMBRA_REDEPLOY_DEV_PROFILE_ID= \
UMBRA_REDEPLOY_DEV_SSH_KEY_ID= \
  make redeploy-dev
unset GHCR_USER GHCR_TOKEN
```

The command prints `DEV_CVM_IMAGE=ghcr.io/...@sha256:...` and records the canary result in `artifacts/dev-cvm-release-<commit>.json`. The canary's MRTD is the shared dstack guest baseline, not an app-image measurement. Review the output, then put all four values in `.env.prod.secrets` (or the selected mode's secret layer), with the measurement values exactly equal:

```text
DEV_CVM_IMAGE=ghcr.io/<owner>/umbra-dev-cvm@sha256:<runtime-manifest>
SECURITY_CVM_IMAGE_REF=ghcr.io/<owner>/umbra-security-cvm@sha256:<runtime-manifest>
DEV_CVM_IMAGE_MEASUREMENT=<shared-96-character-mrtd>
SECURITY_CVM_IMAGE_MEASUREMENT=<same-shared-96-character-mrtd>
```

An app-image-only release changes the digest ref and the full Shade runtime policy; it does not change either MRTD value. Rebuild the generated environment and verify the non-secret relationship before starting or restarting Console:

```bash
make build-env MODE=prod
set -a
. ./.env
set +a
test "$DEV_CVM_IMAGE_MEASUREMENT" = "$SECURITY_CVM_IMAGE_MEASUREMENT"
case "$DEV_CVM_IMAGE" in *@sha256:*) ;; *) exit 1 ;; esac
case "$SECURITY_CVM_IMAGE_REF" in *@sha256:*) ;; *) exit 1 ;; esac
```

`make redeploy-dev` uses the live provider to measure and deletes its Umbra-owned canary by default. To re-observe the guest baseline for an already-published Dev digest without rebuilding, set `DEV_CVM_MEASURE_IMAGE_REF` to that exact digest and run `make measure-dev`.

## 4. Start the Console

Build the selected mode, then start the stack:

```bash
make build-env MODE=prod
make up
```

Check local containers and public health:

```bash
docker compose ps
curl -fsS "https://${CONSOLE_HOST}/healthz"
curl -fsS "https://${CONSOLE_HOST}/readyz"
```

On failure, inspect bounded local logs and redact identifiers before sharing:

```bash
docker compose logs --tail=200 console
docker compose logs --tail=200 reverse-proxy
```

## 5. Bootstrap and first tenant

A new Console contains no users or entities, so OIDC login cannot succeed until the one-shot bootstrap creates the initial platform identity. With the private bootstrap variables configured:

```bash
make bootstrap
```

The bootstrap identity should use the non-routable `platform.umbra.invalid` domain and does not log in through Google. Real tenant admins and developers must use accounts in the tenant domain configured for their entity.

From the platform CLI config, create a tenant and its first admin if your bootstrap automation did not already do so:

```bash
umbra --json entity add example.com --name "Example Corp"
umbra --json user add admin@example.com \
  --entity <entity-id> \
  --permission USER_MANAGE \
  --permission PERMISSION_MANAGE \
  --permission SECURITY_CVM_CONFIGURE \
  --permission AUDIT_VIEW \
  --permission AUDIT_EXPORT \
  --permission TRAFFIC_LOGS_VIEW
```

Replace the reserved examples with real values. The tenant admin then logs in:

```bash
umbra auth login https://console.example.com
```

## 6. Establish the runtime path

Launch one Security CVM before any Dev CVM:

```bash
umbra security-cvm launch
```

Create a profile and add a developer:

```bash
umbra --json profile create engineering
umbra --profile <profile-id> profile configure --policy-file policy.json
umbra --json user add alice@example.com --permission CVM_LAUNCH
umbra --profile <profile-id> profile members add <user-id>
```

The developer can then follow [the quick start](quick-start.md):

```bash
umbra auth login https://console.example.com
umbra cvm launch
umbra ssh
```

Prove both allowed and denied traffic, inspect traffic logs, and inspect the control-plane audit trail before onboarding additional users.

## 7. End-to-end verification

`make verify` is a live, destructive integration journey: it provisions real CVMs, exercises OIDC, attestation, egress, audit, and teardown, and stops the local Compose stack during cleanup. Run it only in an isolated DEV or STAGING environment whose provider workspace and database are disposable for that journey. Never point it at production or a shared provider workspace.

The green path must not use synthesized sessions, local provider fakes, `UMBRA_LOCAL_DEV`, `--insecure-skip-atls-policy`, or another attestation bypass.

```bash
make verify
```

After a staging journey, restore the service if needed:

```bash
make up
curl -fsS "https://${CONSOLE_HOST}/readyz"
```

## 8. Day-two operations

- Use `make up` or the protected deployment workflow for a Console rollout.
- Use `umbra security-cvm update` and `umbra cvm update <id>` for provider-neutral runtime updates.
- Use immutable image digests from one tested release set; do not mix arbitrary CLI, Console, or CVM versions.
- Back up before migration and test the release in staging before production.
- A database at the exact pre-Umbra head `0032_attn_unreachable` upgrades through the lineage-only compatibility branch to `0033_public_legacy_merge`, then `0034_connect_oauth_schema` installs public Connect schema. Use full Alembic revision IDs, and restore the pre-upgrade backup rather than attempting a downgrade across that merge.
- Keep process supervision and restart-on-boot configured for the Compose stack.
- Use `umbra reconcile` for provider drift. Do not edit lifecycle state directly in Postgres.
- Never inspect or mutate provider resources outside the deployment's dedicated workspace and Umbra-owned naming scope.

Operational incidents containing secrets, personal data, or live resource identifiers must be handled privately. Public vulnerability reporting follows [`SECURITY.md`](../SECURITY.md); general support follows [`SUPPORT.md`](../SUPPORT.md).
