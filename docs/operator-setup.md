# Operator setup

This guide prepares a self-hosted Umbra environment. It uses reserved examples and does not describe the maintainers' deployment. Complete it before following [production deploy](production-deploy.md).

## Requirements and cost

A live deployment uses third-party infrastructure that may be paid:

- one Linux x86_64 host for the Console, Postgres, and TLS reverse proxy;
- a supported TDX CVM provider for Dev and Security CVMs;
- public DNS automation for the Console and both CVM namespaces;
- Google OAuth clients for the currently supported OIDC flows;
- a container registry for released or self-built runtime images;
- optional external Postgres stores for audit anchors and exports.

The dominant recurring cost is the always-on Security CVM plus each developer's Dev CVMs. Provider, region, storage, and traffic prices vary; establish a budget and quotas before onboarding users.

## 1. Operator host

Recommended baseline:

- Ubuntu 22.04 or newer;
- 4 vCPU, 8 GiB RAM, and 60 GiB disk or more;
- public TCP 80 and 443 for TLS and the Console;
- Docker with Compose v2, Git, make, Rust, Go, `uv`, curl, jq, and Postgres client tools; Buildx must be exactly 0.34.0;
- the pinned `slsa-verifier` at the absolute path declared in `.env.common`;
- the pinned Phala CLI version and digest declared in `.env.common`;
- this repository at a stable, non-personal path such as `/opt/umbra/umbra`.

If CI reaches the host over cloud IAP, expose SSH only through that private access path. Do not open port 22 to the public internet.

After cloning the repository, run:

```bash
bash ops/host/provision-host.sh
```

Run it as the operator user, not with `sudo`. System tools come only from package sources already trusted by `apt` or Homebrew; the script never executes a downloaded installer script or adds a repository signing key. On Ubuntu it uses the signed `golang-1.24-go` package's `/usr/lib/go-1.24/bin/go` compiler and verifies Go >=1.23.2 before installing the pinned `slsa-verifier` module through `proxy.golang.org` with the public Go checksum database enabled. It then places the verifier at the absolute path declared by `UMBRA_INSTALL_SLSA_VERIFIER`. If a configured Linux repository lacks `rustup`, `uv`, or the versioned Go package, the script fails closed with preinstallation guidance. It creates or verifies the named `umbra-release` builder with the repository's digest-pinned BuildKit 0.32.2 image. A fresh Linux install requires a re-login and one rerun after docker-group membership changes; dry-run never bootstraps a builder. A conflicting builder configuration fails closed. The repository pins Buildx, BuildKit, the Dockerfile frontend, and container bases; it does not pin the host Docker Engine. Treat the daemon and its root-equivalent socket as a trusted release boundary: install it only from an approved signed source, record `docker version` with the release evidence, and do not share the release host with untrusted workloads. The optional Phala path likewise requires Node.js 18 or newer and npm from a distro, vendor, or organization-approved signed source; the script does not add NodeSource. On macOS, install and launch Docker Desktop separately and add Homebrew's keg-only `rustup` bin directory to the shell `PATH`.

After maintainers prove control of the release repository and publish the first approved release, the default installer deployment can synchronize anonymously readable GitHub release assets and authenticate them with SLSA before installation. Before that launch gate, build from reviewed source rather than claiming a public release channel. The published path needs no GitHub credential, and its curl, selector, and verifier child processes run with an explicit environment allowlist that excludes deployment secrets and `GH_TOKEN`. Selecting the workflow-artifact recovery source instead uses the same restricted environment plus an explicit one-shot caller `GH_TOKEN`; never store that token in a merged environment file. The secret-bearing installer preparation path rejects `local`; run `make package-cli` only as a separate package job from a checkout with no deployment `.env` or provider secrets.

## 2. DNS

Choose three names. The two CVM namespaces must be disjoint:

```text
console.example.com       Console A/AAAA record
dev.example.com           cvm-* records managed by Console
sc.example.com            sc-* records managed by Console
```

The Dev and Security namespaces may be separate DNS zones or disjoint subdomains in one zone. Grant the DNS token edit access only to the required zone or zones.

## 3. Google OIDC

Umbra currently supports Google OIDC and needs separate OAuth clients for the two authorization flows:

1. A **Web application** client for browser/loopback login. Configure the exact redirect URI:

   ```text
   https://console.example.com/api/v1/auth/oidc/callback
   ```

2. A **TVs and Limited Input devices** client for `umbra auth login --device` and headless verification.

Put their IDs and secrets only in `.env.<mode>.secrets`. The CLI sends the logical identifier `umbra-cli-v1`; it never receives the Google client secret. Configure the consent screen so every real tenant identity is allowed.

## 4. TDX CVM provider

Create a dedicated provider workspace and least-privilege API token for each environment. A token must be able to list, create, update, and delete CVMs in its own workspace. Do not share a workspace between staging and production: cleanup is scoped by the credentials and Umbra-owned resource prefix, not by the `ENV` label.

Confirm quota for at least one Security CVM and one Dev CVM, then record the approved region and instance types. Install the exact provider CLI version and verify its package digest against `.env.common`.

Umbra also invokes a pinned shade checkout. Set `SHADE_DIR` in the private admin layer to the host path; `.env.common` pins the checkout's content as `SHADE_REF`. `make deploy` converges the checkout to that commit and refuses a dirty tree. Do not hand-edit the checkout on a host. The Console image builds and includes its atlas verification helper; `ATLAS_VERIFIER_CMD` normally remains `/usr/local/bin/umbra-atlas-verify`.

## 5. Container images

Use immutable digest references for Dev and Security CVM images. The supported repository publisher currently authenticates only to an operator-owned `ghcr.io` namespace, so the public environment templates use reserved GHCR examples that operators must replace. Runtime deployment can pull a digest ref from another OCI registry, but this repository does not claim a generic reproducible publisher for it. Follow [production deploy](production-deploy.md#3-build-and-pin-the-runtime-images) for the complete reviewed-source build, two-build reproducibility gates, digest-only publication, and Dev-canary measurement sequence. Set `UMBRA_BUILD_SOURCE_REPOSITORY_URL` to the checkout's normalized HTTPS `origin` identity before either gate; forks must name their own repository.

Dev and Security CVMs use the same dstack guest MRTD. The Dev canary observes that shared guest baseline; it does not compute an app-image-specific measurement. Application image and compose identity are pinned separately by the complete Shade runtime policy. An app-only release changes the immutable image ref and regenerated policy while both measurement variables stay equal.

Once the approved Security CVM and shade images are published for anonymous reads, leave all `DSTACK_DOCKER_*` values unset and the Console will provision those CVMs without registry credentials. The Dev CVM image is always self-built: it bakes proprietary Claude Code, which this project does not redistribute, so build it from this repository's reproducible instructions and host it in your own registry (configure the private-registry credentials below when your registry requires authentication).

`GHCR_USER`, `GHCR_TOKEN`, and `GH_TOKEN` are one-shot host process inputs. Never put them in a merged environment layer: `build-env` rejects those keys, and Compose keeps legacy values out of the Console and installer containers.

Private-registry self-hosters must explicitly set the complete pull-credential trio in a private environment layer:

```text
DSTACK_DOCKER_REGISTRY=<registry-host>
DSTACK_DOCKER_USERNAME=<pull-only-user>
DSTACK_DOCKER_PASSWORD=<pull-only-token>
```

Setting only part of the trio is invalid. Use a pull-only identity and never reuse a token with push or repository-administration rights. Image publishing is a separate, protected build operation; do not persist a push-capable registry token on the Console host or inside a CVM.

## 6. Postgres and durable data

The Compose stack includes Postgres for a single-host deployment. Use a managed Postgres service when your availability and backup requirements call for it. Alembic migrations run on Console startup.

Treat Console data as durable. Configure backups, test restore outside production, and run `make backup-console-db` before an upgrade. Never use `make reset`, volume deletion, table truncation, or database drop as a deployment step.

Audit anchors and audit exports may use separate append-only stores. Give each writer only the operations documented in `docs/specs/console.md`; do not reuse the Console database credential.

## 7. Cryptographic material

Generate an Ed25519 JWT signing key and a JWKS file. Keep the private key out of the repository and restrict its file mode to `0400` or `0600`, or use a supported external key resolver.

Generate an independent 32-byte secret-injection encryption key:

```bash
openssl rand -base64 32
```

Set it as `SECRET_INJECTION_KEK_B64` in the secret layer. It protects stored profile and per-user secret material and must remain stable for the lifetime of the database. Do not derive it from or reuse JWT key material.

## 8. Environment layers

Start from the committed templates:

```bash
cp .env.admin.example .env.admin
cp .env.MODE.secrets.example .env.staging.secrets
```

Edit `.env.staging` (or another mode file) to replace every reserved example, then fill the two gitignored files. Build the generated environment:

```bash
make build-env MODE=staging
```

The four layers and their isolation rules are documented in [environments](environments.md). Each key must appear once. Never commit or paste the generated `.env`; it contains deployment credentials.

At minimum, configure:

- Console hostname and host IP;
- DNS token, zone identifiers, and CVM base domains;
- both Google OIDC client pairs when device login is needed;
- provider token and region;
- JWT key references and secret-injection KEK;
- digest-pinned Dev and Security CVM release material;
- a metrics bearer when metrics are scraped.

## 9. Preflight

Run checks without printing secret values:

```bash
test -f .env
docker info >/dev/null
docker compose version
make check
make test

set -a
. ./.env
set +a

test -n "$CONSOLE_HOST"
test -n "$VM_PUBLIC_IP"
test -d "$SHADE_DIR"
uv run --project "$SHADE_DIR" shade --help >/dev/null
"${PHALA_CLI_PATH}" --version
curl -fsS "https://${CONSOLE_HOST}/healthz" >/dev/null 2>&1 || true
```

Separately verify DNS resolution, provider access, registry pull access, and OIDC configuration without echoing tokens. Continue with [production deploy](production-deploy.md) only after all required external checks succeed.
