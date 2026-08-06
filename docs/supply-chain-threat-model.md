# Supply-chain and release threat model

Umbra's source repository can deploy security-sensitive control-plane and TEE runtime code. A contributor who cannot read deployment secrets must also be unable to turn an untrusted change into a privileged build or deployment.

## Adversaries

This model considers an untrusted fork pull request, a compromised dependency or GitHub Action, a malicious build script or migration, a compromised artifact host or registry account, a leaked CI credential, and a maintainer account that is mistaken or compromised. It also considers a legitimate contributor trying to smuggle generated or private material into a release.

## Protected assets

- Cloud and registry deployment authority.
- OIDC, Cloudflare, Phala, GHCR, database, signing, and Console credentials.
- Integrity of CLI binaries, container images, installer output, migrations, attestation policy, and the public source tree.
- Confidentiality of tenant data, operational records, and pre-public source history.

## Required controls

Pull-request workflows run with read-only repository permissions, no persisted checkout credential, no deployment environment, and no maintainer secrets. Third-party Actions use immutable commit references. Workflow, release, migration, authentication, authorization, attestation, policy, secret-handling, and CVM runtime paths require CODEOWNERS review and protected-branch approval.

Staging and production use separate protected GitHub environments and separate least-privilege cloud identities. Workload Identity Federation conditions bind the exact public repository, workflow, ref, and environment. Production requires a reviewer other than the deploy author, and administrator bypass is disabled where the platform supports it.

Build inputs are locked and container bases are digest-pinned. Before the first public release, protected release jobs MUST publish an SBOM, license report, checksums, and provenance for every distributed binary, container, and assembled release tree; every container MUST also be signed or attested by immutable digest. The installer MUST verify an independently authenticated signature or attestation; a checksum fetched from the same server as the binary is not sufficient.

That paragraph is a release requirement, not a claim that every control is already live. CLI release assets have checksums, SBOMs, SLSA provenance, and installer-side provenance verification. The CVM publisher generates and validates BuildKit SPDX/SLSA attestations for each image. Protected CI publication of container attestations/signatures, complete cross-ecosystem license reports and notices, and the first approved public image release remain open launch gates that must be closed before the first public release.

Every Dev or Security CVM publication first performs two cache-disabled local builds from independent detached worktrees at the captured commit. Both use the exact Buildx 0.34.0 client, named digest-pinned BuildKit 0.32.2 backend, digest-pinned Dockerfile 1.26.0 frontend and SBOM generator, exporter compatibility version 30, source revision labels, provenance mode, `linux/amd64`, and image-layer timestamp normalization. Both runnable runtime manifests must agree before any registry write. Each local attested result index is independently checked for the expected runtime binding, source labels, BuildKit inputs, SPDX document, and max-mode SLSA predicate. BuildKit embeds a fresh invocation ID and wall-clock start/finish times in that provenance, so the top-level attestation-index digests are intentionally not equality inputs. The normalized HTTPS source label must equal the checkout's `origin`, and the publisher additionally requires the captured commit to be advertised by an `origin` branch or tag before it can claim that repository identity.

Publication then performs one tagless registry build with push-by-digest, never creates or relies on a source-commit tag, and re-reads that immutable result index. Its invocation-specific index digest can differ from both local indexes, but its runtime must match the two local subjects; runtime source labels, the subject-bound attestation descriptor, and parsed SPDX/SLSA bodies are revalidated as defense in depth. The returned and deployed reference is exactly `repository@sha256:<runnable-runtime-manifest>` beneath the timestamp-bearing attestation index; the attestation remains bound to that runtime subject.

Debian-based images restore the snapshot timestamps recorded by their pinned base images before installing packages. The Dev image separately pins its Ubuntu snapshot and verifies direct Docker-package digests. Alpine images name the complete added package closure with exact versions; repository replacement therefore fails closed instead of silently selecting a newer revision. Authenticated Docker client proxy settings are explicitly replaced with empty upper- and lower-case build arguments because max-mode provenance records build arguments; release builds never publish proxy credentials.

The host Docker Engine and daemon are a privileged build boundary, not a repository-pinned input. Host provisioning installs Docker only from an already-configured signed package source, but operators must record and review the daemon version, restrict access to its root-equivalent socket, and run release publication on a dedicated trusted host. Two independent outputs catch ordinary nondeterminism; they do not defend against a malicious daemon capable of forging both builds and the registry exchange.

The public seed starts from an exhaustive allowlist and fresh Git history. Private operational records and generated output are denied by construction, then the resulting outsider-equivalent clone is scanned again. Secret scanning, push protection, dependency review, CodeQL, vulnerability scans, DCO, branch protection, and environment protection are repository gates rather than maintainer conventions.

## Build-cache boundary

The pull-request gate caches only public Cargo registries and git checkouts, Cargo build output, and the uv download cache. Cache keys bind the operating system, Python pin, Rust toolchain, and every Rust and Python lock file; prefix fallback keys are forbidden. Neither local configuration nor credentials are cache inputs, and a cache hit is only a performance optimization: locked builds and tests must also pass after a clean miss.

GitHub scopes caches created for a pull request's merge ref away from protected branches. A pull request may consume a default-branch cache containing only public build material, but protected release and deployment workflows consume no pull-request build cache at all. Any future cache path or restore rule needs a fresh review of both directions across this trust boundary.

## High-risk review questions

- Can a fork-controlled expression, cache, artifact, matrix value, or script reach a secret-bearing job?
- Can a changed Dockerfile, lock file, setup script, migration, or release manifest execute before review or outside the reviewed source tree?
- Can a mutable tag, branch action reference, package index, apt repository, or curl-piped installer change the build without a source diff?
- Can one compromised identity publish code, sign an artifact, and deploy it without an independent approval?
- Does any job print bearer material, full environment files, auth state, provider output, or a URL containing a credential to public logs?
- Can caches produced by trusted jobs be restored into untrusted jobs, or vice versa?
- Can rollback select an unsigned artifact, reuse revoked credentials, or run an incompatible older schema?

## Residual risk and verification

GitHub and external cloud/registry providers remain trusted service dependencies. Reproducibility may be limited by upstream package repositories unless inputs are mirrored or snapshot-pinned. Maintainers verify repository and cloud settings through provider APIs at every release; configuration prose alone is not evidence that a control is active.

The release gate includes a fork pull-request test that attempts to read a sentinel secret and obtain deployment authority. It must fail before the first public release and after any material workflow or identity change.
