# Dev CVM

The Dev CVM is a per-developer TDX sandbox for agents, shells, builds, nested Docker workloads, and editor sessions. A Dev CVM belongs to one user, attaches at least one profile, and cannot launch without its entity Security CVM. Its authoritative contract is `docs/specs/dev-cvm.md`.

## Runtime components

| Component | Purpose |
| --- | --- |
| `user-sandbox` | SSH workspace with dtach, native Docker-in-Docker, persistent volumes, and forced proxy environment. |
| `dev-tunnel` | WebSocket-to-SSH relay for CLI tunnels and sessions. |
| `dev-egress-forwarder` | Fail-closed HTTP CONNECT boundary that verifies and forwards to the Security CVM. |
| `umbra-atls-connect` | atlas-rs helper that locally verifies the Security CVM session. |
| `umbra-ca-refresh` | Watcher that atomically installs a rotated Security CVM CA. |

> Temporary security deviation: the aTLS helper currently removes SC runtime-image pins after validating the delivered policy. Genuine quote, TCB, certificate, EKM, and RTMR verification remains. See [`docs/sc-policy-check-disabled.md`](../../docs/sc-policy-check-disabled.md).

## Security model

- The sandbox runs with `sysbox-runc`; namespace root maps to unprivileged host IDs.
- The sandbox joins only an internal Docker network with no default egress route. Only the forwarder has an uplink.
- Proxy and CA variables are forced for shells, sudo, APT, and nested tools.
- Security CVM FQDN, CA, proxy/control bearers, SSH keys, and non-secret placeholders arrive as measured launch material. The full Security CVM aTLS policy never crosses Phala's launch env; the forwarder fetches it from the authenticated Console Dev-control endpoint before the first upstream SC connection or successful CONNECT response.
- The sandbox receives only the CA, authorized keys, and non-secret placeholders. Forwarder-only trust and bearer material is not exposed there.
- CA refresh is authenticated against the RTMR3-bound Console origin and replaces, rather than appends to, the sandbox bundle.
- SSH uses public-key authentication. Keys are fixed for the CVM lifetime.
- Agent sessions use dtach. Claude Code and Codex run inside this boundary; Umbra's Sysbox and Security CVM controls are the intended sandbox.
- Nested Docker is rootful inside the sandbox namespace and never mounts the CVM host Docker socket.

Umbra governs network connections opened inside the Dev CVM. Hosted editor or browser tools may open traffic from outside this namespace and are not covered merely because the editor uses Remote SSH.

## Runtime material

| Variable | Purpose |
| --- | --- |
| `DEV_CVM_IMAGE` | Digest-pinned sandbox image. |
| `SECURITY_CVM_FQDN` | Security CVM network, TLS, and attestation identity. |
| `SECURITY_CVM_PROXY_PORT` | Proxy port. |
| `SECURITY_CVM_PROXY_TOKEN` | Per-CVM proxy bearer, forwarder only. |
| `DEV_CVM_CONTROL_TOKEN` | Per-CVM Console policy-bootstrap and refresh bearer, forwarder only. |
| `SECURITY_CVM_CA_CERT_B64` | Security CVM mitmproxy root CA. |
| `CONSOLE_URL` | Bound Console origin for narrow policy-bootstrap and refresh reads. |
| `AUTHORIZED_SSH_KEYS_B64` | Launch-time SSH public keys. |
| `SANDBOX_ENV_PLACEHOLDERS_B64` | Non-secret sandbox environment values. |

The forwarder MAY bind `:3128` without a policy so the Dev CVM remains reachable for measurement, but before its first upstream SC connection or `200 Connection Established` it MUST use `DEV_CVM_CONTROL_TOKEN` to fetch the complete stored SC policy from the Console, strictly validate it, and atomically install it. A missing, disabled, incomplete, invalid, blank, stub, or dev policy, or failure to fetch one within the bounded bootstrap budget, returns fail-closed `502` and opens no upstream connection; no bypass is permitted. The same endpoint supplies periodic policy refreshes afterward.

## Files and checks

| Path | Purpose |
| --- | --- |
| `docker-compose.yml` | Measured Dev CVM app compose. |
| `shade.yml` | Ingress routing. |
| `user-sandbox/` | Dockerfile, entrypoint, SSH, tunnel, forwarder, watcher, and helper crate. |
| `tests/` | Local smoke and package tests. |

The sandbox image is amd64-only. Its Ubuntu packages, including userspace headers, resolve from the dated Canonical snapshot in the Dockerfile. Container headers do not change the provider-managed guest kernel. Exact Docker Engine, CLI, and containerd `.deb` filenames and SHA-256 digests are reviewed in `user-sandbox/tool-versions.env`. Buildx, Compose, and GitHub CLI compile from checksum-pinned upstream source with Go 1.27.3 and `GOTOOLCHAIN=local`. All three tools pin `golang.org/x/net` v0.60.0. Buildx replaces its vendored network and archive modules with separately checksum-pinned releases and reports `+umbra.2` for the local edits. Compose applies the reviewed module checksums from `user-sandbox/go-net.sum`; GitHub CLI retains its newer upstream module locks. Both build without changing their checksum locks. Architecture or digest drift fails closed.

pip is installed separately with a hash pin so its bundled CA store includes current distrust updates. pip stays at 26.2.2 with a local, hash-verified urllib3 2.8.0 vendor update; its license, SBOM and wheel RECORD reflect the rebuilt contents. npm 12.2.1 uses a checksum-pinned upstream tarball; the build replaces its bundled Undici 6.29.0 with hash-verified 6.29.1 until npm includes that fix. The image smoke checks both npm's copy and Node's built-in Undici.

```bash
make check
make test
make verify-dev-image-repro
```

The local Compose smoke substitutes `runc` for hosts without Sysbox. It checks service startup, key-only SSH, tunnel relay, sandbox credential isolation, dev/root direct-egress denial, and fail-closed CONNECT without attestation policy. A controlled origin brackets denial probes with successful requests and confirms no denied request arrived. Full Sysbox, positive aTLS, and TEE evidence requires an authorized live environment.

`make test-release-images` runs these checks against the selected published Dev digest without rebuilding. Supply the exact Dev/Security refs and source SHA as described in the [runner release-image gate](../../docs/ci-cd.md#runner-release-image-gate).

The opt-in reproducibility gate creates two independent clean worktrees, performs cache-disabled builds with normalized timestamps, and requires identical linux/amd64 runtime-manifest digests. Each result index independently validates the release's pinned SBOM/provenance inputs. Top-level index digests are not compared because max-mode provenance includes a unique invocation ID and wall-clock timestamps. Publication exports the matching result from the fresh isolated cache populated by those two builds, revalidates the tagless push-by-digest registry result, and deploys its stable runtime digest. Both paths use the named `umbra-release` builder with digest-pinned BuildKit 0.34.1, compatibility version 30, a digest-pinned Dockerfile 1.26.0 frontend, and exactly Buildx 0.34.0.

`make verify-cvm-images-repro` applies the gate to both Dev and Security CVM images. Publication enforces the same two independent cache-disabled builds, then verifies the remote runtime and attestations before selecting the digest for deployment.

The canonical `Publish CVM images` workflow records that runtime digest and its
immutable attestation-index reference in a lock-shaped artifact. It deliberately
leaves the shared guest MRTD unset for the private provider canary to measure.

Updates use `umbra cvm update <cvm-id>` and preserve provider-managed named volumes. Published images must use immutable digests, never `latest`.

At startup, an older managed Claude install advances to the baked version without waiting for a network update. Newer managed versions and custom commands remain selected.

Live key rotation, host-level nested-virtualization alternatives, and guaranteed hitless migration are outside v0.

The pinned sandbox tools include Docker Engine/CLI 29.9.2, Buildx 0.38.1+umbra.2, Compose 5.6.1, and GitHub CLI 2.103.0. Their Go dependencies include the upstream security fixes; source archives and binary packages remain checksum-verified. The image smoke test exercises each Docker command and Compose configuration parsing.
