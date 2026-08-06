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
- Security CVM policy, FQDN, CA, proxy/control bearers, SSH keys, and non-secret placeholders arrive as measured launch material.
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
| `DEV_CVM_CONTROL_TOKEN` | Per-CVM Console refresh bearer, forwarder only. |
| `SECURITY_CVM_CA_CERT_B64` | Security CVM mitmproxy root CA. |
| `SECURITY_CVM_ATLS_POLICY_B64` | Policy verified by `umbra-atls-connect`. |
| `CONSOLE_URL` | Bound Console origin for narrow refresh reads. |
| `AUTHORIZED_SSH_KEYS_B64` | Launch-time SSH public keys. |
| `SANDBOX_ENV_PLACEHOLDERS_B64` | Non-secret sandbox environment values. |

## Files and checks

| Path | Purpose |
| --- | --- |
| `docker-compose.yml` | Measured Dev CVM app compose. |
| `shade.yml` | Ingress routing. |
| `user-sandbox/` | Dockerfile, entrypoint, SSH, tunnel, forwarder, watcher, and helper crate. |
| `tests/` | Local smoke and package tests. |

The sandbox image is amd64-only. Its Ubuntu packages resolve from a dated Canonical snapshot, while exact Docker Engine, CLI, containerd, Buildx, and Compose `.deb` filenames and SHA-256 digests are reviewed in `user-sandbox/tool-versions.env`; architecture or digest drift fails closed.

```bash
make check
make test
make verify-dev-image-repro
```

The local Compose smoke substitutes `runc` for hosts without Sysbox and proves that owned services start, key-only SSH works, and the tunnel reaches sshd. Full Sysbox, aTLS, and TEE evidence requires an authorized live environment.

The opt-in reproducibility gate creates two independent clean worktrees, performs cache-disabled builds with normalized timestamps, and requires identical linux/amd64 runtime-manifest digests. Each result index independently validates the release's pinned SBOM/provenance inputs. Top-level index digests are not compared because max-mode provenance includes a unique invocation ID and wall-clock timestamps. Publication revalidates one tagless push-by-digest registry build and deploys its matching stable runtime digest. Both paths use the named `umbra-release` builder with digest-pinned BuildKit 0.32.2, compatibility version 30, a digest-pinned Dockerfile 1.26.0 frontend, and exactly Buildx 0.34.0.

`make verify-cvm-images-repro` applies the gate to both Dev and Security CVM images. Publication enforces the same two independent cache-disabled builds, then verifies the remote runtime and attestations before selecting the digest for deployment.

Updates use `umbra cvm update <cvm-id>` and preserve provider-managed named volumes. Published images must use immutable digests, never `latest`.

Live key rotation, host-level nested-virtualization alternatives, and guaranteed hitless migration are outside v0.
