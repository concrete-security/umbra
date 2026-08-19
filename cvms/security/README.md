# Security CVM

The Security CVM is the per-entity egress gateway. Every Dev CVM request traverses it, including requests allowed by permissive profiles, so policy, DLP, credential injection, and traffic logs remain in the path. The authoritative contract is `docs/specs/security-cvm.md`.

Use `docs/security-cvm-audit-agent.md` for a focused hostile review of this enforcement chain.

## Responsibilities

- Pull effective per-CVM policy from authenticated Console control routes.
- Authenticate each Dev CVM by its per-CVM proxy bearer.
- Enforce scheme, host, port, method, path, request-body, and governed inbound WebSocket constraints fail closed.
- Decode supported content fully and scan headers/body for secrets before proxy-time injection.
- Inject scoped request-header credentials without exposing them to the sandbox.
- Terminate sandbox TLS, re-encrypt upstream, and expose the generated CA only through authenticated export.
- Emit attributed allowed, denied, DLP-blocked, tunnel, and error traffic logs.

## Runtime shape

| Service | Purpose |
| --- | --- |
| `mitmproxy` | Enforcement addon, management API, control polling, and traffic emission. |
| `proxy-tunnel` | Raw-byte shim for the shade proxy route. |

Policy flow:

1. Admins author profiles through the CLI and Console.
2. Console computes effective policy for each Dev CVM.
3. Security CVM polls and atomically swaps validated state.
4. A request authenticates with its per-CVM bearer.
5. The matching policy runs fail closed.
6. The outcome is emitted to Console traffic logs.

Source IP is not the identity boundary; the per-CVM bearer is.

## Files

| Path | Purpose |
| --- | --- |
| `docker-compose.yml` | Measured service compose. |
| `shade.yml` | Proxy and CA routes. |
| `Dockerfile` | Python runtime and mitmproxy package. |
| `src/umbra_security_cvm/runtime.py` | Boot and loop wiring. |
| `src/umbra_security_cvm/policy.py` | Effective-policy parser and validator. |
| `src/umbra_security_cvm/enforcement.py` | Authentication, policy, DLP, injection, and log records. |
| `src/umbra_security_cvm/mitmproxy_runtime.py` | mitmproxy process/addon wiring. |
| `src/umbra_security_cvm/proxy_tunnel.py` | Raw proxy tunnel shim. |
| `src/umbra_security_cvm/traffic.py` | Buffered traffic-log delivery. |
| `src/umbra_security_cvm/binding.py` | RTMR3 binding calculation. |
| `tests/` | Unit and integration-style tests. |

## Build and test

The repository pins Python 3.12 in `.python-version`, matching the Security CVM container. `uv` provisions it when necessary; newer Python minors are not part of the supported or release-tested runtime. The image restores the dated Debian snapshot recorded by its digest-pinned Python base before installing system packages; unavailable reviewed inputs fail the build instead of resolving newer packages.

```bash
make check
make test
```

Use digest-pinned images. Runtime updates go through `umbra security-cvm update`; provider-specific commands and IDs remain behind Console adapters. Dev forwarders can accept a locally verified candidate aTLS policy after an SC policy-only change and can refresh a rotated CA through the authenticated runtime path. Processes that cache trust may need restart after CA rotation.

`make verify-security-image-repro` performs two independent cache-disabled builds, requires identical runnable runtime-manifest digests, and independently validates each result index's attestations; `make verify-cvm-images-repro` runs that gate for both CVM images. Publication exports the matching result from the fresh isolated cache populated by those builds, then revalidates the tagless push-by-digest registry result before selecting the runtime digest.

The canonical `Publish CVM images` workflow records the runtime digest together
with the immutable attestation index that carries its SBOM and provenance. The
Security CVM reuses the Dev canary's private dstack guest MRTD measurement.

## Scope

V0 does not provide multiple active Security CVMs per entity, outbound WebSocket frame filtering, response-body filtering, arbitrary request signing, dynamic SSH-key revocation, or multi-entity Security CVMs. Unknown identity or invalid policy fails closed.
