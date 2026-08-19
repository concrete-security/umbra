# Umbra Dev CVM Spec

This document is the authoritative specification for the Umbra Dev CVM: image build contract, runtime services, network topology, identity model, attestation surface, trust chain, and update lifecycle. Implementations MUST conform.

The CLI surface that reaches a Dev CVM lives in [`docs/specs/cli.md`](cli.md). The Security CVM and Console specs are scoped separately. Plan-level invariants are not restated here; see [`docs/v0_plan.md`](../v0_plan.md) for the system overview, security model, and component ownership.

## 1. Overview

A **Dev CVM** is a per-developer hardened sandbox running on a confidential-VM provider. One CVM per developer, one developer per CVM. The CVM is a single Docker compose stack deployed by the Console; it lives until the developer (or an admin) terminates it and can be updated in place through `umbra cvm update`.

The Dev CVM MUST be provisioned on the **production** dstack OS image, never a dev/debug image. Dev dstack images expose debug conveniences and may alter the measured boot chain; the provider adapter MUST explicitly request the production OS path instead of relying on the `phala` CLI default. The `os_image_hash` returned by shade/Phala remains part of the aTLS policy bundle the CLI verifies (§8.1).

Three services are owned by this repository:

- `user-sandbox` — the developer's container, run under the **`sysbox-runc`** container runtime (shipped by the dstack guest OS). The developer — and any agent the developer runs — logs in as `dev` with **UID/GID 1001** and passwordless sudo inside the container's user namespace. Unrestricted sudo is root-equivalent inside that namespace, and Sysbox maps namespace privilege to an unprivileged UID on the dstack VM. The container holds a writable rootfs, a baked-in `dockerd` (native Docker-in-Docker — no sibling sidecar), sshd, dtach, the pre-installed agents (`claude`, `codex`, `gh`), and forced HTTPS proxy. Capabilities the kernel grants inside the container are scoped to the user namespace by construction; the trust boundary is the CVM, not the container. See §3.2.
- `dev-tunnel` — a thin WebSocket-to-SSH relay so the CLI can reach `user-sandbox:22` over `wss://<fqdn>/umbra/tunnel`.
- `dev-egress-forwarder` — the only Dev CVM service with an outbound route. It accepts the sandbox's HTTP proxy traffic on `cvm-internal` and forwards it over an attested TLS channel to the entity Security CVM. The cross-CVM wire protocol is owned by `docs/specs/security-cvm.md`; this spec fixes the Dev-CVM-side surface (§4.5, §5, §7).

Two services are owned by `shade`:

- `nginx-cert-manager` — TLS termination at `${app_id}.${gateway_domain}` with a dstack-KMS-issued certificate; route plumbing; EKM forwarding.
- `attestation-service` — `POST /tdx_quote`, returning a TDX quote whose `report_data` channel-binds to the active TLS session via EKM.

Audiences and what each consumes from this spec:

| Audience | Sections |
| --- | --- |
| Image builder | §3 image, §4.1 sandbox, §4.2 tunnel, §10 boot, §11 hardening, Appendix B |
| Console implementer | §6 identity, §12 update model |
| CLI implementer | §6, §8 attestation, §9 trust chain |
| Security CVM implementer | §5 networks, §7 egress |
| Security reviewer | §8, §9, §11 |

Non-goals:

- No tutorial. Operational onboarding lives in component READMEs.
- No CLI surface details. `cli.md` is authoritative for the developer-facing commands.
- No Console wire-protocol details. Out of scope here; `docs/specs/console.md` defines how it renders compose, calls Phala, and surfaces records to the CLI.

## 2. Topology

```mermaid
graph LR
  CLI["umbra CLI"] -->|wss://${fqdn}/umbra/tunnel| Nginx
  CLI -->|"POST /tdx_quote"| Nginx

  subgraph DevCVM["Dev CVM (TDX)"]
    Nginx["shade nginx-cert-manager"]
    Attest["shade attestation-service"]
    Tunnel["dev-tunnel"]
    Sandbox["user-sandbox<br/>(runtime: sysbox-runc)<br/>sshd + dockerd (DinD)"]
    Forwarder["dev-egress-forwarder"]

    Nginx -->|"/umbra/tunnel WS upgrade"| Tunnel
    Nginx -->|"X-TLS-EKM-Channel-Binding"| Attest
    Tunnel -->|"raw SSH bytes"| Sandbox
    Sandbox -->|"HTTPS_PROXY (sandbox + nested containers)"| Forwarder
  end

  Forwarder -->|"attested TLS"| SecCVM["Security CVM<br/>policy proxy + scanner + audit"]
  SecCVM -->|"TLS"| Internet
```

### 2.1 Service ownership

| Service | Owner | Image (illustrative) | Role |
| --- | --- | --- | --- |
| `user-sandbox` | this repo (`cvms/dev/user-sandbox/`) | `registry.example.com/umbra/dev-cvm/user-sandbox:<sha>` | sshd; dtach; pre-installed agents; baked-in `dockerd`; `dev` UID/GID 1001 with passwordless sudo inside the Sysbox user namespace — `runtime: sysbox-runc` |
| `dev-tunnel` | this repo (`cvms/dev/tunnel/`) | `registry.example.com/umbra/dev-cvm/tunnel:<sha>` | WebSocket-to-SSH relay |
| `dev-egress-forwarder` | this repo (`cvms/dev/egress-forwarder/`) | `registry.example.com/umbra/dev-cvm/egress-forwarder:<sha>` | local HTTP proxy endpoint; attested tunnel to Security CVM |
| `nginx-cert-manager` | shade | `registry.example.com/umbra/shade-cert-manager:<sha>` | TLS termination, route plumbing, EKM HMAC |
| `attestation-service` | shade | `registry.example.com/umbra/shade-attestation-service:<sha>` | TDX quote endpoint |

### 2.2 Networks

The compose MUST define exactly four networks; names and isolation MUST match the table.

| Network | Driver | `internal` | Members | Purpose |
| --- | --- | --- | --- | --- |
| `proxy` | bridge | no | `nginx-cert-manager`, `dev-tunnel` | shade's reverse-proxy backplane |
| `attestation` | bridge | no | `nginx-cert-manager`, `attestation-service` | quote endpoint reachable only from nginx (§4.4 forbids attestation-service on any other network) |
| `cvm-internal` | bridge | **yes** | `dev-tunnel`, `user-sandbox`, `dev-egress-forwarder` | tunnel ↔ sandbox SSH; sandbox → forwarder HTTP proxy; nested containers spawned by the sandbox's baked-in `dockerd` also exit through the sandbox's netns onto this bridge; no internet route |
| `egress-uplink` | bridge | no | `dev-egress-forwarder` | the forwarder's only public route; used exclusively to reach the entity Security CVM FQDN |

`nginx-cert-manager` publishes host ports `80:80` and `443:443`; that is the only externally exposed listening surface. `dev-egress-forwarder` does NOT publish any host port — it joins `egress-uplink` only to make outbound TLS connections to the Security CVM. `user-sandbox` joins `cvm-internal` only and does NOT publish any host port. The baked-in `dockerd` inside `user-sandbox` (DinD via Sysbox; §3.2) creates virtual bridges *inside* the sandbox's own network namespace for nested containers, and the only physical exit from that namespace is `cvm-internal` (internal:true) — so nested containers inherit the same "no direct internet route" property as the sandbox itself. There is no Docker network or volume shared across CVM boundaries; Dev CVM and Security CVM run as separate Phala TDX deployments and communicate only over the attested forwarder channel (§4.5).

### 2.3 Volumes

| Volume | Owner | Mounted at | Purpose |
| --- | --- | --- | --- |
| `tls-certs-keys` | shade | `nginx-cert-manager:/etc/nginx/ssl/` | dstack-KMS-issued cert/key |
| `dev-home` | this repo | `user-sandbox:/home/dev` | developer's home (persistent for the CVM lifetime) |
| `dev-workspaces` | this repo | `user-sandbox:/home/dev/workspaces` | code; nested containers spawned by the sandbox's baked-in `dockerd` bind-mount from here directly — no cross-container volume sharing is needed |
| `dev-local`, `dev-claude`, `dev-codex`, `dev-cursor-server`, `dev-vscode-server` | this repo | various `/home/dev/*` | tool state |
| `dev-docker-data` | this repo | `user-sandbox:/var/lib/docker` | data root for the dockerd baked into `user-sandbox` (image layers, container state); persistent across container restarts so re-pulls aren't required on every restart |
| `cvm-ca` | `dev-egress-forwarder` | `dev-egress-forwarder:/var/lib/umbra-ca` (`rw`); `user-sandbox:/var/lib/umbra-ca` (`ro`) | current authenticated SC CA plus its forwarder-owned FQDN/current-digest/launch-baseline sidecar; persists across service restarts and in-place Dev CVM updates |

Launch-time material is delivered through Phala's env-file mechanism (`docs/specs/console.md` §8.3 step 3, §10.4a). The compose YAML itself carries only `${VAR}` placeholders and is universal across Dev CVMs in v0 — the per-CVM variation lives entirely in the env-file the Console injects at deploy. The full Security CVM aTLS policy is the deliberate exception: it MUST NOT be included in that Phala env and is fetched over the authenticated Dev-control channel before the first upstream SC connection or successful CONNECT response. The forwarder MAY already be listening so the Dev CVM remains reachable for measurement. The entrypoint (§10) materialises the remaining runtime values into `/run/umbra/*` paths at boot, and the dstack guest agent extends `RTMR3` with the JCS-canonicalized (RFC 8785) SHA-384 digest of those values before the application starts. Tampering with any launch-bound value after boot cannot retroactively rewrite the digest, and the Console's `atlas-rs` policy at first tunnel rejects any quote whose RTMR3 does not replay the values the Console intended for this CVM (§9). All materials below are populated by the Console at deploy time:

| Env name | Materialised path | Mode | Source | Purpose |
| --- | --- | --- | --- | --- |
| `SECURITY_CVM_FQDN` | n/a | n/a | Console-selected entity SC FQDN | Launch-bound SC identity used by both the forwarder and sandbox CA bootstrap to reject a persisted CA from another binding |
| `SECURITY_CVM_CA_CERT_B64` | `user-sandbox:/run/umbra/security-cvm-ca.launch.pem` (bootstrap); `dev-egress-forwarder:/run/umbra/security-cvm-ca.pem` | `0444` | Console-supplied CA export from the entity Security CVM (`docs/specs/console.md` §8.4 step 8) | Launch trust anchor; the sandbox installs either this CA or a valid same-FQDN persisted rotation at `/run/umbra/security-cvm-ca.pem` (§4.5, §10) |
| `SECURITY_CVM_PROXY_TOKEN` | `dev-egress-forwarder:/run/umbra/proxy-token` | `0400` | Console-minted per-Dev-CVM `service_principal_tokens` plaintext (`docs/specs/console.md` §8.3 step 4, `principal_type=dev_cvm`, `purpose=PROXY_AUTH`) | Bearer the `dev-egress-forwarder` presents to the Security CVM as `Proxy-Authorization` for `cvm_id` attribution (§4.5). This value MUST NOT be injected into `user-sandbox`. |
| `DEV_CVM_CONTROL_TOKEN` | n/a | n/a | Console-minted per-Dev-CVM `service_principal_tokens` plaintext (`principal_type=dev_cvm`, `purpose=DEV_CONTROL`) | Bearer the `dev-egress-forwarder` presents only to Console Dev-control routes for mandatory SC-policy bootstrap and periodic refresh (§4.5). The Security CVM MUST NOT accept this token for proxy traffic. This value MUST NOT be injected into `user-sandbox`. |
| `CONSOLE_URL` | n/a | n/a | Console origin URL | Used only by `dev-egress-forwarder` for authenticated SC-policy bootstrap and periodic policy/CA refresh. It is RTMR3-bound so a deploy-plane redirect to a hostile control plane is detected at Dev CVM tunnel verification. Production bootstrap requires HTTPS; non-HTTPS local/dev origins MUST NOT weaken production transport requirements. |
| `AUTHORIZED_SSH_KEYS_B64` | `user-sandbox:/run/umbra/authorized_keys.bootstrap` | `0644` | Console-supplied developer authorized keys (sorted, newline-terminated; see §6.1) | Source for the `dev` user's `authorized_keys` written by the entrypoint at boot |
| `SANDBOX_ENV_PLACEHOLDERS_B64` | `user-sandbox:/run/umbra/sandbox-env-placeholders` | `0444` | Console-rendered, non-secret placeholder env from the attached profiles' `sandbox_env` policy field (`docs/specs/console.md` §8.5) | Lets SDKs and CLIs that require local credential-shaped env vars issue requests so the SC can inject the real header later (§7.1). Values MUST be placeholders such as `umbra-proxy-injected`, never real provider credentials. |

The complete SC policy is generated, stored, and used by the Console's own SC attestation exactly as before; only its transport into the Dev CVM changes. The forwarder MAY bind its listener without a policy for measurement compatibility, but before the first upstream SC connection or `200 Connection Established` it MUST fetch `GET ${CONSOLE_URL}/internal/dev-control/security-cvm-atls-policy` with `DEV_CVM_CONTROL_TOKEN`, require a complete strict policy, bind it to the launch SC FQDN and currently accepted CA digest, and atomically install it at `/run/umbra/security-cvm.atls-policy.json`. Missing material, authentication or transport failure, a disabled/incomplete/invalid policy, or exhaustion of the bounded bootstrap retry budget MUST return fail-closed `502` without opening an upstream connection. A blank, stub, or dev policy and every validation bypass are forbidden. The same authenticated endpoint remains the source for periodic refresh (§4.5).

The credential and trust-anchor values are bound into RTMR3 by their SHA-256 digest or literal value in the JCS payload the Console replays at attestation time (`docs/specs/console.md` §10.4a `JCS({cvm_id, console_url, dev_cvm_control_token_sha256, security_cvm_fqdn, security_cvm_proxy_port, security_cvm_proxy_token_sha256, security_cvm_ca_cert_sha256, authorised_ssh_keys_sha256})`). A deploy-plane swap of any bound value — for example, substituting a different Dev CVM's `SECURITY_CVM_PROXY_TOKEN` to misattribute traffic at the SC, substituting a different `DEV_CVM_CONTROL_TOKEN` to fetch another CVM's policy candidate, or redirecting `CONSOLE_URL` to a hostile policy service — produces a mismatched RTMR3 digest and fails the CLI's `atlas-rs` policy check before any application bytes flow (§9). The Security CVM spec governs the CA export and rotation flow (`docs/specs/security-cvm.md`).

## 3. Image build contract

### 3.1 `user-sandbox` image

Base: `ubuntu:24.04` (or pinned digest). Tooling:

- `openssh-server`, `dtach`, `git`, `curl`, `xz-utils`, `build-essential`, `python3`, `python3-pip`, `rsync`, `jq`, `vim`, `less`, `ca-certificates`, `psmisc` (provides `fuser` for `umbra ps` / `umbra kill` socket probing per `docs/specs/cli.md` §6.4), `lsof` (fallback for the same probe).
- `sudo` MUST be installed with a `dev ALL=(ALL) NOPASSWD:ALL` sudoers drop-in, and that drop-in MUST preserve the proxy and CA-bundle environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy`, `NO_PROXY`, `no_proxy`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`) for the `dev` user. This is root-equivalent inside the Sysbox user namespace, but does not change the host boundary; see §3.2.
- APT MUST be preconfigured through `/etc/apt/apt.conf.d/95umbra-proxy` to use `http://dev-egress-forwarder:3128` for both HTTP and HTTPS acquisitions, and HTTPS acquisitions MUST use `/run/umbra/ca-bundle.pem` as their CA bundle. This keeps `sudo apt update` / `sudo apt install` on the controlled egress path even though `sudo` and APT do not reliably consume the login shell's proxy environment by default.
- **`docker-ce` engine + CLI + `docker-compose-plugin`** — verified install. The daemon runs natively inside `user-sandbox` (DinD via Sysbox; §3.2, §4.1). The image MUST drop `/etc/docker/daemon.json` configuring the SC proxy as `dockerd`'s default `http-proxy`/`https-proxy` so nested containers without baked-in env still pick up the forwarder (§7.2). No `DOCKER_HOST` env override is set — clients hit the local socket `/var/run/docker.sock` by default.
- `uv` (Python toolchain) — copied from `ghcr.io/astral-sh/uv:<pin>`.
- Node.js 22 LTS — verified binary install.
- Claude Code (`claude`) — verified binary install with checksum.
- OpenAI Codex (`codex`) — npm with `--ignore-scripts`. The installed wrapper MUST prepend `--dangerously-bypass-approvals-and-sandbox` on both the updated user-local binary path and the baked fallback path. Umbra's Sysbox/Dev-CVM isolation and Security CVM egress enforcement are the agent boundary; Codex MUST NOT add its nested Linux sandbox or approval prompts inside that boundary.
- GitHub CLI (`gh`) — verified binary install. Configured as a git credential helper for `https://github.com` and `https://gist.github.com` so HTTPS git traffic flows through the Security CVM.
- `tmux` MAY be present for users who prefer it; the CLI MUST NOT invoke it. dtach is the only persistent-session multiplexer the CLI uses (see `cli.md` §6.4).

Versions and image refs are illustrative; Appendix B carries the current pins.

### 3.2 User, privileges, and intra-CVM isolation model

`user-sandbox` MUST be launched under the **`sysbox-runc`** container runtime (the dstack guest OS ships Sysbox 0.6.7 baked in at `/usr/bin/sysbox-runc`, with `sysbox-runc` pre-registered in `/etc/docker/daemon.json`). The compose service therefore declares `runtime: sysbox-runc`. This single decision is what makes the rest of the model coherent.

A single login user `dev` MUST exist with **UID/GID 1001** (`groupadd --gid 1001 dev` and `useradd --uid 1001 --gid 1001 --create-home --home-dir /home/dev --shell /bin/bash dev`). The image MUST replace `useradd`'s default locked shadow password field with an impossible non-locking value, such as `*`; an empty password is forbidden. This keeps OpenSSH public-key login eligible while `PasswordAuthentication no` prevents password login. `dev` MUST be a member of both `sudo` and the Docker socket group, and `/etc/sudoers.d/dev` MUST grant `dev ALL=(ALL) NOPASSWD:ALL` while preserving the proxy/CA env named in §3.1. The interactive default is therefore a non-root Unix user, while `sudo` remains available for package installation, system mutation, daemon administration, and tools that expect root-equivalent control. Outside the namespace, root-equivalent operations are still bounded by Sysbox's user namespace mapping to an unprivileged UID on the dstack VM. This is the design centre.

The intra-CVM threat model that justifies this:

- **Trust boundary is the user namespace, which Sysbox aligns with the container.** Agents inside `user-sandbox` are treated as potentially adversarial (prompt-injection, malicious tool output). The developer normally runs as UID 1001, but passwordless sudo gives root-equivalent control inside the container when requested. Every capability the kernel grants to in-namespace root is scoped to that user namespace. Nothing in the sandbox can read root-owned files on the dstack VM (the host TLS material, `dstack.sock`, and per-CVM proxy bearer are owned by the trusted compose-host's real UID 0), modify routes outside the netns, load kernel modules, or call privileged syscalls against the host. UID 0 inside the namespace is **not** UID 0 on the dstack VM — the kernel checks the mapped UID, not the in-namespace UID.
- **Native DinD replaces the sibling-daemon split.** Sysbox is purpose-built to run dockerd inside a container without privileged mode: it intercepts the procfs/sysfs accesses dockerd needs and arbitrates `mount`/`mknod`/`unshare` calls so dockerd functions inside the userns without escaping it. The Dev CVM therefore runs **one** container with rootful `dockerd` baked in (§3.1, §4.1) — no separate `agent-docker` service, no shared host docker-socket volume, no inter-container API to harden. `dev` is in the Docker socket group, so the normal UX is plain `docker ...` without `sudo`. `docker run --privileged --net=host -v /:/host …` issued from inside the sandbox resolves entirely inside `user-sandbox`'s user + network namespaces — its "privileges" are userns-scoped, its `--net=host` is the sandbox's own netns (which is `cvm-internal` only), and its `/` is the sandbox's rootfs.
- **Topology, not iptables, is what blocks proxy bypass.** `cvm-internal` is `internal: true` (§2.2, §5): Docker installs no default route off this bridge. `user-sandbox` joins `cvm-internal` only. The only container with a non-internal network is `dev-egress-forwarder`, which uses `egress-uplink` solely to reach the entity Security CVM FQDN (§4.5). No in-namespace capability the agent might hold can change this — there is no route to manipulate from inside.
- **Self-DoS is explicitly out of scope.** The sandbox runs without cgroup limits in v0. A fork bomb, `malloc(100 TB)`, or `:(){ :|:& };:` from inside renders the developer's own Dev CVM unresponsive and requires `umbra cvm terminate` + relaunch to recover. Cross-tenant isolation lives at the Phala host (separate TDX VMs per CVM); within a single CVM, all containers share one developer's resource budget by design.
- **Runtime material is delivered at the boundary and bound by attestation.** SSH keys, the SC mitmproxy CA, and the per-CVM proxy/control bearers arrive via Phala's env-file at deploy time (§2.3, §6.1, `docs/specs/console.md` §8.3 step 3). Each value is injected only into the service that needs it: `user-sandbox` receives the CA, authorized keys, and non-secret sandbox placeholders; `dev-egress-forwarder` receives the CA and proxy/control bearers. The full SC aTLS policy never enters the provider launch env: before its first upstream SC connection or successful CONNECT response, the forwarder authenticated-fetches and strictly validates it, then refreshes it from the same endpoint. RTMR3 binds the launch values that authorize and scope that fetch (`docs/specs/console.md` §10.4a), so a deploy-plane swap is detected by the CLI's `atlas-rs` verification at first tunnel (§9). The dev user can read the sandbox's CA/keys/placeholders inside their namespace, but cannot read the forwarder's bearers or runtime policy through the normal compose boundary, cannot rewrite the RTMR digest, and cannot exfiltrate material past the topology-bound egress.

Passwordless sudo is mandatory (see §3.1). It is a convenience and compatibility layer for tools that hard-code `sudo apt install …`, but it is also root-equivalent inside the Sysbox namespace. The sandbox's rootfs IS writable (§3.3) — the agent can use sudo to replace binaries, edit `/etc`, install or remove packages, including modifying the baked-in `dockerd` binary or `daemon.json`. None of that breaks the userns boundary or the egress topology; it only changes what is true inside the sandbox.

Tool installation at runtime is unrestricted: `sudo apt install`, `pip install`, `cargo install`, `npm i -g`, `go install`, kernel-headers, debuggers requiring `ptrace`, all work. Persistence across container restarts comes from named volumes (§2.3); rootfs changes outside those volumes are lost on restart. For workloads that need a different base image, the developer runs them as nested containers via the in-sandbox `dockerd`; nested containers inherit the same userns + netns as their parent. Practical caveat: root-running nested containers may create root-owned files in bind-mounted workspaces. Developers can run those containers with `--user "$(id -u):$(id -g)"` when file ownership matters, or use `sudo chown` inside the sandbox to repair ownership afterward.

### 3.3 Filesystem layout

The image MUST satisfy:

- `read_only` MUST be **false** on `user-sandbox`. The container's rootfs is writable so the developer can use sudo to install packages, modify `/etc/`, drop binaries in `/usr/local/bin/`, etc. Persistence across container restarts comes from named volumes (§2.3), not the rootfs.
- `tmpfs:` mounts at minimum `/run` (so `/run/umbra/*` measured-config material and `/run/ssh/*` are wiped on restart and never persist to disk).
- `/home/dev/.ssh` is a symlink to `/run/ssh/user-ssh` (writable tmpfs); sshd reads from there.
- `/home/dev/.claude.json` is a symlink to `/home/dev/.claude/.claude.json` (volume-backed) so Claude state survives container restarts. The target file MUST contain valid JSON before Claude starts; the entrypoint initializes missing or empty targets to `{}`.

`EXPOSE 22` is the only listening port.

Healthcheck: `pgrep -x sshd >/dev/null` with `interval=500ms`, `timeout=2s`, `start-period=3s`, `retries=5`. `dev-tunnel` MUST NOT gate its startup on `user-sandbox`: it dials the sandbox per connection and surfaces `connection_error` until sshd accepts, while shade's nginx needs the `dev-tunnel:8090` upstream resolvable as soon as the app network exists — gating the tunnel behind the sandbox's (Sysbox-delayed, up to ~5 min) health starves nginx through certbot's entire retry budget and the CVM never obtains its TLS certificate (first live canary measurement, 2026-08-05). If the non-sandbox services reuse the same image artifact as `user-sandbox`, the compose MUST disable the inherited image healthcheck on `dev-tunnel` and `dev-egress-forwarder`; the sshd healthcheck applies only to `user-sandbox`.

### 3.4 Capabilities and runtime bounding

`user-sandbox` uses **`runtime: sysbox-runc`** and the **default OCI capability set** that Sysbox grants inside the container. The compose MUST NOT use `cap_drop: [ALL]` + a narrow `cap_add` allowlist on this service. Two reasons:

1. The boundary that matters is the user namespace, not the in-container cap set. Sysbox places the container in its own userns; every capability the kernel grants is checked against that namespace and confers nothing on the dstack VM.
2. Stripping caps inside a Sysbox container breaks the workloads the design is meant to enable — `dockerd`, `apt`, `ping`/`traceroute`, debuggers using `ptrace`, kernel-header builds, etc. Sysbox's whole point is that you can hand the container a full cap set safely.

The compose MUST set on `user-sandbox`:

- `runtime: sysbox-runc`
- `privileged: false` (Sysbox refuses privileged anyway)
- No `userns_mode` override (Sysbox manages the userns)
- No `pid: host`, `ipc: host`, `network_mode: host` (Sysbox refuses these)
- `security_opt: []` MUST NOT be set; Sysbox supplies its own AppArmor/seccomp profile and the compose MUST NOT override it. In particular do NOT add `no-new-privileges:true` — Sysbox requires the ability to set caps when entering child namespaces; the userns boundary supersedes `no-new-privileges` as a privilege ceiling.

For the **non-sandbox** services (`dev-tunnel`, `dev-egress-forwarder`) Sysbox is NOT used; they keep `cap_drop: [ALL]`, `read_only: true`, and `security_opt: [no-new-privileges:true]` as before. The forbidden-cap list (`NET_ADMIN`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_PTRACE`, `BPF`, `MAC_*`, `AUDIT_CONTROL`, etc.) applies to those services. It does NOT apply to `user-sandbox` — those caps inside the sandbox are userns-scoped by Sysbox and grant nothing on the dstack VM.

The image MUST set up `/etc/subuid` and `/etc/subgid` ranges for the `dev` user (e.g. `dev:100000:65536`) so the in-sandbox `dockerd` can sub-allocate userns ranges for its nested containers. Sysbox-mgr arbitrates host-side range allocation across CVMs; the per-image config only needs to declare what's available inside.

### 3.5 sshd configuration

`/etc/ssh/sshd_config` MUST set at minimum:

- `PasswordAuthentication no`
- `PermitRootLogin no`
- `AllowUsers dev`
- `PubkeyAuthentication yes`
- `AuthorizedKeysFile /run/ssh/authorized_keys/dev`
- `PermitUserEnvironment yes` so `BASH_ENV` and proxy env vars set on the authorized_key line take effect.
- `AcceptEnv` empty — no client-controlled environment.
- `ClientAliveInterval` reasonable (e.g. 60s) so dead tunnels don't pin sessions.

`dev` is UID 1001, not root (§3.2). `PermitRootLogin no` keeps the `root` username out of the v0 login surface, while `AllowUsers dev` limits public-key login to the developer account.

Host keys are generated at every container start (§10). Trust comes from aTLS attestation (§9), not SSH host-key pinning.

### 3.6 Pre-installed agents and update path

The image bakes Claude Code, Codex, and `gh` at known versions. The entrypoint MUST seed `/home/dev/.local/bin/claude` from the verified baked Claude binary when the persistent `.local` volume does not already contain an executable Claude command. The seeded path MUST use the native-install layout under `/home/dev/.local/share/claude/versions/` so Claude's persisted `installMethod` metadata and the command path agree even though `.claude` and `.local` are separate volumes. A `/etc/profile.d` hook MAY upgrade agents in the background on first SSH login per CVM, with a 4-hour cooldown via `/tmp/.umbra-agents-updated`. Auto-update MUST NOT block sshd startup or the entrypoint healthcheck window.

### 3.7 `dev-tunnel` image

A small relay that:

- Listens on TCP `:8090` (HTTP).
- Accepts a WebSocket upgrade on `/umbra/tunnel`, and on `/concrete/tunnel`
  as a transition alias for concrete-branded CLIs (<= 0.4.x); the alias is
  removed once those CLIs are retired.
- Bridges binary WebSocket frames to a TCP connection to `user-sandbox:22`.
- Drops all capabilities (`cap_drop: [ALL]`), `read_only: true`, `security_opt: [no-new-privileges:true]`, `tmpfs: [/tmp]`.
- Exposes no other endpoints.

The relay MUST NOT inspect, log, or modify the framed bytes beyond what the WS framing requires. Logging MUST be limited to connection metadata (peer, duration, byte counts) on stderr.

### 3.8 In-sandbox `dockerd` (DinD) configuration

The Docker daemon baked into `user-sandbox` MUST be configured at image-build time via `/etc/docker/daemon.json`:

- **Proxy defaults injected into every nested container:**
  ```json
  {
    "proxies": {
      "http-proxy":  "http://dev-egress-forwarder:3128",
      "https-proxy": "http://dev-egress-forwarder:3128",
      "no-proxy":    "localhost,127.0.0.1,user-sandbox,dev-tunnel,dev-egress-forwarder"
    }
  }
  ```
  so `docker run` images without baked-in env still pick up the forwarder (§7.2).
- **Storage driver:** `overlay2` is fine — Sysbox arranges idmapped mounts so `overlay2` works inside the userns. (Sysbox alternatively supports `fuse-overlayfs` and `btrfs` if a future image needs them; `overlay2` is the default.)
- **Default runtime:** standard `runc`. Sysbox is the runtime *outside* the sandbox (chosen by the Dev CVM compose); nested containers spawned by the in-sandbox `dockerd` use `runc` by default and run in *nested* user namespaces below the sandbox's own.
- **Socket:** `/var/run/docker.sock`, the default. No `DOCKER_HOST` override is needed. The `dev` user is in the Docker socket group so normal `docker ...` commands work without `sudo`.

The agent can use sudo to modify `daemon.json`, restart `dockerd`, or point it at a different proxy — but cannot route nested-container traffic anywhere except `cvm-internal` (because the sandbox's netns has only one physical exit; §5). Tampering with `dockerd` inside the sandbox does not break egress containment; it only changes what's true inside the sandbox.

## 4. Runtime services

### 4.1 `user-sandbox` runtime

The container's behavior is fully described by §3 (build) + §10 (boot sequence) + §6 (authorized_keys provenance) + §7 (egress). The runtime invariants are:

- **Runtime:** `runtime: sysbox-runc` (§3.2, §3.4). The Dev CVM compose MUST set this on the `user-sandbox` service. Any deploy-plane rewrite that drops or swaps the runtime changes the compose hash and is detected by `policy.json` at first tunnel (§8.1, §9).
- **No cgroup limits in v0.** The sandbox runs without `pids_limit`, `mem_limit`, or `cpus` set on the service. Resource exhaustion from inside the sandbox (fork bomb, `malloc` storm, CPU burner) is the developer's own footgun and renders only their own CVM unresponsive — see §3.2 self-DoS bullet.
- **Processes:**
  - `sshd` — long-running, the only externally reachable listener (port 22, `cvm-internal` only).
  - `dockerd` — long-running, baked-in (§3.1, §3.8). Started by the entrypoint after Sysbox finishes setting up the userns + idmapped mounts; serves `/var/run/docker.sock` to in-sandbox clients. The agent (`dev`) talks to it through Docker socket group membership, so normal `docker ...` commands do not require `sudo`.
- Per-session state lives in `/run/umbra/sessions/<name>.sock` (mode `0700`, owned `dev`); see `cli.md` §6.4.
- `/run/umbra/env.sh` sources the proxy and CA-bundle env into every login shell via `/etc/profile.d/umbra-env.sh`.
- `BASH_ENV=/run/umbra/env.sh` is set on the authorized_keys `environment="…"` options so non-PTY sessions (`ssh -T`) also pick up the env.
- The compose MUST NOT set `userns_mode`, `pid: host`, `ipc: host`, `network_mode: host`, or `privileged: true` on this service; Sysbox refuses these and the compose hash anchors the refusal.
- The compose MUST NOT set `security_opt` on this service (in particular MUST NOT add `no-new-privileges:true` or override `apparmor`/`seccomp`). Sysbox supplies a tailored profile that allows the syscalls dockerd, systemd-style services, and idmapped mounts need; overriding it breaks the runtime.

### 4.2 `dev-tunnel` runtime

- Accepts at most one WebSocket per outbound TCP connection.
- Idle timeout SHOULD be ≥ 1 hour (long-running editor / agent sessions).
- On WS close, the underlying TCP connection MUST be closed; on TCP error, the WS frame MUST signal the close cleanly.
- No authentication. Authorization is enforced upstream by SSH pubkey on `user-sandbox`.

### 4.3 `nginx-cert-manager` runtime (shade)

- Terminates TLS at `${app_id}.${gateway_domain}` with a dstack-KMS-issued cert (volume `tls-certs-keys`, populated via `/var/run/dstack.sock`).
- Publishes ports `80:80` and `443:443` on the host.
- Routes:
  - `POST /tdx_quote` → `attestation-service:8080` with `X-TLS-EKM-Channel-Binding: ${ekm_hex}:${hmac_hex}` (RFC 5705 EKM exporter `EXPORTER-Channel-Binding`, 32 bytes; `hmac_hex` = HMAC-SHA256(`ekm_raw`, in-TEE HMAC key)).
  - `GET /umbra/tunnel` (WebSocket upgrade) → `dev-tunnel:8090`. `proxy_read_timeout` and `proxy_send_timeout` MUST be ≥ 3600s. `GET /concrete/tunnel` routes identically as the concrete-CLI transition alias.
- All other paths MUST return 404.

### 4.4 `attestation-service` runtime (shade)

- Listens only on the `attestation` network (port `8080`).
- Validates `X-TLS-EKM-Channel-Binding`: derives the HMAC key inside the TEE via dstack KMS (`get_key("ekm/hmac-key/v1")`), recomputes `HMAC-SHA256(ekm_raw, hmac_key)`, compares with `hmac_hex` in constant time. On mismatch, return 400 without producing a quote.
- Builds `report_data = SHA512(nonce_bytes || ekm_bytes)`.
- Calls dstack `tdx_quote(report_data)` and returns the raw quote and bootchain metadata.

Network isolation is part of the contract: the attestation service MUST be reachable only from `nginx-cert-manager`. Direct exposure to `proxy` or any external network is a spec violation.

### 4.5 `dev-egress-forwarder` runtime

The forwarder is the only Dev CVM component with an outbound route. Its job is to act as a chained HTTP proxy: it terminates the sandbox's unauthenticated proxy connection on `cvm-internal`, re-encodes the request as an authenticated proxy connection over an attested TLS channel to the entity Security CVM, and bridges the resulting tunnel byte-transparently. The sandbox itself therefore never needs a public route and never sees the Security CVM bearer.

- Listens on `cvm-internal` at TCP `:3128` for HTTP CONNECT and HTTP proxy requests from `user-sandbox`. No authentication on this leg — the network is `internal: true` and `user-sandbox` is the only client.
- Joins `egress-uplink` (non-internal) exclusively to open outbound TLS connections to the Security CVM at `https://${SECURITY_CVM_FQDN}:443`, using `SECURITY_CVM_FQDN` as the TCP target, TLS SNI, certificate identity, attestation identity, and HTTP Host. Any other outbound destination is a spec violation.
- MAY bind `:3128` without a policy for measurement compatibility, but before the first upstream SC connection or `200 Connection Established` MUST authenticated-fetch the complete Security CVM aTLS policy from `GET ${CONSOLE_URL}/internal/dev-control/security-cvm-atls-policy`, strictly validate it, and atomically install it at `/run/umbra/security-cvm.atls-policy.json`. The full policy MUST NOT be sent through Phala's launch env. Bootstrap retries are bounded; missing material, an unavailable endpoint, or an invalid, disabled, incomplete, blank, stub, or dev policy returns fail-closed `502` without opening an upstream connection. No validation or verification bypass is permitted.
- Verifies every Security CVM connection against the installed policy. Fails closed if the endpoint cannot be reached or attestation does not satisfy the policy.
  - **TEMPORARY DEVIATION (sc-policy-check-disabled):** the `umbra-atls-connect` helper currently strips the image/runtime pins from the (still strictly validated) policy before verification, so the forwarder accepts any genuine SC TEE at the bound FQDN regardless of its app image — avoiding fleet-wide Dev CVM updates on SC image bumps. Genuine-TEE proof (DCAP quote, TCB, cert-in-event-log, EKM anti-replay, RTMR replay) is retained; only bootchain/`app_compose`/`os_image_hash` pinning is skipped. This is a hardcoded, clearly-marked mitigation — see `docs/sc-policy-check-disabled.md` for exactly what to remove to re-enable.
- After bootstrap, the forwarder MUST periodically refresh from that same endpoint with `DEV_CVM_CONTROL_TOKEN`; an SC application-image release changes the full runtime policy but not the shared guest MRTD. It MUST reject a candidate if `security_cvm_fqdn` differs from launch-bound `SECURITY_CVM_FQDN`, if `ca_cert_sha256` differs from the latest SC CA accepted through the authenticated runtime CA-refresh path below, or if the policy disables runtime verification or omits `app_compose`, `expected_bootchain`, or `os_image_hash`. A rejected refresh MUST NOT replace the last valid policy. The Console response is a candidate delivery channel, not a substitute for local aTLS verification. The SC `PROXY_AUTH` bearer MUST NOT be sent to Console and `DEV_CVM_CONTROL_TOKEN` MUST NOT be accepted by the Security CVM proxy. A CA digest mismatch remains fail-closed until the independent CA poll converges. **Trust caveat:** this v0 path still relies on the Console to materialize the candidate SC runtime policy; making the Console only an untrusted cache requires release-pipeline-signed SC policy material that the forwarder/helper verifies before accepting the candidate.
- **Runtime SC CA refresh (follow SC CA rotation without `cvm.update`).** In current Umbra Dev images, independently of the aTLS-policy refresh above, the forwarder polls `GET ${CONSOLE_URL}/internal/dev-control/security-cvm-ca` (same `DEV_CVM_CONTROL_TOKEN`, RTMR3-bound origin, reached directly over `egress-uplink` — not through the SC proxy, so it works while the sandbox's current SC CA is stale) for the current SC mitmproxy CA. It MUST reject a CA whose `security_cvm_fqdn` differs from the launch-bound `SECURITY_CVM_FQDN` or whose bytes do not match the response's `ca_cert_sha256`, then publish the accepted CA and a forwarder-owned `{security_cvm_fqdn,ca_cert_sha256,launch_ca_cert_sha256}` sidecar onto the shared `cvm-ca` volume (`dev-egress-forwarder` `rw`, `user-sandbox` `ro`). On ordinary restart, the forwarder MUST preserve a structurally valid pair only when both its FQDN and immutable launch-baseline digest match the current launch; it seeds launch material with no-clobber creation only when both files are absent. Partial, unreadable, malformed, or digest-mismatched state stays fail-closed until an authenticated poll replaces it. A valid pair from another FQDN or launch-CA baseline indicates an in-place Dev update changed the launch binding, so the current attested launch CA replaces that foreign pair. The `umbra-ca-refresh` watcher accepts only a CA whose sidecar matches its bytes, current `SECURITY_CVM_FQDN`, and current launch-CA digest, then rebuilds `/run/umbra/ca-bundle.pem` (§7) as system roots + that CA (**replace**, not append). Sandbox startup prefers a valid persisted same-binding CA over the immutable launch baseline, preventing an ordinary restart from briefly re-trusting an older CA; it uses the launch CA only for an empty volume or a valid foreign binding, and waits fail-closed (bounded by the bootstrap timeout) for authenticated repair of corrupt/partial state. This lets compatible sandboxes follow SC CA rotation without `cvm.update`; path-based verifiers recover on their next connection, but already-running processes that cached the bundle (e.g. Node) need a restart. A persisted `SECURITY_CVM_REBIND_REQUIRED` marker means this capability is unproven for that legacy deployment. The marker MUST remain fail-closed; use the pre-Umbra control plane to terminate/decommission the preserved resource, then launch a replacement under Umbra. The renamed build cannot manage it, and `cvm.update` is not recovery.
- The forwarder MAY delegate the cross-CVM aTLS transport to a pinned local helper inside the Dev CVM image, provided that helper owns the verified TLS session and returns only a loopback relay for that specific session. The helper receives one JSON request on stdin containing `fqdn`, `port`, `policy_path`, and `ca_cert_path`, then writes exactly one newline-terminated JSON response to stdout in the shape `{"host":"127.0.0.1","port":<relay-port>}` after attestation succeeds and the loopback relay is listening. The helper opens TCP to `fqdn`, uses it as the TLS SNI, and validates the certificate and attestation identity against `fqdn` with `fqdn` as HTTP Host. The helper process MUST stay alive while that relay is usable; the forwarder terminates the helper when the client request finishes. The forwarder MUST NOT pass `SECURITY_CVM_PROXY_TOKEN` to this helper. Missing helper, malformed helper output, helper timeout, premature helper exit, or helper attestation failure is a hard fail-closed request failure. Test harnesses MAY override the helper path; production compose MUST use the pinned image helper, never a no-op verifier.
- After the aTLS helper returns a verified byte relay to the SC, the forwarder MUST first issue `GET /umbra/proxy HTTP/1.1` with `Connection: Upgrade` and `Upgrade: umbra-proxy`, using `SECURITY_CVM_FQDN` as the HTTP Host identity. The upgrade request MUST NOT carry `Proxy-Authorization`. If the SC does not return `101 Switching Protocols`, the sandbox request fails closed.
- **Re-issues each sandbox proxy request to the Security CVM.** On every accepted `CONNECT` or HTTP proxy method from the sandbox, the forwarder MUST issue a new proxy request upstream to the Security CVM, **injecting `Proxy-Authorization: Bearer <SECURITY_CVM_PROXY_TOKEN>`** at the proxy-protocol layer. The token is loaded at startup from `/run/umbra/proxy-token` (mode `0400`), populated by the entrypoint from the env-file value `SECURITY_CVM_PROXY_TOKEN` (§2.3, §10). The forwarder MUST strip any `Proxy-Authorization` header the sandbox may have set (the sandbox does not hold the token, so this is defense-in-depth) before substituting its own.
- If the Security CVM rejects a sandbox `CONNECT` request with a non-`200` response, the forwarder MUST relay the response headers and any bounded `Content-Length` or chunked body back to the sandbox before closing. This preserves the SC's `Umbra network restriction` explanation so agents and developers see an Umbra profile-policy block instead of a generic network failure.
- For absolute-form HTTP proxy methods, the forwarder MUST NOT raw-bridge client connection reuse or pipelined follow-up requests to the SC after authenticating only the first request. It MUST either parse and authenticate each HTTP proxy request separately, or force single-request semantics by sending `Connection: close`, relaying only that request body and response, then closing the sandbox connection. This prevents APT-style HTTP connection reuse from producing unauthenticated second requests and `407 Proxy Authentication Required` responses from the SC.
- **No inspection of the bridged payload.** Once the upstream tunnel is established (e.g. after a successful `CONNECT 200`), the forwarder MUST bridge bytes between the sandbox and the Security CVM byte-transparently. It MUST NOT inspect, transform, or log the tunneled application data. The "no inspect" rule scopes the **bridged payload**, not the proxy-protocol framing on either leg — injecting `Proxy-Authorization` upstream is explicitly the forwarder's job, not a violation.
- Identity attribution at the Security CVM is established by the `Proxy-Authorization` bearer the forwarder injects: the Security CVM hashes the token and resolves it to a `cvm_id` via its locally-cached map (see `docs/specs/security-cvm.md` §5.1 and `docs/specs/console.md` §4.3 / §10.4). The bearer is per-Dev-CVM, minted by the Console at launch (`docs/specs/console.md` §8.3 step 4), and delivered via env-file with its SHA-256 bound into RTMR3 — so a deploy-plane swap that substituted one Dev CVM's bearer for another's would produce a mismatched RTMR3 digest and fail the CLI's policy verification at first tunnel (§9 trust chain).
- `cap_drop: [ALL]`; `read_only: true`; `security_opt: [no-new-privileges:true]`; only `/tmp` and `/run` writable via tmpfs.
- Logs connection metadata only (peer, destination host:port, duration, byte counts) on stderr. The plaintext `Proxy-Authorization` bearer MUST NEVER be logged at any level (see §11 hardening invariants).

## 5. Network contract

- **Sandbox → internet** is FORBIDDEN. `user-sandbox` is on `cvm-internal` (internal:true) only. Outbound HTTP/HTTPS MUST flow through `dev-egress-forwarder:3128` on `cvm-internal`. The sandbox has no other route off the CVM. Nested containers spawned by the sandbox's baked-in `dockerd` live in further-nested user + network namespaces below the sandbox's; the only physical exit they reach is `cvm-internal`, so they inherit the same constraint.
- **Tunnel → internet** is FORBIDDEN. `dev-tunnel` is on `cvm-internal` and `proxy` only.
- **Forwarder → internet** is constrained. `dev-egress-forwarder` joins `egress-uplink` (non-internal) and uses it exclusively to reach the entity Security CVM FQDN. No host port is published.
- **shade ingress → public** is the only externally exposed listening surface, via host ports `80` and `443`.
- **No UDP egress from the CVM.** `dev-egress-forwarder` is a TCP-only HTTP CONNECT proxy (§4.5). No Dev CVM service besides the forwarder is a member of `egress-uplink`, and the forwarder does not accept UDP. UDP from any container in the CVM — sandbox or any nested container under its `dockerd` — therefore has no route off the CVM by topology. The agent can spin up a WireGuard / OpenVPN / QUIC client (it has every cap it needs inside the userns; `/dev/net/tun` is available), but the packets reach nothing outside the CVM. This is the topology-level cut for DPI evasion via opaque tunnels.
- **CVM identity for Security-CVM-side audit attribution** is established by attestation, NOT by Docker source IP. Dev CVM and Security CVM are separate Phala TDX deployments under separate Docker daemons, so source IPs do not cross the boundary; the Dev↔Security wire (owned by `docs/specs/security-cvm.md`) MUST bind each Dev CVM connection to the Dev CVM's TDX quote so the Security CVM can map traffic to a specific Dev CVM.

`NO_PROXY` MUST include `localhost,127.0.0.1,user-sandbox,dev-tunnel,dev-egress-forwarder` so internal traffic does not loop through the forwarder.

## 6. Identity and authorized keys

### 6.1 Keys are RTMR3-bound, not freely env-injected

The developer's authorized public keys are delivered through Phala's env-file at deploy time (`AUTHORIZED_SSH_KEYS_B64`, §2.3) and bound into RTMR3 by their SHA-256 digest in the JCS payload the Console replays at attestation (`docs/specs/console.md` §10.4a `authorised_ssh_keys_sha256`). This is the binding that makes `policy.json` prove ownership (§9): the keys are not in the measured compose YAML (the YAML is universal across Dev CVMs and carries only `${VAR}` placeholders), but a deploy-plane swap of the keys produces a mismatched RTMR3 digest and fails the CLI's policy check before any application bytes flow.

The deploy/update step (Console through the CVM provider adapter) MUST:

1. Take the canonical compose template published by the image release pipeline. The template carries `${AUTHORIZED_SSH_KEYS_B64}` (and the other runtime placeholders, §2.3) — no per-CVM substitution into the compose YAML itself.
2. Render the env-file with the developer's keys in `AUTHORIZED_SSH_KEYS_B64` (base64-encoded). The pre-encode bytes MUST be byte-deterministic: keys lexicographically sorted, each line newline-terminated, no trailing whitespace, no blank lines, no comments. The Console MUST produce the same digest when computing `authorised_ssh_keys_sha256` for the RTMR3 binding payload.
3. Submit the universal compose template plus the rendered env-file to the CVM provider. dstack measures the compose YAML (with placeholders) into `app_compose.docker_compose_file`, and dstack-guest-agent extends RTMR3 with the JCS-canonicalized digest of the env-file values at boot.

The sandbox entrypoint MUST refuse to boot if `AUTHORIZED_SSH_KEYS_B64` is missing, empty, or decodes to fewer than one valid key line (§10 step 4) — fail-closed against operator misconfiguration. The forwarder and other services likewise refuse to boot if their required env-file values are missing (§4.5, §10).

### 6.2 Single Linux user

There is one developer user, `dev`. All authorized keys append to `dev`'s file. Per-key Linux users are out of scope (§13).

### 6.3 Key rotation = relaunch

Live in-place rotation is out of scope. Mutating the installed key set requires `umbra cvm terminate` followed by `umbra cvm launch --ssh-key …`, producing a new `app_id`, FQDN, compose hash, and policy. This matches `cli.md` §3.4 and `v0_plan.md` §User Journey 2.

## 7. Egress contract

The sandbox MUST egress only via `dev-egress-forwarder` on `cvm-internal`. The forwarder is responsible for the cross-CVM transport to the entity Security CVM (§4.5). The contract the sandbox sees is fixed:

- **Proxy URL.** `http://dev-egress-forwarder:3128` (HTTP proxy with `CONNECT` for HTTPS).
- **Env propagation.** `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` (and lowercase variants) MUST be set in (a) the container env, (b) `/run/umbra/env.sh` for login shells, and (c) `authorized_keys` `environment="…"` options for non-PTY sessions.
- **Root and APT propagation.** `sudo` MUST preserve the proxy and CA-bundle env listed in §3.1 for `dev`, and APT MUST have explicit `Acquire::http::Proxy`, `Acquire::https::Proxy`, and `Acquire::https::CaInfo` settings pointing at the forwarder and `/run/umbra/ca-bundle.pem`.
- **CA bundle.** `/run/umbra/ca-bundle.pem` = system CA bundle ++ Security CVM mitmproxy root CA from `/run/umbra/security-cvm-ca.pem`. At boot, `umbra-ca-refresh --bootstrap` selects either the current-FQDN CA persisted with its forwarder-owned binding sidecar or the RTMR3-bound launch CA under the strict §4.5 rules. Tools MUST consult this bundle via `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`. The watcher atomically rebuilds this single bundle at runtime when the SC CA rotates, replacing the SC CA in place; already-running processes that cached it need a restart to pick up the new CA.
- **CVM attribution.** The Security CVM identifies the originating Dev CVM by the attested Dev↔Security channel established by `dev-egress-forwarder`, NOT by Docker source IP. The sandbox's address on `cvm-internal` is irrelevant outside the Dev CVM and MAY be assigned by Docker.
- **NPM/Claude/Python hardening env.** `NPM_CONFIG_IGNORE_SCRIPTS=true`, `NPM_CONFIG_AUDIT=false`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `PYTHONDONTWRITEBYTECODE=1`.
- **`dockerd`.** Local, baked-in (§3.1, §3.8). `docker` clients use `/var/run/docker.sock` by default; no `DOCKER_HOST` override is set. `docker pull`, `docker login`, and `docker build`'s base-image-fetch traffic egress through the sandbox's netns → `cvm-internal` → `dev-egress-forwarder` → Security CVM, so the SC's allowlist and audit cover container-registry traffic the same way they cover any other HTTPS request.

### 7.1 Sandbox credential placeholders

Some SDKs and CLIs refuse to send a request unless a local credential variable is present, even when the credential will be supplied later by the Security CVM. The Dev CVM solves that developer-experience problem with **non-secret placeholders**:

- The Console renders the merged `sandbox_env` policy field into the env-file value `SANDBOX_ENV_PLACEHOLDERS_B64` at CVM launch (§2.3, `docs/specs/console.md` §8.5). The entrypoint decodes and writes it to `/run/umbra/sandbox-env-placeholders` (§10). Each line is `NAME=value` with a valid POSIX env name and shell-safe value. Example: `ANTHROPIC_API_KEY=umbra-proxy-injected`. Placeholders are NOT currently in the RTMR3 binding payload (`docs/specs/console.md` §10.4a) — they are non-secret by construction, so a deploy-plane swap cannot exfiltrate credentials; the worst outcome is a confused developer whose SDK uses a different placeholder name than expected.
- The sandbox entrypoint appends these variables to `/run/umbra/env.sh`; login shells and non-PTY SSH commands inherit them through the same env propagation path as proxy and CA-bundle settings (§4.1, §10 step 6).
- Placeholder values MUST NOT be real credentials and MUST NOT be accepted from Phala `allowed_envs`. The entrypoint MUST refuse to boot if a placeholder value matches a configured secret-denylist pattern (for example an Anthropic, OpenAI, GitHub, or AWS key regex) instead of the approved placeholder vocabulary.
- A placeholder only helps a client library send the request. Authorization still depends entirely on the SC's matching `secret_injections` policy and the destination allow-list. If the SC has no matching injection, it forwards or blocks the request according to policy with the placeholder overwritten only when a matching injection exists (`docs/specs/security-cvm.md` §5.4).
- v0 placeholders are launch-time material. Updating `sandbox_env` on an attached profile changes future Dev CVM launches; it does not mutate the environment of already-running sandboxes. Runtime policy enforcement and secret injection still converge through the SC pull loop.

### 7.2 Nested-container egress (in-sandbox `dockerd`)

Containers launched from `user-sandbox` via the baked-in `dockerd` egress under the same constraints as the sandbox itself:

- **Network ceiling.** `user-sandbox` is on `cvm-internal` (internal:true) only. The in-sandbox `dockerd`'s virtual bridges (`bridge`, user-defined networks, `--net=host` resolved inside the sandbox's own netns) all live inside `user-sandbox`'s netns; the only physical exit is `cvm-internal`. Nested containers therefore reach `dev-egress-forwarder` and **only** `dev-egress-forwarder` from outside the Dev CVM.
- **Proxy inheritance.** `dockerd`'s `daemon.json` defaults (§3.8) inject `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` into every nested container that doesn't override them, pointing at `dev-egress-forwarder`. Nested containers that ignore the env still cannot reach the internet (per the network ceiling) — the env injection is an ergonomic default so well-behaved tooling does not need explicit configuration.
- **CA bundle.** Trust of the SC mitmproxy CA inside nested containers is the developer's responsibility (e.g. baking `/run/umbra/security-cvm-ca.pem` into their own image, or mounting it). The Dev CVM does not transparently inject the CA into arbitrary third-party images. Nested HTTPS clients without the SC CA will see certificate-verification failures against the SC's intercepted endpoints — which is the correct failure mode, since the SC is the trust anchor.
- **Userns nesting.** Each nested container runs in a further-nested user namespace below `user-sandbox`'s. The aggregate resource consumption of the sandbox plus every nested container is bounded only by the CVM's own size (Phala TDX VM allocation); nothing in this spec caps it further — self-DoS is the developer's problem (§3.2, §4.1).
- **Audit attribution.** The Security CVM attributes traffic by the `Proxy-Authorization` bearer the forwarder injects (§4.5), so every nested-container request still attributes to the originating Dev CVM. There is no per-nested-container identity in v0; the SC sees a single `cvm_id` for everything that exits this CVM. Per-nested-container attribution is out of scope (§13).

The Security CVM spec defines the Dev↔Security wire protocol, proxy allowlist enforcement, secret scanning, proxy-time secret injection, and audit ingest. This document fixes only what the Dev CVM presents on its side of that boundary.

## 8. Attestation contract

### 8.1 `policy.json` shape

The CLI's aTLS policy file (`cli.md` §6.1) is a JSON document. For Dev CVMs deployed via shade on dstack, it MUST be of `type: "dstack_tdx"` with these top-level fields:

```json
{
  "type": "dstack_tdx",
  "allowed_tcb_status": ["UpToDate"],
  "expected_bootchain": {
    "mrtd":  "<hex>",
    "rtmr0": "<hex>",
    "rtmr1": "<hex>",
    "rtmr2": "<hex>"
  },
  "os_image_hash": "<hex>",
  "app_compose": {
    "docker_compose_file": "<compose template, byte-exact with ${VAR} placeholders>",
    "allowed_envs":        ["<env names that may legitimately vary, e.g. registry credentials>"],
    "manifest_version":    2,
    "name":                "<app name>",
    "runner":              "docker-compose"
  },
  "rtmr3_binding": {
    "cvm_id":                            "<UUID>",
    "console_url":                       "https://console.example.com",
    "security_cvm_fqdn":                 "<host>",
    "security_cvm_proxy_port":           8080,
    "security_cvm_proxy_token_sha256":   "<hex>",
    "dev_cvm_control_token_sha256":      "<hex>",
    "security_cvm_ca_cert_sha256":       "<hex>",
    "authorised_ssh_keys_sha256":        "<hex>"
  }
}
```

`docker_compose_file` is the compose template measured by dstack — universal across Dev CVMs, carrying only `${VAR}` placeholders for the runtime values the Console injects via env-file (§2.3, §6.1, §7.1, `docs/specs/console.md` §10.4a). The per-CVM variation is encoded entirely in `rtmr3_binding`: at boot, the dstack-guest-agent extends `RTMR3` with `SHA-384(JCS(rtmr3_binding))` (RFC 8785), so the CLI MUST replay the same JCS canonicalization to compute the expected digest and compare against the quote. A mismatch on bootchain (§8.3), compose template hash, or RTMR3 binding aborts the tunnel.

`allowed_envs` MUST NOT include any name that conveys a real provider credential. SSH-key and proxy-bearer env names are expected — they are the Console-injected runtime values whose integrity is guaranteed by `rtmr3_binding`, not by exclusion from `allowed_envs`. Other dstack-defined fields (`features`, `gateway_enabled`, `kms_enabled`, `tproxy_enabled`, `public_logs`, `public_sysinfo`, `public_tcbinfo`, `pre_launch_script`) MUST match what dstack records for the deployment; their exact values are determined by the deploy invocation, not by this spec.

### 8.2 Policy is per-CVM

Although the measured compose template is universal across Dev CVMs, the `rtmr3_binding` payload — `cvm_id`, the Console refresh origin, the SHA-256 digests of the developer's keys, the per-CVM proxy/control bearers, and the SC CA — is **specific to one CVM's launch parameters**. The CLI MUST therefore resolve the policy file by CVM identity at tunnel time:

1. **Per-CVM file.** At `umbra cvm launch` success, the CLI writes `${config_dir}/cvms/<cvm_id>.atls-policy.json` (mode `0600`) directly from the Console-returned `<PolicyBundle>` (`docs/specs/console.md` §2.3): `app_compose_json` is parsed as the authoritative full Shade/dstack app-compose object when present, `compose_template` is copied into `app_compose.docker_compose_file`, and the bundle supplies the expected bootchain, `os_image_hash`, and `rtmr3_binding`. The CLI does not synthesise these measured fields. At tunnel time, `umbra tunnel <CVM_ID>` resolves and uses this file. `atlas-rs` consumes the policy and performs the verification described in §8.3 / §9.
2. **Global default.** If no per-CVM file is found (e.g. tunneling by raw FQDN), the CLI falls back to the path resolved from the `atls_policy` config key (`cli.md` §4.1).

This extension is implemented in `cli.md` §6.1 ("Per-CVM policy resolution") and §3.4 (`cvm launch` writes the per-CVM file from a launch-time policy bundle).

### 8.3 EKM channel binding

For a tunnel to be considered attested, the CLI MUST:

1. Complete the TLS handshake against `${app_id}.${gateway_domain}`. The publicly trusted Let's Encrypt cert binds the FQDN.
2. Extract the EKM (RFC 5705, exporter label `EXPORTER-Channel-Binding`, 32 bytes).
3. Generate a fresh nonce (32 random bytes).
4. `POST /tdx_quote` with `nonce_hex`. `nginx-cert-manager` injects the `X-TLS-EKM-Channel-Binding` header transparently; the CLI does not set it itself.
5. Verify the returned TDX quote against `policy.json` (§8.1): bootchain (`mrtd`, `rtmr0..2`), `os_image_hash`, compose-template hash (`app_compose.docker_compose_file`), AND `RTMR3 == SHA-384(JCS(policy.rtmr3_binding))` (RFC 8785). Then verify `report_data == SHA512(nonce_bytes || ekm_bytes)`. Mismatch on any of these MUST abort the tunnel before any application bytes flow.

`atlas-rs` performs step 5 on the CLI side.

### 8.4 Quote freshness

EKM differs per TLS session, so the bound quote also differs. The CLI MUST NOT cache quotes across tunnels. The CLI MAY cache the quote for the lifetime of a single TLS session (one quote per tunnel).

## 9. Trust chain end-to-end

This section is the canonical answer to **"how does the developer know it's their CVM?"**

The chain has five checks, performed locally by the CLI on every tunnel, with `atlas-rs` doing the cryptographic work and `policy.json` providing the expected values:

1. **Hardware authentic.** The TDX quote signature chains to Intel.
2. **Right guest boot chain and OS image.** `mrtd`, `rtmr0..2`, and `os_image_hash` from the quote match the authoritative Shade/dstack policy in `policy.json`. MRTD is the shared dstack-guest baseline used by Dev and Security CVMs; it is not the Dev application version. `atlas-rs` consumes the complete policy.
3. **Right code.** The `app_compose.docker_compose_file` hash from the quote matches the compose template in `policy.json`. The template is universal across Dev CVMs and carries `${VAR}` placeholders, so this check proves the canonical Dev CVM compose YAML is what dstack measured — Sysbox runtime, internal-only `cvm-internal` bridge, forwarder service, etc. — without binding any per-CVM material.
4. **My keys, my bearers, my Console refresh origin, my SC trust anchor.** `RTMR3 == SHA-384(JCS(policy.rtmr3_binding))` (§8.1, §8.3). The Dev CVM extends RTMR3 at boot with the JCS-canonicalized digest of `cvm_id`, `console_url`, `dev_cvm_control_token_sha256`, `security_cvm_fqdn`, `security_cvm_proxy_port`, `security_cvm_proxy_token_sha256`, `security_cvm_ca_cert_sha256`, and `authorised_ssh_keys_sha256` (`docs/specs/console.md` §10.4a). A deploy-plane swap of any of these — substituting a different developer's keys, another CVM's proxy/control bearer, a hostile policy-refresh origin, or a hostile SC CA — produces a mismatched RTMR3 and aborts the tunnel before any application bytes flow.
5. **Channel-bound to this TLS session.** `report_data == SHA512(nonce || EKM)` — the TLS endpoint the CLI is talking to is inside the same TEE that produced the quote.

Console is **not** in the chain. The Console resolves `cvm_id → fqdn` for convenience (`cli.md` §3.3), but a misroute fails verification at step 4 (the wrong CVM does not have my key digest in its RTMR3). DNS spoofing fails at the TLS handshake (Let's Encrypt cert SAN won't match) or at step 5 (a relay can't produce a quote bound to this session's EKM).

The threat model explicitly excludes a compromise of:

- the dstack KMS root that signs `tls-certs-keys`;
- Intel's TDX quoting authority;
- the image release pipeline's golden-measurement publication path.

A compromise of Phala's deployment plane CAN flip env-file values, but the values that matter for security (developer's keys, SC CA, per-CVM proxy/control bearers, and Console refresh origin) are bound into RTMR3 (§9 step 4); a swap mismatches the CLI's expected `rtmr3_binding` and fails verification before any application bytes flow.

## 10. Boot sequence

The `user-sandbox` entrypoint MUST execute these steps in order. Failure at any step MUST exit non-zero before sshd starts.

1. `mkdir -p /run/ssh /run/ssh/authorized_keys /run/ssh/user-ssh /run/sshd /run/umbra /run/umbra/sessions`. Modes `0755` on root-owned runtime directories; `/run/ssh/user-ssh` and `/run/umbra/sessions` owned `dev:dev` and mode `0700`.
2. **Materialise measured runtime values from env-file.** Require the non-secret `SECURITY_CVM_FQDN`. Decode `SECURITY_CVM_CA_CERT_B64` to `/run/umbra/security-cvm-ca.launch.pem` and `AUTHORIZED_SSH_KEYS_B64` to its documented path/mode. Decode `SANDBOX_ENV_PLACEHOLDERS_B64` to `/run/umbra/sandbox-env-placeholders` when present; an empty placeholder file is valid. `SECURITY_CVM_PROXY_TOKEN` and `DEV_CVM_CONTROL_TOKEN` are forwarder-only values and MUST NOT be present in `user-sandbox`; no full SC aTLS policy is carried in any launch env. Refuse boot if any required sandbox value is missing or empty. The base64 env vars SHOULD be unset after materialisation; `SECURITY_CVM_FQDN` remains for the CA watcher.
3. **Select and install the proxy CA fail-closed.** Run `umbra-ca-refresh --bootstrap /run/umbra/security-cvm-ca.launch.pem`. A valid persisted `/var/lib/umbra-ca/security-cvm-ca.pem` plus `/var/lib/umbra-ca/security-cvm-ca.json` sidecar wins only when the sidecar's FQDN and immutable launch-CA digest match the current launch. An empty volume or a valid pair for a previous FQDN/launch baseline uses the current RTMR3-bound launch CA. Partial, unreadable, malformed, or current-CA-digest-mismatched persisted state MUST NOT fall back to launch material; startup remains unhealthy while waiting for the forwarder's authenticated Console poll, then exits non-zero after `UMBRA_CA_BOOTSTRAP_TIMEOUT_SECONDS` (default 120) if repair never arrives. The bootstrap writes the selected CA to `/run/umbra/security-cvm-ca.pem`, atomically builds `/run/umbra/ca-bundle.pem`, and retains the read-only launch CA so the background watcher can continue enforcing the baseline binding.
4. **Provision authorized_keys.** Read `/run/umbra/authorized_keys.bootstrap` (decoded from `AUTHORIZED_SSH_KEYS_B64` in step 2; §6.1). Validate each non-empty line as a bare SSH public key. Supported algorithms: `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp{256,384,521}`, `sk-ssh-ed25519@openssh.com`, `sk-ecdsa-sha2-nistp256@openssh.com`. At least one valid line is required; any unsupported line MUST fail boot. Prepend the `environment="…"` options for proxy / CA bundle / `BASH_ENV` / `PATH` / `PIP_USER` / `GH_CONFIG_DIR`. `install -m 0644` to `/run/ssh/authorized_keys/dev`.
5. **Keep the CA bundle under refresher ownership.** Do not concatenate the immutable launch CA over the bootstrap output. After the remaining setup (and after starting `dockerd`) but before sshd, start `umbra-ca-refresh` in the background. It accepts only a structurally valid CA whose read-only sidecar matches both the current FQDN and CA digest, and atomically replaces `/run/umbra/security-cvm-ca.pem` plus `/run/umbra/ca-bundle.pem` when that authenticated distribution rotates (§4.5).
6. **Write `/run/umbra/env.sh`** with the env vars listed in §7 plus `PATH=/home/dev/.local/bin:$PATH`, `PIP_USER=1`, `GH_CONFIG_DIR=/home/dev/.local/share/gh`, and the validated non-secret placeholder env from `/run/umbra/sandbox-env-placeholders` (§7.1). The entrypoint parses the placeholder file by splitting the decoded payload on `\n`, treating each non-empty line as `NAME=VALUE` (first `=` is the separator), tolerating a missing trailing newline. It MUST reject (a) names not matching `^[A-Za-z_][A-Za-z0-9_]{0,127}$`, (b) any name in the reserved set defined by `docs/specs/console.md` §2.3 `<Profile>.policy.sandbox_env` (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `PATH`, `HOME`, anything starting with `UMBRA_`, `SECURITY_CVM_`, `AUTHORIZED_SSH_`, or `SANDBOX_ENV_`), (c) values containing newlines or NUL bytes, (d) duplicate names with different values, and (e) any value matching `SANDBOX_ENV_VALUE_DENYLIST` (`docs/specs/console.md` §12.1). The Console enforces (a)–(e) at `PATCH /profiles/{id}` and `POST /cvms` (§8.5 sandbox_env merge); the entrypoint check is defense in depth against deploy-plane bypass.
7. **Ensure developer-owned runtime directories and reset volume-stale symlinks** without migrating mounted volume contents. The root entrypoint creates the known developer/tool directories (`/home/dev/workspaces`, `/home/dev/.local`, `/home/dev/.cache`, `/home/dev/.npm`, `/home/dev/.claude`, `/home/dev/.codex`, editor state directories) with `dev:dev` ownership only when they are missing, initializes `/home/dev/.claude/.claude.json` to `{}` when the file is absent or empty, then sets `/home/dev/.ssh → /run/ssh/user-ssh` and `/home/dev/.claude.json → /home/dev/.claude/.claude.json` with symlinks owned `dev:dev`. If `/home/dev/.ssh` already exists as a non-symlink, boot MUST fail rather than rewriting old volume contents. The entrypoint MUST NOT recursively chown `/home/dev`, `/home/dev/workspaces`, or other mounted volumes as a UID-0-era migration, and MUST NOT try to repair existing old-volume ownership beyond the runtime tmpfs paths from step 1.
8. **Generate ephemeral host keys** under `/run/sshd` (ed25519, rsa).
9. **Start `dockerd` in the background.** Sysbox has already set up the userns + idmapped mounts at this point; `dockerd` reads `/etc/docker/daemon.json` (proxy defaults; §3.8) and serves `/var/run/docker.sock`. Failure to start `dockerd` MUST NOT abort entrypoint; the agent or developer can restart it later. `dockerd` writes its data root to `/var/lib/docker` (volume `dev-docker-data`; §2.3).
10. `exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config -h /run/sshd/ssh_host_ed25519_key -h /run/sshd/ssh_host_rsa_key`.

## 11. Hardening invariants

Violations of any line here are spec bugs:

- **Sysbox runtime on `user-sandbox`.** `runtime: sysbox-runc` MUST be set on the `user-sandbox` service (§3.2, §4.1). Any deploy-plane rewrite that drops or swaps the runtime changes the measured compose hash and fails policy verification at first tunnel (§9). The dstack guest OS ships Sysbox baked in (meta-dstack `dstack-sysbox_0.6.7.bb`); a CVM operator cannot disable it from outside the CVM.
- **No Sysbox-forbidden options on `user-sandbox`.** `privileged: false`, no `userns_mode` override, no `pid: host`, `ipc: host`, or `network_mode: host`, no `security_opt` override (Sysbox supplies AppArmor/seccomp). These are spec violations even though Sysbox itself would refuse them at runtime — they belong out of the measured compose so policy verification catches them at attestation time, not at exec time.
- **No cgroup limits on `user-sandbox` in v0.** Self-DoS is out of scope (§3.2, §4.1). If the developer fork-bombs or OOMs their own CVM, the only consequence is that they need to relaunch it.
- **Read-only rootfs** on `dev-tunnel` and `dev-egress-forwarder`. `user-sandbox` is **writable** by design (§3.3) so the dev can use passwordless sudo to install packages, mutate the running system, and run a full `dockerd`. The userns boundary, not rootfs immutability or the in-container Unix user split, is what bounds privilege in `user-sandbox`.
- **Capabilities on non-sandbox services.** `cap_drop: [ALL]` on `dev-tunnel` and `dev-egress-forwarder`; no `cap_add`. Forbidden caps anywhere on these services: `NET_ADMIN`, `SYS_ADMIN`, `SYS_MODULE`, `SYS_PTRACE`, `SYS_RAWIO`, `SYS_BOOT`, `SYS_TIME`, `BPF`, `MAC_*`, `AUDIT_CONTROL`. `user-sandbox` is exempt — caps inside it are userns-scoped by Sysbox.
- **`security_opt: [no-new-privileges:true]` on non-sandbox services.** `dev-tunnel` and `dev-egress-forwarder` MUST set this. `user-sandbox` MUST NOT set this (Sysbox requires the ability to set caps when entering child namespaces).
- **No host docker socket exposure.** The dstack VM's `/var/run/docker.sock` MUST NOT be bind-mounted into any Dev-CVM-owned service. The dockerd reachable from `user-sandbox` is the one baked into the same image, serving on the in-userns `/var/run/docker.sock` — that socket only exists inside the sandbox's mount namespace.
- **No `/var/run/dstack.sock` in `user-sandbox`.** dstack's host socket MUST only be mounted into `nginx-cert-manager` and `attestation-service` (shade services running outside Sysbox). Exposing it to the sandbox would let the agent — even userns-scoped — request quotes or KMS material in its own name.
- **No forwarder-only runtime material in `user-sandbox`.** `SECURITY_CVM_PROXY_TOKEN`, `DEV_CVM_CONTROL_TOKEN`, `/run/umbra/proxy-token`, and the authenticated-fetched `/run/umbra/security-cvm.atls-policy.json` MUST exist only in `dev-egress-forwarder`. The sandbox receives the SC CA so HTTPS clients can trust SC-intercepted traffic, but it does not need either bearer or the SC aTLS policy to run shells, agents, Docker, or editor sessions.
- **No UDP egress from the CVM.** The only egress route is `dev-egress-forwarder`, a TCP-only HTTP CONNECT proxy (§4.5). No other Dev CVM service is a member of `egress-uplink`. UDP from the sandbox or any container nested under its `dockerd` therefore has no path off the CVM by topology (§5). DPI evasion via WireGuard/OpenVPN/QUIC tunnels is cut at this layer regardless of `/dev/net/tun` being available inside the userns.
- **`user-sandbox` is on `cvm-internal` (internal:true) only.** Adding any other network is a spec violation.
- **`dev-tunnel` is on `cvm-internal` and `proxy` only.** Adding a public network or host port is a spec violation.
- **`dev-egress-forwarder` is on `cvm-internal` and `egress-uplink` only.** It MUST NOT publish any host port and MUST NOT connect to any destination other than the Security CVM FQDN baked into the rendered compose. Adding any other network is a spec violation.
- **Runtime values arrive via env-file and MUST be RTMR3-bound.** The Console MUST inject every value the Dev CVM consumes (`AUTHORIZED_SSH_KEYS_B64`, `SECURITY_CVM_CA_CERT_B64`, `SECURITY_CVM_PROXY_TOKEN`, `DEV_CVM_CONTROL_TOKEN`, `CONSOLE_URL`, etc.; §2.3) through Phala's env-file mechanism, and the dstack-guest-agent MUST extend `RTMR3` with the JCS-canonicalized digest of these values at boot (`docs/specs/console.md` §10.4a). The CLI's `policy.json` (§8.1) carries the expected `rtmr3_binding`, so a deploy-plane swap of any bound value — for example, substituting one Dev CVM's proxy bearer for another's to misattribute traffic at the SC (T-5-class), or redirecting policy refresh to a hostile Console — produces a mismatched RTMR3 digest at first tunnel and aborts verification (§9 step 4). The legacy guarantee (compose-hash check alone covering keys and bearer) has been replaced by the compose-hash + RTMR3 pair: both checks are mandatory.
- **`AUTHORIZED_SSH_KEYS_B64` MUST be in the RTMR3 binding payload (`authorised_ssh_keys_sha256`).** A Console implementation that injects keys via env-file without including the digest in the JCS payload is a spec violation.
- **`SECURITY_CVM_PROXY_TOKEN` MUST be in the RTMR3 binding payload (`security_cvm_proxy_token_sha256`).** Same rationale as above (T-5 attribution swap).
- **`DEV_CVM_CONTROL_TOKEN` MUST be in the RTMR3 binding payload (`dev_cvm_control_token_sha256`).** Same rationale as above for Console Dev-control reads; the bearer is distinct from `PROXY_AUTH` so Console-facing refresh cannot impersonate the CVM to the SC proxy.
- **`SECURITY_CVM_CA_CERT_B64` MUST be in the RTMR3 binding payload (`security_cvm_ca_cert_sha256`).** Without this, the deploy plane could swap the SC CA to one issued by a hostile certificate authority and the forwarder would silently trust a wrong SC.
- **No real provider credentials anywhere on the env-file.** The env-file MUST carry only the documented runtime values (§2.3). Real Anthropic/OpenAI/GitHub/AWS-style credentials in `SANDBOX_ENV_PLACEHOLDERS_B64` or in any other env are spec violations; placeholders MUST be from the approved non-secret vocabulary.
- **No real provider secrets in sandbox env.** `sandbox_env_placeholders` (§7.1) may contain only non-secret placeholder values. Anthropic/OpenAI/GitHub/AWS-style real credentials in this file, the env-file, or `/run/umbra/env.sh` are spec violations. **Accepted residual risk:** `SANDBOX_ENV_PLACEHOLDERS_B64` is not currently in the RTMR3 binding payload (§7.1, `docs/specs/console.md` §10.4a). A deploy-plane swap that substitutes a plausibly-shaped non-secret value (e.g. `AWS_PROFILE=internal-prod`, `OPENAI_BASE_URL=http://attacker/`) would not trip the entrypoint's real-credential denylist and would propagate to in-sandbox SDKs. Compensating controls: the SC's per-Dev-CVM policy still gates the actual destination; injection is the authoritative credential path. Adding `sandbox_env_placeholders_sha256` to the RTMR3 binding is a candidate hardening — tracked as an open item.
- **Ephemeral host keys.** Generated at every container start under `/run/sshd`. Trust comes from aTLS attestation (§9).
- **Pre-installed agents do not phone home at install time.** `npm install --ignore-scripts`; verified-binary downloads with checksums for `claude`, `gh`, Node.

## 12. Update model

A Dev CVM is a single, long-lived deployment. Updates flow through the Console's provider-neutral `cvm.update` saga (`umbra cvm update <CVM_ID>`):

- **Image upgrade** (e.g., new digest-pinned `user-sandbox`): the Console re-renders compose/env material from current config, updates the existing provider deployment in place, and preserves named volumes. Shade regenerates the full runtime policy for the new digest and compose; the Console re-attests the CVM and returns a refreshed `<PolicyBundle>` that the CLI MUST write over the per-CVM `policy.json` in lockstep. The shared dstack-guest MRTD stays unchanged unless the underlying guest boot baseline changes.
- **Security CVM rebind** (e.g., Dev CVM bearers rotated, or the Console URL / SC FQDN binding changed): for a current provider-managed Umbra deployment, the same `cvm.update` flow refreshes `SECURITY_CVM_CA_CERT_B64`, the per-CVM proxy/control bearers, RTMR3 binding, and local policy bundle. Before its first post-restart upstream SC connection or successful CONNECT response, the forwarder fetches the current complete SC policy from its newly bound Console origin; the policy is not a provider launch-env value. The `cvm-ca` named volume may survive that update, so its sidecar prevents an old-FQDN or old-launch-baseline CA from being silently reused: a valid foreign pair is replaced from the new attested launch material, while partial/malformed state stays fail-closed for authenticated repair. CA rotation alone uses the runtime path below and is not a new rebind trigger. A persisted legacy `SECURITY_CVM_REBIND_REQUIRED` marker is rejected by this generic flow because the renamed build cannot prove provider ownership or runtime capability; decommission it through the pre-Umbra control plane and launch a replacement under Umbra.
- **Security CVM aTLS-only refresh** (SC image/aTLS policy changed but the SC mitmproxy CA did not): `dev-egress-forwarder` first fails closed against its measured local SC aTLS policy, then may fetch a candidate replacement from the RTMR3-bound Console origin and retry local aTLS verification. The candidate is accepted only when it keeps the launch-bound SC FQDN and CA digest.
- **Security CVM CA rotation** (the SC mitmproxy CA changed, e.g. on an SC image update or restart): on a refresh-capable Umbra runtime, the aTLS-policy refresh candidate is rejected on CA-digest mismatch, but the SC CA itself is followed via the CA refresh path (§4.5) — the forwarder re-fetches the rotated CA from the RTMR3-bound Console and the `umbra-ca-refresh` watcher re-installs it into the trust bundle. So SC CA rotation does not require `umbra cvm update <CVM_ID>` for a compatible sandbox trust binding (already-running cached processes aside). A full current-runtime rebind via `cvm.update` remains required when the launch-bound SC FQDN, the per-CVM proxy/control bearers, or the RTMR3 binding changes. Persisted legacy markers remain fail-closed replacement signals for the pre-Umbra control plane.
- **In-CVM agent upgrade** that doesn't change the image happens via the in-CVM auto-update hook (§3.6). These do NOT change `app_compose.docker_compose_file` and therefore do NOT invalidate `policy.json`.
- **Authorized-key changes** require a new CVM (terminate + launch). See §6.3.

`policy.json` distribution and lifecycle on the developer's machine are CLI and deployment concerns; this spec only fixes what the policy must contain (§8.1).

## 13. Out of scope

- Live `authorized_keys` rotation. Rotation = `cvm terminate` + `cvm launch`.
- Per-key Linux users; everything runs as `dev` (UID/GID 1001 with passwordless sudo).
- Per-nested-container audit attribution. Every request that egresses from this CVM — whether from `user-sandbox` directly or from a container launched via the in-sandbox `dockerd` — carries the same Dev-CVM `Proxy-Authorization` bearer and therefore attributes to a single `cvm_id` at the Security CVM (§7.2). Distinguishing "which nested container made this request" is out of scope; the Dev CVM is the audit-attribution unit in v0.
- Mutual aTLS (maTLS) between `user-sandbox` and the Security CVM. v0 uses one-way TLS from the sandbox to `dev-egress-forwarder`; the cross-CVM channel is attested as defined by the Security CVM spec.
- gVisor / Firecracker / microVM nesting. TDX compatibility is unresolved as of v0.
- SSH certificate authentication. v0 uses pubkey-pinned `authorized_keys` only.
- Console-in-the-Dev-CVM tunnel trust-chain. `policy.json` (shared guest bootchain + authoritative app-compose and OS-image policy + per-CVM RTMR3 binding, verified by `atlas-rs`) is the trust root for the CLI-to-Dev-CVM tunnel. Console verifies the *Security CVM*'s TEE attestation when issuing SC bearers (different boundary — see plan §Attestation), and `dev-egress-forwarder` can use the RTMR3-bound Console origin only as a recovery distribution point for SC aTLS policy candidates (§4.5), not as a replacement for local aTLS verification.

## 14. Cross-doc follow-ups

This spec implied adjustments to peer documents:

- **`docs/specs/cli.md` §6.1 + §3.4 (`cvm launch`)** — implemented. CLI §6.1 names `atlas-rs` as the verification library, opens `wss://<fqdn>/umbra/tunnel`, performs EKM extraction + `POST /tdx_quote` + per-CVM policy verification, and resolves the policy at `${config_dir}/cvms/<cvm_id>.atls-policy.json` (falling back to the configured `atls_policy`). CLI §3.4 documents the launch-time policy bundle the Console returns: the compose template (universal, with `${VAR}` placeholders), golden bootchain, and per-CVM `rtmr3_binding` payload (Console refresh origin plus SHA-256 digests of keys, SC CA, and the per-CVM proxy/control bearers). A bundle whose `rtmr3_binding` does not match what the deployed CVM's RTMR3 attests to causes verification to fail at first tunnel — detection, not bypass.
- **`docs/v0_plan.md` §Attestation** — implemented. Plan §Attestation names `atlas-rs` as the verification library and notes that the complete per-CVM policy file is written directly from the Console's launch response (`<PolicyBundle>`).
- **`docs/v0_plan.md` §Sandboxed Compute** — implemented. Plan §Sandboxed Compute describes the single Sysbox-runtime container, native DinD, user-namespace-as-boundary, topology-bound egress (`internal: true`), TCP-only egress forwarder, and explicit self-DoS out-of-scope framing.

## Appendix A — reference compose (illustrative)

The structure below is **normative** in everything that affects security or attestation: `cap_drop`/`cap_add`, `read_only`, `internal: true`, network names, volume names, env names referenced by `${VAR}` placeholders (resolved by Phala's env-file at deploy; see §2.3, §10, `docs/specs/console.md` §10.4a), and the absence of any plaintext bearer or key material inside the compose YAML. Image refs and version pins are illustrative and move with CI.

```yaml
services:
  user-sandbox:
    image: registry.example.com/umbra/dev-cvm/user-sandbox:<sha>
    # Sysbox runtime: kernel userns boundary aligns with this container.
    # The runtime name is part of the rendered compose and therefore part of
    # the measured app_compose.docker_compose_file (§8.1, §11).
    runtime: sysbox-runc
    read_only: false  # §3.3 — dev can use sudo and writes the rootfs at runtime
    tmpfs: [/run]
    # No cap_drop / cap_add: Sysbox grants the default OCI cap set scoped to
    # the userns. No security_opt: Sysbox supplies its own apparmor/seccomp.
    # No privileged / userns_mode / pid:host / network_mode:host (§3.4, §11).
    # No cgroup limits in v0 — self-DoS is the developer's own problem (§3.2, §4.1).
    environment:
      HTTP_PROXY:  http://dev-egress-forwarder:3128
      HTTPS_PROXY: http://dev-egress-forwarder:3128
      http_proxy:  http://dev-egress-forwarder:3128
      https_proxy: http://dev-egress-forwarder:3128
      NO_PROXY: "localhost,127.0.0.1,user-sandbox,dev-tunnel,dev-egress-forwarder"
      no_proxy: "localhost,127.0.0.1,user-sandbox,dev-tunnel,dev-egress-forwarder"
      NPM_CONFIG_IGNORE_SCRIPTS: "true"
      NPM_CONFIG_AUDIT: "false"
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1"
      PYTHONDONTWRITEBYTECODE: "1"
      # Runtime values injected via Phala env-file at deploy time
      # (`docs/specs/console.md` §10.4a). The entrypoint (§10) materialises
      # them into /run/umbra/* and unsets the env vars before sshd starts.
      SECURITY_CVM_CA_CERT_B64:        "${SECURITY_CVM_CA_CERT_B64}"
      AUTHORIZED_SSH_KEYS_B64:         "${AUTHORIZED_SSH_KEYS_B64}"
      SANDBOX_ENV_PLACEHOLDERS_B64:    "${SANDBOX_ENV_PLACEHOLDERS_B64}"
    volumes:
      - dev-home:/home/dev
      - dev-workspaces:/home/dev/workspaces
      - dev-local:/home/dev/.local
      - dev-claude:/home/dev/.claude
      - dev-codex:/home/dev/.codex
      - dev-cursor-server:/home/dev/.cursor-server
      - dev-vscode-server:/home/dev/.vscode-server
      # Persist the in-sandbox dockerd's data root across container restarts
      # so re-pulls aren't required on every restart (§2.3, §3.8).
      - dev-docker-data:/var/lib/docker
    networks: [cvm-internal]

  dev-egress-forwarder:
    image: registry.example.com/umbra/dev-cvm/egress-forwarder:<sha>
    entrypoint: ["umbra-dev-egress-forwarder"]
    healthcheck:
      test: ["NONE"]
    read_only: true
    tmpfs: [/tmp, /run]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    environment:
      SECURITY_CVM_FQDN:               "${SECURITY_CVM_FQDN}"
      # Forwarder-only values. The forwarder's entrypoint materialises the
      # policy + CA + bearer into /run/umbra/* and clears the env vars before
      # the proxy starts. These are intentionally not injected into user-sandbox.
      SECURITY_CVM_PROXY_PORT:         "${SECURITY_CVM_PROXY_PORT}"
      SECURITY_CVM_CA_CERT_B64:        "${SECURITY_CVM_CA_CERT_B64}"
      SECURITY_CVM_PROXY_TOKEN:        "${SECURITY_CVM_PROXY_TOKEN}"
    networks: [cvm-internal, egress-uplink]

  dev-tunnel:
    image: registry.example.com/umbra/dev-cvm/tunnel:<sha>
    entrypoint: ["umbra-dev-tunnel"]
    healthcheck:
      test: ["NONE"]
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: [no-new-privileges:true]
    environment:
      DEV_CVM_SSH_HOST: user-sandbox
      DEV_CVM_SSH_PORT: "22"
    # No depends_on: gating the tunnel on user-sandbox health starves shade's
    # nginx through certbot's retry budget and the CVM never gets a cert (§3.3).
    networks: [cvm-internal, proxy]

  nginx-cert-manager:
    image: registry.example.com/umbra/shade-cert-manager:<sha>
    ports: ["80:80", "443:443"]
    environment:
      DOMAIN: ${CVM_DOMAIN}
    volumes:
      - tls-certs-keys:/etc/nginx/ssl/
      - /var/run/dstack.sock:/var/run/dstack.sock
    networks: [proxy, attestation]
    restart: unless-stopped

  attestation-service:
    image: registry.example.com/umbra/shade-attestation-service:<sha>
    environment:
      HOST: 0.0.0.0
      PORT: "8080"
    volumes:
      - /var/run/dstack.sock:/var/run/dstack.sock
    expose: ["8080"]
    networks: [attestation]
    restart: unless-stopped

# Runtime env-file values (injected by the Console via Phala at deploy time;
# `docs/specs/console.md` §8.3 step 3, §10.4a). Each value's SHA-256 digest
# appears in the RTMR3 binding payload the CLI's policy.json carries
# (§8.1 `rtmr3_binding`), so a deploy-plane swap is detected at first tunnel.
#
# AUTHORIZED_SSH_KEYS_B64
#   base64 of the sorted, newline-terminated authorized_keys content (§6.1).
#
# SECURITY_CVM_CA_CERT_B64
#   base64 of the entity Security CVM's mitmproxy root CA PEM.
#
#   base64 of the aTLS policy `dev-egress-forwarder` enforces against the SC
#   endpoint (`{ "type": "dstack_tdx", ... }`).
#
# SECURITY_CVM_PROXY_TOKEN
#   plaintext per-Dev-CVM `Proxy-Authorization` bearer the Console minted
#   from `service_principal_tokens` (principal_type=dev_cvm, purpose=PROXY_AUTH).
# - DEV_CVM_CONTROL_TOKEN, plaintext Console Dev-control bearer
#   from `service_principal_tokens` (principal_type=dev_cvm, purpose=DEV_CONTROL).
#
# SANDBOX_ENV_PLACEHOLDERS_B64
#   base64 of the merged profile policy's sandbox_env (§7.1). Non-secret
#   placeholders only; real provider credentials are forbidden here and are
#   injected by the Security CVM at proxy time. NOTE: this value is not
#   currently in the RTMR3 binding payload (§7.1).

networks:
  proxy:
    driver: bridge
  attestation:
    driver: bridge
  cvm-internal:
    name: cvm-internal
    driver: bridge
    internal: true
  egress-uplink:
    name: egress-uplink
    driver: bridge

volumes:
  tls-certs-keys:
  dev-home:
  dev-workspaces:
  dev-local:
  dev-claude:
  dev-codex:
  dev-cursor-server:
  dev-vscode-server:
  # Data root for the dockerd baked into user-sandbox (§3.1, §3.8). Persistent
  # across container restarts so image layers are not re-pulled on every restart.
  dev-docker-data:
```

## Appendix B — reference Dockerfile (illustrative)

`cvms/dev/user-sandbox/Dockerfile` is the authoritative source. The shape below documents the required structure; image refs and pinned versions evolve with CI.

```dockerfile
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
SHELL ["/bin/bash", "-o", "pipefail", "-c"]

RUN apt-get update && apt-get install -y --no-install-recommends \
      openssh-server dtach git curl xz-utils build-essential \
      python3 python3-pip rsync jq vim less ca-certificates \
      psmisc lsof sudo \
    && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/bin/python \
    && rm -f /usr/lib/python*/EXTERNALLY-MANAGED

# Docker CE engine + CLI + compose plugin. The authoritative Dockerfile refuses
# non-amd64 builds, downloads exact .deb filenames from tool-versions.env,
# verifies each reviewed SHA-256 digest, and installs those local files. It does
# not resolve packages through Docker's mutable apt index. dockerd is started by
# the entrypoint (after Sysbox sets up userns + idmapped mounts) and serves
# /var/run/docker.sock to in-sandbox clients (§3.1, §3.8, §4.1).
COPY tool-versions.env /tmp/tool-versions.env

# /etc/docker/daemon.json: inject proxy defaults into nested containers (§3.8).
COPY docker-daemon.json /etc/docker/daemon.json

# /etc/apt/apt.conf.d/95umbra-proxy: keep sudo apt traffic on the forwarder.
COPY apt-umbra-proxy.conf /etc/apt/apt.conf.d/95umbra-proxy

# uv, Node 22, Claude Code, Codex (--ignore-scripts), gh — verified binary installs.
# (See cvms/dev/user-sandbox/Dockerfile for current pins and checksums.)

# Login user `dev` with UID/GID 1001 (§3.2). Sysbox (the runtime selected in
# the compose) maps in-namespace root to an unprivileged UID on the dstack VM.
# Passwordless sudo is root-equivalent inside the namespace, but the trust
# boundary is the userns itself, not an in-container Unix privilege boundary.
# `dev` is in the docker group so plain `docker ...` works without sudo.
# Sub-uid/gid ranges for the in-sandbox dockerd to sub-allocate userns for
# nested containers; Sysbox-mgr arbitrates host-side allocation.
RUN groupadd --gid 1001 dev \
    && useradd --uid 1001 --gid 1001 --create-home --home-dir /home/dev --shell /bin/bash dev \
    && usermod --password '*' dev \
    && usermod -aG sudo,docker dev \
    && { \
      echo 'dev ALL=(ALL) NOPASSWD:ALL'; \
      echo 'Defaults:dev env_keep += "HTTP_PROXY HTTPS_PROXY http_proxy https_proxy NO_PROXY no_proxy REQUESTS_CA_BUNDLE SSL_CERT_FILE CURL_CA_BUNDLE GIT_SSL_CAINFO NODE_EXTRA_CA_CERTS"'; \
    } >/etc/sudoers.d/dev \
    && chmod 0440 /etc/sudoers.d/dev \
    && visudo -cf /etc/sudoers.d/dev \
    && echo 'dev:100000:65536' > /etc/subuid \
    && echo 'dev:100000:65536' > /etc/subgid \
    && mkdir -p /home/dev/workspaces /home/dev/.local/bin /home/dev/.cache /home/dev/.npm

# /etc/profile.d hooks: source /run/umbra/env.sh, run agent updater on login
# /etc/ssh/sshd_config copied from cvms/dev/user-sandbox/sshd_config
# Symlinks: /home/dev/.ssh -> /run/ssh/user-ssh
#           /home/dev/.claude.json -> /home/dev/.claude/.claude.json

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

HEALTHCHECK --interval=500ms --timeout=2s --start-period=3s --retries=5 \
  CMD pgrep -x sshd >/dev/null || exit 1

ENTRYPOINT ["/entrypoint.sh"]
```

Release publication MUST pass the source commit timestamp as `SOURCE_DATE_EPOCH` and use `rewrite-timestamp` on every exporter. Publication and verification MUST select the `umbra-release` builder, whose single node is BuildKit 0.32.2 pinned by image digest, and MUST use exporter compatibility version 30 with the digest-pinned Dockerfile 1.26.0 frontend. Buildx MUST be exactly 0.34.0. The local and publication reproducibility gates build from two independent clean worktrees with the same labels, pinned SBOM generator, and provenance settings, then compare the runnable linux/amd64 OCI manifest digest. Each local result index MUST independently pass runtime-label, subject-binding, SPDX, and max-mode SLSA validation. Its digest is not compared: BuildKit provenance carries a unique invocation ID and wall-clock start/finish times. Only after the stable runtime subjects match may publication perform one tagless push-by-digest registry build. Its remote runtime and attestations MUST be revalidated, and the runtime MUST equal the two local subjects. The helper returns, and deployment MUST use, the stable `repository@sha256:<runtime-manifest>` reference beneath that remote index.
