# Local sandbox execution contract

Status: source preview. This revision integrates folder-based local execution
into the existing `umbra` CLI. It does not establish managed-local deployment,
or remote attestation of the laptop runtime. Console local-workspace admission
and direct, strictly attested Security CVM transport are implemented.

## 1. Public interface and folder context

The public binary MUST remain `umbra`. The runtime package MUST NOT install an
`umbra-local` console script. Python and Swift helpers are private implementation
details, invoked by the Rust command layer with isolated Python import mode.

```bash
cd project
umbra start local --preview    # first preview launch
umbra ssh
umbra claude
umbra codex
umbra code                    # or cursor
umbra status
umbra stop local
umbra start local             # resumes with remembered settings
```

Start/stop accept `--path DIRECTORY`, otherwise use the current directory. Start
MUST use an existing ancestor binding before allocating a new workspace. It MUST
copy the project before reporting success. Preview acceptance is required only
on the first launch; the stored assurance remains `local-preview` thereafter.
The normal global `--profile` selectors (or configured defaults) select 1–16
assigned profiles on first launch. Explicit flags override remembered profiles;
remembered profiles override configured defaults on subsequent starts. `--bundle`, `--cpus` and `--memory` configure the local runtime.
A remote Dev CVM MUST NOT be required for admission, bootstrap, or egress.

`start local --app codex|claude` MUST complete admission, boot, project import,
and guest SSH/proxy readiness before opening a desktop app. It MUST register
only that workspace using its dedicated identity and pinned host key. Existing
SSH/Claude settings MUST be retained and backed up; no provider credentials are
copied into desktop settings. The command MUST report the SSH alias and guest
folder and state that app selection is still required. It MUST NOT open the host
project as a local desktop session or claim an agent was started. The standard
first-launch `--preview` gate still applies. A per-user `local-preview-bundle`
directory is the default when present; explicit and remembered bundles win.

Session resolution order is explicit remote positional target or `--cvm`, then
nearest registered local ancestor, then existing cloud defaults. Explicit remote
targets bypass even malformed local registries.
Connect subcommands remain Console/cloud workflows. Unbound folders retain the
existing cloud behavior. Stopped local VMs, invalid registries, missing helpers
and local errors MUST NOT trigger cloud fallback.

The binding store is owner-only `~/.umbra/local-projects.json`, version 1, with
`projects: [{root, name}]`. Roots are canonical absolute host directories. Names
are derived private workspace IDs, not user-facing required arguments. The nearest
ancestor wins, using component boundaries rather than a raw string prefix. The
binding survives stop. Moving a folder is not an implicit state migration.

Sessions start at `/home/dev/workspaces/project` plus their relative host cwd.
Local `--workspace` stays within this guest project. Named sessions use guest
`dtach`. Local `--identity-file` and `--alias` MUST be rejected, not ignored; local
workspaces use dedicated identities and folder context. Agent executables must
already be installed in the guest and configured with non-secret placeholders.
The guest ships integrity-pinned Codex. Claude must be installed through an
assigned policy or by its desktop SSH backend.

## 2. Whole-folder import and update semantics

The initial import MUST include regular files, directories, relative in-tree
symlinks, hidden files, untracked files, `.git`, and executable permission bits.
It MUST NOT execute Git, project hooks or build scripts on the host. `.gitignore`
is not an import filter. Project-local `.env` files are included; this operation
is not a secret scanner. The home directory, filesystem root and directories
containing/contained by Umbra's private configuration MUST be rejected as roots.

The importer MUST NOT dereference symlinks out of the source tree. Absolute or
escaping symlinks, devices, sockets, FIFOs, unsupported control-character paths,
unreadable directories and concurrent file-content changes fail explicitly.
Missing or skipped directories MUST NOT become silent guest deletions. Directory
and file descriptors use no-follow semantics during source reads.

The host stores the last successfully uploaded content manifest as a merge base.
Before each local session it scans the host tree and uploads changed file payloads
through that workspace's SSH connection. Identical host files MUST NOT overwrite
guest modifications. Guest-only files MUST be retained. A host deletion is applied
only when the guest file remains unchanged; parent-directory removal MUST NOT
recursively erase guest-only content. Identical changes on both sides are not
conflicts. Divergent edits abort the transfer before mutation. Session commands
may then open existing guest files with a warning, enabling conflict resolution.

The transfer protocol is a bounded 4-byte network-order JSON length, a versioned
manifest envelope and a streaming tar payload containing only changed regular
files. The guest MUST reject extra, duplicate, missing, nonregular or digest-
mismatched tar members; tar paths MUST NOT determine unrestricted extraction.
Files are staged and hashed before changes are applied. Normal files use atomic
replacement; directory removals use `rmdir`, never recursive deletion. A
multi-file update is not transactional across process loss: a partial update may
need retry. The merge base advances only on successful completion.

Limits: 100,000 entries, 16 MiB envelope, bounded 4096-byte response, and a bounded
transfer timeout. Source content is not accepted on command-line arguments or
printed in diagnostics. Host response handling MUST treat the guest as untrusted.

There is **no automatic guest-to-host write-back and no writable host mount**.
VM changes persist on its private disk and are edited through remote-in-VM editor
sessions. `umbra ssh --command 'git diff'` can export tracked changes for review;
it is not an all-file exporter. General reviewed write-back remains future work.

## 3. VM and transport invariants

The runtime targets Apple-silicon Macs using Virtualization.framework, with a
fixed ARM64 Linux boot contract. It configures no virtual network adapter and no
host directory sharing. Guest root cannot add host-provided virtual devices.
Local loopback HTTP(S) proxy traffic uses fixed vsock port 4050; host bootstrap
and SSH access use separate fixed ports. No generic host-command or host-file API
is exposed. Optional guest Docker workloads remain subject to the same no-NIC
boundary; this preview requires explicit proxy, CA and guest-network setup.

The host broker connects directly to the Console-selected Security CVM FQDN on
443 using `atlas-rs` and the Console's complete authoritative runtime policy. It
MUST reject missing pins and runtime-verification bypasses. It MUST NOT apply the
Dev forwarder's temporary image-policy exception. The existing `/umbra/proxy`
HTTP upgrade carries proxy bytes only after attestation. No guest-selected host
network destination is opened by the broker.

Console admission requires an active authenticated user with `CVM_LAUNCH`,
entity-scoped assigned profiles, and available owner-secret references. Each
start creates a new local workspace UUID and a random 256-bit proxy bearer.
Only its SHA-256 hash is stored in Console. The bearer is confined to host
process memory and pipes, never argv, guest state, or the project. Provider
credentials remain in the Security CVM. The broker replaces guest proxy-auth
headers. Outer HTTP requests have bounded headers/bodies and cannot pipeline;
HTTPS and WebSockets use CONNECT. Raw TCP fallback is denied for local clients.

Leases last 300 seconds and renew every 60 seconds. Renewals recheck user/profile
permission and verified SC material. Failed renewal stops the local VM. Stop
revokes the lease; if Console is unavailable, server expiry remains the bound.
The SC checks expiry on authentication, CONNECT identity reuse, WebSocket frames
in both directions, and streamed response chunks, even with stale control data.
Policy pull removes revoked/ineligible entries; this is not instant revocation.

`/internal/sc-control/cvms` adds a separate `local_entries` array. Older SC images
ignore it and cannot admit locals. Local entries contain `local_workspace_id`,
`proxy_token_hash`, `expires_at`, merged policy, version and update time. They
MUST be scoped to the authenticated SC, active owner, permission, and all profile
memberships. Traffic uses `local_workspace_id` and a null `cvm_id`; ingest binds
that identity to the emitting SC and entity. Start/stop are audited.

The local client waits for an authenticated proxy decision before reporting a
running VM. Public CA material is bound to the Console-provided digest and
replaced atomically in the guest after rotation. Programs caching trust may need
restart. At most 64 guest connections are active. Guest serial output retained
on the host is capped at 1 MiB per run; excess output is drained and discarded.
No ordinary guest NIC, shared host directory, or direct-network fallback exists.
The native helper observes its supervisor; stop uses bounded child handles, not
stored PIDs. Forced shutdown may interrupt guest writes.

Security CVM policy storage must preserve the authoritative compose JSON key order
through PostgreSQL and local create/renew responses: Atlas hashes its serialized
bytes. Store an ordered policy serialization alongside the JSONB object; legacy
Security CVMs require a normal update to refresh that material. No runtime
verification check may be disabled to compensate for serialization drift.

## 4. Local state and trust

Private runtime state is `~/.umbra/local/<derived-name>/`: config, guest disk,
workspace SSH key, pinned public guest host key, private sockets, last host
manifest, logs, locks and status. State files are atomic owner-only writes. Socket
path length is checked. The kernel, initrd, base disk and helper are covered by a
complete bundle digest manifest; changes are rejected rather than combining a
new kernel with an old persistent disk. These hashes establish drift detection,
not independent release provenance or resistance to a malicious Mac owner.

The Mac's kernel, VM framework, launcher, installed Python runtime and broker are
trusted. No claim is made that a remote server can prove this local software is
unmodified. Local-preview MUST NOT be labeled managed-local or attested-remote.
A live authorization lease is not proof that the host has no other network paths.

The no-NIC guest MUST receive bounded host wall time at boot and after each
successful lease renewal, before HTTPS use. The preview trusts its host clock;
TLS certificate validity checks MUST remain enabled. Bundle version 2 is required
for this bootstrap contract; older bundles fail before VM launch.

An SSH key is created per workspace; bootstrap conveys only its public half,
public SC trust material and host wall time. Strict host-key checking is required after guest
bootstrap. Host agent forwarding, reverse forwarding, X11, local SSH commands,
global SSH control sockets and writable host directories are forbidden. Editor
profiles may forward only to guest loopback. Local/cloud-hosted editor tools and
MCP integrations remain outside the VM boundary unless actually run inside it.

## 5. Output and errors

Start, stop and local status return structured payloads or the shared Rust
`style::local_workspace_card`; progress/diagnostics stay on stderr. On structured
failure stdout is empty. Cards include the source project, guest directory,
state and explicit `local-preview` assurance. A running VM MUST NOT upgrade the
displayed assurance. Raw sessions reject `--json`, stream child output, and use
the CLI's stable error status on failed child exit. Partial output may precede
such a failure, as with existing raw session commands.

## 6. Acceptance and production gates

Portable tests MUST cover main command parsing, explicit-remote precedence,
folder/subdirectory selection, sibling-prefix rejection, invalid registry
failure, import of hidden/untracked files, content changes, guest-edit retention,
conflicts, deletion safety, archive validation, symlink and special-file rejection,
stdout bounds, session access during conflict, stop persistence and transport
failure. Source-string topology tests are regression guards, not hardware proof.

The actual Rust build, native macOS/ARM64 build, guest image creation/boot, agent
installation, editor sessions, SC policy/DLP/injection, packet capture to a
controlled receiver, guest-root/nested-Docker bypass attempts, host import races,
CA rotation, sleep/wake, Wi-Fi/VPN changes and outage recovery require independent
validation before broad use. Portable tests do not replace these checks.

Production managed-local remains gated on: managed deployment and uninstall
resistance; signed release/rollback policy; device posture integration;
appropriate Network Extension protections; independent adversarial review;
and hardware fleet testing. Enrollment identifies the workspace and user,
not remotely measured laptop software.
Existing cloud CVM behavior and production deployments are not weakened or
reconfigured by this preview.
