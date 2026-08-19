# CLI

The `umbra` CLI is the v0 product surface for developers, admins, and operators. There is no separate admin frontend in v0.

The CLI talks to the Console over HTTPS, stores local session/config state, writes per-CVM aTLS policy files, opens verified tunnels to Dev CVMs, and wraps SSH/editor/agent workflows.

The authoritative contract is `docs/specs/cli.md`. Human-readable output formatting is governed by `docs/specs/cli-style.md`.

## Main Jobs

- Resolve Console URL, default CVM/profile, output mode, request ids, and aTLS policy settings from flags, environment, and `config.toml`.
- Log in and refresh sessions through Console-backed Google OIDC.
- Register and remove SSH keys.
- Launch, list, attach to, stop, start, update, and terminate Dev CVMs.
- Launch, inspect, update, attest, and terminate the entity Security CVM.
- Create and configure profiles, profile membership, users, permissions, quotas, and Connect/managed-secret grants (`claude connect`, `codex connect`, `profile grants`).
- Open `umbra tunnel`, `umbra ssh`, `umbra claude`, `umbra codex`, `umbra code`, and `umbra cursor` sessions.
- Read audit events and submit/download audit exports.
- Self-update from immutable published artifacts (`umbra update`) only after checksum and fixed-identity SLSA provenance verification, with a passive once-per-day new-version notice on stderr in interactive terminals.

## Build

From the repository root:

```bash
make build
make release
make install-cli
```

Direct development commands:

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

Inspect the built binary:

```bash
./target/release/umbra --version
./target/release/umbra version --json
./target/release/umbra config show
```

## Release

Run the **Release Umbra CLI** workflow manually. Its dry run packages the crate and builds every installer target without changing either release channel. Published targets are GNU/Linux x86-64 and ARM64 plus Apple Silicon macOS; the installer rejects Intel macOS instead of requesting an artifact the workflow does not build. With `dry_run=false`, crates.io is published first; only then does the workflow create the matching `umbra-cli/<version>` tag and draft GitHub release. Any failed phase fails the workflow, so the installer does not advance to a version that was not released everywhere. A rerun accepts an existing crates.io version only when it is not yanked and its checksum matches the package built from the selected commit. Existing annotated and signed tags are compared by their peeled commit. The workflow rebuilds the release tree deterministically and requires it to match any existing immutable asset byte-for-byte. It publishes checksums, target SBOMs, the canonical installer, and one signed SLSA provenance bundle covering the installer, release tree, binaries, crate, checksums, and SBOMs.

## Code Map

| Path | Purpose |
| --- | --- |
| `src/main.rs` | Binary entrypoint. |
| `src/lib.rs` | Library exports and top-level wiring. |
| `src/cli.rs` | `clap` command tree and global flags. |
| `src/help.rs` | Grouped, per-level `--help` rendering (root groups / group `Usage`+`Commands` / leaf detail); reads clap metadata, holds no command logic. |
| `src/commands/` | Command implementations. |
| `src/commands/auth.rs` | Login, logout, refresh, token, and session-status handling. |
| `src/commands/cvm.rs` | Dev CVM list, instance-type catalog listing, launch, lifecycle, profile attach/detach, operation polling, policy-file writes. |
| `src/commands/ssh.rs` | SSH, dtach session, editor, Claude, and Codex wrappers. |
| `src/commands/claude_connect.rs` | `claude connect`: stdin mint into profile secret material. |
| `src/commands/codex_connect.rs` | `codex connect`: laptop grant upload and sandbox placeholder auth. |
| `src/atls_policy_store.rs` | Per-CVM aTLS policy persist/load shared by launch, update, SSH, and tunnel. |
| `src/prompt.rs` | Typed yes/no consent prompts. |
| `src/commands/alias.rs` | Client-side alias store (CVM/profile/ssh-key/session) and resolution helpers. |
| `src/commands/tunnel.rs` | Low-level WebSocket tunnel over atlas-rs-verified TLS; owns the aTLS connect and policy-file lookup. |
| `src/commands/update.rs` | Fail-closed, SLSA-verified self-update from immutable install-service artifacts plus the passive new-version check (cache, background probe, stderr notice). |
| `src/exit.rs` | Stable process exit status mapping. |
| `src/config.rs` | Local configuration resolution. |
| `src/session.rs` | Local session storage and refresh handling. |
| `src/console.rs` | Shared Console API client: `fetch_json` (GET), `send` / `post_json` (writes), response decoding, and error-envelope-to-bracket mapping. |
| `src/operation.rs` | Console async-operation types and the poll → extract helpers (`wait_for_operation`, `await_result`); the submit itself is a command-layer `post_json`. |
| `src/style.rs` | Human-output rendering primitives and the `--json` emitter (`emit_json`). |
| `src/fsutil.rs` | Atomic, owner-only local-file write (`write_atomic_file`) and bounded `StoreLock` around read→modify→write of local stores. |

Every Console write (POST/PATCH/DELETE) goes through the shared `src/console.rs` client (`send` / `post_json`), and GET reads that need only a typed JSON body use `fetch_json`. Reads that need the raw response — ETag capture, custom 404 handling — and the OAuth device flow still build their own request.

## Local State

By default the CLI uses `~/.umbra`:

| File | Purpose |
| --- | --- |
| `config.toml` | Optional local defaults such as `console_url`, `default_cvm`, `default_profile`, `default_ssh_identity`, `output`, and `atls_policy`. |
| `session.json` | Access and refresh tokens plus user/entity identity. Written mode `0600` on Unix. |
| `ssh-identities.toml` | Local mapping from Console SSH key ids to private-key paths learned by `key add` or automatic launch key creation. Contains paths only, not key material. |
| `cvms/<cvm-id>.atls-policy.json` | Per-CVM policy bundle written after successful launch/update or lazy policy-bundle fetch. |
| `update-check.json` | Cached latest-version probe for the passive new-version notice. Safe to delete. |

Important overrides:

| Override | Purpose |
| --- | --- |
| `--config` / `UMBRA_CONFIG_DIR` | Change the config directory. |
| `--console-url` / `UMBRA_CONSOLE_URL` | Set Console base URL. |
| `--cvm` / `UMBRA_DEFAULT_CVM` | Select default Dev CVM for session commands. |
| `--profile` / `UMBRA_DEFAULT_PROFILE` | Select profile; repeat `--profile` where launch needs multiple profiles. |
| `--json` / `UMBRA_OUTPUT=json` | Request structured output where supported. |
| `--atls-policy` / `UMBRA_ATLS_POLICY` | Supply an explicit aTLS policy file. |
| `UMBRA_INSTALL_BASE_URL` / `install_base_url` | Required before `umbra update` or passive update checks can use a release service; there is no default public install domain until one is approved. Must be `https` unless the host is loopback; executable installation independently requires signed provenance for the fixed canonical release identity. |
| `UMBRA_SLSA_VERIFIER` | Absolute path to the trusted preinstalled `slsa-verifier`. When unset, update searches only absolute `PATH` directories. Install the pinned verifier via `docs/quick-start.md`; missing or rejected verification fails before execution/replacement. |
| `UMBRA_NO_UPDATE_CHECK=1` / `no_update_check` | Disable the passive new-version check and notice. |

`umbra update` never downloads a mutable `latest` binary. It reads the mirror's latest-version pointer, then fetches and verifies that immutable version. Provenance authenticates the artifact, not freshness: a mirror can suppress or replay valid version metadata. Normal updates refuse to downgrade below the installed version; `--force` and explicit version pins deliberately permit rollback. The verified clean-install flow in `docs/quick-start.md` selects an exact GitHub release before invoking the mirror-backed installer.

## Output Contract

- Command payload goes to stdout.
- Logs and diagnostics go to stderr.
- On non-zero exit, stdout must be empty.
- `--json` is honored only by commands with structured payloads.
- Use `ExitStatus` from `src/exit.rs`; do not return ad-hoc process codes.
- Do not accept secrets on argv.
- `--help` uses a custom three-level layout (`src/help.rs`), not clap's default. Global flags are `hide`d from level-2/3 help and re-listed once under `Global options` at the root; they still parse everywhere. Adding an option to a command's `Args` struct in `src/cli.rs` is enough — the synopsis and per-option detail (description, `Default:` from clap's `default_value`, `[values: …]`) render automatically. Adding a whole subcommand also requires a `GROUPS` entry (and an `EXAMPLES` entry for a leaf with args); anti-drift tests enforce both.

## Command Families

| Family | Purpose |
| --- | --- |
| `auth` / `login` / `logout` / `status` / `refresh` / `token` | Session lifecycle. |
| `config` / `version` / `completions` / `update` | Local setup, diagnostics, and self-update. |
| `entity` / `user` / `permissions` / `quota` | Admin resource management. |
| `key` | Self-service SSH key management. |
| `secret` | Self-service per-user, host-bound secrets referenced by profile `value_from` injections (values via stdin/`--value-file`, never argv). |
| `profile` | Policy authoring and membership. |
| `security-cvm` | Per-entity Security CVM lifecycle and attestation diagnostics. |
| `cvm` / `ssh` / `tunnel` / `claude` / `codex` / `code` / `cursor` / `ps` / `attach` / `kill` | Dev CVM lifecycle and attachment. |
| `alias` | Client-side aliases for CVMs, profiles, SSH keys, and sessions. |
| `audit` / `traffic-logs` | Audit and egress observability. |

## Common Flow

```bash
umbra auth login https://console.example.com
umbra security-cvm launch
umbra profile create default
umbra --profile <profile-id> user add dev@example.com --permission CVM_LAUNCH
umbra cvm launch
umbra cvm update <cvm-id>
umbra ssh
umbra claude --name claude-main --workspace ~/workspaces/myrepo
umbra cursor --workspace ~/workspaces/myrepo
umbra traffic-logs --cvm <cvm-id>
```

`claude` / `codex` / `code` / `cursor` all accept `--workspace <PATH>` and share one cached value per CVM. The first invocation that passes `--workspace` writes the path to `~/.umbra/cvms/<cvm-id>.state.toml`; subsequent bare invocations reuse it. To reset, pass `--workspace /home/dev` or delete that file.

`umbra codex` launches the Dev CVM's Codex wrapper with Codex's own approval and Linux sandbox layers bypassed. The attested Dev CVM's Sysbox boundary and Security CVM-controlled egress remain in force and are the intended isolation boundary.

For developer onboarding, `auth login <url>` saves the Console URL in `~/.umbra/config.toml`. An admin should create the developer with `user add`, grant `CVM_LAUNCH`, and assign exactly one profile for the simplest first launch. `key add --file ~/.ssh/<key>.pub` remembers the sibling private key when `~/.ssh/<key>` exists and matches; `--identity-file <path>` can pin a non-sibling private key. `cvm launch` can use the assigned profile automatically and ensures the launched CVM has at least one SSH key with a local private key the CLI can use. It reuses a remembered or discoverable registered key when possible; otherwise it creates and registers `~/.ssh/id_ed25519` or a non-conflicting `~/.ssh/umbra_ed25519...` key. Successful launch saves `default_cvm` and `default_ssh_identity`, so `umbra ssh` and other session verbs can run without a CVM id or manual key selection.

Dev CVM updates preserve the provider-managed named volumes. If the Console-returned aTLS policy bundle differs from an existing local per-CVM policy file, the CLI explains that the file is local trust material and asks before replacing it. After a Security CVM update, refresh-capable Umbra Dev runtimes pull the current SC aTLS policy and mitmproxy CA over their authenticated Console control channel, and the sandbox watcher replaces the trust bundle automatically. When the CA changed, the update result reports `ca_changed=true`; human output scopes automatic recovery to compatible runtimes rather than instructing a fleet-wide `umbra cvm update`. A full Dev CVM update remains the current-runtime rebind path when launch-bound material such as the SC FQDN, per-Dev bearers, or RTMR3 binding changes. If a CVM already carries `SECURITY_CVM_REBIND_REQUIRED`, the CLI treats its runtime capability as unproven and refuses SSH. Use the pre-Umbra control plane to terminate/decommission that preserved resource, then launch a replacement under Umbra; the renamed build cannot manage it, and `umbra cvm update` is not recovery.

`umbra tunnel <target>` is the low-level transport primitive. In the current implementation `<target>` is a Dev CVM FQDN and an aTLS policy must be supplied or resolvable. If verification reports an app-compose hash mismatch for the normal `cvms/<cvm-id>.atls-policy.json` file, the tunnel explains that the measured CVM does not match the local policy, asks on the controlling terminal whether to fetch Console's current policy for that CVM, and retries once after confirmation.

`umbra cursor` only controls the Remote SSH path into the Dev CVM. Cursor-hosted agent tools such as WebFetch/WebSearch, browser MCP, or integrations that run through Cursor's infrastructure or the local workstation may still use the aTLS-protected editor/SSH channel to trigger work in the remote IDE and return results, but the public-web request itself is not necessarily opened by a process inside the Dev CVM network namespace. Those requests are not filtered or logged by the Security CVM. Use `umbra ssh`, `umbra claude`, or `umbra codex` for workflows where tool traffic must stay inside Umbra-controlled egress.

## Security Notes

- Session and token handling must follow `docs/specs/cli.md`.
- Per-CVM aTLS policy files are server-rendered by the Console and stored locally by the CLI.
- `umbra tunnel` rejects `--insecure-skip-atls-policy`; verifier green paths must never use any aTLS bypass.
- Secrets must never be printed, logged, accepted on argv, or stored in world-readable files.
