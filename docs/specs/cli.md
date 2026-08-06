# Umbra CLI Spec

This document is the authoritative specification for the `umbra` command-line interface. It defines command surface, configuration, input/output contracts, exit codes, authentication, and security properties. Implementations must conform to this spec. Peer implementation contracts live in `docs/specs/console.md`, `docs/specs/dev-cvm.md`, and `docs/specs/security-cvm.md`.

## 1. Overview

`umbra` is the command-line client for the Umbra platform. It:

- Authenticates the user against the Console via OIDC (loopback + PKCE by default, device flow as an opt-in alternative — see §5.1).
- Opens attested TLS (aTLS) tunnels to Dev CVMs.
- Orchestrates long-running dtach sessions on those CVMs for interactive SSH and AI agents.
- Manages Console-side resources (CVMs, SSH keys, profiles, Security CVMs).

Two audiences: developers (the session verbs in §3.2 and tunnel in §3.3) and admins / platform operators (the resource-management verbs in §3.4 and maintenance commands in §3.5). The CLI is stateless apart from a small set of files on disk (see §4). It has no daemon, no local dtach instance, and no telemetry.

**Non-goals:**

- No telemetry or analytics. The only non-Console network call the CLI makes on its own initiative is the passive latest-version probe against the install service (§3.6 `umbra update`): a bare GET carrying no user or session data, at most once per 24 hours, active only in interactive terminals, and disabled entirely by `no_update_check` / `UMBRA_NO_UPDATE_CHECK`.
- No silent auto-install. Installing a new version is always an explicit `umbra update` run; the passive check only prints a one-line stderr notice naming that command.
- No server-side state beyond what the Console itself stores.

## 2. Global conventions

Conventions in this section apply across every command. The catalog in §3 does not repeat them.

### 2.1 Binary

The installed binary MUST be named `umbra`. `umbra --version` MUST print a single line containing the semantic version, and `umbra version` MUST print a multi-line block containing version, build commit, target triple, and build date.

The binary should be self contained as much as possible. External dependencies should kept to a minimum to make it usable in a large set of environments.

### 2.2 Global flags

Every subcommand MUST accept these flags (parsed at the top level):

| Flag | Purpose |
| --- | --- |
| `-v`, `--verbose` | Increase log verbosity. Repeatable: `-v` = INFO, `-vv` = DEBUG, `-vvv` = TRACE. Default is WARN. |
| `--config <PATH>` | Override the **config directory** for this invocation. |
| `--console-url <URL>` | Override `console_url` for this invocation. |
| `--profile <PROFILE_ID>` | Override the default profile for this invocation. Used by commands that scope an action to a profile (e.g. `cvm list`, `profile show`, `profile configure`, `cvm attach`, `cvm detach`). On `cvm launch` the flag is **repeatable** — each occurrence is a profile to attach at launch (§3.4 `cvm launch`); a CVM MUST attach ≥ 1 profile. Security CVM commands (`security-cvm show / launch / terminate`) no longer accept `--profile`: the Security CVM is per-entity (§3.4). |
| `--request-id <ID>` | Override the `X-Request-Id` sent on every Console call this invocation. Default: a fresh UUID v4 per command invocation, propagated to every HTTP request the command makes. Useful when correlating CLI activity with server-side logs in support workflows (§2.7). |
| `--force` | Skip `If-Match` on commands that mutate Console resources (§2.7). By default the CLI sends an ETag-aware request; `--force` issues last-writer-wins. Logged at `WARN` because it bypasses concurrent-edit protection. On `umbra update` — which mutates no Console resource — it instead forces the reinstall/downgrade paths (§3.6). |
| `--atls-policy <PATH>` | Path to the aTLS policy file enforced on every aTLS tunnel (see §6.1). |
| `--insecure-skip-atls-policy` | **Dev-only escape hatch.** Skip aTLS policy evaluation for this invocation (see §6.1). The aTLS handshake still runs; only the local policy check is bypassed. |
| `--json` | Emit JSON output (see §2.3). Honored only by commands that emit a structured payload; silently ignored otherwise. |
| `--no-color` | Disable ANSI color in stdout and stderr. |
| `-h`, `--help` | Print help. |
| `-V`, `--version` | Print version (root command only). |

Every global flag MUST have a corresponding config key and environment variable (see §4.1); the flag, env var, and config key are three ways of expressing the same value, and precedence is defined in §4.2.

### 2.3 Output formats

- **Default** output is human-readable and adapts to the content: tables for list-like commands when the columns fit the terminal width; structured text (bulleted items with indented `key: value` fields) when a table would wrap or a record has too many fields to line up cleanly; short sentences for point commands. The per-command "Output" paragraphs in §3 describe the information returned; the exact rendering (table vs. structured list) is an implementation choice driven by fit.
- **JSON** is emitted when `--json` is passed. The catalog in §3 describes the information each command returns.
- Log and diagnostic output MUST go to **stderr**. Command payloads (tables, JSON objects, success messages) MUST go to **stdout**. Scripts can therefore safely consume stdout while leaving stderr to the terminal.
- **Nothing else may be printed to stdout** apart from the JSON object when `--json` is passed. This is a strict contract: a trailing status line, a progress indicator, or an informational note on stdout is a spec violation (it would break the json output). Progress and status belong on stderr.
- Errors MUST be printed to stderr as plain, human-readable text regardless of `--json`. `--json` affects the **success** output only; it does not restructure error output. Error messages SHOULD lead with the exit-code symbol in brackets (e.g. `[auth_required] session expired — run umbra auth login`) so scripts can match on it if they want to branch on the reason without parsing the exit code.
- On a non-zero exit, stdout MUST be empty — no partial payload, no truncated JSON object. Consumers can therefore rely on "exit code 0 and well-formed JSON on stdout" as a single success check in `--json` mode.
- JSON payloads are stable at the field level: a field that exists keeps its name, type, and meaning. New fields may be added; renaming or re-purposing existing fields should be avoided (acceptable during v0, but a breaking change in later versions). Consumers SHOULD ignore unknown fields.

### 2.4 Exit codes

| Code | Symbol | Meaning |
| --- | --- | --- |
| `0` | `ok` | Success. |
| `1` | `error` | Generic failure: API error, I/O error, malformed config, unreachable CVM, remote command non-zero, terminal `FAILED` state reported by the Console. |
| `2` | `auth_required` | Authentication or session problem: not logged in, session expired, HTTP 401 from Console. |
| `3` | `wait_timeout` | A client-side `--wait-timeout` elapsed. The server-side saga is unaffected; the caller can re-query later. |
| `4` | `usage` | Invalid arguments, missing required flags, or unknown subcommand. Emitted by the argument parser. |

Scripts MAY rely on the numeric value; the symbol is used as a leading bracketed tag on error messages (see §2.3) so callers can match on the reason without branching on exit codes alone.

**HTTP status to exit code.** The CLI maps Console HTTP statuses to the table above and surfaces the typed `error.code` from the response envelope as the bracketed tag on stderr (so callers can branch without parsing JSON). In addition to the obvious mappings (`200/201/202/204` → `0`, `401` → `2`, `422 VALIDATION_ERROR` → `4`), specific shapes worth noting:

- `409 CONFLICT` (`details.state="..."`) — `1`. The CLI prints `[error] {message}` plus the `details.state` value so the user can branch on the typed state (e.g. `cvms_attached`, `last_profile`, `no_security_cvm`).
- `409 IDEMPOTENCY_CONFLICT` — `1`. Indicates a stale retry sent the same `Idempotency-Key` with a different body. The CLI tells the user to retry without an explicit retry helper (§2.7).
- `412 PRECONDITION_FAILED` — `1`. The CLI prints `[error] resource changed since last read — re-run the command`. With `--force` this should never fire; without it, the read-modify-write loop in §2.7 is the recovery path.
- `413 PAYLOAD_TOO_LARGE` — `1`. Hardcoded 1 MiB (`/api/v1`) and 4 MiB (`/internal`) caps; the CLI rarely hits this since it only sends bounded payloads.
- `415 UNSUPPORTED_MEDIA_TYPE` — `1`. Should never fire since the CLI always sends `Content-Type: application/json`; treat as a bug.
- `429 RATE_LIMITED` (`details.retry_after_seconds`, `details.limit`) — `1`. The CLI prints `[error] rate limited — retry after {N} seconds (limit: {kind})`. For polling commands (§2.6), the rate-limited poll does NOT count against `--wait-timeout-seconds`; the CLI honors `Retry-After` and resumes.
- `502 UPSTREAM_ERROR` (`details.adapter`) — `1`. External integration (Phala, Cloudflare, IdP, Security CVM push) failed.
- `503 SERVICE_UNAVAILABLE` (`details.component`) — `1`. A required Console dependency (Phala adapter, Cloudflare adapter, DB) is unconfigured or unreachable.

### 2.5 Logging and verbosity

- All log output MUST go to stderr using a structured formatter (e.g. key-value pairs or JSON lines).
- Default filter: `WARN`. Override with `v` (INFO), `vv` (DEBUG), `vvv` (TRACE). `--verbose` and the `UMBRA_LOG_LEVEL` environment variable accept the same level names.
- If `UMBRA_LOG_LEVEL` is set, it is applied as the base filter and overridden by any `v` flags on the command line.
- All important operations MUST be logged at an appropriate level:
    - `INFO` — command start, significant state transitions, successful completions.
    - `DEBUG` — request/response summaries (without secrets), config resolution, retry attempts.
    - `TRACE` — full request/response bodies (bearer tokens and other secrets MUST be redacted regardless of level).
    - `WARN` — recoverable conditions (retried requests, fallback paths).
    - `ERROR` — unrecoverable conditions that cause a non-zero exit.
- Bearer tokens, OIDC codes, and other secrets MUST NOT be logged at any level.

### 2.6 Console async operations

Some Console resource-management routes (§3.4) are asynchronous: they return a typed operation handle immediately and complete out of band. The CLI exposes a uniform contract on top of them.

Affected commands today: `umbra cvm launch`, `umbra cvm update`, `umbra cvm terminate`, `umbra security-cvm launch`, `umbra security-cvm update`, and `umbra audit export`. Future async commands inherit this contract automatically.

**Default (wait).** The CLI polls the operation handle until it reaches a terminal state (`succeeded` / `failed` / `cancelled`) or `--wait-timeout-seconds` elapses.

- On `succeeded`, the CLI prints the resource record carried in the operation's `result` (per the affected command's Output section).
- On `failed`, the CLI prints `[<error_code>] <message>` on stderr — where `error_code` is the Console's typed `Operation.error.code` (e.g. `PHALA_DEPLOY_FAILED`, `CA_EXPORT_TTL_EXPIRED`, see Console contract for the closed set per kind) — and exits `1`.
- On `cancelled`, the CLI prints `[cancelled] <message>` on stderr and exits `1`.
- On timeout, the CLI prints the operation handle on stderr so the caller can re-poll later, and exits `3`. The server-side saga is unaffected.
- **`--no-wait`.** Submits the operation, prints the operation handle, and exits `0` without polling.
- Default output: a one-line confirmation containing the operation `id` and `kind`.
- JSON output: the `<Operation>` shape from Console §2.3 — `{id, kind, status, target: {type, id}, expires_at}`. The operation id is the top-level `id` field (matching the Console schema); a CLI consumer correlates it via `GET /operations/{id}`.
- The caller is responsible for tracking the operation `id` if they want to come back. v1 does not surface a generic `umbra operation` command (see §10 for the planned future work); a script that needs to re-poll a `--no-wait` operation should record the `id` from this output and call `GET /operations/{id}` directly until the future revision lands.
- **`--wait-timeout-seconds <SECONDS>`.** Maximum time, in seconds, to poll. Default `600` (10 minutes). Ignored when `--no-wait` is set. On timeout the CLI exits `3`.

**Polling cadence.** The CLI MUST poll no faster than once per second. It MUST honor a `Retry-After` header on a `429 RATE_LIMITED` response and MUST NOT count rate-limited polls toward the wait budget.

**Re-polling stale operations.** Operations are retained for 30 days after their terminal state per the Console contract; a poll past expiry returns `404`. The CLI exits `1` with `[error] operation expired or not found`.

### 2.7 Console interaction conventions

Every Console call the CLI makes carries the headers below. This section is the CLI-side contract for how they are produced and consumed.

**`Idempotency-Key`.** The CLI sends `Idempotency-Key` on this exact set of routes: `POST /entities`, `POST /me/keys`, `POST /entities/{id}/users`, `POST /entities/{id}/profiles`, `POST /cvms`, `POST /entities/{id}/security-cvm`, `POST /audit/export`, `POST /admin/sessions/revoke`, `POST /admin/keys/rotate`. The Console returns `400 BAD_REQUEST` if the header is missing on any of these. The CLI MUST therefore mint a fresh UUID v4 for the header value and include it on every call to one of those routes. The CLI SHOULD persist `(command, idempotency_key, timestamp)` in memory for the duration of the invocation so a network-level retry sends the same key (idempotency is per-key, not per-attempt). The CLI does NOT persist idempotency keys across invocations — each `umbra cvm launch` invocation gets its own key.

For routes the Console marks `optional` (`POST /cvms/{id}/profiles`, `POST /users/{id}/permissions`, `POST /cvms/{id}/actions/*`, `POST /admin/reconcile`, every `PATCH`), the CLI SHOULD also send a fresh `Idempotency-Key` so a transient network retry doesn't apply the same mutation twice on the wire — the Console accepts the header even when not strictly required.

**`If-Match` (optimistic concurrency).** A subset of mutation routes refuse to write without `If-Match`. The CLI's default behaviour is **read-modify-write**: fetch the resource first, capture the response's `ETag` header, send `If-Match: <etag>` on the mutation. On `412 PRECONDITION_FAILED`, exit `1` with `[error] resource changed since last read — re-run the command`. `--force` (§2.2) skips `If-Match` and accepts last-writer-wins; the CLI logs a `WARN` line on every use.

Routes that REQUIRE `If-Match`: `DELETE /profiles/{id}`, `POST / DELETE /profiles/{id}/users`, `PATCH /profiles/{id}`, `POST / DELETE /users/{id}/permissions[/...]`, `POST /cvms/{id}/profiles`, `DELETE /cvms/{id}/profiles/{profile_id}`. Routes that ACCEPT but don't require: `DELETE /me/keys/{key_id}`, `DELETE /entities/{id}/users/{user_id}`, `POST /cvms/{id}/actions/*`, `DELETE /entities/{id}/security-cvm`.

**`client_id` for loopback flow.** The Console requires the CLI's loopback `/auth/authorize` request to carry a registered `client_id`. The CLI ships with a default `client_id` of `umbra-cli-v1`; advanced users can override via the `oidc_client_id` config key (§4.1). The Console operator registers the `client_id` value in `OIDC_CLIENT_ALLOWLIST` out of band; the CLI does not discover the allow-list at runtime.

## 3. Commands

Each entry lists synopsis, flags, output, and exit codes specific to that command. Global flags from §2.2 are not repeated. The "Output" paragraph describes the information each command returns; consumers parse the JSON directly.

### 3.1 Authentication (`umbra auth`)

Authentication commands are grouped under the `auth` noun. All subcommands operate on the local session file (§4.4) and, where noted, on the Console's OIDC endpoints.

### `umbra auth login`

Authenticate against the Console. By default uses the **loopback + PKCE** flow (OAuth 2.0 Authorization Code with PKCE over a `127.0.0.1` redirect); `--device` / `--no-browser` switches to the **device flow** for environments without a usable local browser. Writes the issued credentials to the session file on success. When `<CONSOLE_URL>` is supplied, or when `--console-url` is supplied globally, a successful login also saves `console_url` to `config.toml` so future commands do not need the URL again. See §5.1 for the full semantics of each flow.

**Synopsis**

```
umbra auth login [<CONSOLE_URL>] [--provider <PROVIDER>] [--device | --no-browser]
```

**Arguments**

- `<CONSOLE_URL>` — optional Console base URL to use and persist on successful login. Equivalent to the global `--console-url` for this invocation, but optimized for first-run onboarding.

**Flags**

- `--provider <PROVIDER>` — OIDC provider identifier. Default: the value of the `oidc_provider` config key (see §4.1).
- `--device`, `--no-browser` — use the device flow instead of the default loopback flow. The two names are synonyms; either accepts the same arguments and has the same behavior. The CLI does **not** attempt to auto-detect whether a browser is available — the user opts into device flow explicitly.

**Output**

- Loopback flow (default): opens the authorize URL in the user's browser, waits for the redirect to `127.0.0.1`, completes the code-for-token exchange. Prints a confirmation (user email, session expiry) on stdout when done; in `--json` mode, the stdout payload is an object with `user_id`, `email`, and `expires_at`.
- Device flow (`--device`): prints the verification URL and user code on stderr, polls the Console until the user completes authentication on any device with a browser, then prints the same confirmation (or JSON payload) on stdout.

**Exit** — `0` on success; `1` on flow timeout, OIDC error, loopback-port binding failure, or I/O failure; `4` on invalid flag values.

---

### `umbra auth logout`

Delete the stored session, if any.

**Synopsis**

```
umbra auth logout
```

**Output**

One-line confirmation on stdout. If no session exists, the command is a no-op and still exits `0`. In `--json` mode, stdout is an object with `cleared: bool`.

**Exit** — `0` on success; `1` on I/O failure.

---

### `umbra auth status`

Show the full state of the current session: identity, access-token and refresh-token expiries, Console URL, and the resolved source (flag / env / file / default) of each auth-related configuration value. No network call — reads the session file and the resolved configuration only.

**Synopsis**

```
umbra auth status
```

**Output**

Default: human-readable rendering (§2.3) containing:

- Logged-in identity: `email`, `user_id`.
- Entity: `name`, `id`.
- Console URL and its configuration source.
- Access-token state: `valid` / `expired`, with `expires_at` and remaining time.
- Refresh-token state: `available` / `expired` / `absent`, with `refresh_expires_at` where present.
- Session file path and file mode (Unix only).

JSON: an object with fields `user`, `entity`, `console_url` (`{value, source}`), `access_token` (`{state, expires_at, remaining_seconds}`), `refresh_token` (`{state, expires_at}`), `session_file` (`{path, mode}`). The access token itself MUST NOT appear in either rendering.

**Exit** — `0` on any session (valid or expired — the command's job is to tell you which); `2` only if no session exists at all; `1` on I/O failure.

---

### `umbra auth refresh`

Force a refresh of the access token using the stored refresh token. The CLI contacts the Console's token endpoint, exchanges the refresh token for a new access token, and rewrites `session.json` atomically (§4.5).

**Synopsis**

```
umbra auth refresh
```

**Output**

Default: one-line confirmation with the new `expires_at`. JSON: object with `expires_at` and `refresh_expires_at`.

**Exit** — `0` on successful refresh; `2` if no session exists, no refresh token is stored, or the refresh token has expired or been revoked (caller must run `umbra auth login`); `1` on I/O failure.

---

### `umbra auth token`

Print the current access token to stdout so it can be captured in scripts (e.g. `curl -H "Authorization: Bearer $(umbra auth token)" …`). If the access token is expired and a valid refresh token is available, the CLI refreshes silently before printing.

This is the only command permitted by §5.5 to emit the access token to stdout; it is the command's sole purpose.

**Synopsis**

```
umbra auth token
```

**Output**

The raw access token on stdout, followed by a single `\\\\n`. Nothing else on stdout. `--json` is ignored (the output is already a single machine-readable value).

**Exit** — `0` on success; `2` if no session or refresh required but no valid refresh token is available (caller must run `umbra auth login`); `1` on I/O failure.

### 3.2 Session verbs

These operate on an explicitly addressed CVM: pass a `<CVM_ID>` positional or the equivalent `--cvm <CVM_ID>` flag. When neither is given they fall back to the **default CVM**. The full resolution order is positional `<CVM_ID>` → `--cvm` → `UMBRA_DEFAULT_CVM` → `default_cvm` (§4.2); missing all four exits `4` (usage). `--cvm` is a per-verb target flag (it is **not** a global flag, and is rejected by commands that do not target a single CVM, such as `traffic-logs`, which keeps its own `--cvm`/`--security-cvm` *filters*). All dtach state lives on the CVM; the CLI does not run a local dtach instance. See §6 for the transport and remote-execution model.

All SSH-backed session and editor flows MUST inspect the fetched CVM before opening a tunnel. A persisted `error_reason="SECURITY_CVM_REBIND_REQUIRED"` is a legacy replacement marker, not proof that the deployed image contains Umbra's runtime CA refresh path. The CLI MUST fail closed with exit `1` and direct the user to use the pre-Umbra control plane to terminate/decommission the preserved CVM/provider resource, then launch a replacement under Umbra. The renamed build cannot manage that resource, and the CLI MUST state that `umbra cvm update` is not a recovery path.

### `umbra ssh`

Open a new interactive SSH session to the default CVM inside a dtach session.

**Synopsis**

```
umbra ssh [<CVM_ID>] [--name <NAME>] [--identity-file <PATH>] [--command <COMMAND>]
```

**Arguments**

- `<CVM_ID>` — Dev CVM UUID. Optional; when omitted, the default CVM from §4.2 is used.

**Flags**

- `--name <NAME>` — start or attach a dtach session with the given name. When omitted, a timestamped name MUST be generated of the form `ssh-<yyyymmdd>-<hhmmss>`.
- `--identity-file <PATH>` — pass a private key path through to `ssh(1)` as `-i <PATH>`. Optional; when omitted, the CLI resolves the launch key automatically: first a local key-id mapping recorded by `umbra key add` or automatic `cvm launch` key creation, then `config.toml` `default_ssh_identity` when that key's public fingerprint matches a key installed on the target CVM, then any local private key whose sidecar public-key fingerprint matches a key installed on the target CVM. When a key is resolved, the CLI passes `-i` with `IdentitiesOnly=yes`. Interactive session verbs use `BatchMode=no` so a passphrase-protected launch key can prompt once; non-interactive `--command` paths keep `BatchMode=yes`. If no matching local key is found, the CLI may fall back to OpenSSH's normal agent/default-key behavior, but the default `cvm launch` path is expected to avoid that fallback by installing a locally usable key.
- `--command <COMMAND>` — execute a single remote shell command directly over the attested SSH tunnel instead of starting or attaching a dtach shell. Intended for scripted smoke tests and automation; it MUST NOT be combined with `--name`.

**Output**

By default, attaches the user's terminal to the remote dtach session. No CLI-generated stdout payload; the remote shell's output is displayed directly. With `--command`, stdout/stderr are the remote command's streams. `--json` is ignored for this command.

**Exit** — `0` on clean exit; `1` on remote command failure or SSH/tunnel setup failure; `2` on auth errors; `4` when no CVM is selected or arguments are invalid.

---

### `umbra claude`

Launch the pre-installed `claude` agent in a dtach session on the target CVM.

**Synopsis**

```
umbra claude [<CVM_ID>] [--name <NAME>] [--workspace <PATH>] [--identity-file <PATH>]
```

**Arguments**

- `<CVM_ID>` — Dev CVM UUID. Optional; when omitted, the default CVM from §4.2 is used.

**Flags**

- `--name <NAME>` — start or attach a dtach session with the given name. When omitted, the generated name MUST be `claude-<yyyymmdd>-<hhmmss>`.
- `--workspace <PATH>` — working directory for the agent on the Dev CVM. Paths starting with `~/` are resolved under the developer home directory; absolute paths MUST start with `/`; otherwise the path is resolved relative to the developer home directory. The remote command MUST `cd` into this directory before starting Claude. If the directory does not exist, the remote command MUST exit non-zero. The path MUST NOT contain `..` or shell metacharacters (see validation in §6.4). When `--name` resolves to an existing dtach session, this flag is ignored and the CLI attaches to the running session as-is. When the flag is supplied, its value is also persisted to the per-CVM state file (§4.4); when omitted, the value cached for the target CVM is used. A bare `umbra claude` with no cached state opens in the developer home directory.
- `--identity-file <PATH>` — pass a private key path through to `ssh(1)` as `-i <PATH>`. Optional; when omitted, the CLI resolves the launch key automatically: first a local key-id mapping recorded by `umbra key add` or automatic `cvm launch` key creation, then `config.toml` `default_ssh_identity` when that key's public fingerprint matches a key installed on the target CVM, then any local private key whose sidecar public-key fingerprint matches a key installed on the target CVM. When a key is resolved, the CLI passes `-i` with `IdentitiesOnly=yes`. Interactive session verbs use `BatchMode=no` so a passphrase-protected launch key can prompt once; non-interactive `--command` paths keep `BatchMode=yes`. If no matching local key is found, the CLI may fall back to OpenSSH's normal agent/default-key behavior, but the default `cvm launch` path is expected to avoid that fallback by installing a locally usable key.

**Output**

Attaches the user's terminal to the Claude agent running inside the remote dtach session. `--json` is ignored.

**Exit** — same as `ssh`.

---

### `umbra codex`

Launch the pre-installed `codex` agent in a dtach session on the target CVM.

**Synopsis**

```
umbra codex [<CVM_ID>] [--name <NAME>] [--workspace <PATH>] [--identity-file <PATH>]
```

**Arguments**

- `<CVM_ID>` — Dev CVM UUID. Optional; when omitted, the default CVM from §4.2 is used.

**Flags**

- `--name <NAME>` — start or attach a dtach session with the given name. When omitted, the generated name MUST be `codex-<yyyymmdd>-<hhmmss>`.
- `--workspace <PATH>` — same semantics as `umbra claude --workspace` (§3.2).
- `--identity-file <PATH>` — pass a private key path through to `ssh(1)` as `-i <PATH>`. Optional; when omitted, the CLI resolves the launch key automatically: first a local key-id mapping recorded by `umbra key add` or automatic `cvm launch` key creation, then `config.toml` `default_ssh_identity` when that key's public fingerprint matches a key installed on the target CVM, then any local private key whose sidecar public-key fingerprint matches a key installed on the target CVM. When a key is resolved, the CLI passes `-i` with `IdentitiesOnly=yes`. Interactive session verbs use `BatchMode=no` so a passphrase-protected launch key can prompt once; non-interactive `--command` paths keep `BatchMode=yes`. If no matching local key is found, the CLI may fall back to OpenSSH's normal agent/default-key behavior, but the default `cvm launch` path is expected to avoid that fallback by installing a locally usable key.

**Output**

Attaches the user's terminal to the Codex agent running inside the remote dtach session. `--json` is ignored.

**Exit** — same as `ssh`.

---

### `umbra code`

Open a local VS Code window connected to the Dev CVM via Remote SSH.

**Synopsis**

```
umbra code [<CVM_ID>] [--cvm <CVM_ID>] [--code-bin <PATH>] [--workspace <PATH>] [--identity-file <PATH>]
```

**Arguments**

- `<CVM_ID>` — Dev CVM UUID. Optional; resolves like the other session verbs (§3.2).

**Flags**

- `--cvm <CVM_ID>` — target Dev CVM UUID; equivalent to the positional (§3.2).
- `--code-bin <PATH>` — override which `code` binary to invoke. Default: `code` on `PATH`.
- `--workspace <PATH>` — same path semantics as `umbra claude --workspace` (§3.2). The path is resolved client-side against the remote home `/home/dev` and injected into the `vscode-remote://` folder URI so the editor opens that directory. When omitted, the value cached for the target CVM (§4.4) is used; when no cached value exists, the editor opens `/home/dev`.
- `--identity-file <PATH>` — pin a private SSH key for the editor's Remote-SSH connection. When supplied, the CLI MUST emit `IdentityFile <PATH>` and `IdentitiesOnly yes` into the managed SSH config so the editor's `ssh -F` invocation uses that key. When omitted, the CLI resolves the identity using the same order as `umbra ssh`: local key-id mapping, matching `default_ssh_identity`, then matching local sidecar public keys. When a key is resolved, the managed config MUST emit `IdentityFile <PATH>` and `IdentitiesOnly yes`; otherwise the editor's `ssh` falls back to default identities (`~/.ssh/id_*`) and any running agent. The user's `~/.ssh/config` is NOT consulted because the managed config uses `-F`.

**Output**

Spawns the local VS Code process and returns as soon as it is launched. No stdout payload. `--json` is ignored.

The CLI MUST resolve the target Dev CVM exactly like the other session verbs, materialize the per-CVM aTLS policy if needed, generate an Umbra-managed SSH config under the CLI config directory, and launch VS Code with a managed `ssh` wrapper at the front of `PATH`. The wrapper MUST invoke the system `ssh` with the same attested `ProxyCommand` used by `umbra ssh`; the CLI MUST NOT edit the user's `~/.ssh/config`.

**Exit** — `0` on successful launch; `1` if the binary is not found or fails to spawn; `2` on auth errors.

---

### `umbra cursor`

Open a local Cursor window connected to the Dev CVM via Remote SSH.

**Synopsis**

```
umbra cursor [<CVM_ID>] [--cvm <CVM_ID>] [--cursor-bin <PATH>] [--workspace <PATH>] [--identity-file <PATH>]
```

**Arguments**

- `<CVM_ID>` — Dev CVM UUID. Optional; resolves like the other session verbs (§3.2).

**Flags**

- `--cvm <CVM_ID>` — target Dev CVM UUID; equivalent to the positional (§3.2).
- `--cursor-bin <PATH>` — override which `cursor` binary to invoke. Default: `cursor` on `PATH`.
- `--workspace <PATH>` — same semantics as `umbra code --workspace` (§3.2).
- `--identity-file <PATH>` — same semantics as `umbra code --identity-file`. Pins the private SSH key Cursor's Remote-SSH connection uses; optional when a local key-id mapping, `default_ssh_identity`, local sidecar key, default identity, or agent identity matches a key installed on the target CVM.

**Output**

Spawns the local Cursor process and returns as soon as it is launched. No stdout payload. `--json` is ignored.

The CLI MUST resolve the target Dev CVM exactly like the other session verbs, materialize the per-CVM aTLS policy if needed, generate an Umbra-managed SSH config under the CLI config directory, and launch Cursor with a managed `ssh` wrapper at the front of `PATH`. The wrapper MUST invoke the system `ssh` with the same attested `ProxyCommand` used by `umbra ssh`; the CLI MUST NOT edit the user's `~/.ssh/config`.

Security boundary: the Remote SSH connection and processes started inside the Dev CVM are covered by the aTLS tunnel and Security-CVM egress policy. Cursor features that execute outside the Dev CVM, including provider-hosted agent tools such as WebFetch/WebSearch and browser/MCP integrations that use Cursor's own infrastructure or the local workstation, may still use the aTLS-protected editor/SSH channel to trigger remote IDE behavior and carry results back into the session. That does not make the external request a Dev-CVM egress event: if the public-web socket is opened by Cursor/local/provider infrastructure instead of by a process inside the Dev CVM network namespace, the Security CVM cannot filter or log it. Umbra MUST NOT claim those tool calls are controlled unless Cursor exposes a mode that forces them to execute inside the remote shell.

**Exit** — `0` on successful launch; `1` if the binary is not found or fails to spawn; `2` on auth errors.

---

### `umbra ps`

List active dtach sessions across the caller's running Dev CVMs.

**Synopsis**

```
umbra ps [<CVM_ID>] [--cvm <CVM_ID>] [--identity-file <PATH>]
```

**Behaviour**

A bare `umbra ps` lists sessions on **all of the caller's `RUNNING` Dev CVMs** (enumerated via `GET /cvms?state=running`, owner-scoped by the Console, §3.6), grouped by CVM. A `<CVM_ID>` positional or `--cvm <CVM_ID>` scopes to one CVM. Unlike the other CVM verbs, a bare `ps` does **not** fall back to `UMBRA_DEFAULT_CVM` / `default_cvm` — it covers every `RUNNING` CVM.

Every `RUNNING` CVM appears in the output. If its SSH/aTLS probe fails, the CVM is still listed, marked with a one-line error in place of its sessions — so `ps` always reflects every running CVM. A probe failure does not fail the command.

**Scope.** A caller only sees sessions on CVMs they can SSH into — their own. An admin with `CVM_MANAGE` can *list* every CVM but cannot read another developer's sessions: authorized keys are bound into RTMR3 at boot and cannot be added live (§6.1), and the Console keeps no session registry (sessions live only inside the CVM). Cross-developer session visibility would require a new Dev-CVM-to-Console reporting channel and is out of scope for v0.

**Flags**

- `<CVM_ID>` / `--cvm <CVM_ID>` — scope the listing to one Dev CVM UUID; when omitted, `ps` covers all of the caller's `RUNNING` Dev CVMs.
- `--identity-file <PATH>` — private key passed to `ssh(1)` as `-i <PATH>` for the probe, for this invocation only (never persisted as a default; only `cvm launch` writes `default_ssh_identity`).

**Output**

Default: one group per `RUNNING` CVM, labelled by CVM id, listing its sessions (session name, attached state, client-side alias if any, creation time) — or a one-line error if the probe failed. JSON: array of `{cvm_id, error, sessions: [...]}` objects (`error` is null on success). The `attached` field is a runtime probe (see §6.4), not first-class dtach metadata.

**Exit** — `0` on success (including CVMs listed with a probe error); `1` if enumerating the caller's CVMs fails; `2` on auth errors.

---

### `umbra attach <TARGET>`

Re-attach to an existing dtach session by name or alias.

**Synopsis**

```
umbra attach <TARGET> [--cvm <CVM_ID>] [--identity-file <PATH>]
```

**Arguments**

- `<TARGET>` — dtach session name or a session alias. A session alias carries the CVM it was created on, so it resolves without `--cvm` even on a non-default CVM.

**Flags**

- `--cvm <CVM_ID>` — target Dev CVM (UUID or alias); when omitted, resolves `UMBRA_DEFAULT_CVM` → `default_cvm` (§4.2). Passing `--cvm` explicitly with a session alias overrides the CVM stored in the alias (a warning is written to stderr).
- `--identity-file <PATH>` — pass a private key path through to `ssh(1)` as `-i <PATH>`.

**Output**

Attaches the user's terminal to the session. `--json` is ignored.

**Exit** — `0` on clean detach; `1` on unknown alias or missing session; `2` on auth errors.

---

### `umbra alias <KIND> ...`

Manage client-side aliases: short local names for the long identifiers the CLI otherwise requires. Four kinds share one `aliases.toml` (§4.4) — `cvm`, `profile`, and `ssh-key` map an alias to a Console resource UUID; `session` maps an alias to a dtach session bound to a specific CVM. An alias may be used anywhere the CLI expects that identifier: a `cvm` alias resolves in every CVM-targeting verb (§4.2), a `profile`/`ssh-key` alias in `--profile`/`--ssh-key` at `cvm launch`, and a `session` alias in `attach`/`kill`. Alias names are globally unique across all kinds, and each resource carries at most one alias.

**Synopsis**

```
umbra alias cvm      <CVM_ID>     <ALIAS>
umbra alias profile  <PROFILE_ID> <ALIAS>
umbra alias ssh-key  <SSH_KEY_ID> <ALIAS>
umbra alias session  <NAME>       <ALIAS> [--cvm <CVM_ID|ALIAS>] [--identity-file <PATH>]
umbra alias list
umbra alias rm       <ALIAS>
umbra alias rename   <OLD> <NEW> [--identity-file <PATH>]
umbra alias prune    [--dry-run] [--identity-file <PATH>]
```

**Creation (fail-fast).** `cvm`/`profile`/`ssh-key` validate the UUID format and confirm the resource exists on the Console (a Dev CVM GET, a profile GET, or a membership check against the caller's registered keys — the Console has no single-key GET) before recording; a resource that does not exist exits `1`. `session` resolves `--cvm` (a UUID or a CVM alias; when omitted, `UMBRA_DEFAULT_CVM` → `default_cvm`, §4.2), confirms over SSH that the session is live on that CVM, then stores `{session, cvm}`; a session alias whose name collides with a live session on that CVM is rejected (exit `1`) so it cannot shadow the real session. Any creation whose alias name is already in use exits `1`, and an alias name that is itself a UUID is rejected (exit `4`) since it could never be told apart from a raw id. A creation whose **target** already has an alias also exits `1`, naming the existing one: a resource carries a single alias — a UUID for `cvm`/`profile`/`ssh-key`, the `{session, cvm}` pair for `session` — which is what makes the reverse display below unambiguous. Use `rename` to change that alias's name, or `rm` then re-create to point the name elsewhere.

**`list`** — every alias, grouped by kind (same `> <group>` idiom as `ps`). In human output a session's CVM is shown by its alias when one exists (the raw UUID otherwise); `--json` emits the `aliases.toml` structure verbatim (always the raw UUID).

**Reverse display.** The read views label a Console record with the local alias the user actually types: `cvm list`, `profile list`, `key list`, `profile show` and `ps` render an `alias` row — the recorded name, `-` when the record has none, or the marker `unreadable` when `aliases.toml` cannot be read at all (see `docs/specs/cli-style.md` §7.2, the shared contract of §7.3/§7.4/§7.9/§7.22). This is local state, not a Console field: it appears in the human rendering only, never in `--json` (a script joins on `umbra alias list --json`).

An unreadable store never fails these commands — they render Console truth and exit `0` — and is never shown as `-`, which would claim every record has no alias. The **full** error is written once to stderr as a `[warn]` line naming the file, which also covers the case no cell can: an empty listing renders no card at all. UUID-backed targets are compared in canonical form, so an alias recorded with a non-canonical id (uppercase, braced, `urn:uuid:`, unhyphenated — all accepted at creation) still matches its record instead of silently reading as "no alias". Canonicalization applies to every id the store compares, records, or is handed — so the same resource typed in two forms is one resource, both for the single-alias rule above and for the auto-prunes of §3.4 below.

**`rm <ALIAS>`** — remove an alias by name; a name not found exits `1`.

**`rename <OLD> <NEW>`** — rename an alias, keeping what it points at. The target is not revalidated (it was valid when recorded); only the name changes. The kind is inferred from the old name; `NEW` must be free (exit `1` if taken) and a valid alias name. Renaming a **session** alias additionally probes its bound CVM so `NEW` cannot shadow a live dtach session (the same guard creation applies, exit `1` on a confirmed collision); `--identity-file` supplies the SSH key for that probe. If the probe cannot run (CVM unreachable, transient/auth failure) the rename warns and proceeds rather than blocking. The other kinds stay purely local. It is also how a resource's single alias is renamed. To instead repoint a name at a different resource, `rm` it and re-create.

**`prune [--dry-run]`** — reconcile the whole store against reality and drop the stale entries in one pass: `cvm`/`profile`/`ssh-key` aliases whose target is absent from the Console, and `session` aliases whose CVM is terminated/stopped or whose session is no longer live (one SSH probe per running CVM). Only **confirmed-absent** targets are removed — a reference fetch that fails (network/SSH) leaves that kind untouched and is reported, so a blip never deletes a good alias. `--dry-run` prints the plan without writing. Output: the removed `(alias, kind, reason)` rows; `--json` emits `{ dry_run, removed: [...] }`.

**Aliasing at the source (`--alias`).** The resource-creating verbs accept `--alias <NAME>` so the alias is recorded in the same step, without a later `umbra alias …`: `cvm launch --alias`, `profile create --alias`, `key add --alias`, and the session verbs `ssh`/`claude`/`codex --alias`. The name is validated and confirmed free **up front** (fail-fast — a bad or taken name aborts before anything is created), and for the session verbs — whose target is known before the session opens, and which `dtach -A` may well re-attach to an already-aliased session — the target is confirmed unaliased up front too, so the refusal precedes the SSH work. At the resource verbs the target cannot be checked up front (it does not exist yet) and is checked at the write instead, where a rejection is a `[warn]` and the create still exits `0`. The alias is then recorded once the resource exists (a session's alias is written at launch, since its name and CVM are already determined then, so no `ps` is needed to discover it — the anti-shadow probe of `alias session` still runs). `cvm launch --alias` requires waiting for completion (rejected with `--no-wait`, since the CVM id is not yet known), and `ssh --alias` conflicts with `--command` (a one-off command opens no session).

**Resolution safety net.** An alias points at a fixed id, so if that resource (or a session) later goes away the alias becomes stale. Two mechanisms keep this clean: (1) CLI-initiated lifecycle actions prune the matching aliases best-effort — `cvm terminate` drops the CVM alias **and** every session alias bound to it; `cvm stop` drops every session alias bound to it (a stopped CVM's sessions die — they live in its tmpfs `/run` — but its CVM alias stays, since it can be restarted); `key remove` drops the ssh-key alias; and `kill` drops the session alias. Note there is deliberately **no `cvm stop`-for-the-CVM-alias prune** (a stopped CVM is restartable) and **no profile prune** at all — there is no `umbra profile delete` command, so a profile alias is never auto-pruned and is cleaned only with `alias rm`/`alias prune`. (2) For anything the CLI cannot see (a deletion or stop done elsewhere), the underlying command revalidates the id at use time and reports a clear error, and the user removes the stale entry with `umbra alias rm` (or sweeps them all with `umbra alias prune`).

**Output**

One-line confirmation on create/rename/rm/prune. In `--json` mode, create emits an object with `kind`, `alias`, and either `target` or (`session`, `cvm`); `rename` emits `{kind, old, new}`; `rm` emits `{alias}`; `prune` emits `{dry_run, removed}`. Writes to the aliases file are atomic and serialized by an exclusive advisory lock across concurrent `umbra` processes, with the full creation check re-run under that lock (§4.4).

**Exit** — `0` on success; `1` on a missing alias, a duplicate alias name, a target that already has an alias, or a resource that does not exist; `2` on auth errors; `4` on invalid arguments.

---

### `umbra kill <TARGET>`

Kill a dtach session on the default CVM by name or alias.

**Synopsis**

```
umbra kill <TARGET> [--cvm <CVM_ID>] [--identity-file <PATH>]
```

**Arguments**

- `<TARGET>` — dtach session name or a session alias. A session alias carries the CVM it was created on, so it resolves without `--cvm` even on a non-default CVM.

**Flags**

- `--cvm <CVM_ID>` — target Dev CVM (UUID or alias); when omitted, resolves `UMBRA_DEFAULT_CVM` → `default_cvm` (§4.2). Passing `--cvm` explicitly with a session alias overrides the CVM stored in the alias (a warning is written to stderr).
- `--identity-file <PATH>` — pass a private key path through to `ssh(1)` as `-i <PATH>`.

**Output**

One-line confirmation. In `--json` mode, an object with `cvm_id`, `session_name`. On success, the session's alias (if any) is pruned from `aliases.toml`.

**Exit** — `0` on success; `1` on unknown alias or remote failure; `2` on auth errors.

### 3.3 Transport

### `umbra tunnel <TARGET>`

Pipe an aTLS tunnel between stdin/stdout and a Dev CVM. Designed as an `ssh(1)` `ProxyCommand` (see §6.2). Used implicitly by every session verb; users may also invoke it directly from `~/.ssh/config` to get `ssh`/`scp`/`rsync`/`git` working against any CVM FQDN.

**Synopsis**

```
umbra tunnel <TARGET>
```

**Arguments**

- `<TARGET>` — a CVM UUID (resolved to an FQDN via the Console) or a hostname (used directly). A UUID requires the caller to be logged in; an FQDN does not, since the tunnel contacts the CVM directly.

**Output**

Byte-transparent bidirectional copy between stdin/stdout and the attested TLS stream. No framing, no protocol layering, no informational output on either stream. `--json` is ignored.

**Exit** — `0` on a clean close by either side; `1` on connection or TLS failure; `2` on auth errors when resolving a UUID.

### 3.4 Resource management

Nested under noun subcommands (`cvm`, `key`, `profile`). All of these require a valid session.

### `umbra cvm list`

List CVMs the caller owns or can manage.

**Synopsis**

```
umbra cvm list [--state <STATE>]
```

**Flags**

- `--state <STATE>` (optional) — filter the listing by CVM lifecycle state. Fixed enum; an unknown value is rejected at argument-parse time (the accepted values are listed in `--help`). One of:
  - `alive` (the default when `--state` is omitted) — every non-terminated state: `provisioning`, `running`, `stopped`, `failed`.
  - `all` — every state, **including** `terminated`.
  - `terminated` — only terminated CVMs.
  - `provisioning` | `running` | `stopped` | `failed` — exactly that state.

  `--state` is optional with no client-side default: when omitted, the CLI sends no `state` query parameter (the Console applies its own `alive` default, §3.6) and the human rendering shows no `state` line in the `Filter:` header; when supplied — including an explicit `--state alive` — the value is sent and surfaced in the header (`docs/specs/cli-style.md` §7.2).

  `--state` only narrows the result by state; it does not change which CVMs the caller may see — that visibility is role-based (`docs/specs/console.md` §3.6) and unaffected by this flag. Filtering is performed server-side: the CLI forwards the value as the `state` query parameter and MUST NOT add, drop, or select rows locally.

**Output**

Default: human-readable rendering (§2.3) of each CVM record. JSON: array of CVM records. The human rendering also carries an `alias` row per record, from local state (§3.4 `umbra alias`, reverse display; `docs/specs/cli-style.md` §7.2); it is absent from `--json`.

Each record contains: CVM id, attached profiles (list of `{id, name}` pairs — a CVM is M:N with profiles, ≥ 1 always attached), FQDN (may be null if not yet provisioned), state, instance type, region, disk size (GB), installed SSH keys (list of `{id, label}` pairs), owner (`{id, email}`), `created_at`, `updated_at`. Owner is always populated; the email is denormalised by the Console from the user record on every read. Provider-specific identifiers (Phala app id, gateway host, etc.) are NOT surfaced — `docs/specs/console.md` §2.3 keeps them operator-internal.

Filtering by profile is done via the global `--profile` flag (§2.2); filtering by state via `--state` (above). The two compose (logical AND). When `--state` is supplied, the human rendering surfaces it in the `Filter:` header (`docs/specs/cli-style.md` §7.2); a bare `umbra cvm list` (default `alive`) shows no state line.

**Exit** — `0` on success; `1` on API error; `2` on auth errors.

---

### `umbra cvm instance-types`

List the machine types a CVM can launch on (name, family, vCPU, memory), served from the Console's instance-type catalog (`docs/specs/console.md` §3.6a). The normal read is cache-backed and never waits on the provider; `--refresh` asks the Console for one explicit provider fetch.

**Synopsis**

```
umbra cvm instance-types [--refresh]
```

**Flags**

- `--refresh` — fetch the latest catalog from the provider instead of the Console cache (bounded inline fetch, Console-side 30 s timeout; slower, may fail). On failure the current cache is served and the failure is reported in the freshness note / `catalog` metadata.

**Output**

Default: the table defined in `docs/specs/cli-style.md` §7.34 (`NAME / FAMILY / VCPU / MEMORY / NOTES`; `default` marks the Dev CVM server default, `not supported yet` marks non-launchable (GPU) types). The provider `hourly_rate` is not shown in the table but stays in the `--json` payload. When the catalog needs explaining — stale, bootstrap fallback, failed or in-flight refresh — a muted freshness note is emitted on stderr (§7.34); a fresh catalog prints no note.

JSON: the Console response restricted to the fields the CLI declares (strict whitelist, `docs/specs/cli-style.md` §11.7) — `{"instance_types": [{name, family, vcpu, memory_gb, hourly_rate, currency, default, launchable}], "catalog": {source, fetched_at, stale, refresh_in_progress, last_refresh_error, field_miss_counts}}`. The freshness metadata lives in the payload, so `--json` emits no stderr note.

GPU-family types are listed for visibility but not launchable yet (payload `launchable: false`); a launch attempt is rejected (`422 instance_type_not_launchable`). They become launchable once a measured GPU dstack image exists in the Umbra config — the catalog reflects the provider's offer, not end-to-end Umbra support.

**Exit** — `0` on success (including when a `--refresh` fetch failed but the cache was served); `1` on API error; `2` on auth errors.

---

### `umbra cvm launch`

Provision a new Dev CVM and attach one or more profiles to it. Async (§2.6): the Console runs the launch saga (Phala deploy + Cloudflare DNS + initial policy materialization for the new CVM) out of band; the CLI polls until the operation reaches a terminal state. The Security CVM picks up the new CVM's policy on its next pull cycle (~5 s) after the saga completes.

**Synopsis**

```
umbra cvm launch [--ssh-key <KEY_ID> [--ssh-key <KEY_ID> ...]]
                    [--profile <PROFILE_ID> [--profile <PROFILE_ID> ...]]
                    [--instance-type <TYPE>]
                    [--region <REGION>]
                    [--disk-size <GB>]
                    [--no-wait]
                    [--wait-timeout-seconds <SECONDS>]
```

**Flags**

- `--ssh-key <KEY_ID>` (optional, repeatable) — one or more SSH key IDs from `umbra key list` to install on the CVM. If omitted, the CLI lists the caller's registered keys and installs them when at least one has a matching remembered or locally discoverable private key. If no registered key has a matching local private key, the CLI creates a local `~/.ssh/id_ed25519` keypair if neither `~/.ssh/id_ed25519` nor `~/.ssh/id_ed25519.pub` exists, registers the public key with label `default`, records the local private-key path in `${config_dir}/ssh-identities.toml`, and installs that locally usable key as well. If a public key exists without the matching private key, the CLI MUST choose a non-conflicting `~/.ssh/umbra_ed25519[...].pub` path instead of overwriting the existing public key. The local key generation path MUST keep `ssh-keygen` output off stdout so success payloads remain parseable and MUST NOT overwrite or delete an existing SSH key file.
- `--profile <PROFILE_ID>` (optional, repeatable, 1..16) — one or more profiles to attach at launch (Console caps the request body at 16 entries; §3.6 of `docs/specs/console.md`). The CVM's effective policy is the field-typed merge of every attached profile's policy. The caller MUST be a member of every profile listed; a non-member receives a `403` and the command exits `1`. If `--profile` is omitted but `default_profile` is configured (§2.2), the default is used as a single attachment. If neither is set, the CLI lists visible profiles and auto-selects the single assigned profile when exactly one exists. This is the normal path when an admin has added the user to one profile. With zero assigned profiles or more than one assigned profile, the command exits `4` with guidance to ask an admin for a profile or rerun with `--profile <PROFILE_ID>`.
- `--instance-type <TYPE>` — instance type (vCPU/RAM); `umbra cvm instance-types` lists the valid set. Default: the `default_instance_type` config key, falling back to a server-selected default if unset. The Console validates the resolved value against its instance-type catalog (`docs/specs/console.md` §3.6a); an unknown name is a `422 VALIDATION_ERROR` whose message enumerates the valid types.
- `--region <REGION>` — region. Default: the `default_region` config key, falling back to the Console's server-side chain (`DEV_CVM_DEFAULT_REGION`, then `PHALA_REGION`) if unset.
- `--disk-size <GB>` (optional) — root disk size in whole GB. **No client-side default:** when omitted the CLI sends no disk size and the Console applies `DEV_CVM_DEFAULT_DISK_GB` (its server default matches the provider's own default, so behavior is unchanged). The requested value is bounded server-side by `[DEV_CVM_MIN_DISK_GB, DEV_CVM_MAX_DISK_GB]` (an out-of-range request is a `422`) and is further constrained by the `disk_gb_per_cvm` and `disk_gb_total` quotas (`umbra quota get`/`set`; `docs/specs/console.md` §3.13); exceeding a quota yields a `403 QUOTA_EXCEEDED` and the command exits `1`. Resizing an existing CVM's disk is a separate concern (not launch-time) and is out of scope here.
- `--no-wait` / `--wait-timeout-seconds <SECONDS>` — see §2.6.

A Dev CVM MUST attach ≥ 1 profile; the Console refuses an empty list. The caller MUST hold `CVM_LAUNCH`, which the admin grants when onboarding the user. The caller's entity MUST have a live Security CVM (one per entity); if not, the command exits `1` with a message indicating an admin must run `umbra security-cvm launch` first.

**Key rotation = relaunch.** A Dev CVM's authorized SSH keys are bound into RTMR3 at boot (`authorised_ssh_keys_sha256` in the `rtmr3_binding` payload; `docs/specs/dev-cvm.md` §6.1, `docs/specs/console.md` §10.4a) and cannot be edited live. Rotating keys means `umbra cvm terminate <CVM_ID>` followed by a fresh `umbra cvm launch --ssh-key <NEW_KEY_ID> ...`; the new CVM has a new `cvm_id`, FQDN, and per-CVM aTLS policy file.

**Output**

By default, waits for the launch operation per §2.6 and prints the final CVM record (same fields as `cvm list`, including the `profiles` list) once it reaches `RUNNING`. With `--no-wait`, prints the operation handle and exits `0`.

On a waited successful launch, the CLI writes `default_cvm = <CVM_ID>` to `config.toml`. If launch used exactly one profile and no default profile was already configured, it also writes `default_profile = <PROFILE_ID>`. When the CLI knows which local private key can authenticate to the launched CVM, it also writes `default_ssh_identity = <PATH>` as a convenience fallback; key-specific identity paths are stored in `${config_dir}/ssh-identities.toml` when learned through `key add` or automatic key creation. This lets follow-on session verbs such as `umbra ssh`, `umbra code`, `umbra cursor`, `umbra claude`, and `umbra codex` run without a CVM id or manual SSH key selection.

**Per-CVM aTLS policy file.** Every Dev CVM has its own aTLS policy (`docs/specs/dev-cvm.md` §8.2). On `succeeded`, the Console's launch/update outcome is `<CVMResult>` (`docs/specs/console.md` §2.3): `{cvm: <CVM>, policy_bundle: <PolicyBundle>}`. The `<PolicyBundle>` carries the full Shade/dstack `app_compose` object measured by dstack (including `docker_compose_file` with `${VAR}` placeholders — runtime values flow through the provider env-file and bind into RTMR3, `docs/specs/console.md` §10.4a), the golden bootchain measurements (`mrtd`, `rtmr0..2`, `os_image_hash`), and the per-CVM `rtmr3_binding` payload (`cvm_id`, `console_url`, `security_cvm_fqdn`, `security_cvm_proxy_port`, plus SHA-256 digests of the proxy/control bearers, SC CA, and authorized keys). The CLI writes `${config_dir}/cvms/<cvm_id>.atls-policy.json` (mode `0600`) directly from the returned current bundle: `app_compose := parse(bundle.app_compose_json)` when present, otherwise `bundle.app_compose`, with `app_compose.docker_compose_file := bundle.compose_template`, `expected_bootchain := bundle.expected_bootchain`, `os_image_hash := bundle.os_image_hash`, `rtmr3_binding := bundle.rtmr3_binding`. `app_compose_json` is authoritative because `atlas-rs` hashes the exact JSON serialization order Shade generated, while JSONB object storage is not order-preserving. No CLI-side rendering is required — `atlas-rs` validates the quote's MRTD against the template hash and `RTMR3 == SHA-384(JCS(rtmr3_binding))` (RFC 8785). A deploy-plane swap of any bound value (a different developer's keys, another CVM's proxy/control bearer, a hostile Console refresh origin, or a hostile SC CA) causes verification to fail at first tunnel as an RTMR3 mismatch. With `--no-wait`, the policy file is NOT written by `cvm launch`; the next `umbra tunnel <CVM_ID>` lazily fetches the active bundle via `GET /cvms/{cvm_id}/policy-bundle` (`docs/specs/console.md` §3.6) and writes the file (§6.1).

JSON without `--no-wait`: the CVM record extended with `policy_file_path` (the per-CVM file location). JSON with `--no-wait`: the operation handle (§2.6).

**Exit** — `0` on `succeeded`; `1` on API error, terminal `failed` (the typed `error_code` is rendered on stderr per §2.6 — `PHALA_DEPLOY_FAILED`, `CLOUDFLARE_TXT_FAILED`, `CLOUDFLARE_CNAME_FAILED` are documented values; the full catalog lives in `docs/specs/console.md` §10.5), no Security CVM in the entity, caller is not a member of one of the listed profiles, unknown profile, or local policy-render failure; `2` on auth errors; `3` on `--wait-timeout-seconds` elapsed; `4` on missing profiles or invalid arguments.

---

### `umbra cvm update [<CVM_ID>]`

Update an existing Dev CVM deployment in place from the current Console-side Dev CVM image/config. Async (§2.6): the Console re-renders the compose/env material, asks the CVM provider to update the existing deployment while preserving named volumes, re-attests the CVM, waits for the Security CVM to learn the new proxy bearer, and returns the refreshed policy bundle. The update also rotates the Dev-control bearer used by Console refresh reads.

**Synopsis**

```
umbra cvm update [<CVM_ID>] [--cvm <CVM_ID>] [--no-wait] [--wait-timeout-seconds <SECONDS>]
```

**Arguments**

- `<CVM_ID>` — Dev CVM UUID. Optional; resolves positional → `--cvm` → `UMBRA_DEFAULT_CVM` → `default_cvm` (§4.2).

**Output**

Default: waits for the operation and prints `updated <CVM summary> policy_file=<path>`. If the returned `<PolicyBundle>` differs from an existing local per-CVM policy file, the CLI explains on stderr that the local file is trusted measurement material and asks before replacing it. If the user declines, or if the command is running in JSON/non-interactive mode, the CLI leaves the local file unchanged and exits `1` with a message telling the user to rerun from an interactive terminal if they trust the new measurement. JSON without `--no-wait`: the CVM record extended with `policy_file_path` and `policy_file_status`. With `--no-wait`, prints the operation handle.

On success, the CLI writes `${config_dir}/cvms/<cvm_id>.atls-policy.json` from the returned current `<PolicyBundle>` only when the file is missing, unchanged, or the user explicitly confirmed replacement. An in-place Security CVM policy or CA change does not by itself require this command for a refresh-capable Umbra runtime: the Dev CVM forwarder pulls both from the RTMR3-bound Console origin and the sandbox watcher replaces the rotated CA at runtime. `cvm update` remains the full rebind path for current, provider-managed deployments when launch-bound material changes, including the SC FQDN, a per-Dev proxy/control bearer, or the RTMR3 binding. Before submitting, the CLI MUST reject a fetched CVM whose `error_reason` is `SECURITY_CVM_REBIND_REQUIRED` with the replacement guidance from §3.2; it must never send that legacy resource to the renamed Console's update route.

**Exit** — `0` on `succeeded`; `1` on API error, the local legacy-marker guard, terminal `failed` (`PROVIDER_UPDATE_FAILED`, `ATTESTATION_IMAGE_MISMATCH`, `SC_PULL_TIMEOUT`, and related Console §10.5 codes), or local policy-file write/render failure; `2` on auth errors; `3` on wait timeout; `4` on invalid `<CVM_ID>`.

---

### `umbra cvm attach [<CVM_ID>]`

Attach a profile to a running Dev CVM. The Console recomputes the CVM's combined policy and bumps `policy_version` synchronously; the Security CVM picks up the change on its next pull cycle (~5 s) — there is no synchronous push to the SC (`docs/specs/console.md` §8.5).

**Synopsis**

```
umbra cvm attach [<CVM_ID>] [--cvm <CVM_ID>] --profile <PROFILE_ID>
```

**Arguments**

- `<CVM_ID>` — Dev CVM UUID. Optional; resolves positional → `--cvm` → `UMBRA_DEFAULT_CVM` → `default_cvm` (§4.2).

**Flags**

- `--profile <PROFILE_ID>` (required, single) — the profile to attach. The caller MUST be a member of this profile.

**Output**

Default: a one-line confirmation including the new `profiles` set (`policy_version` is bumped). JSON: the updated CVM record.

**Exit** — `0` on success; `1` on API error, including caller-not-member-of-profile (HTTP 403) or CVM `TERMINATED`; `2` on auth errors; `4` on invalid arguments.

---

### `umbra cvm detach [<CVM_ID>]`

Detach a profile from a running Dev CVM. The Console recomputes the CVM's combined policy and bumps `policy_version` synchronously; the Security CVM picks up the change on its next pull cycle (~5 s). Refuses to remove the last attached profile (a CVM MUST always have ≥ 1).

**Synopsis**

```
umbra cvm detach [<CVM_ID>] [--cvm <CVM_ID>] --profile <PROFILE_ID>
```

**Arguments**

- `<CVM_ID>` — Dev CVM UUID. Optional; resolves positional → `--cvm` → `UMBRA_DEFAULT_CVM` → `default_cvm` (§4.2).

**Flags**

- `--profile <PROFILE_ID>` (required, single) — the profile to detach. The caller does NOT need to be a member of this profile (detaching is a strict policy reduction, never an escalation).

**Output**

Default: a one-line confirmation. JSON: the updated CVM record.

**Exit** — `0` on success; `1` on API error including "last profile" refusal (`details.state="last_profile"` — operator must terminate instead); `2` on auth errors; `4` on invalid arguments.

---

### `umbra cvm start [<CVM_ID>]`

Start a stopped CVM. The CVM owner may start their own CVM; `CVM_MANAGE` is required to start another user's CVM in the same entity.

**Synopsis**

```
umbra cvm start [<CVM_ID>] [--cvm <CVM_ID>]
```

**Arguments**

- `<CVM_ID>` — Dev CVM UUID. Optional; resolves positional → `--cvm` → `UMBRA_DEFAULT_CVM` → `default_cvm` (§4.2).

**Output**

Default: one-line confirmation with the CVM's current state. JSON: the full CVM record.

**Exit** — `0` on success; `1` on API error or unreachable CVM; `2` on auth errors.

---

### `umbra cvm stop [<CVM_ID>]`

Stop a running CVM. The CVM owner may stop their own CVM; `CVM_MANAGE` is required to stop another user's CVM in the same entity.

**Synopsis / Output / Exit** — same shape as `cvm start`, plus `--cvm <CVM_ID>`.

**Arguments** — as a destructive verb, `stop` requires an **explicit** target: a `<CVM_ID>` positional or `--cvm <CVM_ID>`. It does NOT fall back to `UMBRA_DEFAULT_CVM` or `default_cvm`; missing both exits `4` (usage).

---

### `umbra cvm terminate [<CVM_ID>]`

Soft-delete a CVM. Deprovisions DNS; the record remains in the remote database in `TERMINATED` state. Async (§2.6): Phala terminate plus DNS deprovisioning can take well over the standard HTTP-client timeout, so the Console runs the saga out of band. The CVM owner may terminate their own CVM; `CVM_MANAGE` is required to terminate another user's CVM in the same entity.

**Synopsis**

```
umbra cvm terminate [<CVM_ID>] [--cvm <CVM_ID>] [--no-wait] [--wait-timeout-seconds <SECONDS>]
```

**Arguments**

- `<CVM_ID>` — Dev CVM UUID. As a destructive verb, `terminate` requires an **explicit** target: the positional or `--cvm <CVM_ID>`. It does NOT fall back to `UMBRA_DEFAULT_CVM` or `default_cvm`; missing both exits `4` (usage).

**Flags**

- `--no-wait` / `--wait-timeout-seconds <SECONDS>` — see §2.6.

**Output**

By default, waits for the terminate operation per §2.6 and prints the final CVM record (`state=TERMINATED`). With `--no-wait`, prints the operation handle.

**Exit** — `0` on `succeeded` (including when the CVM was already `TERMINATED` — the operation finishes immediately); `1` on API error, unknown CVM, or terminal `failed`; `2` on auth errors; `3` on `--wait-timeout-seconds` elapsed.

---

### `umbra key list`

List SSH public keys registered by the caller.

**Synopsis**

```
umbra key list
```

**Output**

Default: human-readable rendering (§2.3) of each key record. JSON: array of key records. The human rendering also carries an `alias` row per record, from local state (§3.4 `umbra alias`, reverse display; `docs/specs/cli-style.md` §7.2); it is absent from `--json`.

Each record contains: key id (UUID), label, fingerprint, algorithm, creation time.

**Exit** — `0` on success; `1` on API error; `2` on auth errors.

---

### `umbra key add`

Register a new SSH public key.

**Synopsis**

```
umbra key add --label <LABEL> [--file <PATH>] [--identity-file <PATH>]
```

**Flags**

- `--label <LABEL>` (required) — human-readable label (e.g. `"laptop"`).
- `--file <PATH>` — path to the public key file. When omitted, the key is read from stdin.
- `--identity-file <PATH>` — local private key file corresponding to the public key. When omitted and `--file` points to a `*.pub` file, the CLI infers the sibling private-key path by removing the `.pub` suffix and records it when it exists and matches the public-key fingerprint. When omitted and no matching private key can be inferred, the key is still registered and the CLI prints a warning; users can pass this flag on a future `key add` for the same local key material if they want automatic SSH/editor identity selection on this machine. An explicitly supplied path MUST exist and match the public key.

**Output**

Default: one-line confirmation (key id and fingerprint). JSON: the created key record.

**Exit** — `0` on success; `1` on I/O failure, API error, or malformed key; `2` on auth errors; `4` on missing label.

---

### `umbra key remove <KEY_ID>`

Deregister an SSH public key. **One-way revocation:** removing a key prevents it from being installed on any *future* Dev CVM launches but does NOT revoke the key from CVMs where it was installed at launch time. To revoke access to a running CVM, terminate it and launch a replacement with the new key set (see `docs/specs/console.md` §3.2).

**Synopsis**

```
umbra key remove <KEY_ID>
```

**Arguments**

- `<KEY_ID>` — key UUID from `umbra key list`.

**Output**

Default: one-line confirmation. JSON: `{"key_id": "<uuid>"}`.

**Exit** — `0` on success; `1` on API error or unknown id; `2` on auth errors.

---

### `umbra secret set <NAME>`

Register or update one of the caller's per-user, host-bound secrets (`PUT /me/secrets/{name}`, `docs/specs/console.md` §3.2). Profiles reference the secret by name via `secret_injections[*].value_from` (`docs/specs/console.md` §2.3); at launch the Console injects the **CVM owner's** value.

**Synopsis**

```
umbra secret set <NAME> --host <HOST> [--host <HOST> ...] [--value-file <PATH>]
```

**Arguments**

- `<NAME>` — secret name, `[A-Za-z0-9._:-]{1,100}`.

**Flags**

- `--host <HOST>` (required, repeatable, ≤ 16) — host binding the secret may be injected into: an exact lowercase host (`api.slack.com`), a `*.suffix` wildcard (`*.slack.com`; the apex is NOT covered — list it separately), or the literal `*` as an explicit opt-out of binding. The Console drops any injection whose `match.host` falls outside the binding.
- `--value-file <PATH>` — read the secret value from a file.

**Value sourcing.** The value is read from `--value-file` or stdin (interactive stdin prints a prompt to stderr, then reads until EOF). Only trailing newlines are stripped. The value MUST NOT be accepted on argv (it would leak via `ps` and shell history) and never appears in output, logs, or the URL. Values are limited to 4096 characters with no CR/LF/NUL.

**Output**

Default: confirmation block with the name and host bindings. JSON: the `<UserSecret>` resource (never the value).

**Exit** — `0` on success; `1` on API error (including the 65-secret cap); `2` on auth errors; `4` on invalid name/host/value.

---

### `umbra secret list`

List the caller's secret names, host bindings, and timestamps (`GET /me/secrets`). Values are write-only and never shown.

**Synopsis**

```
umbra secret list [--json]
```

**Output**

Default: one card per secret (name, hosts, created, updated). JSON: array of `<UserSecret>` resources.

**Exit** — `0` on success; `2` on auth errors.

---

### `umbra secret remove <NAME>`

Delete one of the caller's secrets (`DELETE /me/secrets/{name}`). Running CVMs whose attached profiles reference the name lose the injection at the Security CVM's next control pull; requests to the matching destinations then fail at the upstream (401), not at the proxy.

**Synopsis**

```
umbra secret remove <NAME>
```

**Output**

Default: one-line confirmation. JSON: `{"name": "<name>"}`.

**Exit** — `0` on success; `1` on API error or unknown name; `2` on auth errors; `4` on an invalid name.

---

### `umbra profile create <NAME>`

Create a profile in the caller's entity. The CLI sends a fresh `Idempotency-Key`.

**Synopsis**

```
umbra profile create <NAME> [--description <TEXT>]
```

**Arguments**

- `<NAME>` — human-readable profile name, 1..100 chars after trimming. Cannot collide with another live profile in the entity.

**Flags**

- `--description <TEXT>` — optional free-text description, ≤ 1000 chars.

**Output**

Default: one-line confirmation. JSON: the created profile record with an empty policy and `assigned: false`.

**Exit** — `0` on success; `1` on API error (HTTP 403 if the caller lacks `USER_MANAGE`, `409` on name collision); `2` on auth errors; `4` on malformed input.

---

### `umbra profile list`

List the profiles visible to the caller within their entity (the profiles they are assigned to, plus — for a `USER_MANAGE` caller — every profile in the entity).

**Synopsis**

```
umbra profile list [--assigned <yes|no>]
```

**Flags**

- `--assigned <yes|no>` (optional) — filter the listing by whether the current user is a member of the profile. Fixed enum; an unknown value is rejected at argument-parse time (the accepted values are listed in `--help`). One of:
  - `yes` — only profiles you are a member of.
  - `no` — only profiles you are not a member of.

  `--assigned` is optional with no client-side default: when omitted, the CLI sends no `assigned` query parameter (the Console lists every visible profile, §3.6) and the human rendering shows no `assigned` line in the `Filter:` header; when supplied, the value is sent and surfaced in the header (`docs/specs/cli-style.md` §7.3).

  `--assigned` only narrows the result by membership; it does not change which profiles the caller may see — that visibility is role-based (`docs/specs/console.md` §3.6) and unaffected by this flag. Filtering is performed server-side: the CLI forwards the value as the `assigned` query parameter and MUST NOT add, drop, or select rows locally.

**Output**

Default: human-readable rendering (§2.3) of each profile record, including the policy summary and the list of attached Dev CVMs (the §3.6 `umbra status` command groups by CVM; `profile list` groups by profile). JSON: array of profile records. The human rendering also carries an `alias` row per record, from local state (§3.4 `umbra alias`, reverse display; `docs/specs/cli-style.md` §7.2); it is absent from `--json`.

Each record contains: profile id, name, description, policy (object — treated as opaque by the CLI), `attached_cvms` (capped at 100 entries; each entry is `{id, machine_id, state}`), `attached_cvm_count` (precise count), `created_at`, `updated_at`.

**Exit** — `0` on success; `1` on API error; `2` on auth errors.

---

### `umbra profile show`

Show the full profile record, including its policy and the list of attached Dev CVMs.

**Synopsis**

```
umbra profile show
```

The target profile is taken from the global `--profile` flag; if absent, the resolved `default_profile` is used. If neither is set, the command exits `4`.

**Output**

Default: human-readable rendering (§2.3) of the profile record. The `policy` field is rendered as pretty-printed JSON. JSON: the profile record (same fields as `profile list`). The human rendering also carries an `alias` row per record, from local state (§3.4 `umbra alias`, reverse display; `docs/specs/cli-style.md` §7.2); it is absent from `--json`.

**Exit** — `0` on success; `1` on API error; `2` on auth errors; `4` on missing profile.

---

### `umbra profile configure`

Update profile fields. Partial-update semantics: any flag present updates the corresponding field; absent flags leave the current value unchanged.

Profiles carry a typed security policy (`egress_boundary`, `allowed_destinations`, `blocked_destinations`, `secret_patterns`, `secret_injections`, `sandbox_env`). The CLI surfaces the policy as a JSON object loaded from a file via `--policy-file`; typed flags (e.g. `--allow-host`, `--block-host`, `--inject-secret`) are out of scope for v0.

The Console gates this command on `USER_MANAGE`; non-administrators receive HTTP 403 and exit `1`. Updating `--policy-file` writes the new policy and bumps `policy_version` on every Dev CVM that has this profile attached, synchronously from the Console's perspective. The Security CVM converges on the new effective policy on its next pull cycle (~5 s — see `docs/specs/console.md` §8.5).

Other ideas for a future revision:

- Profile templates kept on the remote DB.
- Typed policy flags (`--allow-host`, `--block-host`, `--inject-secret`) so operators don't need to author JSON for common edits.

**Synopsis**

```
umbra profile configure
                    [--name <NAME>]
                    [--description <TEXT>]
                    [--policy-file <PATH>]
```

The target profile is taken from the global `--profile` flag; if absent, the resolved `default_profile` is used. If neither is set, the command exits `4`.

**Flags**

All flags are optional; any flag that is present updates the corresponding field, any flag that is absent leaves the current value unchanged (partial update semantics).

- `--name <NAME>` — human-readable profile name. Cannot collide with another live profile in the entity (HTTP 409 → exit `1`).
- `--description <TEXT>` — free-text description, ≤ 1000 chars.
- `--policy-file <PATH>` — path to a JSON file containing the new policy document. Replaces the profile's `policy` field in its entirety. Use `-` to read from stdin. The CLI only validates that the file parses as a JSON object; the Console validates the policy schema, stores any `secret_injections[*].value` as encrypted write-only secret material, and returns a redacted policy shape.

**Output**

Default: human-readable rendering (§2.3) of the updated profile record, highlighting the fields that changed. JSON: the full profile record after the update.

**Exit** — `0` on success; `1` on API error (HTTP 403 if the caller lacks `USER_MANAGE`, `409` on name collision); `2` on auth errors; `4` on missing profile or invalid flag values.

---

### `umbra entity add <DOMAIN>`

Create a tenant entity (`POST /entities`) after bootstrap. Gated on `PLATFORM_OPERATOR`. The CLI sends a fresh `Idempotency-Key`.

**Synopsis**

```
umbra entity add <DOMAIN> --name <NAME>
```

**Arguments**

- `<DOMAIN>` — entity email domain. Lowercased client-side before submission; Console also lowercases server-side.

**Flags**

- `--name <NAME>` — display name for the entity.

**Output**

Default: one-line confirmation (`id`, `name`, `domain`, `created_at`). JSON: the created `<Entity>` record.

**Exit** — `0` on success; `1` on API error (HTTP 403 lacking `PLATFORM_OPERATOR`, HTTP 409 `domain_taken`); `2` on auth errors; `4` on empty name/domain or malformed server-side validation.

---

### `umbra entity list`

List tenant entities (`GET /entities`). Gated on `PLATFORM_OPERATOR`.

**Synopsis**

```
umbra entity list [--limit <N>] [--cursor <CURSOR>]
```

**Flags**

- `--limit <N>` — page size, 1..500. Default: 100.
- `--cursor <CURSOR>` — opaque cursor from the previous response.

**Output**

Default: one human-readable row per entity. If Console returns a next cursor, it is printed to stderr. JSON: `{"entities": [<Entity>, ...], "next_cursor": <string|null>}`.

**Exit** — `0` on success; `1` on API error; `2` on auth errors; `4` on out-of-range limit or malformed cursor.

---

### `umbra user add <EMAIL>`

Add a user to the caller's entity by default, or to the entity named by `--entity`. The Console creates the user record (`POST /entities/{id}/users`). In the v0 onboarding flow, admins should run this before the developer's first login, grant `CVM_LAUNCH`, and add the user to the intended profile. Optional flags attach the user to one or more profiles and/or grant initial permissions in the same call. Gated on `USER_MANAGE`; granting any permission additionally requires `PERMISSION_MANAGE` (T-14). Cross-entity onboarding additionally requires `PLATFORM_OPERATOR`.

**Synopsis**

```
umbra user add <EMAIL>
                  [--entity <ENTITY_ID>]
                  [--name <NAME>]
                  [--profile <PROFILE_ID>]...
                  [--permission <PERMISSION>]...
```

**Arguments**

- `<EMAIL>` — the user's primary email. The domain MUST match one of the entity's allowed domains (HTTP 422 `email_domain_mismatch` otherwise).

**Flags**

- `--entity <ENTITY_ID>` — entity UUID to add the user to. Defaults to the caller's session entity. Supplying a different entity is the platform-onboarding path after `umbra entity add`; the Console gates it on `PLATFORM_OPERATOR` via the target entity check.
- `--name <NAME>` — display name sent to `POST /entities/{id}/users` (Console §3.3 requires the field). When omitted, the CLI derives the value from the local-part of `<EMAIL>` (e.g. `jane.doe@example.com` → `jane.doe`). Max 100 characters; CR/LF/TAB rejected by the Console with `422 VALIDATION_ERROR`.
- `--profile <PROFILE_ID>` — repeatable. Add the new user to each listed profile via `POST /profiles/{id}/users` (issued after the user is created). Partial failure leaves the user in the entity but exits `1` with a typed error.
- `--permission <PERMISSION>` — repeatable. Initial permissions for the user; sent verbatim in the `POST /entities/{id}/users` body. See §2.7 for the permission enum.

**Output**

Default: one-line confirmation (`user_id`, `email`, `state=active`). JSON: the created user record (`id`, `email`, `state`, `entity_id`, `created_at`).

**Exit** — `0` on success; `1` on API error (HTTP 403 lacking `USER_MANAGE`, HTTP 403 lacking `PERMISSION_MANAGE` when `--permission` is set, HTTP 409 `email_taken`, HTTP 422 `email_domain_mismatch`, partial failure on `--profile`/`--permission`); `2` on auth errors; `4` on missing or malformed email.

---

### `umbra user list`

List users in the caller's entity (`GET /entities/{id}/users`). Gated on `USER_MANAGE`.

**Synopsis**

```
umbra user list [--status <active|deactivated|erased>] [--assigned <yes|no>]
```

**Flags**

- `--status <active|deactivated|erased>` (optional) — filter the listing by account status. Fixed enum; an unknown value is rejected at argument-parse time (the accepted values are listed in `--help`). One of:
  - `active` — only active users (not deactivated, not erased; the default listing excludes only erased users).
  - `deactivated` — only deactivated, non-erased users.
  - `erased` — only erased users (matches soft-deleted records the default listing hides).
- `--assigned <yes|no>` (optional) — filter the listing by whether the user belongs to at least one profile. One of:
  - `yes` — only users who belong to ≥ 1 profile.
  - `no` — only users who belong to no profile.

  Both flags are optional with no client-side default and compose (logical AND): when omitted, the CLI sends no corresponding query parameter (the Console lists all non-erased users with any membership, §3.6) and the human rendering shows no matching line in the `Filter:` header; when supplied, each value is sent and surfaced in the header (`docs/specs/cli-style.md` §7.1). Filtering is performed server-side: the CLI forwards `status` / `assigned` as query parameters and MUST NOT add, drop, or select rows locally.

**Output**

Default: human-readable rendering (§2.3) of each user record. JSON: array of user records.

Each record contains: `id`, `email`, `state` (`active` / `deactivated` / `erased`), profile memberships (list of `{id, name}`), permission grants (list of permission names), `created_at`, `last_login_at`.

**Exit** — `0` on success; `1` on API error (HTTP 403 when the caller lacks `USER_MANAGE`); `2` on auth errors.

---

### `umbra user show <USER_ID>`

Show a single user record (`GET /entities/{id}/users/{user_id}`). Gated on `USER_MANAGE`.

**Synopsis**

```
umbra user show <USER_ID>
```

**Output**

Default: human-readable rendering (§2.3) of the user record. JSON: same fields as `user list`.

**Exit** — `0` on success; `1` on API error or unknown id; `2` on auth errors.

---

### `umbra user deactivate <USER_ID>`

Deactivate a user (`POST /entities/{id}/users/{user_id}/actions/deactivate`). The routine offboarding action: refresh tokens are revoked, in-flight access tokens are denylisted, the user can no longer log in, but their resources stay running. Reversible via `umbra user reactivate`. Gated on `USER_MANAGE`. Does NOT block on owned live Dev CVMs — the user's CVMs continue to run; an admin with `CVM_MANAGE` handles them separately if needed.

**Synopsis**

```
umbra user deactivate <USER_ID>
```

**Output**

Default: one-line confirmation. JSON: the updated user record (`state="deactivated"`).

**Exit** — `0` on success; `1` on API error (HTTP 403 when the caller lacks `USER_MANAGE`, HTTP 409 `already_deactivated` or `already_erased`); `2` on auth errors.

---

### `umbra user reactivate <USER_ID>`

Reactivate a deactivated user (`POST /entities/{id}/users/{user_id}/actions/reactivate`). Profile memberships, permission grants, SSH keys, and CVM ownership are unchanged from deactivation — they were never touched. Gated on `USER_MANAGE`.

**Synopsis**

```
umbra user reactivate <USER_ID>
```

**Output**

Default: one-line confirmation. JSON: the updated user record (`state="active"`).

**Exit** — `0` on success; `1` on API error (HTTP 403, HTTP 409 `not_deactivated` or `already_erased`); `2` on auth errors.

---

### `umbra user erase <USER_ID>`

**Irreversible.** Erase a user's PII (`DELETE /entities/{id}/users/{user_id}`). Tombstones the row, hard-deletes OAuth identities, SSH keys, permission grants, profile memberships, and refresh tokens; redacts PII columns in audit rows (`docs/specs/console.md` §11.9). The user MUST own zero live Dev CVMs (Console returns `409 CONFLICT` with `details.state="user_owns_cvms"` otherwise — terminate them first via `umbra cvm terminate`). Gated on caller-is-self OR `PLATFORM_OPERATOR` — `USER_MANAGE` is deliberately not enough (`docs/specs/console.md` §11.9).

**Synopsis**

```
umbra user erase <USER_ID>
```

**Output**

Default: one-line confirmation. JSON: `{"user_id": "<uuid>", "state": "erased"}`.

**Exit** — `0` on success; `1` on API error (HTTP 403 when caller is neither self nor `PLATFORM_OPERATOR`, HTTP 409 with `details.state="user_owns_cvms"`); `2` on auth errors.

---

### `umbra user permissions list <USER_ID>`

List the permissions a user holds. Gated on `USER_MANAGE`.

**Synopsis**

```
umbra user permissions list <USER_ID>
```

**Output**

Default: one permission name per line. JSON: array of permission names.

**Exit** — `0` on success; `1` on API error or unknown id; `2` on auth errors.

---

### `umbra user permissions grant <USER_ID> <PERMISSION>...`

Grant one or more permissions to a user (`POST /users/{id}/permissions`). Gated on `PERMISSION_MANAGE`. The Console rejects unknown permission names. Idempotent on the resulting set.

**Synopsis**

```
umbra user permissions grant <USER_ID> <PERMISSION>...
```

**Output**

Default: one-line confirmation listing the granted permissions. JSON: `{"user_id": "<uuid>", "granted": [<permission>...]}`.

**Exit** — `0` on success; `1` on API error (HTTP 403 when the caller lacks `PERMISSION_MANAGE`); `2` on auth errors; `4` on unknown permission name.

---

### `umbra user permissions revoke <USER_ID> <PERMISSION>...`

Revoke one or more permissions from a user (`DELETE /users/{id}/permissions/{permission}` per permission). Gated on `PERMISSION_MANAGE`. Idempotent: revoking a permission the user does not hold succeeds silently.

**Synopsis**

```
umbra user permissions revoke <USER_ID> <PERMISSION>...
```

**Output**

Default: one-line confirmation listing the revoked permissions. JSON: `{"user_id": "<uuid>", "revoked": [<permission>...]}`.

**Exit** — `0` on success; `1` on API error; `2` on auth errors; `4` on unknown permission name.

---

### `umbra quota get`

Read effective resource quotas and current usage from the Console quota routes (`GET /entities/{id}/quotas` or `GET /users/{id}/quotas`). Without an explicit scope, the command reads the caller's session entity quotas. Entity quota reads are gated on `USER_MANAGE`; user quota reads are allowed for self and otherwise gated on `QUOTA_MANAGE` or `USER_MANAGE` (`docs/specs/console.md` §3.13).

**Synopsis**

```
umbra quota get [--entity <ENTITY_ID> | --user <USER_ID>]
```

**Flags**

- `--entity <ENTITY_ID>` — read quotas for this entity UUID. Defaults to the current session entity when neither scope flag is provided.
- `--user <USER_ID>` — read quotas for this user UUID. Mutually exclusive with `--entity`.

**Output**

Default: one human-readable row per quota (`scope`, `resource`, `limit`, `source`, `current_usage`, `set_by`, `set_at`). JSON: array of `<EntityQuota>` or `<UserQuota>` records.

**Exit** — `0` on success; `1` on API error or unknown scope id; `2` on auth errors; `4` on malformed scope UUID.

---

### `umbra quota set <RESOURCE> <LIMIT>`

Set or update a quota override. Entity-scoped writes call `PATCH /entities/{id}/quotas/{resource}` and require `PLATFORM_OPERATOR`. User-scoped writes call `PATCH /users/{id}/quotas/{resource}` and require `QUOTA_MANAGE` or `PLATFORM_OPERATOR`. The CLI supplies a fresh `Idempotency-Key` per request.

**Synopsis**

```
umbra quota set <RESOURCE> <LIMIT> [--entity <ENTITY_ID> | --user <USER_ID>]
```

**Arguments**

- `<RESOURCE>` — for entity scope: `dev_cvms`, `ssh_keys`, `users`, `profiles`, `disk_gb_per_cvm`, or `disk_gb_total`; for user scope: `dev_cvms`, `ssh_keys`, `disk_gb_per_cvm`, or `disk_gb_total`. The two `disk_gb_*` limits are expressed in GB (`docs/specs/console.md` §3.13): `disk_gb_per_cvm` caps a single CVM's disk at launch, and `disk_gb_total` caps the summed disk across the scope's live CVMs. In human output their `limit`/`current usage` render with a `GB` suffix.
- `<LIMIT>` — integer ≥ 0.

**Flags**

- `--entity <ENTITY_ID>` — set an entity-level override. Defaults to the current session entity when neither scope flag is provided.
- `--user <USER_ID>` — set a per-user override. Mutually exclusive with `--entity`.

**Output**

Default: one human-readable row for the updated quota. JSON: the updated `<EntityQuota>` or `<UserQuota>` record.

**Exit** — `0` on success; `1` on API error (HTTP 403 lacking permission, HTTP 404 unknown id, HTTP 409 when a limit violates Console quota invariants); `2` on auth errors; `4` on malformed scope UUID, unknown resource for the selected scope, or invalid limit.

---

### `umbra quota clear <RESOURCE>`

Clear a quota override. Entity-scoped clears call `DELETE /entities/{id}/quotas/{resource}` and revert to the global default; user-scoped clears call `DELETE /users/{id}/quotas/{resource}` and revert to the entity/default resolution. Clearing is idempotent.

**Synopsis**

```
umbra quota clear <RESOURCE> [--entity <ENTITY_ID> | --user <USER_ID>]
```

**Arguments**

- `<RESOURCE>` — for entity scope: `dev_cvms`, `ssh_keys`, `users`, `profiles`, `disk_gb_per_cvm`, or `disk_gb_total`; for user scope: `dev_cvms`, `ssh_keys`, `disk_gb_per_cvm`, or `disk_gb_total`. The two `disk_gb_*` limits are expressed in GB (`docs/specs/console.md` §3.13): `disk_gb_per_cvm` caps a single CVM's disk at launch, and `disk_gb_total` caps the summed disk across the scope's live CVMs. In human output their `limit`/`current usage` render with a `GB` suffix.

**Flags**

- `--entity <ENTITY_ID>` — clear an entity-level override. Defaults to the current session entity when neither scope flag is provided.
- `--user <USER_ID>` — clear a per-user override. Mutually exclusive with `--entity`.

**Output**

Default: one-line confirmation. JSON: `{"scope": "entity"|"user", "scope_id": "<uuid>", "resource": "<resource>", "cleared": true}`.

**Exit** — `0` on success; `1` on API error; `2` on auth errors; `4` on malformed scope UUID or unknown resource for the selected scope.

---

### `umbra profile members list`

List the members of the profile addressed by the global `--profile` flag (or `default_profile` config; `4` exit if neither is set). Read scope: any caller who can see the profile (i.e. members + holders of `USER_MANAGE`).

**Synopsis**

```
umbra profile members list
```

**Output**

Default: human-readable rendering of `{user_id, email, added_at}` per member. JSON: array of those records.

**Exit** — `0` on success; `1` on API error or unknown profile; `2` on auth errors; `4` on missing profile.

---

### `umbra profile members add <USER_ID>`

Add a user to the profile addressed by `--profile` / `default_profile` (`POST /profiles/{id}/users`). Gated on `USER_MANAGE`. Idempotent on `(profile_id, user_id)` — adding a current member succeeds silently.

**Synopsis**

```
umbra profile members add <USER_ID>
```

**Output**

Default: one-line confirmation. JSON: `{"profile_id": "<uuid>", "user_id": "<uuid>"}`.

**Exit** — `0` on success; `1` on API error (HTTP 403 lacking `USER_MANAGE`, unknown user); `2` on auth errors; `4` on missing profile.

---

### `umbra profile members remove <USER_ID>`

Remove a user from the profile addressed by `--profile` / `default_profile` (`DELETE /profiles/{id}/users/{user_id}`). Gated on `USER_MANAGE`. Idempotent — removing a non-member succeeds silently. Removing a member does NOT terminate Dev CVMs they launched against this profile; CVMs are M:N with profiles and an attached profile being lost from the user is independent of the CVM-profile attachment.

**Synopsis**

```
umbra profile members remove <USER_ID>
```

**Output**

Default: one-line confirmation. JSON: `{"profile_id": "<uuid>", "user_id": "<uuid>"}`.

**Exit** — `0` on success; `1` on API error; `2` on auth errors; `4` on missing profile.

---

### `umbra security-cvm show`

Show the Security CVM for the caller's entity. There is exactly one Security CVM per entity; shared across every Dev CVM in the entity. Lookup is implicit from the caller's session — no `--profile` or `--entity` flag.

**Synopsis**

```
umbra security-cvm show
```

**Output**

Default: human-readable rendering (§2.3) of the Security CVM record. JSON: the Security CVM record (`id`, `entity_id`, `state`, `fqdn`, `instance_type`, `region`, `policy_version`, `expected_image_measurement`, `image_measurement`, `rtmr3_digest`, `attestation_verified_at`, `error_reason`, `created_at`, `updated_at`). Provider-specific identifiers (Phala app id, Cloudflare gateway host, etc.) are not surfaced in v0; the Console mediates every interaction with the SC.

**Exit** — `0` on success; `1` on API error or the entity has no Security CVM (HTTP 404, in which case the message indicates an admin must run `umbra security-cvm launch`); `2` on auth errors.

---

### `umbra security-cvm attestation`

Show the Console's most recent Security CVM attestation diagnostic (`GET /entities/{id}/security-cvm/attestation`). This is operator-facing diagnostic state, not the CLI's aTLS trust path for Dev CVMs. Gated on `USER_MANAGE` or `PLATFORM_OPERATOR`.

**Synopsis**

```
umbra security-cvm attestation [--probe]
```

**Flags**

- `--probe` — ask Console to run a fresh server-side attestation probe before returning a verdict. Until the atlas-rs probe adapter lands, Console returns `503 SERVICE_UNAVAILABLE` with `details.component="security_cvm_attestation_probe"`.

**Output**

Default: one human-readable row showing `security_cvm_id`, `fqdn`, `verified`, `failure_reason`, `expected_image_measurement`, `image_measurement_seen`, `rtmr3_digest_seen`, and `verified_at`. JSON: the `<SecurityCVMAttestation>` record from Console §2.3.

**Exit** — `0` on success; `1` on API error (HTTP 404 when the entity has no Security CVM, HTTP 409 on attestation drift, HTTP 503 while fresh probing is unavailable); `2` on auth errors.

---

### `umbra security-cvm launch`

Launch the Security CVM for the caller's entity. Async per §2.6 — Phala propagates over 2–5 minutes, after which the Console fetches the mitmproxy root CA and the operation reaches `succeeded`. The Console gates this command on `SECURITY_CVM_CONFIGURE`; non-administrators receive HTTP 403 and exit `1`.

**Synopsis**

```
umbra security-cvm launch
                    [--instance-type <TYPE>]
                    [--region <REGION>]
                    [--no-wait]
                    [--wait-timeout-seconds <SECONDS>]
```

**Flags**

- `--instance-type <TYPE>` — instance type for the Security CVM (e.g. `tdx.small`); `umbra cvm instance-types` lists the valid set (validated against the same Console catalog as Dev CVM launches, `docs/specs/console.md` §3.6a). Default: server-side `PHALA_DEFAULT_INSTANCE_TYPE`.
- `--region <REGION>` — Phala region. Default: the Console's server-side chain (`SECURITY_CVM_DEFAULT_REGION`, then `PHALA_REGION`) when unset.
- `--no-wait` / `--wait-timeout-seconds <SECONDS>` — see §2.6. Default wait timeout is `600` seconds.

An entity MUST have at most one live Security CVM; launching when one already exists exits `1`.

**Output**

By default, the CLI polls the operation per §2.6. On `succeeded`, it prints the one-shot `ca_export_token` and the final Security CVM record. The Console never returns the `INGEST` plaintext. Per the Console's first-read disclosure semantics, the successful poll burns the CA-export disclosure (the operation's `actor_id` — i.e. the user that ran this command — is the only authorized first reader; another admin polling first sees the redacted form).

With `--no-wait`, the CLI prints the operation handle (§2.6) and exits `0`. The bearers will be available on the operation's first read by the submitter once the saga reaches `succeeded`; the operator must re-poll using the recorded `operation_id`.

JSON without `--no-wait`: `{security_cvm: <SecurityCVM record>, ca_export_token: <string>}`.

JSON with `--no-wait`: the operation handle (§2.6).

**Exit** — `0` on `succeeded`; `1` on API error (including HTTP 403 when the caller lacks permission), terminal `failed` (the typed `error_code` is rendered on stderr — `PHALA_DEPLOY_FAILED`, `PHALA_NEVER_RUNNING`, `CA_EXPORT_TTL_EXPIRED`, `CA_FETCH_FAILED` are documented values), or an entity that already has a live Security CVM; `2` on auth errors; `3` on `--wait-timeout-seconds` elapsed; `4` on invalid arguments.

---

### `umbra security-cvm update`

Update the entity Security CVM deployment in place. Async (§2.6): the Console updates the existing provider deployment, re-attests it, fetches the current CA/aTLS policy material, and returns the refreshed Security CVM record. Already-running refresh-capable Umbra Dev CVM forwarders pull the current SC policy and CA through their authenticated Console control channel; the sandbox watcher replaces a rotated CA. Egress may fail closed briefly while polling converges, and CA-caching processes may need a restart, but a CA-only change does not require `umbra cvm update` for those compatible runtimes. Persisted legacy rebind markers retain the fail-closed behavior defined in §3.2.

**Synopsis**

```
umbra security-cvm update [--no-wait] [--wait-timeout-seconds <SECONDS>]
```

**Output**

Default: waits and prints `updated <SecurityCVM summary>`. If the SC CA changed, the confirm block says that compatible Umbra runtimes refresh it automatically and that persisted legacy markers remain fail-closed; it prints no CA-only fleet update step. JSON without `--no-wait`: `{security_cvm: <SecurityCVM>, ca_changed: <bool>, dev_cvms_requiring_update: [<UUID>, ...]}`. The current in-place SC update preserves the SC FQDN, per-Dev bearers, and RTMR3 binding, so `dev_cvms_requiring_update` is empty; the field and its generic manual next-step renderer are reserved for a future operation that explicitly changes such launch-bound material. With `--no-wait`, prints the operation handle.

**Exit** — `0` on `succeeded`; `1` on API error or terminal `failed` (`PROVIDER_UPDATE_FAILED`, `CA_FETCH_FAILED`, attestation errors); `2` on auth errors; `3` on wait timeout; `4` on invalid arguments.

---

### `umbra security-cvm terminate`

Terminate the entity's Security CVM. The Console gates this command on `SECURITY_CVM_CONFIGURE`; non-administrators receive HTTP 403 and exit `1`.

**Synopsis**

```
umbra security-cvm terminate
```

A Security CVM cannot be terminated while live Dev CVMs exist anywhere in the entity (doing so would leave them with no traffic gateway). If any Dev CVMs remain, the command exits `1`; the Console returns `409 CONFLICT` with `details.state="dev_cvms_in_entity"`, `details.dev_cvm_count`, and `details.dev_cvm_ids` (truncated at 100), and the CLI prints the count plus the listed ids on stderr so the caller knows exactly which CVMs to terminate first with `umbra cvm terminate <CVM_ID>`. Once the Security CVM is terminated, the entity has no Security CVM and no new Dev CVMs can be launched until the operator runs `umbra security-cvm launch` again.

**Output**

Default: confirmation block showing the terminated Security CVM record. JSON: the Security CVM record.

**Exit** — `0` on success; `1` on API error (including HTTP 403 when the caller lacks permission, no live Security CVM in the entity, or Dev CVMs still exist); `2` on auth errors.

---

### `umbra traffic-logs`

Query egress traffic logs ingested from Security CVMs (`GET /traffic-logs`). Gated on `TRAFFIC_LOGS_VIEW`; results are scoped by Console to the caller's entity.

**Synopsis**

```
umbra traffic-logs
                      [--cvm <CVM_ID>]
                      [--security-cvm <SECURITY_CVM_ID>]
                      [--from <RFC3339>]
                      [--to <RFC3339>]
                      [--limit <N>]
                      [--cursor <CURSOR>]
```

**Flags**

- `--cvm <CVM_ID>` — filter to logs attributed to one Dev CVM.
- `--security-cvm <SECURITY_CVM_ID>` — filter to logs emitted by one Security CVM.
- `--from <RFC3339>` / `--to <RFC3339>` — timestamp bounds.
- `--limit <N>` — page size, 1..1000. Default: 100.
- `--cursor <CURSOR>` — opaque cursor from the prior page.

**Output**

Default: one compact row per log (`timestamp`, `id`, `security_cvm_id`, `cvm_id`, source/destination, protocol, HTTP fields when present, bytes). If Console returns a next cursor, it is printed to stderr. JSON: `{"logs": [<TrafficLog>, ...], "next_cursor": <string|null>}`.

**Exit** — `0` on success; `1` on API error (including HTTP 403 when the caller lacks `TRAFFIC_LOGS_VIEW`); `2` on auth errors; `4` on malformed UUIDs, timestamps, cursor, or out-of-range limit.

### 3.5 Maintenance and admin

Commands gated on `PLATFORM_OPERATOR`. Entity admins do NOT have access; the CLI prints a `403`-derived `[error]` and exits `1` if the caller lacks the role.

### `umbra reconcile`

Run a single reconciliation pass synchronously. The Console runs reconciliation continuously as a background task; this command triggers one pass on demand, typically for debugging drift or recovering after a known incident.

**Synopsis**

```
umbra reconcile [--no-orphans]
```

**Flags**

- `--no-orphans` — skip the Cloudflare orphan-cleanup pass. Useful when Cloudflare is temporarily unconfigured and the operator only wants Phala state advancement.

**Output**

Default: a summary block (`cvms_advanced`, `security_cvms_advanced`, `orphans_cleaned` — counts and ids). JSON: the same data as a structured object.

**Exit** — `0` on success; `1` on API error (including HTTP 403 when the caller lacks `PLATFORM_OPERATOR`, and `503 SERVICE_UNAVAILABLE` when Phala or Cloudflare is unconfigured); `2` on auth errors.

---

### `umbra admin sessions revoke`

Force-revoke active Console JWTs by predicate. Used in incident response.

**Synopsis**

```
umbra admin sessions revoke [--user <USER_ID>] [--entity <ENTITY_ID>]
                               [--issued-before <RFC3339>]
```

**Flags**

At least one filter MUST be supplied. The predicate is the AND of every supplied filter. The CLI rejects "no filters" with exit `4`.

- `--user <USER_ID>` — revoke sessions for this user only.
- `--entity <ENTITY_ID>` — revoke sessions for this entity only.
- `--issued-before <RFC3339>` — revoke sessions issued before this UTC timestamp. Useful after a JWT-key rotation (`admin keys rotate`) to guarantee no token signed with the old key is still authoritative.

**Output**

Default: a one-line summary (`revoked_jti_count`, `revoked_refresh_token_count`). JSON: an object with both counts.

**Exit** — `0` on success; `1` on API error (HTTP 403 when the caller lacks `PLATFORM_OPERATOR`); `2` on auth errors; `4` if no filter is supplied.

---

### `umbra admin keys rotate`

Rotate the Console's JWT signing key. Mints a new signing `kid`; the old `kid` is retained as verifying for `--retire-old-after-seconds` to allow in-flight tokens to verify until they expire or are revoked.

**Synopsis**

```
umbra admin keys rotate --new-kid <KID>
                           [--retire-old-after-seconds <S>]
```

**Flags**

- `--new-kid <KID>` (required) — identifier for the new signing key. The corresponding key material MUST already be loaded by the Console (out-of-band, via `JWT_PUBLIC_KEYS_REF`); this command activates the `kid` for issuance.
- `--retire-old-after-seconds <S>` — how long to keep the previous active `kid` in the verifying set (max `86400`, default `3600`).

**Output**

Default: a one-line summary (`active_kid`, `retiring_kids`). JSON: the same data.

**Exit** — `0` on success; `1` on API error (HTTP 403, or HTTP 422 if `new_kid` is unknown to the Console); `2` on auth errors; `4` on invalid arguments.

### 3.6 Introspection and utilities

Informational commands, shell integration, audit queries, and local diagnostics.

### `umbra audit events`

Query the **control-plane audit** trail (resource-mutation events emitted by the Console: `USER_ADDED`, `CVM_LAUNCHED`, `PROFILE_POLICY_UPDATED`, etc.; full action catalog in `docs/specs/console.md` §7.18). Gated on `AUDIT_VIEW`; results are scoped to the caller's entity. Read-only — does NOT itself produce an audit row.

Egress-side records (per-request traffic logs emitted by the Security CVM) live in a separate stream (`docs/specs/console.md` §3.11 + §7.21). The CLI verb is `umbra traffic-logs` (spec: §3.4 below; human rendering: `docs/specs/cli-style.md` §7.6).

**Synopsis**

```
umbra audit events [--actor <USER_ID>]
                      [--target-type <TYPE>] [--target-id <ID>]
                      [--action <ACTION>]
                      [--from <RFC3339>] [--to <RFC3339>]
                      [--limit <N>] [--cursor <CURSOR>]
```

**Flags**

- `--actor <USER_ID>` — filter to events recorded with this `actor_id`.
- `--target-type <TYPE>` / `--target-id <ID>` — filter to events whose target matches.
- `--action <ACTION>` — filter to a typed audit action (e.g. `CVM_LAUNCHED`, `PROFILE_POLICY_UPDATED`).
- `--from <RFC3339>` / `--to <RFC3339>` — filter by timestamp range.
- `--limit <N>` — page size (1..500, default 100).
- `--cursor <CURSOR>` — opaque pagination cursor from a prior response's `next_cursor`.

**Output**

Default: human-readable rendering (§2.3) of each event with sequence, id, timestamp, actor email, action, target, description. JSON: `{events: [...], next_cursor: <string|null>}`.

**Chain verification.** Before emitting anything, the CLI re-verifies the page it received and fails closed on any discrepancy — nothing is written to stdout. It recomputes each row's `row_hash` as `SHA-256(JCS(row_minus_row_hash))` (RFC 8785, matching `docs/specs/console.md` §11.6 — non-ASCII stays raw UTF-8, never `\uXXXX`), requires the page to be strictly monotonic in `seq` (rejecting a reordered or repeated row), and requires `prev_hash` linkage between rows whose `seq` are adjacent, in whichever direction the page runs (the Console pages newest-first). A `seq` gap is NOT a failure: every listing is entity-scoped, `--actor`/`--action`/`--target-*` remove interior rows by design, and a rolled-back transaction leaves a permanently unused `seq`. A row deleted from the middle of the chain is therefore indistinguishable, from any single client, from a row that caller may not see; detecting deletion is the server-side end-to-end replay job's job (`docs/specs/console.md` §19.6), not the CLI's.

**Exit** — `0` on success; `1` on API error (HTTP 403 when the caller lacks `AUDIT_VIEW`) or on chain-verification failure; `2` on auth errors; `4` on invalid `--action` or out-of-range `--limit`.

---

### `umbra audit export`

Issue a bulk audit export. Async per §2.6 (`Operation.kind = "audit.export"`); on `succeeded` the `Operation.result` carries a one-shot signed download URL valid for 5 minutes. Gated on `AUDIT_EXPORT` (separate from `AUDIT_VIEW` — bulk export is a distinct capability). Per-credential daily quota of 10 exports.

**Synopsis**

```
umbra audit export --format <FORMAT>
                      [--actor <USER_ID>]
                      [--target-type <TYPE>] [--target-id <ID>]
                      [--action <ACTION>]
                      [--from <RFC3339>] [--to <RFC3339>]
                      [--output <PATH>]
                      [--no-wait] [--wait-timeout-seconds <SECONDS>]
```

**Flags**

- `--format <FORMAT>` (required) — `csv` or `ndjson`.
- Filter flags — same shape as `umbra audit events`.
- `--output <PATH>` — local path to download the artifact to once the operation succeeds. When omitted, the CLI prints the signed download URL on stdout (caller is responsible for fetching). When set, the CLI fetches via the URL and writes to the path before exiting.
- `--no-wait` / `--wait-timeout-seconds <SECONDS>` — see §2.6.

**Output**

By default, waits for the operation per §2.6. On `succeeded` and with `--output`, downloads the artifact and prints a one-line confirmation (`{path, row_count, byte_size, sha256}`); without `--output`, prints the signed URL and the `sha256` (one line each on stdout). With `--no-wait`, prints the operation handle.

JSON without `--no-wait`: `{download_url, expires_at, content_type, sha256, row_count, byte_size}` (the Console's `Operation.result`); with `--output` adds `path`. JSON with `--no-wait`: the operation handle (§2.6).

**Exit** — `0` on success; `1` on API error (HTTP 403 when the caller lacks `AUDIT_EXPORT`, HTTP 429 when the daily quota is exhausted), terminal `failed`, or download failure when `--output` is set; `2` on auth errors; `3` on `--wait-timeout-seconds` elapsed; `4` on invalid arguments.

---

### `umbra status`

Show a summary of everything visible to the caller in their entity: the entity-scoped Security CVM, every profile they belong to, every Dev CVM they can see, and their SSH keys.

**Synopsis**

```
umbra status
```

The global `--profile` flag (§2.2), if set, filters the output to a single profile (and the Dev CVMs it is attached to). SSH keys, the entity record, and the Security CVM are always shown regardless of the filter.

**Scope and filtering**

The CLI does not apply any visibility rules of its own: it calls the Console's list endpoints and renders whatever records come back. A caller with narrower permissions sees fewer profiles or fewer Dev CVMs; a caller with broader permissions sees more. The rendering is identical in both cases.

**Invariant reflected in the output**

The entity has at most one Security CVM; every Dev CVM in the entity routes through it. A Dev CVM has ≥ 1 attached profile. Therefore the combination `security_cvm = null` with `dev_cvms != []` is unreachable.

**Output**

Top-level fields:

- `user` — `{id, email}` of the caller.
- `entity` — `{id, name}` of the caller's entity.
- `security_cvm` — either a Security CVM record or `null` (entity has no Security CVM provisioned).
- `profiles` — array of per-profile blocks the caller can see (the caller's profile memberships).
- `dev_cvms` — array of Dev CVM records visible to the caller. Grouped by profile in the rendering, but the JSON shape is a flat array since each CVM can belong to multiple profiles.
- `ssh_keys` — array of SSH keys registered by the caller.
- `totals` — counts across the response: `profiles`, `dev_cvms`, `dev_cvms_running`, `ssh_keys`.

Per-profile block:

- `id`, `name`, `description`.
- `policy` — pretty-printed JSON in default rendering, redacted typed policy object in JSON output (write-only secret values are not returned).
- `attached_cvm_count` — precise count of Dev CVMs with this profile attached.

Per Dev CVM record:

- `id`, `state`, `instance_type`, `region`, `fqdn` (may be `null`).
- `profiles` — list of `{id, name}` pairs for every attached profile.
- `ssh_keys` — list of `{id, label}` pairs for the SSH keys installed on the CVM.
- `owner` — `{id, email}`. Always populated; the email is denormalised by the Console.
- `created_at`, `updated_at`.

Per Security CVM record:

- `id`, `state`, `instance_type`, `region`, `policy_version`, `created_at`.

Per SSH key record: same fields as `umbra key list` — `id`, `label`, `algorithm`, `fingerprint`.

Default rendering groups Dev CVMs by their attached profiles for readability (a CVM attached to two profiles appears under each, with the second appearance marked as a back-reference). The Security CVM is rendered above the profiles since it is the entity-wide foundation. Owner is displayed as a trailing annotation (`[owner: <email>]`) only when not equal to the caller. A profile with no attached CVMs is shown as a single line: `<name> (<profile_id>) — no CVMs attached`.

**Exit** — `0` on success; `1` on API error; `2` on auth errors.

---

### `umbra completions <SHELL>`

Print a shell-completion script to stdout.

**Synopsis**

```
umbra completions <SHELL>
```

**Arguments**

- `<SHELL>` — one of `bash`, `zsh`, `fish`, `elvish`, `powershell`.

**Output**

The completion script for the requested shell on stdout. Nothing on stderr. `--json` is ignored.

**Exit** — `0` on success; `4` on unknown shell.

---

### `umbra config show`

Print the fully resolved configuration, annotating the source (`flag`, `env`, `file`, `default`) of each value.

**Synopsis**

```
umbra config show
```

**Output**

Default: human-readable rendering (§2.3) of each config entry with fields `key`, `value`, `source`. Secrets (bearer tokens, OIDC codes) MUST be redacted as `<redacted>`. JSON: an object keyed by config name, where each value is `{"value": …, "source": …}`.

**Exit** — `0` on success; `1` on I/O failure reading config files.

---

### `umbra update`

Update the running `umbra` binary in place to a published release. Alias: `umbra upgrade`.

**Synopsis**

```
umbra update [--check] [--version <VERSION>]
```

**Release channel.** The command talks to the same explicitly configured install service the verified bootstrap installer uses (`install_base_url`). There is no built-in production hostname: release operators must configure an approved HTTPS origin, active updates fail before network access when none is configured, and passive checks skip. Once configured, the client reads `/releases/umbra-cli/latest/version`, then downloads only the immutable per-target artifact at `/releases/umbra-cli/<version>/<target>/umbra`, its sibling `umbra.sha256`, and the version-root `umbra-cli.intoto.jsonl` provenance bundle. The target triple is the one compiled into the binary (`umbra version` → `target`); there is no cross-target update and no mutable `latest` artifact fallback.

**Transport and provenance MUST be authenticated.** `install_base_url` MUST use `https`, with one exception: `http` is permitted when the host is loopback (`127.0.0.0/8`, `::1`, or the name `localhost`), which covers local mirrors and the release-tree tests. A non-conforming value MUST be rejected with exit `4` before any request is made, and the passive check (below) MUST NOT probe over it. The same-origin checksum detects transfer corruption but is not a provenance signal. Before executing or replacing anything, the CLI MUST use a preinstalled `slsa-verifier` to authenticate the downloaded artifact against all of the following fixed release identity constraints: source repository `github.com/concrete-security/umbra`, source branch `main`, workflow input `dry_run=false`, and builder `https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0`. This release identity is intentionally inactive until maintainers prove control of the repository and publish the first approved release and provenance; no public-release or deployment claim is valid before that launch gate. `UMBRA_SLSA_VERIFIER` may select an absolute executable path; without it, lookup considers `slsa-verifier` only in absolute `PATH` directories so the current working directory cannot shadow the trusted tool. A missing or rejecting verifier is a hard failure. The verified bootstrap procedure and pinned verifier installation are in `docs/quick-start.md`.

**Behavior**

1. Resolve the requested version: `--version <VERSION>` pins an exact published canonical SemVer (prereleases allowed; `v` prefixes, surrounding whitespace, leading-zero numeric identifiers, and build metadata are rejected); otherwise the latest version is read from the version endpoint under the same canonical rule.
2. Compare with the running version (semver precedence, pre-releases rank below their final release). Without `--force`: equal → report up to date and exit `0`; running version newer than latest → report ahead and exit `0`. `--force` (the global flag) proceeds regardless, which is also the supported way to downgrade to the published latest. An explicit `--version` pin installs in either direction without `--force`.
3. Resolve the trusted verifier and fail fast on an unwritable install directory before downloading executable material.
4. Download the immutable artifact, its `.sha256`, and its version-root provenance bundle. Verify the checksum, stage the binary next to the running executable, and run SLSA verification with every fixed identity constraint above.
5. Only after provenance succeeds, exec-check the staged binary (`<staged> --version`) so an artifact that cannot run on this machine aborts the update with the current install intact; the reported version must match the requested one.
6. Atomically rename the staged binary over the running executable (symlinks resolved first, so installer shims keep pointing at the updated file). The running process is unaffected; the next invocation runs the new version.

**Version metadata is required.** If `latest/version` is missing, the command exits `1` without downloading or executing a mutable `latest` artifact. An explicit `--version <VERSION>` does not need that endpoint.

**Freshness residual.** SLSA authenticates an artifact's source/build identity and digest; it does not make the mirror's mutable `latest/version` response fresh. A mirror can suppress a release, freeze a client on its current version, or offer an older-but-still-newer valid release. Without `--force`, semver comparison prevents a downgrade below the installed version; `--force` and an explicit version pin intentionally permit rollback. The bootstrap procedure avoids mirror version selection by discovering a release through GitHub and passing that exact version to the verified installer.

**`--check`.** Report whether a newer release is published, without installing. Conflicts with `--version`.

**Passive new-version check.** Every command except `update` itself, `completions`, and `tunnel` participates in a passive check so users learn they are behind without running `update --check`: when `${config_dir}/update-check.json` (§4.4) is missing or older than 24 hours, the CLI re-invokes itself as a detached background process (hidden `umbra update --refresh-cache`) that probes the version endpoint and rewrites the cache; the foreground command never waits on the network. After the command finishes, if the cached latest version is newer than the running version, the CLI prints one muted stderr line: `update available: umbra <latest> (installed <current>) -- run `umbra update``. The passive check (both the background probe and the notice) is active only when stderr is a terminal, and is disabled by `no_update_check` / `UMBRA_NO_UPDATE_CHECK` (§4.1). It never affects stdout, exit codes, or `--json` payloads.

**Output**

Default: a confirm block — `updated umbra <old> -> <new>` with the install path and target on success; `up to date: umbra <version>`; or `ahead of latest release: umbra <version>` with the published latest. `--check` prints `update available: umbra <latest>` with the installed version and the `umbra update` next step. JSON: `{status, version, ...}` where `status` is one of `updated` (with `previous_version`, `path`), `up_to_date`, `ahead` (with `latest_version`), `update_available` (with `latest_version`).

**Exit** — `0` on success, including the up-to-date and ahead outcomes; `1` on install-service or download failure, missing version metadata, checksum or provenance failure, missing verifier, exec-check failure, or an unwritable install path; `4` on a malformed `--version` or unauthenticated remote transport.

---

### `umbra version`

Print version, build commit, target triple, and build date.

**Synopsis**

```
umbra version
```

**Output**

Default: multi-line block. JSON: an object with `version`, `commit`, `target`, `build_date`.

**Exit** — `0`.

## 4. Configuration

### 4.1 Config values

The table below is authoritative. For every row, the config key, the environment variable, and (where applicable) the command-line flag all refer to the same value; see §4.2 for precedence.

| Config key | Env var | Flag | Type | Default | Description |
| --- | --- | --- | --- | --- | --- |
| `console_url` | `UMBRA_CONSOLE_URL` | `--console-url` | URL string | *none* (required) | Base URL of the Console REST API. |
| `default_cvm` | `UMBRA_DEFAULT_CVM` | `--cvm` | CVM UUID | *none* | Default target CVM for CVM-targeting verbs (session verbs and `cvm attach/detach/start/stop/update/terminate`). Those verbs also take a `<CVM_ID>` positional, which wins over `--cvm` (§4.2). `stop`/`terminate` ignore this default and require an explicit positional or `--cvm`. |
| `default_profile` | `UMBRA_DEFAULT_PROFILE` | `--profile` | profile UUID | *none* | Default profile for commands that scope an action to a single profile (`profile show`, `profile configure`, `cvm list` filter). On `cvm launch`, used as the sole attached profile when `--profile` is not supplied on the command line. |
| `default_ssh_identity` | `UMBRA_DEFAULT_SSH_IDENTITY` | *(none)* | filesystem path | *none* | Default private SSH key for session verbs. Written by a successful `cvm launch` when the CLI knows the local key path; session verbs also prefer local key-id mappings from `ssh-identities.toml` and fall back to fingerprint-matching a key installed on the target CVM. |
| `atls_policy` | `UMBRA_ATLS_POLICY` | `--atls-policy` | filesystem path | *none* (required for any command that opens an aTLS tunnel, unless `atls_policy_insecure_skip` is true) | Path to the aTLS policy file (JSON). Loaded and enforced on every aTLS tunnel; see §6.1. |
| `atls_policy_insecure_skip` | `UMBRA_ATLS_POLICY_INSECURE_SKIP` | `--insecure-skip-atls-policy` | bool | `false` | **Dev-only escape hatch.** When `true`, skip aTLS policy evaluation. The aTLS handshake still runs; only the local policy check is bypassed. MUST NOT be enabled in production; the CLI logs a `WARN` on every tunnel when active. |
| `default_instance_type` | `UMBRA_DEFAULT_INSTANCE_TYPE` | `--instance-type` | string | *none* | Default instance type for `cvm launch` when neither the `--instance-type` flag nor the Console's `DEV_CVM_DEFAULT_INSTANCE_TYPE` is set. Independent from `security-cvm launch --instance-type` — the Security CVM falls back to the Console's `PHALA_DEFAULT_INSTANCE_TYPE` instead. |
| `default_region` | `UMBRA_DEFAULT_REGION` | `--region` | string | *none* | Default region. When unset, the Console selects one from `DEV_CVM_DEFAULT_REGION`, then `PHALA_REGION` for Dev CVM launch. |
| `oidc_provider` | `UMBRA_OIDC_PROVIDER` | `--provider` | string | `google` | OIDC provider to use for `umbra auth login`. Non-Google providers are post-v0; `google` is the only value the Console accepts in v0. |
| `oidc_client_id` | `UMBRA_OIDC_CLIENT_ID` | (none) | string | `umbra-cli-v1` | The OAuth `client_id` the CLI sends on the loopback `/auth/authorize` request. Must be present in the Console's `OIDC_CLIENT_ALLOWLIST`. Override only if the operator has registered a different `client_id` for the deployment. |
| `request_id` | `UMBRA_REQUEST_ID` | `--request-id` | string | (auto-minted UUID v4 per invocation) | The `X-Request-Id` sent on every Console request this invocation makes (§2.7). Override for cross-system correlation. |
| `force` | `UMBRA_FORCE` | `--force` | bool | `false` | Skip `If-Match` on mutation routes (§2.7). The CLI logs a `WARN` line on every use. |
| `output` | `UMBRA_OUTPUT` | `--json` / `--output` | `text` or `json` | `text` | Default output format. `--json` on the command line is shorthand for `--output json`. |
| `no_color` | `UMBRA_NO_COLOR` | `--no-color` | bool | `false` | Disable ANSI color. Also honored via the conventional `NO_COLOR` environment variable when set to any non-empty value. |
| `log_level` | `UMBRA_LOG_LEVEL` | `--verbose` | `error`/`warn`/`info`/`debug`/`trace` | `warn` | Log filter. `-v` flags increment the level from `warn` upward. |
| `install_base_url` | `UMBRA_INSTALL_BASE_URL` | *(none)* | `https` URL string (`http` for loopback hosts only) | *(none)* | Explicit base URL of the install service hosting published CLI release artifacts. With no value, active update fails before network access and passive checks skip. Plaintext `http` to a non-loopback host is rejected (exit `4`); executable installation additionally requires SLSA provenance — see §3.6. |
| `no_update_check` | `UMBRA_NO_UPDATE_CHECK` | *(none)* | bool | `false` | Disable the passive new-version check entirely: no background probe, no stderr notice (§3.6 `umbra update`). The explicit `umbra update` / `update --check` commands still work. |
| *(env only)* | `UMBRA_SLSA_VERIFIER` | *(none)* | absolute executable path | absolute-`PATH` lookup for `slsa-verifier` | Select the trusted external verifier used by `umbra update`. A relative override, missing executable, or verifier rejection fails closed before the staged binary is executed or installed. |
| *(env only)* | `UMBRA_CONFIG_DIR` | `--config` | filesystem path | platform-dependent (§4.3) | Override the config directory. Controls where `config.toml`, the session file, and the aliases file are read and written. |

All environment variables MUST use the `UMBRA_` prefix. Boolean env vars accept `1`/`0`, `true`/`false`, `yes`/`no` (case-insensitive).

### 4.2 Config precedence

Every per-field value is resolved by this chain, stopping at the first layer that supplies a value:

1. **Command line** — the flag listed in §4.1 for the field, if present on the invocation.
2. **Environment** — the env var listed in §4.1, if set to a non-empty value.
3. **Config file** — the corresponding key in `config.toml`.
4. **Built-in default** — the default listed in §4.1, if any.

For CVM-targeting verbs (§3.2 session verbs and the `cvm` lifecycle verbs), the target CVM adds a positional layer above this chain: `<CVM_ID>` positional → `--cvm` → `UMBRA_DEFAULT_CVM` → `default_cvm`. The destructive verbs `cvm stop` and `cvm terminate` accept only an explicit positional or `--cvm` and never the `UMBRA_DEFAULT_CVM`/`default_cvm` layers.

Config-directory resolution uses the same chain on `config_dir`:

1. `--config <PATH>`
2. `UMBRA_CONFIG_DIR`
3. Platform default (§4.3)

Config-directory resolution is evaluated first; the resulting path is the base for reading `config.toml`.

Fields marked "required" in §4.1 cause the command to exit `4` (usage) with a clear error identifying which field is missing and which layer could have supplied it.

### 4.3 Config file locations

The config directory holds these files:

- `config.toml` — user settings.
- `session.json` — bearer token and identity; machine-written.
- `aliases.toml` — client-side aliases for CVMs, profiles, SSH keys, and dtach sessions.
- `ssh-identities.toml` — local mapping from Console SSH key ids to private-key paths; machine-written, contains paths only and no private key material.
- `cvms/<cvm_id>.state.toml` — per-CVM client-side state (§4.4); machine-written, may be removed safely.
- `update-check.json` — cached latest-version probe for the passive new-version check (§3.6, §4.4); machine-written, may be removed safely.

Platform defaults for the config directory:

| Platform | Default path |
| --- | --- |
| Linux | `$HOME/.umbra`. |
| macOS | `$HOME/.umbra`. |
| Windows | `%USERPROFILE%\\.umbra`. |

### 4.4 File formats

### `config.toml`

All keys are optional at the type level; keys required at use-time (e.g. `console_url`) cause the corresponding command to exit `4` when not resolved from any precedence layer.

```toml
console_url           = "<https://console.example.com>"
default_cvm           = "cvm-abc123"
default_profile       = "prof-9f2d…"
default_instance_type = "tdx.small"
default_region        = "FR-PARIS-1"
atls_policy           = "/etc/umbra/atls-policy.json"
# atls_policy_insecure_skip = true   # dev only — NEVER enable in production
oidc_provider         = "google"
output                = "text"
no_color              = false
log_level             = "warn"
# install_base_url    = "https://installer.example.com"
# no_update_check     = true   # disable the passive new-version check
```

Unknown keys MUST cause a `WARN`-level log line but MUST NOT fail the command — this allows older CLI versions to tolerate forward-looking config files.

### `session.json`

Written by `umbra auth login` for OIDC users, or by Console bootstrap's `--session-file` path for the initial platform operator; machine-edited, not hand-edited.

```json
{
  "access_token": "<JWT>",
  "refresh_token": "<opaque>",
  "user_id": "<UUID>",
  "email": "user@example.com",
  "entity": {"id": "<UUID>", "name": "Acme Inc."},
  "expires_at": "2026-04-16T16:30:00Z",
  "refresh_expires_at": "2026-05-16T16:30:00Z"
}
```

The `user_id`, `email`, and `entity` fields are populated from a `GET /me` call the CLI MUST issue immediately after the login flow returns the JWT pair (the auth response from `/auth/token` and `/auth/device/poll` carries only the tokens). They allow `umbra auth status` to render identity without a network call (§3.1).

`refresh_token` and `refresh_expires_at` are optional fields but MUST be persisted when the Console issues them (see §5.3).

### `aliases.toml`

One flat table per alias kind, each keyed by the alias name. `cvm`, `profile`, and `ssh-key` map an alias to a Console resource UUID; `session` maps an alias to a `{ session, cvm }` value-object (the dtach session name plus the CVM it lives on).

```toml
[cvm]
prod-box = "9a7f6b4a-1111-2222-3333-444444444444"

[profile]
team-prod = "16286507-f87f-449e-a229-be04067fc23c"

[ssh-key]
ma-cle = "3c4c2b64-b059-41a6-b925-3e4816ffee60"

[session.myclaude]
session = "claude-20260416-143022"
cvm = "9a7f6b4a-1111-2222-3333-444444444444"
```

The legacy layout — a top-level `[<cvm_id>]` table mapping `alias_name` → `dtach_session_name` — is migrated on read: each entry folds into `session` bound to that CVM. Alias names are globally unique across all kinds, and each target appears at most once (one UUID → one alias; one `{session, cvm}` → one alias). That second invariant is enforced on every write, not repaired on read: a hand-edited store, or a legacy file that named one session twice, loads as-is and resolves both names. Every UUID is normalized to its canonical hyphenated lowercase form on read, so a hand-written non-canonical id still matches its resource.

Every write is a full-store read-modify-write. It MUST be serialized by an exclusive advisory lock (`flock(LOCK_EX)` on a sibling `aliases.lock`, never on `aliases.toml` itself, whose inode the atomic-rename write replaces) held across the reload → validation re-check → mutate → save critical section, so concurrent `umbra` processes cannot interleave and clobber each other (last-writer-wins). Slow work (Console/SSH calls) MUST happen outside the lock, and the full creation check MUST be repeated under the lock — the name still free **and** the target still unaliased — a check taken before it is not authoritative. A `rename` re-checks only the name: it moves an alias whose target is legitimately aliased already, by that very alias. On non-unix the lock is best-effort (a no-op), as with the store's owner-only permission tightening.

### `cvms/<cvm_id>.state.toml`

Per-CVM remembered values used to make repeated invocations less verbose. The CLI writes this file when a session verb is invoked with an explicit `--workspace`, and reads it as the fallback when the flag is absent. Missing files, malformed TOML, and values that fail workspace validation (§6.4) MUST be treated as "no cached state" — the CLI MUST NOT surface an error to the user; the verb proceeds as if no flag and no cache were provided.

```toml
workspace = "workspaces/myrepo"
```

Scope:

- `--workspace` on `umbra claude`, `umbra codex`, `umbra code`, and `umbra cursor` writes the supplied value into this file under the resolved CVM id.
- Absent `--workspace`, the same four verbs read this file and use `workspace` as if the flag had been supplied.
- A single cached value is shared across all four verbs for a given CVM.
- To reset the cache, pass `--workspace /home/dev`, or delete the file.

Implementations MUST write this file with mode `0600` using the same atomic-replace pattern as `session.json` (§4.5).

### `update-check.json`

Cache backing the passive new-version check (§3.6 `umbra update`); machine-written by the detached background probe and by explicit `umbra update` runs.

```json
{
  "checked_at": "2026-07-08T07:37:00Z",
  "latest_version": "0.4.0"
}
```

`checked_at` is when the probe slot was last claimed; a new background probe is spawned only when it is older than 24 hours. `latest_version` may be `null` between claiming the slot and the probe completing. A missing or malformed file MUST be treated as "never checked" — the CLI MUST NOT surface an error; deleting the file is always safe. Written with mode `0600` using the same atomic-replace pattern as `session.json` (§4.5).

### 4.5 File permissions

On Unix:

- Config directory MUST be created and maintained at mode `0700`. Implementations MUST tighten the mode on every startup if the directory exists at a looser setting (e.g. left over from an earlier version).
- `session.json` MUST be written atomically — write to a temporary file in the same directory with `O_NOFOLLOW`, then `rename(2)` into place. The temporary file's mode MUST be `0600`. The implementation MUST NOT follow a pre-existing symlink at either the target path or the temporary path.
- `config.toml` and `aliases.toml` MUST be written with mode `0600`.

On Windows: files receive the platform default ACL. Implementations SHOULD integrate with the OS secret store (Credential Manager) for bearer tokens when available; until they do, they MUST document the weaker protection model and warn at `WARN`-level on first login.

## 5. Authentication and session

### 5.1 Login flows

`umbra auth login` supports two mutually exclusive flows. The user selects a flow explicitly — the CLI performs no auto-detection of browser availability, `DISPLAY`, SSH session, or similar signals.

**Loopback + PKCE (default).**

1. The CLI binds an ephemeral port on `127.0.0.1` (OS-assigned; retried a small number of times on failure before exiting `1`).
2. It generates a PKCE `code_verifier` and `code_challenge`, then constructs the authorize URL with the `127.0.0.1:<port>/callback` redirect URI, the PKCE challenge, and an unguessable `state` parameter.
3. It opens the authorize URL in the user's default browser.
4. It waits on the loopback server (short timeout — a few minutes) for the browser to redirect back with `code` and `state`.
5. It verifies `state` matches what it generated, rejects any other request.
6. It exchanges `code` + `code_verifier` for tokens at the Console's token endpoint, writes `session.json` atomically (§4.5), and tears down the loopback server.

The loopback server MUST only accept a single request on `/callback` and MUST reject all other paths and methods. It MUST bind to `127.0.0.1` only — never `0.0.0.0` or `::`. A timeout or a mismatched `state` exits `1`.

**Device flow (`--device` / `--no-browser`).**

1. The CLI calls `POST /auth/device/start` on the Console and receives `device_code`, `user_code`, `verification_url`, optional `verification_url_complete`, `polling_secret`, `expires_in`, and `interval`. `device_code` is the opaque polling identifier (RFC 8628); `user_code` is the short human-readable code the user types into the browser.
2. It prints `verification_url`, `user_code`, `expires_in`, and, when present, `verification_url_complete` on stderr (the user can complete authentication on any device with a browser, not necessarily the current machine). The CLI MUST treat `polling_secret` (and `device_code`) as confidential values: they MUST NOT be printed to stdout, logged, or persisted to disk. The CLI MUST NOT infer a complete verification URL locally when the Console omits `verification_url_complete`.
3. It polls `POST /auth/device/poll` at the prescribed `interval`, sending `{device_code, polling_secret}` on every request, until the user completes authentication, the code expires, or a non-retryable error is returned. Console verifies `polling_secret` with a constant-time compare; without it the Console rejects the poll.
4. On success it writes `session.json` atomically (§4.5); on timeout or error it exits `1`.

Either flow, on success, produces the same `session.json` contents and the same stdout/JSON output — downstream commands are agnostic to how the session was obtained.

### 5.2 Session contents

The session file fields are listed in §4.4. After receiving the JWT pair from the Console (loopback flow `POST /auth/token` or device flow `POST /auth/device/poll`), the CLI MUST issue a `GET /me` call with the new access token and copy `id`, `email`, and `entity` (denormalised) from the response into `session.json`. The access token itself is treated as an opaque bearer and MUST NOT be parsed by the CLI for any purpose.

### 5.3 Refresh and freshness

Every command that contacts the Console loads the session file and checks the access token's `expires_at`:

- If `expires_at > now`, the token is used as-is.
- If `expires_at ≤ now` and a `refresh_token` is present with `refresh_expires_at > now`, the CLI silently exchanges the refresh token for a new access token, rewrites `session.json` atomically, and proceeds. The refresh MUST be transparent to the user.
- Otherwise the CLI exits `2` with a message directing the user to run `umbra auth login`.

Refresh failures (e.g. the refresh token was revoked) MUST exit `2` and MUST NOT leave `session.json` in a half-written state.

### 5.4 Logout

`umbra auth logout` deletes `session.json` AND notifies the Console (`POST /auth/logout`) so the Console adds the access-token's `jti` to its revocation denylist and revokes the matching refresh token. If `session.json` is absent the command is a no-op and still exits `0`. The Console MUST be notified — the SHOULD has been tightened to MUST since the Console supports revocation in v0.

A network or API failure during the Console notification MUST NOT cause a non-zero exit: the local session file is cleared regardless, and a `WARN` log line records the failure. The user has logged out from the local CLI's perspective even if the Console's denylist update lagged; the leaked-credentials window is bounded by the access token's TTL.

### 5.5 Token hygiene

- The access token MUST NEVER be logged, implicitly printed to stdout as a side effect of any command, or passed on the command line. A future dedicated command whose sole purpose is to emit the token (e.g. for scripting) is not covered by this prohibition.
- The in-memory representation of the session MUST be zeroed on process exit or when the session is reloaded after a refresh, so the bearer does not survive in core dumps or swap pages.
- The session file MUST NOT contain any field beyond those listed in §4.4; extra fields encountered on load MUST be dropped with a `DEBUG`level log line.

## 6. Transport and remote execution

### 6.1 aTLS tunnel

`umbra tunnel <TARGET>` opens a WebSocket connection to `wss://<fqdn>/umbra/tunnel`, relays bytes between WebSocket frames and stdin/stdout, and verifies that the remote end of the WebSocket lives inside the expected TEE. The Dev CVM's `nginx-cert-manager` (a shade-owned service; see `docs/specs/dev-cvm.md` §2.1) terminates publicly-trusted TLS at `<fqdn>` with a Let's Encrypt certificate; the local TLS endpoint is normal browser-trusted TLS. The WebSocket payload is the underlying TCP stream that the Dev CVM's `dev-tunnel` service relays to (sshd:22 in v0), so SSH and any other protocol run over the tunnel byte-transparently. The verification library is `atlas-rs`; every check below is implemented in that crate.

**Attestation flow.** For every tunnel, the CLI MUST:

1. Complete the public TLS handshake against `<fqdn>` (Let's Encrypt SAN binds the FQDN). Reject any TLS error.
2. Extract the EKM (RFC 5705, exporter label `EXPORTER-Channel-Binding`, 32 bytes).
3. Generate a fresh 32-byte nonce.
4. Issue `POST /tdx_quote` with `nonce_hex` as the request body. The Dev CVM's `nginx-cert-manager` injects the EKM into the upstream request as `X-TLS-EKM-Channel-Binding`; the CLI MUST NOT set that header itself.
5. Verify the returned TDX quote against the per-CVM `policy.json` (schema in `docs/specs/dev-cvm.md` §8.1) AND verify `report_data == SHA512(nonce_bytes || ekm_bytes)`. Any mismatch on bootchain, OS image hash, compose-template hash, RTMR3 binding (`RTMR3 == SHA-384(JCS(policy.rtmr3_binding))`, RFC 8785), or report-data binding MUST abort the tunnel before any application bytes flow in either direction.

`atlas-rs` performs steps 1–5. Quotes are bound to a specific TLS session via the EKM; the CLI MUST NOT cache quotes across tunnels and MAY cache only for the lifetime of a single tunnel.

**Per-CVM policy resolution.** Because each Dev CVM has a unique `rtmr3_binding` payload (its `cvm_id`, per-CVM proxy-bearer digest, and the developer's key digest; `docs/specs/dev-cvm.md` §8.1, §8.2), the policy file is per-CVM, not global. The CLI resolves the policy in this order:

1. **Per-CVM file.** When `<TARGET>` resolves to a known `<cvm_id>`, look for `${config_dir}/cvms/<cvm_id>.atls-policy.json` (mode `0600`). Use it if present.
2. **Lazy bundle fetch.** If the file is missing, the CLI calls `GET /cvms/{cvm_id}/policy-bundle` (`docs/specs/console.md` §3.6) and writes the per-CVM file directly from the current active bundle's `compose_template`, `expected_bootchain`, `os_image_hash`, and `rtmr3_binding` (§3.4 `cvm launch` / `cvm update`). The bundle is re-fetchable for the CVM's lifetime — no first-read disclosure semantics — because it contains hashes rather than bearer plaintext. A successful `cvm update` may replace the active bundle, but an existing local policy file is replaced only after the user confirms the changed trusted measurement.
3. **Global fallback.** If `<TARGET>` is not a known CVM (e.g. `umbra tunnel <FQDN>` invoked directly against a raw FQDN), use the path resolved from the `atls_policy` config key (§4.1).
4. **Unresolved.** If steps 1–3 all fail, exit `4` with a clear message before any network I/O.

If tunnel-time verification fails with an app-compose hash mismatch while using the canonical per-CVM policy path `${config_dir}/cvms/<cvm_id>.atls-policy.json`, the CLI SHOULD explain that the measured CVM does not match the local policy, state that no SSH/agent bytes were sent, prompt on the controlling terminal to fetch Console's current policy from `GET /cvms/{cvm_id}/policy-bundle`, and retry verification once after an explicit yes. The prompt MUST write only to stderr or the controlling terminal, never stdout, because `umbra tunnel` is also used as an SSH `ProxyCommand` and stdout is the tunnel byte stream. If there is no controlling terminal, the user declines, the policy path is not the canonical per-CVM file, the refresh fails, or the retry fails, the tunnel remains failed closed.

A missing, unreadable, or malformed JSON policy MUST exit `4`. The CLI MUST log the effective policy path at `INFO` and the evaluation outcome (pass/fail with reason) at `DEBUG`; the policy document itself MUST NOT be logged. The policy is not negotiated with the remote — it is a local enforcement document controlled by the user or their organisation.

The CLI dials the Dev CVM FQDN directly: the FQDN is the TCP connect target, TLS SNI, certificate identity, attestation policy subject, and WebSocket `Host` header. A legacy policy document MAY still carry a top-level `connect_host` string from an earlier release; the CLI MUST parse such a file without error and ignore that key. It MUST NOT route by it.

Commands that do not open an aTLS tunnel (`auth login`, `cvm list`, `key add`, etc.) are unaffected by this requirement.

**Bypass (dev-only).** The `atls_policy_insecure_skip` configuration (§4.1) disables policy evaluation to speed up local development loops. When it resolves to `true`:

- Steps 1–4 of policy resolution are skipped: the tunnel proceeds regardless of whether a per-CVM file or global path is configured, and regardless of whether the quote would have satisfied the policy.
- The TLS handshake AND the TDX quote retrieval are still performed (the gateway requires `POST /tdx_quote` to succeed before relaying); only the local policy *check* is bypassed. Unattested TLS is still rejected (§7).
- The CLI MUST emit exactly one `WARN`level log line per tunnel: `aTLS policy enforcement disabled — dev-only escape hatch active`. The line MUST include the target CVM identifier. This warning MUST appear even when stderr is not a terminal, so CI logs capture it.
- When both `atls_policy` and `atls_policy_insecure_skip=true` are set, the bypass wins and the configured path is logged at `DEBUG` as "ignored due to insecure skip."

The bypass is intended for ephemeral local development against throwaway CVMs. Deploying a build with `atls_policy_insecure_skip` set via the config file or a persistent env var is a spec violation. The bypass is CLI-side only — the Dev CVM gateway always produces the quote, and the Console-side trust paths (see plan §Attestation) are unaffected.

### 6.2 SSH ProxyCommand pattern

`umbra ssh` is meant to work without additional ssh configuration. Users might choose to configure `~/.ssh/config` along these lines:

```
Host *.cvms.example.com
  User developer
  ProxyCommand umbra tunnel %h
```

The system `ssh`, `scp`, `rsync`, `git` over SSH, and `ssh-copy-id` should then work against any CVM FQDN with no further flags.

**Host-key handling.** The Dev CVM's identity is established by aTLS attestation on the underlying tunnel (§6.1), not by SSH host keys, and CVM containers regenerate host keys on every start. Configurations the CLI generates or recommends MUST therefore set `StrictHostKeyChecking no` and `UserKnownHostsFile /dev/null` for CVM hosts, so that ephemeral host keys do not produce spurious warnings or block reconnection. This relaxation is safe only because the aTLS layer below SSH has already attested the remote.

### 6.3 Session verbs on top of the tunnel

Session verbs (`ssh`, `claude`, `codex`, `ps`, `attach`, `kill`) MUST invoke the system `ssh` under the hood with the same `ProxyCommand`. They differ only in the remote command sent to the CVM (start, attach to, list, or kill the corresponding dtach socket). Editor verbs (`code`, `cursor`) MUST launch the local editor with an Umbra-managed SSH config and `ssh` wrapper that invokes the system `ssh` with the same `ProxyCommand`, because VS Code-compatible Remote SSH clients do not accept a one-shot `ProxyCommand` on their own command line.

### 6.4 dtach session model

Sessions are dtach sockets on the Dev CVM. The CVM image MUST provision a per-user runtime directory at `/run/umbra/sessions/` (mode `0700`, owned by the developer's user) on boot; each session is a socket at `/run/umbra/sessions/<session-name>.sock`. The directory lives on tmpfs, so sessions do not survive a CVM reboot — agent processes are gone in that case anyway. All session state lives on the CVM; the CLI MUST NOT run dtach locally or mirror sockets to the developer machine.

Auto-generated session names MUST be of the form `<verb>-<yyyymmdd>-<hhmmss>` in UTC (e.g. `claude-20260416-143022`); each name corresponds to one socket file. Session names MUST be unique per CVM; if a collision occurs with `--name`, the command MUST exit `1` with a clear message. The default detach key is `Ctrl-\` (dtach's default).

**Listing (`umbra ps`).** The remote command MUST enumerate `/run/umbra/sessions/*.sock` and report one row per socket. Creation time is the socket file's `mtime`. The `attached` state is determined by probing whether any process holds the socket (e.g. via `fuser` or `lsof`); this is a runtime probe, not first-class dtach metadata.

**Killing (`umbra kill`).** The remote command MUST resolve the target to a socket path, find the dtach process holding it (e.g. `fuser` on the socket), send `SIGTERM`, and unlink the socket once the process exits. A process that ignores `SIGTERM` after a short timeout MAY be killed with `SIGKILL`.

**Agent workspace paths (`umbra claude` / `umbra codex --workspace`).** Before starting the agent binary, the remote command MUST change into the requested directory. Workspace paths MUST be validated client-side: non-empty, at most 512 bytes, no `..` segments, and only ASCII letters, digits, `/`, `.`, `_`, and `-` in the path body. Paths beginning with `~/` expand under the developer home directory; absolute paths MUST begin with `/`; all other paths are resolved relative to the developer home directory. Tilde forms other than `~/…` MUST be rejected.

### 6.5 Client-side aliases

`aliases.toml` (§4.4) maps human-friendly names to long identifiers of four kinds — `cvm`, `profile`, `ssh-key` (each a Console resource UUID) and `session` (a `{ session, cvm }` value-object). Resolution is a single funnel per kind:

1. For a UUID-backed kind, a value that is already a UUID resolves to itself **without reading the store** — so a corrupt `aliases.toml` never blocks a command driven by a raw id. (Alias names MUST NOT be UUIDs, which keeps this bypass sound; creating a UUID-shaped alias exits `4`.)
2. Otherwise, if the value matches a known alias of that kind, it resolves to the underlying identifier; a non-UUID value therefore consults the store, and a malformed store surfaces an error rather than being silently ignored.
3. Otherwise the value is used unchanged (so a raw session name, or a not-yet-aliased id, still works).

Resolution MUST be applied wherever the CLI accepts the corresponding identifier: `cvm` aliases in CVM-target resolution (§4.2, covering `ssh`/`claude`/`codex`/`code`/`cursor`/`attach`/`kill`/`cvm` lifecycle verbs), `profile`/`ssh-key` aliases at `cvm launch`, and `session` aliases in `attach`/`kill`. A `session` alias carries its CVM, so it resolves without `--cvm`; an explicit `--cvm` overrides the stored CVM with a stderr warning. `ps` MUST consult `aliases.toml` to display the alias beside each live session, and `cvm list` / `profile list` / `key list` / `profile show` MUST display it beside each record they list (the reverse display of §3.4 `umbra alias`); all five report an unreadable store in the cell plus one stderr line, and none of them fails because of it.

Alias names MUST be globally unique across all kinds; creating a duplicate exits `1`. A resource MUST carry at most one alias — a `cvm`/`profile`/`ssh-key` UUID, or a `{session, cvm}` pair — so creating a second alias for an already-aliased target exits `1` and names the existing alias; `rename` changes that alias's name, and `rm` + re-create repoints it. This is what makes the reverse display of §3.4 well-defined for any store the CLI wrote: at most one local name can label a record. The rule is enforced on writes, so a hand-edited store may still hold two (§4.4). Creation is fail-closed: the target MUST be confirmed to exist (Console lookup for `cvm`/`profile`/`ssh-key`; live-session SSH probe for `session`) before the alias is recorded, and a `session` alias whose name collides with a live dtach session name on that CVM MUST be rejected (exit `1`) so it cannot silently shadow the real session. Deleting a resource through the CLI (`cvm terminate`, `key remove`, `kill`) SHOULD prune the aliases that point at it as a convenience — correctness still rests on the use-time revalidation above (which also covers out-of-CLI deletions this prune cannot see), and a local-store failure MUST NOT fail the delete.

## 7. Security properties

These are contracts the CLI MUST enforce; violations are spec bugs.

- **Session-file integrity** — writes are atomic (tmpfile + rename) with mode `0600` and `O_NOFOLLOW` on Unix. Pre-planted symlinks at the target or temporary path MUST cause the write to fail rather than follow the link.
- **Config-directory confinement** — the directory is created at mode `0700` and tightened to `0700` on every startup if looser.
- **Secret zeroization** — bearer tokens and refresh tokens MUST be zeroed in memory when the session is dropped or reloaded, so they don't survive in core dumps or swap.
- **Attested TLS** — every Dev CVM connection MUST terminate with attestation; an unattested TLS session MUST be rejected even if otherwise valid.
- **aTLS policy enforcement** — every aTLS tunnel MUST be validated against the configured policy file (§6.1). A tunnel with no configured policy, or with attestation evidence that does not satisfy the policy, MUST be refused before any application bytes cross the link. The `atls_policy_insecure_skip` escape hatch (§6.1) bypasses this check for local development; when active, the CLI MUST emit a visible `WARN` per tunnel so the weakened posture cannot go unnoticed.
- **No secrets in argv** — bearer tokens, OIDC codes, and passwords MUST NEVER be accepted as command-line arguments. Secrets arrive via the session file, env vars, or interactive flows.
- **No secrets in logs** — regardless of log level, tokens and OIDC codes MUST be redacted from all log output.
- **Error output is safe** — error messages MUST NOT leak internal paths, stack traces, or configuration values that were not part of the user's input. This applies regardless of output mode.

## 8. Generated artifacts

Implementations MUST produce the following artifacts on release build and include them in the distributed package:

- One troff man page per command and subcommand.
- A single Markdown reference rendered from the command tree.

Artifacts MUST be derived from the same in-process command definitions that drive argument parsing, so they cannot drift from the actual command surface.

## 9. Implementation stack

This section specifies the language and libraries the implementation MUST use to meet the behavioral requirements above. Rationale is given for each choice so future substitutions can be evaluated against the constraints they need to satisfy.

This section is still WIP. Other alternatives have to be assessed before starting the implementation.

### 9.1 Language: Rust

- **Single static binary** across Linux, macOS, and Windows matches the distribution model (§4.3) and lets `umbra update` (§3.6) replace the whole install with one atomic file rename. Rust produces small, self-contained executables with no runtime dependency on a VM or interpreter.
- **Memory-safe secret handling.** The token-zeroization requirement (§5.5) and atomic file writes with `O_NOFOLLOW` and mode `0600` (§4.5) are all expressible directly in safe Rust through `zeroize` and `std::os::unix::fs::OpenOptionsExt`. No unsafe escape hatches are needed.
- **Startup time.** The CLI is invoked repeatedly (every `auth token` call, every SSH `ProxyCommand` spawn for a tunnel, every `ps` check). Compiled Rust binaries start in a few milliseconds; a VM-based runtime would be relatively slower.

### 9.2 CLI framework: `clap` (v4.x, derive API)

- Generates the entire command tree from annotated Rust types; flag definitions double as documentation.
- The `clap_mangen` sibling crate produces troff man pages and `clap-markdown` produces the Markdown reference — both required by §8. Artifacts cannot drift from the parser.
- `clap_complete` produces shell-completion scripts for `umbra completions <SHELL>` (§3.6).

### 9.3 HTTP client: `reqwest` with `rustls` TLS backend

- Async HTTP with JSON convenience methods; used for every Console REST call (§3.4, §3.5).
- The `rustls` backend is pure Rust, keeping the static-binary story intact. An OpenSSL backend would drag in a system dependency that breaks single-file distribution on Linux distros.
- Disables `default-features` to avoid pulling in native-TLS; explicitly opts into `rustls-tls`, `json`, `gzip`.

### 9.4 OIDC flows: `openidconnect` (+ `tiny_http` for the loopback callback)

- `openidconnect` implements both login flows required by §5.1: OAuth 2.0 Authorization Code with PKCE, and device flow. It handles discovery, token validation, JWK fetching, and nonce / `state` handling — all error-prone if reimplemented by hand.
- `tiny_http` is a small, synchronous HTTP server used exclusively for the loopback callback in the Authorization Code flow. It is started on `127.0.0.1` at an OS-assigned port, accepts a single `/callback` request, and shuts down. A sync server is appropriate here: the listener lives for at most a few minutes during login and does not share a runtime with `tokio`.
- Browser launching is delegated to `open` or equivalent, which hands the authorize URL to the user's default browser via the OS-appropriate opener.

### 9.5 aTLS: `atlas-rs`

- `atlas-rs` is the attested TLS implementation that enforces the attestation handshake

### 9.6 Serialization: `serde`, `serde_json`, `toml`

- `serde` + `serde_json` for `session.json` and all JSON output (§2.3, §4.4).
- `toml` for `config.toml` and `aliases.toml` (§4.4).
- Both libraries support `#[serde(deny_unknown_fields)]` selectively, letting the spec's "unknown config keys warn but don't fail" rule be implemented by mixing default handling (for top-level config) with strict handling (for session/alias files).

### 9.7 Secret handling: `zeroize`

- Implements the §5.5 requirement that access tokens and refresh tokens are zeroed on drop via a volatile write the compiler cannot elide.
- Applied to `Session`, and to any intermediate buffers that hold the token (request bodies, refresh responses, device-flow payloads).

### 9.8 Filesystem: `std::fs` + `libc::O_NOFOLLOW`

- No third-party filesystem crate. The atomic-write + symlink-refusal semantics (§4.5) are implemented directly with `std::fs::OpenOptions` + `.custom_flags(libc::O_NOFOLLOW)` on Unix, followed by `rename(2)`.
- On Windows, `std::fs::write` is used; the weaker protection is acknowledged in §4.5 and §10 "out of scope".

### 9.9 Logging: `tracing` + `tracing-subscriber`

- Structured logging to stderr at the levels required by §2.5. `tracing` allows spans (e.g. "tunnel to cvm-xxx") so DEBUG output stays readable under concurrency.
- The `EnvFilter` layer honors `UMBRA_LOG_LEVEL` and integrates with `v`/`vv`/`vvv` flag counts.

### 9.10 Directory discovery: `directories`

- Resolves the platform-appropriate config directory (§4.3) — XDG on Linux, `Application Support` on macOS, `%APPDATA%` on Windows — without each platform's path rules being spelled out by hand.

### 9.11 Terminal rendering: `comfy-table` + `owo-colors`

- `comfy-table` renders tables that adapt to terminal width, falling back to a stacked `key: value` layout when columns would wrap. This is what lets the §2.3 "table or structured list per fit" rule be implemented cleanly.
- `owo-colors` applies ANSI colors that respect `no-color` / `NO_COLOR` / `UMBRA_NO_COLOR`.

### 9.12 Testing

- **Unit tests** — colocated in source modules; cover config parsing, alias resolution, token freshness, file-mode enforcement.
- **Snapshot tests** — `insta` captures the exact `-help` output for every subcommand so CLI-surface changes are intentional and reviewed.
- **API mocking** — `wiremock` stands up a fake Console to exercise every endpoint in success and canonical failure modes.
- **Tunnel tests** — an in-process WebSocket echo server verifies byte transparency of the tunnel (§6.1).
- **CLI integration tests** — spawn the release binary with controlled config and session fixtures to validate end-to-end behavior for each command.

### 9.13 Build profile

Release builds MUST use: `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`, `strip = "symbols"`. This trades build time for smaller binaries and better runtime performance on commands that run many times a day (tunnel, ps, auth token).

## 10. Out of scope

The following are deliberately excluded from this specification. They may be added in a later revision.

- OS secret-store integration for the session file (beyond the Windows note in §4.5).
- Multi-account session storage. The CLI holds exactly one session at a time; users who need to switch between accounts can do so via the config-directory override (`config` / `UMBRA_CONFIG_DIR`).
- Interactive prompting for config values. The CLI is strictly non-interactive except for the `auth login` device-flow URL.
- Generic `umbra operation` noun. Async commands today (§2.6) submit and either wait or return a handle; the user who runs `--no-wait` must record the `operation_id` and re-poll out of band. A future revision will add `umbra operation show <op_id>` (single GET) and `umbra operation wait <op_id>` (poll until terminal) so a `--no-wait` caller has a first-class re-poll surface. `umbra operation list` is on the wishlist but not yet committed.
- Console-routed admin verbs not yet realized in CLI commands. The Console exposes routes for these flows (cited below against `docs/specs/console.md`); each will get a matching CLI verb in a follow-up revision. Until then, operators drive them via direct HTTP:
  - Golden-measurement / aTLS policy fetch (`umbra policy fetch`) — today the CLI consumes a policy file via `--atls-policy` (§6.1) and a per-CVM policy bundle at launch (§3.4); distribution of refreshed templates remains out-of-band until this verb lands.
