---
name: umbra-cli
description: Use when operating Umbra through the `umbra` CLI: authentication, profiles, permissions, quotas, keys, secrets, Dev and Security CVMs, sessions, audit, and traffic logs.
---

# umbra-cli

Umbra runs coding agents inside attested Dev CVMs. Sandbox egress traverses an entity Security CVM for policy, DLP, credential injection, and traffic logs. The Console is authoritative; the CLI is a thin HTTPS and aTLS client.

## Orient in three commands

```bash
umbra auth status
umbra status
umbra config show
```

## Start a developer session

```bash
umbra auth login https://console.example.com
umbra cvm launch
umbra ssh
```

Then open an agent or editor in the sandbox:

```bash
umbra claude --workspace ~/workspaces/myrepo
umbra codex --workspace ~/workspaces/myrepo
umbra code --workspace ~/workspaces/myrepo
umbra cursor --workspace ~/workspaces/myrepo
```

The explicit workspace is cached per CVM and reused by later bare agent/editor commands.

## Command map

| Group | Important verbs | Purpose |
| --- | --- | --- |
| `auth` | `login`, `logout`, `status`, `refresh`, `token` | Google OIDC and Console session lifecycle. Use `--device` for a configured headless flow. |
| `config` | `show` | Show effective values and whether they came from a flag, environment, file, or default. |
| `entity` | `add`, `list` | Tenant entities; creation requires `PLATFORM_OPERATOR`. |
| `user` | `add`, `list`, `show`, `deactivate`, `reactivate`, `erase`, `permissions` | User lifecycle and permission grants. |
| `key` | `list`, `add`, `remove` | The caller's SSH public keys and local identity mapping. |
| `secret` | `set`, `list`, `remove` | Write-only, per-user secrets with mandatory host bindings. Values arrive on stdin or from a file, never argv. |
| `profile` | `create`, `list`, `show`, `configure`, `members`, `grants`, `connections create` | Policy authoring and membership. `configure` replaces the complete policy document. `grants` shows redacted injection status; `connections create` mints a one-time OAuth connect link. |
| `quota` | `get`, `set`, `clear` | Entity or user resource limits. |
| `cvm` | `list`, `instance-types`, `launch`, `attach`, `detach`, `start`, `stop`, `update`, `terminate` | Dev CVM lifecycle. |
| `security-cvm` | `show`, `launch`, `update`, `terminate`, `attestation` | The entity's single Security CVM. |
| `ssh`, `claude`, `codex`, `code`, `cursor` | top-level | Open shell, agent, or editor sessions. `claude connect` and `codex connect` mint SC-injected credentials without putting the real token in the sandbox. |
| `ps`, `attach`, `kill` | top-level | Manage persistent dtach sessions in Dev CVMs. |
| `alias` | `cvm`, `profile`, `ssh-key`, `session`, `list`, `rm`, `rename`, `prune` | Local names for UUID-backed resources and sessions. |
| `tunnel` | top-level | Low-level aTLS-verified WebSocket pipe. |
| `audit` | `events`, `export` | Control-plane audit reads and exports. |
| `traffic-logs` | top-level | Egress log queries by CVM, Security CVM, and time. |
| `admin` | `sessions revoke`, `keys rotate` | Platform maintenance. |
| `reconcile` | top-level | Run one provider reconciliation pass. |
| `version`, `completions`, `update` | top-level | Version information, shell completion, and fail-closed self-update from immutable versioned artifacts. Update requires the retained pinned `slsa-verifier` and verifies checksum plus fixed release provenance before execution or replacement. |

Every command supports `--help`. Consult help before guessing a flag.

`umbra update` fails closed unless the trusted verifier is available. Keep the bootstrap-installed verifier on an absolute `PATH` directory or set `UMBRA_SLSA_VERIFIER` to its absolute executable path. Provenance authenticates the artifact, not the mirror's mutable version-pointer freshness: normal updates refuse to downgrade below the installed version, but a mirror can suppress a newer release or replay an intermediate valid one. Explicit `--version` and `--force` intentionally permit rollback.

## Global flags

| Flag | Environment | Meaning |
| --- | --- | --- |
| `--json` | `UMBRA_OUTPUT=json` | Structured output on commands that define it. |
| `--profile <UUID|alias>` | `UMBRA_DEFAULT_PROFILE` | Select a profile; repeat where multiple profiles are accepted. |
| `--console-url <URL>` | `UMBRA_CONSOLE_URL` | Override the Console. |
| `--config <DIR>` | `UMBRA_CONFIG_DIR` | Override the local state directory. |
| `--request-id <UUID>` | `UMBRA_REQUEST_ID` | Pin a request ID for diagnosis. |
| `--force` | - | Skip optimistic-concurrency protection where supported; use sparingly. |
| `--atls-policy <PATH>` | `UMBRA_ATLS_POLICY` | Supply explicit local trust policy material. |

## Admin onboarding

Pre-create a developer when they need permissions and profile membership before their first login:

```bash
umbra --json user add alice@example.com --permission CVM_LAUNCH
umbra --profile <profile-id> profile members add <user-id>
```

A domain-matched user can otherwise be materialized on first successful OIDC login. `CVM_LAUNCH` is the minimum named permission for launching a Dev CVM; profile membership separately controls which policy may be attached.

## What a bare `cvm launch` does

- Auto-selects the profile only when exactly one assigned profile is available.
- Reuses a registered SSH key with a discoverable private half, or creates and registers a non-conflicting Ed25519 key.
- Persists `default_cvm`, any auto-selected profile, and the local SSH identity.
- Writes `~/.umbra/cvms/<cvm-id>.atls-policy.json` for later tunnel checks.
- Waits for readiness unless `--no-wait` is supplied.

The destructive `cvm stop` and `cvm terminate` require an explicit CVM target; they never silently use the default.

## Sessions and aliases

```bash
umbra alias cvm <cvm-id> dev-box
umbra ssh dev-box
umbra claude dev-box --name review --alias review-session
umbra ps
umbra attach review-session
umbra alias prune --dry-run
```

Aliases are local, globally unique across alias kinds, and revalidated when used. A stale alias produces a clear error; remove it or run `alias prune`.

`umbra cursor` controls the Remote SSH path only. Cursor-hosted web and integration tools may open traffic outside the Dev CVM and therefore outside Security CVM policy and logs. Use `ssh`, `claude`, or `codex` when governed in-sandbox egress is required.

## Per-user secrets

Store personal credentials without giving their plaintext to a profile:

```bash
printf '%s' "$API_TOKEN" | \
  umbra secret set api-token --host api.example.com
umbra secret list
```

A profile references it with:

```json
{
  "secret_injections": [
    {
      "id": "example-api-token",
      "match": {"scheme": "https", "host": "api.example.com", "ports": [443]},
      "type": "request_header",
      "header": "authorization",
      "value_template": "Bearer ${secret}",
      "value_from": {"user_secret": "api-token"}
    }
  ]
}
```

Host binding is the user's consent boundary. `*.example.com` does not include the apex; list both when both are intended. `*` explicitly opts out of host binding.

## Connect and managed credentials

The Security CVM still injects secrets at egress. Connect is the higher-level acquisition path so the sandbox never holds the real token.

```bash
claude setup-token | umbra --profile <profile-id> claude connect --cvm <cvm-id>
umbra --profile <profile-id> codex connect --cvm <cvm-id>
umbra --profile <profile-id> profile grants
umbra --profile <profile-id> profile connections create slack
```

- `claude connect` reads the token from stdin only. The sandbox sees `CLAUDE_CODE_OAUTH_TOKEN=umbra-proxy-injected`; `--no-oauth-env` opts a session out.
- `codex connect` runs a throwaway-home laptop login, uploads the refresh grant, and plants a placeholder `~/.codex/auth.json`. Never run `codex login` inside the CVM.
- `profile grants` shows minted/rotation status without secret values. Re-auth is the same command that connected the first time.
- Browser Connect lives at `/connect/<integration>` after an admin configures the entity OAuth integration. Runbooks: `docs/onboarding/claude-code.md`, `docs/onboarding/codex-chatgpt.md`, `docs/onboarding/slack-claude.md`.

Minted injections are still wiped by `profile configure` unless re-supplied inline; re-mint after any wholesale policy edit.

## Profile guarantees

A profile is one JSON document replaced wholesale by `profile configure`. Important keys are `egress_boundary`, `allowed_destinations`, `blocked_destinations`, `secret_patterns`, `secret_injections`, and `sandbox_env`.

Enforcement is deny list, then allow-list gate, then secret injection. A boundary profile restricts authorization to boundary profiles' allow lists.

Inline `secret_injections[*].value` is an entity-shared, write-only secret. Every configure call must resupply each inline value or its stored material is removed. A `value_from.user_secret` injection stores no profile-side material and can be edited without wiping a user's credential.

Governed inbound WebSocket filtering is fail-closed. A frame must be selected by an assertion and satisfy its required JSON pointers. Author one assertion per envelope/identity-path family; a broad assertion can over-drop legitimate subtypes.

## Output and exit contract

- Payload goes to stdout; diagnostics, prompts, and logs go to stderr.
- On a non-zero exit, stdout is empty.
- `--json` affects only commands with a defined structured payload.

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | General error. |
| 2 | Authentication required or invalid session. |
| 3 | Wait timeout; the server operation may still be running. |
| 4 | Usage error. |

## Local state

```text
~/.umbra/
  config.toml                     resolved defaults
  session.json                    access and refresh tokens; mode 0600
  aliases.toml                    local aliases
  ssh-identities.toml             key-id to private-key path; no key material
  cvms/<id>.atls-policy.json      per-CVM trust material
  cvms/<id>.state.toml            cached workspace
  update-check.json               safe-to-delete release probe cache
  editor-ssh/ and ssh-control/    managed OpenSSH state
```

## Common gotchas

- A profile argument accepts a UUID or known profile alias, not an arbitrary profile display name.
- `cvm instance-types` is the authoritative launchable set; do not guess names.
- Without `CVM_MANAGE`, `cvm list` returns only the caller's CVMs.
- A `412 PRECONDITION_FAILED` on membership means the profile changed between read and write; retry instead of reaching for `--force`.
- The Dev CVM uses dtach, not tmux.
- Editor wrappers use a managed SSH config and may ignore `~/.ssh/config`. Supply `--identity-file` when automatic key resolution cannot find a match.
- Never put a token or secret on argv. `claude connect` reads the token from stdin for this reason.
- Editing a profile with minted injections requires a re-mint; stored values cannot be read back.
- An aTLS policy mismatch is a trust failure. Review the new policy material before accepting a replacement; do not bypass verification.

When diagnosis remains unclear, run command help, `umbra config show`, and `umbra status`, then use the public support process without including tokens, session files, personal data, or live deployment material.
