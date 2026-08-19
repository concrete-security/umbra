# OAuth-minted profile secrets

Contract for putting agent OAuth / subscription credentials into profile
secret injections without the credential ever living inside the Dev CVM.
This spec grows a section per shipped mechanism; the self-service mint
(§2–§5) is the first. Planned follow-ons are listed in §6.

## 1. Goal and trust model

Developers must never authenticate agents by placing long-lived credentials
inside the sandbox (interactive `claude /login`, pasted `~/.codex/auth.json`,
real tokens in env vars). A prompt-injectable, code-running agent can read
anything in its box, and in-box credentials silently expire mid-run.

The model instead is:

- The credential is stored as **profile secret material**
  (`profile_secret_material`, AES-256-GCM under `SECRET_INJECTION_KEK_B64`,
  write-only: no read path ever returns a stored value).
- The **Security CVM injects** it at egress via the profile's
  `secret_injections` entry (header rewrite; the SC overwrites whatever
  header the sandbox sent).
- The sandbox only ever holds a **placeholder** (`umbra-proxy-injected`).
  The Dev CVM's own env validation rejects secret-shaped placeholder values,
  so a real token cannot ride the `sandbox_env` channel even by mistake.
- **Revocation** = overwrite the stored material (re-mint a bogus value) or
  rotate the real credential upstream. Deleting the material outright is a
  hard revoke with a large blast radius (§4).

The developer laptop is trusted only at mint time: the token transits it
once, in a request body over TLS, and is never accepted on argv, logged,
echoed, or returned.

## 2. Self-service secret mint

### `POST /api/v1/profiles/{profile_id}/secrets/{injection_id}`

Write one injection's secret material, leaving every other stored secret of
the profile intact.

- **Auth.** `JWT`. **Permission.** `USER_MANAGE`, **or** the caller is a
  member of the profile AND the profile has exactly one member (the
  sole-member rule). **Idempotency-Key.** `n/a` (naturally idempotent).
  **If-Match.** `n/a`.
- **Request body.** `{"value": <string, 1..8192>}`. The value is stripped of
  surrounding whitespace and MUST NOT contain control characters (header
  injection guard; the SC renders it into an HTTP header).
- **Response body.** `200 {"profile_id": <UUID>, "injection_id": <string>,
  "minted_at": <RFC3339>}`. The value is never echoed.
- **Errors.** `404` (§6.4 of the Console spec: non-members and cross-entity
  callers cannot distinguish "no such profile" from "not a member").
  `409 CONFLICT` (`details.state="multi_member_profile"`,
  `details.member_count`) when a non-`USER_MANAGE` member mints into a
  profile with more than one member. `422 VALIDATION_ERROR`
  (`details.state="unknown_injection"`) when the profile policy does not
  declare `injection_id` in `secret_injections`; plain `422` for a malformed
  injection id or value.
- **Side effects.** Upsert into `profile_secret_material` (anti-wipe path,
  §3); `policy_version` bump on every live attached Dev CVM (the SC picks up
  the new material on its ~5 s pull); one `PROFILE_SECRET_MINTED` audit row
  whose payload carries the injection id only — never the value.

**Why sole-member.** The first credentials minted this way are personal
subscription tokens (Claude Code): sharing one through a multi-member
profile is provider account-sharing and destroys usage attribution, so
self-service writes are limited to profiles that provably belong to one
person. `USER_MANAGE` holders may mint into any profile (they can already
rewrite the policy wholesale). When a per-user secret store lands
(`value_from: {user_secret: …}` resolved per CVM owner), personal
credentials SHOULD move there; the sole-member rule then stops being
load-bearing for them.

## 3. Secret-write semantics: anti-wipe vs wholesale

Two write paths exist and MUST NOT be conflated:

- `upsert_profile_secret_material` (this spec): writes only the named
  injection ids; all other stored secrets survive. Mint and rotation flows
  MUST use this path.
- `replace_profile_secret_material` (profile configure, `PATCH
  /profiles/{id}` with `policy`): **wholesale** — every stored secret whose
  injection id is not re-supplied inline in the submitted policy is
  DELETED. This is unchanged, documented behavior: stored secrets are
  write-only and cannot be read back, so editing any part of a policy that
  has secret injections requires re-supplying every inline `value`, or the
  material is destroyed. Operators re-mint via §2 after a wholesale
  configure instead of inlining values where possible.
  - **Managed injections are re-minted, not lost.** A wholesale replacement
    wipes the scheduler-minted access-token material of any managed injection
    (§8), so the same call also marks that profile's managed secrets due
    (`access_token_expires_at → NULL`) and clears `last_error` (so a stale
    failure backoff can't defer the re-mint by up to an hour). The refresh
    token lives in a separate table and survives, so the next reconciliation
    pass re-mints from it — the grant is not left unusable until the rotation
    threshold. An in-flight rotation's compare-and-set still wins (`updated_at`
    is left untouched).

## 4. Mint-complete gate (mint-before-attach, enforced)

The Security CVM parses a merged policy that carries a declared secret
injection **without** material as invalid and fail-closes the entire CVM
(`deny_all`: every egress request refused). An unminted profile must
therefore never reach a CVM. The Console enforces the ordering:

- `POST /cvms/{cvm_id}/profiles` (attach) → `409 CONFLICT`
  (`details.state="secrets_not_minted"`,
  `details.missing=[{profile_id, injection_id}, ...]`).
- `POST /cvms` (launch) with `profile_ids` → `422 VALIDATION_ERROR`, same
  `details` shape.

Flows mint first, then attach. Note the converse hazard: deleting material
for a profile that is already attached fail-closes every attached CVM's
egress — that is the intended **hard revoke**, not routine rotation. For
targeted revocation, re-mint a bogus value: only the injected credential
breaks, the CVM keeps its other egress.

Where the gate actually bites: `profile configure` requires an inline
`value` on every declared injection and stores it as material immediately,
so profiles authored through the normal configure path always pass. The gate
guards the paths that declare injections **without** inline values —
server-side template provisioning (stored templates are forbidden from
carrying inline values) and any direct policy write — plus drift where
material was removed out-of-band. Onboarding templates that go through
`profile configure` ship a non-secret bootstrap value (e.g.
`umbra-unminted`) that the real mint overwrites; until then the SC
injects the dud credential and only that destination's auth fails.

## 5. Claude Code instantiation (reference values)

Validated recipe for running Claude Code on an SC-injected subscription
token (see `docs/onboarding/claude-code.md` for the runbook):

- Injection: id `claude-code-oauth`, `type: "request_header"`, header
  `authorization`, `value_template: "Bearer ${secret}"`, match
  `https://api.anthropic.com:443`.
- Sandbox placeholder: env `CLAUDE_CODE_OAUTH_TOKEN=umbra-proxy-injected`
  — set at launch via the profile's `sandbox_env`, and exported by
  `umbra claude` at agent spawn (with `ANTHROPIC_API_KEY` and
  `ANTHROPIC_AUTH_TOKEN` unset) so already-running CVMs need no relaunch.
  `--no-oauth-env` opts a session out.
- MUST NOT set `ANTHROPIC_API_KEY` alongside: Claude Code then authenticates
  with `x-api-key` instead of `authorization` and the injection match never
  fires. Claude Code self-supplies its `anthropic-beta: …oauth…` header.
- Destination allow-list: `api.anthropic.com` (API), plus
  `platform.claude.com`, `downloads.claude.ai`, and `registry.npmjs.org`
  for login/update flows.
- Token provenance: the developer's own `claude setup-token`, minted on
  their laptop (the Console never runs Anthropic's OAuth flow). One token =
  one developer = one single-member profile (§2).
- CLI: `umbra claude connect` reads the token from stdin, mints via §2,
  then best-effort attaches the profile to the target CVM.

## 6. Connect links (browser authorize → Console mints)

For credentials that come out of a provider OAuth flow (Slack first), the
Console holds the integration's `client_secret`, serves the redirect URI,
and exchanges the authorization code itself: the developer clicks Allow in
a browser and the token lands directly in the profile's secret injections.
No port-forward out of a CVM, no manual code-shuttling, no token on a
laptop.

### 6.1 Data model

`oauth_integrations` — PK `(entity_id, name)`; `name` is a slug
(`^[a-z0-9][a-z0-9-]{0,63}$`). `authorize_url` / `token_url` MUST be
absolute `https://` URLs (DB CHECK). `client_secret_ciphertext` is AES-GCM
under `SECRET_INJECTION_KEK_B64` with the AAD domain
`umbra.oauth_integration.v2:{entity_id}:{name}` (deliberately disjoint
from profile-secret material) and is **write-only**. `scopes` is the raw
value passed as the standard `scope` parameter; provider-specific
parameters (e.g. Slack's `user_scope`) are configured as query params on
`authorize_url` and are merged, never replaced. `token_pointer` is a JSON
pointer (1..8 segments) into the token-endpoint response naming the value
to mint. `profile_policy_template` (nullable JSONB) is a stored profile
policy validated in **template mode** (`require_injection_values=False`):
inline injection `value`s are FORBIDDEN (also a DB CHECK) — material for
template-provisioned profiles arrives only via mint, guarded by the
mint-complete gate (§4).

`oauth_connection_states` — one row per connect link. Stores only
`state_token_hash = sha256(state)` (the raw state appears exactly once, in
the returned `connect_url`), binds `(entity_id, integration_name,
profile_id, injection_ids, created_by)`, expires after 15 minutes, and is
claimed **atomically and single-use** (`used_at`, set the moment the code
comes back). Success is a **separate** terminal signal: `completed_at` is
set only inside the mint transaction, so a crash between the claim and the
mint never reads as connected. Failures record a sanitized `error` code
(grant observability). Rows are pruned past
`OAUTH_CONNECTION_STATE_RETENTION_SECONDS` (default 30 days) by the
reconciliation pass, using the `expires_at` index.

The callback re-checks authorization at consume time: the `created_by`
user must still exist and either be a member of the bound profile or hold
`USER_MANAGE`, and the profile must be live — a link whose initiator was
removed from the profile no longer mints. This check runs twice: once
before the provider exchange (cheap early reject) and again **inside the
mint transaction under `FOR UPDATE OF ep`**, so a revocation (or a
`profile configure` that would push the rendered header past the SC cap)
landing during the exchange still aborts the mint against one consistent
policy snapshot.

### 6.2 API

- `PUT /api/v1/entities/{entity_id}/oauth-integrations/{name}` —
  `USER_MANAGE` + entity-scoped. Upserts the integration. `client_secret`
  is **required on create** and **optional on update** (omit to preserve
  the stored write-only ciphertext). `profile_policy_template` follows the
  same rule — omit on update to preserve the stored template. `token_url`
  must be `https://` and its host must be on the token-endpoint allowlist
  (`OAUTH_TOKEN_URL_HOSTS`, default `auth.openai.com,slack.com`); the
  resolved IPs are re-checked at every server-side exchange to block
  private/metadata targets (the allowlist is the primary guard; the
  resolved-IP recheck narrows but does not fully close a DNS-rebinding
  TOCTOU, since httpx resolves independently). Template validated as above.
  Audit `OAUTH_INTEGRATION_CONFIGURED`
  (name + client_id only). Response is the redacted resource
  (`has_profile_policy_template` boolean; never ciphertext).
- `GET /api/v1/entities/{entity_id}/oauth-integrations` — `USER_MANAGE`;
  redacted list.
- `DELETE /api/v1/entities/{entity_id}/oauth-integrations/{name}` —
  `USER_MANAGE`. Decommissions the integration and purges its stored
  client-secret ciphertext; `oauth_connection_states` and
  `integration_profiles` cascade-delete (the per-dev profiles themselves
  survive — an admin deletes those separately). `404` if absent; audit
  `OAUTH_INTEGRATION_DELETED`.
- `POST /api/v1/profiles/{profile_id}/connections` — `USER_MANAGE`. Body
  `{"integration": <name>, "injection_ids": [<id>, ...]?}`;
  `injection_ids` defaults to every **material-backed** injection the
  profile policy declares (the inline-value slots the SC actually reads) and
  MUST be a subset of them (422 `unknown_injection`). `value_from:
  {user_secret}` injections are never valid targets — they are minted per
  user via `umbra secret set`, not a connect link — and a profile with no
  mintable injection is `422`. Returns `201
  {"connect_url", "expires_at"}` where `connect_url` is the provider
  authorize URL carrying `response_type=code`, `client_id`,
  `redirect_uri={CONSOLE_URL}/oauth/callback`, `state`, and `scope` (when
  `scopes` is non-empty), merged with any params already on
  `authorize_url`. Audit `PROFILE_CONNECTION_LINK_CREATED` (never the
  state token).

### 6.3 Public callback — `GET /oauth/callback?code&state[&error]`

Unauthenticated, root-level, minimal script-free HTML responses:

1. Hash `state` and atomically claim the row (`used_at IS NULL AND
   expires_at > now()`); unknown/expired/reused states get one generic
   error page (no oracle).
2. Provider `error` (user denied) or missing `code` → record a safe code in
   the state row's `error` column and render a friendly page.
3. Exchange the code at `token_url` — form-encoded
   (`grant_type=authorization_code`, `code`, `redirect_uri`, `client_id`,
   `client_secret`), `Accept: application/json`, 10 s timeout, **outside
   any DB transaction**. Non-200, malformed, `error`-shaped (string or
   dict), and Slack-style `ok:false` responses all map to short safe error
   codes; the token value never appears in errors, logs, or audit.
4. Extract the token via `token_pointer` (miss → `token_pointer_miss`);
   reject non-string/oversized/control-character values.
5. In one transaction, under `FOR UPDATE OF ep`: re-check authorization and
   re-check the rendered header length against the locked policy, then
   anti-wipe upsert into every bound injection id →
   `bump_attached_cvm_policy_versions` → set `completed_at` → audit
   `PROFILE_SECRET_MINTED` (`after = {injection_ids, via: "oauth_connection",
   integration}`). A revoked initiator aborts with `authorization_revoked`; an
   over-long render aborts with `rendered_value_too_long`.
6. Success page. Attached CVMs converge on the SC's ~5 s policy pull.

## 7. Slack instantiation (reference values)

- Slack app: add the redirect URL `{CONSOLE_URL}/oauth/callback`; request
  user scopes via `user_scope` **on the configured `authorize_url`**
  (Slack ignores the standard `scope` param for user tokens). The bundled
  template is **read-only** (`user_scope=channels:read,channels:history,users:read`):
  its egress boundary allows `POST` only to the enumerated read methods on
  the `slack.com` apex, and `GET`-only to other `*.slack.com` subdomains
  (WebSocket handshake / asset reads) — so no write reaches the Slack Web
  API, including at `api.slack.com`, which serves the same methods a leading
  `*.slack.com` wildcard would otherwise expose. Write access (`chat:write` +
  the matching write methods on the boundary and injection `match`) is a
  deliberate widening, not the default.
- `token_url`: `https://slack.com/api/oauth.v2.access` (form-encoded;
  client_secret in the body).
- `token_pointer`: `/authed_user/access_token` (the `xoxp-` user token).
- Profile template: injection `slack-user-token`, header `authorization`,
  `value_template "Bearer ${secret}"`, match `https://slack.com:443`
  `POST /api/`; runbook in `docs/onboarding/slack-claude.md`.

## 8. Managed rotating secrets (Console-held refresh tokens)

For providers whose access tokens expire and whose refresh tokens rotate on
every use (ChatGPT/codex first: ~10-day access tokens, one-shot refresh
tokens), the Console stores the **refresh token** server-side and runs the
refresh loop itself, keeping a fresh access token in the profile's
injection slot. The agent in the sandbox never refreshes anything.

**Sole-refresher rule.** Exactly one party may ever use a rotating refresh
token (the provider revokes it on use). The Console is that party: the
grant is minted from a throwaway login (`umbra codex connect` uses a
throwaway `CODEX_HOME`, deleted after upload) so no laptop copy survives,
and the sandbox policy must keep the provider's token endpoint
(`auth.openai.com` for ChatGPT) unreachable.

### 8.1 Data model — `profile_managed_secrets`

PK `(profile_id, injection_id)`, FK cascade from `entity_profiles`.
`provider` = `oauth_refresh_token` (v1). `token_url` https-CHECKed;
`client_id`; `refresh_token_ciphertext` AES-GCM under the shared KEK with
AAD domain `umbra.managed_secret.v2:{profile_id}:{injection_id}`
(deliberately not interchangeable with injection-material ciphertexts) and
**write-only**; optional non-secret `account_id`;
`access_token_expires_at`, `last_rotated_at`, `last_attempt_at`,
`last_error` (rotation observability).

### 8.2 API

- `PUT /api/v1/profiles/{profile_id}/managed-secrets/{injection_id}` —
  permission rule = §2's (sole member or `USER_MANAGE`); injection must be
  declared in the profile policy. Stores the refresh token encrypted,
  audits `PROFILE_MANAGED_SECRET_CONFIGURED` (never the token), then runs
  an **immediate first rotation** so a bad grant surfaces at once: the
  response is the redacted resource plus `rotated: bool` and
  `rotation_error` when it failed.
- `GET /api/v1/profiles/{profile_id}/managed-secrets` — member-or-404;
  metadata only (expiry, last_rotated_at, last_attempt_at, last_error).
- `DELETE …/managed-secrets/{injection_id}` — stops rotation; audits
  `PROFILE_MANAGED_SECRET_DELETED`. The injection material is left intact
  (the last access token keeps working until expiry; no fail-close), and
  the upstream grant is NOT revoked at the provider.

### 8.3 Scheduler rotation pass

`maybe_rotate_managed_secrets` runs from the reconciliation pass behind a
~300 s wall-clock gate (`MANAGED_SECRET_ROTATION_GATE_SECONDS`) plus a
dedicated pass-level `pg_try_advisory_lock` (single-flight across Console
replicas). Due = less than `MANAGED_SECRET_ROTATION_THRESHOLD_SECONDS`
(default 5 days) of access-token life (or unknown expiry), excluding
soft-deleted profiles.

Each due secret rotates under a **per-secret advisory lock** keyed on
`(profile_id, injection_id)`, the same lock the immediate PUT rotation
takes — so the scheduler and a just-configured PUT can never submit the
same one-shot refresh token concurrently. After acquiring the lock the row
is re-read: a secret already refreshed by the other party is seen as
not-due and reported as success without burning a second refresh. The
token endpoint is re-validated against the allowlist (host + resolved IP)
before the fetch. The refresh-token grant is POSTed as JSON to `token_url`
**outside any DB transaction**; then one transaction commits together — the
rotated refresh token (when the provider returns one), the anti-wipe
access-token upsert into `profile_secret_material`, the attached-CVM
`policy_version` bumps, and a `PROFILE_SECRET_ROTATED` audit row, all
CAS-guarded on the pre-request `updated_at`. Failures record
`last_attempt_at`/`last_error` (also CAS-guarded, in one transaction with
their `PROFILE_SECRET_ROTATION_FAILED` audit) and keep the last good token.
The rendered injection value is bounded before storage. Each row rotates
inside its own exception boundary, so one corrupt ciphertext / bad expiry /
encryption error is recorded and skipped rather than aborting the batch.
Expiry comes from `expires_in`, else the (unverified) access-token JWT
`exp`, else a 10-day default (`MANAGED_SECRET_DEFAULT_TTL_SECONDS`).

**Crash-window residual risk.** A crash between the provider's token
response and the DB commit loses a rotated refresh token (the provider
already revoked the old one): the grant is bricked, the agent keeps its
last injected token's runway, and the next attempt records the provider's
`invalid_grant`-style code in `last_error`. Recovery is re-running the
connect flow with a fresh login. Accepted for v1.

### 8.4 codex/ChatGPT reference values

- Injection: id `codex-chatgpt-oauth`, header `authorization`,
  `value_template "Bearer ${secret}"`, match `https://chatgpt.com:443`
  path `/backend-api/codex`.
- `token_url` `https://auth.openai.com/oauth/token` (JSON body), public
  client id `app_EMoamEEZ73f0CkXaXp7hrann`; the sandbox policy blocks
  `auth.openai.com` (sole-refresher).
- Placeholder `~/.codex/auth.json` planted by `umbra codex connect`:
  far-future-`exp` unsigned JWT access token (codex refreshes only when its
  own token nears expiry — never, here), dummy refresh token, real
  non-secret `account_id` (codex sends it as `ChatGPT-Account-ID`),
  `last_refresh` set. codex never verifies JWT signatures, so three
  base64url segments suffice.
- codex sessions run with `OPENAI_API_KEY`/`CODEX_API_KEY`/
  `CODEX_ACCESS_TOKEN` unset — those env vars override file auth.
- Runbook: `docs/onboarding/codex-chatgpt.md`.

## 9. Self-serve connect page — `{CONSOLE_URL}/connect/{integration}`

One durable URL an admin posts once in a shared channel; any developer
holding `CVM_LAUNCH` self-serves end to end. Granting `CVM_LAUNCH` is the
admin's only per-dev act (a brand-new domain-matched Google login
auto-materializes a user with zero permissions, who sees a friendly "ask
your admin" page).

**Page mechanics.** A static wizard SPA (mirror of the admin dashboard
pattern) served from `console/static/connect/`: client-side PKCE against
the Console's own auth broker using client id `umbra-cli-v1`, JWT pair
in `sessionStorage`, bearer on API calls. The integration slug survives
the Google round-trip in `sessionStorage` alongside the PKCE verifier;
`{CONSOLE_URL}/connect/oauth/callback` is on the redirect-URI allowlist.
`/connect*` static paths get the admin CSP (`script-src 'self'`) and the
static-serving rate-limit exemption; the JSON APIs stay limited. There are
no cookies anywhere, so the new POSTs need no CSRF machinery (CORS
preflights are refused platform-wide).

**API (`/api/v1/connect/{integration}`, server authority — the caller can
never choose profile or injection ids):**

- `GET /{integration}` — wizard state: `entitled` (a 200 flag, not a 403),
  the caller's keyed profile, `secrets.{required,minted,complete}`, the
  last connection outcome (from `oauth_connection_states`), and the
  caller-owned live CVMs with attach flags.
- `POST /{integration}/profile` — idempotent provision under Console
  authority: clones the integration's stored `profile_policy_template`
  (validated in template mode; `409 template_missing` when absent) into a
  per-dev profile keyed by the `integration_profiles` linking table
  (PK `(entity_id, integration_name, user_id)`, `UNIQUE(profile_id)`,
  `template_sha256` snapshot — deliberately no drift propagation), adds the
  caller as member, audits `PROFILE_CREATED`/`PROFILE_USER_ASSIGNED` with
  `via:"connect"` and the developer as actor. Name = `conn-{integration}-
  {email localpart}` with a suffix on collision (cosmetic only; the link
  table is the key). Re-runs return the existing profile.
- `POST /{integration}/connections` — self-serve connect link for the
  caller's OWN keyed profile only (`409 profile_not_provisioned`
  otherwise); injection ids = everything the profile declares; shares
  `create_connection_state` with the admin route (§6.2).
- `POST /{integration}/attach` — owner self-attach, replacing the generic
  route's `CVM_MANAGE`: caller must own the CVM (`cvms.owner_id`; foreign
  CVMs 404, no manager bypass, no ETag ceremony — one server-side
  transaction), be a member of the keyed profile, pass the mint-complete
  gate (§4) and the sandbox-env conflict check. Audits
  `CVM_PROFILE_ATTACHED` with `via:"connect"`. Idempotent
  (`already_attached`).

**Flow order** — provision → authorize → mint (§6.3 callback) → attach —
so mint-before-attach holds by construction; the page additionally
disables attach until `secrets.complete`, and the server 409s regardless.
The public callback finishes with a 303 to
`/connect/{integration}?connected=1|connect_error=<code>`, the slug taken
only from the consumed state row (no open redirect); those query params
are display hints — the page always re-fetches status.

**Accepted v1 postures.** Authorize-URL forwarding (a victim completing an
attacker-initiated connect state donates their provider token to the
attacker's profile) is accepted as with admin-DM'd links — TTL, single
use, audit trail. Template edits do not propagate to existing per-dev
profiles (`template_sha256` gives ops a staleness query). One profile per
(user, integration); the shared-profile variant arrives with per-user
secrets. Entity `profiles` quotas must accommodate devs × integrations —
raising the quota is part of enabling an integration.

## 10. Grant observability and re-auth

### `GET /api/v1/profiles/{profile_id}/secrets-status`

Member-or-404 (`USER_MANAGE` sees any profile in the entity). Always
redacted; never any secret value or ciphertext. Response:

- `injections[*]` — one entry per injection the policy **declares**:
  `material_present` (does `profile_secret_material` hold anything),
  `updated_at`, and a `managed` sub-object (expiry, `last_rotated_at`,
  `last_attempt_at`, `last_error`) when Console-managed rotation is
  configured.
- `last_connection` — how the newest connect attempt ended (integration,
  `connected_at`, or the safe `error` code from
  `oauth_connection_states.error`). This is what closes "a failed exchange
  leaves no trace": denial, exchange failure, and pointer misses all land
  here.

### CLI

- `umbra profile grants` — renders the status per injection
  (`minted` / `NOT MINTED`, managed expiry, last error, last connection);
  `--json` passes the payload through.
- **Re-auth is the same command that connected in the first place**, always
  idempotent into the same slot: `claude setup-token | umbra claude
  connect` (fresh token), `umbra codex connect` (fresh grant),
  `umbra profile connections create <integration>` (fresh single-use
  link — the admin path), or revisiting `/connect/{integration}`
  (self-serve).

## 11. Future work (tracked in the OAuth-credential umbrella)

- **PKCE** (helper `crypto.pkce_s256` exists) and **HTTP-Basic
  token-endpoint auth** (Notion) when a provider requires them.
- **Per-user secrets convergence**: personal credentials as
  `value_from: {user_secret: …}` instead of sole-member profiles.
