# codex on a ChatGPT subscription (Console-managed rotation)

Run codex unattended in a Dev CVM on a ChatGPT subscription with the OAuth
credential never present in the sandbox: the Console holds the rotating
refresh token and keeps a fresh access token in the profile's secret
injection; the Security CVM injects it at egress; the box only carries a
placeholder `~/.codex/auth.json`. This replaces pasting a real
`~/.codex/auth.json` into the CVM — which any prompt-injected process can
read, and which silently expires mid-run.

Contract: `docs/specs/oauth-connections.md` §8. Template:
[`codex-chatgpt/policy.template.json`](codex-chatgpt/policy.template.json).

## Why rotation (and the sole-refresher rule)

ChatGPT OAuth issues ~10-day access tokens with a refresh token that
**rotates on every use** — exactly one party may ever refresh, or the grant
bricks. That party is the Console. Consequences:

- The grant comes from a **throwaway** `codex login` (dedicated
  `CODEX_HOME`, deleted after upload) so no laptop copy survives.
- The sandbox policy **blocks `auth.openai.com`** — the box must never
  attempt the refresh itself.
- The placeholder auth.json carries a far-future unsigned access token so
  codex never tries to self-refresh, and the SC overwrites the bearer on
  `chatgpt.com/backend-api/codex` with the freshly rotated token.

## Admin: one-time per developer

```bash
umbra profile create codex-<dev-name> --description "codex (ChatGPT subscription)" --json
# capture .id as PROFILE_ID
umbra --profile $PROFILE_ID profile configure --policy-file docs/onboarding/codex-chatgpt/policy.template.json
umbra --profile $PROFILE_ID profile members add $DEV_USER_ID   # the ONLY member
```

## Developer: connect and run

```bash
# One command: throwaway browser login -> grant uploaded -> first rotation
# confirmed -> placeholder planted on the CVM -> profile bound.
umbra --profile $PROFILE_ID codex connect --cvm $CVM_ID

# No CVM yet? Configure rotation first, then launch:
umbra --profile $PROFILE_ID codex connect --no-attach
umbra cvm launch --profile $PROFILE_ID
umbra --profile $PROFILE_ID codex connect --cvm $NEW_CVM_ID   # plants the placeholder

umbra codex $CVM_ID
```

`codex connect` fails fast if the first rotation fails (bad grant) — re-run
it for a fresh login. Check rotation health any time:

```bash
TOKEN=$(umbra auth token)
curl -sS "$CONSOLE_URL/api/v1/profiles/$PROFILE_ID/managed-secrets" -H "Authorization: Bearer $TOKEN"
# -> access_token_expires_at / last_rotated_at / last_error (never token material)
```

## Rotation, re-auth, revocation

- The Console rotates automatically when less than ~5 days of access-token
  life remain; attached CVMs pick the new token up on the SC's ~5 s poll.
- Re-auth after a bricked grant (e.g. `last_error: refresh_error:...`) =
  re-run `umbra codex connect` (fresh throwaway login; the upload
  overwrites in place).
- Stop rotation: `DELETE /api/v1/profiles/$PROFILE_ID/managed-secrets/codex-chatgpt-oauth`
  — the last injected token keeps working until it expires; the upstream
  grant is not revoked at OpenAI (revoke there for a hard cut).

## Gotchas

- **Never run `codex login` inside the CVM** and never set
  `OPENAI_API_KEY`/`CODEX_API_KEY`/`CODEX_ACCESS_TOKEN` there — env auth
  overrides the placeholder file. `umbra codex` unsets all three at
  spawn.
- **One grant, one refresher.** Don't reuse the throwaway grant elsewhere;
  a second refresher revokes the Console's copy (shows up as
  `refresh_error:*` in `last_error`).
- **`profile configure` replaces secret material wholesale.** After a
  policy edit, the injected access token is wiped until the next rotation
  pass (≤ ~5 min) re-mints it — or re-run `codex connect`.
- The template's `blocked_destinations` entry documents the
  `auth.openai.com` ban within this profile; because blocked lists
  intersect across attached profiles, don't co-attach a profile that
  allows that host.
