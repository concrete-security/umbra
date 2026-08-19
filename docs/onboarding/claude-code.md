# Claude Code on an SC-injected subscription token

Run Claude Code inside a Dev CVM with the developer's Claude subscription
token held by the Console and injected by the Security CVM at egress — never
present in the sandbox. Interactive `claude /login` inside the box is the
anti-pattern this replaces: those credentials are readable by anything
running in the sandbox and silently expire mid-run.

Contract: `docs/specs/oauth-connections.md` (§2 mint API, §4 mint-before-attach,
§5 the validated Claude recipe). Template: [`claude-code/policy.template.json`](claude-code/policy.template.json).

## Model

- One token = one developer = one **single-member** profile. The mint
  endpoint refuses multi-member profiles for non-admins (sharing a personal
  subscription token is provider account-sharing and destroys attribution).
- The token is minted by the developer's own `claude setup-token` on their
  laptop (the Console never runs Anthropic's OAuth flow) and transits the
  laptop exactly once, into the mint request body.
- The sandbox sees only `CLAUDE_CODE_OAUTH_TOKEN=umbra-proxy-injected`;
  the SC swaps the bearer on `api.anthropic.com` for the stored token.
- The template ships a non-secret bootstrap `value` (`umbra-unminted`)
  because policy validation requires every injection to carry one at
  configure time. Until the developer mints, the SC injects that dud bearer
  and Anthropic calls fail with auth errors — the CVM's other egress is
  unaffected. Profiles whose injections have **no** stored material at all
  (possible when policy is provisioned server-side rather than through
  `profile configure`) are refused at attach/launch (`secrets_not_minted`),
  because a value-less injection fail-closes the whole CVM.

## Admin: one-time per developer

```bash
# 1. Create the per-dev profile from the template.
umbra profile create claude-<dev-name> --description "Claude Code (personal token)" --json
# capture .id as PROFILE_ID

umbra --profile $PROFILE_ID profile configure --policy-file docs/onboarding/claude-code/policy.template.json

# 2. Make the developer the profile's ONLY member.
umbra --profile $PROFILE_ID profile members add $DEV_USER_ID
```

The developer also needs `CVM_LAUNCH` (and an SSH key) per the usual
onboarding.

## Developer: mint and run

```bash
# 1. Mint a long-lived token on your laptop (browser approval happens here).
#    Then pipe it straight into umbra — it never touches argv or disk.
claude setup-token | umbra --profile $PROFILE_ID claude connect --cvm $CVM_ID

# No CVM yet? Mint first, then launch with the profile:
claude setup-token | umbra --profile $PROFILE_ID claude connect --no-attach
umbra cvm launch --profile $PROFILE_ID

# 2. Use it. `umbra claude` exports the placeholder env at spawn, so a
#    running CVM picks the change up with no relaunch.
umbra claude $CVM_ID
```

If the attach step reports it needs `CVM_MANAGE`, the mint still succeeded —
ask an admin to run the printed `umbra cvm attach` command, or launch a
fresh CVM with `--profile`.

## Rotation and revocation

```bash
# Rotate (new token, same command — the upsert overwrites in place):
claude setup-token | umbra --profile $PROFILE_ID claude connect --no-attach

# Targeted revoke (break only the Claude credential, keep other egress):
echo revoked | umbra --profile $PROFILE_ID claude connect --no-attach
```

Do NOT revoke by deleting the profile's secret material while the profile is
attached: a declared injection without material fail-closes the entire CVM's
egress (every destination), which is the hard-revoke hammer, not rotation.

## Gotchas

- **Never set `ANTHROPIC_API_KEY`** in the sandbox or the session: Claude
  Code switches to `x-api-key` auth and the injection match on
  `authorization` never fires. `umbra claude` unsets it (and
  `ANTHROPIC_AUTH_TOKEN`) by default; `--no-oauth-env` opts out for legacy
  in-box `/login` sessions.
- **`profile configure` replaces secrets wholesale.** Editing this profile's
  policy wipes the minted token unless it is re-supplied inline; re-mint via
  `claude connect` after any policy edit.
- The template's `egress_boundary: true` makes this profile a destination
  boundary. If the developer needs broader egress, attach an additional
  boundary profile that allows it, or drop the flag deliberately.
- The token pasted into `claude connect` must be a single line (piping
  `claude setup-token` output is the expected form).
