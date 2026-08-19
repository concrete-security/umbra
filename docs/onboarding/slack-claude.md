# Slack user token via connect link

Give a sandboxed agent a Slack user token (`xoxp-`) without the token ever
touching a laptop or the CVM: the developer clicks Allow in a browser, the
Console exchanges the code and mints the token into their profile's secret
injection, and the Security CVM injects it at egress.

Contract: `docs/specs/oauth-connections.md` §6–§7. Template:
[`slack-claude/policy.template.json`](slack-claude/policy.template.json).

## One-time: entity Slack app + integration (admin)

1. Create the Slack app (workspace admin): add the OAuth redirect URL
   `{CONSOLE_URL}/oauth/callback`, and note the app's **Client ID** and
   **Client Secret**. Request user scopes at authorize time via
   `user_scope` on the authorize URL (Slack ignores the standard `scope`
   parameter for user tokens). The bundled template is **read-only** by
   default (`channels:read`, `channels:history`, `users:read`), matching the
   enumerated read methods its egress boundary allows. Granting write access
   (`chat:write`) is an intentional widening: add the scope here **and** the
   corresponding write methods (e.g. `/api/chat.postMessage`) to the
   template's `allowed_destinations` and injection `match`, or the SC will
   block the write even though Slack issued the scope.
2. Register the integration with the Console (no CLI verb yet — raw API;
   `umbra auth token` prints a bearer):

```bash
TOKEN=$(umbra auth token)
curl -sS -X PUT "$CONSOLE_URL/api/v1/entities/$ENTITY_ID/oauth-integrations/slack" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "authorize_url": "https://slack.com/oauth/v2/authorize?user_scope=channels:read,channels:history,users:read",
    "token_url": "https://slack.com/api/oauth.v2.access",
    "client_id": "<SLACK_CLIENT_ID>",
    "client_secret": "<SLACK_CLIENT_SECRET>",
    "token_pointer": "/authed_user/access_token"
  }'
```

The client secret is write-only and required only when first creating the
integration; on a later PUT you may omit it to preserve the stored value
(and omit `profile_policy_template` likewise). Reads return the integration
redacted.

## Zero-touch alternative: one durable link

Once the integration has a stored `profile_policy_template` (add
`"profile_policy_template": <the template JSON without inline values>` to
the PUT above), skip the per-dev section entirely: post
`{CONSOLE_URL}/connect/slack` once in a shared channel. Any developer with
`CVM_LAUNCH` opens it, signs in with Google, gets their per-dev profile
provisioned automatically, clicks Allow, and binds the profile to their own
CVM — no DM, no per-dev admin work (`docs/specs/oauth-connections.md` §9).
Granting `CVM_LAUNCH` (and a `profiles` quota that covers devs ×
integrations) remains the only admin act.

## Per developer (admin, manual variant)

```bash
# Per-dev profile from the template + membership:
umbra profile create slack-<dev-name> --description "Slack (user token)" --json
umbra --profile $PROFILE_ID profile configure --policy-file docs/onboarding/slack-claude/policy.template.json
umbra --profile $PROFILE_ID profile members add $DEV_USER_ID

# Mint a one-time connect link (15 min TTL, single use) and send it to the dev:
TOKEN=$(umbra auth token)
curl -sS -X POST "$CONSOLE_URL/api/v1/profiles/$PROFILE_ID/connections" \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"integration": "slack"}'
# -> {"connect_url": "...", "expires_at": "..."}
```

## Developer

Open the `connect_url` in a browser and click **Allow**. The Console
exchanges the code and mints your `xoxp-` token into the profile; attached
CVMs pick it up within ~5 s (no relaunch). From the sandbox:

```bash
curl -s -X POST https://slack.com/api/auth.test   # SC injects the bearer
```

The sandbox only ever holds `SLACK_USER_TOKEN=umbra-proxy-injected`.

## Re-auth / rotation / failure

- Re-connect = mint a fresh link and click Allow again; the upsert
  overwrites in place (other injections untouched).
- A declined or failed exchange leaves a safe error code on the connection
  state row (`oauth_connection_states.error`) — nothing mints silently.
- Links are single-use and expire after 15 minutes; a reused link shows a
  generic error page.

## Gotchas

- **`user_scope` lives on the `authorize_url`.** The integration's `scopes`
  field feeds the standard `scope` param, which Slack ignores for user
  tokens.
- **`profile configure` replaces secret material wholesale.** After any
  policy edit on this profile, re-run the connect flow (or the template's
  bootstrap `umbra-unminted` value is what the SC injects).
- The template's second `*.slack.com` rule is **GET-only** (WebSocket
  handshake and subdomain reads such as `files.slack.com`); it does not
  permit POSTs to any Slack subdomain, so a write to the Web API — including
  at `api.slack.com`, which serves the same methods — stays outside the
  boundary. Socket-Mode posting or channel-scoped writes need `chat:write`,
  the matching write methods on the boundary and injection `match`, and
  `body_assertions` / `websocket_assertions` per the profile-authoring recipe
  in the CLI skill.
