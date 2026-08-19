# Umbra Tool CVM Specification

This document specifies the Umbra Tool Confidential VM (Tool CVM or TCVM). The Tool CVM is a proposed post-v0 component for running credentialed agent tools, primarily MCP servers, inside an attested boundary without giving Slack, Notion, GitHub, or similar SaaS credentials to Dev CVMs.

This specification follows the same normative style as the v0 component specs. It is not part of the current v0 verification gate until the Console, Security CVM, Dev CVM, and CLI specs are updated to include Tool CVM lifecycle and policy routes.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, and OPTIONAL in this document are used in the RFC 2119 / RFC 8174 sense.

## 1. Overview

The Tool CVM is the per-entity trusted tool broker for AI agents running in Dev CVMs. It exposes MCP-compatible tools for external work systems such as Slack, Notion, and GitHub. It holds provider credentials, translates semantic tool calls into provider API calls, enforces application-level authorization, and emits tool audit events.

The Tool CVM exists because HTTP method and path policy is not expressive enough for SaaS APIs. Slack, Notion, and GitHub expose operations where "read" and "write" intent does not map cleanly to GET versus POST, and provider-issued tokens are often broader than the exact agent task. Umbra therefore separates network authorization from semantic tool authorization:

- The Security CVM authenticates Dev CVM egress, enforces network policy, injects Umbra identity assertions, and remains on every egress path.
- The Tool CVM validates Umbra identity, enforces provider/tool/resource/action policy, calls SaaS APIs with credentials that never enter the Dev CVM, and emits semantic audit events.
- The Console owns human policy authoring, provider credential storage, Tool CVM lifecycle, and audit/tool-event storage.

The Tool CVM is an enforcer, not an authoring authority. It makes authorization decisions from state pulled from the Console and credentials provisioned by the Console after attestation.

### 1.1 Motivation

The Tool CVM exists to cover a gap that network policy and provider token scopes cannot safely cover on their own.

Many work-app APIs expose tokens that are broader than the exact action an AI agent should perform. For example, Slack and Notion do not reliably let an operator mint a token scoped to "read only these exact Slack channels" or "write only this exact page subtree" in the shape Umbra needs for per-agent policy. Even when a provider offers some scopes or installation boundaries, the scope usually lands at an app, workspace, repository, page share, or broad operation class. It does not express Umbra's runtime decision: this Dev CVM, under these profiles, may call this tool, for this resource id, with this verb.

Method-scoped HTTP egress policy is also too coarse. Read-like SaaS operations may use `POST`, write-like operations may share the same host and path family as reads, and provider APIs often require request-body interpretation to know the real target resource. The Security CVM should therefore remain the network boundary, but it should not be asked to infer Slack, Notion, or GitHub application semantics from raw HTTP.

A local MCP server inside the Dev CVM is not sufficient for privileged Slack, Notion, or GitHub access. The Dev Sandbox is intentionally user- and agent-mutable: the agent can edit files, change local MCP configuration, replace binaries, install packages, and run code as root inside the sandbox namespace. Any policy file, wrapper, or provider token placed there must be treated as compromised. The Dev CVM may run only a thin MCP shim for protocol compatibility; credentials and authorization logic must live in an attested component outside the agent's control.

The Tool CVM is that component. It exposes the MCP tools the agent needs, receives Umbra identity from the Security CVM, checks Console-authored semantic grants, and only then uses provider credentials that never enter the Dev CVM.

### 1.2 Invariants and Security Model

Implementations MUST preserve these invariants:

1. **No provider credentials in Dev CVMs.** Slack, Notion, GitHub, and other SaaS access tokens MUST NOT be written into the Dev Sandbox, Dev CVM environment, local MCP shim config, command argv, logs, or workspace files.
2. **Security CVM remains the network boundary.** Dev CVM traffic to the Tool CVM MUST traverse the entity Security CVM. Tool CVM traffic to the Console and to SaaS providers MUST also traverse the entity Security CVM unless a future spec explicitly carves out a narrower attested control-plane path.
3. **MCP is an interface, not a security boundary.** MCP tool descriptions, JSON Schemas, prompts, resources, and client-side approval UX MUST NOT be trusted for authorization. Every `tools/call` MUST be authorized server-side by the Tool CVM.
4. **Application authorization lives in the Tool CVM.** The Security CVM MUST NOT attempt to infer "may post to Slack channel C123" from raw HTTP requests. It grants only network reachability to the trusted Tool CVM and injects authenticated Umbra identity.
5. **Fail closed.** Missing identity, stale policy, malformed policy, unknown provider credential, invalid resource mapping, and provider-scope mismatch MUST deny the tool call before any provider API request is made.
6. **Provider scoping is defense in depth.** Operators SHOULD use the narrowest provider-supported app scopes, capabilities, GitHub App permissions, installation targets, Notion capabilities, or Slack scopes. Umbra policy remains the authoritative ceiling even when provider credentials are broader.
7. **One live Tool CVM per entity.** The default model is at most one live Tool CVM per entity, matching the Security CVM trust shape. Multi-Tool-CVM sharding is out of scope for this revision.
8. **No generic provider escape hatch.** The Tool CVM MUST NOT expose tools that allow arbitrary provider HTTP calls, arbitrary GraphQL, arbitrary Slack method invocation, arbitrary Notion endpoint invocation, or raw credential retrieval.
9. **Tool results are untrusted content.** Data returned from Slack, Notion, GitHub, or other providers may contain prompt-injection text. The Tool CVM MUST NOT convert provider content into Umbra policy, credentials, or hidden instructions.

## 2. Topology

The expected runtime topology is:

```text
AI agent in Dev Sandbox
  MCP client or local MCP shim
    |
    | HTTP(S), forced proxy
    v
Dev CVM egress forwarder
    |
    | aTLS to Security CVM, Proxy-Authorization: Dev CVM bearer
    v
Security CVM
    |
    | verified Tool CVM upstream, injected Umbra identity assertion
    v
Tool CVM /mcp
    |
    | forced proxy with Tool CVM bearer
    v
Security CVM
    |
    | HTTPS to approved provider APIs
    v
Slack / Notion / GitHub
```

Control-plane state flows by pull:

```text
Tool CVM --forced proxy through Security CVM--> Console /internal/tool-control/bundle
Tool CVM --forced proxy through Security CVM--> Console /internal/tool-events
```

The Tool CVM MAY expose a remote MCP Streamable HTTP endpoint directly to the Dev CVM's MCP client, or the Dev CVM MAY run a small local stdio MCP shim that forwards MCP JSON-RPC messages to the Tool CVM's HTTP endpoint. In both cases, the Dev CVM holds no SaaS credentials. The local shim is convenience glue and is not trusted for authorization.

## 3. Boot Sequence and Attestation

### 3.1 Environment Injection

The Console injects the following configuration into the Tool CVM deployment. Plaintext secret values MUST NOT be written to persistent storage.

| Variable | Purpose |
| --- | --- |
| `CONSOLE_URL` | Base URL of the Umbra Console. |
| `ENTITY_ID` | UUID of the entity this Tool CVM serves. |
| `TOOL_CVM_ID` | UUID of this Tool CVM. |
| `CONSOLE_TOOL_TOKEN` | Service-principal bearer used to pull tool-control state and submit tool events. |
| `TOOL_PROXY_TOKEN` | Service-principal bearer used by the Tool CVM egress forwarder when sending outbound traffic through the Security CVM. |
| `SECURITY_CVM_FQDN` | Entity Security CVM endpoint used for Tool CVM egress. |
| `SECURITY_CVM_CA_B64` | Security CVM mitmproxy CA trusted by Tool CVM egress clients. |

Provider credentials are not injected at boot. The Tool CVM receives provider credential material only through the attested tool-control pull after the Console has verified the Tool CVM. Mirroring the Dev forwarder, the full SC aTLS policy MUST NOT enter the provider launch env: the Tool forwarder MAY listen for measurement compatibility, but before its first upstream SC connection or successful proxy response it MUST authenticated-fetch a complete policy with `CONSOLE_TOOL_TOKEN`, strictly validate it, and atomically install it. Bounded fetch or validation failure returns fail-closed `502`; blank, stub, dev, disabled, or incomplete policies and bypasses are forbidden. It periodically refreshes from the same authenticated control endpoint afterward.

### 3.2 Runtime Measurement Binding

At startup, the Tool CVM MUST extend the hardware runtime measurement register with a canonical payload binding the instance to its Console and entity. The canonical JSON payload is:

```json
{
  "CONSOLE_URL": "<...>",
  "console_tool_token_sha256": "<sha256>",
  "entity_id": "<uuid>",
  "security_cvm_ca_sha256": "<sha256>",
  "security_cvm_fqdn": "<fqdn>",
  "tool_cvm_id": "<uuid>",
  "tool_proxy_token_sha256": "<sha256>"
}
```

The payload MUST be canonicalized with JSON Canonicalization Scheme (RFC 8785) and extended with SHA-384, matching the Security CVM runtime-binding pattern. The Console verifier MUST replay the same payload at provisioning and during reconciler probes. Any mismatch MUST prevent credential disclosure and mark the Tool CVM unhealthy.

### 3.3 Service Startup

After measurement binding, the Tool CVM starts:

- an MCP server on the internal application network;
- a management endpoint for health and attestation routes;
- a control poller for `/internal/tool-control/bundle`;
- a tool-event emitter for `/internal/tool-events`;
- a Tool CVM egress forwarder that is the only service with a non-internal network route.

The Tool CVM application container MUST NOT have a direct default route to the internet. Provider and Console traffic MUST use the Tool CVM egress forwarder and the entity Security CVM.

## 4. Public API Surface

The Tool CVM exposes exactly one public port, `:443`, fronted by shade's `nginx-cert-manager` and attestation routing. Internal service names are implementation details. Public routes are:

| Method + path | Purpose |
| --- | --- |
| `POST /tdx_quote` | Hardware attestation quote endpoint verified by the Console and, when needed, the Security CVM. |
| `POST /mcp` | MCP Streamable HTTP client-to-server messages. |
| `GET /mcp` | OPTIONAL streaming response channel if required by the pinned MCP protocol version. |
| `GET /healthz` | Minimal liveness response. No secrets or policy details. |
| all others | `404 Not Found`. |

### 4.1 MCP Endpoint Authentication

Every `/mcp` request MUST carry `Authorization: Bearer <Umbra tool assertion>`. The assertion is injected by the Security CVM after it authenticates the originating Dev CVM. The Tool CVM MUST reject requests with:

- `401 Unauthorized` when the assertion is missing, malformed, expired, signed by an unknown key, or has the wrong audience;
- `403 Forbidden` when the assertion is valid but the caller has no grant for the requested MCP method or tool call;
- an MCP JSON-RPC error response for denied `tools/call` requests after the MCP session is established.

The Tool CVM MUST NOT accept identity from client-supplied `X-Umbra-*` headers, MCP tool arguments, MCP client metadata, source IP, User-Agent, or any value inside the JSON-RPC payload.

### 4.2 MCP Protocol Profile

The Tool CVM MUST implement the pinned MCP Streamable HTTP version selected by the implementation. At minimum it MUST support:

- lifecycle initialization and capability negotiation;
- `tools/list`;
- `tools/call`;
- JSON Schema input validation for each tool.

The Tool CVM MAY expose MCP resources and prompts, but every resource read and prompt retrieval MUST be policy checked as strictly as tool calls. Tool list results MAY be filtered to the caller's effective grants, but filtering is not authorization. `tools/call` MUST always re-check authorization.

The Tool CVM MUST NOT expose provider credentials, Umbra service-principal bearers, identity assertions, OAuth refresh tokens, or raw provider response headers through MCP tools, resources, prompts, errors, or logs.

## 5. Security CVM Identity Injection

The Security CVM is responsible for injecting Umbra identity assertions into Dev-CVM-originated requests to the Tool CVM.

### 5.1 Injection Preconditions

The Security CVM MUST inject a Tool CVM assertion only when all of the following are true:

1. The inner proxy request is authenticated as a known Dev CVM through its `Proxy-Authorization` bearer.
2. The effective Dev CVM network policy allows the Tool CVM destination and `/mcp` path.
3. The upstream endpoint matches the entity's live Tool CVM FQDN and port.
4. The Security CVM has verified the Tool CVM's attested identity using the current Tool CVM aTLS policy or an equivalent Console-pinned attestation policy.
5. The request path is a Tool CVM MCP path. Assertions MUST NOT be injected for arbitrary destinations, provider APIs, Console routes, or non-Tool-CVM hosts.

Before injection, the Security CVM MUST strip or overwrite sandbox-supplied `Authorization`, `Cookie`, `X-Umbra-Identity`, `X-Umbra-*`, and other Umbra-reserved identity headers on requests to the Tool CVM.

### 5.2 Assertion Format

The Umbra tool assertion SHOULD be a compact JWT signed with EdDSA. It MUST contain at least:

```json
{
  "iss": "umbra-security-cvm/<security_cvm_id>",
  "sub": "umbra-dev-cvm/<cvm_id>",
  "aud": "umbra-tool-cvm/<tool_cvm_id>",
  "entity_id": "<uuid>",
  "cvm_id": "<uuid>",
  "user_id": "<uuid>",
  "profile_ids": ["<uuid>", "..."],
  "policy_version": 123,
  "iat": 1710000000,
  "exp": 1710000300,
  "jti": "<uuid>"
}
```

Requirements:

- `exp - iat` MUST be no more than 5 minutes.
- `aud` MUST bind the assertion to one Tool CVM.
- `jti` MUST be unique enough for replay correlation. The Tool CVM MAY maintain a bounded replay cache for high-risk write tools.
- The Security CVM MUST NOT log the raw assertion.
- The Tool CVM MUST validate the signature, `iss`, `aud`, `entity_id`, `exp`, and `iat` before reading any MCP payload.

The Console distributes active assertion-verification public keys to the Tool CVM through `/internal/tool-control/bundle`. The private signing key is provisioned only to the Security CVM after its attestation succeeds. Key rotation MUST support overlap of old and new public keys.

### 5.3 Security CVM Control State

Before the Console marks a Tool CVM operation `succeeded`, the entity Security CVM MUST have pulled control state that lets it handle both directions of Tool CVM traffic:

```json
{
  "tool_cvms": [
    {
      "tool_cvm_id": "<uuid>",
      "proxy_token_hash": "<sha256>",
      "fqdn": "tool-....example.com",
      "atls_policy": {"...": "..."},
      "assertion_audience": "umbra-tool-cvm/<tool_cvm_id>",
      "egress_policy_version": 3
    }
  ]
}
```

This state is an extension of the Security CVM control bundle. It lets the Security CVM authenticate Tool CVM egress via `TOOL_PROXY_TOKEN`, verify the Tool CVM before Dev-CVM-to-Tool-CVM identity injection, and apply a narrow egress policy for Tool-CVM-originated Console/provider traffic.

If the Security CVM has not yet observed the Tool CVM proxy token hash, Tool CVM egress MUST receive `407 Proxy Authentication Required`. If the Security CVM has not yet observed the Tool CVM attestation policy or assertion audience, Dev CVM requests to `/mcp` MUST fail closed without identity injection.

## 6. Control Plane Synchronization

The Tool CVM pulls state from the Console. The Console never pushes policy or credentials to the Tool CVM.

### 6.1 Tool-Control Bundle

The Tool CVM MUST poll:

```text
GET <CONSOLE_URL>/internal/tool-control/bundle
Authorization: Bearer <CONSOLE_TOOL_TOKEN>
```

The poll cadence SHOULD be 5 seconds with jitter. The Tool CVM MUST use `If-None-Match` and atomically swap new policy state on `200 OK`. On `304 Not Modified`, it keeps the current state. If the Tool CVM cannot refresh state before its local policy TTL expires, it MUST fail closed for provider tool calls.

The response body is:

```json
{
  "entity_id": "<uuid>",
  "tool_cvm_id": "<uuid>",
  "version": 42,
  "assertion_issuers": [
    {
      "security_cvm_id": "<uuid>",
      "kid": "sc-tool-identity-2026-05",
      "alg": "EdDSA",
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
      "not_before": "<timestamp>",
      "not_after": "<timestamp>"
    }
  ],
  "cvms": [
    {
      "cvm_id": "<uuid>",
      "user_id": "<uuid>",
      "profile_ids": ["<uuid>"],
      "policy_version": 7,
      "merged_tool_policy": {"tool_grants": []}
    }
  ],
  "connectors": [
    {
      "connector_id": "<uuid>",
      "provider": "slack",
      "resource_owner": "T012345",
      "credential_type": "oauth_access_token",
      "access_token": "<plaintext token for Tool CVM only>",
      "refresh_token": null,
      "expires_at": null,
      "provider_capabilities": ["chat:write", "channels:read"]
    }
  ]
}
```

Plaintext provider credentials in this response MUST be visible only to the Tool CVM. User-facing Console reads MUST redact them. The Console MUST NOT include connector credentials in traffic logs, audit events, operation results, or error details.

### 6.2 Strict Bundle Validation

The Tool CVM MUST validate the bundle against a closed schema before use. Unknown top-level fields, invalid UUIDs, malformed public keys, duplicate connector ids, malformed credential expiry values, invalid provider names, invalid tool grants, or malformed resource ids MUST cause the Tool CVM to reject the new bundle and continue using the previous valid bundle until its TTL expires. If no valid bundle exists, all MCP calls MUST fail closed.

### 6.3 Credential Lifetime and Refresh

Provider credentials MAY be long-lived or expiring depending on the provider. The preferred model is:

- Console stores refresh material and write-only connector secrets.
- Tool CVM receives only the access token required to execute provider calls.
- Console refreshes expiring credentials and the Tool CVM receives refreshed access tokens on the next poll.

If provider constraints require the Tool CVM to hold refresh material, the refresh token MUST be included only in the attested tool-control bundle and MUST be zeroized when replaced. Refresh failures MUST fail closed for that connector and emit a redacted tool event.

## 7. Tool Policy Schema

The Tool CVM consumes a Console-computed `merged_tool_policy` per Dev CVM. The schema is closed:

```json
{
  "tool_grants": [<ToolGrant>, ...]
}
```

An empty `tool_grants` array means "no provider tools allowed".

`<ToolGrant>`:

```json
{
  "id": "<1..100 chars, [A-Za-z0-9._:-]>",
  "provider": "slack",
  "operation": "messages.post",
  "verb": "create",
  "resource_type": "slack_channel",
  "resource_ids": ["C0123456789"],
  "connector_ids": ["<uuid>"]
}
```

Fields:

- `id`: stable grant id used in audit decisions.
- `provider`: one of `slack`, `notion`, `github` in this revision.
- `operation`: provider operation family. It MUST be from the provider operation catalog implemented by the Tool CVM.
- `verb`: one of `read`, `search`, `create`, `update`, `delete`, `comment`.
- `resource_type`: provider-specific resource namespace, such as `slack_channel`, `notion_page`, `notion_database`, `github_repo`, `github_issue`, or `github_pull_request`.
- `resource_ids`: 1..256 exact provider resource ids in the canonical format for the resource type. Wildcards are not supported in this revision.
- `connector_ids`: 1..16 connector credentials that may satisfy this grant.

The Tool CVM MUST map each MCP `tools/call` to exactly one `(provider, operation, verb, resource_type, resource_id, connector_id)` authorization tuple before contacting the provider. If the tool call cannot be mapped exactly, it MUST be denied.

Canonical resource id formats:

| Resource type | Format |
| --- | --- |
| `slack_workspace` | Slack team/workspace id, e.g. `T0123456789`. |
| `slack_channel` | Slack channel id, e.g. `C0123456789`. |
| `slack_message` | `<channel_id>:<message_ts>`, e.g. `C0123456789:1710000000.123456`. |
| `notion_workspace` | Notion workspace or bot-owner id when available, otherwise connector id. |
| `notion_database` | Notion database id without URL decoration. |
| `notion_page` | Notion page id without URL decoration. |
| `github_repo` | `owner/repo`. |
| `github_issue` | `owner/repo#number`. |
| `github_pull_request` | `owner/repo#number`. |

### 7.1 Merge Semantics

Tool policies are grant-only in this revision. Profile policies that contribute `tool_grants` merge by canonical-json union. There is no `blocked_tools` field in this revision. A call is allowed only when at least one grant exactly covers the provider, operation, verb, resource id, and connector id selected for the call.

Adding a profile can add grants. Removing a profile can remove grants. A Tool CVM MUST treat missing policy, malformed policy, and missing connector credentials as deny all for the affected Dev CVM.

### 7.2 Provider Operation Catalog

The initial operation catalog SHOULD include:

| Provider | Operation | Verb | Resource type |
| --- | --- | --- | --- |
| `slack` | `channels.list` | `read` | `slack_workspace` |
| `slack` | `messages.search` | `search` | `slack_channel` |
| `slack` | `messages.read` | `read` | `slack_channel` |
| `slack` | `messages.post` | `create` | `slack_channel` |
| `slack` | `messages.update` | `update` | `slack_message` |
| `notion` | `search` | `search` | `notion_workspace` |
| `notion` | `database.query` | `read` | `notion_database` |
| `notion` | `page.read` | `read` | `notion_page` |
| `notion` | `page.update` | `update` | `notion_page` |
| `github` | `repo.read` | `read` | `github_repo` |
| `github` | `issue.read` | `read` | `github_repo` |
| `github` | `issue.comment` | `comment` | `github_issue` |
| `github` | `pull_request.read` | `read` | `github_repo` |
| `github` | `pull_request.comment` | `comment` | `github_pull_request` |

Implementations MAY add operations only when the operation's resource mapping and audit fields are specified. Generic operations such as `github.graphql`, `slack.api_call`, `notion.request`, or `http.request` MUST NOT be exposed to agents in this revision.

## 8. MCP Tool Semantics

Each MCP tool MUST be semantic and provider-aware. Examples:

- `slack_messages_search`
- `slack_messages_post`
- `notion_database_query`
- `notion_page_update`
- `github_pull_request_read`
- `github_pull_request_comment`

For every tool:

1. The Tool CVM validates the MCP JSON-RPC envelope and tool input schema.
2. It validates the Umbra assertion and resolves `(entity_id, cvm_id, user_id, profile_ids)`.
3. It maps the input to a provider operation and exact resource ids.
4. It checks `merged_tool_policy.tool_grants`.
5. It selects an allowed connector credential.
6. It runs provider-specific validation and optional DLP on agent-supplied fields.
7. It calls the provider API through the Tool CVM egress forwarder and Security CVM.
8. It returns a bounded, redacted MCP result.
9. It emits a tool event.

Tool results MUST bound payload size. Provider errors MUST be normalized and redacted. Provider tokens, full provider request bodies, full response bodies, and raw provider auth headers MUST NOT be returned to the Dev CVM.

## 9. Provider Connectors

The Console owns connector installation and credential lifecycle. The Tool CVM consumes connector credentials but does not author them.

### 9.1 Slack

Slack connectors SHOULD use a Slack app installation rather than a user-pasted token. The connector metadata MUST include the Slack workspace id. The Tool CVM MUST validate channel ids, message timestamps, and Slack API method selection before calling Slack.

Slack credentials often carry write scopes that cover multiple operations. Umbra policy MUST remain the operation/resource/action ceiling regardless of Slack token scope.

### 9.2 Notion

Notion connectors SHOULD use a Notion integration token with the narrowest available capabilities and explicitly shared pages or databases. The connector metadata MUST include the Notion workspace or bot owner identifier when available.

Notion search and query operations may use POST even for read-like behavior. The Tool CVM MUST authorize Notion intent by operation and target page/database, not by HTTP method.

### 9.3 GitHub

GitHub connectors SHOULD use GitHub App installation tokens scoped to selected organizations and repositories. Fine-grained PATs MAY be supported only when the Console records their intended owner and repository set.

The Tool CVM MUST authorize GitHub writes by semantic operation, repository, and target issue or pull request when applicable. It MUST NOT expose a generic GraphQL or REST tool to agents in this revision.

## 10. Tool CVM Egress Through the Security CVM

The Tool CVM MUST use a local egress forwarder equivalent to the Dev CVM's forwarder. The Tool CVM application container joins only an internal network. The egress forwarder holds `TOOL_PROXY_TOKEN`, authenticated-fetches and strictly validates the complete Security CVM policy before its first upstream SC connection or successful proxy response, verifies the Security CVM with the installed policy, periodically refreshes it from the same Console control endpoint, and forwards all outbound HTTP(S) traffic through the Security CVM. The listener may exist for measurement compatibility, but bounded fetch failure, missing material, or an invalid, disabled, incomplete, blank, stub, or dev policy MUST return fail-closed `502` without an upstream connection; no full policy may be transported through the provider launch env and no bypass is permitted.

The Security CVM MUST distinguish Tool CVM egress from Dev CVM egress by service-principal token purpose. Tool CVM egress policy SHOULD be narrow:

- Console control and tool-event routes;
- approved Slack, Notion, and GitHub API hosts needed by configured connectors;
- provider OAuth token refresh hosts when Tool CVM-side refresh is enabled.

The Security CVM traffic log remains the network source of truth. Tool events are the semantic source of truth. The two streams SHOULD share correlation ids.

Because Tool CVM egress may contain managed provider credentials, DLP responsibility is split:

- The Tool CVM MUST scan and validate agent-supplied tool inputs before provider credentials are attached.
- The Security CVM MUST NOT log provider credential headers or request bodies.
- The Security CVM MAY perform destination policy and metadata logging for Tool CVM egress without body inspection, or MAY inspect with credential-aware redaction. The chosen mode MUST be explicit in the Security CVM spec before implementation.

## 11. Tool Event Ingestion

The Tool CVM emits one tool event per MCP tool call attempt, allowed or denied.

### 11.1 Event Schema

`<ToolEventIn>`:

```json
{
  "timestamp": "<RFC3339>",
  "tool_event_id": "<uuid>",
  "entity_id": "<uuid>",
  "tool_cvm_id": "<uuid>",
  "cvm_id": "<uuid|null>",
  "user_id": "<uuid|null>",
  "profile_ids": ["<uuid>", "..."],
  "mcp_session_id": "<string|null>",
  "tool_name": "slack_messages_post",
  "provider": "slack",
  "operation": "messages.post",
  "verb": "create",
  "resource_refs": [
    {"type": "slack_channel", "id": "C0123456789"}
  ],
  "connector_id": "<uuid|null>",
  "grant_id": "<string|null>",
  "outcome": "allowed",
  "provider_status": 200,
  "provider_request_id": "<string|null>",
  "error_code": null,
  "duration_ms": 123
}
```

Requirements:

- `outcome` is one of `allowed`, `denied`, `provider_error`, `validation_error`, `policy_stale`, or `internal_error`.
- `resource_refs` MUST contain ids and types only. It MUST NOT contain Slack message text, Notion page content, GitHub comment body, file contents, or provider payloads.
- `error_code` MUST be typed and redacted.
- The event MUST NOT include provider tokens, Umbra tokens, identity assertions, request bodies, response bodies, or raw headers.

### 11.2 Ingestion Route

The Tool CVM submits batches to:

```text
POST <CONSOLE_URL>/internal/tool-events
Authorization: Bearer <CONSOLE_TOOL_TOKEN>
```

The route SHOULD mirror `/internal/traffic-logs` semantics:

- `idempotency_key` per batch;
- timestamp skew checks;
- 1..1000 events per batch;
- retry with the same idempotency key on retryable errors;
- bounded in-memory queue with oldest-drop behavior when the Console is unavailable.

Tool events SHOULD be queryable separately from network traffic logs. Control-plane audit events record connector and policy mutations; tool events record runtime tool use.

## 12. Console Responsibilities

The Console owns:

- Tool CVM lifecycle: launch, show, update, terminate, attestation probe, and reconcile.
- Connector lifecycle: create, rotate, revoke, redacted read, and delete.
- Tool policy authoring in profiles.
- Provider credential encryption or write-only storage.
- Tool-control bundle rendering.
- Tool event ingest and retention.
- Security CVM assertion-key issuance and rotation.

The Console MUST NOT expose provider credential plaintext through user-facing APIs. It MUST record audit events for connector creation, rotation, revocation, policy changes, Tool CVM launch/update/terminate, and first credential disclosure to a successfully attested Tool CVM.

## 13. Dev CVM and CLI Responsibilities

The Dev CVM MAY include a local MCP shim for agent compatibility. The shim:

- MUST NOT hold SaaS provider credentials.
- MUST NOT hold long-lived Umbra credentials beyond what is already available to the Dev CVM session.
- SHOULD forward only to the entity Tool CVM MCP endpoint.
- MAY translate stdio MCP to remote Streamable HTTP MCP.

The CLI should expose Tool CVM and connector administration only through Console APIs. It SHOULD provide:

- `umbra tool-cvm launch/show/update/terminate/attestation`;
- `umbra connector add/list/show/rotate/remove`;
- `umbra profile configure --policy-file` support for `tool_grants`;
- a helper to print or install the local Dev CVM MCP shim configuration.

CLI output MUST keep stdout as payload and stderr as diagnostics, matching the existing CLI contract.

## 14. Security Properties

1. **Credential confinement.** Provider credentials are present only in Console secret storage, attested Tool CVM memory, and provider-bound outbound requests from the Tool CVM. They are never exposed to Dev CVMs.
2. **Identity origin.** The Tool CVM trusts only Security-CVM-signed Umbra assertions distributed by Console tool-control state. It does not trust agent-supplied identity.
3. **Attested destination before injection.** The Security CVM injects identity assertions only after verifying it is connected to the entity's live Tool CVM.
4. **Semantic policy ceiling.** Provider scopes may be broader than Umbra grants. The Tool CVM enforces Umbra grants before provider calls.
5. **Network backstop.** Direct Dev CVM access to provider APIs SHOULD be denied by default. Agents reach Slack, Notion, and GitHub through Tool CVM tools unless an admin explicitly authorizes direct egress for another workflow.
6. **No generic API tunnel.** The Tool CVM does not expose arbitrary provider API request tools.
7. **Redacted observability.** Tool events and traffic logs contain metadata and outcome, not secrets or full content.
8. **Policy freshness.** Tool CVM authorization fails closed on stale or invalid tool-control state.
9. **Shared entity trust point.** A compromised Tool CVM can misuse provider credentials for its entity until detected and decommissioned. Mitigations are narrow provider scopes, attestation, Console-authored policy, event logging, and the incident playbook.

## 15. Out of Scope

This revision does not specify:

- a web UI for connector installation or OAuth consent;
- multi-entity Tool CVMs;
- user-personal provider credentials distinct from entity connectors;
- arbitrary third-party MCP server hosting with entity credentials;
- non-MCP protocols for agent tools;
- workflow engines or scheduled automations;
- browser automation tools with SaaS cookies;
- provider-specific exhaustive endpoint coverage;
- human confirmation UX for destructive actions.

Future revisions may add per-user connectors, delete-class operations, richer Notion block mutation policy, GitHub contents write policy, human approval gates, and typed CLI policy helpers.
