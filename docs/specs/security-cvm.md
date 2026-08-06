# Umbra Security CVM Specification

This document is the authoritative specification for the Umbra Security Confidential VM (Security CVM or SC). It defines the SC's boot sequence, hardware attestation integration, control-plane polling, egress proxy semantics, policy enforcement, and traffic-log emission. Implementations MUST conform to this spec.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, and OPTIONAL in this document are used in the RFC 2119 / RFC 8174 sense.

## 1. Overview

The Security CVM acts as the egress gateway and policy enforcement point for an Umbra entity. There is exactly one live Security CVM per entity in v0. Every Dev CVM within that entity MUST route its outbound internet traffic through this SC.

The SC plays three primary roles:
1. **Trust Anchor**: It proves its identity and configuration integrity to the Console via hardware TEE attestation (Intel TDX / AMD SEV-SNP) before any secrets are exchanged or traffic is routed.
2. **Policy Enforcer**: It intercepts Dev CVM egress, authenticates the originating Dev CVM, and applies a merged security policy (allow-lists, deny-lists, secret scanning, and request-header secret injection) via a man-in-the-middle (MITM) proxy.
3. **Audit Source**: It acts as a data-plane observer, securely shipping batched traffic logs back to the Console for tenant visibility.

The SC is an enforcer, not an authoring authority. It makes decisions strictly based on state pulled from the Console. It accepts no incoming connections from developers and exposes no management UI.

### 1.1 Invariants & Security Model
* **Fail-Closed**: If a Dev CVM cannot be authenticated, a policy is malformed, or a destination is not explicitly allowed by the merged policy, the proxy connection MUST be dropped with `407 Proxy Authentication Required` (unknown bearer) or `403 Forbidden` (policy refusal). v0 does NOT implement defer-and-resolve; the SC waits for the next scheduled Console pull to learn new Dev-CVM bearers (§4.1, §5.1).
* **Statelessness, runtime policy/CA refresh**: The SC stores no persistent state across reboots. A restart or provider update can regenerate the in-memory mitmproxy CA and leaf TLS material. The Console's `security_cvm.update` flow updates and re-attests the existing SC deployment, then fetches the current CA/aTLS policy. Refresh-capable Umbra Dev CVM forwarders pull both over their existing authenticated, RTMR3-bound Console control channel, and the sandbox watcher replaces the installed CA (`docs/specs/dev-cvm.md` §4.5). The operation records whether the CA changed but does not create a CA-only Dev CVM rebind marker. Egress may fail closed briefly while polling converges; CA-caching processes may need a restart. A full `cvm.update` remains necessary for current provider-managed deployments when launch-bound SC identity, per-Dev bearers, or RTMR3 material changes. A persisted `SECURITY_CVM_REBIND_REQUIRED` marker is left fail-closed because the legacy runtime's refresh capability is unproven. Use the pre-Umbra control plane to terminate/decommission the preserved resource, then launch a replacement under Umbra; the renamed build cannot manage it, and `cvm.update` is not recovery. Persisting the SC CA, zero-blip propagation, and active-connection draining are later hardening steps.
* **Pull, Not Push**: The SC reaches out to the Console to pull state. The Console NEVER pushes policy to the SC.
* **Single public port, internal routing**: The SC exposes exactly **one** public port — `:443` — fronted by shade's `nginx-cert-manager` sibling, which terminates TLS with a dstack-KMS-issued leaf cert and routes by HTTP path / upgrade semantics to the right internal service (see §3 and §5 for the routing table). The Phala gateway is a layer-4 SNI forwarder only and never sees TLS plaintext, so end-to-end TLS to the SC is preserved — load-bearing for the attestation binding in §2 and `docs/specs/console.md` §10.4. mitmproxy itself listens on `:8080` **inside** the CVM's container network and is not reachable from outside the SC; the Phala gateway publishes no other ports.
* **Production dstack image**: The SC MUST be provisioned on the **production** dstack OS image, never a dev/debug image. Dev dstack images enable debug surfaces (serial console, relaxed boot) that are incompatible with an attested production egress gateway and change the measured boot chain. The provider adapter MUST pin the production image explicitly rather than relying on the `phala` CLI default; relying on the CLI default has shipped dev images in the past. The expected production `os_image_hash` is part of the attested boot chain the Console verifies (§2.2 step 3).

## 2. Boot Sequence and Attestation

The SC runs inside a Confidential VM. At boot, it MUST establish trust, generate its proxy Root CA, and start its services before processing any Dev CVM traffic.

### 2.1 Environment Injection
The Console injects the following configuration via the deployment environment. These values MUST NOT be written to persistent storage:
* `CONSOLE_URL`: The base URL of the control plane.
* `ENTITY_ID`: The UUID of the entity this SC serves.
* `SC_ID`: The UUID of this Security CVM.
* `CONSOLE_INGEST_TOKEN`: The plaintext service-principal bearer for polling the Console and submitting logs.
* `CA_EXPORT_TOKEN`: The plaintext bearer the Console will present to fetch the SC's generated Root CA.

### 2.2 Boot Execution Order
1. **Root CA Generation**: The SC generates a fresh ECDSA P-384 Root CA with a default validity of 365 days. The public cert is exported at `GET /ca.pem`; mitmproxy consumes ephemeral files under a `tmpfs` confdir (`mitmproxy-ca.pem` private bundle mode `0400`, public cert `mitmproxy-ca-cert.pem`). This CA MUST NOT be written to durable disk. It is used by the proxy to generate on-the-fly leaf certificates for intercepted outbound traffic. Because the CA is ephemeral, a restart or provider update can regenerate it — see §1.1's authenticated runtime-refresh invariant.
2. **Leaf TLS Generation**: The SC's leaf certificate for public ingress on `:443` is issued by dstack-KMS at boot (handled by shade's `nginx-cert-manager`, mounted at `/etc/nginx/ssl/`), not by this service. The SC service does NOT mint its own leaf cert — the dstack-KMS-issued cert is the public-CA-trusted material the Console and forwarders see.
3. **Hardware RTMR Extension (Anti-Tamper)**: The SC computes `SHA-256(CONSOLE_INGEST_TOKEN)` and `SHA-256(CA_EXPORT_TOKEN)`. It canonicalizes the boot parameters via JSON Canonicalization Scheme (RFC 8785) as exactly:
   ```json
   {"CONSOLE_URL": "<...>", "ca_export_token_sha256": "<...>", "entity_id": "<...>", "ingest_token_sha256": "<...>", "sc_id": "<...>"}
   ```
   The SC service computes the SHA-384 digest of this payload at boot (for logging and operator diagnostics). The dstack guest stack MUST extend the hardware Runtime Measurement Register (e.g., RTMR3 on TDX) with that digest via the provider env-file path — that extension is not implemented in the Python SC package. This cryptographically binds the running instance to the Console's injected configuration. The SC is verified with **full runtime verification**, exactly like a Dev CVM — never `dev()` / `disable_runtime_verification`. The Console regenerates the SC's aTLS policy from the deployed compose via shade (`generate_policy`) and passes the **complete, authoritative** `app_compose` together with `expected_bootchain` and `os_image_hash` (as sibling policy fields) into the quote-verification request, so the `atlas-rs` verifier runs compose-hash + bootchain + os-image + RTMR replay against the measured quote, with MRTD anchored to the row's `expected_image_measurement` (`docs/specs/console.md` §10.4). Verifying only the MRTD is insufficient: the MRTD is the dstack-guest base measurement shared by every CVM (`SECURITY_CVM_IMAGE_MEASUREMENT == DEV_CVM_IMAGE_MEASUREMENT`), so it proves the TEE is genuine but nothing app-specific. The verifier MUST reject (never relax to `dev()`) if the shade policy does not yield a complete `app_compose` + `expected_bootchain` + `os_image_hash`. **Note on `8bf96c0`:** that regression folded the shade-derived fields alongside an *incomplete* `app_compose` (`{docker_compose_file}` only), which changed the reconstructed compose-hash and produced a spurious `ATTESTATION_IMAGE_MISMATCH` (`reason=app_compose_hash_mismatch`). The fix is to send shade's **complete** `app_compose` as-is (the same source the Dev CVM egress forwarder verifies the SC against in prod) — not to drop the runtime fields. The shade policy is materialized fresh on every provision and reconciler probe, so **app-compose / bootchain / os-image drift is detected** (T-29 image substitution, T-31 compose substitution). **Limitation (T-30 not yet fully enforced):** the JCS binding values `(CONSOLE_URL, entity_id, sc_id, SHA-256(CONSOLE_INGEST_TOKEN), SHA-256(CA_EXPORT_TOKEN))` are carried in `rtmr3_binding` and persisted, but the verifier does **not yet recompute the expected RTMR3 from them and compare** — `atls_connect` (atlas-rs) verifies the event-log replays to the quote's `rt_mr3` and checks the compose-hash/bootchain/os-image events, but it does not expose the event log nor accept an expected binding-digest, so a hostile `CONSOLE_URL`/token injected at boot is not caught by the binding check alone (it would still have to pass compose/image verification). Closing T-30 requires the verifier to obtain the event log and assert the binding event equals `SHA-384(JCS(rtmr3_binding))`; tracked separately. See `docs/specs/console.md` §10.4 T-30.
4. **Service Startup**: The SC starts `mitmdump` (mitmproxy on internal port `:8080`, never published externally), the proxy tunnel shim (`:8082`, reachable only from `nginx-cert-manager`), management HTTP for `/ca.pem` (internal `:8081`, routed by shade nginx), and asyncio background loops for control-plane polling and traffic-log shipping inside the mitmproxy addon. Public `:443` attestation (`POST /tdx_quote`) and TLS termination are owned by shade's `nginx-cert-manager` sibling, not the Python package. nginx routes inbound `:443` traffic by HTTP path / upgrade semantics to the right internal target per §3 and §5.

## 3. Local API Surface (Inbound)

The SC exposes exactly **one public port** — `:443`, terminated by shade's `nginx-cert-manager` with the dstack-KMS-issued leaf cert (§2.2 step 2). nginx routes by HTTP method / path:

| Method + path | Internal target | Purpose |
| --- | --- | --- |
| `POST /tdx_quote` | shade `attestation-service` (internal `:8080`) | TEE remote-attestation surface verified by the Console at provisioning (`docs/specs/console.md` §10.4, §8.4 step 7) and the reconciler (`docs/specs/console.md` §9.2 step 7). |
| `GET /ca.pem` | SC management service | One-shot CA export consumed by the Console's CA-fetch saga step (`docs/specs/console.md` §8.4 step 8). |
| `GET /umbra/proxy` with `Connection: Upgrade`, `Upgrade: umbra-proxy` | SC proxy-tunnel service (internal `:8082`) | Establishes the Dev-CVM egress byte tunnel through shade's path router. After `101 Switching Protocols`, the Dev forwarder sends inner HTTP-proxy requests (`CONNECT host:port` or absolute-form HTTP) byte-for-byte to mitmproxy (`:8080`) (§5). |
| All other paths/methods | n/a | `404 Not Found`. |

Both the management routes and the proxy traffic terminate at the same `nginx-cert-manager`-served leaf cert. The `dev-egress-forwarder` (`docs/specs/dev-cvm.md` §4.5) opens an aTLS-verified TLS session to `https://${SECURITY_CVM_FQDN}:443`, upgrades `GET /umbra/proxy`, then sends the inner HTTP-proxy request over the upgraded byte stream, supplying `Proxy-Authorization: Bearer <Dev-CVM-PROXY_AUTH>` on every inner request. mitmproxy itself MUST NOT be published outside the SC's container network. The upgrade request MUST NOT carry `Proxy-Authorization`; the bearer belongs only to the inner proxy protocol bytes.

### `POST /tdx_quote`
Used by the Console to verify the SC's identity during provisioning (`docs/specs/console.md` §8.4 step 7) and by the reconciler drift-detection loop (`docs/specs/console.md` §9.2 step 7). Uses the same EKM-+ -nonce binding model as Dev CVMs (`docs/specs/dev-cvm.md` §8.3, `docs/specs/cli.md` §6.1) so a single `atlas-rs` verifier path covers every Umbra CVM.

* **Auth**: None (the attestation quote serves as proof, and the verifier supplies a fresh nonce per request).
* **Request body**: `{"nonce_hex": <64-char hex>}` — 32 random bytes the caller has freshly generated. The body MUST be present; `400 Bad Request` on missing or malformed nonce.
* **EKM injection**: `nginx-cert-manager` injects the active TLS session's RFC 5705 EKM exporter (`EXPORTER-Channel-Binding`, 32 bytes) into the upstream request as `X-TLS-EKM-Channel-Binding: ${ekm_hex}:${hmac_hex}` (same wire convention as Dev CVMs — `docs/specs/dev-cvm.md` §4.3, §4.4). Callers MUST NOT set this header themselves; nginx strips and re-injects it.
* **Behavior**: The attestation-service validates the EKM-binding HMAC (`docs/specs/dev-cvm.md` §4.4) inside the TEE, builds `report_data = SHA512(nonce_bytes || ekm_bytes)`, and asks dstack for a fresh quote bound to it. Mismatch on the HMAC → `400 Bad Request` without producing a quote.
* **Response**: `200 OK` containing the raw binary or base64-encoded vendor quote plus the bootchain metadata. The Console's verifier (and the same `atlas-rs` library Dev CVMs are verified with) checks the complete Shade runtime policy: the shared guest `expected_image_measurement`, authoritative `app_compose`, `expected_bootchain`, `os_image_hash`, the JCS-replayed RTMR3 inputs (§2.2 step 3), AND `report_data == SHA512(nonce_bytes || ekm_bytes)`. The SC therefore does NOT bind its leaf-cert SPKI into `report_data`; the EKM binding subsumes that role (a quote produced for one TLS session cannot be replayed against another, regardless of which leaf cert serves the session).

### `GET /ca.pem`
Used by the Console during the provisioning saga to retrieve the Root CA so it can be injected into Dev CVMs as a trusted root via the measured `security_cvm_ca` config block (`docs/specs/dev-cvm.md` §2.3, `docs/specs/console.md` §8.4 step 8).
* **Auth**: `Authorization: Bearer <token>`. The SC MUST perform a constant-time string comparison against the injected plaintext `CA_EXPORT_TOKEN`.
* **Behavior**: Fails with `401 UNAUTHORIZED` on mismatch.
* **Response**: `200 OK` with `Content-Type: application/x-pem-file`. The body is the public `ca.pem` generated at boot. The private key MUST NEVER be exported.

### `GET /umbra/proxy` upgrade
Used only by Dev CVM `dev-egress-forwarder` instances. This endpoint exists because shade's nginx route layer is path-based; it does not forward authority-form `CONNECT host:port` request targets directly to an upstream service.

* **Auth**: None on the upgrade request. Dev-CVM identity is authenticated by the inner `Proxy-Authorization` header after the byte tunnel is established (§5.1).
* **Request**: `GET /umbra/proxy HTTP/1.1` with `Connection: Upgrade` and `Upgrade: umbra-proxy`. The request MUST NOT include `Proxy-Authorization`.
* **Behavior**: On a valid upgrade, return `101 Switching Protocols`, connect to internal `mitmproxy:8080`, and then bridge bytes bidirectionally without parsing, logging, or transforming the inner proxy stream. Invalid upgrade requests fail closed with `4xx`; upstream connection failure returns `502`.
* **Inner stream**: The first bytes after `101` MUST be a regular HTTP-proxy request understood by mitmproxy: `CONNECT host:port` for HTTPS or absolute-form HTTP for plain HTTP. The SC enforcement hook sees and strips `Proxy-Authorization` from that inner request, not from the outer upgrade request.

## 4. Control Plane Synchronization

The SC runs an asynchronous background loop to synchronize the Dev CVM routing map and effective policies from the Console.

### 4.1 The Polling Loop
The SC MUST poll the Console at `GET <CONSOLE_URL>/internal/sc-control/cvms` every **5 seconds** (± 1s jitter) by default. Operators MAY override cadence with `SC_CONTROL_INTERVAL_SECONDS` and `SC_CONTROL_JITTER_SECONDS` for non-production tuning.

* **Auth**: `Authorization: Bearer <CONSOLE_INGEST_TOKEN>`.
* **Caching**: The SC MUST include the `If-None-Match: <ETag>` header from the previous successful response. If the Console returns `304 Not Modified`, the SC sleeps until the next tick.
* **Atomic Swap**: On `200 OK`, the SC MUST update its internal routing map atomically. Ongoing proxy connections MUST NOT be interrupted. Terminated Dev CVMs that drop out of the Console's payload MUST be immediately evicted from the SC's local map.

### 4.2 Strict Policy Schema Validation
The Console validates profile policies at write time and computes merged policies (§8.5), but the SC remains the last boundary before egress.
* The SC MUST validate each incoming `merged_policy` against a strict, hardcoded closed-world schema implemented in Python (same field shapes and limits as this section; there is no separate JSON Schema artifact on the SC).
* If a Dev CVM's policy violates the schema (e.g., invalid types, malformed regexes), the SC MUST drop that specific policy, treat the Dev CVM as having an empty "deny-all" policy, and emit a structured `ERROR` log (`merged_policy_invalid`). A malformed payload MUST NOT crash the proxy process.

### 4.3 Effective Policy Schema

The SC consumes the Console-computed effective `merged_policy` from `/internal/sc-control/cvms` (`docs/specs/console.md` §4.3, §8.5). The v0 schema is closed: unknown top-level fields are invalid. Empty arrays are allowed and mean "no contribution".

```json
{
  "allowed_destinations": [<DestinationRule>, ...],
  "blocked_destinations": [<DestinationRule>, ...],
  "secret_patterns": [<SecretPattern>, ...],
  "secret_injections": [<SecretInjection>, ...],
  "unfulfilled_secret_injections": [<UnfulfilledInjection>, ...],
  "sandbox_env": [<SandboxEnvPlaceholder>, ...]
}
```

`sandbox_env` is included only so the effective policy remains inspectable as one object; the SC MUST ignore it at enforcement time. The Dev CVM consumes the same field as launch-time non-secret placeholder env (`docs/specs/dev-cvm.md` §7.1).

`unfulfilled_secret_injections` is optional and **Console-generated only** (`docs/specs/console.md` §8.5 per-owner `value_from` resolution). Each `<UnfulfilledInjection>` is `{"id": <injection id>, "match": <DestinationRule match, no id / no extensions>, "header": <lower-case injectable header>}` and carries **no** secret material — it names an injection the Console expected to fulfil but could not, because the CVM owner's `value_from` grant was unusable (unminted / expired / rebound). Unlike the otherwise-closed top-level schema, this list is parsed **leniently**: a malformed marker is skipped (never raising), so a bad marker degrades to a lost signal rather than collapsing the CVM to deny-all — a marker can only ever ADD a per-destination fail-closed block and never widens egress, so strict rejection would buy no safety. Its enforcement effect is defined in §5.3 / §5.4. **Rollout:** this is a new closed-schema top-level field, so an SC image that predates it treats it as unknown and fail-closes the CVM to deny-all; the Console emits the key only when a marker exists, and this SC image MUST be deployed before the Console that emits it.

`<DestinationRule>`:

```json
{
  "id": "<1..100 chars, [A-Za-z0-9._:-]>",
  "scheme": "https",
  "host": "api.example.com",
  "ports": [443],
  "methods": ["GET", "POST"],
  "path_prefixes": ["/v1/"],
  "body_assertions": [<BodyAssertion>, ...],
  "websocket_assertions": [<WebsocketAssertion>, ...],
  "traffic_log_attributes": [<TrafficLogAttribute>, ...]
}
```

- `scheme` is `http` or `https`; v0 secret injection is meaningful only for HTTP(S).
- `host` is `"*"`, a lower-case DNS name with at least two labels (e.g. `api.example.com`), or one leading wildcard label such as `*.github.com`. Single-label names are invalid at parse time. Leading wildcards match subdomains only, not the apex. `"*"` matches syntactically public internet destinations: valid multi-label DNS hostnames and public IP literals. It MUST NOT match localhost, single-label names, or loopback/private/link-local/multicast/reserved IP literals. The SC does not perform DNS-resolution-based private-network blocking in v0.
- `ports` is `1..16` integers in `1..65535`; omit only if the schema default is the scheme default (`80` or `443`).
- `methods` is `1..16` uppercase HTTP methods, each at most **20** characters; the SC normalizes incoming methods to uppercase before matching.
- `path_prefixes` is `1..32` absolute, path-only prefixes. `"/"` matches every path. A policy prefix or incoming request path containing a query string, fragment, backslash, control character, raw or decoded `.` / `..` segment, raw or decoded duplicate interior slash, invalid percent escape, or percent-encoded `.` or `\` is ambiguous and MUST NOT match. Percent-encoded `/` is allowed when the decoded path remains canonical; this supports APIs such as npm scoped packages (`/@scope%2fpkg`). The SC rejects ambiguous policy prefixes at parse time and fails closed on ambiguous request paths.
- `body_assertions`, `websocket_assertions`, and `traffic_log_attributes` are optional and MUST appear only on rules inside `allowed_destinations`. They are invalid on `blocked_destinations` rules and on `secret_injections[*].match` rules; the SC MUST reject policies that include them outside `allowed_destinations`.

`<BodyAssertion>`:

```json
{
  "kind": "form",
  "field": "/channel",
  "allow_values": ["C0123456789", "C0987654321"]
}
```

- `kind` is `"form"` (`application/x-www-form-urlencoded`) or `"json"` (`application/json`). The request `Content-Type` media type MUST match the assertion kind, ignoring parameters such as `charset`; absent or mismatched `Content-Type` makes the assertion fail. One kind per rule. Endpoints accepting both encodings MUST be expressed as two parallel rules sharing the same `allow_values`.
- `field` is a bounded RFC 6901 JSON Pointer subset. It MUST begin with `/`. Each segment MUST match `[A-Za-z0-9_.-]{1,64}`. Pointer escapes (`~0`, `~1`) and array-append (`-`) are forbidden. For `kind: "form"`, exactly one segment. For `kind: "json"`, `1..4` segments; the pointer MUST resolve to a JSON scalar (string, number, or boolean) — `null` and non-scalar resolutions cause the rule to not match.
- `allow_values` is `1..256` literal strings of `1..256` chars each. The SC stringifies the extracted scalar (booleans render as `"true"`/`"false"`; numbers via Python `str()`) and tests byte-equality against `allow_values`. No regex, no normalization.
- A `<DestinationRule>` with `body_assertions` matches only when the destination predicate matches AND every assertion evaluates true. Content-Type mismatch, body parse failure, oversized body (> 1 MiB), JSON depth > 32, more than 1024 keys per object or 1024 entries per array, missing field, non-scalar resolution, and value mismatch all cause that rule's assertions to fail. If any destination-matching allow rule has `body_assertions`, the request MUST be allowed only by a destination-matching body-assertion rule whose assertions pass; if none pass, the request is denied with `body_assertion_failed` even if another destination-matching rule without body assertions exists. This prevents a broad rule (for example `host: "*"`) from widening a body-scoped endpoint.
- A rule MUST contain at most `16` `body_assertions`.

`<WebsocketAssertion>`:

```json
{
  "direction": "inbound",
  "when":    { "/type": "events_api" },
  "require": { "/payload/event/channel": {"in": ["C0123456789"]},
               "/payload/event/user":    {"in": ["U0123456789"]} },
  "on_violation": "drop",
  "on_drop_emit": { "envelope_id": "{/envelope_id}" }
}
```

`websocket_assertions` filter individual decrypted WebSocket message frames that ride an already-allowed CONNECT tunnel (`§5.5`). They are the connector-agnostic, declarative sibling of `body_assertions`: a request's `body_assertions` gate whether the sandbox may *send* a request, while `websocket_assertions` gate whether a *received* frame is delivered to the sandbox at all. The motivating use case is Slack Socket Mode, where the SC drops inbound `events_api` frames whose channel or sender is not on the profile allow-list — robust to both a rogue agent and an unwanted Slack invite — and acks them on the bot's behalf so Slack does not redeliver. All connector specifics live in the policy data (JSON pointers and allow-lists); no connector knowledge lives in SC code.

- `direction` selects which frames the assertion governs. v0 accepts only `"inbound"` (server → sandbox); the SC MUST reject `"outbound"` and any other value at parse time. Outbound frame filtering is a reserved, not-yet-implemented sibling.
- `when` is a `1..8` map of JSON pointers to literal scalars that *selects* a frame. A frame is selected only when every pointer resolves to a scalar byte-equal (same stringification as `<BodyAssertion>`) to its expected value. A data frame that is not selected — including any frame missing a `when` pointer — is dropped when any matching rule on the tunnel carries `websocket_assertions`, except for narrow connector lifecycle envelopes with top-level `type` `"hello"` or `"disconnect"` and no `payload` field. The lifecycle exemption skips the `require` content check, so it is bounded to genuine telemetry: only the keys `{type, num_connections, debug_info, connection_info, reason}` may appear, their VALUES must be small (int connection count, short `reason` string, `debug_info`/`connection_info` as flat maps of short scalar values), AND the total attacker-controlled text per frame (map keys + string values + `reason`) MUST be under a small byte ceiling (per-value bounds alone are a floor, not a ceiling). Lifecycle-TYPED frames (`type` ∈ `{hello, disconnect}`) are governed SOLELY by this bound and resolved BEFORE assertion selection: a frame that exceeds any bound is dropped regardless of any `websocket_assertions`, so a profile cannot author a `when:{"/type":"hello"}` guard to re-deliver an oversized lifecycle frame through the cross-rule union. This collapses the exemption to a small bounded telemetry residual rather than an open content channel — it does not reach zero (a lifecycle frame inherently carries a few short server strings such as `host`/`app_id`/`reason`), so a delivered lifecycle frame emits a contents-free traffic log (§6.1) to keep the residual auditable. WebSocket control opcodes (`ping`/`pong`/`close`) are not data frames and are exempt from content filtering.
- `require` is a `1..8` map of JSON pointers to `{"in": [...]}` matchers, evaluated only on a selected frame using the identical engine as `<BodyAssertion>.allow_values` (`1..256` strings, byte-equality after the same scalar stringification). An assertion's `require` *passes* only when *every* required pointer resolves to a scalar in its allow-list; a required pointer that is missing or resolves to a non-scalar makes that assertion's `require` fail (fail-closed). Whether a failing `require` drops the frame is decided by the cross-rule composition below — a frame is dropped only if it is selected and **no** selecting assertion's `require` passes. `require` MUST use the `{"in": [...]}` envelope; other matcher keys are invalid.
- `on_violation` is the action applied to a selected frame that fails `require`. v0 accepts only `"drop"`: the SC MUST NOT forward the frame to the sandbox.
- `on_drop_emit` is optional. When present, it is a `1..8` flat map of output keys (`[a-z_]{1,32}`) to single-pointer templates of the exact form `{/pointer}`. On a drop, the SC renders each template against the dropped frame, serializes the result as one compact JSON **text** frame, and injects it in the OPPOSITE direction of the dropped frame (an inbound drop emits a server-bound ack, `to_client=false`). This lets the SC acknowledge a dropped Socket Mode envelope on the bot's behalf so the server does not redeliver it. If any referenced pointer is missing or non-scalar, the SC still drops the frame but MUST NOT fabricate an emit frame.
- Pointer syntax and caps are identical to `<BodyAssertion>` `kind: "json"` fields: each pointer MUST begin with `/`, have `1..4` segments each matching `[A-Za-z0-9_.-]{1,64}`, and forbid the `~0`/`~1`/`-` escapes. Frames are parsed with the same bounds as request JSON bodies (`> 1 MiB`, depth `> 32`, `> 1024` keys per object, `> 1024` entries per array). On a tunnel governed by one or more matching `websocket_assertions`, non-text data frames, frames that are not valid JSON, and frames that exceed those bounds MUST be dropped instead of delivered. WebSocket control opcodes (`ping`/`pong`/`close`) are exempt from content filtering.
- A rule MUST contain at most `16` `websocket_assertions`.
- **Cross-rule composition (fail-closed, additive).** A tunnel grant authorizes the *connection*; inbound *content* is governed only by `websocket_assertions`. The SC parses the frame once, then gathers every assertion across **all** `allowed_destinations` rules whose tunnel predicate (`scheme`, `host`, `port`) matches the connection. A rule that grants the wss host but carries no `websocket_assertions` contributes nothing to frame governance; it does **not** "allow all inbound". (a) If no matching rule carries any assertion, the connection delivers inbound frames unchanged. (b) If one or more matching assertions exist but **no** assertion selects the parsed frame, the frame is dropped by default, except for lifecycle/control exemptions above. (c) If one or more assertions select the frame, the frame is delivered iff **at least one** selecting assertion's `require` passes (a UNION of allow-lists); otherwise it is dropped. This closes the cross-rule fail-open and keeps the profile model additive: attaching another profile can only ADD allowed values, never silently void another profile's restriction. The SC MUST NOT compute an intersection or "drop if any selecting assertion drops" — that would break additive profiles whose assertions legitimately allow different values. On a selected-frame drop, the ack derives from the **first** selecting assertion's `on_drop_emit`; malformed, oversized, non-text-data, and unselected drops emit no ack because no assertion-specific template has been selected.
- A dropped frame emits one `<TrafficLogIn>` (`§6.1`) carrying only the destination host, port, protocol, `method="GET"`, the WebSocket request path, and `response_code=null`; it MUST NOT carry any frame contents, `attributes`, or matched-rule identifiers. The SC MAY emit a local structured log event named `websocket_frame_blocked` for operations; that name is not a distinct ingest record type. Frames that pass by assertion (selected-and-allowed) or on tunnels without matching assertions emit no per-frame traffic log; a delivered **lifecycle-exempt** frame emits one contents-free `<TrafficLogIn>` (same shape as a drop) so the bounded telemetry residual is auditable; control opcodes emit none.

`<TrafficLogAttribute>`:

```json
{
  "name": "slack_channel",
  "kind": "json",
  "field": "/channel"
}
```

- `name` is `1..32` chars from `[a-z_]`. Names MUST be unique per rule.
- `kind` and `field` use the same syntax and caps as `<BodyAssertion>`.
- A rule MUST contain at most `4` `traffic_log_attributes`.
- The SC extracts each attribute only on the allow path (matched rule, body assertions passed, DLP clear, ready to forward). Denied requests MUST NOT trigger attribute extraction (see §6.1).
- Extracted values are stringified the same way as `<BodyAssertion>` and truncated to `256` chars before being recorded.

`<SecretPattern>`:

```json
{
  "id": "<1..100 chars, [A-Za-z0-9._:-]>",
  "name": "<human label, <= 100 chars>",
  "pattern": "<RE2 regex>",
  "scan_headers": true,
  "scan_body": true
}
```

The SC compiles patterns with RE2 at policy load. Unsupported syntax, catastrophic-regex engines, empty patterns, or patterns longer than 4096 bytes are invalid.

`<SecretInjection>`:

```json
{
  "id": "<1..100 chars, [A-Za-z0-9._:-]>",
  "match": <DestinationRule without id>,
  "type": "request_header",
  "header": "authorization",
  "value": "<plaintext secret expanded by the Console for the SC only>",
  "value_template": "Bearer ${secret}"
}
```

The Console stores write-only profile secret material encrypted outside `<Profile>.policy` and expands it into `value` only on the SC-control response. User-facing profile reads MUST NOT contain `value` (`docs/specs/console.md` §7.6a / §8.5). `value_template` MUST contain the literal token `${secret}` exactly once; the rendered header value MUST be ≤ 8192 bytes.

*Informative:* the Console MAY resolve `value` **per CVM owner** from user-scoped secret material (the `value_from` authoring source, `docs/specs/console.md` §2.3 / §7.6b / §8.5). This is entirely Console-side: the wire schema above and SC behavior are unchanged — each control entry simply carries the value resolved for that CVM's owner, and injections the Console cannot resolve are omitted from `merged_policy` rather than delivered incomplete. The SC never sees a `value_from` key or a value-less injection from this path.

`<SandboxEnvPlaceholder>`:

```json
{
  "name": "ANTHROPIC_API_KEY",
  "value": "umbra-proxy-injected"
}
```

Names MUST be valid POSIX env names. Values MUST be non-secret placeholders from the approved vocabulary in `docs/specs/console.md` §8.5; values matching real provider-secret patterns are invalid.

## 5. Data Plane: Proxy & Policy Enforcement

The core of the SC is an explicit intercepting proxy. mitmproxy listens on the SC's internal container network at `:8080`; it is reachable only from the SC proxy-tunnel shim and is **not** published externally. External Dev CVMs reach the proxy by opening an aTLS-verified TLS session to the SC's public `https://${SECURITY_CVM_FQDN}:443` endpoint, upgrading `GET /umbra/proxy`, and then sending HTTP CONNECT (or absolute-URL HTTP) inside that upgraded byte stream. The shim bridges those inner proxy bytes to mitmproxy per §3's routing table.

### 5.1 Dev CVM Authentication
Every outbound HTTP/HTTPS request from a Dev CVM MUST carry a `Proxy-Authorization: Bearer <Dev-CVM-PROXY_AUTH-token>` header. The bearer is injected by the Dev CVM's `dev-egress-forwarder` from the measured `proxy_token` compose config (`docs/specs/dev-cvm.md` §2.3, §4.5); the sandbox itself does not hold it.

1. **Extraction**: The SC extracts the token and computes `SHA-256(token)`.
2. **Lookup**: The SC searches its local Dev CVM map for a matching `proxy_token_hash`. The map is refreshed every ~5 s by the polling loop in §4.1; entries come from `GET /internal/sc-control/cvms` (`docs/specs/console.md` §4.3).
3. **Hit**: The connection is attributed to `cvm_id`. The SC MUST immediately **strip** the `Proxy-Authorization` header before forwarding the traffic upstream so the bearer never leaks to the destination.
4. **Miss — fail-closed (v0 behavior)**: If the hash is unknown, the SC MUST reject the connection with `407 Proxy Authentication Required` and log the rejection at `INFO` (cvm_id is unknown by definition; logging carries only the token-hash prefix for forensic correlation, never the plaintext token). The SC MUST NOT issue an out-of-band Console pull on miss in v0 — defer-and-resolve is a future revision (`docs/specs/console.md` §8.5 / §10.4). The Console's `cvm.launch` saga already waits for the SC's next pull at the `await_sc_pull` step before finalising the launch (`docs/specs/console.md` §8.3 step 7), so the user-visible window where a fresh Dev CVM hits `407` is bounded by the SC's polling cadence and the operation handle is not marked succeeded until propagation completes.

### 5.2 TLS Interception
For HTTPS traffic, the proxy dynamically generates leaf certificates signed by the boot-generated CA, completing the TLS handshake with the Dev CVM to inspect the plaintext payload. It then establishes its own upstream TLS connection to the target destination.

### 5.3 Policy Enforcement Logic
The proxy evaluates each request against the cached `merged_policy` in this exact order:

1. **Dev-CVM authentication**: authenticate `Proxy-Authorization`, resolve `cvm_id`, and strip the proxy bearer before any upstream forwarding (§5.1).
2. **Destination canonicalization**: extract `scheme`, `host`, `port`, `method`, and path. For HTTPS, the CONNECT target gates the tunnel and the decrypted HTTP request gates method/path-specific rules after TLS interception.
3. **Deny-list precedence**: if the destination matches any `blocked_destinations` entry, block immediately.
4. **Allow-list gate with body assertions**: evaluate all `allowed_destinations` whose destination predicate matches the request. If any destination-matching rule has `body_assertions`, the SC allows the request only when at least one destination-matching body-assertion rule passes; if none pass, block with `body_assertion_failed` and do not fall through to broader rules without body assertions. If no destination-matching rule has body assertions, allow the first destination-matching rule. A rule with `host: "*"` is the reusable "open internet" profile primitive, still bounded by scheme, port, method, path, DLP, secret injection, and traffic logging, but it cannot widen a co-matching body-scoped endpoint. If no rule matches, block. An empty effective `allowed_destinations` list denies all; the Console's profile merge can create this deliberately with an `egress_boundary: true` profile that has no allow rules.
5. **Secret scanning (DLP) on sandbox-supplied data**:
   * For allowed requests, scan the HTTP headers and body as received from the sandbox, after `Proxy-Authorization` stripping and before any real credential is injected.
   * DLP, body assertions, and `traffic_log_attributes` MUST inspect the `Content-Encoding`-DECODED request body, never the on-wire bytes; otherwise a sandbox can hide a secret behind `Content-Encoding: gzip` and slip it past DLP. A declared content-coding the SC cannot decode (an unsupported codec such as `br`/`zstd`, or a body that does not actually decompress) fails closed — the request is rejected, not forwarded with an unscanned body. The SC MUST decode ALL members of a multi-member stream (gzip MAY concatenate members per RFC 1952 §2.2; conformant servers decode them all), or a secret in a later member is forwarded unscanned. Decoding is bounded to the scan limit so a compression bomb cannot exhaust SC memory; if the decoded body would exceed the limit the SC fails closed (rejects) rather than forwarding a body it could only partially scan.
   * DLP MUST also account for the body's declared `Content-Type` charset: a secret in a non-utf-8 charset (e.g. `utf-16`, which interleaves NUL bytes) MUST NOT evade a utf-8-only scan; the SC scans the charset-appropriate decoding(s) and fails closed on a declared charset it cannot decode.
   * Scan up to a bounded streaming limit, e.g. `10 MiB`, using `secret_patterns`.
   * Scanning MUST strictly timeout, e.g. 50 ms per request, to prevent ReDoS.
   * If a match is found, abort the request. The matched secret MUST NEVER be echoed in the response or logs.
6. **Secret injection**: apply matching `secret_injections`; if the request matches an `unfulfilled_secret_injections` marker whose header is not otherwise supplied by a fulfilled injection, block fail-closed with `secret_injection_unfulfilled` (§5.4).
7. **Forward**: establish the upstream connection and stream the response. On allow, extract `traffic_log_attributes` from the matched rule (§4.3) against the sandbox-supplied body and record them on the outgoing `<TrafficLogIn>` (§6.1).

For HTTPS CONNECT specifically, the SC MUST handle the initial mitmproxy CONNECT hook before any decrypted HTTP request exists. That hook authenticates and strips `Proxy-Authorization`, canonicalizes only `scheme=https`, `host`, and `port`, and applies the destination gate. It records the authenticated `cvm_id` on the mitmproxy flow so later decrypted HTTP requests on the same CONNECT tunnel are evaluated as that CVM even though they do not carry `Proxy-Authorization` themselves. It does not run DLP or inject headers; those happen on the later decrypted HTTP request. Allowed CONNECTs emit an immediate tunnel traffic log with `method="CONNECT"`, `response_code=200`, and empty `attributes` so opaque or failed handshakes are still visible. Rejected CONNECTs still fail closed and emit the rejection traffic log when a `cvm_id` is known.

DLP MUST run before secret injection. Running DLP after injection would cause the SC to detect and block credentials it injected itself; that ordering is forbidden.

Blocked authenticated requests return `403 Forbidden` with a plaintext body whose first line starts with `Umbra network restriction:` and states that the request was blocked by the profile policy assigned to this Dev CVM. The body MUST also make clear that this is an Umbra policy decision, not a network or upstream server failure. Responses MUST include `Proxy-Status: umbra-security-cvm; error=<reason>`, `X-Umbra-Blocked: true`, `X-Umbra-Block-Source: profile`, `X-Umbra-Block-Reason: <reason>`, `X-Umbra-CVM-ID: <cvm_id>`, and `X-Umbra-Policy-Version: <policy_version>`. Proxy authentication failures still return `407 Proxy Authentication Required` and MUST NOT claim a profile-policy block because no Dev CVM identity has been authenticated.

### 5.4 Proxy-Time Secret Injection

Secret injection supplies credentials to approved outbound HTTP(S) requests without giving those credentials to the Dev Sandbox.

The v0 mechanism is intentionally narrow:

- The only supported injection type is `request_header`.
- The SC sets or overwrites a request header on a matching decrypted HTTP request after §5.3 steps 1-5 pass.
- Matching uses `secret_injections[*].match` with the same destination semantics as allow/deny rules.
- Header names are canonicalized to lower-case for matching. The SC MUST reject policies that attempt to inject hop-by-hop or proxy/control headers: `host`, `connection`, `content-length`, `transfer-encoding`, `proxy-authorization`, `proxy-authenticate`, `te`, `trailer`, `upgrade`.
- If the sandbox supplied the same header, the SC scans the sandbox-supplied value during DLP and then overwrites it. This is what lets SDKs send placeholder values such as `ANTHROPIC_API_KEY=umbra-proxy-injected` while still preventing a real leaked key from being silently replaced and forwarded.
- If multiple matching injections would write the same header with different rendered values, the SC MUST block the request fail-closed with `403 Forbidden` and log `policy_secret_injection_conflict` without any secret value. The Console is expected to prevent this state before it reaches the SC (§8.5).
- If a request matches an `unfulfilled_secret_injections` marker (§4.3) whose `header` is **not** otherwise supplied by a fulfilled `secret_injections` entry on the same request, the SC MUST block the request fail-closed with `403 Forbidden` and log `secret_injection_unfulfilled`, naming only the marker's injection id (never any secret value). This is the runtime face of a `value_from` grant that became unusable (§8.5): the request is blocked at the point of failure — with the standard `X-Umbra-Block-Reason` response header (§5.3) and a traffic-log decision row (§6.1) — instead of the sandbox placeholder credential reaching the upstream as an opaque auth error. A fulfilled injection for the same header (e.g. contributed by another attached profile) suppresses the block, keeping the profile merge additive (adding a profile can add a credential, never a new block). The block is per-destination: egress to destinations the marker does not match is unaffected.
- The rendered header value is `value_template` with `${secret}` replaced by `value`. The SC MUST NOT log the rendered value, the raw `value`, or the template-expanded header at any level.
- Traffic logs MAY record `injection_ids` or `injection_count` in a future schema, but v0 `TrafficLogIn` MUST NOT include secret values or rendered headers.

Limitations:

- The SC does not inject query parameters, cookies, request bodies, client certificates, SSH credentials, git credential-helper entries, or environment variables.
- The SC does not compute request signatures. AWS SigV4, GCP signed requests, Azure Shared Key, and any protocol where authentication requires hashing or signing the request body on the client side are out of scope for v0 proxy injection.
- The SC does not make non-HTTP protocols credential-aware. It may tunnel them only when destination policy allows the tunnel and no HTTP-layer injection is required.

### 5.5 Inbound WebSocket Frame Filtering

WebSocket connections reach upstreams as an HTTP `GET` upgrade inside an already-authenticated CONNECT tunnel; the tunnel itself is gated by the allow/deny destination rules of §5.3. After the upgrade, mitmproxy reassembles each WebSocket message (permessage-deflate is already decompressed) and the SC evaluates each inbound frame against the `websocket_assertions` (§4.3) of **all** `allowed_destinations` rules whose tunnel predicate (`scheme`, `host`, `port`) matches the connection, using the cross-rule UNION composition defined in §4.3.

- The SC evaluates only inbound frames (server → sandbox). Frames sent by the sandbox and frames the SC itself injected (acks) are never re-filtered. Control frames (ping/pong/close) are not subject to filtering.
- The connection's `cvm_id` is the identity recorded on the CONNECT tunnel in §5.3; the inbound frame carries no `Proxy-Authorization` of its own. When mitmproxy represents the inner WebSocket `GET` as a separate flow, the SC MUST persist the resolved `cvm_id` onto that flow before the first frame is processed. A connection-key cache MAY be used to associate the upgrade flow with the authenticated CONNECT, but cache TTL cleanup MUST NOT make an active WebSocket stream age out of filtering. If a flow was governed by `websocket_assertions` at upgrade time and its `cvm_id` or current tunnel policy can no longer be resolved, or the current policy no longer allows the tunnel, the SC MUST drop inbound data frames instead of delivering them.
- The SC parses the frame once and gathers every assertion across all matching rules (§4.3). If no matching rule carries `websocket_assertions`, and the flow was not previously governed, the connection delivers inbound frames unchanged. Otherwise malformed, oversized, non-text-data, and unselected frames fail closed: the SC drops the frame (it is never forwarded to the sandbox) and emits one contents-free `websocket_frame_blocked` traffic log (§4.3, §6.1). When the frame is selected by at least one assertion but **no** selecting assertion's `require` passes, the SC drops it, optionally injects the rendered `on_drop_emit` ack (from the first selecting assertion) toward the server, and emits the same contents-free traffic log. Frames delivered by the UNION and control-opcode-exempt frames pass through untouched and are not logged per-frame; a delivered lifecycle-exempt frame is forwarded untouched but emits one contents-free `websocket_frame_blocked` traffic log so the bounded telemetry channel is auditable. A host-granting rule without assertions never widens another rule's allow-list.
- This primitive is inbound-only in v0. Filtering of WebSocket frames sent *by* the sandbox (`direction: "outbound"`) and content-level filtering of HTTP response bodies (e.g. paging/enumeration limits) are reserved sibling primitives and are out of scope for this revision (§9).

## 6. Traffic Log Ingestion

The SC is the sole source of truth for Dev CVM network activity. It observes all data-plane events and securely ships them to the Console.

### 6.1 Log Generation
For **every** authenticated outbound request and CONNECT tunnel decision (allowed, blocked by domain policy, or blocked by secret scanner), the proxy generates a `<TrafficLogIn>` record containing: `timestamp`, `cvm_id` (securely resolved from the bearer hash), `source_ip`, `destination_ip`, `destination_host`, `protocol`, `port`, `method`, `path`, `response_code`, `decision`, `bytes_transferred`, and `attributes`.
* The `path` MUST be truncated to 2000 characters.
* Query parameters and payload bodies MUST NOT be included to minimize accidental PII leakage.
* `attributes` is a string-to-string map of `0..4` entries populated only on the allow path by the matched rule's `traffic_log_attributes` (§4.3). Names match `[a-z_]{1,32}`; values are truncated to 256 chars. Denied or DLP-blocked requests MUST emit `attributes = {}`. The Console MUST reject batches whose `<TrafficLogIn>` violates these caps.
* `decision` is the enforcement outcome for the record: `allowed`, a block reason (e.g. `secret_injection_unfulfilled`, `dlp_secret_detected`, `blocked_destination`, `body_assertion_failed`, `policy_secret_injection_conflict`), or `websocket_frame_dropped`. It mirrors the `X-Umbra-Block-Reason` header (§5.3) so a blocked request is diagnosable from the logs by reason without reproducing it. The Console persists it (`docs/specs/console.md` §7.21) and ignores traffic fields it does not yet model, so a newer SC never breaks ingest on an older Console.
* A dropped inbound WebSocket frame (§5.5) emits one record in this same schema with `method="GET"`, the WebSocket request `path`, `response_code=null`, `decision="websocket_frame_dropped"`, `bytes_transferred=0`, and `attributes = {}`. It MUST NOT include any frame contents.

### 6.2 Batching and Shipping
The SC maintains an internal memory buffer of traffic observations.
* **Flush Trigger**: The buffer MUST be flushed to the Console every **1.0 second**, or when the buffer reaches **1,000 entries**, or when the payload approaches **4 MiB**, whichever comes first.
* **Transport**: `POST <CONSOLE_URL>/internal/traffic-logs`.
* **Auth**: `Authorization: Bearer <CONSOLE_INGEST_TOKEN>`.
* **Idempotency**: The SC MUST generate a fresh UUID v4 random value encoded as **32 lowercase hex characters** (no hyphens) as the `idempotency_key` of each batch attempt (Console Spec T-10).

### 6.3 Resilience & Drop Logic
On `429 Rate Limited`, `502`, or `503`, the SC MUST retry the batch with the *same* `idempotency_key`, applying exponential backoff within a single flush attempt (bounded retry count). If the batch remains pending after a failed attempt, the emitter retries on the next flush cycle after the configured flush interval (default **1.0 s**).

If the in-memory queue exceeds a safe bound (e.g., 50MB / 50,000 logs) due to prolonged Console downtime, the SC MUST drop the oldest logs (ring buffer) to prevent an Out-Of-Memory (OOM) crash. The SC MAY also discard a batch that receives a non-retryable HTTP error (e.g. `400`) so a poisoned payload cannot block the queue indefinitely. Drop events MUST be logged locally as `ERROR`.

## 7. Security Properties & Invariants

Implementations MUST uphold the following properties. Violations are spec bugs.

1. **Principle of Least Privilege**: The SC evaluates egress but NEVER authors policy. Even if a Dev CVM manages to exploit the proxy engine, the attacker cannot alter policies because the SC pulls them read-only from the Console. Furthermore, the `INGEST_TOKEN` is scoped to its own entity, preventing cross-tenant data access (Console Spec T-5).
2. **CA Ephemerality**: The `mitmproxy` CA private key MUST exist only in `tmpfs` and process memory. It is generated at boot and destroyed on termination.
3. **No Plaintext Logging**: The SC MUST NOT log the `Proxy-Authorization` plaintexts, the `CONSOLE_INGEST_TOKEN`, the `CA_EXPORT_TOKEN`, injected secret values, rendered injection headers, or any detected secrets to its own stdout/stderr.
4. **Token Hygiene**: The SC MUST remove `CONSOLE_INGEST_TOKEN` and `CA_EXPORT_TOKEN` from the process environment after reading them at boot (`env.pop`). Injected-secret plaintexts live only in the current in-memory policy snapshot and MUST NOT be logged. Full memory zeroization of Python strings is best-effort; the contract is no durable storage and no logging of these values.
5. **Redirect Tamper Detection**: Because `CONSOLE_URL` is measured into the RTMR at boot, any infrastructure-level attempt to hijack log emission to an attacker's server will alter the RTMR3 digest, instantly tripping the Console's reconciler drift detection (Console Spec T-11/T-30).

## 8. Implementation Stack

To fulfill the requirements while minimizing architectural complexity, the SC relies on the following stack:

- **Language:** Python 3.12 only (`>=3.12,<3.13`), matching the Console compatibility contract. Contributor, CI, and release environments use the exact repository `.python-version` patch, matching the digest-pinned runtime image.
- **Proxy Engine:** `mitmproxy` via `mitmdump` subprocess; the SC addon runs asyncio loops for control-plane polling and traffic-log shipping alongside mitmproxy hooks. It natively handles transparent TLS interception, ALPN, and streaming HTTP inspection.
- **Attestation & TLS Sidecar:** `shade` (a Rust-based sidecar bundling `nginx`, `cert-manager`, and `atlas-rs` attestation hooks).
- **HTTP Client:** `httpx` for asynchronous Console polling and log shipping.
- **Regex Engine:** `re2` (via Python bindings) for linear-time secret scanning to guarantee protection against ReDoS attacks caused by poorly authored policy patterns.

### 8.1 Reproducible Image Publication

Security CVM image verification and publication MUST use the shared `umbra-release` builder: BuildKit 0.32.2 pinned by image digest, exporter compatibility version 30, the digest-pinned Dockerfile 1.26.0 frontend, and the exact Buildx 0.34.0 client. The source commit timestamp is passed as `SOURCE_DATE_EPOCH`, every exporter rewrites timestamps, and every release attempt performs two cache-disabled linux/amd64 builds from independent detached worktrees at that commit. Their runnable runtime-manifest digests MUST match. Each local result index MUST independently pass runtime-label, subject-binding, SPDX, and max-mode SLSA validation. Result-index digests are not compared because BuildKit provenance carries a unique invocation ID and wall-clock start/finish times.

After the two local runtime subjects match, publication MUST perform one tagless push-by-digest registry build and MUST NOT create or rely on a source-commit tag. The remotely-read immutable index, runtime labels, subject-bound attestation manifest, and parsed SPDX/SLSA predicates MUST match the reviewed build inputs, and its runtime MUST equal both local subjects. The helper returns only the runnable `repository@sha256:<runtime-manifest>` reference beneath the attestation index, and deployment MUST use that digest reference.

## 9. Out of Scope

The following capabilities are excluded from the v0 SC specification:

- **High Availability / Scaling**: The architecture mandates exactly one live SC per entity. HA pairs and horizontal load balancing are deferred.
- **Hitless SC Upgrades**: v0 supports provider in-place SC updates through the Console's `security_cvm.update` saga. A CA-preserving aTLS policy change can be recovered by a refresh-capable Umbra Dev CVM forwarder after one local verification failure. When the SC CA changes, compatible Dev CVMs follow it at runtime (next bullet) rather than requiring a full `cvm.update`; egress may fail closed for a brief window until the rotated CA propagates, and already-running processes that cached the trust bundle (e.g. Node) need a restart. Graceful connection draining, legacy-runtime replacement, and zero-blip propagation are deferred.
- **Transparent CA Rotation to Dev CVMs**: The SC still cannot push a new mitmproxy CA directly into running Dev CVMs. In current Umbra images, the runtime CA-refresh path (`docs/specs/dev-cvm.md` §4.5) lets the Dev CVM forwarder *pull* the rotated CA from the RTMR3-bound Console (`GET /internal/dev-control/security-cvm-ca`) and publish it with a forwarder-owned sidecar binding the FQDN, current digest, and immutable launch-CA digest; the sandbox `umbra-ca-refresh` watcher verifies that pair and re-installs it into the trust bundle (replace-not-append). A valid same-launch persisted rotation wins over immutable launch material on ordinary service restart, so restart cannot briefly re-trust an older CA; malformed or partial persisted state stays fail-closed for authenticated repair. SC CA rotation therefore does not require a full `cvm.update` for a compatible sandbox trust binding. A full `cvm.update` rebind is still required for current deployments when the launch-bound SC FQDN, the per-CVM bearers, or the RTMR3 binding changes; a retained pair from an old FQDN or launch baseline is not reused under the new binding. Persisted legacy rebind markers remain fail-closed replacement signals handled through the pre-Umbra control plane.
- **Defer-and-resolve on bearer cache miss**: §5.1's v0 behavior is fail-closed (`407 Proxy Authentication Required`). A future revision MAY add an immediate out-of-band Console pull on miss to close the ~5 s window after a fresh Dev CVM launch.
- **Dynamic SSH Key Revocation**: Managing SSH key access on Dev CVMs via the SC is a post-v0 feature.
- **Request-signature injection**: AWS SigV4, GCP signed requests, Azure Shared Key, and similar body-signing schemes are not supported by v0 proxy injection (§5.4).
- **Outbound WebSocket and HTTP response-body filtering**: `websocket_assertions` (§4.3, §5.5) are inbound-only in v0. Filtering of WebSocket frames sent by the sandbox (`direction: "outbound"`) and declarative filtering of HTTP response bodies — e.g. capping enumeration or paging in an allowed response — are reserved sibling primitives that reuse the same JSON-pointer matcher engine. They are deferred; the schema reserves `direction` so an outbound mode can be added without a breaking change.
