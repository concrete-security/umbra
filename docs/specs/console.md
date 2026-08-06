# Umbra Console Backend Specification

This document is the authoritative specification for the Umbra Console backend. It defines the HTTP API surface (user-facing and internal), the data model, authentication and authorization, the resource lifecycle of the things the Console manages, integrations with external systems, and the operational, security, and disaster-recovery properties an implementation must uphold. Implementations MUST conform to this spec; conformance is verified per §19.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, and OPTIONAL in this document are used in the RFC 2119 / RFC 8174 sense.

## 1. Overview

The Console is the central control plane of the Umbra platform. It owns every piece of persistent state about the platform — entities, users, profiles, SSH keys, Dev and Security CVMs, audit logs, and traffic logs — and is the only component that talks to the database. It exposes a single ASGI app with two routers: `/api/v1` for user-facing calls (§3) and `/internal` for service-to-service calls (§4).

The Console plays three roles, each with its own contract:

- **OAuth2 Authorization Server / OIDC Relying Party.** Authenticates human users against an upstream OIDC provider (Google in v0) and issues its own JWTs to clients (§5).
- **CVM control plane.** Drives the lifecycle of Dev and Security CVMs through the Phala / dstack driver and provisions DNS through Cloudflare (§8, §10).
- **Audit and traffic sink.** Writes a tamper-evident audit row for every state-changing call (§11) and accepts batched traffic logs from Security CVMs at `/internal/traffic-logs` (§4).

### 1.1 Primary clients

- The [`umbra` CLI](cli.md), which makes every `/api/v1` call on behalf of a human user.
- The static admin dashboard, which uses the same authenticated `/api/v1` and `/api/v1/admin/*` APIs for tenant-admin and platform-operator inspection and control.
- Security CVMs, which call `/internal/traffic-logs` over the public internet to ship logs.
- Platform operators, who may use the CLI or admin dashboard; there is no DB-direct entry point apart from one-shot bootstrap (§12.3).

> [!NOTE] The Security CVM is currently accessible over the public internet because we don't own the infra and can't make it private.

### 1.2 Actors

Every authenticated call into the Console is attributed to exactly one actor of one of the classes below. Authorization rules in §6 reference these classes by name. Actors not on this list MUST NOT be able to make any call that returns 2xx.

| Actor class | Authentication | Identity | Privileges |
|---|---|---|---|
| `anonymous` | none | (none) | `POST /auth/device/start`, `POST /auth/device/poll`, `POST /auth/logout`, `GET /healthz`, `GET /readyz` only. |
| `user` | Console JWT (§5) | `user_id`, `entity_id` | The implicit grants in §6.5 plus any explicitly granted permission. |
| `tenant_admin` | Console JWT with one or more entity-scoped permissions | `user_id`, `entity_id`, granted permissions | One or more of `USER_MANAGE`, `PERMISSION_MANAGE`, `QUOTA_MANAGE`, `CVM_LAUNCH`, `CVM_MANAGE`, `SECURITY_CVM_CONFIGURE`, `AUDIT_VIEW`, `AUDIT_EXPORT`, `TRAFFIC_LOGS_VIEW`. Each is per-entity. |
| `platform_operator` | Console JWT with `PLATFORM_OPERATOR` | `user_id` | Cross-entity routes under `/api/v1/admin/*`. |
| `service_principal` | Service-principal credential (§4.2) | `principal_type`, `principal_id`, optional `purpose` | `/internal` routes scoped to the principal's class and purpose. Cannot impersonate any user. Today: `security_cvm` with `purpose ∈ {INGEST, CA_EXPORT}` (Console-issued, Console-verified); `dev_cvm` with `purpose=PROXY_AUTH` (Console-issued, SC-verified — the Console hashes the bearer and serves it via `/internal/sc-control/cvms`, §4.3); and `dev_cvm` with `purpose=DEV_CONTROL` (Console-issued, Console-verified for Dev CVM control-plane reads only). |
| `system:reconciler` | (none — internal Python invocation) | `actor_email = "reconciler@umbra.invalid"` | Writes audit rows via the system actor; never serves an HTTP request. The address uses the reserved `.invalid` namespace and is never routable. |
| `system:bootstrap` | OS user running `python -m umbra_console.bootstrap` with `UMBRA_ALLOW_BOOTSTRAP=1` | `actor_email = "system@bootstrap"` | Direct DB writes; not reachable over HTTP. |

### 1.3 Assets

Listed in roughly decreasing sensitivity. Later sections reference each asset by these labels.

- **A1. JWT signing key material.** Compromise enables forgery of any user identity (§5.2, §12.2, §17.2).
- **A2. OIDC client secret.** Compromise enables impersonation of the Console as RP at the IdP (§12).
- **A3. Audit-log integrity.** Tamper compromises forensic and compliance posture (§11).
- **A4. Service-principal bearers** (Security CVM `INGEST`, `CA_EXPORT`; Dev CVM `PROXY_AUTH`, `DEV_CONTROL`). Compromise of an SC bearer allows traffic-log forgery or CA exfiltration (§5.7, §4.2). Compromise of a Dev CVM's `PROXY_AUTH` bearer lets the holder proxy through the SC as that Dev CVM (subject to its merged policy) and have traffic logged under its `cvm_id` (§10.4); the blast radius is bounded by that single CVM's policy. Compromise of a Dev CVM's `DEV_CONTROL` bearer lets the holder read that CVM's attached SC policy-refresh candidate only; the SC does not accept it for proxy traffic.
- **A5. Personally-identifiable information** in `users.email`, `oauth_identities.email`, `audit_events.actor_email`, and audit `before` / `after` payloads. Subject to GDPR / CCPA (§11.9).
- **A6. External-integration credentials** (`PHALA_API_TOKEN`, `CLOUDFLARE_API_TOKEN`, `DSTACK_DOCKER_PASSWORD`) (§12).
- **A7. Traffic-log corpus.** Corporate-sensitive metadata about Dev CVM egress (§7.21).
- **A8. Tenant isolation.** No tenant may read or write another tenant's resources, audit, or traffic (§6, §14.7).
- **A9. Tenant-resource availability.** A misbehaving tenant must not deny service to another tenant (§2.6, §13.2).
- **A10. Account integrity.** No identity may be silently re-bound to a different OIDC subject (§5.6).

### 1.4 Threat model

The threats below are the load-bearing security claims of this spec. Every property in §14 is a mitigation to one or more `T-N`. An implementer MUST be able to point at the section that mitigates each `T-N` for their build.

| ID | Threat | Adversary | Mitigations |
|---|---|---|---|
| T-1 | Forge a JWT for any user. | Anyone with read access to A1. | §5.2 (asymmetric signing + `kid` rotation), §12.2 (file-mounted keys), §15.5 (DB role separation). |
| T-2 | Replay a captured Console JWT after revocation. | Holder of a leaked JWT. | §5.2 (`jti` denylist), §5.4 (polling-secret binding), §5.8 (strict header parse). |
| T-3 | Authenticate as another user via OIDC re-bind. | Compromised Google account previously linked to a Console user, or IdP-side `sub` reissue. | §5.6 (immutable `subject_id`, explicit re-link). |
| T-4 | Cross-tenant read (audit, traffic, profiles, CVMs). | Authenticated `user` or `tenant_admin` of tenant A targeting tenant B. | §6 entity scoping, §6.4 existence-non-leak, §14.7 data-layer rejection. |
| T-5 | Cross-tenant write via internal API. | Compromised Security CVM in tenant A. | §4.3 mode-1 cross-tenant rejection, §4.4 isolation guarantees. |
| T-6 | Audit-trail forgery or tampering. | Anyone with `INSERT`, `UPDATE`, or `DELETE` on `audit_events`, including a compromised Console application role. | §11.6 (hash-chained rows + external anchor), §15.5 (role separation, append-only privileges). |
| T-7 | Denial of service via amplification. | Anonymous internet, or any authenticated client. | §2.6 rate limits, §2.7 payload caps, §4.3 batch caps. |
| T-8 | Existence enumeration of cross-tenant resources by UUID. | Authenticated `user` or `tenant_admin`. | §6.4 existence-non-leak rule. |
| T-9 | Side-channel leak of registered emails. | Authenticated `tenant_admin`. | §7.3 email-domain ↔ entity-domain match: a tenant admin can only register emails whose domain is their entity's, so probing `POST /entities/{id}/users` for `409` cannot enumerate emails in other entities (their email domain wouldn't be accepted at all — `422 VALIDATION_ERROR`). §3.3 uniform response. |
| T-10 | Replay a captured `/internal` ingest body. | Network observer or compromised Security CVM. | §4.3 timestamp window + per-batch `idempotency_key` deduplication. |
| T-11 | Redirect Security CVM log shipping or CA distribution to an attacker-controlled endpoint. | Phala API compromise or post-deploy env mutation injecting a hostile `CONSOLE_URL`. | The SC's TEE attestation RTMR-extends `CONSOLE_URL` at boot (§10.4); the Console's reconciler re-attests every `RECONCILER_ATTESTATION_INTERVAL_SECONDS` and detects any divergent URL via RTMR3 mismatch. The CLI's per-tunnel atlas-rs verification ([CLI spec](cli.md) §6.1, §10.4 of this spec) re-checks before any user-facing artefact is trusted. **Residual exposure**: between an attacker's redirect and the next reconciler probe, the SC ships logs to whichever URL is in env; the operator trades off log-leak window against attestation-refresh load by tuning the interval. The spec explicitly does NOT pin Console TLS at the SC — the operational rotation cost was disproportionate to the marginal protection over the attestation chain. |
| T-12 | JWKS cache poisoning. | Transient verification anomaly during a JWKS refresh (e.g. brief vendor-side cert rotation glitch, single-request error from the IdP). | §5.5 5-minute JWKS cache with single-flight force-refresh on `kid` miss bounds the impact of any one bad refresh. CA-MITM against the IdP itself is a state-level threat covered by §1.5 "compromised IdP" (out of scope: the Console verifies the `id_token`'s signature against the IdP's published key set but cannot detect a coordinated CA + IdP-side compromise). |
| T-13 | Forced swap of the installed `phala` CLI tree at `PHALA_CLI_PATH`. | Anyone with write access to the Console env or filesystem. | §10.1 tarball-digest pinning at boot, §12.2 read-only image mount. |
| T-14 | Privilege escalation via puppet user. | `tenant_admin` with `USER_MANAGE` but not `PERMISSION_MANAGE`. | §6.2 H5 rule on `POST /entities/{id}/users`. |
| T-15 | Permission downgrade race (in-flight request post-revoke). | Adversary holding a still-valid JWT after their grants are revoked. | §5.3 per-request DB read; for compromise response, §5.2 `jti` revocation. |
| T-16 | Email-control squatter at bootstrap or re-registration. | Operator typos a domain at `--admin-email`, or someone outside the org acquires control of an email matching a previously-erased user's address before the legitimate person re-registers. | **Out of scope by policy** (§1.5): control of the email / IdP IS the user — same trust model as Slack, GitHub, Google Workspace. §12.3 catches the narrowest realistic mistake (`--admin-email` whose domain doesn't match `--domain`) with a structural check; everything beyond that is delegated to the operator's IdP and audit. |
| T-17 | Side-channel leak via `error_reason` text. | Authenticated `tenant_admin` reading own resources. | §10.5 `error_reason` is a typed code + template, not free-text. |
| T-18 | CSV-export weaponization (formula injection). | Authenticated `AUDIT_EXPORT` holder. | §11.5 leading-quote prefix, §6.2 `AUDIT_EXPORT` separate gating. |
| T-19 | Credential exfiltration via subprocess inheritance. | Compromised `phala` CLI install. | §10.1 env allowlist (paired with T-13 tarball pin). |
| T-20 | OIDC `id_token` substitution / algorithm confusion. | Network MITM or compromised IdP. | §5.5 `RS256`-only, JWKS pinning, `email_verified` enforcement, `at_hash` enforcement. |
| T-21 | Bulk audit-history exfiltration. | `AUDIT_VIEW` holder probing for incidents. | §6.2 separate `AUDIT_EXPORT`, §2.6 per-permission rate limits. |
| T-22 | Trust-on-first-use poisoning of Phala response. | Compromised Phala API or upstream MITM. | §10.1 strict regex on `app_id` and `gateway_host`. |
| T-23 | Open redirect via `/auth/authorize` `redirect_uri`. | Attacker who can lure a user to a crafted authorize URL (e.g. phishing). | §3.1 strict regex pin on `redirect_uri` (`^http://127\.0\.0\.1:[0-9]{1,5}/callback$`); §12 `OIDC_CLIENT_ALLOWLIST`; §5.4.1 sanitised HTML error pages with no caller-controlled content. |
| T-24 | Authorization-code interception on the loopback redirect. | A second listener on the user's machine racing the legitimate CLI to the loopback port. | §5.4.1 PKCE binding (`code_verifier` ↔ `code_challenge`); single-use `console_authz_code` deletion at `/auth/token`. |
| T-25 | Privilege escalation via profile attachment. | `tenant_admin` with `CVM_MANAGE` attaching a permissive profile to a Dev CVM that previously did not have it, expanding the CVM's reach. | §3.6 attach is gated on `CVM_MANAGE` AND the **CVM owner's** profile membership (`profile_users`) — an admin cannot attach a profile the owner is not entitled to, and cannot use their own membership on someone else's CVM; §11.2 `CVM_PROFILE_ATTACHED` audits every attach; merge semantics in §8 are field-typed (allow-lists union) so attaching is observable in the resulting policy. |
| T-26 | Shared-Security-CVM compromise blast radius. | Compromise of an entity's Security CVM affects every Dev CVM in that entity. | §8.4 entity-scoped Security CVM is a known shared-trust point (§1.6); §17.3 incident response (decommission + re-provision) restores; the Security CVM is an enforcer, not an authoring authority — combined policies are computed Console-side and pushed (§8.5), so a compromised Security CVM cannot author broader rules than the Console produced. |
| T-27 | JWT algorithm confusion / key injection via header. | Network attacker who exfiltrates a Console verifying public key from disk, KMS, backup, or memory (the Console does NOT publish a JWKS endpoint in v1, but the keys exist in deployment artefacts and on host filesystems); also a malicious caller crafting a token with attacker-controlled `jku`, `jwk`, `x5u`, or `x5c` headers. | §5.2 rejects every caller-supplied key-source header (`jku`, `jwk`, `x5u`, `x5c`) before signature verification; per-`kid` algorithm pinning ensures the verifier never tries the public RSA key as an HMAC secret; signature verification uses the algorithm registered for the `kid`, not the algorithm declared in the token header. |
| T-28 | Cross-token confusion. | Attacker presents an inbound id_token (from Google) at a Console route, or vice versa; in a future revision, multiple JWT types coexist. | §5.2 mandates `typ: at+JWT` (RFC 9068) on Console-issued JWTs and refuses tokens whose `typ` is set to anything else. §5.5 verifies the upstream `id_token` against its own audience and at-hash binding, never accepting it as an inbound Console credential. |
| T-29 | SC image substitution. | Phala API compromise, rogue Phala operator, or a compromised SC build / registry pipeline pushes a hostile SC image, then claims it as the operator's intended image. | §10.4 verifies the SC with the complete Shade runtime policy: the row's shared dstack-guest MRTD baseline (`SECURITY_CVM_IMAGE_MEASUREMENT`, equal to `DEV_CVM_IMAGE_MEASUREMENT`), the authoritative `app_compose`, `expected_bootchain`, `os_image_hash`, and the RTMR replay. The app-image digest is pinned in `app_compose`; it is not encoded in a per-app MRTD. The Console refuses to issue `INGEST` / `CA_EXPORT` bearers on any mismatch, and the reconciler repeats the full check to detect drift. |
| T-30 | SC runtime configuration tampering. | Phala API or runtime env mutation changes `CONSOLE_URL`, `INGEST_TOKEN`, `CA_EXPORT_TOKEN`, the bound entity id, or any other deploy-time value the Console expected to bind to the SC. | §10.4 the SC, at startup inside the TEE, RTMR-extends the canonicalised concatenation of its runtime binding values before serving any traffic. The attestation report carries the RTMR digest and the SC's `report_data`. The Console at provisioning, and the CLI on `GET /entities/{id}/security-cvm/attestation` (§3.7), recompute the expected RTMR digest from the values the Console intended to inject and refuse if it diverges. |
| T-31 | Dev CVM image / compose substitution and runtime-config tampering. | Phala API compromise, rogue Phala operator, or compromised Dev CVM build / registry pipeline deploys a Dev CVM whose compose differs from the operator-curated topology (e.g. no internal-only network, exposed docker socket, no proxy sidecar, broader capabilities than the user-container should hold) or whose injected runtime values (proxy host, SC CA, authorised SSH keys) point at attacker-controlled infrastructure. | §10.4a verifies the Dev CVM against the complete Shade runtime policy. MRTD must equal the shared dstack-guest baseline in `cvms.expected_image_measurement`; the authoritative `app_compose` hash, `expected_bootchain`, and `os_image_hash` pin the approved app image and compose; RTMR3 binds the Console-injected values. A divergent image or compose therefore fails full runtime verification, not a per-app MRTD comparison. Drift detected by the reconciler emits `CVM_ATTESTATION_DRIFT` and pages the operator (§9.2). The user-container remains user-controlled by design (§1.6). |
| T-32 | Dev-CVM user (root inside their compose) bypasses the proxy sidecar to talk to the SC directly, with `PROXY_AUTH` extracted from the sidecar via kernel exploit, container escape, or sidecar RCE. | The legitimate user of a Dev CVM, who has root inside the CVM by design. | §10.4a / §14.10a the SC is the security boundary; it applies the per-Dev-CVM merged policy regardless of whether the request arrives via the sidecar or directly. `PROXY_AUTH` is per-Dev-CVM (one row in `service_principal_tokens` per `cvms.id`, §7.12); presenting it does not grant more capability than the Dev CVM's policy already permits. PROXY_AUTH leak to a third party reachable from outside the CVM is a residual concern bounded by per-CVM rate limits, optional rotation, and the SC's policy ceiling — leak does not escalate the Dev CVM's policy, only redistributes its usage. |
| T-33 | Credential impersonation via profile-membership self-assignment. | A `USER_MANAGE` holder self-assigns to a secret-bearing profile (§3.4 membership writes are an admin power with no owner concept) and launches a CVM on it, expecting the SC to inject **another user's** credential so upstream calls are attributed to the wrong human. | Per-user secrets (§2.3 `value_from`, §7.6b, §8.5): personal credentials are stored per user and resolved per **CVM owner** at materialization, so membership grants policy, never someone else's credential — a self-assigned admin gets their *own* secret injected or fails the launch preflight (§3.6). Owner-controlled `allowed_hosts` binding closes the retarget variant (an admin editing policy cannot aim the owner's secret at a different allowed host — §8.5 marks it unfulfilled and the SC fail-closes that destination without injecting). Values are write-only with no admin read path (§3.2, §7.6b), so an admin cannot copy a credential into a profile they control. **Residual:** binding is destination-*host* granular, not credential-*scope* granular — a coarse token bound to a broad host can still perform any action that token allows *at that host*. An admin who authors a profile a victim then launches (owner = launcher) can neither read the victim's credential nor route it off its bound hosts, but the victim's own workload, operating under the admin-authored egress rules, can exercise it within the binding; narrowing that is the profile's `body_assertions` (authored by the same admin) or finer secret binding (path/method — tracked follow-up). T-33 thus closes credential *disclosure* and cross-identity *impersonation*, not admin authorship of the egress rulebook (that is T-25's domain). Inline `value` injections remain entity-shared by design (service/bot credentials); tenants SHOULD author personal credentials as `value_from`. |

### 1.5 Out-of-scope adversaries

The Console explicitly does NOT defend against:

- **Postgres superuser** with direct write access to the database. The audit hash-chain (§11.6) is tamper-evident — a superuser can append, but cannot rewrite history without breaking the chain or the external anchor; defense ends there.
- **Host root** of the Console process. Anyone with `read` on `/proc/<pid>/environ` can read every secret in §1.3 today (§14.11). The spec mandates file-mounted secrets (§12.2) as mitigation, but a compromised host root remains unbounded.
- **Compromised IdP** (Google). The Console verifies the `id_token` (§5.5) but cannot detect a coordinated IdP-side identity takeover.
- **Anyone who controls the email / IdP account.** Whoever the IdP authenticates for `alice@example.com` IS Alice for the Console's purposes (§5.6). The org's IdP (Google Workspace, Okta, etc.) is the trust root for who controls a given address; the Console does not impose a second handshake. This is the same model used by Slack, GitHub, and the IdP itself. Future readers MUST NOT reintroduce console-side first-login challenges (e.g. "confirmation tokens") to defend against email-control changes — that's an IdP-side problem.
- **Compromised Cloudflare** at the API layer. The Console validates response shapes (§10.2) but cannot prevent a successful upstream from returning a misleading-but-syntactically-valid response.
- **Compromised Phala API** is partially in scope: §10.4's TEE attestation defends against image substitution and runtime-config tampering (T-29, T-30) at provisioning and on every reconciler probe, but the Console cannot prevent a hostile Phala from refusing to deploy SCs at all (a denial-of-service, T-7-class, mitigated only by alerting). The attestation chain depends on the TEE-vendor PCS / KDS being honest.
- **Compromised TEE-vendor signing infrastructure** (Intel PCS, AMD KDS). A vendor-signed attestation for an unmeasured image would break T-29/T-30. Mitigation is delegated to atlas-rs's built-in vendor-chain validation against the documented PCS / KDS roots; the spec does not impose an additional Console-side SPKI pinset on top.
- **Compromised SC build pipeline** (operator's CI, image registry, image-signing key). Producing a malicious SC image whose digest and full runtime policy are accepted as the operator-approved release is a supply-chain attack outside the Console's scope; mitigation is reproducible builds, digest-bound signing, and SLSA-style attestations. Matching the shared dstack-guest MRTD alone says nothing app-specific.
- **Long-term cryptanalytic break** of SHA-256, RS256, EdDSA, or the TEE attestation primitives. The spec mandates algorithmic agility (§16.10) but does not pre-emptively migrate.
- **Side-channel attacks against the host process** (Spectre-class, electromagnetic, RowHammer). Out of scope.

### 1.6 Trust boundary

The Console trusts:

- Its own database, accessed via a least-privilege application role (§15.5).
- Its JWT signing key material, sourced as described in §12.2.
- Its upstream IdP's certificate chain (standard public-CA validation, §5.5) and the JWKS served at the configured endpoint.
- The TEE-vendor PCS / KDS chain via atlas-rs's built-in trust store (no additional Console-side SPKI pinset; §10.4).
- Operator-supplied configuration values that are *not* secrets — the secrets path is file-mounted (§12.2).

The Console does NOT trust:

- Client request bodies, query parameters, or headers — every input is validated (§14.13).
- The `permissions` claim on a Console JWT for authorization (§5.3).
- Forwarded headers, unless `TRUST_FORWARDED_HEADERS=true` is paired with a sanitising reverse proxy (§13.8).
- Responses from external integrations — every field is regex- or schema-validated before use in URL construction or persistence (§10).
- Client-supplied `cvm_id` in `/internal/traffic-logs` payloads — every reference is principal-scoped (§4.3).
- A Security CVM's identity until its TEE attestation has passed full runtime verification against the row's shared guest measurement, authoritative app-compose policy, bootchain, OS-image hash, and expected RTMR3 digest (§10.4). Bearer issuance is gated on attestation success.
- The Phala gateway with TLS plaintext. Inbound TLS to every CVM (Dev or SC) terminates inside the CVM; Phala routes encrypted TCP only (§10.2, §10.4, §14.10). A compromised Phala can observe TCP metadata (SNI, source IPs, traffic patterns) but cannot read or modify TLS payload.

**Shared trust within an entity.** The Security CVM is provisioned per-entity (§8.4) and enforces the per-Dev-CVM combined policy (§8.5). Every Dev CVM in the entity routes through the same Security CVM; a compromise affects all of them (T-26). The Console mitigates by computing policies authoritatively on its own side and pushing them — the Security CVM enforces but does not author — and by gating Security CVM lifecycle on `SECURITY_CVM_CONFIGURE` plus the `PLATFORM_OPERATOR`-driven incident playbook (§17.3).

**Dev CVMs are user-controlled by design.** Inside a Dev CVM, the user has root over their own container and shares the CVM kernel with the proxy sidecar. The Console does NOT claim the inside of the Dev CVM is honest; it claims two things, both anchored in the same TEE attestation chain as the SC (§10.4a, T-31, T-32):

1. **The CVM that booted has the approved guest and application policy.** The shared dstack-guest `MRTD` is verified at launch and on every reconciler probe against `cvms.expected_image_measurement` (set from `DEV_CVM_IMAGE_MEASUREMENT`, §12). Full runtime verification separately checks the authoritative `app_compose`, bootchain, and OS-image fields, so a divergent application image or compose (no internal-only network, exposed docker socket, broader capabilities for the user-container, missing proxy sidecar) is refused even though the guest MRTD is common to Dev and Security CVMs.
2. **The runtime values the CVM is bound to are the Console's.** The proxy sidecar's destination, the SC CA, the authorised SSH keys, and the per-CVM `cvm_id` are RTMR3-extended at boot; post-boot Phala-side mutation cannot rewrite that digest.

The proxy sidecar inside a Dev CVM is UX and operator hygiene, not a security boundary. The actual egress boundary is the **SC's per-Dev-CVM policy enforcement**: even if the user reads `PROXY_AUTH` out of the sidecar (kernel exploit, container escape, sidecar RCE) and talks to the SC directly, the SC applies the same policy as it would for the legitimate sidecar path. A user attacking inside-the-CVM components cannot exceed the policy the Console has authored for that Dev CVM.

### 1.7 Non-goals

- No web UI. Every interactive flow goes through the CLI.
- No TLS termination on the Console listener. Deployments MUST front the Console with a TLS-terminating proxy (§13.8).
- No third-party telemetry. Audit and traffic logs are the only persistent observability outputs visible outside the deployment.
- No interactive admin recovery; lost admin credentials are recovered out of band (§17.5).
- No multi-region or multi-tenant runtime separation; one Console deployment serves one platform region.
- No self-service entity signup. Entities are provisioned out of band by a `platform_operator`.

## 2. Global API conventions

Conventions in this section apply to every route under `/api/v1` and `/internal` unless an individual route explicitly overrides them. The catalogs in §3 and §4 do not repeat them.

### 2.1 Base URLs and versioning

Two routers are mounted on the same ASGI app:

- `/api/v1` — user-facing. Every route requires a Console JWT (§5) unless explicitly marked `Auth: none`.
- `/internal` — service-to-service. Every route requires a service-principal credential (§4.2). A token minted for one router MUST be rejected at the other (§4.4).

**Compatibility within `/api/v1`.** Within a major prefix, the following are **breaking** and require a new prefix (`/api/v2`):

1. Removing a route, an HTTP method on a route, a request field, or a response field.
2. Renaming any of the above.
3. Tightening a request schema (narrower regex, lower max length, new required field, narrower enum).
4. Loosening a response invariant a client relies on (a field that was always present becoming optional; a field's value class widening).
5. Changing the meaning of an error `code` or its associated HTTP status.
6. Moving a route between `Auth: none` and `Auth: required`, or between two different permission requirements.

The following are **non-breaking** and do not require a new prefix:

1. Adding a new route.
2. Adding a new optional request field with a defined default.
3. Adding a new response field. (Clients MUST ignore unknown fields, §2.3.)
4. Adding a new error `code` with a status not previously documented as `INTERNAL` for that route.
5. Loosening a request schema (wider regex, higher max length, dropping a required field).

When a non-breaking change deprecates a field or route, the response MUST carry a `Deprecation: true` header (RFC 9745) and a `Sunset: <date>` header (RFC 8594) for at least three releases before removal in the next major.

### 2.2 Request and response format

Every request and response body is JSON, UTF-8 encoded. Routes that accept a body MUST require `Content-Type: application/json`; other content types MUST be rejected with `415 UNSUPPORTED_MEDIA_TYPE`. Field names use `snake_case` consistently.

Request bodies are validated by a schema at the boundary before any database call or external integration runs (§14.13). Unknown fields MUST be rejected with `422 VALIDATION_ERROR` (strict mode). Unknown response fields MUST be ignored by clients (forward compatibility for new servers).

Maximum request body size: `1 MiB` for `/api/v1`, `4 MiB` for `/internal/traffic-logs`. Larger bodies MUST be rejected with `413 PAYLOAD_TOO_LARGE`. Per-route caps on array lengths are stated in §3 / §4.

### 2.3 Resource representations

Every resource type listed below has a single canonical JSON shape. Routes in §3 reference them by name (`<User>`, `<CVM>`, etc.) rather than redefining the shape inline. Field types are JSON-typed; `<UUID>` is a hyphenated lowercase RFC-4122 string; `<Timestamp>` is an RFC 3339 UTC string with explicit `Z` suffix; `<EnumName.VARIANT>` denotes a string drawn from the named enum.

#### `<User>`

```
{
  "id":          <UUID>,
  "email":       <string, ≤ 320>,
  "name":        <string, ≤ 200>,
  "entity":      {"id": <UUID>, "name": <string, ≤ 200>},     # denormalised
  "permissions": [<Permission.SYMBOL>, ...],          # sorted lexicographically
  "profiles":    [{"id": <UUID>, "name": <string>}, ...],
  "state":       <"active"|"deactivated"|"erased">,
  "deactivated_at": <Timestamp|null>,
  "last_login_at": <Timestamp|null>,
  "created_at":  <Timestamp>,
  "deleted_at":  <Timestamp|null>
}
```

`entity` is denormalised on every read so the CLI's `auth status` (which reads from `session.json` without a network call, [CLI spec §3.1](cli.md)) can render the entity name. The `entity_id` field is no longer surfaced separately — clients use `entity.id`.

#### `<Entity>`

```
{
  "id":         <UUID>,
  "name":       <string, ≤ 200>,
  "domain":     <string, ≤ 255>,
  "created_at": <Timestamp>
}
```

#### `<Profile>`

```
{
  "id":                  <UUID>,
  "entity_id":           <UUID>,
  "name":                <string, ≤ 200>,
  "description":         <string, ≤ 1000>,
  "policy":              <object>,                                          # Security CVM policy DSL plus sandbox_env
  "assigned":            <bool>,                                            # caller is a member of profile_users
  "attached_cvms":       [{"id": <UUID>, "fqdn": <string>,
                           "state": <CVMState.VARIANT>}, ..., ≤ 100],
  "attached_cvm_count":  <int>,                                             # precise count; truncate above 100
  "created_at":          <Timestamp>,
  "updated_at":          <Timestamp>
}
```

The `policy` field carries the profile's Security CVM policy plus Dev CVM sandbox placeholders. Implementations MUST validate the active policy fields before persisting profile policy, reject unknown top-level keys, and round-trip the accepted JSON object byte-identically via `PATCH /profiles/{id}` (§3.4). The schema is:

```
"policy": {
  "egress_boundary": <bool>,                     # optional; true means this profile's allow-list is a boundary
  "allowed_destinations": [<DestinationRule>, ...],
  "blocked_destinations": [<DestinationRule>, ...],
  "secret_patterns": [<SecretPattern>, ...],
  "secret_injections": [<SecretInjection>, ...],
  "sandbox_env": {                                # optional; omit or {} for "no placeholders"
    "<NAME>": "<value>",
    ...
  }
}
```

`egress_boundary` is optional and MUST be boolean when present. If one or more attached profiles set `egress_boundary: true`, the Console builds the effective `allowed_destinations` only from those boundary profiles; non-boundary profiles may still contribute DLP, secret injection, and sandbox env, but they cannot widen destination reach. An air-gapped reusable profile is `egress_boundary: true` with an empty `allowed_destinations` list. `allowed_destinations`, `blocked_destinations`, `secret_patterns`, and `secret_injections` use the Security CVM DSL in `docs/specs/security-cvm.md` §4. Console validation MUST reject malformed destinations, ambiguous paths, forbidden body-assertion fields on deny or injection match rules, invalid injectable headers, `secret_patterns[*].pattern` values that `google-re2` cannot compile, and `websocket_assertions` whose `when` targets a connector lifecycle frame type (`/type` = `hello`/`disconnect`) — the Security CVM governs those frames solely by its lifecycle bound (§4.3 of the Security CVM spec), so such a guard is dead and rejected at authoring time. Destination `host` accepts the literal `"*"` as the open-internet wildcard described in the Security CVM spec.

**Secret injection value sources.** Each `secret_injections[*]` entry MUST carry exactly one value source (Console validation rejects both-or-neither with `422 VALIDATION_ERROR`, `details.errors[*].type="value_xor_value_from"`):

- **Inline `value`** — an entity-shared credential (service/bot token) supplied write-only in the policy document and stored encrypted per `(profile_id, injection_id)` in `profile_secret_material` (§7.6a). Policy replacement wipes stored material not re-supplied inline (§3.4).
- **`value_from: {"user_secret": "<name>"}`** — a per-user credential resolved at Security-CVM materialization time from the **CVM owner's** user secret of that `name` (§3.2, §7.6b, §8.5). `<name>` MUST match `^[A-Za-z0-9._:-]{1,100}$` and any other `value_from` shape is rejected (`details.errors[*].type="invalid_value_from"`). `value_from` is public, non-secret metadata: it is stored in `entity_profiles.policy`, returned on profile reads, and carries no material — replacing such a profile's policy wipes nothing. The injection's `match.scheme` MUST be `https` for the reference to resolve (§8.5). For `value_from` entries the `value_template` residual (the template minus `${secret}`) MUST be ≤ 4096 characters so every render of a maximal user-secret value (§3.2) stays within the Security CVM's 8192-character rendered cap.

`sandbox_env` is a map of POSIX environment-variable names to **non-secret** placeholder values that the Console renders into `SANDBOX_ENV_PLACEHOLDERS_B64` and Phala injects into the Dev CVM at deploy (`docs/specs/dev-cvm.md` §2.3, §7.1). Validation MUST enforce, on `POST /entities/{id}/profiles` and `PATCH /profiles/{id}`:

- **Names.** Match `^[A-Za-z_][A-Za-z0-9_]{0,127}$`. Reject anything else with `422 VALIDATION_ERROR`.
- **Values.** Length `≤ 1024`; no NUL bytes; no newline (`\n` or `\r`); UTF-8.
- **Map size.** `≤ 64` entries per profile.
- **Real-credential denylist.** Reject values that match any of the `SANDBOX_ENV_VALUE_DENYLIST` patterns (`SANDBOX_ENV_VALUE_DENYLIST` defaults in §12: Anthropic-shaped (`^sk-ant-[A-Za-z0-9_-]+$`), OpenAI-shaped (`^sk-[A-Za-z0-9]{32,}$`), GitHub-shaped (`^gh[pousr]_[A-Za-z0-9]{36,}$`), AWS-shaped (`^AKIA[0-9A-Z]{16}$`, `^ASIA[0-9A-Z]{16}$`)). The deployer-side entrypoint enforces the same denylist as defense-in-depth (`docs/specs/dev-cvm.md` §11).
- **Reserved names.** Reject names that collide with the Dev CVM's own env (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `PATH`, `HOME`, anything starting with `UMBRA_`, `SECURITY_CVM_`, `AUTHORIZED_SSH_`, `SANDBOX_ENV_`) with `422 VALIDATION_ERROR`.

`attached_cvms` is capped at 100 entries; if the profile is attached to more than 100 CVMs, callers paginate via `GET /cvms?profile_id=<id>` (§3.6) for the full list. `attached_cvm_count` is always exact.

#### `<ProfileMember>`

```
{
  "user_id":  <UUID>,
  "email":    <string, ≤ 320>,
  "added_at": <Timestamp>
}
```

#### `<SSHKey>`

```
{
  "id":          <UUID>,
  "label":       <string, 1..100>,
  "fingerprint": <string, ≤ 128>,
  "public_key":  <string, ≤ 20480>,
  "created_at":  <Timestamp>
}
```

#### `<UserSecret>`

```
{
  "name":          <string, 1..100, ^[A-Za-z0-9._:-]+$>,
  "allowed_hosts": [<string>, ..., 1..16],   # host-binding grammar: exact host | *.suffix | *
  "created_at":    <Timestamp>,
  "updated_at":    <Timestamp>
}
```

A user secret is a per-user, host-bound credential referenced by profile `secret_injections[*].value_from` (§2.3) and resolved per CVM owner at Security-CVM materialization (§8.5). Values are write-only: no read path — user-facing or admin — returns plaintext or ciphertext. `allowed_hosts` entries use the same grammar as `DestinationRule.host` (exact lowercase DNS name of ≥ 2 labels, `*.suffix` wildcard, or the literal `*` as an explicit opt-out of binding).

#### `<CVM>`

```
{
  "id":                          <UUID>,
  "owner":                       {"id": <UUID>, "email": <string>},
  "entity_id":                   <UUID>,
  "profiles":                    [{"id": <UUID>, "name": <string>}, ..., ≥ 1],
  "state":                       <CVMState.VARIANT>,
  "instance_type":               <string, ≤ 100>,
  "region":                      <string|null, ≤ 64>,
  "disk_size_gb":                <int>,                        # root disk size in GB; DEV_CVM_DEFAULT_DISK_GB when omitted at launch (§12)
  "ssh_keys":                    [{"id": <UUID>, "label": <string>}, ...],
  "fqdn":                        <string|null>,                # full DNS name; cvm-<26-base32>.<CLOUDFLARE_BASE_DOMAIN>
  "expected_image_measurement":  <string, 96-char hex|null>,   # captured at launch from DEV_CVM_IMAGE_MEASUREMENT (§10.4a)
  "image_measurement":           <string, 96-char hex|null>,   # TDX MRTD reported by attestation; equals expected when RUNNING
  "rtmr3_digest":                <string, 96-char hex|null>,   # RTMR3 reported at most-recent attestation
  "attestation_verified_at":     <Timestamp|null>,             # last successful attestation verification
  "error_reason":                <ErrorReason|null>,           # see §10.5
  "created_at":                  <Timestamp>,
  "updated_at":                  <Timestamp>
}
```

The `metadata` JSONB column on `cvms` (carrying Phala-side identifiers `app_id`, `gateway_host`) and the `compose_config` column are NOT surfaced in `<CVM>` reads — they are operator-internal state. A `tenant_admin` querying `GET /cvms/{id}` sees only the abstract shape; provider-specific identifiers are an implementation detail.

`owner.email` is denormalised at every read (the `users` row is joined on `cvms.owner_id`); a deactivated user keeps its real email visible here for audit-trail attribution; an erased user surfaces the tombstone email (`<erased-…>@<domain>`) per §7.3. `ssh_keys` is the set of SSH keys installed on the CVM at launch (§8.3); the entries are `{id, label}` only, never the public-key material — that lives on `<SSHKey>`.

`profiles` is the set of profiles currently attached to the CVM (§7.x `cvm_profiles`). At least one profile is always attached — `cvm.launch` requires a non-empty `profile_ids` (§8.3). `entity_id` is denormalised so consumers can filter without joining through `profiles[*]`.

#### `<PolicyBundle>`

Per-Dev-CVM trust bundle returned by `cvm.launch` / `cvm.update` (`Operation.result.policy_bundle`, §3.6) and re-fetchable via `GET /cvms/{cvm_id}/policy-bundle` (§3.6). The active bundle is stored on `cvms.atls_policy_bundle`; the CLI uses it to write the local aTLS policy file (`docs/specs/cli.md` §6.1, §3.4; `docs/specs/dev-cvm.md` §8.1) — the file the CLI evaluates against the running CVM's TDX quote at every tunnel.

```
{
  "cvm_id":                      <UUID>,
  "policy_template_version":     <string, ≤ 64>,             # informational policy-rendering version; never a mutable image tag
  "compose_template":            <string>,                    # same value as `app_compose.docker_compose_file`
  "app_compose":                 <object>,                    # readable copy of the full Shade/dstack `app_compose` object measured by dstack; `docker_compose_file` carries `${VAR}` placeholders only (actual runtime values flow through Phala's env-file at deploy and bind into RTMR3, §7.9, §10.4a)
  "app_compose_json":            <string>,                    # authoritative compact JSON serialization of `app_compose`; clients MUST use this string when present because JSONB object storage does not preserve Shade's hash-sensitive key order
  "expected_bootchain": {                                     # authoritative Shade/dstack guest boot policy; MRTD is the shared guest baseline
    "mrtd":                      <string, 96-char hex>,
    "rtmr0":                     <string, 96-char hex>,
    "rtmr1":                     <string, 96-char hex>,
    "rtmr2":                     <string, 96-char hex>
  },
  "os_image_hash":               <string, 64-char hex>,
  "rtmr3_binding": {                                          # JCS-canonicalized (RFC 8785) payload the Dev CVM extends into RTMR3 at boot, §10.4a. The CLI replays this to compute the expected RTMR3 digest at tunnel time.
    "cvm_id":                            <UUID>,
    "console_url":                       <string>,
    "security_cvm_fqdn":                 <string>,
    "security_cvm_proxy_port":           <integer>,
    "security_cvm_proxy_token_sha256":   <string, 64-char hex>,
    "dev_cvm_control_token_sha256":      <string, 64-char hex>,
    "security_cvm_ca_cert_sha256":       <string, 64-char hex>,
    "authorised_ssh_keys_sha256":        <string, 64-char hex>
  },
  "security_cvm_fqdn":           <string>,                    # the entity SC's stable DNS name (informational; also present inside rtmr3_binding)
  "issued_at":                   <Timestamp>
}
```

`compose_template` carries `${VAR}` placeholders, not resolved values — the bundle therefore does NOT disclose plaintext secrets. `rtmr3_binding.security_cvm_proxy_token_sha256` and `rtmr3_binding.dev_cvm_control_token_sha256` are SHA-256 hashes of per-CVM bearers; they cannot be reversed but act as confirmation oracles for guessed bearers, so the Console gates the read on CVM ownership (`cvms.owner_id == caller.user_id`) OR `CVM_MANAGE`. There is no first-read-only disclosure — the bundle is re-fetchable for the CVM's lifetime, because all bound values are immutable post-launch and re-fetching does not produce a fresh credential. See §3.6 for the route contract.

#### `<CVMLaunchResult>`

The shape of `Operation.result` for `op.kind == "cvm.launch"` after the saga reaches `succeeded` (§8.3 step 9). Returned to the polling caller via `GET /operations/{id}`.

```
{
  "cvm":           <CVM>,
  "policy_bundle": <PolicyBundle>
}
```

The `policy_bundle` field is materialised at finalise and is available on every subsequent read of the operation by an authorised caller. The bundle is also re-fetchable through `GET /cvms/{cvm_id}/policy-bundle` (§3.6), so first-read-only is unnecessary here. The CLI consumes this shape to write `${config_dir}/cvms/<cvm_id>.atls-policy.json` (`docs/specs/cli.md` §3.4).

#### `<SecurityCVM>`

Read-side shape returned by GETs and operation-status responses. NEVER carries plaintext bearers, the CA PEM, or docker credentials. The Security CVM is provisioned per-entity (§8.4) — at most one live `<SecurityCVM>` per entity at any time.

```
{
  "id":                          <UUID>,
  "entity_id":                   <UUID>,
  "state":                       <CVMState.VARIANT>,
  "fqdn":                        <string|null>,               # full DNS name; sc-<26-base32>.<SECURITY_CVM_BASE_DOMAIN>
  "instance_type":               <string, ≤ 100>,
  "region":                      <string|null, ≤ 64>,
  "error_reason":                <ErrorReason|null>,
  "policy_version":              <int>,                       # monotonic counter; bumped on every successful policy push (§8.5)
  "expected_image_measurement":  <string, 96-char hex|null>,  # shared dstack-guest MRTD captured at deploy time (§10.4)
  "image_measurement":           <string, 96-char hex|null>,  # TDX MRTD reported by attestation; equals expected when RUNNING
  "rtmr3_digest":                <string, 96-char hex|null>,  # RTMR3 reported at most-recent attestation
  "attestation_verified_at":     <Timestamp|null>,            # last successful attestation verification
  "created_at":                  <Timestamp>,
  "updated_at":                  <Timestamp>
}
```

Provider-specific identifiers (`metadata.app_id`, `metadata.gateway_host`) and `compose_config` are NOT surfaced in `<SecurityCVM>` reads — they are operator-internal state, same posture as `<CVM>`.

#### `<SecurityCVMProvisionResult>`

The one-shot, plaintext-bearing shape returned exactly once by the provisioning Operation's `result` field. The Console MUST NOT return this shape from any read route; it appears only as `Operation.result` for `op.kind == "security_cvm.provision"` (§8.2).

```
{
  "security_cvm":     <SecurityCVM>,
  "ca_export_token":  <string>                        # plaintext, captured-once (§5.7)
}
```

#### `<SecurityCVMAttestation>`

The operator-facing attestation summary returned by `GET /entities/{id}/security-cvm/attestation` (§3.7). Carries the Console's most recent verification verdict for diagnostic display.

```
{
  "security_cvm_id":             <UUID>,
  "fqdn":                        <string>,                    # the SC's stable DNS name
  "expected_image_measurement":  <string, 96-char hex>,       # the row's expected_image_measurement
  "verdict": {
    "verified":                  <bool>,
    "failure_reason":            <string|null>,                # one of the §10.5 attestation error codes when verified=false
    "image_measurement_seen":    <string, 96-char hex|null>,   # what attestation reported; matches expected when verified=true
    "rtmr3_digest_seen":         <string, 96-char hex|null>,
    "verified_at":               <Timestamp|null>
  }
}
```

#### `<AuditEvent>`

```
{
  "seq":           <integer>,
  "id":            <UUID>,
  "entity_id":     <UUID|null>,
  "timestamp":     <Timestamp>,
  "actor_id":      <UUID|null>,
  "actor_email":   <string|null>,
  "action":        <AuditAction.VARIANT>,
  "target_type":   <string, ≤ 50>,
  "target_id":     <string, ≤ 100>,
  "before":        <object|null>,
  "after":         <object|null>,
  "ip_address":    <string|null>,
  "description":   <string, ≤ 200>,
  "request_id":    <string|null>,
  "prev_hash":     <string, 64-char hex>,             # SHA-256 chain (§11.6)
  "row_hash":      <string, 64-char hex>
}
```

#### `<TrafficLog>`

```
{
  "id":                 <UUID>,
  "timestamp":          <Timestamp>,
  "security_cvm_id":    <UUID>,
  "cvm_id":             <UUID>,                       # non-null since the SC always knows it (§4.3)
  "source_ip":          <string, ≤ 45>,
  "destination_ip":     <string, ≤ 45>,
  "destination_host":   <string|null, ≤ 255>,
  "protocol":           <string, ≤ 20>,
  "port":               <int, 0..65535>,
  "method":             <string|null, ≤ 20>,
  "path":               <string|null, ≤ 2000>,
  "response_code":      <int|null>,
  "decision":           <string|null>,               # SC enforcement decision (§8.5, security-cvm §6.1); null for pre-column rows
  "bytes_transferred":  <int ≥ 0>,
  "attributes":         <map<string,string>>
}
```

#### `<EntityQuota>` and `<UserQuota>`

Returned by `GET /entities/{id}/quotas` (§3.13) and `GET /users/{id}/quotas` (§3.13).

```
<EntityQuota> {
  "entity_id":     <UUID>,
  "resource":      <"dev_cvms"|"ssh_keys"|"users"|"profiles"|"disk_gb_per_cvm"|"disk_gb_total">,
  "limit":         <int ≥ 0>,
  "source":        <"default"|"override">,           # "default" when no entity_quotas row exists
  "current_usage": <int ≥ 0>,
  "set_by":        <UUID|null>,                       # null when source="default"
  "set_at":        <Timestamp|null>
}

<UserQuota> {
  "user_id":       <UUID>,
  "resource":      <"dev_cvms"|"ssh_keys"|"disk_gb_per_cvm"|"disk_gb_total">,   # entity-only resources (users, profiles) excluded
  "limit":         <int ≥ 0>,
  "source":        <"default"|"entity_override"|"user_override">,
  "current_usage": <int ≥ 0>,
  "set_by":        <UUID|null>,
  "set_at":        <Timestamp|null>
}
```

#### `<Operation>`

The polled state of a long-running operation (§8.2). Same shape regardless of which resource the operation targets.

```
{
  "id":         <UUID>,
  "kind":       <string>,                             # e.g. "cvm.launch", "security_cvm.provision"
  "status":     "pending" | "running" | "succeeded" | "failed" | "cancelled",
  "actor_id":   <UUID|null>,
  "target":     {"type": <string>, "id": <UUID|null>},
  "result":     <kind-specific object|null>,         # populated when status == "succeeded"
  "error":      <Error|null>,                        # populated when status == "failed"
  "progress":   {"step": <string>, "percent": <int 0..100>}|null,
  "created_at": <Timestamp>,
  "updated_at": <Timestamp>,
  "expires_at": <Timestamp>                          # see §8.2 retention
}
```

#### `<ListPage<T>>`

The single response shape for every list route (§2.5).

```
{
  "items":       [<T>, ...],
  "next_cursor": <string|null>
}
```

#### `<Error>`

The body of every non-2xx response (§2.4).

### 2.4 Error envelope

Every non-2xx response MUST carry the following body:

```json
{
  "error": {
    "code":       "<SYMBOLIC_CODE>",
    "message":    "<human-readable description>",
    "details":    { ... },
    "request_id": "<string>"
  }
}
```

`code` is the machine-readable handle a client branches on, drawn from the table below. `message` is for human consumption; it MUST be in English, MUST NOT exceed 200 characters, and MUST NOT contain stack traces, internal paths, SQL fragments, or any secret (§14.12). `details` is a structured object whose schema is defined per `code` (the `details` schema for each code is part of the JSON Schema bundle in §19). Absent fields in `details` are equivalent to `{}`. `request_id` echoes §2.7.

| Status | Code | `details` schema | When |
|---|---|---|---|
| `400` | `BAD_REQUEST` | `{}` | Malformed request that is not a schema error (e.g. unparsable JSON). |
| `401` | `UNAUTHORIZED` | `{}` | Authentication is missing, malformed, expired, or has been revoked (§5.2). |
| `403` | `FORBIDDEN` | `{required: <string>}` | The caller is authenticated but lacks `required`. |
| `403` | `QUOTA_EXCEEDED` | `{resource: <string>, scope: <"user"\|"entity">, limit: <int>, current_usage: <int>}` | The action would create a row beyond the resolved quota (§3.13, §6.3 step 5). The caller can either ask an admin to raise the quota (per §6.2 `QUOTA_MANAGE` / `PLATFORM_OPERATOR`) or terminate / soft-delete an existing row to make room. |
| `404` | `NOT_FOUND` | `{}` | The resource does not exist *or* exists outside the caller's tenant (§6.4). |
| `409` | `CONFLICT` | `{state: <string>}` | The action would violate an invariant in the current state (e.g. `state="cvm_running_under_profile"`). |
| `409` | `IDEMPOTENCY_CONFLICT` | `{idempotency_key: <string>}` | Same `Idempotency-Key` was used with a different request body within the retention window (§2.6). |
| `412` | `PRECONDITION_FAILED` | `{etag: <string>}` | The supplied `If-Match` does not match the resource's current ETag (§2.8). |
| `413` | `PAYLOAD_TOO_LARGE` | `{limit_bytes: <int>}` | Request body exceeds the per-route cap. |
| `415` | `UNSUPPORTED_MEDIA_TYPE` | `{}` | `Content-Type` is not `application/json`. |
| `422` | `VALIDATION_ERROR` | `{errors: [{loc: [...], msg: <string>, type: <string>}, ...]}` | Request schema validation failed. |
| `428` | `PRECONDITION_REQUIRED` | `{etag: <string>}` | The route requires `If-Match`, but the request omitted it (§2.8). |
| `429` | `RATE_LIMITED` | `{retry_after_seconds: <int>, limit: <string>}` | Per-key, per-route, or per-IP rate limit hit (§2.6). |
| `500` | `INTERNAL` | `{}` | Unexpected server-side failure. |
| `502` | `UPSTREAM_ERROR` | `{adapter: <string>}` | An external integration (Phala, Cloudflare, IdP) returned an error or was unreachable. |
| `503` | `SERVICE_UNAVAILABLE` | `{component: <string>}` | The Console is up but a required dependency is not (Phala adapter not configured, DB not reachable). |

The set above is the complete `code` contract; extending it is governed by §2.1. Existing codes MUST NOT be reused with a different meaning.

`401` vs `403` vs `404` are distinguished by the §6 enforcement order: authentication is checked before permission, and permission failures collapse into `404` for resources the caller cannot see, so the API does not leak existence.

### 2.5 Pagination

Every list route MUST use cursor pagination with the following query parameters and response shape:

- **Query.** `limit` (int, 1 ≤ `limit` ≤ route-specific maximum, default `100`); `cursor` (opaque string, optional).
- **Response.** `<ListPage<T>>` (§2.3), i.e. `{items, next_cursor}`. `next_cursor` is non-null iff the server has more rows to return; clients pass it back as `cursor` to continue.
- **Ordering.** Defined per route in §3, but always deterministic over a `(timestamp DESC, id DESC)` keyset or equivalent so cursors are stable across calls.
- **Cursor lifetime.** `next_cursor` is valid for at least 24 hours from issuance. A cursor whose anchor has been deleted resumes from the closest still-valid row of the same ordering.

Unpaginated full-list responses are NOT permitted. Routes whose result set is bounded by permission scope (e.g. `GET /me/keys`) MUST still implement pagination; the practical case is that `next_cursor` is always `null`.

Per-route `limit` maxima:

| Route | Max `limit` |
|---|---|
| `GET /audit/events` | `500` |
| `GET /traffic-logs` | `1000` |
| `GET /traffic-logs/summary` | `200` (distinct hosts; bounded top-N aggregate, not a paginated list) |
| `GET /traffic-logs/timeseries` | `500` `buckets` (time buckets; bounded aggregate, not a paginated list) |
| Every other list route | `100` |

### 2.6 Idempotency and rate limits

#### Idempotency keys

Every `POST` that creates a new resource — `POST /entities`, `POST /me/keys`, `POST /entities/{id}/users`, `POST /entities/{id}/profiles`, `POST /cvms`, `POST /entities/{id}/security-cvm`, `POST /audit/export`, `POST /admin/sessions/revoke`, `POST /admin/keys/rotate` — MUST be sent with an `Idempotency-Key` request header. **A request to one of those routes that omits the header MUST be refused with `400 BAD_REQUEST` (`details.errors[*].type="missing_idempotency_key"`).** There is no silent-fallback path: clients that want at-most-once semantics on a creation route always send the header, and clients that don't are bugs.

- Header value: 1–128 ASCII characters from `[A-Za-z0-9._\-]`.
- Server stores `(idempotency_key, sha256(request_body), response_status, response_body, response_headers)` in `idempotency_keys` (§7.16) for 24 hours.
- A second request with the same key and the same body hash MUST return the previous response (status, body, headers required to faithfully replay) byte-for-byte. Side effects MUST NOT re-execute.
- A second request with the same key and a *different* body hash MUST return `409 IDEMPOTENCY_CONFLICT` (§2.4).
- Idempotency keys are scoped per-credential (the deduplication key is `(credential_id, idempotency_key, route)`, §7.16). One client's keys never collide with another's.
- **Concurrency.** Before performing the idempotency lookup, the route MUST acquire `pg_advisory_xact_lock` keyed on `(credential_id, idempotency_key, route)` and hold the lock for the duration of the request transaction. This serialises concurrent requests bearing the same key across the entire platform: a second request blocks at the lock until the first commits, then observes the now-existing `idempotency_keys` row and returns the cached response (or `409 IDEMPOTENCY_CONFLICT` on body-hash mismatch). The lock releases automatically on commit or rollback, so a crashed worker does not leave anything stuck. Without this lock, two simultaneous requests with the same key would both pass the lookup, both perform their side effects (insert duplicate aggregate rows, fire duplicate sagas), and only one would win the `idempotency_keys` UNIQUE — leaving an orphaned aggregate the cached replay would never surface. This advisory-lock pattern matches §11.1's audit-chain serialisation; the same `pg_advisory_xact_lock` primitive is used.

Routes whose semantics are *already* idempotent on a domain-level key — `POST /cvms/{id}/profiles` (keyed on `(cvm_id, profile_id)`); `POST /users/{id}/permissions` (resulting set is the key); `POST /cvms/{id}/actions/start|stop|terminate` (state-machine transitions are state-checked); `POST /admin/reconcile` (the reconciler converges); every `DELETE`; every `PATCH` — MAY accept `Idempotency-Key` but MUST NOT require it. The per-route table in §3 marks each as `optional` or `n/a`. When supplied, the server still applies the dedupe contract above; when omitted, the route's natural idempotency is the user's protection.

#### Rate limits

Every route MUST be governed by at least three rate-limit dimensions:

| Dimension | Key | Default budget | Override |
|---|---|---|---|
| Per IP | source IP after §13.8 resolution | `60 RPM` (anonymous routes), `600 RPM` (authenticated) | per-route in §3 |
| Per credential | `user.id` (Console JWT) or `service_principal.id` | `1200 RPM` | per-permission |
| Per route+credential | `(route, credential)` | route-specific | §3 |

Audit-export routes (§11.5) carry an additional dimension: per-credential `daily_export_count` capped at 10 by default.

A request that exceeds any dimension MUST receive `429 RATE_LIMITED` with `Retry-After: <seconds>` header and the `details.retry_after_seconds` body field. The Console MUST NOT count rate-limited requests as billable load against the dimension that triggered the limit.

### 2.7 Request IDs

Every request carries a `request_id` that the Console resolves as follows:

1. If the request includes an `X-Request-Id` header matching `[A-Za-z0-9._\-]{1,128}`, use that value verbatim.
2. Otherwise, the Console mints a fresh UUID v4.

The resolved value MUST be:

- Echoed back as the `X-Request-Id` response header on every response, success or failure.
- Bound into `structlog.contextvars` so every log line for the request includes `request_id` (§13.2).
- Included as `error.request_id` in every error envelope (§2.4).

### 2.8 Optimistic concurrency

Every resource that is mutable through the API surface MUST support `ETag` / `If-Match`:

- The server emits `ETag: "<weak ETag>"` on every `2xx` response that carries a single resource. The ETag value is `W/"<row.id>:<row.updated_at as epoch ms>"` (or equivalent that changes on every state-mutating commit).
- A `PATCH`, `PUT`, `DELETE`, or `POST */actions/*` request MAY carry `If-Match: "<etag>"`. If present, the server MUST verify the resource's current ETag matches before mutating; mismatch returns `412 PRECONDITION_FAILED`.
- A request without `If-Match` MUST proceed (last-writer-wins) — this is the spec's deliberate choice to avoid breaking the CLI, which does not yet send `If-Match`. Routes that MUST NOT permit last-writer-wins (e.g. permission grants, profile membership changes) are called out in §3 and reject mutations without `If-Match` with `428 PRECONDITION_REQUIRED`.

### 2.9 Identifiers and timestamps

- All resource ids are UUIDs (RFC 4122). URL path parameters MUST accept the canonical hyphenated lowercase form; other casings or formattings are rejected with `400 BAD_REQUEST`.
- All timestamps in JSON bodies are RFC 3339 in UTC with explicit `Z` suffix (e.g. `2026-04-28T14:30:00Z`). Local-zone offsets MUST NOT be emitted. Sub-second precision is permitted but not required; clients MUST tolerate up to nanosecond precision.

### 2.10 Security response headers

Every Console response (success or error, all routes including `/healthz`) MUST set:

| Header | Value |
|---|---|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` (set by the Console even though TLS terminates at the proxy, so a misconfigured proxy that forwards HTTP can still flag the policy). |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `Cache-Control` | `no-store` on every authenticated response; `public, max-age=60` on `GET /healthz` and `GET /readyz`. |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'` |
| `Cross-Origin-Resource-Policy` | `same-origin` |

CORS is not enabled (`Access-Control-Allow-Origin` is not emitted; preflight requests are answered with `403`). Browser-based clients are not part of this contract.

## 3. API catalog (`/api/v1`)

User-facing surface. Every route requires a Console JWT (§5) unless explicitly marked `Auth: anonymous`. Conventions in §2 — error envelope, idempotency, request id, ETag, security headers, rate limits — apply to every route and are not repeated.

Each entry lists:

- **Synopsis.** Method and path.
- **Auth.** `JWT` (any logged-in user) or `anonymous` (no token required).
- **Permission.** The symbolic name from §6, or `implicit` for routes available to any logged-in user.
- **Idempotency-Key.** `required` / `optional` / `n/a` (§2.6).
- **If-Match.** `required` / `optional` / `n/a` (§2.8).
- **Request body.** Schema if any.
- **Response body.** Resource reference from §2.3, with HTTP status.
- **Errors.** Route-specific failures and conditions. Generic codes (`401`, `415`, `422`, `429`, `500`) follow §2.4 and are not repeated.
- **Rate limit (additional).** Per-route limit beyond §2.6 defaults.
- **Side effects.** Audit row (§11), Operation enqueued (§8.2), external integration called (§10).

### 3.1 Authentication (`/api/v1/auth`)

These routes are `Auth: anonymous` because the caller does not yet hold a Console JWT. They implement two flows, matching [CLI spec §5.1](cli.md): OAuth 2.0 Authorization Code with PKCE and loopback redirect (§5.4.1) — the default; and the Device Authorization Grant, RFC 8628 (§5.4.2) — opted into via `--device`.

#### Loopback + PKCE (`/auth/authorize`, `/auth/oidc/callback`, `/auth/token`)

The Console acts as Authorization Server to the CLI and as Relying Party to the upstream IdP in the same flow. The browser-facing leg is `/auth/authorize` → IdP → `/auth/oidc/callback` → CLI's loopback; the CLI's machine-to-machine leg is `POST /auth/token`.

#### `GET /auth/authorize`

Begin the loopback flow. The CLI opens the user's browser to this URL.

- **Auth.** `anonymous`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Query parameters.** `client_id` (string, MUST be in `OIDC_CLIENT_ALLOWLIST`, §12); `redirect_uri` (string, MUST match `^http://127\.0\.0\.1:[0-9]{1,5}/callback$` exactly — no other host, no other path); `response_type` (MUST be `code`); `code_challenge` (string, 43..128 chars from RFC 7636 unreserved); `code_challenge_method` (MUST be `S256`); `state` (string, ≥ 32 chars); `scope` (MUST include `openid`).
- **Response.** `303 See Other` with `Location: <idp_authorize_url>?...` redirecting the browser to Google's authorize endpoint with `state=<idp_state>` and `nonce=<idp_nonce>` (Console-minted). Body is empty.
- **Errors.** `400 BAD_REQUEST` (`details.errors[*].type ∈ {"unknown_client_id", "invalid_redirect_uri", "invalid_response_type", "invalid_pkce", "invalid_state", "invalid_scope"}`). On any error the response is a sanitised HTML page (no JS, no caller-controlled content); the `details` shape applies to the equivalent `Accept: application/json` response so the CLI's loopback debug path can parse it.
- **Rate limit (additional).** Per IP `30 RPM`.
- **Side effects.** Inserts a row into `loopback_auth_pending` (§7.15) keyed on `state`. The row carries `code_challenge`, `redirect_uri`, `client_id`, `idp_state`, `idp_nonce`, and `expires_at = now + 10 minutes`.

#### `GET /auth/oidc/callback`

The redirect URI the Console hands the upstream IdP. Google redirects the user's browser here on consent.

- **Auth.** `anonymous`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Query parameters.** `code` (Google's authorization code); `state` (the `idp_state` we sent at `/authorize`).
- **Response.** `303 See Other` with `Location: <auth_pending.redirect_uri>?code=<console_authz_code>&state=<auth_pending.state>` redirecting the browser to the CLI's loopback. Body is empty.
- **Errors.** Sanitised HTML page (no JSON variant; the browser is the only consumer): unknown `state`, expired pending row, IdP token-exchange failure (§5.5), `id_token` verification failure (§5.5), failed §5.6 account resolution, OIDC re-bind refused (T-3 / §5.6 step 8). The pending row is deleted on any of these.
- **Rate limit (additional).** Per IP `30 RPM`.
- **Side effects.** Calls Google's token endpoint with the supplied `code`; verifies the `id_token` and the `nonce` claim against the stored `idp_nonce`; resolves the user (§5.6); mints a 256-bit `console_authz_code`; persists `SHA-256(console_authz_code)` and the resolved `user_id` on the pending row.

#### `POST /auth/token`

The CLI's machine-to-machine leg. Exchanges the `console_authz_code` for the JWT pair.

- **Auth.** `anonymous`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Request body.** `{"grant_type": "authorization_code", "code": <string>, "code_verifier": <string, 43..128>, "redirect_uri": <string>, "client_id": <string>}`.
- **Response body.** `200 {access_token, token_type: "Bearer", expires_in, refresh_token, refresh_expires_in}` (§5.2).
- **Errors.** `400 {"error": "invalid_grant"}` (RFC 6749 envelope, like the device flow's polling error shape — used so a CLI written against a generic OAuth library still parses the body) when the code is unknown, expired, already redeemed, or `code_verifier` does not match `code_challenge`. `400 {"error": "invalid_request"}` when `redirect_uri` or `client_id` does not match the values from `/authorize`.
- **Rate limit (additional).** Per IP `60 RPM`.
- **Side effects.** Atomically: deletes the `loopback_auth_pending` row (single-use), issues the JWT pair, writes `AUTH_SESSION_ISSUED`.

#### Device flow (`/auth/device/start`, `/auth/device/poll`)

Opt-in flow for environments without a usable browser; selected by `umbra auth login --device`.

#### `POST /auth/device/start`

Begin the device authorization flow.

- **Auth.** `anonymous`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Request body.** `{"provider": <string|null>}` (defaults to `google`).
- **Response body.** `200 {user_code, verification_url, verification_url_complete?, device_code, polling_secret, expires_in, interval}` (§5.4). `verification_url_complete` is present only when the IdP provides a complete verification URI; the Console MUST NOT infer one locally.
- **Errors.** `502 UPSTREAM_ERROR` if the IdP's device-code endpoint is unreachable.
- **Rate limit (additional).** Per IP `30 RPM`. The flow is anonymous; an unbounded budget would let an attacker probe the IdP at scale.
- **Side effects.** Inserts a row into the `device_flow_pending` table (§5.4).

#### `POST /auth/device/poll`

Poll for the result of an in-flight device authorization. Pending and `expired_token` / `access_denied` / `slow_down` responses deliberately follow RFC 8628 (`{"error": <reason>}` with HTTP `400`) and MUST NOT be reshaped into the §2.4 envelope; clients use the `error` value to decide whether to keep polling.

- **Auth.** `anonymous`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Request body.** `{"device_code": <string>, "polling_secret": <string>}`.
- **Response body.** On success: `200 {access_token, token_type: "Bearer", expires_in, refresh_token, refresh_expires_in}` (§5.2). On pending or non-fatal failure: `400 {"error": <"authorization_pending" | "expired_token" | "access_denied" | "slow_down">}`.
- **Errors.** `401 UNAUTHORIZED` (§2.4 envelope) if `polling_secret` does not match the value issued at `start` (§5.4 H2 binding). `403 FORBIDDEN` if the verified OIDC claim cannot be resolved to an active user (§5.6), including when the email domain has no entity, the entity's `users` quota is exhausted, or the matched user is deactivated. `502 UPSTREAM_ERROR` if the IdP token endpoint or the `id_token` verification (§5.5) fails.
- **Rate limit (additional).** Per IP `30 RPM`. Per-`(device_code)` MUST honor the IdP's `interval`; faster polls return `400 {"error": "slow_down"}`.
- **Side effects.** On success: inserts or refreshes the user's `oauth_identity` row (§5.6), issues the JWT pair (§5.2), writes an `AUTH_SESSION_ISSUED` audit row.

#### `POST /auth/refresh`

Exchange a valid refresh token for a fresh access-token pair. Single-use rotation (§5.2).

- **Auth.** `anonymous` (the refresh token is the credential). **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Request body.** `{"refresh_token": <string>}`.
- **Response body.** `200 {access_token, token_type: "Bearer", expires_in, refresh_token, refresh_expires_in}`. The supplied refresh token is revoked atomically with the issuance of the new pair.
- **Errors.** `401 UNAUTHORIZED` if the refresh token is unknown, expired, or already redeemed.
- **Rate limit (additional).** Per IP `60 RPM`.
- **Side effects.** Marks the supplied refresh token redeemed; inserts a fresh refresh-token row; writes an `AUTH_SESSION_REFRESHED` audit row.

#### `POST /auth/logout`

Revoke the caller's session. Server-side: the access-token's `jti` is added to the denylist (§5.2) and the matching refresh token (if presented) is revoked.

- **Auth.** `anonymous`. The route MUST process a valid Console JWT when supplied but MUST also accept a request without one (so a client with an expired token can still log out). **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Request body.** `{"refresh_token": <string|null>}` (optional).
- **Response body.** `204 No Content`.
- **Side effects.** Inserts `(jti, expires_at)` into `revoked_tokens` (§5.2). Soft-deletes any matching refresh-token row. Writes `AUTH_SESSION_REVOKED`.

### 3.2 Self (`/api/v1/me`, `/api/v1/me/keys`, `/api/v1/me/secrets`)

Routes scoped to the caller. They never require an entity- or profile-scoped permission.

#### `GET /me`

- **Auth.** `JWT`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `200 <User>`.

#### `GET /me/keys`

- **Auth.** `JWT`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `200 <ListPage<SSHKey>>`.

#### `POST /me/keys`

Register a new SSH public key for the caller.

- **Auth.** `JWT`. **Permission.** `implicit`. **Idempotency-Key.** `required`. **If-Match.** `n/a`.
- **Request body.** `{"label": <string, 1..100, no CR/LF/TAB>, "public_key": <string, 1..20480>}`.
- **Response body.** `201 <SSHKey>`.
- **Errors.** `403 QUOTA_EXCEEDED` if the caller's `ssh_keys` quota is exhausted (§3.13, §6.3 step 5). `422 VALIDATION_ERROR` on a malformed public key or out-of-bound size.
- **Side effects.** Audit row `SSH_KEY_ADDED`.

#### `DELETE /me/keys/{key_id}`

- **Auth.** `JWT`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `optional`.
- **Response body.** `204`.
- **Errors.** `404 NOT_FOUND` if the key does not exist or belongs to another user (§6.4).
- **Side effects.** Audit row `SSH_KEY_REMOVED`. The `ssh_keys` row is soft-deleted; the matching `cvm_ssh_keys` association rows are NOT touched.

**One-way revocation.** Soft-deleting an SSH key removes it from `umbra key list` and prevents future `cvm launch` calls from referencing it, but **does not remove the key from any Dev CVMs that already have it installed**. SSH key material is copied into the CVM's `authorized_keys` at launch (§8.3); there is no Console-driven mechanism to revoke a key from a running CVM. Operators who need to revoke key access on a live CVM MUST terminate the CVM and re-launch without the key in `--ssh-key`. A future revision MAY add a Security-CVM-mediated SSH-key revocation channel; until then, key removal is effective only for *new* CVMs.

#### `PUT /me/secrets/{name}`

Register or update (upsert) one of the caller's user secrets. Strictly self-service: there is no route for any caller — including `USER_MANAGE` or `PLATFORM_OPERATOR` — to write, read, or list another user's secrets. Secret values MUST travel only in the request body, never in the path or query string.

- **Auth.** `JWT`. **Permission.** `implicit`. **Idempotency-Key.** `n/a` (PUT upsert is naturally idempotent). **If-Match.** `n/a`.
- **Request body.** `{"value": <string, 1..4096, no CR/LF/NUL>, "allowed_hosts": [<host-binding pattern>, ..., 1..16, unique]}`.
- **Response body.** `200 <UserSecret>` — never echoes the value.
- **Errors.** `422 VALIDATION_ERROR` (`details.errors[*].type="invalid_name"`) if `{name}` fails `^[A-Za-z0-9._:-]{1,100}$`; `422 VALIDATION_ERROR` on a malformed value or `allowed_hosts`. `403 QUOTA_EXCEEDED` (`details.resource="user_secrets", details.scope="user", details.limit=64`) when creating a 65th distinct secret (updates to existing names always pass).
- **Side effects.** The value is AES-256-GCM envelope-encrypted (§7.6b) and upserted; audit row `USER_SECRET_SET` (`after` carries `name` and `allowed_hosts` only, never the value). A changed value reaches running CVMs through the Security CVM's next control pull (§8.5): the SC-control ETag is content-derived, so no policy-version bump is needed.

#### `GET /me/secrets`

- **Auth.** `JWT`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `200 <ListPage<UserSecret>>`, ordered by name (no pagination: the per-user cap is 64). Items never include the value or ciphertext.

#### `DELETE /me/secrets/{name}`

- **Auth.** `JWT`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `204`.
- **Errors.** `404 NOT_FOUND` if the caller has no secret of that name.
- **Side effects.** Hard-delete of the row; audit row `USER_SECRET_DELETED`. Running CVMs whose attached profiles reference the name lose the injection at the next SC control pull — the destination rules are untouched, so the SC fail-closes those requests with `secret_injection_unfulfilled` (§8.5) rather than letting them proceed uncredentialed to an opaque upstream failure. User erasure (§3.3 `DELETE /entities/{entity_id}/users/{user_id}`) hard-deletes all of the target's `user_secret_material` rows in the same transaction.

### 3.3 Entities (`/api/v1/entities`, `/api/v1/entities/{entity_id}`)

`POST /entities` is platform-scoped and gated by `PLATFORM_OPERATOR`. For every `/{entity_id}` route in this group, the caller MUST belong to `entity_id`; otherwise the route returns `404 NOT_FOUND` (§6.4 — the same response shape as a non-existent entity).

#### `GET /entities`

List tenant entities for platform operators.

- **Auth.** `JWT`. **Permission.** `PLATFORM_OPERATOR`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Query parameters.** `limit` (1..500, default 100), `cursor` (opaque).
- **Response body.** `200 <ListPage<Entity>>`, newest first.
- **Errors.** `403 FORBIDDEN` if the caller lacks `PLATFORM_OPERATOR`.

#### `POST /entities`

Create a tenant entity. This is the HTTP entity-onboarding path after bootstrap creates the first platform operator.

- **Auth.** `JWT`. **Permission.** `PLATFORM_OPERATOR`. **Idempotency-Key.** `required`. **If-Match.** `n/a`.
- **Request body.** `{"name": <1..200>, "domain": <1..255, lowercased server-side>}`.
- **Response body.** `201 <Entity>`.
- **Errors.** `409 CONFLICT` (`details.state="domain_taken"`) if `domain` is already registered. `422 VALIDATION_ERROR` for malformed fields.
- **Side effects.** Audit row `ENTITY_CREATED`.

#### `GET /entities/{entity_id}`

- **Auth.** `JWT`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `200 <Entity>`.

#### `GET /entities/{entity_id}/users?status=<STATUS>&assigned=<yes|no>`

- **Auth.** `JWT`. **Permission.** `USER_MANAGE`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Query parameters.** Both are optional typed `str` enums; an unknown value is rejected by the framework with `422 VALIDATION_ERROR` (standard envelope, no manual check needed). The base query already carries `u.deleted_at IS NULL`; the filters compose with AND.
  - `status` (`active | deactivated | erased`) — filters by account status, derived from `u.deactivated_at` / `u.deleted_at`:
    - omitted — keep the existing `u.deleted_at IS NULL` clause (all non-erased users). This is the current behavior, unchanged.
    - `active` — keep `u.deleted_at IS NULL` and add `u.deactivated_at IS NULL`.
    - `deactivated` — keep `u.deleted_at IS NULL` and add `u.deactivated_at IS NOT NULL`.
    - `erased` — **drop** `u.deleted_at IS NULL` and add `u.deleted_at IS NOT NULL`. The relaxation is mandatory: erase soft-deletes the row (sets `deleted_at`), so keeping the base clause would always return empty.
  - `assigned` (`yes | no`) — filters by whether the user belongs to at least one **live** profile. Membership joins `profile_users` to `entity_profiles` and excludes soft-deleted profiles (`ep.deleted_at IS NULL`), so the filter matches the displayed `profiles` subquery, which also drops soft-deleted profiles:
    - omitted — no membership predicate (any membership).
    - `yes` — add `EXISTS (SELECT 1 FROM profile_users pu JOIN entity_profiles ep ON ep.id = pu.profile_id WHERE pu.user_id = u.id AND ep.deleted_at IS NULL)`.
    - `no` — add `NOT EXISTS (...)` (users in no live profile).
  - Neither filter binds a value (all predicates are `IS [NOT] NULL` / `EXISTS`), so the clauses are AND-ed into the WHERE without `$N` placeholders.
- **Response body.** `200 <ListPage<User>>`. With no `status`, soft-deleted (erased) users are filtered out; `status=erased` returns exactly those.

#### `GET /entities/{entity_id}/users/{user_id}`

- **Auth.** `JWT`. **Permission.** `USER_MANAGE`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `200 <User>` plus `ETag` for read-modify-write flows that mutate the user's permission set (§3.5).
- **Errors.** `404` (§6.4). Soft-deleted users are invisible.

#### `POST /entities/{entity_id}/users`

Register a new user under `entity_id`. Permission grants at creation additionally require `PERMISSION_MANAGE` (T-14).

- **Auth.** `JWT`. **Permission.** `USER_MANAGE`. **Idempotency-Key.** `required`. **If-Match.** `n/a`.
- **Request body.** `{"email": <RFC-shaped, ≤ 254, lowercased server-side>, "name": <≤ 100, no CR/LF/TAB>, "permissions": <[<Permission.SYMBOL>], 0..32>}`.
- **Response body.** `201 <User>`.
- **Errors.** `403 FORBIDDEN` (`details.required="PERMISSION_MANAGE"`) if `permissions` is non-empty and the caller lacks it. `403 QUOTA_EXCEEDED` (`details.resource="users", details.scope="entity"`) if the entity's `users` quota is exhausted (§3.13, §6.3 step 5). `409 CONFLICT` (`details.state="email_taken"`) if the email is already registered. `422 VALIDATION_ERROR` (`details.errors[*].type="email_domain_mismatch"`) if `split(email, '@')[1] != entity.domain` (§7.3); since a `tenant_admin` for entity A can only invoke this route on entity A, this error is the structural T-9 defense — admins cannot submit emails whose domain belongs to another entity, so cross-entity probing is impossible.
- **Side effects.** `USER_REGISTERED` audit row, plus one `PERMISSION_GRANTED` per granted permission.

#### `POST /entities/{entity_id}/users/{user_id}/actions/deactivate`

Suspend a user. Reversible — the same account can be reactivated by `POST /actions/reactivate`. This is the routine offboarding path; for irreversible erasure see `DELETE` below.

- **Auth.** `JWT`. **Permission.** `USER_MANAGE`. **Idempotency-Key.** `n/a` (state-machine transition; the route is naturally idempotent on `(state, user_id)`). **If-Match.** `optional`.
- **Response body.** `200 <User>` with the user in `deactivated` state.
- **Errors.** `404` (§6.4). `409 CONFLICT` (`details.state="already_deactivated"`) if the user is already deactivated. `409 CONFLICT` (`details.state="already_erased"`) if the user has been erased (§3.3 DELETE) — erasure is terminal. Note: deactivation does NOT block on owned live CVMs (§8.1) — the user's resources stay running but they can no longer self-service them; an admin with `CVM_MANAGE` handles them.
- **Side effects.** `USER_DEACTIVATED` audit row. Same-transaction: `users.deactivated_at = now`, `users.deactivated_by = caller.id`, `refresh_tokens.revoked_at = now` for matching rows. Outstanding access tokens land in `revoked_tokens` via the paired `access_jti` (§7.14) so the next request fails before §5.3's permission reload runs. `oauth_identities`, `user_permissions`, `profile_users`, `ssh_keys`, and `cvms` rows are NOT touched — they sit untouched and return to operation on reactivation. Login is blocked by the explicit user-state check at §5.6 step 5, not by mutating the OAuth-identity binding (which would be a phantom-row-on-reactivation problem).

#### `POST /entities/{entity_id}/users/{user_id}/actions/reactivate`

Restore a deactivated user. The user can log in again on their next OIDC roundtrip; their permissions and profile memberships are picked up automatically because they were never removed.

- **Auth.** `JWT`. **Permission.** `USER_MANAGE`. **Idempotency-Key.** `n/a`. **If-Match.** `optional`.
- **Response body.** `200 <User>` with the user in `active` state.
- **Errors.** `404` (§6.4). `409 CONFLICT` (`details.state="not_deactivated"`) if the user is currently active. `409 CONFLICT` (`details.state="already_erased"`) if the user has been erased — erasure cannot be undone. `409 CONFLICT` (`details.state="email_taken"`, `details.live_user_id: <UUID>`) when the email's slot has been claimed by a fresh user during deactivation (this should be impossible per §7.3's partial unique, but the route MUST check defensively).
- **Side effects.** `USER_REACTIVATED` audit row. Same-transaction: `users.deactivated_at = NULL`, `users.deactivated_by = NULL`. OAuth identities were never touched at deactivation, so the next OIDC login goes through the normal "existing-link" path (§5.6 step 2 hit, skip to step 5; the user-active check now passes). Refresh tokens that were revoked stay revoked — the user logs in fresh and gets a new pair.

#### `DELETE /entities/{entity_id}/users/{user_id}`

**Erase** a user — irreversible PII anonymization plus hard-delete of identity-bearing dependents. This is the GDPR right-to-be-forgotten path. Two callers are authorized:

1. The user themselves (self-erase). The path `user_id` MUST equal `caller.user_id`. No additional approval required — the user is exercising their own data-subject right.
2. `PLATFORM_OPERATOR`, acting on an out-of-band entity-admin request (e.g. a written ticket or signed email from a tenant DPO). The operator's audit trail attribution is the human record; the spec does NOT expose an in-band "tenant admin proposes; operator confirms" workflow because the approval channel is intentionally external (it forces a human decision).

A tenant admin (`USER_MANAGE`) **cannot** erase users directly — they can only deactivate. Erasure escalates to the platform operator.

- **Auth.** `JWT`. **Permission.** Self (`caller.user_id == path.user_id`) OR `PLATFORM_OPERATOR`. **Idempotency-Key.** `required`. **If-Match.** `optional`.
- **Response body.** `204`.
- **Errors.** `403 FORBIDDEN` (`details.required="self_or_platform_operator"`) if neither condition is met. `404` (§6.4). `409 CONFLICT` (`details.state="user_owns_cvms"`, `details.live_cvm_count: <int>`, `details.live_cvm_ids: [<UUID>, ...]` truncated at 100) when the target owns one or more live Dev CVMs (§8.1). The user (or admin terminating on their behalf) MUST terminate the CVMs first; the spec does not auto-terminate.
- **Side effects.** `USER_ERASED` audit row, then the §11.9 redaction procedure runs in the same logical transaction:
  - `users` row tombstoned: `email = '<erased-' || encode(sha256(id::text), 'hex')[:12] || '>@' || entity.domain`, `name = '<erased>'`, `deleted_at = now`, `deleted_by = caller`. The row stays for FK integrity (e.g. terminated `cvms.owner_id` references it).
  - Hard-delete: `oauth_identities`, `ssh_keys`, `user_permissions`, `profile_users`, `refresh_tokens` for this `user_id`. CASCADE on the FKs handles the association tables.
  - Audit-trail redaction: `audit_events.actor_email` and `before/after.email` matching this user are replaced with the same tombstone format under the `umbra_console_redactor` role (§15.5). The hash chain is re-anchored from the redaction point forward (§11.9). Outstanding access tokens land in `revoked_tokens` via `access_jti` so any in-flight requests fail.

#### `GET /entities/{entity_id}/profiles?assigned=<yes|no>`

- **Auth.** `JWT`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Query parameters.**
  - `assigned` (optional, enum) — filters by whether the current user is a member of the profile. The parameter is a typed `str` enum (`yes | no`); an unknown value is rejected by the framework with `422 VALIDATION_ERROR` (standard envelope, no manual check needed). The query LEFT JOINs `profile_users` for the current user, exposing `pu.user_id` (NULL when not a member); each value adds a clause (composed with AND against the role-based visibility scope):
    - omitted — no membership predicate (every visible profile). This is the current behavior, unchanged.
    - `yes` — add `pu.user_id IS NOT NULL` (profiles the caller is a member of).
    - `no` — add `pu.user_id IS NULL` (profiles the caller is not a member of). For a non-`USER_MANAGE` caller this composes with the existing visibility scope (which already requires membership) to an empty page.
  - The clause carries no bind value (it is a pure `IS [NOT] NULL` predicate), so it is AND-ed into the WHERE without a `$N` placeholder.
- **Response body.** `200 <ListPage<Profile>>`. Filtering: `USER_MANAGE` callers see every profile in the entity; otherwise only profiles the caller is a member of.

#### `POST /entities/{entity_id}/profiles`

Create a new profile.

- **Auth.** `JWT`. **Permission.** `USER_MANAGE`. **Idempotency-Key.** `required`. **If-Match.** `n/a`.
- **Request body.** `{"name": <1..100, no CR/LF/TAB>, "description": <≤ 1000, no CR/LF/TAB>}`.
- **Response body.** `201 <Profile>` with `assigned: false`.
- **Errors.** `403 QUOTA_EXCEEDED` (`details.resource="profiles", details.scope="entity"`) if the entity's `profiles` quota is exhausted (§3.13, §6.3 step 5). `409 CONFLICT` if a profile with the same name exists in the entity.
- **Side effects.** `PROFILE_CREATED` audit row.

### 3.4 Profiles (`/api/v1/profiles/{profile_id}`)

Every route loads the profile, then verifies the caller's entity. A profile in another entity returns `404` (§6.4 — same shape as non-existent profile).

#### `GET /profiles/{profile_id}`

Read a single profile, including its policy and the list of attached Dev CVMs.

- **Auth.** `JWT`. **Permission.** `implicit` if the caller is a member of the profile (§7.7); else `USER_MANAGE`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `200 <Profile>` (§2.3) — includes `policy`, `attached_cvms` (capped at 100), `attached_cvm_count`.

#### `GET /profiles/{profile_id}/users`

List users assigned to a profile.

- **Auth.** `JWT`. **Permission.** `implicit` if the caller is a member of the profile (§7.7); else `USER_MANAGE`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `200 <ListPage<ProfileMember>>`.
- **Errors.** `404` (§6.4) if the profile does not exist, is in another entity, or the caller is neither assigned to the profile nor a `USER_MANAGE` holder.

#### `PATCH /profiles/{profile_id}`

Update profile fields. Partial-update semantics: any field that is present is updated; absent fields are unchanged. Updates to `policy` trigger policy push (§8.5) to the entity's Security CVM for every Dev CVM attached to this profile.

- **Auth.** `JWT`. **Permission.** `USER_MANAGE`. **Idempotency-Key.** `optional`. **If-Match.** `required`.
- **Request body.** `{"name": <string|null, ≤ 200>, "description": <string|null, ≤ 1000>, "policy": <object|null>}`. JSON Merge Patch (RFC 7396) semantics on the top level: `null` for `name` or `description` is invalid (use `""` for empty string); `null` for `policy` is invalid (use `{}` for empty policy).
- **Response body.** `200 <Profile>`.
- **Errors.** `404` (§6.4). `409 CONFLICT` (`details.state="profile_name_taken"`) if `name` is supplied and another live profile in the entity already uses it. `409 CONFLICT` (`details.state="sandbox_env_conflict"`, `details.name=<NAME>`, `details.profile_ids=[<UUID>, ...]`) if a `policy` update would introduce a `policy.sandbox_env` conflict on any attached live Dev CVM (§8.5). `422 VALIDATION_ERROR` if `policy` fails validation (§2.3 `<Profile>`: destination schema, secret pattern regex, secret injection schema, sandbox env name regex, value length, denylist, reserved-name collision).
- **Side effects.** `PROFILE_POLICY_UPDATED` audit row when `policy` changes (§11.2). For every Dev CVM with this profile attached, the Console-side merged-policy state is updated and the per-CVM `policy_version` is bumped. The entity's SC picks up the change on its next pull of `/internal/sc-control/cvms` (§4.3); no synchronous push is made (§8.5). The route does NOT block on SC-side acknowledgement — the SC's polling cadence (~5 s) is the convergence window. Secret-material effects differ by value source (§2.3): inline `value` material not re-supplied in the replacement document is **deleted** (write-only semantics, §7.6a), while `value_from` entries carry no profile-side material and are unaffected — a profile whose injections are all user-sourced can be edited freely without destroying credentials. The route does NOT validate `value_from` references against attached CVM owners; a reference an owner cannot satisfy degrades to materialization-time omission (§8.5).

#### `DELETE /profiles/{profile_id}`

Soft-delete a profile.

- **Auth.** `JWT`. **Permission.** `USER_MANAGE`. **Idempotency-Key.** `n/a`. **If-Match.** `required` (concurrent admin race protection).
- **Response body.** `204`.
- **Errors.** `404` (§6.4). `409 CONFLICT` (`details.state="cvms_attached"`, `details.attached_cvm_count: <int>`) if any live Dev CVM is attached. The operator MUST detach every CVM via `DELETE /cvms/{id}/profiles/{profile_id}` (§3.6) before retrying.
- **Side effects.** `PROFILE_DELETED` audit row.

#### `POST /profiles/{profile_id}/users`

Assign a user to a profile (membership = "permitted to attach this profile to a Dev CVM", §6, T-25).

- **Auth.** `JWT`. **Permission.** `USER_MANAGE`. **Idempotency-Key.** `optional`. **If-Match.** `required`.
- **Request body.** `{"user_id": <UUID>}`.
- **Response body.** `204`.
- **Errors.** `404` if either profile or user is not visible to the caller.
- **Side effects.** `PROFILE_USER_ASSIGNED` audit row.

#### `DELETE /profiles/{profile_id}/users/{user_id}`

- **Auth.** `JWT`. **Permission.** `USER_MANAGE`. **Idempotency-Key.** `n/a`. **If-Match.** `required`.
- **Response body.** `204`.
- **Side effects.** `PROFILE_USER_REMOVED` audit row. Removing membership does NOT detach CVMs the user previously attached this profile to — those attachments persist (the policy is property of the CVM, not of the user).

### 3.5 Permission management (`/api/v1/users/{user_id}/permissions`)

Granting and revoking permissions are gated on `PERMISSION_MANAGE`, deliberately split from `USER_MANAGE` (T-14, §6.2).

#### `POST /users/{user_id}/permissions`

Grant one or more permissions. Idempotent on the resulting set.

- **Auth.** `JWT`. **Permission.** `PERMISSION_MANAGE`. **Idempotency-Key.** `optional`. **If-Match.** `required`.
- **Request body.** `{"permissions": [<Permission.SYMBOL>, ..., 1..16]}`.
- **Response body.** `200 {user_id: <UUID>, permissions: [<Permission.SYMBOL>, ...]}` (resulting full set, sorted).
- **Errors.** `404` (§6.4). `422 VALIDATION_ERROR` for unknown permission names.
- **Side effects.** One `PERMISSION_GRANTED` audit row per *newly* granted permission. Already-held permissions are silent no-ops.

#### `DELETE /users/{user_id}/permissions/{permission}`

- **Auth.** `JWT`. **Permission.** `PERMISSION_MANAGE`. **Idempotency-Key.** `n/a`. **If-Match.** `required`.
- **Response body.** `204`.
- **Errors.** `404` (§6.4). `422 VALIDATION_ERROR` for unknown permission name.
- **Side effects.** `PERMISSION_REVOKED` audit row only if the permission was actually held.

### 3.6 Dev CVMs (`/api/v1/cvms`)

#### `GET /cvms?profile_id=<UUID>&state=<STATE>`

List Dev CVMs visible to the caller.

- **Auth.** `JWT`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Query parameters.**
  - `profile_id` (optional, UUID) — filters to CVMs that have the given profile attached (§7 `cvm_profiles`); cross-entity profile ids return an empty page.
  - `state` (optional, enum) — filters by lifecycle state. The parameter is a typed `str` enum (`alive | all | provisioning | running | stopped | failed | terminated`); an unknown value is rejected by the framework with `422 VALIDATION_ERROR` (standard envelope, no manual check needed). The base query already carries `c.deleted_at IS NULL`; each value adjusts it as follows (composed with AND against the role-based visibility scope and `profile_id`):
    - omitted or `alive` — keep the existing `c.deleted_at IS NULL` clause (returns the non-terminated states `provisioning|running|stopped|failed`). This is the current behavior, unchanged.
    - `all` — **drop** the `c.deleted_at IS NULL` clause so soft-deleted (terminated) rows are also returned; add no `state` predicate.
    - `terminated` — **drop** `c.deleted_at IS NULL` and add `c.state = 'TERMINATED'`. The relaxation is mandatory: terminate sets both `state='TERMINATED'` and `deleted_at=now()`, so keeping the clause would always return empty.
    - `provisioning` | `running` | `stopped` | `failed` — keep `c.deleted_at IS NULL` and add `c.state = $N`, binding the **upper-cased** state value as a query parameter (the flag value is lowercase, the `cvm_state` enum is uppercase; do not string-interpolate the value into the SQL).
- **Response body.** `200 <ListPage<CVM>>`. `CVM_MANAGE` broadens the result to every CVM in the entity; without it, only CVMs owned by the caller.

#### `POST /cvms`

Submit a Dev CVM launch. Async: returns an `<Operation>`; the caller polls `GET /operations/{id}` until `status` is `succeeded` or `failed` (§3.8).

- **Auth.** `JWT`. **Permission.** `CVM_LAUNCH`. **Idempotency-Key.** `required`. **If-Match.** `n/a`.
- **Request body.** `{"profile_ids": [<UUID>, ..., 1..16], "instance_type": <string|null, 1..64, [A-Za-z0-9._-]>, "ssh_key_ids": [<UUID>, ..., 1..16], "region": <string|null, ≤ 64, [A-Za-z0-9._-]>, "disk_size_gb": <int|null, 1..1048576>}`. At least one profile MUST be supplied (zero-profile launch is refused, §8.1). `instance_type` and `region` are both optional; when omitted, `instance_type` falls back to `DEV_CVM_DEFAULT_INSTANCE_TYPE` (§12) and `region` falls back to `DEV_CVM_DEFAULT_REGION`, then `PHALA_REGION`. If those server defaults are also empty, the route returns `422 VALIDATION_ERROR`. The resolved `instance_type` MUST belong to the instance-type catalog (§3.6a) — an unknown name returns the `unknown_instance_type` `422` described there. `disk_size_gb` is optional; when omitted it falls back to `DEV_CVM_DEFAULT_DISK_GB` (§12, matching the provider's own default). A supplied value MUST lie within `[DEV_CVM_MIN_DISK_GB, DEV_CVM_MAX_DISK_GB]` (§12) or the route returns `422 VALIDATION_ERROR` (`details.errors[*].{field: "disk_size_gb", type: "out_of_range", min, max}`); a misconfigured server default/bound returns `503 SERVICE_UNAVAILABLE`. The resolved value is persisted on `cvms.disk_size_gb` and passed to the provider deploy.
- **Response body.** `202 <Operation>` with `kind="cvm.launch"`, `status="pending"`, `target.type="cvm"`, `target.id` populated once the saga commits step 1. `Operation.result` on success is `<CVMLaunchResult>` (§2.3): `{cvm: <CVM>, policy_bundle: <PolicyBundle>}` — the `<CVM>` carries the `profiles` field populated from `cvm_profiles`, and the `<PolicyBundle>` carries the compose template, golden bootchain, and RTMR3-binding payload the CLI needs to write `${config_dir}/cvms/<cvm_id>.atls-policy.json` (`docs/specs/cli.md` §3.4, §6.1). The bundle is re-fetchable via `GET /cvms/{cvm_id}/policy-bundle` below (e.g. for `--no-wait` callers polling from a different machine).
- **Errors.** `404` if any profile in `profile_ids` is not visible (§6.4). `403 FORBIDDEN` (`details.required="profile_member"`, `details.profile_id: <UUID>`) if the caller is not a member of every profile in `profile_ids` (T-25). `403 QUOTA_EXCEEDED` if the caller's `dev_cvms` user quota OR the entity's `dev_cvms` quota is exhausted (§3.13, §6.3 step 5); the body's `details.scope` distinguishes which one fired. `403 QUOTA_EXCEEDED` if the requested (or default) disk size exceeds the `disk_gb_per_cvm` cap (`details.resource="disk_gb_per_cvm"`, `details.current_usage` = the requested GB), or if it would push the scope's summed live disk over the `disk_gb_total` budget for the user or entity (`details.resource="disk_gb_total"`, `details.scope` distinguishes which) (§3.13). `409 CONFLICT` (`details.state="no_security_cvm"`) if the entity has no live Security CVM (§8.1). `409 CONFLICT` (`details.state="sandbox_env_conflict"`, `details.name=<NAME>`, `details.profile_ids=[<UUID>, ...]`) if two or more of the requested profiles disagree on the value of a `policy.sandbox_env` key (§8.5 `sandbox_env` merge). `422 VALIDATION_ERROR` if `profile_ids` is empty. `422 VALIDATION_ERROR` if any requested profile carries a `value_from` reference (§2.3) the launcher cannot satisfy: `details.member="launcher"`, `details.user_id` = the launcher, and one `details.errors[*]` entry per failing reference — `{field: "policy.secret_injections", profile_id, injection_id, secret_name, type: "user_secret_missing" | "user_secret_scheme_not_https" | "user_secret_host_not_allowed"}` (host/scheme violations additionally carry `match_host` / `match_scheme`). The details never include secret values or the owner's `allowed_hosts`.
- **Side effects.** Inserts the `Operation`, the `cvms` row in `PROVISIONING` (with `compose_config` rendered inline and `expected_image_measurement` captured from `DEV_CVM_IMAGE_MEASUREMENT` at launch, §7.9), and one `cvm_profiles` row per attachment. Enqueues the launch saga (§8.3) — which writes Phala-side identifiers to `cvms.metadata`, the DNS record ids to `cvms.txt_dns_record_id` / `cvms.cname_dns_record_id`, the per-CVM proxy/control bearers to `service_principal_tokens` (§7.12), and the verified attestation values (`image_measurement`, `rtmr3_digest`, `attestation_verified_at`) at the `verify_attestation` step (§10.4a) before finalise. One `CVM_PROFILE_ATTACHED` audit row per profile is emitted by the saga's `succeeded` finaliser, alongside `CVM_LAUNCHED` and `CVM_ATTESTATION_VERIFIED`.

#### `GET /cvms/{cvm_id}`

- **Auth.** `JWT`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `200 <CVM>`. `CVM_MANAGE` callers see any CVM in their entity; otherwise only owned CVMs. `404` for CVMs the caller cannot see (§6.4).

#### `GET /cvms/{cvm_id}/policy-bundle`

Return the active per-Dev-CVM `<PolicyBundle>` (§2.3) the CLI uses to render the local aTLS policy file. Re-fetchable for the CVM's lifetime from `cvms.atls_policy_bundle`; a successful `cvm.update` replaces this bundle and bumps `cvms.atls_policy_revision`. Used by `umbra tunnel`'s lazy-fetch path when the per-CVM policy file is missing or stale (`docs/specs/cli.md` §6.1).

- **Auth.** `JWT`. **Permission.** `implicit` if the caller is the CVM's owner (`cvms.owner_id == caller.user_id`); else `CVM_MANAGE`. The route returns `404 NOT_FOUND` for CVMs the caller cannot see (§6.4). **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `200 <PolicyBundle>`. The bundle carries hashes (not plaintexts) of the per-CVM proxy/control bearers and SC CA; MUST NOT be cached by intermediaries (`Cache-Control: no-store`, already covered by §2.10).
- **Errors.** `404` (§6.4). `409 CONFLICT` (`details.state="cvm_terminated"`) if the CVM is `TERMINATED` — the bundle is meaningful only for live CVMs. `503 SERVICE_UNAVAILABLE` (`details.component="policy_bundle"`) if the active bundle has not yet been materialized.
- **Rate limit (additional).** Per CVM `30 RPM` (the legitimate use case is one fetch per tunnel-start on a fresh machine; 30 RPM gives headroom for retries without enabling a probing pattern).
- **Side effects.** Reads only. No audit rows (the bundle's content is not a mutation; `CVM_LAUNCHED` / `CVM_UPDATED` carry issuance context).

#### `POST /cvms/{cvm_id}/actions/update`

Update a Dev CVM deployment in place. Async: returns an `<Operation>`; the caller polls `GET /operations/{id}` until terminal.

- **Auth.** `JWT`. **Permission.** implicit if the caller is the CVM owner; otherwise `CVM_MANAGE`. **Idempotency-Key.** `optional`. **If-Match.** `optional`.
- **Request body.** Empty.
- **Response body.** `202 <Operation>` with `kind="cvm.update"`. `Operation.result` on success is `{cvm: <CVM>, policy_bundle: <PolicyBundle>}`. The CLI MUST rewrite `${config_dir}/cvms/<cvm_id>.atls-policy.json` from this returned bundle.
- **Errors.** `404` (§6.4). `409 CONFLICT` if the CVM is not `RUNNING`, `STOPPED`, or `FAILED`, if another operation is active for the CVM, or if the row lacks a provider `deployment_id` / legacy `app_id`. A persisted `error_reason="SECURITY_CVM_REBIND_REQUIRED"` returns `409 CONFLICT` with `details.state="legacy_cvm_replacement_required"` and `details.error_reason="SECURITY_CVM_REBIND_REQUIRED"`: the renamed Console cannot manage that preserved resource, so it must be terminated/decommissioned through the pre-Umbra control plane and replaced under Umbra.
- **Side effects.** For an accepted current-runtime update, re-renders the current Dev CVM compose/config, calls the CVM provider's update method for the existing deployment, mints a fresh `PROXY_AUTH` token with temporary old-token overlap, re-attests the updated CVM, waits for the Security CVM to pull the new token hash, persists `cvms.atls_policy_bundle` and bumps `cvms.atls_policy_revision`, and emits `CVM_UPDATED` or `CVM_UPDATE_FAILED`. The legacy replacement guard runs while the CVM row is locked and before inserting an operation, so rejected rows have no update side effects.

#### `POST /cvms/{cvm_id}/actions/start`
#### `POST /cvms/{cvm_id}/actions/stop`

Synchronous lifecycle actions; Phala start / stop is bounded (~5 s).

- **Auth.** `JWT`. **Permission.** implicit if the caller is the CVM owner; otherwise `CVM_MANAGE`. **Idempotency-Key.** `optional`. **If-Match.** `optional`.
- **Response body.** `200 <CVM>` reflecting the new `state`.
- **Errors.** `404` (§6.4). `409 CONFLICT` (`details.state=<current state>`) if the action is illegal in the current state (§8). `502 UPSTREAM_ERROR` if Phala fails.
- **Side effects.** `CVM_STARTED` / `CVM_STOPPED` audit row.

#### `POST /cvms/{cvm_id}/actions/terminate`

Terminate. Async: returns an `<Operation>`. Phala terminate plus DNS deprovision can take 30 s+, beyond reasonable HTTP client timeouts.

- **Auth.** `JWT`. **Permission.** implicit if the caller is the CVM owner; otherwise `CVM_MANAGE`. **Idempotency-Key.** `optional`. **If-Match.** `optional`.
- **Response body.** `202 <Operation>` with `kind="cvm.terminate"`. `Operation.result` on success is `<CVM>` with `state=TERMINATED`.
- **Errors.** `404` (§6.4). `409 CONFLICT` if `state ∉ {RUNNING, STOPPED, FAILED}`. A `terminate` on already-`TERMINATED` returns a `succeeded` operation directly.
- **Side effects.** Inserts the `Operation`. The saga writes `CVM_TERMINATED` and (if any DNS record was actually deprovisioned) `SUBDOMAIN_DEPROVISIONED` from the `succeeded` finaliser. The CVM's `cvm_profiles` rows are NOT removed; they survive in the DB for audit.

#### `POST /cvms/{cvm_id}/profiles`

Attach a profile to an existing Dev CVM. Synchronous: validates membership, inserts the `cvm_profiles` row, recomputes the CVM's combined policy (§8.5), and pushes to the entity's Security CVM.

- **Auth.** `JWT`. **Permission.** `CVM_MANAGE`. The **CVM owner** (`cvms.owner_id`) MUST be a member of the target profile (§7.7); otherwise `403 FORBIDDEN` with `details.required="profile_member"`, `details.member="cvm_owner"`, `details.owner_id` (T-25). The check is deliberately evaluated against the owner, not the caller: the owner's identity is what the merged policy — including any `value_from` secret resolution (§2.3, §8.5) — binds to, so an admin cannot attach a profile the owner is not entitled to. **Idempotency-Key.** `optional` — the operation is naturally idempotent on `(cvm_id, profile_id)`. **If-Match.** `required` (the CVM's ETag — concurrent attach/detach must serialise).
- **Request body.** `{"profile_id": <UUID>}`.
- **Response body.** `200 <CVM>` reflecting the new `profiles` array.
- **Errors.** `404` (§6.4) if the CVM is not visible or the profile is not visible. `409 CONFLICT` (`details.state="cvm_terminated"`) if the CVM is `TERMINATED`. `409 CONFLICT` (`details.state="sandbox_env_conflict"`, `details.name=<NAME>`, `details.profile_ids=[<UUID>, ...]`) if attaching the profile would introduce a `policy.sandbox_env` key whose value disagrees with an already-attached profile (§8.5 `sandbox_env` merge). `422 VALIDATION_ERROR` if the profile carries a `value_from` reference the **CVM owner** cannot satisfy — same `details` shape as `POST /cvms` with `details.member="cvm_owner"` and `details.user_id` = the owner. The route does NOT call the SC; convergence happens on the SC's next pull (§8.5).
- **Rate limit (additional).** Per CVM `12 RPM` (avoids policy-thrash from misconfigured automation pushing the Security CVM into a hot loop).
- **Side effects.** Inserts a `cvm_profiles` row (`attached_at`, `attached_by`). Bumps the per-CVM `policy_version` on the Console-side state; the SC sees the new merged policy on its next pull (§4.3, §8.5). Audit row `CVM_PROFILE_ATTACHED` (`after` includes `owner_id`).

#### `DELETE /cvms/{cvm_id}/profiles/{profile_id}`

Detach a profile from a Dev CVM. Synchronous: removes the `cvm_profiles` row, recomputes the combined policy, pushes to the Security CVM.

- **Auth.** `JWT`. **Permission.** `CVM_MANAGE`. The caller is NOT required to be a member of the profile to detach — detaching is a *strict reduction* of the CVM's reach and is therefore never an escalation vector. **Idempotency-Key.** `n/a`. **If-Match.** `required`.
- **Response body.** `200 <CVM>` reflecting the new `profiles` array.
- **Errors.** `404` if the CVM or attachment is not visible. `409 CONFLICT` (`details.state="last_profile"`) if the detach would leave the CVM with zero attached profiles (§8.1 — the CVM MUST have ≥ 1 profile while live; the operator must terminate the CVM instead).
- **Side effects.** Deletes the `cvm_profiles` row. Bumps the per-CVM `policy_version`; the SC picks up the new merged policy on its next pull (§4.3, §8.5). Audit row `CVM_PROFILE_DETACHED`.

### 3.6a Instance types (`/api/v1/instance-types`)

The Console maintains an **instance-type catalog**: a last-known-good cache of the machine types the provider can launch (name, family, vCPU, memory, hourly rate). The catalog backs this endpoint and the launch-time allowlist (§3.6 `POST /cvms`, §3.7 `POST .../security-cvm`). Reads are memory-only; the provider is never called inline on the normal read or on any launch path.

#### Catalog lifecycle

- **Structures.** `InstanceType {name, family, vcpu, memory_gb, hourly_rate, currency}` — one unified domain object (specs + price together); every descriptive field is nullable (`currency` is `null` whenever `hourly_rate` is). `InstanceTypeCatalog {instance_types, fetched_at, source, last_refresh_error}` with `source ∈ {provider, database, bootstrap_fallback}` and `last_refresh_error: {kind ∈ {provider_unreachable, schema_drift}, field ∈ {envelope, result, items} | null, at} | null`. Catalogs are immutable values swapped atomically; a failed refresh only attaches `last_refresh_error`, never touches the served list.
- **Virgin boot** (empty DB): memory AND the DB row are seeded with the built-in **bootstrap fallback** (the authoring-time snapshot, prices included, `fetched_at=null`), then a background provider fetch replaces both on success. The boot never waits on the provider. A failed boot fetch re-persists the seed carrying the failure and enters the retry ladder.
- **Warm boot**: the persisted catalog is loaded immediately (`source` becomes `database` unless the stored row is the bootstrap seed, which keeps its label; `fetched_at` is NOT rejuvenated), then a non-blocking warm-up refresh runs.
- **Steady state**: the reconciliation pass (§9) calls the catalog's `spawn_refresh_if_due(reason="scheduler")` — non-blocking: the fetch runs as a tracked background task so a slow provider never stalls the tick; `POST /admin/reconcile` therefore also refreshes the catalog. Success re-schedules at `now + 24h + jitter(0..2h)` and persists memory + DB; failure walks the retry ladder `5m → 10m → 1h → 6h → 12h → 24h`, then settles at the daily cadence (always in the future — a long outage cannot hot-loop). A refresh is single-flight.
- **Parsing** is tolerant (provider adapter): only `result[].items[].id` is load-bearing — an unusable envelope raises `schema_drift` with the broken layer in `field`; renamed/missing descriptive fields degrade to `null`; unknown fields are ignored; ids are format-checked (`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`, mirroring the launch request-body bound so the two rules cannot drift) and deduplicated. Every failure is logged (`instance_types_fetch_failed` / `instance_types_schema_drift` at ERROR; a missing provider token logs `instance_types_provider_not_configured` at WARNING and settles straight at the daily cadence; manual `?refresh=true` failures log without advancing the ladder) and a parse that loses descriptive fields logs `instance_types_field_drift` (WARNING).
- **Staleness** is computed at read time, never stored: `stale = fetched_at is null OR age > 27h` (refresh interval + max jitter + 1h grace — derived so a healthy catalog is never reported stale).

#### `GET /instance-types?refresh=<bool>`

List the launchable instance types.

- **Auth.** `JWT`. **Permission.** `implicit`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Normal read** (`refresh` omitted/false): serves the in-memory catalog immediately — no provider call, ever. When the catalog is stale, a best-effort background refresh is triggered **when due per the retry ladder** (a stale read never bypasses the anti-hot-loop gating); the response's `refresh_in_progress` reports whether one is running or was just spawned.
- **`refresh=true`**: performs ONE bounded inline provider fetch (30s timeout). Success serves the fresh catalog; failure serves the current cache with the failure recorded in `catalog.last_refresh_error`. When a background refresh is already in flight, the route serves the current cache instead of starting a second fetch (single-flight; `catalog.refresh_in_progress: true` reports it).
- **Response body.** `200 {"instance_types": [{name, family, vcpu, memory_gb, hourly_rate, currency, default, launchable}], "catalog": {source, fetched_at, stale, refresh_in_progress, last_refresh_error, field_miss_counts}}`. `field_miss_counts` is a machine-readable drift report — a map of expected provider field → number of entries that failed to parse it (absent, renamed, or an invalid value all normalize to `null`); an empty map means every expected field parsed on every entry, so monitoring can assert it empty. Human wording is left to consumers (the CLI renders the sentence). `default: true` marks the Dev CVM server default (`DEV_CVM_DEFAULT_INSTANCE_TYPE`, §12). `launchable: false` marks a catalogued-but-not-launchable type: GPU-family types (`h200.*`) are listed for visibility but not launchable yet (no measured GPU dstack image), so a launch attempt is rejected (see the allowlist below). They become launchable once a measured GPU dstack image exists in the Umbra config.

#### Launch-time allowlist

`POST /cvms` (§3.6) and `POST /entities/{entity_id}/security-cvm` (§3.7) validate the resolved `instance_type` against the in-memory catalog after their format checks. The resolved type must be **known AND launchable**: absent from the catalog returns `details.errors[*].type="unknown_instance_type"`, while a catalogued-but-not-launchable type (a GPU family) returns `details.errors[*].type="instance_type_not_launchable"`. Either way the `422 VALIDATION_ERROR` message enumerates the launchable types and the error item carries the context per the validation-envelope convention — `details.errors[*].{type, requested, valid_instance_types}` (the valid set is the launchable/CPU names only) — plus `details.catalog` (the same `{source, fetched_at, stale, refresh_in_progress, last_refresh_error, field_miss_counts}` block, so a stale allowlist is visible to the caller), and `details.hint` pointing at `umbra cvm instance-types`. The validation reads memory only — provider downtime can never block or slow a launch.

### 3.7 Security CVMs (`/api/v1/entities/{entity_id}/security-cvm`)

Per-entity Security CVM (§8.4) — at most one live `<SecurityCVM>` per entity. Lifecycle in §8.4; bearer-token model in §5.7. Routes refuse `entity_id` other than the caller's `JWT.entity_id` (§6.3 step 1).

#### `POST /entities/{entity_id}/security-cvm`

Submit Security CVM provisioning. Async: returns an `<Operation>`. The CA-export plaintext in `<SecurityCVMProvisionResult>` (§2.3) is returned exactly once via the **first** `GET /operations/{id}` after the operation reaches `succeeded`, by the operation's `actor_id` only (§3.8 disclosure rule); subsequent reads carry the redacted form. The `INGEST` plaintext is never returned by the Console.

- **Auth.** `JWT`. **Permission.** `SECURITY_CVM_CONFIGURE`. **Idempotency-Key.** `required`. **If-Match.** `n/a`.
- **Request body.** `{"instance_type": <string|null, ≤ 100, [A-Za-z0-9._-]>, "region": <string|null, ≤ 64>, "image_ref": <string|null, ≤ 512>, "image_measurement": <string|null, 96-char hex>}`. `instance_type` defaults from §12 `PHALA_DEFAULT_INSTANCE_TYPE` and MUST belong to the instance-type catalog (§3.6a — same `unknown_instance_type` `422` as Dev CVM launch); `region` defaults from §12 `SECURITY_CVM_DEFAULT_REGION`, then `PHALA_REGION`. `image_ref` / `image_measurement` default from §12 `SECURITY_CVM_IMAGE_REF` / `SECURITY_CVM_IMAGE_MEASUREMENT`. If either of `image_ref` / `image_measurement` is supplied, BOTH MUST be supplied (`422 VALIDATION_ERROR` otherwise) so the row captures a complete image-plus-guest-baseline attestation input. The measurement is the shared dstack-guest MRTD, not a digest of the caller-selected app image; app specificity comes from the generated full runtime policy (§10.4). Caller-supplied values let an operator deploy a per-entity image variant without a global-config update.
- **Response body.** `202 <Operation>` with `kind="security_cvm.provision"`, `target.type="security_cvm"`. `Operation.result` on success is `<SecurityCVMProvisionResult>` with first-read semantics.
- **Errors.** `404` (§6.4). `409 CONFLICT` (`details.state="security_cvm_already_live"`) if a live Security CVM already exists for the entity. `502 UPSTREAM_ERROR` is reflected via `Operation.error` after the saga's `failed` finaliser; the route itself returns `202` whenever the row commits.
- **Side effects.** Inserts the `Operation` and the `security_cvms` row in `PROVISIONING`. The saga emits `SECURITY_CVM_PROVISIONING_STARTED` from the `running` step and `SECURITY_CVM_PROVISIONED` from the `succeeded` finaliser.

#### `GET /entities/{entity_id}/security-cvm`

Read the current state of the entity's Security CVM. Polled by the CLI's `umbra security-cvm show` and by `umbra status`.

- **Auth.** `JWT`. **Permission.** `SECURITY_CVM_CONFIGURE`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `200 <SecurityCVM>`. NEVER carries plaintext bearers, the CA PEM, or docker credentials.
- **Errors.** `404` (§6.4) — no live Security CVM, or entity not the caller's.

#### `POST /entities/{entity_id}/security-cvm/actions/update`

Update the entity Security CVM deployment in place. Async: returns an `<Operation>`.

- **Auth.** `JWT`. **Permission.** `SECURITY_CVM_CONFIGURE`. **Idempotency-Key.** `optional`. **If-Match.** `n/a`.
- **Request body.** Empty.
- **Response body.** `202 <Operation>` with `kind="security_cvm.update"`. `Operation.result` on success is `{security_cvm: <SecurityCVM>, ca_changed: <bool>, dev_cvms_requiring_update: [<UUID>, ...]}`. The current in-place update keeps `dev_cvms_requiring_update` empty; the field is reserved for a future operation that changes launch-bound Dev CVM material.
- **Errors.** `404` (§6.4). `409 CONFLICT` if no live Security CVM exists, if another operation is active for it, if its state is not `RUNNING`, `STOPPED`, or `FAILED`, or if the row lacks a provider `deployment_id` / legacy `app_id`.
- **Side effects.** Re-renders the current Security CVM compose/config, calls the CVM provider's update method for the existing deployment, mints fresh SC `INGEST`/`CA_EXPORT` bearers with old-token overlap, re-attests the updated SC, fetches the current CA/aTLS policy, bumps `security_cvms.policy_version`, and emits `SECURITY_CVM_UPDATED` or `SECURITY_CVM_UPDATE_FAILED`. It records whether the CA changed but does not create CA-only Dev CVM markers: refresh-capable Umbra forwarders retain a valid `DEV_CONTROL` bearer and RTMR3-bound Console origin, pull the new SC policy/CA, and let the sandbox watcher replace the trust bundle. Egress may fail closed until polling converges. Any already-persisted `SECURITY_CVM_REBIND_REQUIRED` value is deliberately left untouched because it is the fail-closed signal that the legacy runtime's refresh capability is unproven. Use the pre-Umbra control plane to terminate/decommission that preserved resource, then launch a replacement under Umbra; the renamed build cannot manage it, and `cvm.update` is not recovery.

#### `DELETE /entities/{entity_id}/security-cvm`

Decommission the entity's Security CVM. Synchronous (Phala terminate is bounded).

- **Auth.** `JWT`. **Permission.** `SECURITY_CVM_CONFIGURE`. **Idempotency-Key.** `n/a`. **If-Match.** `optional`.
- **Response body.** `200 <SecurityCVM>` with `state=TERMINATED`.
- **Errors.** `404` (§6.4). `409 CONFLICT` (`details.state="dev_cvms_in_entity"`, `details.dev_cvm_count: <int>`) if any live Dev CVM exists in the entity (decommissioning would leave them without a proxy, §8.1). `502 UPSTREAM_ERROR` if Phala terminate fails — the row is NOT soft-deleted in that case so the operator can retry.
- **Side effects.** `SECURITY_CVM_DECOMMISSIONED` audit row. Soft-deletes the row plus its `service_principal_tokens` rows. Once decommissioned, every Dev CVM in the entity is effectively offline (their traffic has nowhere to route); the operator MUST re-provision before launching new CVMs.

#### `GET /entities/{entity_id}/security-cvm/attestation`

Return the Console's most recent attestation verdict for the entity's Security CVM as an **operator diagnostic** (§10.4). Used by `USER_MANAGE` admins and platform operators to confirm the SC's image measurement, RTMR3 digest, and last-verified timestamp. NOT a security-critical verification path: the SC's identity is established at provisioning by the Console (§8.4 / §10.4 attestation chain) and re-verified on every reconciler probe (§9.2); the user's machine never trusts the SC's CA directly (the CA is injected into Dev CVMs by Console-driven env at deploy time, and the user's trust path to a Dev CVM is the Dev CVM's own aTLS verification).

- **Auth.** `JWT`. **Permission.** `USER_MANAGE` OR `PLATFORM_OPERATOR`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Query.** `?probe=<bool>` (default `false`). When `true`, the Console runs a fresh server-side attestation probe (same path as the reconciler) and updates persisted state on success; when `false`, it returns the persisted state from the most recent verification.
- **Response body.** `200 <SecurityCVMAttestation>` (§2.3): the Console's verdict (`verified`, `failure_reason`, `image_measurement_seen`, `rtmr3_digest_seen`, `verified_at`) plus the row's `expected_image_measurement` for comparison.
- **Errors.** `404` (§6.4) if the entity has no live SC. `502 UPSTREAM_ERROR` (`details.adapter="security_cvm"`) when `probe=true` and the SC is unreachable or returns a malformed quote. `409 CONFLICT` (`details.state="attestation_drift"`) when `probe=true` produces a result that diverges from the persisted row state — the body still carries the divergence in `console_verdict` for forensic comparison.
- **Side effects.** `probe=true` updates `image_measurement` / `rtmr3_digest` / `attestation_verified_at` when verification succeeds; mismatches emit `SECURITY_CVM_ATTESTATION_DRIFT` (§11.2) and do NOT mutate the persisted state.

### 3.8 Operations (`/api/v1/operations/{operation_id}`)

The polling surface for every async action submitted under §3.

#### `GET /operations/{operation_id}`

- **Auth.** `JWT`. **Permission.** `implicit` if the caller is the operation's `actor_id`, else the same permission required by the route that created it (e.g. `CVM_LAUNCH` for `cvm.launch`). **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `200 <Operation>`. The `result` field is route-specific. For `security_cvm.provision`, the first read **by the operation's `actor_id`** after `succeeded` carries the one-shot CA-export plaintext; subsequent reads (by the same actor or any other authorized caller) carry the redacted form. Reads by another authorized caller — even before the actor reads — never receive plaintext, so a curious teammate cannot burn the disclosure. If the actor is soft-deleted before reading, the CA-export plaintext is unrecoverable; the operator MUST decommission and re-provision the Security CVM (§17.3).
- **Errors.** `404` if the operation does not exist, has expired (§8.2), or belongs to another tenant (§6.4).
- **Side effects.** A successful disclosure (the actor's first plaintext read of `security_cvm.provision`) writes an `OPERATION_RESULT_DISCLOSED` audit row (§11.2). Subsequent reads — whether redacted-because-already-disclosed or redacted-because-non-actor — do NOT write the row.

### 3.9 Audit (`/api/v1/audit/events`)

#### `GET /audit/events`

Query audit events.

- **Auth.** `JWT`. **Permission.** `AUDIT_VIEW`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Query parameters.** `actor_id` (UUID), `target_type` (string), `target_id` (string), `action` (`AuditAction.SYMBOL`), `from` (Timestamp), `to` (Timestamp), `limit` (1..500, default 100), `cursor` (string).
- **Response body.** `200 <ListPage<AuditEvent>>`. Results are ordered newest-first (descending `seq`); the opaque `cursor` walks toward older rows. Results are scoped to actors whose `entity_id == caller.entity_id` PLUS rows whose `target_id` resolves to a resource in the caller's entity (so reconciler-driven state transitions are visible — §11.4).
- **Errors.** `422 VALIDATION_ERROR` for unknown `action` or out-of-range `limit`.
- **Rate limit (additional).** Per-credential `60 RPM`.

### 3.10 Audit export (`/api/v1/audit/export`)

#### `POST /audit/export`

Issue an audit-export bundle. Returns an `<Operation>` whose `result` carries a one-shot signed download URL pointing at an out-of-band object store (§11.5). Bulk export is gated by a permission distinct from `AUDIT_VIEW` (T-21).

- **Auth.** `JWT`. **Permission.** `AUDIT_EXPORT`. **Idempotency-Key.** `required`. **If-Match.** `n/a`.
- **Request body.** Same filters as `GET /audit/events` (`actor_id?`, `target_type?`, `target_id?`, `action?`, `from?`, `to?`); plus `format ∈ {"csv", "ndjson"}`.
- **Response body.** `202 <Operation>` with `kind="audit.export"`. `Operation.result` on success: `{download_url: <string>, expires_at: <Timestamp>, content_type: <string>, sha256: <string, 64 hex>, row_count: <int>, byte_size: <int>}`. `download_url` is valid for 5 minutes and is single-use.
- **Errors.** `429 RATE_LIMITED` (`details.limit="audit_export_daily"`) when the per-credential daily quota of 10 exports is exhausted (§2.6).
- **Side effects.** Writes `AUDIT_EXPORT_REQUESTED` at submission and `AUDIT_EXPORT_ISSUED` (with `row_count`, `byte_size`, and `sha256`) when the export completes.

### 3.11 Traffic logs (`/api/v1/traffic-logs`)

#### `GET /traffic-logs`

Query traffic logs ingested from Security CVMs (§4).

- **Auth.** `JWT`. **Permission.** `TRAFFIC_LOGS_VIEW`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Query parameters.** `cvm_id` (UUID), `security_cvm_id` (UUID), `destination_host` (string ≤ 255, exact match on the logged hostname), `from` (Timestamp), `to` (Timestamp), `limit` (1..1000, default 100), `cursor` (string).
- **Response body.** `200 <ListPage<TrafficLog>>`. Scoped via `traffic_logs → security_cvms → profiles → entity` to the caller's entity.
- **Rate limit (additional).** Per-credential `30 RPM`.

#### `GET /traffic-logs/summary`

Per-host egress counts over a time window. Backs the "top hosts" panel, which must reflect the whole selected range independent of `GET /traffic-logs` pagination. This is a **bounded top-N aggregate, not a resource list** — there is no cursor and pagination does not apply; `limit` caps the number of distinct hosts returned.

- **Auth.** `JWT`. **Permission.** `TRAFFIC_LOGS_VIEW`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Query parameters.** `cvm_id` (UUID), `security_cvm_id` (UUID), `from` (Timestamp), `to` (Timestamp), `limit` (1..200, default 50).
- **Response body.** `200 {"hosts": [{"host": <string>, "count": <int>}, ...]}`, ordered by `count` descending then `host` ascending, truncated to `limit` rows. Entries with a null `destination_host` are excluded. Scoped to the caller's entity via the same join as `GET /traffic-logs`.
- **Rate limit (additional).** Per-credential `30 RPM`.

#### `GET /traffic-logs/timeseries`

Egress request volume bucketed over a time window, split into allowed and blocked counts with a running cumulative total. Backs the "egress over time" chart (per-period bars + a cumulative growth line), which — like the summary — must reflect the whole selected range independent of `GET /traffic-logs` pagination. This is a **bounded time-bucketed aggregate, not a resource list**: there is no cursor and pagination does not apply.

- **Auth.** `JWT`. **Permission.** `TRAFFIC_LOGS_VIEW`. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Query parameters.** `cvm_id` (UUID), `security_cvm_id` (UUID), `destination_host` (string ≤ 255, exact match), `from` (Timestamp), `to` (Timestamp), `buckets` (1..500, default 60; `auto` granularity only), `granularity` (one of `auto` (default), `hour`, `day`, `week`, `month`).
- **Bucketing.** `to` defaults to now. With `granularity=auto`, `from` defaults to `to − 24h`, the bucket width is `ceil((to − from) / buckets)` seconds (≥ 1s), and `from` is floored to a width boundary so buckets align to absolute epoch boundaries. With a **calendar** granularity, buckets are `date_trunc`'d to **UTC** boundaries (`hour`, `day` = midnight, `week` = Monday, `month` = the 1st) so day-to-day / week-to-week / month-to-month comparisons line up exactly; `from` defaults to a granularity-appropriate trailing window (48h / 30d / 12w / 12mo) and the bucket count is bounded to the most recent 500. An absent or inverted range falls back to the trailing default window.
- **Response body.** `200 {"from": <Timestamp>, "to": <Timestamp>, "granularity": <string>, "bucket_seconds": <int|null>, "buckets": [{"ts": <Timestamp>, "allowed": <int>, "blocked": <int>, "cumulative": <int>}, ...], "totals": {"allowed": <int>, "blocked": <int>, "total": <int>, "peak": <int>, "peak_ts": <Timestamp|null>}}`. `bucket_seconds` is the fixed width for `auto` and `null` for calendar granularities. Every bucket in `[from, to]` is present (gaps zero-filled), ordered ascending by `ts`; `cumulative` is the running total of allowed+blocked through that bucket (proof of growth across the window). `totals.peak`/`peak_ts` report the busiest single bucket and when it occurred. `blocked` counts logs with `response_code = 403` (the SC policy-block convention); everything else (including a null `response_code`) counts as `allowed`. Scoped to the caller's entity via the same join as `GET /traffic-logs`.
- **Rate limit (additional).** Per-credential `30 RPM`.

### 3.12 Admin (`/api/v1/admin`)

Routes restricted to `platform_operator` (§1.2). They operate across every entity; tenant admins MUST NOT have access (T-4).

#### `POST /admin/reconcile`

Run a single reconciliation pass synchronously (§9.5).

- **Auth.** `JWT`. **Permission.** `PLATFORM_OPERATOR`. **Idempotency-Key.** `optional`. **If-Match.** `n/a`.
- **Request body.** `{"include_orphans": <bool, default true>}`. Setting `include_orphans=false` skips the Cloudflare orphan-cleanup pass (§9.5).
- **Response body.** `200 {cvms_advanced: [<UUID>...], security_cvms_advanced: [<UUID>...], orphans_cleaned: [<string>...]}`.
- **Errors.** `503 SERVICE_UNAVAILABLE` (`details.component="phala_adapter"`) if Phala is not configured. `503 SERVICE_UNAVAILABLE` (`details.component="cloudflare_adapter"`) only if `include_orphans=true` and Cloudflare is unconfigured.
- **Rate limit (additional).** Per-credential `6 RPM`.

#### `POST /admin/sessions/revoke`

Force-revoke active Console JWTs by predicate. Used in incident response (§17.2).

- **Auth.** `JWT`. **Permission.** `PLATFORM_OPERATOR`. **Idempotency-Key.** `required`. **If-Match.** `n/a`.
- **Request body.** `{"user_id": <UUID|null>, "entity_id": <UUID|null>, "issued_before": <Timestamp|null>}` — at least one filter is required; the predicate is the AND of supplied fields.
- **Response body.** `200 {revoked_jti_count: <int>, revoked_refresh_token_count: <int>}`.
- **Errors.** `400 BAD_REQUEST` if no filter is supplied (the spec rejects "revoke all").
- **Side effects.** SELECTs every `refresh_tokens` row matching the predicate (`user_id`, `entity_id` resolved to a list of `user_id`, `issued_at < issued_before`); for each, inserts `(access_jti, access_expires_at)` into `revoked_tokens` and sets `revoked_at = now()` on the refresh-token row. Audit row `SESSIONS_REVOKED` with the predicate echoed in `after`.

#### `POST /admin/keys/rotate`

Rotate the JWT signing key (§5.2 rotation procedure, §17.2 incident response).

- **Auth.** `JWT`. **Permission.** `PLATFORM_OPERATOR`. **Idempotency-Key.** `required`. **If-Match.** `n/a`.
- **Request body.** `{"new_kid": <string, 1..64, [A-Za-z0-9._-]>, "retire_old_after_seconds": <int, 0..86400, default 3600>}`.
- **Response body.** `200 {active_kid: <string>, retiring_kids: [<string>, ...]}`.
- **Side effects.** Loads the new key from configured storage, sets it active for issuance, retains old `kid`s for verification until `retire_old_after_seconds` elapses. Audit row `JWT_KEY_ROTATED`.

### 3.13 Resource quotas (`/api/v1/entities/{entity_id}/quotas`, `/api/v1/users/{user_id}/quotas`)

Two-tier quota model (§7.4a, §7.4b): per-entity caps set by `PLATFORM_OPERATOR`, per-user caps set by `QUOTA_MANAGE` within the entity. Resolution at every create call: user quota → entity quota → global default (§12).

The count-based resources (`dev_cvms`, `ssh_keys`, `users`, `profiles`) cap *how many* rows a scope may hold. The two disk resources cap *gigabytes* (GB) instead: **`disk_gb_per_cvm`** bounds a single Dev CVM's disk at launch — the requested (or defaulted) `disk_size_gb` must not exceed the resolved cap (a value ceiling, not a running total) — and **`disk_gb_total`** bounds the summed `disk_size_gb` across a scope's live CVMs, so the new CVM's disk plus the existing sum must stay within the limit. Here **live** means not soft-deleted and neither `TERMINATED` nor `FAILED`: a failed launch never became a usable CVM, so it MUST NOT consume budget (nor self-inflict a `QUOTA_EXCEEDED` denial) until it is explicitly terminated — the same rule applies to the `dev_cvms` count. Both are enforced at `cvm.launch` (§3.6, §8.3, §6.3 step 5) against the resolved user→entity→default limit; `disk_gb_total` is checked against both the user and the entity budgets (like `dev_cvms`). Because the check is read-sum-then-insert, `cvm.launch` acquires a **per-entity** `pg_advisory_xact_lock` before reading and holds it until commit, so two concurrent launches (which take *distinct* idempotency locks, §2.6) cannot both pass against a stale total; the same lock serializes the `dev_cvms` count check on that path.

#### `GET /entities/{entity_id}/quotas`

Read effective quotas + current usage for the entity.

- **Auth.** `JWT`. **Permission.** `USER_MANAGE` (any tenant admin can see the caps that bind their entity). **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `200 {quotas: [<EntityQuota>, ...]}` covering every value in the `quota_resource` enum. For each: `{resource, limit, source: "default"|"override", current_usage, set_by, set_at}`. `current_usage` is computed live; cheap because it's a single indexed COUNT per resource — except the disk resources, where it is a `SUM(disk_size_gb)` (`disk_gb_total`) or `MAX(disk_size_gb)` (`disk_gb_per_cvm`, reported only as informational headroom against the value cap) over the scope's live CVMs.
- **Errors.** `404` (§6.4) if `entity_id` is not the caller's. Cross-entity access is refused identically per §6.4.

#### `PATCH /entities/{entity_id}/quotas/{resource}`

Set or update an entity-level quota override.

- **Auth.** `JWT`. **Permission.** `PLATFORM_OPERATOR`. **Idempotency-Key.** `required`. **If-Match.** `optional`.
- **Request body.** `{"limit": <int ≥ 0>}`.
- **Response body.** `200 <EntityQuota>`.
- **Errors.** `400 VALIDATION_ERROR` if `resource` is not in `quota_resource`. `404 NOT_FOUND` if `entity_id` not found (`PLATFORM_OPERATOR` is platform-scoped, so cross-entity is permitted). `409 CONFLICT` (`details.state="user_quota_above_new_entity_quota"`, `details.user_quota_count: <int>`) when the new limit would be lower than at least one existing user quota for the same resource — the spec does NOT clamp existing user quotas; the operator must clear or lower them first.
- **Side effects.** Upserts the row; audit row `QUOTA_SET` (§11.2) with the previous and new values.

#### `DELETE /entities/{entity_id}/quotas/{resource}`

Clear an entity-level override, reverting to the global default.

- **Auth.** `JWT`. **Permission.** `PLATFORM_OPERATOR`. **Idempotency-Key.** `n/a`. **If-Match.** `optional`.
- **Response body.** `204`.
- **Side effects.** Deletes the `entity_quotas` row (no soft-delete; a clear is a clear). Audit row `QUOTA_CLEARED`.

#### `GET /users/{user_id}/quotas`

Read effective quotas + current usage for the user.

- **Auth.** `JWT`. **Permission.** `implicit` when `user_id == caller.id`; `QUOTA_MANAGE` or `USER_MANAGE` otherwise. **Idempotency-Key.** `n/a`. **If-Match.** `n/a`.
- **Response body.** `200 {quotas: [<UserQuota>, ...]}` covering every user-scope resource (`dev_cvms`, `ssh_keys`, `disk_gb_per_cvm`, `disk_gb_total`). For each: `{resource, limit, source: "default"|"entity_override"|"user_override", current_usage, set_by, set_at}`.
- **Errors.** `404` (§6.4) if cross-tenant.

#### `PATCH /users/{user_id}/quotas/{resource}`

Set or update a per-user quota override.

- **Auth.** `JWT`. **Permission.** `QUOTA_MANAGE` (entity-scoped) or `PLATFORM_OPERATOR`. **Idempotency-Key.** `required`. **If-Match.** `optional`.
- **Request body.** `{"limit": <int ≥ 0>}`.
- **Response body.** `200 <UserQuota>`.
- **Errors.** `400 VALIDATION_ERROR` if `resource` is not user-scoped (`users` and `profiles` are entity-only). `404 NOT_FOUND` if cross-tenant. `409 CONFLICT` (`details.state="user_quota_above_entity_quota"`, `details.entity_quota: <int>`) when the supplied `limit` exceeds the effective entity quota.
- **Side effects.** Upserts the `user_quotas` row; audit row `QUOTA_SET`.

#### `DELETE /users/{user_id}/quotas/{resource}`

Clear a per-user override, reverting the user to the entity default.

- **Auth.** `JWT`. **Permission.** `QUOTA_MANAGE` or `PLATFORM_OPERATOR`. **Idempotency-Key.** `n/a`. **If-Match.** `optional`.
- **Response body.** `204`.
- **Side effects.** Deletes the `user_quotas` row. Audit row `QUOTA_CLEARED`.

## 4. Internal API (`/internal`)

Service-to-service surface. Today the only consumer is the Security CVM shipping batched traffic logs (§3.11 reads what `/internal` writes), but the contract is generalised over the actor class `service_principal` (§1.2) so future internal callers — backup probes, attestation services, upgrade orchestrators — slot in without re-designing the auth model.

### 4.1 Mount and exposure

`/internal` is mounted on the same ASGI app as `/api/v1`. Because Security CVMs run on Phala infrastructure and post over the public internet, `/internal` MUST be publicly reachable; operators cannot firewall it off. The protection is therefore the bearer token (§4.2) plus the integrity guards in §4.3 — `/internal` is **not** a private surface.

Operators MUST front the listener with a TLS-terminating proxy (§13.8). The proxy MAY apply a separate rate-limit pool to `/internal` (recommended: a pool sized to expected traffic-log throughput) so a Security CVM under attack cannot starve `/api/v1` of capacity.

### 4.2 Authentication and identity

Every `/internal` route MUST authenticate via the HTTP `Authorization` header in the form `Bearer <token>`. The header is parsed strictly per §5.8 (single space, non-empty token, no whitespace slop). The token is an opaque service-principal bearer with the following properties (§5.7):

- A 256-bit random secret, base64url-encoded, returned exactly once at issuance and persisted only as `SHA-256(secret)`.
- Bound to a `principal_type` (`security_cvm` or `dev_cvm`), a `principal_id` (the parent's `id` row), and a `purpose` (`INGEST`, `CA_EXPORT` for SC; `PROXY_AUTH`, `DEV_CONTROL` for Dev CVM). Authentication looks up by hash and verifies `(principal_type, purpose)` matches the route's expectations; mismatch is `401 UNAUTHORIZED`. The `dev_cvm` `PROXY_AUTH` bearer is **not** verified at any Console route — it is verified by the SC's mitmproxy against the local map pulled from `/internal/sc-control/cvms` (§4.3, §10.4). The `dev_cvm` `DEV_CONTROL` bearer is not accepted by the SC.
- Bound to the parent record's lifecycle: a bearer for a soft-deleted Security CVM MUST fail authentication (§5.7).

#### Critical isolation rules

- A Console JWT MUST NOT authenticate any `/internal` route. The two credential classes are syntactically distinct (JWT = `xxx.yyy.zzz` with at least two dots; bearer = base64url with no dots); the verifier MUST refuse the wrong shape with `401` before any DB lookup.
- A service-principal bearer MUST NOT authenticate any `/api/v1` route. Same rule, opposite direction.
- An `/internal` request MUST NOT cause any audit row attributed to a `user` actor, even if the principal was originally provisioned by a known operator. Internal-write audit attribution uses `actor_id=NULL` with `actor_email = "<principal_type>:<principal_id>"` (e.g. `"security_cvm:0d7e...:INGEST"`).

#### Token rotation

Deployment update sagas rotate the bearer classes they rebind: `security_cvm.update` mints fresh `INGEST` / `CA_EXPORT` bearers for the existing Security CVM, and `cvm.update` mints fresh per-Dev-CVM `PROXY_AUTH` and `DEV_CONTROL` bearers. The old bearer remains valid only for an overlap window (currently `≤ 1 hour` for Security CVM bearers and `≤ 10 minutes` for Dev CVM bearers) and is then expired or superseded.

A future spec revision MAY add a narrow operator route that rotates one service-principal bearer without changing the parent deployment and returns the new plaintext exactly once. Until that generic route lands, use the relevant deployment update flow for live Dev/Security CVM bearer rebinding; use decommission/re-provision only when the parent deployment itself must be replaced.

### 4.3 Routes

#### `POST /internal/traffic-logs`

Ingest a batch of traffic-log entries observed by the Security CVM identified by the bearer.

- **Auth.** `Bearer <ingest_token>` with `principal_type="security_cvm"`, `purpose="INGEST"`.
- **Permission.** Implicit; the bearer's `principal_id` resolves to the `security_cvms` row whose `entity_id` is the only authority. Cross-tenant references in the payload are rejected (see Mode 1 below).
- **Idempotency-Key.** `n/a` — replay protection is built into the request body (`idempotency_key` field; see below).
- **Request body.** Maximum `4 MiB` (§2.2). Maximum `1000` log entries per batch.

  ```
  {
    "idempotency_key": <string, 1..128, [A-Za-z0-9._-]>,    # per-batch unique
    "logs": [<TrafficLogIn>, ..., 1..1000]
  }
  ```

  Each `TrafficLogIn`:

  | Field | Type | Notes |
  |---|---|---|
  | `timestamp` | `<Timestamp>` | When the Security CVM observed the request. MUST be within `± 10 minutes` of server time (T-10). |
  | `cvm_id` | `<UUID>` | Dev CVM origin. REQUIRED. The SC resolves it from the request's `Proxy-Authorization` bearer against its locally-cached map (§10.4). |
  | `source_ip` | string, 1..45 | Stored verbatim; mitmproxy occasionally emits non-canonical values. |
  | `destination_ip` | string, 1..45 | As above. |
  | `destination_host` | string, ≤ 255, optional | Hostname from the proxied request. |
  | `protocol` | string, ≤ 20 | e.g. `tcp`, `https`, `http`. |
  | `port` | int, 0..65535 | Destination port. |
  | `method` | string, ≤ 20, optional | HTTP method. |
  | `path` | string, ≤ 2000, optional | HTTP path-only origin-form value. Query strings, fragments, backslashes, and control characters are rejected. |
  | `response_code` | int, optional | HTTP status (`0`–`599`). |
  | `decision` | string, ≤ 64, optional | SC enforcement decision: `allowed`, a block reason (e.g. `secret_injection_unfulfilled`), or `websocket_frame_dropped` (`docs/specs/security-cvm.md` §6.1). Optional so an older SC that predates it still ingests (stored NULL). Ingest ignores unknown extra fields rather than rejecting the batch, so a newer SC can add traffic fields without breaking an older Console. |
  | `bytes_transferred` | int ≥ 0 | Bytes observed. |
  | `attributes` | map<string,string>, optional | Per-request rule-driven attributes extracted by the SC from the sandbox-supplied body when an allowed rule defines `traffic_log_attributes` (`docs/specs/security-cvm.md` §4.3, §6.1). Names match `[a-z_]{1,32}`; values are truncated to 256 chars. At most 4 entries per record. Denied or DLP-blocked records MUST submit `{}` (or omit the field). |

- **Response body.** `200 {accepted: <int>, deduplicated: <bool>}`. `accepted` is the row count persisted; `deduplicated=true` iff the request matched a prior `idempotency_key` for this principal in the last 24 hours and was a no-op (the `accepted` count MUST equal the prior response's).

- **Addressing.** `cvm_id` is **REQUIRED** on every entry. The SC always knows which Dev CVM made each outbound request because it resolved the request's `Proxy-Authorization` bearer to a `cvm_id` from its locally-cached mapping (§10.4 SC-control pull); shipping the cvm_id on the log entry is therefore costless. The Console MUST verify the referenced Dev CVM belongs to the bearer's entity (`security_cvms.entity_id == cvms.entity_id`); cross-tenant references fail the entire batch with `422 VALIDATION_ERROR` (`details.errors[*].type="cross_tenant_cvm"`, T-5). Missing `cvm_id` is `422 VALIDATION_ERROR` (`details.errors[*].type="missing_cvm_id"`). The Console does NOT attempt source-IP-based fallback resolution: Dev CVMs and SCs run in different Phala apps so the SC sees only the public-gateway NAT'd source, which would not identify the originating Dev CVM.

- **Replay protection (T-10).** `idempotency_key` is unique per principal per 24 hours. A second request with the same `idempotency_key` and the same body hash is a no-op returning the prior response (`deduplicated=true`). A second request with the same `idempotency_key` and a *different* body hash is rejected with `409 IDEMPOTENCY_CONFLICT`. The `timestamp` window check rejects batches whose newest `timestamp` is more than 10 minutes outside server time, with `details.errors[*].type="timestamp_skew"`. **Concurrency.** Before the lookup, the route MUST acquire `pg_advisory_xact_lock` keyed on `(security_cvm_id, idempotency_key)` and hold it until the request transaction commits — same pattern as §2.6 idempotency for the JWT routes. Without this lock, two concurrent batches with the same key would both write `traffic_logs` rows and only one would win the `traffic_log_batches` UNIQUE, leaving duplicate per-entry rows.

- **Errors.** `401 UNAUTHORIZED` for any auth failure (header malformed, token unknown, wrong purpose, parent soft-deleted). `409 IDEMPOTENCY_CONFLICT` per the rule above. `413 PAYLOAD_TOO_LARGE`. `422 VALIDATION_ERROR` for malformed or missing `cvm_id`, cross-tenant `cvm_id`, or out-of-window `timestamp`.

- **Rate limit (additional).** Per principal `120 RPM` (every 0.5 s under typical load). Per principal `5000 logs / minute` aggregate.

- **Side effects.** One `traffic_logs` row per entry. The route does NOT write audit rows — high-volume ingest is deliberately excluded from `audit_events` (§11.1).

#### `GET /internal/sc-control/cvms`

The SC's polling endpoint for the Dev-CVM mapping it needs to authenticate `Proxy-Authorization` bearers and apply per-CVM merged policies (§10.4). Returns the canonical view of every live Dev CVM under the bearer's entity.

- **Auth.** `Bearer <token>` with `principal_type="security_cvm"`, `purpose="INGEST"` (reused; the SC already holds this bearer and adding a new purpose is unnecessary surface).
- **Idempotency-Key.** `n/a`.
- **Caching.** The Console MUST set `ETag: <sha256(serialized response)>` and accept conditional `If-None-Match` returning `304 NOT MODIFIED` when nothing changed. The SC SHOULD send `If-None-Match` on every poll to keep ingress noise low.
- **Polling cadence.** The SC SHOULD poll at most every 5 s under normal operation. On unknown bearer at the proxy the SC MUST fail closed (`407`) and MUST NOT trigger an immediate refresh in v0; defer-and-resolve is deferred (§10.4, `docs/specs/security-cvm.md` §5.1).
- **Response body.** `200 {entries: [<DevCVMControlEntry>, ...]}` where each entry is:

  ```
  {
    "cvm_id":             <UUID>,
    "fqdn":               <string>,                 # the Dev CVM's full DNS name
    "proxy_token_hash":   <string, 64-char hex>,    # SHA-256 of the bearer the Dev CVM presents
    "merged_policy":      <object>,                 # field-typed merge of cvm_profiles → entity_profiles.policy (§8.5)
    "policy_version":     <int>,                    # monotonic per cvm; bumped on attach/detach/edit
    "updated_at":         <Timestamp>
  }
  ```

  The list contains only Dev CVMs in `state ∈ {RUNNING, PROVISIONING}` that belong to the bearer's entity. Terminated / failed CVMs disappear from this list and the SC SHOULD evict them from its local map.

- **Errors.** `401 UNAUTHORIZED` for any auth failure. `403 FORBIDDEN` if the bearer's `principal_id` resolves to a Security CVM whose `entity_id` is the wrong scope (defense-in-depth; should not happen in practice). `429 RATE_LIMITED` if the SC polls faster than `60 RPM`.
- **Rate limit.** Per-principal `60 RPM` so a runaway SC cannot DoS the route.
- **Side effects.** Updates the calling `security_cvms` row's internal pull-observation fields (`last_policy_pull_at`, `last_policy_pull_etag`, `last_policy_pull_entry_count`) on both `200` and `304` responses. This does **not** bump `security_cvms.updated_at`, does not change the user-facing `<SecurityCVM>` ETag, and emits no audit row. The launch saga consumes this observation at `await_sc_pull` (§8.3) by comparing the observation timestamp to the new Dev CVM's `service_principal_tokens.created_at`.

#### `GET /internal/dev-control/security-cvm-atls-policy`

Recovery endpoint for a Dev CVM's `dev-egress-forwarder` after its locally stored SC aTLS policy fails verification. This path handles SC image/aTLS-policy refreshes where the SC mitmproxy CA did not rotate. It MUST NOT return a new CA, a new Dev-CVM proxy bearer, profile policy, or user-facing secret.

- **Auth.** `Bearer <token>` with `principal_type="dev_cvm"`, `purpose="DEV_CONTROL"`. The Dev CVM's `PROXY_AUTH` bearer MUST NOT authenticate here; it is only for the SC proxy data plane.
- **Response body.** `200`:

  ```
  {
    "cvm_id":                  <UUID>,
    "security_cvm_id":         <UUID>,
    "security_cvm_fqdn":       <string>,
    "ca_cert_sha256":          <string, 64-char hex>,
    "atls_policy":             <object>,
    "image_measurement":       <string, 96-char hex>,
    "attestation_verified_at": <Timestamp>
  }
  ```

- **Scope.** The bearer resolves to exactly one live Dev CVM. The route has no caller-supplied CVM id; the response is scoped to that CVM's entity and attached Security CVM.
- **Trust boundary.** The Console distributes a candidate policy; the Dev forwarder/helper still performs local aTLS verification before forwarding. This route does not, by itself, make a Console-authored golden measurement independently trustworthy: v0 relies on the Console to materialize the candidate SC measurement, then narrows acceptance to the launch-bound SC FQDN and the latest CA accepted through the authenticated runtime CA endpoint. To make the Console only an untrusted cache, production deployments need release-pipeline signed SC measurement material embedded in or referenced by `atls_policy`, with the Dev forwarder/helper rejecting unsigned or unverifiable measurement updates.
- **CA pin.** The Dev CVM compares `ca_cert_sha256` with the latest SC CA accepted from `GET /internal/dev-control/security-cvm-ca`. The forwarder persists that CA with a forwarder-owned `{security_cvm_fqdn,ca_cert_sha256,launch_ca_cert_sha256}` sidecar. A valid same-launch pair survives service restart; an empty volume is seeded from RTMR3-bound launch material without clobbering existing state, a changed FQDN or launch baseline rebases to the current attested launch CA, and partial/malformed state remains fail-closed until this authenticated endpoint repairs it. A mismatch rejects the policy candidate until the independent CA poll converges; it does not require `cvm.update`.
- **Attestation freshness.** The route returns `409 CONFLICT` (`details.state="security_cvm_attestation_unverified"`) unless the Console's current SC attestation state is successful (`image_measurement == expected_image_measurement` and `attestation_verified_at != null`). This check does not replace the forwarder's own aTLS verification.
- **Errors.** `401 UNAUTHORIZED` for any auth failure. `409 CONFLICT` for missing/unavailable SC or unverified attestation. `503 SERVICE_UNAVAILABLE` if the SC CA or aTLS policy has not been materialized.
- **Rate limit.** Per-principal `30 RPM`.
- **Side effects.** None. No audit row is emitted; this is a high-frequency data-plane recovery read.

#### `GET /internal/dev-control/security-cvm-ca`

Distribution endpoint for the current SC mitmproxy CA so a refresh-capable Umbra Dev CVM's `dev-egress-forwarder` can re-install it at runtime and follow SC CA rotation without a fleet-wide `cvm.update` (see `docs/specs/dev-cvm.md` §3.6, §4.5). Returns the **public** CA certificate only — never the CA private key, a proxy bearer, profile policy, or user-facing secret. The Dev CVM already holds this CA from its launch material, so this discloses nothing new to the authenticated caller. The endpoint's existence does not prove that a preserved legacy runtime polls it.

- **Auth.** `Bearer <token>` with `principal_type="dev_cvm"`, `purpose="DEV_CONTROL"` (the same principal as the aTLS-policy route). The Dev CVM's `PROXY_AUTH` bearer MUST NOT authenticate here.
- **Response body.** `200`:

  ```
  {
    "cvm_id":                  <UUID>,
    "security_cvm_id":         <UUID>,
    "security_cvm_fqdn":       <string>,
    "ca_cert_sha256":          <string, 64-char hex>,
    "ca_cert_pem":             <string, PEM>,
    "attestation_verified_at": <Timestamp>
  }
  ```

- **Scope.** As the aTLS-policy route: the bearer resolves to exactly one live Dev CVM; the response is scoped to that CVM's entity and attached Security CVM. No caller-supplied CVM id.
- **Attestation freshness.** Returns `409 CONFLICT` (`details.state="security_cvm_attestation_unverified"`) unless the Console's current SC attestation is successful (`image_measurement == expected_image_measurement`, `attestation_verified_at != null`, `error_reason != "ATTESTATION_DRIFT"`).
- **Trust boundary.** Same v0 caveat as the aTLS-policy route: the Console is the RTMR3-bound distributor of the candidate CA. The Dev forwarder validates `security_cvm_fqdn` and `ca_cert_sha256` before atomically publishing the CA and its FQDN/current-digest/launch-baseline sidecar for the sandbox, which verifies that pair and installs it replace-not-append. Making the Console only an untrusted cache requires release-pipeline-signed material or fetching the CA over the attested SC channel.
- **Errors.** `401 UNAUTHORIZED` for auth failure. `409 CONFLICT` for missing/unavailable SC or unverified attestation. `503 SERVICE_UNAVAILABLE` if the SC CA has not been materialized.
- **Rate limit.** Same per-principal dev-control budget as the aTLS-policy route.
- **Side effects.** None. No audit row is emitted; this is a high-frequency data-plane read.

### 4.4 Isolation guarantees

Every isolation property below is a contract `/internal` MUST hold at the route layer, not at the network edge:

1. **Credential-class isolation.** A Console JWT MUST NOT authenticate any `/internal` route. A service-principal bearer MUST NOT authenticate any `/api/v1` route. The verifier MUST distinguish credential classes by token shape (§4.2) and refuse the wrong shape with `401` before any database lookup.
2. **Cross-tenant rejection at the data layer.** Every reference inside an `/internal` payload that names a Console-managed resource (today: `cvm_id`) MUST be validated against the bearer's principal scope (`entity_id` for Security CVM bearers). References outside the scope fail the request; they MUST NOT be silently coerced to NULL or persisted (T-5).
3. **Identity attribution.** Rows written by `/internal` callers are attributed to the principal, never to any user. Audit consumers can therefore distinguish "user X did Y" from "Security CVM Z observed W".
4. **Read scoping for future internal routes.** Any future internal read route MUST scope its result set to the bearer's principal — a compromised Security CVM MUST NOT be able to use `/internal` to enumerate other tenants' data. Read routes for service principals MUST default to `principal_id`-scoped queries; broadening requires a separate authorization design.
5. **Replay protection at the route, not at the proxy.** §4.3's `idempotency_key` and `timestamp` window are MANDATORY at the route. A reverse proxy MAY add deduplication of its own but MUST NOT be the only layer enforcing replay.

## 5. Authentication

The Console issues two distinct credential classes, each with its own format, lifecycle, and verification path. Their separation is the core of the trust boundary between `/api/v1` and `/internal` (§4.2).

### 5.1 Credential classes

| Class | Format | Holder | Issued by | Verified at | Used at |
|---|---|---|---|---|---|
| Console access JWT | Asymmetric JWT (`EdDSA` default; `RS256` permitted) | `user` / `tenant_admin` / `platform_operator` | `POST /auth/device/poll` (§3.1), `POST /auth/refresh` (§3.1) | every `/api/v1` route's request middleware | every `/api/v1` route except `/auth/*` |
| Console refresh token | Opaque 256-bit random string | Same as above | Same as above | `POST /auth/refresh` only | `POST /auth/refresh` only |
| Service-principal bearer | Opaque 256-bit random string | A `service_principal` (today: a Security CVM) | The provisioning route for that principal's class (§3.7 for Security CVM) | every `/internal` route's request middleware | `/internal` routes (§4.3) and the Console's outbound calls to the principal (e.g. `/ca.pem` fetch, §10.4) |

The classes are syntactically distinguishable. A JWT is `<header>.<payload>.<signature>` (two dots). An opaque bearer is base64url with no dots. The verifier MUST inspect token shape before any database lookup and reject the wrong shape with `401 UNAUTHORIZED` (T-2).

### 5.2 Console access JWT

Signed payload that carries the caller's identity from `/auth/device/poll` to every subsequent `/api/v1` request.

#### Algorithm and key management

- **Algorithm.** `EdDSA` (Ed25519) is the default; `RS256` (RSA-2048 minimum) is permitted as a fallback for FIPS-locked or legacy-KMS deployments. `HS256` MUST NOT be used for issued JWTs (T-1: a shared HMAC secret means anyone with read access can forge any user). Asymmetric signing keeps signing capability bounded to the holder of the private key.
- **Key material.** The signing private key and verification public key are loaded from configured storage (§12.2) at boot and on rotation. Keys are referenced by `kid`. The Console MAY use a KMS-backed signer (`gcp-kms`, `aws-kms`) so the private key never appears in process memory; this is the recommended deployment.
- **Public key set.** The Console loads its verifying public keys from `JWT_PUBLIC_KEYS_REF` (§12, a JWKS-shaped local file or KMS reference) and uses them only for its own request-middleware verification path. The Console does NOT publish a public JWKS endpoint in v1 — no v1 component (Security CVM, CLI, internal services) needs to verify Console-issued JWTs externally. The SC's binding is rooted in TEE attestation (§10.4), not in Console JWT signature verification. A future revision MAY add a published JWKS when (and only when) a real external verifier appears (e.g. a service-to-service consumer of Console-issued user JWTs).
- **Active vs verifying `kid`s.** At any moment exactly one `kid` is the **active** signing key (used for new issuance); zero or more `kid`s are **verifying** (accepted on inbound JWTs but no longer issued). Rotation (§17.2): activate a new `kid`, retain the old `kid` as verifying for `retire_old_after_seconds` (default 1 hour, max 24 hours; admin override via §3.12 `POST /admin/keys/rotate`), then retire it.
- **Refused at boot.** The Console MUST refuse to start if no active key is loaded; if any loaded key has fewer than 2048 bits of RSA strength or fails an Ed25519 self-test; if `kid` is empty or contains characters outside `[A-Za-z0-9._\-]`.

#### Header

The JWS header carries exactly:

| Field | Value | Notes |
|---|---|---|
| `alg` | `EdDSA` or `RS256` | One of the configured algorithms; pinned per `kid` (see verification). |
| `kid` | string, 1..64, `[A-Za-z0-9._\-]` | Identifies the signing / verifying key. |
| `typ` | `at+JWT` | RFC 9068 marker — distinguishes a Console access token from an OIDC id_token, an OAuth refresh token, or any other JWT shape (T-28). |

The header MUST NOT contain `jku`, `jwk`, `x5u`, or `x5c` (T-27). Any token whose header includes one of these MUST be refused with `401 UNAUTHORIZED` *before* signature verification. The Console loads verifying keys exclusively from `JWT_PUBLIC_KEYS_REF` (§12); a caller-supplied key source is never honored.

#### Claims

| Claim | Type | Notes |
|---|---|---|
| `iss` | string | Configured `jwt_issuer` (default `umbra-console`). |
| `aud` | string OR string[] | Configured `jwt_audience` (default `umbra-console`). RFC 7519 permits either shape; the Console accepts both forms — a string equal to the configured audience, or a non-empty array containing it. |
| `sub` | UUID string | `user.id`. |
| `entity_id` | UUID string | The user's entity at issuance. Verified against the `users.entity_id` row at step 8 below. |
| `iat`, `nbf`, `exp` | int (epoch s) | TTL is `jwt_access_token_ttl_seconds` (default `3600`, range `300..3600`). |
| `jti` | UUID v4 string | Required. Unique per token; the revocation key (§5.2 revocation). |

The JWT MUST NOT carry `email`, `permissions`, or `profiles` claims:

- `email` is PII; placing it in a signed-but-not-encrypted JWT exposes it to anyone who captures the token (Curity's "minimise PII in JWTs" rule). The audit recorder reads `users.email` from the row already loaded at verification step 8 — there is no per-request DB cost.
- `permissions` and `profiles` would be advisory only; authorization always reloads from the database (§5.3).

Clients MUST NOT rely on identity or permission claims beyond `sub` and `entity_id`.

#### Verification

Every protected route MUST verify, in this order. **Order matters**: the implementation MUST short-circuit at the first failure and MUST NOT touch the database, the signature primitive, or any disk before step 4.

1. **Token shape.** The token has the form `<header>.<payload>.<signature>` — three non-empty base64url-encoded segments separated by exactly two dots. An empty signature segment, missing dots, or non-base64url characters MUST refuse with `401 UNAUTHORIZED` before any decode. (Defends against signature-stripping attacks.)
2. **Header parse and attack-vector rejection.** Decode the header. Refuse with `401 UNAUTHORIZED` if any of the following holds:
   - The header contains a `jku`, `jwk`, `x5u`, or `x5c` claim (T-27).
   - `alg` is missing, equals `none` (case-insensitive), or is not in the static allow-list (`EdDSA`, `RS256`).
   - `kid` is missing or fails the `[A-Za-z0-9._\-]{1,64}` format check. Format validation precedes the kid lookup so a hostile value cannot smuggle a malformed string into the key map.
   - `typ` is present and not `at+JWT` (T-28). For forward-compat, the Console MAY accept tokens with no `typ` claim during the transition; new tokens issued post-transition always carry `typ: at+JWT`.
3. **Per-`kid` algorithm pinning.** Look up `kid` in the loaded key set. The key entry has its own `alg` field; the JWT header's `alg` MUST equal it. Mismatch refuses with `401 UNAUTHORIZED`. Without this check, an attacker with the public key for an RS256 `kid` could craft a token signed with HS256 using the public key as the HMAC secret — the spec's allow-list permits HS256-style alg values broadly were it not for this pin (T-1, T-27).
4. **Signature verification.** Verify the JWS signature using the kid's pinned public key and the algorithm bound to that kid (NOT the algorithm declared in the token header — that's a hint, not authority). Failure refuses with `401 UNAUTHORIZED`.
5. **Standard claim validation.**
   - `iss` exactly matches `JWT_ISSUER` (string equality, case-sensitive — Curity: "the value of `iss` should match exactly").
   - `aud` includes `JWT_AUDIENCE`. If `aud` is a string, it MUST equal `JWT_AUDIENCE`; if it is an array, the array MUST contain `JWT_AUDIENCE` as a string element. A token whose audience does not include the Console's configured value MUST refuse with `401 UNAUTHORIZED`.
   - `iat`, `nbf`, `exp` are present and numeric. `nbf ≤ now + jwt_leeway_seconds`; `exp > now - jwt_leeway_seconds`; `iat ≤ now + jwt_leeway_seconds` (defends against forward-clock-skew issuers). Default leeway `30 s`, range `0..300`.
6. **Identity claim validation.** `sub` parses as a UUID v4; `entity_id` parses as a UUID v4.
7. **Revocation lookup.** `jti` is **not** present in `revoked_tokens` (T-2).
8. **User reachability.** The `User` row for `sub` exists, is **active** (`deactivated_at IS NULL AND deleted_at IS NULL`, §7.3), and `users.entity_id` matches the `entity_id` claim. Otherwise `401 UNAUTHORIZED` (a JWT for a deactivated, erased, or relocated user is treated as stale). The hydrated User row is the source of `email` for audit attribution downstream — the JWT carries no `email` claim.

After this, §5.3 reloads permissions for §6 enforcement.

**Zero-trust verification.** Every Console process / worker MUST run the full verification on every request. There is no "trusted internal-network" shortcut — a JWT presented to one Console replica MUST NOT be implicitly trusted by a sibling replica without re-verification. The verification cost is bounded by §13.2's SLO (`≤ 1 ms` p99 for permission reload; signature verification is a few microseconds for the supported algorithms).

#### Token-body visibility (informational)

A signed JWT is **not encrypted** — the payload is base64url and trivially decodable by any holder. With `email` removed from the payload (above), the only sensitive data in a Console JWT is the `(sub, entity_id, jti)` triple. The Console treats this triple as non-secret: it identifies the user but reveals no PII beyond the bearer's already-implied scope (the Console's own user database is the authoritative source of email and identity).

Tokens in transit are protected only by TLS (§13.9). Tokens MUST NOT be logged at any level (§13.5) and MUST NOT appear in URL paths or query strings (`Authorization` header only).

The spec does NOT use JWE encryption for access tokens. Future revisions MAY adopt sender-constrained tokens (DPoP per RFC 9449, or the `cnf` claim with mTLS-bound credentials per RFC 8705) to harden against bearer-token theft (§20).

#### Revocation

The Console maintains a `revoked_tokens(jti UUID PK, expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ, revoked_by UUID|NULL)` table. The verification step (7) above is a `SELECT 1 FROM revoked_tokens WHERE jti = $1 LIMIT 1`.

- `POST /auth/logout` (§3.1) inserts `(jti, exp)` for the access token and soft-deletes the matching refresh token.
- `POST /admin/sessions/revoke` (§3.12) bulk-inserts `(jti, exp)` rows for matching predicate; this is the incident-response path (T-15, §17.2).
- A daily prune job removes rows where `expires_at < now() - 1 day` (the access token has been expired for at least a day, so its `jti` is no longer needed).

The `revoked_tokens` table is the spec's mitigation for T-2; an implementation that omits it cannot claim conformance.

#### Refresh tokens

Each issuance returns a paired access token and refresh token:

- The refresh token is a 256-bit random secret, base64url-encoded.
- Stored per §7.14. Each row carries `family_id`, `access_jti`, and `access_expires_at` alongside the refresh-token columns; the `access_jti` is the single source of truth for which access-token `jti` to deny when revoking this issuance.
- TTL: `refresh_token_ttl_seconds` (default `2592000` = 30 days, range `86400..7776000` = 1 day to 90 days).
- **Single-use rotation.** `POST /auth/refresh` MUST atomically: verify the supplied refresh token's hash matches a row with `redeemed_at IS NULL` and `revoked_at IS NULL` and `expires_at > now`; mark `redeemed_at = now`; insert a new refresh-token row with `parent_jti` pointing back to the parent and `family_id` inherited from it; issue both new tokens (recording the new access token's `jti` and `exp` on the new row's `access_jti` / `access_expires_at`).
- **Replay defense.** A presented-already-redeemed refresh token MUST cause the Console to revoke the entire family in one shot: `UPDATE refresh_tokens SET revoked_at = now() WHERE family_id = $f AND revoked_at IS NULL`. For every now-revoked row, insert `(access_jti, access_expires_at)` into `revoked_tokens` so the matching access tokens fail their next request. Emit one `AUTH_REFRESH_REUSE_DETECTED` audit row (§11.2) carrying `family_root_jti = $f`. The replay response is the spec's mitigation for refresh-token theft per RFC 9700 §4.13.2 — a thief redeeming the stolen token kicks the legitimate user out, and the resulting audit row gives SOC / SIEM a high-signal alert.
- A user-driven `POST /auth/logout` revokes the access-token's `jti` AND soft-deletes the matching refresh token's row.

### 5.3 Authoritative permission resolution

The Console JWT does not carry a `permissions` claim. Every protected route MUST load the user's permissions from `user_permissions` on every request (T-15: revocations take effect on the next request, not on JWT expiry). The reload is a single indexed lookup; under §13.2's SLO it MUST complete in `≤ 1 ms` p99.

### 5.4 Login flows

The Console exposes two mutually exclusive login flows, matching [CLI spec §5.1](cli.md):

- **Loopback + PKCE** (default) — OAuth 2.0 Authorization Code with PKCE, redirect URI on `127.0.0.1`. Selected by `umbra auth login` without `--device`. The browser leg is invisible to the user; this is the OAuth-native shape for native CLIs.
- **Device flow** (RFC 8628) — selected by `umbra auth login --device` / `--no-browser`. Used when no usable browser is available (CI, headless servers, SSH sessions without `DISPLAY`).

Both flows verify the upstream IdP `id_token` per §5.5, resolve to a Console `User` per §5.6, and issue the JWT pair per §5.2. They differ in the browser-vs-no-browser dance and in the rendezvous mechanism between user and CLI.

#### 5.4.1 Loopback + PKCE flow

The Console plays Authorization Server to the CLI and Relying Party to Google in the same flow. Three Console routes (§3.1): `GET /auth/authorize`, `GET /auth/oidc/callback`, `POST /auth/token`.

**Sequence.**

1. The CLI generates `code_verifier` (43..128 chars from RFC 7636 unreserved), `code_challenge = base64url(sha256(code_verifier))`, and `state` (≥ 32 bytes random). It binds an ephemeral port `<P>` on `127.0.0.1` and opens the user's browser to `GET <console_url>/api/v1/auth/authorize?client_id=<configured>&redirect_uri=http://127.0.0.1:<P>/callback&response_type=code&code_challenge=<…>&code_challenge_method=S256&state=<…>&scope=openid+email+profile`.
2. The Console (`/auth/authorize`):
   1. Validates every query parameter (§3.1's strict rules). The `redirect_uri` regex pin `^http://127\.0\.0\.1:[0-9]{1,5}/callback$` blocks open-redirect — no other host, no other path.
   2. Validates `client_id` against `OIDC_CLIENT_ALLOWLIST` (§12). The CLI's `client_id` is registered out of band so an attacker cannot mint pending rows for an unrelated client.
   3. Mints `idp_state` (32 bytes random) and `idp_nonce` (32 bytes random).
   4. Inserts a `loopback_auth_pending` row keyed on the CLI's `state` (§7.15).
   5. Redirects the browser to Google's authorize endpoint with `client_id=<GOOGLE_OIDC_CLIENT_ID>`, `redirect_uri=<console_url>/api/v1/auth/oidc/callback`, `response_type=code`, `scope=openid email profile`, `state=<idp_state>`, `nonce=<idp_nonce>`, `prompt=consent`.
3. The user authenticates at Google. Google redirects the browser to `GET <console_url>/api/v1/auth/oidc/callback?code=<google_code>&state=<idp_state>`.
4. The Console (`/auth/oidc/callback`):
   1. Looks up `loopback_auth_pending` by `idp_state`. Unknown ⇒ HTML error page; pending row (if any) is deleted.
   2. Verifies `expires_at > now`. Expired ⇒ delete row, HTML error.
   3. Calls Google's token endpoint with the supplied `code`. Verifies the `id_token` per §5.5 AND verifies `nonce == idp_nonce` (loopback flow uses `nonce`; device flow does not because RFC 8628 omits it).
   4. Resolves to a Console `User` per §5.6. Re-bind protection (§5.6 step 8) applies.
   5. Mints `console_authz_code` (32 bytes random). Persists `SHA-256(console_authz_code)` and the resolved `user_id` on the pending row.
   6. Redirects the browser (303) to `<auth_pending.redirect_uri>?code=<console_authz_code>&state=<auth_pending.state>` — the CLI's loopback URL.
5. The CLI's loopback receives the redirect, verifies the `state` matches the value it sent (already in the [CLI spec](cli.md)), and exchanges the code at the Console: `POST /api/v1/auth/token` with `{"grant_type": "authorization_code", "code": <console_authz_code>, "code_verifier": <code_verifier>, "redirect_uri": <same as authorize>, "client_id": <same>}`.
6. The Console (`/auth/token`):
   1. Looks up `loopback_auth_pending` by `SHA-256(code)`. Unknown ⇒ `400 {"error": "invalid_grant"}`.
   2. Verifies `expires_at > now`, `redirect_uri` and `client_id` match the stored values, `user_id` is set (the IdP roundtrip completed).
   3. Verifies `base64url(sha256(code_verifier)) == code_challenge`. Mismatch ⇒ `400 {"error": "invalid_grant"}`.
   4. Atomically deletes the row (single-use; replay returns `invalid_grant`) and issues the JWT pair (§5.2).
   5. Writes `AUTH_SESSION_ISSUED`.

**Browser-leg sanitisation.** Errors during steps 2–4 render plain HTML pages with no JavaScript, no caller-controlled content, no PII, and no upstream messages. The browser-served HTML is in scope for XSS / phishing / CSRF concerns; the response MUST set `Cache-Control: no-store` and the §2.10 security headers. The Console MUST NOT include the `state`, `code`, or `idp_*` values in error pages — they are short-lived secrets.

**Why a `client_id` allow-list.** Without it, an attacker who controls a malicious page can craft a `/auth/authorize` URL that completes the IdP roundtrip and redirects Google's response to attacker-controlled `127.0.0.1:<port>` — except the loopback redirect is bound to the user's local browser, so the attacker would also need a malicious local listener. The allow-list is a belt-and-braces defence against rogue `client_id`s entering the auth-pending table.

#### 5.4.2 Device flow

Two Console routes (§3.1): `POST /auth/device/start`, `POST /auth/device/poll`.

**Sequence.**

1. `POST /auth/device/start` — the Console calls the upstream IdP's device-code endpoint with the **device client** (`GOOGLE_OIDC_DEVICE_CLIENT_ID` / `GOOGLE_OIDC_DEVICE_CLIENT_SECRET`, falling back to `GOOGLE_OIDC_CLIENT_ID` / `_SECRET` when unset — §12; the same client is used for the `/auth/device/poll` token exchange), receives `{device_code, user_code, verification_url, expires_in, interval}` plus optional `verification_url_complete`, generates a 32-byte `polling_secret`, persists a `device_flow_pending` row, returns the IdP fields plus the `polling_secret` to the CLI. `verification_url_complete` is passed through only when the IdP provides it.
2. The user opens `verification_url` (or `verification_url_complete`, if present) and approves at the IdP.
3. `POST /auth/device/poll` — the CLI presents `(device_code, polling_secret)`. The Console:
   1. Looks up `device_code` in `device_flow_pending`. Unknown ⇒ `400 {"error": "access_denied"}`.
   2. Constant-time compares `polling_secret` against `polling_secret_hash`. Mismatch ⇒ `401 UNAUTHORIZED` (T-2 binding).
   3. Checks `expires_at`. Expired ⇒ `400 {"error": "expired_token"}`; row deleted.
   4. Honors the IdP's `interval`: if the previous successful poll for this `device_code` was less than `interval - 1` seconds ago, return `400 {"error": "slow_down"}` without forwarding to the IdP.
   5. Forwards to the IdP token endpoint. `authorization_pending` / `slow_down` ⇒ `400 {"error": <same>}`, row kept. Hard error ⇒ row deleted, `400 {"error": <reason>}`.
   6. On success, verifies the `id_token` per §5.5, resolves the user per §5.6, issues the JWT pair, returns `200 <token-pair>`. Writes `AUTH_SESSION_ISSUED`.

#### 5.4.3 State and cleanup

Both flows persist their state in dedicated tables under §7.15 — `loopback_auth_pending` and `device_flow_pending` — so multi-process Console deployments work via the shared database. In-process dictionaries are NOT permitted.

Both tables MUST be swept by the reconciler (§9.2): rows where `expires_at < now` are deleted on every pass plus opportunistically on every `/start`, `/authorize`, `/poll`, `/oidc/callback`, and `/token` call. A stuck IdP MUST NOT strand entries indefinitely.

Both stored secrets are hashed: `polling_secret_hash` and `console_authz_code_hash` are `SHA-256(plaintext)` so a DB read does not expose the live binding values.

### 5.5 ID-token verification (upstream IdP)

When the IdP's token endpoint returns an `id_token`, the Console MUST verify, in this order (the same shape as §5.2's verification chain — refusing hostile headers before signature):

- **Header attack-vector rejection (T-27).** The id_token's header MUST NOT contain `jku`, `jwk`, `x5u`, or `x5c`. Any of these refuses with `502 UPSTREAM_ERROR`. Verifying keys come from the configured `GOOGLE_JWKS_URL` (§12) — never from a header-supplied URL or embedded key.
- **Algorithm.** `RS256` only. Any other `alg` (especially `none` or `HS256`) MUST be refused (T-20). The algorithm declared in the header MUST also equal the algorithm registered for the `kid` in the JWKS (per-kid algorithm pinning, §5.2 step 3).
- **`kid` format.** The header's `kid` MUST match the IdP's expected charset (Google's are 40-character lowercase hex). The Console MUST format-check before any JWKS lookup.
- **TLS chain validation.** The Console's outbound HTTPS to the IdP uses standard public-CA chain validation (the operator's host trust store). A compromised public CA issuing a forged certificate for the IdP's hostname is a state-level threat outside this spec's scope (§1.5 "compromised IdP" already covers IdP-side identity takeover; CA compromise is a strictly weaker variant of the same class).
- **JWKS cache.** The IdP's JWKS is cached for `5 minutes` to bound the impact of any transient verification failure (T-12). On a `kid` miss the cache is force-refreshed exactly once before failing.
- **Issuer.** For Google, `iss ∈ {"https://accounts.google.com", "accounts.google.com"}`. Each provider added in a future revision MUST list its allowed issuers explicitly.
- **Audience.** Each flow verifies against its own Google client (§12): the loopback flow (§5.4.1) against `GOOGLE_OIDC_CLIENT_ID`, the device flow (§5.4.2) against `GOOGLE_OIDC_DEVICE_CLIENT_ID` (which falls back to `GOOGLE_OIDC_CLIENT_ID` when unset). `aud` MUST equal that flow's client id; if the token's `aud` is an array, every entry MUST equal it — a token shared with another audience is refused (Curity's "reject any request that contains a token intended for different audiences"). A token minted for the *other* flow's client is therefore rejected.
- **`azp` claim** (when present). When the IdP issues `aud` as an array, OIDC requires `azp` (authorized party) and the Console MUST verify `azp` equals that flow's client id.
- **`iat` / `exp`.** Required and validated with the same `5-minute` leeway as §5.2.
- **`email_verified`.** MUST be the literal boolean `true`. Missing or false is treated as a failed assertion.
- **`at_hash`.** When the token endpoint also returned an `access_token`, the Console MUST present that access_token to the JWT decoder so the `at_hash` binding is enforced. Skipping this check would let an attacker substitute one user's `id_token` for another user's `access_token` from the same provider.
- **`nonce`.** The loopback flow (§5.4.1) MUST mint a `nonce` at `/auth/authorize` and verify it on the returned `id_token`. The device flow (§5.4.2) does NOT use `nonce` (RFC 8628 omits it).
- **`typ` header.** Google's id_tokens carry `typ: JWT`; the Console accepts that. A token with `typ: at+JWT` (i.e. a Console-issued access token) presented as if it were an inbound id_token MUST be refused (T-28).

If any verification step fails, the route returns `502 UPSTREAM_ERROR` — the failure is attributed to the IdP, not to the user.

### 5.6 Account resolution

After a verified `id_token`, the Console converts OIDC claims into a Console `User`:

1. Strip and lowercase the `email` claim.
2. Look up `oauth_identities` by `(provider, provider_subject_id)`. **If a row exists**, use its `user_id`; the `email` claim is recorded as the most-recent observation but does NOT change the binding. Continue at step 6.
3. **No matching `oauth_identities` row.** Look up `Entity` by `domain == split(email, "@")[1]` where `entities.deleted_at IS NULL`. Missing ⇒ `403 FORBIDDEN`.
4. Look up `User` by `(email)` among non-erased users (§7.3). **If missing**, materialize a new user in the entity from step 3 (see below). **If present** but `user.deactivated_at IS NOT NULL` ⇒ `403 FORBIDDEN` — a deactivated user MUST NOT get a fresh JWT pair, even though §5.2 step 8 would also refuse the JWT on the next request. Refusing at login keeps the OIDC path clean (no phantom `oauth_identities` first-time-link inserts during deactivation, no wasted IdP roundtrip).
5. Verify `user.entity_id == entity.id`. Mismatch ⇒ `403 FORBIDDEN`. (The §7.3 email-domain ↔ entity-domain invariant guarantees the two columns agree at write time, so this check is defense-in-depth against a corrupted row rather than a routine outcome.)
6. **Verify the user is active.** `user.deleted_at IS NULL` (and, for the step-4 branch, `user.deactivated_at IS NULL` already enforced). The oauth-identity fast path (step 2) MUST also refuse deactivated or erased users here.
7. **First-time link.** If no `oauth_identities` row existed in step 2, insert one binding `(user.id, provider, subject)`. The `(provider, subject_id)` pair is then **immutable** for that user.
8. **Re-bind protection (T-3).** If an `oauth_identities` row exists with `provider = X` for `user.id` but the IdP returned a different `subject_id`, the Console MUST refuse the login with `403 FORBIDDEN`. Re-binding requires a `platform_operator`-gated route (`POST /admin/users/{user_id}/oauth-identities/rebind`, future addition) that creates an audit-trail-bearing re-link explicitly. Silent re-bind would let an IdP-side `sub` reissue (account migration, takeover) silently inherit an existing Console identity.
9. Issue the JWT pair (§5.2).

**OIDC materialization (step 4, user missing).** Runs inside the same database transaction as the rest of the login:

- Enforce the entity's `users` quota (§3.13) before insert. On exhaustion, return the uniform `403 FORBIDDEN` from this section — NOT `QUOTA_EXCEEDED` with `details` — so an unauthenticated caller cannot learn headroom.
- `INSERT` a `users` row: `email` from the claim; `name` from the IdP `name` claim when present and non-blank, otherwise the local-part of `email`; `entity_id` from step 3. No `user_permissions` or `profile_users` rows.
- Emit one `USER_REGISTERED` audit row with `actor_id = user.id` (self-provisioned).
- On `UniqueViolationError` (concurrent first logins for the same email), re-fetch the user by email and continue if the row is active and domain-consistent; otherwise `403 FORBIDDEN`.
- Re-registration after **erasure** (§7.22): the tombstoned row frees the email slot; materialization inserts a fresh `user_id` with no resurrected permissions or memberships.

The `403` paths in steps 3–6 are the boundary that prevents an attacker who controls a Google account at an unrelated domain from logging into the Console. All `403` responses on this route MUST share the same body shape so the response does not leak which step failed (T-9): `{"error": {"code": "FORBIDDEN", "message": "Account is not authorized for this Console", "details": {}, "request_id": "..."}}`.

### 5.7 Service-principal bearer tokens

Per-principal opaque random secrets, one per `(principal_id, purpose)` pair, returned exactly once at issuance and persisted only as SHA-256 hashes.

#### Issuance and storage

- Each token is a 256-bit random secret from `secrets.token_urlsafe(32)`.
- Stored as `service_principal_tokens(id UUID PK, principal_type TEXT, principal_id UUID FK, purpose TEXT, token_hash TEXT NOT NULL UNIQUE, issued_at TIMESTAMPTZ, expires_at TIMESTAMPTZ NULL, deleted_at TIMESTAMPTZ NULL, deleted_by UUID NULL)`. The combination `(principal_type, purpose)` is a typed enum; `(principal_id, purpose) WHERE deleted_at IS NULL` is partially-unique (one live token per purpose).
- The plaintext is returned exactly once via the issuing route's `Operation.result` on first read (§3.7, §3.8). The Console MUST NEVER return the plaintext via any read route.

#### Authentication

`SHA-256(presented_token)` is matched against `service_principal_tokens.token_hash` with a B-tree index. The implementation MUST additionally:

- Verify `(principal_type, purpose)` match the route's expectation; mismatch is `401 UNAUTHORIZED` (T-2 across purposes).
- Verify the token row is **live**, defined as `deleted_at IS NULL AND (expires_at IS NULL OR expires_at > now())`. Verify the parent principal row is `deleted_at IS NULL`. A bearer for a soft-deleted-or-expired token, or a soft-deleted parent, MUST fail authentication (defense in depth — the FK does not auto-cascade soft-delete). The same live-row predicate is reused by the unique index (§7.12) so the two cannot drift.
- The `revoked_tokens` table from §5.2 does **not** apply to service-principal bearers; their revocation is via soft-delete of either the token row or the parent.

#### Plaintext stash for Security CVM provisioning bearers

The Console acts as a deployer of the Security CVM during the provisioning saga (§8.4) and as a client to its `/ca.pem` endpoint (§10.4). At the provider-deploy step, the scheduler mints both `INGEST` and `CA_EXPORT` plaintexts in saga-local memory, persists their SHA-256 hashes to `service_principal_tokens`, and passes the plaintexts only through Phala's env-file mechanism. The `INGEST` plaintext is never written to the database. The `CA_EXPORT` plaintext is briefly stashed on the `security_cvms` row as `ca_export_token_plaintext` / `ca_export_token_stashed_at` so the saga can fetch `/ca.pem` and disclose that one-shot bearer after attestation.

- The CA-export stash is read by the provisioning saga's CA-fetch and finalise steps. The plaintext MUST NOT be copied into `operations.result` until after `verify_attestation` succeeds.
- The CA-export plaintext pair is nulled on success before the operation is marked `succeeded`; the only remaining plaintext copy is the one-shot `operations.result` payload governed by §3.8's first-read disclosure rule.
- If the saga is interrupted after hash insert and before provider deploy, the row stays `PROVISIONING`; the next deploy attempt rotates both bearer rows and uses freshly minted plaintexts.
- After the Security CVM token plaintext TTL (1 h hard expiry, T-2), the stash is unconditionally scrubbed even if the saga keeps failing — the row is "stuck" and the operator must re-provision.

#### Rotation

Security CVM provisioning and update sagas rotate `INGEST` and `CA_EXPORT` bearers as part of deployment rebinding. A future generic in-place rotation route (`POST /api/v1/entities/{id}/security-cvm/tokens/rotate`, future addition) is still reserved for operator-driven bearer rotation without a provider update.

When rotation lands, it MUST:

- Mint a new `(principal_id, purpose)` token, return the plaintext exactly once via `Operation.result`.
- Mark the old token row `deleted_at = now() + 5 minutes` (graceful overlap window).
- Refuse a second rotation against the same purpose while the previous overlap is still live.

#### Revocation

Decommissioning the parent (`DELETE /entities/{id}/security-cvm`, §3.7) soft-deletes the row and the token rows. Bearers presented after revocation MUST fail authentication.

### 5.8 Authorization header parsing

Every authenticated route MUST parse `Authorization` strictly:

- Header equals exactly `Bearer <token>` with one ASCII space and a non-empty token.
- Multiple spaces, leading or trailing whitespace, or a non-`Bearer` scheme MUST be rejected with `401 UNAUTHORIZED` (T-2). Implementations MUST use a strict split; libraries that accept whitespace-tolerant forms (e.g. Python's default `str.split(" ", 1)`) MUST NOT be used directly.

The same parsing rule applies to both Console JWTs (§5.2) and service-principal bearers (§5.7).

## 6. Authorization and permissions

The permission model the Console enforces. §3 cites a permission name per route; this section defines what each name grants and how the check is performed.

### 6.1 Scopes

Three scopes exist:

- **Platform.** Crosses every entity. The only platform-scoped permission today is `PLATFORM_OPERATOR`; it gates the `/admin/*` routes (§3.12) — `POST /admin/reconcile`, `POST /admin/sessions/revoke`, `POST /admin/keys/rotate` — and any future cross-tenant operator route.
- **Entity.** Bounded by `user.entity_id`. Most permissions are entity-scoped: a `USER_MANAGE` admin in entity A cannot manage users in entity B.
- **Profile.** Bounded by membership in `profile_users` (§7.7). Membership grants the right to **attach** the profile to a Dev CVM at launch or via `POST /cvms/{id}/profiles` (T-25, §3.6); detach is not gated on membership (a strict reduction is never an escalation). There is no profile-named permission row in `user_permissions` — membership is its own first-class scope.

Resource ownership rules:

- A `User` belongs to exactly one `Entity` (`User.entity_id`).
- A `Profile` belongs to exactly one `Entity` (`Profile.entity_id`).
- A `Dev CVM` belongs to exactly one `Entity` (`cvms.entity_id`) and is **owned by** exactly one `User` within that entity (`cvms.owner_id`, FK with `ON DELETE RESTRICT` so the user row cannot be hard-deleted while it owns CVMs; soft-delete is unaffected per §7.22). The owner is the caller of `POST /cvms` and is denormalised onto every `<CVM>` read (§2.3). A Dev CVM is also attached to one or more `Profile`s via `cvm_profiles` (M:N).
- A `Security CVM` belongs to exactly one `Entity` (`security_cvms.entity_id`); at most one live row per entity.
- An `SSH key` belongs to exactly one `User`.
- An `OAuth identity` belongs to exactly one `User`.

These ownership invariants are enforced at the database (foreign keys, §7) and re-checked at the API boundary by route-level same-entity checks.

### 6.2 Permission catalog

| Symbol | Scope | Gates |
|---|---|---|
| `CVM_LAUNCH` | entity | `POST /cvms` (§3.6). |
| `CVM_MANAGE` | entity | `POST /cvms/{id}/actions/{start,stop,terminate}` on another user's CVM (§3.6); owners may start, stop, and terminate their own CVMs without this permission. `POST /cvms/{id}/profiles` and `DELETE /cvms/{id}/profiles/{profile_id}` (attach / detach, §3.6) — attach additionally requires the caller to be a member of the target profile (T-25). Broadens the result of `GET /cvms` and `GET /cvms/{id}` to every CVM in the entity (default scope is "owned by caller"). |
| `SECURITY_CVM_CONFIGURE` | entity | `POST`, `GET`, `DELETE` on `/entities/{id}/security-cvm` (§3.7). |
| `TRAFFIC_LOGS_VIEW` | entity | `GET /traffic-logs` (§3.11). |
| `AUDIT_VIEW` | entity | `GET /audit/events` (§3.9). |
| `AUDIT_EXPORT` | entity | `POST /audit/export` (§3.10). Distinct from `AUDIT_VIEW` because bulk export is a different capability than reading recent events: it produces a stand-alone artifact that survives outside the Console (T-21). |
| `USER_MANAGE` | entity | User and profile administration: `GET / POST /entities/{id}/users` (§3.3); `POST /entities/{id}/users/{user_id}/actions/deactivate` and `…/actions/reactivate` (§3.3) — the routine offboarding pair; `POST / DELETE /profiles/{id}/users` (§3.4); `PATCH / DELETE /profiles/{id}` (§3.4); `POST /entities/{id}/profiles` (§3.3). Broadens `GET /entities/{id}/profiles` to every profile in the entity (default scope is the caller's memberships). **Does NOT cover** `DELETE /entities/{id}/users/{user_id}` (user erasure) — erasure is gated by self or `PLATFORM_OPERATOR` (§3.3, §11.9). |
| `PERMISSION_MANAGE` | entity | `POST /users/{id}/permissions` and `DELETE /users/{id}/permissions/{permission}` (§3.5). Additionally required when `POST /entities/{id}/users` is called with a non-empty `permissions` list (T-14). |
| `QUOTA_MANAGE` | entity | `PATCH / DELETE /users/{id}/quotas/{resource}` (§3.13) — set or clear per-user quotas within the entity. Cannot raise a user's quota above the entity's quota; that requires `PLATFORM_OPERATOR` (§3.13). Distinct from `USER_MANAGE` so a user-management admin who can register new accounts cannot also lift the resource limits the platform operator imposed. |
| `PLATFORM_OPERATOR` | platform | `POST /entities` (§3.3), `POST /admin/reconcile` (§3.12), `POST /admin/sessions/revoke` (§3.12), `POST /admin/keys/rotate` (§3.12), `PATCH / DELETE /entities/{id}/quotas/{resource}` (§3.13), and any future cross-tenant `/admin/*` route. |

`USER_MANAGE` and `PERMISSION_MANAGE` are deliberately split (T-14). A `USER_MANAGE`-only admin can administer users but cannot grant permissions, and in particular cannot mint a puppet user holding `PERMISSION_MANAGE` to self-escalate (`POST /entities/{id}/users` enforces this when `permissions` is non-empty).

`PLATFORM_OPERATOR` is held by a small set of operators across the platform. Tenant admins MUST NOT hold it. Granting it MUST be possible only via direct database write or a `platform_operator`-only route (the spec does not currently expose such a route; `bootstrap` is the only path); the Console MUST refuse to grant `PLATFORM_OPERATOR` via `POST /users/{id}/permissions` (`403 FORBIDDEN` with `details.required="self_grant_forbidden"`).

### 6.3 Enforcement order

The check order on every protected route is:

1. **Authentication** (§5.2). Token shape, signature, claims, freshness, revocation. Failure ⇒ `401 UNAUTHORIZED`.
2. **User reachability.** The `sub` claim resolves to a non-soft-deleted `User` whose `entity_id` matches the JWT's `entity_id` claim. Failure ⇒ `401 UNAUTHORIZED` (a JWT for a removed or relocated user is a stale token, not a permission failure).
3. **Permission.** The user's grants are reloaded from `user_permissions` (§5.3) and the route's required permission is asserted. Failure ⇒ `403 FORBIDDEN` with `details.required = <symbol>`.
4. **Scoping.** The target resource's ownership chain is verified against the caller's entity. Failure ⇒ `404 NOT_FOUND` per §6.4.
5. **Quota** (creation routes only). The route resolves the effective limit (user override → entity override → default, §3.13) and counts live rows for the relevant scope (for CVMs, "live" excludes `TERMINATED` **and** `FAILED`; §3.13). For the Dev CVM disk quotas it instead sums `disk_size_gb` across live CVMs (`disk_gb_total`, checked for both user and entity) or compares the requested size to the cap (`disk_gb_per_cvm`); see §3.13. Failure ⇒ `403 FORBIDDEN` with `code="QUOTA_EXCEEDED"`, `details.{resource, scope, limit, current_usage}`. The check runs after permission so a caller without the right permission gets the standard `403 FORBIDDEN` without the quota body leaking the entity's headroom. `cvm.launch` serializes this step per-entity (a `pg_advisory_xact_lock` held for the launch transaction) so concurrent launches cannot both pass against a stale count/sum (§3.13); the other creation routes rely on the per-key idempotency lock (§2.6) alone.
6. **Invariants.** Route-specific business rules (e.g. "cannot decommission a Security CVM while live Dev CVMs exist"). Failure ⇒ `409 CONFLICT` with `details.state = <named state>`.
7. **Optimistic concurrency** (§2.8). If `If-Match` is required or supplied, the resource's current ETag is compared. Failure ⇒ `412 PRECONDITION_FAILED`.
8. **Action.** The mutation runs, audit rows are written, the response is built.

A failure at any earlier step short-circuits the response; later steps do not run, so a `403` response cannot leak whether the resource exists.

### 6.4 Existence non-leak rule

For any route that accepts a resource id in its path (`/cvms/{id}`, `/profiles/{id}/...`, `/users/{id}/...`, `/me/keys/{id}`, `/operations/{id}`, etc.), the response status MUST be identical for "the resource does not exist" and "the resource exists in another tenant the caller cannot see". Both MUST collapse to `404 NOT_FOUND` (T-8). A `403` distinguishing the two would let an attacker enumerate resource UUIDs across tenants.

Exception: **`/entities/{id}` and `/entities/{id}/...`** check the caller's entity *before* loading any row, so the response is `404 NOT_FOUND` for any `entity_id` other than the caller's, regardless of whether that entity exists. The check is a property of the JWT (caller's `entity_id`), not the database, so there is no leak even though the predicate is identity-based.

The implementation MUST verify this property route-by-route under the §19 conformance suite.

### 6.5 Implicit permissions

Any logged-in user, regardless of granted permissions, MAY:

- Read their own identity (`GET /me`, §3.2).
- List, add, and remove their own SSH keys (`GET / POST / DELETE /me/keys[/...]`, §3.2).
- Read the entity they belong to (`GET /entities/{id}` for their own `entity_id`, §3.3).
- List the profiles they are members of (`GET /entities/{id}/profiles` without `USER_MANAGE` returns the caller's memberships only, §3.3).
- Read Dev CVMs they own (`GET /cvms`, `GET /cvms/{id}` for owned CVMs, §3.6).
- Read the operations they themselves submitted (`GET /operations/{id}` when `operation.actor_id == caller.user_id`, §3.8).
- **Erase themselves** (`DELETE /entities/{id}/users/{user_id}` when path `user_id == caller.user_id`, §3.3). The data subject's own GDPR Article 17 right; no `PLATFORM_OPERATOR` escalation required for self-erase. Their CVMs MUST be terminated first (§8.1), which they can do via the implicit `cvm.terminate` grant on owned CVMs (§3.6).

These implicit grants are not represented as `user_permissions` rows; they fall out of route logic that distinguishes "scoped to caller" from "scoped to entity by permission". Revoking every permission from a user does NOT lock them out of `/me` or their own keys. Still, users can be deactivated by admins in case of emergencies to prevent them from acting on the platform.²²

### 6.6 Granting and revoking permissions

A grant is an `INSERT` into `user_permissions` keyed on `(user_id, permission)`. A revoke is a `DELETE`. Both operations:

- Are gated by `PERMISSION_MANAGE` (§3.5).
- Require the target user to be in the caller's entity; cross-tenant grants return `404` (§6.4).
- Refuse `PLATFORM_OPERATOR` as the granted permission (`403 FORBIDDEN` with `details.required="self_grant_forbidden"`); platform-wide privilege escalation MUST go through a dedicated platform-operator-only path.
- Are idempotent: granting an already-held permission is a no-op (the response returns the current full set), revoking an absent permission is a no-op (the response is `204`).
- Require `If-Match` (§2.8) so concurrent admin actions on the same user serialise (T-14 race protection).
- Write an audit row per *newly* granted or actually-revoked permission (§11).
- Take effect on the **next request** the affected user makes, because §5.3 reloads permissions from the database on every request (T-15). For compromise response, `POST /admin/sessions/revoke` (§3.12) immediately invalidates outstanding access tokens.

A user creation flow (`POST /entities/{id}/users` with a non-empty `permissions` body, §3.3) writes a row per permission in the same transaction as the user insert. Audit rows are emitted in the order: `USER_REGISTERED`, then one `PERMISSION_GRANTED` per permission.

## 7. Data model

The persistent state the Console owns. Each subsection below defines one table — column types, constraints, and indexes are normative.

### 7.1 Conventions

- **Primary keys.** Every aggregate row has a UUID v4 primary key (`PG_UUID(as_uuid=True)`, generated client-side). Association tables use composite PKs over their FKs.
- **Timestamps.** `created_at` is set on insert via the `TimestampMixin`; rows whose representation includes a "last write" field carry `updated_at` with `onupdate=utcnow`. Every timestamp column is `TIMESTAMP WITH TIME ZONE`.
- **Soft delete.** The `SoftDeleteMixin` adds `deleted_at` (nullable timestamp) and `deleted_by` (nullable FK to `users.id`). Append-only tables (`audit_events`, `traffic_logs`, `audit_anchors`) and ephemeral tables (`revoked_tokens`, `idempotency_keys`, `device_flow_pending`, `loopback_auth_pending`, `operations`) do NOT carry the soft-delete columns; they are hard-pruned by `expires_at`-driven jobs (§11.8, §15.6).
  - **Read invisibility (property).** Read paths that surface "live" rows MUST filter `deleted_at IS NULL`. The spec mandates this as a property of every protected route in §3 and every internal query, not as a specific implementation mechanism. §19.4 includes a conformance test that fuzzes every read endpoint against a soft-deleted target and asserts invisibility.
  - **`updated_at` bump (ETag-bearing tables only).** Tables that surface `updated_at` in their resource representation (today: `cvms`, `entity_profiles`, `security_cvms`) MUST bump it on soft-delete (the `onupdate=utcnow` default already does this). The row's ETag therefore changes at the moment of soft-deletion, so a stale `If-Match` against the pre-deletion ETag fails with `412 PRECONDITION_FAILED` rather than racing the delete. Tables that do NOT carry `updated_at` (`users`, `ssh_keys`, `service_principal_tokens`, `oauth_identities`) are not ETag-bearing in v1; their soft-delete does not have an ETag-race concern.
  - **Cascade `deleted_by`.** When soft-deletion of one row cascades to dependents in the same transaction (§7.22), every cascaded row's `deleted_by` MUST be set to the actor that triggered the parent action — NOT the parent row's id and NOT NULL. The audit chain is therefore "actor Y → parent X soft-delete → dependent Z cascade" and any `deleted_by` lookup yields Y.
  - **Audit / forensic reads** MAY include soft-deleted rows (e.g. `audit_events` queries that join `users` to render `actor_email` for a soft-deleted user). The query MUST opt in explicitly; default scope is live-only.
- **Foreign keys.** The `ON DELETE` policy is intentional and specified per table below. Aggregate-to-actor FKs use `SET NULL` (so soft-deletion of the actor doesn't cascade away the audit trail); aggregate-to-aggregate FKs use either `CASCADE` (composition: child cannot exist without parent) or `RESTRICT` (referential lock: parent cannot be hard-deleted while children exist — soft-deletion of the parent does not fire it).
- **Enums.** `Permission`, `CVMState`, and `AuditAction` are stored as Postgres `ENUM` types (`permission`, `cvm_state`, `audit_action`) defined by Alembic migrations. Adding a value requires a new migration.
- **JSONB.** `cvms.metadata`, `security_cvms.metadata`, `audit_events.before`, and `audit_events.after` are JSONB. The schema does not constrain their shape — payload contracts are spec-level invariants enforced by the writer.

### 7.2 `entities`

Top-level tenant. Matched on user-email domain at login (§5.6).

The `deleted_at` / `deleted_by` columns are present on this table for forward compatibility with the `SoftDeleteMixin` (§7.1), but **soft-deleting an entity is undefined behaviour in v1**: no operational route exposes it, the §7.22 cascade table omits `entities`, and the spec makes no claim about what happens to the entity's users, profiles, CVMs, or audit rows when `entities.deleted_at` is set. Operators MUST NOT manually soft-delete entities via SQL today; entity removal is `out of scope` (§20).

**Domain is immutable after creation.** The future `PATCH /entities/{id}` route (§20) MUST NOT expose `domain` as a mutable field, and direct SQL `UPDATE entities SET domain = …` is a spec violation. Rationale: `domain` is the OIDC entry point (§5.6) AND the binding constraint for every `users.email` in the entity (§7.3 email-domain ↔ entity-domain invariant). Changing it in place would require rewriting every `users.email` (every existing OIDC `oauth_identities` row would no longer match the IdP-asserted email-domain), invalidating every outstanding session, and re-binding identities one-by-one. The supported pattern for a real domain change (rebrand, acquisition) is "create a new entity at the new domain, migrate users via the lost-admin recovery script (§17.5), decommission the old entity" — operationally heavier but at least every step is explicit and auditable.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `name` | `VARCHAR(200) NOT NULL` | Display name. |
| `domain` | `VARCHAR(255) NOT NULL UNIQUE` | Stored lowercase. The `find_by_domain` lookup is the entry point of `/auth/device/poll` (§5.6). **Immutable after creation** — see invariant below. |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |
| `deleted_at` | `TIMESTAMPTZ NULL` | Soft delete. |
| `deleted_by` | `UUID NULL FK users.id SET NULL` | |

### 7.3 `users`

Members of an entity. Email is globally unique among non-erased users, with the domain part forced to match the entity's `domain`.

A user is in one of three states, tracked by two nullable timestamp columns:

| State | `deactivated_at` | `deleted_at` | What it means |
|---|---|---|---|
| **Active** | NULL | NULL | Can log in, owns resources, has live permissions / memberships. |
| **Deactivated** | NOT NULL | NULL | Cannot log in (§5.6 step 5 refuses); permissions, memberships, and OAuth identities sit dormant; resources owned (CVMs, etc.) are preserved. Reversible via `POST /entities/{id}/users/{user_id}/actions/reactivate` (§3.3). |
| **Erased** | (any) | NOT NULL | The §3.3 erase procedure has run: PII fields tombstoned, dependents hard-deleted, audit rows redacted (§11.9). Irreversible. The row's `id` and `entity_id` survive for FK integrity (e.g. terminated `cvms.owner_id`); `email`, `name`, and `oauth_identities` are gone. |

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `entity_id` | `UUID NOT NULL FK entities.id CASCADE` | One entity per user. |
| `email` | `VARCHAR(320) NOT NULL` | Lowercased server-side. The domain part (`split(email, '@')[1]`) MUST equal `entities.domain` for the linked entity (validated at write time, see below). After erasure, replaced with the tombstone `'<erased-' || sha256(id)[:12] || '>@' || entity.domain` so the domain-match invariant remains satisfied on tombstoned rows. |
| `name` | `VARCHAR(200) NOT NULL` | Empty string allowed. After erasure, replaced with `'<erased>'`. |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |
| `deactivated_at` | `TIMESTAMPTZ NULL` | Set on `POST /actions/deactivate`; cleared on `POST /actions/reactivate`. |
| `deactivated_by` | `UUID NULL FK users.id SET NULL` | |
| `deleted_at` | `TIMESTAMPTZ NULL` | Set on the irreversible erase procedure (§3.3 `DELETE`). Once non-NULL, never cleared (the SoftDeleteMixin's `deleted_at` semantics shift from "removed" to "erased" for this table specifically). |
| `deleted_by` | `UUID NULL FK users.id SET NULL` | The actor that triggered erasure: the user themselves (self-erase) or a `PLATFORM_OPERATOR` (operator-driven). |

**Constraints.**

- Partial unique index `ux_users_email_live` on `(email) WHERE deleted_at IS NULL`. Email is globally unique among **non-erased** users — note this includes deactivated users, so a deactivated row holds the email slot until reactivation OR erasure. Erased rows fall out of the partial unique because their email is the tombstone (`<erased-…>@<domain>`), distinct from any live email at the same domain. The fresh registration of `alice@example.com` after Alice's erasure is therefore allowed.
- **Email-domain ↔ entity-domain match (service-layer invariant).** Every write to `users` (insert, reactivate, even the erasure tombstone) MUST satisfy `split(email, '@')[1].lower() == entities.domain` for the linked entity. The route boundary refuses with `422 VALIDATION_ERROR` (`details.errors[*].type="email_domain_mismatch"`); bootstrap refuses with exit `2`. The DB MAY add a CHECK constraint or trigger to enforce this directly; the spec REQUIRES service-layer enforcement and accepts the DB layer as defense-in-depth. The erasure tombstone format is constructed to satisfy this same invariant.

The domain-match invariant collapses the T-9 cross-entity enumeration defense into the structural form: a `tenant_admin` for entity A can only submit emails whose domain is A's domain, so they cannot probe for emails registered in entity B.

### 7.4 `user_permissions` (association table)

Authoritative source of truth for what each user can do. Reloaded on every protected request (§5.3).

| Column | Type | Notes |
|---|---|---|
| `user_id` | `UUID NOT NULL FK users.id CASCADE` | PK part 1. |
| `permission` | `ENUM permission` | PK part 2. Values: §6.2 (`CVM_LAUNCH`, `CVM_MANAGE`, `SECURITY_CVM_CONFIGURE`, `TRAFFIC_LOGS_VIEW`, `AUDIT_VIEW`, `AUDIT_EXPORT`, `USER_MANAGE`, `PERMISSION_MANAGE`, `QUOTA_MANAGE`, `PLATFORM_OPERATOR`). |

Composite PK on `(user_id, permission)`. No timestamps — grants and revokes are recorded in `audit_events`.

### 7.4a `entity_quotas`

Per-entity resource caps set by `PLATFORM_OPERATOR`. The default for any unset `(entity_id, resource)` pair is the global `DEFAULT_QUOTA_<RESOURCE>` config (§12). The presence of a row means the platform operator has overridden that default for this entity.

| Column | Type | Notes |
|---|---|---|
| `entity_id` | `UUID NOT NULL FK entities.id CASCADE` | PK part 1. |
| `resource` | `ENUM quota_resource NOT NULL` | PK part 2. Values: `dev_cvms`, `ssh_keys`, `users`, `profiles`, `disk_gb_per_cvm`, `disk_gb_total`. Adding a value is an Alembic migration (§15). |
| `limit_value` | `INT NOT NULL CHECK (limit_value >= 0)` | The max count of live rows scoped to this entity. `0` means "deny all creates of this resource for this entity"; the spec accepts `0` as a valid lockdown value. |
| `set_by` | `UUID NULL FK users.id SET NULL` | The platform operator who set the quota. |
| `set_at` | `TIMESTAMPTZ NOT NULL` | Last set; bumped on update. Surfaced in `<EntityQuota>` for audit. |

Composite PK on `(entity_id, resource)`. No soft-delete; clearing an override is `DELETE` (the row goes back to default-via-config). The `quota_resource` enum is intentionally narrow — quotas are for things users *create* that consume scarce resources; permission grants, refresh tokens, and audit reads are bounded by other mechanisms (§14.x).

### 7.4b `user_quotas`

Per-user resource caps set by `QUOTA_MANAGE` (entity admin) or `PLATFORM_OPERATOR`. Resolution order at every create call: `user_quotas[user_id, resource]` if present, else `entity_quotas[user.entity_id, resource]` if present, else the **per-user** default `DEFAULT_QUOTA_<RESOURCE>_PER_USER` from §12 (the per-entity default binds only the entity-scope resolution above, never a user's fall-through).

| Column | Type | Notes |
|---|---|---|
| `user_id` | `UUID NOT NULL FK users.id CASCADE` | PK part 1. |
| `resource` | `ENUM quota_resource NOT NULL` | PK part 2. Only resources whose scope is "user-level" are valid here — `dev_cvms`, `ssh_keys`, `disk_gb_per_cvm`, and `disk_gb_total` (enforced by a `CHECK` constraint, widened in §15). The entity-only resources (`users`, `profiles`) are refused with `400 VALIDATION_ERROR`. |
| `limit_value` | `INT NOT NULL CHECK (limit_value >= 0)` | The max count of live rows scoped to this user. MUST NOT exceed the effective entity quota at write time; the route refuses with `409 CONFLICT` (`details.state="user_quota_above_entity_quota"`) when it would. Note: the entity quota MAY later be lowered below an existing user quota — the spec does not retroactively clamp; instead, the next create call enforces the lower of (user, entity), which is then `entity_quota`. |
| `set_by` | `UUID NULL FK users.id SET NULL` | The actor who set the quota. |
| `set_at` | `TIMESTAMPTZ NOT NULL` | |

Composite PK on `(user_id, resource)`.

### 7.5 `oauth_identities`

Links a `User` to one or more upstream OIDC subjects. The schema permits multiple providers per user but at most one *live* identity per `(user_id, provider)` pair; this is the multi-provider story (e.g. user X is bound to one Google identity AND one Okta identity, but never two Google identities). Identities are NOT touched when the parent user is **deactivated** (§7.22); login is blocked by the user-active check in §5.6 step 5, so reactivation preserves the existing binding. Identities are hard-deleted when the parent user is **erased** (§3.3, §11.9); a re-bind via the `platform_operator`-gated route (§5.6 step 8) soft-deletes the old row and inserts a fresh row.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `user_id` | `UUID NOT NULL FK users.id CASCADE` | |
| `provider` | `VARCHAR(50) NOT NULL` | e.g. `google`, `okta`, `azure`. |
| `provider_subject_id` | `VARCHAR(255) NOT NULL` | The IdP's `sub`. **Immutable** after first link (T-3); §5.6 step 8. |
| `email` | `VARCHAR(320) NOT NULL` | The email asserted by the IdP at first link. Updated on subsequent logins. |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |
| `last_login_at` | `TIMESTAMPTZ NULL` | Set on every successful `/auth/device/poll` for this identity. |
| `deleted_at` | `TIMESTAMPTZ NULL` | Soft delete. **NOT touched** by user deactivation (login is gated at §5.6 step 5 directly); set only by an explicit re-bind admin path (future), or hard-DELETEd when the parent user is **erased** (§3.3, §11.9). |
| `deleted_by` | `UUID NULL FK users.id SET NULL` | |

Constraints (uniqueness scoped to **live** rows for forward compatibility with a future admin-driven re-bind — current paths only soft-delete an `oauth_identity` if and when that route lands):

- Partial unique index `ux_oauth_identities_provider_subject_live` on `(provider, provider_subject_id) WHERE deleted_at IS NULL` — a live IdP subject maps to exactly one Console user.
- Partial unique index `ux_oauth_identities_user_provider_live` on `(user_id, provider) WHERE deleted_at IS NULL` — a user has at most one live identity per provider.

§5.6 lookups (`oauth_identities` by `(provider, provider_subject_id)`) MUST filter `deleted_at IS NULL`; a hit on a soft-deleted row is treated as "no row" and falls through to the email-domain resolution path.

### 7.6 `entity_profiles`

A profile is a named, entity-scoped policy carrier. Profiles are attached to Dev CVMs via `cvm_profiles` (§7.7); a Dev CVM's effective policy is the field-typed merge of every attached profile's `policy`.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `entity_id` | `UUID NOT NULL FK entities.id CASCADE` | |
| `name` | `VARCHAR(200) NOT NULL` | |
| `description` | `VARCHAR(1000) NOT NULL` | Empty string allowed. |
| `policy` | `JSONB NOT NULL DEFAULT '{}'` | Profile policy. Active top-level keys are `egress_boundary`, `allowed_destinations`, `blocked_destinations`, `secret_patterns`, `secret_injections`, and `sandbox_env` (§2.3 `<Profile>`); unknown top-level keys are rejected before persistence. `secret_injections[*].value` MUST NOT be stored in this JSONB document. |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |
| `updated_at` | `TIMESTAMPTZ NOT NULL` | `onupdate=utcnow`. Bumped on every `PATCH /profiles/{id}` (§3.4). |
| `deleted_at` | `TIMESTAMPTZ NULL` | |
| `deleted_by` | `UUID NULL FK users.id SET NULL` | |

`UNIQUE(entity_id, name)`. The unique constraint is partial in spirit (only live rows count) — the spec REQUIRES the index `WHERE deleted_at IS NULL` so soft-deleted profiles do not block name reuse, mirroring §7.3's email rule.

### 7.6a `profile_secret_material`

Profile secret-injection values are write-only material encrypted outside `<Profile>.policy`.

| Column | Type | Notes |
|---|---|---|
| `profile_id` | `UUID NOT NULL FK entity_profiles.id CASCADE` | PK part 1. |
| `injection_id` | `VARCHAR(100) NOT NULL` | PK part 2. Matches `secret_injections[*].id`; ids are unique within a profile policy. |
| `ciphertext` | `TEXT NOT NULL` | AES-GCM envelope encrypted with `SECRET_INJECTION_KEK_B64`, AAD-bound to `(profile_id, injection_id)`. |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` | |
| `updated_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` | |

The Console strips `secret_injections[*].value` before writing `entity_profiles.policy`, upserts the corresponding encrypted rows here, and deletes rows for injections removed by policy replacement. A DB check constraint MUST reject `entity_profiles.policy` documents containing `secret_injections[*].value`, and active writes use `v2:` envelope format for `profile_secret_material.ciphertext`. User-facing profile reads MUST NOT return plaintext or ciphertext. Internal SC-control expands plaintext `value` only when rendering the Security CVM policy pull.

Current writes use Umbra AAD `umbra.profile_secret_material.v2:{profile_id}:{injection_id}`; `v2:` is the active envelope version for all new rows. Reads remain compatibility-only for legacy `v1:` ciphertext bound to the historical AAD `concrete.profile_secret_material.v1:{profile_id}:{injection_id}` until an explicit decrypt-and-re-encrypt migration completes.

`value_from` injections (§2.3) store nothing in this table — their material lives in `user_secret_material` (§7.6b) keyed by user, so policy replacement neither wipes nor rewrites it.

### 7.6b `user_secret_material`

Per-user, host-bound secret values referenced by profile `secret_injections[*].value_from` (§2.3) and resolved per CVM owner at SC-control materialization (§8.5). Managed exclusively through the self-service `/me/secrets` routes (§3.2).

| Column | Type | Notes |
|---|---|---|
| `user_id` | `UUID NOT NULL FK users.id CASCADE` | PK part 1. |
| `name` | `VARCHAR(100) NOT NULL` | PK part 2. Matches `^[A-Za-z0-9._:-]{1,100}$`; referenced by `value_from.user_secret`. |
| `ciphertext` | `TEXT NOT NULL` | AES-GCM envelope encrypted with `SECRET_INJECTION_KEK_B64` (same KEK as §7.6a), AAD `umbra.user_secret_material.v2:{user_id}:{name}` for active writes (`v2:` envelope). Legacy reads for historical `concrete.user_secret_material.v1:{user_id}:{name}` (`v1:` envelope) remain supported for migration only. |
| `allowed_hosts` | `JSONB NOT NULL` | Non-empty array (≤ 16) of host-binding patterns in the `DestinationRule.host` grammar: exact host, `*.suffix`, or `*`. DB check: array type. |
| `created_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` | |
| `updated_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` | |

Values are write-only: no route returns plaintext or ciphertext, and there is no admin or operator read path. The AAD binds each ciphertext to `(user_id, name)`, so material cannot be re-attributed to another user or name even with database write access. User erasure (§3.3) hard-deletes the target's rows in the erase transaction (users are soft-deleted, so the FK CASCADE alone would never fire).

### 7.7 Profile association tables

Two M:N tables anchored on profiles.

#### `profile_users`

User membership in a profile. Membership grants the right to attach the profile to a Dev CVM (T-25, §6.6).

| Column | Type | Notes |
|---|---|---|
| `profile_id` | `UUID NOT NULL FK entity_profiles.id CASCADE` | PK part 1. |
| `user_id` | `UUID NOT NULL FK users.id CASCADE` | PK part 2. |
| `added_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` | Membership creation time exposed by `GET /profiles/{profile_id}/users` and the CLI. |

Composite PK on `(profile_id, user_id)`.

#### `cvm_profiles`

Attachment of profiles to Dev CVMs (M:N, B3 pivot). Each row binds one CVM to one profile; the CVM's effective policy is the field-typed merge of every attached profile's policy (§8.5).

| Column | Type | Notes |
|---|---|---|
| `cvm_id` | `UUID NOT NULL FK cvms.id CASCADE` | PK part 1. |
| `profile_id` | `UUID NOT NULL FK entity_profiles.id RESTRICT` | PK part 2. `RESTRICT` so a profile cannot be hard-deleted while attachments exist; soft-delete is blocked at the service layer (§3.4 `DELETE /profiles/{id}` returns `409` when attached). |
| `attached_at` | `TIMESTAMPTZ NOT NULL` | When the row was inserted. |
| `attached_by` | `UUID NULL FK users.id SET NULL` | The actor who attached this profile. Used for audit attribution; soft-deleting the user does not remove the attachment. |

Composite PK on `(cvm_id, profile_id)`. The CVM-and-profile-belong-to-same-entity invariant is enforced at the API boundary (§3.6 attach route, T-4). Index on `profile_id` for `<Profile>.attached_cvms` rendering and for the policy-recompute query.

### 7.8 `ssh_keys`

User-owned SSH public keys.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `user_id` | `UUID NOT NULL FK users.id CASCADE` | |
| `label` | `VARCHAR(200) NOT NULL` | |
| `public_key` | `TEXT NOT NULL` | Raw OpenSSH-encoded public key. |
| `fingerprint` | `VARCHAR(128) NOT NULL` | Computed at insert. |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |
| `deleted_at` | `TIMESTAMPTZ NULL` | |
| `deleted_by` | `UUID NULL FK users.id SET NULL` | |

### 7.9 `cvms`

The Dev CVM aggregate. Profile attachments are M:N via `cvm_profiles` (§7.7). Shares a unified "Phala-deployed CVM" core with `security_cvms` (§7.11): same column set for `id`, `entity_id`, `state`, `fqdn`, `instance_type`, `region`, `metadata`, `compose_config`, DNS record ids, `error_reason`, lifecycle timestamps. Type-specific tail (`owner_id`, `security_cvm_id`) follows.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `entity_id` | `UUID NOT NULL FK entities.id RESTRICT` | Denormalised from `users.entity_id` so cross-entity scoping queries don't need a join. The launch saga MUST set this to `owner.entity_id`; the columns are kept in sync by service-layer invariant. |
| `state` | `ENUM cvm_state NOT NULL DEFAULT 'PROVISIONING'` | Lifecycle state (§8.3). |
| `fqdn` | `VARCHAR(253) NOT NULL UNIQUE` | The full DNS name where this CVM is reachable. Constructed at the saga's `persist_stub` step as `cvm-<token>.<CLOUDFLARE_BASE_DOMAIN>`, where `token = base32(secrets.token_bytes(16)).rstrip("=").lower()` (26 chars, 128 bits of entropy, **independent of `id`**). Stored on the row at provisioning so the value remains stable even if `CLOUDFLARE_BASE_DOMAIN` is later rotated — the row continues to identify what was actually deployed. The `UNIQUE` constraint catches DNS-collision at insert time before any external Cloudflare call (the 128-bit entropy makes collision astronomically unlikely; UNIQUE is defense-in-depth). The first DNS label (`cvm-<token>`) is **not** derivable from `id` — this prevents existence enumeration via DNS lookup against guessed UUIDs (T-8). The 253-char width matches the RFC 1035 total-FQDN limit; the route config also rejects generated FQDNs longer than 64 chars because the Phala shade cert-manager uses the FQDN as the X.509 Common Name. |
| `instance_type` | `VARCHAR(100) NOT NULL` | Operator-controlled abstraction (e.g. `tdx.small`). Indexable for capacity / billing queries. |
| `region` | `VARCHAR(64) NULL` | Operator-controlled abstraction; provider-agnostic at the column level. Defaults from `DEV_CVM_DEFAULT_REGION`, then `PHALA_REGION` (§12), when the request omits it. |
| `disk_size_gb` | `INT NULL` | Root disk size in GB, resolved at launch from the request or `DEV_CVM_DEFAULT_DISK_GB` (§12) and passed to the provider deploy. `NULL`-able for forward-compat; the launch route always writes a non-null value, and rows created before this column existed were backfilled to the current default (§15). Summed across live CVMs for the `disk_gb_total` quota, and the max is reported for `disk_gb_per_cvm` (§3.13). |
| `metadata` | `JSONB NOT NULL DEFAULT '{}'` | Provider-coupled identifiers that the operator does NOT query as primary access patterns. Provider-neutral keys are `provider`, `deployment_id`, and `status`; v1 Phala metadata may also carry adapter-private `app_id` and `gateway_host` for compatibility. Clients validate certificate and attestation identity against `cvms.fqdn` and use that FQDN as the TCP target, TLS SNI, and HTTP Host. The column type stays JSONB so a future provider migration doesn't require a schema change; the `provider` discriminator lets the Console dispatch on it. |
| `atls_policy_bundle` | `JSONB NULL` | Active per-CVM `<PolicyBundle>` used by `GET /cvms/{id}/policy-bundle` and rewritten after `cvm.launch` / `cvm.update` finalise. |
| `atls_policy_revision` | `BIGINT NOT NULL DEFAULT 0` | Monotonic revision of `atls_policy_bundle`. Bumped every time the active bundle is replaced. |
| `compose_config` | `TEXT NOT NULL DEFAULT ''` | Provider compose YAML. `${VAR}` placeholders only — actual env values are passed via the provider env-file at deploy/update and never persisted (env values are secrets — Dev CVM bearer plaintexts, SC CA — and have no spec-level reader once the deploy is complete). The YAML itself is non-sensitive. Updated only by the provider-neutral CVM update flow after a successful provider update. |
| `txt_dns_record_id` | `VARCHAR(100) NULL` | Cloudflare record id for the dstack-app-address TXT (`_dstack-app-address.<fqdn>` → `<metadata.app_id>:443`). DNS records are NOT Phala-coupled (Cloudflare is a separate provider) so this stays a first-class column. Populated at `cf_txt_create`. |
| `cname_dns_record_id` | `VARCHAR(100) NULL` | Cloudflare record id for the gateway CNAME (`<fqdn>` → `_.<metadata.gateway_host>`). Populated at `cf_cname_create`. |
| `error_reason` | `TEXT NULL` | Typed code from §10.5; normally set on `FAILED`. A preserved `SECURITY_CVM_REBIND_REQUIRED` may coexist with a live legacy row as a fail-closed replacement signal. The periodic Dev attestation reconciler excludes it both when claiming candidates and in the success/drift UPDATE predicates, so neither a normal probe nor a marker set concurrently during verification can clear or replace it. MUST NOT carry a secret (§14). |
| `expected_image_measurement` | `VARCHAR(96) NULL` | TDX MRTD the Console will accept for this Dev CVM. Populated at the launch saga's `persist_stub` step from `DEV_CVM_IMAGE_MEASUREMENT` in effect at deploy time, so a later config rotation does not flag this row's CVM as drifted (§10.4a). NOT NULL after step 2 of the launch saga. |
| `image_measurement` | `VARCHAR(96) NULL` | TDX MRTD actually reported by the Dev CVM's attestation, captured at the `verify_attestation` step (§8.3). Equals `expected_image_measurement` whenever the CVM is `RUNNING`. |
| `rtmr3_digest` | `CHAR(96) NULL` | SHA-384 of RTMR3 captured at the launch saga's `verify_attestation` step. Updated on each successful reconciler drift probe. |
| `attestation_verified_at` | `TIMESTAMPTZ NULL` | Most recent successful attestation verification (launch saga or reconciler refresh). |
| `owner_id` | `UUID NOT NULL FK users.id RESTRICT` | Type-tail: Dev CVMs are user-owned. Hard-delete of the user is refused; soft-delete (deactivation) is unaffected. |
| `security_cvm_id` | `UUID NULL FK security_cvms.id SET NULL` | Type-tail: the entity's Security CVM at launch time. NULL indicates "unattached"; the launch saga (§8.3) MUST set this to the entity's live Security CVM before transitioning out of `PROVISIONING`. |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |
| `updated_at` | `TIMESTAMPTZ NOT NULL` | `onupdate=utcnow`. Surfaced as `<CVM>.updated_at` (§2.3). |
| `deleted_at` | `TIMESTAMPTZ NULL` | |
| `deleted_by` | `UUID NULL FK users.id SET NULL` | |

Profile attachments live in `cvm_profiles` (§7.7). At least one `cvm_profiles` row MUST exist while the CVM is non-`TERMINATED` (§8.1, T-25); enforced at the service layer.

Dev CVMs and Security CVMs run in different Phala apps, so a Dev CVM's internal-network address is not a useful identifier at the SC: the SC sees only the public-gateway NAT'd source IP. Dev-CVM identity at the SC's mitmproxy is established by a per-CVM bearer (§7.11, `principal_type=dev_cvm`, `purpose=PROXY_AUTH`) carried in `Proxy-Authorization`, not by source-IP attribution. The schema therefore carries no internal-IP column.

Launch-time `compose_config` lives directly on this row rather than in a separate snapshot table; immutability post-launch is enforced at the service layer (no UPDATE path touches the column). This matches `security_cvms`'s shape, which similarly co-locates immutable attestation snapshots with mutable runtime state.

### 7.10 `cvm_ssh_keys` (association table)

Which SSH keys are installed on which Dev CVMs.

| Column | Type | Notes |
|---|---|---|
| `cvm_id` | `UUID NOT NULL FK cvms.id CASCADE` | PK part 1. |
| `ssh_key_id` | `UUID NOT NULL FK ssh_keys.id CASCADE` | PK part 2. |

### 7.11 `security_cvms`

The per-entity Security CVM. At most one live row per entity (§8.4). Shares the unified "Phala-deployed CVM" core with `cvms` (§7.9): same column set for `id`, `entity_id`, `state`, `fqdn`, `instance_type`, `region`, `metadata`, `compose_config`, DNS record ids, `error_reason`, lifecycle timestamps. SC-specific tail follows.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `entity_id` | `UUID NOT NULL FK entities.id CASCADE` | |
| `state` | `ENUM cvm_state NOT NULL DEFAULT 'PROVISIONING'` | Same lifecycle as Dev CVMs (§8.4) but the `STOPPED` value is unreachable for SCs in v1. |
| `fqdn` | `VARCHAR(253) NOT NULL UNIQUE` | The full DNS name where the SC's `:443` is reachable. Constructed at the saga's `persist_tokens_and_stub` step as `sc-<token>.<SECURITY_CVM_BASE_DOMAIN>`, where `token = base32(secrets.token_bytes(16)).rstrip("=").lower()` (26 chars, 128 bits of entropy, independent of `id`). Same shape and rationale as `cvms.fqdn` (§7.9): UNIQUE catches DNS collision; the slug-part doesn't reveal `id` (T-8 anti-enumeration); stored at provisioning so the value is stable across config rotation. The aTLS / `/tdx_quote` / `/ca.pem` endpoints used by the Console and CLI all derive from this value. |
| `instance_type` | `VARCHAR(100) NULL` | Operator-controlled abstraction. Per-launch flag; falls back to `PHALA_DEFAULT_INSTANCE_TYPE` (§12). |
| `region` | `VARCHAR(64) NULL` | Operator-controlled abstraction. Per-launch flag; falls back to `SECURITY_CVM_DEFAULT_REGION`, then `PHALA_REGION` (§12). |
| `metadata` | `JSONB NOT NULL DEFAULT '{}'` | Provider-coupled identifiers and the SC's generated atlas/shade aTLS policy. Provider-neutral keys are `provider`, `deployment_id`, `status`, `deploy_compose_yaml`, and `atls_policy`; v1 Phala metadata may also carry adapter-private `app_id` and `gateway_host` for compatibility. Verifiers validate the certificate and attestation identity against `security_cvms.fqdn` and use that FQDN as the TCP target, TLS SNI, and HTTP Host. `atls_policy` is the raw policy emitted by `shade policy generate` for `security_cvms.fqdn`; it carries no plaintext bearers and is injected into Dev CVMs as `SECURITY_CVM_ATLS_POLICY_B64` so the Dev egress forwarder can verify the entity SC before proxying. Same column type and provider-discriminator semantics as `cvms.metadata`. |
| `compose_config` | `TEXT NOT NULL DEFAULT ''` | Provider compose YAML rendered for the SC image. `${VAR}` placeholders only (env values flow through the provider env-file mechanism). Updated only by the provider-neutral Security CVM update flow after a successful provider update. |
| `txt_dns_record_id` | `VARCHAR(100) NULL` | Cloudflare record id for the dstack-app-address TXT (`_dstack-app-address.<fqdn>` → `<metadata.app_id>:443`). Populated at `cf_txt_create`. |
| `cname_dns_record_id` | `VARCHAR(100) NULL` | Cloudflare record id for the gateway CNAME (`<fqdn>` → `_.<metadata.gateway_host>`). Populated at `cf_cname_create`. |
| `error_reason` | `TEXT NULL` | Set on `FAILED`. Typed code from §10.5; MUST NOT carry a secret (§14). |
| `proxy_port` | `INT NULL` | SC-tail: the mitmproxy port the Security CVM listens on. |
| `ca_cert_pem` | `TEXT NULL` | SC-tail: the MITM CA cert PEM. NULL until the saga's CA-fetch step completes. |
| `ca_export_token_plaintext` | `VARCHAR(128) NULL` | SC-tail: temporarily stashed plaintext of the `CA_EXPORT` bearer (§5.7). |
| `ca_export_token_stashed_at` | `TIMESTAMPTZ NULL` | SC-tail: independent from `updated_at`. |
| `expected_image_measurement` | `VARCHAR(96) NULL` | SC-tail: the TDX MRTD the Console will accept for this SC. Populated at the saga's `persist_stub` step from `SECURITY_CVM_IMAGE_MEASUREMENT` (or per-entity override) in effect at deploy time, so a later config rotation does not flag this row's SC as drifted (§10.4). NOT NULL after step 2 of the provisioning saga. |
| `image_measurement` | `VARCHAR(96) NULL` | SC-tail: TDX MRTD actually reported by the SC's attestation, captured at the `verify_attestation` step (§8.4). Equals `expected_image_measurement` whenever the SC is in `RUNNING`. |
| `rtmr3_digest` | `CHAR(96) NULL` | SC-tail: SHA-384 of RTMR3 captured at provisioning. Updated on each successful drift probe. |
| `attestation_verified_at` | `TIMESTAMPTZ NULL` | SC-tail: most recent successful attestation verification. |
| `policy_version` | `BIGINT NOT NULL DEFAULT 0` | SC-tail: monotonic counter for the SC's overall pulled-state version (§8.5). Bumped when the SC's last-poll ETag matches the current state. Primarily diagnostic. |
| `last_policy_pull_at` | `TIMESTAMPTZ NULL` | SC-tail: internal observation timestamp of the most recent authenticated `/internal/sc-control/cvms` pull, including `304 NOT MODIFIED` polls. Used by `cvm.launch` `await_sc_pull`; not surfaced in `<SecurityCVM>` and does not bump `updated_at`. |
| `last_policy_pull_etag` | `VARCHAR(80) NULL` | SC-tail: ETag value returned on the most recent SC-control pull. Diagnostic only. |
| `last_policy_pull_entry_count` | `INT NULL` | SC-tail: number of Dev CVM control entries in the most recent SC-control response. Diagnostic only. |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |
| `updated_at` | `TIMESTAMPTZ NOT NULL` | `onupdate=utcnow`. Surfaced as `<SecurityCVM>.updated_at` (§2.3). |
| `deleted_at` | `TIMESTAMPTZ NULL` | |
| `deleted_by` | `UUID NULL FK users.id SET NULL` | |

**Constraint.** Partial unique index `ux_security_cvms_entity_id_live` on `(entity_id) WHERE deleted_at IS NULL` enforces "at most one live Security CVM per entity" (B3.1, T-26). Soft-deleted rows (failed provisioning attempts, previous generations) coexist for audit.

Provider-coupled identifiers (`app_id`, `gateway_host`) live in `metadata` JSONB rather than as first-class column names so a future provider migration changes the JSONB shape without a schema change. The DNS-friendly slug-part of the FQDN (`sc-<26-base32-random>`) is part of the stored `fqdn` value rather than a separate column; if a reader needs the bare label it is recoverable as `split(fqdn, '.', 1)[0]`.

### 7.12 `service_principal_tokens`

Hashed bearers for any `service_principal` (§4.2). The table is generalised across principal types (§4) — today's principals are Security CVMs and Dev CVMs.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `principal_type` | `ENUM service_principal_type NOT NULL` | Values: `security_cvm`, `dev_cvm`. The `dev_cvm` value is for per-Dev-CVM bearers (§7.9, §10.4). |
| `principal_id` | `UUID NOT NULL` | FK target depends on `principal_type`. For `security_cvm`, references `security_cvms.id` with `ON DELETE CASCADE`. For `dev_cvm`, references `cvms.id` with `ON DELETE CASCADE`. The migration MUST add a CHECK constraint or trigger validating referential integrity for each `principal_type`. |
| `purpose` | `ENUM service_principal_token_purpose NOT NULL` | Values: `INGEST`, `CA_EXPORT` (both Security-CVM-only), `PROXY_AUTH` (Dev-CVM-only — the `Proxy-Authorization` bearer presented by the Dev CVM to the entity's SC at every outbound proxied request, §10.4), and `DEV_CONTROL` (Dev-CVM-only — the bearer presented to Dev-control Console routes such as SC aTLS policy refresh). |
| `token_hash` | `VARCHAR(128) NOT NULL UNIQUE` | `SHA-256(plaintext)` hex-encoded. |
| `issued_at` | `TIMESTAMPTZ NOT NULL` | |
| `expires_at` | `TIMESTAMPTZ NULL` | NULL means "live until the parent is decommissioned". A future timestamp means "live until then" — used for graceful rotation overlap (see below). Auth (§5.7) MUST treat the row as live when `deleted_at IS NULL AND (expires_at IS NULL OR expires_at > now())`. |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |
| `deleted_at` | `TIMESTAMPTZ NULL` | Hard tombstone: a row with `deleted_at <= now()` MUST fail authentication. The previous-draft "future-dated `deleted_at` for overlap" idea was incorrect because auth's `deleted_at IS NULL` predicate kills any non-NULL value immediately; overlap is now expressed via `expires_at`. |
| `deleted_by` | `UUID NULL FK users.id SET NULL` | |

Partial unique index `ux_service_principal_tokens_live_purpose` on `(principal_type, principal_id, purpose) WHERE deleted_at IS NULL AND (expires_at IS NULL OR expires_at > now())` enforces "at most one live token per `(principal, purpose)`". Graceful overlap during rotation (§5.7) is implemented by setting the old row's `expires_at = now() + 5 minutes` (the row stays `deleted_at IS NULL` so auth still accepts it during the window) and inserting the new row with `expires_at = NULL`. The partial index includes both predicates so the two rows coexist briefly without violating uniqueness; once the old row's `expires_at` passes, it falls out of the partial index and `deleted_at` is set in a follow-up sweep (best-effort; auth rejects expired rows even when `deleted_at` lags).

A live-row predicate (used by both auth and the unique index) is therefore: `deleted_at IS NULL AND (expires_at IS NULL OR expires_at > now())`. This MUST be the only definition of "live" used anywhere in the spec; using one form in the index and another in auth would let the two drift and break the rotation overlap.

### 7.13 `revoked_tokens`

The denylist for revoked Console JWTs (§5.2 revocation, T-2).

| Column | Type | Notes |
|---|---|---|
| `jti` | UUID | PK. The `jti` claim of the revoked JWT. |
| `expires_at` | `TIMESTAMPTZ NOT NULL` | The `exp` of the revoked JWT. Once `expires_at < now()`, the row is no longer load-bearing (the token is expired anyway). |
| `revoked_at` | `TIMESTAMPTZ NOT NULL` | When the row was inserted. |
| `revoked_by` | `UUID NULL FK users.id SET NULL` | The actor that triggered revocation; NULL for self-logout. |

Index on `expires_at` for the daily prune job. Per §5.2, rows are deleted when `expires_at < now() - INTERVAL '1 day'` so the table stays bounded.

### 7.14 `refresh_tokens`

Refresh tokens issued to users (§5.2). One row per *issuance* — login produces a root row, `/auth/refresh` produces a child row, etc. Each row is paired with the access-token JTI it issued so that admin and replay-driven revocation can enumerate the access JTIs to insert into `revoked_tokens` (§7.13).

| Column | Type | Notes |
|---|---|---|
| `jti` | UUID | PK. The unique id of this refresh token. |
| `user_id` | `UUID NOT NULL FK users.id CASCADE` | |
| `token_hash` | `TEXT NOT NULL UNIQUE` | `SHA-256(plaintext)` hex-encoded. |
| `family_id` | `UUID NOT NULL` | Identifies the rotation family. The root sets `family_id = jti`; children inherit. Index on `(family_id)` so "revoke the whole family" is a single index seek (vs `WITH RECURSIVE` on `parent_jti`). |
| `parent_jti` | `UUID NULL FK refresh_tokens.jti SET NULL` | The refresh token that produced this one. Useful for forensic reconstruction of the rotation chain; not load-bearing for revocation, which uses `family_id`. NULL for the root. |
| `access_jti` | `UUID NOT NULL UNIQUE` | The `jti` of the access token issued together with this refresh token. Single-valued because each issuance produces exactly one access token; used by `POST /admin/sessions/revoke` (§3.12) and by refresh-reuse detection (§5.2) to enumerate the access-token JTIs that need to land in `revoked_tokens`. |
| `access_expires_at` | `TIMESTAMPTZ NOT NULL` | The `exp` of the paired access token. The same value goes into `revoked_tokens.expires_at` when this access token is revoked. |
| `issued_at` | `TIMESTAMPTZ NOT NULL` | |
| `expires_at` | `TIMESTAMPTZ NOT NULL` | The refresh token's own expiry. |
| `redeemed_at` | `TIMESTAMPTZ NULL` | Set when the token is exchanged for a new pair. Single-use rotation. |
| `revoked_at` | `TIMESTAMPTZ NULL` | Set on logout, family revocation (§5.2 — re-redemption invalidates the family), or admin-driven revocation. |
| `ip_address` | `VARCHAR(45) NULL` | Caller IP at issuance, surfaced in `AUTH_REFRESH_REUSE_DETECTED` audit rows (§11.2) for replay-vs-original IP comparison. |
| `request_id` | `VARCHAR(128) NULL` | The `X-Request-Id` of the issuance request, surfaced in the same audit rows. |

Indexes: `(user_id, issued_at DESC)` for `POST /admin/sessions/revoke` predicates (e.g. `issued_before=T`, `user_id=X`); `(family_id)` for family revocation; `(expires_at)` for the daily prune.

### 7.15 Pending login state

Two tables, one per login flow (§5.4). Both replace previous in-process dictionaries so multi-process Console deployments are safe.

#### `loopback_auth_pending`

State for an in-flight loopback + PKCE flow (§5.4.1). One row per `/auth/authorize` call; deleted on `/auth/token` success or expiry.

| Column | Type | Notes |
|---|---|---|
| `state` | `VARCHAR(255) NOT NULL` | PK. The CLI-issued `state` parameter. |
| `client_id` | `VARCHAR(255) NOT NULL` | Validated against `OIDC_CLIENT_ALLOWLIST` at `/auth/authorize` (§3.1, §12). |
| `code_challenge` | `VARCHAR(128) NOT NULL` | PKCE `code_challenge`; `code_challenge_method` is always `S256`. |
| `redirect_uri` | `VARCHAR(255) NOT NULL` | The CLI's loopback URI; pinned to `^http://127\.0\.0\.1:[0-9]{1,5}/callback$`. |
| `idp_state` | `VARCHAR(64) NOT NULL UNIQUE` | The state value the Console sends to Google. The Console looks up the row by `idp_state` at `/auth/oidc/callback`. UNIQUE because it is the only rendezvous key on the IdP-callback path; collision (random 32-byte value, vanishing probability) MUST be impossible-by-construction so the callback cannot match the wrong pending row. |
| `idp_nonce` | `VARCHAR(64) NOT NULL` | The nonce the Console sends to Google; verified against the `id_token`'s `nonce` claim (§5.5). |
| `console_authz_code_hash` | `CHAR(64) NULL` | `SHA-256(console_authz_code)`. NULL until the IdP roundtrip completes; populated by `/auth/oidc/callback`. Partial unique index `ux_loopback_auth_pending_authz_code_live` on `(console_authz_code_hash) WHERE console_authz_code_hash IS NOT NULL` because this is the rendezvous key on the `/auth/token` exchange — same justification as `idp_state`. |
| `user_id` | `UUID NULL FK users.id SET NULL` | Resolved by `/auth/oidc/callback` after §5.6 completes. NULL until then. |
| `expires_at` | `TIMESTAMPTZ NOT NULL` | `created_at + 10 minutes`. |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |

Index on `idp_state` (for the IdP-callback lookup), `console_authz_code_hash` (for the token-exchange lookup), and `expires_at` (for cleanup).

#### `device_flow_pending`

State for an in-flight device flow (§5.4.2).

| Column | Type | Notes |
|---|---|---|
| `device_code` | `VARCHAR(255) NOT NULL` | PK. Issued by the IdP. |
| `polling_secret_hash` | `VARCHAR(128) NOT NULL` | `SHA-256(polling_secret)` so a DB read does not reveal the live binding secret. |
| `provider` | `VARCHAR(50) NOT NULL` | The OIDC provider name. |
| `expires_at` | `TIMESTAMPTZ NOT NULL` | From the IdP's `expires_in`. |
| `interval_seconds` | `INTEGER NOT NULL DEFAULT 5` | Polling interval returned by the IdP. Drives `slow_down` enforcement across Console workers and restarts. |
| `last_polled_at` | `TIMESTAMPTZ NULL` | Last time `/auth/device/poll` was called for this `device_code`. Drives the `slow_down` enforcement in §5.4. |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |

Index on `expires_at`.

### 7.16 `idempotency_keys`

Per-credential idempotency cache (§2.6).

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `credential_id` | `VARCHAR(128) NOT NULL` | The deduplication scope. For Console JWTs, `user.id`. For service principals, `principal_type + ":" + principal_id + ":" + purpose`. |
| `idempotency_key` | `VARCHAR(128) NOT NULL` | The header value. |
| `route` | `VARCHAR(255) NOT NULL` | Method + path (e.g. `POST /api/v1/cvms`). |
| `request_body_sha256` | `VARCHAR(64) NOT NULL` | Hex digest of the request body. |
| `response_status` | `INT NOT NULL` | The cached HTTP status. |
| `response_body` | `JSONB NULL` | The cached response body. NULL means the original response had no body (e.g. `204 No Content`); `{}` would be ambiguous against a literal empty-object body, so NULL is the only correct sentinel. |
| `response_headers` | `JSONB NOT NULL DEFAULT '{}'` | Headers required to faithfully replay (e.g. `Location`). |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |
| `expires_at` | `TIMESTAMPTZ NOT NULL` | `created_at + 24 hours` (§2.6). |

`UNIQUE(credential_id, idempotency_key, route)`. Index on `expires_at` for prune.

### 7.17 `operations`

The persistent representation of long-running operations (§8.2).

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `kind` | `VARCHAR(64) NOT NULL` | e.g. `cvm.launch`, `cvm.update`, `cvm.terminate`, `security_cvm.provision`, `security_cvm.update`, `audit.export`. |
| `status` | `ENUM operation_status NOT NULL DEFAULT 'pending'` | Values: `pending`, `running`, `succeeded`, `failed`, `cancelled`. |
| `actor_id` | `UUID NULL FK users.id SET NULL` | The `user.id` that submitted the operation. NULL only for system-driven operations (none today). |
| `actor_email` | `VARCHAR(320) NULL` | Denormalised for audit-trail attribution post-soft-delete. |
| `target_type` | `VARCHAR(50) NULL` | The aggregate type the operation targets (e.g. `cvm`, `security_cvm`). |
| `target_id` | `UUID NULL` | Set as soon as the aggregate row is committed by saga step 1 (may start NULL). |
| `idempotency_key` | `VARCHAR(128) NULL` | Bound by the submitting route's `Idempotency-Key`. |
| `request_body_sha256` | `VARCHAR(64) NULL` | Used for `(idempotency_key, body_hash)` deduplication. |
| `progress_step` | `VARCHAR(64) NULL` | The current saga step name. |
| `progress_percent` | `INT NULL` | 0..100. |
| `result` | `JSONB NULL` | Populated when `status = 'succeeded'`. Schema is `kind`-specific (§3.0). For `security_cvm.provision`, the one-shot CA-export plaintext is present at first read and replaced with `"<redacted-after-first-read>"` afterwards. |
| `result_disclosed_at` | `TIMESTAMPTZ NULL` | Set on first read of a `succeeded` result that contains one-shot fields. |
| `error` | `JSONB NULL` | Populated when `status = 'failed'` (`<Error>` shape from §2.4). |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |
| `updated_at` | `TIMESTAMPTZ NOT NULL` | `onupdate=utcnow`. |
| `expires_at` | `TIMESTAMPTZ NULL` | NULL while the operation is in-progress (`pending`, `running`); set to `now() + OPERATION_RETENTION_DAYS` (§12, default 30 d) at the transition into a terminal status (`succeeded`, `failed`, `cancelled`). The cleanup task only removes rows where `expires_at IS NOT NULL AND expires_at < now()` — so an in-progress row never expires regardless of how long it runs. |

Index on `(actor_id, created_at DESC)` for `GET /operations` listings (when added). Partial index on `status WHERE status IN ('pending', 'running')` for reconciler scans.

### 7.17a `audit_export_artifacts`

Redemption metadata for `audit.export` operation results (§11.5). The artefact bytes live in the configured export store; this table stores the immutable storage URI plus the Console-side one-shot download-token hash so the signed URL can be redeemed only once. Rows are pruned when the parent `operations` row expires.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `operation_id` | `UUID NOT NULL UNIQUE FK operations(id) ON DELETE CASCADE` | One artefact per export operation. |
| `storage_uri` | `TEXT NOT NULL` | Storage URI for the immutable artefact. For the production Postgres backend this is a sanitized `postgresql://host/db?table=...#objects/<urlencoded-key>` URI with credentials omitted. |
| `download_token_hash` | `VARCHAR(64) NOT NULL UNIQUE` | SHA-256 of the bearer token embedded in `Operation.result.download_url`. Plaintext token is never stored. |
| `content_type` | `VARCHAR(100) NOT NULL` | `text/csv; charset=utf-8` or `application/x-ndjson`. |
| `sha256` | `VARCHAR(64) NOT NULL` | SHA-256 of the artefact bytes returned in `Operation.result.sha256`. |
| `row_count` | `INT NOT NULL` | Number of audit rows materialised. |
| `byte_size` | `BIGINT NOT NULL` | Artefact byte length. |
| `expires_at` | `TIMESTAMPTZ NOT NULL` | Download URL expiry (`issued_at + 5 minutes`). |
| `redeemed_at` | `TIMESTAMPTZ NULL` | Set on the first successful signed-URL redemption. A non-null value makes later redemptions return `404`. |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |

### 7.18 `audit_events` (append-only, hash-chained)

The audit trail. No soft delete, no UPDATE, no DELETE on application paths. Each row carries `prev_hash` linking to the previous row's `row_hash`; the chain is anchored externally (§11.6) so tampering is detectable end-to-end (T-6).

**One narrow exception: GDPR redaction.** The right-to-be-forgotten procedure (§11.9) overwrites PII fields (`actor_email`, `before.email`, `after.email`) and re-anchors the chain forward from the redaction point. This procedure runs under a dedicated `umbra_console_redactor` Postgres role (§15.5) that holds `UPDATE` on a strict column allow-list and is gated by a separate "data protection officer" approval recorded in the audit trail. The application runtime role does NOT hold `UPDATE` and the spec REQUIRES the redactor role's grants are scoped to the named columns, never row-level deletes. The redaction is the only legitimate path that mutates an `audit_events` row; every other write is `INSERT`-only.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. Generated client-side. |
| `seq` | `BIGINT NOT NULL UNIQUE` | Monotonic sequence (Postgres `BIGSERIAL`). The hash chain follows `seq` ordering; `id` ordering is irrelevant. |
| `timestamp` | `TIMESTAMPTZ NOT NULL` | |
| `actor_id` | `UUID NULL FK users.id SET NULL` | NULL for system actors. |
| `actor_email` | `VARCHAR(320) NULL` | Denormalised; survives soft-delete of the user. |
| `action` | `ENUM audit_action NOT NULL` | §11.2 catalog. |
| `target_type` | `VARCHAR(50) NOT NULL` | e.g. `User`, `CVM`, `EntityProfile`, `Operation`. |
| `target_id` | `VARCHAR(100) NOT NULL` | Stringified PK. |
| `before` | `JSONB NULL` | Pre-mutation snapshot. MUST NOT contain secrets (§14.11). |
| `after` | `JSONB NULL` | Post-mutation snapshot. Same constraint. |
| `ip_address` | `VARCHAR(45) NULL` | Caller IP (§13.8). |
| `description` | `VARCHAR(200) NOT NULL DEFAULT ''` | Human-readable line. |
| `request_id` | `VARCHAR(128) NULL` | The `X-Request-Id` for the HTTP request that wrote this row, when applicable. |
| `prev_hash` | `CHAR(64) NOT NULL` | Hex SHA-256 of the previous row's `row_hash` (§11.6). For the first row, `prev_hash = SHA-256("")`. |
| `row_hash` | `CHAR(64) NOT NULL` | Hex `SHA-256(JCS({seq, id, entity_id, actor_id, actor_email, action, target_type, target_id, before, after, ip_address, description, request_id, timestamp, prev_hash}))`. |

Indexes: `actor_id`, `(target_type, target_id)`, `(action, timestamp)`, and `seq`.

### 7.19 `audit_anchors`

Periodic external anchors of the audit hash chain (§11.6). Each row is a checkpoint that an auditor can verify against an external append-only store.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `last_seq` | `BIGINT NOT NULL` | The `audit_events.seq` of the last row included in this anchor. |
| `last_row_hash` | `CHAR(64) NOT NULL` | The `row_hash` of that row. |
| `external_anchor_uri` | `TEXT NOT NULL` | Sanitized URI of the external commitment (`postgresql://host/db?table=...#anchors/<uuid>`, with credentials omitted). |
| `external_anchor_digest` | `CHAR(64) NOT NULL` | Hex SHA-256 of the bytes committed externally (which include `last_seq` and `last_row_hash`). |
| `anchored_at` | `TIMESTAMPTZ NOT NULL` | |
| `anchored_by` | `UUID NULL FK users.id SET NULL` | NULL for the system anchor task. |
| `redaction_event_seq` | `BIGINT NULL` | When set, this anchor checkpoints the hash chain **after** a GDPR redaction that began at this `audit_events.seq`; older anchors retain the pre-redaction `last_row_hash` for the same `seq` range (§11.9). |

### 7.20 `traffic_log_batches` (append-only batch ledger)

Per-batch deduplication ledger for `/internal/traffic-logs` (§4.3). Each successful batch ingest writes one row here; the unique constraint on `(security_cvm_id, idempotency_key)` is the per-principal replay defense. The constraint lives on this table rather than on `traffic_logs` so a batch can carry many entries (every entry shares the batch key) without violating the index.

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `security_cvm_id` | `UUID NOT NULL FK security_cvms.id CASCADE` | The principal that submitted the batch. |
| `idempotency_key` | `VARCHAR(128) NOT NULL` | The `idempotency_key` field from the request body (§4.3). |
| `request_body_sha256` | `CHAR(64) NOT NULL` | Body digest; lets the route distinguish "same key, same body" (idempotent replay → echo prior outcome) from "same key, different body" (collision → `409`, T-10). |
| `row_count` | `INT NOT NULL` | Number of `traffic_logs` rows written by this batch. |
| `accepted_at` | `TIMESTAMPTZ NOT NULL` | When the batch was committed. |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |

Partial unique index `ux_traffic_log_batches_idempotency` on `(security_cvm_id, idempotency_key)`. The `idempotency_key` here is the key for the **whole batch**, not per-row.

The reconciler MAY prune rows older than `TRAFFIC_LOG_RETENTION_DAYS` (§12) once their `traffic_logs` rows have been pruned; this table's retention follows `traffic_logs`.

### 7.21 `traffic_logs` (append-only)

Observations from Security CVMs (§4.3). No soft delete; no UPDATE; subject to retention pruning (§11.8). Each row is the per-entry record; batch-level dedup lives on `traffic_log_batches` (§7.20).

| Column | Type | Notes |
|---|---|---|
| `id` | UUID | PK. |
| `batch_id` | `UUID NOT NULL FK traffic_log_batches.id CASCADE` | The batch this row was ingested in. Lets a forensic query reconstruct the batch from any single row, and lets retention prune both tables in lockstep. |
| `timestamp` | `TIMESTAMPTZ NOT NULL` | |
| `security_cvm_id` | `UUID NOT NULL FK security_cvms.id CASCADE` | The Security CVM that observed the request. Denormalised from `traffic_log_batches.security_cvm_id` so the common tenant query doesn't join through batches. |
| `cvm_id` | `UUID NULL FK cvms.id SET NULL` | The Dev CVM the request originated from, when known. |
| `source_ip` | `VARCHAR(45) NOT NULL` | Stored as `VARCHAR(45)` (not `INET`) so non-canonical values from mitmproxy persist. |
| `destination_ip` | `VARCHAR(45) NOT NULL` | Same. |
| `destination_host` | `VARCHAR(255) NULL` | |
| `protocol` | `VARCHAR(20) NOT NULL` | |
| `port` | `INT NOT NULL` | |
| `method` | `VARCHAR(20) NULL` | |
| `path` | `VARCHAR(2000) NULL` | |
| `response_code` | `INT NULL` | |
| `decision` | `VARCHAR(64) NULL` | SC enforcement decision (`allowed` / block reason / `websocket_frame_dropped`); NULL for rows written before migration `0027` or by an SC that predates the field. Added in `0027_traffic_logs_decision`. |
| `bytes_transferred` | `BIGINT NOT NULL DEFAULT 0` | |
| `created_at` | `TIMESTAMPTZ NOT NULL` | |

Index on `(security_cvm_id, timestamp DESC)` for tenant queries; index on `(cvm_id, timestamp DESC)` when `cvm_id IS NOT NULL`; index on `batch_id` for batch reconstruction.

### 7.21a `instance_type_catalog` (singleton)

Last-known-good persistence of the provider instance-type catalog (§3.6a). Exactly one row (`CHECK (id = 1)`), upserted on every successful provider fetch and on the virgin-boot bootstrap seed; loaded into memory at startup so a restart never empties the catalog.

| Column | Type | Notes |
| --- | --- | --- |
| `id` | `SMALLINT PRIMARY KEY CHECK (id = 1)` | Singleton row. |
| `payload` | `JSONB NOT NULL` | The `InstanceType[]` list (§3.6a structures). |
| `fetched_at` | `TIMESTAMPTZ NULL` | Time of the last successful **provider** fetch; `NULL` for the bootstrap seed. Never rejuvenated by a DB load. |
| `source` | `TEXT NOT NULL` | `provider` or `bootstrap_fallback` at write time; served as `database` after a reload (except the bootstrap seed, which keeps its label). |
| `last_refresh_error` | `JSONB NULL` | `{kind, field, at}` of the most recent failed refresh, if any. |
| `updated_at` | `TIMESTAMPTZ NOT NULL DEFAULT now()` | |

### 7.22 Cross-cutting invariants

Some invariants are enforced at the database (constraint), some at the service layer (Python check), some at both. The spec mandates "both" wherever a service-layer-only invariant could be violated by a future code path that bypasses the service.

- **One live Security CVM per entity.** DB: partial unique index `ux_security_cvms_entity_id_live` (§7.11, B3.1).
- **At least one profile attached to every live Dev CVM.** Service-layer (§8.1, T-25). The DB does not constrain this; service-layer checks at `cvm.launch` and `DELETE /cvms/{id}/profiles/{profile_id}` enforce.
- **One live OAuth identity per `(user, provider)`.** DB: `UNIQUE(user_id, provider)` (§7.5).
- **Email globally unique among live users.** DB: partial unique `ux_users_email_live` on `(email) WHERE deleted_at IS NULL` (§7.3). Soft-deleted rows do not block reuse.
- **User email's domain matches the linked entity's domain.** Service-layer at every write (`POST /entities/{id}/users`, bootstrap, §5.6 OIDC materialization, lost-admin recovery script). The route refuses with `422` (`details.errors[*].type="email_domain_mismatch"`); the DB MAY add a CHECK / trigger as defense-in-depth. This invariant collapses email uniqueness, T-9 enumeration defense, and §5.6 OIDC resolution coherence into one rule: an email's domain identifies its entity, which identifies its user.
- **`entities.domain` is immutable after creation.** No application code path issues `UPDATE entities SET domain = …`. The future `PATCH /entities/{id}` route (§20) excludes `domain` from its allowed-fields list. A real domain change is "new entity + user migration + decommission old" (§7.2). Rationale: the email-domain match invariant above would otherwise cascade to every `users.email`, every `oauth_identities` row, every outstanding session — all of them would need rewriting in lockstep, which is operationally indistinguishable from creating a new entity anyway.
- **One live token per `(principal, purpose)`.** DB: partial unique `ux_service_principal_tokens_live_purpose` (§7.12).
- **The entity MUST have a live Security CVM before any Dev CVM can launch.** Service-layer (`POST /cvms` returns `409 CONFLICT` with `details.state="no_security_cvm"`). The DB MAY add a deferrable check; the spec does not require one.
- **A Security CVM cannot be decommissioned while live Dev CVMs exist in its entity.** Service-layer (`DELETE /entities/{id}/security-cvm` returns `409 CONFLICT`).
- **A profile cannot be soft-deleted while attached to live Dev CVMs.** Service-layer (`DELETE /profiles/{id}` returns `409 CONFLICT` with `details.state="cvms_attached"`).
- **A Dev CVM cannot detach its last profile while live.** Service-layer (`DELETE /cvms/{id}/profiles/{profile_id}` returns `409 CONFLICT` with `details.state="last_profile"`). Operators must terminate the CVM instead.
- **A user cannot be erased while owning live Dev CVMs.** Service-layer (`DELETE /entities/{id}/users/{user_id}` returns `409 CONFLICT` with `details.state="user_owns_cvms"`, §3.3). The user themselves (self-erase) or the platform operator (operator-driven erase) MUST terminate every owned CVM first. The DB does not enforce this; `cvms.owner_id RESTRICT` only fires on hard-delete and would be silent on tombstone update. **Deactivation has no such block** — it succeeds regardless of CVM ownership.
- **Cross-tenant references in `traffic_logs.cvm_id`.** Service-layer rejection in `/internal/traffic-logs` (§4.3, T-5). The DB does not constrain `traffic_logs.cvm_id` to belong to the same entity as `security_cvm_id`; if the rejection check were skipped, a compromised Security CVM could write rows pointing at any tenant's CVMs. A future migration MAY add a CHECK or trigger; until then, conformance §19 MUST verify the service-layer rejection per request.
- **Soft-delete transactional cascade.** No table cascades soft-deletion. Dependent rows MUST be soft-deleted in the same transaction as the parent. The mapping is fixed:
  - **User deactivation** (`users.deactivated_at = X`) ⇒ same transaction sets `refresh_tokens.revoked_at = X` for matching rows; outstanding access JTIs are inserted into `revoked_tokens` via the paired `access_jti` (§7.14). `oauth_identities`, `ssh_keys`, `user_permissions`, `profile_users`, and owned `cvms` are NOT touched (they return on reactivation). Login itself is gated by the user-active check in §5.6 step 5, not by mutating the OAuth-identity binding.
  - **User erasure** (`users.deleted_at = X`, irreversible) ⇒ `users` row tombstoned (PII fields replaced, see §3.3 / §7.3); same transaction hard-DELETEs `oauth_identities`, `ssh_keys`, `user_permissions`, `profile_users`, `refresh_tokens` for that user; under the `umbra_console_redactor` role (§15.5) `audit_events` PII columns are redacted per §11.9; the user's `cvms` rows already exist in `TERMINATED` (the §8.1 invariant blocks erasure otherwise) and keep `owner_id` pointing at the tombstoned row for FK integrity.
  - `entity_profiles.deleted_at = X` requires no dependents (the route refuses if any live CVM exists).
  - `security_cvms.deleted_at = X` ⇒ same transaction sets `service_principal_tokens.deleted_at = X` for that principal.
  - `cvms.deleted_at = X` ⇒ same transaction soft-deletes the CVM's `service_principal_tokens` rows (`principal_type=dev_cvm`, all purposes) so the SC's next pull no longer carries the `PROXY_AUTH` bearer mapping and Dev-control routes stop accepting the `DEV_CONTROL` bearer. The CVM's `cvm_profiles` and `cvm_ssh_keys` association rows are NOT touched: they survive in the database for audit reconstruction ("which profiles / keys was this CVM attached to when it was terminated?"). Future attach/detach is impossible because the CVM is `TERMINATED` (§3.6 returns `409 CONFLICT`). The DNS record ids on `cvms.txt_dns_record_id` / `cname_dns_record_id` are nulled by the terminate saga (§8.3) on successful Cloudflare cleanup; reconciler retries on failure (§9.2).
  - `entities.deleted_at = X` is **undefined behaviour** (§7.2). No cascade rule exists; the spec makes no claim about what happens.
- **Cascade actor attribution.** Every cascaded `deleted_by` MUST be the actor of the parent action — see §7.1's "Cascade `deleted_by`" rule.
- **Append-only tables (`audit_events`, `traffic_logs`).** No application code path issues `UPDATE` or `DELETE`. The spec REQUIRES this enforcement via Postgres role privileges (§15.5: the application role holds `INSERT` only on these tables). DELETEs by the prune job (§11.8) run with a separate, time-limited role.
- **Audit hash chain.** Every `audit_events` row's `prev_hash` MUST equal the `row_hash` of the row with the next-lower `seq` (or `SHA-256("")` if `seq = 1`). The spec REQUIRES a verification job (§19) that walks the chain end-to-end at least daily.

## 8. Resource lifecycle and operations

The state machines for the aggregates the Console manages, plus the uniform Operation contract that every async action submitted under §3 conforms to. State machines are described as invariants and transitions; sagas as preconditions, postconditions, and per-step compensation.

### 8.1 Dependency invariants

These cross-aggregate invariants are enforced both at the route boundary (§3) and in the saga step that mutates state. Conformance §19 verifies them through the test fixture.

- **Dev CVM requires the entity's Security CVM.** A Dev CVM cannot launch unless its entity has a live Security CVM (state ∈ {`PROVISIONING`, `RUNNING`}). The Security CVM is per-entity (B3.1, §7.11) — there is exactly one for the entire entity, shared by every Dev CVM.
- **Dev CVM requires ≥ 1 attached profile.** A live Dev CVM (state ∉ {`TERMINATED`}) MUST have at least one row in `cvm_profiles` (§7.7). The launch saga refuses an empty `profile_ids`; the detach route refuses the last detachment (T-25 — explicit policy is mandatory).
- **Security CVM blocked by live Dev CVMs.** The entity's Security CVM cannot transition to `TERMINATED` while live Dev CVMs exist anywhere in the entity (their traffic would have nowhere to route).
- **Profile blocked by attached CVMs.** A profile cannot be soft-deleted while attached to any live Dev CVM. Operators must detach first.
- **User deactivation is non-blocking on owned CVMs.** `POST /entities/{id}/users/{user_id}/actions/deactivate` (§3.3) succeeds regardless of the user's CVM ownership. The user's CVMs continue running; they simply lose self-service access. An admin with `CVM_MANAGE` handles them (terminate, transfer when that arrives) according to the org's policy. This matches the typical offboarding sequence: suspend access first, deal with resources at admin's pace.
- **User erasure blocked by owned live CVMs.** `DELETE /entities/{id}/users/{user_id}` (§3.3, §8.1) refuses with `409 CONFLICT` when the target owns one or more live Dev CVMs. The user (or admin acting for them via `CVM_MANAGE`) MUST `cvm.terminate` every owned CVM before erasure. Rationale: erasure is irreversible — auto-terminating would be silent data loss with no rollback. The `409` body lists `details.live_cvm_ids` truncated at 100 so the actor can address them.
- **User deactivation cascade** runs same-transaction (§7.22): only `users.deactivated_at` is set and `refresh_tokens.revoked_at` is bumped for matching rows. Outstanding access JTIs are inserted into `revoked_tokens` so in-flight access tokens fail. **`oauth_identities` is not touched** — login is refused by the explicit user-active check at §5.6 step 5, which keeps the OAuth-identity binding intact across deactivate / reactivate cycles. `cvm_profiles`, `user_permissions`, `profile_users`, `ssh_keys`, and owned `cvms` rows all survive untouched and return to operation on reactivation.
- **User erasure cascade** also runs same-transaction (§7.22): the user row is tombstoned (PII anonymized, FK targets preserved); `oauth_identities`, `ssh_keys`, `user_permissions`, `profile_users`, `refresh_tokens` for that user are hard-DELETEd; audit-row PII fields are redacted under the `umbra_console_redactor` role (§11.9, §15.5); terminated `cvms` rows keep `owner_id` referencing the tombstone for audit integrity.
- **Re-registration after erasure is a fresh user, not a resurrection.** Same semantics as the previous "re-registration after soft-delete" rule, just applied to the new terminal state. After erasure, `POST /entities/{id}/users` with the same email creates a fresh `user_id`; the email-domain invariant (§7.3) routes a future OIDC login to that fresh row; the previous incarnations' rows (tombstoned `users`, hard-deleted dependents) are gone or anonymized — nothing resurrects.
- **Re-registration after erasure is a fresh user, not a resurrection.** `POST /entities/{id}/users` with the same `email` after the previous holder was **erased** inserts a NEW row with a fresh `user_id` (the partial unique on `(email) WHERE deleted_at IS NULL` allows it because the erased row's email is the tombstone, not the original address). The new user starts from zero: no permissions resurrect (the previous user's `user_permissions` rows were hard-deleted at erasure), no profile memberships, no SSH keys, no CVM ownership (those CVMs were terminated before erasure per §8.1). On subsequent OIDC login, §5.6 binds `(provider, provider_subject_id)` to the new `user_id` via a fresh `oauth_identities` row. The audit trail is the only continuity, and the previous incarnation's PII has been redacted (§11.9); `actor_email` for old rows is the tombstone, `actor_id` survives but resolves to the tombstone user. Note that **deactivation does not produce a re-registration scenario** — the same `user_id` resumes on reactivation, with all permissions and memberships intact.

### 8.2 The Operation contract

Every async action submitted under `/api/v1` materialises an `<Operation>` resource (§7.17, §2.3) and returns it as `202`. Clients poll `GET /operations/{id}` (§3.8) until `status` reaches a terminal value.

#### Lifecycle

```
            submit
              │
              ▼
         ┌────────┐
         │pending │  ──── (no work yet started; queued)
         └────────┘
              │ scheduler picks up the row
              ▼
         ┌────────┐
         │running │  ──── (saga in progress; updated_at advances per step)
         └────────┘
            │      │       │
            │      │       │
            ▼      ▼       ▼
      succeeded  failed  cancelled
        (terminal — `expires_at = updated_at + 30 days`)
```

- `pending` → `running` is internal (the scheduler claims the row).
- `running` → `succeeded`: every step's postcondition holds; `result` is populated.
- `running` → `failed`: any step's postcondition fails; compensation runs; `error` is populated with an `<Error>` envelope (§2.4).
- `running` → `cancelled`: only for operations that document cancellability (none today). Reserved.

Terminal states are immutable: once `succeeded`, the operation row's `result` MUST NOT change (except the one-shot redaction described in §3.7); once `failed`, the `error` MUST NOT change.

#### Persistence and retention

Operations are rows in `operations` (§7.17). They survive a Console restart; the scheduler claims `pending`/`running` rows on boot and resumes (§9). Terminal operations are retained 30 days, then pruned by a daily cleanup task. Reading an expired operation returns `404 NOT_FOUND`.

#### Idempotency

Every submitting route requires `Idempotency-Key` (§2.6). The route persists `(idempotency_key, request_body_sha256)` on the operation row. A second submission with the same key and the same body returns the existing operation; with a different body returns `409 IDEMPOTENCY_CONFLICT`.

#### Concurrency

The scheduler (§9) claims `pending`/`running` rows with `SELECT ... FOR UPDATE SKIP LOCKED`. At most one worker runs an operation at a time. An interrupted operation (worker died mid-saga) is re-claimed on the next tick; sagas MUST be designed so each step is idempotent on re-entry (every step in §8.3 and §8.4 below has an explicit "if already done" short-circuit).

#### Saga step contract

Every saga is a sequence of typed steps. Each step has:

- A **name** (e.g. `"phala_deploy"`, `"cf_txt_create"`).
- A **precondition** asserted before the step runs.
- A **postcondition** written to the database before the step is considered complete.
- An **idempotent re-entry path** for when the worker died after the side effect but before the postcondition committed.
- A **compensation** that runs on saga failure, in reverse order.

Each step's commit boundary MUST be a single transaction. Steps NEVER hold a transaction across an external call — the call runs after a commit, and the result is captured in the next commit.

The scheduler MUST emit a structured log line for every step entry / exit (§13.2), including operation `id`, step `name`, and elapsed milliseconds.

### 8.3 Dev CVM lifecycle

#### State machine

| From | Trigger | To | Operation kind |
|---|---|---|---|
| (none) | `POST /cvms` | `PROVISIONING` | `cvm.launch` |
| `PROVISIONING` | launch saga succeeded | `RUNNING` | `cvm.launch` |
| `PROVISIONING` | launch saga compensated | `FAILED` | `cvm.launch` |
| `RUNNING`, `STOPPED`, `FAILED` | `POST /cvms/{id}/actions/update` succeeded | `RUNNING` | `cvm.update` |
| `RUNNING`, `STOPPED`, `FAILED` | `POST /cvms/{id}/actions/update` failed before finalise | unchanged or `FAILED` | `cvm.update` |
| `RUNNING` | `POST /cvms/{id}/actions/stop` | `STOPPED` | (synchronous) |
| `STOPPED` | `POST /cvms/{id}/actions/start` | `RUNNING` | (synchronous) |
| `RUNNING`, `STOPPED`, `FAILED` | `POST /cvms/{id}/actions/terminate` | `TERMINATED` | `cvm.terminate` |

Transitions outside this table MUST `409 CONFLICT`. Action verbs on already-target states are no-ops returning the current `<CVM>` for synchronous actions or a directly-`succeeded` operation for async terminate.

#### `cvm.launch` saga

Submitted by `POST /cvms` (§3.6).

| Step | Precondition | Action | Postcondition | On failure |
|---|---|---|---|---|
| 1. `validate` | The entity has a live Security CVM (§8.4). | Validate `profile_ids` is non-empty; every id belongs to the caller's entity AND the caller is a member of every profile via `profile_users` (T-25). Validate `ssh_key_ids` belong to the actor; resolve and validate `instance_type` and `region` using the §12 default chain. Compute the initial combined policy from the union of attached profiles' `policy` documents per §8.5. | (no DB write) | Operation → `failed`. |
| 2. `persist_stub` | Step 1 done. | Resolve `expected_image_measurement` from `DEV_CVM_IMAGE_MEASUREMENT` (§12) in effect at launch time. Mint `token = base32(secrets.token_bytes(16)).rstrip("=").lower()` (26 chars, 128 bits, independent of `cvms.id`, §7.9). Construct `fqdn = "cvm-" + token + "." + CLOUDFLARE_BASE_DOMAIN`. INSERT `cvms` with `state=PROVISIONING`, `entity_id`, `security_cvm_id`, `fqdn`, `expected_image_measurement`, `instance_type`, `region`, rendered `compose_config` (with `${VAR}` placeholders, no resolved env values), plus one `cvm_profiles` row per id in `profile_ids`. The `UNIQUE` constraint on `fqdn` catches collision; at 128 bits this is effectively impossible, but a `23505` violation MAY trigger one re-mint with a fresh `token`. Update `operations.target_id`. | `cvms.id` exists; `cvms.fqdn` is non-null and unique; `cvms.expected_image_measurement` is non-null; `cvm_profiles` rows exist; `operation.target_id` set. | Compensate: nothing to undo; mark operation `failed`. |
| 3. `phala_deploy` | Step 2 done; the Dev CVM bearers minted in step 4 are computed first so the deploy env can carry them (saga step ordering MAY interleave the local-DB step 4 mint before the external-call step 3 in the implementation; the table lists them in their logical commit order). Build the env dict locally — `SECURITY_CVM_FQDN`, `SECURITY_CVM_PROXY_PORT`, `SECURITY_CVM_PROXY_TOKEN` (the plaintext SC proxy bearer from step 4), `DEV_CVM_CONTROL_TOKEN` (the plaintext Console Dev-control bearer from step 4), `SECURITY_CVM_CA_CERT_B64`, `SECURITY_CVM_ATLS_POLICY_B64`, `AUTHORIZED_SSH_KEYS_B64`, `SANDBOX_ENV_PLACEHOLDERS_B64` — and pass it to Phala's deploy via the env-file mechanism. `SECURITY_CVM_ATLS_POLICY_B64` is the stored `security_cvms.metadata.atls_policy` from the entity SC; if absent, fail closed before deployment with `SECURITY_CVM_ATLS_POLICY_UNAVAILABLE`. The authoritative inventory lives in `docs/specs/dev-cvm.md` §2.3; the Console MUST inject every value the Dev CVM consumes, including the values whose SHA-256 digests appear in the RTMR3 binding (§10.4a). **The env dict is NOT persisted on the Console side** (§7.9): it would carry plaintext secrets and serves no spec-level reader. If `cvms.metadata->>'app_id'` is set (re-entry), call `phala.get_status` instead. Else call `phala.deploy`. Write `cvms.metadata = {"provider": "phala", "app_id": <id>, "gateway_host": <host>, "policy_bundle": <PolicyBundle>}`. The FQDN is the certificate, attestation, TCP target, TLS SNI, and HTTP Host identity. | `cvms.metadata->>'app_id'` is non-null. | Compensate steps 3..1; mark operation `failed`. The env dict (held in saga-local memory only) is zeroed before the saga returns. |
| 4. `mint_dev_bearers` | Step 3 done. | Mint the per-Dev-CVM `Proxy-Authorization` bearer (`secrets.token_urlsafe(32)`) and a separate Dev-control bearer for Console refresh reads. Hash both. INSERT `service_principal_tokens` rows for `principal_type=dev_cvm`, `principal_id=cvms.id`, `purpose=PROXY_AUTH` and `purpose=DEV_CONTROL`. The `PROXY_AUTH` plaintext is injected into Phala's deploy env as `SECURITY_CVM_PROXY_TOKEN`; the `DEV_CONTROL` plaintext is injected as `DEV_CVM_CONTROL_TOKEN`. | Both token rows exist with `deleted_at IS NULL`. | Compensate steps 4..1; mark operation `failed`. |
| 5. `cf_txt_create` | Step 4 done. | Look up TXT record at `_dstack-app-address.<cvms.fqdn>`. If a TXT with the expected content (`<cvms.metadata->>'app_id'>:443`) exists, reuse its id. Else `cf.create_txt`. Persist `txt_dns_record_id` to **`cvms`** (§7.9). | `cvms.txt_dns_record_id` is non-null. | Compensate steps 5..1; mark operation `failed`. |
| 6. `cf_cname_create` | Step 5 done. | Same shape for CNAME at `<cvms.fqdn>` → `_.<cvms.metadata->>'gateway_host'>`. Persist `cname_dns_record_id` to **`cvms`**. | `cvms.cname_dns_record_id` is non-null. | Compensate steps 6..1; **the TXT record from step 5 MUST be deleted** before the operation is marked `failed`. |
| 7. `verify_attestation` | Step 6 done. | Open an aTLS connection to `https://<cvms.fqdn>/tdx_quote` (the endpoint shade's `attestation-service` sibling container serves on every Dev CVM, §10.4a). Retry with exponential backoff for up to `DEV_CVM_ATTESTATION_TIMEOUT_SECONDS` (§12, default `180`) to absorb the Phala boot window. Materialize the complete Shade policy for the deployed compose and run atlas-rs verification over its authoritative `app_compose`, `expected_bootchain` (including the shared `cvms.expected_image_measurement` MRTD), `os_image_hash`, and RTMR3 JCS replay of the values injected in step 3. atlas-rs handles vendor-chain validation, freshness, and TLS-session report-data binding internally. Missing runtime-policy fields or any mismatch fail closed. On success persist `cvms.image_measurement = expected_image_measurement`, `cvms.rtmr3_digest`, `cvms.attestation_verified_at = now`. Emit `CVM_ATTESTATION_VERIFIED` audit row. | Persisted attestation columns are non-null and equal the expected values. | Compensate per the typed `error.code` (one of `ATTESTATION_FETCH_FAILED`, `ATTESTATION_QUOTE_INVALID`, `ATTESTATION_IMAGE_MISMATCH`, `ATTESTATION_RTMR_MISMATCH`, `ATTESTATION_SESSION_BINDING_INVALID`, §10.5). Compensate steps 7..1; per-CVM Dev bearer rows MUST be soft-deleted so a later boot cannot reuse them; mark operation `failed`. |
| 8. `await_sc_pull` | Step 7 done. | Wait for the entity's Security CVM to pick up the new Dev CVM via `GET /internal/sc-control/cvms` (§4.3). The Console compares the Dev CVM's live `PROXY_AUTH` `service_principal_tokens.created_at` to `security_cvms.last_policy_pull_at` and waits up to `SC_PULL_PROPAGATION_TIMEOUT_SECONDS` (§12, default `15`). Without this wait, the Dev CVM would boot and immediately try to proxy through an SC that hasn't learned its bearer yet, returning `407 Proxy Authentication Required` (fail-closed; §10.4). | The SC's most recent pull observation is on or after the new bearer's `created_at`. | If the timeout elapses, fail the operation with `SC_PULL_TIMEOUT`; if the live `PROXY_AUTH` row is missing, fail with `PROXY_AUTH_MISSING`. Either way, **compensate steps 8..1** (the reverse-order rule below: Phala terminate + DNS delete + Dev bearer soft-delete) before marking `failed`; do not finalise the Dev CVM launch. A `WARN`-level log line records the staleness. |
| 9. `policy_push` | Step 8 done. | Bump `security_cvms.policy_version` and the per-CVM policy version on the entity's SC's pulled state (§8.5). The merged policy is computed Console-side from `cvm_profiles` → `entity_profiles.policy` and surfaces in the next SC pull. | Logical only — no separate push call; the SC reads the new merged policy on its next poll. | Step is best-effort; the SC pulls eventually. |
| 10. `finalise` | Step 9 done. | Set `cvms.state = RUNNING`, clear `cvms.error_reason`. Emit `CVM_LAUNCHED`, `SUBDOMAIN_PROVISIONED`, and one `CVM_PROFILE_ATTACHED` audit row per attached profile. Build the `<CVMLaunchResult>` payload (§2.3): the `<CVM>` plus the complete `<PolicyBundle>` materialized from `cvms.compose_config` (authoritative `app_compose`, shared guest bootchain, OS-image hash) and the RTMR3-binding values injected at step 3 (§3.6 `GET /cvms/{cvm_id}/policy-bundle`). Set `operations.status = succeeded`, `operations.result = <CVMLaunchResult>`. | `cvms.state = RUNNING`; `operations.status = succeeded`; `operations.result` is `<CVMLaunchResult>`. | Cannot fail — this step is local DB only. |

Compensation order on `failed`: every persisted side effect is undone in reverse step order (CNAME delete → TXT delete → Dev bearer soft-delete → Phala terminate → `cvm_profiles` and `cvms` rows soft-deleted). Compensation is best-effort; a compensation failure is logged at `ERROR`, the operation row is marked `failed` regardless, and the reconciler (§9) cleans up any orphans on its next pass.

`error_reason` (set on `cvms.state = FAILED`) is a typed code from §10.5 (`PHALA_DEPLOY_FAILED`, `CLOUDFLARE_TXT_FAILED`, etc.) plus a sanitised template — never raw exception text.

#### `cvm.update` saga

Submitted by `POST /cvms/{id}/actions/update` (§3.6). It reuses launch rendering, runtime env binding, attestation verification, SC pull propagation, and policy-bundle materialization, but targets the existing provider deployment and preserves provider-managed named volumes.

| Step | Action | Postcondition |
|---|---|---|
| 1. `provider_update` | Re-render the Dev CVM compose from current Console config; mint new `PROXY_AUTH` and `DEV_CONTROL` bearers; mark old Dev CVM bearers expiring after an overlap window; call the provider adapter's update method for `metadata.deployment_id`. | `cvms.compose_config`, `expected_image_measurement`, provider metadata, and `metadata.pending_policy_bundle` reflect the update attempt; the new bearer hashes are live. |
| 2. `await_provider_running` | Wait for the provider status to report the updated deployment running, then compare the provider-visible runtime `docker_compose_file` SHA-256 with `metadata.pending_policy_bundle.deploy_compose_yaml`. | The provider deployment is running the pending compose before the Console attempts attestation. |
| 3. `verify_attestation` | Materialize the full Shade/dstack policy for the provider-applied pending compose, including the full `app_compose` / `app_compose_json`, `expected_bootchain`, and `os_image_hash`, then verify the updated CVM's shared guest measurement, application policy, and RTMR3 binding against that pending bundle. | `image_measurement`, `rtmr3_digest`, and `attestation_verified_at` are refreshed. |
| 4. `await_sc_pull` | Wait until the attached SC's latest control pull is newer than the new bearer. | The SC has learned the new `PROXY_AUTH` hash before the operation can succeed. |
| 5. `policy_push` | Bump the Dev CVM and SC policy versions. | The SC will re-pull the merged policy. |
| 6. `finalise` | Move `metadata.pending_policy_bundle` to the active `metadata.policy_bundle`, persist it to `cvms.atls_policy_bundle`, bump `atls_policy_revision`, clear `error_reason`, set `state=RUNNING`, emit `CVM_UPDATED`, and return `{cvm, policy_bundle}`. | The active policy bundle is current and the CLI can overwrite its local file. |

Failures mark the operation `failed` with a typed code and emit `CVM_UPDATE_FAILED`. Attestation mismatch MAY mark the CVM `FAILED`; provider/update-precondition failures leave the prior state unchanged where possible.

#### Synchronous actions: `start`, `stop`

Both transitions complete in a single transaction:

1. Load `cvms` row; verify caller can act on it (owner, or `CVM_MANAGE` for another user's CVM, + entity scope).
2. Verify the transition is legal (§8.3 state machine); else `409 CONFLICT`.
3. If `If-Match` was supplied, verify ETag.
4. Call `phala.start` or `phala.stop`. Phala timeout is 30 s; if it elapses, return `502 UPSTREAM_ERROR` and leave state unchanged.
5. Update `cvms.state` and `cvms.updated_at` in the same transaction as the audit row write.
6. Return `200 <CVM>`.

#### `cvm.terminate` saga

Submitted by `POST /cvms/{id}/actions/terminate` (§3.6).

| Step | Action | On failure |
|---|---|---|
| 1. `validate` | Verify state and entity scope. | Mark operation `failed`. |
| 2. `phala_terminate` | Call `phala.terminate(cvms.metadata->>'app_id')`. Tolerate `PhalaNotFound`. | Surface as `error.code = "PHALA_TERMINATE_FAILED"`. The row is NOT soft-deleted; the operation is `failed`; the operator can retry. |
| 3. `cf_deprovision` | Best-effort `cf.delete_record` for both DNS records. Persisted record IDs are nulled regardless of API success (a stale record id is reaped by the reconciler in §9). | Logged at `WARN`; saga proceeds. |
| 4. `finalise` | Set `cvms.state = TERMINATED`, `cvms.deleted_at = now`. Soft-delete `service_principal_tokens` for this Dev CVM (`principal_type=dev_cvm`, all purposes) so the SC's next `/internal/sc-control/cvms` pull no longer carries this CVM's `PROXY_AUTH` bearer and Dev-control routes stop accepting the `DEV_CONTROL` bearer. Emit `CVM_TERMINATED` and (if any DNS record was actually deleted) `SUBDOMAIN_DEPROVISIONED`. Operation `succeeded` with `result = <CVM>`. | Cannot fail. |

### 8.4 Security CVM lifecycle

#### State machine

The `STOPPED` enum value is **not reachable through user/admin lifecycle actions** for Security CVMs; there is no SC stop/start route in v0. It is reserved for reconciler-observed Phala drift when the provider reports a `RUNNING` SC as stopped (§9.2), and requires operator intervention.

| From | Trigger | To | Operation kind |
|---|---|---|---|
| (none) | `POST /entities/{id}/security-cvm` | `PROVISIONING` | `security_cvm.provision` |
| `PROVISIONING` | provisioning saga succeeded | `RUNNING` | `security_cvm.provision` |
| `PROVISIONING` | provisioning saga compensated | `FAILED` | `security_cvm.provision` |
| `RUNNING`, `STOPPED`, `FAILED` | `POST /entities/{id}/security-cvm/actions/update` succeeded | `RUNNING` | `security_cvm.update` |
| `PROVISIONING` | reconciler: Phala FAILED | `FAILED` | (reconciler-driven; no operation row) |
| `RUNNING` | reconciler: Phala STOPPED | `STOPPED` | (reconciler-driven; no operation row) |
| `RUNNING` | reconciler: Phala FAILED | `FAILED` | (reconciler-driven; no operation row) |
| `RUNNING`, `FAILED` | `DELETE /entities/{id}/security-cvm` | `TERMINATED` | (synchronous) |

#### `security_cvm.provision` saga

| Step | Precondition | Action | Postcondition | On failure |
|---|---|---|---|---|
| 1. `validate` | Caller's entity has no live Security CVM. | Resolve `instance_type` / `region` / `image_ref` / `image_measurement` defaults from §12. Validate `SECURITY_CVM_BASE_DOMAIN` is configured. | (no DB write) | Operation → `failed`. |
| 2. `persist_stub` | Step 1 done. | Resolve `expected_image_measurement` from the request body (when supplied) or §12 defaults. Mint `token = base32(secrets.token_bytes(16)).rstrip("=").lower()` (26 chars, 128 bits, independent of `security_cvms.id`, §7.11). Construct `fqdn = "sc-" + token + "." + SECURITY_CVM_BASE_DOMAIN`. INSERT `security_cvms` (`entity_id`, `state=PROVISIONING`, `fqdn`, `proxy_port=8080`, `expected_image_measurement`, `instance_type`, `region`, `compose_config` rendered for the SC image). Update `operations.target_id`. | `expected_image_measurement` and `fqdn` are non-null; no bearer plaintext or hash has been persisted yet. | Mark operation `failed`; tokens were not yet minted, so no leak risk. |
| 3. `phala_deploy` | Step 2 done. | Run shade build for the rendered SC compose. Mint `INGEST` and `CA_EXPORT` plaintexts (`secrets.token_urlsafe(32)`) in saga-local memory, hash both, soft-delete any prior live SC bearer rows for this principal, insert fresh `service_principal_tokens` rows, and stash only `ca_export_token_plaintext` / `ca_export_token_stashed_at`. Build env-vars (`CONSOLE_URL`, `ENTITY_ID`, `SC_ID`, `CONSOLE_INGEST_TOKEN`, `CA_EXPORT_TOKEN`, ...) and pass to Phala via the env-file mechanism (env values not persisted beyond the temporary Phala env file, see §7.11 / §7.9). Then call `phala.deploy`. Write `security_cvms.metadata = {"provider": "phala", "app_id": <id>, "gateway_host": <host>, "atls_policy": <shade dstack_tdx policy>}`. `security_cvms.fqdn` is the certificate, attestation, TCP target, TLS SNI, and HTTP Host identity. Emit `SECURITY_CVM_PROVISIONING_STARTED` audit row. Set `operations.status = running` (still in saga). | `security_cvms.metadata->>'app_id'` is non-null and `security_cvms.metadata->'atls_policy'` is a JSON object. Token rows persist with `deleted_at IS NULL`; only CA-export plaintext is stashed. | Compensate: terminate the Phala app (best-effort), soft-delete the `security_cvms` row, soft-delete every token row, scrub the CA-export plaintext stash, emit `SECURITY_CVM_PROVISIONING_FAILED` (typed action, §11.2). |
| 4. `cf_txt_create` | Step 3 done. | Look up TXT record at `_dstack-app-address.<security_cvms.fqdn>`. If a TXT with the expected content (`<security_cvms.metadata->>'app_id'>:443`) exists, reuse its id. Else `cf.create_txt`. Persist `txt_dns_record_id` to the `security_cvms` row. | `security_cvms.txt_dns_record_id` is non-null. | Compensate steps 4..1; mark operation `failed` with `error.code = "CLOUDFLARE_TXT_FAILED"` (§10.5). |
| 5. `cf_cname_create` | Step 4 done. | Same shape for CNAME at `<security_cvms.fqdn>` → `_.<security_cvms.metadata->>'gateway_host'>`. Persist `cname_dns_record_id` to the `security_cvms` row. Emit `SUBDOMAIN_PROVISIONED` audit row (§11.2; same action used by Dev CVMs). | `security_cvms.cname_dns_record_id` is non-null. | Compensate steps 5..1; **the TXT record from step 4 MUST be deleted** before the operation is marked `failed` with `error.code = "CLOUDFLARE_CNAME_FAILED"`. |
| 6. `await_phala_running` | Step 5 done. | Yield. The reconciler (§9) polls Phala and advances `security_cvms.state` to `RUNNING` when Phala reports it. | `security_cvms.state = RUNNING`. | If Phala reports `FAILED` for `> 5 minutes`, **compensate steps 6..1** (terminate the Phala app, delete the DNS records, soft-delete the row + token rows, scrub the CA-export stash) and mark operation `failed` with `error.code = "PHALA_NEVER_RUNNING"`. |
| 7. `verify_attestation` | Step 6 done. | Open an aTLS connection to `https://<security_cvms.fqdn>/tdx_quote` (the same surface Dev CVMs expose via shade's `attestation-service`, §10.4), using `security_cvms.fqdn` as the TCP connect target, TLS SNI, certificate identity, attestation identity, and HTTP Host. Retry transient `ATTESTATION_FETCH_FAILED` verifier results with exponential backoff for up to `SECURITY_CVM_ATTESTATION_TIMEOUT_SECONDS` (§12, default `180`) to absorb the Phala/shade boot and certificate window. Materialize the complete Shade policy for the deployed compose and run atlas-rs verification over its authoritative `app_compose`, `expected_bootchain` (including the shared `security_cvms.expected_image_measurement` MRTD), `os_image_hash`, and RTMR3 JCS replay of the values injected in step 3. Missing runtime-policy fields or any mismatch fail closed. atlas-rs handles vendor-chain validation, freshness, and TLS-session report-data binding internally. On success persist `security_cvms.image_measurement = expected_image_measurement`, `security_cvms.rtmr3_digest`, `security_cvms.attestation_verified_at = now`. Emit `SECURITY_CVM_ATTESTATION_VERIFIED` audit row. | Persisted attestation columns are non-null and equal the expected values. | After the retry window, compensate per the typed `error.code` (one of `ATTESTATION_FETCH_FAILED`, `ATTESTATION_QUOTE_INVALID`, `ATTESTATION_IMAGE_MISMATCH`, `ATTESTATION_RTMR_MISMATCH`, `ATTESTATION_SESSION_BINDING_INVALID`, §10.5). The CA-export plaintext MUST NOT be disclosed: scrub the stash, soft-delete the row + token rows + DNS records, emit `SECURITY_CVM_PROVISIONING_FAILED`. |
| 8. `fetch_ca` | Step 7 done. | Read `ca_export_token_plaintext` from the row. If the CA-export stash is missing or `now - ca_export_token_stashed_at > 1 hour`, scrub and abort with `error.code = "CA_EXPORT_TTL_EXPIRED"`. Otherwise resolve `security_cvms.fqdn` to an IP with the Console's own resolver, retrying past the transient NXDOMAIN a freshly-created gateway CNAME returns for the first minutes (up to `SECURITY_CVM_FQDN_RESOLVE_TIMEOUT_SECONDS`, §12, default `120`; the SC's own cert-manager FQDN gate resolves from the SC's vantage point and does not cover the Console's resolver). Then call `https://<security_cvms.fqdn>/ca.pem` with `Authorization: Bearer <plaintext>`, 15 s timeout, connecting to that **pinned IP** while keeping `security_cvms.fqdn` as the TLS SNI, certificate identity, and HTTP Host — so this single-shot connect never re-resolves and cannot hit an NXDOMAIN gap. | `ca_pem` available in scope. | **Compensate steps 8..1**: scrub the plaintext stash, **terminate the Phala app, delete the DNS records, and soft-delete the row + token rows** (a post-deploy CA failure — `CA_FETCH_FAILED` (`reason` includes `fqdn_unresolvable` when the FQDN never resolved within the budget) / `CA_EXPORT_TTL_EXPIRED` — MUST NOT leave the SC's Phala deployment and Cloudflare records dangling), then mark operation `failed`. |
| 9. `finalise` | Step 8 done. | In a single transaction: persist `security_cvms.ca_cert_pem`, set `state=RUNNING`, scrub `ca_export_token_plaintext` and `ca_export_token_stashed_at`, set `operations.result = <SecurityCVMProvisionResult>` (carrying the CA-export plaintext, §2.3), set `operations.status = succeeded`. Emit `SECURITY_CVM_PROVISIONED`. | `security_cvms.state = RUNNING`; CA-export plaintext scrubbed from `security_cvms`; CA-export bearer staged in `operations.result` for first-read disclosure. | Cannot fail (purely local DB writes). |

The CA-export plaintext is exposed via `operations.result` once and exactly once **after** attestation verification has succeeded. The `INGEST` plaintext is not disclosed and is never persisted. Earlier drafts staged the result mid-saga, which would have allowed a polling caller to capture bearers before the SC's identity was verified — that ordering is FORBIDDEN. The disclosure write is gated by the caller's auth; the next read of the operation by the same caller writes `operations.result_disclosed_at` and MUST replace bearer fields with `"<redacted-after-first-read>"` on subsequent reads. The Console MUST emit `OPERATION_RESULT_DISCLOSED` (§11.2) on the first disclosure so the act of capture is auditable.

#### `security_cvm.update` saga

Submitted by `POST /entities/{id}/security-cvm/actions/update` (§3.7). v0 keeps the one-live-SC-per-entity model and updates the existing provider deployment. The MVP may disrupt Dev CVM egress if the SC CA changes; Dev CVM data is not deleted.

| Step | Action | Postcondition |
|---|---|---|
| 1. `provider_update` | Re-render the SC compose from current Console config; mint fresh `INGEST` and `CA_EXPORT` bearers; keep old SC bearer hashes valid for an overlap window; call the provider adapter's update method for `metadata.deployment_id`. | `security_cvms.compose_config`, `expected_image_measurement`, metadata, and the CA-export plaintext stash reflect the update attempt. |
| 2. `await_provider_running` | Wait for the provider status to report the updated deployment running. | The provider deployment is ready for attestation. |
| 3. `verify_attestation` | Regenerate the complete Shade policy from the provider-applied compose, verify the shared guest measurement, full app-compose/bootchain/OS-image policy, and RTMR3 binding, then persist the refreshed SC aTLS policy in metadata. | Attestation columns and `metadata.atls_policy` are current. |
| 4. `fetch_ca` | Fetch the SC's current `ca.pem` using the stashed `CA_EXPORT` bearer. | `security_cvms.ca_cert_pem` is refreshed. |
| 5. `finalise` | Scrub CA-export plaintext, set `state=RUNNING`, bump `policy_version`, emit `SECURITY_CVM_UPDATED`, and return `{security_cvm, ca_changed, dev_cvms_requiring_update: []}`. A CA change is recorded but does not create CA-only Dev CVM markers or clear persisted legacy markers. | Refresh-capable Umbra forwarders pull the current policy and CA over their authenticated Dev-control channel. Persisted `SECURITY_CVM_REBIND_REQUIRED` rows remain fail-closed replacement signals handled by the pre-Umbra control plane. |

Failures mark the operation `failed`, scrub plaintext bearer stashes, and emit `SECURITY_CVM_UPDATE_FAILED`. Attestation/provider failures MAY leave the Security CVM `FAILED` when the updated deployment is known bad.

#### Synchronous decommission

`DELETE /entities/{id}/security-cvm` (§3.7):

1. Load the live Security CVM. `404` if absent. `409 CONFLICT` (`details.state="dev_cvms_in_entity"`) if any live Dev CVM exists in the entity (§8.1).
2. Call `phala.terminate(security_cvms.metadata->>'app_id')`. Tolerate `PhalaNotFound`. Surface other `PhalaError` as `502 UPSTREAM_ERROR` — the row is NOT soft-deleted in that case; operator retries.
3. Best-effort `cf.delete_record(txt_dns_record_id)` and `cf.delete_record(cname_dns_record_id)`. `CloudflareError` is logged at `WARN` and the record id stays non-null on the row; the reconciler's "Orphaned DNS records" pass (§9.2) retries asynchronously. The decommission MUST proceed regardless of DNS-cleanup outcome — the SC is the operator-visible authority and Phala-terminate has already neutered the deployed instance.
4. In one transaction: set `security_cvms.state = TERMINATED`, `security_cvms.deleted_at = now`, soft-delete every `service_principal_tokens` row for this principal. On a successful DNS-cleanup in step 3, null the corresponding `txt_dns_record_id` / `cname_dns_record_id`. Emit `SECURITY_CVM_DECOMMISSIONED` and (if at least one DNS record was actually deleted) `SUBDOMAIN_DEPROVISIONED` audit rows (§11.2).
5. Return `200 <SecurityCVM>`.

After step 4, every bearer minted for this Security CVM MUST fail authentication with `401 UNAUTHORIZED` (§5.7 parent-state check, T-2).

### 8.5 Profile-policy combination and policy push

A Dev CVM's effective policy is the merge of every attached profile's `policy` document (§7.6). The merge function is **field-typed**:

- **Allow-lists** (e.g. `allowed_destinations`): union. Adding a non-boundary profile can only add allowed destinations. If any attached profile sets `egress_boundary: true`, the union is computed only over boundary profiles, so accidentally attaching a broad non-boundary profile cannot widen egress. A boundary profile with an empty allow-list is the reusable air-gapped primitive. If multiple boundary profiles are attached, their allow-lists are unioned. Allow-list rules MAY carry `body_assertions` and `traffic_log_attributes` (`docs/specs/security-cvm.md` §4.3); the merge is a canonical-JSON union of whole rule objects. A rule with `host: "*"` is the reusable open-internet profile primitive. Multiple profiles authoring rules with the same `(host, method, path_prefixes, body_assertions[*].kind, body_assertions[*].field)` shape but different `allow_values` survive as parallel rules; the SC matches whichever rule's assertion passes — operators authoring overlapping rules are responsible for the resulting widened effective allow-set.
- **Deny-lists** (e.g. `blocked_destinations`): intersection. Adding a profile can only remove denials (i.e. relax restrictions). Deny-list rules MUST NOT contain `body_assertions` or `traffic_log_attributes`; `validate_profile_policy` rejects them at write time.
- **Keyed maps** (e.g. `sandbox_env`): union by key; identical-value duplicates collapse silently; conflicting values on the same key refuse the attach with `409 CONFLICT` (see `sandbox_env` rule below).
- **Scalars** (e.g. `max_egress_mbps`): merge rule TBD per the policy schema (forthcoming). Until the schema is published, conformance §19 MUST exercise the allow-list, deny-list, and keyed-map cases above; scalar conflicts are out of scope.

The active `<Profile>.policy` schema contains `egress_boundary`, `allowed_destinations`, `blocked_destinations`, `secret_patterns`, `secret_injections`, and `sandbox_env`. Console validation MUST reject unknown top-level fields and malformed destination, secret-pattern, and secret-injection entries before persisting a profile policy, including path-prefix ambiguity and RE2 regexes that the Security CVM cannot compile. What this spec mandates today:

- `policy` is a JSON object after validation, except `secret_injections[*].value` is write-only input and is stripped before persistence/response. Public profile reads round-trip the redacted policy shape; SC-control is the only response path that rehydrates plaintext values.
- `secret_injections[*].id` values are unique within a profile so encrypted material can be bound to a stable `(profile_id, injection_id)` key.
- The merge function for any defined field MUST be one of the four types above, declared inline in the published schema.
- Profile attachment is observable in the resulting policy (T-25): if profile P contributes to allow-list A, the CVM's effective allow-list MUST include A's contents after attach and MUST NOT after detach.

#### `sandbox_env` merge and rendering

For each Dev CVM, the Console computes the merged `sandbox_env` as the union of every attached profile's `policy.sandbox_env` map (§2.3 `<Profile>`):

- **Union by key with conflict refusal.** For every `NAME` present in two or more attached profiles, the values MUST be byte-identical; otherwise the attach (`POST /cvms/{id}/profiles`, §3.6), profile policy patch (`PATCH /profiles/{id}`, §3.4), or initial launch (`POST /cvms`, §3.6) refuses with `409 CONFLICT` (`details.state="sandbox_env_conflict"`, `details.name=<NAME>`, `details.profile_ids=[<UUID>, ...]`). Conflict refusal is deterministic — the Console MUST NOT pick a winner.
- **Canonical ordering.** The merged map is rendered with keys in lexicographic (UTF-8 code-point) order. The byte-exact rendering is `"\n".join(f"{name}={value}" for name, value in sorted(merged.items())) + "\n"` (no header, trailing newline). This is the pre-base64 input for `SANDBOX_ENV_PLACEHOLDERS_B64` (§8.3 step 3) and, when `sandbox_env_placeholders_sha256` is later added to the RTMR3 binding (currently a tracked open item — `docs/specs/dev-cvm.md` §11), is the input to that SHA-256.
- **Bumps `policy_version`.** Any `cvm_profiles` insert/delete or `entity_profiles.policy` PATCH that changes the merged `sandbox_env` for a CVM bumps that CVM's pulled `policy_version` (§4.3, §8.5 pull contract). The new placeholders take effect on the **next CVM launch** — the running sandbox's env is fixed at deploy time and is NOT updated live (`docs/specs/dev-cvm.md` §7.1).
- **Empty merge.** If no attached profile defines `sandbox_env` (or every entry is `{}`), the merged map is `{}` and `SANDBOX_ENV_PLACEHOLDERS_B64` decodes to the empty byte string.

#### Per-owner `value_from` resolution

When rendering the SC-control response (§4.3), the Console hydrates each `secret_injections[*]` entry to the wire shape the Security CVM accepts (`id`, `match`, `type`, `header`, `value`, `value_template` — nothing else):

- **Inline entries** decrypt their `(profile_id, injection_id)` material (§7.6a) exactly as before.
- **`value_from` entries** resolve against the **CVM owner's** (`cvms.owner_id`) `user_secret_material` (§7.6b): the referenced `name` is decrypted under the owner's AAD and emitted as the injection's `value`; the `value_from` key is stripped. Two CVMs attached to the same profile therefore receive **different** injected values — each owner's own credential — which is the mechanism that makes profile membership grant policy, never another user's identity.
- **Resolve-or-mark-unfulfilled, never pass through.** A `value_from` entry that cannot be resolved never silently proceeds uncredentialed. The outcome depends on why it failed:
    - **Grant unusable** — the owner has no secret of that name; the secret's `allowed_hosts` binding does not cover the injection's `match.host` (containment below); the material fails to decrypt; or the rendered value would exceed the SC's 8192-character cap. The Console emits the injection into a wire-only `unfulfilled_secret_injections` list as an `{id, match, header}` marker (never a `value` or `value_from`). The SC fail-closes **that destination** with `secret_injection_unfulfilled` (`docs/specs/security-cvm.md` §4.3, §5.3, §5.4): matching requests are blocked with the `X-Umbra-Block-Reason` response header and a traffic-log decision row, so a missing/expired/rebound grant is legible at the point of failure instead of the sandbox placeholder reaching the upstream as an opaque auth error. This blocks one destination, **not** the whole CVM.
    - **Malformed definition** — `match.scheme` is not `https`, or the `value_template` is malformed. These are shapes the authoring validator (§2.3) already rejects, so they should never reach the wire; the injection is silently omitted (a non-https marker would be inert anyway).
  Either outcome logs a structured warning naming only `cvm_id`/`owner_id`/`profile_id`/`injection_id`/`secret_name`/`reason`/`outcome`. This is mandatory fail-safe behavior: the SC rejects unknown injection fields and fail-closes the whole CVM to deny-all on a malformed `secret_injections` policy, so a `value_from` key (or a value-less `secret_injections` entry) MUST never reach the wire — the marker carries neither, and rides the separate `unfulfilled_secret_injections` list the SC parses **leniently** (a malformed marker is dropped, never deny-all).
- **Host-binding containment.** A secret pattern `S` covers an injection `match.host` `I` under Security CVM host-match semantics (exact / `*.suffix` strict subdomains / `*`): `S == I`; `S == "*"` covers everything (the owner's explicit opt-out); `*.s` covers an exact host `h` iff `h` ends with `.s` and `h != s` (the apex stays excluded, mirroring the SC); `*.s` covers `*.i` iff `i == s` or `i` ends with `.s`; an exact `S` covers only the identical exact host; no pattern other than `*` covers `I == "*"`. Coverage over `allowed_hosts` is per-entry (some single entry must cover the injection host).
- **Launch/attach preflight.** `POST /cvms` validates every reference against the **launcher** and `POST /cvms/{id}/profiles` against the **CVM owner** (§3.6) so unresolvable references fail fast with `422` instead of silently degrading. A reference can still become unresolvable later (the owner deletes or re-binds the secret, or a `USER_MANAGE` holder edits the profile): the materializer then marks the injection **unfulfilled** at the next pull and the SC fail-closes that destination (above) — documented, legible degradation, not an error and not a whole-CVM outage. Validating `PATCH /profiles/{id}` against the owners of all attached CVMs is tracked future work.
- **Propagation.** The SC-control ETag is content-derived (§4.3), so a `PUT /me/secrets/{name}` that changes a resolved value changes the response body and the SC converges on its next poll (~5 s) with no `policy_version` bump. Re-encryption of an unchanged value leaves the hydrated body byte-identical (304s continue).
- **Exfiltration bound.** The host binding is owner-controlled: a `USER_MANAGE` holder who edits a profile to point a `value_from` injection at a different allowed destination cannot cause the owner's credential to be injected toward a host outside the owner's `allowed_hosts` — the materializer marks the injection unfulfilled (a `host_binding` miss) and the SC fail-closes that destination instead of ever injecting the credential off-binding.

#### Policy distribution (pull, not push)

The Console does NOT actively push policy to the Security CVM. Instead, the SC pulls the per-Dev-CVM mapping (`(cvm_id, proxy_token_hash, merged_policy, policy_version)`) from `GET /internal/sc-control/cvms` (§4.3) on a polling cadence (~5 s, ETag-cached). The Console maintains the canonical state; every event that changes a CVM's effective policy updates the Console-side state that the SC will see on its next poll:

- `cvm.launch` saga (§8.3) inserts the `cvms`, `cvm_profiles`, and `service_principal_tokens` rows that the next pull surfaces.
- `POST /cvms/{id}/profiles` and `DELETE /cvms/{id}/profiles/{profile_id}` (§3.6) — attach / detach — update `cvm_profiles` and bump per-CVM `policy_version`.
- `PATCH /profiles/{id}` (§3.4) when `policy` changes — bumps `policy_version` for every CVM that has this profile attached, since each CVM's merged policy now differs.
- `cvm.terminate` saga soft-deletes the `service_principal_tokens` row and the SC drops the bearer from its local map on the next pull.

Properties of the pull-based distribution:

- **Eventual consistency, ~5 s window.** Between the Console-side mutation and the SC's next poll, the SC operates on stale data. New Dev CVMs whose bearer hasn't propagated yet receive `407 Proxy Authentication Required` from the SC's mitmproxy (fail-closed; §10.4). The cvm.launch saga's `await_sc_pull` step (§8.3 step 7) waits for the next pull before finalising, so the user-visible launch operation only succeeds after the SC has the new mapping.
- **Idempotent on `policy_version`.** The SC tracks the highest version it has applied; a polling response containing the same `(cvm_id, policy_version)` is a no-op.
- **No Console-to-SC channel.** The Console does not initiate any call to the SC after `fetch_ca` provisioning (§10.4). All control-plane state flows through SC-initiated pulls. This eliminates the need for an authenticated push channel from Console to SC, with its associated TLS-pinning surface.
- **The `security_cvms.policy_version` column** tracks the SC's overall pulled version (the Console writes it when the SC's last-poll ETag matches the current state); it's primarily diagnostic.
- **Fail-closed in v0; defer-and-resolve later** (§10.4). On unknown bearer the SC refuses traffic with `407`; a future revision MAY have the SC issue an immediate pull on miss before failing.

Security-CVM-side enforcement of the policy DSL is specified in `docs/specs/security-cvm.md` §4 and §5.3; the Console-side validator is the authoring gate for the same schema.

### 8.6 Polling and progress

Clients of async routes follow the contract in §3.8 (`GET /operations/{id}`):

- Poll cadence is the client's choice; the Console does not enforce a server-side minimum interval.
- The `progress.step` field carries the saga step name from §8.3 / §8.4. Clients MAY render a progress bar from `progress.percent`.
- Long-running operations (e.g. Security CVM provisioning, 2–5 minutes) MUST receive at least one heartbeat update per minute so a polling client can distinguish "in progress" from "stuck".
- The Console does not bound how long a saga may run beyond per-external-call timeouts (§10). The CLI sets `--wait-timeout` on its own clock.

## 9. Reconciliation and the operation scheduler

A single background component drives two responsibilities: (a) the **operation scheduler** claims `pending` and `running` rows from `operations` (§7.17) and runs the saga steps from §8.3 / §8.4, and (b) the **reconciler** detects and repairs drift between Console state and external state for resources that are *not* under an active operation. They share a worker pool, a database session factory, and the Phala / Cloudflare adapters. The reconciliation pass also drives the instance-type catalog refresh (§3.6a `spawn_refresh_if_due()` — its own 24h + retry-ladder cadence, spawned as a background task, not a per-tick provider call).

The same logic is exposed on demand via `POST /admin/reconcile` (§3.12) for the platform operator's incident playbook (§17).

### 9.1 The operation scheduler

The scheduler claims work from `operations`:

```sql
SELECT * FROM operations
WHERE status IN ('pending', 'running')
  AND updated_at < now() - INTERVAL '30 seconds'   -- avoid claiming rows another worker is actively progressing
ORDER BY created_at
LIMIT <batch>
FOR UPDATE SKIP LOCKED;
```

Each claimed row is dispatched to a saga handler keyed by `kind` (`cvm.launch`, `cvm.update`, `cvm.terminate`, `security_cvm.provision`, `security_cvm.update`, `audit.export`). The handler executes the next-step contract from §8.2, commits the postcondition, releases the row, and the next tick picks it up again until the operation is terminal.

This pattern enables horizontal scale: any number of Console worker processes can coexist, each claiming rows the others have not. The `FOR UPDATE SKIP LOCKED` and the per-step idempotency guarantees from §8.2 are the entire concurrency-correctness story.

### 9.2 The reconciler pass

A reconciler pass runs once per `RECONCILER_INTERVAL_SECONDS` (default `30 s`, minimum `1 s`, §12). Each pass performs the following jobs in sequence on a single session:

1. **Drift on Dev CVMs not under active operation.** For every `cvms` row in state `RUNNING` whose Phala status (via cached or fresh `phala.get_status`) is `FAILED` or `STOPPED`, transition to the matching state and emit the audit row. A `RUNNING → FAILED` transition records `error_reason = "PHALA_OBSERVED_FAILED"` (typed code, §10.5).
2. **Drift on Security CVMs not under active operation.** Same shape for `security_cvms`.
3. **Orphaned DNS records.** Find every `cvms` row (Dev CVMs) and every `security_cvms` row (SCs) where `deleted_at < now - 5 minutes` and at least one Cloudflare record id is still non-null. Best-effort `cf.delete_record`; null the column on success.
4. **Expired auth-flow state.** Delete `loopback_auth_pending` and `device_flow_pending` rows whose `expires_at < now`, matching §5.4.3 so a stuck IdP cannot strand login state.
5. **Orphaned `revoked_tokens` and `idempotency_keys`.** Delete rows whose `expires_at < now - 1 day`.
6. **Audit-anchor checkpoint** (§11.6). If the most recent `audit_anchors` row is older than `audit_anchor_interval_seconds` (default 1 hour), publish a new anchor.
7. **Operation TTL prune.** Delete `operations` rows where `expires_at < now`.
8. **Security CVM attestation refresh** (§10.4, T-29, T-30). For every `security_cvms` row in state `RUNNING` whose `attestation_verified_at < now - RECONCILER_ATTESTATION_INTERVAL_SECONDS` (default `21600`, §12), open an aTLS connection to the SC's `/tdx_quote` endpoint, regenerate the complete Shade policy from the deployed compose, and run atlas-rs verification over `app_compose`, `expected_bootchain` (including the row's shared guest MRTD), `os_image_hash`, and the RTMR JCS replay. On success update `attestation_verified_at` and `image_measurement` / `rtmr3_digest` if not already persisted; emit `SECURITY_CVM_ATTESTATION_VERIFIED`. On any runtime-policy mismatch, set `error_reason = "ATTESTATION_DRIFT"`, emit `SECURITY_CVM_ATTESTATION_DRIFT`, and page the operator (§17.4) — the row is NOT auto-decommissioned. Tolerates `ATTESTATION_FETCH_FAILED` (logged at `WARN`, retried next pass).
9. **Dev CVM attestation refresh** (§10.4a, T-31, T-32). For every `cvms` row in state `RUNNING` whose `attestation_verified_at < now - RECONCILER_ATTESTATION_INTERVAL_SECONDS`, open an aTLS connection to the Dev CVM's `/tdx_quote` endpoint, regenerate the complete Shade policy from the deployed compose, and run atlas-rs verification over `app_compose`, `expected_bootchain` (including the row's shared guest MRTD), `os_image_hash`, and the RTMR JCS replay. On success update `attestation_verified_at` and `image_measurement` / `rtmr3_digest`; emit `CVM_ATTESTATION_VERIFIED`. On any mismatch, set `error_reason = "ATTESTATION_DRIFT"`, emit `CVM_ATTESTATION_DRIFT`, and page the operator (§17.4) — the row is NOT auto-terminated; the Dev CVM's egress remains policed by the SC regardless. Tolerates `ATTESTATION_FETCH_FAILED` (logged at `WARN`, retried next pass).

Each job runs with `FOR UPDATE SKIP LOCKED` on the rows it touches so it can run on multiple workers without conflict.

### 9.3 Cadence and error handling

- The loop sleeps `RECONCILER_INTERVAL_SECONDS` between passes; passes do not run in parallel on the same worker.
- A pass that raises an exception logs at `ERROR` (with `request_id` synthesised for the pass) and the next pass starts on schedule. The loop stays alive across exceptions.
- Individual jobs inside a pass tolerate `PhalaError` and `CloudflareError` (logged at `WARN`, the row is skipped, retried next pass).
- The lifespan shutdown path cancels the loop; the `asyncio.CancelledError` is logged and re-raised cleanly.

### 9.4 Concurrency model

Multi-worker is supported. The scheduler MUST acquire row-level locks via `SELECT ... FOR UPDATE SKIP LOCKED` on `operations` and on every saga-step `UPDATE`. The reconciler MUST do the same on the rows it touches.

The Console MUST NOT rely on a single-leader assumption. Pods MAY be scaled horizontally to handle higher operation throughput.

### 9.5 Audit attribution

Scheduler-driven and reconciler-driven mutations write audit rows with the system actor:

- For operation steps that have an `actor_id`, audit rows carry the original actor (the user who submitted the operation), not the system actor — the operation is "the user's request being progressed", not "the system did this".
- For drift repairs that are not tied to any operation, audit rows carry `(actor_id=NULL, actor_email="reconciler@umbra.invalid")`. These rows are visible to `AUDIT_VIEW` callers when their `target_id` resolves to a resource in the caller's entity (§11.4).

### 9.6 On-demand pass (`POST /admin/reconcile`)

`POST /admin/reconcile` runs one immediate reconciler pass synchronously inside the HTTP request. The caller MUST hold `PLATFORM_OPERATOR` (§6).

Body and response are documented in §3.12. Notable behaviour:

- `include_orphans=false` skips the Cloudflare orphan-cleanup pass; the route succeeds without Cloudflare configured.
- `include_orphans=true` requires Cloudflare; the route returns `503 SERVICE_UNAVAILABLE` (`details.component="cloudflare_adapter"`) if the adapter is unconfigured.
- If Phala is unconfigured the route returns `503 SERVICE_UNAVAILABLE` (`details.component="phala_adapter"`) regardless of other flags.

The on-demand pass and the background loop share the same code path and the same locking model — running them concurrently is safe.

## 10. External integrations

The Console depends on three external systems and acts as a client to a fourth (the Security CVMs it provisions). Each integration has its own contract surface, auth model, retry / timeout posture, and failure-to-state mapping.

### 10.1 Phala / dstack

Phala Cloud is the CVM provider. The Console drives it through a pinned Node/npm adapter boundary: the `phala` CLI for lifecycle calls and in-place updates, and `@phala/cloud` SDK actions in a Node subprocess for provider compose-file hash reads.

#### Distribution integrity (T-13, T-19)

The Phala CLI is distributed as an npm package (`phala` on the public npm registry, e.g. `phala@1.1.19`). The on-disk shape is a launcher at `PHALA_CLI_PATH` (default `/usr/local/bin/phala`) symlinked to the package's JS entrypoint under `node_modules/phala/dist/index.js`, plus its transitive `node_modules` tree. There is no single-file binary to hash; the integrity anchor is the **npm tarball** the package was installed from. The Console MUST verify that integrity at startup and refuse to start otherwise:

- `PHALA_CLI_PATH` is fixed in the deployment image (e.g. `/usr/local/bin/phala`); it is permitted only as a deploy-time configuration, NOT a runtime env override that production can mutate.
- The CLI tree (e.g. `/usr/lib/node_modules/phala/`) and its launcher live on a read-only mount in production.
- The deployment image is built by `npm ci --ignore-scripts` against a committed `package-lock.json` pinning `phala@<version>`. The SHA-256 of the resolved npm tarball is `PHALA_CLI_SHA256` (§12).
- At startup, the Console MUST verify the on-disk installation against the pin. Acceptable mechanisms: (a) the build copies the resolved tarball alongside the install at a known path and the Console re-hashes that file, or (b) the Console re-fetches the tarball at boot from the npm registry by the lockfile's resolution URL and re-hashes it. Mismatch is a fatal startup error.
- Per-subprocess re-verification is NOT required — the read-only mount and image-rebuild rotation procedure together preclude a live-tree mutation between calls.
- The pin is rotated whenever the operator upgrades the bundled CLI; the spec REQUIRES the rotation procedure to be a deployment artifact change (image rebuild), not a live environment edit.

#### Subprocess hygiene

- **Operations called.** `phala deploy --no-dev-os`, `phala deploy --cvm-id <id> --no-dev-os`, `phala cvms get -j`, `phala cvms start`, `phala cvms stop`, `phala cvms delete --force`; for in-place updates, the CLI's documented update path (`phala deploy --cvm-id`) submits the attested compose file and encrypted environment together, targeting the live Phala `vm_uuid` when `phala cvms get` exposes one. `--no-dev-os` is mandatory for both Security and Dev CVMs so the provider uses the production dstack OS image instead of a dev/debug image. The SDK action `getCvmComposeFile` is used to verify the provider-visible compose hash before re-attestation.
- **Authentication.** `PHALA_CLOUD_API_KEY` is set on the subprocess environment per invocation. Never in `argv`. Never persisted to disk via `phala login`.
- **Allowlist env.** The subprocess receives only `PHALA_CLOUD_API_KEY`, `PATH`, `HOME`, `LANG`, `LC_ALL`. The Console MUST NOT `os.environ.copy()` (T-19).
- **Compose + env-file staging.** Compose YAML and env-file are written to `/dev/shm` at mode `0600` (tmpfs, falling back to the system tempdir if `/dev/shm` is unwritable). Both are `shred -u`-deleted on exit; `os.unlink` if `shred` is unavailable. Cleanup runs even when the deploy raises.
- **Env-value sanitisation.** Any env value containing `\r` or `\n` is refused with `PhalaError("invalid_env_value")`. Smuggleable values are blocked at the writer.
- **Timeout.** Default 5 minutes per provider subprocess call. Provider update sagas submit in-place CVM updates through `phala deploy --cvm-id` without the CLI `--wait`; the scheduler then polls provider status and provider compose-file hash in the saga's `await_provider_running` step so the Console verifies the runtime compose before re-attestation and avoids the CLI's shorter readiness wait. On subprocess timeout the subprocess is `kill()`'d and `PhalaError("cli_timeout")` is raised; tmpfs cleanup still runs.

#### Output validation (T-22)

Phala's response is untrusted. The Console MUST regex-validate every field used downstream:

- `app_id` matches `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`. Mismatch ⇒ `PhalaError("invalid_response", field="app_id")`.
- `gateway_host` is a strict DNS hostname (`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`). Mismatch ⇒ `PhalaError("invalid_response", field="gateway_host")`.

These regexes are the only sanitiser before fields are interpolated into URLs that carry the `CA_EXPORT` bearer (T-11 prerequisite).

#### Status normalisation

Phala's free-text statuses are normalised to the typed enum `PhalaDeployStatus`:

| Phala raw | Normalised |
|---|---|
| `running`, `active`, `healthy` | `RUNNING` |
| `starting`, `creating`, `provisioning`, `booting`, `initializing`, `pulling` | `PENDING` |
| `stopped`, `stopping`, `paused`, `exited` | `STOPPED` |
| `failed`, `error`, `errored`, `crashed` | `FAILED` |
| `terminated`, `deleted`, `removed` | `TERMINATED` |
| anything else | `UNKNOWN` |

Saga and reconciler logic branch only on normalised values.

#### Failure handling

- `PhalaNotFound` (substring `"not found"` in stderr / stdout): for `cvms delete`, treat as success. For `cvms get`, raise `PhalaNotFound` (the saga retries through Phala's post-deploy propagation window).
- All other non-zero exits raise `PhalaError`. Stderr / stdout passed through to the exception is scrubbed: the API token, every secret in §13.4's denylist, and any matched value from a configured `PHALA_OUTPUT_REDACTION_PATTERNS` list are replaced with `[redacted]`.
- At the route boundary, `PhalaError` maps to `502 UPSTREAM_ERROR` with `details.adapter = "phala"` (§2.4). Inside a saga, `PhalaError` triggers compensation (§8.3, §8.4).

### 10.2 Cloudflare

Async HTTPS client (`httpx`) against Cloudflare's REST v4 API.

- **Operations called.** `GET /zones/{zone_id}/dns_records?name=...&type=...`, `POST /zones/{zone_id}/dns_records`, `DELETE /zones/{zone_id}/dns_records/{id}`.
- **Authentication.** `Authorization: Bearer <CLOUDFLARE_API_TOKEN>`. The token MUST have `DNS:Edit` on the configured `CLOUDFLARE_ZONE_ID` and no broader scope.
- **TLS.** Standard public-CA chain validation. The token's narrow scope (`DNS:Edit` on a specific zone) bounds the blast radius of any successful MITM.
- **Record-naming convention.**
   - **Dev CVMs.** TXT `_dstack-app-address.<cvms.fqdn>` → `<cvms.metadata->>'app_id'>:443`; CNAME `<cvms.fqdn>` → `_.<cvms.metadata->>'gateway_host'>`. The Dev-CVM FQDN has the form `cvm-<26-base32-random>.<CLOUDFLARE_BASE_DOMAIN>` per §7.9.
   - **Security CVMs.** TXT `_dstack-app-address.<security_cvms.fqdn>` → `<security_cvms.metadata->>'app_id'>:443`; CNAME `<security_cvms.fqdn>` → `_.<security_cvms.metadata->>'gateway_host'>`. The SC FQDN has the form `sc-<26-base32-random>.<SECURITY_CVM_BASE_DOMAIN>` per §7.11. The `SECURITY_CVM_BASE_DOMAIN` (§12) is a separate operator-controlled zone (e.g. `sc.example.com`) so SC namespaces are visibly disjoint from Dev CVM namespaces and can carry distinct TLS / WAF policy.
- **Idempotency.** `find_records` is the lookup primitive every saga step uses to short-circuit duplicate creation. `delete_record` treats HTTP `404` as success.
- **TTL.** `ttl: 1` ("automatic"). CNAME `proxied: false` — neither Cloudflare nor the Phala gateway terminates TLS; **TLS terminates end-to-end inside the target CVM** (shade's `cert-manager` + `nginx` sibling containers handle the certificate lifecycle and TLS handshake on `:443` of the CVM). Phala's gateway performs TCP-level SNI routing only and never sees TLS plaintext. This is load-bearing for the aTLS attestation binding (§10.4): the verifier's TLS session terminates at the CVM's leaf cert, whose SPKI digest is included in the attestation report-data — a binding that would be impossible if Phala terminated and re-encrypted.
- **Timeout.** 20 s per request.
- **Failure mapping.** Non-2xx or `success: false` raises `CloudflareError`. Inside a saga, triggers compensation. At the route boundary, maps to `502 UPSTREAM_ERROR` with `details.adapter = "cloudflare"`.

### 10.3 Google OIDC

Covered from the verification side in §5.5. Operationally:

- **Endpoints.** Device code, token, and JWKS endpoints listed in §5.5. Each URL is overridable via env (`GOOGLE_DEVICE_CODE_URL`, `GOOGLE_TOKEN_URL`, `GOOGLE_JWKS_URL`) only when `LOG_LEVEL=debug` AND a runtime flag `OIDC_OVERRIDES_ALLOWED=true` is set; production deployments MUST leave them unset and the override-flag false (so a misconfigured production cannot accidentally trust a mock IdP).
- **TLS.** Standard public-CA chain validation. CA-MITM against the IdP is a state-level threat; the spec accepts this scope per §1.5 ("compromised IdP").
- **JWKS cache.** 5-minute TTL with single-flight force-refresh on `kid` miss (§5.5).

### 10.4 Security CVMs (Console as server, SC as client) — TEE-attested binding + control-plane pull

Two-direction story:

- **Console as server.** The SC is the client for two reasons: (1) verifying TEE attestation (the Console fetches `/tdx_quote` from the SC at provisioning, see "Attestation contract" below); (2) the SC polls `GET /internal/sc-control/cvms` (§4.3) for the per-Dev-CVM mapping (`cvm_id`, proxy-bearer hash, merged policy, policy version) it needs to authenticate `Proxy-Authorization` headers and apply per-CVM policy at its mitmproxy. The Console issues no outbound calls to the SC after `fetch_ca` provisioning — this is a deliberate design choice that eliminates the need for an authenticated push channel from Console to SC and its associated TLS-pinning surface.
- **SC as enforcement point.** The SC's mitmproxy intercepts every Dev CVM's outbound request. It reads `Proxy-Authorization: Bearer <token>` and looks up the token's SHA-256 in its locally-cached map (refreshed every ~5 s via the pull above). On hit, it applies the per-CVM merged policy and ships the corresponding traffic-log entry to `/internal/traffic-logs` with the resolved `cvm_id`. **On miss, the SC fails closed with `407 Proxy Authentication Required`** in v0. A future revision MAY add defer-and-resolve (issue an immediate Console pull on miss) to close the user-visible ~5 s convergence window after a fresh Dev CVM launch; v0 accepts the brief outage in exchange for protocol simplicity.

The Security CVM exposes a `/tdx_quote` HTTP endpoint via shade's `attestation-service` sibling container, and is verified with the same atlas-rs (or equivalent) verifier the CLI uses for Dev CVMs ([CLI spec](cli.md) §6.1, §9.5). The SC does NOT expose the `/atls` WebSocket route that Dev CVMs use: that route exists on Dev CVMs to host user-initiated aTLS-tunneled SSH sessions (`umbra tunnel`). Every Console / CLI interaction with the SC is a short-lived HTTPS request (`/tdx_quote`, `/ca.pem`) whose attestation binding via the regular TLS leaf SPKI is sufficient. The SC's `/umbra/proxy` upgrade route is data-plane-only for Dev CVM egress and is not a Console/CLI management tunnel. Reusing the verifier code path keeps code and threat-modelling surface narrow without exposing a user-initiated tunnel route the SC has no use case for.

The SC identity is the **stable, operator-controlled DNS name** stored in `security_cvms.fqdn`, of the form `sc-<26-base32-random>.<SECURITY_CVM_BASE_DOMAIN>` (e.g. `sc-aaaaaaaaaaaaaaaaaaaaaaaaaa.sc.example.com`) provisioned in Cloudflare at the same provisioning saga that deploys it (§8.4). Phala's gateway hostname (`security_cvms.metadata->>'gateway_host'`) is NOT used directly for any URL the Console or CLI reaches — that hostname rotates with Phala-side state and cannot satisfy aTLS / public-CA TLS validation for a stable identity. All transport — TCP target, TLS SNI, certificate validation, attestation identity, and HTTP Host — is bound to `security_cvms.fqdn`. The per-CVM custom-domain DNS created at provisioning (CNAME `<fqdn>` -> gateway plus the `_dstack-app-address.<fqdn>` TXT record) makes the dstack gateway pass an `fqdn`-SNI connection straight through to the enclave.

The trust root for the SC's identity is its TEE remote attestation, verified by the Console at provisioning and on every reconciler probe (T-11, T-29, T-30).

#### Attestation contract

The SC runs in an Intel TDX / AMD SEV-SNP (or equivalent) confidential VM operated by Phala. The TEE produces a hardware-rooted **remote attestation report** that proves:

- **Shared guest measurement.** `MRTD` (or the architecture-equivalent launch measurement) identifies the approved dstack guest boot baseline. Dev and Security CVMs on that baseline use the same value: `SECURITY_CVM_IMAGE_MEASUREMENT == DEV_CVM_IMAGE_MEASUREMENT`. It does not identify the SC application image or compose; those are bound by the full runtime policy below.
- **RTMR-extended runtime values.** The SC, as part of its boot sequence inside the TEE, extends `RTMR3` (on TDX; equivalent register on other architectures) with the canonicalised concatenation `JCS({CONSOLE_URL, entity_id, sc_id, ingest_token_sha256, ca_export_token_sha256})` of every binding value the Console injected at deploy time. Any post-boot mutation of these values cannot retroactively alter the RTMR digest.
- **Report data + TLS session binding.** atlas-rs binds the attestation evidence to the TLS session the verifier negotiates: the SC's TLS leaf public-key digest is included in the report-data field, so a quote produced for one TLS session cannot be replayed against another. The verifier opens the TLS connection, captures the leaf SPKI, and validates the report-data binding before trusting the quote — the same mechanism Dev CVM verification uses. **TLS terminates inside the SC** (`:443` is served by shade's `cert-manager` + `nginx`); the Phala gateway forwards encrypted TCP via SNI routing only (§10.2). End-to-end TLS to the CVM is load-bearing for this binding — terminate-and-reproxy at the gateway would mean the verifier's TLS session terminates at Phala, breaking the report-data binding and letting a compromised Phala observe or rewrite the cleartext.

#### Console-side verification (provisioning, T-29, T-30)

At the `verify_attestation` step of the `security_cvm.provision` saga (§8.4), **before** the bearer plaintexts are exposed via `Operation.result`, the Console:

1. Opens an aTLS connection to `https://<security_cvms.fqdn>/tdx_quote` (the same surface Dev CVMs expose, served at the SC's `:443` via shade's nginx + cert-manager). The `fqdn` value is the row's, populated at the saga's `cf_cname_create` step before this verification step runs.
2. Captures the TLS leaf SPKI and uses it as the report-data binding input for the verifier.
3. Verifies the quote against the complete aTLS policy generated by Shade for this provisioning. The policy MUST include the authoritative `app_compose`, `expected_bootchain`, and `os_image_hash` as well as the RTMR replay inputs; verification MUST NOT relax to `dev()` / `disable_runtime_verification`:
   - **Shared guest measurement** equals the row's `expected_image_measurement` (captured at deploy time, see below). Mismatch refuses with `error_reason = "ATTESTATION_IMAGE_MISMATCH"` (§10.5).
   - **Application image and compose** match the full `app_compose` policy, including the digest-pinned SC image. A compose-hash, bootchain, or OS-image mismatch also refuses. App-image publication changes this policy, not the shared MRTD.
   - **RTMR3 digest** equals the JCS replay of the binding values the Console itself injected. Mismatch refuses with `error_reason = "ATTESTATION_RTMR_MISMATCH"`.
   - **Vendor freshness and signature chain**: standard atlas-rs checks against Intel PCS / AMD KDS using the verifier's built-in trust store.
4. Persists `image_measurement = expected_image_measurement` and `rtmr3_digest = <verified>` on the `security_cvms` row, plus `attestation_verified_at = now`. Emits `SECURITY_CVM_ATTESTATION_VERIFIED` (§11.2).

Only after these checks pass does the saga progress to its `succeeded` finaliser.

The verifier MUST implement the dstack TDX attestation protocol — atlas-rs (Rust) for components in the Rust ecosystem, a Python equivalent (subprocess to atlas-rs CLI, or a maintained Python binding) for the Console. Implementations MAY ship the verifier as a sidecar / library; the implementation choice is part of §18, not §10.

#### Per-deployment shared guest measurement

The Console captures `SECURITY_CVM_IMAGE_MEASUREMENT` onto each row so later verification is stable even if the configured dstack guest baseline changes. The value is the shared guest MRTD and MUST equal `DEV_CVM_IMAGE_MEASUREMENT`; it is not coupled to a particular SC application image. Operators rolling out a new SC app image:

- publish the image by immutable runtime-manifest digest;
- update `SECURITY_CVM_IMAGE_REF` and regenerate the complete Shade runtime policy that pins that digest;
- keep both measurement variables unchanged unless the underlying dstack guest boot baseline changes. When it does, obtain the new shared MRTD from a trusted provider canary and update both variables to the same value.

Existing rows keep their persisted guest baseline so a later baseline rotation does not retroactively flag them as drifted.

Per-entity custom SC images (e.g. a tenant requiring a specific image variant for compliance) are supported by reading both fields from a per-entity override in `entity_security_cvm_overrides` (§7.x) when present, falling back to the global config otherwise. The override table is a v1.1 surface; v1 ships with the global config only.

#### CA fetch

- **URL.** `https://<security_cvms.fqdn>/ca.pem` on port `:443`.
- **Authentication.** `Authorization: Bearer <CA_EXPORT plaintext>` from the row's stash (§5.7).
- **Attestation prerequisite.** The CA-fetch HTTP request MUST be issued **after** `verify_attestation` passes. The connection MUST reuse the same aTLS-verified TLS session whose leaf SPKI was bound into the attestation's report-data; reusing a session ensures the cert serving the CA bytes is the same cert the attestation endorsed.
- **Timeout.** 15 s.
- **Hostname validation.** The `fqdn` value is constructed at the `persist_tokens_and_stub` step from `sc-<token>.<SECURITY_CVM_BASE_DOMAIN>` and stored on the row; the Console MUST re-validate the hostname against `^[a-z0-9-]+\.[a-z0-9.-]+$` before issuing any request to it (defense-in-depth).

#### Operator diagnostic surface

`GET /entities/{id}/security-cvm/attestation` (§3.7) exposes the Console's most recent attestation verdict as a diagnostic for entity admins (`USER_MANAGE`) and platform operators. It is NOT a security-critical verification path — the SC's identity is established at provisioning by the Console (§10.4) and re-verified by the reconciler (below); the user's own machine never trusts the SC's CA directly (the SC's CA is injected into Dev CVMs by Console-driven env at deploy time, and the user's trust path to a Dev CVM is the Dev CVM's own aTLS verification). The route exists so operators can confirm the SC's measurement and last-verified timestamp; the CLI rendering is informational.

#### Drift detection (T-29 follow-on)

The reconciler (§9.2) re-attests each live SC at most once per `RECONCILER_ATTESTATION_INTERVAL_SECONDS` (default `21600` = 6 h, range `3600..86400`). If the shared measurement, full runtime policy, or RTMR drifts from the persisted deployment state, the reconciler:

1. Records `error_reason = "ATTESTATION_DRIFT"` on the `security_cvms` row.
2. Emits `SECURITY_CVM_ATTESTATION_DRIFT` (§11.2).
3. Pages the operator (§17). The Console does NOT auto-decommission — drift may be a legitimate guest-baseline or full-runtime-policy rollout that has not yet completed, but an ordinary app-image rebuild does not change MRTD.

The expected-measurement value is the ROW's `expected_image_measurement`, not the env config; see "Per-deployment shared guest measurement" above.

#### No TLS-SPKI pinning

The spec deliberately does NOT pin Console TLS SPKIs into the SC image, nor does it pin the TEE-vendor PCS / KDS chain at the Console:

- **Console TLS at the SC.** The SC contacts the Console at `CONSOLE_URL` using standard public-CA TLS validation. The honest residual: an attacker who compromises Phala's API to flip `CONSOLE_URL` and possesses a valid public-CA cert for the redirected hostname can intercept log shipping until the next reconciler attestation refresh detects the divergent `CONSOLE_URL` in RTMR3. The attack window is bounded by `RECONCILER_ATTESTATION_INTERVAL_SECONDS`; operators trading off log-leak exposure against attestation-refresh load can shorten it. Defense-in-depth: monitoring Phala admin actions detects the precondition (a Phala API call mutating env) before the redirect takes effect.
- **TEE-vendor SPKI at the Console.** atlas-rs handles vendor TLS validation against the documented Intel PCS / AMD KDS chains via its built-in trust store. A second layer of operator-managed SPKI pins would introduce rotation operational burden for marginal additional protection beyond what the verifier already enforces.

#### Re-binding

`CONSOLE_URL` cannot be rotated through `security_cvm.update` because it is RTMR-extended at boot and defines where the SC sends control-plane traffic. Changing it for an existing SC requires decommissioning and provisioning a replacement. The provider-backed `security_cvm.update` path is limited to image/config/bearer/CA/aTLS rebinding that the Console can re-render and re-attest safely.

### 10.4a Dev CVMs (Console as attestation verifier) — full runtime-policy pinning

Dev CVMs run user code: inside the CVM, the user has root. The trust property the Console enforces is therefore not "the inside of the CVM is honest" but "the CVM that booted is the operator-curated CVM whose compose locks the user-container into a network-isolated topology with the proxy sidecar as its only egress neighbour, and whose runtime-injected values are the ones the Console intended." Both halves are anchored in the same TEE attestation chain as the SC (§10.4).

The Dev CVM exposes `/tdx_quote` via shade's `attestation-service` sibling container (the same surface the CLI uses for per-tunnel verification, [CLI spec](cli.md) §6.1, §9.5). The Console reuses that endpoint and the same atlas-rs verifier the SC path uses. The Dev CVM additionally hosts the `/atls` WebSocket route for user-initiated aTLS-tunneled SSH sessions (`umbra tunnel`), but that route is the CLI's surface — the Console does not call it.

The Dev CVM is reachable at the stable, operator-controlled DNS name stored in `cvms.fqdn`, of the form `cvm-<26-base32-random>.<CLOUDFLARE_BASE_DOMAIN>`, provisioned in Cloudflare during the launch saga (§8.3). End-to-end TLS terminates inside the Dev CVM (shade's `cert-manager` + `nginx`, same as the SC); Phala's gateway forwards encrypted TCP only.

#### Attestation contract

Same primitives as §10.4: a hardware-rooted remote attestation report carrying

- **Shared guest measurement** (`MRTD` on TDX, equivalent on other architectures), captured by the hardware for the approved dstack guest boot baseline. It is the same baseline used by the entity's Security CVM and does not incorporate the Dev application image or compose.
- **Full runtime policy.** Shade's authoritative `app_compose`, `expected_bootchain`, and `os_image_hash` pin the digest-selected Dev image and compose topology. A divergent image or compose produces a compose-hash/runtime-policy mismatch even though the shared guest MRTD remains unchanged.
- **RTMR-extended runtime values.** At boot, the Dev CVM (via dstack-guest-agent) extends `RTMR3` with `JCS({cvm_id, console_url, dev_cvm_control_token_sha256, security_cvm_fqdn, security_cvm_proxy_port, security_cvm_proxy_token_sha256, security_cvm_ca_cert_sha256, authorised_ssh_keys_sha256})` — every runtime-injected binding value the Console intended for this Dev CVM. Any post-boot mutation of these env values cannot retroactively rewrite the RTMR digest.
- **Report data + TLS session binding.** Same atlas-rs mechanism: the Dev CVM's TLS leaf SPKI is bound into the report-data field, so a quote produced for one TLS session cannot be replayed against another. End-to-end TLS termination inside the CVM is load-bearing for this binding (§10.2, §14.10).

#### Console-side verification (launch saga, T-31, T-32)

At the `verify_attestation` step of the `cvm.launch` saga (§8.3), **before** the Dev CVM transitions to `RUNNING`, the Console:

1. Opens an aTLS connection to `https://<cvms.fqdn>/tdx_quote`. Retries with exponential backoff for up to `DEV_CVM_ATTESTATION_TIMEOUT_SECONDS` (§12, default `180`) to absorb the Phala boot window — `ATTESTATION_FETCH_FAILED` only fires after the timeout elapses without a reachable endpoint.
2. Captures the TLS leaf SPKI and uses it as the report-data binding input for the verifier.
3. Verifies the quote against the complete Shade aTLS policy derived from this launch. The authoritative `app_compose`, `expected_bootchain`, and `os_image_hash` MUST all be present; verification MUST NOT relax to a shared-MRTD-only policy:
   - **Shared guest measurement** equals the row's `expected_image_measurement` (captured at `persist_stub` from `DEV_CVM_IMAGE_MEASUREMENT`). Mismatch refuses with `error_reason = "ATTESTATION_IMAGE_MISMATCH"` (§10.5).
   - **Application image and compose** match the digest and topology in the full runtime policy. Compose-hash, bootchain, or OS-image mismatch refuses before the CVM reaches `RUNNING`.
   - **RTMR3 digest** equals the JCS replay of the binding values the Console injected at `phala_deploy` (Console URL, proxy host/port, Dev bearer hashes, SC CA digest, authorised SSH keys digest, plus the row's `cvm_id`). Mismatch refuses with `error_reason = "ATTESTATION_RTMR_MISMATCH"`.
   - **Vendor freshness and signature chain**: standard atlas-rs checks against Intel PCS / AMD KDS using the verifier's built-in trust store.
4. Persists `image_measurement = expected_image_measurement` and `rtmr3_digest = <verified>` on the `cvms` row, plus `attestation_verified_at = now`. Emits `CVM_ATTESTATION_VERIFIED` (§11.2).

Only after these checks pass does the saga progress to `await_sc_pull` and `finalise`. A Dev CVM that fails attestation is compensated: per-CVM Dev bearer rows are soft-deleted (so a later boot cannot reuse them), DNS records are deprovisioned, the Phala app is terminated, the row is soft-deleted, and the operation is marked `failed` with the typed `error.code`.

#### Per-deployment shared guest measurement

The expected measurement is captured at launch from `DEV_CVM_IMAGE_MEASUREMENT` and persisted on `cvms.expected_image_measurement` at the saga's `persist_stub` step. It identifies the dstack guest baseline, not the digest-pinned `DEV_CVM_IMAGE`. Operators rolling out a new Dev app image:

- publish the new image by immutable runtime-manifest digest and update `DEV_CVM_IMAGE`; Shade then generates the full runtime policy for that digest;
- use the repository's short-lived direct Dev canary to observe and record the provider's shared guest MRTD. That canary confirms the guest baseline used by the release; it does not derive an image-specific measurement;
- set `DEV_CVM_IMAGE_MEASUREMENT` and `SECURITY_CVM_IMAGE_MEASUREMENT` to that same MRTD. Keep both unchanged for an app-image-only release.

Existing rows retain the guest baseline captured at launch, so a later dstack baseline rotation does not retroactively flag them as drifted.

A future revision MAY accept a list of acceptable guest measurements to support staged dstack-baseline rollouts; v1 ships with one configured shared baseline. Compose generations coexist through their complete runtime policies, not through distinct MRTDs.

#### Drift detection

The reconciler (§9.2) re-attests each live Dev CVM at most once per `RECONCILER_ATTESTATION_INTERVAL_SECONDS`. If the shared measurement, full runtime policy, or RTMR drifts from the persisted deployment state, the reconciler:

1. Records `error_reason = "ATTESTATION_DRIFT"` on the `cvms` row.
2. Emits `CVM_ATTESTATION_DRIFT` (§11.2).
3. Pages the operator (§17). The Console does NOT auto-terminate — the Dev CVM's egress remains policed by the SC regardless of inside-CVM drift; an operator can investigate before terminating.

The expected-measurement value is the ROW's `expected_image_measurement`, not the env config.

#### Trust model inside the Dev CVM

The user has root inside their compose. The Console claims nothing about what the user does with that root. What it claims is:

- The shared dstack guest booted with the approved MRTD, while the Dev image and compose matched the authoritative full runtime policy (`app_compose`, bootchain, and OS-image fields).
- The injected runtime values (where the proxy sidecar talks to, which SSH keys can log in, which CA the user trusts for the SC's certificate) are the Console's — anchored in `RTMR3`.
- Network egress from the user's container is whatever the SC policy permits, regardless of whether the request leaves through the proxy sidecar or is sent directly by a user who extracted the sidecar's `PROXY_AUTH`. The SC is the egress boundary; the sidecar is UX, not a security layer (§1.6).

A user who attacks the sidecar (kernel exploit, container-escape, sidecar RCE) gains at most the sidecar's own capability — which is "talk to the SC's egress proxy as this Dev CVM's `PROXY_AUTH`." That capability is bounded by the SC's per-CVM policy and is no different from the legitimate path.

#### No TLS-SPKI pinning

Same posture as §10.4: the Console relies on atlas-rs's built-in TEE-vendor trust store and on standard public-CA TLS for the Dev CVM's leaf cert; no additional operator-managed SPKI pinset is required.

#### Re-binding

RTMR-extended values cannot be mutated inside a running Dev CVM without changing what the next attestation reports. For a current provider-managed Umbra deployment, the supported rebind path is `cvm.update`: the Console updates the existing provider deployment in place, injects fresh runtime material, verifies the new RTMR3 binding, and replaces the active policy bundle. A persisted `SECURITY_CVM_REBIND_REQUIRED` marker identifies a legacy deployment whose runtime and provider-management capability are unproven. The renamed build rejects its update; use the pre-Umbra control plane to terminate/decommission the preserved resource, then launch a replacement under Umbra. SSH authorized-key changes remain excluded and require terminating the CVM and launching a replacement.

### 10.5 Typed `error_reason` (T-17)

`cvms.error_reason` and `security_cvms.error_reason` are surfaced verbatim by `GET /cvms/{id}` and `GET /entities/{id}/security-cvm` (§3). To prevent leakage of upstream stderr / paths / hostnames into tenant-visible responses, `error_reason` MUST be a typed code drawn from the closed set below, with an optional sanitised payload chosen from a per-code template.

| Code | Used by | Optional payload fields |
|---|---|---|
| `CVM_NOT_FOUND` | Dev CVM launch / terminate saga re-entry when the target row disappeared unexpectedly | `state` |
| `SECURITY_CVM_NOT_FOUND` | Security CVM provisioning saga re-entry when the target row disappeared unexpectedly | `state` |
| `SHADE_BUILD_FAILED` | Dev CVM launch/update or Security CVM provision/update saga while rendering Shade build or policy artifacts | `adapter`, `reason` (allowlisted shade error reason such as `invalid_shade_dir`, `cli_failed`) |
| `SECURITY_CVM_CA_UNAVAILABLE` | Dev CVM launch saga step `phala_deploy` before injecting the entity SC CA bundle | `component` |
| `SECURITY_CVM_ATLS_POLICY_UNAVAILABLE` | Dev CVM launch saga step `phala_deploy` before injecting the entity SC aTLS policy | `component` |
| `PHALA_DEPLOY_FAILED` | launch saga step `phala_deploy` | `phala_status` (normalised, §10.1) |
| `PHALA_APP_MISSING` | DNS provisioning or provider cleanup after Phala deploy metadata is unexpectedly absent | `field` |
| `PHALA_GATEWAY_MISSING` | CNAME provisioning after Phala deploy metadata is unexpectedly missing a gateway host | `field` |
| `PHALA_TERMINATE_FAILED` | terminate saga step `phala_terminate` | `phala_status` |
| `PHALA_NEVER_RUNNING` | provisioning saga step `await_phala_running` | `elapsed_seconds` (int) |
| `PHALA_OBSERVED_FAILED` | reconciler drift detection | (none) |
| `PROVIDER_DEPLOYMENT_MISSING` | CVM update route/saga when provider metadata lacks a deployment id | `field` |
| `PROVIDER_UPDATE_FAILED` | Dev CVM or Security CVM update saga `provider_update` | `adapter`, `reason` |
| `PROVIDER_COMPOSE_NOT_APPLIED` | Dev CVM update saga `await_provider_running` when the provider-visible runtime compose hash does not match the pending compose after the update wait window | `adapter`, `expected_compose_sha256`, `provider_compose_sha256` |
| `CLOUDFLARE_TXT_FAILED` | launch saga step `cf_txt_create` | `cloudflare_code` (Cloudflare's typed error code, validated against an allowlist) |
| `CLOUDFLARE_CNAME_FAILED` | launch saga step `cf_cname_create` | `cloudflare_code` |
| `CA_EXPORT_TTL_EXPIRED` | provisioning saga step `fetch_ca` | (none) |
| `CA_FETCH_FAILED` | provisioning saga step `fetch_ca` (`reason="fqdn_unresolvable"` when the SC FQDN never resolved from the Console's resolver within `SECURITY_CVM_FQDN_RESOLVE_TIMEOUT_SECONDS`) | `http_status` (int), `reason` (string) |
| `ATTESTATION_FETCH_FAILED` | SC provisioning/update saga `verify_attestation` step (§10.4); Dev CVM launch/update saga `verify_attestation` step (§10.4a); reconciler attestation refresh for either CVM type (§9.2) | `http_status` (int) |
| `ATTESTATION_QUOTE_INVALID` | SC provisioning/update saga, Dev CVM launch/update saga, reconciler, on-demand `GET /entities/{id}/security-cvm/attestation?probe=true` | `vendor_error_code` (Intel PCS / AMD KDS error code, validated against an allowlist) |
| `ATTESTATION_IMAGE_MISMATCH` | SC provisioning/update saga, Dev CVM launch/update saga; on-demand attestation fetch | `expected_image_measurement` (hex 96), `reported_image_measurement` (hex 96) |
| `ATTESTATION_RTMR_MISMATCH` | SC provisioning/update saga, Dev CVM launch/update saga; on-demand attestation fetch | (none) — the offending RTMR inputs may include secrets (token hashes); the audit row's `after` field carries the comparison while the operator-visible `error_reason` does not echo them |
| `ATTESTATION_SESSION_BINDING_INVALID` | any attestation fetch | (none) — atlas-rs reported the quote's report-data does not bind the negotiated TLS session (§10.4, §10.4a) |
| `ATTESTATION_DRIFT` | reconciler attestation refresh for either CVM type (§9.2); on-demand fetch returning `409` | `drift_kind` (`"image"` / `"rtmr3"` / `"both"`) |
| `PROXY_AUTH_MISSING` | Dev CVM launch/update saga `await_sc_pull` step | (none) |
| `SC_PULL_TIMEOUT` | Dev CVM launch/update saga `await_sc_pull` step | `elapsed_seconds` (int), `timeout_seconds` (int) |
| `SECURITY_CVM_REBIND_REQUIRED` | persisted legacy Dev CVM replacement marker; no current Umbra saga produces or clears it | (none) |
| `POLICY_BUNDLE_MISSING` | Dev CVM launch/update saga finalise when the generated policy bundle is absent from metadata | `field` |
| `POLICY_INVALID` | combined policy validation prior to push | `field` (the offending field name in the policy schema) |
| `INVALID_PHALA_RESPONSE` | any Phala adapter call | `field` (one of `app_id`, `gateway_host`) |
| `INTERNAL` | any unexpected exception path | (none) |

Tenant-visible `error_reason` is rendered server-side as `{"code": <CODE>, "fields": {...}}`. The Console MUST NOT include any free-text component (no upstream stderr, no exception message) in this object. Implementations MAY log the raw upstream output internally (§13.4 redaction rules apply) but MUST NOT expose it to tenant API responses.

### 10.6 Cross-integration invariants

- **No external call inside a database transaction.** Every saga step commits before calling Phala, Cloudflare, IdP, or a Security CVM, and the result is captured in the next commit.
- **Every external response is validated at the boundary.** Phala outputs through §10.1's regexes; Cloudflare responses through the `success` flag plus field presence; IdP responses through §5.5; Security CVM responses through HTTP status only (the body is just the PEM).
- **Secrets never appear in audit, logs, or error responses.** §13.4 lists the denylist; §10.5's typed `error_reason` ensures no upstream text leaks into tenant responses.
- **Outbound TLS uses standard public-CA chain validation.** No SPKI pinning is configured for any integration; the spec accepts CA-MITM as a state-level adversary class outside its scope (§1.5). Phala is invoked via subprocess; the CLI does its own TLS internally and the Console treats it as a process boundary.

## 11. Audit logging

The Console writes a tamper-evident, hash-chained audit trail. It is the canonical record of every state-changing action against managed resources, the source of truth for security-incident investigation, and the substrate that survives a Postgres-superuser compromise (T-6).

### 11.1 Recording contract

Every state-changing service method takes an `AuditRecorder` instance and stages one audit row on the same `AsyncSession` as the business mutation. The session commit is the caller's responsibility; the audit row and the business row commit atomically — either both land, or neither does.

`AuditRecorder` carries an `ActorContext = (user_id, email, ip_address, request_id)`:

- For an HTTP-driven action, the context is built by the FastAPI request dependency from `(sub, entity_id, jti)` extracted from the verified JWT (§5.2) plus `email` read from the hydrated `User` row at §5.2 verification step 8 — the JWT body does NOT carry an `email` claim (Curity: minimise PII in JWTs). `ip_address` is the resolved client IP (§13.8) and `request_id` is the resolved request id (§2.7).
- For a system-driven action, the context is `(user_id=None, email="system@bootstrap" | "reconciler@umbra.invalid", ip_address=None, request_id=<synthesised>)`.
- For a device-flow login, the recorder's actor is upgraded *after* OIDC resolution to the resolved `User` so any audit row emitted in the same request carries the correct identity.

A read route MUST NOT write audit rows, with one exception: `GET /operations/{id}` writes an `OPERATION_RESULT_DISCLOSED` row when the read first exposes a one-shot bearer payload (§8.4). High-volume internal ingest (`/internal/traffic-logs`, §4.3) is excluded — audit is for managed-resource changes, not data-plane observations.

Each `audit_events` row writer MUST atomically:

1. Acquire the `seq` advisory lock (Postgres `pg_advisory_xact_lock(<known constant>)`) so the chain stays linear under concurrent writers.
2. SELECT the previous row's `row_hash` (or `SHA-256("")` if this is the first row).
3. INSERT the new row with `prev_hash` set to that value and `row_hash = SHA-256(JCS(row_minus_row_hash))`.
4. Commit.

The advisory lock makes the linearisation explicit; without it, two concurrent transactions could both observe the same `prev_hash` and produce a fork. The lock is released at commit/rollback.

`JCS` is RFC 8785 and is load-bearing for non-ASCII: strings serialize as ECMAScript `JSON.stringify` does — raw UTF-8, escaping only control characters, quote and backslash. Emitting `\uXXXX` instead (Python's `json.dumps` default) produces a `row_hash` no conformant verifier can reproduce, so a genuine row reads as tampered and the CLI's chain check (`docs/specs/cli.md` §3.6, `umbra audit events`) refuses the whole page. Builds before 2026-08-06 escaped non-ASCII; rows they wrote keep that historical `row_hash` and remain unverifiable under JCS even though their bytes are intact and their chain links hold. Those rows are an accepted artifact — they MUST NOT be rewritten (that would break every subsequent `prev_hash`), and a verifier reporting them is correct.

### 11.2 Action catalog

The `audit_action` enum is the closed set below. Adding a value is a Alembic migration (§15). Deprecating a value follows §2.1.

| Action | Emitted from | When |
|---|---|---|
| `ENTITY_CREATED` | bootstrap, `POST /entities` | First entity creation or platform-operator tenant onboarding. |
| `ENTITY_UPDATED` | (reserved) | Reserved for a future `PATCH /entities/{id}` route; emit when wired. |
| `USER_REGISTERED` | `POST /entities/{id}/users`, bootstrap, §5.6 OIDC materialization | One row per registration. |
| `USER_DEACTIVATED` | `POST /entities/{id}/users/{user_id}/actions/deactivate` (§3.3) | One row per deactivation. `before` carries `{deactivated_at: null}`; `after` carries `{deactivated_at, deactivated_by}`. |
| `USER_REACTIVATED` | `POST /entities/{id}/users/{user_id}/actions/reactivate` (§3.3) | One row per reactivation. `before` carries the prior `{deactivated_at, deactivated_by}`; `after` carries `{deactivated_at: null}`. |
| `USER_ERASED` | `DELETE /entities/{id}/users/{user_id}` (§3.3) | One row per erasure. `before` carries the user's pre-tombstone `{email, name}` (these PII fields then get redacted by the §11.9 procedure as part of the same audit-trail walk — the erase row itself is one of the rows whose `before` is rewritten); `after` carries `{deleted_at, deleted_by, tombstone_email}`. The `actor_id` is the eraser (the user themselves on self-erase, or the platform operator). |
| `PERMISSION_GRANTED` | grant routes | One row per *newly* granted permission. |
| `PERMISSION_REVOKED` | revoke routes | One row per *actually* revoked permission. |
| `PROFILE_CREATED` | `POST /entities/{id}/profiles` | |
| `PROFILE_DELETED` | `DELETE /profiles/{id}` | |
| `PROFILE_USER_ASSIGNED` | `POST /profiles/{id}/users` | |
| `PROFILE_USER_REMOVED` | `DELETE /profiles/{id}/users/{user_id}` | |
| `SSH_KEY_ADDED` | `POST /me/keys` | |
| `SSH_KEY_REMOVED` | `DELETE /me/keys/{key_id}` | |
| `USER_SECRET_SET` | `PUT /me/secrets/{name}` | `after` carries `name` + `allowed_hosts` only — never the value. |
| `USER_SECRET_DELETED` | `DELETE /me/secrets/{name}` | `before` carries `name` + `allowed_hosts` only. |
| `CVM_LAUNCHED` | `cvm.launch` saga `succeeded` finaliser | One row per Dev CVM reaching `RUNNING`. |
| `CVM_UPDATED` | `cvm.update` saga `succeeded` finaliser | Active aTLS policy bundle refreshed. |
| `CVM_UPDATE_FAILED` | `cvm.update` saga failure | Typed failure code only; no provider stderr or secret material. |
| `CVM_STARTED` | sync `start` action | |
| `CVM_STOPPED` | sync `stop` action; reconciler-observed Phala `STOPPED` drift (§9.2) | |
| `CVM_FAILED` | reconciler-observed Phala `FAILED` drift (§9.2) | `after.error_reason = "PHALA_OBSERVED_FAILED"` |
| `CVM_TERMINATED` | `cvm.terminate` saga `succeeded` finaliser, or `cvm.launch` compensation | |
| `SUBDOMAIN_PROVISIONED` | `cvm.launch` saga finaliser | DNS records persisted. |
| `SUBDOMAIN_DEPROVISIONED` | `cvm.terminate` saga | At least one DNS record was deleted. |
| `SECURITY_CVM_PROVISIONING_STARTED` | `security_cvm.provision` saga provider-deploy step | After the provider deployment id is recorded. |
| `SECURITY_CVM_PROVISIONED` | `security_cvm.provision` saga `finalise` | After CA fetch. |
| `SECURITY_CVM_PROVISIONING_FAILED` | `security_cvm.provision` saga compensation | One row per failed provisioning, including attestation-failure compensation paths (§10.4). |
| `SECURITY_CVM_UPDATED` | `security_cvm.update` saga `succeeded` finaliser | Includes `ca_changed` and the reserved `dev_cvms_requiring_update` list; CA-only updates leave the list empty for refresh-capable Umbra runtimes and do not clear persisted legacy markers. |
| `SECURITY_CVM_UPDATE_FAILED` | `security_cvm.update` saga failure | Typed failure code only; no provider stderr or secret material. |
| `SECURITY_CVM_STOPPED` | reconciler-observed Phala `STOPPED` drift (§9.2) | |
| `SECURITY_CVM_FAILED` | reconciler-observed Phala `FAILED` drift (§9.2) | `after.error_reason = "PHALA_OBSERVED_FAILED"` |
| `SECURITY_CVM_DECOMMISSIONED` | `DELETE /entities/{id}/security-cvm` | One row per decommission. |
| `SECURITY_CVM_ATTESTATION_VERIFIED` | `security_cvm.provision` / `security_cvm.update` saga, reconciler attestation refresh, `GET /entities/{id}/security-cvm/attestation?probe=true` | One row per successful attestation verification. `after` carries `{image_measurement, rtmr3_digest, attestation_verified_at, source: "provisioning"\|"update"\|"reconciler"\|"on_demand"}`. |
| `SECURITY_CVM_ATTESTATION_DRIFT` | reconciler attestation refresh, `GET /entities/{id}/security-cvm/attestation?probe=true` | One row per detected drift. `before` carries `{image_measurement, rtmr3_digest}` (persisted state); `after` carries `{image_measurement, rtmr3_digest, drift_kind: "image"\|"rtmr3"\|"both"}` (freshly observed). |
| `CVM_ATTESTATION_VERIFIED` | `cvm.launch` / `cvm.update` saga `verify_attestation` step, reconciler attestation refresh (§9.2) | One row per successful Dev CVM attestation verification. `after` carries `{image_measurement, rtmr3_digest, attestation_verified_at, source: "launch"\|"update"\|"reconciler"}`. |
| `CVM_ATTESTATION_DRIFT` | reconciler attestation refresh (§9.2) | One row per detected Dev CVM drift. `before` carries `{image_measurement, rtmr3_digest}` (persisted state); `after` carries `{image_measurement, rtmr3_digest, drift_kind: "image"\|"rtmr3"\|"both"}` (freshly observed). |
| `CVM_PROFILE_ATTACHED` | `POST /cvms/{id}/profiles` (§3.6); `cvm.launch` saga finaliser (one row per profile in `profile_ids`). | One row per attachment. `before` is null; `after` carries `{cvm_id, profile_id, profile_name, policy_version}`. |
| `CVM_PROFILE_DETACHED` | `DELETE /cvms/{id}/profiles/{profile_id}` (§3.6). | One row per detach. `before` carries `{cvm_id, profile_id, profile_name, policy_version_before}`; `after` carries `{policy_version_after}`. |
| `PROFILE_POLICY_UPDATED` | `PATCH /profiles/{id}` (§3.4) when `policy` changed. | `before.policy_sha256` and `after.policy_sha256` are recorded so the audit row size stays bounded; the full policies live on the `entity_profiles` row's history (or a separate version table — implementation detail). |
| `AUTH_SESSION_ISSUED` | `POST /auth/device/poll` success | New JWT pair issued. |
| `AUTH_SESSION_REFRESHED` | `POST /auth/refresh` success | Refresh-token rotation. |
| `AUTH_SESSION_REVOKED` | `POST /auth/logout` | Per-session revocation. |
| `AUTH_REFRESH_REUSE_DETECTED` | `POST /auth/refresh` presenting an already-redeemed refresh token (§5.2) | High-signal probable-theft event. `before` carries `{family_root_jti, replayed_jti, redeemed_at, original_ip, original_request_id}`; `after` carries `{revoked_jti_count, revoked_refresh_token_count, replay_ip, replay_request_id}`. The `actor_id` on this row MUST be the user the family belongs to — even though the request that triggered detection may have been the attacker's. |
| `OAUTH_IDENTITY_LINKED` | first `oauth_identity` insert per `(user, provider)` | First-time link (§5.6 step 7). |
| `OAUTH_REBIND_REFUSED` | `/auth/device/poll` returning 403 due to subject change (T-3) | Defensive log line for re-bind attempts. |
| `OPERATION_RESULT_DISCLOSED` | `GET /operations/{id}` first read of a one-shot result | One row per disclosure of a `<SecurityCVMProvisionResult>`. |
| `AUDIT_EXPORT_REQUESTED` | `POST /audit/export` submission | |
| `AUDIT_EXPORT_ISSUED` | `audit.export` operation `succeeded` finaliser | Records `row_count`, `byte_size`, `sha256` of the artefact. |
| `JWT_KEY_ROTATED` | `POST /admin/keys/rotate` | One row per rotation. |
| `QUOTA_SET` | `PATCH /entities/{id}/quotas/{resource}` (§3.13); `PATCH /users/{id}/quotas/{resource}` (§3.13) | One row per upsert. `before` carries the prior limit (or null when source was `default`); `after` carries `{scope, scope_id, resource, limit}`. |
| `QUOTA_CLEARED` | `DELETE /entities/{id}/quotas/{resource}` (§3.13); `DELETE /users/{id}/quotas/{resource}` (§3.13) | One row per cleared override. `before` carries the previous limit; `after = null`. |
| `SESSIONS_REVOKED` | `POST /admin/sessions/revoke` | Predicate echoed in `after`; `revoked_jti_count` recorded. |

### 11.3 Row schema

Defined in §7.18. The fields the writer chooses to populate in `before` / `after` MUST follow the conventions:

- For `_CREATED` events, `before = null`, `after` contains the inserted row's externally-visible fields.
- For `_REMOVED` / `_DECOMMISSIONED` / `_DELETED` events, `before` contains the row's externally-visible fields prior to soft-delete; `after = null`.
- For mutations, both are populated. Field name MUST match the resource representation in §2.3.
- Secrets MUST NEVER appear in `before` or `after`. Sensitive fields enumerated in §13.5's denylist MUST be redacted to `"<redacted>"` at row-construction time, before the row reaches the DB — the audit-writer is the boundary, not the log emitter. The runtime log-redaction processor (§13.5) is a defense-in-depth alarm, not the primary defense for audit payloads.
- `description` MUST be a templated string with no caller-controlled text; templates are a closed set tied to the action.
- `request_id` MUST be the resolved request id (§2.7) or `null` for non-HTTP actors.
- `prev_hash` and `row_hash` are computed at insert (§11.1).

### 11.4 Read API and entity scoping

`GET /audit/events` (§3.9) scopes results to:

- Rows whose `actor_id` belongs to the caller's entity (`actor_id IN (SELECT id FROM users WHERE entity_id = caller.entity_id)`); OR
- Rows whose `target_id` resolves to a resource owned by the caller's entity, joining through the appropriate aggregate's `entity_id` chain. This brings system-actor rows (reconciler, scheduler) into the tenant's view when they pertain to the tenant's own resources.

The implementation MAY materialise the `target → entity_id` resolution as a denormalised column (`entity_id` on `audit_events`) to make the query cheap; if so, the column is populated by the writer at insert and is part of §7.18's schema. Either approach is conformant.

Cursor pagination uses a `(seq ASC)` keyset (the chain order, not the `timestamp` order — clock skew between writers could otherwise produce weird interleaving).

### 11.5 Audit export

`POST /audit/export` (§3.10) is gated by `AUDIT_EXPORT` (T-21) — distinct from `AUDIT_VIEW` because bulk export produces an artefact that survives outside the Console. The export Operation:

1. Materialises the rows matching the supplied filters (paginating internally; row cap `1_000_000` per export).
2. Streams them as `csv` or `ndjson` to the configured artifact store. v0 supports `file://` for local testing and an external Postgres store for production. The Postgres store MUST be separate from the Console runtime database and use credentials separate from `DATABASE_URL`; `AUDIT_EXPORT_BUCKET` is a `postgresql://`/`postgres://` DSN with optional `table=<identifier>` (active default `umbra_audit_export_artifacts`). Legacy deployments MAY set `table=concrete_audit_export_artifacts` only as an explicit migration window. The external table MUST be pre-created and grant the writer `INSERT, SELECT` only:

```
CREATE TABLE umbra_audit_export_artifacts (
  object_key TEXT PRIMARY KEY,
  content BYTEA NOT NULL,
  content_type TEXT NOT NULL,
  content_sha256 CHAR(64) NOT NULL,
  row_count BIGINT NOT NULL,
  byte_size BIGINT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT INSERT, SELECT ON umbra_audit_export_artifacts TO export_writer;
REVOKE UPDATE, DELETE ON umbra_audit_export_artifacts FROM export_writer;
```

   S3/R2/GCS object-lock backends are future extensions and are not accepted by the v0 implementation.
3. Computes `sha256` of the artefact.
4. Issues a one-time signed URL valid for 5 minutes; the URL is single-use. The external store rejects overwriting by primary key / role grants, while the Console tracks URL redemption in `audit_export_artifacts.redeemed_at` and MAY mirror that timestamp into the operation result.
5. Sets `operations.result = {download_url, expires_at, content_type, sha256, row_count, byte_size}`.
6. Emits `AUDIT_EXPORT_ISSUED`.

CSV-injection defense (T-18): every cell whose first non-whitespace character is `=`, `+`, `-`, `@`, `|`, `\t`, `\r`, or `\n` is prefixed with a single quote. CR / LF inside cell values are replaced with spaces. The Content-Disposition filename is built from validated UUIDs only — no header injection vector.

### 11.6 Tamper-evident chain (T-6)

Every `audit_events` row carries `prev_hash` and `row_hash` (§7.18). The chain extends with the linearisation lock from §11.1 so a verifier can replay it sequentially:

```
previous = null
for row in audit_events ORDER BY seq:
    expected_prev = SHA-256(empty) if previous is null else previous.row_hash
    assert row.prev_hash == expected_prev
    assert row.row_hash == SHA-256(JCS(row_minus_row_hash))
    previous = row
```

The replay processes every committed row in ascending `seq` order, from the first row through the latest, and verifies the hash links between adjacent rows. Numeric `seq` continuity is not an invariant: PostgreSQL sequences are non-transactional, so a rolled-back insert can legitimately consume a value. This replay is the only place a *deleted* row is detectable: deleting an interior row breaks the next row's `prev_hash` link or its recomputed `row_hash`, while deleting the tail breaks the latest anchor binding. No client can distinguish such deletion from a row that entity scoping (§11.4) or a filter withheld. The `umbra audit events` chain check verifies what a scoped page can prove (`docs/specs/cli.md` §3.6); the end-to-end replay of §19.6 is what proves the chain whole.

The chain is anchored periodically to an external append-only store:

- A scheduler-driven task (§9.2 step 5) takes the latest `(seq, row_hash)` and writes it to the configured external Postgres anchor store (`AUDIT_ANCHOR_TARGET`, §12). The bytes committed externally are `JCS({last_seq,last_row_hash,anchored_at,console_kid})`.
- `AUDIT_ANCHOR_TARGET` MUST be a `postgresql://` or `postgres://` DSN for a database that is separate from the Console runtime database and uses credentials separate from `DATABASE_URL`. The optional query parameter `table=<identifier>` selects the external table name; the active default is `umbra_audit_anchors`. Legacy deployments MAY set `table=concrete_audit_anchors` only as an explicit migration window. Other query parameters are passed to the Postgres driver. The table MUST be pre-created by the operator:

```
CREATE TABLE umbra_audit_anchors (
  id UUID PRIMARY KEY,
  last_seq BIGINT NOT NULL,
  last_row_hash CHAR(64) NOT NULL,
  anchored_at TIMESTAMPTZ NOT NULL,
  console_kid TEXT NOT NULL,
  payload JSONB NOT NULL,
  payload_sha256 CHAR(64) NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
GRANT INSERT, SELECT ON umbra_audit_anchors TO anchor_writer;
REVOKE UPDATE, DELETE ON umbra_audit_anchors FROM anchor_writer;
```

- The external commitment digest is recorded in `audit_anchors` (§7.19) so a verifier can correlate the in-database chain with the external evidence.
- Cadence: at least one anchor per hour (`AUDIT_ANCHOR_INTERVAL_SECONDS`, default `3600`, range `60..86400`); also one anchor on graceful shutdown (lifespan stop hook).

The §19.6 server-side verifier MUST replay every committed row in the global chain in ascending `seq` order, from the first row through the current tip, then validate the latest local anchor against its correlated row in the external anchor store:

- Canonicalize the external payload as `JCS({last_seq,last_row_hash,anchored_at,console_kid})` and require `payload_sha256 == SHA-256(canonical_payload)`.
- Require the four canonical payload values to match the external row's typed columns and the corresponding latest local `audit_anchors` values, and require the external commitment digest recorded locally to equal the external `payload_sha256`.
- Require an `audit_events` row at the anchor's `last_seq` whose `row_hash` equals the anchored `last_row_hash`. The anchor binds that row, not necessarily the current live tip. Every row after `last_seq` is a valid unanchored tail only if the same full-chain replay verifies it through the current tip.

A missing local or external anchor, missing anchored sequence, malformed payload, digest or correlation mismatch, anchored-row hash mismatch, broken hash link, `prev_hash` mismatch, or recomputed `row_hash` mismatch is a verification failure. A numeric `seq` gap alone is not a failure. Each failed replay MUST increment `umbra_console_audit_chain_verification_failures_total`; the operator's alerting layer MUST page on that signal (§17.1, §17.6). A legitimate append after the latest anchor does not fail verification merely because the current tip differs from the anchored row.

A Postgres superuser who deletes, reorders, or rewrites rows breaks the replayed chain or its binding to the separately credentialed external anchor. Both are detectable by §19's verification job.

The `audit_anchor_target` writer credential MUST be different from the Console's runtime credentials (§15.5) so that compromising the Console process does not also compromise the anchor target. S3/object-lock and Rekor-style transparency-log targets are future extensions and are not accepted by the v0 implementation.

### 11.7 Immutability and role enforcement

No application code path issues `UPDATE` or `DELETE` against `audit_events`. The spec REQUIRES Postgres role privileges that enforce this (§15.5):

- The Console runtime role: `SELECT, INSERT` only on `audit_events` and `audit_anchors`; no `UPDATE`, no `DELETE`.
- The migration role: full DDL.
- The anchor-writer role: `INSERT, SELECT` on `audit_anchors`; nothing on `audit_events`.

The chain plus the role separation is the mitigation for T-6.

### 11.8 Retention

- **`audit_events`.** Retained indefinitely. Pruning is FORBIDDEN — the chain MUST remain verifiable end-to-end. Operators who need a bounded retention window MUST implement legal-hold-aware archival via a downstream consumer (e.g. ship rows to cold storage with object lock, then prune the live DB *after the chain has been re-anchored to the cold store*); this archival path is NOT part of v1.
- **`traffic_logs`.** Retained for `TRAFFIC_LOG_RETENTION_DAYS` (default `90`, range `7..730`). A daily prune job DELETEs rows with `timestamp < now - retention_days`. The prune job runs under a dedicated, time-limited DB role (§15.5) so the Console's runtime role retains its `INSERT`-only privilege.

### 11.9 PII and data-subject erasure

`actor_email`, `before.email`, and `after.email` are PII (§1.3 A5). The user-erase path (`DELETE /entities/{id}/users/{user_id}`, §3.3) is the GDPR Article 17 ("right to be forgotten") implementation. It runs as one logical procedure with two layers:

**Layer 1: user-row tombstone** (handled by the route's service layer under the runtime DB role).
- Tombstone `users.email` to `'<erased-' || sha256(id)[:12] || '>@' || entity.domain` and `users.name` to `'<erased>'`.
- Set `users.deleted_at = now()`, `users.deleted_by = caller`.
- Hard-DELETE `oauth_identities`, `ssh_keys`, `user_permissions`, `profile_users`, `refresh_tokens` for that user. Any in-flight access tokens land in `revoked_tokens` via the paired `access_jti` so the next request fails.
- Emit `USER_ERASED` audit row (§11.2).

**Layer 2: audit-trail redaction** (handled under the `umbra_console_redactor` role, §15.5).
- A "right to be forgotten" request MUST NOT DELETE `audit_events` rows (§11.7) or break the chain.
- Wherever the user's PII appears in `audit_events.actor_email`, `audit_events.before.email`, `audit_events.after.email` (including the `before` of the just-emitted `USER_ERASED` row, which carried the pre-tombstone email), the redaction step REPLACES it with the same `'<erased-' || sha256(user_id)[:12] || '>@' || entity.domain` tombstone — pseudonymization rather than deletion. The chain is therefore traversable: an investigator can still group all of one person's actions by the tombstone string, but the tombstone reveals no PII to a reader who doesn't already hold the `(user_id, entity)` mapping.
- The hash chain MUST be re-computed from the earliest redacted row's `seq` forward, the new chain re-anchored to the external store (§11.6), and the old anchors retained alongside the new ones with a `redaction_event_seq` marker so a future verifier can prove "the chain bifurcates here because of erasure, not tampering".

**Authorization for the layer-2 step.**
- **Self-erase path.** When a user erases themselves (path `user_id == caller.user_id`), the erase route is gated only by self-identity; no separate DPO approval is required because the data subject is exercising their own right. The redaction layer still runs under the `umbra_console_redactor` role (the runtime role doesn't hold `UPDATE` on `audit_events`); the role is granted just-in-time for this run and revoked after.
- **Operator-driven path.** When `PLATFORM_OPERATOR` invokes the route on behalf of an entity admin's out-of-band request (e.g. a signed email from a tenant DPO), the operator's audit-row attribution is the human accountability record. The spec deliberately does NOT expose an in-band "tenant admin proposes; operator confirms" workflow — the channel is intentionally external so it forces a human decision and creates a paper trail outside the Console.

`traffic_logs` rows are pruned by retention (§11.8); PII concerns there are bounded by the retention window. The user-erase procedure does not touch `traffic_logs` — by the time erasure is requested, the user's CVMs have been terminated (§8.1) and traffic-log retention will eventually prune their entries naturally.

## 12. Configuration

The Console reads configuration from two sources: **plain values** (env vars or a config file) and **secrets** (file-mounted or KMS-resolved). Plain values may live in env; secrets MUST NOT (T-1, T-19). The split is enforced at boot.

### 12.1 Configuration values

`*` marks values that MUST be configured to operate (no useful default). `secret` marks values resolved through §12.2.

| Variable | Type | Default | Notes |
|---|---|---|---|
| `DATABASE_URL` | string | `postgresql+asyncpg://umbra:umbra@localhost:5432/umbra` | Async Postgres DSN. Production MUST override. |
| `JWT_ALGORITHM` | enum `EdDSA` / `RS256` | `EdDSA` | Asymmetric algorithm for issued JWTs (§5.2). `HS256` is forbidden. |
| `JWT_PRIVATE_KEY_REF` `secret` `*` | URI | (none) | URI of the active signing key (file path, KMS reference). §12.2. |
| `JWT_PUBLIC_KEYS_REF` `*` | URI | (none) | URI of a JWKS-shaped JSON file listing every active and verifying public key with their `kid`s. The file MUST contain at least one entry whose `kid` matches the active signing key. |
| `JWT_ACTIVE_KID` `*` | string | (none) | The `kid` used for new issuance. MUST appear in `JWT_PUBLIC_KEYS_REF`. |
| `JWT_ACCESS_TOKEN_TTL_SECONDS` | int 300..3600 | `3600` | TTL for issued JWTs. |
| `JWT_REFRESH_TOKEN_TTL_SECONDS` | int 86400..7776000 | `2592000` | Refresh-token TTL (§5.2). |
| `JWT_ISSUER` | string | `umbra-console` | `iss` claim and verification value. |
| `JWT_AUDIENCE` | string | `umbra-console` | `aud` claim and verification value. |
| `JWT_LEEWAY_SECONDS` | int 0..300 | `30` | Clock-skew tolerance for `iat` / `exp`. |
| `SECRET_INJECTION_KEK_B64` `secret` `*` | base64 bytes | (none) | 32-byte AES-GCM key-encryption key for `profile_secret_material.ciphertext` (§7.6a). MUST be distinct from JWT signing material. |
| `GOOGLE_OIDC_CLIENT_ID` `*` | string | (none) | OIDC client id at Google. |
| `GOOGLE_OIDC_CLIENT_SECRET` `secret` `*` | string | (none) | OIDC client secret at Google. |
| `GOOGLE_OIDC_DEVICE_CLIENT_ID` | string | (= `GOOGLE_OIDC_CLIENT_ID`) | Device-code flow (§5.4.2) client id — a Google "TVs and Limited Input devices" client. Falls back to `GOOGLE_OIDC_CLIENT_ID` when unset. |
| `GOOGLE_OIDC_DEVICE_CLIENT_SECRET` `secret` | string | (= `GOOGLE_OIDC_CLIENT_SECRET`) | Device-code flow client secret. Falls back to `GOOGLE_OIDC_CLIENT_SECRET` when unset. |
| `OIDC_CLIENT_ALLOWLIST` `*` | comma-list of strings | (none) | Allow-list of `client_id` values accepted by `GET /auth/authorize` (§3.1, §5.4.1). The CLI's registered `client_id` MUST appear here; unknown values are rejected with `400 BAD_REQUEST`. |
| `OIDC_OVERRIDES_ALLOWED` | bool | `false` | Permits `GOOGLE_*_URL` overrides. MUST be `false` in production. |
| `GOOGLE_DEVICE_CODE_URL` | string | `""` (= Google's URL) | Override accepted only when `OIDC_OVERRIDES_ALLOWED=true`. |
| `GOOGLE_TOKEN_URL` | string | `""` (= Google's URL) | Same. |
| `GOOGLE_JWKS_URL` | string | `""` (= Google's URL) | Same. |
| `CLOUDFLARE_API_TOKEN` `secret` | string | `""` | Cloudflare API token with `DNS:Edit` on the zone only. Required for any DNS-touching saga. |
| `CLOUDFLARE_ZONE_ID` | string | `""` | Required when `CLOUDFLARE_API_TOKEN` is set. |
| `CLOUDFLARE_BASE_DOMAIN` | string | `""` | Required when `CLOUDFLARE_API_TOKEN` is set. The zone where Dev-CVM records are provisioned (`cvm-<26-base32>.<CLOUDFLARE_BASE_DOMAIN>`). The generated full FQDN MUST be ≤64 chars because the shade cert-manager uses it as the X.509 Common Name. |
| `SECURITY_CVM_BASE_DOMAIN` `*` | string | `""` | The zone where Security-CVM records are provisioned (`sc-<26-base32>.<SECURITY_CVM_BASE_DOMAIN>`, e.g. `sc.example.com`). MUST be a distinct sub-zone or zone from `CLOUDFLARE_BASE_DOMAIN` so SC namespaces are visibly disjoint from Dev CVMs. The generated full FQDN MUST be ≤64 chars because the shade cert-manager uses it as the X.509 Common Name. The Cloudflare API token MUST have `DNS:Edit` on this zone in addition to `CLOUDFLARE_BASE_DOMAIN`. |
| `CLOUDFLARE_API_BASE` | string | `""` (= Cloudflare's) | E2E override; refused unless `OIDC_OVERRIDES_ALLOWED=true`. |
| `PHALA_API_TOKEN` `secret` | string | `""` | Required for the Phala adapter. |
| `PHALA_CLI_PATH` | filesystem path | `/usr/local/bin/phala` | Read-only mount in production. |
| `PHALA_NODE_PATH` | filesystem path | `node` | Node executable used for Phala SDK helper subprocesses. |
| `PHALA_CLI_SHA256` `*` | hex 64 | (none, REQUIRED when `PHALA_API_TOKEN` is set) | SHA-256 of the **npm tarball** the bundled `phala@<version>` resolved from. Verified at boot against the on-disk installation (§10.1). The CLI is distributed via npm; pinning a single on-disk binary is not meaningful. |
| `PHALA_OUTPUT_REDACTION_PATTERNS` | comma-list of regex | (empty) | Additional regex patterns to scrub from Phala stdout/stderr in error paths (§10.1). |
| `PROVIDER_UPDATE_TIMEOUT_SECONDS` | int | `900` | Timeout for the provider update submit call. Must be between 300 and 1800 seconds. The provider-running wait is handled by the operation scheduler after submit. |
| `PHALA_REGION` | string | `FR-PARIS-1` | Default region. |
| `PHALA_DEFAULT_INSTANCE_TYPE` | string | `tdx.small` | Default Security CVM instance type when `POST /entities/{id}/security-cvm` omits it. |
| `SHADE_DIR` | filesystem path | `""` | Required for provisioning sagas. Directory of the operator-approved pinned shade checkout. The Console invokes `uv run --project ${SHADE_DIR} shade build -c <shade.yml> -f <docker-compose.yml> -o <docker-compose.shade.yml>` and `shade policy generate` at the adapter boundary (§18.8). |
| `DEV_CVM_DEFAULT_INSTANCE_TYPE` | string | `tdx.small` | Default Dev CVM instance type when `POST /cvms` omits it (§3.6). When empty, the route returns `422 VALIDATION_ERROR` if the request also omits `instance_type`. |
| `DEV_CVM_DEFAULT_REGION` | string | `""` | Dev-specific region default when `POST /cvms` omits it. When empty, Dev launch falls back to `PHALA_REGION`; when both are empty AND the request omits `region`, the route returns `422 VALIDATION_ERROR`. |
| `DEV_CVM_DEFAULT_DISK_GB` | int | `40` | Default Dev CVM root disk (GB) when `POST /cvms` omits `disk_size_gb` (§3.6). Matches the provider's own default so existing launch behavior is unchanged. A value outside `[DEV_CVM_MIN_DISK_GB, DEV_CVM_MAX_DISK_GB]` (or unparseable) yields `503 SERVICE_UNAVAILABLE`. |
| `DEV_CVM_MIN_DISK_GB` | int | `40` | Minimum accepted `disk_size_gb`; a smaller request is `422 VALIDATION_ERROR`. |
| `DEV_CVM_MAX_DISK_GB` | int | `2000` | Maximum accepted `disk_size_gb` (structural ceiling); a larger request is `422`. The overridable `disk_gb_per_cvm` quota (§3.13) is the per-tenant knob below this ceiling. |
| `SECURITY_CVM_DEFAULT_REGION` | string | `""` | Security-CVM-specific region default when `POST /entities/{id}/security-cvm` omits it. When empty, Security CVM provisioning falls back to `PHALA_REGION`; when both are empty AND the request omits `region`, the route returns `422 VALIDATION_ERROR`. |
| `DEV_CVM_IMAGE` | OCI ref | `""` | Required for `POST /cvms`. |
| `DEV_CVM_IMAGE_MEASUREMENT` `*` | hex 96 | (none, REQUIRED when `DEV_CVM_IMAGE` is set) | Expected TDX MRTD of the approved dstack guest boot baseline. It MUST equal `SECURITY_CVM_IMAGE_MEASUREMENT`; neither value identifies the app image or compose. The full Shade runtime policy pins those by digest and compose hash (§10.4a). Captured per deployment onto `cvms.expected_image_measurement`; update it only when the dstack guest baseline changes, not for an app-image release. |
| `SECURITY_CVM_IMAGE_REF` | OCI ref | `""` | Required for `POST /entities/{id}/security-cvm`. The OCI reference (digest-pinned in production) of the SC image to deploy. |
| `SECURITY_CVM_IMAGE_MEASUREMENT` `*` | hex 96 | (none, REQUIRED when `SECURITY_CVM_IMAGE_REF` is set) | Expected TDX MRTD of the approved dstack guest boot baseline. It MUST equal `DEV_CVM_IMAGE_MEASUREMENT`. SC app-image and compose identity come from the complete Shade runtime policy, not a distinct MRTD (§10.4). Captured per deployment; update it only with a dstack guest baseline change. |
| `DSTACK_DOCKER_REGISTRY` | string | `""` | Private runtime-image registry hostname. Leave this unset only after approved release images are published for anonymous reads. Until then, and for any private registry, configure the complete `DSTACK_DOCKER_*` trio. When any value is set, all three are required. |
| `DSTACK_DOCKER_USERNAME` | string | `""` | Private runtime-image registry username. Never falls back to host-side image-publishing credentials such as `GHCR_USER`. |
| `DSTACK_DOCKER_PASSWORD` `secret` | string | `""` | Private runtime-image registry password forwarded only during CVM provisioning/update. Never falls back to `GHCR_TOKEN`. |
| `CONSOLE_URL` `*` | URL | `http://localhost:8000` | Public URL of *this* Console. Validated at boot: scheme MUST be `http://` or `https://`, host MUST be present, userinfo MUST be absent. Injected as the `CONSOLE_URL` env on every Security CVM at provisioning and RTMR-extended into the SC's attestation report (§10.4). |
| `RECONCILER_ATTESTATION_INTERVAL_SECONDS` | int 3600..86400 | `21600` | Cadence of the reconciler's per-CVM attestation refresh, applied to both Security CVMs (§10.4 drift detection) and Dev CVMs (§10.4a drift detection). Trades off post-redirect / post-substitution leak window against attestation-refresh load. |
| `DEV_CVM_ATTESTATION_TIMEOUT_SECONDS` | int 30..600 | `180` | Maximum wait at the launch saga's `verify_attestation` step (§8.3) for the Dev CVM's `/tdx_quote` endpoint to become reachable. Absorbs the Phala boot window. |
| `SECURITY_CVM_ATTESTATION_TIMEOUT_SECONDS` | int 30..600 | `180` | Maximum wait at the provisioning saga's `verify_attestation` step (§8.4) for the Security CVM's `/tdx_quote` endpoint to become reachable. Absorbs the Phala/shade boot and certificate window. |
| `SECURITY_CVM_FQDN_RESOLVE_TIMEOUT_SECONDS` | int 10..600 | `120` | Maximum wait at the provisioning saga's `fetch_ca` step (§8.4) for the freshly-created SC gateway CNAME to resolve from the Console's own resolver, before pinning that IP for the CA-fetch connect. Absorbs the DNS-propagation / negative-cache window on the Phala-served gateway zone. |
| `ATLAS_VERIFIER_CMD` | argv string | `""` | Optional subprocess command implementing the Console-side atlas-rs verifier boundary (§18.8). Required for the real provider green path. When unset, the scheduler leaves `verify_attestation` waiting for an external verifier to populate persisted attestation columns and `GET /entities/{id}/security-cvm/attestation?probe=true` returns `503 SERVICE_UNAVAILABLE`. |
| `DEFAULT_QUOTA_DEV_CVMS_PER_USER` | int 0..10000 | `5` | Default cap on live owned Dev CVMs per user (§3.13). Per-user override (`QUOTA_MANAGE`) and per-entity override (`PLATFORM_OPERATOR`) supersede. |
| `DEFAULT_QUOTA_DEV_CVMS_PER_ENTITY` | int 0..100000 | `50` | Default cap on the entity's total live Dev CVMs. Per-entity override (`PLATFORM_OPERATOR`) supersedes. |
| `DEFAULT_QUOTA_SSH_KEYS_PER_USER` | int 0..1000 | `10` | Default cap on a user's live registered SSH keys (§3.2). |
| `DEFAULT_QUOTA_SSH_KEYS_PER_ENTITY` | int 0..100000 | `1000` | Default cap on all live SSH keys across the entity. Bounds the table-bloat blast radius if a single tenant has many users. |
| `DEFAULT_QUOTA_USERS_PER_ENTITY` | int 1..1000000 | `1000` | Default cap on live users per entity (§3.3). |
| `DEFAULT_QUOTA_PROFILES_PER_ENTITY` | int 0..10000 | `50` | Default cap on live profiles per entity (§3.4). |
| `DEFAULT_QUOTA_DISK_GB_PER_CVM_PER_USER` | int 0..1048576 | `200` | Default per-user cap on a single Dev CVM's disk (GB) at launch (`disk_gb_per_cvm`, §3.13). |
| `DEFAULT_QUOTA_DISK_GB_PER_CVM_PER_ENTITY` | int 0..1048576 | `500` | Default entity cap on a single Dev CVM's disk (GB) at launch. |
| `DEFAULT_QUOTA_DISK_GB_TOTAL_PER_USER` | int 0..1048576 | `1000` | Default per-user cap on summed disk (GB) across the user's live Dev CVMs (`disk_gb_total`, §3.13). |
| `DEFAULT_QUOTA_DISK_GB_TOTAL_PER_ENTITY` | int 0..1048576 | `10000` | Default entity cap on summed disk (GB) across the entity's live Dev CVMs. |
| `RECONCILER_INTERVAL_SECONDS` | int ≥ 1 | `30` | Background loop interval. |
| `OPERATION_RETENTION_DAYS` | int 1..365 | `30` | Per-operation TTL after `succeeded` / `failed` / `cancelled` (§7.17). |
| `TRAFFIC_LOG_RETENTION_DAYS` | int 7..730 | `90` | Daily prune horizon for `traffic_logs` (§11.8). |
| `AUDIT_ANCHOR_TARGET` | URI | (none, REQUIRED in production) | External Postgres anchor DSN (`postgresql://...` or `postgres://...`; optional `?table=<identifier>`, active default `umbra_audit_anchors`, with `concrete_audit_anchors` available only during explicit migration). §11.6. |
| `AUDIT_ANCHOR_INTERVAL_SECONDS` | int 60..86400 | `3600` | Anchor cadence. |
| `AUDIT_EXPORT_BUCKET` | URI | (none, REQUIRED for `POST /audit/export`) | Local `file://` bucket for development or external Postgres artifact-store DSN (`postgresql://...`; optional `?table=<identifier>`, active default `umbra_audit_export_artifacts`, with `concrete_audit_export_artifacts` available only during explicit migration). §11.5. |
| `METRICS_TOKEN` `secret` | string | `""` | Bearer token required by `GET /metrics` (§13.6). When empty, `/metrics` returns `503` so an unconfigured deployment does not accidentally expose metrics. |
| `LOG_LEVEL` | enum `debug` / `info` / `warn` / `error` | `info` | Stdlib + structlog filter (§13.3). |
| `TRUST_FORWARDED_HEADERS` | bool | `false` | When `true`, `X-Forwarded-For` is honored. MUST remain `false` unless fronted by a sanitising reverse proxy (§13.8). |
| `AUTO_PROVISION_SECURITY_CVM_ON_PROFILE_CREATE` | bool | `false` | Logs an auto-provision marker on profile creation; the saga itself does not run inline. |
| `UMBRA_ALLOW_BOOTSTRAP` | bool | `false` | Bootstrap (§12.3) refuses to run unless `true`. Not read elsewhere. |
| `SANDBOX_ENV_VALUE_DENYLIST` | comma-list of regex | `^sk-ant-[A-Za-z0-9_-]+$,^sk-[A-Za-z0-9]{32,}$,^gh[pousr]_[A-Za-z0-9]{36,}$,^AKIA[0-9A-Z]{16}$,^ASIA[0-9A-Z]{16}$` | Patterns rejected by `policy.sandbox_env` validation (§2.3 `<Profile>`, §8.5). Defaults cover Anthropic, OpenAI, GitHub, and AWS access-key shapes; operators MAY extend with provider-specific patterns. |

### 12.2 Secrets policy

Every value marked `secret` above MUST be loaded through one of the resolvers below. Plain env-var resolution is FORBIDDEN in production for secrets; the Console refuses to start (`ValueError("secret in env")`) when a `secret` value's URI begins with `env:` and `ENVIRONMENT != "dev"`.

| URI scheme | Resolver | Notes |
|---|---|---|
| `file:///path` | Read the file at boot. | Mode MUST be `0400` or `0600`; the Console refuses to start otherwise. The mount MUST be on tmpfs (no swap leakage) when the orchestrator can guarantee it. |
| `kms://aws/<arn>` | Resolve via AWS KMS at boot and on rotation. | The Console process MAY hold the plaintext in memory (zeroed on shutdown); KMS-backed signing (private key never leaves KMS) is the recommended deployment for `JWT_PRIVATE_KEY_REF` (§5.2). |
| `kms://gcp/<name>` | Same for GCP KMS. | |
| `vault://<path>` | Resolve via HashiCorp Vault at boot. | The Console MUST refresh the lease per Vault's TTL. |
| `env:<NAME>` | Read from `os.environ[<NAME>]`. | DEV-ONLY (`ENVIRONMENT=dev`). |

The resolver mechanism is a deployment artifact, NOT an implementation detail. Conformance §19 verifies the boot-time refusal.

### 12.3 Bootstrap

Bootstrap is a one-shot CLI entry point — the only operational path that talks to the database directly. It creates the first entity, the first admin user, and a default profile.

```bash
UMBRA_ALLOW_BOOTSTRAP=true python -m umbra_console.bootstrap \
    --domain <entity-domain> --admin-email <email> \
    [--admin-name ...] [--entity-name ...] [--default-profile ...] \
    [--session-file <path>]
```

#### Argument-consistency check (T-16)

The threat model accepts "control of the email / IdP IS the user" (§1.5), so the Console does NOT issue a first-login confirmation token. The single defense bootstrap applies is structural: an `--admin-email` whose domain does not match `--domain` is rejected before any DB write.

- **Domain match.** Bootstrap MUST refuse with exit code `2` and a clear stderr message when `split(admin_email, "@")[1] != domain` (case-insensitive after lowercasing both). This catches the only realistic typo in the threat model — the operator types `exampl.com` for the entity but `example.com` (or vice versa) for the admin email — without introducing any out-of-band token.
- **Bootstrap creates the user with `PERMISSION_MANAGE` and `AUDIT_VIEW` already granted** in the same transaction as the `users` insert, alongside `USER_REGISTERED` and one `PERMISSION_GRANTED` audit row per granted permission. If `--session-file` is omitted, the first OIDC login authenticated against the operator's IdP issues the JWT pair without any additional handshake; if a person other than the intended admin happens to control the email at the IdP, that's an IdP / domain-ownership issue, not a Console issue (§1.5).
- **Bootstrap assigns the first admin to the default profile** by inserting the matching `profile_users` row in the same transaction as `PROFILE_CREATED`, and emits `PROFILE_USER_ASSIGNED`. The admin's `USER_MANAGE` permission still broadens profile reads, but the membership row keeps the default profile usable by non-admin-scoped workflows after bootstrap.
- **Bootstrap MAY emit the initial platform-operator CLI session** when invoked with `--session-file <path>`. This is for deployments where the platform entity is an operational owner rather than a Google-managed tenant domain. The session MUST be a normal Console-issued access/refresh-token pair persisted in `refresh_tokens`, MUST produce an `AUTH_SESSION_ISSUED` audit row, MUST be written as a CLI-compatible `session.json` with mode `0600`, and MUST NOT print bearer or refresh tokens to stdout/stderr.


#### Re-run safety

- `UMBRA_ALLOW_BOOTSTRAP=true` is required (env-only flag, by design); without it bootstrap exits `2` without touching the database.
- Bootstrap refuses to run if the target entity already has *any* user holding `PERMISSION_MANAGE`. It exits `0` without changes.
- When `--session-file` is supplied on a re-run, bootstrap still refuses to create or mutate users after the permission-manager guard, but it MAY issue a fresh session for the requested `--admin-email` if that user already exists, is active, and holds `PLATFORM_OPERATOR`.
- Lost-admin recovery is NOT bootstrap's job; see §17.5 for the operator-run SQL playbook.

## 13. Operations and observability

What the Console exposes for the platform operating it. SLOs are first-class — they shape the implementation choices in §16.

### 13.1 Health and readiness

Two distinct endpoints with distinct contracts. Orchestrator probes MUST use the right one.

#### `GET /healthz`

Liveness. Returns `200 {"status": "ok"}` whenever the process is answering. Auth: anonymous; rate limit: per IP `60 RPM`. Excluded from the OpenAPI schema. A failing `healthz` (no answer or non-`200`) means "kill and restart".

#### `GET /readyz`

Readiness. Returns `200 {"checks": {<name>: "ok"|"failed", ...}}` when every required dependency is up; `503 {"checks": {...}}` otherwise. Auth: anonymous; rate limit: per IP `60 RPM`. The probe MUST run all checks in parallel with a 1-second cap each so a slow dependency doesn't make the route itself slow:

| Check | Pass condition |
|---|---|
| `database` | `SELECT 1` returns inside 200 ms. |
| `jwt_keys` | The active and verifying key sets are loaded and the active `kid` resolves. |
| `phala_adapter` | When `PHALA_API_TOKEN` is configured: the installed `phala` npm tarball digest matches `PHALA_CLI_SHA256` (§10.1). |
| `cloudflare_adapter` | When configured: `GET /zones/{zone_id}` returns 200 within 500 ms. |
| `oidc_jwks` | A JWKS fetch with `force_refresh=False` succeeds within 500 ms (cached path; doesn't hit Google every probe). |
| `audit_anchor_target` | When configured: connects to the external Postgres anchor DSN and confirms the configured table is readable within 500 ms. |
| `operation_scheduler` | The scheduler's last successful tick was within `2 × RECONCILER_INTERVAL_SECONDS`. |

Orchestrator probe routing: `/readyz` is the readiness probe; `/healthz` is the liveness probe. A `/readyz` 503 should remove the pod from the load-balancer pool but NOT kill it.

### 13.2 Service-level objectives

Per-route latency budgets the implementation MUST meet at the spec's reference load (defined by the conformance suite, §19). Times are wall-clock between request first-byte received and response first-byte sent, measured at the Console process (not at the proxy).

| Route class | p50 | p99 |
|---|---|---|
| Health (`/healthz`, `/readyz`) | ≤ 5 ms | ≤ 50 ms |
| Authenticated read of a single resource (e.g. `GET /me`, `GET /cvms/{id}`) | ≤ 20 ms | ≤ 200 ms |
| Authenticated list with cursor (e.g. `GET /audit/events`) | ≤ 50 ms | ≤ 500 ms |
| Permission reload + auth (every authenticated request, in addition to route work) | ≤ 1 ms | ≤ 10 ms |
| Authenticated mutation, no external call (e.g. `POST /me/keys`) | ≤ 30 ms | ≤ 300 ms |
| Async submit (`POST /cvms`, `POST /entities/{id}/security-cvm`) — return-the-Operation only | ≤ 100 ms | ≤ 500 ms |
| Sync mutation with external call (`POST /cvms/{id}/actions/start`) | ≤ 5 s | ≤ 30 s |
| Saga step latency (within the scheduler) | ≤ 5 s | ≤ 60 s |

**Availability.** 99.9% monthly availability for `/api/v1` and `/internal`; both surfaces share the same listener so both budgets are the same. `audit.export` is 99.5% (object-store dependency).

**Throughput floors.** `/internal/traffic-logs` MUST sustain 50 RPS per Console instance with batches of 100 entries (5000 logs / s) without exceeding the latency budget for the synchronous insert.

The conformance suite (§19) MUST exercise the SLO floors against a reference deployment.

### 13.3 Structured logging

All logs go to stdout as JSON, one line per event. The library is `structlog`.

- Standard fields per line: `timestamp` (ISO 8601 UTC), `level`, `event` (the event name), `request_id` (§2.7) if applicable, `actor_id` if applicable, `route` and `status` for request log lines, `duration_ms` for completed requests. Plus any kwargs the call site supplied.
- Stack info is rendered when an exception is logged.
- `request_id` and `actor_id` are bound to the request via `structlog.contextvars` at the FastAPI dependency that resolves the JWT (§5).

### 13.4 Log levels

| Level | When |
|---|---|
| `DEBUG` | Request / response summaries (without secrets), config resolution at boot, retry attempts. |
| `INFO` | One request-completed line per request (with `route`, `status`, `duration_ms`, `request_id`, `actor_id`). One saga-step line per saga-step entry / exit. Reconciler progress. |
| `WARN` | Recoverable conditions (TTL-scrubbed plaintext bearer, retryable upstream error). |
| `ERROR` | Unrecoverable conditions (saga compensation, scheduler tick failure, secret-denylist match in a log line — see §13.5). |

The default filter is `info`. `LOG_LEVEL=debug` is appropriate for short-term incident response. There is no `trace` level.

### 13.5 Redaction

The following values MUST NEVER appear in any log line at any level:

- Console JWTs (access OR refresh).
- OIDC `id_token` / `access_token` from Google.
- OIDC `device_code` / `polling_secret`.
- Service-principal bearers (`INGEST`, `CA_EXPORT`, `PROXY_AUTH`), plaintext or hash.
- `JWT_PRIVATE_KEY_REF` resolved value, `GOOGLE_OIDC_CLIENT_SECRET`, `GOOGLE_OIDC_DEVICE_CLIENT_SECRET`, `CLOUDFLARE_API_TOKEN`, `PHALA_API_TOKEN`, `DSTACK_DOCKER_PASSWORD`.
- `ca_export_token_plaintext`, `ca_cert_pem`, full `compose_config` from `cvms` / `security_cvms` (the YAML carries `${VAR}` placeholders, not values, but the full file is bulky and noisy in logs).
- `before` / `after` JSONB payloads on `audit_events`.

Defense is layered. Listed from primary to last-resort:

**1. Typed secrets at the source (primary defense).** Every secret value lives inside a `pydantic.SecretStr` (or `SecretBytes`) wrapper from the moment it enters Console code:

- The settings loader (§12, §18.5) wraps every `secret`-marked config value into `SecretStr` automatically; no service code receives the plaintext as `str`.
- Freshly-minted plaintexts (`secrets.token_urlsafe(32)` for bearers, `secrets.token_bytes()` for nonces) MUST be wrapped at the call site that returned them before crossing any function boundary.
- `SecretStr.__repr__` and `__str__` return the literal string `"<redacted>"`. Passing a `SecretStr` to `log.info("issued", token=plaintext)` renders `token=<redacted>` with no processor involvement. The only path to plaintext is `.get_secret_value()`, which MUST appear only at the boundary that actually needs to transmit it (an outbound HTTP header, a database INSERT of a hash, an env-file write).

**2. Source-level discipline at boundaries that aren't statically typed.** Some sensitive content enters the process as untyped strings (upstream stderr, response bodies that may echo a token, third-party logger output). For those:

- Subprocess output from Phala is routed through the redaction scrubber in §10.1 before any log emission, not after.
- HTTP error bodies from external integrations (Phala, Cloudflare, IdP, SC) are surfaced as typed-code error envelopes (§10.5), not echoed verbatim.
- Audit row construction is the boundary for `before` / `after` payloads (see §11.3): sensitive fields are redacted to `"<redacted>"` at row-construction time, before the row reaches the DB. The log emitter never sees the plaintext.
- Third-party loggers (`asyncpg`, `httpx`) MUST be configured at boot to a level that does NOT emit request URLs containing query secrets or auth headers; the spec REQUIRES `httpx` debug logging stays off in production.

**3. Runtime processor as defense-in-depth alarm.** A structlog processor runs as the last step of the rendering pipeline:

1. Walks the event dict recursively.
2. Matches each leaf value against a configured-secret denylist (constructed at boot from §12 `SecretStr` values' `.get_secret_value()` plus a fixed pattern set for token / certificate shapes — `Bearer ey...`, PEM headers, 32+ char base64url-safe blobs adjacent to known field names).
3. Replaces matches with `"<redacted>"`.
4. Emits an `ERROR`-level log line `redacted_value_in_log` with `{key, source}` (path inside the event, and emitter file:line when available) AND increments the `umbra_console_redacted_value_in_log_total{source}` counter (§13.6) so the leak attempt is observable in dashboards and SLOs.

**The processor is an alarm, not a fix.** An `ERROR`-level emission from the processor means a source-level invariant was violated — the call site MUST be located and corrected. The conformance suite (§19) includes a test that boots the Console with a deliberately-misconfigured logger and asserts the alarm fires for every value class above. Operators MUST alert on any non-zero rate of `umbra_console_redacted_value_in_log_total` (§17.1).

### 13.6 Metrics

The Console MUST expose a Prometheus-format metrics endpoint:

#### `GET /metrics`

- **Auth.** Bearer-token authenticated by a separate `METRICS_TOKEN` secret (§12). Distinct from §5's auth surfaces. NOT exposed publicly; intended for an internal scrape.
- **Rate limit.** Per IP `60 RPM`.
- **Body.** Prometheus text format.

Required metric series (label conventions: `route`, `method`, `status`, `principal_type`):

| Metric | Type | Labels |
|---|---|---|
| `umbra_console_request_duration_seconds` | histogram | `route`, `method`, `status` |
| `umbra_console_requests_total` | counter | same |
| `umbra_console_rate_limit_drops_total` | counter | `route`, `dimension` |
| `umbra_console_jwt_verification_duration_seconds` | histogram | (none) |
| `umbra_console_jwt_revocation_lookup_duration_seconds` | histogram | (none) |
| `umbra_console_operation_duration_seconds` | histogram | `kind`, `terminal_status` |
| `umbra_console_operations_inflight` | gauge | `kind` |
| `umbra_console_saga_step_duration_seconds` | histogram | `kind`, `step` |
| `umbra_console_external_call_duration_seconds` | histogram | `adapter`, `op`, `outcome` |
| `umbra_console_audit_chain_seq` | gauge | (none — last anchored `seq`) |
| `umbra_console_audit_anchor_age_seconds` | gauge | (none) |
| `umbra_console_auth_refresh_reuse_detected_total` | counter | (none) — incremented on every `AUTH_REFRESH_REUSE_DETECTED` audit row (§11.2). High-signal probable-theft event; alerts on any non-zero rate (§17.1). |
| `umbra_console_traffic_logs_ingested_total` | counter | `principal_id` |
| `umbra_console_traffic_log_resolution_rate` | gauge | (mode 2 success rate) |
| `umbra_console_redacted_value_in_log_total` | counter | `source` (emitter file or component) — incremented every time the §13.5 runtime processor catches a leaked secret. **Non-zero means a source-level invariant was violated and the offending call site needs fixing** (§17.1 alert). |

Metric labels MUST NOT include any value from §13.5's denylist. `principal_id` is the UUID, not the plaintext bearer. The `source` label on `umbra_console_redacted_value_in_log_total` is a code-location identifier (emitter file or component name), not user content.

### 13.7 Tracing

Optional. When `OTEL_EXPORTER_OTLP_ENDPOINT` is configured (§12), the Console MUST emit OpenTelemetry traces:

- One span per request, parent of any subspans.
- Subspans for: JWT verification, permission reload, every external call (Phala, Cloudflare, IdP, Security CVM CA fetch), every saga step, every DB transaction.
- Span attributes: `request_id`, `actor_id`, `route`, `kind` (for operations), `step` (for saga steps), `adapter` / `op` (for external calls). NEVER any value from §13.5.
- Trace IDs are propagated to outbound calls via the `traceparent` header (W3C Trace Context).

### 13.8 Client IP resolution

Audit rows carry `ip_address` (§7.18). The IP is resolved from the request as follows:

- If `TRUST_FORWARDED_HEADERS` is `false` (default), the IP is the direct peer address.
- If `TRUST_FORWARDED_HEADERS` is `true`, the IP is the **leftmost public IPv4/IPv6 address** in `X-Forwarded-For`, after stripping any private-range entries (RFC 1918, RFC 4193, link-local). The deployment MUST front the Console with a reverse proxy that strips client-supplied `X-Forwarded-For` before adding its own; without this, an attacker can spoof the audit-recorded IP.

If no public address is found, `ip_address` is set to the direct peer's address (typically the proxy itself); a log line at `WARN` records the truncated header for forensics.

### 13.9 TLS termination policy

The Console listens on plain HTTP. Production deployments MUST front the listener with a TLS-terminating reverse proxy. The proxy MUST:

- Negotiate TLS 1.2 minimum (TLS 1.3 preferred).
- Refuse the cipher suites listed as compromised in the deployment's compliance baseline (e.g. NIST SP 800-52). At minimum: no NULL, no EXPORT, no RC4, no DES, no 3DES.
- Set `Strict-Transport-Security` (`max-age=63072000; includeSubDomains; preload`) at the proxy edge; the Console also sets it (§2.10) for defense in depth.
- Strip incoming `X-Forwarded-For` and replace with the verified peer chain.

The proxy ↔ Console hop MUST be either (a) a localhost loopback, (b) a private-network connection on a network that the operator vouches for, or (c) mTLS. Plain HTTP across a hostile network is forbidden.

## 14. Security properties

Cross-cutting contracts the Console MUST uphold. Each property is anchored to one or more threats from §1.4; conformance §19 verifies each property against its threat. Violations are spec bugs.

### 14.1 JWT integrity (T-1, T-2, T-27, T-28)

- Issued JWTs use `EdDSA` (default) or `RS256` only. `HS256` and `none` are forbidden for issuance and verification.
- Signing key material is loaded at boot from `JWT_PRIVATE_KEY_REF` (§12.2); KMS-backed signing is the recommended deployment so the private key never sits in process memory.
- **Header attack-vector rejection (T-27).** Verification refuses any token whose header contains `jku`, `jwk`, `x5u`, or `x5c` *before* signature verification. The Console loads verifying keys exclusively from `JWT_PUBLIC_KEYS_REF`; caller-supplied key sources are never honored.
- **Per-`kid` algorithm pinning (T-1, T-27).** Each `kid` in the loaded key set carries its own `alg`. Verification uses that algorithm — NOT the algorithm declared in the token header. The header's `alg` MUST equal the kid's pinned `alg`; mismatch refuses with `401`. This eliminates the RS256-vs-HS256 confusion class (an attacker who has the public key cannot use it as an HMAC secret).
- **`typ: at+JWT` (T-28).** Issued tokens carry `typ: at+JWT` per RFC 9068. Tokens with a different `typ` are refused; cross-token-confusion (id_token presented as access token) is impossible.
- **Verification ordering (§5.2).** Token shape → header parse + attack-vector rejection → algorithm pin → signature → standard claims → identity claims → `jti` denylist → user reachability. The implementation MUST short-circuit at the first failure and MUST NOT touch the database before step 4.
- **`aud` matching.** Either string equality with the configured audience OR a non-empty array containing it. A token whose audience does not include the Console MUST be refused.
- **No PII in claims.** The JWT carries `(iss, aud, sub, entity_id, iat, nbf, exp, jti)`. `email`, `permissions`, `profiles` are not in the JWT — they are read from the database at request time (§5.2).
- **Authoritative permissions** are reloaded from `user_permissions` per request (§5.3); the JWT carries no `permissions` claim.
- **Active and verifying `kid`s** are tracked separately. Rotation (§5.2, §17.2) maintains overlap so in-flight tokens keep working.
- **Revocation.** The `revoked_tokens` denylist (§5.2, §7.13) makes self-logout, admin-driven revocation, and refresh-token-family invalidation effective on the next request.
- **Zero-trust verification.** Every Console worker re-validates every JWT on every request; there is no internal-network exemption.
- Boot fails when secret resolution falls outside §12.2's allowed schemes in non-dev environments.

### 14.2 OIDC verification (T-12, T-20, T-27, T-28)

- Algorithm allow-list on inbound `id_token`s: `RS256` only.
- **Header attack-vector rejection** on inbound `id_token`s: `jku`, `jwk`, `x5u`, `x5c` are refused before signature verification (same rule as §14.1, applied on the IdP side).
- **Per-`kid` algorithm pinning** on inbound `id_token`s: the kid's algorithm in the IdP's JWKS is authoritative; the token-header's `alg` is verified to equal it.
- Outbound HTTPS to the IdP uses standard public-CA chain validation. CA-MITM against the IdP is treated as a state-level adversary out of scope (§1.5).
- JWKS cache is force-refreshed exactly once on `kid` miss; cache TTL is 5 minutes.
- `iss` allow-list per provider (Google: `https://accounts.google.com`, `accounts.google.com`).
- `aud` matches the flow's Google client — `GOOGLE_OIDC_CLIENT_ID` (loopback) or `GOOGLE_OIDC_DEVICE_CLIENT_ID` (device; falls back to `GOOGLE_OIDC_CLIENT_ID`); if `aud` is an array, every entry MUST equal it. `azp` (when present) MUST equal the flow's client id.
- `email_verified` MUST be the literal boolean `true`.
- `at_hash` is enforced when an `access_token` is present in the same response.
- `nonce` is verified on the loopback flow (`§5.4.1`); the device flow omits it per RFC 8628.
- IdP endpoint overrides (`GOOGLE_*_URL`) are refused unless `OIDC_OVERRIDES_ALLOWED=true` is paired with `LOG_LEVEL=debug` (§10.3).

### 14.3 Device-flow polling secret (T-2)

- The server-issued `polling_secret` (32 bytes) is the binding value the CLI MUST echo on every `/poll`. Hash-side comparison is constant-time.
- Pending-flow rows live in `device_flow_pending` (§7.15), not in process memory; multi-worker deployments are supported.
- A pending row is deleted on hard upstream errors so a stuck IdP cannot strand entries indefinitely.

### 14.4 Service-principal bearer tokens (T-2 across purposes)

- Plaintext is returned exactly once via `Operation.result` (§3.7, §8.4) — first-read disclosure semantics.
- Storage is `SHA-256(plaintext)`.
- Authentication is hash equality on the indexed column plus an `expected_purpose` check; a token of the wrong purpose MUST fail with `401`.
- A bearer for a soft-deleted parent principal MUST fail, even if its own `deleted_at` is `NULL`.
- The Security CVM provisioning plaintext stash is scrubbed unconditionally after 1 hour, regardless of the saga's progress.
- Rotation (when added) MUST overlap old and new bearers for at most 5 minutes (§5.7).

### 14.5 Authorization header parsing (T-2)

- `Authorization: Bearer <token>` is parsed strictly: exactly one ASCII space, non-empty token, no leading / trailing whitespace, no alternative scheme.
- Implementations MUST NOT use whitespace-tolerant string splits.

### 14.6 Existence non-leak (T-8)

- Routes accepting a resource id in their path MUST return `404 NOT_FOUND` identically for "the resource does not exist" and "the resource exists in another tenant the caller cannot see".
- `/entities/{id}` is the only exception: the entity check is a property of the JWT, not the database, so the response is uniformly `404` regardless of whether the entity actually exists.
- Profile-scoped routes (`/profiles/{id}/...`) MUST follow the rule. Conformance §19 verifies it route-by-route.

### 14.7 Cross-tenant rejection at the data layer (T-4, T-5)

- Every `/internal` payload field naming a Console-managed resource MUST be validated against the bearer's principal scope before insert (§4.3 Mode 1).
- Every `/api/v1` route with a path id MUST verify the resource's ownership chain leads to the caller's entity. The check happens after permission, before invariant; failure returns `404` per §6.4.
- Cross-tenant `users.email` enumeration is impossible because the email-domain ↔ entity-domain invariant (§7.3) refuses any email whose domain is not the caller's entity's domain with `422 VALIDATION_ERROR`. A tenant admin therefore cannot probe `POST /entities/{id}/users` with an email belonging to another entity's domain — the request fails before any DB lookup. T-9.

### 14.8 Internal API isolation (T-2 across surfaces)

- A Console JWT MUST NOT authenticate any `/internal` route.
- A service-principal bearer MUST NOT authenticate any `/api/v1` route.
- The verifier MUST distinguish credential classes by token shape (JWT vs opaque bearer) and refuse the wrong shape with `401` before any DB lookup.
- `/internal` callers cannot impersonate users; their audit attribution is the principal, never a user.

### 14.9 Subprocess and external-call hygiene (T-13, T-19, T-22)

- The Phala subprocess receives only the allowlist env (§10.1); the Console MUST NOT pass `os.environ.copy()`.
- The installed `phala` npm tarball's `SHA-256` is verified at boot against the configured `PHALA_CLI_SHA256` pin (§10.1). Per-invocation re-verification is not required; the read-only mount + image-rebuild rotation procedure preclude live-tree mutation between calls.
- The binary's path is fixed in the deployment image and lives on a read-only mount in production.
- Env-file values MUST NOT contain `\r` or `\n`; smuggleable values are refused.
- Outputs from Phala are regex-validated against §10.1's allowlists before being interpolated into URLs.
- Outbound HTTPS to Cloudflare and the upstream IdP uses standard public-CA chain validation (no SPKI pinning, §10.2 / §10.3, §10.6).
- Secret values appearing in subprocess output or HTTP error bodies are replaced with `[redacted]` before any log emission.

### 14.10 TEE-attested Security CVM binding (T-11, T-29, T-30)

The Console binds each Security CVM to its expected identity via a hardware-rooted attestation chain (§10.4). The SC exposes the same `/tdx_quote` HTTP endpoint as Dev CVMs and is verified by the same atlas-rs verifier ([CLI spec](cli.md) §6.1, §9.5). The SC does NOT expose the `/atls` WebSocket route — there is no user-initiated tunnel use case for the SC. Its `/umbra/proxy` upgrade route is scoped to Dev-CVM egress, not Console or user management. Properties:

- **Per-deployment guest baseline and full runtime policy.** At provisioning the Console captures `SECURITY_CVM_IMAGE_MEASUREMENT` onto `security_cvms.expected_image_measurement` (§7.11). It is the shared dstack-guest MRTD, equal to the Dev value. The Console refuses to mark the SC `RUNNING` or disclose the CA-export bearer unless both that baseline and the complete Shade runtime policy for the digest-pinned SC image verify.
- **RTMR-extended runtime values.** At boot inside the TEE, the SC RTMR-extends a canonicalised JCS digest of `(CONSOLE_URL, entity_id, sc_id, ingest_token_sha256, ca_export_token_sha256)`. Any post-boot env mutation (T-30) cannot retroactively rewrite the RTMR.
- **TLS-session-bound report data.** atlas-rs binds the attestation evidence to the verifier's TLS leaf SPKI via the report-data field. A quote produced for one TLS session cannot be replayed against another (T-29 anti-replay).
- **Operator diagnostic.** `GET /entities/{id}/security-cvm/attestation` (§3.7) exposes the Console's last verification verdict for entity admins (`USER_MANAGE`) and platform operators. The SC's CA is injected into Dev CVMs by the Console at deploy time; the user's machine never trusts it directly, so this route is diagnostic, not a security-critical verification path.
- **Drift detection.** The reconciler re-attests per `RECONCILER_ATTESTATION_INTERVAL_SECONDS`; mismatches against persisted state emit `SECURITY_CVM_ATTESTATION_DRIFT` and page the operator (§17).
- **No TLS pinning.** The spec deliberately does not pin Console TLS SPKIs at the SC, nor TEE-vendor PCS / KDS SPKIs at the Console. atlas-rs handles vendor-chain validation via its built-in trust store; SC-to-Console transport relies on standard public-CA TLS validation. The residual log-shipping leak window (Phala redirect undetected until next reconciler probe) is documented in T-11.
- **Re-binding requires an update saga.** RTMR-extended values cannot be mutated inside a running SC without changing attestation. The supported live path is `security_cvm.update`, which updates the existing provider deployment, injects fresh bearer material, re-attests, and refreshes CA/aTLS material. Values outside that update path, such as a changed `CONSOLE_URL`, still require decommission and re-provisioning.
- **End-to-end TLS to the CVM.** TLS terminates inside the CVM (Dev CVM and SC alike; shade's `cert-manager` + `nginx` handle the leaf cert). Phala's gateway forwards encrypted TCP via SNI routing and never sees TLS plaintext. This is required for the aTLS report-data binding (above) to be meaningful — a Phala-side terminate-and-reproxy would let a compromised Phala observe or rewrite cleartext, and would break the verifier's leaf-SPKI binding into the attestation. Cloudflare CNAMEs are configured `proxied: false` (§10.2) so no intermediate (Cloudflare or Phala) terminates TLS.

### 14.10a Dev CVM network isolation via attested compose (T-31, T-32)

The Console binds each Dev CVM to its expected identity via the same atlas-rs attestation chain it uses for the SC (§10.4a). The user has root inside their own container; the boundary the Console enforces is twofold — what booted, and where its egress goes. Properties:

- **Per-deployment guest baseline and full runtime policy.** At launch the Console captures `DEV_CVM_IMAGE_MEASUREMENT` onto `cvms.expected_image_measurement` (§7.9) and refuses to mark the CVM `RUNNING` unless the shared dstack-guest MRTD and every full-runtime-policy field verify. The app image and compose are pinned by `app_compose`, `expected_bootchain`, and `os_image_hash`, so a divergent topology fails the runtime-policy check rather than producing an app-specific MRTD.
- **RTMR-extended runtime values.** At boot inside the TEE, the Dev CVM RTMR3-extends a canonicalised JCS digest of `(cvm_id, console_url, dev_cvm_control_token_sha256, security_cvm_fqdn, security_cvm_proxy_port, security_cvm_proxy_token_sha256, security_cvm_ca_cert_sha256, authorised_ssh_keys_sha256)`. Any post-boot Phala-side mutation of these values (e.g. redirecting egress through a hostile proxy or policy-refresh endpoint) cannot retroactively rewrite the RTMR digest.
- **TLS-session-bound report data.** Same atlas-rs binding as the SC: the Dev CVM's TLS leaf SPKI is bound into the report-data field; a quote for one TLS session cannot be replayed against another.
- **Drift detection.** The reconciler (§9.2) re-attests each live Dev CVM at most once per `RECONCILER_ATTESTATION_INTERVAL_SECONDS`; mismatches against persisted state emit `CVM_ATTESTATION_DRIFT` and page the operator (§17). The Console does NOT auto-terminate — SC policy continues to police egress regardless of inside-CVM drift.
- **SC is the egress boundary.** The proxy sidecar inside a Dev CVM is UX and operator hygiene, not a security layer. The SC enforces the per-Dev-CVM merged policy regardless of whether requests come through the sidecar or directly from the user's container (with `PROXY_AUTH` extracted via kernel exploit, container escape, or sidecar RCE). Per-CVM `PROXY_AUTH` (one row in `service_principal_tokens` per `cvms.id`, §7.12) lets the SC attribute traffic but does not grant capability beyond the Dev CVM's policy.
- **CLI cross-check.** The CLI runs its own atlas-rs verification at `umbra tunnel` time ([CLI spec](cli.md) §6.1, §9.5) against the Dev CVM's `/atls` and `/tdx_quote` endpoints, with the same `expected_image_measurement` and `rtmr3_digest` the Console verified at launch. The user is therefore protected against a Console / Phala collusion that would let an incorrectly-measured CVM accept user input.
- **No TLS pinning.** Same posture as §14.10: atlas-rs handles vendor-chain validation; standard public-CA TLS handles the Dev CVM's leaf cert.

### 14.11 Replay protection on `/internal` (T-10)

`POST /internal/traffic-logs` enforces:

- Per-batch `idempotency_key` uniqueness per principal, enforced by the unique index on `traffic_log_batches` (§4.3, §7.20).
- Newest `timestamp` in the batch MUST be within `± 10 minutes` of server time; out-of-window batches are rejected with `422`.

A captured payload cannot be replayed to amplify or backdate.

### 14.12 No external call inside a transaction (T-7 secondary)

Every saga step commits before calling Phala, Cloudflare, the IdP, or a Security CVM, and the result is captured in the next commit. Crashed external calls leave recoverable rows the scheduler can advance — they do not strand a transaction.

### 14.13 Audit-trail integrity (T-6)

- Every `audit_events` row carries `prev_hash` and `row_hash` (§7.18); the chain is linear under `seq` order.
- Writes are linearised by an advisory lock so concurrent writers cannot fork the chain.
- The chain is anchored to an external append-only store at least every `AUDIT_ANCHOR_INTERVAL_SECONDS` (§11.6).
- The Console's runtime DB role has `INSERT` only on `audit_events` (§15.5); rewriting requires a separate, distinctly-credentialed role.
- A daily verification job (§19) replays the chain end-to-end and compares the latest external anchor to the in-database state.

### 14.14 Secret hygiene (T-1, A1, A2, A4, A6)

- No bearer token, OIDC code, refresh token, JWT signing material, OAuth client secret, integration credential, or `CA_EXPORT` plaintext MUST appear in any log line, audit row, or error response (§13.5).
- The structlog redaction processor runs as the last step of the rendering pipeline; a match emits an `ERROR`-level `redacted_value_in_log` with the offending key path.
- Secrets MUST be loaded through §12.2's resolvers; plain env-var resolution of secret values is refused at boot in non-dev environments.
- `CONSOLE_URL` MUST NOT contain userinfo; refused at boot.

### 14.15 Error response sanitisation (T-17)

Error responses MUST NOT contain stack traces, internal file paths, raw upstream error bodies, SQL fragments, or any configuration value the client did not supply.

`error_reason` on `cvms` and `security_cvms` is a typed code drawn from §10.5's closed set, with optional sanitised payload fields. Free-text reason strings are FORBIDDEN — the field carries an enum + a structured object, never an exception message.

### 14.16 Input validation at the boundary

Every request body, query parameter, and path parameter MUST be validated by a schema before any database call or external integration runs. Internal code MAY assume validation has happened.

Free-text inputs (labels, names, descriptions, paths) MUST reject CR / LF / TAB so audit and CSV exports cannot be line-injected.

Maximum body size is 1 MiB on `/api/v1` and 4 MiB on `/internal/traffic-logs`. Per-route array caps are stated in §3 / §4.

### 14.17 Append-only audit and traffic tables (T-6)

The Console runtime DB role holds `INSERT` only on `audit_events`, `traffic_log_batches`, and `traffic_logs`. The migration role, the time-limited prune role, and the GDPR redactor role are distinct (§15.5). The redactor role is the **only** path that issues `UPDATE` on `audit_events` (§7.18, §11.9); it runs out-of-band, requires DPO approval, and is itself audited.

### 14.18 Rate limiting and payload caps (T-7)

Every route is governed by per-IP, per-credential, and per-route+credential rate limits (§2.6). The audit-export route additionally carries a per-credential daily quota (§3.10). `/internal/traffic-logs` is bounded by per-principal RPM and per-principal logs-per-minute floors (§4.3).

Body-size, array-length, and per-field caps MUST be enforced at the request parser, before any database or external call.

### 14.18a Resource quotas (T-7 corollary)

Rate limits bound *throughput*; resource quotas bound *cumulative state*. A user can stay under every rate limit while still creating resources that consume scarce capacity (Phala compute, DNS records, storage). The quota system (§3.13, §7.4a, §7.4b) gives operators a separate control surface:

- Every creation route in §3 MUST run the quota check between permission and invariant (§6.3 step 5). The check is a single indexed COUNT against the live-row predicate plus a comparison against the resolved limit (`user_quotas` → `entity_quotas` → `DEFAULT_QUOTA_*`).
- Default limits live in §12 config; operator overrides live in DB. Default quota of `0` for any resource is a valid lockdown posture.
- Refusal is `403 QUOTA_EXCEEDED` (§2.4) with `details.{resource, scope, limit, current_usage}` so the caller can render the exact ceiling.
- Quota changes are audited (`QUOTA_SET`, `QUOTA_CLEARED`, §11.2). Lowering an entity quota below an existing user quota is refused at the route boundary (§3.13) — operators must clear / lower user quotas first, so a quota reduction is never silent.
- The quota system is NOT a security boundary against a compromised admin: a `PERMISSION_MANAGE` admin could still grant themselves `QUOTA_MANAGE` and lift their own caps. Defense-in-depth is `PLATFORM_OPERATOR`-set entity caps, which `QUOTA_MANAGE` cannot exceed (§3.13). The sole purpose is bounded blast radius and operator cost control, not anti-escalation.

### 14.19 OIDC re-bind protection (T-3)

`oauth_identities.provider_subject_id` is immutable after first link. A second login that returns a different `subject_id` for an existing `(user_id, provider)` MUST be refused with `403 FORBIDDEN` and an `OAUTH_REBIND_REFUSED` audit row. Re-binding requires an admin-gated re-link route (future addition; not in v1).

### 14.20 Permission downgrade race response (T-15)

For high-stakes revocations (compromise response), `POST /admin/sessions/revoke` (§3.12) bulk-inserts `(jti, exp)` rows so any in-flight access tokens matching the predicate fail on the next request. The spec accepts the per-request reload latency (§5.3, §13.2 SLO `≤ 1 ms` p99) as the maximum window during which a revoked permission can still authorise.

### 14.21 Bootstrap argument-consistency check (T-16)

Bootstrap refuses to run when `--admin-email`'s domain does not match `--domain` (§12.3). This is the only structural defense against operator typos at bootstrap; the broader "anyone who controls the email IS the user" trust model (§1.5) deliberately delegates everything else to the operator's IdP.

### 14.22 No client-supplied trust

The Console does NOT trust:

- Forwarded headers, unless `TRUST_FORWARDED_HEADERS=true` is paired with a sanitising reverse proxy (§13.8, T-7).
- The user-supplied `cvm_id` field in `/internal/traffic-logs` payloads (§4.3, T-5).
- The IdP's `id_token` claims (§5.5, T-20).
- Phala's response bodies (§10.1, T-22).
- Phala's claim that an SC is the requested image — measurement is verified via TEE attestation at provisioning and on every reconciler probe (§10.4, T-29).
- Phala's runtime env injection — the SC RTMR-extends its boot config inside the TEE; mismatches against Console-side replay are refused (§10.4, T-30).
- Cloudflare's response bodies beyond the documented `success` flag and field shapes (§10.2).
- The `permissions` claim on Console JWTs for authorization (§5.3, T-15).
- The `kid` of an inbound JWT — it MUST resolve to a configured key set (§5.2, T-1).

## 15. Database migrations

The Console MUST evolve its schema through forward-only versioned migrations. The first migration creates the entire schema; subsequent migrations are incremental. Each migration carries a sequential identifier so the deployed schema's version can be queried.

### 15.1 Migration policy

- **Forward-only in production.** Down-migrations exist for development convenience but MUST NOT run against production data.
- **Online migrations.** Migrations MUST be runnable while the Console is serving traffic. Avoid long-held locks: no full-table rewrites without `CONCURRENTLY`, no destructive renames in a single migration.
- **Naming.** Each migration carries a zero-padded sequential identifier (`NNNN`) and a short human-readable slug.
- **Single head.** The migration chain MUST be linear (one revision, one parent). Divergent branches MUST be merged in source before commit.
- **Timestamped.** The migration files should include a timestamp so that they are sorted and easily readable in order.

### 15.2 Backfills

Any migration that adds a non-nullable column to a populated table MUST follow the three-step pattern:

1. Add the column as nullable.
2. Backfill in bounded chunks (the spec recommends ≤ 10 000 rows per transaction) to avoid lock escalation.
3. Set `NOT NULL` (and add the relevant index).

Steps 1 and 3 MAY live in the same migration if the table is small enough that the transaction completes in under a few seconds. Otherwise the backfill is a separate migration so it can run in its own transaction.

### 15.3 Destructive changes

Drops, renames, and type changes that lose data MUST be split across releases so application code can tolerate either schema for one release:

1. Release N: introduce the new column / structure; both old and new are populated by writes.
2. Release N+1: reads switch to the new column; the old column is no longer touched.
3. Release N+2: drop the old column.

Failing this discipline means a rolled-back deploy crashes against a schema it no longer understands.

### 15.4 Schema deliverables

Every release artifact (§19) MUST include:

- The accumulated migration chain bundled in the deployment image.
- A reference `psql` script that creates the four database roles in §15.5 with the right grants.
- The current schema dump (`pg_dump --schema-only`) used by §19's conformance harness as the canonical comparison target.

### 15.5 Database role separation

The Console deployment MUST provision **four distinct Postgres roles**. Sharing roles across responsibilities is FORBIDDEN.

| Role | Privileges | Where it runs |
|---|---|---|
| `umbra_console_app` | `SELECT, INSERT, UPDATE, DELETE` on every table in §7 EXCEPT `audit_events`, `audit_anchors`, `traffic_log_batches`, `traffic_logs`. `SELECT, INSERT` only on those four. `USAGE` on every enum type. NO `CREATE`, NO `DROP`, NO `TRUNCATE`. | Console runtime process. |
| `umbra_console_migrate` | Full DDL on the schema. `SELECT, INSERT, UPDATE, DELETE` on every table for backfills. | Migration runner. Time-limited credential — a fresh credential per migration run, revoked after. |
| `umbra_console_anchor` | `SELECT, INSERT` on `audit_anchors`. `SELECT` on `audit_events` (read the chain to compute the anchor). NOTHING else. | Anchor task (§11.6). MAY run inside the Console process but MUST authenticate with this distinct credential, NOT the runtime credential. |
| `umbra_console_prune` | `DELETE` on `traffic_logs` and `traffic_log_batches` only, scoped by `WHERE created_at < $1` / `WHERE accepted_at < $1`. NOTHING else. | The retention prune job (§11.8). Time-limited credential per prune run. |
| `umbra_console_redactor` | `UPDATE` on `audit_events` restricted to the columns `actor_email`, `before`, `after`, `prev_hash`, `row_hash` (the last two needed for chain re-hash on PII redaction, §11.9). NOTHING else, including no DELETE, no INSERT, no SELECT on other tables, and no UPDATE on any other column. | The layer-2 audit-redaction step of the user-erase procedure (§3.3 `DELETE /entities/{id}/users/{user_id}`, §11.9). Time-limited credential per erase run; for the self-erase path the user's request itself is the data-subject authorization; for the operator-driven path DPO approval is recorded in the operator's audit attribution. The route emits `USER_ERASED` (§11.2) before the redaction step runs. |

The runtime role MUST NOT be able to:

- Issue DDL (CREATE / DROP / ALTER) — prevents schema drift from a compromised application.
- UPDATE or DELETE rows in `audit_events` — the foundation of T-6 mitigation.
- Read or write `audit_anchors` — separates anchor production from chain writing.
- DELETE rows in `traffic_logs` — pruning is a privileged time-windowed operation, not a casual application capability.

### 15.6 Retention pruning

The prune job MUST:

- Run daily under `umbra_console_prune`.
- DELETE `traffic_logs` rows in chunks of `≤ 10 000` per transaction so the table stays available to writers.
- Use a per-run advisory lock so concurrent runs don't double-prune.
- Emit a `RETENTION_PRUNED` log line at `INFO` with the row count.
- NEVER touch `audit_events`. Audit retention is governed exclusively by §11.8 (indefinite).

## 16. Backup and disaster recovery

The Console owns all platform state. Loss of `audit_events` is unrecoverable from the platform's perspective (the chain anchors §11.6 are the only external trail); loss of operational state means tenants cannot manage their CVMs.

### 16.1 Recovery objectives

| Metric | Target |
|---|---|
| RPO (recovery point objective) | ≤ 5 minutes |
| RTO (recovery time objective) | ≤ 30 minutes |
| Audit-trail durability | "indefinite, off-host" (anchored to an append-only store, §11.6) |
| Traffic-log durability | retention window (§11.8); loss of pre-retention rows is acceptable |

### 16.2 Backup contract

Operators MUST run continuous WAL-shipping or equivalent point-in-time-recovery (PITR) tooling against the Postgres instance:

- Base backups every 24 hours, retained for at least 30 days.
- WAL archives shipped to off-host storage (different cloud account / region than the live database) within the RPO budget.
- The off-host store MUST be encrypted at rest and access-controlled to the operator's break-glass identity, NOT the Console's runtime credentials.
- A weekly automated restore-test job verifies the backup is restorable; failure pages the operator.

### 16.3 Database encryption at rest

The Console's Postgres instance MUST be deployed with at-rest encryption enabled — either at the volume / storage layer (managed disk encryption with operator-controlled keys) or via Postgres TDE-style page encryption. The off-host backup store MUST also be encrypted at rest.

Column-level encryption MAY be applied to high-sensitivity columns (`audit_events.before`, `audit_events.after`, `oauth_identities.email`); when applied, the encryption key MUST be a different KEK from the JWT signing key (so a JWT-key compromise does not also reveal column-encrypted data).

### 16.4 Recovery procedure

1. Provision a fresh Postgres instance in the secondary region / cloud.
2. Restore the latest base backup, then replay WAL up to the desired recovery point.
3. Verify the audit chain by replaying §11.6's verification job against the restored DB; the latest `last_row_hash` MUST match an `audit_anchors` row whose external anchor still verifies.
4. If the chain fails to verify (because rows were written after the last anchor and lost in the recovery window), produce a documented gap report: enumerate the operations that were `pending` / `running` at the recovery point, the audit rows lost, and a one-shot post-recovery anchor that establishes the new starting point. The gap report is itself an audit row (`AUDIT_RECOVERY_GAP`, future enum value).
5. Bring the Console's runtime role online. Existing JWTs remain valid (the JWT signing keys are loaded from `JWT_PRIVATE_KEY_REF`, not from DB). `revoked_tokens` rows committed before the recovery point are preserved; rows lost in the recovery window MUST be re-applied via `POST /admin/sessions/revoke` if any sessions were revoked in that window.
6. Re-anchor the chain (§11.6) immediately after recovery so subsequent forensics has a known good origin.

### 16.5 Multi-region readiness

Multi-region active-active is out of scope for v1 (§20). The spec's RPO of 5 minutes is met by single-region with off-host WAL shipping. A v2 multi-region design would need to address: leader election for the operation scheduler, cross-region serialisation of the audit chain, and tenant-pinned routing.

## 17. Incident response

This section defines the playbook the Console MUST support for the platform-operator role to handle the most common compromise scenarios. The routes referenced here (`/admin/sessions/revoke`, `/admin/keys/rotate`) are spec-mandated.

### 17.1 Detection signals

The Console MUST emit metrics (§13.6) that an external alerting system can use to detect:

- A spike in `umbra_console_request_duration_seconds{status=~"4xx"}` — credential stuffing or enumeration.
- A spike in `umbra_console_rate_limit_drops_total` — DOS or scraping.
- A non-zero `umbra_console_redacted_value_in_log_total` — code path leaking secrets.
- A growing `umbra_console_audit_anchor_age_seconds` — the anchor task is failing (§11.6 attack window).
- A non-zero `umbra_console_audit_chain_verification_failures_total` (emitted by the §19 verification job) — chain tampering detected.
- A non-zero `umbra_console_auth_refresh_reuse_detected_total` — refresh-token replay, probable session-file theft (§5.2, RFC 9700 §4.13.2). Per-tenant SOC investigation: pull the matching `AUTH_REFRESH_REUSE_DETECTED` audit rows for `family_root_jti`, `original_ip`, `replay_ip` to triage.
- A growing `umbra_console_operation_duration_seconds{terminal_status="failed"}` — saga compensation is firing more than usual.

The Console does NOT itself page on these signals; the operator's alerting layer does.

### 17.2 Compromise response — JWT signing key

Trigger: A1 (JWT signing key) is suspected leaked.

1. **Rotate immediately.** `POST /admin/keys/rotate` (§3.12) with a fresh `kid` and `retire_old_after_seconds=0`. The old `kid` is removed from the verifying set immediately; every JWT signed with the old `kid` MUST fail verification on the next request.
2. **Force-revoke outstanding sessions.** `POST /admin/sessions/revoke` (§3.12) with `issued_before=now()`. Every JWT issued before the rotation is added to `revoked_tokens`.
3. **Re-anchor the audit chain** so the rotation event is publicly committed (§11.6).
4. **Rotate every other secret loaded with the same KMS key.** A KMS-key compromise typically affects a class of secrets, not just A1.
5. **Inform tenants** that all sessions were revoked. The CLI receives `401 UNAUTHORIZED` on the next call and re-runs device-flow login.

Target time-to-respond: ≤ 5 minutes from detection to step 2.

### 17.3 Compromise response — Service-principal bearer

Trigger: a Security CVM's `INGEST` or `CA_EXPORT` bearer is suspected leaked.

1. **Decommission the Security CVM** via `DELETE /entities/{id}/security-cvm` (§3.7). This soft-deletes the row and every token row, breaking the bearer's authentication via the §5.7 parent-state check.
2. **Re-provision** via `POST /entities/{id}/security-cvm` so Dev CVMs under the profile have a working Security CVM again. The new bearer is exposed via `Operation.result` once.
3. **Audit any `traffic_logs` rows written by the leaked principal** during the suspected leak window for anomalies. The query is `SELECT * FROM traffic_logs WHERE security_cvm_id = $compromised_id AND timestamp > $leak_window_start`.

A future revision adds in-place rotation (§5.7) so step 1 / 2 can be replaced with a single rotation route.

### 17.4 Compromise response — Security CVM attestation drift (T-29, T-30)

Trigger: the reconciler emits `SECURITY_CVM_ATTESTATION_DRIFT` (§11.2), or an operator-driven `GET /entities/{id}/security-cvm/attestation?probe=true` returns `409 CONFLICT` `details.state="attestation_drift"`.

1. **Pause Dev-CVM-to-SC traffic exposure to users.** Until verification, mark the entity's SC as untrusted: the CLI's `umbra ssh` and any flow that resolves the SC's gateway MUST refuse with the §10.5 `error_reason="ATTESTATION_DRIFT"`. The Console suspends new `cvm.launch` operations against the entity (§9.2) until the operator clears.
2. **Diagnose the drift.** Compare the persisted `security_cvms.image_measurement` and `security_cvms.rtmr3_digest` against the freshly-fetched values returned in the §3.7 `<SecurityCVMAttestation>` response. Drift modes:
   - **Image-measurement mismatch.** The provider booted a different dstack guest baseline, or an operator-driven guest-baseline rollout has not yet updated both `DEV_CVM_IMAGE_MEASUREMENT` and `SECURITY_CVM_IMAGE_MEASUREMENT` to the same MRTD. An SC app-image-only rollout does not explain this mismatch; inspect the full runtime-policy verdict separately for image/compose substitution (T-29).
   - **RTMR3 mismatch only.** Runtime-config tampering (T-30) — `CONSOLE_URL`, bearer hashes, or the `entity_id` binding has changed without re-provisioning. Always treated as malicious.
3. **Decommission and re-provision.** Issue `DELETE /entities/{id}/security-cvm` (which always succeeds even when attestation refuses, §3.7) followed by `POST /entities/{id}/security-cvm`. The new SC's attestation MUST verify before bearer disclosure (§10.4).
4. **Investigate the Phala account** for image-substitution drift: rotate `PHALA_API_TOKEN` (§12), audit Phala-side deployment history for the offending `app_id`, contact the Phala vendor with the attestation evidence.
5. **Notify tenants** of the entity per §17.7: their traffic logs from the suspect window (`security_cvms.attestation_verified_at` to drift detection) should be treated as potentially intercepted.

The persisted `image_measurement` / `rtmr3_digest` are append-only at provisioning — the reconciler's drift check compares fresh attestations against them but never overwrites them. The new SC after re-provisioning gets its own row.

### 17.5 Lost-admin recovery

Trigger: the only `PERMISSION_MANAGE` admin in an entity has been removed / disabled / lost their account.

The Console does NOT expose an interactive "promote a new admin" route to anyone but `PERMISSION_MANAGE` holders themselves (T-14). Recovery is operator-run:

1. Operator (with `PLATFORM_OPERATOR`) opens a privileged psql session as `umbra_console_migrate` (§15.5).
2. Operator runs the documented recovery script: identifies the entity by `domain`, validates the new admin's email's domain matches the entity's `domain` (the same structural check bootstrap enforces, §12.3), then either INSERTs a fresh `users` row (when no row exists, or when the previous one is **erased** — the email tombstone leaves the slot free) or reactivates a **deactivated** row by clearing `deactivated_at`. Grants `PERMISSION_MANAGE` in the same transaction.
3. The new admin's first OIDC login authenticated against the operator's IdP issues the JWT pair via the standard §5.6 path; no out-of-band token is required because the threat model treats email / IdP control as identity (§1.5).
4. An `ADMIN_RECOVERED` audit row is written by the recovery script with the operator's identity, and the standard `USER_REGISTERED` + `PERMISSION_GRANTED` rows from the user insert.

The procedure is documented as a deployment runbook, not a Console route, deliberately: forcing it through `psql` keeps the path narrow and audited.

### 17.6 Audit-trail tampering response

Trigger: §19's chain verifier reports a `prev_hash` mismatch or an external-anchor mismatch.

1. Treat the database as compromised until proven otherwise. Pause writes by scaling the Console runtime to zero replicas (the scheduler stops claiming operations; in-flight HTTP requests fail).
2. Snapshot the database for forensics.
3. Identify the breakpoint: the latest `seq` whose `prev_hash` and `row_hash` are consistent with each other and with the most recent verifying external anchor.
4. Restore from a backup taken before the breakpoint (§16). Re-anchor the chain.
5. Re-apply lost legitimate writes from the post-breakpoint period if recoverable; otherwise document the gap.
6. Investigate the privileged credential responsible for the tampering — by §15.5, only the migration role and Postgres superuser can issue UPDATE / DELETE on `audit_events`.
7. Emit an `AUDIT_TAMPER_DETECTED` audit row (future enum value) describing the breakpoint and recovery actions.

### 17.7 Communication template

For tenant-impacting incidents (compromise response §17.2), the operator MUST notify affected tenants within 24 hours:

- The fact and timing of the incident.
- Which sessions were revoked and which credentials were rotated.
- Whether tenant data was potentially exposed.
- The actions tenants should take (re-login, audit their own logs).

The template is a deployment artifact; the spec does not mandate the wording, only the content categories.

## 18. Implementation stack

The language and libraries the implementation MUST use to meet the requirements above. Same "rationale per choice" style as [CLI spec §9](cli.md). Substitutions are evaluated against the constraints below, not preference.

### 18.1 Language: Python 3.12

- Async-first standard library; type-hint syntax that supports `Mapped[T | None]` cleanly.
- Package compatibility is pinned to `>=3.12,<3.13`; Python 3.13 is not a supported runtime until a CI re-validation pass covers the dependency matrix. Contributor, CI, and release environments use the exact repository `.python-version` patch, matching the digest-pinned runtime image.
- uv package manager + ruff

### 18.2 Web framework: FastAPI

- Pydantic v2 schemas double as request validation and OpenAPI generation, satisfying §2.2 boundary validation without a separate layer.
- `lifespan` hooks drive the reconciler background task, the operation scheduler, the audit-anchor task, and adapter lifecycle.
- Per-request dependencies are the natural home for the §6.3 enforcement order.

### 18.3 ORM: SQLAlchemy 2.x async + asyncpg

- `Mapped[T]` types align with Pydantic v2's strict typing.
- `async_sessionmaker` + per-request session is the standard pattern.
- `selectinload` is the load strategy of choice; lazy loading is disabled to prevent accidental sync calls.
- `asyncpg` is the only async driver with first-class SQLAlchemy 2.x support.
- `SELECT ... FOR UPDATE SKIP LOCKED` is used by the operation scheduler (§9.1) and the reconciler (§9.4).

### 18.4 Migrations: Alembic

Per §15.

### 18.5 Schema validation: Pydantic v2 (+ pydantic-settings)

Used for request bodies, response shapes, and `Settings` (§12). Field-level validators are the canonical home for boundary checks.

Every `secret`-marked configuration value (§12) MUST be typed as `pydantic.SecretStr` (or `SecretBytes`) in the `Settings` model; the loader resolves the raw value through §12.2's mechanism and wraps it. Service code receives the wrapper, never the raw `str` — `.get_secret_value()` is the only path to plaintext and MUST appear only at boundaries that actually emit the value (an outbound HTTP header, a hash write, an env-file write to a subprocess). `SecretStr`'s `__repr__` / `__str__` returns the literal `"<redacted>"`, so accidental logging renders the marker without involving the runtime redaction processor (§13.5).

### 18.6 OIDC / JWT: `python-jose` (or `joserfc`) + `httpx`

- The JWT library MUST support asymmetric algorithms (`EdDSA`, `RS256`) AND `at_hash` enforcement (`joserfc` covers both and is the recommended choice as `python-jose` is deprecated upstream; implementations MUST pin to a maintained library).
- `httpx` is the async HTTP client; pinning is implemented via the client's transport configuration (§10.2, §10.3).
- `authlib` is a good alternative that integrates well with FastAPI. It is supposed to handle all the login process, and no custom code would be required. I'm just not sure yet on the license. It sounds like we would need a commercial license, but it also mention a BSD license. So not sure if we can use it for free in such a product (commercial + closed source).

### 18.7 KMS-backed signing

When `JWT_PRIVATE_KEY_REF` is `kms://...`, the implementation MUST use the KMS provider's signing API rather than holding the private key in process memory. Recommended libraries: `boto3 kms.sign` for AWS, `google-cloud-kms` for GCP. The verifier always uses the public key; only signing is delegated to KMS.

### 18.8 External integrations

- **Phala / dstack:** the `phala` CLI (subprocess), per §10.1.
- **Cloudflare:** thin httpx wrapper, NOT the synchronous `cloudflare` SDK.
- **shade:** an operator-approved checkout pinned by commit for Dev CVM compose generation and configured through `SHADE_DIR`.
- **atlas-rs verifier:** subprocess command from `ATLAS_VERIFIER_CMD`, invoked with JSON on stdin and no shell. Request shape: `{"kind":"dev_cvm"|"security_cvm","fqdn":<fqdn>,"policy":{...}}`, where `policy` carries the dstack TDX policy values from §10.4 / §10.4a. The verifier opens TCP to `fqdn`, uses it as the TLS SNI, and validates the certificate and attestation identity against `fqdn` with `fqdn` as HTTP Host. Success stdout is `{"image_measurement":<96hex>,"rtmr3_digest":<96hex>}`. Failure stdout MAY be `{"error":{"code":<§10.5 attestation code>,"details":{...}}}`; stderr is diagnostic only and MUST be redacted before logging.

### 18.9 Logging: `structlog`

Per §13.3 / §13.5.

### 18.10 Subprocess: stdlib `asyncio`

Phala adapter uses `asyncio.create_subprocess_exec` with explicit `env=` (no inherited env, §10.1). No third-party subprocess library.

### 18.11 Cryptography: stdlib `secrets`, `hashlib`, plus `cryptography`

- `secrets.token_urlsafe(32)` for service-principal bearers, refresh tokens, polling secrets.
- `hashlib.sha256` for token hashing and the audit hash chain.
- `cryptography` for asymmetric signing when not delegated to KMS.

### 18.12 Build and packaging

- Container image based on `python:3.12-slim` (or equivalent).
- `uv` for dependency resolution; `uv.lock` is the lockfile of record.
- The image bundles the `phala` CLI by `npm ci --ignore-scripts` against a committed `package-lock.json` pinning a specific `phala@<version>`. The launcher is symlinked at `PHALA_CLI_PATH`. The resolved npm tarball's SHA-256 is baked into the image as `PHALA_CLI_SHA256` (§10.1).
- The image lives on a read-only mount in production.

### 18.13 Testing

- **Unit tests** colocated in source modules.
- **Integration tests** against real Postgres via `testcontainers-postgres`.
- **API tests** with fake IdP, fake Phala adapter, fake Cloudflare adapter.
- **Saga tests** model-checking the state machines from §8 against fixtures.
- **No in-memory DB shortcut.** SQLite cannot model partial-unique indexes, JSONB columns, advisory locks, or `FOR UPDATE SKIP LOCKED`.
- **Conformance suite** (§19) is part of every release artifact.

## 19. Conformance and deliverables

Implementations MUST publish the artifacts below per release. Conformance is verified by running the suite against a reference deployment of the implementation.

### 19.1 OpenAPI

- The implementation MUST publish `GET /openapi.json` returning the OpenAPI 3.1 document for `/api/v1`. The internal API (`/internal`) is documented in a parallel `GET /internal/openapi.json` with bearer-only auth (the same `METRICS_TOKEN` style as §13.6).
- Every route in §3 and §4 MUST appear in the OpenAPI document with the exact request / response schema referenced from §2.3.
- The conformance harness MUST check that the routes exposed by the running server match the routes described in this spec — no extra public routes, no missing routes.

### 19.2 JSON Schemas

- A `schemas/` directory in the release artifact MUST contain one JSON Schema file per resource representation in §2.3 (`User.json`, `CVM.json`, `Operation.json`, etc.) and one per error code's `details` shape (§2.4).
- The schemas MUST be the source of truth for both server-side validation and client-side parsing (the CLI consumes them).

### 19.3 State-machine reference

For each saga in §8, a state-machine reference (e.g. PlantUML / Mermaid + a transition table CSV) is published. The saga implementation MUST be model-checked against the reference: every reachable state is reachable in tests; every documented transition fires under at least one test case.

### 19.4 Conformance test suite

A black-box test suite MUST be published as a deployable artifact (a Docker image with embedded fixtures + assertions). Implementations are conformant if they pass the suite. The suite covers:

| Area | What it tests |
|---|---|
| Auth and revocation | JWT verification rejects each of the §14.1 failure modes; `POST /admin/sessions/revoke` invalidates outstanding tokens before the next request. |
| Existence non-leak | Every path-id route returns identical responses for "doesn't exist" and "exists in another tenant". |
| RBAC | Each permission gates only its declared routes; `PLATFORM_OPERATOR` cannot be self-granted. |
| Idempotency | `Idempotency-Key` retention is at least 24 hours; same-body repeat is a no-op; different-body collision returns `409 IDEMPOTENCY_CONFLICT`. |
| Idempotency under concurrency | 100 concurrent `POST /cvms` (or any creation route from §2.6) bearing the same `Idempotency-Key` and same body MUST result in exactly one created aggregate row, exactly one `idempotency_keys` row, and 100 byte-identical responses. The test verifies the §2.6 advisory-lock pattern serialises correctly across worker processes; absence of the lock would surface as duplicate aggregate rows. The same property MUST hold for `/internal/traffic-logs` batch-key concurrency (§4.3): 100 concurrent batches with the same `idempotency_key` MUST yield exactly one `traffic_log_batches` row and zero duplicate `traffic_logs` rows. |
| Pagination | Cursor stability across 24 hours; `next_cursor=null` exactly when no more rows. |
| Operations | Submit returns `202 <Operation>`; polling reaches a terminal state; one-shot results redact on second read. |
| Sagas | `cvm.launch` and `security_cvm.provision` reach `succeeded` or `failed` deterministically against fake adapters; compensation order is exactly the §8 reverse-step order. |
| Audit chain | A test-controlled mutation appends a row whose `row_hash` matches the canonical computation; an injected gap is detected by the verifier. |
| External-anchor | An anchor cycle commits a verifiable digest; tampering breaks verification. |
| Internal API isolation | A `/api/v1` JWT presented at `/internal` returns `401`; a `/internal` bearer presented at `/api/v1` returns `401`; cross-tenant `cvm_id` rejected. |
| SC attestation gate | The `security_cvm.provision` saga's `verify_attestation` step (§8.4) refuses each of the failure modes against a fake-attestation harness: bad vendor chain, image-measurement mismatch, RTMR3 mismatch, nonce mismatch, malformed quote. In every refusal case the bearer plaintexts MUST NOT appear in `Operation.result`. |
| SC attestation drift | A test-controlled SC whose `image_measurement` is mutated post-provisioning trips `SECURITY_CVM_ATTESTATION_DRIFT` on the next reconciler probe; `GET /entities/{id}/security-cvm/attestation?probe=true` returns `409` with both reports. |
| Replay protection | `/internal/traffic-logs` rejects timestamps outside the ±10 minute window; idempotency-key replay returns `deduplicated=true`. |
| Rate limits | Per-route, per-credential, per-IP limits trip at the configured budgets; `Retry-After` is set. |
| Secret hygiene | Logs of induced error paths are scanned for §13.5 denylist values; zero matches. |
| Soft-delete read invisibility | For every read endpoint in §3, soft-delete the target row in a fixture and assert the route returns `404` (or filters the row out for list endpoints) — verifies §7.1's "Read invisibility" property. The fixture covers every aggregate carrying `SoftDeleteMixin`. |
| Soft-delete cascade | Soft-deleting a parent row commits the §7.22 dependent rows in the same transaction with `deleted_by` set to the actor of the parent action (not the parent's id, not NULL). The test exercises every cascade pair listed in §7.22. |
| User erasure blocked by owned CVMs | A fixture user with one live Dev CVM is the target of `DELETE /entities/{id}/users/{user_id}`; the response MUST be `409 CONFLICT` with `details.state="user_owns_cvms"` and `details.live_cvm_count = 1`. After terminating the CVM, the same DELETE MUST succeed. The same fixture's `POST /actions/deactivate` MUST succeed regardless of CVM ownership (deactivation is non-blocking, §8.1). |
| User lifecycle state machine | Active → Deactivate → Reactivate → Active is reversible; the user can log in again after Reactivate. Active → Erase MUST refuse subsequent Reactivate with `409 CONFLICT details.state="already_erased"`. Deactivated → Erase MUST work; the deactivation timestamp is preserved alongside the erasure tombstone. |
| Soft-delete ETag | Soft-deletion bumps the row's `updated_at`; an `If-Match` against the pre-deletion ETag fails with `412 PRECONDITION_FAILED`. |
| SLOs | Reference load yields p50 / p99 within §13.2 budgets. |

### 19.5 Release artifacts

A conformant release publishes:

- A signed container image; the bundled `phala` CLI npm tarball's SHA-256 matches the image's `PHALA_CLI_SHA256` env (§10.1).
- The OpenAPI documents for `/api/v1` and `/internal`.
- The JSON Schema bundle.
- The state-machine references.
- The conformance-suite image.
- The four DB-role grant scripts (§15.5).
- A `CHANGES.md` entry per change between releases, classified per §2.1 (breaking vs additive).

### 19.6 Verification jobs

Two verification jobs MUST run continuously against a production deployment:

- **Audit chain replay** (§11.6, §14.13). At least daily, as a server-side production job. Recomputes the complete global chain by processing every committed row in ascending `seq` order, from the first row through the current tip, and verifies every `prev_hash` link and JCS-derived `row_hash`; numeric `seq` gaps are permitted because rolled-back inserts can consume sequence values. It then fetches the latest local anchor and its correlated external PostgreSQL anchor, verifies the external JCS payload and commitment digest, and requires the anchored `last_row_hash` to match the `audit_events` row at the anchor's `last_seq`. It continues replaying any post-anchor tail through the current tip; the anchor need not equal that live tip. Any chain, payload, digest, correlation, or anchored-row mismatch increments `umbra_console_audit_chain_verification_failures_total` and triggers the operator alert (§17.1, §17.6).
- **OpenAPI conformance** (§19.1). At least per-deploy. Compares the running server's `GET /openapi.json` to the artifact published with the release; mismatch fails the deploy.

## 20. Out of scope

Deliberately excluded from this specification.

- **Developer web app.** The CLI is the only developer-facing product UI in v0; the static admin dashboard remains an operator/admin surface over the authenticated API.
- **Self-service entity signup.** Entities are provisioned via bootstrap (§12.3) by a `platform_operator`; there is no public route to create a tenant.
- **Multi-region active-active.** One Console deployment serves one platform region (§16.5). Cross-region replication, leader election, and conflict resolution are unaddressed.
- **Standalone service-principal token rotation.** Deployment update sagas already rotate their service-principal bearers. A standalone route for rotating one bearer without a provider update remains out of scope.
- **Multi-account session storage at the Console.** The CLI manages multi-account on the client side; the Console is single-session per JWT.
- **OS secret-store integration on the host.** §12.2 mandates file-mounted or KMS-backed secrets; integration with host-level credential daemons (Linux Keyring, macOS Keychain) is out of scope.
- **`PATCH /entities/{id}`** (entity update). The `ENTITY_UPDATED` audit value is reserved; the route lands in v1.1. When it does, **`entities.domain` MUST remain immutable** (§7.2). The domain identifies the tenant in OIDC resolution (§5.6), and the email-domain ↔ entity-domain invariant (§7.3) binds every user's email to it; changing `domain` would require rewriting every `users.email` in the entity, invalidating every cached `oauth_identities` (since the IdP-side email-domain wouldn't match), and either re-issuing every outstanding session or letting the next OIDC login fail until users re-login from scratch. The cleaner answer is "create a new entity at the new domain and migrate" — the operator runs the lost-admin recovery script (§17.5) for every user, terminates / re-launches CVMs under the new entity, and decommissions the old one. The PATCH route in v1.1 will surface only mutable fields (`name`, etc.); the domain is set once at bootstrap and never changes.
- **In-CLI Console image upgrades.** The Console image is a deployment artifact; upgrades go through the platform operator's image-rebuild pipeline (§18.12).
- **Billing, quotas, per-tenant resource caps.** §2.6 mandates rate limits as a defense-in-depth posture; tenant-billing semantics are out of scope.
- **Restore / undelete of soft-deleted rows** (non-user). Once a non-user row's `deleted_at` is set the spec exposes no runtime route to clear it. Recovery is operator-only via direct SQL, with the operator personally responsible for resolving partial-unique-index collisions. A future `PLATFORM_OPERATOR`-gated restore route is possible but not in v1. Users are NOT covered by this — user lifecycle has its own state machine (active / deactivated / erased, §7.3); deactivation is reversible by the standard `POST /actions/reactivate` route (§3.3), and erasure is intentionally terminal.
- **Entity deletion.** `entities` carries the `SoftDeleteMixin` columns for forward compatibility, but no operational path exposes deletion and the §7.22 cascade table omits `entities` (§7.2). Soft-deleting an entity is undefined behaviour today; if entity removal becomes a requirement, a future revision MUST specify the cascade scope (every user, profile, CVM, Security CVM, plus the audit retention question for the entity's audit rows) and the procedure (operator runbook vs Console route).
- **SSH-key revocation from running CVMs.** `umbra key remove` deregisters a key from future launches but cannot remove it from CVMs that already have it installed (§3.2). A Security-CVM-mediated key-removal channel is on the roadmap; today the only revocation path is `umbra cvm terminate` + re-launch.
- **Sender-constrained access tokens (DPoP / mTLS-bound `cnf`).** §5.2 issues bearer JWTs: any process that captures one can replay it within the TTL window. RFC 9449 (DPoP) and RFC 8705 (mTLS-bound tokens, `cnf` claim) tie a token to a key the holder must prove possession of, eliminating bearer replay. The TLS-only transport posture (§13.9), the short TTL (default 1 h, §5.2), and the `revoked_tokens` table (§5.2) are the v1 mitigations; sender-constrained issuance is a v1.1+ candidate. Adoption requires Console issuance changes (`cnf.jkt` claim or `cnf.x5t#S256` claim), CLI changes (DPoP proof minting per request, or client-cert provisioning), and verifier changes (`DPoP` header validation, key-thumbprint matching). Out of scope until the threat model evolves.
- **JWE encryption of access tokens.** §5.2 issues JWS (signed-not-encrypted) tokens; the body is decodable by anyone holding the token. The v1 claim set excludes PII (§5.2) so the body carries only `(sub, entity_id, jti, iat/nbf/exp, iss, aud)` — no encryption is required at this scope. If a future revision introduces sensitive claims, JWE (RFC 7516) with `alg=ECDH-ES+A256KW` and `enc=A256GCM` is the candidate; until then, body-encryption is unwarranted complexity.
- **Arbitrary live Security CVM rebinding.** §10.4 binds an SC's identity to RTMR-extended boot values (`CONSOLE_URL`, bearer hashes, etc.). The supported live rebind is the provider-backed `security_cvm.update` saga. Arbitrary in-process mutation of RTMR-bound values without a provider update, and `CONSOLE_URL` rotation for an existing SC, remain out of scope; those require `DELETE` + re-`POST` on `/entities/{id}/security-cvm` (§3.7).
- **Public JWKS endpoint.** §5.2 deliberately omits the `GET /api/v1/.well-known/jwks.json` route in v1 because no v1 component verifies Console-issued JWTs externally. A future revision MAY add it when (and only when) a real external verifier appears (e.g. a service-to-service consumer of Console-issued user JWTs); the SC binding is rooted in TEE attestation, not in JWT signature verification, so this endpoint is not load-bearing for SC trust.
- **Comprehensive PII erasure beyond the §11.9 procedure.** The user-erase procedure covers `users.email` / `users.name` (tombstoned) plus `audit_events.actor_email` and `audit_events.before/after.email` (rewritten under the redactor role). The following residues survive erasure today and would need separate handling in a future revision: (a) `audit_events.ip_address` — IPs are PII per GDPR Art. 4 but the redactor role's column allow-list does not include this column; (b) `audit_events.before/after.name` and other non-email PII keys nested in the JSONB payloads (the procedure only walks `.email`); (c) `operations.actor_email` — denormalised on `operations` rows and not part of the audit-events redaction walk; (d) `idempotency_keys.response_body` for routes that returned `<User>` within the 24 h cache window before erasure; (e) `traffic_logs` rows tied to the user's terminated CVMs, which survive until the configured retention window prunes them naturally. Operator DSAR responses today MUST flag these residues to the data subject. A future revision MAY extend the redactor role's grants to cover (a)–(c) and add a runtime-role pass that hard-DELETEs (d)–(e) at erase time.
