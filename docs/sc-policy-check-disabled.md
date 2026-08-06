# TEMPORARY: Security CVM aTLS image-policy check disabled in the Dev CVM

**Status: temporary mitigation. Remove when a robust solution lands.**

This document is the single pointer to a deliberately-hardcoded weakening of the Dev CVM's egress attestation, and the exact steps to undo it. If you are hardening the platform, this is the thing to remove.

## Why this exists

Updating the Security CVM (SC) image changes the SC's measured `app_compose`. Each Dev CVM's egress forwarder pins that `app_compose` through its aTLS policy (`SECURITY_CVM_ATLS_POLICY_B64`). After an SC image bump the forwarder verifies the new-image SC against the old-image policy → `app_compose_hash_mismatch` → fail-closed `502` on every egress CONNECT. Historically, recovering required a fleet-wide Dev CVM update.

The authenticated runtime policy-refresh path in current Umbra Dev images removes that operational fleet churn: after the runtime CA poll accepts the current CA, the forwarder can fetch and locally verify the current SC policy. A persisted `SECURITY_CVM_REBIND_REQUIRED` marker does not prove this runtime exists; the renamed build leaves that resource fail-closed for termination/decommission through the pre-Umbra control plane and replacement under Umbra. That candidate still comes from the Console, however, so it is not an independently signed release measurement. Until release-pipeline-signed SC policy material is verified locally, the Dev aTLS helper remains hardcoded to **disable the SC image/runtime policy check** and accepts any genuine SC TEE at the bound FQDN regardless of its app image.

> This addresses only the **aTLS image-policy** binding. The SC mitmproxy **CA** also rotates on an SC update; that binding is handled separately by the runtime CA fetch/install feature (Console `GET /internal/dev-control/security-cvm-ca` + the Dev forwarder CA poller + the sandbox `umbra-ca-refresh` watcher). That feature is durable and is **not** removed when re-enabling this check.

## Security posture while disabled

Still verified by `atlas-rs` on every egress tunnel to the SC (unchanged):

- the DCAP quote is a genuine Intel TDX TEE quote,
- TCB status is allowed,
- the SC's TLS certificate is bound into the attested event log,
- report-data binds `nonce || EKM` (anti-replay / anti-relay),
- RTMR replay matches the verified report.

**Skipped while disabled:** bootchain (MRTD/RTMR0-2), `app_compose` hash, `os_image_hash`. In other words: we still prove we are talking to a real SC TEE at the bound FQDN — we just stop pinning *which SC image* it runs.

## Exactly what is hardcoded (and where)

All of it is in one file: [`cvms/dev/user-sandbox/atls-connect/src/lib.rs`](../cvms/dev/user-sandbox/atls-connect/src/lib.rs), in three blocks each fenced with `===== UMBRA TEMPORARY: SC aTLS image-policy check disabled =====`:

1. **`load_policy()`** — after the (unchanged) `validate_policy(&policy)?`, a call to `force_disable_sc_runtime_verification(policy)` strips the image/runtime pins from the already-validated policy before it is returned to the verifier.
2. **`force_disable_sc_runtime_verification()`** — the helper fn that sets `disable_runtime_verification = true` and clears `expected_bootchain` / `app_compose` / `os_image_hash`.
3. **`temporarily_forces_runtime_verification_disabled`** — the unit test that pins this behavior.

`validate_policy()` itself is **unchanged**: it still rejects a malformed or `disable_runtime_verification`-bearing policy *as delivered*. The disable is applied by us, after validation — so a stray disabled policy from the control plane is still rejected.

## How to re-enable (remove the mitigation)

1. In `cvms/dev/user-sandbox/atls-connect/src/lib.rs`, delete the three `UMBRA TEMPORARY` blocks (the call site in `load_policy`, the `force_disable_sc_runtime_verification` fn, and the `temporarily_forces_runtime_verification_disabled` test). After removal, `load_policy` ends with `validate_policy(&policy)?; Ok(policy)` again.
2. Remove the matching `UMBRA TEMPORARY` notes in [`cvms/dev/README.md`](../cvms/dev/README.md), [`docs/specs/dev-cvm.md`](specs/dev-cvm.md) §4.5, and the pointer in [`AGENTS.md`](../AGENTS.md). Delete this file.
3. `make check && make test`.
4. `make redeploy-dev`, then roll the Dev fleet so the strict helper is in effect. Because the strict check is back, the operator flow for SC image changes again depends on the CA being stable and the SC aTLS policy refresh path (`docs/specs/dev-cvm.md` §4.5) — verify those before re-enabling in production.

## Rollout

Shipping (and later removing) this requires one Dev CVM image rebuild + fleet redeploy, because the check lives in the `umbra-atls-connect` binary baked into the image. After the disable is deployed, SC image updates no longer require Dev CVM updates for the aTLS-policy reason.
