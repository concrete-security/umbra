# Architecture snapshot

This captures the initial design for the cross-language RA-TLS client stack and proxy, distilled from the provided implementation-grade plan.

## Goals
- End-to-end TLS 1.3 from browser/Node/Python to the TEE, with tunnel only forwarding bytes.
- Remote attestation verification during TLS handshake via DICE evidence extension (OID 2.23.133.5.4.9).
- Consistent policy enforcement across platforms (TEE type, measurements, TCB, workload IDs).
- Reuse a vetted TLS stack (rustls) with custom certificate verification rather than reimplementing TLS.

## High-level data path
Browser (WASM TLS) --wss/WebTransport--> Proxy (byte forwarder) --TCP--> TEE (RA-TLS server)
The proxy never terminates TLS; the browser runs TLS inside WASM to access certificates and verify attestation.

## Core pieces
- **rustls-based verifier**: `ServerCertVerifier` extracts the DICE extension, parses tagged CBOR evidence, verifies SNP/TDX quotes + endorsements, and checks key binding (`hash(subjectPublicKeyInfo)`).
- **Transport abstraction**: async byte stream trait to support direct TCP (Node/Python) and tunneled transports (WebSocket/WebTransport) for browsers.
- **Policy model**: JSON-friendly policy covering `teeType`, allowed measurements/workload IDs, minimum TCB, validity windows, and pubkey hash algorithms (SHA-256/384).
- **Bindings**:
  - WASM: wasm-bindgen + TypeScript API returning `{send, recv, close, attestation}`.
  - Node: napi-rs with direct TCP default and tunnel fallback.
  - Python: PyO3 async connect helper.
- **Proxy**: WebSocket (and later WebTransport) listener mapping to TCP sockets with target ACLs, origin allowlist, optional JWT/mTLS auth, idle timeouts, and metrics.
- **Server demos**: SNP and TDX examples that generate TLS keys inside the TEE/guest, embed SPKI hash in quote user data, build CBOR evidence, and issue short-lived RA-TLS certs.

## Evidence schema (MVP)
Tagged CBOR inside the DICE extension:
```
{
  "fmt": "dice-ratls-v1",
  "tee_type": "snp" | "tdx",
  "quote": h'<vendor quote/report>',
  "endorsements": h'<optional collateral>',
  "claims": {
    "pubkey_hash_alg": "sha-256" | "sha-384",
    "pubkey_hash": h'<32|48 bytes>',
    "measurement": h'<TEE-specific measurement>',
    "workload_id": "string-or-uuid",
    "timestamp": uint,
    "nonce": h'<optional>',
    "snp_tcb": { ... },
    "tdx_tcb": { ... }
  }
}
```

## Milestones (phase A/B/C/D)
- **A (core + proxy)**: stand up `ratls-core` crate with verifier + transport traits; scaffold proxy byte forwarder and basic ACLs.
- **B (bindings)**: wasm-bindgen wrapper, napi-rs Node binding, PyO3 Python binding.
- **C (server demos)**: SNP and TDX RA-TLS cert issuance examples with short-lived cert rotation.
- **D (hardening)**: endorsement cache endpoint for browsers, fuzzers for ASN.1/CBOR, negative test vectors, policy matrix.

## Testing plan (early focus)
- Unit: CBOR encode/decode, X.509 extension extraction, SPKI hash binding.
- Golden vectors: recorded SNP/TDX quotes + collateral under expected policies.
- E2E: proxy + mock RA-TLS server + WASM client; expect rejection on stale cert, wrong workload, or key-hash mismatch.
