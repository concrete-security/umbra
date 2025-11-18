# core (Rust)

Rust crate that owns TLS 1.3 client logic (rustls) and attestation verification.

## Responsibilities
- Custom `ServerCertVerifier` extracting DICE OID 2.23.133.5.4.9, parsing tagged CBOR evidence, and dispatching SNP/TDX verification + key-binding.
- Policy model (JSON/serde) governing tee type, measurements, TCB, workload IDs, validity windows, and hash algorithms.
- Transport abstraction for async byte streams (direct TCP and tunneled).

## Near-term tasks
- Set up Cargo.toml with rustls, webpki-roots (for non-RA cases), cborg/serde_cbor, x509-parser/asn1-rs.
- Implement SPKI hash helper and unit tests with vectors.
- Prototype evidence parser with schema in `docs/ARCHITECTURE.md`.
