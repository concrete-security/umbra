# ratls (scaffold)

A portable RA-TLS client/proxy toolkit intended for browser (WASM), Node.js, and Python clients to establish an end-to-end remotely attested TLS channel to a TEE. This directory bootstraps the workspace structure that will be developed alongside the frontend.

## Layout
- `core/` — Rust crate for TLS + attestation verification (rustls + custom `ServerCertVerifier`).
- `wasm/` — wasm-bindgen wrapper and TypeScript-facing API plus tunnel transports for WebSocket/WebTransport.
- `node/` — napi-rs binding with direct TCP + tunnel fallback.
- `python/` — PyO3 binding with async connect helpers.
- `proxy/` — byte-forwarding proxy (WebSocket/WebTransport <-> TCP) with ACL/auth hooks.
- `server-examples/` — demo RA-TLS servers for SNP and TDX showing cert generation and key binding.
- `docs/` — living design notes and task tracking.

## Immediate targets
1) Define the Rust core crate shape (Cargo.toml, feature flags, policy model, transport traits).
2) Draft CBOR evidence schema and DICE OID parsing helpers with unit tests.
3) Sketch proxy interface and safety requirements (origin/target ACL, backpressure).
4) Capture demo server flow for SNP/TDX RA-TLS cert issuance.

## Usage notes
This scaffold is self-contained and does not alter the existing Next.js app. Add code and build tooling inside this directory. Keep secrets out of the tree; rely on local `.env` per the repository guidelines when introducing test fixtures or endorsement fetchers.

## Build helpers
- `make test` / `make test-wasm` – run the native Rust tests or the wasm32 check build.
- `make proxy`, `make web-check`, `make demo` – start the tunnel, serve the static harness, or run both (demo defaults to `ws://127.0.0.1:9000` with the wasm app on `http://localhost:8080/web-check/`).
- `./build-wasm.sh` – runs `wasm-pack build --target web --out-dir pkg` inside `wasm/`. Set `WASM_TARGET` or `WASM_OUT_DIR` env vars to tweak the output, or pass extra args (e.g. `--release`).
