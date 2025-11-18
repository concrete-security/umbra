# wasm (browser client)

wasm-bindgen wrapper around the Rust core to expose a TypeScript-friendly API for browsers. Carries TLS 1.3 inside WASM and uses WebSocket/WebTransport tunnels to reach the proxy.

## Targets
- Expose `connect(options)` returning `{send, recv, close, attestation}` matching the design report.
- Implement WebSocket transport (binary frames) first; abstract to allow WebTransport later.
- Use `crypto.getRandomValues` for RNG seeding; rely on `Date.now` for wall clock.

## Next steps
- Create wasm-pack config and minimal TS declaration file.
- Add integration test harness (headless) that talks to a mock proxy + mock RA-TLS server.
