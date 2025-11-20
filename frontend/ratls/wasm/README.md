# wasm (browser client)

wasm-bindgen wrapper around the Rust core to expose a TypeScript-friendly API for browsers. Carries TLS 1.3 inside WASM and uses WebSocket/WebTransport tunnels to reach the proxy.

## Targets
- Expose `connect_websocket` and a simple `run_attestation_check(url, server_name)` wasm export for quick diagnostics.
- Implement WebSocket transport (binary frames) first; abstract to allow WebTransport later.
- Use `crypto.getRandomValues` for RNG seeding; rely on `Date.now` for wall clock.

## Building the bindings

The crate is set up for `wasm-pack`:

```sh
cd ratls/wasm
wasm-pack build --target web --out-dir pkg
```

This produces `pkg/ratls_wasm.{js,wasm}` which can be imported from browser code. Building on macOS requires a Clang toolchain with WebAssembly targets enabled (e.g. `brew install llvm` and make sure `clang --target=wasm32-unknown-unknown` works). If your default Xcode clang lacks the wasm backend the build will fail before linking `ring`.

## Web check demo

`web-check/` is a static harness that loads the wasm bindings and connects to a WebSocket tunnel for a one-off RA-TLS check.

1. Run `wasm-pack build --target web --out-dir pkg` (as above).
2. Serve the directory (for example `python -m http.server` or `npx serve`) from `ratls/wasm`.
3. Open `http://localhost:8000/web-check/`. By default it points the WebSocket client at `ws://127.0.0.1:9000` (matching `make demo`). Enter the TLS target (`host:port`) and SNI; the UI will append `?target=host:port` to the proxy URL automatically so each connection can choose its own upstream. Clicking “Run attestation check” dials the proxy, runs the RA-TLS handshake end-to-end, and prints the resulting JSON.

## Next steps
- Add integration test harness (headless) that talks to a mock proxy + mock RA-TLS server.
