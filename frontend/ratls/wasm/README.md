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

You can also run `make build-wasm` (or `./build-wasm.sh`) from the repo root, which wraps the same command and accepts the usual `WASM_TARGET`/`WASM_OUT_DIR` overrides.

This produces `pkg/ratls_wasm.{js,wasm}` which can be imported from browser code. Building on macOS requires a Clang toolchain with WebAssembly targets enabled (e.g. `brew install llvm` and make sure `clang --target=wasm32-unknown-unknown` works). If your default Xcode clang lacks the wasm backend the build will fail before linking `ring`.

### Using the bindings

Once the bundle is built you can import it from any ESM environment (Next.js, plain `<script type="module">`, etc.):

```ts
import init, { run_attestation_check, connect_websocket } from "./pkg/ratls_wasm.js";

await init(); // load the wasm module

// 1. Fire-and-forget attestation check (returns the AttestationResult JSON)
const attestation = await run_attestation_check("ws://proxy.example.com?tunnel", "vllm.concrete-security.com");
console.log(attestation);

// 2. Full TLS stream if you want to keep the connection open
const policy = {}; // optional JSON policy mirrors the Rust struct
const [tlsStream, quote] = await connect_websocket("ws://proxy.example.com?tunnel", "vllm.concrete-security.com", policy, null);
// tlsStream implements AsyncRead/AsyncWrite semantics; use wasm-bindgen-futures helpers to drive it.

// 3. OpenAI-compatible vLLM call (runs attestation, keeps the TLS session, posts to /v1/chat/completions)
const chat = await run_vllm_chat_completion(
  "ws://proxy.example.com?tunnel",
  "vllm.concrete-security.com",
  "vllm.concrete-security.com",
  process.env.OPENAI_API_KEY,
  "Give me a two sentence summary of RA-TLS in browsers",
  "openai/gpt-oss-120b"
);
```

`run_attestation_check` is ideal for diagnostics (fetch quote → verify → close). Use `connect_websocket` when you need the verified TLS stream to send application data after attestation succeeds.

## Web check demo

`web-check/` is a static harness that loads the wasm bindings and connects to a WebSocket tunnel for a one-off RA-TLS check.

1. Run `wasm-pack build --target web --out-dir pkg` (as above).
2. Serve the directory (for example `python -m http.server` or `npx serve`) from `ratls/wasm`.
3. Open `http://localhost:8000/web-check/`. By default it points the WebSocket client at `ws://127.0.0.1:9000` (matching `make demo`). Enter the TLS target (`host:port`) and SNI; the UI will append `?target=host:port` to the proxy URL automatically so each connection can choose its own upstream. Clicking “Run attestation check” dials the proxy, runs the RA-TLS handshake end-to-end, and prints the resulting JSON.

Tip: `make demo` runs both the proxy (listening on `127.0.0.1:9000`) and a static server for `web-check/`, so you can try the workflow in one terminal and simply refresh the page after rebuilding.

## vLLM chat demo

`vllm-chat/` dials the proxy, performs RA-TLS, and posts to `https://vllm.concrete-security.com/v1/chat/completions` using the new `run_vllm_chat_completion` export. It accepts your proxy URL, target host:port, SNI override, optional API key, model name, and prompt before returning the attestation result plus the raw OpenAI JSON.

1. Rebuild the bindings (`wasm-pack build --target web --out-dir pkg` or `./build-wasm.sh`) so the new export is available to the browser.
2. Serve `ratls/wasm` (e.g. `make web-check` or `python -m http.server`) and open `/vllm-chat/`.
3. Leave the defaults (`ws://127.0.0.1:9000` proxy, `vllm.concrete-security.com:443` target) or adjust for your tunnel. Paste an API key if the vLLM endpoint enforces auth, then send a prompt to see the attestation + completion payloads.

## Next steps
- Add integration test harness (headless) that talks to a mock proxy + mock RA-TLS server.
