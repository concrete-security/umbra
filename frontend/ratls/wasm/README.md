# wasm (browser client)

wasm-bindgen wrapper around the Rust core to expose a TypeScript-friendly API for browsers. Carries TLS 1.3 inside WASM and uses WebSocket/WebTransport tunnels to reach the proxy.

## Targets
- Expose `run_attestation_check(url, server_name)` for quick diagnostics.
- Provide `httpRequest` for HTTP/1.1 over RA-TLS with streaming bodies.
- Ship a fetch-compatible shim (`ratls-fetch.js`) so higher-level AI SDKs can plug in without custom plumbing.
- Implement WebSocket transport (binary frames) first; abstract to allow WebTransport later.
- Use `crypto.getRandomValues` for RNG seeding; rely on `Date.now` for wall clock.

## Building the bindings

The crate is set up for `wasm-pack`:

```sh
cd ratls/wasm
wasm-pack build --target web --out-dir pkg
```

You can also run `make build-wasm` (or `./build-wasm.sh`) from the repo root, which wraps the same command and accepts the usual `WASM_TARGET`/`WASM_OUT_DIR` overrides.

This produces `pkg/ratls_wasm.{js,wasm}` plus `ratls-fetch.{js,d.ts}` so you can import the fetch shim straight from the package. Building on macOS requires a Clang toolchain with WebAssembly targets enabled (e.g. `brew install llvm` and make sure `clang --target=wasm32-unknown-unknown` works). If your default Xcode clang lacks the wasm backend the build will fail before linking `ring`.

### Using the bindings

Once the bundle is built you can import it from any ESM environment (Next.js, plain `<script type="module">`, etc.):

```ts
import init, { httpRequest, run_attestation_check } from "ratls-wasm";
import { createRatlsFetch } from "ratls-wasm/ratls-fetch.js";

await init(); // load the wasm module

// 1. Fire-and-forget attestation check (returns the AttestationResult JSON)
const attestation = await run_attestation_check("ws://proxy.example.com?tunnel", "vllm.concrete-security.com");
console.log(attestation);

// 2. Manual HTTP/1.1 over RA-TLS with a streaming body
const ratlsResponse = await httpRequest(
  "ws://proxy.example.com?tunnel",
  "vllm.concrete-security.com",
  "vllm.concrete-security.com:443", // Host header
  "POST",
  "/v1/chat/completions?stream=true",
  [{ name: "Content-Type", value: "application/json" }],
  new TextEncoder().encode(JSON.stringify({ hello: "world" }))
);
// Read with await ratlsResponse.readChunk() until it returns an empty Uint8Array, then await ratlsResponse.close().
// ratlsResponse.attestation() gives you the attestation result for logging/metrics.

// 3. Fetch-compatible shim for libraries like @ai-sdk/openai
const ratlsFetch = createRatlsFetch({
  proxyUrl: "ws://127.0.0.1:9000",
  targetHost: "vllm.concrete-security.com:443",
  serverName: "vllm.concrete-security.com",
});
// response.ratlsAttestation carries the attestation metadata
```

`run_attestation_check` is ideal for diagnostics (fetch quote → verify → close). `httpRequest` returns a `RatlsResponse` that exposes `status`, `statusText`, `headers()`, `readChunk()`, and `close()` for streaming use cases. `createRatlsFetch` wraps that lower-level API in a drop-in `fetch` replacement, including streaming bodies for chat completions.
Hand `ratlsFetch` to any SDK that accepts a custom `fetch` (for example `createOpenAI({ fetch: ratlsFetch })`) to keep AI streaming responses inside the attested TLS channel.

## AI SDK + RA-TLS smoke test (Node)

You can stream from `@ai-sdk/openai` through the proxy using the included shim:

```sh
pnpm add -D @ai-sdk/openai ai ws zod@^4
make build-wasm           # produces wasm/pkg/*
make demo                 # starts proxy -> vllm.concrete-security.com:443
node wasm/examples/ai-sdk-openai-demo.mjs "Send a short attested hello from RA-TLS"
```

Environment knobs (all optional): `RATLS_PROXY_URL` (default `ws://127.0.0.1:9000`), `RATLS_TARGET` (default `vllm.concrete-security.com:443`), `RATLS_SNI` (default `vllm.concrete-security.com`), `OPENAI_API_KEY`, and `OPENAI_MODEL`. The script prints the streaming reply and the attestation payload from the response (`response.ratlsAttestation`).

## Web check demo

`web-check/` is a static harness that loads the wasm bindings and connects to a WebSocket tunnel for a one-off RA-TLS check.

1. Run `wasm-pack build --target web --out-dir pkg` (as above).
2. Serve the directory (for example `python -m http.server` or `npx serve`) from `ratls/wasm`.
3. Open `http://localhost:8000/web-check/`. By default it points the WebSocket client at `ws://127.0.0.1:9000` (matching `make demo`). Enter the TLS target (`host:port`) and SNI; the UI will append `?target=host:port` to the proxy URL automatically so each connection can choose its own upstream. Clicking “Run attestation check” dials the proxy, runs the RA-TLS handshake end-to-end, and prints the resulting JSON.

Tip: `make demo` runs both the proxy (listening on `127.0.0.1:9000`) and a static server for `web-check/`, so you can try the workflow in one terminal and simply refresh the page after rebuilding.

## Next steps
- Add integration test harness (headless) that talks to a mock proxy + mock RA-TLS server.
