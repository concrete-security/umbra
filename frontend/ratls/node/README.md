# node (napi-rs binding) — direct RA-TLS for Node apps

Planned Node bindings for `ratls-core`. The Node flavor connects **directly over TCP to the RA-TLS server** (no proxy needed) and exposes a fetch-compatible adapter so AI SDKs (e.g. `@ai-sdk/openai`) can stream through an attested TLS channel.

## Current API surface (native N-API module)
- `http_request(targetHost, serverName, method, path, headers, body?) -> Promise<{ status, statusText, headers, body, attestation }>` (direct TCP, buffered body).
- `http_stream_request(...) -> { status, status_text, headers, attestation, stream_id }` plus `stream_read(stream_id, max_bytes?)` and `stream_close(stream_id)` for true streaming bodies.
- `ratls-fetch.js` exports `createRatlsFetch` (Node fetch shim) that prefers the streaming API when available; attaches attestation to `response.ratlsAttestation` and `x-ratls-attestation`.
- Shared attestation JSON shape matches the WASM client.

## Building the native module + running the AI SDK smoke test

```sh
rustup override set 1.88.0   # or newer
cargo build -p ratls-node --release
pnpm add -D @ai-sdk/openai ai ws zod@^4
node examples/ai-sdk-openai-demo.mjs "Hello from RA-TLS"
```

The loader at `node/index.js` defaults to `target/release/ratls_node.node` (falls back to debug); override via `RATLS_NODE_BINARY=/path/to/ratls_node.node`.

## Usage with AI SDKs (direct TCP, no proxy)

```ts
import { http_request } from "ratls-node"
import { createOpenAI } from "@ai-sdk/openai"
import { streamText } from "ai"

import { createRatlsFetch } from "ratls-node/ratls-fetch.js"

const ratlsFetch = await createRatlsFetch({
  targetHost: "vllm.concrete-security.com:443",
  serverName: "vllm.concrete-security.com",
  defaultHeaders: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
})

const openai = createOpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  baseURL: "https://vllm.concrete-security.com/v1",
  fetch: ratlsFetch,
})

const { textStream, response } = await streamText({
  model: openai("openai/gpt-oss-120b"),
  messages: [{ role: "user", content: "Attested hello from Node" }],
})

for await (const delta of textStream) process.stdout.write(delta.textDelta ?? delta)
console.log("\nattestation:", response.ratlsAttestation)
```

Notes:
- No proxy required; RA-TLS runs directly over TCP from Node to the TEE endpoint.
- Streaming is supported via the `http_stream_request` path in the fetch shim; tokens should flow incrementally. Attestation is available on `response.ratlsAttestation` and also in an `x-ratls-attestation` header for clones.

## Tests
- `make test-node` (requires rustc >= 1.88 + network): builds the native addon and runs `node/examples/ai-sdk-openai-demo.mjs` against `vllm.concrete-security.com` using the RA-TLS fetch shim.
- Rust unit test exercises request path normalization (`cargo test -p ratls-node --lib`). Live RA-TLS tests require a real attested endpoint and are not enabled by default.
