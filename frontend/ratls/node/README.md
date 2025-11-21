# node (napi-rs binding) — direct RA-TLS for Node apps

Planned Node bindings for `ratls-core`. The Node flavor connects **directly over TCP to the RA-TLS server** (no proxy needed) and exposes a fetch-compatible adapter so AI SDKs (e.g. `@ai-sdk/openai`) can stream through an attested TLS channel.

## Current API surface (native N-API module)
- `http_request(targetHost, serverName, method, path, headers, body?) -> Promise<{ status, statusText, headers, body, attestation }>` (direct TCP, no proxy).
- Shared attestation JSON shape matches the WASM client (available on `response.attestation` and echoed in `x-ratls-attestation`).

## Building the native module

```sh
cargo build -p ratls-node --release   # requires rustc >= 1.88
node -e "require('./node')"
```

The loader at `node/index.js` defaults to `target/release/ratls_node.node` (falls back to debug); override via `RATLS_NODE_BINARY=/path/to/ratls_node.node`.

## Usage with AI SDKs (direct TCP, no proxy)

```ts
import { http_request } from "ratls-node"
import { createOpenAI } from "@ai-sdk/openai"
import { streamText } from "ai"

async function ratlsFetch(input: RequestInfo, init?: RequestInit) {
  const req = new Request(input, init)
  const targetHost = "vllm.concrete-security.com:443"
  const url = new URL(req.url, `https://${targetHost}`)
  const hostHeader = req.headers.get("host") || url.host || targetHost

  const headers = Array.from(req.headers.entries()).map(([name, value]) => ({
    name,
    value,
  }))
  const body = req.body ? Buffer.from(await req.arrayBuffer()) : undefined

  const resp = await http_request(
    targetHost,
    hostHeader,
    req.method || "GET",
    `${url.pathname}${url.search}`,
    headers,
    body
  )

  const nodeHeaders = new Headers()
  resp.headers.forEach(({ name, value }) => nodeHeaders.append(name, value))
  nodeHeaders.set("x-ratls-attestation", JSON.stringify(resp.attestation))

  const res = new Response(resp.body, {
    status: resp.status,
    statusText: resp.status_text,
    headers: nodeHeaders,
  })
  Object.defineProperty(res, "ratlsAttestation", {
    value: resp.attestation,
    enumerable: false,
  })
  return res
}

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
- Streaming works via the custom fetch; attestation is available on `response.ratlsAttestation` and also in an `x-ratls-attestation` header for clones.

## Tests
- Rust unit test exercises request path normalization (`cargo test -p ratls-node --lib`).
  Live RA-TLS tests require a real attested endpoint and are not enabled by default.
