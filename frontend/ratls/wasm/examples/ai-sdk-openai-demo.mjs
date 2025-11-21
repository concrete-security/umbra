#!/usr/bin/env node
// Minimal smoke test that wires ratls-wasm into @ai-sdk/openai using the local proxy
// (`make demo`). Requires dev deps: @ai-sdk/openai, ai, ws.

import init from "../pkg/ratls_wasm.js"
import { createRatlsFetch } from "../pkg/ratls-fetch.js"
import WebSocket from "ws"
import { readFile } from "node:fs/promises"

// Provide browser globals needed by ratls-wasm in Node.
globalThis.WebSocket = WebSocket
// Initialize WASM from bytes to avoid file:// fetch limitations in Node.
const wasmBytes = await readFile(new URL("../pkg/ratls_wasm_bg.wasm", import.meta.url))
await init({ module_or_path: wasmBytes })

async function loadAiSdk() {
  try {
    const { createOpenAI } = await import("@ai-sdk/openai")
    const { streamText } = await import("ai")
    return { createOpenAI, streamText }
  } catch (err) {
    const msg = err?.message || ""
    if (err?.code === "ERR_PACKAGE_PATH_NOT_EXPORTED" && msg.includes("zod")) {
      console.error(
        "Missing zod/v4 export. Install zod@^4 alongside @ai-sdk/openai and ai: pnpm add -D zod@^4 @ai-sdk/openai ai ws"
      )
      process.exit(1)
    }
    throw err
  }
}

const { createOpenAI, streamText } = await loadAiSdk()

const proxyUrl = process.env.RATLS_PROXY_URL || "ws://127.0.0.1:9000"
const targetHost = process.env.RATLS_TARGET || "vllm.concrete-security.com:443"
const serverName = process.env.RATLS_SNI || "vllm.concrete-security.com"
const apiKey = process.env.OPENAI_API_KEY || "dummy-key"
const model = process.env.OPENAI_MODEL || "openai/gpt-oss-120b"
const prompt =
  process.argv.slice(2).join(" ").trim() ||
  "Say hello from RA-TLS over the proxy tunnel."

let lastAttestation
const baseFetch = createRatlsFetch({
  proxyUrl,
  targetHost,
  serverName,
  defaultHeaders: { Authorization: `Bearer ${apiKey}` },
})
const ratlsFetch = async (...args) => {
  const resp = await baseFetch(...args)
  lastAttestation =
    resp.ratlsAttestation ||
    resp.headers?.get?.("x-ratls-attestation") ||
    resp?.response?.ratlsAttestation
  return resp
}

const openai = createOpenAI({
  apiKey,
  baseURL: `https://${serverName}/v1`,
  fetch: ratlsFetch,
})

const { textStream, response } = await streamText({
  model: openai(model),
  messages: [{ role: "user", content: prompt }],
})

process.stdout.write(`Streaming reply (${model} via ${targetHost})...\n`)
for await (const part of textStream) {
  if (typeof part === "string") {
    process.stdout.write(part)
    continue
  }
  // ai-sdk sometimes yields objects with textDelta
  const delta = part?.textDelta ?? part?.value ?? ""
  if (typeof delta === "string") {
    process.stdout.write(delta)
  }
}
process.stdout.write("\n\nAttestation:\n")
const attestation =
  response?.ratlsAttestation ||
  response?.response?.ratlsAttestation ||
  response?.headers?.get?.("x-ratls-attestation") ||
  response?.response?.headers?.get?.("x-ratls-attestation") ||
  lastAttestation
if (attestation) {
  try {
    const parsed = typeof attestation === "string" ? JSON.parse(attestation) : attestation
    console.log(parsed)
  } catch (_err) {
    console.log(attestation)
  }
} else {
  console.log("// missing attestation (check fetch shim)")
  try {
    console.log("debug headers:", Array.from(response?.headers?.entries?.() || []))
  } catch (_err) {}
}
