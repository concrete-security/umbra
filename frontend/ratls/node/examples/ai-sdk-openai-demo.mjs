#!/usr/bin/env node
// Direct TCP RA-TLS smoke test with @ai-sdk/openai using the native ratls-node binding.
// Requires: cargo build -p ratls-node --release, Node 18+ (built-in fetch), deps @ai-sdk/openai ai ws zod@^4.

import { createRequire } from "module"
import { createRatlsFetch } from "../ratls-fetch.js"

const require = createRequire(import.meta.url)
const { createOpenAI } = require("@ai-sdk/openai")
const { streamText } = require("ai")

const targetHost = process.env.RATLS_TARGET || "vllm.concrete-security.com:443"
const serverName = process.env.RATLS_SNI || "vllm.concrete-security.com"
const apiKey = process.env.OPENAI_API_KEY || "dummy-key"
const model = process.env.OPENAI_MODEL || "openai/gpt-oss-120b"
const prompt =
  process.argv.slice(2).join(" ").trim() ||
  "Say hello from Node RA-TLS over direct TCP."

const ratlsFetch = await createRatlsFetch({
  targetHost,
  serverName,
  defaultHeaders: { Authorization: `Bearer ${apiKey}` },
})

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
for await (const delta of textStream) {
  const text = typeof delta === "string" ? delta : delta?.textDelta ?? delta?.value ?? ""
  process.stdout.write(text)
}

const attestationHeader =
  response?.ratlsAttestation ||
  response?.headers?.get?.("x-ratls-attestation") ||
  response?.response?.headers?.get?.("x-ratls-attestation")
let attestation = attestationHeader
if (typeof attestation === "string") {
  try {
    attestation = JSON.parse(attestation)
  } catch (_) {}
}

process.stdout.write("\n\nAttestation:\n")
console.log(attestation || "// missing attestation")
