import init, { run_vllm_chat_completion } from "../pkg/ratls_wasm.js"

const form = document.getElementById("chat-form")
const statusEl = document.getElementById("status")
const attestationEl = document.getElementById("attestation")
const responseEl = document.getElementById("response")
const outputEl = document.getElementById("model-output")
const proxyField = document.getElementById("proxy-url")
const targetField = document.getElementById("target-host")
const serverField = document.getElementById("server-name")
const apiKeyField = document.getElementById("api-key")
const modelField = document.getElementById("model")
const promptField = document.getElementById("prompt")
const runButton = document.getElementById("run-chat")

let wasmReady = false

async function ensureWasmLoaded() {
  if (!wasmReady) {
    await init()
    wasmReady = true
  }
}

function setStatus(message) {
  statusEl.textContent = message
}

function setAttestation(value) {
  attestationEl.textContent = format(value) || "// no attestation yet"
}

function setResponse(value) {
  responseEl.textContent = format(value) || ""
}

function setModelOutput(text) {
  outputEl.textContent = text || "No completion text returned. Check the raw response."
}

function format(value) {
  if (value === undefined || value === null) return ""
  if (typeof value === "string") return value
  try {
    return JSON.stringify(value, null, 2)
  } catch (error) {
    console.error(error)
    return String(value)
  }
}

function normalizeProxyUrl(raw) {
  if (!raw) return ""
  if (/^wss?:\/\//i.test(raw)) {
    return raw
  }
  return `ws://${raw.replace(/^\/+/, "")}`
}

function normalizeTarget(value) {
  if (!value) return ""
  return value.includes(":") ? value : `${value}:443`
}

function extractHost(value) {
  if (!value) return ""
  const [host] = value.split(":")
  return host
}

function hostHeaderFor(target) {
  if (!target) return ""
  const [host, port] = target.split(":")
  if (!host) return ""
  if (port && port !== "443") {
    return `${host}:${port}`
  }
  return host
}

function buildProxyUrl(base, target) {
  const normalized = normalizeProxyUrl(base)
  const url = new URL(normalized)
  url.searchParams.set("target", target)
  return url.toString()
}

function syncServerName(targetValue, force = false) {
  const host = extractHost(targetValue.trim())
  if (!host) return
  const userEdited = serverField.dataset.userEdited === "true"
  if (force || !userEdited || !serverField.value.trim()) {
    serverField.value = host
  }
}

serverField.addEventListener("input", () => {
  serverField.dataset.userEdited = "true"
})

targetField.addEventListener("input", () => {
  syncServerName(targetField.value)
})

syncServerName(targetField.value, true)

form.addEventListener("submit", async (event) => {
  event.preventDefault()
  const proxyUrl = proxyField.value.trim()
  const targetHost = normalizeTarget(targetField.value.trim())
  const serverNameRaw = serverField.value.trim()
  const serverName = serverNameRaw || extractHost(targetHost)
  const prompt = promptField.value.trim()

  if (!proxyUrl || !targetHost || !serverName) {
    setStatus("Proxy URL, target host, and server name are required.")
    return
  }
  if (!prompt) {
    setStatus("Prompt cannot be empty.")
    return
  }

  const model = modelField.value.trim()
  const apiKey = apiKeyField.value.trim()

  let wsUrl
  try {
    wsUrl = buildProxyUrl(proxyUrl, targetHost)
  } catch (error) {
    console.error(error)
    setStatus("Proxy URL is invalid.")
    return
  }

  setStatus(`Connecting to ${wsUrl} with SNI ${serverName}…`)
  runButton.disabled = true

  try {
    await ensureWasmLoaded()
    const result = await run_vllm_chat_completion(
      wsUrl,
      serverName,
      hostHeaderFor(targetHost) || null,
      apiKey || null,
      prompt,
      model || null
    )
    setStatus(`Model replied with HTTP ${result.status} ${result.statusText}`)
    setModelOutput(result.completion || "No completion text returned. Check the raw response.")
    setAttestation(result.attestation)
    setResponse({
      status: result.status,
      statusText: result.statusText,
      headers: result.headers,
      body: result.body,
    })
  } catch (error) {
    console.error(error)
    setStatus("Request failed.")
    setModelOutput(error instanceof Error ? error.message : String(error))
    setAttestation("// no attestation")
    setResponse(error instanceof Error ? error.message : String(error))
  } finally {
    runButton.disabled = false
  }
})
