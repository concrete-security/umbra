import init, { run_attestation_check } from "../pkg/ratls_wasm.js"

const form = document.getElementById("check-form")
const statusEl = document.getElementById("status")
const outputEl = document.getElementById("output")
const runButton = document.getElementById("run-check")
const proxyField = document.getElementById("proxy-url")
const targetField = document.getElementById("target-host")
const serverField = document.getElementById("server-name")

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

function setOutput(value) {
  outputEl.textContent = typeof value === "string" ? value : JSON.stringify(value, null, 2)
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

function buildProxyUrl(base, target) {
  const normalized = normalizeProxyUrl(base)
  const url = new URL(normalized)
  url.searchParams.set("target", target)
  return url.toString()
}

function syncServerName(targetValue, force = false) {
  const host = extractHost(targetValue.trim())
  if (!host) {
    return
  }
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

  if (!proxyUrl || !targetHost) {
    setStatus("Proxy URL and target host are required.")
    return
  }
  if (!serverName) {
    setStatus("Server name (SNI) is required; it was not inferred from the target.")
    return
  }

  const wsUrl = buildProxyUrl(proxyUrl, targetHost)

  runButton.disabled = true
  setStatus("Loading wasm bindings…")

  try {
    await ensureWasmLoaded()
    setStatus(`Establishing attested TLS session via ${wsUrl}…`)
    const result = await run_attestation_check(wsUrl, serverName)
    setStatus("Attestation complete.")
    setOutput(result)
  } catch (error) {
    console.error(error)
    setStatus("Attestation failed.")
    setOutput(error instanceof Error ? error.message : String(error))
  } finally {
    runButton.disabled = false
  }
})
