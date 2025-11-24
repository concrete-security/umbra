import init, { RatlsClient } from "./ratls_wasm.js"

const ATTESTATION_HEADER = "x-ratls-attestation"

function ensurePrototypeGetter() {
  if (typeof Response !== "undefined" && !Object.getOwnPropertyDescriptor(Response.prototype, "ratlsAttestation")) {
    Object.defineProperty(Response.prototype, "ratlsAttestation", {
      get() {
        const header = this.headers?.get?.(ATTESTATION_HEADER)
        if (!header) return undefined
        try {
          return JSON.parse(header)
        } catch (_err) {
          return undefined
        }
      },
    })
  }
}

let wasmReady

async function ensureWasm() {
  if (!wasmReady) {
    wasmReady = init()
  }
  return wasmReady
}

function isLoopbackHostname(host) {
  const value = host?.toLowerCase?.() || ""
  return value === "localhost" || value === "0.0.0.0" || value === "::1" || value.startsWith("127.")
}

function normalizeProxyUrl(raw) {
  if (!raw) return ""
  const candidate = /^wss?:\/\//i.test(raw) ? raw : `ws://${raw.replace(/^\/+/, "")}`
  try {
    const url = new URL(candidate)
    const isProd = typeof process !== "undefined" && process?.env?.NODE_ENV === "production"
    if (isProd && url.protocol !== "wss:" && !isLoopbackHostname(url.hostname)) {
      throw new Error("RA-TLS proxy URL must use wss:// in production")
    }
    return url.toString()
  } catch (error) {
    if (error instanceof Error && /must use wss/i.test(error.message || "")) {
      throw error
    }
    return candidate
  }
}

function enhanceProxyError(error, proxyUrl) {
  if (!error || typeof proxyUrl !== "string") return error
  const message = typeof error.message === "string" ? error.message.toLowerCase() : ""
  if (!message) return error
  if (message.includes("websocket") && (message.includes("failed") || message.includes("error"))) {
    const friendly = new Error(`Failed to reach RA-TLS proxy at ${proxyUrl}. Ensure the proxy is running and reachable.`)
    friendly.cause = error
    return friendly
  }
  return error
}

function normalizeTarget(value) {
  if (!value) return ""
  return value.includes(":") ? value : `${value}:443`
}

function hostHeaderFor(target) {
  const [host, port] = target.split(":")
  if (port && port !== "443") {
    return `${host}:${port}`
  }
  return host
}

function buildProxyUrl(base, target) {
  const url = new URL(normalizeProxyUrl(base))
  if (target) {
    url.searchParams.set("target", target)
  }
  return url.toString()
}

function debugEnabled() {
  try {
    if (typeof process !== "undefined" && (process?.env?.DEBUG_RATLS_FETCH === "true" || process?.env?.NEXT_PUBLIC_DEBUG_RATLS_FETCH === "true")) return true
    if (typeof globalThis !== "undefined" && globalThis?.NEXT_PUBLIC_DEBUG_RATLS_FETCH === true) return true
    if (typeof localStorage !== "undefined" && localStorage.getItem("DEBUG_RATLS_FETCH") === "1") return true
    if (typeof window !== "undefined" && window.DEBUG_RATLS_FETCH === true) return true
  } catch {
    // ignore
  }
  return false
}

function readBodyStream(ratlsResponse) {
  return new ReadableStream({
    async pull(controller) {
      try {
        const chunk = new Uint8Array(await ratlsResponse.readChunk())
        if (chunk.length === 0) {
          controller.close()
          await ratlsResponse.close()
          return
        }
        controller.enqueue(chunk)
      } catch (error) {
        await ratlsResponse.close()
        controller.error(error)
      }
    },
    async cancel() {
      await ratlsResponse.close()
    },
  })
}

export function createRatlsFetch(options) {
  const { proxyUrl, targetHost, serverName, defaultHeaders, onAttestation } = options
  if (!proxyUrl || !targetHost) {
    throw new Error("proxyUrl and targetHost are required for RA-TLS fetch")
  }
  ensurePrototypeGetter()
  const normalizedTarget = normalizeTarget(targetHost)
  const sni = serverName || normalizedTarget.split(":")[0]
  const base = new URL(`https://${normalizedTarget}`)
  const websocketUrl = buildProxyUrl(proxyUrl, normalizedTarget)
  const hostHeader = hostHeaderFor(normalizedTarget)

  let clientPromise

  async function getClient() {
    await ensureWasm()
    if (!clientPromise) {
      clientPromise = (async () => {
        const client = new RatlsClient(websocketUrl, sni, hostHeader)
        try {
          await client.handshake()
        } catch (error) {
          try {
            await client.close()
          } catch {}
          throw enhanceProxyError(error, websocketUrl)
        }
        return client
      })().catch((error) => {
        clientPromise = undefined
        throw error
      })
    }
    return clientPromise
  }

  const clientReady = getClient()

  return async function ratlsFetch(input, init = {}) {
    const client = await clientReady.catch(() => getClient())

    const request = new Request(input, init)
    const resolved = new URL(request.url, base)
    const headers = new Headers(defaultHeaders || undefined)
    request.headers.forEach((value, name) => headers.set(name, value))
    const headerEntries = Array.from(headers.entries()).map(([name, value]) => ({
      name,
      value,
    }))
    const body = request.body ? new Uint8Array(await request.arrayBuffer()) : undefined

    const path = `${resolved.pathname}${resolved.search}`
    if (debugEnabled()) {
      console.debug("[ratls-fetch] request", {
        url: resolved.toString(),
        method: request.method || "GET",
        target: normalizedTarget,
        sni,
        proxy: websocketUrl,
        headers: headerEntries,
      })
    }

    let ratlsResponse
    try {
      ratlsResponse = await client.httpRequest(request.method || "GET", path, headerEntries, body && body.length ? body : undefined)
    } catch (error) {
      throw enhanceProxyError(error, websocketUrl)
    }
    if (debugEnabled()) {
      console.debug("[ratls-fetch] response", {
        target: normalizedTarget,
        sni,
        status: ratlsResponse.status,
        statusText: ratlsResponse.statusText,
        headers: ratlsResponse.headers,
        attestation: ratlsResponse.attestation?.(),
      })
    }

    const attestation = ratlsResponse.attestation()
    if (attestation && typeof onAttestation === "function") {
      try {
        onAttestation(attestation)
      } catch (error) {
        if (debugEnabled()) {
          console.warn("[ratls-fetch] onAttestation callback failed", error)
        }
      }
    }
    const rawHeaders = ratlsResponse.headers || []
    const responseHeaders = new Headers()
    rawHeaders.forEach(({ name, value }) => responseHeaders.append(name, value))
    if (attestation) {
      try {
        responseHeaders.set(ATTESTATION_HEADER, JSON.stringify(attestation))
      } catch (error) {
        // ignore serialization errors; attestation still attached below
      }
    } else if (process?.env?.DEBUG_RATLS_FETCH) {
      console.warn("ratls-fetch: attestation missing from RA-TLS response")
    }

    const bodyStream = readBodyStream(ratlsResponse)
    const response = new Response(bodyStream, {
      status: ratlsResponse.status,
      statusText: ratlsResponse.statusText,
      headers: responseHeaders,
    })
    Object.defineProperty(response, "ratlsAttestation", {
      value: attestation,
      enumerable: false,
      configurable: false,
      writable: false,
    })
    return response
  }
}

export { RatlsClient } from "./ratls_wasm.js"
