import init, { httpRequest } from "./ratls_wasm.js"

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

function normalizeProxyUrl(raw) {
  if (!raw) return ""
  if (/^wss?:\/\//i.test(raw)) return raw
  return `ws://${raw.replace(/^\/+/, "")}`
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
  const { proxyUrl, targetHost, serverName, defaultHeaders } = options
  if (!proxyUrl || !targetHost) {
    throw new Error("proxyUrl and targetHost are required for RA-TLS fetch")
  }
  ensurePrototypeGetter()
  const normalizedTarget = normalizeTarget(targetHost)
  const sni = serverName || normalizedTarget.split(":")[0]
  const base = new URL(`https://${normalizedTarget}`)

  return async function ratlsFetch(input, init = {}) {
    await ensureWasm()

    const request = new Request(input, init)
    const resolved = new URL(request.url, base)
    const headers = new Headers(defaultHeaders || undefined)
    request.headers.forEach((value, name) => headers.set(name, value))
    const headerEntries = Array.from(headers.entries()).map(([name, value]) => ({
      name,
      value,
    }))
    const body = request.body ? new Uint8Array(await request.arrayBuffer()) : undefined

    const ratlsResponse = await httpRequest(
      buildProxyUrl(proxyUrl, normalizedTarget),
      sni,
      hostHeaderFor(normalizedTarget),
      request.method || "GET",
      `${resolved.pathname}${resolved.search}`,
      headerEntries,
      body && body.length ? body : undefined
    )

    const attestation = ratlsResponse.attestation()
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
