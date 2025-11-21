import binding, { httpRequest as exportedHttpRequest } from "./index.js"

const ATTESTATION_HEADER = "x-ratls-attestation"
const streamRequest = binding.http_stream_request || binding.httpStreamRequest
const streamRead = binding.stream_read || binding.streamRead
const streamClose = binding.stream_close || binding.streamClose

export async function createRatlsFetch(options) {
  const { targetHost, serverName, defaultHeaders } = options
  if (!targetHost) throw new Error("targetHost is required")
  const sni = serverName || targetHost.replace(/:.*/, "")
  const httpRequest = exportedHttpRequest || binding.http_request || binding.httpRequest

  const resolveHttp = () => {
    if (typeof httpRequest !== "function") {
      throw new Error(
        `ratls-node binding did not export http_request/httpRequest (exports: ${Object.keys(
          binding
        )})`
      )
    }
    return httpRequest
  }

  return async function ratlsFetch(input, init = {}) {
    const req = new Request(input, init)
    const url = new URL(req.url, `https://${targetHost}`)

    const headers = new Headers(defaultHeaders || undefined)
    req.headers.forEach((value, name) => headers.set(name, value))
    const headerEntries = Array.from(headers.entries()).map(([name, value]) => ({
      name,
      value,
    }))

    const body =
      req.body === null ? undefined : Buffer.from(await req.arrayBuffer())

    const useStreaming =
      typeof streamRequest === "function" &&
      typeof streamRead === "function" &&
      typeof streamClose === "function"

    if (useStreaming) {
      const resp = await streamRequest(
        targetHost,
        sni,
        req.method || "GET",
        `${url.pathname}${url.search}`,
        headerEntries,
        body
      )

      const nodeHeaders = new Headers()
      resp.headers.forEach(({ name, value }) => nodeHeaders.append(name, value))
      nodeHeaders.set(ATTESTATION_HEADER, JSON.stringify(resp.attestation))

      const streamId = resp.stream_id || resp.streamId || 0
      let done = !streamId
      const bodyStream = new ReadableStream({
        async pull(controller) {
          if (done) {
            controller.close()
            return
          }
          const chunk = await streamRead(streamId, 4096)
          if (!chunk || chunk.length === 0) {
            done = true
            await streamClose(streamId).catch(() => undefined)
            controller.close()
            return
          }
          controller.enqueue(chunk)
        },
        async cancel() {
          if (streamId) {
            await streamClose(streamId).catch(() => undefined)
          }
        },
      })

      const response = new Response(bodyStream, {
        status: resp.status,
        statusText: resp.status_text || resp.statusText || "",
        headers: nodeHeaders,
      })
      Object.defineProperty(response, "ratlsAttestation", {
        value: resp.attestation,
        enumerable: false,
        configurable: false,
        writable: false,
      })
      return response
    }

    const resp = await resolveHttp()(
      targetHost,
      sni,
      req.method || "GET",
      `${url.pathname}${url.search}`,
      headerEntries,
      body
    )

    const nodeHeaders = new Headers()
    resp.headers.forEach(({ name, value }) => nodeHeaders.append(name, value))
    nodeHeaders.set(ATTESTATION_HEADER, JSON.stringify(resp.attestation))

    const bodyBuf = new Uint8Array(resp.body)
    const chunkSize = 2048
    let offset = 0
    const bodyStream = new ReadableStream({
      pull(controller) {
        if (offset >= bodyBuf.length) {
          controller.close()
          return
        }
        const end = Math.min(offset + chunkSize, bodyBuf.length)
        controller.enqueue(bodyBuf.slice(offset, end))
        offset = end
      },
    })

    const response = new Response(bodyStream, {
      status: resp.status,
      statusText: resp.status_text || resp.statusText || "",
      headers: nodeHeaders,
    })
    Object.defineProperty(response, "ratlsAttestation", {
      value: resp.attestation,
      enumerable: false,
      configurable: false,
      writable: false,
    })
    return response
  }
}
