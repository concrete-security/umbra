const trustedOrigin = process.env.NEXT_PUBLIC_APP_URL?.trim() ?? null

function normalizeOrigin(candidate: string | null | undefined): string | null {
  if (!candidate) {
    return null
  }
  try {
    const url = new URL(candidate)
    url.hash = ""
    url.pathname = ""
    url.search = ""
    return `${url.protocol}//${url.host}`.toLowerCase()
  } catch {
    return null
  }
}

export class CrossOriginRequestError extends Error {
  constructor(message = "Cross-origin request blocked") {
    super(message)
    this.name = "CrossOriginRequestError"
  }
}

export class UnsupportedContentTypeError extends Error {
  constructor(message = "Unsupported content type") {
    super(message)
    this.name = "UnsupportedContentTypeError"
  }
}

export function ensureSameOrigin(request: Request) {
  const originHeader = request.headers.get("origin")
  if (!originHeader) {
    return
  }

  const normalizedOrigin = normalizeOrigin(originHeader)
  if (!normalizedOrigin) {
    throw new CrossOriginRequestError("Invalid origin header.")
  }

  const allowedOrigin = trustedOrigin ? normalizeOrigin(trustedOrigin) : null
  if (allowedOrigin) {
    if (normalizedOrigin !== allowedOrigin) {
      throw new CrossOriginRequestError()
    }
    return
  }

  const host = request.headers.get("host")
  if (!host) {
    throw new CrossOriginRequestError("Unable to verify request origin.")
  }
  const forwardedProto = request.headers.get("x-forwarded-proto")
  let protocol = forwardedProto?.trim().toLowerCase() ?? null
  if (!protocol) {
    try {
      const urlProtocol = new URL(request.url).protocol
      protocol = urlProtocol.endsWith(":") ? urlProtocol.slice(0, -1) : urlProtocol
    } catch {
      protocol = "https"
    }
  }
  const fallbackOrigin = `${protocol}://${host.toLowerCase()}`
  if (normalizedOrigin !== fallbackOrigin) {
    throw new CrossOriginRequestError()
  }
}

export function assertJsonRequest(request: Request) {
  const contentType = request.headers.get("content-type")?.toLowerCase() ?? ""
  if (!contentType.includes("application/json")) {
    throw new UnsupportedContentTypeError()
  }
}
