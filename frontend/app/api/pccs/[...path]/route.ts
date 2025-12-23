import { NextRequest, NextResponse } from "next/server"

const DEFAULT_UPSTREAM = "https://api.trustedservices.intel.com/tdx/certification/v4/"

function normalizeBase(value?: string | null) {
  if (!value) return DEFAULT_UPSTREAM
  const trimmed = value.trim()
  if (!trimmed) return DEFAULT_UPSTREAM
  return trimmed.endsWith("/") ? trimmed : `${trimmed}/`
}

function buildUpstreamUrl(base: string, path: string, search: string) {
  const url = new URL(path, base)
  url.search = search
  return url
}

function copyHeader(from: Headers, to: Headers, key: string) {
  const value = from.get(key)
  if (value) {
    to.set(key, value)
  }
}

export async function GET(request: NextRequest, context: { params: Promise<{ path?: string[] }> }) {
  const { path: pathSegments = [] } = await context.params
  const targetPath = pathSegments.join("/")
  if (!targetPath) {
    return NextResponse.json({ error: "Missing PCCS path" }, { status: 400 })
  }

  const upstreamBase = normalizeBase(process.env.PCCS_UPSTREAM_URL ?? null)
  const upstreamUrl = buildUpstreamUrl(upstreamBase, targetPath, request.nextUrl.search)

  const upstreamHeaders = new Headers()
  const subscriptionKey = process.env.PCCS_SUBSCRIPTION_KEY
  if (subscriptionKey && subscriptionKey.trim().length > 0) {
    upstreamHeaders.set("Ocp-Apim-Subscription-Key", subscriptionKey.trim())
  }

  let upstreamResponse: Response
  try {
    upstreamResponse = await fetch(upstreamUrl.toString(), {
      method: "GET",
      headers: upstreamHeaders,
      cache: "no-store",
    })
  } catch (error) {
    console.error("[PCCS proxy] Network error", { targetPath, upstreamUrl: upstreamUrl.toString(), error })
    return NextResponse.json(
      { error: "Unable to reach PCCS upstream", upstreamUrl: upstreamUrl.toString() },
      { status: 502 },
    )
  }

  if (!upstreamResponse.ok) {
    const text = await upstreamResponse.text().catch(() => "")
    console.error("[PCCS proxy] Upstream error", {
      targetPath,
      upstreamUrl: upstreamUrl.toString(),
      status: upstreamResponse.status,
      bodyPreview: text.slice(0, 2048),
    })
    return NextResponse.json(
      {
        error: "PCCS upstream responded with an error",
        upstreamUrl: upstreamUrl.toString(),
        status: upstreamResponse.status,
        body: text.slice(0, 2048),
      },
      { status: upstreamResponse.status },
    )
  }

  const payload = await upstreamResponse.arrayBuffer()

  const responseHeaders = new Headers()
  ;["content-type", "cache-control", "pragma", "expires", "last-modified", "etag", "content-length"].forEach((key) =>
    copyHeader(upstreamResponse.headers, responseHeaders, key)
  )

  return new NextResponse(payload, {
    status: upstreamResponse.status,
    headers: responseHeaders,
  })
}


