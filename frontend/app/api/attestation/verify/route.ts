import { NextResponse } from "next/server"

const DEFAULT_VERIFIER_ENDPOINT = "https://cloud-api.phala.network/api/v1/attestations/verify"
const publicVerifierEndpoint = process.env.NEXT_PUBLIC_PHALA_TDX_VERIFIER_API?.trim()
const privateVerifierEndpoint = process.env.PHALA_TDX_VERIFIER_API?.trim()
const verifierEndpoint = privateVerifierEndpoint ?? publicVerifierEndpoint ?? DEFAULT_VERIFIER_ENDPOINT

type VerifyRequestBody = {
  quoteHex?: unknown
  hex?: unknown
}

export async function POST(request: Request) {
  try {
    const body = (await request.json().catch(() => null)) as VerifyRequestBody | null
    const raw = body?.quoteHex ?? body?.hex
    const quoteHex = typeof raw === "string" ? raw : null

    if (!quoteHex) {
      return NextResponse.json({ error: "quoteHex is required." }, { status: 400 })
    }

    const response = await fetch(verifierEndpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hex: quoteHex }),
      cache: "no-store",
    })

    if (!response.ok) {
      const message = await response.text()
      return NextResponse.json(
        { error: message || `Verifier rejected the quote with status ${response.status}` },
        { status: response.status }
      )
    }

    const payload = await response.json()
    return NextResponse.json(payload)
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unable to verify quote."
    return NextResponse.json({ error: message }, { status: 400 })
  }
}

