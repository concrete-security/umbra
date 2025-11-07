import { NextResponse } from "next/server"

import { verifyTdxQuote } from "@/lib/attestation-verifier"

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

    const payload = await verifyTdxQuote(quoteHex)
    return NextResponse.json(payload)
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unable to verify quote."
    return NextResponse.json({ error: message }, { status: 400 })
  }
}
