export type IntelVerificationPayload = {
  verified?: boolean
  message?: string
  reportdata?: string
  checksum?: string
  hash?: string
  quote?: {
    verified?: boolean
    checksum?: string
    body?: {
      reportdata?: string
      mrconfig?: string
    }
  }
}

function stripHexPrefix(value?: string | null): string | null {
  if (!value) return null
  const trimmed = value.trim()
  if (!trimmed) return null
  return trimmed.startsWith("0x") ? trimmed.slice(2).toLowerCase() : trimmed.toLowerCase()
}

export function normalizeHex(value?: string | null): string | null {
  const stripped = stripHexPrefix(value)
  return stripped ? `0x${stripped}` : null
}

export function compareReportData(expected: string | null, fromVerifier: string | null): boolean | null {
  const expectedBody = stripHexPrefix(expected)
  const verifierBody = stripHexPrefix(fromVerifier)

  if (!expectedBody || !verifierBody) {
    return null
  }

  if (verifierBody.length < expectedBody.length) {
    return false
  }

  return verifierBody.startsWith(expectedBody)
}

function optionalEnv(value?: string): string | null {
  if (!value) return null
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

const publicVerifierEndpoint = optionalEnv(process.env.NEXT_PUBLIC_PHALA_TDX_VERIFIER_API) ?? "https://cloud-api.phala.network/api/v1/attestations/verify"

export async function verifyTdxQuote(quoteHex: string): Promise<IntelVerificationPayload> {
  if (!quoteHex || typeof quoteHex !== "string" || quoteHex.trim().length === 0) {
    throw new Error("quoteHex is required.")
  }

  const response = await fetch(publicVerifierEndpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hex: quoteHex }),
    cache: "no-store",
  })

  if (!response.ok) {
    const message = await response.text()
    throw new Error(message || `Verifier rejected the quote with status ${response.status}`)
  }

  const payload = await response.json()
  return payload as IntelVerificationPayload
}

export async function verifyTdxQuoteWithFallback(quoteHex: string): Promise<IntelVerificationPayload> {
  return verifyTdxQuote(quoteHex)
}
