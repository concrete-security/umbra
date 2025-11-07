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

const DEFAULT_VERIFIER_ENDPOINT = "https://cloud-api.phala.network/api/v1/attestations/verify"
const LOCAL_VERIFY_ENDPOINT = "/api/attestation/verify"
const publicVerifierEndpoint = optionalEnv(process.env.NEXT_PUBLIC_PHALA_TDX_VERIFIER_API)
const privateVerifierEndpoint = optionalEnv(process.env.PHALA_TDX_VERIFIER_API)
const serverVerifierEndpoint = privateVerifierEndpoint ?? publicVerifierEndpoint ?? DEFAULT_VERIFIER_ENDPOINT

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    cache: "no-store",
  })

  if (!response.ok) {
    const message = await response.text()
    throw new Error(message || `Verifier rejected the quote with status ${response.status}`)
  }

  return (await response.json()) as T
}

function isBrowserEnvironment() {
  return typeof window !== "undefined"
}

export async function verifyTdxQuote(quoteHex: string): Promise<IntelVerificationPayload> {
  if (!quoteHex || typeof quoteHex !== "string" || quoteHex.trim().length === 0) {
    throw new Error("quoteHex is required.")
  }

  if (isBrowserEnvironment()) {
    return postJson<IntelVerificationPayload>(LOCAL_VERIFY_ENDPOINT, { quoteHex })
  }

  return postJson<IntelVerificationPayload>(serverVerifierEndpoint, { hex: quoteHex })
}

export async function verifyTdxQuoteWithFallback(quoteHex: string): Promise<IntelVerificationPayload> {
  return verifyTdxQuote(quoteHex)
}
