export type TdxQuoteSuccessResponse = {
  success: true
  quote_type: string
  timestamp: string
  quote?: unknown
  test_mode?: boolean
}

export type TdxQuoteFailureResponse = {
  success: false
  quote_type?: string
  error?: string
}

export type TdxQuoteResponse = TdxQuoteSuccessResponse | TdxQuoteFailureResponse

type FetchTdxQuoteOptions = {
  signal?: AbortSignal
  fetchImpl?: typeof fetch
}

function optionalEnv(value?: string): string | null {
  if (!value) return null
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "")
}

function safeParseJson(raw: string): unknown {
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}

function extractErrorMessage(payload: unknown): string | null {
  if (!payload || typeof payload !== "object") {
    return null
  }

  const typed = payload as Record<string, unknown>

  if (typeof typed.error === "string" && typed.error.trim().length > 0) {
    return typed.error.trim()
  }

  const detail = typed.detail
  if (typeof detail === "string" && detail.trim().length > 0) {
    return detail.trim()
  }

  if (detail && typeof detail === "object") {
    const detailRecord = detail as Record<string, unknown>
    if (typeof detailRecord.error === "string" && detailRecord.error.trim().length > 0) {
      return detailRecord.error.trim()
    }
    if (typeof detailRecord.message === "string" && detailRecord.message.trim().length > 0) {
      return detailRecord.message.trim()
    }
  }

  if (typeof typed.message === "string" && typed.message.trim().length > 0) {
    return typed.message.trim()
  }

  return null
}

export function isTdxQuoteSuccess(payload: unknown): payload is TdxQuoteSuccessResponse {
  if (!payload || typeof payload !== "object") {
    return false
  }
  const typed = payload as Record<string, unknown>
  if (typed.success !== true) {
    return false
  }
  return typeof typed.quote_type === "string" && typeof typed.timestamp === "string"
}

const publicAttestationBaseUrl = optionalEnv(process.env.NEXT_PUBLIC_ATTESTATION_BASE_URL)

export function getAttestationServiceBaseUrl() {
  return publicAttestationBaseUrl
}

export async function fetchTdxQuote(
  baseUrl: string,
  reportData: string,
  options: FetchTdxQuoteOptions = {}
): Promise<TdxQuoteSuccessResponse> {
  if (!baseUrl) {
    throw new Error("Attestation service base URL is not configured.")
  }

  const endpoint = `${trimTrailingSlash(baseUrl)}/tdx_quote`

  const fetchFn = options.fetchImpl ?? fetch

  const response = await fetchFn(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ report_data: reportData }),
    cache: "no-store",
    signal: options.signal,
  })

  const rawBody = await response.text()
  const parsed = rawBody ? safeParseJson(rawBody) : null

  if (!response.ok) {
    const message = extractErrorMessage(parsed) ?? `Attestation service request failed with status ${response.status}`
    throw new Error(message)
  }

  if (!isTdxQuoteSuccess(parsed)) {
    if (parsed && typeof parsed === "object") {
      const failure = parsed as TdxQuoteFailureResponse
      if (failure.success === false) {
        throw new Error(failure.error ?? "Attestation service reported failure.")
      }
    }
    throw new Error("Attestation service returned an unexpected payload.")
  }

  return parsed
}

export async function fetchTdxQuoteWithFallback(
  baseUrl: string,
  reportData: string,
  options: FetchTdxQuoteOptions = {}
): Promise<TdxQuoteSuccessResponse> {
  return fetchTdxQuote(baseUrl, reportData, options)
}
