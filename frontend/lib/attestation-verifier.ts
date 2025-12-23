type ByteSource =
  | Uint8Array
  | ArrayBuffer
  | SharedArrayBuffer
  | ArrayBufferView
  | number[]
  | string
  | null
  | undefined

type DcapModule = typeof import("@phala/dcap-qvl-web")

export type VerifyTdxQuoteOptions = {
  pccsUrl?: string | null
  forceTestMode?: boolean
}

export type QuoteCollateralV3Payload = {
  pck_crl_issuer_chain?: string
  root_ca_crl?: ByteSource
  pck_crl?: ByteSource
  tcb_info_issuer_chain?: string
  tcb_info?: string
  tcb_info_signature?: ByteSource
  qe_identity_issuer_chain?: string
  qe_identity?: string
  qe_identity_signature?: ByteSource
}

export type VerifiedReportPayload = {
  status?: string | null
  advisory_ids?: string[]
  report?: Record<string, unknown> | null
  ppid?: ByteSource
}

export type QuoteVerificationMetadata = {
  generatedAt?: number
  testMode?: boolean
  pccsUrl?: string | null
}

export type DcapVerificationResult = {
  verifiedReport: VerifiedReportPayload
  quoteCollateral: QuoteCollateralV3Payload | null
  reportDataHex: string | null
  metadata?: QuoteVerificationMetadata
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

  if (verifierBody.startsWith(expectedBody)) {
    return true
  }

  const asciiEncodedExpected = Array.from(expectedBody)
    .map((char) => char.charCodeAt(0).toString(16).padStart(2, "0"))
    .join("")

  return verifierBody.startsWith(asciiEncodedExpected)
}

function optionalEnv(value?: string | null): string | null {
  if (!value) return null
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

function isAttestationTestModeEnabled() {
  const browserFlag = optionalEnv(process.env.NEXT_PUBLIC_ATTESTATION_TEST_MODE)
  return browserFlag === "true"
}

const DEFAULT_TDX_PCCS_URL = "https://api.trustedservices.intel.com/tdx/certification/v4/"

function getConfiguredPccsUrl(override?: string | null) {
  const explicitOverride = optionalEnv(override)
  if (explicitOverride) {
    return explicitOverride
  }
  const publicUrl = optionalEnv(process.env.NEXT_PUBLIC_PCCS_URL)
  return publicUrl ?? DEFAULT_TDX_PCCS_URL
}

let bindingsPromise: Promise<DcapModule> | null = null

async function loadBindings(): Promise<DcapModule> {
  if (!bindingsPromise) {
    bindingsPromise = (async () => {
      const bindings = (await import("@phala/dcap-qvl-web")) as DcapModule
      if (typeof bindings.default === "function") {
        await bindings.default()
      }
      return bindings
    })()
  }
  return bindingsPromise
}

function getUnixTimeSeconds(): bigint {
  return BigInt(Math.floor(Date.now() / 1000))
}

function hexStringToBytes(hexValue: string): Uint8Array {
  const stripped = stripHexPrefix(hexValue)
  if (!stripped) {
    throw new Error("quoteHex is required.")
  }
  if (stripped.length % 2 !== 0) {
    throw new Error("quoteHex must contain an even number of hex characters.")
  }
  const bytes = new Uint8Array(stripped.length / 2)
  for (let index = 0; index < stripped.length; index += 2) {
    const segment = stripped.slice(index, index + 2)
    const parsed = Number.parseInt(segment, 16)
    if (Number.isNaN(parsed)) {
      throw new Error("quoteHex contains invalid characters.")
    }
    bytes[index / 2] = parsed
  }
  return bytes
}

function bytesToHex(bytes: ArrayLike<number>): string {
  const parts: string[] = []
  for (let index = 0; index < bytes.length; index += 1) {
    parts.push(bytes[index]!.toString(16).padStart(2, "0"))
  }
  return `0x${parts.join("")}`
}

function decodeBase64(value: string): Uint8Array {
  if (typeof Buffer !== "undefined") {
    return Uint8Array.from(Buffer.from(value, "base64"))
  }
  if (typeof atob === "function") {
    const binary = atob(value)
    const bytes = new Uint8Array(binary.length)
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index)
    }
    return bytes
  }
  throw new Error("Base64 decoding is not supported in this environment.")
}

function decodeStringToBytes(value: string): Uint8Array | null {
  const normalized = normalizeHex(value)
  if (normalized) {
    return hexStringToBytes(normalized)
  }
  try {
    return decodeBase64(value)
  } catch {
    return null
  }
}

function byteSourceToUint8Array(source: ByteSource): Uint8Array | null {
  if (source == null) {
    return null
  }
  if (source instanceof Uint8Array) {
    return source
  }
  if (ArrayBuffer.isView(source)) {
    const view = source as ArrayBufferView
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
  }
  const hasSharedArrayBuffer = typeof SharedArrayBuffer !== "undefined"
  if (source instanceof ArrayBuffer || (hasSharedArrayBuffer && source instanceof SharedArrayBuffer)) {
    return new Uint8Array(source as ArrayBufferLike)
  }
  if (Array.isArray(source)) {
    if (source.every((value) => typeof value === "number" && Number.isFinite(value))) {
      return new Uint8Array(source as number[])
    }
    return null
  }
  if (typeof source === "string") {
    return decodeStringToBytes(source)
  }
  return null
}

function extractReportDataHex(report: unknown): string | null {
  if (!report || typeof report !== "object") {
    return null
  }

  const extractFromObject = (value: unknown): string | null => {
    const bytes = byteSourceToUint8Array(value as ByteSource)
    return bytes ? bytesToHex(bytes) : null
  }

  const typed = report as Record<string, unknown>

  if (typed.TD10 && typeof typed.TD10 === "object") {
    const candidate = typed.TD10 as Record<string, unknown>
    const hex = extractFromObject(candidate.report_data)
    if (hex) return hex
  }

  if (typed.TD15 && typeof typed.TD15 === "object") {
    const td15 = typed.TD15 as Record<string, unknown>
    if (td15.base && typeof td15.base === "object") {
      const baseHex = extractFromObject((td15.base as Record<string, unknown>).report_data)
      if (baseHex) return baseHex
    }
    const directHex = extractFromObject(td15.report_data)
    if (directHex) return directHex
  }

  if (typed.SgxEnclave && typeof typed.SgxEnclave === "object") {
    const sgx = typed.SgxEnclave as Record<string, unknown>
    const hex = extractFromObject(sgx.report_data)
    if (hex) return hex
  }

  if ("report_data" in typed) {
    return extractFromObject(typed.report_data)
  }

  return null
}

function describeError(error: unknown): string {
  if (!error) return "Unknown verification error."
  if (typeof error === "string" && error.trim().length > 0) {
    return error.trim()
  }
  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message.trim()
  }
  if (typeof error === "object") {
    const message = (error as Record<string, unknown>).message
    if (typeof message === "string" && message.trim().length > 0) {
      return message.trim()
    }
  }
  return "Unknown verification error."
}

function createTestResult(pccsUrl: string): DcapVerificationResult {
  return {
    verifiedReport: {
      status: "TEST_MODE",
      advisory_ids: [],
      report: null,
    },
    quoteCollateral: null,
    reportDataHex: null,
    metadata: { testMode: true, generatedAt: Date.now(), pccsUrl },
  }
}

async function verifyTdxQuoteLocally(
  quoteHex: string,
  options: VerifyTdxQuoteOptions = {},
): Promise<DcapVerificationResult> {
  const normalizedQuote = normalizeHex(quoteHex)
  if (!normalizedQuote) {
    throw new Error("quoteHex is required.")
  }

  const pccsUrl = getConfiguredPccsUrl(options.pccsUrl)
  const testModeEnabled = options.forceTestMode ?? isAttestationTestModeEnabled()

  if (testModeEnabled) {
    return createTestResult(pccsUrl)
  }

  const rawQuote = hexStringToBytes(normalizedQuote)
  const bindings = await loadBindings()

  if (typeof bindings.js_get_collateral !== "function" || typeof bindings.js_verify !== "function") {
    throw new Error("DCAP verifier bindings are unavailable.")
  }

  let collateral: QuoteCollateralV3Payload
  try {
    collateral = await bindings.js_get_collateral(pccsUrl, rawQuote)
  } catch (error) {
    throw new Error(`Failed to download quote collateral: ${describeError(error)}`)
  }

  if (!collateral) {
    throw new Error("Quote collateral is empty.")
  }

  let verifiedReport: VerifiedReportPayload
  try {
    verifiedReport = bindings.js_verify(rawQuote, collateral, getUnixTimeSeconds())
  } catch (error) {
    throw new Error(`Quote verification failed: ${describeError(error)}`)
  }

  const reportDataHex = extractReportDataHex(verifiedReport?.report ?? null)

  return {
    verifiedReport,
    quoteCollateral: collateral,
    reportDataHex,
    metadata: { generatedAt: Date.now(), pccsUrl },
  }
}

export async function verifyTdxQuote(
  quoteHex: string,
  options?: VerifyTdxQuoteOptions,
): Promise<DcapVerificationResult> {
  return verifyTdxQuoteLocally(quoteHex, options)
}

export async function verifyTdxQuoteWithFallback(
  quoteHex: string,
  options?: VerifyTdxQuoteOptions,
): Promise<DcapVerificationResult> {
  return verifyTdxQuote(quoteHex, options)
}
