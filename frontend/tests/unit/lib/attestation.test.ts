import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { compareReportData } from "@/lib/attestation-verifier"

type MockResponse = {
  ok: boolean
  status: number
  text: () => Promise<string>
}

const mockFetch = vi.fn<[
  input: RequestInfo | URL,
  init?: RequestInit
], Promise<MockResponse>>()

async function importModule() {
  return import("@/lib/attestation")
}

beforeEach(() => {
  vi.resetModules()
  delete process.env.NEXT_PUBLIC_ATTESTATION_BASE_URL
  mockFetch.mockReset()
  vi.stubGlobal("fetch", mockFetch)
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("getAttestationServiceBaseUrl", () => {
  it("returns null when env is missing", async () => {
    const { getAttestationServiceBaseUrl } = await importModule()
    expect(getAttestationServiceBaseUrl()).toBeNull()
  })

  it("returns trimmed base url from env", async () => {
    process.env.NEXT_PUBLIC_ATTESTATION_BASE_URL = " https://attest.example.com "
    const { getAttestationServiceBaseUrl } = await importModule()
    expect(getAttestationServiceBaseUrl()).toBe("https://attest.example.com")
  })
})

describe("fetchTdxQuote", () => {
  it("posts to /tdx_quote and returns the parsed payload", async () => {
    const { fetchTdxQuote } = await importModule()
    const payload = {
      success: true as const,
      quote_type: "tdx",
      timestamp: "1733270400",
      quote: { measurement: "abc" },
    }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve(JSON.stringify(payload)),
    })

    const result = await fetchTdxQuote("https://attest.example.com/", "deadbeef")

    expect(result).toEqual(payload)
    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [url, init] = mockFetch.mock.calls[0]
    expect(url).toBe("https://attest.example.com/tdx_quote")
    expect(init?.method).toBe("POST")
    expect(init?.headers).toMatchObject({ "Content-Type": "application/json" })
    expect(init?.cache).toBe("no-store")
    expect(init?.body).toBeDefined()
    const parsedBody = JSON.parse(String(init?.body))
    expect(parsedBody).toEqual({ report_data: "deadbeef" })
  })

  it("throws an error when the response is not ok and exposes provider error", async () => {
    const { fetchTdxQuote } = await importModule()

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      text: () => Promise.resolve(JSON.stringify({ error: "unreachable" })),
    })

    await expect(fetchTdxQuote("https://attest.example.com", "ff"))
      .rejects.toThrow("unreachable")
  })

  it("throws an error when the payload reports failure", async () => {
    const { fetchTdxQuote } = await importModule()

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve(JSON.stringify({ success: false, error: "hardware missing" })),
    })

    await expect(fetchTdxQuote("https://attest.example.com", "ff"))
      .rejects.toThrow("hardware missing")
  })

  it("uses a custom fetch implementation when supplied", async () => {
    const { fetchTdxQuote } = await importModule()
    const payload = {
      success: true as const,
      quote_type: "tdx",
      timestamp: "1733270400",
    }
    const customFetch = vi.fn<[
      RequestInfo | URL,
      RequestInit | undefined
    ], Promise<MockResponse>>().mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve(JSON.stringify(payload)),
    })

    const result = await fetchTdxQuote("https://cvm.example.com", "bead", { fetchImpl: customFetch })
    expect(result).toEqual(payload)
    expect(customFetch).toHaveBeenCalledWith("https://cvm.example.com/tdx_quote", expect.any(Object))
  })
})

describe("compareReportData", () => {
  it("returns true for different casing and prefixes", () => {
    expect(compareReportData("deadbeef", "0xDEADBEEF")).toBe(true)
  })

  it("returns false when values differ", () => {
    expect(compareReportData("deadbeef", "cafebabe")).toBe(false)
  })

  it("returns null when one side missing", () => {
    expect(compareReportData(null, "0x01")).toBeNull()
  })

  it("treats verifier padding as acceptable", () => {
    expect(compareReportData("deadbeef", "0xDEADBEEF000000000000")).toBe(true)
  })

  it("matches verifier-style padded report data", () => {
    const localNonce = "6465616462656566"
    const verifierReportData =
      "0x64656164626565660000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    expect(compareReportData(localNonce, verifierReportData)).toBe(true)
  })

  it("fails when verifier data is shorter", () => {
    expect(compareReportData("deadbeef", "0xdead")).toBe(false)
  })

  it("accepts verifier data encoded as ASCII", () => {
    const nonce = "c348f494033ae00ff8d47bbdb1741626"
    const asciiEncoded = Buffer.from(nonce, "utf8").toString("hex")
    expect(compareReportData(nonce, `0x${asciiEncoded}0000`)).toBe(true)
  })
})

describe("fetchTdxQuoteWithFallback", () => {
  it("always uses client-side calls", async () => {
    const { fetchTdxQuoteWithFallback } = await importModule()
    const payload = {
      success: true as const,
      quote_type: "tdx",
      timestamp: "1733270400",
    }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve(JSON.stringify(payload)),
    })

    const result = await fetchTdxQuoteWithFallback("https://attest.example.com", "deadbeef")

    expect(result).toEqual(payload)
    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [url] = mockFetch.mock.calls[0]
    expect(url).toBe("https://attest.example.com/tdx_quote")
  })
})
