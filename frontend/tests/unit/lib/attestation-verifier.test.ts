import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

type MockResponse = {
  ok: boolean
  status: number
  text: () => Promise<string>
  json: () => Promise<unknown>
}

const mockFetch = vi.fn<[
  input: RequestInfo | URL,
  init?: RequestInit
], Promise<MockResponse>>()

async function importModule() {
  return import("@/lib/attestation-verifier")
}

function simulateBrowserEnv() {
  ;(globalThis as unknown as { window?: Record<string, unknown> }).window = {}
}

function resetBrowserEnv() {
  delete (globalThis as { window?: unknown }).window
}

beforeEach(() => {
  vi.resetModules()
  delete process.env.NEXT_PUBLIC_PHALA_TDX_VERIFIER_API
  delete process.env.PHALA_TDX_VERIFIER_API
  mockFetch.mockReset()
  vi.stubGlobal("fetch", mockFetch)
  resetBrowserEnv()
})

afterEach(() => {
  resetBrowserEnv()
  vi.unstubAllGlobals()
})

describe("verifyTdxQuote", () => {
  it("calls the default verifier endpoint on the server", async () => {
    const { verifyTdxQuote } = await importModule()
    const payload = {
      verified: true,
      quote: {
        verified: true,
        body: {
          reportdata: "0xdeadbeef",
        },
      },
    }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve(""),
      json: () => Promise.resolve(payload),
    })

    const result = await verifyTdxQuote("0xdeadbeef")

    expect(result).toEqual(payload)
    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [url, init] = mockFetch.mock.calls[0]
    expect(url).toBe("https://cloud-api.phala.network/api/v1/attestations/verify")
    expect(init?.method).toBe("POST")
    expect(init?.headers).toMatchObject({ "Content-Type": "application/json" })
    expect(init?.cache).toBe("no-store")
    const parsedBody = JSON.parse(String(init?.body))
    expect(parsedBody).toEqual({ hex: "0xdeadbeef" })
  })

  it("uses a custom server verifier endpoint from env", async () => {
    process.env.NEXT_PUBLIC_PHALA_TDX_VERIFIER_API = "https://custom-verifier.example.com/verify"
    const { verifyTdxQuote } = await importModule()
    const payload = { verified: true }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve(""),
      json: () => Promise.resolve(payload),
    })

    await verifyTdxQuote("0xabc123")

    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [url] = mockFetch.mock.calls[0]
    expect(url).toBe("https://custom-verifier.example.com/verify")
  })

  it("prefers PHALA_TDX_VERIFIER_API when provided", async () => {
    process.env.NEXT_PUBLIC_PHALA_TDX_VERIFIER_API = "https://ignored.example.com/verify"
    process.env.PHALA_TDX_VERIFIER_API = "https://private.example.com/verify"
    const { verifyTdxQuote } = await importModule()

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve(""),
      json: () => Promise.resolve({ verified: true }),
    })

    await verifyTdxQuote("0xabc123")

    const [url] = mockFetch.mock.calls[0]
    expect(url).toBe("https://private.example.com/verify")
  })

  it("routes through the internal API when window is present", async () => {
    simulateBrowserEnv()
    const { verifyTdxQuote } = await importModule()
    const payload = { verified: true }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve(""),
      json: () => Promise.resolve(payload),
    })

    const result = await verifyTdxQuote("0xfeed")

    expect(result).toEqual(payload)
    const [url, init] = mockFetch.mock.calls[0]
    expect(url).toBe("/api/attestation/verify")
    expect(JSON.parse(String(init?.body))).toEqual({ quoteHex: "0xfeed" })
  })

  it("throws an error when the response is not ok", async () => {
    const { verifyTdxQuote } = await importModule()

    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      text: () => Promise.resolve("Invalid quote"),
      json: () => Promise.resolve({}),
    })

    await expect(verifyTdxQuote("0xbad")).rejects.toThrow("Invalid quote")
  })

  it("throws an error when quoteHex is missing", async () => {
    const { verifyTdxQuote } = await importModule()

    await expect(verifyTdxQuote("")).rejects.toThrow("quoteHex is required")
  })
})

describe("verifyTdxQuoteWithFallback", () => {
  it("delegates to verifyTdxQuote", async () => {
    simulateBrowserEnv()
    const { verifyTdxQuoteWithFallback } = await importModule()
    const payload = { verified: true }

    mockFetch.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: () => Promise.resolve(""),
      json: () => Promise.resolve(payload),
    })

    const result = await verifyTdxQuoteWithFallback("0xdeadbeef")

    expect(result).toEqual(payload)
    expect(mockFetch).toHaveBeenCalledTimes(1)
    const [url] = mockFetch.mock.calls[0]
    expect(url).toBe("/api/attestation/verify")
  })
})
