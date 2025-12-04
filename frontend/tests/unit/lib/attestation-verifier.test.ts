import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

const initMock = vi.fn(() => Promise.resolve())
const getCollateralMock = vi.fn()
const verifyMock = vi.fn()

vi.mock("@phala/dcap-qvl-web", () => ({
  __esModule: true,
  default: initMock,
  js_get_collateral: getCollateralMock,
  js_verify: verifyMock,
}))

async function importModule() {
  return import("@/lib/attestation-verifier")
}

const baseCollateral = {
  tcb_info: "{}",
  pck_crl_issuer_chain: "",
  qe_identity: "",
}

function resetBrowserEnv() {
  delete (globalThis as { window?: unknown }).window
}

beforeEach(() => {
  vi.resetModules()
  initMock.mockClear()
  getCollateralMock.mockReset()
  verifyMock.mockReset()
  getCollateralMock.mockResolvedValue(baseCollateral)
  verifyMock.mockReturnValue({
    status: "UpToDate",
    advisory_ids: [],
    report: {
      TD10: {
        report_data: new Uint8Array([0xde, 0xad]),
      },
    },
  })
  delete process.env.NEXT_PUBLIC_PCCS_URL
  delete process.env.NEXT_PUBLIC_ATTESTATION_TEST_MODE
  resetBrowserEnv()
})

afterEach(() => {
  vi.unstubAllGlobals()
  resetBrowserEnv()
})

describe("verifyTdxQuote", () => {
  it("invokes the DCAP bindings with normalized quote bytes", async () => {
    const { verifyTdxQuote } = await importModule()

    const result = await verifyTdxQuote("0xdeadbeef")

    expect(initMock).toHaveBeenCalledTimes(1)
    expect(getCollateralMock).toHaveBeenCalledTimes(1)
    const [, collateralBytes] = getCollateralMock.mock.calls[0]!
    expect(Array.from(collateralBytes as Uint8Array)).toEqual([0xde, 0xad, 0xbe, 0xef])

    expect(verifyMock).toHaveBeenCalledTimes(1)
    const [, , timestamp] = verifyMock.mock.calls[0]!
    expect(typeof timestamp).toBe("bigint")

    expect(result.verifiedReport.status).toBe("UpToDate")
    expect(result.reportDataHex).toBe("0xdead")
    expect(result.quoteCollateral).toEqual(baseCollateral)
    expect(result.metadata?.pccsUrl).toBe("https://api.trustedservices.intel.com/tdx/certification/v4/")
  })

  it("throws when quoteHex is missing", async () => {
    const { verifyTdxQuote } = await importModule()
    await expect(verifyTdxQuote("")).rejects.toThrow("quoteHex is required")
    expect(getCollateralMock).not.toHaveBeenCalled()
  })

  it("surfaces collateral download errors", async () => {
    getCollateralMock.mockRejectedValueOnce(new Error("missing pccs"))
    const { verifyTdxQuote } = await importModule()
    await expect(verifyTdxQuote("0xdead")).rejects.toThrow("Failed to download quote collateral: missing pccs")
  })

  it("surfaces verification errors", async () => {
    verifyMock.mockImplementationOnce(() => {
      throw new Error("revoked")
    })
    const { verifyTdxQuote } = await importModule()
    await expect(verifyTdxQuote("0xdeadbeef")).rejects.toThrow("Quote verification failed: revoked")
  })

  it("extracts TD15 base report data", async () => {
    verifyMock.mockReturnValueOnce({
      status: "UpToDate",
      advisory_ids: [],
      report: {
        TD15: {
          base: {
            report_data: new Uint8Array([0xaa, 0xbb, 0xcc]),
          },
        },
      },
    })

    const { verifyTdxQuote } = await importModule()
    const result = await verifyTdxQuote("0x01")

    expect(result.reportDataHex).toBe("0xaabbcc")
  })

  it("passes NEXT_PUBLIC_PCCS_URL overrides to the wasm binding", async () => {
    process.env.NEXT_PUBLIC_PCCS_URL = "https://public-pccs.example.com/tdx"
    const { verifyTdxQuote } = await importModule()

    await verifyTdxQuote("0x1234")

    expect(getCollateralMock).toHaveBeenCalledWith("https://public-pccs.example.com/tdx", expect.any(Uint8Array))
  })

  it("prefers explicit PCCS overrides over env configuration", async () => {
    process.env.NEXT_PUBLIC_PCCS_URL = "https://public-pccs.example.com/tdx"
    const { verifyTdxQuote } = await importModule()

    const result = await verifyTdxQuote("0x1234", { pccsUrl: "https://override.example.com/tdx" })

    expect(getCollateralMock).toHaveBeenCalledWith("https://override.example.com/tdx", expect.any(Uint8Array))
    expect(result.metadata?.pccsUrl).toBe("https://override.example.com/tdx")
  })

  it("short-circuits when attestation test mode flag is set", async () => {
    process.env.NEXT_PUBLIC_ATTESTATION_TEST_MODE = "true"
    const { verifyTdxQuote } = await importModule()

    const result = await verifyTdxQuote("0x1234", { pccsUrl: "https://override.example.com/tdx" })

    expect(getCollateralMock).not.toHaveBeenCalled()
    expect(result.metadata?.testMode).toBe(true)
    expect(result.verifiedReport.status).toBe("TEST_MODE")
    expect(result.metadata?.pccsUrl).toBe("https://override.example.com/tdx")
  })

  it("respects forceTestMode override even when env flag is false", async () => {
    const { verifyTdxQuote } = await importModule()

    const result = await verifyTdxQuote("0x1234", { forceTestMode: true })

    expect(getCollateralMock).not.toHaveBeenCalled()
    expect(result.metadata?.testMode).toBe(true)
    expect(result.verifiedReport.status).toBe("TEST_MODE")
  })
})

describe("verifyTdxQuoteWithFallback", () => {
  it("delegates to verifyTdxQuote", async () => {
    const { verifyTdxQuoteWithFallback } = await importModule()

    await verifyTdxQuoteWithFallback("0xfeed")

    expect(getCollateralMock).toHaveBeenCalledTimes(1)
    expect(verifyMock).toHaveBeenCalledTimes(1)
  })

  it("passes through PCCS overrides", async () => {
    const { verifyTdxQuoteWithFallback } = await importModule()

    await verifyTdxQuoteWithFallback("0xfeed", { pccsUrl: "https://local-pccs/tdx" })

    expect(getCollateralMock).toHaveBeenCalledWith("https://local-pccs/tdx", expect.any(Uint8Array))
  })
})
