import { test, expect, Page } from "@playwright/test"
import { writeFileSync } from "fs"
import { join } from "path"

import { compareReportData } from "@/lib/attestation-verifier"

const ATTESTATION_URL = "https://vllm.concrete-security.com/tdx_quote"
const PCCS_ENDPOINTS = [
  {
    label: "Phala PCCS",
    url: "https://pccs.phala.network/tdx/certification/v4",
  },
  // Intel PCCS temporarily disabled until the endpoint is reachable without custom credentials.
]

type VerificationPayload = {
  verifiedReport: {
    status?: string | null
    advisory_ids?: string[]
    [key: string]: unknown
  }
  quoteCollateral: unknown
  reportDataHex?: string | null
  metadata?: {
    pccsUrl?: string | null
    [key: string]: unknown
  }
  [key: string]: unknown
}

type VerificationRun = {
  label: string
  verificationResult: VerificationPayload
}

const EXPECTED_VERIFICATION_STATUS = "uptodate"

async function runBrowserVerification(
  page: Page,
  quoteHex: string,
  pccsUrl: string,
  label: string,
  expectedReportData: string,
): Promise<VerificationRun> {
  console.log(`\n2. Verifying quote via ${label}...`)
  const url = new URL("http://127.0.0.1:3000/test-verify-quote")
  url.searchParams.set("quoteHex", quoteHex)
  url.searchParams.set("pccsUrl", pccsUrl)
  url.searchParams.set("forceTestMode", "false")

  await page.goto(url.toString())
  await page.waitForFunction(
    () => (window as any).__verificationResult !== undefined || (window as any).__verificationError !== undefined,
    { timeout: 60_000 },
  )

  const hasError = await page.evaluate(() => (window as any).__verificationError !== undefined)

  if (hasError) {
    const error = await page.evaluate(() => (window as any).__verificationError)
    throw new Error(`${label} verification failed: ${error}`)
  }

  const verificationResult = await page.evaluate<VerificationPayload>(() => (window as any).__verificationResult)

  console.log(`   ✅ ${label} verification completed.`)
  console.log(`   Status: ${verificationResult.verifiedReport.status}`)
  console.log(`   PCCS URL: ${verificationResult.metadata?.pccsUrl ?? "unknown"}`)

  if (verificationResult.verifiedReport.advisory_ids?.length) {
    console.log(`   Advisories (${verificationResult.verifiedReport.advisory_ids.length}):`)
    verificationResult.verifiedReport.advisory_ids.forEach((advisory: string) => {
      console.log(`     - ${advisory}`)
    })
  }

  const reportDataMatch = compareReportData(expectedReportData, verificationResult.reportDataHex ?? null)
  expect(reportDataMatch).toBe(true)

  return { label, verificationResult }
}

test("fetch and verify TDX quote with DCAP", async ({ page }) => {
  console.log("1. Fetching quote from attestation endpoint...")

  const reportDataRaw = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
  const reportData = `0x${reportDataRaw}`

  const quoteResponse = await fetch(ATTESTATION_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ report_data: reportDataRaw }),
  })

  expect(quoteResponse.ok).toBe(true)
  const quoteData = await quoteResponse.json()
  expect(quoteData.success).toBe(true)
  expect(quoteData.quote?.quote).toBeDefined()

  const quoteHex = quoteData.quote.quote
  console.log(`   ✅ Quote fetched successfully (length: ${quoteHex.length})`)

  const verificationRuns: VerificationRun[] = []

  for (const endpoint of PCCS_ENDPOINTS) {
    const run = await runBrowserVerification(page, quoteHex, endpoint.url, endpoint.label, reportData)
    verificationRuns.push(run)
  }

  const statuses = verificationRuns.map(({ label, verificationResult }) => ({
    label,
    raw: verificationResult.verifiedReport.status,
    normalized: (verificationResult.verifiedReport.status ?? "").toLowerCase(),
    pccsUrl: verificationResult.metadata?.pccsUrl ?? null,
  }))

  statuses.forEach(({ label, normalized, raw, pccsUrl }) => {
    expect(normalized).toBe(EXPECTED_VERIFICATION_STATUS)
    console.log(`\n${label} status confirmed as: ${raw} (PCCS: ${pccsUrl ?? "unknown"})`)
  })

  // Ensure both verifications returned structured data
  verificationRuns.forEach(({ verificationResult }) => {
    expect(verificationResult.verifiedReport).toBeDefined()
    expect(verificationResult.verifiedReport.status).toBeDefined()
    expect(verificationResult.quoteCollateral).toBeDefined()
    expect(verificationResult.metadata?.pccsUrl?.toLowerCase()).toContain("pccs")
  })

  const outputPath = join(process.cwd(), "..", "dcap-verification-result.json")
  writeFileSync(outputPath, JSON.stringify(verificationRuns[0]?.verificationResult ?? {}, null, 2), "utf-8")
  console.log(`\n   💾 Intel verification saved to: ${outputPath}`)

  console.log("\n✅ Test completed successfully with matching PCCS results")
})
