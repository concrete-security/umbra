import { test, expect } from "@playwright/test"

const PROVIDER_ROUTE = "**/chat/completions"
const ATTESTATION_ROUTE = "**/tdx_quote"

const HERO_PROMPT = "Can you secure my documents?"
const FOLLOW_UP_PROMPT = "How is the data encrypted?"
const HERO_REPLY = "Secure session established."
const FOLLOW_UP_REPLY = "All data stays encrypted in transit and at rest."

test("landing page contact link, hero hand-off, and confidential chat flow", async ({ page }) => {
  let requestCount = 0
  let latestReportData: string | null = null
  let attestationRequests = 0

  await page.route(PROVIDER_ROUTE, async (route) => {
    const method = route.request().method()

    if (method === "OPTIONS") {
      await route.fulfill({
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Allow-Methods": "POST, OPTIONS",
        },
      })
      return
    }

    const payload = route.request().postDataJSON() as {
      messages?: Array<{ role: string; content: string }>
    }

    const latestMessage = payload?.messages?.at(-1)?.content ?? ""

    if (requestCount === 0) {
      expect(latestMessage).toContain(HERO_PROMPT)
    } else {
      expect(latestMessage).toContain(FOLLOW_UP_PROMPT)
    }

    const responseContent = requestCount === 0 ? HERO_REPLY : FOLLOW_UP_REPLY
    requestCount += 1

    const streamBody = [
      `data: {"choices":[{"delta":{"content":"${responseContent}"}}]}`,
      "",
      "data: [DONE]",
      "",
    ].join("\n")

    await route.fulfill({
      status: 200,
      headers: {
        "Content-Type": "text/event-stream",
        "Access-Control-Allow-Origin": "*",
      },
      body: streamBody,
    })
  })

  await page.route(ATTESTATION_ROUTE, async (route) => {
    attestationRequests += 1
    const payload = (route.request().postDataJSON() ?? {}) as { report_data?: string }
    latestReportData = typeof payload.report_data === "string" ? payload.report_data : null
    const reportData = latestReportData ?? "0x" + "ab".repeat(16)

    await route.fulfill({
      status: 200,
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        success: true,
        quote_type: "tdx.quote.v1",
        timestamp: new Date().toISOString(),
        test_mode: true,
        report_data: reportData,
        quote: {
          quote: "0x" + "11".repeat(64),
          report_data: reportData,
          event_log: JSON.stringify([
            { event: "system-preparing", digest: "0f".repeat(12) },
            { event: "app-id", digest: "1a".repeat(12) },
            { event: "system-ready", digest: "2b".repeat(12) },
          ]),
        },
      }),
    })
  })

  await page.addInitScript((providerBase) => {
    const key = "confidential-provider-settings-v1"
    const lockedValue = JSON.stringify({ baseUrl: providerBase })
    const originalSetItem = window.localStorage.setItem.bind(window.localStorage)
    window.localStorage.setItem(key, lockedValue)
    window.localStorage.setItem = (name, value) => {
      if (name === key) {
        return originalSetItem(name, lockedValue)
      }
      return originalSetItem(name, value)
    }
  }, "https://e2e-provider.test")

  await page.goto("/")

  const contactLink = page.locator('a[href="mailto:contact@concrete-security.com"]').first()
  await expect(contactLink).toBeVisible()
  await expect(contactLink).toHaveAttribute("href", "mailto:contact@concrete-security.com")

  const heroInput = page.locator("#hero-input")
  await expect(heroInput).toBeVisible()
  await heroInput.fill(HERO_PROMPT)
  await page.getByRole("button", { name: "Start secure session" }).click()

  await page.waitForURL("**/confidential-ai**", { timeout: 15_000 })
  await expect(page).toHaveURL(/\/confidential-ai(?:\?.*)?$/)
  const storedProvider = await page.evaluate(() => localStorage.getItem("confidential-provider-settings-v1"))
  console.log("[e2e] provider settings:", storedProvider)
  await expect
    .poll(() => attestationRequests, { timeout: 15_000 })
    .toBeGreaterThan(0)
  await expect(page.getByText("Attestation verified")).toBeVisible({ timeout: 15_000 })

  const transcript = page.getByRole("log", { name: "Confidential space transcript" })
  await expect(transcript).toContainText(HERO_PROMPT, { timeout: 15_000 })
  await expect(transcript).toContainText(HERO_REPLY, { timeout: 15_000 })

  const chatInput = page.locator("#secure-input")
  const sendButton = page.getByRole("button", { name: "Send secure message" })

  await chatInput.fill(FOLLOW_UP_PROMPT)
  await expect(sendButton).toBeEnabled({ timeout: 15_000 })
  await sendButton.click()

  await expect(transcript).toContainText(FOLLOW_UP_PROMPT, { timeout: 15_000 })
  await expect(transcript).toContainText(FOLLOW_UP_REPLY, { timeout: 15_000 })

  expect(requestCount).toBeGreaterThanOrEqual(2)
})
