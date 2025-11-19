import { defineConfig, devices } from "@playwright/test"

export default defineConfig({
  testDir: "tests/e2e",
  fullyParallel: true,
  timeout: 60_000,
  expect: {
    timeout: 5_000,
  },
  retries: process.env.CI ? 2 : 0,
  reporter: [["list"]],
  use: {
    baseURL: "http://127.0.0.1:3000",
    trace: "on-first-retry",
    navigationTimeout: 15_000,
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: {
    command: "pnpm dev --hostname 127.0.0.1 --port 3000",
    url: "http://127.0.0.1:3000",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      NEXT_PUBLIC_VLLM_BASE_URL: "http://127.0.0.1:4000",
      NEXT_PUBLIC_VLLM_MODEL: "test-model",
      FORM_TOKEN_SECRET: process.env.FORM_TOKEN_SECRET ?? "test-form-token",
      NEXT_PUBLIC_SUPABASE_URL: process.env.NEXT_PUBLIC_SUPABASE_URL ?? "https://dummy.supabase.co",
      NEXT_PUBLIC_SUPABASE_ANON_KEY: process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ?? "dummy-anon-key",
      NEXT_PUBLIC_ATTESTATION_TEST_MODE: process.env.NEXT_PUBLIC_ATTESTATION_TEST_MODE ?? "false",
      NEXT_PUBLIC_ATTESTATION_BASE_URL: "https://attestation.umbra.test",
      NEXT_PUBLIC_PCCS_URL: "https://pccs.phala.network/tdx/certification/v4",
    },
  },
})
