"use client"

import { useEffect, useState } from "react"
import { verifyTdxQuoteWithFallback } from "@/lib/attestation-verifier"

export default function TestVerifyQuotePage() {
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search)
    const quoteHex = urlParams.get("quoteHex")
    const pccsUrlParam = urlParams.get("pccsUrl")
    const forceTestModeParam = urlParams.get("forceTestMode")

    const pccsUrl = pccsUrlParam && pccsUrlParam.trim().length > 0 ? pccsUrlParam : undefined
    const forceTestMode = forceTestModeParam === "false" ? false : forceTestModeParam === "true" ? true : undefined

    if (!quoteHex) {
      setError("Missing quoteHex parameter")
      return
    }

    verifyTdxQuoteWithFallback(quoteHex, { pccsUrl, forceTestMode })
      .then((verificationResult) => {
        setResult(verificationResult)
        ;(window as any).__verificationResult = verificationResult
        ;(window as any).__verificationContext = { pccsUrl: pccsUrl ?? null }
      })
      .catch((err) => {
        const message = err instanceof Error ? err.message : String(err)
        setError(message)
        ;(window as any).__verificationError = message
        ;(window as any).__verificationContext = { pccsUrl: pccsUrl ?? null }
      })
  }, [])

  if (error) {
    return (
      <div style={{ padding: "20px" }}>
        <h1>Verification Error</h1>
        <pre>{error}</pre>
      </div>
    )
  }

  if (!result) {
    return (
      <div style={{ padding: "20px" }}>
        <h1>Verifying quote...</h1>
      </div>
    )
  }

  return (
    <div style={{ padding: "20px" }}>
      <h1>Verification Complete</h1>
      <pre>{JSON.stringify(result, null, 2)}</pre>
    </div>
  )
}
