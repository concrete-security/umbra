"use client"

import { useCallback, useEffect, useState } from "react"

type UseFormTokenResult = {
  token: string | null
  loading: boolean
  error: string | null
  refreshToken: () => Promise<void>
}

export function useFormToken(): UseFormTokenResult {
  const [token, setToken] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const refreshToken = useCallback(async () => {
    setLoading(true)
    try {
      const response = await fetch("/api/form-token", {
        method: "GET",
        headers: {
          "Cache-Control": "no-store",
        },
      })
      if (!response.ok) {
        throw new Error("Unable to fetch form token")
      }
      const payload = (await response.json().catch(() => ({}))) as { token?: string }
      if (!payload.token) {
        throw new Error("Form token not returned")
      }
      setToken(payload.token)
      setError(null)
    } catch (err) {
      console.error("Form token fetch failed", err)
      setToken(null)
      setError("Secure form token unavailable. Please refresh the page.")
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refreshToken()
  }, [refreshToken])

  return { token, loading, error, refreshToken }
}
