import { NextResponse } from "next/server"

import { createSupabaseServiceRoleClient } from "@/lib/supabase/service-role"
import { CrossOriginRequestError, UnsupportedContentTypeError, assertJsonRequest, ensureSameOrigin } from "@/lib/security/origin"
import { enforceRateLimit, RateLimitError } from "@/lib/security/rate-limit"
import { getClientIp } from "@/lib/security/request"
import { FormTokenError, verifyFormToken } from "@/lib/security/form-token"

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

type WaitlistPayload = {
  email?: unknown
  company?: unknown
  use_case?: unknown
  metadata?: unknown
  form_token?: unknown
  checkpoint?: unknown
}

function sanitizeString(value: unknown, maxLength: number): string | null {
  if (typeof value !== "string") {
    return null
  }
  const trimmed = value.trim()
  if (!trimmed) {
    return null
  }
  return trimmed.length > maxLength ? trimmed.slice(0, maxLength) : trimmed
}

function sanitizeMetadata(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return null
  }
  const entries = Object.entries(value)
    .filter(([key, val]) => typeof key === "string" && key.length > 0 && val !== undefined)
    .slice(0, 12)
  if (entries.length === 0) {
    return null
  }
  return Object.fromEntries(entries)
}

export async function POST(request: Request) {
  try {
    ensureSameOrigin(request)
    assertJsonRequest(request)
  } catch (error) {
    if (error instanceof CrossOriginRequestError) {
      return NextResponse.json({ error: error.message }, { status: 403 })
    }
    if (error instanceof UnsupportedContentTypeError) {
      return NextResponse.json({ error: error.message }, { status: 415 })
    }
    throw error
  }

  const clientIp = getClientIp(request)
  try {
    enforceRateLimit(`waitlist:${clientIp}`, 5, 60_000)
  } catch (error) {
    if (error instanceof RateLimitError) {
      return NextResponse.json({ error: error.message }, { status: 429, headers: { "Retry-After": String(error.retryAfter) } })
    }
    throw error
  }

  const payload = (await request.json().catch(() => ({}))) as WaitlistPayload

  const checkpointValue = typeof payload.checkpoint === "string" ? payload.checkpoint.trim() : ""
  if (checkpointValue.length > 0) {
    return NextResponse.json({ error: "Unable to process the request." }, { status: 400 })
  }

  try {
    verifyFormToken(payload.form_token)
  } catch (error) {
    const message = error instanceof FormTokenError ? error.message : "Invalid form token."
    return NextResponse.json({ error: message }, { status: 400 })
  }

  const email = sanitizeString(payload.email, 160)?.toLowerCase()
  if (!email) {
    return NextResponse.json({ error: "Email is required" }, { status: 400 })
  }
  if (!emailRegex.test(email)) {
    return NextResponse.json({ error: "Email appears invalid" }, { status: 422 })
  }

  const company = sanitizeString(payload.company, 160)
  const useCase = sanitizeString(payload.use_case, 320)
  const metadata = sanitizeMetadata(payload.metadata)

  try {
    const supabase = createSupabaseServiceRoleClient()
    const { error } = await supabase
      .from("waitlist_requests")
      .upsert(
        {
          email,
          company,
          use_case: useCase,
          metadata,
        } as never,
        {
          onConflict: "email",
        }
      )

    if (error) {
      console.error("Failed to store waitlist request", error)
      return NextResponse.json({ error: "Unable to record your request at the moment." }, { status: 500 })
    }

    return NextResponse.json({ success: true })
  } catch (error) {
    console.error("Unexpected waitlist error", error)
    return NextResponse.json({ error: "Unexpected error recording your request." }, { status: 500 })
  }
}
