import { NextResponse } from "next/server"

import { createSupabaseServiceRoleClient } from "@/lib/supabase/service-role"

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

type WaitlistPayload = {
  email?: unknown
  company?: unknown
  use_case?: unknown
  metadata?: unknown
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
  const payload = (await request.json().catch(() => ({}))) as WaitlistPayload

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
        },
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
