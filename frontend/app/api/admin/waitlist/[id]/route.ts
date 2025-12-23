import { NextResponse } from "next/server"

import { AuthenticatedAccessError, requireAdminUser } from "@/lib/auth"
import { isWaitlistStatus } from "@/lib/waitlist"
import { createSupabaseRouteHandlerClient } from "@/lib/supabase/route-handler"
import { createSupabaseServiceRoleClient } from "@/lib/supabase/service-role"
import { CrossOriginRequestError, UnsupportedContentTypeError, assertJsonRequest, ensureSameOrigin } from "@/lib/security/origin"

type UpdatePayload = {
  status?: unknown
  notes?: unknown
  priority?: unknown
  mark_contacted?: unknown
}

function sanitizeNotes(value: unknown): string | null | undefined {
  if (value === undefined) {
    return undefined
  }
  if (value === null) {
    return null
  }
  if (typeof value !== "string") {
    return null
  }
  const trimmed = value.trim()
  if (!trimmed) {
    return null
  }
  return trimmed.length > 2000 ? trimmed.slice(0, 2000) : trimmed
}

function sanitizePriority(value: unknown): number | null | undefined {
  if (value === undefined) {
    return undefined
  }
  if (value === null || value === "") {
    return null
  }
  const numeric = Number(value)
  if (Number.isNaN(numeric)) {
    return null
  }
  return Math.min(Math.max(Math.round(numeric), 0), 10)
}

export async function PATCH(request: Request, { params }: { params: Promise<{ id: string }> }) {
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

  const supabase = await createSupabaseRouteHandlerClient()

  try {
    await requireAdminUser(supabase)
  } catch (error) {
    if (error instanceof AuthenticatedAccessError) {
      return NextResponse.json({ error: error.message }, { status: error.status })
    }
    throw error
  }

  const { id: requestId } = await params
  if (!requestId) {
    return NextResponse.json({ error: "Waitlist id is required" }, { status: 400 })
  }

  const payload = (await request.json().catch(() => ({}))) as UpdatePayload
  const updates: Record<string, unknown> = {}

  if (payload.status !== undefined) {
    if (typeof payload.status !== "string" || !isWaitlistStatus(payload.status)) {
      return NextResponse.json({ error: "Invalid status" }, { status: 400 })
    }
    updates.status = payload.status
  }

  const notes = sanitizeNotes(payload.notes)
  if (notes !== undefined) {
    updates.notes = notes
  }

  const priority = sanitizePriority(payload.priority)
  if (priority !== undefined) {
    updates.priority = priority
  }

  if (payload.mark_contacted) {
    updates.last_contacted_at = new Date().toISOString()
  }

  if (Object.keys(updates).length === 0) {
    return NextResponse.json({ error: "No updates provided" }, { status: 400 })
  }

  const serviceRole = createSupabaseServiceRoleClient()
  const { data, error } = await serviceRole
    .from("waitlist_requests")
    .update(updates as never)
    .eq("id", requestId)
    .select("*")
    .maybeSingle()

  if (error) {
    console.error("Failed to update waitlist request", error)
    return NextResponse.json({ error: "Unable to update waitlist entry" }, { status: 500 })
  }

  if (!data) {
    return NextResponse.json({ error: "Waitlist entry not found" }, { status: 404 })
  }

  return NextResponse.json({ request: data })
}
