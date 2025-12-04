import { NextResponse } from "next/server"

import { AuthenticatedAccessError, requireAdminUser } from "@/lib/auth"
import { WAITLIST_STATUSES, isWaitlistStatus } from "@/lib/waitlist"
import { createSupabaseRouteHandlerClient } from "@/lib/supabase/route-handler"
import { createSupabaseServiceRoleClient } from "@/lib/supabase/service-role"
import { CrossOriginRequestError, ensureSameOrigin } from "@/lib/security/origin"

export async function GET(request: Request) {
  try {
    ensureSameOrigin(request)
  } catch (error) {
    if (error instanceof CrossOriginRequestError) {
      return NextResponse.json({ error: error.message }, { status: 403 })
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

  const url = new URL(request.url)
  const statusParam = url.searchParams.get("status")
  const limitParam = url.searchParams.get("limit")

  const serviceRole = createSupabaseServiceRoleClient()
  let query = serviceRole.from("waitlist_requests").select("*").order("created_at", { ascending: false })

  if (statusParam) {
    if (!isWaitlistStatus(statusParam)) {
      return NextResponse.json({ error: "Invalid status filter" }, { status: 400 })
    }
    query = query.eq("status", statusParam)
  }

  const limit = limitParam ? Math.min(Math.max(Number(limitParam) || 0, 1), 500) : 200
  query = query.limit(limit)

  const { data, error } = await query
  if (error) {
    console.error("Failed to load waitlist requests", error)
    return NextResponse.json({ error: "Unable to load waitlist" }, { status: 500 })
  }

  return NextResponse.json({
    requests: data ?? [],
    statuses: WAITLIST_STATUSES,
  })
}
