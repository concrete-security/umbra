import { NextResponse } from "next/server"

import { AuthenticatedAccessError, requireAdminUser } from "@/lib/auth"
import { createSupabaseRouteHandlerClient } from "@/lib/supabase/route-handler"
import { createSupabaseServiceRoleClient } from "@/lib/supabase/service-role"
import { sendWaitlistActivationEmail } from "@/lib/email/templates/waitlist-activation"

function resolveAppUrl(request: Request): string {
  if (process.env.NEXT_PUBLIC_APP_URL) {
    return process.env.NEXT_PUBLIC_APP_URL
  }

  const forwardedProto = request.headers.get("x-forwarded-proto")
  const forwardedHost = request.headers.get("x-forwarded-host")
  const host = request.headers.get("host")

  const protocol = forwardedProto ?? (process.env.NODE_ENV === "development" ? "http" : "https")
  const hostname = forwardedHost ?? host

  if (!hostname) {
    return "http://localhost:3000"
  }

  return `${protocol}://${hostname}`
}

export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }) {
  const supabase = await createSupabaseRouteHandlerClient()

  try {
    await requireAdminUser(supabase)
  } catch (error) {
    if (error instanceof AuthenticatedAccessError) {
      return NextResponse.json({ error: error.message }, { status: error.status })
    }
    throw error
  }

  const { id: entryId } = await params
  if (!entryId) {
    return NextResponse.json({ error: "Waitlist id is required" }, { status: 400 })
  }

  const serviceRole = createSupabaseServiceRoleClient()
  const { data: entry, error: entryError } = await serviceRole
    .from("waitlist_requests")
    .select("*")
    .eq("id", entryId)
    .maybeSingle()

  if (entryError) {
    console.error("Failed to load waitlist entry", entryError)
    return NextResponse.json({ error: "Unable to load waitlist entry" }, { status: 500 })
  }

  if (!entry) {
    return NextResponse.json({ error: "Waitlist entry not found" }, { status: 404 })
  }

  const appUrl = resolveAppUrl(request)
  const redirectTo = `${appUrl}/sign-in?redirect=/confidential-ai`

  const { data: linkData, error: linkError } = await serviceRole.auth.admin.generateLink({
    type: "magiclink",
    email: entry.email,
    options: {
      redirectTo,
      data: {
        waitlist_request_id: entry.id,
        company: entry.company ?? undefined,
        use_case: entry.use_case ?? undefined,
      },
    },
  })

  if (linkError) {
    console.error("Failed to generate activation magic link", linkError)
    return NextResponse.json({ error: "Unable to generate activation link" }, { status: 500 })
  }

  const magicLink = linkData?.properties?.action_link
  if (!magicLink) {
    console.error("Supabase magic link response missing action_link", linkData)
    return NextResponse.json({ error: "Activation link was not returned" }, { status: 500 })
  }

  const supabaseUserId = linkData?.user?.id ?? entry.supabase_user_id ?? null

  if (supabaseUserId) {
    try {
      await serviceRole.auth.admin.updateUserById(supabaseUserId, {
        app_metadata: {
          roles: ["member"],
          waitlist_request_id: entry.id,
        },
        user_metadata: {
          company: entry.company ?? undefined,
          use_case: entry.use_case ?? undefined,
        },
      })
    } catch (error) {
      console.error("Failed to update Supabase user metadata", error)
      // Continue; metadata enrichment is secondary.
    }
  }

  try {
    await sendWaitlistActivationEmail({
      email: entry.email,
      magicLink,
      company: entry.company,
      useCase: entry.use_case,
    })
  } catch (error) {
    return NextResponse.json({ error: "Failed to deliver activation email" }, { status: 500 })
  }

  const now = new Date().toISOString()
  const { data: updatedEntry, error: updateError } = await serviceRole
    .from("waitlist_requests")
    .update({
      status: "invited",
      last_contacted_at: now,
      activation_sent_at: now,
      activation_link: magicLink,
      supabase_user_id: supabaseUserId,
    })
    .eq("id", entryId)
    .select("*")
    .maybeSingle()

  if (updateError) {
    console.error("Failed to update waitlist entry after activation", updateError)
    return NextResponse.json({ error: "Activation succeeded but we couldn't record it" }, { status: 500 })
  }

  if (!updatedEntry) {
    return NextResponse.json({ error: "Waitlist entry not found after update" }, { status: 404 })
  }

  return NextResponse.json({ request: updatedEntry })
}
