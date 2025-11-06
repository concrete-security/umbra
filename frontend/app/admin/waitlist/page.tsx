import { redirect } from "next/navigation"

import AdminWaitlistClient from "./client"

import { AuthenticatedAccessError, requireAdminUser } from "@/lib/auth"
import { ForceLightTheme } from "@/components/force-light-theme"
import { createSupabaseServerClient } from "@/lib/supabase/server"

export default async function AdminWaitlistPage() {
  try {
    const supabase = await createSupabaseServerClient()
    await requireAdminUser(supabase)
  } catch (error) {
    if (error instanceof AuthenticatedAccessError) {
      if (error.status === 401) {
        const params = new URLSearchParams({
          redirect: "/admin/waitlist",
          auth: "required",
        })
        redirect(`/sign-in?${params.toString()}`)
      }
      if (error.status === 403) {
        redirect("/")
      }
    }
    throw error
  }

  return (
    <ForceLightTheme>
      <AdminWaitlistClient />
    </ForceLightTheme>
  )
}
