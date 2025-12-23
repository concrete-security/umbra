import { redirect } from "next/navigation"

export default function AdminInvitationsRedirectPage() {
  redirect("/admin/waitlist")
}
