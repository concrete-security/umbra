import type { WaitlistRequestRow, WaitlistStatus } from "@/lib/supabase/types"

export type WaitlistRequest = WaitlistRequestRow

export const WAITLIST_STATUSES: WaitlistStatus[] = ["requested", "contacted", "invited", "activated", "archived"]

export function isWaitlistStatus(value: string): value is WaitlistStatus {
  return WAITLIST_STATUSES.includes(value as WaitlistStatus)
}

export type { WaitlistStatus } from "@/lib/supabase/types"
