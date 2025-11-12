export type Json = string | number | boolean | null | { [key: string]: Json | undefined } | Json[]

export type WaitlistStatus = "requested" | "contacted" | "invited" | "activated" | "archived"

export type WaitlistRequestRow = {
  id: string
  created_at: string
  email: string
  company: string | null
  use_case: string | null
  status: WaitlistStatus
  notes: string | null
  priority: number | null
  last_contacted_at: string | null
  supabase_user_id: string | null
  activation_sent_at: string | null
  activation_link: string | null
  activated_at: string | null
  metadata: Json | null
}

export type Database = {
  public: {
    Tables: {
      waitlist_requests: {
        Row: WaitlistRequestRow
        Insert: Partial<Omit<WaitlistRequestRow, "id" | "created_at">> & {
          email: string
        }
        Update: Partial<Omit<WaitlistRequestRow, "id">>
      }
    }
    Views: Record<string, never>
    Functions: Record<string, never>
    Enums: {
      waitlist_status: WaitlistStatus
    }
  }
}

export type Tables = Database["public"]["Tables"]
