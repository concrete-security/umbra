"use client"

import { useEffect, useMemo } from "react"
import { useRouter } from "next/navigation"
import type { AuthChangeEvent, Session } from "@supabase/supabase-js"

import { createSupabaseBrowserClient } from "@/lib/supabase/client"

type SupabaseAuthListenerPayload = {
  event: AuthChangeEvent
  session: Session | null
}

export function SupabaseAuthListener() {
  const router = useRouter()
  const supabase = useMemo(() => {
    try {
      return createSupabaseBrowserClient()
    } catch (error) {
      if (process.env.NODE_ENV !== "production") {
        console.warn("Supabase auth listener disabled:", error)
      }
      return null
    }
  }, [])

  useEffect(() => {
    if (!supabase) {
      return
    }

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((event: AuthChangeEvent, session: Session | null) => {
      // Only sync session state when there's an actual session change to persist
      if (event === "SIGNED_IN" || event === "TOKEN_REFRESHED" || event === "SIGNED_OUT") {
        const payload: SupabaseAuthListenerPayload = { event, session }

        void fetch("/auth/callback", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(payload),
        }).catch((error) => {
          console.error("Failed to update Supabase auth session", error)
        })
      }

      if (event === "SIGNED_IN" || event === "SIGNED_OUT") {
        router.refresh()
      }
    })

    return () => {
      subscription.unsubscribe()
    }
  }, [router, supabase])

  return null
}
