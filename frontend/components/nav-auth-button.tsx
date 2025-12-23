"use client"

import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"

import { Button } from "@/components/ui/button"
import { createSupabaseBrowserClient } from "@/lib/supabase/client"
import { isAuthSessionMissingError } from "@/lib/supabase/errors"

type AuthState = "loading" | "signed-in" | "signed-out"

export function NavAuthButton() {
  const router = useRouter()
  const supabase = useMemo(() => {
    try {
      return createSupabaseBrowserClient()
    } catch (error) {
      if (process.env.NODE_ENV !== "production") {
        console.warn("Supabase nav auth button disabled:", error)
      }
      return null
    }
  }, [])
  const [authState, setAuthState] = useState<AuthState>(supabase ? "loading" : "signed-out")
  const [isSigningOut, setIsSigningOut] = useState(false)
  const isInitializedRef = useRef(false)

  const applySession = useCallback((sessionUserPresent: boolean) => {
    setAuthState((previous) => {
      const next = sessionUserPresent ? "signed-in" : "signed-out"
      if (previous === next) {
        return previous
      }
      return next
    })
  }, [])

  useEffect(() => {
    if (isInitializedRef.current) {
      return
    }
    const client = supabase
    if (!client) {
      isInitializedRef.current = true
      setAuthState("signed-out")
      return
    }

    const authClient = client as NonNullable<typeof client>
    let mounted = true
    isInitializedRef.current = true

    async function resolveInitialState() {
      try {
        const { data, error } = await authClient.auth.getUser()
        if (!mounted) {
          return
        }
        if (error) {
          if (isAuthSessionMissingError(error)) {
            setAuthState((prev) => (prev === "signed-out" ? prev : "signed-out"))
            return
          }
          console.error("Failed to resolve Supabase user", error)
          setAuthState((prev) => (prev === "signed-out" ? prev : "signed-out"))
          return
        }
        const newState = data.user ? "signed-in" : "signed-out"
        setAuthState((prev) => (prev === newState ? prev : newState))
      } catch (error) {
        console.error("Unexpected error resolving Supabase user", error)
        if (mounted) {
          setAuthState((prev) => (prev === "signed-out" ? prev : "signed-out"))
        }
      }
    }

    void resolveInitialState()

    const {
      data: { subscription },
    } = authClient.auth.onAuthStateChange((_event: string, session: { user: unknown } | null) => {
      if (!mounted) {
        return
      }
      const newState = session?.user ? "signed-in" : "signed-out"
      setAuthState((prev) => (prev === newState ? prev : newState))
    })

    return () => {
      mounted = false
      subscription.unsubscribe()
    }
  }, [supabase])

  if (authState === "loading") {
    return (
      <Button
        variant="outline"
        className="h-9 rounded-full border border-[#1B0986] px-4 text-sm text-[#1B0986]"
        disabled
      >
        Checking access…
      </Button>
    )
  }

  if (authState === "signed-in") {
    const handleSignOut = async () => {
      if (!supabase || isSigningOut) {
        return
      }
      setIsSigningOut(true)
      try {
        await supabase.auth.signOut()
        applySession(false)
        router.replace("/")
      } catch (error) {
        console.error("Failed to sign out", error)
      } finally {
        setIsSigningOut(false)
      }
    }

    return (
      <div className="flex items-center gap-2">
        <Button className="h-9 rounded-full bg-[#08070B] px-5 text-sm font-medium text-white shadow-[0_14px_28px_-16px_rgba(15,11,56,0.65)] hover:bg-[#111015]" asChild>
          <Link href="/admin/waitlist">Waitlist console</Link>
        </Button>
        <Button
          type="button"
          variant="outline"
          className="h-9 rounded-full border border-[#1B0986] px-4 text-sm font-medium text-[#1B0986] transition hover:border-[#0B0870] hover:text-[#0B0870]"
          onClick={handleSignOut}
          disabled={isSigningOut}
        >
          {isSigningOut ? "Signing out…" : "Sign out"}
        </Button>
      </div>
    )
  }

  return (
    <Button
      variant="outline"
      className="h-9 rounded-full border border-[#1B0986] px-5 text-sm font-medium text-[#1B0986] transition hover:border-[#0B0870] hover:text-[#0B0870]"
      asChild
    >
      <Link href="/sign-in">Sign in</Link>
    </Button>
  )
}
