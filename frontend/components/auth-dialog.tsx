"use client"

import { useEffect, useMemo, useRef, useState, type FormEvent } from "react"
import { useRouter } from "next/navigation"
import Image from "next/image"
import { ArrowRight, Mail, Building2, Sparkles, CheckCircle2 } from "lucide-react"

import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Button } from "@/components/ui/button"
import { createSupabaseBrowserClient } from "@/lib/supabase/client"
import { isAuthSessionMissingError } from "@/lib/supabase/errors"
import { useFormToken } from "@/hooks/use-form-token"

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

type AuthDialogProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function AuthDialog({ open, onOpenChange }: AuthDialogProps) {
  const router = useRouter()
  const { client: supabase, error: supabaseInitError } = useMemo(() => {
    try {
      return {
        client: createSupabaseBrowserClient(),
        error: null,
      }
    } catch (error) {
      const initializationError = error instanceof Error ? error : new Error("Failed to initialize Supabase client")
      if (process.env.NODE_ENV !== "production") {
        console.warn("Supabase auth dialog disabled:", initializationError)
      }
      return { client: null, error: initializationError }
    }
  }, [])

  const [authState, setAuthState] = useState<"checking" | "authenticated" | "unauthenticated">("checking")
  const [signInEmail, setSignInEmail] = useState("")
  const [signInPassword, setSignInPassword] = useState("")
  const [signInLoading, setSignInLoading] = useState(false)
  const [signInError, setSignInError] = useState<string | null>(supabaseInitError?.message ?? null)
  
  const [waitlistEmail, setWaitlistEmail] = useState("")
  const [waitlistCompany, setWaitlistCompany] = useState("")
  const [waitlistUseCase, setWaitlistUseCase] = useState("")
  const [waitlistStatus, setWaitlistStatus] = useState<"idle" | "loading" | "success">("idle")
  const [waitlistError, setWaitlistError] = useState<string | null>(null)
  const waitlistHoneypotRef = useRef<HTMLInputElement | null>(null)
  const {
    token: waitlistFormToken,
    loading: waitlistFormTokenLoading,
    error: waitlistFormTokenError,
    refreshToken: refreshWaitlistFormToken,
  } = useFormToken()

  const [activeTab, setActiveTab] = useState("signin")

  useEffect(() => {
    const client = supabase
    if (!open || !client) {
      setAuthState("unauthenticated")
      return
    }

    const authClient = client as NonNullable<typeof client>
    let mounted = true

    async function checkAuth() {
      try {
        const { data, error } = await authClient.auth.getUser()
        if (!mounted) return
        if (error) {
          if (isAuthSessionMissingError(error)) {
            setAuthState("unauthenticated")
            return
          }
          console.error("Failed to check auth status", error)
          setAuthState("unauthenticated")
          return
        }
        if (data.user) {
          setAuthState("authenticated")
        } else {
          setAuthState("unauthenticated")
        }
      } catch (error) {
        console.error("Unexpected error checking auth", error)
        if (mounted) {
          setAuthState("unauthenticated")
        }
      }
    }

    setAuthState("checking")
    void checkAuth()

    const {
      data: { subscription },
    } = authClient.auth.onAuthStateChange((_event: string, session: { user: unknown } | null) => {
      if (!mounted) return
      if (session?.user) {
        setAuthState("authenticated")
      } else {
        setAuthState("unauthenticated")
      }
    })

    return () => {
      mounted = false
      subscription.unsubscribe()
    }
  }, [open, supabase])

  useEffect(() => {
    if (authState === "authenticated") {
      const timer = setTimeout(() => {
        onOpenChange(false)
        router.push("/confidential-ai")
      }, 1500)
      return () => clearTimeout(timer)
    }
  }, [authState, onOpenChange, router])

  const handleSignIn = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!supabase) {
      setSignInError("Supabase is not configured.")
      return
    }
    setSignInLoading(true)
    setSignInError(null)

    try {
      const { error: signInError } = await supabase.auth.signInWithPassword({
        email: signInEmail.trim().toLowerCase(),
        password: signInPassword,
      })

      if (signInError) {
        setSignInError(signInError.message)
        setSignInLoading(false)
        return
      }
    } catch (err) {
      console.error("Supabase sign-in failed", err)
      setSignInError(err instanceof Error ? err.message : "Unexpected error signing in")
      setSignInLoading(false)
    }
  }

  const handleWaitlistSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (waitlistStatus === "loading") {
      return
    }

    const checkpointValue = waitlistHoneypotRef.current?.value?.trim() ?? ""
    if (checkpointValue.length > 0) {
      setWaitlistError("Unable to process the request.")
      return
    }

    if (!waitlistFormToken) {
      setWaitlistError("Secure form token unavailable. Please refresh and try again.")
      void refreshWaitlistFormToken()
      return
    }

    const trimmedEmail = waitlistEmail.trim()
    if (!trimmedEmail) {
      setWaitlistError("Add a work email so we know where to reach you.")
      return
    }
    if (!emailRegex.test(trimmedEmail)) {
      setWaitlistError("That email looks off. Double-check and try again.")
      return
    }

    setWaitlistError(null)
    setWaitlistStatus("loading")

    try {
      const response = await fetch("/api/waitlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: trimmedEmail,
          company: waitlistCompany.trim() || undefined,
          use_case: waitlistUseCase.trim() || undefined,
          form_token: waitlistFormToken,
          checkpoint: checkpointValue || undefined,
        }),
      })

      const payload = (await response.json().catch(() => ({}))) as { error?: string }

      if (!response.ok) {
        setWaitlistError(payload.error ?? "We couldn't save your request. Please try again in a moment.")
        setWaitlistStatus("idle")
        return
      }

      setWaitlistStatus("success")
      setWaitlistEmail("")
      setWaitlistCompany("")
      setWaitlistUseCase("")
      if (waitlistHoneypotRef.current) {
        waitlistHoneypotRef.current.value = ""
      }

      setTimeout(() => {
        onOpenChange(false)
        router.push("/confidential-ai")
      }, 2000)
      void refreshWaitlistFormToken()
    } catch (err) {
      console.error("Pre-registration request failed", err)
      setWaitlistError("We couldn't save your request. Please try again in a moment.")
      setWaitlistStatus("idle")
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-3 text-2xl font-semibold text-[#08070B]">
            <Image src="/logo.png" alt="Umbra logo" width={32} height={32} className="mix-blend-multiply" />
            <span>Get Started</span>
          </DialogTitle>
        </DialogHeader>

        {authState === "checking" ? (
          <div className="flex items-center justify-center py-8">
            <div className="text-sm text-[#1F1E28]/60">Checking authentication...</div>
          </div>
        ) : authState === "authenticated" ? (
          <div className="flex flex-col items-center gap-4 py-8 text-center">
            <CheckCircle2 className="h-12 w-12 text-emerald-500" />
            <div>
              <p className="text-base font-medium text-[#08070B]">You're signed in!</p>
              <p className="mt-1 text-sm text-[#1F1E28]/70">Redirecting to secure session...</p>
            </div>
          </div>
        ) : (
          <Tabs value={activeTab} onValueChange={setActiveTab} className="mt-4">
            <TabsList className="grid w-full grid-cols-2">
              <TabsTrigger value="signin">Sign In</TabsTrigger>
              <TabsTrigger value="waitlist">Join Waitlist</TabsTrigger>
            </TabsList>

            <TabsContent value="signin" className="space-y-4 mt-6">
              {signInError ? (
                <div className="rounded-lg border border-[#fca5a5] bg-[#fee2e2] px-3 py-2 text-xs text-[#b91c1c]">
                  {signInError}
                </div>
              ) : null}

              {!supabase && !signInError ? (
                <div className="rounded-lg border border-[#fcd34d]/70 bg-[#fef3c7] px-3 py-2 text-xs text-[#92400e]">
                  Supabase environment variables are missing.
                </div>
              ) : null}

              <form onSubmit={handleSignIn} className="space-y-4">
                <div className="space-y-2">
                  <label htmlFor="dialog-email" className="text-xs font-medium uppercase tracking-[0.2em] text-[#1F1E28]/70">
                    Email
                  </label>
                  <input
                    id="dialog-email"
                    type="email"
                    value={signInEmail}
                    autoComplete="email"
                    onChange={(event) => setSignInEmail(event.target.value)}
                    required
                    className="w-full rounded-xl border border-[#d7d5eb] bg-white px-4 py-3 text-sm leading-relaxed text-[#08070B] shadow-sm transition focus:border-[#1B0986] focus:outline-none focus:ring-2 focus:ring-[#1B0986]/25"
                  />
                </div>
                <div className="space-y-2">
                  <label htmlFor="dialog-password" className="text-xs font-medium uppercase tracking-[0.2em] text-[#1F1E28]/70">
                    Password
                  </label>
                  <input
                    id="dialog-password"
                    type="password"
                    value={signInPassword}
                    autoComplete="current-password"
                    onChange={(event) => setSignInPassword(event.target.value)}
                    required
                    className="w-full rounded-xl border border-[#d7d5eb] bg-white px-4 py-3 text-sm leading-relaxed text-[#08070B] shadow-sm transition focus:border-[#1B0986] focus:outline-none focus:ring-2 focus:ring-[#1B0986]/25"
                  />
                </div>
                <Button
                  type="submit"
                  disabled={signInLoading || !supabase}
                  className="w-full rounded-xl bg-[#08070B] py-3 text-sm font-semibold text-white shadow-[0_16px_36px_-20px_rgba(15,11,56,0.65)] transition hover:bg-[#111015]"
                >
                  {signInLoading ? "Signing in…" : supabase ? "Sign in" : "Configure Supabase"}
                </Button>
              </form>
              <p className="text-xs text-[#1F1E28]/60">
                Problems accessing your account?{" "}
                <a href="mailto:contact@concrete-security.com" className="font-medium text-[#1B0986] hover:underline">
                  Contact support
                </a>
                .
              </p>
            </TabsContent>

            <TabsContent value="waitlist" className="space-y-4 mt-6">
              <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.32em] text-[#1F1E28]/60">
                <Sparkles className="size-4 text-[#facc15]" />
                <span>Private launch</span>
              </div>
              <p className="text-sm leading-6 text-[#1F1E28]/80">
                Join the shortlist for Confidential AI. We'll reach out as soon as your workspace is prioritized for the private rollout.
              </p>

              {waitlistError ? (
                <div className="rounded-lg border border-[#fca5a5] bg-[#fee2e2] px-3 py-2 text-xs text-[#b91c1c]">
                  {waitlistError}
                </div>
              ) : null}

              {waitlistFormTokenError ? (
                <div className="rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-800">
                  {waitlistFormTokenError}
                </div>
              ) : null}

              {waitlistStatus === "success" ? (
                <div className="rounded-2xl border border-emerald-400/30 bg-emerald-400/10 px-4 py-3 text-sm text-emerald-700">
                  You're on the list. Redirecting to secure session...
                </div>
              ) : null}

              <form onSubmit={handleWaitlistSubmit} className="space-y-4">
                <input
                  ref={waitlistHoneypotRef}
                  type="text"
                  name="workspace-url"
                  tabIndex={-1}
                  autoComplete="off"
                  aria-hidden="true"
                  className="absolute h-px w-px opacity-0"
                  defaultValue=""
                />
                <label htmlFor="waitlist-email" className="flex items-center gap-2 rounded-2xl border border-[#d7d5eb] bg-white px-4 py-3 text-sm text-[#1F1E28]/80 focus-within:border-[#1B0986] focus-within:bg-white focus-within:text-[#08070B]">
                  <Mail className="size-4 text-[#1B0986]" />
                  <input
                    id="waitlist-email"
                    type="email"
                    placeholder="Your email"
                    className="w-full bg-transparent text-sm text-[#08070B] placeholder:text-[#1F1E28]/50 focus:outline-none"
                    value={waitlistEmail}
                    onChange={(event) => setWaitlistEmail(event.target.value)}
                    disabled={waitlistStatus === "loading" || waitlistStatus === "success"}
                    required
                  />
                </label>

                <label htmlFor="waitlist-company" className="flex items-center gap-2 rounded-2xl border border-[#d7d5eb] bg-white px-4 py-3 text-sm text-[#1F1E28]/70 focus-within:border-[#1B0986] focus-within:bg-white focus-within:text-[#08070B]">
                  <Building2 className="size-4 text-[#1B0986]" />
                  <input
                    id="waitlist-company"
                    type="text"
                    placeholder="Company (optional)"
                    className="w-full bg-transparent text-sm text-[#08070B] placeholder:text-[#1F1E28]/40 focus:outline-none"
                    value={waitlistCompany}
                    onChange={(event) => setWaitlistCompany(event.target.value)}
                    disabled={waitlistStatus === "loading" || waitlistStatus === "success"}
                  />
                </label>

                <textarea
                  id="waitlist-use-case"
                  placeholder="Tell us what you're looking to secure (optional)"
                  className="min-h-[90px] w-full rounded-2xl border border-[#d7d5eb] bg-white px-4 py-3 text-sm text-[#08070B] placeholder:text-[#1F1E28]/40 focus:border-[#1B0986] focus:outline-none"
                  value={waitlistUseCase}
                  onChange={(event) => setWaitlistUseCase(event.target.value)}
                  disabled={waitlistStatus === "loading" || waitlistStatus === "success"}
                />

                <Button
                  type="submit"
                  className="h-12 w-full rounded-full bg-[#08070B] px-6 text-sm font-semibold text-white transition hover:bg-[#111015]"
                  disabled={
                    waitlistStatus === "loading" ||
                    waitlistStatus === "success" ||
                    waitlistFormTokenLoading ||
                    !waitlistFormToken
                  }
                >
                  {waitlistStatus === "loading" ? "Submitting…" : waitlistStatus === "success" ? "Request received" : "Request early access"}
                  <ArrowRight className="ml-2 size-4" />
                </Button>
                <p className="text-[11px] text-[#1F1E28]/60">
                  We review requests manually to keep customer data safe. No spam — just next steps when we're ready.
                </p>
              </form>
            </TabsContent>
          </Tabs>
        )}
      </DialogContent>
    </Dialog>
  )
}
