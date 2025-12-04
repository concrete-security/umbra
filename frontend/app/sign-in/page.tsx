"use client"

import { Suspense, useEffect, useMemo, useRef, useState, type FormEvent } from "react"
import Image from "next/image"
import Link from "next/link"
import { useRouter, useSearchParams } from "next/navigation"
import { ArrowRight, Mail, Building2, Sparkles } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ForceLightTheme } from "@/components/force-light-theme"
import { createSupabaseBrowserClient } from "@/lib/supabase/client"
import { isAuthSessionMissingError } from "@/lib/supabase/errors"
import { useFormToken } from "@/hooks/use-form-token"

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

function sanitizeRedirect(redirectParam: string | null) {
  if (!redirectParam) {
    return "/confidential-ai"
  }
  return redirectParam.startsWith("/") ? redirectParam : "/confidential-ai"
}

function SignInForm() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const { client: supabase, error: supabaseInitError } = useMemo(() => {
    try {
      return {
        client: createSupabaseBrowserClient(),
        error: null,
      }
    } catch (error) {
      const initializationError = error instanceof Error ? error : new Error("Failed to initialize Supabase client")
      if (process.env.NODE_ENV !== "production") {
        console.warn("Supabase sign-in form disabled:", initializationError)
      }
      return { client: null, error: initializationError }
    }
  }, [])

  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(supabaseInitError?.message ?? null)
  const hasRedirectedRef = useRef(false)

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

  const redirectTo = sanitizeRedirect(searchParams.get("redirect"))
  const authRequired = searchParams.get("auth") === "required"

  useEffect(() => {
    let active = true
    async function checkExistingSession() {
      if (!supabase) {
        return
      }
      const { data, error: sessionError } = await supabase.auth.getUser()
      if (!active) {
        return
      }
      if (sessionError) {
        if (isAuthSessionMissingError(sessionError)) {
          return
        }
        console.error("Failed to verify existing Supabase session", sessionError)
        return
      }
      if (data.user) {
        hasRedirectedRef.current = true
        router.replace(redirectTo)
      }
    }

    if (supabase) {
      void checkExistingSession()
    }
    return () => {
      active = false
    }
  }, [redirectTo, router, supabase])

  useEffect(() => {
    if (!supabase) {
      return
    }

    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((event: string) => {
      if (event === "SIGNED_IN" && !hasRedirectedRef.current) {
        hasRedirectedRef.current = true
        router.replace(redirectTo)
      }

      if (event === "SIGNED_OUT") {
        hasRedirectedRef.current = false
      }
    })

    return () => {
      subscription.unsubscribe()
    }
  }, [redirectTo, router, supabase])

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (!supabase) {
      setError("Supabase is not configured. Set NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY in .env.local.")
      return
    }
    setLoading(true)
    setError(null)

    try {
      const { error: signInError } = await supabase.auth.signInWithPassword({
        email: email.trim().toLowerCase(),
        password,
      })

      if (signInError) {
        setError(signInError.message)
        setLoading(false)
        return
      }
    } catch (err) {
      console.error("Supabase sign-in failed", err)
      setError(err instanceof Error ? err.message : "Unexpected error signing in")
      setLoading(false)
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
      void refreshWaitlistFormToken()
    } catch (err) {
      console.error("Pre-registration request failed", err)
      setWaitlistError("We couldn't save your request. Please try again in a moment.")
      setWaitlistStatus("idle")
    }
  }

  return (
    <ForceLightTheme>
      <div className="flex min-h-screen flex-col bg-[#E2E2E2] text-[#08070B]">
        <header className="relative z-10 border-b border-[#d4d3e6] bg-transparent">
          <div className="container flex items-center justify-between gap-4 px-6 py-6">
            <Link href="/" className="flex items-center gap-3 text-lg font-semibold tracking-tight">
              <Image src="/logo.png" alt="Umbra logo" width={40} height={40} className="mix-blend-multiply" />
            </Link>
            <div className="flex items-center gap-3">
              <Button
                variant="ghost"
                className="h-9 rounded-full border border-transparent px-5 text-sm font-medium text-[#1F1E28]/80 transition hover:border-[#1B0986]/40 hover:text-[#08070B]"
                asChild
              >
                <Link href="/">Back home</Link>
              </Button>
              <Button
                className="hidden h-9 rounded-full border border-[#1B0986] bg-white px-5 text-sm font-medium text-[#1B0986] transition hover:border-[#0B0870] hover:bg-white hover:text-[#0B0870] md:inline-flex"
                asChild
                variant="outline"
              >
                <a href="mailto:contact@concrete-security.com">Contact us</a>
              </Button>
            </div>
          </div>
        </header>
        <main className="flex flex-1 items-center justify-center px-6 py-12">
          <div className="w-full max-w-md rounded-2xl border border-[#d7d5eb] bg-white/95 p-8 shadow-[0_32px_90px_-60px_rgba(15,11,56,0.45)]">
            <div className="flex flex-col gap-2">
              <h1 className="text-2xl font-semibold text-[#08070B]">Get Started</h1>
              <p className="text-sm text-[#1F1E28]/80">Sign in to access your workspace or join the waitlist for early access.</p>
            </div>

            {authRequired ? (
              <div className="mt-4 rounded-lg border border-[#fcd34d]/70 bg-[#fef3c7] px-3 py-2 text-xs text-[#92400e]">
                Sign in to continue. Your previous request requires authentication.
              </div>
            ) : null}

            <Tabs defaultValue="signin" className="mt-6">
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="signin">Sign In</TabsTrigger>
                <TabsTrigger value="waitlist">Join Waitlist</TabsTrigger>
              </TabsList>

              <TabsContent value="signin" className="space-y-4 mt-6">
                {error ? (
                  <div className="rounded-lg border border-[#fca5a5] bg-[#fee2e2] px-3 py-2 text-xs text-[#b91c1c]">
                    {error}
                  </div>
                ) : null}

                {!supabase && !error ? (
                  <div className="rounded-lg border border-[#fcd34d]/70 bg-[#fef3c7] px-3 py-2 text-xs text-[#92400e]">
                    Supabase environment variables are missing. Update `.env.local` with your project credentials.
                  </div>
                ) : null}

                <form onSubmit={handleSubmit} className="space-y-5">
                  <div className="space-y-2">
                    <label htmlFor="email" className="text-xs font-medium uppercase tracking-[0.2em] text-[#1F1E28]/70">
                      Email
                    </label>
                    <input
                      id="email"
                      type="email"
                      value={email}
                      autoComplete="email"
                      onChange={(event) => setEmail(event.target.value)}
                      required
                      className="w-full rounded-xl border border-[#d7d5eb] bg-white px-4 py-3 text-sm leading-relaxed text-[#08070B] shadow-sm transition focus:border-[#1B0986] focus:outline-none focus:ring-2 focus:ring-[#1B0986]/25"
                    />
                  </div>
                  <div className="space-y-2">
                    <label htmlFor="password" className="text-xs font-medium uppercase tracking-[0.2em] text-[#1F1E28]/70">
                      Password
                    </label>
                    <input
                      id="password"
                      type="password"
                      value={password}
                      autoComplete="current-password"
                      onChange={(event) => setPassword(event.target.value)}
                      required
                      className="w-full rounded-xl border border-[#d7d5eb] bg-white px-4 py-3 text-sm leading-relaxed text-[#08070B] shadow-sm transition focus:border-[#1B0986] focus:outline-none focus:ring-2 focus:ring-[#1B0986]/25"
                    />
                  </div>
                  <Button
                    type="submit"
                    disabled={loading || !supabase}
                    className="w-full rounded-xl bg-[#08070B] py-3 text-sm font-semibold text-white shadow-[0_16px_36px_-20px_rgba(15,11,56,0.65)] transition hover:bg-[#111015]"
                  >
                    {loading ? "Signing in…" : supabase ? "Sign in" : "Configure Supabase"}
                  </Button>
                </form>
                <div className="text-xs text-[#1F1E28]/60">
                  Problems accessing your account?{" "}
                  <a href="mailto:contact@concrete-security.com" className="font-medium text-[#1B0986] hover:underline">
                    Contact support
                  </a>
                  .
                </div>
              </TabsContent>

              <TabsContent value="waitlist" className="space-y-4 mt-6">
                <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.32em] text-[#1F1E28]/60">
                  <Sparkles className="size-4 text-[#facc15]" />
                  <span>Private launch</span>
                </div>
                <p className="text-sm leading-6 text-[#1F1E28]/80">
                  Join the shortlist for Umbra. We'll reach out as soon as your workspace is prioritized for the private rollout.
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
                    You're on the list. We'll reach out as we expand access.
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
          </div>
        </main>
      </div>
    </ForceLightTheme>
  )
}

export default function SignInPage() {
  return (
    <Suspense fallback={
      <ForceLightTheme>
        <div className="flex min-h-screen flex-col bg-[#E2E2E2] text-[#08070B]">
          <header className="border-b border-[#d4d3e6] bg-white/90 backdrop-blur">
            <div className="mx-auto flex w-full max-w-xl items-center justify-between px-6 py-5">
              <Link href="/" className="text-lg font-semibold tracking-tight text-[#08070B]">
                Confidential AI
              </Link>
              <Link href="/" className="text-sm text-[#1F1E28]/70 hover:text-[#08070B]">
                Back home
              </Link>
            </div>
          </header>
          <main className="flex flex-1 items-center justify-center px-6 py-12">
            <div className="w-full max-w-md rounded-2xl border border-[#d7d5eb] bg-white/95 p-8 shadow-[0_32px_90px_-60px_rgba(15,11,56,0.45)]">
              <div className="flex flex-col gap-2">
                <h1 className="text-2xl font-semibold text-[#08070B]">Get Started</h1>
                <p className="text-sm text-[#1F1E28]/80">
                  Sign in to access your workspace or join the waitlist for early access.
                </p>
              </div>
              <div className="mt-6 flex items-center justify-center">
                <div className="text-sm text-[#1F1E28]/60">Loading...</div>
              </div>
            </div>
          </main>
        </div>
      </ForceLightTheme>
    }>
      <SignInForm />
    </Suspense>
  )
}
