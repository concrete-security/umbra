"use client"

import { useRef, useState, type FormEvent } from "react"
import Image from "next/image"
import { ArrowRight, Mail, Building2, Sparkles } from "lucide-react"

import { Button } from "@/components/ui/button"
import { useFormToken } from "@/hooks/use-form-token"

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

export function PreRegisterCard() {
  const [email, setEmail] = useState("")
  const [company, setCompany] = useState("")
  const [useCase, setUseCase] = useState("")
  const [status, setStatus] = useState<"idle" | "loading" | "success">("idle")
  const [error, setError] = useState<string | null>(null)
  const honeypotRef = useRef<HTMLInputElement | null>(null)
  const { token: formToken, loading: formTokenLoading, error: formTokenError, refreshToken } = useFormToken()

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (status === "loading") {
      return
    }

    const checkpointValue = honeypotRef.current?.value?.trim() ?? ""
    if (checkpointValue.length > 0) {
      setError("Unable to submit this request.")
      return
    }

    if (!formToken) {
      setError("Secure form token unavailable. Please refresh and try again.")
      void refreshToken()
      return
    }

    const trimmedEmail = email.trim()
    if (!trimmedEmail) {
      setError("Add a work email so we know where to reach you.")
      return
    }
    if (!emailRegex.test(trimmedEmail)) {
      setError("That email looks off. Double-check and try again.")
      return
    }

    setError(null)
    setStatus("loading")

    try {
      const response = await fetch("/api/waitlist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: trimmedEmail,
          company: company.trim() || undefined,
          use_case: useCase.trim() || undefined,
          form_token: formToken,
          checkpoint: checkpointValue || undefined,
        }),
      })

      const payload = (await response.json().catch(() => ({}))) as { error?: string }

      if (!response.ok) {
        setError(payload.error ?? "We couldn't save your request. Please try again in a moment.")
        setStatus("idle")
        return
      }

      setStatus("success")
      setEmail("")
      setCompany("")
      setUseCase("")
      honeypotRef.current && (honeypotRef.current.value = "")
      void refreshToken()
    } catch (err) {
      console.error("Pre-registration request failed", err)
      setError("We couldn't save your request. Please try again in a moment.")
      setStatus("idle")
    }
  }

  return (
    <div className="relative overflow-hidden rounded-[32px] border border-[#1B0986]/30 bg-[radial-gradient(circle_at_top,rgba(27,9,134,0.28),rgba(8,7,11,0.9))] p-[1px] shadow-[0_48px_160px_-96px_rgba(15,11,56,0.75)]">
      <div className="relative z-10 flex flex-col gap-6 rounded-[31px] bg-[#060511]/85 p-6 text-white md:flex-row md:items-center md:gap-10 md:p-8 lg:p-10">
        <div className="flex flex-1 flex-col gap-4">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center overflow-hidden rounded-xl border border-white/20 bg-white/10 shadow-[0_12px_30px_-20px_rgba(248,248,255,0.8)]">
              <Image src="/logo.png" alt="Umbra logo" width={32} height={32} className="mix-blend-multiply" />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2 text-xs font-medium uppercase tracking-[0.32em] text-white/60">
                <Sparkles className="size-4 text-[#facc15]" />
                <span>Private launch</span>
              </div>
              <span className="text-[11px] uppercase tracking-[0.28em] text-white/40">Waitlist invite</span>
            </div>
          </div>
          <div>
            <h2 className="text-2xl font-semibold tracking-tight text-white md:text-[28px]">Pre-register for early access</h2>
            <p className="mt-2 text-sm leading-6 text-white/70">
              Join the shortlist for Confidential AI. We'll reach out as soon as your workspace is prioritized for the private
              rollout.
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="flex w-full flex-col gap-4 md:max-w-sm">
          <input
            ref={honeypotRef}
            type="text"
            name="workspace-url"
            tabIndex={-1}
            autoComplete="off"
            aria-hidden="true"
            className="absolute h-px w-px opacity-0"
            defaultValue=""
          />
          <label htmlFor="pre-register-email" className="flex items-center gap-2 rounded-2xl border border-white/15 bg-white/5 px-4 py-3 text-sm text-white/80 focus-within:border-white/50 focus-within:bg-white/10 focus-within:text-white">
            <Mail className="size-4 text-white/60" />
            <input
              id="pre-register-email"
              type="email"
              placeholder="Your email"
              className="w-full bg-transparent text-sm text-white placeholder:text-white/50 focus:outline-none"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              disabled={status === "loading" || status === "success"}
              required
            />
          </label>

          <label htmlFor="pre-register-company" className="flex items-center gap-2 rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm text-white/70 focus-within:border-white/40 focus-within:bg-white/10 focus-within:text-white">
            <Building2 className="size-4 text-white/50" />
            <input
              id="pre-register-company"
              type="text"
              placeholder="Company (optional)"
              className="w-full bg-transparent text-sm text-white placeholder:text-white/40 focus:outline-none"
              value={company}
              onChange={(event) => setCompany(event.target.value)}
              disabled={status === "loading" || status === "success"}
            />
          </label>

          <textarea
            id="pre-register-use-case"
            placeholder="Tell us what you’re looking to secure (optional)"
            className="min-h-[90px] rounded-2xl border border-white/10 bg-white/[0.04] px-4 py-3 text-sm text-white placeholder:text-white/40 focus:border-white/40 focus:bg-white/10 focus:outline-none"
            value={useCase}
            onChange={(event) => setUseCase(event.target.value)}
            disabled={status === "loading" || status === "success"}
          />

          {error ? <p className="text-xs font-medium text-[#fda4af]">{error}</p> : null}
          {formTokenError ? <p className="text-xs font-medium text-amber-200">{formTokenError}</p> : null}
          {status === "success" ? (
            <p className="rounded-2xl border border-emerald-400/30 bg-emerald-400/10 px-4 py-3 text-sm text-emerald-100">
              You&apos;re on the list. We&apos;ll reach out as we expand access.
            </p>
          ) : null}

          <Button
            type="submit"
            className="h-12 rounded-full bg-white px-6 text-sm font-semibold text-[#060511] transition hover:bg-white/90"
            disabled={status === "loading" || status === "success" || formTokenLoading || !formToken}
          >
            {status === "loading" ? "Submitting…" : status === "success" ? "Request received" : "Request early access"}
            <ArrowRight className="ml-2 size-4" />
          </Button>
          <p className="text-[11px] text-white/40">
            We review requests manually to keep customer data safe. No spam — just next steps when we&apos;re ready.
          </p>
        </form>
      </div>

      <div className="absolute inset-0 -z-10 bg-[radial-gradient(circle_at_top,_rgba(27,24,212,0.35),_transparent_70%)]" />
    </div>
  )
}
