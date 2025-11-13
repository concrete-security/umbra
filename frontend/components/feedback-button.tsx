"use client"

import { FormEvent, useRef, useState } from "react"
import { MessageSquare } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { cn } from "@/lib/utils"
import { useFormToken } from "@/hooks/use-form-token"

type FeedbackButtonProps = {
  source: "landing" | "confidential"
  position?: "bottom-right" | "top-right"
}

const initialFormState = {
  name: "",
  email: "",
  message: "",
}

export function FeedbackButton({ source, position = "bottom-right" }: FeedbackButtonProps) {
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState(initialFormState)
  const [status, setStatus] = useState<"idle" | "loading" | "success" | "error">("idle")
  const [error, setError] = useState<string | null>(null)
  const honeypotRef = useRef<HTMLInputElement | null>(null)
  const { token: formToken, loading: formTokenLoading, error: formTokenError, refreshToken } = useFormToken()

  const resetForm = () => {
    setForm(initialFormState)
    setStatus("idle")
    setError(null)
  }

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (status === "loading") return

    const checkpointValue = honeypotRef.current?.value?.trim() ?? ""
    if (checkpointValue.length > 0) {
      setError("Unable to send feedback right now.")
      return
    }

    if (!formToken) {
      setError("Secure form token unavailable. Please try again.")
      void refreshToken()
      return
    }

    setStatus("loading")
    setError(null)

    try {
      const response = await fetch("/api/feedback", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          name: form.name,
          email: form.email,
          message: form.message,
          source,
          form_token: formToken,
          checkpoint: checkpointValue || undefined,
        }),
      })

      if (!response.ok) {
        const payload = await response.json().catch(() => null)
        throw new Error(payload?.error ?? "Unable to send feedback right now.")
      }

      setStatus("success")
      if (honeypotRef.current) {
        honeypotRef.current.value = ""
      }
      void refreshToken()
    } catch (err) {
      console.error("Feedback submission failed", err)
      setStatus("error")
      setError(err instanceof Error ? err.message : "Unable to send feedback right now.")
    }
  }

  const handleOpenChange = (nextOpen: boolean) => {
    setOpen(nextOpen)
    if (!nextOpen && status === "success") {
      resetForm()
    }
  }
  const placementClass =
    position === "top-right"
      ? "top-[calc(env(safe-area-inset-top,0)+16px)] right-4 sm:right-6 sm:top-[calc(env(safe-area-inset-top,0)+24px)]"
      : "bottom-[calc(env(safe-area-inset-bottom,0)+20px)] right-4 sm:bottom-6 sm:right-6"

  return (
    <div className={cn("fixed z-20 flex flex-col items-end gap-3 md:z-40", placementClass)}>
      <Button
        onClick={() => setOpen(true)}
        className="rounded-full bg-[#08070B] px-5 py-2 text-sm font-semibold text-white shadow-lg shadow-[#08070B]/30 hover:bg-[#1B0986]"
      >
        <MessageSquare className="size-4" />
        Give feedback
      </Button>
      <Dialog open={open} onOpenChange={handleOpenChange}>
        <DialogContent className="max-w-md border border-[#d4d3e6] bg-white/95 p-0 shadow-xl">
          <DialogHeader className="space-y-2 border-b border-[#d4d3e6]/60 px-6 py-4">
            <DialogTitle className="text-lg font-semibold text-[#08070B]">Private beta feedback</DialogTitle>
            <DialogDescription className="text-sm text-[#1F1E28]/80">
              Share what&apos;s working, what&apos;s broken, or what you&apos;d like to see next. We read every note.
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={handleSubmit} className="flex flex-col gap-4 px-6 py-5">
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
            <label className="text-sm font-medium text-[#1F1E28]">
              Name (optional)
              <input
                type="text"
                value={form.name}
                onChange={(event) => setForm((prev) => ({ ...prev, name: event.target.value }))}
                className="mt-1 w-full rounded-xl border border-[#d4d3e6] bg-white px-3 py-2 text-sm text-[#08070B] placeholder:text-[#1F1E28]/50 focus:border-[#1B0986] focus:outline-none"
                placeholder="Pat from Concrete Security"
                disabled={status === "loading" || status === "success"}
              />
            </label>
            <label className="text-sm font-medium text-[#1F1E28]">
              Email
              <input
                type="email"
                value={form.email}
                onChange={(event) => setForm((prev) => ({ ...prev, email: event.target.value }))}
                className="mt-1 w-full rounded-xl border border-[#d4d3e6] bg-white px-3 py-2 text-sm text-[#08070B] placeholder:text-[#1F1E28]/50 focus:border-[#1B0986] focus:outline-none"
                placeholder="you@company.com"
                required
                disabled={status === "loading" || status === "success"}
              />
            </label>
            <label className="text-sm font-medium text-[#1F1E28]">
              Feedback
              <textarea
                value={form.message}
                onChange={(event) => setForm((prev) => ({ ...prev, message: event.target.value }))}
                className="mt-1 min-h-[120px] w-full rounded-2xl border border-[#d4d3e6] bg-white px-3 py-3 text-sm text-[#08070B] placeholder:text-[#1F1E28]/50 focus:border-[#1B0986] focus:outline-none"
                placeholder="What should we improve before the public launch?"
                required
                disabled={status === "loading" || status === "success"}
              />
            </label>
            {error ? <p className="text-sm font-medium text-[#dc2626]">{error}</p> : null}
            {formTokenError ? <p className="text-sm font-medium text-amber-600">{formTokenError}</p> : null}
            {status === "success" ? (
              <p className="rounded-2xl border border-emerald-400/40 bg-emerald-400/10 px-3 py-2 text-sm text-emerald-900">
                Thanks for the signal. The team will review it shortly.
              </p>
            ) : null}
            <div className="flex items-center justify-between">
              <p className="text-xs text-[#1F1E28]/60">We&apos;ll reply if we need more context.</p>
              <Button
                type="submit"
                className="rounded-full bg-[#1B0986] px-5 py-2 text-sm font-semibold text-white hover:bg-[#120463]"
                disabled={status === "loading" || status === "success" || formTokenLoading || !formToken}
              >
                {status === "loading" ? "Sending…" : status === "success" ? "Sent" : "Send feedback"}
              </Button>
            </div>
          </form>
        </DialogContent>
      </Dialog>
    </div>
  )
}
