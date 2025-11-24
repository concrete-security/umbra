"use client"

import { Shield, Lock, Loader2 } from "lucide-react"
import { cn } from "@/lib/utils"

interface LoadingTransitionProps {
  message?: string
  className?: string
}

export function LoadingTransition({ message = "Establishing secure connection...", className }: LoadingTransitionProps) {
  return (
    <div
      className={cn(
        "fixed inset-0 z-50 flex items-center justify-center bg-[#E2E2E2]/95 backdrop-blur-md",
        "animate-in fade-in duration-300",
        className
      )}
    >
      <div className="relative flex flex-col items-center gap-6">
        <div
          className="pointer-events-none absolute inset-0 -translate-y-12 bg-[radial-gradient(circle_at_center,#102A8C_0%,transparent_70%)] opacity-20"
          aria-hidden="true"
        />
        <div className="relative flex items-center justify-center">
          <div className="absolute inset-0 animate-ping rounded-full bg-[#102A8C]/20" style={{ animationDuration: "2s" }} />
          <div className="relative flex size-20 items-center justify-center rounded-full border-2 border-[#102A8C]/30 bg-white shadow-lg">
            <Lock className="size-8 animate-pulse text-[#102A8C]" />
          </div>
        </div>
        <div className="flex flex-col items-center gap-3">
          <div className="flex items-center gap-2">
            <Loader2 className="size-4 animate-spin text-[#102A8C]" />
            <p className="text-sm font-medium text-black/70">{message}</p>
          </div>
          <div className="flex items-center gap-2 text-xs text-black/50">
            <Shield className="size-3" />
            <span>End-to-end encrypted</span>
          </div>
        </div>
      </div>
    </div>
  )
}
