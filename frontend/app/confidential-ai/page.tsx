"use client"

import { useState, FormEvent, KeyboardEvent, useMemo, useRef, useEffect, useCallback, Suspense, type CSSProperties } from "react"

import Link from "next/link"
import Image from "next/image"
import { useTheme } from "next-themes"
import {
  ArrowDown,
  Send,
  Lock,
  ShieldCheck,
  Cpu,
  CheckCircle2,
  Bot,
  Globe,
  Paperclip,
  FileText,
  X,
  Sparkles,
  Save,
  MessageSquarePlus,
  PanelLeftClose,
  PanelLeftOpen,
  Key,
  Sun,
  Moon,
  Info,
  Circle,
  UserCircle2,
  ChevronDown,
  AlertTriangle,
  ExternalLink,
} from "lucide-react"
import { Button } from "@/components/ui/button"
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion"
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { FeedbackButton } from "@/components/feedback-button"
import { streamConfidentialChat, confidentialChatConfig } from "@/lib/confidential-chat"
import { getAttestationServiceBaseUrl, isTdxQuoteSuccess, fetchTdxQuoteWithFallback, type TdxQuoteSuccessResponse } from "@/lib/attestation"
import { compareReportData, normalizeHex, verifyTdxQuoteWithFallback } from "@/lib/attestation-verifier"
import { Markdown } from "@/components/markdown"
import { cn } from "@/lib/utils"
import { createSupabaseBrowserClient } from "@/lib/supabase/client"
import { isAuthSessionMissingError } from "@/lib/supabase/errors"


type Message = {
  role: "user" | "assistant"
  content: string
  attachments?: UploadedFile[]
  reasoning_content?: string
  streaming?: boolean
  finishReason?: string
  reasoningStartTime?: number
  reasoningEndTime?: number
}
type UploadedFile = { name: string; content: string; size: number; type: string }

type HostParts = {
  host: string
  hostname: string
}

type StoredProviderSettings = {
  baseUrl?: string
}

type AttestationSummary = {
  teeType?: string | null
  tcbStatus?: string | null
  measurement?: string | null
  advisoryIds?: string[]
}

type ProofState =
  | { status: "idle" }
  | { status: "loading"; reportData: string; sourceBaseUrl: string }
  | {
      status: "ready"
      reportData: string
      payload: TdxQuoteSuccessResponse
      fetchedAt: number
      sourceBaseUrl: string
      attestation?: AttestationSummary
    }
  | { status: "error"; reportData: string; error: string; sourceBaseUrl: string }
  | { status: "unavailable"; reason?: string }

type RuntimeSignal = {
  label: string
  value: string
  description?: string
}

type VerificationState =
  | { status: "idle" }
  | { status: "running" }
  | {
      status: "success"
      quoteVerified: boolean
      reportDataMatches: boolean | null
      checksum?: string | null
      quoteHex?: string | null
      statusText?: string | null
      testMode?: boolean
      derivedReportData?: string | null
      advisoryIds?: string[]
      isOutOfDate?: boolean
    }
  | { status: "error"; error: string }

const PROVIDER_SETTINGS_STORAGE_KEY = "confidential-provider-settings-v1"
const PROVIDER_TOKEN_SESSION_KEY = "confidential-provider-token"
const HERO_MESSAGE_STORAGE_KEY = "hero-initial-message"
const HERO_FILES_STORAGE_KEY = "hero-uploaded-files"
const GUEST_USAGE_STORAGE_KEY = "confidential-chat-guest-used"
const GUEST_ACTIVE_SESSION_KEY = "confidential-chat-guest-active"
const GUEST_LIMITS_ENABLED = process.env.NEXT_PUBLIC_CONFIDENTIAL_ENABLE_GUEST_LIMITS === "true"

function normalize(value?: string | null): string | null {
  if (!value) return null
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : null
}

function parseHost(value?: string | null): HostParts | null {
  if (!value) return null
  try {
    const candidate = value.includes("://") ? value : `http://${value}`
    const url = new URL(candidate)
    const host = url.port ? `${url.hostname}:${url.port}` : url.hostname
    return { host, hostname: url.hostname }
  } catch {
    return null
  }
}

function isLoopbackHostname(hostname?: string | null) {
  if (!hostname) return false
  const normalized = hostname.toLowerCase()
  if (normalized === "localhost" || normalized === "::1" || normalized === "0.0.0.0") {
    return true
  }
  if (normalized.startsWith("127.")) {
    return true
  }
  return false
}

function sanitizeDisplayName(displayName: string | null) {
  if (!displayName) return null
  return displayName.toLowerCase().includes("vllm") ? null : displayName
}

function buildGreeting(model: string | null, displayName: string | null, host: string | null) {
  void model
  void displayName
  void host
  return "Secure channel with Umbra. How can I help you today?"
}

function truncateMiddle(str: string, maxLength: number = 40): string {
  if (str.length <= maxLength) return str
  const ellipsis = "..."
  const charsToShow = maxLength - ellipsis.length
  const frontChars = Math.ceil(charsToShow / 2)
  const backChars = Math.floor(charsToShow / 2)
  return str.slice(0, frontChars) + ellipsis + str.slice(-backChars)
}

function formatIdentifierSnippet(value: string, maxLength = 40) {
  if (!value) return "—"
  return truncateMiddle(value, maxLength)
}

function normalizeAttestationOrigin(value?: string | null): string | null {
  if (!value) return null
  const trimmed = value.trim()
  if (!trimmed) return null

  const candidate = trimmed.includes("://") ? trimmed : `https://${trimmed}`

  try {
    const url = new URL(candidate)
    if (url.protocol !== "https:" && !(url.protocol === "http:" && isLoopbackHostname(url.hostname))) {
      return null
    }
    return `${url.protocol}//${url.host}`
  } catch {
    return null
  }
}

function deriveAttestationOrigin(primary?: string | null, fallback?: string | null) {
  return normalizeAttestationOrigin(primary) ?? normalizeAttestationOrigin(fallback) ?? null
}

function getHostLabelFromUrl(value: string | null) {
  if (!value) return null
  try {
    return new URL(value).host
  } catch {
    return value
  }
}

function getReadableError(error: unknown): string {
  if (!error) return "Unknown error"
  if (typeof error === "string" && error.trim().length > 0) {
    return error.trim()
  }
  if (error instanceof Error && typeof error.message === "string" && error.message.trim().length > 0) {
    return error.message.trim()
  }
  if (typeof error === "object" && error !== null) {
    const message = (error as Record<string, unknown>).message
    if (typeof message === "string" && message.trim().length > 0) {
      return message.trim()
    }
  }
  return "Unknown error"
}

function generateReportData(bytes = 32) {
  if (typeof crypto === "undefined" || typeof crypto.getRandomValues !== "function") {
    throw new Error("Secure randomness is unavailable in this environment.")
  }
  const buffer = new Uint8Array(Math.max(1, bytes))
  crypto.getRandomValues(buffer)
  return Array.from(buffer, (value) => value.toString(16).padStart(2, "0")).join("")
}

function hexStringToUint8Array(value: string): Uint8Array | null {
  if (!value) return null
  const stripped = value.trim().toLowerCase().replace(/^0x/, "")
  if (!stripped || stripped.length === 0 || stripped.length % 2 !== 0) {
    return null
  }
  const bytes = new Uint8Array(stripped.length / 2)
  for (let index = 0; index < stripped.length; index += 2) {
    const byte = Number.parseInt(stripped.slice(index, index + 2), 16)
    if (Number.isNaN(byte)) {
      return null
    }
    bytes[index / 2] = byte
  }
  return bytes
}

function bytesToHex(value: Uint8Array) {
  return `0x${Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("")}`
}

async function deriveQuoteChecksum(quoteHex: string): Promise<string | null> {
  const normalized = normalizeHex(quoteHex)
  if (!normalized) {
    return null
  }
  const bytes = hexStringToUint8Array(normalized)
  if (!bytes) {
    return normalized
  }
  try {
    if (typeof crypto !== "undefined" && typeof crypto.subtle?.digest === "function") {
      const digest = await crypto.subtle.digest("SHA-256", bytes.slice().buffer)
      return bytesToHex(new Uint8Array(digest))
    }
  } catch (error) {
    console.warn("[Verification] Failed to derive checksum", error)
  }
  return normalized
}

function generateUUID(): string {
  if (typeof crypto === "undefined") {
    throw new Error("crypto is not available in this environment")
  }
  if (typeof crypto.randomUUID === "function") {
    return crypto.randomUUID()
  }
  if (typeof crypto.getRandomValues !== "function") {
    throw new Error("crypto.getRandomValues is not available in this environment")
  }
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  bytes[6] = (bytes[6] & 0x0f) | 0x40
  bytes[8] = (bytes[8] & 0x3f) | 0x80
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`
}

function formatTimestampLabel(timestamp: string) {
  const numeric = Number(timestamp)
  if (Number.isFinite(numeric) && numeric > 0) {
    try {
      return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" }).format(
        new Date(numeric * 1000)
      )
    } catch {
      return new Date(numeric * 1000).toLocaleString()
    }
  }
  return timestamp
}

function formatLocalTime(value: number) {
  try {
    return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" }).format(new Date(value))
  } catch {
    return new Date(value).toLocaleString()
  }
}

function summarizeQuote(value: unknown, maxLength = 84) {
  if (value == null) return "—"
  if (typeof value === "string") {
    return truncateMiddle(value, maxLength)
  }
  try {
    return truncateMiddle(JSON.stringify(value), maxLength)
  } catch {
    return "[unserializable quote payload]"
  }
}

function formatReportDataPreview(reportData: string) {
  if (!reportData) return "—"
  const candidate = reportData.startsWith("0x") ? reportData : `0x${reportData}`
  return truncateMiddle(candidate, 56)
}

function formatHexSnippet(value: string, max = 20) {
  const normalized = value.startsWith("0x") ? value.slice(2) : value
  if (!normalized) return "—"
  if (normalized.length <= max) {
    return `0x${normalized}`
  }
  const slice = Math.floor((max - 1) / 2)
  return `0x${normalized.slice(0, slice)}…${normalized.slice(-slice)}`
}

const runtimeEventDescriptors: Array<{ key: string; label: string; description?: string }> = [
  { key: "system-preparing", label: "System preparing" },
  { key: "app-id", label: "App ID", description: "Umbra workload identifier." },
  { key: "compose-hash", label: "Compose hash", description: "Container stack measurement." },
  { key: "instance-id", label: "Instance ID", description: "Unique CVM launch identifier." },
  { key: "mr-kms", label: "KMS measurement", description: "Key provider measurement." },
  { key: "os-image-hash", label: "OS image hash", description: "Measured OS image." },
  { key: "system-ready", label: "System ready" },
]

function extractRuntimeSignalsFromQuote(quote: unknown): RuntimeSignal[] {
  if (!quote || typeof quote !== "object") {
    return []
  }
  const typed = quote as Record<string, unknown>
  const rawLog = typed.event_log
  if (typeof rawLog !== "string" || rawLog.trim().length === 0) {
    return []
  }

  try {
    const parsed = JSON.parse(rawLog)
    if (!Array.isArray(parsed)) return []
    const lookup = new Map<string, Record<string, unknown>>()
    for (const item of parsed) {
      if (!item || typeof item !== "object") continue
      const entry = item as Record<string, unknown>
      const eventName = entry.event
      if (typeof eventName === "string" && eventName.trim().length > 0) {
        lookup.set(eventName.toLowerCase(), entry)
      }
    }

    const signals: RuntimeSignal[] = []
    for (const descriptor of runtimeEventDescriptors) {
      const entry = lookup.get(descriptor.key)
      if (!entry) continue
      const payload = typeof entry.event_payload === "string" && entry.event_payload.trim().length > 0 ? entry.event_payload : null
      const digest = typeof entry.digest === "string" && entry.digest.trim().length > 0 ? entry.digest : null
      const value = payload ?? digest
      signals.push({
        label: descriptor.label,
        value: value ? formatHexSnippet(value) : "Present",
        description: descriptor.description,
      })
    }
    return signals
  } catch {
    return []
  }
}

function ConfidentialAIContent() {
  const envProviderApiBase = normalize(confidentialChatConfig.providerApiBase)
  const envProviderModel = normalize(confidentialChatConfig.providerModel)
  const envProviderName = normalize(confidentialChatConfig.providerName)
  const attestationBaseUrl = getAttestationServiceBaseUrl()

  const [providerBaseUrlInput, setProviderBaseUrlInput] = useState(() => envProviderApiBase ?? "")
  const [providerApiKeyInput, setProviderApiKeyInput] = useState("")
  const [configError, setConfigError] = useState<string | null>(null)
  const [showAdvancedSettings, setShowAdvancedSettings] = useState(false)
  const [sessionDialogOpen, setSessionDialogOpen] = useState(false)
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const supabase = useMemo(() => {
    try {
      return createSupabaseBrowserClient()
    } catch (error) {
      if (process.env.NODE_ENV !== "production") {
        console.warn("Supabase client unavailable in confidential chat:", error)
      }
      return null
    }
  }, [])
  const [authState, setAuthState] = useState<"loading" | "signed-in" | "signed-out">(supabase ? "loading" : "signed-out")
  const [authUserEmail, setAuthUserEmail] = useState<string | null>(null)
  const [guestUsageRestricted, setGuestUsageRestricted] = useState(false)
  const [guestNotice, setGuestNotice] = useState<string | null>(null)
  const [proofState, setProofState] = useState<ProofState>({ status: "idle" })
  const [verificationState, setVerificationState] = useState<VerificationState>({ status: "idle" })
  const [proofDetailsModalOpen, setProofDetailsModalOpen] = useState(false)
  const proofAbortRef = useRef<AbortController | null>(null)

  const providerApiBase = normalize(providerBaseUrlInput)
  const derivedAttestationOrigin = useMemo(
    () => deriveAttestationOrigin(providerApiBase, attestationBaseUrl),
    [providerApiBase, attestationBaseUrl]
  )
  const providerModel = envProviderModel
  const sanitizedEnvDisplayName = sanitizeDisplayName(envProviderName)
  const sanitizedModelDisplayName = sanitizeDisplayName(providerModel)
  const providerDisplayName = sanitizedEnvDisplayName ?? sanitizedModelDisplayName

  const providerHostParts = useMemo(() => {
    if (providerApiBase) {
      return parseHost(providerApiBase)
    }
    if (envProviderApiBase) {
      return parseHost(envProviderApiBase)
    }
    return null
  }, [providerApiBase, envProviderApiBase])

  const providerHost = providerHostParts?.host ?? null

  const assistantName = (() => {
    if (providerDisplayName) {
      return providerDisplayName
    }
    if (!providerModel) {
      return "Umbra"
    }
    return /concrete/i.test(providerModel) ? "Umbra" : providerModel
  })()

  const connectionSummary = providerApiBase
    ? providerDisplayName
      ? `Direct connection to ${providerDisplayName}${providerHost ? ` via ${providerHost}` : ""}.`
      : providerModel
        ? `Direct connection to model ${providerModel}${providerHost ? ` via ${providerHost}` : ""}.`
        : providerHost
          ? `Direct connection via ${providerHost}.`
          : "Direct connection configured."
    : "Provide a confidential provider base URL to enable remote inference."
  const modelDisplayLabel = providerDisplayName ?? providerModel ?? null
  const modelDisplayTitle =
    modelDisplayLabel && providerModel && modelDisplayLabel !== providerModel ? providerModel : undefined
  const providerConfigured = Boolean(providerApiBase)
  const tokenPresent = providerApiKeyInput.trim().length > 0
  const guestLimitsEnabled = Boolean(supabase) && GUEST_LIMITS_ENABLED
  const connectionState: "connected" | "disconnected" = providerConfigured ? "connected" : "disconnected"
  const connectionLabel = providerConfigured ? "Connected" : "Not connected"
  const guestRestrictionActive = guestLimitsEnabled && authState === "signed-out" && guestUsageRestricted
  const authStatusLabel =
    !guestLimitsEnabled
      ? "Beta preview"
      : authState === "loading"
        ? "Checking access…"
        : authState === "signed-in"
          ? authUserEmail
            ? `Signed in as ${authUserEmail}`
            : "Signed in"
          : guestRestrictionActive
            ? "Guest preview · limit reached"
            : "Guest preview"

  const [messages, setMessages] = useState<Message[]>(() => [
    {
      role: "assistant",
      content: buildGreeting(providerModel, assistantName, providerHost),
    },
  ])

  const runtimeSignals = useMemo(() => {
    if (proofState.status !== "ready") return []
    return extractRuntimeSignalsFromQuote(proofState.payload.quote)
  }, [proofState])

  const quoteVerified =
    verificationState.status === "success" && verificationState.quoteVerified && verificationState.reportDataMatches === true
  const secureChannelReady = quoteVerified

  const applySupabaseSession = useCallback(
    (sessionUserEmail: string | null) => {
      setAuthState((previous) => {
        const next = sessionUserEmail ? "signed-in" : "signed-out"
        return previous === next ? previous : next
      })
      setAuthUserEmail((previous) => (previous === sessionUserEmail ? previous : sessionUserEmail))
    },
    []
  )

  useEffect(() => {
    const client = supabase
    if (!client) {
      applySupabaseSession(null)
      return
    }
    const authClient = client as NonNullable<typeof client>

    let mounted = true

    async function resolveInitialUser() {
      try {
        const { data, error } = await authClient.auth.getUser()
        if (!mounted) return
        if (error) {
          if (isAuthSessionMissingError(error)) {
            applySupabaseSession(null)
            return
          }
          console.error("Failed to resolve Supabase user", error)
          applySupabaseSession(null)
          return
        }
        applySupabaseSession(data.user?.email ?? null)
      } catch (error) {
        console.error("Unexpected error resolving Supabase user", error)
        if (mounted) {
          applySupabaseSession(null)
        }
      }
    }

    void resolveInitialUser()

    const {
      data: { subscription },
    } = authClient.auth.onAuthStateChange((_event: string, session: { user?: { email?: string | null } } | null) => {
      if (!mounted) return
      applySupabaseSession(session?.user?.email ?? null)
    })

    return () => {
      mounted = false
      subscription.unsubscribe()
    }
  }, [applySupabaseSession, supabase])

  useEffect(() => {
    if (!guestLimitsEnabled) {
      setGuestUsageRestricted(false)
      setGuestNotice(null)
      return
    }

    if (authState === "loading") {
      return
    }

    if (authState === "signed-in") {
      setGuestUsageRestricted(false)
      setGuestNotice(null)
      try {
        sessionStorage.removeItem(GUEST_ACTIVE_SESSION_KEY)
      } catch (error) {
        if (process.env.NODE_ENV !== "production") {
          console.warn("Failed to reset guest session flag", error)
        }
      }
      return
    }

    try {
      const alreadyUsed = localStorage.getItem(GUEST_USAGE_STORAGE_KEY)
      const activeSession = sessionStorage.getItem(GUEST_ACTIVE_SESSION_KEY)
      const locked = Boolean(alreadyUsed && !activeSession)
      setGuestUsageRestricted(locked)
      setGuestNotice(
        locked ? "You've already used your guest confidential session. Sign in to continue." : null
      )
    } catch (error) {
      console.warn("Failed to resolve guest usage state", error)
      setGuestUsageRestricted(false)
      setGuestNotice(null)
    }
  }, [authState, guestLimitsEnabled])

  useEffect(() => {
    if (typeof window === "undefined") return
    try {
      const raw = window.localStorage.getItem(PROVIDER_SETTINGS_STORAGE_KEY)
      if (raw) {
        const parsed = JSON.parse(raw) as StoredProviderSettings
        if (typeof parsed.baseUrl === "string") {
          setProviderBaseUrlInput(parsed.baseUrl)
        }
      }

      const storedToken = window.sessionStorage.getItem(PROVIDER_TOKEN_SESSION_KEY)
      if (typeof storedToken === "string") {
        setProviderApiKeyInput(storedToken)
      }
    } catch (error) {
      console.warn("Failed to restore provider settings", error)
    }
  }, [])

  useEffect(() => {
    if (typeof window === "undefined") return
    try {
      const payload: StoredProviderSettings = {
        baseUrl: providerBaseUrlInput,
      }
      window.localStorage.setItem(PROVIDER_SETTINGS_STORAGE_KEY, JSON.stringify(payload))
    } catch (error) {
      console.warn("Failed to persist provider settings", error)
    }
  }, [providerBaseUrlInput])

  useEffect(() => {
    if (typeof window === "undefined") return
    try {
      const trimmed = providerApiKeyInput.trim()
      if (trimmed) {
        window.sessionStorage.setItem(PROVIDER_TOKEN_SESSION_KEY, trimmed)
      } else {
        window.sessionStorage.removeItem(PROVIDER_TOKEN_SESSION_KEY)
      }
    } catch (error) {
      console.warn("Failed to persist provider token", error)
    }
  }, [providerApiKeyInput])

  useEffect(() => {
    if (configError && configError.includes("base URL") && providerApiBase) {
      setConfigError(null)
    }
  }, [configError, providerApiBase])

  useEffect(() => {
    setMessages((previous) => {
      if (previous.length === 0) return previous
      if (previous.some((message) => message.role === "user")) return previous

      const [first, ...rest] = previous
      if (first.role !== "assistant") return previous

      const updatedGreeting = buildGreeting(providerModel, assistantName, providerHost)
      if (first.content === updatedGreeting) return previous

      return [{ ...first, content: updatedGreeting }, ...rest]
    })
  }, [providerModel, assistantName, providerHost])
  
  const [input, setInput] = useState("")

  const [encrypting, setEncrypting] = useState(false)
  const [cipherPreview, setCipherPreview] = useState<string | null>(null)
  const [isSending, setIsSending] = useState(false)
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([])
  const [reasoningEffort, setReasoningEffort] = useState<"low" | "medium" | "high">("medium")
  const fileInputRef = useRef<HTMLInputElement>(null)
  const chatFormRef = useRef<HTMLFormElement | null>(null)
  const heroSubmissionRef = useRef<{ message: string; hasFiles: boolean } | null>(null)
  const heroAutoSubmitAttemptedRef = useRef(false)
  const sendMessageRef = useRef<((payload?: { text: string; files: UploadedFile[] }) => Promise<void>) | null>(null)
  const [heroSubmissionVersion, setHeroSubmissionVersion] = useState(0)

  useEffect(() => {
    try {
      const storedMessage = sessionStorage.getItem(HERO_MESSAGE_STORAGE_KEY)
      const storedFiles = sessionStorage.getItem(HERO_FILES_STORAGE_KEY)

      if (storedMessage === null && !storedFiles) {
        return
      }

      let parsedFiles: UploadedFile[] = []
      if (storedFiles) {
        try {
          parsedFiles = JSON.parse(storedFiles) as UploadedFile[]
        } catch (error) {
          console.error("Failed to parse hero files", error)
        }
      }

      if (parsedFiles.length > 0) {
        setUploadedFiles(parsedFiles)
      }

      const message = storedMessage ?? ""
      const hasMessage = message.trim().length > 0
      const hasFiles = parsedFiles.length > 0

      if (hasMessage) {
        setInput(message)
      } else if (hasFiles) {
        setInput("")
      }

      if (hasMessage || hasFiles) {
        heroSubmissionRef.current = { message, hasFiles }
        setHeroSubmissionVersion((previous) => previous + 1)
      }

      sessionStorage.removeItem(HERO_MESSAGE_STORAGE_KEY)
      sessionStorage.removeItem(HERO_FILES_STORAGE_KEY)
    } catch (error) {
      console.error("Failed to restore hero submission", error)
    }
  }, [])

  // ref that will serve as the "scroll anchor" for the chat bottom
  const messagesEndRef = useRef<HTMLDivElement | null>(null)
  const messagesContainerRef = useRef<HTMLDivElement | null>(null)
  const lastScrollTopRef = useRef(0)
  const isProgrammaticScrollRef = useRef(false)

  // Scroll behavior state
  const [reasoningOpen, setReasoningOpen] = useState<Record<number, boolean>>({})
  const [isPinnedToBottom, setIsPinnedToBottom] = useState(true)
  const [hasNewMessages, setHasNewMessages] = useState(false)
  const [autoScrollEnabled, setAutoScrollEnabled] = useState(true)
  const autoScrollRef = useRef(autoScrollEnabled)

  const updateAutoScrollEnabled = useCallback((value: boolean) => {
    autoScrollRef.current = value
    setAutoScrollEnabled(value)
  }, [])

  const { theme: currentTheme, resolvedTheme, setTheme } = useTheme()
  const [themeReady, setThemeReady] = useState(false)
  const [cacheSalt, setCacheSalt] = useState<string | null>(null)

  useEffect(() => {
    setThemeReady(true)
  }, [])

  useEffect(() => {
    const CACHE_SALT_KEY = "confidential-ai-cache-salt"
    let salt = localStorage.getItem(CACHE_SALT_KEY)
    if (!salt) {
      salt = generateUUID()
      localStorage.setItem(CACHE_SALT_KEY, salt)
    }
    setCacheSalt(salt)
  }, [])

  const activeTheme = (currentTheme === "system" ? resolvedTheme : currentTheme) ?? "light"
  const isStreaming = useMemo(() => messages.some((message) => message.streaming), [messages])
  const hasConversationHistory = useMemo(
    () => messages.some((message) => message.role === "user") || messages.length > 1,
    [messages]
  )
  const showScrollToLatest = !isPinnedToBottom || hasNewMessages
  const toHexPreview = (s: string) => {
    try {
      const hex = Array.from(s)
        .map((ch) => ch.charCodeAt(0).toString(16).padStart(2, "0"))
        .join("")
        .slice(0, 48)
      return `0x${hex}${s.length > 24 ? "…" : ""}`
    } catch {
      return "0x…"
    }
  }

  const runQuoteVerification = useCallback(
    async (quote: TdxQuoteSuccessResponse, expectedReportData: string): Promise<boolean> => {
      const rawQuote = quote.quote as Record<string, unknown> | undefined
      const quoteHex = typeof rawQuote?.quote === "string" ? rawQuote.quote : null
      if (!quoteHex) {
        console.error("[Verification] Quote payload missing")
        setVerificationState({ status: "error", error: "Quote payload missing." })
        return false
      }

      const attestedReportData =
        typeof rawQuote?.report_data === "string" && rawQuote.report_data.trim().length > 0
          ? rawQuote.report_data
          : expectedReportData

      console.log("[Verification] Starting DCAP verification", {
        reportData: formatReportDataPreview(attestedReportData),
        quoteLength: quoteHex.length,
      })
      setVerificationState({ status: "running" })
      try {
        const forceTestMode = quote.test_mode === true
        const result = await verifyTdxQuoteWithFallback(quoteHex, { forceTestMode })

        console.log("[Verification] dcap-qvl result:", JSON.stringify(result, null, 2))

        const statusTextRaw =
          typeof result?.verifiedReport?.status === "string" ? result.verifiedReport.status.trim() : null
        const statusText = statusTextRaw && statusTextRaw.length > 0 ? statusTextRaw : null
        const testMode = result?.metadata?.testMode === true
        const advisoryIds = Array.isArray(result?.verifiedReport?.advisory_ids)
          ? result.verifiedReport.advisory_ids.filter((id): id is string => typeof id === "string" && id.trim().length > 0)
          : []
        const derivedReportData = result?.reportDataHex ?? null
        const reportDataMatches = testMode ? true : compareReportData(attestedReportData, derivedReportData)
        const statusLower = statusText?.toLowerCase() ?? ""
        const isOutOfDate = statusLower === "outofdate"
        const verificationPassed = testMode ? true : Boolean(statusText && (statusLower === "uptodate" || isOutOfDate))
        const checksum = await deriveQuoteChecksum(quoteHex)

        console.log("[Verification] Verification completed", {
          statusText,
          quoteVerified: verificationPassed,
          reportDataMatches,
          checksum: checksum ? formatHexSnippet(checksum) : null,
          checksumRaw: checksum,
          testMode,
          advisoryCount: advisoryIds.length,
          quoteHexLength: quoteHex.length,
        })

        setVerificationState({
          status: "success",
          quoteVerified: verificationPassed,
          reportDataMatches,
          checksum,
          quoteHex,
          statusText,
          testMode,
          derivedReportData,
          advisoryIds,
          isOutOfDate,
        })
        return verificationPassed && reportDataMatches === true
      } catch (error) {
        console.error("[Verification] Verification error", error)
        setVerificationState({ status: "error", error: getReadableError(error) })
        return false
      }
    },
    []
  )

  const refreshProof = useCallback(async () => {
    const baseUrl = deriveAttestationOrigin(providerApiBase, attestationBaseUrl)
    if (!baseUrl) {
      console.warn("[Attestation] Cannot fetch quote: no attestation origin configured")
      setProofState({
        status: "unavailable",
        reason: "Provide a confidential provider base URL or set NEXT_PUBLIC_ATTESTATION_BASE_URL to fetch quotes.",
      })
      setVerificationState({ status: "idle" })
      return
    }

    proofAbortRef.current?.abort()
    const controller = new AbortController()
    proofAbortRef.current = controller

    let reportData: string
    try {
      reportData = generateReportData()
    } catch (error) {
      const readable = getReadableError(error)
      console.error("[Attestation] Unable to generate report data", error)
      setProofState({ status: "error", reportData: "", error: readable, sourceBaseUrl: baseUrl })
      setVerificationState({ status: "idle" })
      return
    }

    console.log("[Attestation] Starting attestation request", { baseUrl, reportData: formatReportDataPreview(reportData) })
    setProofState({ status: "loading", reportData, sourceBaseUrl: baseUrl })
    setVerificationState({ status: "idle" })

    try {
      const parsed = await fetchTdxQuoteWithFallback(baseUrl, reportData, {
        signal: controller.signal,
      })

      console.log("[Attestation] Quote fetched successfully", { 
        quoteType: parsed.quote_type, 
        timestamp: parsed.timestamp,
        sourceBaseUrl: baseUrl 
      })
      setProofState({ status: "ready", reportData, payload: parsed, fetchedAt: Date.now(), sourceBaseUrl: baseUrl })
      const verified = await runQuoteVerification(parsed, reportData)
      if (!verified) {
        return
      }
    } catch (error) {
      if ((error as Error)?.name === "AbortError") {
        console.log("[Attestation] Quote request aborted")
        return
      }
      console.error("[Attestation] Error fetching quote", error)
      setProofState({ status: "error", reportData, error: getReadableError(error), sourceBaseUrl: baseUrl })
    }
  }, [providerApiBase, attestationBaseUrl, runQuoteVerification])

  const handleProofRefresh = useCallback(async () => {
    await refreshProof()
  }, [refreshProof])


    useEffect(() => {
    void refreshProof()
    return () => {
      proofAbortRef.current?.abort()
    }
  }, [refreshProof])

  const ProofContent = ({
    variant,
    verificationState,
    runtimeSignals,
    onViewDetails,
  }: {
    variant: "sidebar" | "dialog"
    verificationState: VerificationState
    runtimeSignals: RuntimeSignal[]
    onViewDetails?: () => void
  }) => {
    const isCompact = variant === "sidebar"
    const badgeBase =
      "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.24em]"
    const runtimePreview = runtimeSignals.slice(0, 4)
    const runtimeOverflow = runtimeSignals.length - runtimePreview.length

    const activeSourceBaseUrl =
      proofState.status === "ready" || proofState.status === "loading" || proofState.status === "error"
        ? proofState.sourceBaseUrl
        : derivedAttestationOrigin

    const hostLabel = getHostLabelFromUrl(activeSourceBaseUrl) ?? "Umbra CVM attestation endpoint"

    const baseConnectionCopy = activeSourceBaseUrl
      ? `Intel TDX quote fetched from ${hostLabel}.`
      : "Connect to your Umbra CVM origin to fetch attestation quotes."
    const connectionCopy = baseConnectionCopy

    const refreshDisabled =
      proofState.status === "loading" || !derivedAttestationOrigin || verificationState.status === "running"

    const statusBadge = (() => {
      switch (proofState.status) {
        case "ready":
          return (
            <div className={cn(badgeBase, "border-[#1BAF9F]/60 bg-[#1BAF9F]/10 text-[#037C6A]")}>
              <CheckCircle2 className="h-3.5 w-3.5" /> Fetched
            </div>
          )
        case "loading":
          return (
            <div className={cn(badgeBase, "border-brand-primary/40 bg-brand-primary/10 text-brand-primary")}>
              <Sparkles className="h-3.5 w-3.5" /> Fetching
            </div>
          )
        case "error":
          return (
            <div className={cn(badgeBase, "border-rose-400/60 bg-rose-400/10 text-rose-600")}> 
              <X className="h-3.5 w-3.5" /> Error
            </div>
          )
        case "unavailable":
          return (
            <div className={cn(badgeBase, "border-border/70 bg-transparent text-muted-foreground")}>Config</div>
          )
        default:
          return (
            <div className={cn(badgeBase, "border-border/60 bg-card/40 text-muted-foreground")}>Pending</div>
          )
      }
    })()

    type ChecklistState = "pending" | "running" | "ok" | "error"
    const quoteState: ChecklistState =
      proofState.status === "loading"
        ? "running"
        : proofState.status === "ready"
          ? "ok"
          : proofState.status === "error"
            ? "error"
            : "pending"
    const machineSecureState: ChecklistState =
      proofState.status === "loading"
        ? "running"
        : proofState.status === "ready" && verificationState.status === "success" && verificationState.quoteVerified && verificationState.reportDataMatches === true
          ? "ok"
          : proofState.status === "error" || verificationState.status === "error"
            ? "error"
            : "pending"

    const checklistItems: Array<{ label: string; description: string; state: ChecklistState }> = [
      {
        label: "Quote fetched",
        description: connectionCopy,
        state: quoteState,
      },
      {
        label: "Machine is secure",
        description: "Attestation verified and secure",
        state: machineSecureState,
      },
    ]

    const renderChecklistIcon = (state: ChecklistState) => {
      switch (state) {
        case "ok":
          return <CheckCircle2 className="h-4 w-4 text-emerald-600" />
        case "running":
          return <Sparkles className="h-4 w-4 text-brand-primary animate-pulse" />
        case "error":
          return <X className="h-4 w-4 text-rose-600" />
        default:
          return <Circle className="h-4 w-4 text-muted-foreground" />
      }
    }

    const body = (() => {
      switch (proofState.status) {
        case "ready": {
          const isVerified =
            verificationState.status === "success" &&
            verificationState.quoteVerified &&
            verificationState.reportDataMatches === true
          return (
            <div className={cn("space-y-2", isCompact ? "text-xs" : "text-sm")}>
              <div
                className={cn(
                  "flex items-center gap-2 rounded-2xl border px-3 py-2.5 shadow-sm",
                  isVerified && !verificationState.isOutOfDate
                    ? "border-emerald-400/60 bg-emerald-400/10 text-emerald-600 dark:border-emerald-400/40 dark:bg-emerald-400/5"
                    : verificationState.status === "success" && verificationState.isOutOfDate
                      ? "border-amber-400/60 bg-amber-400/10 text-amber-700 dark:border-amber-400/40 dark:bg-amber-400/5 dark:text-amber-300"
                      : verificationState.status === "success"
                        ? "border-rose-400/60 bg-rose-400/10 text-rose-600 dark:border-rose-400/40 dark:bg-rose-400/5"
                        : verificationState.status === "running"
                          ? "border-brand-primary/60 bg-brand-primary/10 text-brand-primary dark:border-brand-primary/40 dark:bg-brand-primary/5"
                          : "border-border/40 bg-card/70 text-muted-foreground dark:border-border/60 dark:bg-card/10"
                )}
              >
                {onViewDetails && (
                  <button
                    type="button"
                    onClick={onViewDetails}
                    className="absolute -top-2 -right-2 h-6 w-6 rounded-full border border-border/40 bg-card/80 text-muted-foreground hover:bg-card/90 hover:text-foreground shadow-sm dark:border-border/60 dark:bg-card/40 dark:hover:bg-card/50 flex items-center justify-center transition z-10"
                    title="View details"
                  >
                    <ChevronDown className="h-3.5 w-3.5" />
                  </button>
                )}
                {verificationState.status === "idle" && (
                  <>
                    <Info className="h-4 w-4" />
                    <span className="text-xs">Verification pending</span>
                  </>
                )}
                {verificationState.status === "running" && (
                  <>
                    <Sparkles className="h-4 w-4 animate-pulse" />
                    <span className="text-xs">Verifying attestation…</span>
                  </>
                )}
                {verificationState.status === "error" && (
                  <>
                    <X className="h-4 w-4" />
                    <span className="text-xs truncate" title={verificationState.error}>{verificationState.error}</span>
                  </>
                )}
                {verificationState.status === "success" && (
                  <>
                    {isVerified && !verificationState.isOutOfDate ? (
                      <>
                        <Lock className="h-4 w-4" />
                        <span className="text-xs font-medium">Verified and secure</span>
                      </>
                    ) : isVerified && verificationState.isOutOfDate ? (
                      <>
                        <AlertTriangle className="h-4 w-4" />
                        <span className="text-xs font-medium">Verified (update recommended)</span>
                      </>
                    ) : (
                      <>
                        <X className="h-4 w-4" />
                        <span className="text-xs font-medium">Verification failed</span>
                      </>
                    )}
                  </>
                )}
              </div>
            </div>
          )
        }
        case "loading": {
          return (
            <div
              className={cn(
                "rounded-2xl border border-border/40 bg-card/70 px-3 py-2 text-muted-foreground shadow-sm dark:border-border/60 dark:bg-card/20",
                isCompact ? "text-xs" : "text-sm"
              )}
            >
              Requesting quote for
              <span className="ml-1 font-mono text-foreground">
                {formatReportDataPreview(proofState.reportData)}
              </span>
              …
            </div>
          )
        }
        case "error":
          return (
            <div className={cn("space-y-2", isCompact ? "text-xs" : "text-sm")}> 
              <div className="rounded-2xl border border-destructive/40 bg-destructive/10 px-3 py-2 text-destructive">
                {proofState.error}
              </div>
              <p className="text-muted-foreground">
                Challenge: <span className="font-mono text-foreground">{formatReportDataPreview(proofState.reportData)}</span>
              </p>
            </div>
          )
        case "unavailable":
          return (
            <div
              className={cn(
                "rounded-2xl border border-border/40 bg-card/60 px-3 py-2 text-muted-foreground dark:border-border/60 dark:bg-card/10",
                isCompact ? "text-xs" : "text-sm"
              )}
            >
              {proofState.reason ?? "Configure NEXT_PUBLIC_ATTESTATION_BASE_URL to enable live quotes."}
            </div>
          )
        case "idle":
        default:
          return (
            <div
              className={cn(
                "rounded-2xl border border-border/40 bg-card/60 px-3 py-2 text-muted-foreground dark:border-border/60 dark:bg-card/15",
                isCompact ? "text-xs" : "text-sm"
              )}
            >
              Preparing attestation challenge…
            </div>
          )
      }
    })()

    return (
      <div className="space-y-3">
        <div className="space-y-2">
          <div className={cn("flex items-start justify-between gap-3", !isCompact && "gap-4")}>
            <div className="flex items-start gap-3">
              <div className={cn("rounded-full border border-brand-primary/40 bg-brand-primary/10 text-brand-primary", isCompact ? "p-2" : "p-3")}> 
                <Cpu className={cn("text-brand-primary", isCompact ? "h-4 w-4" : "h-5 w-5")} />
              </div>
              <div className="space-y-1">
                <p className={cn("font-semibold text-foreground", isCompact ? "text-sm" : "text-base")}>Intel TDX Quote</p>
              </div>
            </div>
            {statusBadge}
          </div>
          <p className={cn("text-muted-foreground w-full", isCompact ? "text-[11px]" : "text-sm")}>{connectionCopy}</p>
        </div>
        <div className="rounded-2xl border border-border/40 bg-card/70 p-3 shadow-sm dark:border-border/60 dark:bg-card/15">
          <p className="text-[10px] uppercase tracking-[0.32em] text-muted-foreground/80 mb-2">
            Attestation checklist
          </p>
          <div className="space-y-2">
            {checklistItems.map((item) => (
              <div key={item.label} className="flex items-start gap-3">
                <div className="mt-0.5">{renderChecklistIcon(item.state)}</div>
                <div className="space-y-0.5">
                  <p className="text-xs font-semibold text-foreground">{item.label}</p>
                  <p className="text-[11px] text-muted-foreground">{item.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
        {body}
        <div className="flex flex-wrap gap-2">
          <Button
            type="button"
            variant="secondary"
            size={isCompact ? "sm" : "default"}
            onClick={handleProofRefresh}
            disabled={refreshDisabled}
            className="rounded-full"
          >
            {verificationState.status === "running" ? "Refreshing…" : "Refresh & verify"}
          </Button>
        </div>
      </div>
    )
  }

  const ProofDetailsModal = () => {
    if (proofState.status !== "ready") return null

    const issuedAt = formatTimestampLabel(proofState.payload.timestamp)
    const refreshedAt = formatLocalTime(proofState.fetchedAt)
    const quotePreview = summarizeQuote(proofState.payload.quote)
    const activeSourceBaseUrl = proofState.sourceBaseUrl ?? derivedAttestationOrigin
    const hostLabel = getHostLabelFromUrl(activeSourceBaseUrl) ?? "Umbra CVM attestation endpoint"

    return (
      <Dialog open={proofDetailsModalOpen} onOpenChange={setProofDetailsModalOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto border border-border/50 bg-background/95 backdrop-blur dark:border-border/60 dark:bg-background/80">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-lg font-semibold">
              <ShieldCheck className="h-5 w-5 text-brand-primary" />
              Proof of Confidentiality Details
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-foreground">Attestation Information</h3>
              <div className="rounded-2xl border border-border/40 bg-card/80 p-3 shadow-sm dark:border-border/60 dark:bg-card/20">
                <dl className="space-y-2 text-sm">
                  <div className="flex items-center justify-between">
                    <dt className="text-muted-foreground">Challenge</dt>
                    <dd className="font-mono text-[#102A8C]">{formatReportDataPreview(proofState.reportData)}</dd>
                  </div>
                  <div className="flex items-center justify-between">
                    <dt className="text-muted-foreground">TEE</dt>
                    <dd className="font-mono text-foreground/80 uppercase">
                      {proofState.attestation?.teeType || proofState.payload.quote_type || "tdx"}
                    </dd>
                  </div>
                  <div className="flex items-center justify-between">
                    <dt className="text-muted-foreground">TCB status</dt>
                    <dd className="font-mono text-foreground/80">
                      {proofState.attestation?.tcbStatus || "Unknown"}
                    </dd>
                  </div>
                  <div className="flex items-center justify-between">
                    <dt className="text-muted-foreground">Measurement</dt>
                    <dd className="font-mono text-brand-primary">
                      {formatIdentifierSnippet(proofState.attestation?.measurement ?? "—")}
                    </dd>
                  </div>
                  <div className="flex items-center justify-between">
                    <dt className="text-muted-foreground">Advisories</dt>
                    <dd className="font-mono text-foreground/80">{proofState.attestation?.advisoryIds?.length ?? 0}</dd>
                  </div>
                  <div className="flex items-center justify-between">
                    <dt className="text-muted-foreground">Last refreshed</dt>
                    <dd className="font-mono text-foreground/80">{refreshedAt}</dd>
                  </div>
                  <div className="flex items-center justify-between">
                    <dt className="text-muted-foreground">Machine endpoint</dt>
                    <dd className="font-mono text-foreground/80">{hostLabel}</dd>
                  </div>
                </dl>
              </div>
            </div>

            <Accordion type="single" collapsible className="w-full">
              <AccordionItem value="technical-details" className="border-none">
                <AccordionTrigger className="text-sm font-semibold text-foreground py-2 hover:no-underline">
                  Technical Details
                </AccordionTrigger>
                <AccordionContent>
                  <div className="rounded-2xl border border-border/40 bg-background/70 p-3 font-mono text-[11px] leading-relaxed text-foreground/90 shadow-inner dark:border-border/60 dark:bg-background/30 max-h-[200px] overflow-y-auto">
                    <p className="text-[10px] uppercase tracking-[0.28em] text-muted-foreground/70 mb-2">Quote excerpt</p>
                    <p className="break-all">{quotePreview}</p>
                  </div>
                </AccordionContent>
              </AccordionItem>
            </Accordion>

            {runtimeSignals.length > 0 && (
              <div className="space-y-3">
                <h3 className="text-sm font-semibold text-foreground">Runtime Attestations</h3>
                <div className="rounded-2xl border border-border/40 bg-card/80 p-3 shadow-sm dark:border-border/60 dark:bg-card/15 max-h-[300px] overflow-y-auto">
                  <div className="space-y-2">
                    {runtimeSignals.map((signal) => (
                      <div key={signal.label} className="flex items-start justify-between gap-3">
                        <div className="space-y-0.5">
                          <p className="text-xs font-medium text-foreground">{signal.label}</p>
                          {signal.description && (
                            <p className="text-[11px] text-muted-foreground">{signal.description}</p>
                          )}
                        </div>
                        <span className="font-mono text-[11px] text-[#102A8C]">{signal.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-foreground">Verification Status</h3>
              <div className="rounded-2xl border border-border/40 bg-card/70 p-3 shadow-sm dark:border-border/60 dark:bg-card/10">
                {verificationState.status === "idle" && (
                  <p className="text-xs text-muted-foreground">Verification not yet performed.</p>
                )}
                {verificationState.status === "running" && (
                  <p className="text-xs text-muted-foreground">Verifying machine attestation…</p>
                )}
                {verificationState.status === "error" && (
                  <p className="text-xs text-rose-600">{verificationState.error}</p>
                )}
                {verificationState.status === "success" && (
                  <div className="space-y-2 text-xs">
                    <p
                      className={cn(
                        "flex items-center gap-2",
                        verificationState.quoteVerified && verificationState.reportDataMatches === true
                          ? "text-emerald-600"
                          : "text-rose-600"
                      )}
                    >
                      {verificationState.quoteVerified && verificationState.reportDataMatches === true ? (
                        <CheckCircle2 className="h-3.5 w-3.5" />
                      ) : (
                        <X className="h-3.5 w-3.5" />
                      )}
                      <span className="font-medium">
                        Status:{" "}
                        {verificationState.quoteVerified && verificationState.reportDataMatches === true ? "Verified and secure" : "Verification failed"}
                      </span>
                    </p>
                    {verificationState.statusText && (
                      <p className="text-xs text-muted-foreground">
                        Security status: <span className={cn("font-semibold", verificationState.isOutOfDate ? "text-amber-600" : "text-foreground")}>{verificationState.statusText === "OutOfDate" ? "Update recommended" : verificationState.statusText}</span>
                      </p>
                    )}
                    {verificationState.isOutOfDate && (
                      <div className="rounded-lg border border-amber-400/60 bg-amber-400/10 p-2.5 space-y-1.5 dark:border-amber-400/40 dark:bg-amber-400/5">
                        <div className="flex items-start gap-2">
                          <AlertTriangle className="h-3.5 w-3.5 shrink-0 text-amber-600 mt-0.5 dark:text-amber-400" />
                          <div className="flex-1 space-y-1">
                            <p className="text-xs font-medium text-amber-700 dark:text-amber-300">Security update recommended</p>
                            <p className="text-[11px] text-amber-600 dark:text-amber-400 leading-relaxed">
                              The service is working normally, but the provider should apply security updates.
                            </p>
                          </div>
                        </div>
                      </div>
                    )}
                    {verificationState.testMode && (
                      <p className="text-xs text-amber-600">Test mode enabled — verification simulated for automated checks.</p>
                    )}
                    {verificationState.reportDataMatches !== null && (
                      <p className={cn("text-xs", verificationState.reportDataMatches ? "text-emerald-600" : "text-rose-600")}>
                        Challenge Verification: {verificationState.reportDataMatches ? "matches" : "mismatch"}
                      </p>
                    )}
                    {verificationState.advisoryIds && verificationState.advisoryIds.length > 0 && (
                      <div className="pt-2 border-t border-border/40 dark:border-border/60 space-y-1">
                        <p className="text-xs text-muted-foreground">Security Advisories:</p>
                        <div className="flex flex-wrap gap-1">
                          {verificationState.advisoryIds.map((advisory) => (
                            <span
                              key={advisory}
                              className="rounded-full border border-border/50 px-2 py-0.5 text-[10px] text-muted-foreground"
                            >
                              {advisory}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>

            {verificationState.status === "success" && verificationState.checksum && (
              <Accordion type="single" collapsible className="w-full">
                <AccordionItem value="advanced-details" className="border-none">
                  <AccordionTrigger className="text-sm font-semibold text-foreground py-2 hover:no-underline">
                    Advanced Details
                  </AccordionTrigger>
                  <AccordionContent>
                    <div className="rounded-2xl border border-border/40 bg-card/70 p-3 shadow-sm dark:border-border/60 dark:bg-card/10 space-y-3">
                      <div className="space-y-2">
                        <div className="flex items-center justify-between gap-2">
                          <span className="text-xs text-muted-foreground">SHA-256 checksum:</span>
                          <div className="flex items-center gap-2 flex-1 justify-end min-w-0">
                            <code className="font-mono text-[10px] text-brand-primary break-all text-right truncate max-w-[200px]" title={verificationState.checksum}>
                              {verificationState.checksum}
                            </code>
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                const checksumToCopy = verificationState.checksum!
                                console.log("[Checksum] Copying checksum from modal:", checksumToCopy, "Length:", checksumToCopy.length)
                                navigator.clipboard.writeText(checksumToCopy).then(() => {
                                  console.log("[Checksum] Successfully copied to clipboard")
                                }).catch((err) => {
                                  console.error("[Checksum] Failed to copy:", err)
                                })
                              }}
                              className="h-5 w-5 p-0 shrink-0"
                              title="Copy checksum (without 0x prefix)"
                            >
                              <Save className="h-3 w-3" />
                            </Button>
                          </div>
                        </div>
                        <div className="space-y-2">
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() => {
                              const quoteHex = verificationState.quoteHex || ""
                              console.log("[Quote] Copying raw quote hex, length:", quoteHex.length)
                              navigator.clipboard.writeText(quoteHex).then(() => {
                                console.log("[Quote] Successfully copied quote hex to clipboard")
                                alert("Quote hex copied! Paste it into the TEE Attestation Explorer.")
                              }).catch((err) => {
                                console.error("[Quote] Failed to copy:", err)
                              })
                            }}
                            className="w-full rounded-full text-xs"
                            disabled={!verificationState.quoteHex}
                          >
                            <Save className="h-3 w-3 mr-2" />
                            Copy raw quote hex (for TEE Explorer)
                          </Button>
                          {verificationState.checksum && (
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              onClick={() => {
                                const checksumForUrl = verificationState.checksum || ""
                                console.log("[Checksum] Opening TEE Explorer with checksum:", checksumForUrl, "Length:", checksumForUrl.length)
                                console.log("[Checksum] Full URL:", `https://proof.t16z.com/reports/${checksumForUrl}`)
                                window.open(`https://proof.t16z.com/reports/${checksumForUrl}`, '_blank')
                              }}
                              className="w-full rounded-full text-xs"
                            >
                              <Globe className="h-3 w-3 mr-2" />
                              View on TEE Attestation Explorer (if already uploaded)
                            </Button>
                          )}
                        </div>
                      </div>
                    </div>
                  </AccordionContent>
                </AccordionItem>
              </Accordion>
            )}
          </div>
        </DialogContent>
      </Dialog>
    )
  }

  // Upload files
  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    if (guestRestrictionActive) {
      return
    }
    const files = event.target.files
    if (!files) return

    for (let i = 0; i < files.length; i++) {
      const file = files[i]

      // Check file size (limit to 100MB for all files)
      const maxSize = 100 * 1024 * 1024 
      if (file.size > maxSize) {
        const maxSizeText = '100MB'
        alert(`File "${file.name}" is too large. Maximum size is ${maxSizeText}.`)
        continue
      }

      try {
        let content: string

        if (file.type === 'application/pdf') {
          // ici
          content = await extractTextFromPDF(file)
        } else {
          content = await file.text()
        }

        const uploadedFile: UploadedFile = {
          name: file.name,
          content,
          size: file.size,
          type: file.type || 'text/plain'
        }

        setUploadedFiles(prev => [...prev, uploadedFile])
      } catch (error) {
        console.error('Error reading file:', error)
        alert(`Failed to read file "${file.name}": ${error instanceof Error ? error.message : 'Unknown error'}`)
      }
    }

    // Reset the input
    if (fileInputRef.current) {
      fileInputRef.current.value = ''
    }
  }

  const removeFile = (index: number) => {
    setUploadedFiles(prev => prev.filter((_, i) => i !== index))
  }

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const countWords = (text: string) => {
    return text.trim().split(/\s+/).filter(word => word.length > 0).length
  }

  const formatWordCount = (count: number) => {
    return count === 1 ? '1 word' : `${count} words`
  }
  // Extract only text
  const extractTextFromPDF = async (file: File): Promise<string> => {
    try {
      const pdfModuleUrl = `${window.location.origin}/pdfjs/pdf.mjs`
      const pdfWorkerUrl = `${window.location.origin}/pdfjs/pdf.worker.mjs`
      const pdfjsLibModule = await import(/* webpackIgnore: true */ pdfModuleUrl)
      const pdfjsLib = (pdfjsLibModule as unknown as { default?: any }).default ?? (window as any).pdfjsLib ?? pdfjsLibModule

      pdfjsLib.GlobalWorkerOptions.workerSrc = pdfWorkerUrl

      const arrayBuffer = await file.arrayBuffer()
      const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise
      let text = ''

      for (let i = 1; i <= pdf.numPages; i++) {
        const page = await pdf.getPage(i)
        const textContent = await page.getTextContent()
        const pageText = textContent.items
          .map((item: any) => ("str" in item ? item.str : ""))
          .join(' ')
        text += pageText + '\n'
      }
      return text.trim()
    } catch (error) {
      console.error('Error extracting text from PDF:', error)
      throw new Error('Failed to extract text from PDF')
    }
  }


  const scrollToBottom = useCallback((behavior: ScrollBehavior = "smooth") => {
    isProgrammaticScrollRef.current = true

    if (messagesContainerRef.current) {
      messagesContainerRef.current.scrollTo({
        top: messagesContainerRef.current.scrollHeight,
        behavior,
      })
    }

    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior, block: "end" })
    }

    window.requestAnimationFrame(() => {
      if (messagesContainerRef.current) {
        lastScrollTopRef.current = messagesContainerRef.current.scrollTop
      }
    })

    const releaseDelay = behavior === "smooth" ? 250 : 0
    window.setTimeout(() => {
      isProgrammaticScrollRef.current = false
    }, releaseDelay)

    setHasNewMessages(false)
    setIsPinnedToBottom(true)
    updateAutoScrollEnabled(true)
  }, [updateAutoScrollEnabled])

  const handleStreamingFollow = useCallback(
    (behavior: ScrollBehavior = "auto") => {
      if (autoScrollRef.current) {
        scrollToBottom(behavior)
      } else {
        setHasNewMessages(true)
      }
    },
    [scrollToBottom]
  )

  const handleStartNewConversation = useCallback(() => {
    if (hasConversationHistory && typeof window !== "undefined") {
      const confirmed = window.confirm(
        "Starting a new conversation will clear the current transcript. Conversations aren't saved automatically. Continue?"
      )
      if (!confirmed) {
        return
      }
    }

    const greeting = buildGreeting(providerModel, assistantName, providerHost)
    setMessages([{ role: "assistant", content: greeting }])
    setReasoningOpen({})
    setInput("")
    setUploadedFiles([])
    setCipherPreview(null)
    setEncrypting(false)
    setIsSending(false)
    heroSubmissionRef.current = null
    heroAutoSubmitAttemptedRef.current = false
    scrollToBottom("auto")
  }, [assistantName, hasConversationHistory, providerHost, providerModel, scrollToBottom])

  const handleSaveConversation = useCallback(() => {
    if (messages.length === 0 || typeof window === "undefined") return

    const exportedAt = new Date().toISOString()
    const exportPayload = {
      exportedAt,
      assistant: assistantName,
      provider: {
        model: providerModel ?? null,
        baseUrl: providerApiBase ?? null,
        host: providerHost ?? null,
      },
      messages: messages.map(({ role, content, attachments, reasoning_content, finishReason }) => ({
        role,
        content,
        attachments:
          attachments?.map(({ name, type, size, content }) => ({
            name,
            type,
            size,
            content,
          })) ?? undefined,
        reasoning_content,
        finishReason,
      })),
    }

    const json = JSON.stringify(exportPayload, null, 2)
    const blob = new Blob([json], { type: "application/json" })
    const url = URL.createObjectURL(blob)
    const fileName = `confidential-conversation-${exportedAt.replace(/[:.]/g, "-")}.json`

    const link = document.createElement("a")
    link.href = url
    link.download = fileName
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)

    window.setTimeout(() => {
      URL.revokeObjectURL(url)
    }, 0)
  }, [assistantName, messages, providerApiBase, providerHost, providerModel])

  useEffect(() => {
    if (!autoScrollRef.current) return

    const container = messagesContainerRef.current
    if (!container) return

    const { scrollTop, clientHeight, scrollHeight } = container
    const distanceFromBottom = scrollHeight - (scrollTop + clientHeight)

    if (distanceFromBottom > 100) return

    scrollToBottom("smooth")
  }, [reasoningOpen, scrollToBottom])

  const sendMessage = async (override?: { text: string; files: UploadedFile[] }) => {
    if (isSending) return
    if (!secureChannelReady) {
      return
    }
    if (guestRestrictionActive) {
      setGuestNotice("You've already used your guest confidential session. Sign in to continue.")
      return
    }
    const rawText = override?.text ?? input
    const activeFiles = override?.files ?? uploadedFiles
    const text = rawText.trim()
    if (!text && activeFiles.length === 0) return

    if (!providerApiBase) {
      setConfigError("Add a confidential provider base URL before starting a session.")
      return
    }

    if (!providerModel) {
      setConfigError("Set NEXT_PUBLIC_VLLM_MODEL in your environment before starting a session.")
      return
    }

    if (guestLimitsEnabled && authState !== "signed-in") {
      try {
        sessionStorage.setItem(GUEST_ACTIVE_SESSION_KEY, "1")
        localStorage.setItem(GUEST_USAGE_STORAGE_KEY, new Date().toISOString())
        setGuestUsageRestricted(false)
        setGuestNotice(null)
      } catch (error) {
        if (process.env.NODE_ENV !== "production") {
          console.warn("Failed to persist guest usage state", error)
        }
      }
    }

    const trimmedToken = providerApiKeyInput.trim()

    let messageContent = text
    if (activeFiles.length > 0) {
      const fileContents = activeFiles
        .map((file) => `\n\n[File: ${file.name}]\n${file.content}`)
        .join("")
      messageContent = `${text}${fileContents}`
    }

    const userMessage: Message = {
      role: "user",
      content: messageContent,
      attachments: activeFiles.length > 0 ? activeFiles.map((file) => ({ ...file })) : undefined,
    }

    const conversationBeforeAssistant: Message[] = [...messages, userMessage]
      const assistantPlaceholder: Message = {
      role: "assistant",
      content: "",
      streaming: true,
      reasoningStartTime: Date.now(),
    }

    const conversationWithAssistant: Message[] = [...conversationBeforeAssistant, assistantPlaceholder]
    const assistantIndex = conversationWithAssistant.length - 1

    setEncrypting(true)
    setCipherPreview(toHexPreview(messageContent))
    setMessages(conversationWithAssistant)
    setReasoningOpen((prev) => ({ ...prev, [assistantIndex]: false }))
    setInput("")
    setUploadedFiles([])
    setIsSending(true)

    scrollToBottom("smooth")

    const sanitizedHistory = conversationBeforeAssistant.map((m) => ({ role: m.role, content: m.content }))

    const updateAssistantMessage = (patch: Partial<Message>) => {
      setMessages((prev) => {
        if (assistantIndex < 0 || assistantIndex >= prev.length) return prev
        const next = [...prev]
        const existing = next[assistantIndex]
        if (!existing) return prev
        next[assistantIndex] = { ...existing, ...patch }
        return next
      })
    }

    try {
      let streamedContent = ""
      let streamedReasoning = ""
      let finishReason: string | undefined

      for await (const chunk of streamConfidentialChat(
        {
          messages: sanitizedHistory,
          ...(providerModel ? { model: providerModel } : {}),
          reasoning_effort: reasoningEffort,
          ...(cacheSalt ? { cache_salt: cacheSalt } : {}),
        },
        {
          provider: {
            baseUrl: providerApiBase,
            apiKey: trimmedToken || undefined,
          },
        }
      )) {
        if (chunk.type === "delta" && chunk.content) {
          streamedContent += chunk.content
          updateAssistantMessage({ content: streamedContent })
          handleStreamingFollow()
        }

        if (chunk.type === "reasoning_delta" && chunk.reasoning_content) {
          streamedReasoning += chunk.reasoning_content
          updateAssistantMessage({ reasoning_content: streamedReasoning })
        }

        if (chunk.type === "error") {
          throw new Error(chunk.error)
        }

        if (chunk.type === "done") {
          if (chunk.content) {
            streamedContent = chunk.content
          }
          if (chunk.reasoning_content) {
            streamedReasoning = chunk.reasoning_content
          }
          if (chunk.finish_reason) {
            finishReason = chunk.finish_reason
          }
        }
      }

      const finalContent = streamedContent.trim()
      const finalReasoning = streamedReasoning.trim()

      updateAssistantMessage({
        content: finalContent || "No response received from the confidential service.",
        reasoning_content: finalReasoning || undefined,
        streaming: false,
        finishReason,
        reasoningEndTime: Date.now(),
      })
      handleStreamingFollow("smooth")
    } catch (error) {
      console.warn("Confidential chat request failed", error)
      const errorMessage = error instanceof Error && error.message ? error.message : "An unexpected error occurred. Please try again later."
      updateAssistantMessage({
        content: errorMessage,
        streaming: false,
        reasoning_content: undefined,
        finishReason: undefined,
      })
      handleStreamingFollow("smooth")
    } finally {
      setIsSending(false)
      setEncrypting(false)
      setCipherPreview(null)
    }
  }

  sendMessageRef.current = sendMessage

  useEffect(() => {
    if (heroAutoSubmitAttemptedRef.current) {
      return
    }
    if (!providerApiBase) {
      return
    }
    if (!secureChannelReady) {
      return
    }
    const pendingSubmission = heroSubmissionRef.current
    if (!pendingSubmission) {
      return
    }
    if (guestLimitsEnabled && guestUsageRestricted) {
      heroSubmissionRef.current = null
      return
    }

    const pendingMessage = pendingSubmission.message ?? ""
    const pendingFiles = pendingSubmission.hasFiles ? [...uploadedFiles] : []
    const hasContent = pendingMessage.trim().length > 0 || pendingFiles.length > 0
    if (!hasContent) {
      heroSubmissionRef.current = null
      return
    }

    if (pendingSubmission.hasFiles && pendingFiles.length === 0) {
      heroAutoSubmitAttemptedRef.current = false
      return
    }

    heroAutoSubmitAttemptedRef.current = true
    const timeout = window.setTimeout(() => {
      const send = sendMessageRef.current
      if (!send) {
        heroAutoSubmitAttemptedRef.current = false
        return
      }

      heroSubmissionRef.current = null
      void send({ text: pendingMessage, files: pendingFiles })
    }, 600)

    return () => {
      window.clearTimeout(timeout)
    }
  }, [providerApiBase, guestLimitsEnabled, guestUsageRestricted, uploadedFiles, secureChannelReady, heroSubmissionVersion])

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    void sendMessage()
  }

  const onKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault()
      void sendMessage()
    }
  }

  useEffect(() => {
    const container = messagesContainerRef.current
    if (!container) return

    const handleScroll = () => {
      const { scrollTop, clientHeight, scrollHeight } = container
      const distanceFromBottom = Math.max(0, scrollHeight - (scrollTop + clientHeight))
      const tolerance = 24
      const isAtBottom = distanceFromBottom <= tolerance

      // Detect user scrolling up (scrollTop decreased)
      const previousScrollTop = lastScrollTopRef.current
      const scrolledUp = scrollTop < previousScrollTop - 1 // 1px threshold for sensitive detection

      lastScrollTopRef.current = scrollTop

      setIsPinnedToBottom(isAtBottom)

      if (isAtBottom) {
        // User scrolled back to bottom, re-enable auto-scroll
        setHasNewMessages(false)
        updateAutoScrollEnabled(true)
      } else if (scrolledUp && !isProgrammaticScrollRef.current) {
        // User actively scrolled up, disable auto-scroll
        updateAutoScrollEnabled(false)
      }
      // Otherwise, don't change auto-scroll state (content added, programmatic scroll, etc.)
    }

    // Detect wheel events (mousewheel/trackpad) to immediately disable auto-scroll
    const handleWheel = (e: WheelEvent) => {
      // If user scrolls up (negative deltaY), immediately disable auto-scroll
      if (e.deltaY < 0) {
        updateAutoScrollEnabled(false)
      }
    }

    // Detect touch start for mobile scrolling
    const handleTouchStart = () => {
      // When user starts touching to scroll, disable auto-scroll
      // We'll re-enable if they scroll back to bottom (detected by handleScroll)
      const { scrollTop, clientHeight, scrollHeight } = container
      const distanceFromBottom = scrollHeight - (scrollTop + clientHeight)
      // Only disable if not already at bottom
      if (distanceFromBottom > 24) {
        updateAutoScrollEnabled(false)
      }
    }

    handleScroll()
    container.addEventListener("scroll", handleScroll, { passive: true })
    container.addEventListener("wheel", handleWheel, { passive: true })
    container.addEventListener("touchstart", handleTouchStart, { passive: true })

    return () => {
      container.removeEventListener("scroll", handleScroll)
      container.removeEventListener("wheel", handleWheel)
      container.removeEventListener("touchstart", handleTouchStart)
    }
  }, [updateAutoScrollEnabled])

  return (
    <div className="flex h-[100dvh] flex-col bg-[#E8E7F0] text-foreground dark:bg-background">
      <main className="flex flex-1 flex-col min-h-0">
        <section className="relative flex h-full w-full flex-1 flex-col md:flex-row" aria-label="Confidential space">
          <aside
            className={cn(
              "flex flex-col border-border/40 bg-white/95 transition-[opacity,transform,width] duration-200 dark:border-border/60 dark:bg-[#0B0820]/95 md:border-border/40 md:bg-white/85 md:dark:bg-card/25",
              "fixed inset-y-0 left-0 z-40 h-[100dvh] w-[min(360px,90vw)] overflow-y-auto border-r shadow-[0_20px_60px_-25px_rgba(5,3,15,0.85)] md:static md:h-full md:w-auto md:flex-none md:border-b-0 md:border-r md:shadow-none",
              sidebarOpen
                ? "translate-x-0 opacity-100 pointer-events-auto gap-6 p-5 sm:p-6 md:p-4 md:w-full md:max-w-[320px]"
                : "-translate-x-full opacity-0 pointer-events-none md:translate-x-0 md:opacity-100 md:pointer-events-auto md:w-[56px] md:items-center md:justify-between md:px-2 md:py-4"
            )}
          >
            {sidebarOpen ? (
              <>
                <div className="space-y-6">
                  <div className="flex items-start justify-between gap-2">
                    <div className="flex flex-col gap-2">
                      <div className="flex items-center gap-2 text-sm font-bold text-foreground">
                        <Lock className="h-4 w-4 text-brand-accent" />
                        <span className="tracking-tight">Confidential Space</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-1">
                      {themeReady && (
                        <Button
                          type="button"
                          variant="ghost"
                          size="icon"
                          onClick={() => setTheme(activeTheme === "dark" ? "light" : "dark")}
                          className="h-7 w-7 rounded-full text-muted-foreground hover:bg-muted/50 hover:text-foreground"
                          title={`Switch to ${activeTheme === "dark" ? "light" : "dark"} theme`}
                        >
                          {activeTheme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
                        </Button>
                      )}
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        onClick={() => setSidebarOpen(false)}
                        className="h-7 w-7 rounded-full text-muted-foreground hover:bg-muted/50 hover:text-foreground"
                      >
                        <PanelLeftClose className="h-4 w-4" />
                        <span className="sr-only">Collapse panel</span>
                      </Button>
                    </div>
                  </div>

                  <div className={cn(
                    "rounded-xl border p-3 transition-colors",
                    secureChannelReady 
                      ? "border-emerald-500/20 bg-emerald-500/5 dark:border-emerald-500/30 dark:bg-emerald-500/10"
                      : "border-amber-500/20 bg-amber-500/5"
                  )}>
                    <div className="flex items-center gap-2">
                      <div className={cn("h-2 w-2 rounded-full animate-pulse", secureChannelReady ? "bg-emerald-500" : "bg-amber-500")} />
                      <span className={cn("text-xs font-medium", secureChannelReady ? "text-emerald-700 dark:text-emerald-400" : "text-amber-700 dark:text-amber-400")}>
                        {secureChannelReady ? "Secure Channel Active" : "Establishing Security..."}
                      </span>
                    </div>
                    <div className="mt-2 flex flex-col gap-1 border-t border-border/50 pt-2">
                       <div className="flex items-center gap-2 text-xs text-muted-foreground">
                          <UserCircle2 className="h-3.5 w-3.5 text-brand-accent" />
                          <span className="truncate max-w-[180px]">{authState === "signed-in" ? authUserEmail : "Guest User"}</span>
                       </div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <h3 className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground/70">Session</h3>
                    <div className="grid grid-cols-2 gap-2">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="gap-2 border-border/50 bg-card/50 hover:bg-card/80"
                        onClick={handleSaveConversation}
                        disabled={!hasConversationHistory}
                        title="Download JSON"
                      >
                        <Save className="h-3.5 w-3.5 text-brand-primary" />
                        <span className="text-xs">Save</span>
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="gap-2 border-border/50 bg-card/50 hover:bg-card/80"
                        onClick={handleStartNewConversation}
                        disabled={isSending || isStreaming}
                      >
                        <MessageSquarePlus className="h-3.5 w-3.5 text-brand-primary" />
                        <span className="text-xs">New</span>
                      </Button>
                    </div>
                  </div>
                </div>

                <Accordion type="single" collapsible>
                  <AccordionItem value="proof" className="border-none">
                    <AccordionTrigger
                      className="flex w-full items-center justify-between gap-3 rounded-2xl border border-brand-primary/60 bg-[linear-gradient(130deg,hsl(var(--brand-primary)/0.18),hsl(var(--brand-secondary)/0.42))] px-4 py-3 text-left text-sm font-semibold uppercase tracking-[0.24em] text-white shadow-[0_18px_35px_-24px_rgba(16,42,140,0.9)] transition hover:brightness-110 data-[state=open]:brightness-110 dark:border-brand-primary dark:bg-[linear-gradient(130deg,rgba(16,42,140,0.32),rgba(11,31,102,0.45))]"
                    >
                      <span className="inline-flex items-center gap-2 text-[11px]">
                        <ShieldCheck className="h-4 w-4" />
                        Proof of Confidentiality
                      </span>
                    </AccordionTrigger>
                    <AccordionContent className="mt-3 space-y-3 rounded-2xl border border-brand-primary/30 bg-[linear-gradient(135deg,hsl(var(--brand-primary)/0.08),hsl(var(--brand-secondary)/0.12))] p-4 shadow-sm dark:border-brand-primary/40 dark:bg-[linear-gradient(135deg,rgba(16,42,140,0.18),rgba(11,31,102,0.28))]">
                      <ProofContent
                        variant="sidebar"
                        verificationState={verificationState}
                        runtimeSignals={runtimeSignals}
                        onViewDetails={() => setProofDetailsModalOpen(true)}
                      />
                    </AccordionContent>
                  </AccordionItem>
                </Accordion>

                <div className="space-y-2">
                  <h3 className="text-[11px] font-semibold uppercase tracking-[0.28em] text-muted-foreground">Reasoning intensity</h3>
                  <div className="flex flex-wrap gap-2">
                    {["low", "medium", "high"].map((effort) => (
                      <Button
                        key={effort}
                        type="button"
                        variant="ghost"
                        size="sm"
                        className={cn(
                          "h-8 rounded-full border px-4 text-[11px] uppercase tracking-[0.24em]",
                          reasoningEffort === effort
                            ? "border-brand-primary bg-brand-gradient text-white hover:brightness-110"
                            : "border-border/40 bg-card/70 text-muted-foreground hover:bg-card/80 dark:border-border/60 dark:bg-card/20 dark:text-muted-foreground dark:hover:bg-card/30"
                        )}
                        onClick={() => setReasoningEffort(effort as "low" | "medium" | "high")}
                        disabled={isSending}
                      >
                        {effort}
                      </Button>
                    ))}
                  </div>
                </div>

                <div className="mt-auto pt-4 flex items-center justify-center">
                  <Link
                    href="/"
                    className="inline-flex items-center justify-center whitespace-nowrap transition-opacity hover:opacity-80"
                  >
                    <Image src="/logo.png" alt="Confidential AI logo" width={20} height={20} className="shrink-0" />
                  </Link>
                </div>
              </>
            ) : (
              <div className="flex h-full flex-col items-center justify-between gap-4 py-3">
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  onClick={() => setSidebarOpen(true)}
                  className="rounded-full border border-border/40 bg-card/80 text-muted-foreground transition hover:bg-card/90 dark:border-border/60 dark:bg-card/20 dark:text-foreground dark:hover:bg-card/30"
                >
                  <PanelLeftOpen className="h-4 w-4" />
                  <span className="sr-only">Expand panel</span>
                </Button>
                <div className="flex flex-col items-center gap-3 text-muted-foreground">
                  <Lock className="h-5 w-5 text-brand-accent" />
                  <span className="text-[10px] font-semibold uppercase tracking-[0.4em] [writing-mode:vertical-rl] [text-orientation:mixed]">
                    Confidential
                  </span>
                </div>
                <Link
                  href="/"
                  className="inline-flex items-center justify-center whitespace-nowrap transition-opacity hover:opacity-80"
                >
                  <Image src="/logo.png" alt="Confidential AI logo" width={20} height={20} className="shrink-0" />
                </Link>
              </div>
            )}
          </aside>

          {sidebarOpen ? (
            <button
              type="button"
              aria-label="Close confidential tools"
              onClick={() => setSidebarOpen(false)}
              className="fixed inset-0 z-30 bg-[#08070B]/40 backdrop-blur-[2px] transition-opacity md:hidden"
            />
          ) : null}

          {!sidebarOpen ? (
            <Button
              type="button"
              variant="ghost"
              size="icon"
              onClick={() => setSidebarOpen(true)}
              className="fixed left-4 top-[calc(env(safe-area-inset-top,0)+16px)] z-30 rounded-full border border-border/50 bg-white/90 text-muted-foreground shadow-md backdrop-blur md:hidden"
            >
              <PanelLeftOpen className="h-4 w-4" />
              <span className="sr-only">Open confidential tools</span>
            </Button>
          ) : null}

          <div className="flex flex-1 flex-col min-h-0">
            <div
              ref={messagesContainerRef}
              className="flex-1 overflow-y-auto px-4 py-6 sm:px-8"
              role="log"
              aria-live="polite"
              aria-label="Confidential space transcript"
            >
              <div className="mx-auto flex w-full max-w-4xl flex-col space-y-8">
                {/* Onboarding Banner */}
                {messages.length <= 1 && !guestNotice && (
                  <div className="relative overflow-hidden rounded-2xl bg-gradient-to-br from-brand-primary/10 via-brand-secondary/5 to-transparent p-6 border border-brand-primary/20 dark:border-brand-primary/30">
                     <div className="relative z-10 flex gap-4">
                        <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-primary/10 text-brand-primary dark:text-brand-accent dark:bg-brand-accent/10">
                           <ShieldCheck className="h-5 w-5" />
                        </div>
                        <div className="space-y-2">
                           <h3 className="font-semibold text-foreground">Welcome to Confidential AI</h3>
                           <p className="text-sm text-muted-foreground leading-relaxed max-w-lg">
                              This chat session is end-to-end encrypted and processed inside a secure enclave (TEE). 
                              Your data remains confidential even from the cloud provider. 
                              Verify the "Attestation" status in the sidebar to ensure system integrity.
                           </p>
                        </div>
                     </div>
                     {/* Background decoration */}
                     <div className="absolute -top-12 -right-12 h-48 w-48 rounded-full bg-brand-primary/5 blur-3xl" />
                  </div>
                )}
                {guestNotice ? (
                  <div className="rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-xs text-amber-800 shadow-sm dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-200">
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                      <p>{guestNotice}</p>
                      {authState !== "signed-in" ? (
                        <Button
                          asChild
                          size="sm"
                          variant="ghost"
                          className="inline-flex items-center gap-2 rounded-full border border-amber-300 bg-white/70 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.24em] text-amber-700 transition hover:bg-white dark:border-amber-400/70 dark:bg-transparent dark:text-amber-200 dark:hover:bg-amber-400/10"
                        >
                          <Link href="/sign-in">Sign in</Link>
                        </Button>
                      ) : null}
                    </div>
                  </div>
                ) : null}
                {messages.map((m, i) => {
                  const isUser = m.role === "user"
                  const isAssistant = !isUser
                  const isReasoningOpen = reasoningOpen[i] ?? false
                  const reasoningAvailable =
                    typeof m.reasoning_content === "string" && m.reasoning_content.trim().length > 0
                  const hasReasoningActivity = m.streaming || reasoningAvailable
                  const showReasoningPanel = isAssistant && (m.streaming || reasoningAvailable)
                  const truncatedByLength = isAssistant && m.finishReason === "length"

                  const bubbleText =
                    isUser && m.attachments && m.attachments.length > 0
                      ? m.content.split("\n\n[File:")[0] || "File(s) attached"
                      : m.content.trim().length > 0
                        ? m.content
                        : isAssistant && m.streaming
                          ? "Synthesising a confidential response…"
                          : m.content

                  const label = isUser ? "You" : assistantName

                  const bubbleClass = isUser
                    ? "w-full sm:max-w-[85%] md:max-w-3xl self-end whitespace-pre-wrap break-words rounded-3xl bg-brand-gradient px-6 py-4 text-left text-white shadow-md dark:shadow-none"
                    : "w-full sm:max-w-[85%] md:max-w-4xl self-start whitespace-pre-wrap break-words rounded-none bg-transparent px-0 py-0 text-left text-foreground leading-7"

                  const bubbleStyle: CSSProperties | undefined = isUser
                    ? ({
                        "--foreground": "0 0% 100%",
                        "--muted-foreground": "0 0% 85%",
                      } as CSSProperties)
                    : undefined

                  const attachmentsContainerClass = cn(
                    "flex flex-col gap-1 text-xs text-muted-foreground",
                    isUser ? "items-end self-end text-right" : "items-start self-start text-left"
                  )

                  const toggleReasoningPanel = () => {
                    setReasoningOpen((prev) => ({ ...prev, [i]: !isReasoningOpen }))
                  }

                  const messageRowClass = cn(
                    "flex w-full gap-4",
                    isAssistant ? "flex-col items-start sm:flex-row sm:items-start" : "flex-row",
                    isUser ? "justify-end" : "justify-start"
                  )

                  return (
                    <div key={i} className={cn("flex w-full", isUser ? "justify-end" : "justify-start")}>
                      <div className={messageRowClass}>
                        {isAssistant && (
                          <div className="relative mt-1">
                            <button
                              type="button"
                              onClick={showReasoningPanel ? toggleReasoningPanel : undefined}
                              disabled={!showReasoningPanel}
                              className={cn(
                                "flex size-8 items-center justify-center rounded-full border border-border/40 bg-card/80 text-brand-primary transition-all dark:border-border/60 dark:bg-card/30",
                                "cursor-pointer hover:brightness-110 hover:bg-brand-primary/10",
                                isReasoningOpen && "text-brand-primary ring-2 ring-brand-primary/20"
                              )}
                              title={showReasoningPanel ? (isReasoningOpen ? "Hide reasoning" : "Show reasoning") : undefined}
                            >
                              <Bot className="h-5 w-5" />
                              {hasReasoningActivity && !isReasoningOpen && (
                                <div className="absolute -right-0.5 -top-0.5 flex size-3 items-center justify-center rounded-full bg-brand-primary text-white ring-2 ring-background">
                                  <Sparkles className="h-2 w-2" />
                                </div>
                              )}
                            </button>
                          </div>
                        )}
                        <div
                          className={cn(
                            "flex w-full sm:max-w-[85%] flex-col gap-1",
                            isUser ? "items-end text-right" : "items-start text-left"
                          )}
                        >
                          {isAssistant && hasReasoningActivity && isReasoningOpen && (
                            <div className="w-full overflow-hidden border-l-2 border-brand-primary/30 pl-4 ml-1 mb-4 mt-1 animate-in fade-in slide-in-from-top-1 duration-200">
                              <div className="text-sm text-muted-foreground/90 leading-relaxed">
                                <Markdown
                                  content={
                                    reasoningAvailable
                                      ? m.reasoning_content?.trim() ?? ""
                                      : m.streaming
                                        ? "Thinking..."
                                        : "No reasoning shared."
                                  }
                                  className="markdown-body text-sm !text-muted-foreground"
                                />
                              </div>
                            </div>
                          )}
                          {m.attachments && m.attachments.length > 0 && (
                            <div className={cn(attachmentsContainerClass, "w-full mb-2")}>
                              {m.attachments.map((file, fileIndex) => (
                                <div
                                  key={fileIndex}
                                  className={cn(
                                    "flex max-w-full items-center gap-2 rounded-xl border p-2",
                                    isUser
                                      ? "border-brand-primary/20 bg-brand-primary/10 text-foreground self-end dark:border-white/20 dark:bg-white/10 dark:text-white"
                                      : "border-border/40 bg-card/50 text-foreground self-start w-full"
                                  )}
                                >
                                  <FileText
                                    className={cn(
                                      "size-3",
                                      isUser ? "text-brand-primary dark:text-white/80" : "text-muted-foreground"
                                    )}
                                  />
                                  <span className="font-medium">{file.name}</span>
                                  <span className={cn("text-xs", isUser ? "text-muted-foreground dark:text-white/70" : "text-muted-foreground")}>
                                    ({formatFileSize(file.size)}, {formatWordCount(countWords(file.content))})
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                          <div className={bubbleClass} style={bubbleStyle}>
                            <Markdown
                              content={bubbleText}
                              className={cn("markdown-body", isUser ? "text-white" : "text-foreground")}
                            />
                          </div>
                          {truncatedByLength && (
                            <div className="w-full text-[11px] text-muted-foreground">
                              Umbra paused because the API token limit was reached. Ask to continue for more detail.
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  )
                })}
                <div ref={messagesEndRef} aria-hidden />
              </div>
            </div>
            {showScrollToLatest && (
              <div className="pointer-events-none absolute inset-x-0 bottom-3 flex justify-center">
                <Button
                  type="button"
                  size="sm"
                  variant="ghost"
                  className={cn(
                    "pointer-events-auto gap-1 rounded-full border border-border/40 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.2em] shadow-sm backdrop-blur transition dark:border-border/60",
                    hasNewMessages
                      ? "bg-brand-gradient text-white hover:brightness-110"
                      : "bg-white/95 text-foreground hover:bg-white dark:bg-card/30 dark:text-foreground dark:hover:bg-card/40"
                  )}
                  onClick={() => scrollToBottom()}
                >
                  <ArrowDown className="size-4" />
                  <span>{hasNewMessages ? "New reply" : "Scroll to latest"}</span>
                </Button>
              </div>
            )}
            <form
              ref={chatFormRef}
              onSubmit={onSubmit}
              className="shrink-0 border-t border-border/40 bg-white/95 px-4 py-4 shadow-inner dark:bg-card/25"
            >
               <div className="mx-auto w-full space-y-4">
                {verificationState.status === "success" && verificationState.isOutOfDate && (
                  <div className="flex items-start gap-2 rounded-xl border border-amber-400/60 bg-amber-400/10 px-3 py-2.5 text-xs text-amber-700 dark:border-amber-400/40 dark:bg-amber-400/5 dark:text-amber-300">
                    <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                    <div className="flex-1 space-y-1.5">
                      <p className="font-medium">Security update recommended</p>
                      <p className="text-[11px] leading-relaxed">
                        The service is working normally, but the provider should apply security updates.
                      </p>
                      {verificationState.advisoryIds && verificationState.advisoryIds.length > 0 && (
                        <div className="pt-1.5 space-y-1">
                          <p className="text-[11px] font-medium">Security advisories:</p>
                          <div className="flex flex-wrap gap-1">
                            {verificationState.advisoryIds.map((advisory) => (
                              <a
                                key={advisory}
                                href={`https://www.intel.com/content/www/us/en/security-center/advisory/${advisory.toLowerCase()}.html`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 px-2 py-0.5 text-[10px] text-amber-700 hover:bg-amber-500/20 dark:text-amber-300 dark:border-amber-400/40 dark:hover:bg-amber-400/10"
                              >
                                {advisory}
                                <ExternalLink className="h-2.5 w-2.5" />
                              </a>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}
                {(() => {
                  const isAttestationLoading = proofState.status === "loading"
                  const isVerificationRunning = verificationState.status === "running"
                  const isInProgress = isAttestationLoading || isVerificationRunning
                  const isVerified = secureChannelReady
                  const hasFailed =
                    proofState.status === "error" ||
                    verificationState.status === "error" ||
                    (verificationState.status === "success" && !quoteVerified)
                  
                  if (proofState.status === "unavailable" || proofState.status === "idle") {
                    return null
                  }

                  const isOutOfDate = verificationState.status === "success" && verificationState.isOutOfDate
                  
                  return (
                    <div
                      className={cn(
                        "flex items-center gap-2 rounded-xl border px-3 py-2 text-xs font-medium",
                        isVerified && !isOutOfDate
                          ? "border-emerald-400/60 bg-emerald-400/10 text-emerald-700 dark:border-emerald-400/40 dark:bg-emerald-400/5 dark:text-emerald-300"
                          : isVerified && isOutOfDate
                            ? "border-amber-400/60 bg-amber-400/10 text-amber-700 dark:border-amber-400/40 dark:bg-amber-400/5 dark:text-amber-300"
                            : isInProgress
                              ? "border-brand-primary/60 bg-brand-primary/10 text-brand-primary dark:border-brand-primary/40 dark:bg-brand-primary/5"
                              : hasFailed
                                ? "border-rose-400/60 bg-rose-400/10 text-rose-700 dark:border-rose-400/40 dark:bg-rose-400/5 dark:text-rose-300"
                                : "border-amber-400/60 bg-amber-400/10 text-amber-700 dark:border-amber-400/40 dark:bg-amber-400/5 dark:text-amber-300"
                      )}
                    >
                      {isVerified && !isOutOfDate ? (
                        <>
                          <Lock className="h-4 w-4 shrink-0" />
                          <span>Attestation verified</span>
                        </>
                      ) : isVerified && isOutOfDate ? (
                        <>
                          <AlertTriangle className="h-4 w-4 shrink-0" />
                          <span>Secure channel verified (update recommended)</span>
                        </>
                      ) : isInProgress ? (
                        <>
                          <Sparkles className="h-4 w-4 shrink-0 animate-pulse" />
                          <span>
                            {isAttestationLoading && isVerificationRunning
                              ? "Attesting and verifying…"
                              : isAttestationLoading
                                ? "Attesting enclave…"
                                : "Verifying attestation…"}
                          </span>
                        </>
                      ) : hasFailed ? (
                        <>
                          <X className="h-4 w-4 shrink-0" />
                          <span className="truncate">Security verification failed</span>
                        </>
                      ) : (
                        <>
                          <Info className="h-4 w-4 shrink-0" />
                          <span>Verification pending</span>
                        </>
                      )}
                    </div>
                  )
                })()}
                {uploadedFiles.length > 0 && (
                  <div className="space-y-2">
                    {uploadedFiles.map((file, index) => (
                      <div
                        key={index}
                        className="flex items-center justify-between rounded-xl border border-border/40 bg-white p-3 text-xs text-muted-foreground dark:border-border/60 dark:bg-card/25"
                      >
                        <div className="flex items-center gap-2">
                          <FileText className="size-3 text-brand-primary" />
                          <span className="font-medium text-foreground">{file.name}</span>
                          <span className="text-muted-foreground">
                            ({formatFileSize(file.size)}, {formatWordCount(countWords(file.content))})
                          </span>
                        </div>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          onClick={() => removeFile(index)}
                          className="h-6 w-6 rounded-full border border-border/40 p-0 text-foreground hover:bg-card/80 dark:border-border/60 dark:hover:bg-card/30"
                        >
                          <X className="size-3" />
                        </Button>
                      </div>
                    ))}
                  </div>
                )}

                <div className="flex w-full items-end gap-3">
                  <div className="min-w-0 flex-1">
                    <label htmlFor="secure-input" className="sr-only">
                      Secure message input
                    </label>
                    <textarea
                      id="secure-input"
                      value={input}
                      onChange={(e) => {
                        setInput(e.target.value)
                      }}
                      onKeyDown={onKeyDown}
                      disabled={isSending || guestRestrictionActive}
                      placeholder="Shift+Enter for a newline. Messages and attachments stay inside this secure workspace."
                      className="min-h-[96px] w-full resize-none rounded-2xl border border-border/40 bg-white px-4 py-3 text-sm text-foreground placeholder:text-muted-foreground/70 shadow-sm focus:outline-none focus:ring-2 focus:ring-[#102A8C]/45 dark:border-border/60 dark:bg-card/15 sm:min-h-[56px]"
                      rows={2}
                    />
                  </div>
                  <div className="ml-auto flex h-[96px] shrink-0 flex-col items-stretch justify-end gap-2 sm:ml-0 sm:h-[56px] sm:flex-row sm:items-stretch sm:gap-3">
                    <input
                      type="file"
                      ref={fileInputRef}
                      onChange={handleFileUpload}
                      multiple
                      accept=".txt,.md,.json,.csv,.py,.js,.ts,.tsx,.jsx,.html,.css,.xml,.yaml,.yml,.pdf"
                      className="hidden"
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="icon"
                      onClick={() => fileInputRef.current?.click()}
                      disabled={isSending || guestRestrictionActive}
                      className="flex-1 h-full min-h-0 w-[56px] shrink-0 rounded-xl border border-border/40 bg-white text-foreground transition hover:bg-white/90 dark:border-border/60 dark:bg-card/20 dark:hover:bg-card/30 sm:flex-none"
                      title="Upload files"
                    >
                      <Paperclip className="h-5 w-5 text-brand-primary dark:text-foreground" />
                    </Button>
                    <Button
                      type="submit"
                      size="icon"
                      className="flex-1 h-full min-h-0 w-[56px] shrink-0 rounded-xl bg-brand-gradient text-white transition hover:brightness-110 dark:bg-white dark:text-foreground sm:flex-none"
                      disabled={
                        guestRestrictionActive ||
                        isSending ||
                        (!input.trim() && uploadedFiles.length === 0) ||
                        !providerApiBase ||
                        !secureChannelReady
                      }
                    >
                      <Send className="h-5 w-5" />
                      <span className="sr-only">Send secure message</span>
                    </Button>
                  </div>
                </div>
              </div>
            </form>
          </div>
        </section>
      </main>
      <Dialog open={sessionDialogOpen} onOpenChange={setSessionDialogOpen}>
        <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto border border-border/50 bg-background/95 backdrop-blur dark:border-border/60 dark:bg-background/80">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-lg font-semibold">
              <Lock className="h-5 w-5 text-brand-primary" />
              Secure Session
            </DialogTitle>
          </DialogHeader>
          <Tabs defaultValue="session" className="w-full">
            <TabsList className="grid w-full grid-cols-2 gap-2 rounded-full border border-border/40 bg-card/80 p-1 dark:border-border/60 dark:bg-card/20">
              <TabsTrigger
                value="session"
                className="rounded-full px-4 py-2 text-[11px] uppercase tracking-[0.24em] data-[state=active]:bg-[linear-gradient(135deg,#102A8C,#0B1F66)] data-[state=active]:text-white"
              >
                Session Details
              </TabsTrigger>
              <TabsTrigger
                value="proof"
                className="rounded-full px-4 py-2 text-[11px] uppercase tracking-[0.24em] data-[state=active]:bg-[linear-gradient(135deg,#102A8C,#0B1F66)] data-[state=active]:text-white"
              >
                Proof of Confidentiality
              </TabsTrigger>
            </TabsList>
            <TabsContent value="session" className="space-y-4 mt-4">
              <div className="space-y-3">
                <p className="text-sm text-muted-foreground">{connectionSummary}</p>
                <div className="space-y-3 text-xs">
                  {modelDisplayLabel && (
                    <div className="flex items-center gap-2">
                      <Bot className="size-4 text-brand-primary" />
                      <span className="text-muted-foreground">
                        <span className="font-medium">Model:</span>{" "}
                        <span title={modelDisplayTitle}>{modelDisplayLabel}</span>
                      </span>
                    </div>
                  )}
                  <div className="flex items-center gap-2">
                    <Bot className="size-4 text-brand-primary" />
                    <span className="text-muted-foreground">
                      <span className="font-medium">Assistant:</span> {assistantName}
                    </span>
                  </div>
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className={cn("size-4", providerConfigured ? "text-foreground" : "text-muted-foreground/50")} />
                    <span className="text-muted-foreground">
                      <span className="font-medium">Base URL:</span>{" "}
                      {providerApiBase ? truncateMiddle(providerApiBase, 35) : "Not configured"}
                    </span>
                  </div>
                  {providerHost && (
                    <div className="flex items-center gap-2">
                      <Globe className="size-4 text-muted-foreground" />
                      <span className="text-muted-foreground" title={providerHost}>
                        <span className="font-medium">Host:</span> {truncateMiddle(providerHost, 35)}
                      </span>
                    </div>
                  )}
                  <div className="flex items-center gap-2">
                    <Lock className="size-4 text-muted-foreground" />
                    <span className="text-muted-foreground">
                      <span className="font-medium">Bearer token:</span>{" "}
                      {tokenPresent ? "Loaded in session" : "Not provided (optional)"}
                    </span>
                  </div>
                  {cacheSalt && (
                    <div className="flex items-center gap-2">
                      <Key className="size-4 text-muted-foreground" />
                      <span className="text-muted-foreground" title={cacheSalt}>
                        <span className="font-medium">KV cache salt:</span>{" "}
                        <span className="font-mono">{cacheSalt.slice(0, 8)}...{cacheSalt.slice(-4)}</span>
                      </span>
                    </div>
                  )}
                </div>
                <div className="pt-3">
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    className="w-full rounded-full border border-border/40 bg-card/70 text-foreground hover:bg-card/80 dark:border-border/60 dark:bg-card/20 dark:text-foreground dark:hover:bg-card/30"
                    onClick={() => setShowAdvancedSettings((previous) => !previous)}
                  >
                    {showAdvancedSettings ? "Hide Advanced Settings" : "Show Advanced Settings"}
                  </Button>
                </div>
                {showAdvancedSettings && (
                  <div className="space-y-3 rounded-2xl border border-border/40 bg-card/80 p-5 text-xs text-muted-foreground dark:border-border/60 dark:bg-card/20">
                    <h3 className="text-[11px] font-semibold uppercase tracking-[0.24em] text-muted-foreground">
                      Advanced provider settings
                    </h3>
                    <label htmlFor="provider-base-url" className="block space-y-1 text-muted-foreground">
                      <span className="font-medium text-foreground">Base URL</span>
                      <input
                        id="provider-base-url"
                        type="url"
                        inputMode="url"
                        autoComplete="off"
                        spellCheck={false}
                        placeholder="https://tee.example.com"
                        value={providerBaseUrlInput}
                        onChange={(event) => setProviderBaseUrlInput(event.target.value)}
                        className="w-full rounded-xl border border-border/40 bg-card px-3 py-2 text-sm text-foreground placeholder:text-muted-foreground/70 focus:outline-none focus:ring-2 focus:ring-[#102A8C]/35 dark:border-border/60 dark:bg-card/15"
                      />
                    </label>
                    <label htmlFor="provider-api-key" className="block space-y-1 text-muted-foreground">
                      <span className="font-medium text-foreground">Bearer token (optional)</span>
                      <input
                        id="provider-api-key"
                        type="password"
                        autoComplete="off"
                        spellCheck={false}
                        placeholder="token-..."
                        value={providerApiKeyInput}
                        onChange={(event) => setProviderApiKeyInput(event.target.value)}
                        className="w-full rounded-xl border border-border/40 bg-card px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-[#102A8C]/35 dark:border-border/60 dark:bg-card/15"
                      />
                    </label>
                    {configError && (
                      <div className="rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-[11px] text-destructive">
                        {configError}
                      </div>
                    )}
                    <p className="text-[11px] text-muted-foreground">
                      Stored locally. Refreshing the page clears the token (session storage).
                    </p>
                  </div>
                )}
              </div>
            </TabsContent>
            <TabsContent value="proof" className="space-y-4 mt-4">
              <p className="text-sm text-muted-foreground">
                {derivedAttestationOrigin
                  ? `Each refresh requests a fresh Intel TDX quote from ${getHostLabelFromUrl(derivedAttestationOrigin) ?? derivedAttestationOrigin}.`
                  : "Point NEXT_PUBLIC_ATTESTATION_BASE_URL at your Umbra CVM to surface the attestation origin."}
              </p>
              <ProofContent
                variant="dialog"
                verificationState={verificationState}
                runtimeSignals={runtimeSignals}
                onViewDetails={() => setProofDetailsModalOpen(true)}
              />
            </TabsContent>
          </Tabs>
        </DialogContent>
      </Dialog>
      <ProofDetailsModal />
      <FeedbackButton source="confidential" position="top-right" />
    </div>
  )
}

export default function ConfidentialAIPage() {
  return (
    <Suspense fallback={
      <div className="flex h-[100dvh] items-center justify-center">
        <div className="text-center">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-brand-primary border-t-transparent mx-auto mb-4"></div>
          <p className="text-sm text-muted-foreground">Loading confidential space...</p>
        </div>
      </div>
    }>
      <ConfidentialAIContent />
    </Suspense>
  )
}
