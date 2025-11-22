import { createOpenAI } from "@ai-sdk/openai"
import type { LanguageModel } from "ai"
import { systemPrompt as defaultSystemPrompt } from "./system-prompt"

export type ConfidentialChatMessage = {
  role: "user" | "assistant" | "system"
  content: string
}

export type ConfidentialChatProviderConfig = {
  baseUrl?: string
  apiKey?: string
  systemPrompt?: string
}

export type RatlsAttestation = {
  trusted: boolean
  teeType: string
  measurement?: string | null
  tcbStatus: string
  advisoryIds: string[]
}

export type RatlsConfig = {
  proxyUrl: string
  targetHost: string
  serverName: string
}

export type ConfidentialModelOptions = {
  model?: string
  cacheSalt?: string | null
  provider?: ConfidentialChatProviderConfig
  onAttestation?: (attestation: RatlsAttestation) => void
}

export type ConfidentialModelResult = {
  model: LanguageModel
  modelId: string
  systemPrompt: string
  temperature?: number
  maxOutputTokens: number
  apiBaseUrl: string
}

const defaultProviderApiBase = optionalEnv(process.env.NEXT_PUBLIC_VLLM_BASE_URL)
const defaultModel = optionalEnv(process.env.NEXT_PUBLIC_VLLM_MODEL)
const defaultProviderName = optionalEnv(process.env.NEXT_PUBLIC_VLLM_PROVIDER_NAME)
const resolvedSystemPrompt = optionalEnv(process.env.NEXT_PUBLIC_DEFAULT_SYSTEM_PROMPT) ?? defaultSystemPrompt
const defaultMaxTokens = parseNumber(process.env.NEXT_PUBLIC_DEFAULT_MAX_TOKENS, 4098)
const defaultTemperature = parseNumber(process.env.NEXT_PUBLIC_DEFAULT_TEMPERATURE, 0.7)
const ratlsProxyUrl = optionalEnv(process.env.NEXT_PUBLIC_RATLS_PROXY_URL)
const ratlsTarget = optionalEnv(process.env.NEXT_PUBLIC_RATLS_TARGET)
const ratlsServerName = optionalEnv(process.env.NEXT_PUBLIC_RATLS_SERVER_NAME)
const defaultProviderToken = optionalEnv(process.env.NEXT_PUBLIC_CONFIDENTIAL_PROVIDER_TOKEN)

export const confidentialChatConfig = {
  providerApiBase: defaultProviderApiBase,
  providerModel: defaultModel,
  providerName: defaultProviderName,
  systemPrompt: resolvedSystemPrompt,
  defaultMaxTokens,
  defaultTemperature,
}

export async function createConfidentialModel(options: ConfidentialModelOptions = {}): Promise<ConfidentialModelResult> {
  const resolved = resolveProviderConfig(options.provider)

  if (!resolved.baseUrl) {
    throw new Error("No provider base URL configured. Please set the provider URL in the Provider settings.")
  }

  if (!isSecureProviderUrl(resolved.baseUrl)) {
    throw new Error("Insecure provider URL: use https:// (or localhost/127.0.0.1 for local dev).")
  }

  const ratlsConfig = resolveRatlsConfig(resolved.baseUrl)
  if (!ratlsConfig) {
    throw new Error(
      "RA-TLS proxy configuration is missing or insecure. Set NEXT_PUBLIC_RATLS_PROXY_URL (wss:// in production) and NEXT_PUBLIC_RATLS_TARGET (or provide a provider URL that includes host:port)."
    )
  }

  const modelId = optionalEnv(options.model) ?? resolved.model
  if (!modelId) {
    throw new Error("No model specified. Please set a model ID in the Provider settings.")
  }

  const [{ createRatlsFetch }] = await Promise.all([import("../ratls/wasm/pkg/ratls-fetch.js")])

  const baseFetch = createRatlsFetch({
    proxyUrl: ratlsConfig.proxyUrl,
    targetHost: ratlsConfig.targetHost,
    serverName: ratlsConfig.serverName,
    defaultHeaders: resolved.apiKey ? { Authorization: `Bearer ${resolved.apiKey}` } : undefined,
    onAttestation: options.onAttestation,
  })
  const ratlsFetch = wrapFetchWithMiddleware(baseFetch, options.cacheSalt ?? undefined)

  const apiBaseUrl = appendDefaultApiPath(resolved.baseUrl ?? `https://${ratlsConfig.serverName}`)
  const temperature = isReasoningModel(modelId) ? undefined : resolved.temperature
  const openai = createOpenAI({
    baseURL: apiBaseUrl,
    apiKey: resolved.apiKey ?? "placeholder-token",
    fetch: ratlsFetch,
  })

  return {
    model: openai.chat(modelId),
    modelId,
    systemPrompt: resolved.systemPrompt,
    temperature,
    maxOutputTokens: resolved.maxTokens,
    apiBaseUrl,
  }
}

export function getRatlsConfig(providerBaseUrl?: string | null): RatlsConfig | null {
  return resolveRatlsConfig(providerBaseUrl)
}

export function buildRatlsProxyUrl(config: RatlsConfig): string {
  const url = new URL(config.proxyUrl)
  url.searchParams.set("target", config.targetHost)
  return url.toString()
}

type ResolvedProviderConfig = {
  baseUrl?: string
  apiKey?: string
  model?: string
  systemPrompt: string
  temperature: number
  maxTokens: number
}

function resolveProviderConfig(provider?: ConfidentialChatProviderConfig): ResolvedProviderConfig {
  const baseUrl = normalizeBaseUrl(provider?.baseUrl ?? defaultProviderApiBase)
  const apiKey = optionalEnv(provider?.apiKey) ?? defaultProviderToken ?? "placeholder-token"
  const model = optionalEnv(defaultModel)
  const systemPrompt = optionalEnv(provider?.systemPrompt) ?? resolvedSystemPrompt
  const temperature = defaultTemperature
  const maxTokens = defaultMaxTokens

  return {
    baseUrl,
    apiKey,
    model,
    systemPrompt,
    temperature,
    maxTokens,
  }
}

function resolveRatlsConfig(providerBaseUrl?: string | null): RatlsConfig | null {
  const proxyUrl = normalizeRatlsProxy(ratlsProxyUrl)
  if (!proxyUrl) {
    return null
  }

  const targetHost = normalizeRatlsTarget(ratlsTarget ?? providerBaseUrl)
  if (!targetHost) {
    return null
  }

  const serverName = ratlsServerName ?? hostFromTarget(targetHost)
  return {
    proxyUrl,
    targetHost,
    serverName,
  }
}

function normalizeRatlsProxy(raw?: string | null): string | null {
  if (!raw) return null
  const trimmed = raw.trim()
  if (!trimmed) return null
  const candidate = /^wss?:\/\//i.test(trimmed) ? trimmed : `ws://${trimmed.replace(/^\/+/, "")}`

  try {
    const url = new URL(candidate)
    const isProd = process.env.NODE_ENV === "production"
    if (isProd && url.protocol !== "wss:" && !isLoopbackHostname(url.hostname)) {
      return null
    }
    return url.toString()
  } catch {
    return null
  }
}

function normalizeRatlsTarget(raw?: string | null): string | null {
  if (!raw) return null
  const trimmed = raw.trim()
  if (!trimmed) return null

  const hasProtocol = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(trimmed)
  if (hasProtocol) {
    try {
      const url = new URL(trimmed)
      const port = url.port || "443"
      return `${url.hostname}:${port}`
    } catch {
      return null
    }
  }

  const withoutPrefix = trimmed.replace(/^\/+/, "")
  const hostPort = withoutPrefix.split(/[/?#]/)[0] ?? ""
  if (!hostPort) return null
  const [host, port] = hostPort.split(":")
  const normalizedHost = host?.trim()
  if (!normalizedHost) return null
  const normalizedPort = (port && port.trim()) || "443"
  return `${normalizedHost}:${normalizedPort}`
}

function hostFromTarget(target: string): string {
  const [host] = target.split(":")
  return host || target
}

function isLoopbackHostname(host: string) {
  const normalized = host.toLowerCase()
  return normalized === "localhost" || normalized === "::1" || normalized === "0.0.0.0" || normalized.startsWith("127.")
}

function appendDefaultApiPath(baseUrl: string): string {
  try {
    const url = new URL(baseUrl)
    if (url.pathname === "/" || url.pathname === "") {
      url.pathname = "/v1"
    }
    url.hash = ""
    return stripTrailingSlash(url.toString())
  } catch {
    return stripTrailingSlash(baseUrl.endsWith("/v1") ? baseUrl : `${stripTrailingSlash(baseUrl)}/v1`)
  }
}

function wrapFetchWithMiddleware(fetchImpl: typeof fetch, cacheSalt?: string): typeof fetch {
  return async (input: RequestInfo | URL, init?: RequestInit) => {
    let request: Request
    try {
      request = input instanceof Request ? input.clone() : new Request(input, init)
    } catch {
      return fetchImpl(input, init)
    }

    if (!request.body && !init?.body) {
      return fetchImpl(input, init)
    }

    let bodyText: string
    try {
      bodyText = await request.text()
    } catch {
      return fetchImpl(input, init)
    }

    if (!bodyText) {
      return fetchImpl(input, init)
    }

    let parsed: any
    try {
      parsed = JSON.parse(bodyText)
    } catch {
      return fetchImpl(input, init)
    }

    let modified = false
    const debug = isDebugEnabled()

    if (parsed && typeof parsed === "object" && Array.isArray(parsed.messages)) {
      parsed.messages = parsed.messages.map((msg: any) => {
        let nextMsg = msg
        if (nextMsg?.role === "developer") {
          nextMsg = { ...nextMsg, role: "system" }
          modified = true
        }
        if (nextMsg?.role === "assistant" && Array.isArray(nextMsg.content)) {
          const textParts = nextMsg.content.filter((p: any) => p?.type === "output_text" || p?.type === "text")
          if (textParts.length > 0) {
            const flattened = textParts.map((p: any) => (typeof p.text === "string" ? p.text : "")).join("")
            nextMsg = { ...nextMsg, content: flattened }
            modified = true
          }
        }
        return nextMsg
      })
    }

    if (cacheSalt && parsed && typeof parsed === "object" && !("cache_salt" in parsed)) {
      parsed = { ...parsed, cache_salt: cacheSalt }
      modified = true
    }

    if (!modified) {
      if (debug) {
        console.debug("[ratls-middleware] passthrough request", { url: request.url })
      }
      return fetchImpl(input, init)
    }

    const newHeaders = new Headers(request.headers)
    if (init?.headers) {
      new Headers(init.headers).forEach((value, key) => newHeaders.set(key, value))
    }
    if (!newHeaders.has("Content-Type")) {
      newHeaders.set("Content-Type", "application/json")
    }

    const nextInit: RequestInit = {
      ...(init || {}),
      method: request.method,
      headers: newHeaders,
      body: JSON.stringify(parsed),
      signal: request.signal || init?.signal,
    }

    if (debug) {
      try {
        console.debug("[ratls-middleware] sanitized request", {
          url: request.url,
          body: parsed,
        })
      } catch {
        // ignore logging errors
      }
    }

    return fetchImpl(request.url, nextInit)
  }
}

function isDebugEnabled(): boolean {
  try {
    if (process?.env?.NEXT_PUBLIC_DEBUG_RATLS_FETCH === "true") return true
    if (typeof localStorage !== "undefined" && localStorage.getItem("DEBUG_RATLS_FETCH") === "1") return true
    if (typeof window !== "undefined" && (window as unknown as Record<string, unknown>).DEBUG_RATLS_FETCH === true) return true
  } catch {
    // ignore
  }
  return false
}

function optionalEnv(value: string | undefined): string | undefined {
  if (!value) return undefined
  const trimmed = value.trim()
  return trimmed.length > 0 ? trimmed : undefined
}

function parseNumber(value: string | undefined, fallback: number) {
  if (value === undefined || value === null) return fallback
  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

function normalizeBaseUrl(value?: string): string | undefined {
  if (!value) return undefined
  const trimmed = value.trim()
  if (!trimmed) return undefined

  const hasProtocol = /^[a-zA-Z][a-zA-Z\d+\-.]*:\/\//.test(trimmed)
  const candidate = hasProtocol ? trimmed : `https://${trimmed}`

  try {
    const url = new URL(candidate)
    url.hash = ""
    return stripTrailingSlash(url.toString())
  } catch {
    return stripTrailingSlash(trimmed)
  }
}

function stripTrailingSlash(value: string) {
  return value.endsWith("/") ? value.slice(0, -1) : value
}

function isSecureProviderUrl(value: string): boolean {
  try {
    const url = new URL(value)
    if (url.protocol === "https:") return true
    if (url.protocol === "http:" && isLoopbackHostname(url.hostname)) return true
    return false
  } catch {
    return false
  }
}

function isReasoningModel(modelId: string): boolean {
  return (modelId.startsWith("o") || modelId.startsWith("gpt-5")) && !modelId.startsWith("gpt-5-chat")
}
