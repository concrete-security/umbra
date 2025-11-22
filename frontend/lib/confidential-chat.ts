import { systemPrompt } from "./system-prompt"

export type ConfidentialChatMessage = {
  role: "user" | "assistant" | "system"
  content: string
}

export type ConfidentialChatPayload = {
  messages: ConfidentialChatMessage[]
  model?: string
  temperature?: number
  max_tokens?: number
  stream?: boolean
  reasoning_effort?: "low" | "medium" | "high"
  cache_salt?: string
}

export type ConfidentialChatProviderConfig = {
  baseUrl?: string
  apiKey?: string
  systemPrompt?: string
}

export type ConfidentialChatOptions = {
  signal?: AbortSignal
  provider?: ConfidentialChatProviderConfig
}

export type ConfidentialChatStreamChunk =
  | { type: "delta"; content: string }
  | { type: "reasoning_delta"; reasoning_content: string }
  | { type: "done"; content: string; reasoning_content?: string; finish_reason?: string }
  | { type: "error"; error: string }

type ReasoningPayload = unknown

type Message = {
  role: "system" | "user" | "assistant"
  content: string
  reasoning_content?: ReasoningPayload
}

type ProviderErrorInfo = {
  status: number
  message: string
}

type ResolvedProviderConfig = {
  baseUrl?: string
  apiKey?: string
  model?: string
  systemPrompt: string
  temperature: number
  maxTokens: number
}

export type RatlsConfig = {
  proxyUrl: string
  targetHost: string
  serverName: string
}

type AiMessage = {
  role: "system" | "user" | "assistant"
  content: string
}

const defaultProviderApiBase = optionalEnv(process.env.NEXT_PUBLIC_VLLM_BASE_URL)
const defaultModel = optionalEnv(process.env.NEXT_PUBLIC_VLLM_MODEL)
const defaultProviderName = optionalEnv(process.env.NEXT_PUBLIC_VLLM_PROVIDER_NAME)
const defaultSystemPrompt = optionalEnv(process.env.NEXT_PUBLIC_DEFAULT_SYSTEM_PROMPT) ?? systemPrompt
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
  systemPrompt: defaultSystemPrompt,
  defaultMaxTokens,
  defaultTemperature,
}

export async function* streamConfidentialChat(
  payload: ConfidentialChatPayload,
  options: ConfidentialChatOptions = {}
): AsyncGenerator<ConfidentialChatStreamChunk, void, unknown> {
  const resolved = resolveProviderConfig(options.provider)

  if (!resolved.baseUrl) {
    yield { type: "error", error: "No provider base URL configured. Please set the provider URL in the Provider settings." }
    return
  }

  // Enforce HTTPS in production (allow loopback for local development)
  if (!isSecureProviderUrl(resolved.baseUrl)) {
    yield {
      type: "error",
      error: "Insecure provider URL: use https:// (or localhost/127.0.0.1 for local dev).",
    }
    return
  }

  let sanitizedMessages: Message[]
  try {
    sanitizedMessages = ensureSystemMessage(sanitizeMessages(payload.messages), resolved.systemPrompt)
  } catch (error) {
    const rawMessage = extractErrorMessage(error)
    yield { type: "error", error: rawMessage }
    return
  }

  const model = optionalEnv(payload.model) ?? resolved.model
  if (!model) {
    yield { type: "error", error: "No model specified. Please set a model ID in the Provider settings." }
    return
  }

  const temperature = typeof payload.temperature === "number" ? payload.temperature : resolved.temperature
  const maxTokens = typeof payload.max_tokens === "number" ? payload.max_tokens : resolved.maxTokens
  const stream = payload.stream !== false

  const ratlsConfig = resolveRatlsConfig(resolved.baseUrl)
  if (!ratlsConfig) {
    yield {
      type: "error",
      error:
        "RA-TLS proxy configuration is missing or insecure. Set NEXT_PUBLIC_RATLS_PROXY_URL (wss:// in production) and NEXT_PUBLIC_RATLS_TARGET (or provide a provider URL that includes host:port).",
    }
    return
  }

  const aiMessages = sanitizedMessages.map((message) => ({ role: message.role, content: message.content }))
  for await (const chunk of streamWithRatlsAiSdk({
    messages: aiMessages,
    model,
    temperature,
    maxTokens,
    stream,
    cacheSalt: payload.cache_salt,
    reasoningEffort: payload.reasoning_effort,
    providerApiKey: resolved.apiKey,
    providerBaseUrl: resolved.baseUrl,
    ratlsConfig,
    signal: options.signal,
  })) {
    yield chunk
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

type RatlsStreamOptions = {
  messages: AiMessage[]
  model: string
  temperature: number
  maxTokens: number
  stream: boolean
  cacheSalt?: string
  reasoningEffort?: ConfidentialChatPayload["reasoning_effort"]
  providerApiKey?: string
  providerBaseUrl?: string
  ratlsConfig: RatlsConfig
  signal?: AbortSignal
}

async function* streamWithRatlsAiSdk({
  messages,
  model,
  temperature,
  maxTokens,
  stream,
  cacheSalt,
  reasoningEffort,
  providerApiKey,
  providerBaseUrl,
  ratlsConfig,
  signal,
}: RatlsStreamOptions): AsyncGenerator<ConfidentialChatStreamChunk, void, unknown> {
  try {
    const [{ createRatlsFetch }] = await Promise.all([
      import("../ratls/wasm/pkg/ratls-fetch.js"),
    ])

    const baseFetch = createRatlsFetch({
      proxyUrl: ratlsConfig.proxyUrl,
      targetHost: ratlsConfig.targetHost,
      serverName: ratlsConfig.serverName,
      defaultHeaders: providerApiKey ? { Authorization: `Bearer ${providerApiKey}` } : undefined,
    })
    const ratlsFetch = wrapFetchWithMiddleware(baseFetch, cacheSalt)

    const apiBase = appendDefaultApiPath(providerBaseUrl ?? `https://${ratlsConfig.serverName}`)
    if (process.env.NEXT_PUBLIC_DEBUG_RATLS_FETCH === "true") {
      console.debug("[confidential-chat] streaming via RA-TLS", {
        baseURL: apiBase,
        model,
        target: ratlsConfig.targetHost,
        proxy: ratlsConfig.proxyUrl,
        sni: ratlsConfig.serverName,
        hasApiKey: Boolean(providerApiKey),
      })
    }

    const endpoint = `${apiBase}/chat/completions`
    const body: Record<string, unknown> = {
      model,
      messages,
      temperature,
      max_tokens: maxTokens,
      stream,
    }
    if (cacheSalt) {
      body.cache_salt = cacheSalt
    }
    if (reasoningEffort) {
      body.reasoning_effort = reasoningEffort
    }

    const response = await ratlsFetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(providerApiKey ? { Authorization: `Bearer ${providerApiKey}` } : {}),
      },
      body: JSON.stringify(body),
      cache: "no-store",
      signal,
    })

    if (!response.ok) {
      const message = await readProviderError(response)
      yield { type: "error", error: message }
      return
    }

    if (!stream) {
      const payloadJson = (await response.json()) as any
      const choice = payloadJson?.choices?.[0]
      const content = extractText(choice?.message?.content) ?? ""
      const finishReason = choice?.finish_reason ?? undefined
      yield {
        type: "done",
        content,
        reasoning_content: extractReasoning(choice?.message?.reasoning_content ?? choice?.message?.reasoning) || undefined,
        finish_reason: finishReason,
      }
      return
    }

    const reader = response.body?.getReader()
    if (!reader) {
      yield { type: "error", error: "Streaming is not supported in this environment." }
      return
    }

    let accumulatedContent = ""
    let accumulatedReasoning = ""
    let finishReason: string | undefined

    const decoder = new TextDecoder()
    let buffer = ""

    while (true) {
      const { done, value } = await reader.read()
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: !done })

      let newlineIndex = buffer.indexOf("\n")
      while (newlineIndex >= 0) {
        const rawLine = buffer.slice(0, newlineIndex).trim()
        buffer = buffer.slice(newlineIndex + 1)

        if (rawLine.startsWith("data:")) {
          const data = rawLine.slice(5).trim()
          if (data === "[DONE]") {
            yield {
              type: "done",
              content: accumulatedContent,
              finish_reason: finishReason,
            }
            return
          }
          try {
            const parsed = JSON.parse(data) as any
            const choice = parsed?.choices?.[0]
            if (choice?.finish_reason && !finishReason) {
              finishReason = choice.finish_reason
            }
            const delta = extractText(choice?.delta?.content)
            const reasoningDelta = extractReasoning(choice?.delta?.reasoning_content ?? choice?.delta?.reasoning)
            if (delta) {
              accumulatedContent += delta
              yield { type: "delta", content: delta }
            }
            if (reasoningDelta) {
              accumulatedReasoning += reasoningDelta
              yield { type: "reasoning_delta", reasoning_content: reasoningDelta }
            }
          } catch (err) {
            const rawMessage = extractErrorMessage(err)
            const interpreted = interpretProviderError(rawMessage)
            yield { type: "error", error: interpreted?.message ?? rawMessage }
            return
          }
        }

        newlineIndex = buffer.indexOf("\n")
      }

      if (done) {
        break
      }
    }

    yield {
      type: "done",
      content: accumulatedContent,
      reasoning_content: accumulatedReasoning || undefined,
      finish_reason: finishReason,
    }
  } catch (error) {
    if (process.env.NEXT_PUBLIC_DEBUG_RATLS_FETCH === "true") {
      console.error("[confidential-chat] RA-TLS stream failed", {
        target: ratlsConfig.targetHost,
        proxy: ratlsConfig.proxyUrl,
        sni: ratlsConfig.serverName,
        baseURL: providerBaseUrl ?? `https://${ratlsConfig.serverName}`,
        error,
      })
    }
    const rawMessage = extractErrorMessage(error)
    const interpreted = interpretProviderError(rawMessage)
    yield { type: "error", error: interpreted?.message ?? rawMessage }
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

/**
 * Wraps the RA-TLS fetch with a middleware layer to sanitise requests.
 * - Maps 'developer' role back to 'system'.
 * - Flattens structured assistant content arrays into plain strings.
 * - Injects cache_salt if provided.
 * - Handles both URL strings and Request objects (cloning bodies safely).
 */
function wrapFetchWithMiddleware(fetchImpl: typeof fetch, cacheSalt?: string): typeof fetch {
  return async (input: RequestInfo | URL, init?: RequestInit) => {
    let request: Request
    try {
      request = input instanceof Request ? input.clone() : new Request(input, init)
    } catch {
      return fetchImpl(input, init)
    }

    // No body to sanitize
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

function resolveProviderConfig(provider?: ConfidentialChatProviderConfig): ResolvedProviderConfig {
  const baseUrl = normalizeBaseUrl(provider?.baseUrl ?? defaultProviderApiBase)
  const apiKey = optionalEnv(provider?.apiKey) ?? defaultProviderToken ?? "placeholder-token"
  const model = defaultModel
  const resolvedSystemPrompt = optionalEnv(provider?.systemPrompt) ?? defaultSystemPrompt
  const temperature = defaultTemperature
  const maxTokens = defaultMaxTokens

  return {
    baseUrl,
    apiKey,
    model,
    systemPrompt: resolvedSystemPrompt,
    temperature,
    maxTokens,
  }
}

function sanitizeMessages(messages: ConfidentialChatMessage[]): Message[] {
  return messages.map((msg) => {
    const role = msg.role
    const content = msg.content

    if (role !== "system" && role !== "user" && role !== "assistant") {
      throw new Error("Invalid message role")
    }

    if (typeof content !== "string" || content.trim().length === 0) {
      throw new Error("Message content must be a non-empty string")
    }

    return {
      role,
      content,
    }
  })
}

function ensureSystemMessage(messages: Message[], providedPrompt: string): Message[] {
  if (messages.some((msg) => msg.role === "system")) {
    return messages
  }
  return [{ role: "system", content: providedPrompt }, ...messages]
}

function extractErrorMessage(error: unknown): string {
  if (!error) return "Unknown error"
  if (typeof error === "string") {
    return error
  }

  const maybeRecord = error as Record<string, unknown>
  const nestedError = maybeRecord?.error

  if (nestedError && typeof nestedError === "object") {
    const nestedMessage = (nestedError as Record<string, unknown>)?.message
    if (typeof nestedMessage === "string" && nestedMessage.trim().length > 0) {
      return nestedMessage.trim()
    }
  }

  const directMessage = maybeRecord?.message
  if (typeof directMessage === "string" && directMessage.trim().length > 0) {
    return directMessage.trim()
  }

  if (error instanceof Error && typeof error.message === "string" && error.message.trim().length > 0) {
    return error.message.trim()
  }

  return "Unknown error"
}

function interpretProviderError(message: string): ProviderErrorInfo | null {
  const trimmed = message.trim()
  if (!trimmed) {
    return null
  }

  const lower = trimmed.toLowerCase()

  const maxTokenPatterns = [
    /max_tokens must be at least 1/,
    /max tokens must be greater than 0/,
    /maximum context length/,
    /prompt is too long/,
    /context length exceeded/,
  ]

  if (maxTokenPatterns.some((pattern) => pattern.test(lower))) {
    return {
      status: 400,
      message: "This request is larger than the model can process. Try removing some content.",
    }
  }

  const authPatterns = [/unauthorized/, /forbidden/, /invalid api key/, /not permitted/, /missing api key/]
  if (authPatterns.some((pattern) => pattern.test(lower))) {
    return {
      status: 401,
      message: "Authorization failed. Check the bearer token you supplied in Provider settings.",
    }
  }

  // Check for specific network error patterns
  if (/failed to fetch|networkerror|load failed/.test(lower)) {
    return {
      status: 503,
      message: "Cannot connect to the provider. Please check that the provider URL is correct and the service is running.",
    }
  }

  if (/cors/.test(lower)) {
    return {
      status: 503,
      message: "CORS error: The provider is blocking requests from this domain. Please check the provider's CORS configuration.",
    }
  }

  if (/certificate|ssl|tls/.test(lower)) {
    return {
      status: 503,
      message: "TLS/SSL certificate error. Please verify the provider URL uses the correct protocol (https://) and has a valid certificate.",
    }
  }

  if (/timed out|timeout/.test(lower)) {
    return {
      status: 503,
      message: "Request timed out. The provider may be overloaded or unreachable. Please try again later.",
    }
  }

  if (/connection refused|connection reset|econnrefused/.test(lower)) {
    return {
      status: 503,
      message: "Connection refused. The provider service may be down or the URL may be incorrect. Please check the provider settings.",
    }
  }

  return null
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

function isLoopbackHostname(host: string) {
  const h = host.toLowerCase()
  return h === 'localhost' || h === '::1' || h === '0.0.0.0' || h.startsWith('127.')
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

function isSecureProviderUrl(value: string): boolean {
  try {
    const url = new URL(value)
    if (url.protocol === 'https:') return true
    if (url.protocol === 'http:' && isLoopbackHostname(url.hostname)) return true
    return false
  } catch {
    return false
  }
}

function extractText(content: unknown): string {
  if (!content) return ""
  if (typeof content === "string") return content
  if (Array.isArray(content)) {
    return content
      .map((part) => {
        if (!part) return ""
        if (typeof part === "string") return part
        if (typeof part === "object" && typeof (part as { text?: string }).text === "string") {
          return (part as { text: string }).text
        }
        return ""
      })
      .join("")
  }
  if (typeof content === "object" && typeof (content as { text?: string }).text === "string") {
    return (content as { text: string }).text
  }
  return ""
}

function extractReasoning(value: unknown): string {
  if (!value) return ""
  if (typeof value === "string") return value
  if (Array.isArray(value)) {
    return value
      .map((part) => {
        if (!part) return ""
        if (typeof part === "string") return part
        if (typeof part === "object" && typeof (part as { text?: string }).text === "string") {
          return (part as { text: string }).text
        }
        return ""
      })
      .join("")
  }
  if (typeof value === "object") {
    const typed = value as Record<string, unknown>
    if (typeof typed.text === "string") return typed.text
    if (Array.isArray(typed.content)) return extractReasoning(typed.content)
    if (typeof typed.content === "string") return typed.content
  }
  return ""
}
