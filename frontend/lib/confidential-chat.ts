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

type ProviderResponseChoice = {
  message?: Message & { content: string; reasoning_content?: ReasoningPayload }
  delta?: Partial<Message> & { content?: string; reasoning_content?: ReasoningPayload }
  text?: string
  finish_reason?: string | null
}

type ProviderResponse = {
  id?: string
  choices?: ProviderResponseChoice[]
  message?: string
  reply?: string
  content?: string
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

const defaultProviderApiBase = optionalEnv(process.env.NEXT_PUBLIC_VLLM_BASE_URL)
const defaultModel = optionalEnv(process.env.NEXT_PUBLIC_VLLM_MODEL)
const defaultProviderName = optionalEnv(process.env.NEXT_PUBLIC_VLLM_PROVIDER_NAME)
const defaultSystemPrompt = optionalEnv(process.env.NEXT_PUBLIC_DEFAULT_SYSTEM_PROMPT) ?? systemPrompt
const defaultMaxTokens = parseNumber(process.env.NEXT_PUBLIC_DEFAULT_MAX_TOKENS, 4098)
const defaultTemperature = parseNumber(process.env.NEXT_PUBLIC_DEFAULT_TEMPERATURE, 0.7)

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

  const requestBody: Record<string, unknown> = {
    model,
    messages: sanitizedMessages,
    temperature,
    max_tokens: maxTokens,
    stream,
  }

  if (payload.reasoning_effort) {
    requestBody.reasoning_effort = payload.reasoning_effort
  }
  if (payload.cache_salt) {
    requestBody.cache_salt = payload.cache_salt
  }

  const endpoint = `${resolved.baseUrl}/v1/chat/completions`
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  }
  if (resolved.apiKey) {
    headers.Authorization = `Bearer ${resolved.apiKey}`
  }

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(requestBody),
      cache: "no-store",
      signal: options.signal,
    })

    if (!response.ok) {
      const message = await readProviderError(response)
      yield { type: "error", error: message }
      return
    }

    if (!stream) {
      const payloadJson = (await response.json()) as ProviderResponse
      const result = parseNonStreamingResponse(payloadJson)
      yield {
        type: "done",
        content: result.message,
        reasoning_content: result.reasoning_content,
        finish_reason: result.finish_reason,
      }
      return
    }

    const reader = response.body?.getReader()
    if (!reader) {
      yield { type: "error", error: "Streaming is not supported in this environment." }
      return
    }

    for await (const chunk of readStreamingResponse(reader)) {
      yield chunk
    }
  } catch (error) {
    const rawMessage = extractErrorMessage(error)
    const interpreted = interpretProviderError(rawMessage)
    yield { type: "error", error: interpreted?.message ?? rawMessage }
  }
}

async function* readStreamingResponse(
  reader: ReadableStreamDefaultReader<Uint8Array>
): AsyncGenerator<ConfidentialChatStreamChunk, void, unknown> {
  const decoder = new TextDecoder()
  let buffer = ""
  let accumulatedContent = ""
  let accumulatedReasoning = ""
  let finishReason: string | undefined

  try {
    while (true) {
      const { value, done } = await reader.read()
      buffer += decoder.decode(value ?? new Uint8Array(), { stream: !done })

      let newlineIndex = buffer.indexOf("\n")
      while (newlineIndex >= 0) {
        const rawLine = buffer.slice(0, newlineIndex).trim()
        buffer = buffer.slice(newlineIndex + 1)

        if (!rawLine || rawLine.startsWith(":")) {
          newlineIndex = buffer.indexOf("\n")
          continue
        }

        if (!rawLine.startsWith("data:")) {
          newlineIndex = buffer.indexOf("\n")
          continue
        }

        const data = rawLine.slice(5).trim()
        if (!data) {
          newlineIndex = buffer.indexOf("\n")
          continue
        }

        if (data === "[DONE]") {
          yield {
            type: "done",
            content: accumulatedContent,
            reasoning_content: accumulatedReasoning || undefined,
            finish_reason: finishReason,
          }
          return
        }

        try {
          const parsed = JSON.parse(data) as ProviderResponse
          const choice = parsed.choices?.[0]
          if (!choice) {
            newlineIndex = buffer.indexOf("\n")
            continue
          }

          if (choice.finish_reason && !finishReason) {
            finishReason = choice.finish_reason
          }

          const deltaContent = extractContentDelta(choice.delta?.content)
          const messageContent = extractContentDelta(choice.message?.content)
          const reasoningDelta = extractReasoningDelta(choice.delta)
          const reasoningMessageFull = normalizeReasoning(choice.message?.reasoning_content)

          const contentPiece = deltaContent || computeRemainder(messageContent, accumulatedContent)
          const reasoningPiece = reasoningDelta || computeRemainder(reasoningMessageFull, accumulatedReasoning)

          if (contentPiece) {
            accumulatedContent += contentPiece
            yield { type: "delta", content: contentPiece }
          }

          if (reasoningPiece) {
            accumulatedReasoning += reasoningPiece
            yield { type: "reasoning_delta", reasoning_content: reasoningPiece }
          }
        } catch (error) {
          console.error("Failed to parse stream line", data, error)
          const rawMessage = extractErrorMessage(error)
          const interpreted = interpretProviderError(rawMessage)
          yield { type: "error", error: interpreted?.message ?? rawMessage }
          return
        }

        newlineIndex = buffer.indexOf("\n")
      }

      if (done) {
        break
      }
    }

    const remaining = buffer.trim()
    if (remaining.startsWith("data:")) {
      const data = remaining.slice(5).trim()
      if (data === "[DONE]") {
        yield {
          type: "done",
          content: accumulatedContent,
          reasoning_content: accumulatedReasoning || undefined,
          finish_reason: finishReason,
        }
        return
      }

      try {
        const parsed = JSON.parse(data) as ProviderResponse
        const choice = parsed.choices?.[0]
        if (choice) {
          if (choice.finish_reason && !finishReason) {
            finishReason = choice.finish_reason
          }

          const deltaContent = extractContentDelta(choice.delta?.content)
          const messageContent = extractContentDelta(choice.message?.content)
          const reasoningDelta = extractReasoningDelta(choice.delta)
          const reasoningMessageFull = normalizeReasoning(choice.message?.reasoning_content)

          const contentPiece = deltaContent || computeRemainder(messageContent, accumulatedContent)
          const reasoningPiece = reasoningDelta || computeRemainder(reasoningMessageFull, accumulatedReasoning)

          if (contentPiece) {
            accumulatedContent += contentPiece
            yield { type: "delta", content: contentPiece }
          }

          if (reasoningPiece) {
            accumulatedReasoning += reasoningPiece
            yield { type: "reasoning_delta", reasoning_content: reasoningPiece }
          }
        }
      } catch (error) {
        console.error("Failed to parse trailing stream line", data, error)
        const rawMessage = extractErrorMessage(error)
        const interpreted = interpretProviderError(rawMessage)
        yield { type: "error", error: interpreted?.message ?? rawMessage }
        return
      }
    }

    yield {
      type: "done",
      content: accumulatedContent,
      reasoning_content: accumulatedReasoning || undefined,
      finish_reason: finishReason,
    }
  } finally {
    reader.releaseLock()
  }
}

function resolveProviderConfig(provider?: ConfidentialChatProviderConfig): ResolvedProviderConfig {
  const baseUrl = normalizeBaseUrl(provider?.baseUrl ?? defaultProviderApiBase)
  const apiKey = optionalEnv(provider?.apiKey)
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

function parseNonStreamingResponse(payload: ProviderResponse) {
  const first = payload.choices?.[0]
  const message =
    first?.message?.content ??
    getProviderResponseText(payload) ??
    JSON.stringify(payload)
  const reasoningContent = extractReasoningFromChoice(first) ?? undefined
  const finishReason = first?.finish_reason ?? undefined

  return {
    message,
    reasoning_content: reasoningContent,
    finish_reason: finishReason,
  }
}

async function readProviderError(response: Response): Promise<string> {
  let text = ""
  try {
    text = await response.text()
  } catch (error) {
    console.error("Failed to read provider error response", error)
  }

  const fallback = response.statusText || `Provider returned ${response.status}`

  if (!text) {
    return fallback
  }

  try {
    const parsed = JSON.parse(text) as unknown
    const rawMessage = extractErrorMessage(parsed)
    const interpreted = interpretProviderError(rawMessage)
    return interpreted?.message ?? rawMessage
  } catch {
    const trimmed = text.trim()
    if (!trimmed) {
      return fallback
    }
    const interpreted = interpretProviderError(trimmed)
    return interpreted?.message ?? trimmed
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

function getProviderResponseText(payload: ProviderResponse): string | null {
  if (!payload) {
    return null
  }

  if (typeof payload.message === "string" && payload.message.trim().length > 0) {
    return payload.message.trim()
  }

  if (typeof payload.reply === "string" && payload.reply.trim().length > 0) {
    return payload.reply.trim()
  }

  if (typeof payload.content === "string" && payload.content.trim().length > 0) {
    return payload.content.trim()
  }

  const firstChoice = payload.choices?.[0]
  if (firstChoice?.message?.content) {
    return firstChoice.message.content.trim()
  }

  if (firstChoice?.text) {
    return firstChoice.text.trim()
  }

  if (firstChoice?.delta?.content) {
    return firstChoice.delta.content.trim()
  }

  return null
}

function extractContentDelta(content: unknown): string {
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

function normalizeReasoning(value: unknown): string {
  if (!value) return ""
  if (typeof value === "string") return value
  if (Array.isArray(value)) {
    return value.map((item) => normalizeReasoning(item)).join("")
  }
  if (typeof value === "object") {
    const typed = value as Record<string, unknown>
    if (typeof typed.text === "string") return typed.text
    if (typeof typed.reasoning === "string") return typed.reasoning
    if (Array.isArray(typed.content)) return typed.content.map((item) => normalizeReasoning(item)).join("")
    if (typeof typed.content === "string") return typed.content
    if (typeof typed.output_text === "string") return typed.output_text
  }
  return ""
}

function extractReasoningDelta(delta: unknown): string {
  if (!delta || typeof delta !== "object") return ""
  const typed = delta as Record<string, unknown>
  const reasoningSource = typed.reasoning_content ?? typed.reasoning
  return normalizeReasoning(reasoningSource)
}

function computeRemainder(full: string, seen: string): string {
  if (!full) return ""
  if (!seen) return full
  if (full.startsWith(seen)) {
    return full.slice(seen.length)
  }
  return full
}

function extractReasoningFromChoice(choice?: ProviderResponseChoice): string | null {
  if (!choice) return null
  const fromMessage = normalizeReasoning(choice.message?.reasoning_content)
  if (fromMessage) return fromMessage
  const fromChoice = normalizeReasoning((choice as unknown as Record<string, unknown>)?.reasoning_content)
  if (fromChoice) return fromChoice
  return null
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
