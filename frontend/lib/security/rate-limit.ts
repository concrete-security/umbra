const buckets = new Map<string, { count: number; expiresAt: number }>()

export class RateLimitError extends Error {
  retryAfter: number

  constructor(message: string, retryAfter: number) {
    super(message)
    this.name = "RateLimitError"
    this.retryAfter = retryAfter
  }
}

export function enforceRateLimit(key: string, limit: number, windowMs: number) {
  const now = Date.now()
  const entry = buckets.get(key)

  if (!entry || entry.expiresAt <= now) {
    buckets.set(key, { count: 1, expiresAt: now + windowMs })
    return
  }

  if (entry.count >= limit) {
    const retryAfter = Math.max(0, Math.ceil((entry.expiresAt - now) / 1000))
    throw new RateLimitError("Too many requests. Please slow down.", retryAfter)
  }

  entry.count += 1
}
