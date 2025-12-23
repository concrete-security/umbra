import { createHmac, randomBytes } from "node:crypto"

const TOKEN_TTL_MS = 10 * 60 * 1000
const TOKEN_SECRET = process.env.FORM_TOKEN_SECRET

function requireSecret() {
  if (!TOKEN_SECRET) {
    throw new Error("FORM_TOKEN_SECRET must be configured")
  }
  return TOKEN_SECRET
}

export class FormTokenError extends Error {
  constructor(message: string) {
    super(message)
    this.name = "FormTokenError"
  }
}

export function createFormToken() {
  const secret = requireSecret()
  const nonce = randomBytes(16).toString("hex")
  const issuedAt = Date.now()
  const payload = `${nonce}.${issuedAt}`
  const signature = createHmac("sha256", secret).update(payload).digest("hex")
  return `${payload}.${signature}`
}

export function verifyFormToken(token: unknown) {
  if (typeof token !== "string" || token.split(".").length !== 3) {
    throw new FormTokenError("Form token is malformed.")
  }

  const [nonce, timestamp, signature] = token.split(".")
  if (!nonce || !timestamp || !signature) {
    throw new FormTokenError("Form token is incomplete.")
  }

  const issuedAt = Number(timestamp)
  if (!Number.isFinite(issuedAt)) {
    throw new FormTokenError("Form token timestamp is invalid.")
  }

  if (Date.now() - issuedAt > TOKEN_TTL_MS) {
    throw new FormTokenError("Form token expired. Refresh the page and try again.")
  }

  const expected = createHmac("sha256", requireSecret())
    .update(`${nonce}.${timestamp}`)
    .digest("hex")

  if (!timingSafeEqual(signature, expected)) {
    throw new FormTokenError("Form token signature mismatch.")
  }
}

function timingSafeEqual(a: string, b: string) {
  if (a.length !== b.length) {
    return false
  }

  let result = 0
  for (let index = 0; index < a.length; index += 1) {
    result |= a.charCodeAt(index) ^ b.charCodeAt(index)
  }
  return result === 0
}

export const FORM_TOKEN_TTL_MS = TOKEN_TTL_MS
