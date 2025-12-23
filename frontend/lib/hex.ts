const HEX_PATTERN = /^[0-9a-f]+$/i

function stripPrefix(value: string) {
  return value.startsWith("0x") || value.startsWith("0X") ? value.slice(2) : value
}

export function normalizeHex(value?: string | null): string {
  if (!value) {
    throw new Error("Hex value is required.")
  }
  const trimmed = value.trim()
  if (!trimmed) {
    throw new Error("Hex value is required.")
  }
  const body = stripPrefix(trimmed).toLowerCase()
  if (!body) {
    throw new Error("Hex value is empty.")
  }
  if (body.length % 2 !== 0) {
    throw new Error("Hex value must contain an even number of characters.")
  }
  if (!HEX_PATTERN.test(body)) {
    throw new Error("Hex value contains invalid characters.")
  }
  return body
}

export function hexToBytes(value: string): Uint8Array {
  const normalized = normalizeHex(value)
  const bytes = new Uint8Array(normalized.length / 2)
  for (let index = 0; index < normalized.length; index += 2) {
    bytes[index / 2] = Number.parseInt(normalized.slice(index, index + 2), 16)
  }
  return bytes
}

export function bytesToHex(bytes: ArrayLike<number>): string {
  const out = new Array(bytes.length)
  for (let index = 0; index < bytes.length; index += 1) {
    out[index] = bytes[index].toString(16).padStart(2, "0")
  }
  return out.join("")
}

export function ensureHexOrNull(value?: string | null): string | null {
  try {
    return value ? normalizeHex(value) : null
  } catch {
    return null
  }
}

export function withHexPrefix(value: string): string {
  return `0x${value}`
}
