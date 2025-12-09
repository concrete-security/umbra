import { bytesToHex } from "./hex"

function ensureUint8Array(value: ArrayBuffer | ArrayBufferView | Uint8Array): Uint8Array {
  if (value instanceof Uint8Array) {
    return value
  }
  if (ArrayBuffer.isView(value)) {
    const view = value as ArrayBufferView
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength)
  }
  if (value instanceof ArrayBuffer) {
    return new Uint8Array(value)
  }
  throw new TypeError("Unsupported data type for hashing.")
}

function getCrypto(): Crypto {
  if (typeof window !== "undefined") {
    if (window.crypto?.subtle) {
      return window.crypto
    }
    const isLocalhost = window.location?.hostname === "localhost" || 
                        window.location?.hostname === "127.0.0.1" ||
                        window.location?.hostname?.endsWith(".localhost")
    if (window.location?.protocol === "http:" && !isLocalhost) {
      throw new Error(
        `WebCrypto requires HTTPS or localhost. Current URL: ${window.location?.protocol}//${window.location?.hostname}. Please access over HTTPS or use localhost/127.0.0.1 for development.`
      )
    }
  }
  if (typeof globalThis !== "undefined") {
    const provider = (globalThis.crypto ??
      (globalThis as { webcrypto?: Crypto }).webcrypto) as Crypto | undefined
    if (provider?.subtle && typeof provider.subtle.digest === "function") {
      return provider
    }
  }
  if (typeof crypto !== "undefined" && crypto.subtle) {
    return crypto
  }
  const context = typeof window !== "undefined" ? "browser" : typeof globalThis !== "undefined" ? "global" : "unknown"
  throw new Error(
    `WebCrypto is unavailable in this environment (${context}). Ensure you're using a modern browser with WebCrypto support and accessing over HTTPS.`
  )
}

async function digestBytes(
  algorithm: AlgorithmIdentifier,
  data: ArrayBuffer | ArrayBufferView | Uint8Array
): Promise<Uint8Array> {
  const provider = getCrypto()
  const bytes = ensureUint8Array(data)
  const digest = await provider.subtle.digest(algorithm, bytes.slice().buffer)
  return new Uint8Array(digest)
}

export async function sha384Bytes(
  data: ArrayBuffer | ArrayBufferView | Uint8Array
): Promise<Uint8Array> {
  return digestBytes("SHA-384", data)
}

export async function sha384Hex(
  data: ArrayBuffer | ArrayBufferView | Uint8Array
): Promise<string> {
  return bytesToHex(await sha384Bytes(data))
}

export async function sha256Bytes(
  data: ArrayBuffer | ArrayBufferView | Uint8Array
): Promise<Uint8Array> {
  return digestBytes("SHA-256", data)
}

export async function sha256Hex(
  data: ArrayBuffer | ArrayBufferView | Uint8Array
): Promise<string> {
  return bytesToHex(await sha256Bytes(data))
}
