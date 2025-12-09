export function getClientIp(request: Request): string {
  const headerValue =
    request.headers.get("x-forwarded-for") ??
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-real-ip") ??
    ""

  if (headerValue) {
    const first = headerValue.split(",")[0].trim()
    if (first) {
      return first
    }
  }

  return "unknown"
}
