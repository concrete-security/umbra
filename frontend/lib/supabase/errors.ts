type MaybeAuthError = {
  message?: unknown
  status?: unknown
}

function extractMessage(error: unknown): string | null {
  if (!error) {
    return null
  }
  if (typeof error === 'string') {
    return error
  }
  if (error instanceof Error) {
    return error.message
  }
  if (typeof error === 'object' && error !== null && 'message' in error) {
    const message = (error as MaybeAuthError).message
    return typeof message === 'string' ? message : null
  }
  return null
}

function extractStatus(error: unknown): number | null {
  if (typeof error === 'object' && error !== null && 'status' in error) {
    const status = (error as MaybeAuthError).status
    return typeof status === 'number' ? status : null
  }
  return null
}

export function isAuthSessionMissingError(error: unknown): boolean {
  const message = extractMessage(error)?.toLowerCase() ?? null
  if (message && message.includes('auth session missing')) {
    return true
  }

  const status = extractStatus(error)
  if (status === 401 || status === 403) {
    // Supabase returns 401/403 when the session cookie has expired or is absent.
    return !!message && message.includes('session')
  }

  return false
}
