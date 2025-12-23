import type { SupabaseClient, User } from "@supabase/supabase-js"

import type { Database } from "@/lib/supabase/types"
import { isAuthSessionMissingError } from "@/lib/supabase/errors"

export class AuthenticatedAccessError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.status = status
    this.name = "AuthenticatedAccessError"
  }
}

type TypedSupabaseClient = SupabaseClient<Database>

export async function getAuthUser(client: TypedSupabaseClient): Promise<User | null> {
  const { data, error } = await client.auth.getUser()

  if (error) {
    if (isAuthSessionMissingError(error)) {
      return null
    }

    const status = typeof error.status === "number" ? error.status : 500
    throw new AuthenticatedAccessError(error.message, status)
  }

  return data?.user ?? null
}

export async function requireAdminUser(client: TypedSupabaseClient): Promise<User> {
  const user = await getAuthUser(client)

  if (!user) {
    throw new AuthenticatedAccessError("Authentication required", 401)
  }

  const roles = (user.app_metadata?.roles as string[] | undefined) ?? []
  if (!roles.includes("admin")) {
    throw new AuthenticatedAccessError("Administrator role required", 403)
  }

  return user
}
