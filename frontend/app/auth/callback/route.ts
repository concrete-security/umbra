import { cookies } from "next/headers"
import { NextResponse } from "next/server"
import type { AuthChangeEvent, Session } from "@supabase/supabase-js"
import { createServerClient } from "@supabase/ssr"

import type { Database } from "@/lib/supabase/types"

export async function GET(request: Request) {
  const requestUrl = new URL(request.url)
  const code = requestUrl.searchParams.get("code")
  const rawRedirect = requestUrl.searchParams.get("next")
  const redirectPath = rawRedirect && rawRedirect.startsWith("/") ? rawRedirect : "/confidential-ai"
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

  if (!code) {
    return NextResponse.redirect(new URL(redirectPath, requestUrl.origin))
  }

  if (!supabaseUrl || !supabaseAnonKey) {
    console.warn("Supabase callback skipped: environment variables missing.")
    return NextResponse.redirect(new URL(redirectPath, requestUrl.origin))
  }

  try {
    const cookieStore = await cookies()
    const supabase = createServerClient<Database>(
      supabaseUrl,
      supabaseAnonKey,
      {
        cookies: {
          getAll() {
            return cookieStore.getAll()
          },
          setAll(cookiesToSet) {
            try {
              cookiesToSet.forEach(({ name, value, options }) =>
                cookieStore.set(name, value, options)
              )
            } catch {
              // Ignore errors
            }
          },
        },
      }
    )
    await supabase.auth.exchangeCodeForSession(code)
  } catch (error) {
    console.error("Failed to exchange Supabase auth code for session", error)
  }

  return NextResponse.redirect(new URL(redirectPath, requestUrl.origin))
}

type AuthCallbackPayload = {
  event: AuthChangeEvent
  session: Session | null
}

export async function POST(request: Request) {
  try {
    const { event, session } = (await request.json().catch(() => ({}))) as Partial<AuthCallbackPayload>
    const cookieStore = await cookies()
    const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
    const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

    if (!supabaseUrl || !supabaseAnonKey) {
      console.warn("Supabase callback POST skipped: environment variables missing.")
      return NextResponse.json({ ok: false, error: "Supabase environment not configured." }, { status: 500 })
    }

    const supabase = createServerClient<Database>(
      supabaseUrl,
      supabaseAnonKey,
      {
        cookies: {
          getAll() {
            return cookieStore.getAll()
          },
          setAll(cookiesToSet) {
            try {
              cookiesToSet.forEach(({ name, value, options }) =>
                cookieStore.set(name, value, options)
              )
            } catch {
              // Ignore errors
            }
          },
        },
      }
    )

    if (event === "SIGNED_OUT") {
      await supabase.auth.signOut()
      return NextResponse.json({ ok: true })
    }

    if ((event === "SIGNED_IN" || event === "TOKEN_REFRESHED") && session) {
      await supabase.auth.setSession(session)
      return NextResponse.json({ ok: true })
    }

    return NextResponse.json({ ok: true })
  } catch (error) {
    console.error("Failed to persist Supabase auth session", error)
    return NextResponse.json({ ok: false, error: "Failed to persist Supabase auth session" }, { status: 500 })
  }
}
