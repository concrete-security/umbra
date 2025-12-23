import { NextResponse } from "next/server"

import { createFormToken } from "@/lib/security/form-token"
import { CrossOriginRequestError, ensureSameOrigin } from "@/lib/security/origin"

export async function GET(request: Request) {
  try {
    ensureSameOrigin(request)
  } catch (error) {
    if (error instanceof CrossOriginRequestError) {
      return NextResponse.json({ error: error.message }, { status: 403 })
    }
    throw error
  }

  try {
    const token = createFormToken()
    return NextResponse.json({ token })
  } catch (error) {
    console.error("Failed to issue form token", error)
    return NextResponse.json({ error: "Unable to issue a form token. Please try again later." }, { status: 500 })
  }
}
