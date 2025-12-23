import { NextResponse } from "next/server"

import { sendEmail } from "@/lib/email/resend"
import { CrossOriginRequestError, UnsupportedContentTypeError, assertJsonRequest, ensureSameOrigin } from "@/lib/security/origin"
import { enforceRateLimit, RateLimitError } from "@/lib/security/rate-limit"
import { getClientIp } from "@/lib/security/request"
import { FormTokenError, verifyFormToken } from "@/lib/security/form-token"

type FeedbackPayload = {
  email?: unknown
  name?: unknown
  message?: unknown
  source?: unknown
  form_token?: unknown
  checkpoint?: unknown
}

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

function sanitizeString(value: unknown, maxLength: number): string | null {
  if (typeof value !== "string") {
    return null
  }
  const trimmed = value.trim()
  if (!trimmed) {
    return null
  }
  return trimmed.length > maxLength ? trimmed.slice(0, maxLength) : trimmed
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;"
      case "<":
        return "&lt;"
      case ">":
        return "&gt;"
      case '"':
        return "&quot;"
      case "'":
        return "&#39;"
      default:
        return char
    }
  })
}

export async function POST(request: Request) {
  try {
    ensureSameOrigin(request)
    assertJsonRequest(request)
  } catch (error) {
    if (error instanceof CrossOriginRequestError) {
      return NextResponse.json({ error: error.message }, { status: 403 })
    }
    if (error instanceof UnsupportedContentTypeError) {
      return NextResponse.json({ error: error.message }, { status: 415 })
    }
    throw error
  }

  const clientIp = getClientIp(request)
  try {
    enforceRateLimit(`feedback:${clientIp}`, 3, 120_000)
  } catch (error) {
    if (error instanceof RateLimitError) {
      return NextResponse.json({ error: error.message }, { status: 429, headers: { "Retry-After": String(error.retryAfter) } })
    }
    throw error
  }

  const payload = (await request.json().catch(() => ({}))) as FeedbackPayload

  const checkpointValue = typeof payload.checkpoint === "string" ? payload.checkpoint.trim() : ""
  if (checkpointValue.length > 0) {
    return NextResponse.json({ error: "Unable to process the request." }, { status: 400 })
  }

  try {
    verifyFormToken(payload.form_token)
  } catch (error) {
    const message = error instanceof FormTokenError ? error.message : "Invalid form token."
    return NextResponse.json({ error: message }, { status: 400 })
  }

  const email = sanitizeString(payload.email, 200)?.toLowerCase()
  if (!email) {
    return NextResponse.json({ error: "Email is required." }, { status: 400 })
  }
  if (!emailRegex.test(email)) {
    return NextResponse.json({ error: "Email looks invalid." }, { status: 422 })
  }

  const name = sanitizeString(payload.name, 200)
  const message = sanitizeString(payload.message, 2000)
  if (!message) {
    return NextResponse.json({ error: "Feedback cannot be empty." }, { status: 400 })
  }

  const source = sanitizeString(payload.source, 140) ?? "unspecified"

  const inbox = process.env.RESEND_TO_EMAIL_FEEDBACK
  if (!inbox) {
    console.error("Feedback inbox is not configured; set RESEND_TO_EMAIL_FEEDBACK.")
    return NextResponse.json({ error: "Feedback inbox not configured." }, { status: 500 })
  }
  const subject = `Umbra beta feedback (${source})`
  const plainTextLines = [
    `Source: ${source}`,
    `Name: ${name ?? "Not provided"}`,
    `Email: ${email}`,
    "",
    "Message:",
    message,
  ]
  const text = plainTextLines.join("\n")
  const html = `
    <p style="font-family:'Inter','Helvetica Neue',Arial,sans-serif;font-size:14px;color:#08070B;">
      <strong>Source:</strong> ${escapeHtml(source)}
    </p>
    <p style="font-family:'Inter','Helvetica Neue',Arial,sans-serif;font-size:14px;color:#08070B;">
      <strong>Name:</strong> ${escapeHtml(name ?? "Not provided")}
    </p>
    <p style="font-family:'Inter','Helvetica Neue',Arial,sans-serif;font-size:14px;color:#08070B;">
      <strong>Email:</strong> <a href="mailto:${escapeHtml(email)}" style="color:#1B0986;text-decoration:none;">${escapeHtml(email)}</a>
    </p>
    <div style="margin-top:16px;padding:16px;border-radius:12px;background-color:#F5F4FF;font-family:'Inter','Helvetica Neue',Arial,sans-serif;font-size:14px;line-height:22px;color:#1F1E28;">
      ${escapeHtml(message).replace(/\n/g, "<br />")}
    </div>
  `

  try {
    await sendEmail({
      to: inbox,
      subject,
      html,
      text,
    })
    return NextResponse.json({ success: true })
  } catch (error) {
    console.error("Feedback email send failed", error)
    return NextResponse.json({ error: "Unable to send feedback right now." }, { status: 500 })
  }
}
