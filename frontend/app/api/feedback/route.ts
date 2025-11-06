import { NextResponse } from "next/server"

import { sendEmail } from "@/lib/email/resend"

type FeedbackPayload = {
  email?: unknown
  name?: unknown
  message?: unknown
  source?: unknown
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
  const payload = (await request.json().catch(() => ({}))) as FeedbackPayload

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
