"use server"

type SendEmailArgs = {
  to: string
  subject: string
  html: string
  text: string
}

const RESEND_API_URL = "https://api.resend.com/emails"

export async function sendEmail({ to, subject, html, text }: SendEmailArgs): Promise<void> {
  const apiKey = process.env.RESEND_API_KEY
  const fromAddress = process.env.RESEND_FROM_EMAIL ?? "Concrete Security <onboarding@resend.dev>"

  if (!apiKey) {
    console.warn("RESEND_API_KEY is not configured; skip email dispatch.")
    return
  }

  if (process.env.NODE_ENV !== "production") {
    console.log("[Resend] Dispatching email", {
      to,
      subject,
      from: fromAddress,
    })
  }

  const response = await fetch(RESEND_API_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: fromAddress,
      to,
      subject,
      html,
      text,
    }),
  })

  if (!response.ok) {
    const payload = await response.json().catch(() => null)
    console.error("Resend email send failed", { status: response.status, payload })
    throw new Error("Failed to send transactional email")
  }

  if (process.env.NODE_ENV !== "production") {
    console.log("[Resend] Email accepted by API", { to, subject })
  }
}
