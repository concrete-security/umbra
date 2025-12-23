import { sendEmail } from "@/lib/email/resend"

type WaitlistActivationArgs = {
  email: string
  magicLink: string
  company?: string | null
  useCase?: string | null
}

const SUBJECT = "Your Umbra access link"

function escapeHtml(value: string | null | undefined) {
  if (!value) {
    return ""
  }
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

function buildPlainText({ magicLink, company, useCase }: { magicLink: string; company?: string | null; useCase?: string | null }): string {
  const lines = [
    "Hi there,",
    "",
    "Umbra, Concrete Security's secure assistant, is ready for your workspace.",
    "",
    `Activate your account: ${magicLink}`,
    "",
    "What to expect:",
    "• Sign in with the link above to create your workspace credentials.",
    "• You can invite teammates once signed in.",
    "• The link expires after a single use for security.",
  ]

  if (company || useCase) {
    lines.push("", "Context we captured:")
    if (company) lines.push(`• Company: ${company}`)
    if (useCase) lines.push(`• Focus: ${useCase}`)
  }

  lines.push("", "If the link expires, reply to this email and we’ll refresh it.", "", "— The Concrete Security team")

  return lines.join("\n")
}

function buildHtml({ magicLink, company, useCase }: { magicLink: string; company?: string | null; useCase?: string | null }): string {
  return `
  <table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="background-color:#F5F4FF;padding:32px 0;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0" role="presentation" style="background-color:#ffffff;border-radius:24px;padding:40px 48px;font-family:'Inter','Helvetica Neue',Arial,sans-serif;color:#08070B;">
          <tr>
            <td style="padding-bottom:24px;">
              <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;">
                <tr>
                  <td style="width:44px;">
                    <img src="https://concrete-security.com/logo.png" width="44" height="44" alt="Concrete Security" style="border-radius:12px;display:block;" />
                  </td>
                  <td style="padding-left:16px;vertical-align:middle;">
                    <div style="font-size:14px;letter-spacing:0.24em;text-transform:uppercase;color:#6F6C90;font-weight:600;">Concrete Security</div>
                    <div style="font-size:13px;color:#A3A1C2;">Umbra activation</div>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="font-size:26px;line-height:32px;font-weight:600;padding-bottom:16px;">Your Umbra access is live</td>
          </tr>
          <tr>
            <td style="font-size:15px;line-height:24px;color:#1F1E28;padding-bottom:24px;">
              Umbra is ready for your workspace. Use the button below to activate your account and step into the secure assistant.
            </td>
          </tr>
          <tr>
            <td align="center" style="padding-bottom:24px;">
              <a href="${magicLink}" style="display:inline-block;padding:14px 28px;border-radius:999px;background-color:#08070B;color:#ffffff;font-weight:600;text-decoration:none;">Activate Umbra access</a>
            </td>
          </tr>
          <tr>
            <td style="background-color:#F8F8FF;border-radius:18px;padding:20px 24px;font-size:14px;line-height:22px;color:#1F1E28;">
              <div style="font-weight:600;color:#08070B;margin-bottom:12px;">What happens next</div>
              <ul style="padding-left:18px;margin:0;">
                <li style="margin-bottom:8px;">The link is single-use. Once activated you'll sign in with your email and password.</li>
                <li style="margin-bottom:8px;">You can invite teammates and manage permissions directly inside Umbra.</li>
                <li>The Concrete Security team is on hand if you need help during onboarding.</li>
              </ul>
            </td>
          </tr>
          ${
            company || useCase
              ? `<tr>
            <td style="padding-top:24px;font-size:14px;line-height:22px;color:#1F1E28;">
              <div style="font-weight:600;color:#08070B;margin-bottom:8px;">Context we noted</div>
              <ul style="padding-left:18px;margin:0;">
                ${company ? `<li style="margin-bottom:6px;"><strong>Company:</strong> ${escapeHtml(company)}</li>` : ""}
                ${useCase ? `<li><strong>Focus:</strong> ${escapeHtml(useCase)}</li>` : ""}
              </ul>
            </td>
          </tr>`
              : ""
          }
          <tr>
            <td style="padding-top:24px;font-size:15px;line-height:24px;color:#1F1E28;">
              If the link expires or you have questions, reply directly and we&rsquo;ll refresh it.
            </td>
          </tr>
          <tr>
            <td style="padding-top:24px;font-size:15px;line-height:24px;font-weight:600;color:#08070B;">— The Concrete Security team</td>
          </tr>
          <tr>
            <td style="padding-top:32px;font-size:11px;line-height:16px;color:#8C8AA6;">
              Concrete Security, 500 Market Street, Suite 410, San Francisco, CA 94105
              <br />
              You received this email because your team requested access to Umbra.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>`
}

export async function sendWaitlistActivationEmail({ email, magicLink, company, useCase }: WaitlistActivationArgs): Promise<void> {
  const text = buildPlainText({ magicLink, company, useCase })
  const html = buildHtml({ magicLink, company, useCase })

  try {
    await sendEmail({ to: email, subject: SUBJECT, html, text })
  } catch (error) {
    console.error("Failed to send Umbra activation email", error)
    throw error
  }
}
