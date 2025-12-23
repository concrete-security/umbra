import type React from "react"
import "@/styles/globals.css"
import type { Metadata } from "next"
import { Analytics } from "@vercel/analytics/next"
import { ChunkRecovery } from "@/components/chunk-recovery"
import { ThemeProvider } from "@/components/theme-provider"
import { SupabaseAuthListener } from "@/components/supabase-auth-listener"

export const metadata: Metadata = {
  title: "Umbra — Confidential AI for Your Data",
  description:
    "Umbra for sensitive data — security, privacy, and confidentiality backed by modern cryptography.",
  generator: "Umbra",
  icons: {
    icon: "/icon.png",
    shortcut: "/favicon.ico",
    apple: "/apple-icon.png",
  },
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
          <ChunkRecovery />
          <SupabaseAuthListener />
          {children}
        </ThemeProvider>
        <Analytics />
      </body>
    </html>
  )
}
