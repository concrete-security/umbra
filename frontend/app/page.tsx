"use client"

import Link from "next/link"
import Image from "next/image"
import { useState, FormEvent, KeyboardEvent, useRef } from "react"
import { useRouter } from "next/navigation"
import {
  ArrowRight,
  Shield,
  Lock,
  Fingerprint,
  CircuitBoard,
  Send,
  FileText,
  Paperclip,
  X,
  CheckCircle2,
  Brain,
} from "lucide-react"

import { LoadingTransition } from "@/components/loading-transition"
import { ForceLightTheme } from "@/components/force-light-theme"
import { FeedbackButton } from "@/components/feedback-button"
import { Button } from "@/components/ui/button"
import AnnouncementBar from "@/components/announcement-bar"
import peopleData from "@/people.json"
import { EXAMPLE_THEMES, type ExampleTheme } from "@/lib/example-themes"

const HERO_MESSAGE_STORAGE_KEY = "hero-initial-message"
const HERO_FILES_STORAGE_KEY = "hero-uploaded-files"
const examplePrompts: ExampleTheme[] = Object.values(EXAMPLE_THEMES)
const flowSteps = [
  {
    title: "Client Encryption",
    description: "Data is encrypted in your browser before transmission",
    icon: Lock,
  },
  {
    title: "Secure Machine",
    description: "Encrypted data reaches TEE with cryptographic verification",
    icon: Shield,
  },
  {
    title: "Decryption",
    description: "Data is decrypted inside the secure TEE environment",
    icon: Fingerprint,
  },
  {
    title: "AI Processing",
    description: "Your documents are processed by AI within the secure environment",
    icon: Brain,
  },
  {
    title: "Encryption",
    description: "Results are encrypted before leaving the TEE",
    icon: Lock,
  },
  {
    title: "Client",
    description: "Encrypted response is sent back to your browser",
    icon: CircuitBoard,
  },
  {
    title: "Decryption",
    description: "You decrypt and view the results locally",
    icon: Fingerprint,
  },
]

type UploadedFile = { name: string; content: string; size: number; type: string }

export default function LandingPage() {
  const router = useRouter()
  const [input, setInput] = useState("")
  const [isTransitioning, setIsTransitioning] = useState(false)
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([])
  const fileInputRef = useRef<HTMLInputElement>(null)
  // Track which example theme is currently loading (null = none)
  const [loadingExampleId, setLoadingExampleId] = useState<string | null>(null)
  // Track loading and selected example theme
  const [selectedExampleId, setSelectedExampleId] = useState<string | null>(null)
  // Progress (0..100) for the currently loading example
  const [loadingProgress, setLoadingProgress] = useState(0)
  // Keep timer ids to stop them cleanly
  const loadingTimerRef = useRef<number | null>(null)
  const loadingTimeoutRef = useRef<number | null>(null)

  const requestIdRef = useRef(0)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    const trimmed = input.trim()
    if (!trimmed && uploadedFiles.length === 0) return

    try {
      sessionStorage.setItem(HERO_MESSAGE_STORAGE_KEY, trimmed)
      if (uploadedFiles.length > 0) {
        sessionStorage.setItem(HERO_FILES_STORAGE_KEY, JSON.stringify(uploadedFiles))
      } else {
        sessionStorage.removeItem(HERO_FILES_STORAGE_KEY)
      }
    } catch (error) {
      console.error("Failed to store hero submission", error)
    }

    setIsTransitioning(true)
    setTimeout(() => {
      router.push("/confidential-ai")
    }, 600)
  }

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault()
      handleSubmit(e as unknown as FormEvent)
    }
  }

  // Handles clicks on "Try an example" buttons
  const handleExampleClick = async (example: ExampleTheme) => {

    if (!example?.id) return

    // Stop any previous loading timer
    if (loadingTimerRef.current !== null) {
      window.clearInterval(loadingTimerRef.current)
      loadingTimerRef.current = null
    }
    if (loadingTimeoutRef.current !== null) {
      window.clearTimeout(loadingTimeoutRef.current)
      loadingTimeoutRef.current = null
    }

    // Reset UI when switching demos
    setSelectedExampleId(null)
    setUploadedFiles([])
    setInput("")
    setLoadingExampleId(example.id)
    setLoadingProgress(0)

    // Progress grows while downloading/parsing
    loadingTimerRef.current = window.setInterval(() => {
      setLoadingProgress((p) => (p >= 95 ? 95 : p + 2))
    }, 70)

    let success = false

    try {

      // Fetch demo documents for this theme
      const res = await fetch(`/api/example-docs/${example.id}`)
      if (!res.ok) throw new Error("Failed to load example files")

      // Expected payload: { files: [{ name, type, data (base64) }, ...] }
      const data: { files: { name: string; type: string; data: string }[] } = await res.json()

      // Convert each base64-encoded PDF to a File, extract its text, and store it as UploadedFile
      const newFiles: UploadedFile[] = await Promise.all(
        data.files.map(async (f) => {
          const binary = Uint8Array.from(atob(f.data), (c) => c.charCodeAt(0))
          const blob = new Blob([binary], { type: f.type })
          const file = new File([blob], f.name, { type: f.type })
          const content = await extractTextFromPDF(file)

          return { name: f.name, content, size: binary.byteLength, type: f.type }
        }),
      )

      // Finished: fill to 100%
      setLoadingProgress(100)
      // Now apply the UI (files + prompt)
      setUploadedFiles(newFiles)
      setInput(example.prompt)
      setSelectedExampleId(example.id)
      success = true
    } catch (err) {
      console.error("Error loading example", err)
    } finally {
      if (loadingTimerRef.current !== null) {
        window.clearInterval(loadingTimerRef.current)
        loadingTimerRef.current = null
      }

      loadingTimeoutRef.current = window.setTimeout(() => {
        setLoadingExampleId(null)
        setLoadingProgress(0)
        if (!success) setSelectedExampleId(null)
        loadingTimeoutRef.current = null
      }, 250)
    }
  }


  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files
    if (!files) return

    for (let i = 0; i < files.length; i++) {
      const file = files[i]

      const maxSize = 100 * 1024 * 1024
      if (file.size > maxSize) {
        alert(`File "${file.name}" is too large. Maximum size is 100MB.`)
        continue
      }

      try {
        let content: string

        if (file.type === "application/pdf") {
          content = await extractTextFromPDF(file)
        } else {
          content = await file.text()
        }

        const uploadedFile: UploadedFile = {
          name: file.name,
          content,
          size: file.size,
          type: file.type || "text/plain",
        }

        setUploadedFiles((prev) => [...prev, uploadedFile])
      } catch (error) {
        console.error("Error reading file:", error)
        alert(`Failed to read file "${file.name}": ${error instanceof Error ? error.message : "Unknown error"}`)
      }
    }

    if (fileInputRef.current) {
      fileInputRef.current.value = ""
    }
  }

  const removeFile = (index: number) => {
    setUploadedFiles((prev) => prev.filter((_, i) => i !== index))
  }

  const extractTextFromPDF = async (file: File): Promise<string> => {
    try {
      // @ts-expect-error - PDF.js is loaded from public folder
      const pdfjsLibModule = await import(/* webpackIgnore: true */ "/pdfjs/pdf.mjs")
      const pdfjsLib =
        (pdfjsLibModule as unknown as { default?: unknown }).default ?? (window as any).pdfjsLib ?? pdfjsLibModule

      pdfjsLib.GlobalWorkerOptions.workerSrc = "/pdfjs/pdf.worker.mjs"

      const arrayBuffer = await file.arrayBuffer()
      const pdf = await pdfjsLib.getDocument({ data: arrayBuffer }).promise
      let text = ""

      for (let i = 1; i <= pdf.numPages; i++) {
        const page = await pdf.getPage(i)
        const textContent = await page.getTextContent()
        const pageText = textContent.items.map((item: any) => ("str" in item ? item.str : "")).join(" ")
        text += pageText + "\n"
      }
      return text.trim()
    } catch (error) {
      console.error("Error extracting text from PDF:", error)
      throw new Error("Failed to extract text from PDF")
    }
  }

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return "0 Bytes"
    const k = 1024
    const sizes = ["Bytes", "KB", "MB"]
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i]
  }

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#E2E2E2] text-[#08070B]">
      <ForceLightTheme />
      <header className="relative z-10 border-b border-[#d4d3e6] bg-transparent">
        <div className="container flex items-center justify-between gap-4 px-6 py-6">
          <Link href="/" className="flex items-center gap-3 text-lg font-semibold tracking-tight">
            <Image src="/logo.png" alt="Umbra logo" width={40} height={40} className="mix-blend-multiply" />
          </Link>
          <div className="flex items-center gap-3">
            <Button
              className="hidden h-9 rounded-full border border-[#1B0986] bg-white px-5 text-sm font-medium text-[#1B0986] transition hover:border-[#0B0870] hover:bg-white hover:text-[#0B0870] md:inline-flex"
              asChild
              variant="outline"
            >
              <a href="mailto:contact@concrete-security.com">Contact us</a>
            </Button>
          </div>
        </div>
      </header>
      <AnnouncementBar
        message="Umbra internal beta is live — secure chat is unlocked for testers."
        storageKey="announcement:private-beta"
      />
      <main className="relative z-10">
        <section className="flex justify-center px-4 pt-6 pb-16 md:pt-8 md:pb-24">
          <div className="relative w-full max-w-[900px] overflow-hidden rounded-[40px] border border-[#d4d3e6] bg-white/95 px-12 pb-16 pt-12 shadow-[0_48px_140px_-80px_rgba(11,31,102,0.45)] backdrop-blur">
              <div className="relative z-10 flex flex-col items-center gap-6">
                <h1 className="text-[58px] font-bold leading-[62px] text-[#08070B]">Umbra</h1>
              </div>
              <div className="relative flex flex-col gap-8 pt-4">
                <div className="flex flex-col gap-6 text-center">
                  <p className="mx-auto max-w-[520px] text-base leading-7 text-[#1F1E28]">
                    Query your confidential documents securely. Upload sensitive files and ask questions inside a locked-down
                    confidential workspace. Every interaction stays within a protected channel and runtime.
                  </p>
                </div>
                <form onSubmit={handleSubmit} className="flex flex-col gap-6">
                  <div className="flex items-center justify-center gap-2 text-xs font-semibold uppercase tracking-[0.24em] text-[#1F1E28]/70">
                    <Shield className="h-3.5 w-3.5 text-[#1B0986]" />
                    <span>Private channel · Secure workspace</span>
                  </div>
                  {uploadedFiles.length > 0 && (
                    <div className="space-y-2">
                      {uploadedFiles.map((file, index) => (
                        <div
                          key={index}
                          className="flex items-center justify-between rounded-xl border border-[#d7d5eb] bg-white/80 p-3 text-xs text-[#1F1E28]/80"
                        >
                          <div className="flex items-center gap-2">
                            <FileText className="size-3 text-[#1B0986]" />
                            <span className="font-medium text-[#08070B]">{file.name}</span>
                            <span className="text-[#1F1E28]/70">({formatFileSize(file.size)})</span>
                          </div>
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => removeFile(index)}
                            className="h-6 w-6 rounded-full border border-[#d7d5eb] p-0 text-[#08070B] transition hover:bg-white/80"
                          >
                            <X className="size-3" />
                          </Button>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="flex w-full flex-col gap-3">
                    <label htmlFor="hero-input" className="sr-only">
                      Ask about your confidential documents
                    </label>
                    <textarea
                      id="hero-input"
                      value={input}
                      onChange={(e) => setInput(e.target.value)}
                      onKeyDown={handleKeyDown}
                      disabled={isTransitioning}
                      placeholder="Ask about your confidential documents..."
                      className="min-h-[140px] w-full resize-none rounded-[32px] border border-[#d7d5eb] bg-white px-5 py-5 text-base leading-relaxed text-[#08070B] placeholder:text-[#1F1E28]/40 shadow-[0_32px_80px_-60px_rgba(11,31,102,0.55)] transition focus:outline-none focus:ring-2 focus:ring-[#1B0986]/45"
                      rows={4}
                    />
                    <div className="flex w-full items-center gap-3">
                      <input
                        type="file"
                        ref={fileInputRef}
                        onChange={handleFileUpload}
                        multiple
                        accept=".txt,.md,.json,.csv,.py,.js,.ts,.tsx,.jsx,.html,.css,.xml,.yaml,.yml,.pdf"
                        className="hidden"
                      />
                      <Button
                        type="button"
                        variant="ghost"
                        size="icon"
                        onClick={() => fileInputRef.current?.click()}
                        disabled={isTransitioning}
                        className="h-12 w-12 shrink-0 rounded-xl border border-[#d7d5eb] bg-white/80 text-[#08070B] shadow-sm transition hover:bg-white"
                        title="Upload files"
                      >
                        <Paperclip className="h-4 w-4 text-[#1B0986]" />
                      </Button>
                      <Button
                        type="submit"
                        className="flex-1 h-12 rounded-xl bg-[linear-gradient(135deg,#1B0986,#0B0870)] text-white shadow-sm transition hover:shadow-lg disabled:bg-[#1B0986]/55 disabled:text-white/75 disabled:hover:shadow-none"
                        disabled={isTransitioning || (!input.trim() && uploadedFiles.length === 0)}
                      >
                        <Send className="mr-2 h-4 w-4" />
                        Start secure session
                      </Button>
                    </div>
                  </div>
                  <div className="flex flex-col gap-2 text-center">
                    <p className="text-xs font-medium uppercase tracking-[0.24em] text-[#1F1E28]/60">Try an example:</p>
                    <div className="flex flex-wrap justify-center gap-2">
                      {examplePrompts.map((example) => {
                      const isLoading = loadingExampleId === example.id
                      const isSelected = selectedExampleId === example.id

                      const fillPercent = isLoading ? loadingProgress : isSelected ? 100 : 0

                      return (
                        <button
                          key={example.id}
                          type="button"
                          onClick={() => handleExampleClick(example)}
                          disabled={isTransitioning || loadingExampleId !== null}
                          className={[
                              "relative inline-flex items-center gap-1.5 rounded-full border px-3 py-1.5 text-xs overflow-hidden transition",
                            fillPercent > 0
                              ? "border-transparent"
                              : "border-[#d7d5eb] bg-white/80 text-[#1F1E28]/80 hover:bg-white hover:text-[#08070B]",
                          ].join(" ")}
                          >
                            {/* Fill layer: left -> right */}
                            {fillPercent > 0 && (
                              <span
                                aria-hidden="true"
                                className="absolute inset-0 example-fill z-0"
                                style={{ transform: `scaleX(${fillPercent / 100})` }}
                              />
                            )}

                          <span className="relative z-10 inline-flex items-center gap-1.5">
                            <FileText className="h-3 w-3" />

                            <span className="relative inline-block">
                              {/* Base text */}
                              <span className="text-[#08070B]">{example.buttonLabel}</span>

                              {/* White text overlay (no icon here) */}
                              {fillPercent > 0 && (
                                <span
                                  aria-hidden="true"
                                  className="absolute inset-0 text-white pointer-events-none overflow-hidden"
                                  style={{ clipPath: `inset(0 ${100 - fillPercent}% 0 0)` }}
                                >
                                  {example.buttonLabel}
                                </span>
                              )}
                            </span>
                          </span>
                          </button>
                        )
                    })}
                    </div>
                  </div>
                  <div className="flex items-center justify-center gap-4 text-xs text-[#1F1E28]/70">
                    <div className="flex items-center gap-2">
                      <Lock className="h-3.5 w-3.5 text-[#1F1E28]" />
                      <span>Encrypted</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Shield className="h-3.5 w-3.5 text-[#1F1E28]" />
                      <span>Attested</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <Fingerprint className="h-3.5 w-3.5 text-[#1F1E28]" />
                      <span>Verified</span>
                    </div>
                  </div>
                </form>
            </div>
          </div>
        </section>

        <section className="px-4 pb-20" id="how-it-works">
          <div className="container flex flex-col gap-10">
            <div className="max-w-[720px] space-y-4">
              <span className="text-xs uppercase tracking-[0.4em] text-[#1F1E28]/70">How It Works</span>
              <h2 className="text-[34px] font-semibold leading-[38px] text-[#08070B]">
                Confidential Chat with Cryptographic Guarantees
              </h2>
              <p className="text-base leading-6 text-[#1F1E28]">
                Umbra is a Confidential Chat that allows you to query documents with cryptographic guarantees. Your data
                is encrypted client-side in the browser, and the machine processing your queries is verified through
                cryptographic means. Umbra relies on Trusted Execution Environments (TEE) to ensure your sensitive
                documents remain private throughout the entire process.
              </p>
            </div>
          </div>
        </section>

        <section className="px-4 pb-24" id="security-flow">
          <div className="container flex flex-col gap-10">
            <div className="max-w-[720px] space-y-4">
              <span className="text-xs uppercase tracking-[0.4em] text-[#1F1E28]/70">Security Flow</span>
              <h2 className="text-[34px] font-semibold leading-[38px] text-[#08070B]">
                End-to-End Protection
              </h2>
              <p className="text-base leading-6 text-[#1F1E28]">
                At each step of the process, the secure machine code and integrity are verified cryptographically. Your
                data never leaves the protected environment unencrypted.
              </p>
            </div>
            <div className="relative overflow-x-auto pb-8">
              <div className="flex min-w-max gap-4 md:gap-6">
                {flowSteps.map((step, index) => {
                  const Icon = step.icon
                  const isLast = index === flowSteps.length - 1
                  return (
                    <div key={index} className="flex items-start gap-4">
                      <div className="flex min-w-[200px] flex-col gap-4 rounded-[28px] border border-[#d4d3e6] bg-white p-6 shadow-[0_32px_78px_-64px_rgba(15,10,80,0.35)] md:min-w-[220px]">
                        <div className="flex items-center gap-3">
                          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[#1B0986]">
                            <Icon className="h-5 w-5 text-white" />
                          </div>
                          <div className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-green-100">
                            <CheckCircle2 className="h-4 w-4 text-green-600" />
                          </div>
                        </div>
                        <div className="space-y-2">
                          <h3 className="text-base font-semibold leading-5 text-[#08070B]">{step.title}</h3>
                          <p className="text-sm leading-5 text-[#1F1E28]/80">{step.description}</p>
                        </div>
                      </div>
                      {!isLast && (
                        <div className="flex items-center pt-6">
                          <ArrowRight className="h-6 w-6 text-[#1B0986]" />
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
            <div className="rounded-[28px] border border-[#d4d3e6] bg-white/95 p-6 shadow-[0_32px_78px_-64px_rgba(15,10,80,0.35)]">
              <p className="text-sm leading-6 text-[#1F1E28]">
                <strong className="font-semibold text-[#08070B]">Security Assumptions:</strong> Umbra assumes the TEE
                hardware vendors (Intel, AMD, NVIDIA) are trusted and correctly implements the security guarantees. The cryptographic verification
                ensures that only verified code runs in the TEE, protecting against software-based attacks.
              </p>
            </div>
          </div>
        </section>

        <section className="px-4 pb-24" id="team">
          <div className="container flex flex-col gap-10">
            <div className="max-w-[720px] space-y-4">
              <span className="text-xs uppercase tracking-[0.4em] text-[#1F1E28]/70">Our Team</span>
              <h2 className="text-[34px] font-semibold leading-[38px] text-[#08070B]">
                Building the Future of Confidential AI
              </h2>
              <p className="text-base leading-6 text-[#1F1E28]">
                We are a team of AI researchers, Security researchers, AI engineers, and Security engineers that seek
                to build the best solutions for confidentiality, privacy, and IP protection using state-of-the-art
                technology. Our team has deep expertise in TEE (Trusted Execution Environments), FHE (Fully Homomorphic Encryption), PPML (Privacy-Preserving Machine Learning), Side channels, and Hardware security.
              </p>
            </div>
            <div className="grid gap-6 md:grid-cols-3">
              {peopleData.people.map((person) => (
                <div
                  key={person.name}
                  className="flex flex-col gap-5 rounded-[28px] border border-[#d4d3e6] bg-white/95 p-6 shadow-[0_32px_78px_-64px_rgba(15,10,80,0.35)] backdrop-blur-sm"
                >
                  <div className="relative h-24 w-24 overflow-hidden rounded-full border-2 border-[#d4d3e6]">
                    <Image
                      src={person.image}
                      alt={person.name}
                      fill
                      className="object-cover"
                      sizes="96px"
                    />
                  </div>
                  <div className="space-y-2">
                    <h3 className="text-lg font-semibold leading-6 text-[#08070B]">{person.name}</h3>
                    <p className="text-sm leading-6 text-[#1F1E28]/80">{person.expertise}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="flex justify-center px-4 pb-24">
          <div className="relative w-full max-w-[880px] overflow-hidden rounded-[40px] border border-[#d4d3e6] bg-[#0B0870] px-10 py-14 text-white shadow-[0_60px_140px_-80px_rgba(9,8,112,0.65)]">
            <div className="pointer-events-none absolute inset-0 card-gradient-royal opacity-95" aria-hidden />
            <div className="relative flex flex-col gap-6 text-center md:items-center">
              <span className="text-xs uppercase tracking-[0.4em] text-white/70">Ready to build?</span>
              <h2 className="text-[34px] font-semibold leading-[40px] md:max-w-[520px]">
                Launch a confidential AI program that scales with your compliance and trust requirements.
              </h2>
              <p className="mx-auto max-w-[520px] text-sm leading-6 text-white/80">
                Partner with our security engineers to deploy in your preferred region, integrate with existing data controls,
                and evolve your policies alongside secure AI workloads.
              </p>
              <div className="flex flex-col items-center justify-center gap-3 sm:flex-row">
                <Button
                  className="h-11 w-full rounded-full border border-white bg-white px-6 text-sm font-semibold text-[#08070B] transition hover:bg-white/95 hover:shadow-lg sm:w-auto sm:min-w-[180px]"
                  asChild
                >
                  <Link href="/confidential-ai" className="flex items-center justify-center gap-2">
                    Start Secure Chat
                    <ArrowRight className="h-4 w-4" />
                  </Link>
                </Button>
                <Button
                  variant="outline"
                  className="h-11 w-full rounded-full border-2 border-white/80 bg-transparent px-6 text-sm font-semibold text-white transition hover:border-white hover:bg-white/10 sm:w-auto sm:min-w-[180px]"
                  asChild
                >
                  <a href="mailto:contact@concrete-security.com" className="flex items-center justify-center">
                    Schedule a briefing
                  </a>
                </Button>
              </div>
            </div>
          </div>
        </section>
      </main>
      <footer className="relative z-10 border-t border-[#d4d3e6] bg-transparent">
        <div className="container flex flex-col gap-4 px-6 py-10 text-sm text-[#1F1E28]/70 md:flex-row md:items-center md:justify-between">
          <p>© {new Date().getFullYear()} Umbra. Umbra for sensitive data.</p>
          <div className="flex flex-wrap gap-4">
            <Link className="transition hover:text-[#1B0986]" href="/confidential-ai">
              Confidential Chat
            </Link>
            <a className="transition hover:text-[#1B0986]" href="mailto:contact@concrete-security.com">
              Contact
            </a>
            <Link className="transition hover:text-[#1B0986]" href="/">
              Privacy Policy
            </Link>
          </div>
        </div>
      </footer>
      <FeedbackButton source="landing" />
      {isTransitioning && <LoadingTransition message="Opening secure session..." />}
    </div>
  )
}
