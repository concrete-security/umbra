"use client"

import type { ReactElement, ReactNode } from "react"
import clsx from "clsx"
import { memo, useCallback, useEffect, useMemo, useState, isValidElement } from "react"
import { Check, Copy, ExternalLink } from "lucide-react"
import ReactMarkdown from "react-markdown"
import type { Components } from "react-markdown"
import rehypeSanitize, { defaultSchema } from "rehype-sanitize"
import remarkGfm from "remark-gfm"

type HastElement = { properties?: Record<string, unknown> }
type Schema = Record<string, unknown>
type HeadingTag = "h1" | "h2" | "h3" | "h4" | "h5" | "h6"

const SUSPICIOUS_CONTENT_PATTERN = /<(?:script|iframe|object|embed)|javascript:|data:text\/html|on[a-z]+\s*=|style=/i

const SANITIZE_SCHEMA: Schema = {
  ...defaultSchema,
  allowComments: false,
  tagNames: [
    "a",
    "blockquote",
    "br",
    "code",
    "del",
    "em",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "kbd",
    "hr",
    "input",
    "li",
    "ol",
    "p",
    "pre",
    "span",
    "strong",
    "sub",
    "sup",
    "table",
    "tbody",
    "td",
    "th",
    "thead",
    "tr",
    "ul",
  ],
  attributes: {
    ...defaultSchema.attributes,
    "*": [
      ...(defaultSchema.attributes?.["*"] ?? []),
      ["align", ["left", "center", "right"]],
      ["className"],
    ],
    a: [
      ...(defaultSchema.attributes?.a ?? []),
      ["href"],
      ["title"],
      ["rel"],
      ["target"],
    ],
    th: [
      ["align"],
      ["colspan"],
      ["rowspan"],
    ],
    td: [
      ["align"],
      ["colspan"],
      ["rowspan"],
    ],
    code: [["className"]],
    pre: [["className"]],
    span: [["className"]],
    input: [
      ["type", ["checkbox"]],
      ["disabled"],
      ["checked"],
    ],
  },
  protocols: {
    ...defaultSchema.protocols,
    href: ["http", "https", "mailto", "tel"],
  },
}

function alignClass(node?: HastElement) {
  const align = (node?.properties?.align as string | undefined)?.toLowerCase()
  if (align === "center" || align === "right") {
    return `text-${align}`
  }
  return "text-left"
}

function createHeading(level: number) {
  const base = "font-semibold tracking-tight text-foreground"
  const spacing = level === 1 ? "mt-7 mb-4 text-xl" : level === 2 ? "mt-6 mb-3.5 text-lg" : "mt-5 mb-3 text-base"
  return function Heading({ children }: { children?: ReactNode }) {
    const Tag = `h${level}` as HeadingTag
    return <Tag className={clsx(base, spacing)}>{children}</Tag>
  }
}

function extractText(node: ReactNode): string {
  if (node === undefined || node === null) {
    return ""
  }
  if (typeof node === "string" || typeof node === "number") {
    return String(node)
  }
  if (Array.isArray(node)) {
    return node.map(extractText).join("")
  }
  if (isValidElement(node)) {
    const element = node as ReactElement
    const child = (element.props as { children?: ReactNode }).children
    return extractText(child ?? "")
  }
  return ""
}

function MarkdownCodeBlock({ children }: { children: ReactNode }) {
  const [copied, setCopied] = useState(false)
  const textContent = useMemo(() => extractText(children).trim(), [children])

  useEffect(() => {
    if (!copied) {
      return
    }
    const timeout = window.setTimeout(() => setCopied(false), 2000)
    return () => window.clearTimeout(timeout)
  }, [copied])

  const handleCopy = useCallback(async () => {
    if (!textContent) {
      return
    }
    try {
      await navigator.clipboard.writeText(textContent)
      setCopied(true)
    } catch (error) {
      console.warn("[Markdown] Failed to copy code block", error)
    }
  }, [textContent])

  return (
    <div className="group relative my-3 overflow-hidden rounded-lg border border-border/60 bg-muted/60">
      <pre className="overflow-x-auto px-3 py-2 text-xs leading-6 text-foreground">
        <code className="font-mono text-xs">
          {children}
        </code>
      </pre>
      {textContent && (
        <button
          type="button"
          onClick={handleCopy}
          className="absolute right-2 top-2 inline-flex items-center gap-1 rounded-md border border-border bg-background/80 px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.2em] text-foreground shadow-sm transition hover:bg-background focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary/40"
          aria-label={copied ? "Code copied" : "Copy code"}
        >
          {copied ? <Check className="h-3 w-3" aria-hidden /> : <Copy className="h-3 w-3" aria-hidden />}
          {copied ? "Copied" : "Copy"}
        </button>
      )}
    </div>
  )
}

export function safeUrl(href?: string | null) {
  if (typeof href !== "string") {
    return undefined
  }
  const trimmed = href.trim()
  if (!trimmed) {
    return undefined
  }
  const lower = trimmed.toLowerCase()
  if (trimmed.startsWith("#") || trimmed.startsWith("/")) {
    return trimmed
  }
  if (lower.startsWith("http://") || lower.startsWith("https://") || lower.startsWith("mailto:") || lower.startsWith("tel:")) {
    return trimmed
  }
  return undefined
}

const components: Components = {
  h1: createHeading(1),
  h2: createHeading(2),
  h3: createHeading(3),
  h4: createHeading(4),
  h5: createHeading(5),
  h6: createHeading(6),
  p: ({ children }) => (
    <p className="whitespace-pre-wrap mb-4 text-sm leading-[1.9] text-foreground last:mb-0">
      {children}
    </p>
  ),
  strong: ({ children }) => <strong className="font-semibold text-foreground">{children}</strong>,
  em: ({ children }) => <em className="italic text-foreground">{children}</em>,
  ul: ({ children }) => (
    <ul className="ml-4 mb-4 list-disc space-y-2 text-sm leading-[1.6] text-foreground">
      {children}
    </ul>
  ),
  ol: ({ children }) => (
    <ol className="ml-4 mb-4 list-decimal space-y-2 text-sm leading-[1.6] text-foreground">
      {children}
    </ol>
  ),
  li: ({ children }) => <li className="leading-[1.6]">{children}</li>,
  blockquote: ({ children }) => (
    <blockquote className="my-4 border-l-2 border-primary/30 pl-4 text-sm italic leading-[1.7] text-muted-foreground">
      {children}
    </blockquote>
  ),
  hr: () => <hr className="my-6 border-border/60" />,
  a: ({ href, children, ...props }) => {
    const sanitizedHref = safeUrl(href)
    const isExternal = Boolean(sanitizedHref && sanitizedHref.startsWith("http"))
    const rel = isExternal ? "noopener noreferrer nofollow ugc" : "nofollow ugc"

    return (
      <a
        {...props}
        href={sanitizedHref}
        className="inline-flex items-center gap-1 underline decoration-dashed decoration-foreground/40 hover:decoration-foreground"
        target={isExternal ? "_blank" : undefined}
        rel={rel}
        onClick={
          sanitizedHref
            ? undefined
            : (event) => {
                event.preventDefault()
              }
        }
      >
        {children}
        {isExternal && <ExternalLink className="h-3 w-3" aria-hidden />}
      </a>
    )
  },
  code: ({ inline = false, className, children }: { inline?: boolean; className?: string; children?: ReactNode }) =>
    inline ? (
      <code className={clsx("rounded bg-muted/60 px-1.5 py-1 font-mono text-xs text-foreground", className)}>
        {children}
      </code>
    ) : (
      <code className={clsx("font-mono text-xs", className)}>{children}</code>
    ),
  pre: ({ children }) => <MarkdownCodeBlock>{children}</MarkdownCodeBlock>,
  table: ({ children }) => (
    <div className="my-4 overflow-auto rounded-xl border border-border/50">
      <table className="w-full min-w-[480px] border-collapse text-sm leading-[1.4] text-foreground">
        {children}
      </table>
    </div>
  ),
  thead: ({ children }) => <thead className="bg-muted/50 text-xs uppercase tracking-wide text-muted-foreground">{children}</thead>,
  tbody: ({ children }) => <tbody>{children}</tbody>,
  th: ({ node, children }) => (
    <th className={clsx("border-b border-border/50 px-3 py-2 text-left font-semibold", alignClass(node))}>{children}</th>
  ),
  td: ({ node, children }) => (
    <td className={clsx("border-b border-border/40 px-3 py-2 align-top", alignClass(node))}>{children}</td>
  ),
  br: () => <br />,
}

const MARKDOWN_PLUGINS = [remarkGfm]
const SANITIZE_PLUGIN: [typeof rehypeSanitize, Schema] = [rehypeSanitize, SANITIZE_SCHEMA]

export const Markdown = memo(function Markdown({
  content,
  className,
}: {
  content: string
  className?: string
}) {
  const trimmed = content.trim()
  const flagged = useMemo(() => SUSPICIOUS_CONTENT_PATTERN.test(content), [content])
  useEffect(() => {
    if (flagged) {
      console.warn("[Markdown] Received content containing potentially unsafe patterns", {
        preview: content.slice(0, 200),
      })
    }
  }, [flagged, content])

  if (!trimmed) {
    return <div className={className}>{content}</div>
  }

  return (
    <div className={clsx("markdown-root flex flex-col gap-2.5 whitespace-normal", className)}>
      <ReactMarkdown remarkPlugins={MARKDOWN_PLUGINS} rehypePlugins={[SANITIZE_PLUGIN]} components={components}>
        {trimmed}
      </ReactMarkdown>
    </div>
  )
})

export type { Markdown as MarkdownComponent }
