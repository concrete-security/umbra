// Next.js server runtime helpers:
// - NextRequest is the typed request object the route handler receives (URL, headers, cookies, body, etc.)
// - NextResponse is used to build HTTP responses (JSON, status codes, headers, redirects, cookies)
import { NextRequest, NextResponse } from "next/server"


// Node.js filesystem API (Promise-based):
// Allow read/write files asynchronously with async/await (readFile, writeFile, readdir, mkdir, ...)
import fs from "fs/promises"

import path from "path"

// App-specific theme:
// - EXAMPLE_THEMES is the map of all available example themes.
import { EXAMPLE_THEMES, type ExampleThemeId } from "@/lib/example-themes"


// GET /api/example-docs/[anything]
// Exemple: /api/example-docs/medical-report
export async function GET(
    _req: NextRequest,
    { params }: { params: Promise<{ id: string }> },
) {

  // Extract the dynamic route parameter "id" from context.params
  const { id } = await params

  // Get the given example theme id
  const theme = EXAMPLE_THEMES[id as ExampleThemeId]

  // If the id is unknown, return HTTP 404 Not Found
  if (!theme) {
    return NextResponse.json(
      { error: `Unknown example id: ${id}` },
      { status: 404 },
    )
  }

  // Build the path based on the theme: <projet>/examples_docs/<dir>/
  const baseDir = path.join(process.cwd(), "examples_docs", theme.dir)


  try {
    // 1) Read all entries in the theme directory (files + sub-directories)
    const entries = await fs.readdir(baseDir, { withFileTypes: true })

    // 2) Keep only regular files that end with ".pdf"
    const pdfEntries = entries.filter(
      (entry) =>
        entry.isFile() &&
        entry.name.toLowerCase().endsWith(".pdf"),
    )

    if (pdfEntries.length === 0) {
      return NextResponse.json(
        { error: `No PDF found for theme: ${id}` },
        { status: 404 },
      )
    }

    // 3) For each PDF, read its content and encode it as base64
    const files = await Promise.all(
      pdfEntries.map(async (entry) => {
        const filePath = path.join(baseDir, entry.name)
        const fileBuffer = await fs.readFile(filePath)

        return {
          name: entry.name,
          type: "application/pdf",            // all demo files are PDFs
          data: fileBuffer.toString("base64") // binary content encoded as base64
        }
      }),
    )

    // 4) Return a JSON payload containing all the files for this theme
    return NextResponse.json({ files })
  } catch (error) {
    console.error("Error reading example files", error)
    return NextResponse.json(
      { error: "Failed to read example files" },
      { status: 500 },
    )
  }

}
