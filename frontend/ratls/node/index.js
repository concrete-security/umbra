import fs from "node:fs"
import path from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"
import { createRequire } from "module"

const require = createRequire(import.meta.url)
const __dirname = path.dirname(fileURLToPath(import.meta.url))

const envPath = process.env.RATLS_NODE_BINARY
const releasePath = path.resolve(__dirname, "../target/release/ratls_node.node")
const debugPath = path.resolve(__dirname, "../target/debug/ratls_node.node")

function ensureNodeBinary(nodePath, libPath) {
  if (!fs.existsSync(libPath)) return null
  try {
    if (fs.existsSync(nodePath)) fs.rmSync(nodePath)
    fs.copyFileSync(libPath, nodePath)
  } catch {
    try {
      fs.symlinkSync(libPath, nodePath)
    } catch {
      /* ignore */
    }
  }
  return fs.existsSync(nodePath) ? nodePath : null
}

function resolveCandidate() {
  if (envPath) return envPath

  const platformLib =
    process.platform === "win32"
      ? "ratls_node.dll"
      : process.platform === "darwin"
      ? "libratls_node.dylib"
      : "libratls_node.so"

  const releaseLib = path.resolve(__dirname, "../target/release", platformLib)
  const debugLib = path.resolve(__dirname, "../target/debug", platformLib)

  const release = ensureNodeBinary(releasePath, releaseLib)
  if (release) return release
  const debug = ensureNodeBinary(debugPath, debugLib)
  if (debug) return debug

  throw new Error(
    `ratls_node native module not found. Expected at ${releasePath} or ${debugPath} (or matching platform library). Build with "cargo build -p ratls-node --release".`
  )
}

const binding = require(resolveCandidate())
export default binding
export const httpRequest = binding.http_request || binding.httpRequest
export const exportsMap = binding
