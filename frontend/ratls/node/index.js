const path = require("path")
const fs = require("fs")

const envPath = process.env.RATLS_NODE_BINARY
const releasePath = path.resolve(__dirname, "../target/release/ratls_node.node")
const debugPath = path.resolve(__dirname, "../target/debug/ratls_node.node")

const candidate = envPath || (fs.existsSync(releasePath) ? releasePath : debugPath)
module.exports = require(candidate)
