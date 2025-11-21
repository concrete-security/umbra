# Node examples

- `ai-sdk-openai-demo.mjs`: direct TCP RA-TLS request to `vllm.concrete-security.com` using the native `ratls-node` binding and `@ai-sdk/openai`. Requires Rust 1.88+ (`cargo build -p ratls-node --release`) and dev deps (`pnpm add -D @ai-sdk/openai ai ws zod@^4`).
