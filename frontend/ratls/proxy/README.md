# proxy (byte forwarder)

WebSocket (and later WebTransport) to TCP bridge that forwards raw bytes to the TEE. Does not terminate inner TLS.

## Requirements
- Endpoints: `wss://proxy/tunnel?target=host:port`; optional WebTransport stream mapping to TCP.
- AuthN/AuthZ (JWT or mTLS) plus destination ACL to prevent SSRF.
- Origin allowlist for browser clients, idle timeouts, backpressure, and metrics (connects, bytes, duration).

## Next steps
- Choose Rust (tokio + axum + tokio-tungstenite) or Node for the first cut; add config for target allowlist.
- Build a simple echo/mirror integration test with the WASM client once available.
