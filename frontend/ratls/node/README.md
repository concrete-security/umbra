# node (napi-rs binding)

Node binding for the Rust core. Prefers direct TCP to the TEE, with optional tunnel path identical to the browser (WebSocket/WebTransport via proxy).

## Responsibilities
- Provide `connectTcp` and `connectTunnel` async APIs returning a stream-like object with attestation metadata.
- Surface the same policy and attestation result shapes as the browser client.
- Reuse Rust async runtime; map into Node buffers cleanly.

## Next steps
- Initialize napi-rs project scaffold and build script from the core crate.
- Add smoke tests that connect to mock RA-TLS servers and verify key-binding failures.
