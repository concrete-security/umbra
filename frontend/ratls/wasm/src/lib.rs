#![cfg(target_arch = "wasm32")]

mod transport;

pub use transport::WasmWsStream;

use ratls_core::{platform::TlsStream, tls_connect, AttestationResult, Policy, RatlsError};

/// Establish a TLS + attestation session over a browser WebSocket.
pub async fn connect_websocket(
    url: &str,
    server_name: &str,
    policy: Policy,
    alpn: Option<Vec<String>>,
) -> Result<(TlsStream<WasmWsStream>, AttestationResult), RatlsError> {
    let ws = transport::WasmWsStream::connect(url).await?;
    tls_connect(ws, server_name, policy, alpn).await
}
