#![cfg(target_arch = "wasm32")]

mod transport;

pub use transport::WasmWsStream;

use ratls_core::{
    platform::{AsyncWriteExt, TlsStream},
    tls_connect, AttestationResult, Policy, RatlsError, TeeType,
};
use serde::Serialize;
use serde_wasm_bindgen::to_value;
use wasm_bindgen::prelude::*;

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct JsAttestationResult {
    trusted: bool,
    tee_type: String,
    measurement: Option<String>,
    tcb_status: String,
    advisory_ids: Vec<String>,
}

impl From<AttestationResult> for JsAttestationResult {
    fn from(value: AttestationResult) -> Self {
        let AttestationResult {
            trusted,
            tee_type,
            measurement,
            tcb_status,
            advisory_ids,
        } = value;
        Self {
            trusted,
            tee_type: tee_type_label(tee_type).to_string(),
            measurement,
            tcb_status,
            advisory_ids,
        }
    }
}

#[wasm_bindgen]
pub async fn run_attestation_check(url: String, server_name: String) -> Result<JsValue, JsValue> {
    let (mut stream, attestation) = connect_websocket(&url, &server_name, Policy::default(), None)
        .await
        .map_err(to_js_error)?;
    let _ = stream.close().await;
    to_value(&JsAttestationResult::from(attestation))
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

fn tee_type_label(kind: TeeType) -> &'static str {
    match kind {
        TeeType::Tdx => "tdx",
    }
}

fn to_js_error(err: RatlsError) -> JsValue {
    JsValue::from_str(&err.to_string())
}
