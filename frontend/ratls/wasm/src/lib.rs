#![cfg(target_arch = "wasm32")]

mod transport;

pub use transport::WasmWsStream;

use ratls_core::{
    platform::{AsyncReadExt, AsyncWriteExt, TlsStream},
    tls_connect, AttestationResult, Policy, RatlsError, TeeType,
};
use serde::Serialize;
use serde_json::{json, Value};
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HeaderEntry {
    name: String,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChatDemoResult {
    attestation: JsAttestationResult,
    status: u16,
    status_text: String,
    headers: Vec<HeaderEntry>,
    completion: Option<String>,
    body: Value,
}

struct ParsedHttpResponse {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

const DEFAULT_MODEL: &str = "openai/gpt-oss-120b";

#[wasm_bindgen]
pub async fn run_vllm_chat_completion(
    websocket_url: String,
    server_name: String,
    host_header: Option<String>,
    api_key: Option<String>,
    prompt: String,
    model: Option<String>,
) -> Result<JsValue, JsValue> {
    let host = pick_host(host_header, &server_name);
    let model_name = model
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .unwrap_or(DEFAULT_MODEL)
        .to_string();

    let policy = chat_policy();
    let (mut stream, attestation) =
        connect_websocket(&websocket_url, &server_name, policy, Some(vec!["http/1.1".into()]))
            .await
            .map_err(to_js_error)?;

    let request =
        build_chat_request(&host, api_key.as_deref(), &model_name, &prompt).map_err(to_js_error)?;
    let response = send_http_request(&mut stream, &request)
        .await
        .map_err(to_js_error)?;

    let body_value: Value = serde_json::from_slice(&response.body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&response.body).into_owned()));
    let completion = extract_completion(&body_value);

    let result = ChatDemoResult {
        attestation: JsAttestationResult::from(attestation),
        status: response.status,
        status_text: response.reason,
        headers: response
            .headers
            .into_iter()
            .map(|(name, value)| HeaderEntry { name, value })
            .collect(),
        completion,
        body: body_value,
    };

    to_value(&result).map_err(|err| JsValue::from_str(&err.to_string()))
}

fn pick_host(host_header: Option<String>, server_name: &str) -> String {
    host_header
        .map(|value| value.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| server_name.to_string())
}

fn chat_policy() -> Policy {
    Policy {
        allowed_tdx_status: vec![
            "UpToDate".into(),
            "UpToDateWithWarnings".into(),
            "ConfigurationNeeded".into(),
            "SWHardeningNeeded".into(),
            "ConfigurationAndSWHardeningNeeded".into(),
            "OutOfDate".into(),
            "OutOfDateConfigurationNeeded".into(),
        ],
        ..Policy::default()
    }
}

fn build_chat_request(
    host: &str,
    api_key: Option<&str>,
    model: &str,
    prompt: &str,
) -> Result<String, RatlsError> {
    let payload = json!({
        "model": model,
        "messages": [
            {
                "role": "user",
                "content": prompt,
            }
        ],
        "stream": false,
    });
    let body = serde_json::to_string(&payload).map_err(|err| RatlsError::Io(err.to_string()))?;

    let mut request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\n\
         Host: {host}\r\n\
         Content-Type: application/json\r\n\
         Accept: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n",
        body.len()
    );
    if let Some(token) = api_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&body);
    Ok(request)
}

fn extract_completion(body: &Value) -> Option<String> {
    let choices = body.get("choices")?.as_array()?;
    let choice = choices.first()?;
    if let Some(content) = choice
        .get("message")
        .and_then(|msg| msg.get("content"))
        .and_then(|v| v.as_str())
    {
        return Some(content.to_string());
    }
    choice
        .get("text")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

async fn send_http_request(
    stream: &mut TlsStream<WasmWsStream>,
    request: &str,
) -> Result<ParsedHttpResponse, RatlsError> {
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|err| RatlsError::Io(err.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|err| RatlsError::Io(err.to_string()))?;
    read_http_response(stream).await
}

async fn read_http_response(
    stream: &mut TlsStream<WasmWsStream>,
) -> Result<ParsedHttpResponse, RatlsError> {
    let raw_headers = read_raw_headers(stream).await?;
    let (status, reason, headers) = parse_headers(&raw_headers)?;
    let body = read_body(stream, &headers).await?;

    Ok(ParsedHttpResponse {
        status,
        reason,
        headers,
        body,
    })
}

async fn read_raw_headers(stream: &mut TlsStream<WasmWsStream>) -> Result<Vec<u8>, RatlsError> {
    let mut header_buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|err| RatlsError::Io(err.to_string()))?;
        header_buffer.push(byte[0]);
        if header_buffer.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buffer.len() > 16 * 1024 {
            return Err(RatlsError::Io("HTTP header too large".into()));
        }
    }
    Ok(header_buffer)
}

fn parse_headers(raw: &[u8]) -> Result<(u16, String, Vec<(String, String)>), RatlsError> {
    let headers_str = String::from_utf8(raw.to_vec())
        .map_err(|err| RatlsError::Io(format!("invalid HTTP header bytes: {err}")))?;
    let mut lines = headers_str.split("\r\n").filter(|line| !line.is_empty());
    let status_line = lines
        .next()
        .ok_or_else(|| RatlsError::Vendor("missing status line".into()))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let _http_version = status_parts.next().unwrap_or_default();
    let status_code: u16 = status_parts
        .next()
        .ok_or_else(|| RatlsError::Vendor("missing status code".into()))?
        .parse()
        .map_err(|_| RatlsError::Vendor("invalid status code".into()))?;
    let reason = status_parts.next().unwrap_or("").to_string();

    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect::<Vec<_>>();
    Ok((status_code, reason, headers))
}

async fn read_body(
    stream: &mut TlsStream<WasmWsStream>,
    headers: &[(String, String)],
) -> Result<Vec<u8>, RatlsError> {
    if let Some(len) = find_content_length(headers) {
        let mut body = vec![0u8; len];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|err| RatlsError::Io(err.to_string()))?;
        return Ok(body);
    }

    if is_chunked(headers) {
        return read_chunked_body(stream).await;
    }

    let mut body = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let read = stream
            .read(&mut buf)
            .await
            .map_err(|err| RatlsError::Io(err.to_string()))?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buf[..read]);
    }
    Ok(body)
}

fn find_content_length(headers: &[(String, String)]) -> Option<usize> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    })
}

async fn read_chunked_body(
    stream: &mut TlsStream<WasmWsStream>,
) -> Result<Vec<u8>, RatlsError> {
    let mut body = Vec::new();
    loop {
        let size_line = read_line(stream).await?;
        let size_str = size_line
            .split(';')
            .next()
            .map(str::trim)
            .unwrap_or_default();
        let chunk_size =
            usize::from_str_radix(size_str, 16).map_err(|_| RatlsError::Vendor("invalid chunk size in response".into()))?;

        if chunk_size == 0 {
            // Consume trailer lines until the terminating CRLF.
            loop {
                let trailer = read_line(stream).await?;
                if trailer.is_empty() {
                    break;
                }
            }
            break;
        }

        let mut chunk = vec![0u8; chunk_size];
        stream
            .read_exact(&mut chunk)
            .await
            .map_err(|err| RatlsError::Io(err.to_string()))?;
        body.extend_from_slice(&chunk);

        // Discard trailing CRLF after each chunk.
        let mut crlf = [0u8; 2];
        stream
            .read_exact(&mut crlf)
            .await
            .map_err(|err| RatlsError::Io(err.to_string()))?;
    }
    Ok(body)
}

async fn read_line(stream: &mut TlsStream<WasmWsStream>) -> Result<String, RatlsError> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|err| RatlsError::Io(err.to_string()))?;
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            buf.push(byte[0]);
        }
        if buf.len() > 8192 {
            return Err(RatlsError::Io("line too long while reading response".into()));
        }
    }
    String::from_utf8(buf).map_err(|err| RatlsError::Io(format!("invalid utf-8 in response line: {err}")))
}
