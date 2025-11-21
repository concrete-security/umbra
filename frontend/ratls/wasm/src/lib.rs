#![cfg(target_arch = "wasm32")]

mod transport;

pub use transport::WasmWsStream;

use ratls_core::{
    platform::{AsyncReadExt, AsyncWriteExt, TlsStream},
    tls_connect, AttestationResult, Policy, RatlsError, TeeType,
};
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::{from_value, to_value};
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

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HeaderEntry {
    name: String,
    value: String,
}

fn pick_host(host_header: Option<String>, server_name: &str) -> String {
    host_header
        .map(|value| value.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| server_name.to_string())
}

const DEFAULT_BODY_CHUNK: usize = 8192;

enum BodyMode {
    ContentLength(usize),
    Chunked { remaining_in_chunk: usize },
    Close,
    Finished,
}

#[wasm_bindgen]
pub struct RatlsResponse {
    attestation: JsAttestationResult,
    status: u16,
    status_text: String,
    headers: Vec<HeaderEntry>,
    stream: Option<TlsStream<WasmWsStream>>,
    body_mode: BodyMode,
}

#[wasm_bindgen]
impl RatlsResponse {
    #[wasm_bindgen(getter)]
    pub fn status(&self) -> u16 {
        self.status
    }

    #[wasm_bindgen(getter, js_name = statusText)]
    pub fn status_text(&self) -> String {
        self.status_text.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn headers(&self) -> Result<JsValue, JsValue> {
        to_value(&self.headers).map_err(|err| JsValue::from_str(&err.to_string()))
    }

    #[wasm_bindgen(js_name = attestation)]
    pub fn attestation(&self) -> Result<JsValue, JsValue> {
        to_value(&self.attestation).map_err(|err| JsValue::from_str(&err.to_string()))
    }

    /// Read the next chunk of the HTTP response body.
    /// Returns an empty Uint8Array when the body is fully consumed.
    #[wasm_bindgen(js_name = readChunk)]
    pub async fn read_chunk(&mut self, max_bytes: Option<usize>) -> Result<Box<[u8]>, JsValue> {
        let limit = max_bytes.unwrap_or(DEFAULT_BODY_CHUNK).max(1);
        let stream = self
            .stream
            .as_mut()
            .ok_or_else(|| JsValue::from_str("response body already dropped"))?;

        let chunk = match self.body_mode {
            BodyMode::Finished => Vec::new(),
            BodyMode::ContentLength(remaining) => {
                if remaining == 0 {
                    self.body_mode = BodyMode::Finished;
                    Vec::new()
                } else {
                    let to_read = remaining.min(limit);
                    let data = read_limited(stream, to_read)
                        .await
                        .map_err(to_js_error)?;
                    if data.is_empty() {
                        self.body_mode = BodyMode::Finished;
                        self.stream = None;
                        return Err(JsValue::from_str(
                            "unexpected EOF while reading response body",
                        ));
                    }
                    let left = remaining.saturating_sub(data.len());
                    if left == 0 {
                        self.body_mode = BodyMode::Finished;
                        self.stream = None;
                    } else {
                        self.body_mode = BodyMode::ContentLength(left);
                    }
                    data
                }
            }
            BodyMode::Chunked {
                mut remaining_in_chunk,
            } => loop {
                if remaining_in_chunk == 0 {
                    let size_line = read_line(stream).await.map_err(to_js_error)?;
                    let size_str = size_line
                        .split(';')
                        .next()
                        .map(str::trim)
                        .unwrap_or_default();
                    let chunk_size = usize::from_str_radix(size_str, 16)
                        .map_err(|_| RatlsError::Vendor("invalid chunk size in response".into()))
                        .map_err(to_js_error)?;
                    if chunk_size == 0 {
                        loop {
                            let trailer = read_line(stream).await.map_err(to_js_error)?;
                            if trailer.is_empty() {
                                break;
                            }
                        }
                        self.body_mode = BodyMode::Finished;
                        self.stream = None;
                        break Vec::new();
                    }
                    remaining_in_chunk = chunk_size;
                }

                let to_read = remaining_in_chunk.min(limit);
                let data = read_limited(stream, to_read)
                    .await
                    .map_err(to_js_error)?;
                if data.is_empty() {
                    self.body_mode = BodyMode::Finished;
                    self.stream = None;
                    return Err(JsValue::from_str(
                        "unexpected EOF while reading chunked response",
                    ));
                }

                remaining_in_chunk = remaining_in_chunk.saturating_sub(data.len());
                if remaining_in_chunk == 0 {
                    let mut crlf = [0u8; 2];
                    stream
                        .read_exact(&mut crlf)
                        .await
                        .map_err(|err| RatlsError::Io(err.to_string()))
                        .map_err(to_js_error)?;
                }

                self.body_mode = BodyMode::Chunked {
                    remaining_in_chunk,
                };
                break data;
            },
            BodyMode::Close => {
                let data = read_limited(stream, limit)
                    .await
                    .map_err(to_js_error)?;
                if data.is_empty() {
                    self.body_mode = BodyMode::Finished;
                    self.stream = None;
                }
                data
            }
        };

        Ok(chunk.into_boxed_slice())
    }

    /// Close the underlying TLS stream.
    pub async fn close(&mut self) -> Result<(), JsValue> {
        if let Some(mut stream) = self.stream.take() {
            stream
                .close()
                .await
                .map_err(|err| JsValue::from_str(&err.to_string()))?;
        }
        self.body_mode = BodyMode::Finished;
        Ok(())
    }
}

#[wasm_bindgen(js_name = httpRequest)]
pub async fn ratls_http_request(
    websocket_url: String,
    server_name: String,
    host_header: Option<String>,
    method: String,
    path_and_query: String,
    headers: JsValue,
    body: Option<Vec<u8>>,
) -> Result<RatlsResponse, JsValue> {
    let mut header_entries = parse_header_entries(headers)?;
    let body_bytes = body.unwrap_or_default();
    let host = pick_host(host_header, &server_name);

    ensure_header(&mut header_entries, "host", host.clone());
    let has_transfer_encoding = header_entries
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"));
    if !body_bytes.is_empty()
        && !has_transfer_encoding
        && !has_header(&header_entries, "content-length")
    {
        header_entries.push(HeaderEntry {
            name: "Content-Length".into(),
            value: body_bytes.len().to_string(),
        });
    }
    if !has_header(&header_entries, "connection") {
        header_entries.push(HeaderEntry {
            name: "Connection".into(),
            value: "close".into(),
        });
    }

    let request_line = format!(
        "{} {} HTTP/1.1\r\n",
        method.trim().to_uppercase(),
        normalize_path(path_and_query)
    );
    let mut request = request_line.into_bytes();
    for HeaderEntry { name, value } in &header_entries {
        request.extend_from_slice(name.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(value.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    if !body_bytes.is_empty() {
        request.extend_from_slice(&body_bytes);
    }

    let (mut stream, attestation) = connect_websocket(
        &websocket_url,
        &server_name,
        Policy::default(),
        Some(vec!["http/1.1".into()]),
    )
    .await
    .map_err(to_js_error)?;

    stream
        .write_all(&request)
        .await
        .map_err(|err| JsValue::from_str(&err.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|err| JsValue::from_str(&err.to_string()))?;

    let raw_headers = read_raw_headers(&mut stream).await.map_err(to_js_error)?;
    let (status, status_text, parsed_headers) =
        parse_headers(&raw_headers).map_err(|err| JsValue::from_str(&err.to_string()))?;

    let headers_for_js = parsed_headers
        .iter()
        .map(|(name, value)| HeaderEntry {
            name: name.clone(),
            value: value.clone(),
        })
        .collect::<Vec<_>>();

    let body_mode = if let Some(len) = find_content_length(&parsed_headers) {
        if len == 0 {
            BodyMode::Finished
        } else {
            BodyMode::ContentLength(len)
        }
    } else if is_chunked(&parsed_headers) {
        BodyMode::Chunked {
            remaining_in_chunk: 0,
        }
    } else {
        BodyMode::Close
    };

    Ok(RatlsResponse {
        attestation: JsAttestationResult::from(attestation),
        status,
        status_text,
        headers: headers_for_js,
        stream: Some(stream),
        body_mode,
    })
}

fn normalize_path(path_and_query: String) -> String {
    let trimmed = path_and_query.trim();
    if trimmed.is_empty() {
        "/".into()
    } else if trimmed.starts_with('/') {
        trimmed.into()
    } else {
        format!("/{}", trimmed)
    }
}

fn ensure_header(entries: &mut Vec<HeaderEntry>, name: &str, value: String) {
    if !has_header(entries, name) {
        entries.push(HeaderEntry {
            name: name
                .chars()
                .enumerate()
                .map(|(idx, c)| {
                    if idx == 0 {
                        c.to_ascii_uppercase()
                    } else {
                        c
                    }
                })
                .collect(),
            value,
        });
    }
}

fn has_header(entries: &[HeaderEntry], name: &str) -> bool {
    entries
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case(name))
}

fn parse_header_entries(headers: JsValue) -> Result<Vec<HeaderEntry>, JsValue> {
    if headers.is_undefined() || headers.is_null() {
        return Ok(Vec::new());
    }
    from_value::<Vec<HeaderEntry>>(headers)
        .map_err(|err| JsValue::from_str(&format!("invalid headers: {err}")))
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

async fn read_limited(
    stream: &mut TlsStream<WasmWsStream>,
    limit: usize,
) -> Result<Vec<u8>, RatlsError> {
    let mut buf = vec![0u8; limit];
    let read = stream
        .read(&mut buf)
        .await
        .map_err(|err| RatlsError::Io(err.to_string()))?;
    buf.truncate(read);
    Ok(buf)
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
