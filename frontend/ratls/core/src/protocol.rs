use crate::platform::{AsyncReadExt, AsyncWriteExt, TlsStream};
use crate::tdx::{self, TcgEvent};
use crate::{AsyncByteStream, AttestationEndpoint, AttestationResult, Policy, RatlsError};
use dcap_qvl::QuoteCollateralV3;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;

fn success_default_true() -> bool {
    true
}

#[derive(Serialize)]
struct AttestationRequest {
    report_data: String,
}

#[derive(Deserialize)]
struct AttestationResponse {
    #[serde(default = "success_default_true")]
    success: bool,
    quote: Option<DstackQuote>,
    error: Option<String>,
    #[serde(default)]
    collateral: Option<QuoteCollateralV3>,
}

#[derive(Deserialize)]
struct DstackQuote {
    quote: String,
    #[serde(default)]
    event_log: Value,
}

pub async fn verify_attestation_stream<S>(
    stream: &mut TlsStream<S>,
    server_cert: &[u8],
    policy: &Policy,
    endpoint: &AttestationEndpoint,
) -> Result<AttestationResult, RatlsError>
where
    S: AsyncByteStream,
{
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let nonce_hex = hex::encode(nonce);

    let body_json = serde_json::to_string(&AttestationRequest {
        report_data: nonce_hex.clone(),
    })
    .map_err(|e| RatlsError::Io(e.to_string()))?;
    let request = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: {}\r\n\
         \r\n\
         {}",
        endpoint.path,
        endpoint.host,
        body_json.len(),
        if endpoint.use_keep_alive {
            "keep-alive"
        } else {
            "close"
        },
        body_json
    );

    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;

    let mut header_buffer = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| RatlsError::Io(e.to_string()))?;
        header_buffer.push(byte[0]);
        if header_buffer.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buffer.len() > 8192 {
            return Err(RatlsError::Io("HTTP header too large".into()));
        }
    }

    let headers_str = String::from_utf8_lossy(&header_buffer);
    if !headers_str.starts_with("HTTP/1.1 200 OK") {
        let status_line = headers_str.lines().next().unwrap_or_default();
        return Err(RatlsError::Vendor(format!(
            "Server returned error: {status_line}"
        )));
    }

    let len_prefix = "content-length: ";
    let content_len = headers_str
        .to_lowercase()
        .lines()
        .find(|line| line.starts_with(len_prefix))
        .ok_or_else(|| RatlsError::Io("Missing Content-Length".into()))
        .and_then(|line| {
            line[len_prefix.len()..]
                .trim()
                .parse::<usize>()
                .map_err(|_| RatlsError::Io("Invalid Content-Length".into()))
        })?;

    let mut body = vec![0u8; content_len];
    stream
        .read_exact(&mut body)
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;

    let response: AttestationResponse = serde_json::from_slice(&body)
        .map_err(|e| RatlsError::Vendor(format!("Invalid server response: {e}")))?;
    if !response.success {
        let message = response
            .error
            .unwrap_or_else(|| "attestation server reported failure".into());
        return Err(RatlsError::Vendor(message));
    }

    let dstack_quote = response
        .quote
        .ok_or_else(|| RatlsError::Vendor("missing quote payload".into()))?;
    let quote_bytes = hex::decode(&dstack_quote.quote)
        .map_err(|e| RatlsError::Vendor(format!("Invalid quote hex: {e}")))?;
    let event_log = parse_event_log(dstack_quote.event_log)?;

    let collateral = if let Some(collateral) = response.collateral {
        collateral
    } else if let Some(pccs) = policy.pccs_url.as_deref() {
        dcap_qvl::collateral::get_collateral(pccs, &quote_bytes)
            .await
            .map_err(|e| RatlsError::Vendor(format!("Failed to fetch collateral: {e}")))?
    } else {
        return Err(RatlsError::Policy(
            "Server did not provide collateral and no PCCS configured".into(),
        ));
    };

    let attestation = tdx::verify_attestation(&quote_bytes, &collateral, policy).await?;

    tdx::verify_quote_freshness(&quote_bytes, nonce_hex.as_bytes())?;
    tdx::verify_event_log_integrity(&quote_bytes, &event_log)?;

    tdx::verify_tls_certificate_in_log(&event_log, server_cert)?;

    Ok(attestation)
}

fn parse_event_log(value: Value) -> Result<Vec<TcgEvent>, RatlsError> {
    match value {
        Value::Null => Ok(vec![]),
        Value::Array(_) => serde_json::from_value(value)
            .map_err(|e| RatlsError::Vendor(format!("Invalid event log array: {e}"))),
        Value::String(s) => {
            if s.trim().is_empty() {
                Ok(vec![])
            } else {
                let preview = event_log_preview(&s);
                serde_json::from_str::<Vec<TcgEvent>>(&s).map_err(|e| {
                    RatlsError::Vendor(format!(
                        "Invalid event log string (len {}, preview {}): {e}",
                        s.len(),
                        preview
                    ))
                })
            }
        }
        other => Err(RatlsError::Vendor(format!(
            "Unsupported event log format: {other}"
        ))),
    }
}

fn event_log_preview(s: &str) -> String {
    let trimmed = s.trim();
    let mut snippet: String = trimmed.chars().take(120).collect();
    if trimmed.len() > snippet.len() {
        snippet.push('…');
    }
    snippet.replace('\n', "\\n")
}
