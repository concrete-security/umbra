use super::{is_lower_hex, CliError, ATTESTATION_QUOTE_INVALID, CA_FETCH_FAILED};
use rustls::pki_types::DnsName;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{net::IpAddr, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEADER_BYTES: usize = 8192;
const MAX_CA_BYTES: usize = 16 * 1024;
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaExport {
    token: String,
    pub expected_rtmr3: String,
    pub connect_ip: Option<IpAddr>,
}

impl CaExport {
    pub fn validate(&self, fqdn: &str, policy: &Value) -> Result<(), CliError> {
        if !fqdn.contains('.')
            || !fqdn
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b".-".contains(&c))
            || DnsName::try_from(fqdn).is_err()
        {
            return Err(CliError::new(
                ATTESTATION_QUOTE_INVALID,
                "invalid_ca_export_fqdn",
            ));
        }
        if !is_lower_hex(&self.expected_rtmr3) {
            return Err(CliError::new(
                ATTESTATION_QUOTE_INVALID,
                "invalid_ca_export_rtmr3",
            ));
        }
        if self.token.is_empty()
            || self.token.len() > 256
            || !self
                .token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            || policy
                .pointer("/rtmr3_binding/ca_export_token_sha256")
                .and_then(Value::as_str)
                != Some(hex::encode(Sha256::digest(self.token.as_bytes())).as_str())
        {
            return Err(CliError::new(
                ATTESTATION_QUOTE_INVALID,
                "invalid_ca_export_token",
            ));
        }
        Ok(())
    }

    /// The only caller supplies the stream that has just passed full attestation.
    pub async fn fetch<S>(&self, stream: &mut S, fqdn: &str) -> Result<String, CliError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        tokio::time::timeout(HTTP_TIMEOUT, async {
            let request = format!(
                "GET /ca.pem HTTP/1.1\r\nHost: {fqdn}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
                self.token
            );
            stream.write_all(request.as_bytes()).await.map_err(|_| connection_failed())?;
            stream.flush().await.map_err(|_| connection_failed())?;
            read_ca_response(stream).await
        })
        .await
        .map_err(|_| CliError::new(CA_FETCH_FAILED, "ca_response_timeout"))?
    }
}

fn connection_failed() -> CliError {
    CliError::new(CA_FETCH_FAILED, "ca_connection_failed")
}

fn invalid_response() -> CliError {
    CliError::new(CA_FETCH_FAILED, "invalid_ca_response")
}

async fn read_ca_response<S: AsyncRead + Unpin>(stream: &mut S) -> Result<String, CliError> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 1024];
    let header_end = loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|_| connection_failed())?;
        if read == 0 {
            return Err(invalid_response());
        }
        bytes.extend_from_slice(&chunk[..read]);
        if let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            if end + 4 <= MAX_HEADER_BYTES {
                break end + 4;
            }
            return Err(invalid_response());
        }
        if bytes.len() >= MAX_HEADER_BYTES {
            return Err(invalid_response());
        }
    };
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    if response
        .parse(&bytes[..header_end])
        .map_err(|_| invalid_response())?
        != httparse::Status::Complete(header_end)
    {
        return Err(invalid_response());
    }
    let status = response.code.ok_or_else(invalid_response)?;
    if status != 200 {
        return Err(CliError::new(CA_FETCH_FAILED, "ca_http_status").detail("http_status", status));
    }
    if response
        .headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        return Err(invalid_response());
    }
    let mut lengths = response
        .headers
        .iter()
        .filter(|h| h.name.eq_ignore_ascii_case("content-length"));
    let length = lengths
        .next()
        .and_then(|h| {
            if !h.value.iter().all(u8::is_ascii_digit) {
                return None;
            }
            std::str::from_utf8(h.value).ok()?.parse::<usize>().ok()
        })
        .filter(|len| (1..=MAX_CA_BYTES).contains(len))
        .ok_or_else(invalid_response)?;
    if lengths.next().is_some() || bytes.len() > header_end + length {
        return Err(invalid_response());
    }
    let buffered = bytes.len();
    bytes.resize(header_end + length, 0);
    stream
        .read_exact(&mut bytes[buffered..])
        .await
        .map_err(|_| invalid_response())?;
    String::from_utf8(bytes.split_off(header_end)).map_err(|_| invalid_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Request the CA and read its body through the stream supplied by the verifier.
    #[tokio::test]
    async fn fetch_uses_supplied_stream_success() {
        let (mut stream, mut peer) = tokio::io::duplex(32);
        let export = CaExport {
            token: "fixture-token".into(),
            expected_rtmr3: "a".repeat(96),
            connect_ip: None,
        };
        let request = b"GET /ca.pem HTTP/1.1\r\nHost: sc.example.com\r\nAuthorization: Bearer fixture-token\r\nConnection: close\r\n\r\n";
        let peer_task = tokio::spawn(async move {
            let mut observed = vec![0; request.len()];
            peer.read_exact(&mut observed).await.unwrap();
            assert_eq!(observed, request);
            peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody")
                .await
                .unwrap();
        });
        assert_eq!(
            export.fetch(&mut stream, "sc.example.com").await.unwrap(),
            "body"
        );
        peer_task.await.unwrap();
    }

    /// A redirect is a terminal error and does not cause a new connection.
    #[tokio::test]
    async fn response_redirect_failure() {
        let mut stream = &b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://other.example/ca.pem\r\nContent-Length: 0\r\n\r\n"[..];
        let error = read_ca_response(&mut stream).await.unwrap_err();
        assert_eq!(error.details["http_status"], 307);
    }

    /// The declared size must fit the bounded response buffer before reading it.
    #[tokio::test]
    async fn oversized_ca_response_failure() {
        let mut stream = &b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n"[..];
        let error = read_ca_response(&mut stream).await.unwrap_err();
        assert_eq!(error.details["reason"], "invalid_ca_response");
    }

    /// The bearer sent over TLS must match the policy value supplied by the Console.
    #[test]
    fn ca_export_token_policy_mismatch_failure() {
        let export = CaExport {
            token: "fixture-token".into(),
            expected_rtmr3: "a".repeat(96),
            connect_ip: None,
        };
        let policy =
            serde_json::json!({"rtmr3_binding": {"ca_export_token_sha256": "b".repeat(64)}});
        let error = export.validate("sc.example.com", &policy).unwrap_err();
        assert_eq!(error.details["reason"], "invalid_ca_export_token");
    }
}
