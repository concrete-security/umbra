//! Quote-anchored RTMR3 replay states. Never export event payloads.
use super::{CliError, ATTESTATION_QUOTE_INVALID, ATTESTATION_RTMR_MISMATCH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_EVENTS: usize = 512;
const DSTACK_EVENT_TYPE: u32 = 0x08000001;

pub struct RecordingStream<S> {
    inner: S,
    response: Vec<u8>,
}

impl<S> RecordingStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            response: Vec::new(),
        }
    }
    pub fn response(&self) -> &[u8] {
        &self.response
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let bytes = &buf.filled()[before..];
                if self.response.len() + bytes.len() > MAX_RESPONSE_BYTES {
                    // AsyncRead errors must not advance the caller's filled buffer.
                    buf.set_filled(before);
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "quote response too large",
                    )));
                }
                self.response.extend_from_slice(bytes);
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Deserialize)]
struct EndpointResponse {
    quote: QuoteEvidence,
}
#[derive(Deserialize)]
struct QuoteEvidence {
    event_log: String,
}
#[derive(Deserialize)]
struct Event {
    imr: u32,
    event_type: u32,
    digest: String,
    event: String,
    event_payload: String,
}

#[derive(Debug, Serialize)]
pub struct ReplayState {
    digest: String,
    tls_certificate_event: bool,
}

fn invalid() -> CliError {
    CliError::new(ATTESTATION_QUOTE_INVALID, "invalid_rtmr3_evidence")
}

/// Validate metadata as well as replay: an unverified event label cannot grant
/// the certificate exception. The terminal state must equal Atlas's VERIFIED
/// report, and the last certificate must match this same TLS session.
pub fn replay_evidence(
    response: &[u8],
    verified_rtmr3: &str,
    peer_cert: &[u8],
) -> Result<Vec<ReplayState>, CliError> {
    if response.len() > MAX_RESPONSE_BYTES
        || !(response.starts_with(b"HTTP/1.1 200 ") || response.starts_with(b"HTTP/1.0 200 "))
    {
        return Err(invalid());
    }
    let start = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(invalid)?
        + 4;
    let endpoint: EndpointResponse =
        serde_json::from_slice(&response[start..]).map_err(|_| invalid())?;
    let events: Vec<Event> =
        serde_json::from_str(&endpoint.quote.event_log).map_err(|_| invalid())?;
    if events.len() > MAX_EVENTS {
        return Err(invalid());
    }
    let mut mr = [0u8; 48];
    let mut history = Vec::new();
    let mut last_certificate = None;
    for event in events.into_iter().filter(|event| event.imr == 3) {
        if event.event.len() > 128 || event.event_payload.len() > 8192 {
            return Err(invalid());
        }
        let payload = hex::decode(&event.event_payload).map_err(|_| invalid())?;
        let recorded = hex::decode(&event.digest).map_err(|_| invalid())?;
        // dstack amd64 event encoding: LE event type, colon, name, colon, payload.
        let mut digest = Sha384::new();
        digest.update(event.event_type.to_le_bytes());
        digest.update(b":");
        digest.update(event.event.as_bytes());
        digest.update(b":");
        digest.update(&payload);
        let expected: [u8; 48] = digest.finalize().into();
        if recorded.as_slice() != expected {
            return Err(invalid());
        }
        let certificate =
            event.event_type == DSTACK_EVENT_TYPE && event.event == "New TLS Certificate";
        if certificate {
            if payload.len() != 64
                || !payload
                    .iter()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                return Err(invalid());
            }
            last_certificate = Some(payload);
        }
        let mut replay = Sha384::new();
        replay.update(mr);
        replay.update(&recorded);
        mr = replay.finalize().into();
        history.push(ReplayState {
            digest: hex::encode(mr),
            tls_certificate_event: certificate,
        });
    }
    if history.is_empty() || hex::encode(mr) != verified_rtmr3 {
        return Err(CliError::new(
            ATTESTATION_RTMR_MISMATCH,
            "rtmr3_evidence_mismatch",
        ));
    }
    if last_certificate.as_deref() != Some(hex::encode(Sha256::digest(peer_cert)).as_bytes()) {
        return Err(invalid());
    }
    Ok(history)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn event(name: &str, payload: &[u8]) -> Value {
        let mut digest = Sha384::new();
        digest.update(DSTACK_EVENT_TYPE.to_le_bytes());
        digest.update(b":");
        digest.update(name.as_bytes());
        digest.update(b":");
        digest.update(payload);
        json!({"imr":3,"event_type":DSTACK_EVENT_TYPE,"event":name,
            "event_payload":hex::encode(payload),"digest":hex::encode(digest.finalize())})
    }
    fn fixture(events: &[Value]) -> (Vec<u8>, String) {
        let mut mr = [0u8; 48];
        for e in events {
            let mut digest = Sha384::new();
            digest.update(mr);
            digest.update(hex::decode(e["digest"].as_str().unwrap()).unwrap());
            mr = digest.finalize().into();
        }
        let body =
            json!({"quote":{"event_log":serde_json::to_string(events).unwrap()}}).to_string();
        (
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
            .into_bytes(),
            hex::encode(mr),
        )
    }
    /// Keep immutable events classified separately from a genuine certificate extension.
    #[test]
    fn certificate_replay_evidence_success() {
        let cert = b"current DER certificate";
        let events = vec![
            event("system-ready", b""),
            event(
                "New TLS Certificate",
                hex::encode(Sha256::digest(cert)).as_bytes(),
            ),
        ];
        let (response, mr) = fixture(&events);
        let history = replay_evidence(&response, &mr, cert).unwrap();
        assert_eq!(
            history
                .iter()
                .map(|s| s.tls_certificate_event)
                .collect::<Vec<_>>(),
            vec![false, true]
        );
    }

    /// The original certificate state survives unchanged when a new leaf is measured.
    #[test]
    fn renewed_certificate_preserves_replay_prefix_success() {
        let cert = b"renewed certificate";
        let old_events = vec![
            event("system-ready", b""),
            event(
                "New TLS Certificate",
                hex::encode(Sha256::digest(b"old certificate")).as_bytes(),
            ),
        ];
        let (_, old_mr) = fixture(&old_events);
        let mut events = old_events;
        events.push(event(
            "New TLS Certificate",
            hex::encode(Sha256::digest(cert)).as_bytes(),
        ));
        let (response, mr) = fixture(&events);
        let history = replay_evidence(&response, &mr, cert).unwrap();
        assert_eq!(history[1].digest, old_mr);
        assert!(history[2].tls_certificate_event);
    }
    /// Relabeling an unexpected event without recomputing its measured digest must fail.
    #[test]
    fn forged_certificate_label_failure() {
        let cert = b"cert";
        let mut e = event(
            "configuration-changed",
            hex::encode(Sha256::digest(cert)).as_bytes(),
        );
        e["event"] = json!("New TLS Certificate");
        let (response, mr) = fixture(&[e]);
        assert!(replay_evidence(&response, &mr, cert).is_err());
    }
    /// A valid event log from another report cannot authorize this quote's drift.
    #[test]
    fn replay_not_anchored_to_quote_failure() {
        let cert = b"cert";
        let (response, _) = fixture(&[event(
            "New TLS Certificate",
            hex::encode(Sha256::digest(cert)).as_bytes(),
        )]);
        assert_eq!(
            replay_evidence(&response, &"a".repeat(96), cert)
                .unwrap_err()
                .code,
            ATTESTATION_RTMR_MISMATCH
        );
    }
    /// Even valid quote-anchored metadata must name the verified session's certificate.
    #[test]
    fn other_tls_session_certificate_failure() {
        let (response, mr) = fixture(&[event(
            "New TLS Certificate",
            hex::encode(Sha256::digest(b"other cert")).as_bytes(),
        )]);
        assert!(replay_evidence(&response, &mr, b"current cert").is_err());
    }

    /// Correctly measured metadata still needs the exact certificate payload format.
    #[test]
    fn measured_malformed_certificate_failure() {
        let (response, mr) = fixture(&[event("New TLS Certificate", b"arbitrary configuration")]);
        assert!(replay_evidence(&response, &mr, b"cert").is_err());
    }

    /// A known name under an unknown extension type cannot receive the exception.
    #[test]
    fn unknown_event_type_is_not_certificate_success() {
        let cert = b"cert";
        let payload = hex::encode(Sha256::digest(cert));
        let mut unknown = event("New TLS Certificate", payload.as_bytes());
        unknown["event_type"] = json!(7u32);
        let mut digest = Sha384::new();
        digest.update(7u32.to_le_bytes());
        digest.update(b":New TLS Certificate:");
        digest.update(payload.as_bytes());
        unknown["digest"] = json!(hex::encode(digest.finalize()));
        let (response, mr) = fixture(&[unknown, event("New TLS Certificate", payload.as_bytes())]);
        let history = replay_evidence(&response, &mr, cert).unwrap();
        assert!(!history[0].tls_certificate_event);
    }

    /// Capture every original byte once, even when reads arrive in fragments.
    #[tokio::test]
    async fn recording_original_fragmented_response_success() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut sender, receiver) = tokio::io::duplex(4);
        let writer = tokio::spawn(async move {
            sender.write_all(b"exact quote response").await.unwrap();
        });
        let mut recording = RecordingStream::new(receiver);
        let mut read = Vec::new();
        recording.read_to_end(&mut read).await.unwrap();
        writer.await.unwrap();
        assert_eq!(recording.response(), read);
    }

    /// Bound untrusted evidence before the verifier can buffer an unlimited body.
    #[tokio::test]
    async fn oversized_recorded_response_failure() {
        use tokio::io::AsyncReadExt;
        let bytes = vec![b'x'; MAX_RESPONSE_BYTES + 1];
        let mut recording = RecordingStream::new(bytes.as_slice());
        let mut read = Vec::new();
        assert_eq!(
            recording.read_to_end(&mut read).await.unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
