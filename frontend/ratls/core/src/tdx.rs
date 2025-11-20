use crate::{platform::SystemTime, AttestationResult, Policy, RatlsError, TeeType};
use dcap_qvl::quote::{Quote, Report, TDReport10, TDReport15};
use dcap_qvl::QuoteCollateralV3;
use hex::{decode, encode};
use serde::Deserialize;
use sha2::{Digest, Sha256, Sha384};

#[derive(Debug, Clone, Default)]
pub struct TdxTcbPolicy {
    pub mrseam: Option<Vec<u8>>,
    pub mrtmrs: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcgEvent {
    pub message: String,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
}

pub async fn verify_attestation(
    quote: &[u8],
    collateral: &QuoteCollateralV3,
    policy: &Policy,
) -> Result<AttestationResult, RatlsError> {
    if policy.tee_type != TeeType::Tdx {
        return Err(RatlsError::TeeUnsupported(
            "only TDX attestation supported".into(),
        ));
    }

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| RatlsError::Policy(e.to_string()))?
        .as_secs();
    let verified = dcap_qvl::verify::verify(quote, collateral, now)
        .map_err(|e| RatlsError::Vendor(format!("tdx verify failed: {e}")))?;
    let status = verified.status.clone();
    if !policy
        .allowed_tdx_status
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&status))
    {
        return Err(RatlsError::Policy(format!(
            "tdx status {status} not allowed"
        )));
    }

    let report = TdReportRef::from_report(&verified.report)?;

    if let Some(tcb_policy) = &policy.min_tdx_tcb {
        enforce_tcb_policy(report.as_td10(), tcb_policy)?;
    }

    let measurement = encode(report.as_td10().mr_td);

    Ok(AttestationResult {
        trusted: true,
        tee_type: TeeType::Tdx,
        measurement: Some(measurement),
        tcb_status: status,
        advisory_ids: verified.advisory_ids,
    })
}

pub fn verify_quote_freshness(quote: &[u8], nonce: &[u8]) -> Result<(), RatlsError> {
    let parsed = parse_quote_report(quote)?;
    let report = TdReportRef::from_report(&parsed.report)?;
    let report_data = report.report_data();
    if nonce.len() > report_data.len() {
        return Err(RatlsError::Policy(
            "nonce is larger than report data field".into(),
        ));
    }
    if report_data[..nonce.len()] != nonce[..] {
        return Err(RatlsError::Policy(
            "report data mismatch (nonce binding)".into(),
        ));
    }
    Ok(())
}

pub fn verify_event_log_integrity(quote: &[u8], events: &[TcgEvent]) -> Result<(), RatlsError> {
    if events.is_empty() {
        return Err(RatlsError::Policy(
            "event log missing from attestation response".into(),
        ));
    }

    let parsed = parse_quote_report(quote)?;
    let report = TdReportRef::from_report(&parsed.report)?;
    let mut accumulator = [0u8; 48];

    for event in events {
        let digest = event.digest_bytes()?;
        if digest.len() != accumulator.len() {
            return Err(RatlsError::Vendor(format!(
                "event '{}' digest has invalid length {}",
                event.message,
                digest.len()
            )));
        }

        let mut hasher = Sha384::new();
        hasher.update(&accumulator);
        hasher.update(&digest);
        let hashed = hasher.finalize();
        accumulator.copy_from_slice(&hashed);
    }

    if accumulator != report.as_td10().rt_mr3 {
        return Err(RatlsError::Policy(
            "event log replay does not match RTMR3".into(),
        ));
    }

    Ok(())
}

pub fn verify_tls_certificate_in_log(events: &[TcgEvent], spki: &[u8]) -> Result<(), RatlsError> {
    let mut hasher = Sha256::new();
    hasher.update(spki);
    let cert_hash = encode(hasher.finalize());

    for event in events {
        if event.message.eq_ignore_ascii_case("New TLS Certificate") {
            if let Some(details) = event.normalized_details() {
                if details == cert_hash {
                    return Ok(());
                }
            }
        }
    }

    Err(RatlsError::Policy(
        "TLS public key hash missing from event log".into(),
    ))
}

impl TcgEvent {
    fn digest_bytes(&self) -> Result<Vec<u8>, RatlsError> {
        let digest = self.digest.as_deref().ok_or_else(|| {
            RatlsError::Vendor(format!("event '{}' is missing digest data", self.message))
        })?;
        decode_hex_field(digest).map_err(|e| {
            RatlsError::Vendor(format!("invalid digest for event '{}': {e}", self.message))
        })
    }

    fn normalized_details(&self) -> Option<String> {
        self.details.as_deref().map(normalize_hex)
    }
}

fn enforce_tcb_policy(report: &TDReport10, policy: &TdxTcbPolicy) -> Result<(), RatlsError> {
    if let Some(expected) = &policy.mrseam {
        if report.mr_seam[..expected.len()] != expected[..] {
            return Err(RatlsError::Policy("mr_seam mismatch".into()));
        }
    }
    if let Some(expected) = &policy.mrtmrs {
        if report.rt_mr0[..expected.len()] != expected[..] {
            return Err(RatlsError::Policy("rt_mr0 mismatch".into()));
        }
    }
    Ok(())
}

enum TdReportRef<'a> {
    Td10(&'a TDReport10),
    Td15(&'a TDReport15),
}

impl<'a> TdReportRef<'a> {
    fn from_report(report: &'a Report) -> Result<Self, RatlsError> {
        match report {
            Report::TD10(r) => Ok(TdReportRef::Td10(r)),
            Report::TD15(r) => Ok(TdReportRef::Td15(r)),
            other => Err(RatlsError::TeeUnsupported(format!(
                "unsupported report type: {other:?}"
            ))),
        }
    }

    fn as_td10(&self) -> &TDReport10 {
        match self {
            TdReportRef::Td10(r) => r,
            TdReportRef::Td15(r) => &r.base,
        }
    }

    fn report_data(&self) -> &[u8; 64] {
        match self {
            TdReportRef::Td10(r) => &r.report_data,
            TdReportRef::Td15(r) => &r.base.report_data,
        }
    }
}

fn parse_quote_report(quote: &[u8]) -> Result<Quote, RatlsError> {
    Quote::parse(quote).map_err(|e| RatlsError::Vendor(format!("failed to parse quote: {e}")))
}

fn decode_hex_field(value: &str) -> Result<Vec<u8>, String> {
    let normalized = normalize_hex(value);
    decode(&normalized).map_err(|e| format!("invalid hex '{value}': {e}"))
}

fn normalize_hex(value: &str) -> String {
    let trimmed = value.trim();
    let trimmed = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let mut cleaned = String::with_capacity(trimmed.len());
    for ch in trimmed.chars() {
        if !ch.is_ascii_whitespace() {
            cleaned.push(ch);
        }
    }
    cleaned.make_ascii_lowercase();
    cleaned
}
