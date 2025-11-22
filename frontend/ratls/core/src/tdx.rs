use crate::{platform::SystemTime, AttestationResult, Policy, RatlsError, TeeType};
use dcap_qvl::quote::{Quote, Report, TDReport10, TDReport15};
use dcap_qvl::QuoteCollateralV3;
use hex::{decode, encode};
use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256, Sha384};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TdxTcbPolicy {
    #[serde(
        default,
        serialize_with = "serialize_hex_opt",
        deserialize_with = "deserialize_hex_opt"
    )]
    pub mrseam: Option<Vec<u8>>,
    #[serde(
        default,
        serialize_with = "serialize_hex_opt",
        deserialize_with = "deserialize_hex_opt"
    )]
    pub mrtmrs: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TcgEvent {
    #[serde(default, alias = "type", alias = "event")]
    pub message: Option<String>,
    #[serde(default, alias = "event_payload")]
    pub details: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub imr: Option<u32>,
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

pub fn verify_quote_freshness(quote: &[u8], report_data_expected: &[u8]) -> Result<(), RatlsError> {
    let parsed = parse_quote_report(quote)?;
    let report = TdReportRef::from_report(&parsed.report)?;
    let report_data = report.report_data();
    if report_data_expected.len() > report_data.len() {
        return Err(RatlsError::Policy(
            "nonce is larger than report data field".into(),
        ));
    }
    if report_data[..report_data_expected.len()] != report_data_expected[..] {
        let expected = hex::encode(&report_data_expected[..report_data_expected.len().min(16)]);
        let actual = hex::encode(&report_data[..report_data_expected.len().min(16)]);
        return Err(RatlsError::Policy(format!(
            "report data mismatch (nonce binding): expected prefix {expected}, quote prefix {actual}"
        )));
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
    let mut last_event = None;
    let mut processed = 0usize;

    for event in events {
        if event.imr.unwrap_or(0) != 3 {
            continue;
        }

        let mut digest = event.digest_bytes()?;
        if digest.len() < accumulator.len() {
            digest.resize(accumulator.len(), 0);
        }
        if digest.len() != accumulator.len() {
            let label = event.message.as_deref().unwrap_or("unknown");
            return Err(RatlsError::Vendor(format!(
                "event '{label}' digest has invalid length {}",
                digest.len()
            )));
        }

        let mut hasher = Sha384::new();
        hasher.update(&accumulator);
        hasher.update(&digest);
        let hashed = hasher.finalize();
        accumulator.copy_from_slice(&hashed);
        processed += 1;
        last_event = Some((
            event.message.clone().unwrap_or_else(|| "unknown".into()),
            hex::encode(&digest),
        ));
    }

    if accumulator != report.as_td10().rt_mr3 {
        let expected = hex::encode(report.as_td10().rt_mr3);
        let actual = hex::encode(accumulator);
        let (last_msg, last_digest) = last_event.unwrap_or_else(|| ("none".into(), "n/a".into()));
        return Err(RatlsError::Policy(format!(
            "event log replay does not match RTMR3 (expected {expected}, computed {actual}, events_processed {processed}, last_event '{last_msg}' digest {last_digest})"
        )));
    }

    Ok(())
}

pub fn verify_tls_certificate_in_log(
    events: &[TcgEvent],
    cert_data: &[u8],
) -> Result<(), RatlsError> {
    let mut hasher = Sha256::new();
    hasher.update(cert_data);
    let cert_hash = encode(hasher.finalize());

    for event in events {
        if event
            .message
            .as_deref()
            .map(|msg| msg.eq_ignore_ascii_case("New TLS Certificate"))
            .unwrap_or(false)
        {
            if let Some(payload) = event.payload_as_string() {
                if payload == cert_hash {
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
            RatlsError::Vendor(match self.message.as_deref() {
                Some(msg) => format!("event '{msg}' is missing digest data"),
                None => "event log entry is missing digest data".into(),
            })
        })?;
        decode_hex_field(digest).map_err(|e| {
            RatlsError::Vendor(match self.message.as_deref() {
                Some(msg) => format!("invalid digest for event '{msg}': {e}"),
                None => format!("invalid digest for unnamed event: {e}"),
            })
        })
    }

    fn payload_as_string(&self) -> Option<String> {
        let raw = self.details.as_deref()?;
        let bytes = decode_hex_field(raw).ok()?;
        String::from_utf8(bytes).ok()
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

fn serialize_hex_opt<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match value {
        Some(bytes) => serializer.serialize_some(&encode(bytes)),
        None => serializer.serialize_none(),
    }
}

fn deserialize_hex_opt<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    opt.map(|s| {
        let normalized = normalize_hex(&s);
        decode(&normalized).map_err(DeError::custom)
    })
    .transpose()
}
