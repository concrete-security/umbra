//! concrete-atlas-verify — out-of-process attestation verifier invoked by the Console
//! via `ATLAS_VERIFIER_CMD` (see console/src/concrete_console/attestation.py).
//!
//! Contract (must match AtlasVerifierClient):
//!   stdin : {"kind":"dev_cvm"|"security_cvm","fqdn":"<host>","policy":{...}}
//!   exit 0: {"image_measurement":"<hex>","rtmr3_digest":"<hex>"}
//!   exit 1: {"error":{"code":"<ATTESTATION_*>","details":{...}}}
//!
//! It connects to <fqdn>:443, runs aTLS via atlas-rs (which POSTs /tdx_quote, binds the
//! quote to the TLS session via EKM, and verifies the policy), then returns mr_td and
//! rt_mr3 read straight from the TD report inside the quote. `policy.rtmr3_binding` is
//! passed by the Console but not consumed here: the Console persists rtmr3_digest and
//! does drift detection on it. atlas is consumed as a published dependency, never patched.
use atlas_rs::{atls_connect, AtlsVerificationError, Policy, Report};
use rustls::crypto::aws_lc_rs::default_provider;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::{self, Read};
use std::process::ExitCode;
use tokio::net::TcpStream;

const ATTESTATION_FETCH_FAILED: &str = "ATTESTATION_FETCH_FAILED";
const ATTESTATION_QUOTE_INVALID: &str = "ATTESTATION_QUOTE_INVALID";
const ATTESTATION_IMAGE_MISMATCH: &str = "ATTESTATION_IMAGE_MISMATCH";
const ATTESTATION_RTMR_MISMATCH: &str = "ATTESTATION_RTMR_MISMATCH";
const ATTESTATION_SESSION_BINDING_INVALID: &str = "ATTESTATION_SESSION_BINDING_INVALID";

#[derive(Debug, Deserialize)]
struct VerifyRequest {
    kind: String,
    fqdn: String,
    policy: Value,
}

/// stdout is the machine-readable channel: the Console parses it as the single JSON result
/// (success report or error). To keep that contract true *by construction* — not by the
/// convention "no logger is installed, so the `log` facade is silent" — we claim the global
/// logger at startup and send every record to stderr. rustls (built with the `logging`
/// feature) and atlas-rs emit through this facade; routing it to stderr guarantees no
/// dependency log line can ever interleave with, and corrupt, the JSON payload on stdout.
struct StderrLogger;

impl log::Log for StderrLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        eprintln!("[atlas-verify] {} {}", record.level(), record.args());
    }

    fn flush(&self) {}
}

static STDERR_LOGGER: StderrLogger = StderrLogger;

#[tokio::main]
async fn main() -> ExitCode {
    // Reserve stdout for the JSON payload before any dependency can log (see StderrLogger).
    let _ = log::set_logger(&STDERR_LOGGER);
    log::set_max_level(log::LevelFilter::Info);
    let _ = default_provider().install_default();

    match run().await {
        Ok(output) => {
            println!("{output}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            println!("{}", error.to_json());
            ExitCode::from(1)
        }
    }
}

async fn run() -> Result<String, CliError> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).map_err(|exc| {
        CliError::new(ATTESTATION_FETCH_FAILED, "stdin_read_failed").message(exc.to_string())
    })?;
    let request: VerifyRequest = serde_json::from_str(&input).map_err(|exc| {
        CliError::new(ATTESTATION_QUOTE_INVALID, "request_json_invalid").message(exc.to_string())
    })?;

    if request.kind != "dev_cvm" && request.kind != "security_cvm" {
        return Err(
            CliError::new(ATTESTATION_QUOTE_INVALID, "kind_invalid").detail("kind", request.kind),
        );
    }
    let fqdn = request.fqdn.trim();
    if fqdn.is_empty() {
        return Err(CliError::new(ATTESTATION_QUOTE_INVALID, "fqdn_missing"));
    }

    let expected_image_measurement = expected_image_measurement(&request.policy)?;
    let policy = policy_from_request(&request.policy)?;

    let tcp = TcpStream::connect((fqdn, 443)).await.map_err(|exc| {
        CliError::new(ATTESTATION_FETCH_FAILED, "tcp_connect_failed").message(exc.to_string())
    })?;
    let (_tls, report) = atls_connect(tcp, fqdn, policy, None)
        .await
        .map_err(CliError::from_atlas)?;

    let (image_measurement, rtmr3_digest) = tdx_measurements(&report)?;
    if let Some(expected) = expected_image_measurement {
        if image_measurement != expected {
            return Err(
                CliError::new(ATTESTATION_IMAGE_MISMATCH, "image_measurement_mismatch")
                    .detail("expected_image_measurement", expected)
                    .detail("reported_image_measurement", image_measurement),
            );
        }
    }

    Ok(json!({
        "image_measurement": image_measurement,
        "rtmr3_digest": rtmr3_digest,
    })
    .to_string())
}

fn expected_image_measurement(policy: &Value) -> Result<Option<String>, CliError> {
    let Some(value) = policy.get("expected_image_measurement") else {
        return Ok(None);
    };
    let Some(measurement) = value.as_str() else {
        return Err(CliError::new(
            ATTESTATION_QUOTE_INVALID,
            "expected_image_measurement_invalid",
        ));
    };
    let normalized = measurement.trim().to_ascii_lowercase();
    if !is_lower_hex(&normalized) {
        return Err(CliError::new(
            ATTESTATION_QUOTE_INVALID,
            "expected_image_measurement_invalid",
        ));
    }
    Ok(Some(normalized))
}

/// Build the atlas policy from the request. Per docs/specs/security-cvm.md §2.2 and
/// dev-cvm.md §8.1/§9, BOTH dev_cvm and security_cvm are verified with FULL runtime
/// verification: the request MUST carry the authoritative, complete app_compose plus
/// expected_bootchain and os_image_hash, so atlas runs compose-hash + bootchain +
/// os-image + RTMR replay against the quote. MRTD alone is the dstack-guest base
/// measurement shared by every CVM (SECURITY_CVM == DEV_CVM) and proves nothing
/// app-specific.
///
/// The verifier MUST fail closed — never relax to DstackTdxPolicy::dev() — if any of
/// those fields is missing. The floor is enforced HERE, not left to the request builder.
fn policy_from_request(policy: &Value) -> Result<Policy, CliError> {
    let mut missing: Vec<&'static str> = Vec::new();
    if policy.get("app_compose").is_none() {
        missing.push("app_compose");
    }
    if policy.get("expected_bootchain").is_none() {
        missing.push("expected_bootchain");
    }
    if policy.get("os_image_hash").is_none() {
        missing.push("os_image_hash");
    }
    if !missing.is_empty() {
        return Err(
            CliError::new(ATTESTATION_QUOTE_INVALID, "runtime_policy_incomplete").detail(
                "missing_fields",
                Value::Array(
                    missing
                        .into_iter()
                        .map(|f| Value::String(f.to_string()))
                        .collect(),
                ),
            ),
        );
    }

    // Full runtime policy. atlas-rs ignores the extra expected_image_measurement /
    // rtmr3_binding keys; expected_image_measurement is checked separately in run() and
    // rtmr3_digest is persisted by the Console for drift detection. Optional knobs
    // (allowed_tcb_status, pccs_url, cache_collateral) flow through here when present.
    //
    // KNOWN GAP — deferred to a follow-up PR (NOT in scope here): the per-CVM RTMR3 binding
    // is NOT cryptographically verified. atlas only replays RTMR0/1/2 against
    // expected_bootchain (../atlas core/src/dstack/verifier.rs); rt_mr3 is read from the
    // report but never checked against an expected value, so the `rtmr3_binding` sent in the
    // policy is informational only (the Console persists rtmr3_digest for TOFU drift
    // detection, but there is no point-in-time enforcement). The fix — atlas support for an
    // expected_rtmr3, or a Console-side comparison of the reported rt_mr3 against the
    // recomputed binding — is tracked separately and must NOT be assumed in place here.
    serde_json::from_value(policy.clone()).map_err(|exc| {
        CliError::new(ATTESTATION_QUOTE_INVALID, "policy_invalid").message(exc.to_string())
    })
}

fn tdx_measurements(report: &Report) -> Result<(String, String), CliError> {
    let verified = report
        .as_tdx()
        .ok_or_else(|| CliError::new(ATTESTATION_QUOTE_INVALID, "tdx_report_missing"))?;
    let td_report = verified
        .report
        .as_td10()
        .ok_or_else(|| CliError::new(ATTESTATION_QUOTE_INVALID, "td10_report_missing"))?;
    Ok((hex::encode(td_report.mr_td), hex::encode(td_report.rt_mr3)))
}

fn is_lower_hex(value: &str) -> bool {
    !value.is_empty()
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

#[derive(Debug)]
struct CliError {
    code: &'static str,
    details: serde_json::Map<String, Value>,
}

impl CliError {
    fn new(code: &'static str, reason: &'static str) -> Self {
        let mut details = serde_json::Map::new();
        details.insert("reason".to_string(), Value::String(reason.to_string()));
        Self { code, details }
    }

    fn detail(mut self, key: &'static str, value: impl Into<Value>) -> Self {
        self.details.insert(key.to_string(), value.into());
        self
    }

    fn message(mut self, message: String) -> Self {
        self.details
            .insert("message".to_string(), Value::String(message));
        self
    }

    fn to_json(&self) -> String {
        json!({
            "error": {
                "code": self.code,
                "details": self.details,
            },
        })
        .to_string()
    }

    fn from_atlas(error: AtlsVerificationError) -> Self {
        match error {
            AtlsVerificationError::Io(message) => {
                CliError::new(ATTESTATION_FETCH_FAILED, "io_error").message(message)
            }
            AtlsVerificationError::TlsHandshake(message) => {
                CliError::new(ATTESTATION_FETCH_FAILED, "tls_handshake_failed").message(message)
            }
            // Permanent failures — NOT retryable (mapping to a non-FETCH_FAILED code makes
            // verify_with_fetch_retries fail fast instead of burning the whole boot-window
            // budget). InvalidServerName is a structural name-parse failure before any I/O
            // (atlas-rs connect.rs:64). MissingCertificate is only reachable AFTER a
            // successful server-auth handshake that returned zero peer certs (connect.rs:71-75)
            // — unreachable for standard nginx HTTPS, where a not-yet-issued/invalid cert fails
            // the handshake as TlsHandshake instead. The genuinely transient boot states stay
            // retryable as Io / TlsHandshake above.
            AtlsVerificationError::InvalidServerName(message) => {
                CliError::new(ATTESTATION_QUOTE_INVALID, "invalid_server_name").message(message)
            }
            AtlsVerificationError::MissingCertificate => {
                CliError::new(ATTESTATION_QUOTE_INVALID, "missing_server_certificate")
            }
            AtlsVerificationError::Quote(message) => {
                CliError::new(ATTESTATION_QUOTE_INVALID, "quote_invalid").message(message)
            }
            AtlsVerificationError::BootchainMismatch {
                field,
                expected,
                actual,
            } => CliError::new(ATTESTATION_IMAGE_MISMATCH, "bootchain_mismatch")
                .detail("field", field)
                .detail("expected", expected)
                .detail("actual", actual),
            AtlsVerificationError::RtmrMismatch {
                index,
                expected,
                actual,
            } => CliError::new(ATTESTATION_RTMR_MISMATCH, "rtmr_mismatch")
                .detail("index", index)
                .detail("expected", expected)
                .detail("actual", actual),
            AtlsVerificationError::CertificateNotInEventLog => CliError::new(
                ATTESTATION_SESSION_BINDING_INVALID,
                "certificate_not_in_event_log",
            ),
            AtlsVerificationError::EventLogParse(message) => {
                CliError::new(ATTESTATION_QUOTE_INVALID, "event_log_parse_failed").message(message)
            }
            AtlsVerificationError::TeeTypeMismatch(message) => {
                CliError::new(ATTESTATION_QUOTE_INVALID, "tee_type_mismatch").message(message)
            }
            AtlsVerificationError::AppComposeHashMismatch { expected, actual } => {
                CliError::new(ATTESTATION_IMAGE_MISMATCH, "app_compose_hash_mismatch")
                    .detail("expected", expected)
                    .detail("actual", actual)
            }
            AtlsVerificationError::OsImageHashMismatch { expected, actual } => {
                CliError::new(ATTESTATION_IMAGE_MISMATCH, "os_image_hash_mismatch")
                    .detail("expected", expected)
                    .detail("actual", actual.unwrap_or_default())
            }
            AtlsVerificationError::TcbStatusNotAllowed { status, allowed } => {
                CliError::new(ATTESTATION_QUOTE_INVALID, "tcb_status_not_allowed")
                    .detail("status", status)
                    .detail(
                        "allowed",
                        Value::Array(allowed.into_iter().map(Value::String).collect()),
                    )
            }
            AtlsVerificationError::ReportDataMismatch { expected, actual } => {
                CliError::new(ATTESTATION_SESSION_BINDING_INVALID, "report_data_mismatch")
                    .detail("expected", expected)
                    .detail("actual", actual)
            }
            AtlsVerificationError::Configuration(message) => {
                CliError::new(ATTESTATION_QUOTE_INVALID, "policy_configuration_invalid")
                    .message(message)
            }
            AtlsVerificationError::Other(error) => {
                CliError::new(ATTESTATION_QUOTE_INVALID, "verifier_failed")
                    .message(error.to_string())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// docs/specs/security-cvm.md §2.2 / dev-cvm.md §8.1: the verifier MUST fail closed
    /// (never relax to dev()) when the runtime policy is incomplete. Each missing field
    /// is reported individually.
    #[test]
    fn rejects_incomplete_runtime_policy() {
        for missing in ["app_compose", "expected_bootchain", "os_image_hash"] {
            let mut policy = json!({
                "type": "dstack_tdx",
                "app_compose": {"docker_compose_file": "x"},
                "expected_bootchain": {"mrtd": "00"},
                "os_image_hash": "ab",
            });
            policy.as_object_mut().unwrap().remove(missing);

            let err = policy_from_request(&policy)
                .err()
                .unwrap_or_else(|| panic!("expected rejection when {missing} is missing"));
            assert_eq!(err.code, ATTESTATION_QUOTE_INVALID);
            assert_eq!(
                err.details.get("reason").and_then(Value::as_str),
                Some("runtime_policy_incomplete"),
            );
            let reported = err
                .details
                .get("missing_fields")
                .and_then(Value::as_array)
                .expect("missing_fields present");
            assert!(reported.iter().any(|v| v.as_str() == Some(missing)));
        }
    }

    /// The exact policy shape the Console emits (attestation.py `_dstack_tdx_request`):
    /// the runtime fields atlas verifies PLUS the extra keys it must ignore
    /// (`expected_image_measurement`, `rtmr3_binding`). This MUST deserialize Ok into the
    /// atlas `Policy` — guards against a future atlas-rs bump adding `deny_unknown_fields`,
    /// which would otherwise fail every attestation closed (silent platform-wide outage).
    #[test]
    fn full_console_policy_with_extra_keys_deserializes() {
        let policy = json!({
            "type": "dstack_tdx",
            "expected_image_measurement": "a".repeat(96),
            "app_compose": {
                "runner": "docker-compose",
                "docker_compose_file": "services: {}\n",
                "features": ["kms", "tproxy-net"],
            },
            "expected_bootchain": {
                "mrtd": "b".repeat(96),
                "rtmr0": "0".repeat(96),
                "rtmr1": "1".repeat(96),
                "rtmr2": "2".repeat(96),
            },
            "os_image_hash": "c".repeat(64),
            "rtmr3_binding": {
                "CONSOLE_URL": "https://console.example.com",
                "entity_id": "00000000-0000-4000-8000-000000000001",
                "sc_id": "00000000-0000-4000-8000-000000000041",
                "ingest_token_sha256": "d".repeat(64),
                "ca_export_token_sha256": "e".repeat(64),
            },
        });
        policy_from_request(&policy)
            .expect("the exact Console-emitted policy must deserialize into the atlas Policy");
    }
}
