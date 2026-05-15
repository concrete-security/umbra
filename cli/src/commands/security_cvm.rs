use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    cli::{SecurityCvmAttestationArgs, SecurityCvmCommand},
    commands::auth,
    config::ResolvedConfig,
    exit::ExitStatus,
    session::Session,
};

#[derive(Debug, Deserialize, Serialize)]
struct SecurityCvm {
    id: String,
    entity_id: String,
    state: String,
    fqdn: String,
    instance_type: Option<String>,
    region: Option<String>,
    error_reason: Option<String>,
    policy_version: u64,
    expected_image_measurement: Option<String>,
    image_measurement: Option<String>,
    rtmr3_digest: Option<String>,
    attestation_verified_at: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SecurityCvmAttestation {
    security_cvm_id: String,
    fqdn: String,
    expected_image_measurement: Option<String>,
    verdict: AttestationVerdict,
}

#[derive(Debug, Deserialize, Serialize)]
struct AttestationVerdict {
    verified: bool,
    failure_reason: Option<String>,
    image_measurement_seen: Option<String>,
    rtmr3_digest_seen: Option<String>,
    verified_at: Option<String>,
}

pub fn run(command: SecurityCvmCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        SecurityCvmCommand::Show => show(config, json),
        SecurityCvmCommand::Attestation(args) => attestation(config, args, json),
    }
}

fn show(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let security_cvm = match fetch_security_cvm(console_url, &session) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    print_security_cvm(&security_cvm, json_output);
    ExitStatus::Ok
}

fn attestation(
    config: &ResolvedConfig,
    args: SecurityCvmAttestationArgs,
    json_output: bool,
) -> ExitStatus {
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let attestation = match fetch_attestation(console_url, &session, args.probe) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    print_attestation(&attestation, json_output);
    ExitStatus::Ok
}

fn console_session(config: &ResolvedConfig) -> Result<(&str, Session), (ExitStatus, String)> {
    let console_url = config
        .require_console_url()
        .map_err(|message| (ExitStatus::Usage, message))?;
    let session = auth::session_for_console(config)?;
    Ok((console_url, session))
}

fn fetch_security_cvm(
    console_url: &str,
    session: &Session,
) -> Result<SecurityCvm, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!(
            "{console_url}/api/v1/entities/{}/security-cvm",
            session.entity.id
        ))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch Security CVM: {err}"),
            )
        })?;
    read_json_response(response, "fetch Security CVM")
}

fn fetch_attestation(
    console_url: &str,
    session: &Session,
    probe: bool,
) -> Result<SecurityCvmAttestation, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!(
            "{console_url}/api/v1/entities/{}/security-cvm/attestation",
            session.entity.id
        ))
        .bearer_auth(&session.access_token)
        .query(&[("probe", probe)])
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch Security CVM attestation: {err}"),
            )
        })?;
    read_json_response(response, "fetch Security CVM attestation")
}

fn read_json_response<T: for<'de> Deserialize<'de>>(
    response: Response,
    action: &str,
) -> Result<T, (ExitStatus, String)> {
    if !response.status().is_success() {
        return Err(error_for_response(response, action));
    }
    response.json::<T>().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] malformed {action} response: {err}"),
        )
    })
}

fn error_for_response(response: Response, action: &str) -> (ExitStatus, String) {
    let status = response.status();
    let exit = if status == reqwest::StatusCode::UNAUTHORIZED {
        ExitStatus::AuthRequired
    } else if status == reqwest::StatusCode::BAD_REQUEST
        || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY
    {
        ExitStatus::Usage
    } else {
        ExitStatus::Error
    };
    let text = response.text().unwrap_or_default();
    let message = if status == reqwest::StatusCode::NOT_FOUND {
        "no Security CVM for this entity".to_string()
    } else {
        console_error_message(&text).unwrap_or_else(|| format!("{action} failed: HTTP {status}"))
    };
    let tag = if matches!(exit, ExitStatus::AuthRequired) {
        "auth_required"
    } else if matches!(exit, ExitStatus::Usage) {
        "usage"
    } else {
        "error"
    };
    (exit, format!("[{tag}] {message}"))
}

fn console_error_message(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    let error = value.get("error")?;
    let message = error.get("message")?.as_str()?;
    let code = error.get("code").and_then(|value| value.as_str());
    let details = error.get("details");
    let state = details
        .and_then(|details| details.get("state"))
        .and_then(|value| value.as_str());
    let component = details
        .and_then(|details| details.get("component"))
        .and_then(|value| value.as_str());
    Some(match (state, component, code) {
        (Some(state), _, _) => format!("{message} ({state})"),
        (_, Some(component), _) => format!("{message} ({component})"),
        (_, _, Some(code)) if code != "UNAUTHORIZED" && code != "VALIDATION_ERROR" => {
            format!("{message} ({code})")
        }
        _ => message.to_string(),
    })
}

fn print_security_cvm(security_cvm: &SecurityCvm, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(security_cvm).expect("Security CVM output serializes")
        );
    } else {
        println!(
            "security_cvm {} state={} fqdn={} region={} instance_type={} policy_version={} attestation_verified_at={} error_reason={}",
            security_cvm.id,
            security_cvm.state,
            security_cvm.fqdn,
            security_cvm.region.as_deref().unwrap_or("-"),
            security_cvm.instance_type.as_deref().unwrap_or("-"),
            security_cvm.policy_version,
            security_cvm.attestation_verified_at.as_deref().unwrap_or("-"),
            security_cvm.error_reason.as_deref().unwrap_or("-"),
        );
    }
}

fn print_attestation(attestation: &SecurityCvmAttestation, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(attestation)
                .expect("Security CVM attestation output serializes")
        );
    } else {
        println!(
            "security_cvm={} fqdn={} verified={} failure_reason={} expected_image_measurement={} image_measurement_seen={} rtmr3_digest_seen={} verified_at={}",
            attestation.security_cvm_id,
            attestation.fqdn,
            attestation.verdict.verified,
            attestation.verdict.failure_reason.as_deref().unwrap_or("-"),
            attestation.expected_image_measurement.as_deref().unwrap_or("-"),
            attestation.verdict.image_measurement_seen.as_deref().unwrap_or("-"),
            attestation.verdict.rtmr3_digest_seen.as_deref().unwrap_or("-"),
            attestation.verdict.verified_at.as_deref().unwrap_or("-"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_error_message_includes_attestation_drift_state() {
        let body = r#"{"error":{"code":"CONFLICT","message":"attestation drift detected","details":{"state":"attestation_drift"}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("attestation drift detected (attestation_drift)")
        );
    }

    #[test]
    fn console_error_message_includes_probe_component() {
        let body = r#"{"error":{"code":"SERVICE_UNAVAILABLE","message":"security CVM attestation probe is not implemented","details":{"component":"security_cvm_attestation_probe"}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some(
                "security CVM attestation probe is not implemented (security_cvm_attestation_probe)"
            )
        );
    }
}
