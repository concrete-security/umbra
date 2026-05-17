use std::{
    thread,
    time::{Duration, Instant},
};

use reqwest::{
    blocking::{Client, Response},
    header::RETRY_AFTER,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
    cli::{SecurityCvmAttestationArgs, SecurityCvmCommand, SecurityCvmLaunchArgs},
    commands::{auth, operation_debug},
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

#[derive(Debug, Deserialize, Serialize)]
struct Operation {
    id: String,
    kind: String,
    status: String,
    actor_id: Option<String>,
    target: OperationTarget,
    result: Option<Value>,
    error: Option<OperationError>,
    progress: Option<OperationProgress>,
    created_at: String,
    updated_at: String,
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OperationTarget {
    #[serde(rename = "type")]
    kind: String,
    id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OperationError {
    code: String,
    message: String,
    details: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OperationProgress {
    step: String,
    percent: u8,
}

#[derive(Debug, Deserialize, Serialize)]
struct SecurityCvmProvisionResult {
    security_cvm: SecurityCvm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ingest_token: Option<String>,
    ca_export_token: String,
}

enum OperationPoll {
    Operation(Box<Operation>),
    RateLimited(Duration),
}

pub fn run(command: SecurityCvmCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        SecurityCvmCommand::Show => show(config, json),
        SecurityCvmCommand::Launch(args) => launch(config, args, json),
        SecurityCvmCommand::Terminate => terminate(config, json),
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

fn launch(config: &ResolvedConfig, args: SecurityCvmLaunchArgs, json_output: bool) -> ExitStatus {
    if let Err(message) = validate_launch_args(&args) {
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let operation = match submit_launch(console_url, &session, &args) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if args.no_wait {
        print_operation(&operation, json_output, false);
        return ExitStatus::Ok;
    }
    let operation = match wait_for_operation(
        console_url,
        &session.access_token,
        operation,
        Duration::from_secs(u64::from(args.wait_timeout_seconds)),
        json_output,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let result = match security_cvm_launch_result(&operation) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Error;
        }
    };
    print_launch_result(&result, json_output);
    ExitStatus::Ok
}

fn terminate(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let security_cvm = match submit_terminate(console_url, &session) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    print_terminate_result(&security_cvm, json_output);
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

fn submit_launch(
    console_url: &str,
    session: &Session,
    args: &SecurityCvmLaunchArgs,
) -> Result<Operation, (ExitStatus, String)> {
    let mut body = Map::new();
    if let Some(value) = &args.instance_type {
        body.insert("instance_type".to_string(), Value::String(value.clone()));
    }
    if let Some(value) = &args.region {
        body.insert("region".to_string(), Value::String(value.clone()));
    }
    let response = Client::new()
        .post(format!(
            "{console_url}/api/v1/entities/{}/security-cvm",
            session.entity.id
        ))
        .bearer_auth(&session.access_token)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(&Value::Object(body))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to submit Security CVM launch: {err}"),
            )
        })?;
    read_json_response(response, "submit Security CVM launch")
}

fn submit_terminate(
    console_url: &str,
    session: &Session,
) -> Result<SecurityCvm, (ExitStatus, String)> {
    let response = Client::new()
        .delete(format!(
            "{console_url}/api/v1/entities/{}/security-cvm",
            session.entity.id
        ))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to terminate Security CVM: {err}"),
            )
        })?;
    read_json_response(response, "terminate Security CVM")
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

fn fetch_operation(
    console_url: &str,
    access_token: &str,
    operation_id: &str,
) -> Result<OperationPoll, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/operations/{operation_id}"))
        .bearer_auth(access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to poll operation: {err}"),
            )
        })?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Ok(OperationPoll::RateLimited(retry_after(&response)));
    }
    read_json_response(response, "poll operation")
        .map(|operation| OperationPoll::Operation(Box::new(operation)))
}

fn wait_for_operation(
    console_url: &str,
    access_token: &str,
    mut operation: Operation,
    timeout: Duration,
    json_output: bool,
) -> Result<Operation, (ExitStatus, String)> {
    let started = Instant::now();
    let mut excluded = Duration::ZERO;
    loop {
        match operation.status.as_str() {
            "succeeded" => return Ok(operation),
            "failed" => return Err((ExitStatus::Error, operation_failure_message(&operation))),
            "cancelled" => {
                return Err((
                    ExitStatus::Error,
                    "[cancelled] operation was cancelled".to_string(),
                ));
            }
            "pending" | "running" => {}
            status => {
                return Err((
                    ExitStatus::Error,
                    format!("[error] operation returned unknown status: {status}"),
                ));
            }
        }
        if Instant::now()
            .duration_since(started)
            .saturating_sub(excluded)
            >= timeout
        {
            print_operation(&operation, json_output, true);
            return Err((
                ExitStatus::WaitTimeout,
                "[wait_timeout] operation did not complete before timeout".to_string(),
            ));
        }
        thread::sleep(Duration::from_secs(1));
        match fetch_operation(console_url, access_token, &operation.id)? {
            OperationPoll::Operation(next) => operation = *next,
            OperationPoll::RateLimited(delay) => {
                thread::sleep(delay);
                excluded += delay;
            }
        }
    }
}

fn read_json_response<T: for<'de> Deserialize<'de>>(
    response: Response,
    action: &str,
) -> Result<T, (ExitStatus, String)> {
    if !response.status().is_success() {
        return Err(error_for_response(response, action));
    }
    let body = response.bytes().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to read {action} response: {err}"),
        )
    })?;
    serde_json::from_slice::<T>(&body).map_err(|err| {
        operation_debug::log_poll_decode_failure(action, &body, &err);
        (
            ExitStatus::Error,
            format!("[error] malformed {action} response: {err}"),
        )
    })
}

fn retry_after(response: &Response) -> Duration {
    response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| Duration::from_secs(seconds.max(1)))
        .unwrap_or_else(|| Duration::from_secs(1))
}

fn operation_failure_message(operation: &Operation) -> String {
    if let Some(error) = &operation.error {
        format!("[{}] {}", error.code, error.message)
    } else {
        "[error] operation failed".to_string()
    }
}

fn security_cvm_launch_result(operation: &Operation) -> Result<SecurityCvmProvisionResult, String> {
    let result = operation.result.clone().ok_or_else(|| {
        "[error] Security CVM launch operation succeeded without result".to_string()
    })?;
    serde_json::from_value::<SecurityCvmProvisionResult>(result)
        .map_err(|err| format!("[error] malformed Security CVM launch result: {err}"))
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
    let dev_cvm_count = details
        .and_then(|details| details.get("dev_cvm_count"))
        .and_then(|value| value.as_u64());
    Some(match (state, component, dev_cvm_count, code) {
        (Some("dev_cvms_in_entity"), _, Some(count), _) => {
            format!("{message} (dev_cvms_in_entity; dev_cvm_count={count})")
        }
        (Some(state), _, _, _) => format!("{message} ({state})"),
        (_, Some(component), _, _) => format!("{message} ({component})"),
        (_, _, _, Some(code)) if code != "UNAUTHORIZED" && code != "VALIDATION_ERROR" => {
            format!("{message} ({code})")
        }
        _ => message.to_string(),
    })
}

fn validate_launch_args(args: &SecurityCvmLaunchArgs) -> Result<(), String> {
    if let Some(value) = args.instance_type.as_deref() {
        validate_security_cvm_config_value("--instance-type", value, 100)?;
    }
    if let Some(value) = args.region.as_deref() {
        validate_security_cvm_config_value("--region", value, 64)?;
    }
    Ok(())
}

fn validate_security_cvm_config_value(
    name: &str,
    value: &str,
    max_len: usize,
) -> Result<(), String> {
    if value.is_empty() || value.len() > max_len {
        return Err(format!("[usage] {name} must be 1..{max_len} characters"));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(format!(
            "[usage] {name} may contain only letters, digits, '.', '_', and '-'"
        ));
    }
    Ok(())
}

fn print_security_cvm(security_cvm: &SecurityCvm, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(security_cvm).expect("Security CVM output serializes")
        );
    } else {
        println!("{}", security_cvm_summary(security_cvm));
    }
}

fn print_operation(operation: &Operation, json_output: bool, stderr: bool) {
    let text = if json_output {
        serde_json::to_string_pretty(operation).expect("operation output serializes")
    } else {
        format!(
            "operation {} kind={} status={} target={}/{}",
            operation.id,
            operation.kind,
            operation.status,
            operation.target.kind,
            operation.target.id.as_deref().unwrap_or("-")
        )
    };
    if stderr {
        eprintln!("{text}");
    } else {
        println!("{text}");
    }
}

fn print_launch_result(result: &SecurityCvmProvisionResult, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(result).expect("Security CVM launch output serializes")
        );
    } else {
        if let Some(ingest_token) = &result.ingest_token {
            println!("ingest_token={ingest_token}");
        }
        println!("ca_export_token={}", result.ca_export_token);
        println!("{}", security_cvm_summary(&result.security_cvm));
    }
}

fn print_terminate_result(security_cvm: &SecurityCvm, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(security_cvm).expect("Security CVM output serializes")
        );
    } else {
        println!("terminated {}", security_cvm_summary(security_cvm));
    }
}

fn security_cvm_summary(security_cvm: &SecurityCvm) -> String {
    format!(
        "security_cvm {} state={} fqdn={} region={} instance_type={} policy_version={} attestation_verified_at={} error_reason={}",
        security_cvm.id,
        security_cvm.state,
        security_cvm.fqdn,
        security_cvm.region.as_deref().unwrap_or("-"),
        security_cvm.instance_type.as_deref().unwrap_or("-"),
        security_cvm.policy_version,
        security_cvm.attestation_verified_at.as_deref().unwrap_or("-"),
        security_cvm.error_reason.as_deref().unwrap_or("-"),
    )
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

    #[test]
    fn console_error_message_includes_dev_cvm_count() {
        let body = r#"{"error":{"code":"CONFLICT","message":"cannot decommission Security CVM while Dev CVMs exist","details":{"state":"dev_cvms_in_entity","dev_cvm_count":2}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some(
                "cannot decommission Security CVM while Dev CVMs exist (dev_cvms_in_entity; dev_cvm_count=2)"
            )
        );
    }

    #[test]
    fn validate_security_cvm_config_value_rejects_slash() {
        assert_eq!(
            validate_security_cvm_config_value("--instance-type", "tdx/small", 100)
                .expect_err("slash rejected"),
            "[usage] --instance-type may contain only letters, digits, '.', '_', and '-'"
        );
    }
}
