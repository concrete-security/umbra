use std::{collections::BTreeMap, time::Duration};

use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
    cli::{
        SecurityCvmAttestationArgs, SecurityCvmCommand, SecurityCvmLaunchArgs,
        SecurityCvmUpdateArgs,
    },
    config::ResolvedConfig,
    console::{self, console_session},
    exit::ExitStatus,
    operation::{self, Operation},
    session::Session,
    style,
};

const NO_SECURITY_CVM: &str = "[error] no Security CVM for this entity";

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

    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
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
struct SecurityCvmProvisionResult {
    security_cvm: SecurityCvm,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ingest_token: Option<String>,
    ca_export_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SecurityCvmUpdateResult {
    security_cvm: SecurityCvm,
    dev_cvms_requiring_update: Vec<String>,
}

pub fn run(command: SecurityCvmCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        SecurityCvmCommand::Show => show(config, json),
        SecurityCvmCommand::Launch(args) => launch(config, args, json),
        SecurityCvmCommand::Update(args) => update(config, args, json),
        SecurityCvmCommand::Terminate => terminate(config, json),
        SecurityCvmCommand::Attestation(args) => attestation(config, args, json),
    }
}

fn show(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let security_cvm = try_or_eprintln!(fetch_security_cvm(console_url, &session));
    print_security_cvm(&security_cvm, json_output);
    ExitStatus::Ok
}

fn launch(config: &ResolvedConfig, args: SecurityCvmLaunchArgs, json_output: bool) -> ExitStatus {
    if let Err(message) = validate_launch_args(&args) {
        crate::style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let op = try_or_eprintln!(submit_launch(console_url, &session, &args));
    if args.no_wait {
        operation::print_operation(&op, json_output, false);
        return ExitStatus::Ok;
    }
    let op = try_or_eprintln!(operation::wait_for_operation(
        console_url,
        &session.access_token,
        op,
        Duration::from_secs(u64::from(args.wait_timeout_seconds)),
        json_output,
        true,
    ));
    let result: SecurityCvmProvisionResult =
        match operation::extract_operation_result(&op, "Security CVM launch") {
            Ok(value) => value,
            Err(message) => {
                crate::style::eprintln_error(&message);
                return ExitStatus::Error;
            }
        };
    print_launch_result(&result, json_output);
    ExitStatus::Ok
}

fn update(config: &ResolvedConfig, args: SecurityCvmUpdateArgs, json_output: bool) -> ExitStatus {
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let op = try_or_eprintln!(submit_update(console_url, &session));
    if args.no_wait {
        operation::print_operation(&op, json_output, false);
        return ExitStatus::Ok;
    }
    let op = try_or_eprintln!(operation::wait_for_operation(
        console_url,
        &session.access_token,
        op,
        Duration::from_secs(u64::from(args.wait_timeout_seconds)),
        json_output,
        true,
    ));
    let result: SecurityCvmUpdateResult =
        match operation::extract_operation_result(&op, "Security CVM update") {
            Ok(value) => value,
            Err(message) => {
                crate::style::eprintln_error(&message);
                return ExitStatus::Error;
            }
        };
    print_update_result(&result, json_output);
    ExitStatus::Ok
}

fn terminate(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let security_cvm = try_or_eprintln!(submit_terminate(console_url, &session));
    print_terminate_result(&security_cvm, json_output);
    ExitStatus::Ok
}

fn attestation(
    config: &ResolvedConfig,
    args: SecurityCvmAttestationArgs,
    json_output: bool,
) -> ExitStatus {
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let attestation = try_or_eprintln!(fetch_attestation(console_url, &session, args.probe));
    print_attestation(&attestation, json_output);
    ExitStatus::Ok
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
    sc_read_json_response(response, "fetch Security CVM")
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
    sc_read_json_response(response, "submit Security CVM launch")
}

fn submit_update(console_url: &str, session: &Session) -> Result<Operation, (ExitStatus, String)> {
    let response = Client::new()
        .post(format!(
            "{console_url}/api/v1/entities/{}/security-cvm/actions/update",
            session.entity.id
        ))
        .bearer_auth(&session.access_token)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to submit Security CVM update: {err}"),
            )
        })?;
    sc_read_json_response(response, "submit Security CVM update")
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
    sc_read_json_response(response, "terminate Security CVM")
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
    sc_read_json_response(response, "fetch Security CVM attestation")
}

/// Security-CVM-specific JSON reader that maps HTTP 404 to the canned
/// "no Security CVM for this entity" message before falling back to the
/// shared envelope-to-bracket mapper.
fn sc_read_json_response<T: for<'de> Deserialize<'de>>(
    response: Response,
    action: &str,
) -> Result<T, (ExitStatus, String)> {
    if !response.status().is_success() {
        return Err(console::error_for_response_with(
            response,
            action,
            Some(NO_SECURITY_CVM),
        ));
    }
    response.json::<T>().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] malformed {action} response: {err}"),
        )
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
        let view = style::SecurityCvmView {
            id: &security_cvm.id,
            state: &security_cvm.state,
            error_reason: security_cvm.error_reason.as_deref(),
            fqdn: &security_cvm.fqdn,
            instance_type: security_cvm.instance_type.as_deref(),
            region: security_cvm.region.as_deref(),
            policy_version: security_cvm.policy_version,
            attestation_verified_at: security_cvm.attestation_verified_at.as_deref(),
            created_at: &security_cvm.created_at,
            updated_at: &security_cvm.updated_at,
            extra: &security_cvm.extra,
        };
        println!("{}", style::security_cvm_card(&view));
    }
}

fn print_launch_result(result: &SecurityCvmProvisionResult, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(result).expect("Security CVM launch output serializes")
        );
    } else {
        let sc = &result.security_cvm;
        let mut confirm = style::ConfirmBlock::new("launched", "security cvm", sc.id.clone())
            .field("fqdn", sc.fqdn.clone())
            .field("state", sc.state.clone())
            .field(
                "ca export token",
                format!("{}  (save now -- not recoverable)", result.ca_export_token),
            )
            .next_step("concrete cvm launch --profile <profile-id> --ssh-key <key-id>");
        if let Some(token) = &result.ingest_token {
            confirm = confirm.field("ingest token", token.clone());
        }
        println!("{}", style::render_confirm(&confirm));
    }
}

fn print_update_result(result: &SecurityCvmUpdateResult, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(result).expect("Security CVM update output serializes")
        );
    } else {
        let sc = &result.security_cvm;
        let mut confirm = style::ConfirmBlock::new("updated", "security cvm", sc.id.clone())
            .field("fqdn", sc.fqdn.clone())
            .field("state", sc.state.clone())
            .field("policy version", format!("v{}", sc.policy_version));
        // Section 7.19: when the SC update bumps the policy and one or more
        // Dev CVMs in the entity now point at a stale policy version, the
        // Console returns their ids in `dev_cvms_requiring_update`. Surface
        // them as an additional field on the confirm so the operator sees
        // exactly which CVMs they need to relaunch / update next.
        if !result.dev_cvms_requiring_update.is_empty() {
            confirm = confirm
                .field(
                    "dev cvms requiring update",
                    result.dev_cvms_requiring_update.join(", "),
                )
                .next_step("run concrete cvm update <cvm-id> for each listed Dev CVM");
        }
        println!("{}", style::render_confirm(&confirm));
    }
}

fn print_terminate_result(security_cvm: &SecurityCvm, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(security_cvm).expect("Security CVM output serializes")
        );
    } else {
        let confirm =
            style::ConfirmBlock::new("terminated", "security cvm", security_cvm.id.clone())
                .field("state", security_cvm.state.clone())
                .field(
                    "warning",
                    "any live Dev CVM in this entity will lose egress until the SC is re-launched",
                );
        println!("{}", style::render_confirm(&confirm));
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
        let view = style::SecurityCvmAttestationView {
            security_cvm_id: &attestation.security_cvm_id,
            fqdn: &attestation.fqdn,
            verified: attestation.verdict.verified,
            failure_reason: attestation.verdict.failure_reason.as_deref(),
            expected_image_measurement: attestation.expected_image_measurement.as_deref(),
            image_measurement_seen: attestation.verdict.image_measurement_seen.as_deref(),
            rtmr3_digest_seen: attestation.verdict.rtmr3_digest_seen.as_deref(),
            verified_at: attestation.verdict.verified_at.as_deref(),
        };
        println!("{}", style::security_cvm_attestation_card(&view));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_security_cvm_config_value_rejects_slash() {
        assert_eq!(
            validate_security_cvm_config_value("--instance-type", "tdx/small", 100)
                .expect_err("slash rejected"),
            "[usage] --instance-type may contain only letters, digits, '.', '_', and '-'"
        );
    }
}
