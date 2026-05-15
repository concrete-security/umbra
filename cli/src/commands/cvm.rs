use reqwest::{
    blocking::{Client, Response},
    header::{ETAG, IF_MATCH},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    cli::CvmCommand, commands::auth, config::ResolvedConfig, exit::ExitStatus, session::Session,
};

#[derive(Debug, Deserialize)]
struct CvmListPage {
    items: Vec<Cvm>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Cvm {
    id: String,
    owner: OwnerRef,
    entity_id: String,
    profiles: Vec<ProfileRef>,
    state: String,
    instance_type: Option<String>,
    region: Option<String>,
    ssh_keys: Vec<SshKeyRef>,
    fqdn: Option<String>,
    expected_image_measurement: Option<String>,
    image_measurement: Option<String>,
    rtmr3_digest: Option<String>,
    attestation_verified_at: Option<String>,
    error_reason: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct OwnerRef {
    id: String,
    email: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProfileRef {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SshKeyRef {
    id: String,
    label: String,
}

#[derive(Debug)]
struct CvmWithEtag {
    cvm: Cvm,
    etag: String,
}

pub fn run(command: CvmCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        CvmCommand::List => list(config, json),
        CvmCommand::Attach { cvm_id } => profile_mutation(config, &cvm_id, Mutation::Attach, json),
        CvmCommand::Detach { cvm_id } => profile_mutation(config, &cvm_id, Mutation::Detach, json),
    }
}

#[derive(Clone, Copy)]
enum Mutation {
    Attach,
    Detach,
}

impl Mutation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Attach => "attach",
            Self::Detach => "detach",
        }
    }
}

fn list(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let profile_id = match optional_profile_filter(config) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Usage;
        }
    };
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let page = match fetch_cvms(console_url, &session, profile_id.as_deref()) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    print_cvm_list(page, json_output);
    ExitStatus::Ok
}

fn profile_mutation(
    config: &ResolvedConfig,
    cvm_id: &str,
    mutation: Mutation,
    json_output: bool,
) -> ExitStatus {
    if let Err(message) = validate_uuid("CVM_ID", cvm_id) {
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let profile_id = match selected_profile(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let current = match fetch_cvm_with_etag(console_url, &session, cvm_id) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let cvm = match mutate_profile(
        console_url,
        &session.access_token,
        cvm_id,
        &current.etag,
        profile_id,
        mutation,
    ) {
        Ok(value) => value.cvm,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&cvm).expect("CVM output serializes")
        );
    } else {
        println!(
            "{} profile {} {}",
            mutation.as_str(),
            profile_id,
            cvm_summary(&cvm)
        );
    }
    ExitStatus::Ok
}

fn console_session(config: &ResolvedConfig) -> Result<(&str, Session), (ExitStatus, String)> {
    let console_url = config
        .require_console_url()
        .map_err(|message| (ExitStatus::Usage, message))?;
    let session = auth::session_for_console(config)?;
    Ok((console_url, session))
}

fn optional_profile_filter(config: &ResolvedConfig) -> Result<Option<String>, String> {
    if config.profile_flags.len() > 1 {
        return Err("[usage] expected at most one --profile for cvm list".to_string());
    }
    if let Some(profile_id) = config.profile_flags.first() {
        validate_uuid("--profile", profile_id)?;
        Ok(Some(profile_id.clone()))
    } else {
        Ok(None)
    }
}

fn selected_profile(config: &ResolvedConfig) -> Result<&str, (ExitStatus, String)> {
    let profile_id = config
        .require_profile()
        .map_err(|message| (ExitStatus::Usage, message))?;
    validate_uuid("--profile", profile_id).map_err(|message| (ExitStatus::Usage, message))?;
    Ok(profile_id)
}

fn fetch_cvms(
    console_url: &str,
    session: &Session,
    profile_id: Option<&str>,
) -> Result<CvmListPage, (ExitStatus, String)> {
    let mut request = Client::new()
        .get(format!("{console_url}/api/v1/cvms"))
        .bearer_auth(&session.access_token);
    if let Some(profile_id) = profile_id {
        request = request.query(&[("profile_id", profile_id)]);
    }
    let response = request.send().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to list CVMs: {err}"),
        )
    })?;
    read_json_response(response, "list CVMs")
}

fn fetch_cvm_with_etag(
    console_url: &str,
    session: &Session,
    cvm_id: &str,
) -> Result<CvmWithEtag, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/cvms/{cvm_id}"))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch CVM: {err}"),
            )
        })?;
    read_cvm_with_etag(response, "fetch CVM")
}

fn mutate_profile(
    console_url: &str,
    access_token: &str,
    cvm_id: &str,
    etag: &str,
    profile_id: &str,
    mutation: Mutation,
) -> Result<CvmWithEtag, (ExitStatus, String)> {
    let client = Client::new();
    let request = match mutation {
        Mutation::Attach => client
            .post(format!("{console_url}/api/v1/cvms/{cvm_id}/profiles"))
            .json(&json!({ "profile_id": profile_id })),
        Mutation::Detach => client.delete(format!(
            "{console_url}/api/v1/cvms/{cvm_id}/profiles/{profile_id}"
        )),
    };
    let response = request
        .bearer_auth(access_token)
        .header(IF_MATCH, etag)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to {} CVM profile: {err}", mutation.as_str()),
            )
        })?;
    read_cvm_with_etag(response, mutation.as_str())
}

fn read_cvm_with_etag(
    response: Response,
    action: &str,
) -> Result<CvmWithEtag, (ExitStatus, String)> {
    if !response.status().is_success() {
        return Err(error_for_response(response, action));
    }
    let etag = response
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| {
            (
                ExitStatus::Error,
                format!("[error] {action} response did not include ETag"),
            )
        })?;
    let cvm = response.json::<Cvm>().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] malformed {action} response: {err}"),
        )
    })?;
    Ok(CvmWithEtag { cvm, etag })
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
    } else if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
        ExitStatus::Usage
    } else {
        ExitStatus::Error
    };
    let text = response.text().unwrap_or_default();
    let message =
        console_error_message(&text).unwrap_or_else(|| format!("{action} failed: HTTP {status}"));
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
    let required = details
        .and_then(|details| details.get("required"))
        .and_then(|value| value.as_str());
    let validation_type = details
        .and_then(|details| details.get("errors"))
        .and_then(|errors| errors.as_array())
        .and_then(|errors| errors.first())
        .and_then(|error| error.get("type"))
        .and_then(|value| value.as_str());
    Some(match (state, required, validation_type, code) {
        (Some(state), _, _, _) => format!("{message} ({state})"),
        (_, Some(required), _, _) => format!("{message} ({required})"),
        (_, _, Some(validation_type), _) => format!("{message} ({validation_type})"),
        (_, _, _, Some(code)) if code != "UNAUTHORIZED" && code != "VALIDATION_ERROR" => {
            format!("{message} ({code})")
        }
        _ => message.to_string(),
    })
}

fn print_cvm_list(page: CvmListPage, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&page.items).expect("CVM list output serializes")
        );
    } else if page.items.is_empty() {
        println!("no cvms");
    } else {
        for cvm in &page.items {
            println!("{}", cvm_summary(cvm));
        }
        if let Some(cursor) = page.next_cursor {
            eprintln!("next cursor: {cursor}");
        }
    }
}

fn cvm_summary(cvm: &Cvm) -> String {
    format!(
        "cvm {} state={} fqdn={} owner={} profiles={} ssh_keys={} updated_at={}",
        cvm.id,
        cvm.state,
        cvm.fqdn.as_deref().unwrap_or("-"),
        cvm.owner.email,
        cvm.profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>()
            .join(","),
        cvm.ssh_keys
            .iter()
            .map(|key| key.label.as_str())
            .collect::<Vec<_>>()
            .join(","),
        cvm.updated_at
    )
}

fn validate_uuid(name: &str, value: &str) -> Result<(), String> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| format!("[usage] {name} must be a UUID"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_error_message_includes_last_profile_state() {
        let body = r#"{"error":{"code":"CONFLICT","message":"cannot detach the last CVM profile","details":{"state":"last_profile"}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("cannot detach the last CVM profile (last_profile)")
        );
    }

    #[test]
    fn console_error_message_includes_required_membership() {
        let body = r#"{"error":{"code":"FORBIDDEN","message":"profile membership is required","details":{"required":"profile_member"}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("profile membership is required (profile_member)")
        );
    }
}
