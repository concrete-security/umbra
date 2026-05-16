use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{commands::auth, config::ResolvedConfig, exit::ExitStatus, session::Session};

#[derive(Debug, Deserialize, Serialize)]
struct Entity {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct User {
    id: String,
    email: String,
    entity: Entity,
}

#[derive(Debug, Deserialize)]
struct ListPage<T> {
    items: Vec<T>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Profile {
    id: String,
    name: String,
    description: String,
    policy: Value,
    attached_cvm_count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct Cvm {
    id: String,
    owner: OwnerRef,
    profiles: Vec<ProfileRef>,
    state: String,
    instance_type: Option<String>,
    region: Option<String>,
    ssh_keys: Vec<SshKeyRef>,
    fqdn: Option<String>,
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

#[derive(Debug, Deserialize, Serialize)]
struct SecurityCvm {
    id: String,
    state: String,
    instance_type: Option<String>,
    region: Option<String>,
    policy_version: u64,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct ConsoleSshKey {
    id: String,
    label: String,
    fingerprint: String,
    public_key: String,
}

#[derive(Debug, Serialize)]
struct SshKeyOutput {
    id: String,
    label: String,
    algorithm: String,
    fingerprint: String,
}

#[derive(Debug, Serialize)]
struct Totals {
    profiles: usize,
    dev_cvms: usize,
    dev_cvms_running: usize,
    ssh_keys: usize,
}

#[derive(Debug, Serialize)]
struct StatusOutput {
    user: StatusUser,
    entity: Entity,
    security_cvm: Option<SecurityCvm>,
    profiles: Vec<Profile>,
    dev_cvms: Vec<Cvm>,
    ssh_keys: Vec<SshKeyOutput>,
    totals: Totals,
}

#[derive(Debug, Serialize)]
struct StatusUser {
    id: String,
    email: String,
}

pub fn run(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
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
    let status = match fetch_status(console_url, &session, profile_id.as_deref()) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    print_status(&status, json_output);
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
        return Err("[usage] expected at most one --profile for status".to_string());
    }
    if let Some(profile_id) = config.profile_flags.first() {
        Uuid::parse_str(profile_id).map_err(|_| "[usage] --profile must be a UUID".to_string())?;
        Ok(Some(profile_id.clone()))
    } else {
        Ok(None)
    }
}

fn fetch_status(
    console_url: &str,
    session: &Session,
    profile_id: Option<&str>,
) -> Result<StatusOutput, (ExitStatus, String)> {
    let user = fetch_me(console_url, session)?;
    let security_cvm = fetch_security_cvm_optional(console_url, session)?;
    let mut profiles = fetch_profiles(console_url, session)?.items;
    if let Some(profile_id) = profile_id {
        profiles.retain(|profile| profile.id == profile_id);
    }
    let dev_cvms = fetch_cvms(console_url, session, profile_id)?.items;
    let ssh_keys = fetch_keys(console_url, session)?
        .items
        .iter()
        .map(key_output)
        .collect::<Vec<_>>();
    let totals = Totals {
        profiles: profiles.len(),
        dev_cvms: dev_cvms.len(),
        dev_cvms_running: dev_cvms.iter().filter(|cvm| cvm.state == "RUNNING").count(),
        ssh_keys: ssh_keys.len(),
    };
    Ok(StatusOutput {
        user: StatusUser {
            id: user.id,
            email: user.email,
        },
        entity: user.entity,
        security_cvm,
        profiles,
        dev_cvms,
        ssh_keys,
        totals,
    })
}

fn fetch_me(console_url: &str, session: &Session) -> Result<User, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/me"))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch session identity: {err}"),
            )
        })?;
    read_json_response(response, "fetch session identity")
}

fn fetch_profiles(
    console_url: &str,
    session: &Session,
) -> Result<ListPage<Profile>, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!(
            "{console_url}/api/v1/entities/{}/profiles",
            session.entity.id
        ))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to list profiles: {err}"),
            )
        })?;
    read_json_response(response, "list profiles")
}

fn fetch_cvms(
    console_url: &str,
    session: &Session,
    profile_id: Option<&str>,
) -> Result<ListPage<Cvm>, (ExitStatus, String)> {
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

fn fetch_keys(
    console_url: &str,
    session: &Session,
) -> Result<ListPage<ConsoleSshKey>, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/me/keys"))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to list SSH keys: {err}"),
            )
        })?;
    read_json_response(response, "list SSH keys")
}

fn fetch_security_cvm_optional(
    console_url: &str,
    session: &Session,
) -> Result<Option<SecurityCvm>, (ExitStatus, String)> {
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
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    read_json_response(response, "fetch Security CVM").map(Some)
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
    Some(match (state, required, code) {
        (Some(state), _, _) => format!("{message} ({state})"),
        (_, Some(required), _) => format!("{message} ({required})"),
        (_, _, Some(code)) if code != "UNAUTHORIZED" && code != "VALIDATION_ERROR" => {
            format!("{message} ({code})")
        }
        _ => message.to_string(),
    })
}

fn key_output(key: &ConsoleSshKey) -> SshKeyOutput {
    SshKeyOutput {
        id: key.id.clone(),
        label: key.label.clone(),
        algorithm: key
            .public_key
            .split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string(),
        fingerprint: key.fingerprint.clone(),
    }
}

fn print_status(status: &StatusOutput, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(status).expect("status output serializes")
        );
        return;
    }
    println!(
        "user {} entity={} ({})",
        status.user.email, status.entity.name, status.entity.id
    );
    match &status.security_cvm {
        Some(security_cvm) => println!(
            "security_cvm {} state={} region={} instance_type={} policy_version={}",
            security_cvm.id,
            security_cvm.state,
            security_cvm.region.as_deref().unwrap_or("-"),
            security_cvm.instance_type.as_deref().unwrap_or("-"),
            security_cvm.policy_version
        ),
        None => println!("security_cvm none"),
    }
    println!(
        "totals profiles={} dev_cvms={} running={} ssh_keys={}",
        status.totals.profiles,
        status.totals.dev_cvms,
        status.totals.dev_cvms_running,
        status.totals.ssh_keys
    );
    for profile in &status.profiles {
        let cvms = status
            .dev_cvms
            .iter()
            .filter(|cvm| {
                cvm.profiles
                    .iter()
                    .any(|attached| attached.id == profile.id)
            })
            .collect::<Vec<_>>();
        if cvms.is_empty() {
            println!(
                "profile {} ({}) - no CVMs attached",
                profile.name, profile.id
            );
        } else {
            println!("profile {} ({})", profile.name, profile.id);
            for cvm in cvms {
                let owner = if cvm.owner.email == status.user.email {
                    String::new()
                } else {
                    format!(" owner={}", cvm.owner.email)
                };
                println!(
                    "  cvm {} state={} fqdn={} region={} instance_type={}{}",
                    cvm.id,
                    cvm.state,
                    cvm.fqdn.as_deref().unwrap_or("-"),
                    cvm.region.as_deref().unwrap_or("-"),
                    cvm.instance_type.as_deref().unwrap_or("-"),
                    owner
                );
            }
        }
    }
    if status.ssh_keys.is_empty() {
        println!("ssh_keys none");
    } else {
        println!("ssh_keys");
        for key in &status.ssh_keys {
            println!(
                "  {} {} {} {}",
                key.id, key.label, key.algorithm, key.fingerprint
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_output_extracts_algorithm() {
        let key = ConsoleSshKey {
            id: "key-1".to_string(),
            label: "workstation".to_string(),
            fingerprint: "SHA256:abc".to_string(),
            public_key: "ssh-ed25519 AAAA comment".to_string(),
        };

        assert_eq!(key_output(&key).algorithm, "ssh-ed25519");
    }

    #[test]
    fn console_error_message_includes_required_permission() {
        let body = r#"{"error":{"code":"FORBIDDEN","message":"permission denied","details":{"required":"SECURITY_CVM_CONFIGURE"}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("permission denied (SECURITY_CVM_CONFIGURE)")
        );
    }
}
