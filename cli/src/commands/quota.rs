use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    cli::{QuotaClearArgs, QuotaCommand, QuotaScopeArgs, QuotaSetArgs},
    commands::auth,
    config::ResolvedConfig,
    exit::ExitStatus,
    session::Session,
};

const ENTITY_QUOTA_RESOURCES: &[&str] = &["dev_cvms", "ssh_keys", "users", "profiles"];
const USER_QUOTA_RESOURCES: &[&str] = &["dev_cvms", "ssh_keys"];

#[derive(Debug)]
enum QuotaScope {
    Entity(String),
    User(String),
}

#[derive(Debug, Deserialize)]
struct QuotaList {
    quotas: Vec<Quota>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Quota {
    #[serde(default)]
    entity_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    resource: String,
    limit: u64,
    source: String,
    current_usage: u64,
    set_by: Option<String>,
    set_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct QuotaClearOutput<'a> {
    scope: &'static str,
    scope_id: &'a str,
    resource: &'a str,
    cleared: bool,
}

pub fn run(command: QuotaCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        QuotaCommand::Get(args) => get(config, args, json),
        QuotaCommand::Set(args) => set(config, args, json),
        QuotaCommand::Clear(args) => clear(config, args, json),
    }
}

fn get(config: &ResolvedConfig, args: QuotaScopeArgs, json_output: bool) -> ExitStatus {
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let scope = match resolve_scope(&args, &session) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Usage;
        }
    };
    let quotas = match fetch_quotas(console_url, &session.access_token, &scope) {
        Ok(value) => value.quotas,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    print_quotas(&quotas, json_output);
    ExitStatus::Ok
}

fn set(config: &ResolvedConfig, args: QuotaSetArgs, json_output: bool) -> ExitStatus {
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let scope = match resolve_scope(&args.scope, &session) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Usage;
        }
    };
    if let Err(message) = validate_resource(&scope, &args.resource) {
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let quota = match set_quota(
        console_url,
        &session.access_token,
        &scope,
        &args.resource,
        args.limit,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    print_quota(&quota, json_output, "set");
    ExitStatus::Ok
}

fn clear(config: &ResolvedConfig, args: QuotaClearArgs, json_output: bool) -> ExitStatus {
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let scope = match resolve_scope(&args.scope, &session) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Usage;
        }
    };
    if let Err(message) = validate_resource(&scope, &args.resource) {
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    if let Err((status, message)) =
        clear_quota(console_url, &session.access_token, &scope, &args.resource)
    {
        eprintln!("{message}");
        return status;
    }
    let (scope_name, scope_id) = scope_parts(&scope);
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&QuotaClearOutput {
                scope: scope_name,
                scope_id,
                resource: &args.resource,
                cleared: true,
            })
            .expect("quota clear output serializes")
        );
    } else {
        println!("cleared {scope_name} {scope_id} quota {}", args.resource);
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

fn resolve_scope(args: &QuotaScopeArgs, session: &Session) -> Result<QuotaScope, String> {
    match (args.entity.as_deref(), args.user.as_deref()) {
        (Some(_), Some(_)) => Err("[usage] choose either --entity or --user".to_string()),
        (Some(entity_id), None) => {
            validate_uuid("--entity", entity_id)?;
            Ok(QuotaScope::Entity(entity_id.to_string()))
        }
        (None, Some(user_id)) => {
            validate_uuid("--user", user_id)?;
            Ok(QuotaScope::User(user_id.to_string()))
        }
        (None, None) => Ok(QuotaScope::Entity(session.entity.id.clone())),
    }
}

fn fetch_quotas(
    console_url: &str,
    access_token: &str,
    scope: &QuotaScope,
) -> Result<QuotaList, (ExitStatus, String)> {
    let url = match scope {
        QuotaScope::Entity(entity_id) => {
            format!("{console_url}/api/v1/entities/{entity_id}/quotas")
        }
        QuotaScope::User(user_id) => format!("{console_url}/api/v1/users/{user_id}/quotas"),
    };
    let response = Client::new()
        .get(url)
        .bearer_auth(access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to get quotas: {err}"),
            )
        })?;
    read_json_response(response, "get quotas")
}

fn set_quota(
    console_url: &str,
    access_token: &str,
    scope: &QuotaScope,
    resource: &str,
    limit: u64,
) -> Result<Quota, (ExitStatus, String)> {
    let url = match scope {
        QuotaScope::Entity(entity_id) => {
            format!("{console_url}/api/v1/entities/{entity_id}/quotas/{resource}")
        }
        QuotaScope::User(user_id) => {
            format!("{console_url}/api/v1/users/{user_id}/quotas/{resource}")
        }
    };
    let response = Client::new()
        .patch(url)
        .bearer_auth(access_token)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(&json!({ "limit": limit }))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to set quota: {err}"),
            )
        })?;
    read_json_response(response, "set quota")
}

fn clear_quota(
    console_url: &str,
    access_token: &str,
    scope: &QuotaScope,
    resource: &str,
) -> Result<(), (ExitStatus, String)> {
    let url = match scope {
        QuotaScope::Entity(entity_id) => {
            format!("{console_url}/api/v1/entities/{entity_id}/quotas/{resource}")
        }
        QuotaScope::User(user_id) => {
            format!("{console_url}/api/v1/users/{user_id}/quotas/{resource}")
        }
    };
    let response = Client::new()
        .delete(url)
        .bearer_auth(access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to clear quota: {err}"),
            )
        })?;
    read_empty_response(response, "clear quota")
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

fn read_empty_response(response: Response, action: &str) -> Result<(), (ExitStatus, String)> {
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        Ok(())
    } else {
        Err(error_for_response(response, action))
    }
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
    let validation_type = details
        .and_then(|details| details.get("errors"))
        .and_then(|errors| errors.as_array())
        .and_then(|errors| errors.first())
        .and_then(|error| error.get("type"))
        .and_then(|value| value.as_str());
    Some(match (state, validation_type, code) {
        (Some(state), _, _) => format!("{message} ({state})"),
        (_, Some(validation_type), _) => format!("{message} ({validation_type})"),
        (_, _, Some(code)) if code != "UNAUTHORIZED" && code != "VALIDATION_ERROR" => {
            format!("{message} ({code})")
        }
        _ => message.to_string(),
    })
}

fn validate_resource(scope: &QuotaScope, resource: &str) -> Result<(), String> {
    let valid = match scope {
        QuotaScope::Entity(_) => ENTITY_QUOTA_RESOURCES.contains(&resource),
        QuotaScope::User(_) => USER_QUOTA_RESOURCES.contains(&resource),
    };
    if valid {
        Ok(())
    } else {
        Err(format!(
            "[usage] unknown quota resource for scope: {resource}"
        ))
    }
}

fn validate_uuid(name: &str, value: &str) -> Result<(), String> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| format!("[usage] {name} must be a UUID"))
}

fn scope_parts(scope: &QuotaScope) -> (&'static str, &str) {
    match scope {
        QuotaScope::Entity(entity_id) => ("entity", entity_id),
        QuotaScope::User(user_id) => ("user", user_id),
    }
}

fn quota_scope_id(quota: &Quota) -> (&'static str, &str) {
    if let Some(entity_id) = quota.entity_id.as_deref() {
        ("entity", entity_id)
    } else if let Some(user_id) = quota.user_id.as_deref() {
        ("user", user_id)
    } else {
        ("scope", "-")
    }
}

fn print_quotas(quotas: &[Quota], json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(quotas).expect("quota list output serializes")
        );
    } else if quotas.is_empty() {
        println!("no quotas");
    } else {
        for quota in quotas {
            print_quota(quota, false, "quota");
        }
    }
}

fn print_quota(quota: &Quota, json_output: bool, prefix: &str) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(quota).expect("quota output serializes")
        );
    } else {
        let (scope, scope_id) = quota_scope_id(quota);
        println!(
            "{prefix} {scope}={scope_id} resource={} limit={} source={} current_usage={} set_by={} set_at={}",
            quota.resource,
            quota.limit,
            quota.source,
            quota.current_usage,
            quota.set_by.as_deref().unwrap_or("-"),
            quota.set_at.as_deref().unwrap_or("-"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_scope_rejects_entity_only_resource() {
        let err = validate_resource(&QuotaScope::User("user-1".to_string()), "profiles")
            .expect_err("profiles is entity-only");

        assert_eq!(err, "[usage] unknown quota resource for scope: profiles");
    }

    #[test]
    fn console_error_message_includes_conflict_state() {
        let body = r#"{"error":{"code":"CONFLICT","message":"user quota exceeds effective entity quota","details":{"state":"user_quota_above_entity_quota","entity_quota":1}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("user quota exceeds effective entity quota (user_quota_above_entity_quota)")
        );
    }
}
