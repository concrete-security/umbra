use chrono::DateTime;
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    cli::{
        AdminCommand, AdminKeysCommand, AdminKeysRotateArgs, AdminSessionsCommand,
        AdminSessionsRevokeArgs,
    },
    commands::auth,
    config::ResolvedConfig,
    exit::ExitStatus,
};

#[derive(Debug, Deserialize, Serialize)]
struct SessionsRevokeOutput {
    revoked_jti_count: u64,
    revoked_refresh_token_count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct KeysRotateOutput {
    active_kid: String,
    retiring_kids: Vec<String>,
}

pub fn run(command: AdminCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        AdminCommand::Sessions(command) => match command {
            AdminSessionsCommand::Revoke(args) => sessions_revoke(config, args, json),
        },
        AdminCommand::Keys(command) => match command {
            AdminKeysCommand::Rotate(args) => keys_rotate(config, args, json),
        },
    }
}

fn sessions_revoke(
    config: &ResolvedConfig,
    args: AdminSessionsRevokeArgs,
    json_output: bool,
) -> ExitStatus {
    let body = match sessions_revoke_body(&args) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Usage;
        }
    };
    let (console_url, access_token) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let output: SessionsRevokeOutput = match post_json(
        format!("{console_url}/api/v1/admin/sessions/revoke"),
        &access_token,
        &Value::Object(body),
        "revoke sessions",
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("session revoke output serializes")
        );
    } else {
        println!(
            "revoked_jti_count={} revoked_refresh_token_count={}",
            output.revoked_jti_count, output.revoked_refresh_token_count
        );
    }
    ExitStatus::Ok
}

fn keys_rotate(
    config: &ResolvedConfig,
    args: AdminKeysRotateArgs,
    json_output: bool,
) -> ExitStatus {
    let (console_url, access_token) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let body = json!({
        "new_kid": args.new_kid,
        "retire_old_after_seconds": args.retire_old_after_seconds,
    });
    let output: KeysRotateOutput = match post_json(
        format!("{console_url}/api/v1/admin/keys/rotate"),
        &access_token,
        &body,
        "rotate JWT keys",
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("key rotation output serializes")
        );
    } else {
        let retiring = if output.retiring_kids.is_empty() {
            "-".to_string()
        } else {
            output.retiring_kids.join(",")
        };
        println!("active_kid={} retiring_kids={retiring}", output.active_kid);
    }
    ExitStatus::Ok
}

fn console_session(config: &ResolvedConfig) -> Result<(&str, String), (ExitStatus, String)> {
    let console_url = config
        .require_console_url()
        .map_err(|message| (ExitStatus::Usage, message))?;
    let session = auth::session_for_console(config)?;
    Ok((console_url, session.access_token.clone()))
}

fn post_json<T: for<'de> Deserialize<'de>>(
    url: String,
    access_token: &str,
    body: &Value,
    action: &str,
) -> Result<T, (ExitStatus, String)> {
    let response = Client::new()
        .post(url)
        .bearer_auth(access_token)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(body)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to {action}: {err}"),
            )
        })?;
    read_json_response(response, action)
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

fn sessions_revoke_body(args: &AdminSessionsRevokeArgs) -> Result<Map<String, Value>, String> {
    if args.user.is_none() && args.entity.is_none() && args.issued_before.is_none() {
        return Err("[usage] at least one revoke filter is required".to_string());
    }
    let mut body = Map::new();
    if let Some(user_id) = args.user.as_deref() {
        Uuid::parse_str(user_id).map_err(|_| "[usage] --user must be a UUID".to_string())?;
        body.insert("user_id".to_string(), Value::String(user_id.to_string()));
    }
    if let Some(entity_id) = args.entity.as_deref() {
        Uuid::parse_str(entity_id).map_err(|_| "[usage] --entity must be a UUID".to_string())?;
        body.insert(
            "entity_id".to_string(),
            Value::String(entity_id.to_string()),
        );
    }
    if let Some(issued_before) = args.issued_before.as_deref() {
        DateTime::parse_from_rfc3339(issued_before)
            .map_err(|_| "[usage] --issued-before must be an RFC3339 timestamp".to_string())?;
        body.insert(
            "issued_before".to_string(),
            Value::String(issued_before.to_string()),
        );
    }
    Ok(body)
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
    let component = error
        .get("details")
        .and_then(|details| details.get("component"))
        .and_then(|value| value.as_str());
    Some(match (code, component) {
        (_, Some(component)) => format!("{message} ({component})"),
        (Some(code), _) if code != "UNAUTHORIZED" && code != "VALIDATION_ERROR" => {
            format!("{message} ({code})")
        }
        _ => message.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_revoke_requires_filter() {
        let args = AdminSessionsRevokeArgs {
            user: None,
            entity: None,
            issued_before: None,
        };

        assert_eq!(
            sessions_revoke_body(&args).expect_err("empty predicate is rejected"),
            "[usage] at least one revoke filter is required"
        );
    }

    #[test]
    fn sessions_revoke_rejects_invalid_timestamp() {
        let args = AdminSessionsRevokeArgs {
            user: None,
            entity: None,
            issued_before: Some("not-a-time".to_string()),
        };

        assert_eq!(
            sessions_revoke_body(&args).expect_err("invalid timestamp is rejected"),
            "[usage] --issued-before must be an RFC3339 timestamp"
        );
    }

    #[test]
    fn console_error_message_includes_component() {
        let body = r#"{"error":{"code":"SERVICE_UNAVAILABLE","message":"JWT key material is not ready for rotation","details":{"component":"jwt_key_store"}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("JWT key material is not ready for rotation (jwt_key_store)")
        );
    }
}
