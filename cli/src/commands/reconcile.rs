use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{cli::ReconcileArgs, commands::auth, config::ResolvedConfig, exit::ExitStatus};

#[derive(Debug, Deserialize, Serialize)]
struct ReconcileOutput {
    cvms_advanced: Vec<String>,
    security_cvms_advanced: Vec<String>,
    orphans_cleaned: Vec<String>,
}

pub fn run(args: ReconcileArgs, config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let console_url = match config.require_console_url() {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Usage;
        }
    };
    let session = match auth::session_for_console(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let body = json!({"include_orphans": !args.no_orphans});
    let output: ReconcileOutput = match post_json(
        format!("{console_url}/api/v1/admin/reconcile"),
        &session.access_token,
        &body,
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
            serde_json::to_string_pretty(&output).expect("reconcile output serializes")
        );
    } else {
        println!(
            "cvms_advanced={} ids={}",
            output.cvms_advanced.len(),
            format_ids(&output.cvms_advanced)
        );
        println!(
            "security_cvms_advanced={} ids={}",
            output.security_cvms_advanced.len(),
            format_ids(&output.security_cvms_advanced)
        );
        println!(
            "orphans_cleaned={} ids={}",
            output.orphans_cleaned.len(),
            format_ids(&output.orphans_cleaned)
        );
    }
    ExitStatus::Ok
}

fn post_json<T: for<'de> Deserialize<'de>>(
    url: String,
    access_token: &str,
    body: &Value,
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
                format!("[error] failed to run reconcile: {err}"),
            )
        })?;
    read_json_response(response)
}

fn read_json_response<T: for<'de> Deserialize<'de>>(
    response: Response,
) -> Result<T, (ExitStatus, String)> {
    if !response.status().is_success() {
        return Err(error_for_response(response));
    }
    response.json::<T>().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] malformed reconcile response: {err}"),
        )
    })
}

fn error_for_response(response: Response) -> (ExitStatus, String) {
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
        console_error_message(&text).unwrap_or_else(|| format!("reconcile failed: HTTP {status}"));
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
    let component = error
        .get("details")
        .and_then(|details| details.get("component"))
        .and_then(|value| value.as_str());
    Some(match component {
        Some(component) => format!("{message} ({component})"),
        None => message.to_string(),
    })
}

fn format_ids(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_error_message_includes_component() {
        let body = r#"{"error":{"code":"SERVICE_UNAVAILABLE","message":"CVM provider adapter is not configured","details":{"component":"cvm_provider_adapter"}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("CVM provider adapter is not configured (cvm_provider_adapter)")
        );
    }

    #[test]
    fn empty_human_ids_render_dash() {
        assert_eq!(format_ids(&[]), "-");
    }
}
