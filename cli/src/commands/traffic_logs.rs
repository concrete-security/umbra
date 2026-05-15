use chrono::DateTime;
use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{cli::TrafficLogsArgs, commands::auth, config::ResolvedConfig, exit::ExitStatus};

#[derive(Debug, Deserialize, Serialize)]
struct TrafficLogListPage {
    items: Vec<TrafficLog>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TrafficLogsOutput {
    logs: Vec<TrafficLog>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TrafficLog {
    id: String,
    timestamp: String,
    security_cvm_id: String,
    cvm_id: Option<String>,
    source_ip: String,
    destination_ip: String,
    destination_host: Option<String>,
    protocol: String,
    port: u16,
    method: Option<String>,
    path: Option<String>,
    response_code: Option<u16>,
    bytes_transferred: u64,
}

pub fn run(args: TrafficLogsArgs, config: &ResolvedConfig, json: bool) -> ExitStatus {
    if let Err(message) = validate_args(&args) {
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
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
    let page = match fetch_traffic_logs(console_url, &session.access_token, &args) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    print_traffic_logs(page, json);
    ExitStatus::Ok
}

fn validate_args(args: &TrafficLogsArgs) -> Result<(), String> {
    if args.limit == 0 || args.limit > 1000 {
        return Err("[usage] --limit must be between 1 and 1000".to_string());
    }
    if let Some(cvm_id) = args.cvm.as_deref() {
        validate_uuid("--cvm", cvm_id)?;
    }
    if let Some(security_cvm_id) = args.security_cvm.as_deref() {
        validate_uuid("--security-cvm", security_cvm_id)?;
    }
    if let Some(from) = args.from.as_deref() {
        validate_timestamp("--from", from)?;
    }
    if let Some(to) = args.to.as_deref() {
        validate_timestamp("--to", to)?;
    }
    Ok(())
}

fn fetch_traffic_logs(
    console_url: &str,
    access_token: &str,
    args: &TrafficLogsArgs,
) -> Result<TrafficLogListPage, (ExitStatus, String)> {
    let mut query = vec![("limit", args.limit.to_string())];
    push_query(&mut query, "cvm_id", &args.cvm);
    push_query(&mut query, "security_cvm_id", &args.security_cvm);
    push_query(&mut query, "from", &args.from);
    push_query(&mut query, "to", &args.to);
    push_query(&mut query, "cursor", &args.cursor);
    let response = Client::new()
        .get(format!("{console_url}/api/v1/traffic-logs"))
        .bearer_auth(access_token)
        .query(&query)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to query traffic logs: {err}"),
            )
        })?;
    read_json_response(response, "query traffic logs")
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
    let validation_type = details
        .and_then(|details| details.get("errors"))
        .and_then(|errors| errors.as_array())
        .and_then(|errors| errors.first())
        .and_then(|error| error.get("type"))
        .and_then(|value| value.as_str());
    Some(match (validation_type, code) {
        (Some(validation_type), _) => format!("{message} ({validation_type})"),
        (_, Some(code)) if code != "UNAUTHORIZED" && code != "VALIDATION_ERROR" => {
            format!("{message} ({code})")
        }
        _ => message.to_string(),
    })
}

fn print_traffic_logs(page: TrafficLogListPage, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&TrafficLogsOutput {
                logs: page.items,
                next_cursor: page.next_cursor,
            })
            .expect("traffic log output serializes")
        );
    } else if page.items.is_empty() {
        println!("no traffic logs");
    } else {
        for log in &page.items {
            let cvm_id = log.cvm_id.as_deref().unwrap_or("-");
            let host = log.destination_host.as_deref().unwrap_or("-");
            let method = log.method.as_deref().unwrap_or("-");
            let path = log.path.as_deref().unwrap_or("-");
            let response_code = log
                .response_code
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "{} {} sc={} cvm={} src={} dst={}:{} host={} protocol={} method={} path={} response={} bytes={}",
                log.timestamp,
                log.id,
                log.security_cvm_id,
                cvm_id,
                log.source_ip,
                log.destination_ip,
                log.port,
                host,
                log.protocol,
                method,
                path,
                response_code,
                log.bytes_transferred,
            );
        }
        if let Some(cursor) = &page.next_cursor {
            eprintln!("next cursor: {cursor}");
        }
    }
}

fn push_query(query: &mut Vec<(&'static str, String)>, key: &'static str, value: &Option<String>) {
    if let Some(value) = value {
        query.push((key, value.clone()));
    }
}

fn validate_uuid(name: &str, value: &str) -> Result<(), String> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| format!("[usage] {name} must be a UUID"))
}

fn validate_timestamp(name: &str, value: &str) -> Result<(), String> {
    DateTime::parse_from_rfc3339(value)
        .map(|_| ())
        .map_err(|_| format!("[usage] {name} must be an RFC3339 timestamp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_args_rejects_bad_cvm_uuid() {
        let args = TrafficLogsArgs {
            cvm: Some("not-a-uuid".to_string()),
            security_cvm: None,
            from: None,
            to: None,
            limit: 100,
            cursor: None,
        };

        assert_eq!(
            validate_args(&args).expect_err("invalid cvm uuid is rejected"),
            "[usage] --cvm must be a UUID"
        );
    }

    #[test]
    fn console_error_message_includes_validation_type() {
        let body = r#"{"error":{"code":"VALIDATION_ERROR","message":"request validation failed","details":{"errors":[{"type":"datetime_from_date_parsing"}]}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("request validation failed (datetime_from_date_parsing)")
        );
    }
}
