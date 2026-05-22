use std::collections::BTreeMap;

use chrono::DateTime;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    cli::TrafficLogsArgs,
    config::ResolvedConfig,
    console::{console_session, read_json_response, validate_uuid},
    exit::ExitStatus,
    style,
};

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

    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
}

pub fn run(args: TrafficLogsArgs, config: &ResolvedConfig, json: bool) -> ExitStatus {
    if let Err(message) = validate_args(&args) {
        crate::style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let page = match fetch_traffic_logs(console_url, &session.access_token, &args) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    print_traffic_logs(page, json, &args);
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

fn print_traffic_logs(page: TrafficLogListPage, json_output: bool, args: &TrafficLogsArgs) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&TrafficLogsOutput {
                logs: page.items,
                next_cursor: page.next_cursor,
            })
            .expect("traffic log output serializes")
        );
        return;
    }
    // Section 7.6: v0 guarantees at most one SC per entity, so the renderer
    // emits a single table block; the SC value is hoisted into the Filter
    // header either from `--security-cvm` or from the constant value observed
    // across the returned rows. `limit` and `cursor` go into the Filter header
    // per section 6.2.1.
    let filter = style::TrafficLogsFilter {
        cvm: args.cvm.clone(),
        security_cvm: args.security_cvm.clone(),
        from: args.from.clone(),
        to: args.to.clone(),
        limit: Some(u32::from(args.limit)),
        cursor: args.cursor.clone(),
    };
    let views: Vec<style::TrafficLogView<'_>> = page
        .items
        .iter()
        .map(|log| style::TrafficLogView {
            timestamp: &log.timestamp,
            cvm_id: log.cvm_id.as_deref(),
            security_cvm_id: Some(log.security_cvm_id.as_str()),
            method: log.method.as_deref(),
            destination_host: log.destination_host.as_deref(),
            response_code: log.response_code,
            bytes_transferred: log.bytes_transferred,
            path: log.path.as_deref(),
            extra: &log.extra,
        })
        .collect();
    println!("{}", style::traffic_logs_table(&views, &filter));
    if let Some(cursor) = &page.next_cursor {
        eprintln!("{}", style::next_cursor_diagnostic(cursor));
    }
}

fn push_query(query: &mut Vec<(&'static str, String)>, key: &'static str, value: &Option<String>) {
    if let Some(value) = value {
        query.push((key, value.clone()));
    }
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
}
