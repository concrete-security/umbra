use reqwest::blocking::{Client, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    cli::{EntityAddArgs, EntityCommand, EntityListArgs},
    commands::auth,
    config::ResolvedConfig,
    exit::ExitStatus,
};

#[derive(Debug, Deserialize)]
struct EntityListPage {
    items: Vec<Entity>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Entity {
    id: String,
    name: String,
    domain: String,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct EntityListOutput {
    entities: Vec<Entity>,
    next_cursor: Option<String>,
}

pub fn run(command: EntityCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        EntityCommand::Add(args) => add(config, args, json),
        EntityCommand::List(args) => list(config, args, json),
    }
}

fn add(config: &ResolvedConfig, args: EntityAddArgs, json_output: bool) -> ExitStatus {
    let domain = args.domain.trim().to_lowercase();
    let name = args.name.trim();
    if domain.is_empty() {
        eprintln!("[usage] DOMAIN must not be empty");
        return ExitStatus::Usage;
    }
    if name.is_empty() {
        eprintln!("[usage] --name must not be empty");
        return ExitStatus::Usage;
    }
    let (console_url, access_token) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let entity = match create_entity(console_url, &access_token, name, &domain) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    print_entity(&entity, json_output, "created");
    ExitStatus::Ok
}

fn list(config: &ResolvedConfig, args: EntityListArgs, json_output: bool) -> ExitStatus {
    if args.limit == 0 || args.limit > 500 {
        eprintln!("[usage] --limit must be between 1 and 500");
        return ExitStatus::Usage;
    }
    let (console_url, access_token) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let page = match fetch_entities(console_url, &access_token, &args) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    print_entities(page, json_output);
    ExitStatus::Ok
}

fn console_session(config: &ResolvedConfig) -> Result<(&str, String), (ExitStatus, String)> {
    let console_url = config
        .require_console_url()
        .map_err(|message| (ExitStatus::Usage, message))?;
    let session = auth::session_for_console(config)?;
    Ok((console_url, session.access_token.clone()))
}

fn create_entity(
    console_url: &str,
    access_token: &str,
    name: &str,
    domain: &str,
) -> Result<Entity, (ExitStatus, String)> {
    let response = Client::new()
        .post(format!("{console_url}/api/v1/entities"))
        .bearer_auth(access_token)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(&json!({ "name": name, "domain": domain }))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to create entity: {err}"),
            )
        })?;
    read_json_response(response, "create entity")
}

fn fetch_entities(
    console_url: &str,
    access_token: &str,
    args: &EntityListArgs,
) -> Result<EntityListPage, (ExitStatus, String)> {
    let mut query = vec![("limit", args.limit.to_string())];
    if let Some(cursor) = &args.cursor {
        query.push(("cursor", cursor.clone()));
    }
    let response = Client::new()
        .get(format!("{console_url}/api/v1/entities"))
        .bearer_auth(access_token)
        .query(&query)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to list entities: {err}"),
            )
        })?;
    read_json_response(response, "list entities")
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

fn print_entities(page: EntityListPage, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&EntityListOutput {
                entities: page.items,
                next_cursor: page.next_cursor,
            })
            .expect("entity list output serializes")
        );
    } else if page.items.is_empty() {
        println!("no entities");
    } else {
        for entity in &page.items {
            print_entity(entity, false, "entity");
        }
        if let Some(cursor) = &page.next_cursor {
            eprintln!("next cursor: {cursor}");
        }
    }
}

fn print_entity(entity: &Entity, json_output: bool, prefix: &str) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(entity).expect("entity output serializes")
        );
    } else {
        println!(
            "{prefix} {} name={} domain={} created_at={}",
            entity.id, entity.name, entity.domain, entity.created_at
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_error_message_includes_conflict_state() {
        let body = r#"{"error":{"code":"CONFLICT","message":"entity domain is already registered","details":{"state":"domain_taken"}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("entity domain is already registered (domain_taken)")
        );
    }

    #[test]
    fn console_error_message_includes_validation_type() {
        let body = r#"{"error":{"code":"VALIDATION_ERROR","message":"request validation failed","details":{"errors":[{"type":"string_too_short"}]}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("request validation failed (string_too_short)")
        );
    }
}
