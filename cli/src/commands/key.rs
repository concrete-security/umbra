use std::{
    fs,
    io::{self, Read},
    path::Path,
};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use uuid::Uuid;

use crate::{
    cli::{KeyAddArgs, KeyCommand},
    commands::auth,
    config::ResolvedConfig,
    exit::ExitStatus,
};

#[derive(Debug, Deserialize)]
struct KeyListPage {
    items: Vec<ConsoleSshKey>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ConsoleSshKey {
    id: String,
    label: String,
    fingerprint: String,
    public_key: String,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct SshKeyOutput {
    id: String,
    label: String,
    fingerprint: String,
    algorithm: String,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct KeyRemoveOutput<'a> {
    key_id: &'a str,
}

pub fn run(command: KeyCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        KeyCommand::List => list(config, json),
        KeyCommand::Add(args) => add(config, args, json),
        KeyCommand::Remove { key_id } => remove(config, &key_id, json),
    }
}

fn list(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, access_token) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let page = match fetch_keys(console_url, access_token) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let keys: Vec<_> = page.items.iter().map(key_output).collect();
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&keys).expect("key list output serializes")
        );
    } else if keys.is_empty() {
        println!("no keys");
    } else {
        for key in &keys {
            println!(
                "{} {} {} {} {}",
                key.id, key.label, key.fingerprint, key.algorithm, key.created_at
            );
        }
        if let Some(cursor) = page.next_cursor {
            eprintln!("next cursor: {cursor}");
        }
    }
    ExitStatus::Ok
}

fn add(config: &ResolvedConfig, args: KeyAddArgs, json_output: bool) -> ExitStatus {
    let public_key = match read_public_key(args.file.as_deref()) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Error;
        }
    };
    let (console_url, access_token) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let key = match create_key(console_url, access_token, &args.label, &public_key) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let output = key_output(&key);
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("key add output serializes")
        );
    } else {
        println!("added key {} {}", output.id, output.fingerprint);
    }
    ExitStatus::Ok
}

fn remove(config: &ResolvedConfig, key_id: &str, json_output: bool) -> ExitStatus {
    if Uuid::parse_str(key_id).is_err() {
        eprintln!("[usage] KEY_ID must be a UUID");
        return ExitStatus::Usage;
    }
    let (console_url, access_token) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if let Err((status, message)) = delete_key(console_url, access_token, key_id) {
        eprintln!("{message}");
        return status;
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&KeyRemoveOutput { key_id })
                .expect("key remove output serializes")
        );
    } else {
        println!("removed key {key_id}");
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

fn fetch_keys(
    console_url: &str,
    access_token: String,
) -> Result<KeyListPage, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/me/keys"))
        .bearer_auth(access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to list SSH keys: {err}"),
            )
        })?;
    read_json_response(response, "list SSH keys")
}

fn create_key(
    console_url: &str,
    access_token: String,
    label: &str,
    public_key: &str,
) -> Result<ConsoleSshKey, (ExitStatus, String)> {
    let response = Client::new()
        .post(format!("{console_url}/api/v1/me/keys"))
        .bearer_auth(access_token)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(&json!({ "label": label, "public_key": public_key }))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to add SSH key: {err}"),
            )
        })?;
    read_json_response(response, "add SSH key")
}

fn delete_key(
    console_url: &str,
    access_token: String,
    key_id: &str,
) -> Result<(), (ExitStatus, String)> {
    let response = Client::new()
        .delete(format!("{console_url}/api/v1/me/keys/{key_id}"))
        .bearer_auth(access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to remove SSH key: {err}"),
            )
        })?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(());
    }
    Err(error_for_response(response, "remove SSH key"))
}

fn read_json_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::blocking::Response,
    action: &str,
) -> Result<T, (ExitStatus, String)> {
    if !response.status().is_success() {
        return Err(error_for_response(response, action));
    }
    let body = response.text().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to read {action} response: {err}"),
        )
    })?;
    serde_json::from_str(&body).map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] malformed {action} response: {err}"),
        )
    })
}

fn error_for_response(response: reqwest::blocking::Response, action: &str) -> (ExitStatus, String) {
    let status = response.status();
    let exit = if status == reqwest::StatusCode::UNAUTHORIZED {
        ExitStatus::AuthRequired
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
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let error = value.get("error")?;
    let message = error.get("message")?.as_str()?;
    let code = error.get("code").and_then(|value| value.as_str());
    Some(match code {
        Some(code) if code != "UNAUTHORIZED" && code != "VALIDATION_ERROR" => {
            format!("{message} ({code})")
        }
        _ => message.to_string(),
    })
}

fn read_public_key(path: Option<&Path>) -> Result<String, String> {
    let mut value = String::new();
    if let Some(path) = path {
        value = fs::read_to_string(path)
            .map_err(|err| format!("[error] failed to read public key file: {err}"))?;
    } else {
        io::stdin()
            .read_to_string(&mut value)
            .map_err(|err| format!("[error] failed to read public key from stdin: {err}"))?;
    }
    let value = value.trim();
    if value.is_empty() {
        return Err("[error] public key is empty".to_string());
    }
    Ok(value.to_string())
}

fn key_output(key: &ConsoleSshKey) -> SshKeyOutput {
    SshKeyOutput {
        id: key.id.clone(),
        label: key.label.clone(),
        fingerprint: key.fingerprint.clone(),
        algorithm: ssh_key_algorithm(&key.public_key).to_string(),
        created_at: key.created_at.clone(),
    }
}

fn ssh_key_algorithm(public_key: &str) -> &str {
    public_key.split_whitespace().next().unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssh_key_algorithm_uses_openssh_prefix() {
        assert_eq!(
            ssh_key_algorithm("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest user@example"),
            "ssh-ed25519"
        );
    }

    #[test]
    fn console_error_message_uses_error_envelope_message() {
        let body = r#"{"error":{"code":"VALIDATION_ERROR","message":"malformed public key"}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("malformed public key")
        );
    }
}
