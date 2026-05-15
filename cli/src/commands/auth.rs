use std::{thread, time::Duration};

use chrono::{SecondsFormat, Utc};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    cli::AuthCommand,
    config::ResolvedConfig,
    exit::ExitStatus,
    session::{self, Entity, Session},
};

#[derive(Debug, Deserialize)]
struct DeviceStart {
    device_code: String,
    user_code: String,
    verification_url: String,
    polling_secret: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, Serialize)]
struct DeviceStartRequest<'a> {
    provider: &'a str,
}

#[derive(Debug, Deserialize)]
struct TokenPair {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: i64,
    refresh_expires_in: Option<i64>,
}

#[derive(Debug, Deserialize)]
struct OAuthError {
    error: String,
}

#[derive(Debug, Deserialize)]
struct Me {
    id: String,
    email: String,
    entity: Entity,
}

#[derive(Debug, Serialize)]
struct StatusJson<'a> {
    user: StatusUser<'a>,
    entity: &'a Entity,
    config_dir: ConfigPath,
    console_url: ConfigValue<'a>,
    access_token: TokenState,
    refresh_token: RefreshState,
    session_file: SessionFile,
}

#[derive(Debug, Serialize)]
struct ConfigValue<'a> {
    value: Option<&'a str>,
    source: &'static str,
}

#[derive(Debug, Serialize)]
struct ConfigPath {
    value: String,
    source: &'static str,
}

#[derive(Debug, Serialize)]
struct StatusUser<'a> {
    id: &'a str,
    email: &'a str,
}

#[derive(Debug, Serialize)]
struct TokenState {
    state: &'static str,
    expires_at: String,
    remaining_seconds: i64,
}

#[derive(Debug, Serialize)]
struct RefreshState {
    state: &'static str,
    expires_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct SessionFile {
    path: String,
    mode: Option<String>,
}

pub fn run(command: AuthCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        AuthCommand::Login {
            provider,
            device,
            no_browser,
        } => login(config, json, provider, device || no_browser),
        AuthCommand::Logout => logout(config, json),
        AuthCommand::Status => status(config, json),
    }
}

fn login(
    config: &ResolvedConfig,
    json_output: bool,
    provider: Option<String>,
    device: bool,
) -> ExitStatus {
    let provider = provider.unwrap_or_else(|| config.oidc_provider.clone());
    if provider != "google" {
        eprintln!("[usage] unsupported OIDC provider: {provider}");
        return ExitStatus::Usage;
    }
    if !device {
        eprintln!("[usage] loopback auth login is not implemented yet; rerun with --device");
        return ExitStatus::Usage;
    }
    let console_url = match config.require_console_url() {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Usage;
        }
    };
    let client = Client::new();
    let start = match device_start(&client, console_url, &provider) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Error;
        }
    };
    eprintln!("Open this URL to authenticate: {}", start.verification_url);
    eprintln!("Enter code: {}", start.user_code);

    let token_pair = match poll_device(&client, console_url, &start) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Error;
        }
    };
    match complete_login(
        &client,
        console_url,
        &config.config_dir,
        token_pair,
        json_output,
    ) {
        Ok(()) => ExitStatus::Ok,
        Err((status, message)) => {
            eprintln!("{message}");
            status
        }
    }
}

fn device_start(client: &Client, console_url: &str, provider: &str) -> Result<DeviceStart, String> {
    let response = client
        .post(format!("{console_url}/api/v1/auth/device/start"))
        .json(&DeviceStartRequest { provider })
        .send()
        .map_err(|err| format!("[error] failed to start device login: {err}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "[error] Console rejected device login start: HTTP {}",
            response.status()
        ));
    }
    response
        .json::<DeviceStart>()
        .map_err(|err| format!("[error] malformed device login response: {err}"))
}

fn poll_device(
    client: &Client,
    console_url: &str,
    start: &DeviceStart,
) -> Result<TokenPair, String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(start.expires_in);
    let mut interval = start.interval.max(1);
    while std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_secs(interval));
        let response = client
            .post(format!("{console_url}/api/v1/auth/device/poll"))
            .json(&json!({
                "device_code": start.device_code,
                "polling_secret": start.polling_secret,
            }))
            .send()
            .map_err(|err| format!("[error] failed to poll device login: {err}"))?;

        if response.status().is_success() {
            return response
                .json::<TokenPair>()
                .map_err(|err| format!("[error] malformed token response: {err}"));
        }
        let status = response.status();
        let error = response.json::<OAuthError>().ok().map(|body| body.error);
        match error.as_deref() {
            Some("authorization_pending") => continue,
            Some("slow_down") => {
                interval += 5;
                continue;
            }
            Some("expired_token") => return Err("[error] device login expired".to_string()),
            Some("access_denied") => return Err("[error] device login was denied".to_string()),
            Some(other) => return Err(format!("[error] device login failed: {other}")),
            None => return Err(format!("[error] device login failed: HTTP {status}")),
        }
    }
    Err("[error] device login timed out".to_string())
}

fn complete_login(
    client: &Client,
    console_url: &str,
    config_dir: &std::path::Path,
    token_pair: TokenPair,
    json_output: bool,
) -> Result<(), (ExitStatus, String)> {
    let me = client
        .get(format!("{console_url}/api/v1/me"))
        .bearer_auth(&token_pair.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch session identity: {err}"),
            )
        })?;
    if me.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err((
            ExitStatus::AuthRequired,
            "[auth_required] Console rejected the issued session".to_string(),
        ));
    }
    if !me.status().is_success() {
        return Err((
            ExitStatus::Error,
            format!(
                "[error] failed to fetch session identity: HTTP {}",
                me.status()
            ),
        ));
    }
    let me = me.json::<Me>().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] malformed /me response: {err}"),
        )
    })?;
    let now = Utc::now();
    let session = Session {
        access_token: token_pair.access_token,
        refresh_token: token_pair.refresh_token,
        user_id: me.id,
        email: me.email,
        entity: me.entity,
        expires_at: now + chrono::Duration::seconds(token_pair.expires_in),
        refresh_expires_at: token_pair
            .refresh_expires_in
            .map(|seconds| now + chrono::Duration::seconds(seconds)),
    };
    session::write_atomic(config_dir, &session).map_err(|message| (ExitStatus::Error, message))?;
    if json_output {
        println!(
            "{}",
            serde_json::json!({
                "user_id": session.user_id,
                "email": session.email,
                "expires_at": format_time(session.expires_at),
            })
        );
    } else {
        println!(
            "logged in as {} until {}",
            session.email,
            format_time(session.expires_at)
        );
    }
    Ok(())
}

fn logout(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let session = match session::load(&config.config_dir) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Error;
        }
    };
    let cleared = match session::remove(&config.config_dir) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Error;
        }
    };
    if let (Some(session), Some(console_url)) = (session.as_ref(), config.console_url.as_deref()) {
        let _ = Client::new()
            .post(format!("{console_url}/api/v1/auth/logout"))
            .bearer_auth(&session.access_token)
            .json(&json!({ "refresh_token": session.refresh_token }))
            .send();
    }
    if json_output {
        println!("{}", serde_json::json!({ "cleared": cleared }));
    } else if cleared {
        println!("logged out");
    } else {
        println!("no session");
    }
    ExitStatus::Ok
}

fn status(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let session = match session::load(&config.config_dir) {
        Ok(Some(value)) => value,
        Ok(None) => {
            eprintln!("[auth_required] no session found");
            return ExitStatus::AuthRequired;
        }
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Error;
        }
    };
    let now = Utc::now();
    let remaining = (session.expires_at - now).num_seconds();
    let access_state = if remaining > 0 { "valid" } else { "expired" };
    let refresh_state = match session.refresh_expires_at {
        Some(expires_at) if expires_at > now => "available",
        Some(_) => "expired",
        None => "absent",
    };

    if json_output {
        let payload = StatusJson {
            user: StatusUser {
                id: &session.user_id,
                email: &session.email,
            },
            entity: &session.entity,
            config_dir: ConfigPath {
                value: config.config_dir.display().to_string(),
                source: config.config_dir_source.as_str(),
            },
            console_url: ConfigValue {
                value: config.console_url.as_deref(),
                source: config.console_url_source.as_str(),
            },
            access_token: TokenState {
                state: access_state,
                expires_at: format_time(session.expires_at),
                remaining_seconds: remaining,
            },
            refresh_token: RefreshState {
                state: refresh_state,
                expires_at: session.refresh_expires_at.map(format_time),
            },
            session_file: SessionFile {
                path: session::session_path(&config.config_dir)
                    .display()
                    .to_string(),
                mode: session::mode_string(&config.config_dir),
            },
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).expect("status payload serializes")
        );
    } else {
        println!("user:    {} ({})", session.email, session.user_id);
        println!("entity:  {} ({})", session.entity.name, session.entity.id);
        println!(
            "config:  {} ({})",
            config.config_dir.display(),
            config.config_dir_source.as_str()
        );
        println!(
            "console: {} ({})",
            config.console_url.as_deref().unwrap_or("<unset>"),
            config.console_url_source.as_str()
        );
        println!(
            "provider: {} ({})",
            config.oidc_provider,
            config.oidc_provider_source.as_str()
        );
        println!(
            "client_id: {} ({})",
            config.oidc_client_id,
            config.oidc_client_id_source.as_str()
        );
        println!(
            "session_file: {}{}",
            session::session_path(&config.config_dir).display(),
            session::mode_string(&config.config_dir)
                .map(|mode| format!(" ({mode})"))
                .unwrap_or_default()
        );
        println!(
            "access:  {access_state} until {}",
            format_time(session.expires_at)
        );
        println!(
            "refresh: {refresh_state}{}",
            session
                .refresh_expires_at
                .map(|value| format!(" until {}", format_time(value)))
                .unwrap_or_default()
        );
    }
    ExitStatus::Ok
}

fn format_time(value: chrono::DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}
