use std::{
    io::{self, IsTerminal, Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{SecondsFormat, Utc};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    cli::AuthCommand,
    commands::skill,
    config::{self, ConfigSource, ResolvedConfig},
    exit::ExitStatus,
    session::{self, Entity, Session},
    style,
};

#[derive(Debug, Deserialize)]
struct DeviceStart {
    device_code: String,
    user_code: String,
    verification_url: String,
    verification_url_complete: Option<String>,
    polling_secret: String,
    expires_in: u64,
    interval: u64,
}

#[derive(Debug, Serialize)]
struct DeviceStartRequest<'a> {
    provider: &'a str,
}

#[derive(Debug, Serialize)]
struct RefreshRequest<'a> {
    refresh_token: &'a str,
}

#[derive(Debug, Serialize)]
struct LoopbackTokenRequest<'a> {
    grant_type: &'a str,
    code: &'a str,
    code_verifier: &'a str,
    redirect_uri: &'a str,
    client_id: &'a str,
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
            login_url,
            provider,
            device,
            no_browser,
        } => login(config, json, login_url, provider, device || no_browser),
        AuthCommand::Logout => logout(config, json),
        AuthCommand::Status => status(config, json),
        AuthCommand::Refresh => refresh(config, json),
        AuthCommand::Token => token(config),
    }
}

fn login(
    config: &ResolvedConfig,
    json_output: bool,
    console_url_arg: Option<String>,
    provider: Option<String>,
    device: bool,
) -> ExitStatus {
    let provider = provider.unwrap_or_else(|| config.oidc_provider.clone());
    if provider != "google" {
        crate::style::eprintln_error(&format!("[usage] unsupported OIDC provider: {provider}"));
        return ExitStatus::Usage;
    }
    let console_url_value = match selected_console_url(config, console_url_arg.as_deref()) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let console_url = console_url_value.as_str();
    let persist_console_url =
        console_url_arg.is_some() || config.console_url_source == ConfigSource::Flag;
    let client = Client::new();
    if !device {
        return match loopback_login(
            &client,
            config,
            console_url,
            persist_console_url,
            json_output,
        ) {
            Ok(()) => {
                maybe_offer_skill(config, json_output);
                ExitStatus::Ok
            }
            Err((status, message)) => {
                crate::style::eprintln_error(&message);
                status
            }
        };
    }
    let start = match device_start(&client, console_url, &provider) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    // Section 7.18 device-flow prompts: emit through the Layer 2 helper so
    // the activation rules (no ANSI when colors are off) apply.
    eprintln!(
        "{}",
        style::info_line(&format!(
            "Open this URL to authenticate: {}",
            start.verification_url
        ))
    );
    eprintln!(
        "{}",
        style::info_line(&format!("Enter code: {}", start.user_code))
    );
    if let Some(verification_url_complete) = start
        .verification_url_complete
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        eprintln!(
            "{}",
            style::info_line(&format!("Complete URL: {verification_url_complete}"))
        );
    }
    eprintln!(
        "{}",
        style::info_line(&format!(
            "Code expires in {} seconds; approve before it expires.",
            start.expires_in
        ))
    );

    let token_pair = match poll_device(&client, console_url, &start) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    match complete_login(
        &client,
        console_url,
        &config.config_dir,
        persist_console_url,
        token_pair,
        json_output,
        None,
    ) {
        Ok(()) => {
            maybe_offer_skill(config, json_output);
            ExitStatus::Ok
        }
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            status
        }
    }
}

fn selected_console_url(config: &ResolvedConfig, arg: Option<&str>) -> Result<String, String> {
    let value = match arg {
        Some(value) => value,
        None => config.require_console_url()?,
    };
    let value = value.trim().trim_end_matches('/');
    if value.is_empty() {
        return Err("[usage] CONSOLE_URL must not be empty".to_string());
    }
    let parsed = Url::parse(value).map_err(|err| format!("[usage] invalid CONSOLE_URL: {err}"))?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return Err("[usage] CONSOLE_URL must start with https:// or http://".to_string());
    }
    if parsed.host_str().is_none() {
        return Err("[usage] CONSOLE_URL must include a host".to_string());
    }
    Ok(value.to_string())
}

fn loopback_login(
    client: &Client,
    config: &ResolvedConfig,
    console_url: &str,
    persist_console_url: bool,
    json_output: bool,
) -> Result<(), (ExitStatus, String)> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to bind loopback callback: {err}"),
        )
    })?;
    listener.set_nonblocking(true).map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to configure loopback callback: {err}"),
        )
    })?;
    let port = listener
        .local_addr()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to read loopback callback address: {err}"),
            )
        })?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");
    let code_verifier =
        Zeroizing::new(random_urlsafe(32).map_err(|message| (ExitStatus::Error, message))?);
    let code_challenge = pkce_s256(&code_verifier);
    let state = Zeroizing::new(random_urlsafe(32).map_err(|message| (ExitStatus::Error, message))?);
    let authorize_url = authorize_url(
        console_url,
        &config.oidc_client_id,
        &redirect_uri,
        &code_challenge,
        &state,
    )
    .map_err(|message| (ExitStatus::Error, message))?;

    // Section 7.18: the loopback saga has 4 CLI-side steps. This is the
    // documented exception to the no-hardcode rule (section 6.3) -- the saga
    // never touches the Console so the CLI MUST declare the labels.
    let mut steps: Option<style::StepsRenderer> = (!json_output).then(style::new_stderr_steps);

    if let Some(s) = steps.as_mut() {
        s.observe("open_browser", style::OperationStatus::Running);
    }
    webbrowser::open(authorize_url.as_str()).map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to open browser; rerun with --device if this host is headless: {err}"),
        )
    })?;

    if let Some(s) = steps.as_mut() {
        s.observe("await_callback", style::OperationStatus::Running);
    }
    let code = Zeroizing::new(
        wait_for_loopback_code(&listener, &state, Duration::from_secs(300))
            .map_err(|message| (ExitStatus::Error, message))?,
    );

    if let Some(s) = steps.as_mut() {
        s.observe("exchange_tokens", style::OperationStatus::Running);
    }
    let token_pair = exchange_loopback_token(
        client,
        console_url,
        &code,
        &code_verifier,
        &redirect_uri,
        &config.oidc_client_id,
    )?;

    if let Some(s) = steps.as_mut() {
        s.observe("fetch_profile", style::OperationStatus::Running);
    }
    complete_login(
        client,
        console_url,
        &config.config_dir,
        persist_console_url,
        token_pair,
        json_output,
        steps,
    )
}

fn authorize_url(
    console_url: &str,
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    state: &str,
) -> Result<Url, String> {
    let mut url = Url::parse(&format!("{console_url}/api/v1/auth/authorize"))
        .map_err(|err| format!("[error] invalid console_url: {err}"))?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("code_challenge", code_challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", state)
        .append_pair("scope", "openid email profile");
    Ok(url)
}

fn exchange_loopback_token(
    client: &Client,
    console_url: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
    client_id: &str,
) -> Result<TokenPair, (ExitStatus, String)> {
    let response = client
        .post(format!("{console_url}/api/v1/auth/token"))
        .json(&LoopbackTokenRequest {
            grant_type: "authorization_code",
            code,
            code_verifier,
            redirect_uri,
            client_id,
        })
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to exchange authorization code: {err}"),
            )
        })?;
    if !response.status().is_success() {
        let status = response.status();
        let error = response.json::<OAuthError>().ok().map(|body| body.error);
        return Err((
            ExitStatus::Error,
            match error {
                Some(value) => format!("[error] authorization code exchange failed: {value}"),
                None => format!("[error] authorization code exchange failed: HTTP {status}"),
            },
        ));
    }
    response.json::<TokenPair>().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] malformed token response: {err}"),
        )
    })
}

fn wait_for_loopback_code(
    listener: &TcpListener,
    expected_state: &str,
    timeout: Duration,
) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((mut stream, _)) => return handle_loopback_callback(&mut stream, expected_state),
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err("[error] loopback authentication timed out".to_string());
                }
                thread::sleep(Duration::from_millis(50));
            }
            Err(err) => return Err(format!("[error] loopback callback failed: {err}")),
        }
    }
}

fn handle_loopback_callback(
    stream: &mut TcpStream,
    expected_state: &str,
) -> Result<String, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|err| format!("[error] failed to configure loopback callback: {err}"))?;
    let mut buffer = [0_u8; 8192];
    let bytes = stream
        .read(&mut buffer)
        .map_err(|err| format!("[error] failed to read loopback callback: {err}"))?;
    let request = std::str::from_utf8(&buffer[..bytes])
        .map_err(|_| "[error] loopback callback was not valid UTF-8".to_string())?;
    let result = parse_loopback_request(request, expected_state);
    let response = if result.is_ok() {
        loopback_response(
            "200 OK",
            "Authentication complete. Return to the Concrete CLI.",
        )
    } else {
        loopback_response(
            "400 Bad Request",
            "Authentication failed. Return to the CLI.",
        )
    };
    stream
        .write_all(response.as_bytes())
        .map_err(|err| format!("[error] failed to write loopback callback response: {err}"))?;
    result
}

fn parse_loopback_request(request: &str, expected_state: &str) -> Result<String, String> {
    let request_line = request
        .lines()
        .next()
        .ok_or_else(|| "[error] loopback callback was empty".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "[error] loopback callback method was missing".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "[error] loopback callback target was missing".to_string())?;
    if method != "GET" {
        return Err("[error] loopback callback used an unexpected method".to_string());
    }
    parse_loopback_target(target, expected_state)
}

fn parse_loopback_target(target: &str, expected_state: &str) -> Result<String, String> {
    let url = if target.starts_with("http://") || target.starts_with("https://") {
        Url::parse(target)
    } else {
        Url::parse(&format!("http://127.0.0.1{target}"))
    }
    .map_err(|_| "[error] loopback callback URL was malformed".to_string())?;
    if url.path() != "/callback" {
        return Err("[error] loopback callback used an unexpected path".to_string());
    }
    let mut code = None;
    let mut state = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "code" => code = Some(value.into_owned()),
            "state" => state = Some(value.into_owned()),
            _ => {}
        }
    }
    if state.as_deref() != Some(expected_state) {
        return Err("[error] loopback callback state did not match".to_string());
    }
    code.filter(|value| !value.is_empty())
        .ok_or_else(|| "[error] loopback callback did not include a code".to_string())
}

fn loopback_response(status: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\ncontent-type: text/plain; charset=utf-8\r\ncache-control: no-store\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn random_urlsafe(byte_len: usize) -> Result<String, String> {
    let mut bytes = Zeroizing::new(vec![0_u8; byte_len]);
    getrandom::fill(bytes.as_mut_slice())
        .map_err(|err| format!("[error] failed to generate random auth token: {err}"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes.as_slice()))
}

fn pkce_s256(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()))
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
    persist_console_url: bool,
    token_pair: TokenPair,
    json_output: bool,
    steps: Option<style::StepsRenderer>,
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
    if persist_console_url {
        config::persist_string_values(config_dir, &[("console_url", console_url.to_string())])
            .map_err(|message| (ExitStatus::Error, message))?;
    }
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
        let session_path = session::session_path(config_dir).display().to_string();
        let confirm = style::ConfirmBlock::new("signed in as", "", session.email.clone())
            .field(
                "entity",
                format!("{}  ({})", session.entity.name, session.entity.id),
            )
            .field("session", session_path)
            .field(
                "expires at",
                style::format_timestamp(&format_time(session.expires_at)),
            );
        // When the steps renderer is active, route the confirm block through
        // it so the final step transitions to `done` before the confirm prints.
        if let Some(s) = steps {
            s.finalize_success(&confirm);
        } else {
            println!("{}", style::render_confirm(&confirm));
        }
    }
    Ok(())
}

fn refresh(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    match refresh_existing_session(config) {
        Ok(session) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::json!({
                        "expires_at": format_time(session.expires_at),
                        "refresh_expires_at": session.refresh_expires_at.map(format_time),
                    })
                );
            } else {
                let confirm = style::ConfirmBlock::new("refreshed", "", "session").field(
                    "expires at",
                    style::format_timestamp(&format_time(session.expires_at)),
                );
                println!("{}", style::render_confirm(&confirm));
            }
            ExitStatus::Ok
        }
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            status
        }
    }
}

fn token(config: &ResolvedConfig) -> ExitStatus {
    let session = match load_session_or_auth_required(config) {
        Ok(session) => session,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    if session.expires_at > Utc::now() {
        println!("{}", session.access_token);
        return ExitStatus::Ok;
    }
    match refresh_existing_session(config) {
        Ok(session) => {
            println!("{}", session.access_token);
            ExitStatus::Ok
        }
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            status
        }
    }
}

pub(crate) fn session_for_console(
    config: &ResolvedConfig,
) -> Result<Session, (ExitStatus, String)> {
    let session = load_session_or_auth_required(config)?;
    if session.expires_at > Utc::now() {
        Ok(session)
    } else {
        refresh_existing_session(config)
    }
}

fn load_session_or_auth_required(config: &ResolvedConfig) -> Result<Session, (ExitStatus, String)> {
    match session::load(&config.config_dir) {
        Ok(Some(value)) => Ok(value),
        Ok(None) => Err((
            ExitStatus::AuthRequired,
            "[auth_required] no session found".to_string(),
        )),
        Err(message) => Err((ExitStatus::Error, message)),
    }
}

fn refresh_existing_session(config: &ResolvedConfig) -> Result<Session, (ExitStatus, String)> {
    let mut session = load_session_or_auth_required(config)?;
    let refresh_token = Zeroizing::new(session.refresh_token.clone().ok_or_else(|| {
        (
            ExitStatus::AuthRequired,
            "[auth_required] no refresh token stored; run concrete auth login".to_string(),
        )
    })?);
    match session.refresh_expires_at {
        Some(expires_at) if expires_at > Utc::now() => {}
        _ => {
            return Err((
                ExitStatus::AuthRequired,
                "[auth_required] refresh token expired; run concrete auth login".to_string(),
            ))
        }
    }
    let console_url = config
        .require_console_url()
        .map_err(|message| (ExitStatus::Usage, message))?;
    let client = Client::new();
    let token_pair = refresh_token_pair(&client, console_url, refresh_token.as_str())?;
    let now = Utc::now();
    session.access_token = token_pair.access_token;
    session.refresh_token = token_pair.refresh_token;
    session.expires_at = now + chrono::Duration::seconds(token_pair.expires_in);
    session.refresh_expires_at = token_pair
        .refresh_expires_in
        .map(|seconds| now + chrono::Duration::seconds(seconds));
    session::write_atomic(&config.config_dir, &session)
        .map_err(|message| (ExitStatus::Error, message))?;
    Ok(session)
}

fn refresh_token_pair(
    client: &Client,
    console_url: &str,
    refresh_token: &str,
) -> Result<TokenPair, (ExitStatus, String)> {
    let response = client
        .post(format!("{console_url}/api/v1/auth/refresh"))
        .json(&RefreshRequest { refresh_token })
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to refresh session: {err}"),
            )
        })?;
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err((
            ExitStatus::AuthRequired,
            "[auth_required] refresh token rejected; run concrete auth login".to_string(),
        ));
    }
    if !response.status().is_success() {
        return Err((
            ExitStatus::Error,
            format!(
                "[error] failed to refresh session: HTTP {}",
                response.status()
            ),
        ));
    }
    response.json::<TokenPair>().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] malformed refresh response: {err}"),
        )
    })
}

fn logout(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let session = match session::load(&config.config_dir) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    let cleared = match session::remove(&config.config_dir) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
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
        let session_path = session::session_path(&config.config_dir)
            .display()
            .to_string();
        let confirm = style::ConfirmBlock::new("signed", "", "out")
            .field("session", format!("removed: {session_path}"));
        println!("{}", style::render_confirm(&confirm));
    } else {
        let confirm = style::ConfirmBlock::new("no session", "", "");
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn status(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let session = match session::load(&config.config_dir) {
        Ok(Some(value)) => value,
        Ok(None) => {
            // Section 7.21 empty-state: when no session is loaded, the
            // renderer emits `no session` styled muted on stdout. The exit
            // code remains AuthRequired per cli.md.
            if json_output {
                println!("{}", serde_json::json!({ "session": null }));
            } else {
                // Build an empty AuthStatusView so the renderer emits the
                // `no session` literal exactly once. This keeps the
                // rendering path consolidated in style.rs.
                let view = style::AuthStatusView {
                    user_id: None,
                    user_email: None,
                    entity_id: None,
                    entity_name: None,
                    access_token_state: "missing",
                    access_token_expires_at: None,
                    refresh_token_state: "missing",
                    refresh_token_expires_at: None,
                    config_dir: "",
                    config_dir_source: "default",
                    console_url: None,
                    console_url_source: "default",
                    session_path: "",
                    session_permissions: None,
                };
                println!("{}", style::auth_status_card(&view));
            }
            return ExitStatus::AuthRequired;
        }
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    let now = Utc::now();
    let remaining = (session.expires_at - now).num_seconds();
    let access_state = if remaining > 0 { "valid" } else { "expired" };
    let refresh_state = match session.refresh_expires_at {
        Some(expires_at) if expires_at > now => "valid",
        Some(_) => "expired",
        None => "missing",
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
        let config_dir = config.config_dir.display().to_string();
        let session_path = session::session_path(&config.config_dir)
            .display()
            .to_string();
        let session_mode = session::mode_string(&config.config_dir);
        let access_expires = format_time(session.expires_at);
        let refresh_expires = session.refresh_expires_at.map(format_time);
        let view = style::AuthStatusView {
            user_id: Some(&session.user_id),
            user_email: Some(&session.email),
            entity_id: Some(&session.entity.id),
            entity_name: Some(&session.entity.name),
            access_token_state: access_state,
            access_token_expires_at: Some(&access_expires),
            refresh_token_state: refresh_state,
            refresh_token_expires_at: refresh_expires.as_deref(),
            config_dir: &config_dir,
            config_dir_source: config.config_dir_source.as_str(),
            console_url: config.console_url.as_deref(),
            console_url_source: config.console_url_source.as_str(),
            session_path: &session_path,
            session_permissions: session_mode.as_deref(),
        };
        println!("{}", style::auth_status_card(&view));
    }
    ExitStatus::Ok
}

fn format_time(value: chrono::DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// After a successful login, install the agent skill per the stored preference:
/// refresh silently when opted in, prompt once when undecided. Never prompts in
/// JSON mode or a non-interactive shell.
fn maybe_offer_skill(config: &ResolvedConfig, json_output: bool) {
    match config.skill_auto_install {
        // Opted in earlier: refresh quietly so a CLI upgrade propagates.
        Some(true) => skill::install_on_login(config, true),
        // Opted out earlier (or CONCRETE_NO_SKILL): do nothing.
        Some(false) => {}
        // Not asked yet: prompt once, but only in an interactive text session
        // with at least one agent to install for.
        None => {
            if json_output || !io::stdin().is_terminal() || !io::stderr().is_terminal() {
                return;
            }
            let agents = skill::detected_agents();
            if agents.is_empty() {
                return;
            }
            let yes = prompt_yes_no(&format!(
                "Install the Concrete skill for {}? It teaches the AI agent how to drive this CLI.",
                agents.join(", ")
            ));
            // Record the answer so the prompt never reappears.
            let _ = config::persist_string_values(
                &config.config_dir,
                &[(
                    "skill_auto_install",
                    if yes { "true" } else { "false" }.to_string(),
                )],
            );
            if yes {
                skill::install_on_login(config, false);
            }
        }
    }
}

/// Ask a yes/no question on stderr, defaulting to yes on empty input. Returns
/// false when stdin cannot be read.
fn prompt_yes_no(question: &str) -> bool {
    eprint!("{}", style::info_line(&format!("{question} [Y/n] ")));
    let _ = io::stderr().flush();
    let mut line = String::new();
    if io::stdin().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim().to_ascii_lowercase().as_str(), "" | "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_s256_matches_rfc7636_example() {
        assert_eq!(
            pkce_s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn parse_loopback_target_returns_code_for_matching_state() {
        let code = parse_loopback_target("/callback?code=console-code&state=expected", "expected")
            .expect("callback parses");

        assert_eq!(code, "console-code");
    }

    #[test]
    fn parse_loopback_target_rejects_mismatched_state() {
        let error = parse_loopback_target("/callback?code=console-code&state=wrong", "expected")
            .expect_err("state mismatch is rejected");

        assert!(error.contains("state"));
    }
}
