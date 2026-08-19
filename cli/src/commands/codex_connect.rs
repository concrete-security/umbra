//! `umbra codex connect` — mint a dedicated ChatGPT OAuth grant into a
//! Console-managed rotating secret and plant the sandbox placeholder.
//!
//! The grant comes from a throwaway-`CODEX_HOME` `codex login` on the laptop
//! so no local codex install shares it; the refresh token is uploaded to the
//! Console once (request body over TLS, never argv, never logged) and the
//! Console becomes its sole refresher. The Dev CVM gets a placeholder
//! `~/.codex/auth.json` whose far-future unsigned access token keeps codex
//! from ever self-refreshing; the Security CVM swaps the bearer for the
//! freshly rotated token at egress.

use std::{env, fs, path::Path, process::Command};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{SecondsFormat, Utc};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    cli::CodexConnectArgs,
    commands::{
        connect_common::{attach_profile, AttachOutcome},
        profile::selected_profile_session,
        select_cvm, ssh,
    },
    config::ResolvedConfig,
    console::read_json_response,
    exit::ExitStatus,
    style,
};

const CHATGPT_TOKEN_URL: &str = "https://auth.openai.com/oauth/token";
const CHATGPT_CLIENT_ID: &str = "app_EMoamEEZ73f0CkXaXp7hrann";
const PLACEHOLDER_REFRESH_TOKEN: &str = "umbra-proxy-managed";
// 2100-01-01T00:00:00Z: codex refreshes only when its token's exp nears, so a
// far-future placeholder never triggers a self-refresh.
const PLACEHOLDER_EXP: u64 = 4_102_444_800;

struct ThrowawayGrant {
    refresh_token: String,
    account_id: Option<String>,
}

pub fn run_connect(
    args: CodexConnectArgs,
    config: &ResolvedConfig,
    json_output: bool,
) -> ExitStatus {
    let (console_url, session, profile_id) = match selected_profile_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let grant = match throwaway_codex_login() {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    eprintln!(
        "{}",
        style::info_line("uploading the grant; the Console becomes its sole refresher")
    );
    let managed = match configure_managed_secret(
        console_url,
        &session.access_token,
        &profile_id,
        &args.injection_id,
        &grant,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    if managed.get("rotated").and_then(Value::as_bool) != Some(true) {
        let error = managed
            .get("rotation_error")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        style::eprintln_error(&format!(
            "[error] first rotation failed ({error}); the grant was stored but is not working — re-run connect with a fresh login"
        ));
        return ExitStatus::Error;
    }
    let expires_at = managed
        .get("access_token_expires_at")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    eprintln!(
        "{}",
        style::info_line(&format!(
            "first rotation confirmed (access token expires {expires_at})"
        ))
    );

    let mut attached = false;
    let mut placeholder_planted = false;
    let mut target_cvm: Option<String> = None;
    if args.no_attach {
        eprintln!(
            "{}",
            style::info_line("placeholder + attach skipped (--no-attach)")
        );
    } else {
        match select_cvm(
            args.target.cvm_id.as_deref(),
            args.target.cvm.as_deref(),
            &[config.default_cvm.as_deref()],
            config,
        ) {
            Ok(cvm_id) => {
                match plant_placeholder_auth_json(&cvm_id, config, grant.account_id.as_deref()) {
                    Ok(()) => {
                        placeholder_planted = true;
                        eprintln!(
                            "{}",
                            style::info_line(&format!(
                                "placeholder ~/.codex/auth.json planted on CVM {cvm_id}"
                            ))
                        );
                    }
                    Err((status, message)) => {
                        style::eprintln_error(&message);
                        // Rotation already succeeded, so the grant is live and
                        // refreshing in the Console — only the box-side setup
                        // failed. Tell the operator how to finish it.
                        eprintln!(
                            "{}",
                            style::info_line(&format!(
                                "the managed grant for profile {profile_id} is active and rotating; re-run `umbra --profile {profile_id} codex connect {cvm_id}` to retry planting the placeholder and attaching"
                            ))
                        );
                        return status;
                    }
                }
                match attach_profile(console_url, &session.access_token, &cvm_id, &profile_id) {
                    Ok(AttachOutcome::Attached) => {
                        attached = true;
                        eprintln!(
                            "{}",
                            style::info_line(&format!("profile bound to CVM {cvm_id}"))
                        );
                    }
                    Ok(AttachOutcome::Forbidden) => {
                        eprintln!(
                            "{}",
                            style::info_line(&format!(
                                "attach needs CVM_MANAGE; ask an admin to run: umbra --profile {profile_id} cvm attach {cvm_id}, or launch with: umbra cvm launch --profile {profile_id}"
                            ))
                        );
                    }
                    Err((status, message)) => {
                        style::eprintln_error(&message);
                        eprintln!(
                            "{}",
                            style::info_line(&format!(
                                "the managed grant for profile {profile_id} is active and rotating, and the placeholder is planted; only the CVM attach failed — retry with `umbra --profile {profile_id} cvm attach {cvm_id}`"
                            ))
                        );
                        return status;
                    }
                }
                target_cvm = Some(cvm_id);
            }
            Err(_) => {
                eprintln!(
                    "{}",
                    style::info_line(&format!(
                        "no target CVM resolved; launch one with: umbra cvm launch --profile {profile_id} (the placeholder is planted on next connect)"
                    ))
                );
            }
        }
    }

    if json_output {
        let payload = json!({
            "profile_id": profile_id,
            "injection_id": args.injection_id,
            "rotated": true,
            "access_token_expires_at": expires_at,
            "placeholder_planted": placeholder_planted,
            "attached": attached,
            "cvm_id": target_cvm,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).expect("connect output serializes")
        );
    } else {
        println!("profile: {profile_id}");
        println!("injection: {}", args.injection_id);
        println!("rotation: ok (expires {expires_at})");
        match &target_cvm {
            Some(cvm_id) if attached => println!("attached: yes ({cvm_id})"),
            _ => println!("attached: no"),
        }
        println!(
            "placeholder: {}",
            if placeholder_planted {
                "planted"
            } else {
                "skipped"
            }
        );
    }
    ExitStatus::Ok
}

/// Best-effort shred + confirmed removal of the throwaway login dir, whose
/// `auth.json` holds the real refresh token. Returns Err (with the path) only
/// when the token file provably survives, so the caller can hard-fail rather
/// than leave a live credential on disk.
fn secure_cleanup(home: &Path) -> Result<(), String> {
    let auth = home.join("auth.json");
    if fs::remove_dir_all(home).is_ok() {
        return Ok(());
    }
    // Removal failed: overwrite the token file in place, then try again.
    if auth.exists() {
        if let Ok(len) = fs::metadata(&auth).map(|m| m.len()) {
            let _ = fs::write(&auth, vec![0u8; len as usize]);
        }
        let _ = fs::remove_file(&auth);
    }
    let _ = fs::remove_dir_all(home);
    if auth.exists() {
        return Err(auth.display().to_string());
    }
    Ok(())
}

fn throwaway_codex_login() -> Result<ThrowawayGrant, (ExitStatus, String)> {
    let home = env::temp_dir().join(format!("umbra-codex-login-{}", Uuid::new_v4()));
    // Create the dir 0700 in one step so there is no window where `codex
    // login` could write the refresh token into a world-readable directory.
    // (mkdir's 0700 mode has no group/other bits for any umask to add.)
    let create = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&home)
        }
        #[cfg(not(unix))]
        {
            fs::create_dir_all(&home)
        }
    };
    create.map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to create throwaway CODEX_HOME: {err}"),
        )
    })?;
    eprintln!(
        "{}",
        style::info_line(
            "launching `codex login` with a throwaway CODEX_HOME (approve in the browser); your regular codex setup is untouched"
        )
    );
    let login = Command::new("codex")
        .arg("login")
        .env("CODEX_HOME", &home)
        .status();
    let outcome = (|| -> Result<ThrowawayGrant, (ExitStatus, String)> {
        let status = login.map_err(|err| {
            (
                ExitStatus::Usage,
                format!("[usage] failed to run `codex login`: {err}; is codex installed locally?"),
            )
        })?;
        if !status.success() {
            return Err((
                ExitStatus::Error,
                "[error] codex login did not complete".to_string(),
            ));
        }
        let raw = fs::read_to_string(home.join("auth.json")).map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] codex login left no auth.json: {err}"),
            )
        })?;
        let parsed: Value = serde_json::from_str(&raw).map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] malformed codex auth.json: {err}"),
            )
        })?;
        let tokens = parsed.get("tokens").cloned().unwrap_or(Value::Null);
        let refresh_token = tokens
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                (
                    ExitStatus::Error,
                    "[error] codex auth.json carries no refresh token".to_string(),
                )
            })?
            .to_string();
        let account_id = tokens
            .get("account_id")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(ThrowawayGrant {
            refresh_token,
            account_id,
        })
    })();
    // The throwaway home holds the real grant; scrub it so the Console ends up
    // the only holder. If the token file provably survives, abort before the
    // grant is ever uploaded rather than leave two live copies.
    match secure_cleanup(&home) {
        Ok(()) => outcome,
        Err(path) => Err((
            ExitStatus::Error,
            format!(
                "[error] could not delete the throwaway login file at {path}; \
                 the refresh token was NOT uploaded. Delete that file manually and re-run."
            ),
        )),
    }
}

fn configure_managed_secret(
    console_url: &str,
    access_token: &str,
    profile_id: &str,
    injection_id: &str,
    grant: &ThrowawayGrant,
) -> Result<Value, (ExitStatus, String)> {
    let mut body = json!({
        "token_url": CHATGPT_TOKEN_URL,
        "client_id": CHATGPT_CLIENT_ID,
        "refresh_token": grant.refresh_token,
    });
    if let Some(account_id) = &grant.account_id {
        body["account_id"] = Value::String(account_id.clone());
    }
    let response = Client::new()
        .put(format!(
            "{console_url}/api/v1/profiles/{profile_id}/managed-secrets/{injection_id}"
        ))
        .bearer_auth(access_token)
        .json(&body)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to configure managed secret: {err}"),
            )
        })?;
    read_json_response::<Value>(response, "configure managed secret")
}

fn unsigned_jwt(payload: &str) -> String {
    format!(
        "{}.{}.unsigned",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#),
        URL_SAFE_NO_PAD.encode(payload.as_bytes()),
    )
}

fn placeholder_auth_json(account_id: Option<&str>) -> String {
    let tokens = json!({
        "id_token": unsigned_jwt("{}"),
        "access_token": unsigned_jwt(&format!(r#"{{"exp":{PLACEHOLDER_EXP}}}"#)),
        "refresh_token": PLACEHOLDER_REFRESH_TOKEN,
        "account_id": account_id,
    });
    serde_json::to_string_pretty(&json!({
        "auth_mode": "chatgpt",
        "tokens": tokens,
        "last_refresh": Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
    }))
    .expect("placeholder auth.json serializes")
}

fn plant_placeholder_auth_json(
    cvm_id: &str,
    config: &ResolvedConfig,
    account_id: Option<&str>,
) -> Result<(), (ExitStatus, String)> {
    let content = placeholder_auth_json(account_id);
    // umask before mkdir so the dir is created 0700; rm -f before the write so
    // a pre-existing auth.json's looser mode can't survive (the file is
    // recreated 0600 under the umask).
    let script = format!(
        "umask 077 && mkdir -p \"$HOME/.codex\" && rm -f \"$HOME/.codex/auth.json\" && printf '%s' {} > \"$HOME/.codex/auth.json\"",
        ssh::shell_quote(&content),
    );
    ssh::run_remote_command_capture(cvm_id, script, config).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{placeholder_auth_json, secure_cleanup, unsigned_jwt, PLACEHOLDER_REFRESH_TOKEN};

    #[test]
    fn secure_cleanup_removes_the_login_dir_and_token() {
        let home =
            std::env::temp_dir().join(format!("umbra-cleanup-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(
            home.join("auth.json"),
            b"{\"tokens\":{\"refresh_token\":\"secret\"}}",
        )
        .unwrap();

        assert!(secure_cleanup(&home).is_ok());
        assert!(!home.join("auth.json").exists());
        assert!(!home.exists());
    }

    #[test]
    fn secure_cleanup_is_ok_when_dir_already_absent() {
        let home =
            std::env::temp_dir().join(format!("umbra-cleanup-none-{}", uuid::Uuid::new_v4()));
        assert!(secure_cleanup(&home).is_ok());
    }

    #[test]
    fn unsigned_jwt_is_three_base64url_segments() {
        let token = unsigned_jwt(r#"{"exp":4102444800}"#);
        let segments: Vec<&str> = token.split('.').collect();
        assert_eq!(segments.len(), 3);
        assert!(segments.iter().all(|segment| !segment.is_empty()));
        assert!(!token.contains('='));
    }

    #[test]
    fn placeholder_auth_json_carries_no_secret_material() {
        let content = placeholder_auth_json(Some("acct-123"));
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["auth_mode"], "chatgpt");
        assert_eq!(parsed["tokens"]["refresh_token"], PLACEHOLDER_REFRESH_TOKEN);
        assert_eq!(parsed["tokens"]["account_id"], "acct-123");
        assert!(parsed["last_refresh"].as_str().unwrap().ends_with("Z"));
        // The far-future exp keeps codex from self-refreshing.
        assert!(
            content.contains("4102444800") || {
                let access = parsed["tokens"]["access_token"].as_str().unwrap();
                access.split('.').count() == 3
            }
        );
    }

    #[test]
    fn placeholder_auth_json_handles_missing_account_id() {
        let content = placeholder_auth_json(None);
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed["tokens"]["account_id"].is_null());
    }
}
