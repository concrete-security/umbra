//! `umbra claude connect` — mint a Claude Code OAuth token into the
//! selected profile's secret injection and bind that profile to a Dev CVM.
//!
//! The token is read from stdin (never argv), travels only in the mint
//! request body over TLS, and is never logged or echoed. The Security CVM
//! injects the stored credential at egress; the sandbox only ever sees the
//! `umbra-proxy-injected` placeholder. Minting happens before any attach
//! so the Console's mint-complete gate always passes.

use std::io::{self, IsTerminal, Read};

use reqwest::blocking::Client;
use serde_json::{json, Value};

use crate::{
    cli::ClaudeConnectArgs,
    commands::{
        connect_common::{attach_profile, AttachOutcome},
        profile::selected_profile_session,
        select_cvm,
    },
    config::ResolvedConfig,
    console::read_json_response,
    exit::ExitStatus,
    style,
};

pub fn run_connect(
    args: ClaudeConnectArgs,
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
    let token = match read_token_from_stdin() {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let mint = match mint_profile_secret(
        console_url,
        &session.access_token,
        &profile_id,
        &args.injection_id,
        &token,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    eprintln!(
        "{}",
        style::info_line(&format!(
            "minted injection '{}' into profile {profile_id}",
            args.injection_id
        ))
    );

    let mut attached = false;
    let mut target_cvm: Option<String> = None;
    if args.no_attach {
        eprintln!("{}", style::info_line("attach skipped (--no-attach)"));
    } else {
        match select_cvm(
            args.target.cvm_id.as_deref(),
            args.target.cvm.as_deref(),
            &[config.default_cvm.as_deref()],
            config,
        ) {
            Ok(cvm_id) => {
                match attach_profile(console_url, &session.access_token, &cvm_id, &profile_id) {
                    Ok(AttachOutcome::Attached) => {
                        attached = true;
                        eprintln!(
                            "{}",
                            style::info_line(&format!("profile bound to CVM {cvm_id}"))
                        );
                        target_cvm = Some(cvm_id);
                    }
                    Ok(AttachOutcome::Forbidden) => {
                        eprintln!(
                            "{}",
                            style::info_line(&format!(
                                "attach needs CVM_MANAGE; ask an admin to run: umbra --profile {profile_id} cvm attach {cvm_id}, or launch with: umbra cvm launch --profile {profile_id}"
                            ))
                        );
                        target_cvm = Some(cvm_id);
                    }
                    Err((status, message)) => {
                        style::eprintln_error(&message);
                        return status;
                    }
                }
            }
            Err(_) => {
                eprintln!(
                    "{}",
                    style::info_line(&format!(
                        "no target CVM resolved; launch one with: umbra cvm launch --profile {profile_id}"
                    ))
                );
            }
        }
    }

    let minted_at = mint
        .get("minted_at")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if json_output {
        let payload = json!({
            "profile_id": profile_id,
            "injection_id": args.injection_id,
            "minted_at": minted_at,
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
        println!("minted at: {minted_at}");
        match &target_cvm {
            Some(cvm_id) if attached => println!("attached: yes ({cvm_id})"),
            _ => println!("attached: no"),
        }
    }
    ExitStatus::Ok
}

fn mint_profile_secret(
    console_url: &str,
    access_token: &str,
    profile_id: &str,
    injection_id: &str,
    token: &str,
) -> Result<Value, (ExitStatus, String)> {
    let response = Client::new()
        .post(format!(
            "{console_url}/api/v1/profiles/{profile_id}/secrets/{injection_id}"
        ))
        .bearer_auth(access_token)
        .json(&json!({ "value": token }))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to mint profile secret: {err}"),
            )
        })?;
    read_json_response::<Value>(response, "mint profile secret")
}

fn read_token_from_stdin() -> Result<String, (ExitStatus, String)> {
    let mut stdin = io::stdin();
    if stdin.is_terminal() {
        return Err((
            ExitStatus::Usage,
            "[usage] pipe the token on stdin, for example: claude setup-token | umbra claude connect"
                .to_string(),
        ));
    }
    let mut raw = String::new();
    stdin.read_to_string(&mut raw).map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to read token from stdin: {err}"),
        )
    })?;
    parse_token(&raw).map_err(|message| (ExitStatus::Usage, message))
}

fn parse_token(raw: &str) -> Result<String, String> {
    let token = raw.trim();
    if token.is_empty() {
        return Err("[usage] stdin did not contain a token".to_string());
    }
    if token.chars().any(char::is_control) {
        return Err("[usage] token must be a single line without control characters".to_string());
    }
    Ok(token.to_string())
}

#[cfg(test)]
mod tests {
    use super::parse_token;

    #[test]
    fn parse_token_trims_surrounding_whitespace() {
        assert_eq!(
            parse_token("  sk-ant-oat01-abc\n").unwrap(),
            "sk-ant-oat01-abc"
        );
    }

    #[test]
    fn parse_token_rejects_empty_input() {
        assert!(parse_token("").is_err());
        assert!(parse_token("   \n").is_err());
    }

    #[test]
    fn parse_token_rejects_multiline_or_control_input() {
        assert!(parse_token("line1\nline2").is_err());
        assert!(parse_token("tok\ten").is_err());
    }
}
