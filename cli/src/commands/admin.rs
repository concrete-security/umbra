use chrono::DateTime;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    cli::{
        AdminCommand, AdminKeysCommand, AdminKeysRotateArgs, AdminSessionsCommand,
        AdminSessionsRevokeArgs,
    },
    config::ResolvedConfig,
    console::{console_session, post_json},
    exit::ExitStatus,
    style,
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
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let output: SessionsRevokeOutput = try_or_eprintln!(post_json(
        console_url,
        &session.access_token,
        "/api/v1/admin/sessions/revoke",
        &Value::Object(body),
        "revoke sessions",
    ));
    if json_output {
        style::emit_json(&output);
    } else {
        // Confirm template for the admin sessions revoke mutation. The
        // command has no single primary identifier; the identifier slot
        // documents what was revoked.
        let confirm = style::ConfirmBlock::new("revoked", "sessions", "-")
            .field("jti", output.revoked_jti_count.to_string())
            .field(
                "refresh tokens",
                output.revoked_refresh_token_count.to_string(),
            );
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn keys_rotate(
    config: &ResolvedConfig,
    args: AdminKeysRotateArgs,
    json_output: bool,
) -> ExitStatus {
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let body = json!({
        "new_kid": args.new_kid,
        "retire_old_after_seconds": args.retire_old_after_seconds,
    });
    let output: KeysRotateOutput = try_or_eprintln!(post_json(
        console_url,
        &session.access_token,
        "/api/v1/admin/keys/rotate",
        &body,
        "rotate JWT keys",
    ));
    if json_output {
        style::emit_json(&output);
    } else {
        let retiring = if output.retiring_kids.is_empty() {
            "-".to_string()
        } else {
            output.retiring_kids.join(",")
        };
        // Confirm template for the admin keys rotate mutation. The
        // identifier slot is the newly active kid; retiring kids surface as
        // a detail row.
        let confirm = style::ConfirmBlock::new("rotated", "key", output.active_kid.clone())
            .field("retiring", retiring);
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
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
}
