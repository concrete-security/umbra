use std::collections::BTreeMap;

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    cli::{QuotaClearArgs, QuotaCommand, QuotaScopeArgs, QuotaSetArgs},
    config::ResolvedConfig,
    console::{
        console_session, fetch_json, read_empty_response, read_json_response, resolve_entity_name,
        resolve_user_email, send, validate_uuid,
    },
    exit::ExitStatus,
    session::Session,
    style,
};

const ENTITY_QUOTA_RESOURCES: &[&str] = &[
    "dev_cvms",
    "ssh_keys",
    "users",
    "profiles",
    "disk_gb_per_cvm",
    "disk_gb_total",
];
const USER_QUOTA_RESOURCES: &[&str] = &["dev_cvms", "ssh_keys", "disk_gb_per_cvm", "disk_gb_total"];

#[derive(Debug)]
enum QuotaScope {
    Entity(String),
    User(String),
}

#[derive(Debug, Deserialize)]
struct QuotaList {
    quotas: Vec<Quota>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Quota {
    #[serde(default)]
    entity_id: Option<String>,
    #[serde(default)]
    user_id: Option<String>,
    resource: String,
    limit: u64,
    source: String,
    current_usage: u64,
    set_by: Option<String>,
    set_at: Option<String>,

    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize)]
struct QuotaClearOutput<'a> {
    scope: &'static str,
    scope_id: &'a str,
    resource: &'a str,
    cleared: bool,
}

pub fn run(command: QuotaCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        QuotaCommand::Get(args) => get(config, args, json),
        QuotaCommand::Set(args) => set(config, args, json),
        QuotaCommand::Clear(args) => clear(config, args, json),
    }
}

fn get(config: &ResolvedConfig, args: QuotaScopeArgs, json_output: bool) -> ExitStatus {
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let scope = match resolve_scope(&args, &session) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let quotas = try_or_eprintln!(fetch_quotas(console_url, &session, &scope)).quotas;
    print_quotas(
        &quotas,
        json_output,
        &scope,
        &session,
        console_url,
        &session.access_token,
    );
    ExitStatus::Ok
}

fn set(config: &ResolvedConfig, args: QuotaSetArgs, json_output: bool) -> ExitStatus {
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let scope = match resolve_scope(&args.scope, &session) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    if let Err(message) = validate_resource(&scope, &args.resource) {
        crate::style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    // Capture the previous limit (when present) for the confirm block's
    // `previous limit` row (section 7.24). On 404/error, simply leave it `-`.
    let previous_limit = fetch_quotas(console_url, &session, &scope)
        .ok()
        .and_then(|list| {
            list.quotas
                .into_iter()
                .find(|q| q.resource == args.resource)
                .map(|q| q.limit)
        });
    let quota = try_or_eprintln!(set_quota(
        console_url,
        &session.access_token,
        &scope,
        &args.resource,
        args.limit,
    ));
    if json_output {
        style::emit_json(&quota);
    } else {
        let (scope_noun, scope_id) = scope_parts(&scope);
        let human = match &scope {
            QuotaScope::Entity(id) => {
                resolve_entity_name(&session, console_url, &session.access_token, id)
            }
            QuotaScope::User(id) => {
                resolve_user_email(&session, console_url, &session.access_token, id)
            }
        };
        println!(
            "{}",
            style::quota_set_confirm(&style::QuotaSetConfirm {
                resource: &args.resource,
                scope_noun,
                scope_human: human.as_deref(),
                scope_id,
                limit: quota.limit,
                previous_limit,
                set_by: quota.set_by.as_deref(),
                next_step_flag: scope_noun,
            })
        );
    }
    ExitStatus::Ok
}

fn clear(config: &ResolvedConfig, args: QuotaClearArgs, json_output: bool) -> ExitStatus {
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let scope = match resolve_scope(&args.scope, &session) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    if let Err(message) = validate_resource(&scope, &args.resource) {
        crate::style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    // Capture previous limit before clearing (section 7.24 `previous limit`).
    let previous_limit = fetch_quotas(console_url, &session, &scope)
        .ok()
        .and_then(|list| {
            list.quotas
                .into_iter()
                .find(|q| q.resource == args.resource)
                .map(|q| q.limit)
        });
    if let Err((status, message)) =
        clear_quota(console_url, &session.access_token, &scope, &args.resource)
    {
        crate::style::eprintln_error(&message);
        return status;
    }
    let (scope_noun, scope_id) = scope_parts(&scope);
    if json_output {
        style::emit_json(&QuotaClearOutput {
            scope: scope_noun,
            scope_id,
            resource: &args.resource,
            cleared: true,
        });
    } else {
        let human = match &scope {
            QuotaScope::Entity(id) => {
                resolve_entity_name(&session, console_url, &session.access_token, id)
            }
            QuotaScope::User(id) => {
                resolve_user_email(&session, console_url, &session.access_token, id)
            }
        };
        println!(
            "{}",
            style::quota_clear_confirm(&style::QuotaClearConfirm {
                resource: &args.resource,
                scope_noun,
                scope_human: human.as_deref(),
                scope_id,
                previous_limit,
                next_step_flag: scope_noun,
            })
        );
    }
    ExitStatus::Ok
}

fn resolve_scope(args: &QuotaScopeArgs, session: &Session) -> Result<QuotaScope, String> {
    match (args.entity.as_deref(), args.user.as_deref()) {
        (Some(_), Some(_)) => Err("[usage] choose either --entity or --user".to_string()),
        (Some(entity_id), None) => {
            validate_uuid("--entity", entity_id)?;
            Ok(QuotaScope::Entity(entity_id.to_string()))
        }
        (None, Some(user_id)) => {
            validate_uuid("--user", user_id)?;
            Ok(QuotaScope::User(user_id.to_string()))
        }
        (None, None) => Ok(QuotaScope::Entity(session.entity.id.clone())),
    }
}

fn fetch_quotas(
    console_url: &str,
    session: &Session,
    scope: &QuotaScope,
) -> Result<QuotaList, (ExitStatus, String)> {
    let path = match scope {
        QuotaScope::Entity(entity_id) => format!("/api/v1/entities/{entity_id}/quotas"),
        QuotaScope::User(user_id) => format!("/api/v1/users/{user_id}/quotas"),
    };
    fetch_json(console_url, session, &path, &[], "get quotas")
}

fn set_quota(
    console_url: &str,
    access_token: &str,
    scope: &QuotaScope,
    resource: &str,
    limit: u64,
) -> Result<Quota, (ExitStatus, String)> {
    let url = match scope {
        QuotaScope::Entity(entity_id) => {
            format!("{console_url}/api/v1/entities/{entity_id}/quotas/{resource}")
        }
        QuotaScope::User(user_id) => {
            format!("{console_url}/api/v1/users/{user_id}/quotas/{resource}")
        }
    };
    let response = send(
        Client::new()
            .patch(url)
            .bearer_auth(access_token)
            .header("Idempotency-Key", Uuid::new_v4().to_string())
            .json(&json!({ "limit": limit })),
        "set quota",
    )?;
    read_json_response(response, "set quota")
}

fn clear_quota(
    console_url: &str,
    access_token: &str,
    scope: &QuotaScope,
    resource: &str,
) -> Result<(), (ExitStatus, String)> {
    let url = match scope {
        QuotaScope::Entity(entity_id) => {
            format!("{console_url}/api/v1/entities/{entity_id}/quotas/{resource}")
        }
        QuotaScope::User(user_id) => {
            format!("{console_url}/api/v1/users/{user_id}/quotas/{resource}")
        }
    };
    let response = send(
        Client::new().delete(url).bearer_auth(access_token),
        "clear quota",
    )?;
    read_empty_response(response, "clear quota")
}

fn validate_resource(scope: &QuotaScope, resource: &str) -> Result<(), String> {
    let valid = match scope {
        QuotaScope::Entity(_) => ENTITY_QUOTA_RESOURCES.contains(&resource),
        QuotaScope::User(_) => USER_QUOTA_RESOURCES.contains(&resource),
    };
    if valid {
        Ok(())
    } else {
        Err(format!(
            "[usage] unknown quota resource for scope: {resource}"
        ))
    }
}

fn scope_parts(scope: &QuotaScope) -> (&'static str, &str) {
    match scope {
        QuotaScope::Entity(entity_id) => ("entity", entity_id),
        QuotaScope::User(user_id) => ("user", user_id),
    }
}

fn print_quotas(
    quotas: &[Quota],
    json_output: bool,
    scope: &QuotaScope,
    session: &Session,
    console_url: &str,
    access_token: &str,
) {
    if json_output {
        style::emit_json(quotas);
        return;
    }
    let (filter_entity_id, filter_user_id) = match scope {
        QuotaScope::Entity(id) => (Some(id.clone()), None),
        QuotaScope::User(id) => (None, Some(id.clone())),
    };
    // Section 7.8: resolve the scope filter to a human-readable name when
    // possible. Session-local data first; fall back to a Console lookup; on
    // 404/403, the renderer falls back to the bare UUID.
    let (entity_name, user_email) = match scope {
        QuotaScope::Entity(id) => (
            resolve_entity_name(session, console_url, access_token, id),
            None,
        ),
        QuotaScope::User(id) => (
            None,
            resolve_user_email(session, console_url, access_token, id),
        ),
    };
    let filter = style::QuotaListFilter {
        entity_id: filter_entity_id,
        user_id: filter_user_id,
        entity_name,
        user_email,
    };
    let views: Vec<style::QuotaView<'_>> = quotas
        .iter()
        .map(|q| style::QuotaView {
            resource: &q.resource,
            entity_id: q.entity_id.as_deref(),
            entity_name: None,
            user_id: q.user_id.as_deref(),
            user_email: None,
            limit: q.limit,
            current_usage: q.current_usage,
            source: &q.source,
            set_by: q.set_by.as_deref(),
            set_at: q.set_at.as_deref(),
            extra: &q.extra,
        })
        .collect();
    println!("{}", style::quota_get_cards(&views, &filter));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_scope_rejects_entity_only_resource() {
        let err = validate_resource(&QuotaScope::User("user-1".to_string()), "profiles")
            .expect_err("profiles is entity-only");

        assert_eq!(err, "[usage] unknown quota resource for scope: profiles");
    }

    #[test]
    fn disk_resources_valid_for_both_scopes() {
        for resource in ["disk_gb_per_cvm", "disk_gb_total"] {
            validate_resource(&QuotaScope::Entity("entity-1".to_string()), resource)
                .expect("disk resource valid at entity scope");
            validate_resource(&QuotaScope::User("user-1".to_string()), resource)
                .expect("disk resource valid at user scope");
        }
    }
}
