use std::collections::BTreeMap;

use reqwest::{
    blocking::{Client, Response},
    header::IF_MATCH,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    cli::{wire, UserAddArgs, UserCommand, UserListArgs, UserPermissionsCommand},
    config::ResolvedConfig,
    console::{
        console_session, fetch_json, read_empty_response, read_etag_only, read_json_response,
        read_with_etag, validate_uuid,
    },
    exit::ExitStatus,
    session::Session,
    style,
};

#[derive(Debug, Deserialize)]
struct UserListPage {
    items: Vec<User>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct User {
    id: String,
    email: String,
    name: String,
    entity: EntityRef,
    permissions: Vec<String>,
    profiles: Vec<ProfileRef>,
    state: String,
    deactivated_at: Option<String>,
    last_login_at: Option<String>,
    created_at: String,
    deleted_at: Option<String>,

    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct EntityRef {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProfileRef {
    id: String,
    name: String,
}

#[derive(Debug)]
struct UserWithEtag {
    user: User,
    etag: String,
}

#[derive(Debug, Deserialize)]
struct PermissionSet {
    user_id: String,
    permissions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PermissionGrantOutput<'a> {
    user_id: &'a str,
    granted: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PermissionRevokeOutput<'a> {
    user_id: &'a str,
    revoked: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UserEraseOutput<'a> {
    user_id: &'a str,
    state: &'static str,
}

pub fn run(command: UserCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        UserCommand::Add(args) => add(config, args, json),
        UserCommand::List(args) => list(config, args, json),
        UserCommand::Show { user_id } => show(config, &user_id, json),
        UserCommand::Deactivate { user_id } => lifecycle(config, &user_id, "deactivate", json),
        UserCommand::Reactivate { user_id } => lifecycle(config, &user_id, "reactivate", json),
        UserCommand::Erase { user_id } => erase(config, &user_id, json),
        UserCommand::Permissions(command) => permissions(config, command, json),
    }
}

fn add(config: &ResolvedConfig, args: UserAddArgs, json_output: bool) -> ExitStatus {
    let name = match args.name {
        Some(name) => name,
        None => match derived_name(&args.email) {
            Ok(value) => value.to_string(),
            Err(message) => {
                crate::style::eprintln_error(&message);
                return ExitStatus::Usage;
            }
        },
    };
    if let Err(message) = validate_email(&args.email) {
        crate::style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    let profile_ids = match profile_flags(config) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    if let Some(entity_id) = &args.entity {
        if let Err(message) = validate_uuid("--entity", entity_id) {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let target_entity_id = match target_entity_id(args.entity.as_ref(), &session.entity.id) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let created = match create_user(
        console_url,
        &session.access_token,
        &target_entity_id,
        &args.email,
        &name,
        &args.permissions,
    ) {
        Ok(value) => value.user,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    for profile_id in &profile_ids {
        let profile_etag = match fetch_profile_etag(console_url, &session.access_token, profile_id)
        {
            Ok(value) => value,
            Err((status, message)) => {
                crate::style::eprintln_error(&message);
                return status;
            }
        };
        if let Err((status, message)) = assign_profile_member(
            console_url,
            &session.access_token,
            profile_id,
            &profile_etag,
            &created.id,
        ) {
            crate::style::eprintln_error(&message);
            return status;
        }
    }
    let output = if profile_ids.is_empty() {
        created
    } else {
        match fetch_user_with_etag(console_url, &session, &target_entity_id, &created.id) {
            Ok(value) => value.user,
            Err((status, message)) => {
                crate::style::eprintln_error(&message);
                return status;
            }
        }
    };
    print_user_add(&output, json_output);
    ExitStatus::Ok
}

fn list(config: &ResolvedConfig, args: UserListArgs, json_output: bool) -> ExitStatus {
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    // Build the query string `?status=..&assigned=..` from --status and
    // --assigned. The Console does the filtering, not the CLI.
    let query = args.query_params();
    let path = format!("/api/v1/entities/{}/users", session.entity.id);
    let page: UserListPage = match fetch_json(console_url, &session, &path, &query, "list users") {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let status_filter = args.status.map(wire);
    let assigned_filter = args.assigned.map(wire);
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&page.items).expect("user list output serializes")
        );
    } else {
        let views: Vec<style::UserView<'_>> = page
            .items
            .iter()
            .map(|user| style::UserView {
                id: &user.id,
                email: &user.email,
                state: &user.state,
                permissions: &user.permissions,
                profile_names: user.profiles.iter().map(|p| p.name.clone()).collect(),
                created_at: &user.created_at,
                extra: &user.extra,
            })
            .collect();
        let filter = style::UserListFilter {
            status: status_filter,
            assigned: assigned_filter,
        };
        println!("{}", style::user_list_cards(&views, &filter));
        if let Some(cursor) = page.next_cursor {
            eprintln!("{}", style::next_cursor_diagnostic(&cursor));
        }
    }
    ExitStatus::Ok
}

impl UserListArgs {
    fn query_params(&self) -> Vec<(&'static str, String)> {
        let mut query: Vec<(&'static str, String)> = Vec::new();
        // Each flag is sent only when set; absent flags are omitted so the
        // Console keeps its defaults (all non-erased users, any membership).
        if let Some(status) = self.status {
            query.push(("status", wire(status)));
        }
        if let Some(assigned) = self.assigned {
            query.push(("assigned", wire(assigned)));
        }
        query
    }
}

fn show(config: &ResolvedConfig, user_id: &str, json_output: bool) -> ExitStatus {
    if let Err(message) = validate_uuid("USER_ID", user_id) {
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
    let user = match fetch_user_with_etag(console_url, &session, &session.entity.id, user_id) {
        Ok(value) => value.user,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    print_user(&user, json_output);
    ExitStatus::Ok
}

fn lifecycle(
    config: &ResolvedConfig,
    user_id: &str,
    action: &str,
    json_output: bool,
) -> ExitStatus {
    if let Err(message) = validate_uuid("USER_ID", user_id) {
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
    let user = match post_user_action(console_url, &session, user_id, action) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&user).expect("user lifecycle output serializes")
        );
    } else {
        // Section 7.25 mutation confirm: verb = `<action>d` (deactivated /
        // reactivated), identifier = email, detail rows = user id / state.
        let confirm = style::ConfirmBlock::new(format!("{action}d"), "user", user.email.clone())
            .field("id", user.id.clone())
            .field("state", user.state.clone());
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn erase(config: &ResolvedConfig, user_id: &str, json_output: bool) -> ExitStatus {
    if let Err(message) = validate_uuid("USER_ID", user_id) {
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
    if let Err((status, message)) = delete_user(console_url, &session, user_id) {
        crate::style::eprintln_error(&message);
        return status;
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&UserEraseOutput {
                user_id,
                state: "erased",
            })
            .expect("user erase output serializes")
        );
    } else {
        // Section 7.25 mutation confirm: erase is irreversible and emits a
        // single-line block (no detail rows; we do not have the user's email
        // post-deletion).
        let confirm = style::ConfirmBlock::new("erased", "user", user_id);
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn permissions(
    config: &ResolvedConfig,
    command: UserPermissionsCommand,
    json_output: bool,
) -> ExitStatus {
    match command {
        UserPermissionsCommand::List { user_id } => permissions_list(config, &user_id, json_output),
        UserPermissionsCommand::Grant {
            user_id,
            permissions,
        } => permissions_grant(config, &user_id, permissions, json_output),
        UserPermissionsCommand::Revoke {
            user_id,
            permissions,
        } => permissions_revoke(config, &user_id, permissions, json_output),
    }
}

fn permissions_list(config: &ResolvedConfig, user_id: &str, json_output: bool) -> ExitStatus {
    if let Err(message) = validate_uuid("USER_ID", user_id) {
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
    let user = match fetch_user_with_etag(console_url, &session, &session.entity.id, user_id) {
        Ok(value) => value.user,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&user.permissions)
                .expect("permission list output serializes")
        );
    } else {
        println!("{}", style::user_permissions_list(&user.permissions));
    }
    ExitStatus::Ok
}

fn permissions_grant(
    config: &ResolvedConfig,
    user_id: &str,
    permissions: Vec<String>,
    json_output: bool,
) -> ExitStatus {
    if let Err(message) = validate_uuid("USER_ID", user_id) {
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
    let user = match fetch_user_with_etag(console_url, &session, &session.entity.id, user_id) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let result = match grant_permissions(
        console_url,
        &session.access_token,
        user_id,
        &user.etag,
        &permissions,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&PermissionGrantOutput {
                user_id: &result.user_id,
                granted: permissions,
            })
            .expect("permission grant output serializes")
        );
    } else {
        let confirm = style::ConfirmBlock::new("granted", "permission", result.user_id.clone())
            .field("permissions", permissions_join(&result.permissions));
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn permissions_revoke(
    config: &ResolvedConfig,
    user_id: &str,
    permissions: Vec<String>,
    json_output: bool,
) -> ExitStatus {
    if let Err(message) = validate_uuid("USER_ID", user_id) {
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
    for permission in &permissions {
        let user = match fetch_user_with_etag(console_url, &session, &session.entity.id, user_id) {
            Ok(value) => value,
            Err((status, message)) => {
                crate::style::eprintln_error(&message);
                return status;
            }
        };
        if let Err((status, message)) = revoke_permission(
            console_url,
            &session.access_token,
            user_id,
            &user.etag,
            permission,
        ) {
            crate::style::eprintln_error(&message);
            return status;
        }
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&PermissionRevokeOutput {
                user_id,
                revoked: permissions.clone(),
            })
            .expect("permission revoke output serializes")
        );
    } else {
        let confirm = style::ConfirmBlock::new("revoked", "permission", user_id)
            .field("permissions", permissions_join(&permissions));
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn fetch_user_with_etag(
    console_url: &str,
    session: &Session,
    entity_id: &str,
    user_id: &str,
) -> Result<UserWithEtag, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!(
            "{console_url}/api/v1/entities/{entity_id}/users/{user_id}"
        ))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch user: {err}"),
            )
        })?;
    read_user_with_etag(response, "fetch user")
}

fn create_user(
    console_url: &str,
    access_token: &str,
    entity_id: &str,
    email: &str,
    name: &str,
    permissions: &[String],
) -> Result<UserWithEtag, (ExitStatus, String)> {
    let response = Client::new()
        .post(format!("{console_url}/api/v1/entities/{entity_id}/users"))
        .bearer_auth(access_token)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(&json!({ "email": email, "name": name, "permissions": permissions }))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to add user: {err}"),
            )
        })?;
    read_user_with_etag(response, "add user")
}

fn post_user_action(
    console_url: &str,
    session: &Session,
    user_id: &str,
    action: &str,
) -> Result<User, (ExitStatus, String)> {
    let response = Client::new()
        .post(format!(
            "{console_url}/api/v1/entities/{}/users/{user_id}/actions/{action}",
            session.entity.id
        ))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to {action} user: {err}"),
            )
        })?;
    read_json_response(response, action)
}

fn delete_user(
    console_url: &str,
    session: &Session,
    user_id: &str,
) -> Result<(), (ExitStatus, String)> {
    let response = Client::new()
        .delete(format!(
            "{console_url}/api/v1/entities/{}/users/{user_id}",
            session.entity.id
        ))
        .bearer_auth(&session.access_token)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to erase user: {err}"),
            )
        })?;
    read_empty_response(response, "erase user")
}

fn fetch_profile_etag(
    console_url: &str,
    access_token: &str,
    profile_id: &str,
) -> Result<String, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/profiles/{profile_id}"))
        .bearer_auth(access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch profile: {err}"),
            )
        })?;
    read_etag_response(response, "fetch profile")
}

fn assign_profile_member(
    console_url: &str,
    access_token: &str,
    profile_id: &str,
    etag: &str,
    user_id: &str,
) -> Result<(), (ExitStatus, String)> {
    let response = Client::new()
        .post(format!("{console_url}/api/v1/profiles/{profile_id}/users"))
        .bearer_auth(access_token)
        .header(IF_MATCH, etag)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(&json!({ "user_id": user_id }))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to assign profile: {err}"),
            )
        })?;
    read_empty_response(response, "assign profile")
}

fn grant_permissions(
    console_url: &str,
    access_token: &str,
    user_id: &str,
    etag: &str,
    permissions: &[String],
) -> Result<PermissionSet, (ExitStatus, String)> {
    let response = Client::new()
        .post(format!("{console_url}/api/v1/users/{user_id}/permissions"))
        .bearer_auth(access_token)
        .header(IF_MATCH, etag)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(&json!({ "permissions": permissions }))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to grant permissions: {err}"),
            )
        })?;
    read_json_response(response, "grant permissions")
}

fn revoke_permission(
    console_url: &str,
    access_token: &str,
    user_id: &str,
    etag: &str,
    permission: &str,
) -> Result<(), (ExitStatus, String)> {
    let response = Client::new()
        .delete(format!(
            "{console_url}/api/v1/users/{user_id}/permissions/{permission}"
        ))
        .bearer_auth(access_token)
        .header(IF_MATCH, etag)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to revoke permission: {err}"),
            )
        })?;
    read_empty_response(response, "revoke permission")
}

fn read_user_with_etag(
    response: Response,
    action: &str,
) -> Result<UserWithEtag, (ExitStatus, String)> {
    let (user, etag) = read_with_etag::<User>(response, action)?;
    Ok(UserWithEtag { user, etag })
}

fn read_etag_response(response: Response, action: &str) -> Result<String, (ExitStatus, String)> {
    read_etag_only(response, action)
}

fn target_entity_id(
    entity_arg: Option<&String>,
    session_entity_id: &str,
) -> Result<String, String> {
    match entity_arg {
        Some(entity_id) => {
            validate_uuid("--entity", entity_id)?;
            Ok(entity_id.clone())
        }
        None => Ok(session_entity_id.to_string()),
    }
}

fn validate_email(value: &str) -> Result<(), String> {
    let (local, domain) = value
        .split_once('@')
        .ok_or_else(|| "[usage] EMAIL must contain @".to_string())?;
    if local.is_empty() || domain.is_empty() || domain.contains('@') {
        return Err("[usage] EMAIL must be a valid email address".to_string());
    }
    Ok(())
}

fn derived_name(email: &str) -> Result<&str, String> {
    let (local, _) = email
        .split_once('@')
        .ok_or_else(|| "[usage] EMAIL must contain @".to_string())?;
    if local.is_empty() {
        return Err("[usage] EMAIL must have a non-empty local part".to_string());
    }
    Ok(local)
}

fn profile_flags(config: &ResolvedConfig) -> Result<Vec<String>, String> {
    for profile_id in &config.profile_flags {
        Uuid::parse_str(profile_id).map_err(|_| "[usage] --profile must be a UUID".to_string())?;
    }
    Ok(config.profile_flags.clone())
}

fn permissions_join(permissions: &[String]) -> String {
    if permissions.is_empty() {
        "-".to_string()
    } else {
        permissions.join(",")
    }
}

fn print_user_add(user: &User, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(user).expect("user add output serializes")
        );
    } else {
        // Section 7.25 mutation confirm: identifier = email, detail rows =
        // user id / state.
        let confirm = style::ConfirmBlock::new("added", "user", user.email.clone())
            .field("id", user.id.clone())
            .field("state", user.state.clone());
        println!("{}", style::render_confirm(&confirm));
    }
}

fn print_user(user: &User, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(user).expect("user output serializes")
        );
        return;
    }
    let profiles: Vec<(String, String)> = user
        .profiles
        .iter()
        .map(|p| (p.id.clone(), p.name.clone()))
        .collect();
    let view = style::UserShowView {
        id: &user.id,
        email: &user.email,
        name: &user.name,
        entity_id: &user.entity.id,
        entity_name: &user.entity.name,
        state: &user.state,
        permissions: &user.permissions,
        profiles,
        last_login_at: user.last_login_at.as_deref(),
        deactivated_at: user.deactivated_at.as_deref(),
        created_at: &user.created_at,
        deleted_at: user.deleted_at.as_deref(),
        extra: &user.extra,
    };
    println!("{}", style::user_show_card(&view));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Assigned, UserStatus};

    #[test]
    fn user_list_query_params_maps_status_and_assigned_flags() {
        // Absent flags are omitted; present flags appear as `status` then
        // `assigned`, each carrying clap's lowercase value.
        let cases = [
            (None, None, vec![]),
            (
                Some(UserStatus::Deactivated),
                None,
                vec![("status", "deactivated".to_string())],
            ),
            (
                None,
                Some(Assigned::No),
                vec![("assigned", "no".to_string())],
            ),
            (
                Some(UserStatus::Erased),
                Some(Assigned::Yes),
                vec![
                    ("status", "erased".to_string()),
                    ("assigned", "yes".to_string()),
                ],
            ),
        ];
        for (status, assigned, expected) in cases {
            assert_eq!(UserListArgs { status, assigned }.query_params(), expected);
        }
    }

    #[test]
    fn derived_name_uses_email_local_part() {
        assert_eq!(
            derived_name("jane.doe@example.com").as_deref(),
            Ok("jane.doe")
        );
    }

    #[test]
    fn validate_email_rejects_missing_domain() {
        assert_eq!(
            validate_email("jane@").expect_err("missing domain is rejected"),
            "[usage] EMAIL must be a valid email address"
        );
    }

    #[test]
    fn target_entity_id_defaults_to_session_entity() {
        assert_eq!(
            target_entity_id(None, "00000000-0000-4000-8000-000000000001").as_deref(),
            Ok("00000000-0000-4000-8000-000000000001")
        );
    }

    #[test]
    fn target_entity_id_accepts_entity_override() {
        let entity_id = "00000000-0000-4000-8000-000000000002".to_string();

        assert_eq!(
            target_entity_id(Some(&entity_id), "00000000-0000-4000-8000-000000000001").as_deref(),
            Ok("00000000-0000-4000-8000-000000000002")
        );
    }

    #[test]
    fn target_entity_id_rejects_bad_entity_override() {
        let entity_id = "not-a-uuid".to_string();

        assert_eq!(
            target_entity_id(Some(&entity_id), "00000000-0000-4000-8000-000000000001")
                .expect_err("bad entity id is rejected"),
            "[usage] --entity must be a UUID"
        );
    }
}
