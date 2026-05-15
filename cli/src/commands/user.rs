use reqwest::{
    blocking::{Client, Response},
    header::{ETAG, IF_MATCH},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    cli::{UserAddArgs, UserCommand, UserPermissionsCommand},
    commands::auth,
    config::ResolvedConfig,
    exit::ExitStatus,
    session::Session,
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
        UserCommand::List => list(config, json),
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
                eprintln!("{message}");
                return ExitStatus::Usage;
            }
        },
    };
    if let Err(message) = validate_email(&args.email) {
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let profile_ids = match profile_flags(config) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Usage;
        }
    };
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let created = match create_user(console_url, &session, &args.email, &name, &args.permissions) {
        Ok(value) => value.user,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    for profile_id in &profile_ids {
        let profile_etag = match fetch_profile_etag(console_url, &session.access_token, profile_id)
        {
            Ok(value) => value,
            Err((status, message)) => {
                eprintln!("{message}");
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
            eprintln!("{message}");
            return status;
        }
    }
    let output = if profile_ids.is_empty() {
        created
    } else {
        match fetch_user_with_etag(console_url, &session, &created.id) {
            Ok(value) => value.user,
            Err((status, message)) => {
                eprintln!("{message}");
                return status;
            }
        }
    };
    print_user_add(&output, json_output);
    ExitStatus::Ok
}

fn list(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let page = match fetch_users(console_url, &session) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&page.items).expect("user list output serializes")
        );
    } else if page.items.is_empty() {
        println!("no users");
    } else {
        for user in &page.items {
            println!(
                "{} {} state={} permissions={} profiles={} created_at={}",
                user.id,
                user.email,
                user.state,
                user.permissions.join(","),
                user.profiles
                    .iter()
                    .map(|profile| profile.name.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                user.created_at
            );
        }
        if let Some(cursor) = page.next_cursor {
            eprintln!("next cursor: {cursor}");
        }
    }
    ExitStatus::Ok
}

fn show(config: &ResolvedConfig, user_id: &str, json_output: bool) -> ExitStatus {
    if let Err(message) = validate_uuid("USER_ID", user_id) {
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let user = match fetch_user_with_etag(console_url, &session, user_id) {
        Ok(value) => value.user,
        Err((status, message)) => {
            eprintln!("{message}");
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
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let user = match post_user_action(console_url, &session, user_id, action) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&user).expect("user lifecycle output serializes")
        );
    } else {
        println!("{action}d user {} state={}", user.id, user.state);
    }
    ExitStatus::Ok
}

fn erase(config: &ResolvedConfig, user_id: &str, json_output: bool) -> ExitStatus {
    if let Err(message) = validate_uuid("USER_ID", user_id) {
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if let Err((status, message)) = delete_user(console_url, &session, user_id) {
        eprintln!("{message}");
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
        println!("erased user {user_id}");
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
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let user = match fetch_user_with_etag(console_url, &session, user_id) {
        Ok(value) => value.user,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&user.permissions)
                .expect("permission list output serializes")
        );
    } else if user.permissions.is_empty() {
        println!("no permissions");
    } else {
        for permission in user.permissions {
            println!("{permission}");
        }
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
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let user = match fetch_user_with_etag(console_url, &session, user_id) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
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
            eprintln!("{message}");
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
        println!(
            "granted user {} permissions={}",
            result.user_id,
            permissions_join(&result.permissions)
        );
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
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    for permission in &permissions {
        let user = match fetch_user_with_etag(console_url, &session, user_id) {
            Ok(value) => value,
            Err((status, message)) => {
                eprintln!("{message}");
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
            eprintln!("{message}");
            return status;
        }
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&PermissionRevokeOutput {
                user_id,
                revoked: permissions,
            })
            .expect("permission revoke output serializes")
        );
    } else {
        println!(
            "revoked user {user_id} permissions={}",
            permissions_join(&permissions)
        );
    }
    ExitStatus::Ok
}

fn console_session(config: &ResolvedConfig) -> Result<(&str, Session), (ExitStatus, String)> {
    let console_url = config
        .require_console_url()
        .map_err(|message| (ExitStatus::Usage, message))?;
    let session = auth::session_for_console(config)?;
    Ok((console_url, session))
}

fn fetch_users(console_url: &str, session: &Session) -> Result<UserListPage, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!(
            "{console_url}/api/v1/entities/{}/users",
            session.entity.id
        ))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to list users: {err}"),
            )
        })?;
    read_json_response(response, "list users")
}

fn fetch_user_with_etag(
    console_url: &str,
    session: &Session,
    user_id: &str,
) -> Result<UserWithEtag, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!(
            "{console_url}/api/v1/entities/{}/users/{user_id}",
            session.entity.id
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
    session: &Session,
    email: &str,
    name: &str,
    permissions: &[String],
) -> Result<UserWithEtag, (ExitStatus, String)> {
    let response = Client::new()
        .post(format!(
            "{console_url}/api/v1/entities/{}/users",
            session.entity.id
        ))
        .bearer_auth(&session.access_token)
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
    if !response.status().is_success() {
        return Err(error_for_response(response, action));
    }
    let etag = response
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| {
            (
                ExitStatus::Error,
                format!("[error] {action} response did not include ETag"),
            )
        })?;
    let user = response.json::<User>().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] malformed {action} response: {err}"),
        )
    })?;
    Ok(UserWithEtag { user, etag })
}

fn read_etag_response(response: Response, action: &str) -> Result<String, (ExitStatus, String)> {
    if !response.status().is_success() {
        return Err(error_for_response(response, action));
    }
    response
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
        .ok_or_else(|| {
            (
                ExitStatus::Error,
                format!("[error] {action} response did not include ETag"),
            )
        })
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

fn read_empty_response(response: Response, action: &str) -> Result<(), (ExitStatus, String)> {
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        Ok(())
    } else {
        Err(error_for_response(response, action))
    }
}

fn error_for_response(response: Response, action: &str) -> (ExitStatus, String) {
    let status = response.status();
    let exit = if status == reqwest::StatusCode::UNAUTHORIZED {
        ExitStatus::AuthRequired
    } else if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
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
    let required = details
        .and_then(|details| details.get("required"))
        .and_then(|value| value.as_str());
    let validation_type = details
        .and_then(|details| details.get("errors"))
        .and_then(|errors| errors.as_array())
        .and_then(|errors| errors.first())
        .and_then(|error| error.get("type"))
        .and_then(|value| value.as_str());
    Some(match (state, required, validation_type, code) {
        (Some(state), _, _, _) => format!("{message} ({state})"),
        (_, Some(required), _, _) => format!("{message} ({required})"),
        (_, _, Some(validation_type), _) => format!("{message} ({validation_type})"),
        (_, _, _, Some(code)) if code != "UNAUTHORIZED" && code != "VALIDATION_ERROR" => {
            format!("{message} ({code})")
        }
        _ => message.to_string(),
    })
}

fn validate_uuid(name: &str, value: &str) -> Result<(), String> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| format!("[usage] {name} must be a UUID"))
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
        println!("added user {} {} state={}", user.id, user.email, user.state);
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
    println!("id: {}", user.id);
    println!("email: {}", user.email);
    println!("name: {}", user.name);
    println!("entity: {} {}", user.entity.id, user.entity.name);
    println!("state: {}", user.state);
    println!("permissions: {}", permissions_join(&user.permissions));
    if user.profiles.is_empty() {
        println!("profiles: []");
    } else {
        println!("profiles:");
        for profile in &user.profiles {
            println!("  {} {}", profile.id, profile.name);
        }
    }
    println!(
        "last_login_at: {}",
        user.last_login_at.as_deref().unwrap_or("-")
    );
    println!(
        "deactivated_at: {}",
        user.deactivated_at.as_deref().unwrap_or("-")
    );
    println!("created_at: {}", user.created_at);
    println!("deleted_at: {}", user.deleted_at.as_deref().unwrap_or("-"));
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn console_error_message_includes_validation_type() {
        let body = r#"{"error":{"code":"VALIDATION_ERROR","message":"email domain must match entity domain","details":{"errors":[{"type":"email_domain_mismatch","field":"email"}]}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("email domain must match entity domain (email_domain_mismatch)")
        );
    }
}
