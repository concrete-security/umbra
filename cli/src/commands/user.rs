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
        read_with_etag, send, validate_uuid, ListPage,
    },
    exit::ExitStatus,
    session::Session,
    style,
};

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
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let target_entity_id = match target_entity_id(args.entity.as_ref(), &session.entity.id) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let created = try_or_eprintln!(create_user(
        console_url,
        &session.access_token,
        &target_entity_id,
        &args.email,
        &name,
        &args.permissions,
    ))
    .user;
    for profile_id in &profile_ids {
        let profile_etag = try_or_eprintln!(fetch_profile_etag(console_url, &session, profile_id));
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
        try_or_eprintln!(fetch_user_with_etag(
            console_url,
            &session,
            &target_entity_id,
            &created.id
        ))
        .user
    };
    print_user_add(&output, json_output);
    ExitStatus::Ok
}

fn list(config: &ResolvedConfig, args: UserListArgs, json_output: bool) -> ExitStatus {
    let (console_url, session) = try_or_eprintln!(console_session(config));
    // Build the query string `?status=..&assigned=..` from --status and
    // --assigned. The Console does the filtering, not the CLI.
    let query = args.query_params();
    let path = format!("/api/v1/entities/{}/users", session.entity.id);
    let page: ListPage<User> = try_or_eprintln!(fetch_json(
        console_url,
        &session,
        &path,
        &query,
        "list users"
    ));
    let status_filter = args.status.map(wire);
    let assigned_filter = args.assigned.map(wire);
    if json_output {
        style::emit_json(&page.items);
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
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let user = try_or_eprintln!(fetch_user_with_etag(
        console_url,
        &session,
        &session.entity.id,
        user_id
    ))
    .user;
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
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let user = try_or_eprintln!(post_user_action(console_url, &session, user_id, action));
    if json_output {
        style::emit_json(&user);
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
    let (console_url, session) = try_or_eprintln!(console_session(config));
    if let Err((status, message)) = delete_user(console_url, &session, user_id) {
        crate::style::eprintln_error(&message);
        return status;
    }
    if json_output {
        style::emit_json(&UserEraseOutput {
            user_id,
            state: "erased",
        });
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
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let user = try_or_eprintln!(fetch_user_with_etag(
        console_url,
        &session,
        &session.entity.id,
        user_id
    ))
    .user;
    if json_output {
        style::emit_json(&user.permissions);
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
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let user = try_or_eprintln!(fetch_user_with_etag(
        console_url,
        &session,
        &session.entity.id,
        user_id
    ));
    let result = try_or_eprintln!(grant_permissions(
        console_url,
        &session.access_token,
        user_id,
        &user.etag,
        &permissions,
    ));
    if json_output {
        style::emit_json(&PermissionGrantOutput {
            user_id: &result.user_id,
            granted: permissions,
        });
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
    let (console_url, session) = try_or_eprintln!(console_session(config));
    for permission in &permissions {
        let user = try_or_eprintln!(fetch_user_with_etag(
            console_url,
            &session,
            &session.entity.id,
            user_id
        ));
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
        style::emit_json(&PermissionRevokeOutput {
            user_id,
            revoked: permissions.clone(),
        });
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
    let response = send(
        Client::new()
            .post(format!("{console_url}/api/v1/entities/{entity_id}/users"))
            .bearer_auth(access_token)
            .header("Idempotency-Key", Uuid::new_v4().to_string())
            .json(&json!({ "email": email, "name": name, "permissions": permissions })),
        "add user",
    )?;
    read_user_with_etag(response, "add user")
}

fn post_user_action(
    console_url: &str,
    session: &Session,
    user_id: &str,
    action: &str,
) -> Result<User, (ExitStatus, String)> {
    let label = format!("{action} user");
    let response = send(
        Client::new()
            .post(format!(
                "{console_url}/api/v1/entities/{}/users/{user_id}/actions/{action}",
                session.entity.id
            ))
            .bearer_auth(&session.access_token),
        &label,
    )?;
    read_json_response(response, &label)
}

fn delete_user(
    console_url: &str,
    session: &Session,
    user_id: &str,
) -> Result<(), (ExitStatus, String)> {
    let response = send(
        Client::new()
            .delete(format!(
                "{console_url}/api/v1/entities/{}/users/{user_id}",
                session.entity.id
            ))
            .bearer_auth(&session.access_token)
            .header("Idempotency-Key", Uuid::new_v4().to_string()),
        "erase user",
    )?;
    read_empty_response(response, "erase user")
}

fn fetch_profile_etag(
    console_url: &str,
    session: &Session,
    profile_id: &str,
) -> Result<String, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/profiles/{profile_id}"))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch profile: {err}"),
            )
        })?;
    read_etag_only(response, "fetch profile")
}

fn assign_profile_member(
    console_url: &str,
    access_token: &str,
    profile_id: &str,
    etag: &str,
    user_id: &str,
) -> Result<(), (ExitStatus, String)> {
    let response = send(
        Client::new()
            .post(format!("{console_url}/api/v1/profiles/{profile_id}/users"))
            .bearer_auth(access_token)
            .header(IF_MATCH, etag)
            .header("Idempotency-Key", Uuid::new_v4().to_string())
            .json(&json!({ "user_id": user_id })),
        "assign profile",
    )?;
    read_empty_response(response, "assign profile")
}

fn grant_permissions(
    console_url: &str,
    access_token: &str,
    user_id: &str,
    etag: &str,
    permissions: &[String],
) -> Result<PermissionSet, (ExitStatus, String)> {
    let response = send(
        Client::new()
            .post(format!("{console_url}/api/v1/users/{user_id}/permissions"))
            .bearer_auth(access_token)
            .header(IF_MATCH, etag)
            .header("Idempotency-Key", Uuid::new_v4().to_string())
            .json(&json!({ "permissions": permissions })),
        "grant permissions",
    )?;
    read_json_response(response, "grant permissions")
}

fn revoke_permission(
    console_url: &str,
    access_token: &str,
    user_id: &str,
    etag: &str,
    permission: &str,
) -> Result<(), (ExitStatus, String)> {
    let response = send(
        Client::new()
            .delete(format!(
                "{console_url}/api/v1/users/{user_id}/permissions/{permission}"
            ))
            .bearer_auth(access_token)
            .header(IF_MATCH, etag),
        "revoke permission",
    )?;
    read_empty_response(response, "revoke permission")
}

fn read_user_with_etag(
    response: Response,
    action: &str,
) -> Result<UserWithEtag, (ExitStatus, String)> {
    let (user, etag) = read_with_etag::<User>(response, action)?;
    Ok(UserWithEtag { user, etag })
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
    config
        .profile_flags
        .iter()
        .map(|raw| {
            // Resolve an alias to its id (a raw UUID passes straight through), so
            // `--profile <alias>` works here as everywhere a profile id is taken.
            let id = crate::commands::alias::resolve_or_passthrough(
                config,
                crate::commands::alias::AliasKind::Profile,
                raw,
            )?;
            Uuid::parse_str(&id)
                .map_err(|_| "[usage] --profile must be a UUID or a known alias".to_string())?;
            Ok(id)
        })
        .collect()
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
        style::emit_json(user);
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
        style::emit_json(user);
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
    use rstest::rstest;

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

    const PROFILE_UUID: &str = "16286507-f87f-449e-a229-be04067fc23c";

    /// A `ResolvedConfig` on a throwaway config dir with the given `--profile`
    /// flags — no Console needed, `profile_flags` only reads local state.
    fn config_with_profile_flags(flags: &[&str]) -> crate::config::ResolvedConfig {
        let dir = std::env::temp_dir().join(format!("umbra-user-test-{}", uuid::Uuid::new_v4()));
        crate::config::ResolvedConfig::resolve(crate::config::ConfigOverrides {
            config_dir: Some(dir),
            profile: flags.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        })
    }

    /// `--profile` accepts an alias as well as a raw UUID: a profile alias resolves
    /// to its id, and a bare UUID passes straight through. Pins that `user add`'s
    /// flag resolution honours the store, not just UUIDs.
    #[rstest]
    #[case::alias("prod", PROFILE_UUID)]
    #[case::raw_uuid(PROFILE_UUID, PROFILE_UUID)]
    fn test_profile_flags_resolves_alias_success(#[case] flag: &str, #[case] expected: &str) {
        let config = config_with_profile_flags(&[flag]);
        let mut store = crate::commands::alias::Aliases::default();
        store.profile.insert("prod".into(), PROFILE_UUID.into());
        crate::commands::alias::save(&config.config_dir, &store).expect("seed store");
        assert_eq!(profile_flags(&config).unwrap(), vec![expected.to_string()]);
    }

    /// An unknown `--profile` name (no matching alias, not a UUID) is a usage
    /// error rather than being sent to the Console as-is.
    #[test]
    fn test_profile_flags_unknown_name_failure() {
        let config = config_with_profile_flags(&["ghost"]);
        assert!(profile_flags(&config)
            .expect_err("an unknown non-uuid profile flag is rejected")
            .contains("must be a UUID or a known alias"));
    }
}
