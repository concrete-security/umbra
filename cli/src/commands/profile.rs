use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    path::Path,
};

use reqwest::{blocking::Client, header::IF_MATCH};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    cli::{
        wire, ProfileCommand, ProfileConfigureArgs, ProfileCreateArgs, ProfileListArgs,
        ProfileMembersCommand,
    },
    commands::alias,
    config::ResolvedConfig,
    console::{self, console_session, fetch_json, read_empty_response, read_with_etag, ListPage},
    exit::ExitStatus,
    session::Session,
    style,
};

#[derive(Debug, Deserialize, Serialize)]
struct Profile {
    id: String,
    entity_id: String,
    name: String,
    description: String,
    policy: Value,
    assigned: bool,
    attached_cvms: Vec<AttachedCvm>,
    attached_cvm_count: u64,
    created_at: String,
    updated_at: String,

    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AttachedCvm {
    id: String,
    fqdn: String,
    state: String,
}

#[derive(Debug)]
struct ProfileWithEtag {
    profile: Profile,
    etag: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProfileMember {
    user_id: String,
    email: String,
    added_at: String,
}

#[derive(Debug, Serialize)]
struct ProfileMemberOutput<'a> {
    profile_id: &'a str,
    user_id: &'a str,
}

pub fn run(command: ProfileCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        ProfileCommand::Create(args) => create(config, args, json),
        ProfileCommand::List(args) => list(config, args, json),
        ProfileCommand::Show => show(config, json),
        ProfileCommand::Configure(args) => configure(config, args, json),
        ProfileCommand::Members(command) => members(config, command, json),
    }
}

fn create(config: &ResolvedConfig, args: ProfileCreateArgs, json_output: bool) -> ExitStatus {
    let name = args.name.trim();
    if name.is_empty() {
        crate::style::eprintln_error("[usage] NAME must not be empty");
        return ExitStatus::Usage;
    }
    let description = args.description.unwrap_or_default();
    // Fail fast on a bad/taken alias before creating anything.
    if let Some(nick) = args.alias.as_deref() {
        if let Err((status, message)) = crate::commands::alias::validate_alias(config, nick, None) {
            crate::style::eprintln_error(&message);
            return status;
        }
    }
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let profile =
        try_or_eprintln!(create_profile(console_url, &session, name, &description)).profile;
    if let Some(nick) = args.alias.as_deref() {
        if let Err(message) = crate::commands::alias::record_resource_alias(
            config,
            crate::commands::alias::AliasKind::Profile,
            &profile.id,
            nick,
        ) {
            crate::style::eprintln_warn(&format!(
                "[warn] profile created but alias not saved: {message}"
            ));
        }
    }
    if json_output {
        style::emit_json(&profile);
    } else {
        let confirm = style::ConfirmBlock::new("created", "profile", profile.name.clone())
            .field("id", profile.id.clone())
            .next_step(format!(
                "concrete profile members add <user-id> --profile {}",
                profile.id
            ));
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn list(config: &ResolvedConfig, args: ProfileListArgs, json_output: bool) -> ExitStatus {
    let (console_url, session) = try_or_eprintln!(console_session(config));
    // Build the query string `?assigned=..` from --assigned. The Console does
    // the filtering, not the CLI.
    let query = args.query_params();
    let path = format!("/api/v1/entities/{}/profiles", session.entity.id);
    let page: ListPage<Profile> = try_or_eprintln!(fetch_json(
        console_url,
        &session,
        &path,
        &query,
        "list profiles"
    ));
    let assigned_filter = args.assigned.map(wire);
    if json_output {
        style::emit_json(&page.items);
    } else {
        // Local alias names for the page, read once (human view only).
        let aliases = alias::load_for_display(config);
        let views: Vec<style::ProfileView<'_>> = page
            .items
            .iter()
            .map(|p| style::ProfileView {
                id: &p.id,
                alias: alias::cell_source(&aliases, alias::AliasKind::Profile, &p.id),
                name: &p.name,
                assigned: p.assigned,
                attached_cvm_count: p.attached_cvm_count,
                attached_cvm_ids: p.attached_cvms.iter().map(|c| c.id.clone()).collect(),
                created_at: &p.created_at,
                updated_at: &p.updated_at,
                extra: &p.extra,
            })
            .collect();
        let filter = style::ProfileListFilter {
            assigned: assigned_filter,
        };
        println!("{}", style::profile_list_cards(&views, &filter));
        if let Some(cursor) = page.next_cursor {
            eprintln!("{}", style::next_cursor_diagnostic(&cursor));
        }
    }
    ExitStatus::Ok
}

impl ProfileListArgs {
    fn query_params(&self) -> Vec<(&'static str, String)> {
        let mut query: Vec<(&'static str, String)> = Vec::new();
        // No --assigned -> send no `assigned` param (the Console lists every
        // visible profile). Otherwise send "yes" or "no".
        if let Some(assigned) = self.assigned {
            query.push(("assigned", wire(assigned)));
        }
        query
    }
}

fn show(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, session, profile_id) = try_or_eprintln!(selected_profile_session(config));
    let profile_id = profile_id.as_str();
    let profile = try_or_eprintln!(fetch_profile(console_url, &session, profile_id)).profile;
    print_profile(&profile, config, json_output);
    ExitStatus::Ok
}

fn configure(config: &ResolvedConfig, args: ProfileConfigureArgs, json_output: bool) -> ExitStatus {
    let (console_url, session, profile_id) = try_or_eprintln!(selected_profile_session(config));
    let profile_id = profile_id.as_str();
    let policy = try_or_eprintln!(read_policy(args.policy_file.as_deref()));
    let current = try_or_eprintln!(fetch_profile(console_url, &session, profile_id));
    let mut body = Map::new();
    if let Some(name) = args.name {
        body.insert("name".to_string(), Value::String(name));
    }
    if let Some(description) = args.description {
        body.insert("description".to_string(), Value::String(description));
    }
    if let Some(policy) = policy {
        body.insert("policy".to_string(), policy);
    }
    let changed = !body.is_empty();
    let profile = if !changed {
        current.profile
    } else {
        try_or_eprintln!(patch_profile(
            console_url,
            &session.access_token,
            profile_id,
            &current.etag,
            &Value::Object(body),
        ))
        .profile
    };
    if json_output {
        style::emit_json(&profile);
    } else if !changed {
        let confirm = style::ConfirmBlock::new("unchanged", "profile", profile.name.clone())
            .field("id", profile.id.clone());
        println!("{}", style::render_confirm(&confirm));
    } else {
        let confirm = style::ConfirmBlock::new("updated", "profile", profile.name.clone())
            .field("id", profile.id.clone());
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn members(
    config: &ResolvedConfig,
    command: ProfileMembersCommand,
    json_output: bool,
) -> ExitStatus {
    match command {
        ProfileMembersCommand::List => member_list(config, json_output),
        ProfileMembersCommand::Add { user_id } => member_add(config, &user_id, json_output),
        ProfileMembersCommand::Remove { user_id } => member_remove(config, &user_id, json_output),
    }
}

fn member_list(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, session, profile_id) = try_or_eprintln!(selected_profile_session(config));
    let profile_id = profile_id.as_str();
    let page = try_or_eprintln!(fetch_profile_members(console_url, &session, profile_id));
    if json_output {
        style::emit_json(&page.items);
    } else {
        // Section 7.23: resolve the profile name with one extra profile fetch to
        // populate the Filter: header; a single extra call, acceptable for a
        // one-shot list rendering.
        let profile_name = fetch_profile(console_url, &session, profile_id)
            .ok()
            .map(|p| p.profile.name);
        let extras_empty: BTreeMap<String, Value> = BTreeMap::new();
        let views: Vec<style::ProfileMemberView<'_>> = page
            .items
            .iter()
            .map(|m| style::ProfileMemberView {
                user_id: &m.user_id,
                email: &m.email,
                added_at: &m.added_at,
                extra: &extras_empty,
            })
            .collect();
        let filter = style::ProfileMembersFilter {
            profile_id: profile_id.to_string(),
            profile_name,
        };
        println!("{}", style::profile_members_list_cards(&views, &filter));
        if let Some(cursor) = page.next_cursor {
            eprintln!("{}", style::next_cursor_diagnostic(&cursor));
        }
    }
    ExitStatus::Ok
}

fn member_add(config: &ResolvedConfig, user_id: &str, json_output: bool) -> ExitStatus {
    if Uuid::parse_str(user_id).is_err() {
        crate::style::eprintln_error("[usage] USER_ID must be a UUID");
        return ExitStatus::Usage;
    }
    let (console_url, session, profile_id) = try_or_eprintln!(selected_profile_session(config));
    let profile_id = profile_id.as_str();
    let profile = try_or_eprintln!(fetch_profile(console_url, &session, profile_id));
    if let Err((status, message)) = assign_member(
        console_url,
        &session.access_token,
        profile_id,
        &profile.etag,
        user_id,
    ) {
        crate::style::eprintln_error(&message);
        return status;
    }
    // Section 7.16: resolve the user's email for the confirm header.
    let user_email =
        console::resolve_user_email(&session, console_url, &session.access_token, user_id);
    print_member_output(
        profile_id,
        &profile.profile.name,
        user_id,
        user_email.as_deref(),
        json_output,
        true,
    );
    ExitStatus::Ok
}

fn member_remove(config: &ResolvedConfig, user_id: &str, json_output: bool) -> ExitStatus {
    if Uuid::parse_str(user_id).is_err() {
        crate::style::eprintln_error("[usage] USER_ID must be a UUID");
        return ExitStatus::Usage;
    }
    let (console_url, session, profile_id) = try_or_eprintln!(selected_profile_session(config));
    let profile_id = profile_id.as_str();
    let profile = try_or_eprintln!(fetch_profile(console_url, &session, profile_id));
    if let Err((status, message)) = remove_member(
        console_url,
        &session.access_token,
        profile_id,
        &profile.etag,
        user_id,
    ) {
        crate::style::eprintln_error(&message);
        return status;
    }
    let user_email =
        console::resolve_user_email(&session, console_url, &session.access_token, user_id);
    print_member_output(
        profile_id,
        &profile.profile.name,
        user_id,
        user_email.as_deref(),
        json_output,
        false,
    );
    ExitStatus::Ok
}

fn selected_profile_session(
    config: &ResolvedConfig,
) -> Result<(&str, Session, String), (ExitStatus, String)> {
    let raw = config
        .require_profile()
        .map_err(|message| (ExitStatus::Usage, message))?;
    let profile_id = crate::commands::alias::resolve_or_passthrough(
        config,
        crate::commands::alias::AliasKind::Profile,
        raw,
    )
    .map_err(|message| (ExitStatus::Usage, message))?;
    if Uuid::parse_str(&profile_id).is_err() {
        return Err((
            ExitStatus::Usage,
            "[usage] profile must be a UUID".to_string(),
        ));
    }
    let (console_url, session) = console_session(config)?;
    Ok((console_url, session, profile_id))
}

fn create_profile(
    console_url: &str,
    session: &Session,
    name: &str,
    description: &str,
) -> Result<ProfileWithEtag, (ExitStatus, String)> {
    let response = console::send(
        Client::new()
            .post(format!(
                "{console_url}/api/v1/entities/{}/profiles",
                session.entity.id
            ))
            .bearer_auth(&session.access_token)
            .header("Idempotency-Key", Uuid::new_v4().to_string())
            .json(&json!({ "name": name, "description": description })),
        "create profile",
    )?;
    read_profile_with_etag(response, "create profile")
}

/// Ids of the profiles visible to the caller, for `alias prune` to drop aliases
/// whose profile no longer exists.
pub(crate) fn profile_ids(
    console_url: &str,
    session: &Session,
) -> Result<Vec<String>, (ExitStatus, String)> {
    let path = profiles_path(&session.entity.id);
    let page: ListPage<Profile> = fetch_json(console_url, session, &path, &[], "list profiles")?;
    Ok(page.items.into_iter().map(|profile| profile.id).collect())
}

/// Path of the entity's profile list, the one source of truth shared by the
/// fetcher and the test mock (`MockConsole`) so the two never drift.
pub(crate) fn profiles_path(entity_id: &str) -> String {
    format!("/api/v1/entities/{entity_id}/profiles")
}

/// Whether a profile with `profile_id` exists, for fail-fast alias creation.
pub(crate) fn profile_exists(
    console_url: &str,
    session: &Session,
    profile_id: &str,
) -> Result<(), (ExitStatus, String)> {
    fetch_profile(console_url, session, profile_id).map(|_| ())
}

/// Path of the single-profile GET, the one source of truth shared by the
/// fetcher and the test mock (`MockConsole`) so the two never drift.
pub(crate) fn profile_path(profile_id: &str) -> String {
    format!("/api/v1/profiles/{profile_id}")
}

fn fetch_profile(
    console_url: &str,
    session: &Session,
    profile_id: &str,
) -> Result<ProfileWithEtag, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}{}", profile_path(profile_id)))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch profile: {err}"),
            )
        })?;
    read_profile_with_etag(response, "fetch profile")
}

fn fetch_profile_members(
    console_url: &str,
    session: &Session,
    profile_id: &str,
) -> Result<ListPage<ProfileMember>, (ExitStatus, String)> {
    let path = format!("/api/v1/profiles/{profile_id}/users");
    fetch_json(console_url, session, &path, &[], "list profile members")
}

fn patch_profile(
    console_url: &str,
    access_token: &str,
    profile_id: &str,
    etag: &str,
    body: &Value,
) -> Result<ProfileWithEtag, (ExitStatus, String)> {
    let response = console::send(
        Client::new()
            .patch(format!("{console_url}/api/v1/profiles/{profile_id}"))
            .bearer_auth(access_token)
            .header(IF_MATCH, etag)
            .header("Idempotency-Key", Uuid::new_v4().to_string())
            .json(body),
        "configure profile",
    )?;
    read_profile_with_etag(response, "configure profile")
}

fn assign_member(
    console_url: &str,
    access_token: &str,
    profile_id: &str,
    etag: &str,
    user_id: &str,
) -> Result<(), (ExitStatus, String)> {
    let response = console::send(
        Client::new()
            .post(format!("{console_url}/api/v1/profiles/{profile_id}/users"))
            .bearer_auth(access_token)
            .header(IF_MATCH, etag)
            .header("Idempotency-Key", Uuid::new_v4().to_string())
            .json(&json!({ "user_id": user_id })),
        "add profile member",
    )?;
    read_empty_response(response, "add profile member")
}

fn remove_member(
    console_url: &str,
    access_token: &str,
    profile_id: &str,
    etag: &str,
    user_id: &str,
) -> Result<(), (ExitStatus, String)> {
    let response = console::send(
        Client::new()
            .delete(format!(
                "{console_url}/api/v1/profiles/{profile_id}/users/{user_id}"
            ))
            .bearer_auth(access_token)
            .header(IF_MATCH, etag),
        "remove profile member",
    )?;
    read_empty_response(response, "remove profile member")
}

fn read_profile_with_etag(
    response: reqwest::blocking::Response,
    action: &str,
) -> Result<ProfileWithEtag, (ExitStatus, String)> {
    let (profile, etag) = read_with_etag::<Profile>(response, action)?;
    Ok(ProfileWithEtag { profile, etag })
}

fn read_policy(path: Option<&Path>) -> Result<Option<Value>, (ExitStatus, String)> {
    let Some(path) = path else {
        return Ok(None);
    };
    let mut value = String::new();
    if path == Path::new("-") {
        io::stdin().read_to_string(&mut value).map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to read policy from stdin: {err}"),
            )
        })?;
    } else {
        value = fs::read_to_string(path).map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to read policy file: {err}"),
            )
        })?;
    }
    let value: Value = serde_json::from_str(&value).map_err(|err| {
        (
            ExitStatus::Usage,
            format!("[usage] policy file must be valid JSON: {err}"),
        )
    })?;
    if !value.is_object() {
        return Err((
            ExitStatus::Usage,
            "[usage] policy file must contain a JSON object".to_string(),
        ));
    }
    Ok(Some(value))
}

fn print_profile(profile: &Profile, config: &ResolvedConfig, json_output: bool) {
    if json_output {
        style::emit_json(profile);
        return;
    }
    let policy_pretty =
        serde_json::to_string_pretty(&profile.policy).expect("policy output serializes");
    let attached_ids: Vec<String> = profile.attached_cvms.iter().map(|c| c.id.clone()).collect();
    // Human view only.
    let aliases = alias::load_for_display(config);
    let view = style::ProfileShowView {
        id: &profile.id,
        alias: alias::cell_source(&aliases, alias::AliasKind::Profile, &profile.id),
        name: &profile.name,
        description: Some(profile.description.as_str()),
        assigned: profile.assigned,
        attached_cvm_count: profile.attached_cvm_count,
        attached_cvm_ids: attached_ids,
        policy_pretty: &policy_pretty,
        created_at: &profile.created_at,
        updated_at: &profile.updated_at,
        extra: &profile.extra,
    };
    println!("{}", style::profile_show_card(&view));
}

fn print_member_output(
    profile_id: &str,
    profile_name: &str,
    user_id: &str,
    user_email: Option<&str>,
    json_output: bool,
    added: bool,
) {
    if json_output {
        style::emit_json(&ProfileMemberOutput {
            profile_id,
            user_id,
        });
        return;
    }
    // Section 7.16 confirm shape:
    //   added: `[OK] added user <email> to profile <name>` with details
    //          `user id`, `profile id`, `next step` (cvm launch)
    //   removed: `[OK] removed user <email> from profile <name>` (single-line)
    let identifier_email = user_email.unwrap_or(user_id);
    if added {
        let confirm = style::ConfirmBlock::new(
            "added user",
            format!("to profile {profile_name}"),
            identifier_email,
        )
        .field("user id", user_id)
        .field("profile id", profile_id)
        .next_step(format!(
            "concrete cvm launch --profile {profile_id} --ssh-key <key-id>"
        ));
        println!("{}", style::render_confirm(&confirm));
    } else {
        let confirm = style::ConfirmBlock::new(
            "removed user",
            format!("from profile {profile_name}"),
            identifier_email,
        );
        println!("{}", style::render_confirm(&confirm));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Assigned;
    use crate::commands::alias;
    use crate::test_support::{authenticated_config, MockConsole};

    #[test]
    fn profile_list_query_params_maps_assigned_flag() {
        // No --assigned -> empty query; Some -> one `assigned=<value>` pair.
        let cases = [
            (None, vec![]),
            (Some(Assigned::Yes), vec![("assigned", "yes".to_string())]),
            (Some(Assigned::No), vec![("assigned", "no".to_string())]),
        ];
        for (assigned, expected) in cases {
            assert_eq!(ProfileListArgs { assigned }.query_params(), expected);
        }
    }

    #[test]
    fn read_policy_rejects_non_object_json() {
        let path = std::env::temp_dir().join(format!("concrete-policy-{}.json", Uuid::new_v4()));
        fs::write(&path, "[]").expect("test policy file written");

        let err = read_policy(Some(&path)).expect_err("array policy is rejected");

        assert!(matches!(err.0, ExitStatus::Usage));
        assert!(err.1.contains("JSON object"));
        fs::remove_file(path).expect("test policy file removed");
    }

    /// `profile create --alias` writes NO alias when the create fails: the alias
    /// is recorded only after the profile exists, so a failed create (here an
    /// empty mock Console that 404s the create call) must leave the store empty.
    #[test]
    fn test_profile_create_alias_failure() {
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        let status = run(
            ProfileCommand::Create(ProfileCreateArgs {
                name: "prod".into(),
                description: None,
                alias: Some("nick".into()),
            }),
            &config,
            false,
        );
        assert!(!matches!(status, ExitStatus::Ok));
        assert!(
            alias::load(&config.config_dir)
                .unwrap()
                .kind_of("nick")
                .is_none(),
            "a failed create must not write an orphan alias"
        );
    }
}
