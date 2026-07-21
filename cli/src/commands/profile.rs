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
    config::ResolvedConfig,
    console::{
        self, console_session, fetch_json, read_empty_response, read_json_response, read_with_etag,
        ListPage,
    },
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
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let profile = match create_profile(console_url, &session, name, &description) {
        Ok(value) => value.profile,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&profile).expect("profile create output serializes")
        );
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
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    // Build the query string `?assigned=..` from --assigned. The Console does
    // the filtering, not the CLI.
    let query = args.query_params();
    let path = format!("/api/v1/entities/{}/profiles", session.entity.id);
    let page: ListPage<Profile> =
        match fetch_json(console_url, &session, &path, &query, "list profiles") {
            Ok(value) => value,
            Err((status, message)) => {
                crate::style::eprintln_error(&message);
                return status;
            }
        };
    let assigned_filter = args.assigned.map(wire);
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&page.items).expect("profile list output serializes")
        );
    } else {
        let views: Vec<style::ProfileView<'_>> = page
            .items
            .iter()
            .map(|p| style::ProfileView {
                id: &p.id,
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
    let (console_url, session, profile_id) = match selected_profile_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let profile = match fetch_profile(console_url, &session.access_token, profile_id) {
        Ok(value) => value.profile,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    print_profile(&profile, json_output);
    ExitStatus::Ok
}

fn configure(config: &ResolvedConfig, args: ProfileConfigureArgs, json_output: bool) -> ExitStatus {
    let (console_url, session, profile_id) = match selected_profile_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let policy = match read_policy(args.policy_file.as_deref()) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let current = match fetch_profile(console_url, &session.access_token, profile_id) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
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
        match patch_profile(
            console_url,
            &session.access_token,
            profile_id,
            &current.etag,
            &Value::Object(body),
        ) {
            Ok(value) => value.profile,
            Err((status, message)) => {
                crate::style::eprintln_error(&message);
                return status;
            }
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&profile).expect("profile configure output serializes")
        );
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
    let (console_url, session, profile_id) = match selected_profile_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let page = match fetch_profile_members(console_url, &session.access_token, profile_id) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&page.items)
                .expect("profile member list output serializes")
        );
    } else {
        // Section 7.23: resolve the profile name via a cached/lookup path. We
        // fetch the profile once to populate the Filter: header; this is a
        // single extra call, acceptable for a one-shot list rendering.
        let profile_name = fetch_profile(console_url, &session.access_token, profile_id)
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
    let (console_url, session, profile_id) = match selected_profile_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let profile = match fetch_profile(console_url, &session.access_token, profile_id) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
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
    let (console_url, session, profile_id) = match selected_profile_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let profile = match fetch_profile(console_url, &session.access_token, profile_id) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
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
) -> Result<(&str, Session, &str), (ExitStatus, String)> {
    let profile_id = config
        .require_profile()
        .map_err(|message| (ExitStatus::Usage, message))?;
    if Uuid::parse_str(profile_id).is_err() {
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
    let response = Client::new()
        .post(format!(
            "{console_url}/api/v1/entities/{}/profiles",
            session.entity.id
        ))
        .bearer_auth(&session.access_token)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(&json!({ "name": name, "description": description }))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to create profile: {err}"),
            )
        })?;
    read_profile_with_etag(response, "create profile")
}

fn fetch_profile(
    console_url: &str,
    access_token: &str,
    profile_id: &str,
) -> Result<ProfileWithEtag, (ExitStatus, String)> {
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
    read_profile_with_etag(response, "fetch profile")
}

fn fetch_profile_members(
    console_url: &str,
    access_token: &str,
    profile_id: &str,
) -> Result<ListPage<ProfileMember>, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/profiles/{profile_id}/users"))
        .bearer_auth(access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to list profile members: {err}"),
            )
        })?;
    read_json_response(response, "list profile members")
}

fn patch_profile(
    console_url: &str,
    access_token: &str,
    profile_id: &str,
    etag: &str,
    body: &Value,
) -> Result<ProfileWithEtag, (ExitStatus, String)> {
    let response = Client::new()
        .patch(format!("{console_url}/api/v1/profiles/{profile_id}"))
        .bearer_auth(access_token)
        .header(IF_MATCH, etag)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(body)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to configure profile: {err}"),
            )
        })?;
    read_profile_with_etag(response, "configure profile")
}

fn assign_member(
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
                format!("[error] failed to add profile member: {err}"),
            )
        })?;
    read_empty_response(response, "add profile member")
}

fn remove_member(
    console_url: &str,
    access_token: &str,
    profile_id: &str,
    etag: &str,
    user_id: &str,
) -> Result<(), (ExitStatus, String)> {
    let response = Client::new()
        .delete(format!(
            "{console_url}/api/v1/profiles/{profile_id}/users/{user_id}"
        ))
        .bearer_auth(access_token)
        .header(IF_MATCH, etag)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to remove profile member: {err}"),
            )
        })?;
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

fn print_profile(profile: &Profile, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(profile).expect("profile output serializes")
        );
        return;
    }
    let policy_pretty =
        serde_json::to_string_pretty(&profile.policy).expect("policy output serializes");
    let attached_ids: Vec<String> = profile.attached_cvms.iter().map(|c| c.id.clone()).collect();
    let view = style::ProfileShowView {
        id: &profile.id,
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
        println!(
            "{}",
            serde_json::to_string_pretty(&ProfileMemberOutput {
                profile_id,
                user_id,
            })
            .expect("profile member output serializes")
        );
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
}
