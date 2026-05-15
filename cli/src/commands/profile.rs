use std::{
    fs,
    io::{self, Read},
    path::Path,
};

use reqwest::{
    blocking::{Client, Response},
    header::{ETAG, IF_MATCH},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    cli::{ProfileCommand, ProfileConfigureArgs, ProfileMembersCommand},
    commands::auth,
    config::ResolvedConfig,
    exit::ExitStatus,
    session::Session,
};

#[derive(Debug, Deserialize)]
struct ProfileListPage {
    items: Vec<Profile>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProfileMemberListPage {
    items: Vec<ProfileMember>,
    next_cursor: Option<String>,
}

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
        ProfileCommand::List => list(config, json),
        ProfileCommand::Show => show(config, json),
        ProfileCommand::Configure(args) => configure(config, args, json),
        ProfileCommand::Members(command) => members(config, command, json),
    }
}

fn list(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let page = match fetch_profiles(console_url, &session) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&page.items).expect("profile list output serializes")
        );
    } else if page.items.is_empty() {
        println!("no profiles");
    } else {
        for profile in &page.items {
            println!(
                "{} {} assigned={} cvms={} updated_at={}",
                profile.id,
                profile.name,
                profile.assigned,
                profile.attached_cvm_count,
                profile.updated_at
            );
        }
        if let Some(cursor) = page.next_cursor {
            eprintln!("next cursor: {cursor}");
        }
    }
    ExitStatus::Ok
}

fn show(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, session, profile_id) = match selected_profile_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let profile = match fetch_profile(console_url, &session.access_token, profile_id) {
        Ok(value) => value.profile,
        Err((status, message)) => {
            eprintln!("{message}");
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
            eprintln!("{message}");
            return status;
        }
    };
    let policy = match read_policy(args.policy_file.as_deref()) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let current = match fetch_profile(console_url, &session.access_token, profile_id) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
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
                eprintln!("{message}");
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
        println!("profile {} unchanged", profile.id);
    } else {
        println!("updated profile {} {}", profile.id, profile.name);
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
            eprintln!("{message}");
            return status;
        }
    };
    let page = match fetch_profile_members(console_url, &session.access_token, profile_id) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&page.items)
                .expect("profile member list output serializes")
        );
    } else if page.items.is_empty() {
        println!("no profile members");
    } else {
        for member in &page.items {
            println!(
                "{} {} added_at={}",
                member.user_id, member.email, member.added_at
            );
        }
        if let Some(cursor) = page.next_cursor {
            eprintln!("next cursor: {cursor}");
        }
    }
    ExitStatus::Ok
}

fn member_add(config: &ResolvedConfig, user_id: &str, json_output: bool) -> ExitStatus {
    if Uuid::parse_str(user_id).is_err() {
        eprintln!("[usage] USER_ID must be a UUID");
        return ExitStatus::Usage;
    }
    let (console_url, session, profile_id) = match selected_profile_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let profile = match fetch_profile(console_url, &session.access_token, profile_id) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
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
        eprintln!("{message}");
        return status;
    }
    print_member_output(profile_id, user_id, json_output, "added");
    ExitStatus::Ok
}

fn member_remove(config: &ResolvedConfig, user_id: &str, json_output: bool) -> ExitStatus {
    if Uuid::parse_str(user_id).is_err() {
        eprintln!("[usage] USER_ID must be a UUID");
        return ExitStatus::Usage;
    }
    let (console_url, session, profile_id) = match selected_profile_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let profile = match fetch_profile(console_url, &session.access_token, profile_id) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
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
        eprintln!("{message}");
        return status;
    }
    print_member_output(profile_id, user_id, json_output, "removed");
    ExitStatus::Ok
}

fn console_session(config: &ResolvedConfig) -> Result<(&str, Session), (ExitStatus, String)> {
    let console_url = config
        .require_console_url()
        .map_err(|message| (ExitStatus::Usage, message))?;
    let session = auth::session_for_console(config)?;
    Ok((console_url, session))
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

fn fetch_profiles(
    console_url: &str,
    session: &Session,
) -> Result<ProfileListPage, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!(
            "{console_url}/api/v1/entities/{}/profiles",
            session.entity.id
        ))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to list profiles: {err}"),
            )
        })?;
    read_json_response(response, "list profiles")
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
) -> Result<ProfileMemberListPage, (ExitStatus, String)> {
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
    response: Response,
    action: &str,
) -> Result<ProfileWithEtag, (ExitStatus, String)> {
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
    let profile = response.json::<Profile>().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] malformed {action} response: {err}"),
        )
    })?;
    Ok(ProfileWithEtag { profile, etag })
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
    let state = error
        .get("details")
        .and_then(|details| details.get("state"))
        .and_then(|value| value.as_str());
    Some(match (code, state) {
        (_, Some(state)) => format!("{message} ({state})"),
        (Some(code), _) if code != "UNAUTHORIZED" && code != "VALIDATION_ERROR" => {
            format!("{message} ({code})")
        }
        _ => message.to_string(),
    })
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
    println!("id: {}", profile.id);
    println!("name: {}", profile.name);
    println!("description: {}", profile.description);
    println!("assigned: {}", profile.assigned);
    println!("attached_cvm_count: {}", profile.attached_cvm_count);
    if profile.attached_cvms.is_empty() {
        println!("attached_cvms: []");
    } else {
        println!("attached_cvms:");
        for cvm in &profile.attached_cvms {
            println!("  {} {} {}", cvm.id, cvm.fqdn, cvm.state);
        }
    }
    println!("policy:");
    let policy = serde_json::to_string_pretty(&profile.policy).expect("policy output serializes");
    for line in policy.lines() {
        println!("  {line}");
    }
    println!("created_at: {}", profile.created_at);
    println!("updated_at: {}", profile.updated_at);
}

fn print_member_output(profile_id: &str, user_id: &str, json_output: bool, verb: &str) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&ProfileMemberOutput {
                profile_id,
                user_id,
            })
            .expect("profile member output serializes")
        );
    } else {
        println!("{verb} user {user_id} profile {profile_id}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_policy_rejects_non_object_json() {
        let path = std::env::temp_dir().join(format!("concrete-policy-{}.json", Uuid::new_v4()));
        fs::write(&path, "[]").expect("test policy file written");

        let err = read_policy(Some(&path)).expect_err("array policy is rejected");

        assert!(matches!(err.0, ExitStatus::Usage));
        assert!(err.1.contains("JSON object"));
        fs::remove_file(path).expect("test policy file removed");
    }

    #[test]
    fn console_error_message_includes_conflict_state() {
        let body = r#"{"error":{"code":"CONFLICT","message":"profile name is already registered","details":{"state":"profile_name_taken"}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("profile name is already registered (profile_name_taken)")
        );
    }
}
