use std::collections::BTreeMap;

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    cli::{EntityAddArgs, EntityCommand, EntityListArgs},
    config::ResolvedConfig,
    console::{console_session, read_json_response},
    exit::ExitStatus,
    style,
};

#[derive(Debug, Deserialize)]
struct EntityListPage {
    items: Vec<Entity>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Entity {
    id: String,
    name: String,
    domain: String,
    created_at: String,

    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize)]
struct EntityListOutput {
    entities: Vec<Entity>,
    next_cursor: Option<String>,
}

pub fn run(command: EntityCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        EntityCommand::Add(args) => add(config, args, json),
        EntityCommand::List(args) => list(config, args, json),
    }
}

fn add(config: &ResolvedConfig, args: EntityAddArgs, json_output: bool) -> ExitStatus {
    let domain = args.domain.trim().to_lowercase();
    let name = args.name.trim();
    if domain.is_empty() {
        crate::style::eprintln_error("[usage] DOMAIN must not be empty");
        return ExitStatus::Usage;
    }
    if name.is_empty() {
        crate::style::eprintln_error("[usage] --name must not be empty");
        return ExitStatus::Usage;
    }
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let entity = try_or_eprintln!(create_entity(
        console_url,
        &session.access_token,
        name,
        &domain
    ));
    print_entity(&entity, json_output, "created");
    ExitStatus::Ok
}

fn list(config: &ResolvedConfig, args: EntityListArgs, json_output: bool) -> ExitStatus {
    if args.limit == 0 || args.limit > 500 {
        crate::style::eprintln_error("[usage] --limit must be between 1 and 500");
        return ExitStatus::Usage;
    }
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let page = try_or_eprintln!(fetch_entities(console_url, &session.access_token, &args));
    print_entities(page, json_output);
    ExitStatus::Ok
}

fn create_entity(
    console_url: &str,
    access_token: &str,
    name: &str,
    domain: &str,
) -> Result<Entity, (ExitStatus, String)> {
    let response = Client::new()
        .post(format!("{console_url}/api/v1/entities"))
        .bearer_auth(access_token)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(&json!({ "name": name, "domain": domain }))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to create entity: {err}"),
            )
        })?;
    read_json_response(response, "create entity")
}

fn fetch_entities(
    console_url: &str,
    access_token: &str,
    args: &EntityListArgs,
) -> Result<EntityListPage, (ExitStatus, String)> {
    let mut query = vec![("limit", args.limit.to_string())];
    if let Some(cursor) = &args.cursor {
        query.push(("cursor", cursor.clone()));
    }
    let response = Client::new()
        .get(format!("{console_url}/api/v1/entities"))
        .bearer_auth(access_token)
        .query(&query)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to list entities: {err}"),
            )
        })?;
    read_json_response(response, "list entities")
}

fn print_entities(page: EntityListPage, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&EntityListOutput {
                entities: page.items,
                next_cursor: page.next_cursor,
            })
            .expect("entity list output serializes")
        );
    } else {
        let views: Vec<style::EntityView<'_>> = page
            .items
            .iter()
            .map(|e| style::EntityView {
                id: &e.id,
                name: &e.name,
                domain: &e.domain,
                created_at: &e.created_at,
                extra: &e.extra,
            })
            .collect();
        println!("{}", style::entity_list_cards(&views));
        if let Some(cursor) = &page.next_cursor {
            eprintln!("{}", style::next_cursor_diagnostic(cursor));
        }
    }
}

fn print_entity(entity: &Entity, json_output: bool, verb: &str) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(entity).expect("entity output serializes")
        );
    } else {
        let confirm = style::ConfirmBlock::new(verb, "entity", entity.name.clone())
            .field("id", entity.id.clone())
            .field("domain", entity.domain.clone());
        println!("{}", style::render_confirm(&confirm));
    }
}
