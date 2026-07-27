use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    cli::{EntityAddArgs, EntityCommand, EntityListArgs},
    config::ResolvedConfig,
    console::{console_session, fetch_json, post_json, push_query, ListPage},
    exit::ExitStatus,
    session::Session,
    style,
};

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
    let page = try_or_eprintln!(fetch_entities(console_url, &session, &args));
    print_entities(page, json_output);
    ExitStatus::Ok
}

fn create_entity(
    console_url: &str,
    access_token: &str,
    name: &str,
    domain: &str,
) -> Result<Entity, (ExitStatus, String)> {
    post_json(
        console_url,
        access_token,
        "/api/v1/entities",
        &json!({ "name": name, "domain": domain }),
        "create entity",
    )
}

fn fetch_entities(
    console_url: &str,
    session: &Session,
    args: &EntityListArgs,
) -> Result<ListPage<Entity>, (ExitStatus, String)> {
    let mut query = vec![("limit", args.limit.to_string())];
    push_query(&mut query, "cursor", &args.cursor);
    fetch_json(
        console_url,
        session,
        "/api/v1/entities",
        &query,
        "list entities",
    )
}

fn print_entities(page: ListPage<Entity>, json_output: bool) {
    if json_output {
        style::emit_json(&EntityListOutput {
            entities: page.items,
            next_cursor: page.next_cursor,
        });
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
        style::emit_json(entity);
    } else {
        let confirm = style::ConfirmBlock::new(verb, "entity", entity.name.clone())
            .field("id", entity.id.clone())
            .field("domain", entity.domain.clone());
        println!("{}", style::render_confirm(&confirm));
    }
}
