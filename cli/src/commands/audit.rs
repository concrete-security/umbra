use std::{collections::BTreeMap, fs, path::Path};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{
    cli::{AuditCommand, AuditEventsArgs, AuditExportArgs},
    config::ResolvedConfig,
    console::{self, push_query, ListPage},
    exit::ExitStatus,
    operation::{self, Operation},
    session::Session,
    style,
};

const AUDIT_ACTIONS: &[&str] = &[
    "ENTITY_CREATED",
    "ENTITY_UPDATED",
    "USER_REGISTERED",
    "USER_DEACTIVATED",
    "USER_REACTIVATED",
    "USER_ERASED",
    "PERMISSION_GRANTED",
    "PERMISSION_REVOKED",
    "PROFILE_CREATED",
    "PROFILE_DELETED",
    "PROFILE_USER_ASSIGNED",
    "PROFILE_USER_REMOVED",
    "SSH_KEY_ADDED",
    "SSH_KEY_REMOVED",
    "CVM_LAUNCHED",
    "CVM_STARTED",
    "CVM_STOPPED",
    "CVM_TERMINATED",
    "SUBDOMAIN_PROVISIONED",
    "SUBDOMAIN_DEPROVISIONED",
    "SECURITY_CVM_PROVISIONING_STARTED",
    "SECURITY_CVM_PROVISIONED",
    "SECURITY_CVM_PROVISIONING_FAILED",
    "SECURITY_CVM_DECOMMISSIONED",
    "SECURITY_CVM_ATTESTATION_VERIFIED",
    "SECURITY_CVM_ATTESTATION_DRIFT",
    "SECURITY_CVM_ATTESTATION_UNREACHABLE",
    "CVM_ATTESTATION_VERIFIED",
    "CVM_ATTESTATION_DRIFT",
    "CVM_ATTESTATION_UNREACHABLE",
    "CVM_PROFILE_ATTACHED",
    "CVM_PROFILE_DETACHED",
    "PROFILE_POLICY_UPDATED",
    "AUTH_SESSION_ISSUED",
    "AUTH_SESSION_REFRESHED",
    "AUTH_SESSION_REVOKED",
    "AUTH_REFRESH_REUSE_DETECTED",
    "OAUTH_IDENTITY_LINKED",
    "OAUTH_REBIND_REFUSED",
    "OPERATION_RESULT_DISCLOSED",
    "AUDIT_EXPORT_REQUESTED",
    "AUDIT_EXPORT_ISSUED",
    "JWT_KEY_ROTATED",
    "QUOTA_SET",
    "QUOTA_CLEARED",
    "SESSIONS_REVOKED",
];

#[derive(Debug, Deserialize, Serialize)]
struct AuditOutput {
    events: Vec<AuditEvent>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuditEvent {
    seq: u64,
    id: String,
    entity_id: Option<String>,
    actor_id: Option<String>,
    actor_email: Option<String>,
    action: String,
    target_type: String,
    target_id: String,
    before: Value,
    after: Value,
    request_id: Option<String>,
    ip_address: Option<String>,
    description: String,
    timestamp: String,
    prev_hash: String,
    row_hash: String,

    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct AuditExportResult {
    download_url: String,
    expires_at: String,
    content_type: String,
    sha256: String,
    row_count: u64,
    byte_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
}

pub fn run(command: AuditCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        AuditCommand::Events(args) => events(config, args, json),
        AuditCommand::Export(args) => export(config, args, json),
    }
}

fn events(config: &ResolvedConfig, args: AuditEventsArgs, json_output: bool) -> ExitStatus {
    if args.limit == 0 || args.limit > 500 {
        crate::style::eprintln_error("[usage] --limit must be between 1 and 500");
        return ExitStatus::Usage;
    }
    if let Some(action) = args.action.as_deref() {
        if !AUDIT_ACTIONS.contains(&action) {
            crate::style::eprintln_error(&format!("[usage] unknown audit action: {action}"));
            return ExitStatus::Usage;
        }
    }
    let (console_url, session) = try_or_eprintln!(console::console_session(config));
    let page = try_or_eprintln!(fetch_events(console_url, &session, &args));
    if let Err(message) = verify_events(&page.items) {
        crate::style::eprintln_error(&message);
        return ExitStatus::Error;
    }
    if json_output {
        let output = AuditOutput {
            events: page.items,
            next_cursor: page.next_cursor,
        };
        style::emit_json(&output);
    } else {
        let views: Vec<style::AuditEventView<'_>> = page
            .items
            .iter()
            .map(|e| style::AuditEventView {
                seq: e.seq,
                timestamp: &e.timestamp,
                actor_email: e.actor_email.as_deref(),
                action: &e.action,
                target_type: &e.target_type,
                target_id: &e.target_id,
                description: &e.description,
                extra: &e.extra,
            })
            .collect();
        // Section 7.5: when `--actor <UUID>` is set, resolve the user to a
        // human-readable email via the same helper as `quota get` (section
        // 7.8). Format: `user <email> <UUID>` with single spaces; fallback to
        // bare UUID. Reuse console::resolve_user_email.
        let resolved_actor = args.actor.as_deref().map(|id| {
            let email =
                console::resolve_user_email(&session, console_url, &session.access_token, id);
            match email {
                Some(e) => format!("user {e} {id}"),
                None => format!("user {id}"),
            }
        });
        let filter = style::AuditEventsFilter {
            actor: resolved_actor,
            action: args.action.clone(),
            target_type: args.target_type.clone(),
            target_id: args.target_id.clone(),
            from: args.from.clone(),
            to: args.to.clone(),
            // Section 7.5 + 12.5: operational filters land in the Filter
            // header so the operator can see the page bounds without
            // re-parsing argv.
            limit: Some(u32::from(args.limit)),
            cursor: args.cursor.clone(),
        };
        println!("{}", style::audit_events_cards(&views, &filter));
        if let Some(cursor) = &page.next_cursor {
            eprintln!("{}", style::next_cursor_diagnostic(cursor));
        }
    }
    ExitStatus::Ok
}

fn export(config: &ResolvedConfig, args: AuditExportArgs, json_output: bool) -> ExitStatus {
    if let Err(message) = validate_export_args(&args) {
        crate::style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    let (console_url, session) = try_or_eprintln!(console::console_session(config));
    let op = try_or_eprintln!(submit_export(console_url, &session.access_token, &args));
    let mut result: AuditExportResult = match try_or_eprintln!(operation::await_result(
        console_url,
        &session.access_token,
        op,
        &args.wait,
        json_output,
        false,
        "audit export",
    )) {
        Some(value) => value,
        None => return ExitStatus::Ok,
    };
    if let Some(output) = args.output.as_deref() {
        if let Err(message) = download_export(&result, output) {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
        result.path = Some(output.display().to_string());
    }
    print_export_result(&result, json_output);
    ExitStatus::Ok
}

fn fetch_events(
    console_url: &str,
    session: &Session,
    args: &AuditEventsArgs,
) -> Result<ListPage<AuditEvent>, (ExitStatus, String)> {
    let mut query = vec![("limit", args.limit.to_string())];
    push_query(&mut query, "actor_id", &args.actor);
    push_query(&mut query, "target_type", &args.target_type);
    push_query(&mut query, "target_id", &args.target_id);
    push_query(&mut query, "action", &args.action);
    push_query(&mut query, "from", &args.from);
    push_query(&mut query, "to", &args.to);
    push_query(&mut query, "cursor", &args.cursor);
    console::fetch_json(
        console_url,
        session,
        "/api/v1/audit/events",
        &query,
        "query audit events",
    )
}

fn submit_export(
    console_url: &str,
    access_token: &str,
    args: &AuditExportArgs,
) -> Result<Operation, (ExitStatus, String)> {
    console::post_json(
        console_url,
        access_token,
        "/api/v1/audit/export",
        &export_body(args),
        "submit audit export",
    )
}

fn export_body(args: &AuditExportArgs) -> Value {
    let mut body = Map::new();
    body.insert("format".to_string(), Value::String(args.format.clone()));
    push_body(&mut body, "actor_id", &args.actor);
    push_body(&mut body, "target_type", &args.target_type);
    push_body(&mut body, "target_id", &args.target_id);
    push_body(&mut body, "action", &args.action);
    push_body(&mut body, "from", &args.from);
    push_body(&mut body, "to", &args.to);
    Value::Object(body)
}

fn push_body(body: &mut Map<String, Value>, key: &str, value: &Option<String>) {
    if let Some(value) = value {
        body.insert(key.to_string(), Value::String(value.clone()));
    }
}

fn download_export(result: &AuditExportResult, output: &Path) -> Result<(), String> {
    let response = Client::new()
        .get(&result.download_url)
        .send()
        .map_err(|err| format!("[error] failed to download audit export: {err}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "[error] audit export download failed: HTTP {}",
            response.status()
        ));
    }
    let bytes = response
        .bytes()
        .map_err(|err| format!("[error] failed to read audit export download: {err}"))?;
    let actual_sha256 = sha256_hex(&bytes);
    if !actual_sha256.eq_ignore_ascii_case(&result.sha256) {
        return Err(format!(
            "[error] audit export sha256 mismatch: expected {}, got {}",
            result.sha256, actual_sha256
        ));
    }
    fs::write(output, &bytes)
        .map_err(|err| format!("[error] failed to write audit export: {err}"))?;
    Ok(())
}

/// Verify one page of the audit chain, as far as a client legitimately can.
///
/// Three things are checked on every page:
///
/// - each row's own `row_hash`, recomputed over its fields (which include
///   `prev_hash`, so no field can be edited without detection);
/// - strict monotonic `seq` ordering, so a reordered or repeated row fails;
/// - `prev_hash` linkage between rows whose `seq` are adjacent.
///
/// Linkage is checked in whichever direction the page runs. The Console pages
/// newest-first (`ORDER BY seq DESC`), so the older row of a pair is the one
/// that comes *second*; requiring ascending order — as this once did — meant
/// the link was never actually checked on a real response.
///
/// A gap between two returned rows is NOT treated as tampering, because gaps
/// are routine and legitimate: every listing is entity-scoped by RBAC
/// (`list_audit_events`), so another tenant's rows are simply absent, and
/// `--actor`/`--action`/`--target-*` remove interior rows by design. A `seq`
/// consumed by a rolled-back transaction leaves a permanent gap too. That is
/// also the limit of what a client can prove: a row deleted from the middle of
/// the chain is indistinguishable from a row this caller may not see, so
/// detecting deletion requires the server-side end-to-end chain replay the
/// spec mandates (`docs/specs/console.md` §19.6), not this function.
fn verify_events(events: &[AuditEvent]) -> Result<(), String> {
    let empty_hash = sha256_hex(b"");
    let mut descending: Option<bool> = None;
    let mut previous: Option<&AuditEvent> = None;
    for event in events {
        let expected_hash = audit_row_hash(event)?;
        if event.row_hash != expected_hash {
            return Err(format!("[error] audit hash mismatch at seq {}", event.seq));
        }
        if event.seq == 1 && event.prev_hash != empty_hash {
            return Err("[error] audit chain first row has invalid prev_hash".to_string());
        }
        if let Some(previous) = previous {
            let pair_descending = match previous.seq.cmp(&event.seq) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => {
                    return Err(format!("[error] audit chain repeats seq {}", event.seq));
                }
            };
            if *descending.get_or_insert(pair_descending) != pair_descending {
                return Err(format!(
                    "[error] audit chain is out of order at seq {}",
                    event.seq
                ));
            }
            let (older, newer) = if pair_descending {
                (event, previous)
            } else {
                (previous, event)
            };
            if older.seq + 1 == newer.seq && newer.prev_hash != older.row_hash {
                return Err(format!(
                    "[error] audit chain link mismatch at seq {}",
                    newer.seq
                ));
            }
        }
        previous = Some(event);
    }
    Ok(())
}

fn audit_row_hash(event: &AuditEvent) -> Result<String, String> {
    let mut row = BTreeMap::new();
    row.insert("action", Value::String(event.action.clone()));
    row.insert("actor_email", opt_string(&event.actor_email));
    row.insert("actor_id", opt_string(&event.actor_id));
    row.insert("after", canonical_json_value(&event.after));
    row.insert("before", canonical_json_value(&event.before));
    row.insert("description", Value::String(event.description.clone()));
    row.insert("entity_id", opt_string(&event.entity_id));
    row.insert("id", Value::String(event.id.clone()));
    row.insert("ip_address", opt_string(&event.ip_address));
    row.insert("prev_hash", Value::String(event.prev_hash.clone()));
    row.insert("request_id", opt_string(&event.request_id));
    row.insert("seq", Value::Number(event.seq.into()));
    row.insert("target_id", Value::String(event.target_id.clone()));
    row.insert("target_type", Value::String(event.target_type.clone()));
    row.insert("timestamp", Value::String(event.timestamp.clone()));
    let payload = serde_json::to_vec(&row)
        .map_err(|err| format!("[error] failed to verify audit hash: {err}"))?;
    Ok(sha256_hex(&payload))
}

fn canonical_json_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonical_json_value).collect()),
        Value::Object(values) => {
            let mut sorted = BTreeMap::new();
            for (key, value) in values {
                sorted.insert(key.clone(), canonical_json_value(value));
            }
            let mut canonical = Map::new();
            for (key, value) in sorted {
                canonical.insert(key, value);
            }
            Value::Object(canonical)
        }
        _ => value.clone(),
    }
}

fn validate_export_args(args: &AuditExportArgs) -> Result<(), String> {
    if !matches!(args.format.as_str(), "csv" | "ndjson") {
        return Err("[usage] --format must be csv or ndjson".to_string());
    }
    if let Some(action) = args.action.as_deref() {
        if !AUDIT_ACTIONS.contains(&action) {
            return Err(format!("[usage] unknown audit action: {action}"));
        }
    }
    if args.wait.no_wait && args.output.is_some() {
        return Err("[usage] --output cannot be used with --no-wait".to_string());
    }
    Ok(())
}

fn print_export_result(result: &AuditExportResult, json_output: bool) {
    if json_output {
        style::emit_json(result);
    } else {
        // Section 7.26 confirm: one block on success, ordered
        // (download url, sha256, rows, bytes, path?). The path field is only
        // present when `--output <FILE>` was passed and the download
        // succeeded. The header verb is `exported` (synchronous success).
        let mut confirm = style::ConfirmBlock::new("exported", "audit", "events")
            .field("download url", result.download_url.clone())
            .field("sha256", result.sha256.clone())
            .field("rows", result.row_count.to_string())
            .field("bytes", result.byte_size.to_string());
        if let Some(path) = &result.path {
            confirm = confirm.field("path", path.clone());
        }
        println!("{}", style::render_confirm(&confirm));
    }
}

fn opt_string(value: &Option<String>) -> Value {
    value
        .as_ref()
        .map(|value| Value::String(value.clone()))
        .unwrap_or(Value::Null)
}

/// Lowercase-hex SHA-256. Shared with `commands::update`, which verifies
/// downloaded release artifacts against their published `.sha256` files.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn sample_event() -> AuditEvent {
        let mut event = AuditEvent {
            seq: 1,
            id: "00000000-0000-4000-8000-000000000001".to_string(),
            entity_id: Some("00000000-0000-4000-8000-000000000002".to_string()),
            actor_id: Some("00000000-0000-4000-8000-000000000003".to_string()),
            actor_email: Some("admin@example.com".to_string()),
            action: "USER_REGISTERED".to_string(),
            target_type: "user".to_string(),
            target_id: "00000000-0000-4000-8000-000000000004".to_string(),
            before: Value::Null,
            after: serde_json::json!({"email": "user@example.com"}),
            request_id: Some("request-1".to_string()),
            ip_address: Some("203.0.113.10".to_string()),
            description: "user registered".to_string(),
            timestamp: "2026-05-15T17:00:00Z".to_string(),
            prev_hash: sha256_hex(b""),
            row_hash: String::new(),
            extra: BTreeMap::new(),
        };
        event.row_hash = audit_row_hash(&event).expect("hash computes");
        event
    }

    /// One correctly linked run of rows, oldest first: each row's `prev_hash`
    /// is the previous row's `row_hash`, as the Console writes them.
    fn linked_chain(seqs: &[u64]) -> Vec<AuditEvent> {
        let mut previous_hash = sha256_hex(b"");
        let mut chain = Vec::new();
        for seq in seqs {
            let mut event = sample_event();
            event.seq = *seq;
            event.id = format!("00000000-0000-4000-8000-{seq:012}");
            event.prev_hash = previous_hash.clone();
            event.row_hash = audit_row_hash(&event).expect("hash computes");
            previous_hash = event.row_hash.clone();
            chain.push(event);
        }
        chain
    }

    /// The wire order of a Console page: newest first (`ORDER BY seq DESC`).
    fn page(mut chain: Vec<AuditEvent>) -> Vec<AuditEvent> {
        chain.reverse();
        chain
    }

    #[test]
    fn verify_events_accepts_valid_single_row_chain() {
        let event = sample_event();

        verify_events(&[event]).expect("chain verifies");
    }

    #[test]
    fn verify_events_rejects_hash_mismatch() {
        let mut event = sample_event();
        event.row_hash = "0".repeat(64);

        let error = verify_events(&[event]).expect_err("hash mismatch fails");

        assert!(error.contains("hash mismatch"));
    }

    /// Pages the verifier must accept, including the real newest-first wire
    /// order. `page_with_absent_row` is the honest limit of a client-side
    /// check: every listing is entity-scoped, so a missing `seq` is far more
    /// likely another tenant's row (verified live: seq 7639 on the first
    /// deployment) than a deletion, and failing on gaps would break
    /// `umbra audit events` for every tenant.
    #[rstest]
    #[case::descending_page(page(linked_chain(&[7, 8, 9])))]
    #[case::ascending_page(linked_chain(&[7, 8, 9]))]
    #[case::single_row_page(page(linked_chain(&[9])))]
    #[case::empty_page(Vec::new())]
    #[case::page_with_absent_row(
        page(linked_chain(&[7, 8, 9]))
            .into_iter()
            .filter(|event| event.seq != 8)
            .collect()
    )]
    fn verify_events_page_success(#[case] events: Vec<AuditEvent>) {
        verify_events(&events).expect("page verifies");
    }

    /// Pages the verifier must reject. `tampered_link` is the one the old
    /// ascending-only comparison could never see: on a newest-first page the
    /// link condition was unreachable, so a rewritten `prev_hash` passed.
    #[rstest]
    #[case::tampered_link(
        {
            let mut events = page(linked_chain(&[7, 8, 9]));
            events[0].prev_hash = "0".repeat(64);
            events[0].row_hash = audit_row_hash(&events[0]).expect("hash computes");
            events
        },
        "chain link mismatch"
    )]
    #[case::reordered_pair(
        {
            let mut events = page(linked_chain(&[7, 8, 9]));
            events.swap(0, 1);
            events
        },
        "out of order"
    )]
    #[case::repeated_row(
        {
            let mut events = page(linked_chain(&[7, 8, 9]));
            events.insert(1, page(linked_chain(&[7, 8, 9])).remove(1));
            events
        },
        "repeats seq"
    )]
    fn verify_events_page_failure(#[case] events: Vec<AuditEvent>, #[case] expected: &str) {
        let error = verify_events(&events).expect_err("page is rejected");

        assert!(error.contains(expected), "unexpected error: {error}");
    }

    /// The Console hashes audit rows as JCS (RFC 8785): non-ASCII stays raw
    /// UTF-8. This fixture and digest are byte-identical to
    /// `NON_ASCII_ROW`/`NON_ASCII_ROW_HASH` in console/tests/test_audit.py; if
    /// the two ever diverge, `umbra audit events` reports genuine rows as
    /// tampered (rows written before console 2026-08-06 escaped non-ASCII and
    /// keep their historical, unverifiable hash — a documented artifact).
    #[test]
    fn audit_hash_non_ascii_matches_console_jcs_success() {
        let mut event = sample_event();
        event.seq = 5791;
        event.after = serde_json::json!({
            "email": "user@example.com",
            "name": "José Ávila",
            "note": "テスト 😀",
        });
        event.timestamp = "2026-07-27T08:06:46.691850Z".to_string();

        assert_eq!(
            audit_row_hash(&event).expect("hash computes"),
            "543b7c176ad5eb8a7acfa5f92a380cc41fa998283bf4e2566847a0dc0c803438"
        );
    }

    #[test]
    fn audit_hash_sorts_nested_json_objects() {
        let mut first = sample_event();
        first.after =
            serde_json::from_str(r#"{"name":"Example Corp","domain":"example.com"}"#).unwrap();
        let mut second = sample_event();
        second.after =
            serde_json::from_str(r#"{"domain":"example.com","name":"Example Corp"}"#).unwrap();

        assert_eq!(
            audit_row_hash(&first).expect("first hash computes"),
            audit_row_hash(&second).expect("second hash computes")
        );
    }

    #[test]
    fn validate_export_args_rejects_unsupported_format() {
        let args = AuditExportArgs {
            format: "xml".to_string(),
            actor: None,
            target_type: None,
            target_id: None,
            action: None,
            from: None,
            to: None,
            output: None,
            wait: crate::cli::WaitArgs {
                no_wait: false,
                wait_timeout_seconds: 600,
            },
        };

        assert_eq!(
            validate_export_args(&args).expect_err("format is rejected"),
            "[usage] --format must be csv or ndjson"
        );
    }
}
