//! Shared Console HTTP helpers used by every `commands/*.rs` that talks to
//! the Console API.
//!
//! Before this module existed, [`read_json_response`], [`error_for_response`],
//! and a `console_error_message` helper were copy-pasted across roughly a
//! dozen command files. The copies had drifted over time -- some included
//! `state`/`required`/`component`/`validation_type`/`limit` detail lookups
//! and others did not. Centralising them here keeps the envelope-to-bracket
//! mapping in one place per `docs/specs/cli-style.md` section 6.5 / 7.20.
//!
//! The [`console_session`] helper used to be duplicated ~10x too; it now lives
//! here.
use std::time::Duration;

use reqwest::{
    blocking::{Client, Response},
    header::{ETAG, RETRY_AFTER},
};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{
    commands::{auth, operation_debug},
    config::ResolvedConfig,
    exit::ExitStatus,
    session::Session,
};

/// Resolve `(console_url, Session)` for a Console-backed command, mapping
/// "no console url" to `ExitStatus::Usage`. The session carries
/// `access_token`; callers that only need the token read
/// `session.access_token` from the returned tuple.
pub(crate) fn console_session(
    config: &ResolvedConfig,
) -> Result<(&str, Session), (ExitStatus, String)> {
    let console_url = config
        .require_console_url()
        .map_err(|message| (ExitStatus::Usage, message))?;
    let session = auth::session_for_console(config)?;
    Ok((console_url, session))
}

/// Decode a Console JSON response into `T`, mapping non-2xx statuses to
/// section 6.5 single-line error strings via [`error_for_response`].
///
/// Used by every commands file that calls the Console. The poll-loop callers
/// (`operation.rs::fetch_operation`) implicitly hit the `"poll operation"`
/// branch of [`operation_debug::log_poll_decode_failure`] when the body fails
/// to decode and the `UMBRA_DEBUG_POLL` env var is set.
pub(crate) fn read_json_response<T: DeserializeOwned>(
    response: Response,
    action: &str,
) -> Result<T, (ExitStatus, String)> {
    if !response.status().is_success() {
        return Err(error_for_response(response, action));
    }
    let body = response.bytes().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to read {action} response: {err}"),
        )
    })?;
    serde_json::from_slice::<T>(&body).map_err(|err| {
        operation_debug::log_poll_decode_failure(action, &body, &err);
        (
            ExitStatus::Error,
            format!("[error] malformed {action} response: {err}"),
        )
    })
}

/// Map a `204 No Content` response to `Ok(())`; any other non-2xx status maps
/// to a section 6.5 error string. Used by `DELETE` endpoints that return no
/// body on success.
pub(crate) fn read_empty_response(
    response: Response,
    action: &str,
) -> Result<(), (ExitStatus, String)> {
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        Ok(())
    } else {
        Err(error_for_response(response, action))
    }
}

/// Decode a response that carries both a typed payload AND an `ETag` header
/// (mutation endpoints that return the new resource state + the new ETag for
/// optimistic-concurrency follow-ups). Mirrors the previous per-file copies
/// of `read_cvm_with_etag` / `read_user_with_etag` / `read_profile_with_etag`.
pub(crate) fn read_with_etag<T: DeserializeOwned>(
    response: Response,
    action: &str,
) -> Result<(T, String), (ExitStatus, String)> {
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
    let payload = response.json::<T>().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] malformed {action} response: {err}"),
        )
    })?;
    Ok((payload, etag))
}

/// Read just the `ETag` header off a successful response, discarding the
/// body. Used by mutation endpoints that return the ETag alone.
pub(crate) fn read_etag_only(
    response: Response,
    action: &str,
) -> Result<String, (ExitStatus, String)> {
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

/// Honour `Retry-After` on an HTTP 429 by sleeping at least that long before
/// the next poll. Floors at one second so a hostile / malformed header cannot
/// turn the poll loop into a busy-spin.
pub(crate) fn retry_after(response: &Response) -> Duration {
    response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| Duration::from_secs(seconds.max(1)))
        .unwrap_or_else(|| Duration::from_secs(1))
}

/// Resolve an entity UUID to its display name (section 7.8). Returns `None`
/// when resolution is not available so the renderer falls back to bare UUID.
/// Lives here (not in the per-command file) because both `quota` and
/// `audit` / `profile` call it across modules.
pub(crate) fn resolve_entity_name(
    session: &Session,
    console_url: &str,
    access_token: &str,
    entity_id: &str,
) -> Option<String> {
    if entity_id == session.entity.id {
        return Some(session.entity.name.clone());
    }
    #[derive(serde::Deserialize)]
    struct EntityResp {
        name: String,
    }
    let response = reqwest::blocking::Client::new()
        .get(format!("{console_url}/api/v1/entities/{entity_id}"))
        .bearer_auth(access_token)
        .send()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<EntityResp>().ok().map(|e| e.name)
}

/// Resolve a user UUID to its email address (section 7.8). Same cross-module
/// rationale as [`resolve_entity_name`].
pub(crate) fn resolve_user_email(
    session: &Session,
    console_url: &str,
    access_token: &str,
    user_id: &str,
) -> Option<String> {
    if user_id == session.user_id {
        return Some(session.email.clone());
    }
    #[derive(serde::Deserialize)]
    struct UserResp {
        email: String,
    }
    let response = reqwest::blocking::Client::new()
        .get(format!(
            "{console_url}/api/v1/entities/{}/users/{user_id}",
            session.entity.id
        ))
        .bearer_auth(access_token)
        .send()
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json::<UserResp>().ok().map(|u| u.email)
}

/// Validate a CLI argument as a UUID v4 string. The error message matches the
/// per-command copies that previously existed (`[usage] <name> must be a
/// UUID`).
pub(crate) fn validate_uuid(name: &str, value: &str) -> Result<(), String> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| format!("[usage] {name} must be a UUID"))
}

/// Validates a CVM/Security-CVM config value: 1..=`max_len` chars, restricted to
/// letters, digits, '.', '_', and '-'. Shared by the `cvm` and `security-cvm`
/// command validators.
pub(crate) fn validate_config_value(name: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.is_empty() || value.len() > max_len {
        return Err(format!("[usage] {name} must be 1..{max_len} characters"));
    }
    if !value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(format!(
            "[usage] {name} may contain only letters, digits, '.', '_', and '-'"
        ));
    }
    Ok(())
}

/// Adds one `key=value` pair to a URL query string (the `?state=running&...`
/// part of the request), but only when the value exists; `None` is skipped.
///
/// ```text
/// push_query(q, "state", Some("running"))  ->  q gets ("state", "running")
/// push_query(q, "cursor", None)            ->  q unchanged
/// ```
pub(crate) fn push_query(
    query: &mut Vec<(&'static str, String)>,
    key: &'static str,
    value: &Option<String>,
) {
    if let Some(value) = value {
        query.push((key, value.clone()));
    }
}

/// A Console list-page envelope: `{ "items": [...], "next_cursor": ... }`.
/// Deserialize `ListPage<T>` via [`fetch_json`] instead of each caller defining
/// its own page struct.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct ListPage<T> {
    pub items: Vec<T>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Authenticated Console `GET` with the session token and the given query
/// filters, decoding the JSON body into `T`. Used for both list-page endpoints
/// (`{items, next_cursor}`) and structured documents; `T` names the shape.
///
/// ```text
/// fetch_json(.., "/api/v1/cvms", [("state", "running")])
///   ->  GET /api/v1/cvms?state=running  ->  parsed CVM list page
/// ```
pub(crate) fn fetch_json<T: DeserializeOwned>(
    console_url: &str,
    session: &Session,
    path: &str,
    query: &[(&'static str, String)],
    action: &str,
) -> Result<T, (ExitStatus, String)> {
    let response = send(
        Client::new()
            .get(format!("{console_url}{path}"))
            .bearer_auth(&session.access_token)
            .query(query),
        action,
    )?;
    read_json_response(response, action)
}

/// Send a prepared Console request, mapping a transport-level failure to a
/// section 6.5 error string. The single home of the `.send().map_err(...)` that
/// every write endpoint (POST/PATCH/DELETE) otherwise re-hand-rolls: build the
/// request (bearer auth, `Idempotency-Key`, `If-Match`, body — whatever the
/// endpoint needs), pass it here, then decode with the matching
/// `read_*_response`. GET reads that decode a typed JSON body go through
/// [`fetch_json`] (itself built on this); reads that need the raw response
/// (ETag capture, custom 404 handling) build their own.
pub(crate) fn send(
    request: reqwest::blocking::RequestBuilder,
    action: &str,
) -> Result<Response, (ExitStatus, String)> {
    request.send().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to {action}: {err}"),
        )
    })
}

/// The common write: an idempotent `POST` of `body` that decodes a JSON payload
/// back into `T`. A fresh `Idempotency-Key` is generated per call. Endpoints
/// that need an `If-Match`, return `204`, or hand back an `ETag` build the
/// request themselves and pair [`send`] with the matching `read_*_response`.
pub(crate) fn post_json<T: DeserializeOwned>(
    console_url: &str,
    access_token: &str,
    path: &str,
    body: &Value,
    action: &str,
) -> Result<T, (ExitStatus, String)> {
    let response = send(
        Client::new()
            .post(format!("{console_url}{path}"))
            .bearer_auth(access_token)
            .header("Idempotency-Key", uuid::Uuid::new_v4().to_string())
            .json(body),
        action,
    )?;
    read_json_response(response, action)
}

/// Convert a non-2xx [`Response`] into a `[<bracket>] <message>` string the
/// rest of the CLI feeds into `style::eprintln_error`.
///
/// The bracket value follows the rule in `docs/specs/cli-style.md` section
/// 6.5:
///
/// - When the body is a recognised Console error envelope, the bracket is
///   the typed `error.code` (e.g. `NOT_FOUND`, `VALIDATION_ERROR`,
///   `FORBIDDEN`).
/// - Otherwise the bracket falls back to the client-side table -- one of
///   `usage` / `auth_required` / `wait_timeout` / `error` derived from the
///   exit-code symbol (`cli.md` section 2.4).
///
/// The mapping from HTTP status to exit symbol matches the union of every
/// per-command copy that previously existed:
///
/// - `401` -> `auth_required`
/// - `400` / `422` -> `usage`
/// - any other non-2xx -> `error`
///
/// Independently of the bracket, the exit code is still computed from the
/// HTTP status. The bracket and the exit code are decoupled by design.
pub(crate) fn error_for_response(response: Response, action: &str) -> (ExitStatus, String) {
    error_for_response_with(response, action, None)
}

/// Same as [`error_for_response`] but, if the response is HTTP 404 and
/// `not_found_message` is `Some`, the canned text replaces the envelope-based
/// message. Used by `security_cvm` show / fetch endpoints to surface "no
/// Security CVM for this entity" without re-decoding the Console envelope.
pub(crate) fn error_for_response_with(
    response: Response,
    action: &str,
    not_found_message: Option<&str>,
) -> (ExitStatus, String) {
    if let Some(message) = not_found_message {
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return (ExitStatus::Error, message.to_string());
        }
    }
    let status = response.status();
    let exit = if status == reqwest::StatusCode::UNAUTHORIZED {
        ExitStatus::AuthRequired
    } else if status == reqwest::StatusCode::BAD_REQUEST
        || status == reqwest::StatusCode::UNPROCESSABLE_ENTITY
    {
        ExitStatus::Usage
    } else {
        ExitStatus::Error
    };
    let text = response.text().unwrap_or_default();
    let parsed = console_error_envelope(&text);
    let (message, console_code) =
        parsed.unwrap_or_else(|| (format!("{action} failed: HTTP {status}"), None));
    let tag = console_code.unwrap_or_else(|| client_side_bracket(exit).to_string());
    (exit, format!("[{tag}] {message}"))
}

/// Client-side bracket fallback per `docs/specs/cli-style.md` section 6.5.
fn client_side_bracket(exit: ExitStatus) -> &'static str {
    match exit {
        ExitStatus::AuthRequired => "auth_required",
        ExitStatus::Usage => "usage",
        ExitStatus::WaitTimeout => "wait_timeout",
        _ => "error",
    }
}

/// Try to extract `(message, Option<typed_error_code>)` from a Console JSON
/// error envelope. The typed code is the verbatim Console value of
/// `error.code` (e.g. `NOT_FOUND`, `VALIDATION_ERROR`, `FORBIDDEN`), used as
/// the bracket tag per `docs/specs/cli-style.md` section 6.5.
///
/// The message string is enriched with the most informative `details.*`
/// key the envelope carries (the canonical set is `state`, `required`,
/// `component`, `limit`, `dev_cvm_count`, and `errors[0].type`). Per the
/// section 6.5 reconciliation the typed code is NOT duplicated as a
/// parenthesised suffix on the message; it only appears in the bracket.
///
/// Returns `None` when the body is not a recognized Console envelope; the
/// caller MUST fall back to a synthetic message in that case.
pub(crate) fn console_error_envelope(body: &str) -> Option<(String, Option<String>)> {
    let value: Value = serde_json::from_str(body).ok()?;
    let error = value.get("error")?;
    let message = error.get("message")?.as_str()?;
    let code = error
        .get("code")
        .and_then(|value| value.as_str())
        .map(str::to_string);
    let details = error.get("details");
    let state = details
        .and_then(|details| details.get("state"))
        .and_then(|value| value.as_str());
    let required = details
        .and_then(|details| details.get("required"))
        .and_then(|value| value.as_str());
    let component = details
        .and_then(|details| details.get("component"))
        .and_then(|value| value.as_str());
    let limit = details
        .and_then(|details| details.get("limit"))
        .and_then(|value| value.as_str());
    let dev_cvm_count = details
        .and_then(|details| details.get("dev_cvm_count"))
        .and_then(|value| value.as_u64());
    let validation_type = details
        .and_then(|details| details.get("errors"))
        .and_then(|errors| errors.as_array())
        .and_then(|errors| errors.first())
        .and_then(|error| error.get("type"))
        .and_then(|value| value.as_str());

    // Special case from security_cvm: when both state and dev_cvm_count are
    // populated and the state names the dev-cvm-in-entity invariant, surface
    // the count so the operator knows how many resources blocked the action.
    if let (Some("dev_cvms_in_entity"), Some(count)) = (state, dev_cvm_count) {
        return Some((
            format!("{message} (dev_cvms_in_entity; dev_cvm_count={count})"),
            code,
        ));
    }

    // Special case for launch/attach refusals over per-user secret references:
    // name the secrets so the fix is one `umbra secret set` away.
    if let Some(errors) = details
        .and_then(|details| details.get("errors"))
        .and_then(|errors| errors.as_array())
    {
        let mut names: Vec<&str> = errors
            .iter()
            .filter(|error| {
                error
                    .get("type")
                    .and_then(|value| value.as_str())
                    .is_some_and(|value| value.starts_with("user_secret_"))
            })
            .filter_map(|error| error.get("secret_name").and_then(|value| value.as_str()))
            .collect();
        if !names.is_empty() {
            names.sort_unstable();
            names.dedup();
            return Some((
                format!(
                    "{message} (user secrets: {}; run `umbra secret set <NAME> --host <HOST>` as the CVM owner)",
                    names.join(", ")
                ),
                code,
            ));
        }
    }

    let enriched = match (state, required, component, limit, validation_type) {
        (Some(state), _, _, _, _) => format!("{message} ({state})"),
        (_, Some(required), _, _, _) => format!("{message} ({required})"),
        (_, _, Some(component), _, _) => format!("{message} ({component})"),
        (_, _, _, Some(limit), _) => format!("{message} ({limit})"),
        (_, _, _, _, Some(validation_type)) => {
            // For instance-type launch errors, point the user at the catalog listing
            // instead of surfacing the bare error-type token.
            if matches!(
                validation_type,
                "unknown_instance_type" | "instance_type_not_launchable"
            ) {
                format!("{message}; run `umbra cvm instance-types` for more information")
            } else {
                format!("{message} ({validation_type})")
            }
        }
        _ => message.to_string(),
    };
    Some((enriched, code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_error_envelope_returns_message_and_typed_code() {
        let body = r#"{"error":{"code":"INTERNAL","message":"boom"}}"#;
        let (message, code) = console_error_envelope(body).expect("envelope parses");
        assert_eq!(message, "boom");
        assert_eq!(code.as_deref(), Some("INTERNAL"));
    }

    #[test]
    fn console_error_envelope_preserves_unauthorized_code() {
        // The typed code goes in the bracket; it is no longer suppressed for
        // UNAUTHORIZED / VALIDATION_ERROR (those used to be filtered out in
        // the legacy `(code)` suffix to avoid duplicating the bracket symbol).
        let body = r#"{"error":{"code":"UNAUTHORIZED","message":"nope"}}"#;
        let (message, code) = console_error_envelope(body).expect("envelope parses");
        assert_eq!(message, "nope");
        assert_eq!(code.as_deref(), Some("UNAUTHORIZED"));
    }

    #[test]
    fn console_error_envelope_includes_last_profile_state() {
        let body = r#"{"error":{"code":"CONFLICT","message":"cannot remove","details":{"state":"last_profile"}}}"#;
        let (message, code) = console_error_envelope(body).expect("envelope parses");
        assert_eq!(message, "cannot remove (last_profile)");
        assert_eq!(code.as_deref(), Some("CONFLICT"));
    }

    #[test]
    fn console_error_envelope_includes_required_membership() {
        let body = r#"{"error":{"code":"FORBIDDEN","message":"need access","details":{"required":"PROFILE_MEMBERSHIP"}}}"#;
        let (message, code) = console_error_envelope(body).expect("envelope parses");
        assert_eq!(message, "need access (PROFILE_MEMBERSHIP)");
        assert_eq!(code.as_deref(), Some("FORBIDDEN"));
    }

    #[test]
    fn console_error_envelope_includes_missing_component() {
        let body = r#"{"error":{"code":"SERVICE_UNAVAILABLE","message":"adapter down","details":{"component":"cvm_provider"}}}"#;
        let (message, code) = console_error_envelope(body).expect("envelope parses");
        assert_eq!(message, "adapter down (cvm_provider)");
        assert_eq!(code.as_deref(), Some("SERVICE_UNAVAILABLE"));
    }

    #[test]
    fn console_error_envelope_includes_validation_type() {
        let body = r#"{"error":{"code":"VALIDATION_ERROR","message":"bad input","details":{"errors":[{"type":"string_too_short"}]}}}"#;
        let (message, code) = console_error_envelope(body).expect("envelope parses");
        assert_eq!(message, "bad input (string_too_short)");
        assert_eq!(code.as_deref(), Some("VALIDATION_ERROR"));
    }

    #[test]
    fn console_error_envelope_points_instance_type_errors_at_catalog() {
        // Both instance-type validation errors replace the bare error-type token with
        // a pointer to the catalog listing, so the launch error is actionable.
        for validation_type in ["unknown_instance_type", "instance_type_not_launchable"] {
            let body = format!(
                r#"{{"error":{{"code":"VALIDATION_ERROR","message":"bad type","details":{{"errors":[{{"type":"{validation_type}"}}]}}}}}}"#
            );
            let (message, _code) = console_error_envelope(&body).expect("envelope parses");
            assert_eq!(
                message,
                "bad type; run `umbra cvm instance-types` for more information"
            );
        }
    }

    #[test]
    fn console_error_envelope_names_missing_user_secrets() {
        let body = r#"{"error":{"code":"VALIDATION_ERROR","message":"profiles reference user secrets that are missing or not host-authorized","details":{"member":"launcher","errors":[{"type":"user_secret_missing","secret_name":"slack-user-token"},{"type":"user_secret_host_not_allowed","secret_name":"gh-token"},{"type":"user_secret_missing","secret_name":"slack-user-token"}]}}}"#;
        let (message, code) = console_error_envelope(body).expect("envelope parses");
        assert_eq!(
            message,
            "profiles reference user secrets that are missing or not host-authorized (user secrets: gh-token, slack-user-token; run `umbra secret set <NAME> --host <HOST>` as the CVM owner)"
        );
        assert_eq!(code.as_deref(), Some("VALIDATION_ERROR"));
    }

    #[test]
    fn console_error_envelope_includes_dev_cvm_count() {
        let body = r#"{"error":{"code":"CONFLICT","message":"sc has dev cvms","details":{"state":"dev_cvms_in_entity","dev_cvm_count":3}}}"#;
        let (message, code) = console_error_envelope(body).expect("envelope parses");
        assert_eq!(
            message,
            "sc has dev cvms (dev_cvms_in_entity; dev_cvm_count=3)"
        );
        assert_eq!(code.as_deref(), Some("CONFLICT"));
    }

    #[test]
    fn validate_uuid_accepts_v4() {
        assert!(validate_uuid("--id", "00000000-0000-4000-8000-000000000001").is_ok());
    }

    #[test]
    fn validate_uuid_rejects_garbage_with_section_6_5_bracket() {
        assert_eq!(
            validate_uuid("--id", "not-a-uuid").unwrap_err(),
            "[usage] --id must be a UUID"
        );
    }

    #[test]
    fn validate_config_value_rejects_slash() {
        assert_eq!(
            validate_config_value("--instance-type", "tdx/small", 100).unwrap_err(),
            "[usage] --instance-type may contain only letters, digits, '.', '_', and '-'"
        );
    }

    /// `fetch_json` (and thus the shared GET path) maps HTTP status to the
    /// section-6.5 exit code: 401 -> auth_required, 400/422 -> usage, else error.
    #[test]
    fn fetch_json_maps_status_to_exit_code_failure() {
        use crate::test_support::{fake_authenticated_session, MockConsole};
        let mock = MockConsole::start();
        let session = fake_authenticated_session();
        for (status, expected) in [
            (401u16, ExitStatus::AuthRequired),
            (400u16, ExitStatus::Usage),
            (422u16, ExitStatus::Usage),
            (500u16, ExitStatus::Error),
        ] {
            let path = format!("/api/v1/probe-{status}");
            mock.reply_raw(&path, status, r#"{"error":{"code":"E","message":"boom"}}"#);
            let (got, _message) =
                fetch_json::<Value>(mock.base_url(), &session, &path, &[], "probe")
                    .expect_err("a non-2xx status must be an error");
            assert_eq!(got as u8, expected as u8, "status {status}");
        }
    }

    /// `post_json` sends the body and decodes a 200 JSON payload back into `T`.
    #[test]
    fn post_json_round_trips_success() {
        use crate::test_support::{fake_authenticated_session, MockConsole};
        let mock = MockConsole::start();
        let session = fake_authenticated_session();
        mock.reply_raw("/api/v1/echo", 200, r#"{"ok":true}"#);
        let value: Value = post_json(
            mock.base_url(),
            &session.access_token,
            "/api/v1/echo",
            &serde_json::json!({}),
            "echo",
        )
        .expect("a 200 body decodes");
        assert_eq!(value["ok"], serde_json::json!(true));
    }
}
