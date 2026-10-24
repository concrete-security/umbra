//! Shared Console operation wire types and polling helpers.
//!
//! Before this module existed, `cli/src/commands/cvm.rs`,
//! `cli/src/commands/security_cvm.rs`, and `cli/src/commands/audit.rs` each
//! declared their own copies of `Operation`, `OperationTarget`,
//! `OperationError`, `OperationProgress`, and `OperationPoll`, plus a
//! near-identical `wait_for_operation` poll loop. Centralising the types and
//! the loop here keeps the Console saga shape in one place.
//!
//! The poll loop accepts an optional [`StepProgress`] callback so the CVM and
//! Security CVM commands can render the `StepsRenderer` template on stderr,
//! while the audit-export command leaves it unset and gets the plain poll
//! semantics.
use std::{
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    cli::WaitArgs, commands::auth, config::ResolvedConfig, console, exit::ExitStatus, style,
};

/// Console async operation envelope.
///
/// Returned by every saga submit / poll endpoint. The CLI never reads the
/// payload directly; it polls until the saga terminates and then decodes
/// `result` into the saga-specific result type.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct Operation {
    pub id: String,
    pub kind: String,
    pub status: String,
    pub actor_id: Option<String>,
    pub target: OperationTarget,
    pub result: Option<Value>,
    pub error: Option<OperationError>,
    pub progress: Option<OperationProgress>,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OperationTarget {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OperationError {
    pub code: String,
    pub message: String,
    pub details: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct OperationProgress {
    pub step: String,
    pub percent: u8,
}

/// Result of a single poll request.
pub(crate) enum OperationPoll {
    Operation(Box<Operation>),
    RateLimited(Duration),
}

/// Fetch a single operation poll cycle. Maps HTTP 429 to
/// [`OperationPoll::RateLimited`] using the `Retry-After` header so the caller
/// can stall the loop and exclude the wait from the user-visible timeout.
pub(crate) fn fetch_operation(
    console_url: &str,
    access_token: &str,
    operation_id: &str,
) -> Result<OperationPoll, (ExitStatus, String)> {
    let response = crate::console::client(console_url)?
        .get(format!("{console_url}/api/v1/operations/{operation_id}"))
        .bearer_auth(access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to poll operation: {err}"),
            )
        })?;
    if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Ok(OperationPoll::RateLimited(console::retry_after(&response)));
    }
    console::read_json_response(response, "poll operation")
        .map(|operation| OperationPoll::Operation(Box::new(operation)))
}

/// Format the user-visible failure message for a terminal `failed` operation.
/// Honors the typed `error.code` (rendered as the bracket symbol) when the
/// Console returned one; otherwise emits a generic `[error] operation failed`.
pub(crate) fn operation_failure_message(operation: &Operation) -> String {
    if let Some(error) = &operation.error {
        format!("[{}] {}", error.code, error.message)
    } else {
        "[error] operation failed".to_string()
    }
}

/// Why the Console cancelled the operation, when it says. The envelope carries a
/// reason and dropping it left the caller with nothing to act on.
fn operation_cancelled_message(operation: &Operation) -> String {
    match &operation.error {
        Some(error) => format!("[cancelled] {}", error.message),
        None => "[cancelled] operation was cancelled".to_string(),
    }
}

/// Print the operation handle on stdout (or stderr when timing out). Identical
/// shape across cvm / security_cvm / audit: `--json` dumps the envelope as-is,
/// human mode uses [`style::operation_handle_confirm`].
pub(crate) fn print_operation(operation: &Operation, json_output: bool, stderr: bool) {
    let text = if json_output {
        serde_json::to_string_pretty(operation).expect("operation output serializes")
    } else {
        style::operation_handle_confirm(
            &operation.id,
            &operation.kind,
            &operation.status,
            &operation.target.kind,
            operation.target.id.as_deref(),
        )
    };
    if stderr {
        eprintln!("{text}");
    } else {
        println!("{text}");
    }
}

/// Poll an operation until it reaches a terminal state or the caller's
/// timeout elapses.
///
/// `wire_steps` selects whether to drive a `StepsRenderer` against stderr
/// during the poll loop. CVM and Security CVM sagas pass `true` so the
/// operator sees per-step progress; audit-export passes `false` because its
/// async lifecycle is a single async step with no intermediate progress.
pub(crate) fn wait_for_operation(
    config: &ResolvedConfig,
    initial_session: &crate::session::Session,
    mut operation: Operation,
    timeout: Duration,
    json_output: bool,
    wire_steps: bool,
) -> Result<Operation, (ExitStatus, String)> {
    let started = Instant::now();
    let mut current_session = initial_session.clone();
    let mut excluded = Duration::ZERO;
    // Section 6.3 + 12.4: drive the steps template against stderr during the
    // polling phase. The JSON path renders no steps so structured output stays
    // free of ANSI / decorative lines. Audit-export disables the renderer
    // because its single async step carries no per-step progress.
    let mut steps: Option<style::StepsRenderer> =
        (wire_steps && !json_output).then(style::new_stderr_steps);
    loop {
        if let (Some(s), Some(progress)) = (steps.as_mut(), operation.progress.as_ref()) {
            let status = match operation.status.as_str() {
                "succeeded" => style::OperationStatus::Succeeded,
                "failed" => style::OperationStatus::Failed,
                "running" => style::OperationStatus::Running,
                _ => style::OperationStatus::Pending,
            };
            s.observe(&progress.step, status);
        }
        match operation.status.as_str() {
            "succeeded" => {
                // Transition the last step from yellow (running) to green
                // (done) before returning; the caller emits the success
                // confirm separately so we MUST NOT emit it here.
                if let Some(steps) = steps {
                    steps.close();
                }
                return Ok(operation);
            }
            "failed" => {
                if let Some(steps) = steps {
                    let block =
                        style::ErrorBlock::parse_legacy(&operation_failure_message(&operation));
                    steps.finalize_error(&block);
                    return Err((ExitStatus::Error, String::new()));
                }
                return Err((ExitStatus::Error, operation_failure_message(&operation)));
            }
            "cancelled" => {
                return Err((ExitStatus::Error, operation_cancelled_message(&operation)));
            }
            "pending" | "running" => {}
            status => {
                return Err((
                    ExitStatus::Error,
                    format!("[error] operation returned unknown status: {status}"),
                ));
            }
        }
        if Instant::now()
            .duration_since(started)
            .saturating_sub(excluded)
            >= timeout
        {
            if json_output {
                print_operation(&operation, true, true);
                return Err((ExitStatus::WaitTimeout, String::new()));
            }
            let block = style::wait_timeout_block(
                &operation.id,
                &operation.kind,
                operation.target.id.as_deref(),
                &operation.status,
                timeout.as_secs(),
            );
            match steps {
                Some(steps) => steps.finalize_timeout(&block),
                None => style::eprintln_error_block(&block),
            }
            return Err((ExitStatus::WaitTimeout, String::new()));
        }
        thread::sleep(Duration::from_secs(1));
        // A saga can outlive the access token used to submit it. Reload the
        // current session and use the normal expiry/refresh contract for each
        // read; never repeat the accepted mutation or retry a rejected bearer.
        current_session = auth::session_for_operation(config, &current_session)?;
        let console_url = config
            .require_console_url()
            .map_err(|message| (ExitStatus::Usage, message))?;
        match fetch_operation(console_url, &current_session.access_token, &operation.id)? {
            OperationPoll::Operation(next) => operation = *next,
            OperationPoll::RateLimited(delay) => {
                thread::sleep(delay);
                excluded += delay;
            }
        }
    }
}

/// Decode a saga `result` payload into the saga-specific result type.
///
/// Both `cvm` and `security_cvm` consume this for their `launch` / `update` /
/// `terminate` saga results. `label` is the user-visible saga noun used in the
/// error string (e.g., `CVM launch`, `Security CVM update`, `audit export`).
pub(crate) fn extract_operation_result<T>(operation: &Operation, label: &str) -> Result<T, String>
where
    T: for<'de> Deserialize<'de>,
{
    let result = operation
        .result
        .clone()
        .ok_or_else(|| format!("[error] {label} operation succeeded without result"))?;
    serde_json::from_value::<T>(result).map_err(|_| format!("[error] malformed {label} result"))
}

/// Drive a just-submitted saga to its result: honor `--no-wait` (print the
/// handle and stop), else poll to completion and decode the `result` into `T`.
///
/// The single home of the `if no_wait { print; return } else { wait; extract }`
/// block every saga command repeats. Returns `Ok(None)` when `--no-wait` handled
/// the operation (the caller returns success), `Ok(Some(result))` on completion,
/// and the usual `(ExitStatus, String)` on failure so the caller's
/// `try_or_eprintln!` reports it. `wire_steps` matches [`wait_for_operation`].
pub(crate) fn await_result<T>(
    config: &ResolvedConfig,
    initial_session: &crate::session::Session,
    op: Operation,
    wait: &WaitArgs,
    json_output: bool,
    wire_steps: bool,
    label: &str,
) -> Result<Option<T>, (ExitStatus, String)>
where
    T: for<'de> Deserialize<'de>,
{
    if wait.no_wait {
        print_operation(&op, json_output, false);
        return Ok(None);
    }
    let op = wait_for_operation(
        config,
        initial_session,
        op,
        Duration::from_secs(u64::from(wait.wait_timeout_seconds)),
        json_output,
        wire_steps,
    )?;
    extract_operation_result(&op, label)
        .map(Some)
        .map_err(|message| (ExitStatus::Error, message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::WaitArgs;

    fn unused_config() -> ResolvedConfig {
        ResolvedConfig::resolve(crate::config::ConfigOverrides {
            config_dir: Some(
                std::env::temp_dir().join(format!("umbra-unused-{}", uuid::Uuid::new_v4())),
            ),
            ..Default::default()
        })
    }

    fn op(status: &str, result: Option<Value>) -> Operation {
        Operation {
            id: "op-1".into(),
            kind: "cvm.launch".into(),
            status: status.into(),
            actor_id: None,
            target: OperationTarget {
                kind: "cvm".into(),
                id: Some("c1".into()),
            },
            result,
            error: None,
            progress: None,
            created_at: "2030-01-01T00:00:00Z".into(),
            updated_at: "2030-01-01T00:00:00Z".into(),
            expires_at: None,
        }
    }

    /// `--no-wait` prints the handle and returns `Ok(None)` without any poll, so
    /// the caller returns success. The unused url/token prove no request is made.
    #[test]
    fn await_result_no_wait_returns_none_success() {
        let wait = WaitArgs {
            no_wait: true,
            wait_timeout_seconds: 60,
        };
        let out: Result<Option<Value>, _> = await_result(
            &unused_config(),
            &crate::test_support::fake_authenticated_session(),
            op("running", None),
            &wait,
            true,
            true,
            "launch",
        );
        assert!(matches!(out, Ok(None)));
    }

    /// An already-terminal `succeeded` operation is extracted into `Some(result)`
    /// without polling (wait_for_operation returns immediately on a terminal op).
    #[test]
    fn await_result_terminal_extracts_result_success() {
        let wait = WaitArgs {
            no_wait: false,
            wait_timeout_seconds: 60,
        };
        let out: Result<Option<Value>, _> = await_result(
            &unused_config(),
            &crate::test_support::fake_authenticated_session(),
            op("succeeded", Some(serde_json::json!({ "id": "c1" }))),
            &wait,
            true,
            true,
            "launch",
        );
        let value = out
            .expect("terminal succeeded extracts")
            .expect("some result");
        assert_eq!(value["id"], serde_json::json!("c1"));
    }

    #[derive(Clone, Copy)]
    enum PollCase {
        Expired,
        ExternalRotation,
        ConcurrentLogin,
        ConcurrentLogout,
        MissingRefresh,
        RejectedRefresh,
        UnauthorizedPoll,
        RateLimited,
    }

    type PollOutcome = Result<Option<Value>, (ExitStatus, String)>;

    /// Real local HTTP exchanges prove bearer selection and resource submission count.
    fn run_poll_case(case: PollCase) -> (PollOutcome, Vec<String>) {
        use crate::{config::ConfigOverrides, session, test_support::fake_authenticated_session};
        use std::{
            fs,
            io::{BufRead, BufReader, Read, Write},
            net::TcpListener,
        };
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let console_url = format!("http://{}", listener.local_addr().unwrap());
        let config = ResolvedConfig::resolve(ConfigOverrides {
            config_dir: Some(
                std::env::temp_dir().join(format!("umbra-poll-{}", uuid::Uuid::new_v4())),
            ),
            console_url: Some(console_url.clone()),
            ..Default::default()
        });
        let mut stored = fake_authenticated_session();
        stored.access_token = "fixture-submit-token".into();
        stored.refresh_token = if matches!(case, PollCase::MissingRefresh) {
            None
        } else {
            Some("fixture-refresh-token".into())
        };
        stored.expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
        stored.refresh_expires_at = Some(chrono::Utc::now() + chrono::Duration::days(1));
        session::write_atomic(&config.config_dir, &stored).unwrap();
        let config_dir = config.config_dir.clone();
        let initial_session = stored.clone();
        let server = thread::spawn(move || {
            let refresh = matches!(
                case,
                PollCase::Expired
                    | PollCase::RejectedRefresh
                    | PollCase::RateLimited
                    | PollCase::ConcurrentLogin
                    | PollCase::ConcurrentLogout
            );
            let complete = matches!(case, PollCase::Expired | PollCase::RateLimited);
            let count = 2 + usize::from(refresh) + usize::from(complete);
            let mut observed = Vec::new();
            for step in 0..count {
                let deadline = Instant::now() + Duration::from_secs(10);
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "mock poll request deadline");
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => panic!("mock poll accept failed"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                let request = line
                    .split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ");
                let mut authorization = None;
                let mut length = 0;
                loop {
                    line.clear();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" {
                        break;
                    }
                    if let Some((name, value)) = line.split_once(':') {
                        if name.eq_ignore_ascii_case("authorization") {
                            authorization = Some(value.trim().to_string());
                        }
                        if name.eq_ignore_ascii_case("content-length") {
                            length = value.trim().parse::<usize>().unwrap();
                        }
                    }
                }
                assert!(length <= 8192);
                let mut body = vec![0; length];
                reader.read_exact(&mut body).unwrap();
                drop(reader);
                let resource_submit = step == 0;
                let first_poll = step == 1;
                let token_refresh = step == 2 && refresh;
                let expected = if resource_submit {
                    "POST /api/v1/cvms/c1/actions/update"
                } else if token_refresh {
                    "POST /api/v1/auth/refresh"
                } else {
                    "GET /api/v1/operations/op-1"
                };
                assert_eq!(request, expected);
                if token_refresh {
                    assert!(authorization.is_none());
                    assert!(
                        serde_json::from_slice::<Value>(&body).unwrap()["refresh_token"]
                            == "fixture-refresh-token"
                    );
                } else {
                    let expected_token = if step < 2 {
                        "Bearer fixture-submit-token"
                    } else {
                        "Bearer fixture-poll-token"
                    };
                    assert!(
                        authorization.as_deref() == Some(expected_token),
                        "unexpected poll credential"
                    );
                }
                observed.push(request);
                let mut status = 200;
                let mut headers = "";
                let response = if token_refresh {
                    // Same-user login/logout during the HTTP refresh must survive CAS.
                    if matches!(case, PollCase::ConcurrentLogin) {
                        stored.access_token = "fixture-foreign-token".into();
                        stored.refresh_token = Some("fixture-foreign-refresh".into());
                        session::write_atomic(&config_dir, &stored).unwrap();
                    }
                    if matches!(case, PollCase::ConcurrentLogout) {
                        session::remove(&config_dir).unwrap();
                    }
                    if matches!(case, PollCase::RejectedRefresh) {
                        status = 401;
                        serde_json::json!({"error":{"code":"UNAUTHORIZED","message":"invalid refresh"}})
                    } else {
                        serde_json::json!({"access_token":"fixture-poll-token","refresh_token":"fixture-rotated-refresh","expires_in":3600,"refresh_expires_in":86400})
                    }
                } else if first_poll && matches!(case, PollCase::UnauthorizedPoll) {
                    status = 401;
                    serde_json::json!({"error":{"code":"UNAUTHORIZED","message":"invalid bearer token"}})
                } else {
                    if first_poll {
                        stored.expires_at = chrono::Utc::now() - chrono::Duration::seconds(1);
                        if matches!(case, PollCase::ExternalRotation) {
                            stored.access_token = "fixture-foreign-token".into();
                            stored.refresh_token = Some("fixture-foreign-refresh".into());
                            stored.expires_at = chrono::Utc::now() + chrono::Duration::hours(1);
                        }
                        if matches!(case, PollCase::MissingRefresh) {
                            stored.refresh_token = None;
                        }
                        session::write_atomic(&config_dir, &stored).unwrap();
                    }
                    if first_poll && matches!(case, PollCase::RateLimited) {
                        status = 429;
                        headers = "Retry-After: 1\r\n";
                        serde_json::json!({})
                    } else {
                        serde_json::to_value(if resource_submit || first_poll {
                            op("running", None)
                        } else {
                            op("succeeded", Some(serde_json::json!({"id":"c1"})))
                        })
                        .unwrap()
                    }
                };
                let body = response.to_string();
                write!(stream,"HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n{body}",body.len()).unwrap();
                stream.flush().unwrap();
            }
            observed
        });
        let accepted: Operation = console::post_json(
            &console_url,
            "fixture-submit-token",
            "/api/v1/cvms/c1/actions/update",
            &serde_json::json!({}),
            "submit fixture update",
        )
        .unwrap();
        let result = await_result(
            &config,
            &initial_session,
            accepted,
            &WaitArgs {
                no_wait: false,
                wait_timeout_seconds: 8,
            },
            true,
            false,
            "CVM update",
        );
        let observed = server.join().expect("bounded mock Console exchanges");
        if matches!(case, PollCase::ConcurrentLogin | PollCase::ExternalRotation) {
            assert!(
                session::load(&config.config_dir)
                    .unwrap()
                    .unwrap()
                    .access_token
                    == "fixture-foreign-token",
                "another login must survive"
            );
        }
        if matches!(case, PollCase::ConcurrentLogout) {
            assert!(
                session::load(&config.config_dir).unwrap().is_none(),
                "logout must survive"
            );
        }
        fs::remove_dir_all(&config.config_dir).unwrap();
        (result, observed)
    }

    /// This operation's own refresh changes the next poll bearer without resubmission.
    #[rstest::rstest]
    #[case::expired(PollCase::Expired, 1)]
    #[case::rate_limited_expiry(PollCase::RateLimited, 1)]
    fn polling_session_changes_complete_without_resubmission_success(
        #[case] case: PollCase,
        #[case] refreshes: usize,
    ) {
        let (result, requests) = run_poll_case(case);
        assert_eq!(result.unwrap().unwrap()["id"], "c1");
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.as_str() == "POST /api/v1/cvms/c1/actions/update")
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.as_str() == "POST /api/v1/auth/refresh")
                .count(),
            refreshes
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.as_str() == "GET /api/v1/operations/op-1")
                .count(),
            2
        );
    }

    /// Auth failures and another login/logout never leak its credentials or resubmit.
    #[rstest::rstest]
    #[case::missing_refresh(PollCase::MissingRefresh, 0)]
    #[case::rejected_refresh(PollCase::RejectedRefresh, 1)]
    #[case::unauthorized_poll(PollCase::UnauthorizedPoll, 0)]
    #[case::external_rotation(PollCase::ExternalRotation, 0)]
    #[case::same_user_login_during_refresh(PollCase::ConcurrentLogin, 1)]
    #[case::logout_during_refresh(PollCase::ConcurrentLogout, 1)]
    fn polling_auth_failure_does_not_retry_or_resubmit_failure(
        #[case] case: PollCase,
        #[case] refreshes: usize,
    ) {
        let (result, requests) = run_poll_case(case);
        let (status, message) = result.unwrap_err();
        assert!(matches!(status, ExitStatus::AuthRequired));
        assert!(
            !message.contains("fixture-submit-token") && !message.contains("fixture-refresh-token")
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.as_str() == "POST /api/v1/cvms/c1/actions/update")
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.as_str() == "POST /api/v1/auth/refresh")
                .count(),
            refreshes
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.as_str() == "GET /api/v1/operations/op-1")
                .count(),
            1
        );
    }

    /// An elapsed wait never refreshes or polls and leaves the operation running.
    #[test]
    fn elapsed_wait_stops_before_session_reload_failure() {
        let result = wait_for_operation(
            &unused_config(),
            &crate::test_support::fake_authenticated_session(),
            op("running", None),
            Duration::ZERO,
            true,
            false,
        );
        assert!(matches!(result, Err((ExitStatus::WaitTimeout, _))));
    }

    /// A malformed terminal payload must not be copied into the CLI diagnostic.
    #[test]
    fn test_extract_operation_result_malformed_value_redaction_failure() {
        let hostile_value = "operation-result-must-not-appear-in-diagnostics";
        let operation = op("succeeded", Some(serde_json::json!(hostile_value)));

        let message = extract_operation_result::<bool>(&operation, "CVM launch")
            .expect_err("a string cannot decode as a boolean result");

        assert_eq!(message, "[error] malformed CVM launch result");
        assert!(!message.contains(hostile_value));
    }

    /// An already-terminal `failed` or `cancelled` operation surfaces as an error
    /// (no poll), keeping the Console's own reason when the envelope carries one
    /// rather than flattening it to a generic message.
    #[rstest::rstest]
    #[case::failed_generic("failed", None, "[error] operation failed")]
    #[case::cancelled_generic("cancelled", None, "[cancelled] operation was cancelled")]
    #[case::cancelled_with_reason(
        "cancelled",
        Some("superseded by a newer update"),
        "[cancelled] superseded by a newer update"
    )]
    fn await_result_terminal_failure(
        #[case] status: &str,
        #[case] reason: Option<&str>,
        #[case] expected: &str,
    ) {
        let wait = WaitArgs {
            no_wait: false,
            wait_timeout_seconds: 60,
        };
        let mut operation = op(status, None);
        operation.error = reason.map(|message| OperationError {
            code: "cancelled".into(),
            message: message.into(),
            details: None,
        });
        let out: Result<Option<Value>, _> = await_result(
            &unused_config(),
            &crate::test_support::fake_authenticated_session(),
            operation,
            &wait,
            true,
            true,
            "launch",
        );
        let (exit_status, message) = out.expect_err("terminal failure surfaces");
        assert!(matches!(exit_status, ExitStatus::Error));
        assert_eq!(message, expected);
    }
}
