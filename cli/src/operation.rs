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

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{cli::WaitArgs, console, exit::ExitStatus, style};

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
    let response = Client::new()
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
    console_url: &str,
    access_token: &str,
    mut operation: Operation,
    timeout: Duration,
    json_output: bool,
    wire_steps: bool,
) -> Result<Operation, (ExitStatus, String)> {
    let started = Instant::now();
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
                return Err((
                    ExitStatus::Error,
                    "[cancelled] operation was cancelled".to_string(),
                ));
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
            print_operation(&operation, json_output, true);
            return Err((
                ExitStatus::WaitTimeout,
                "[wait_timeout] operation did not complete before timeout".to_string(),
            ));
        }
        thread::sleep(Duration::from_secs(1));
        match fetch_operation(console_url, access_token, &operation.id)? {
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
    console_url: &str,
    access_token: &str,
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
        console_url,
        access_token,
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
            "http://unused",
            "tok",
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
            "http://unused",
            "tok",
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

    /// An already-terminal `failed` operation surfaces as an error (no poll).
    #[test]
    fn await_result_terminal_failed_failure() {
        let wait = WaitArgs {
            no_wait: false,
            wait_timeout_seconds: 60,
        };
        let out: Result<Option<Value>, _> = await_result(
            "http://unused",
            "tok",
            op("failed", None),
            &wait,
            true,
            true,
            "launch",
        );
        assert!(out.is_err());
    }
}
