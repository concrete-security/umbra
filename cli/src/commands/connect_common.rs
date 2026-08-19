//! Shared plumbing for the `claude connect` / `codex connect` verbs.

use reqwest::{blocking::Client, header::IF_MATCH, StatusCode};
use serde_json::json;
use uuid::Uuid;

use crate::{console::read_etag_only, exit::ExitStatus};

pub(crate) enum AttachOutcome {
    Attached,
    Forbidden,
}

/// Best-effort profile→CVM bind used after a successful mint. `Forbidden`
/// (missing `CVM_MANAGE`) is a soft outcome the caller turns into guidance;
/// every other failure is a hard error.
pub(crate) fn attach_profile(
    console_url: &str,
    access_token: &str,
    cvm_id: &str,
    profile_id: &str,
) -> Result<AttachOutcome, (ExitStatus, String)> {
    let etag_response = Client::new()
        .get(format!("{console_url}/api/v1/cvms/{cvm_id}"))
        .bearer_auth(access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch CVM: {err}"),
            )
        })?;
    let etag = read_etag_only(etag_response, "fetch CVM")?;
    let response = Client::new()
        .post(format!("{console_url}/api/v1/cvms/{cvm_id}/profiles"))
        .bearer_auth(access_token)
        .header(IF_MATCH, etag)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(&json!({ "profile_id": profile_id }))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to attach CVM profile: {err}"),
            )
        })?;
    if response.status() == StatusCode::FORBIDDEN {
        return Ok(AttachOutcome::Forbidden);
    }
    read_etag_only(response, "attach CVM profile")?;
    Ok(AttachOutcome::Attached)
}
