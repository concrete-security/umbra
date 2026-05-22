use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    config::ResolvedConfig,
    console::{console_session, read_json_response},
    exit::ExitStatus,
    session::Session,
    style,
};

#[derive(Debug, Deserialize, Serialize)]
struct Entity {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct User {
    id: String,
    email: String,
    entity: Entity,
}

#[derive(Debug, Deserialize)]
struct ListPage<T> {
    items: Vec<T>,
}

#[derive(Debug, Deserialize, Serialize)]
struct Profile {
    id: String,
    name: String,
    description: String,
    policy: Value,
    attached_cvm_count: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct Cvm {
    id: String,
    owner: OwnerRef,
    profiles: Vec<ProfileRef>,
    state: String,
    instance_type: Option<String>,
    region: Option<String>,
    ssh_keys: Vec<SshKeyRef>,
    fqdn: Option<String>,
    /// Populated by the Console when `state` is `error` / `failed`. Used by
    /// the `Dev CVMs by profile` section (spec 7.10) as the tail value when
    /// the CVM is not running. Tolerant to absence so it stays None for
    /// healthy CVMs.
    #[serde(default)]
    error_reason: Option<String>,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct OwnerRef {
    id: String,
    email: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct ProfileRef {
    id: String,
    name: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SshKeyRef {
    id: String,
    label: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct SecurityCvm {
    id: String,
    state: String,
    instance_type: Option<String>,
    region: Option<String>,
    policy_version: u64,
    created_at: String,
}

#[derive(Debug, Deserialize)]
struct ConsoleSshKey {
    id: String,
    label: String,
    fingerprint: String,
    public_key: String,
}

#[derive(Debug, Serialize)]
struct SshKeyOutput {
    id: String,
    label: String,
    algorithm: String,
    fingerprint: String,
}

#[derive(Debug, Serialize)]
struct Totals {
    profiles: usize,
    dev_cvms: usize,
    dev_cvms_running: usize,
    ssh_keys: usize,
}

#[derive(Debug, Serialize)]
struct StatusOutput {
    user: StatusUser,
    entity: Entity,
    security_cvm: Option<SecurityCvm>,
    /// True when the caller lacks `SECURITY_CVM_CONFIGURE` (HTTP 403 on the
    /// SC read). The human renderer omits the Security CVM section entirely
    /// in that case; the JSON output sets `security_cvm` to `null` (same as
    /// "no SC provisioned" -- the two states are not distinguishable in JSON
    /// today and that is acceptable because previously the command crashed
    /// outright).
    #[serde(skip)]
    security_cvm_hidden: bool,
    profiles: Vec<Profile>,
    dev_cvms: Vec<Cvm>,
    ssh_keys: Vec<SshKeyOutput>,
    totals: Totals,
}

#[derive(Debug, Serialize)]
struct StatusUser {
    id: String,
    email: String,
}

pub fn run(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let profile_id = match optional_profile_filter(config) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let status = match fetch_status(console_url, &session, profile_id.as_deref()) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    print_status(&status, json_output, config.console_url.as_deref());
    ExitStatus::Ok
}

fn optional_profile_filter(config: &ResolvedConfig) -> Result<Option<String>, String> {
    if config.profile_flags.len() > 1 {
        return Err("[usage] expected at most one --profile for status".to_string());
    }
    if let Some(profile_id) = config.profile_flags.first() {
        Uuid::parse_str(profile_id).map_err(|_| "[usage] --profile must be a UUID".to_string())?;
        Ok(Some(profile_id.clone()))
    } else {
        Ok(None)
    }
}

fn fetch_status(
    console_url: &str,
    session: &Session,
    profile_id: Option<&str>,
) -> Result<StatusOutput, (ExitStatus, String)> {
    let user = fetch_me(console_url, session)?;
    let (security_cvm, security_cvm_hidden) =
        match fetch_security_cvm_optional(console_url, session)? {
            SecurityCvmFetch::Visible(sc) => (Some(sc), false),
            SecurityCvmFetch::NotProvisioned => (None, false),
            SecurityCvmFetch::Hidden => (None, true),
        };
    let mut profiles = fetch_profiles(console_url, session)?.items;
    if let Some(profile_id) = profile_id {
        profiles.retain(|profile| profile.id == profile_id);
    }
    let dev_cvms = fetch_cvms(console_url, session, profile_id)?.items;
    let ssh_keys = fetch_keys(console_url, session)?
        .items
        .iter()
        .map(key_output)
        .collect::<Vec<_>>();
    let totals = Totals {
        profiles: profiles.len(),
        dev_cvms: dev_cvms.len(),
        dev_cvms_running: dev_cvms.iter().filter(|cvm| cvm.state == "RUNNING").count(),
        ssh_keys: ssh_keys.len(),
    };
    Ok(StatusOutput {
        user: StatusUser {
            id: user.id,
            email: user.email,
        },
        entity: user.entity,
        security_cvm,
        security_cvm_hidden,
        profiles,
        dev_cvms,
        ssh_keys,
        totals,
    })
}

fn fetch_me(console_url: &str, session: &Session) -> Result<User, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/me"))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch session identity: {err}"),
            )
        })?;
    read_json_response(response, "fetch session identity")
}

fn fetch_profiles(
    console_url: &str,
    session: &Session,
) -> Result<ListPage<Profile>, (ExitStatus, String)> {
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

fn fetch_cvms(
    console_url: &str,
    session: &Session,
    profile_id: Option<&str>,
) -> Result<ListPage<Cvm>, (ExitStatus, String)> {
    let mut request = Client::new()
        .get(format!("{console_url}/api/v1/cvms"))
        .bearer_auth(&session.access_token);
    if let Some(profile_id) = profile_id {
        request = request.query(&[("profile_id", profile_id)]);
    }
    let response = request.send().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to list CVMs: {err}"),
        )
    })?;
    read_json_response(response, "list CVMs")
}

fn fetch_keys(
    console_url: &str,
    session: &Session,
) -> Result<ListPage<ConsoleSshKey>, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/me/keys"))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to list SSH keys: {err}"),
            )
        })?;
    read_json_response(response, "list SSH keys")
}

/// Result of attempting to fetch the entity's Security CVM. The caller may
/// lack the `SECURITY_CVM_CONFIGURE` permission required by the Console
/// endpoint (console.md section 3.7); in that case the CLI MUST silently
/// omit the Security CVM section from `concrete status` instead of failing
/// the whole command. See cli-style.md section 7.10.
enum SecurityCvmFetch {
    /// The endpoint returned the SC record.
    Visible(SecurityCvm),
    /// HTTP 404 -- the entity has no live SC.
    NotProvisioned,
    /// HTTP 403 -- caller lacks `SECURITY_CVM_CONFIGURE`. Render as if the
    /// section did not exist for this caller.
    Hidden,
}

fn fetch_security_cvm_optional(
    console_url: &str,
    session: &Session,
) -> Result<SecurityCvmFetch, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!(
            "{console_url}/api/v1/entities/{}/security-cvm",
            session.entity.id
        ))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch Security CVM: {err}"),
            )
        })?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(SecurityCvmFetch::NotProvisioned);
    }
    if response.status() == reqwest::StatusCode::FORBIDDEN {
        return Ok(SecurityCvmFetch::Hidden);
    }
    read_json_response(response, "fetch Security CVM").map(SecurityCvmFetch::Visible)
}

fn key_output(key: &ConsoleSshKey) -> SshKeyOutput {
    SshKeyOutput {
        id: key.id.clone(),
        label: key.label.clone(),
        algorithm: key
            .public_key
            .split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string(),
        fingerprint: key.fingerprint.clone(),
    }
}

fn print_status(status: &StatusOutput, json_output: bool, console_url: Option<&str>) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(status).expect("status output serializes")
        );
        return;
    }
    let sc_view = status
        .security_cvm
        .as_ref()
        .map(|sc| style::StatusSecurityCvm {
            id: &sc.id,
            state: &sc.state,
            region: sc.region.as_deref(),
            instance_type: sc.instance_type.as_deref(),
            policy_version: sc.policy_version,
        });
    let mut state_counts: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    for cvm in &status.dev_cvms {
        *state_counts
            .entry(cvm.state.to_ascii_lowercase())
            .or_insert(0) += 1;
    }
    let totals_breakdown: Vec<(String, usize)> = state_counts.into_iter().collect();
    let profile_summaries: Vec<style::StatusProfileSummary<'_>> = status
        .profiles
        .iter()
        .map(|p| style::StatusProfileSummary {
            id: &p.id,
            name: &p.name,
            attached_cvm_count: p.attached_cvm_count,
        })
        .collect();
    let key_summaries: Vec<style::StatusKeySummary<'_>> = status
        .ssh_keys
        .iter()
        .map(|k| style::StatusKeySummary {
            id: &k.id,
            label: &k.label,
            fingerprint: &k.fingerprint,
            algorithm: &k.algorithm,
        })
        .collect();
    // Section 7.10 / cli.md section 3.6: group Dev CVMs under the profiles
    // the caller belongs to. A CVM attached to multiple profiles appears
    // under each. The tail value is the FQDN when running, otherwise the
    // CVM's error_reason field (or `-`).
    let lower_running = "running";
    let dev_cvms_by_profile: Vec<style::StatusDevCvmsByProfile<'_>> = status
        .profiles
        .iter()
        .map(|profile| {
            let cvms: Vec<style::StatusDevCvmRow<'_>> = status
                .dev_cvms
                .iter()
                .filter(|cvm| {
                    cvm.profiles
                        .iter()
                        .any(|profile_ref| profile_ref.id == profile.id)
                })
                .map(|cvm| {
                    let state_lower = cvm.state.to_ascii_lowercase();
                    let tail = if state_lower == lower_running {
                        cvm.fqdn.as_deref().unwrap_or("-")
                    } else {
                        cvm.error_reason.as_deref().unwrap_or("-")
                    };
                    style::StatusDevCvmRow {
                        id: &cvm.id,
                        state: &cvm.state,
                        tail,
                    }
                })
                .collect();
            style::StatusDevCvmsByProfile {
                profile_name: &profile.name,
                cvms,
            }
        })
        .collect();
    let view = style::StatusView {
        user_email: &status.user.email,
        user_id: &status.user.id,
        entity_name: &status.entity.name,
        entity_id: &status.entity.id,
        console_url,
        security_cvm: sc_view,
        security_cvm_hidden: status.security_cvm_hidden,
        totals_profiles: status.totals.profiles,
        totals_dev_cvms: status.totals.dev_cvms,
        totals_dev_cvms_state_breakdown: totals_breakdown,
        totals_ssh_keys: status.totals.ssh_keys,
        dev_cvms_by_profile,
        profiles: profile_summaries,
        ssh_keys: key_summaries,
    };
    println!("{}", style::status_multi_section(&view));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_output_extracts_algorithm() {
        let key = ConsoleSshKey {
            id: "key-1".to_string(),
            label: "workstation".to_string(),
            fingerprint: "SHA256:abc".to_string(),
            public_key: "ssh-ed25519 AAAA comment".to_string(),
        };

        assert_eq!(key_output(&key).algorithm, "ssh-ed25519");
    }
}
