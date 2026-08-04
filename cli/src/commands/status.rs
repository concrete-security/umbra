use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

use crate::{
    config::ResolvedConfig,
    console::{console_session, fetch_json, read_json_response, ListPage},
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
    /// today, which is acceptable).
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
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let status = try_or_eprintln!(fetch_status(console_url, &session, profile_id.as_deref()));
    print_status(&status, json_output, config.console_url.as_deref());
    ExitStatus::Ok
}

fn optional_profile_filter(config: &ResolvedConfig) -> Result<Option<String>, String> {
    if config.profile_flags.len() > 1 {
        return Err("[usage] expected at most one --profile for status".to_string());
    }
    match config.profile_flags.first() {
        Some(raw) => {
            // Resolve an alias to its id (a raw UUID passes straight through), so
            // `--profile <alias>` works here as everywhere a profile id is taken.
            let id = crate::commands::alias::resolve_or_passthrough(
                config,
                crate::commands::alias::AliasKind::Profile,
                raw,
            )?;
            Uuid::parse_str(&id)
                .map_err(|_| "[usage] --profile must be a UUID or a known alias".to_string())?;
            Ok(Some(id))
        }
        None => Ok(None),
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
    fetch_json(
        console_url,
        session,
        "/api/v1/me",
        &[],
        "fetch session identity",
    )
}

fn fetch_profiles(
    console_url: &str,
    session: &Session,
) -> Result<ListPage<Profile>, (ExitStatus, String)> {
    let path = format!("/api/v1/entities/{}/profiles", session.entity.id);
    fetch_json(console_url, session, &path, &[], "list profiles")
}

fn fetch_cvms(
    console_url: &str,
    session: &Session,
    profile_id: Option<&str>,
) -> Result<ListPage<Cvm>, (ExitStatus, String)> {
    let query = match profile_id {
        Some(profile_id) => vec![("profile_id", profile_id.to_string())],
        None => Vec::new(),
    };
    fetch_json(console_url, session, "/api/v1/cvms", &query, "list CVMs")
}

fn fetch_keys(
    console_url: &str,
    session: &Session,
) -> Result<ListPage<ConsoleSshKey>, (ExitStatus, String)> {
    fetch_json(
        console_url,
        session,
        "/api/v1/me/keys",
        &[],
        "list SSH keys",
    )
}

/// Result of attempting to fetch the entity's Security CVM. The caller may
/// lack the `SECURITY_CVM_CONFIGURE` permission required by the Console
/// endpoint (console.md section 3.7); in that case the CLI MUST silently
/// omit the Security CVM section from `umbra status` instead of failing
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
        style::emit_json(status);
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
    use rstest::rstest;

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

    const PROFILE_UUID: &str = "16286507-f87f-449e-a229-be04067fc23c";

    /// A `ResolvedConfig` on a throwaway config dir with the given `--profile`
    /// flags — no Console needed, `optional_profile_filter` only reads local state.
    fn config_with_profile_flags(flags: &[&str]) -> ResolvedConfig {
        let dir = std::env::temp_dir().join(format!("umbra-status-test-{}", uuid::Uuid::new_v4()));
        ResolvedConfig::resolve(crate::config::ConfigOverrides {
            config_dir: Some(dir),
            profile: flags.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        })
    }

    /// `status --profile` accepts an alias as well as a raw UUID (resolves to the
    /// id), and no flag yields no filter. Pins that status honours the alias store,
    /// not just UUIDs.
    #[rstest]
    #[case::alias(&["prod"], Some(PROFILE_UUID))]
    #[case::raw_uuid(&[PROFILE_UUID], Some(PROFILE_UUID))]
    #[case::none(&[], None)]
    fn test_optional_profile_filter_resolves_alias_success(
        #[case] flags: &[&str],
        #[case] expected: Option<&str>,
    ) {
        let config = config_with_profile_flags(flags);
        let mut store = crate::commands::alias::Aliases::default();
        store.profile.insert("prod".into(), PROFILE_UUID.into());
        crate::commands::alias::save(&config.config_dir, &store).expect("seed store");
        assert_eq!(
            optional_profile_filter(&config).unwrap(),
            expected.map(str::to_string)
        );
    }

    /// An unknown `--profile` name is rejected, and more than one `--profile` is a
    /// usage error for status (it filters by a single profile).
    #[rstest]
    #[case::unknown(&["ghost"], "must be a UUID or a known alias")]
    #[case::too_many(&[PROFILE_UUID, PROFILE_UUID], "at most one --profile")]
    fn test_optional_profile_filter_failure(#[case] flags: &[&str], #[case] expected: &str) {
        let config = config_with_profile_flags(flags);
        assert!(optional_profile_filter(&config)
            .expect_err("bad profile flags are rejected")
            .contains(expected));
    }
}
