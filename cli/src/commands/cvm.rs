use std::{
    collections::BTreeMap,
    env,
    fs::{self, OpenOptions},
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use reqwest::{blocking::Client, header::IF_MATCH};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    cli::{
        wire, CvmCommand, CvmInstanceTypesArgs, CvmLaunchArgs, CvmListArgs, CvmTerminateArgs,
        CvmUpdateArgs,
    },
    commands::{alias, select_cvm},
    config::{self, ResolvedConfig},
    console::{
        fetch_json, post_json, push_query, read_json_response, read_with_etag, send, validate_uuid,
        ListPage,
    },
    exit::ExitStatus,
    operation::{self, Operation},
    session::Session,
    ssh_identity::{self, persistable_path},
    ssh_identity_store, style,
};

// Every Console-response struct carries an `extra` catch-all (per
// `docs/specs/cli-style.md` §11.7): unknown fields are CAPTURED rather than
// silently dropped, so `has_unknown_fields()` can flag a Console/CLI version
// skew, while `skip_serializing` keeps `--json` a strict whitelist.
#[derive(Debug, Deserialize, Serialize)]
struct InstanceTypesResponse {
    instance_types: Vec<InstanceTypeEntry>,
    catalog: CatalogMetadata,
    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
}

impl InstanceTypesResponse {
    /// True when the Console returned any field this CLI build does not model --
    /// a signal the CLI may be out of date. Unknown fields are captured (not
    /// dropped) so this can surface a drift note without leaking them to `--json`.
    fn has_unknown_fields(&self) -> bool {
        !self.extra.is_empty()
            || !self.catalog.extra.is_empty()
            || self
                .catalog
                .last_refresh_error
                .as_ref()
                .is_some_and(|e| !e.extra.is_empty())
            || self.instance_types.iter().any(|e| !e.extra.is_empty())
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct InstanceTypeEntry {
    name: String,
    family: Option<String>,
    vcpu: Option<u64>,
    memory_gb: Option<f64>,
    hourly_rate: Option<f64>,
    currency: Option<String>,
    #[serde(default)]
    default: bool,
    // Default true so a response from an older Console that predates this field
    // renders as launchable rather than spuriously "not supported yet".
    #[serde(default = "default_true")]
    launchable: bool,
    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize, Serialize)]
struct CatalogMetadata {
    source: String,
    fetched_at: Option<String>,
    stale: bool,
    #[serde(default)]
    refresh_in_progress: bool,
    last_refresh_error: Option<CatalogRefreshError>,
    // Console-side drift report, machine-readable: expected provider field -> how
    // many entries failed to parse it. Empty == the provider schema still matches.
    // The CLI renders the human sentence; the wire stays wording-free.
    #[serde(default)]
    field_miss_counts: BTreeMap<String, u64>,
    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct CatalogRefreshError {
    kind: String,
    field: Option<String>,
    at: Option<String>,
    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Deserialize)]
struct LaunchProfile {
    id: String,
    name: String,
    assigned: bool,
}

#[derive(Debug, Deserialize)]
struct ConsoleSshKey {
    id: String,
    label: String,
    fingerprint: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Cvm {
    id: String,
    owner: OwnerRef,
    entity_id: String,
    profiles: Vec<ProfileRef>,
    state: String,
    instance_type: Option<String>,
    region: Option<String>,
    disk_size_gb: Option<u64>,
    ssh_keys: Vec<SshKeyRef>,
    fqdn: Option<String>,
    expected_image_measurement: Option<String>,
    image_measurement: Option<String>,
    rtmr3_digest: Option<String>,
    attestation_verified_at: Option<String>,
    error_reason: Option<String>,
    created_at: String,
    updated_at: String,

    /// Forward-compat per `docs/specs/cli-style.md` section 11.7: catch any
    /// new fields the Console adds so the human renderer can still surface
    /// them. `skip_serializing` keeps `--json` restricted to the fields the
    /// CLI explicitly knows, so a future sensitive Console field would NOT
    /// leak through `--json` until the CLI is updated.
    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
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

#[derive(Debug, Deserialize)]
struct CvmLaunchResult {
    cvm: Cvm,
    policy_bundle: PolicyBundle,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PolicyBundle {
    cvm_id: String,
    compose_template: String,
    expected_bootchain: Value,
    os_image_hash: String,
    rtmr3_binding: Value,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Debug, Serialize)]
struct CvmLaunchOutput {
    #[serde(flatten)]
    cvm: Cvm,
    policy_file_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_file_status: Option<String>,
}

#[derive(Clone, Copy, Debug)]
enum PolicyWriteStatus {
    Installed,
    Unchanged,
    ReplacedAfterConfirmation,
}

impl PolicyWriteStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Unchanged => "unchanged",
            Self::ReplacedAfterConfirmation => "replaced_after_confirmation",
        }
    }
}

#[derive(Clone, Copy)]
enum Mutation {
    Attach,
    Detach,
}

impl Mutation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Attach => "attach",
            Self::Detach => "detach",
        }
    }
}

#[derive(Clone, Copy)]
enum LifecycleAction {
    Start,
    Stop,
}

impl LifecycleAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
        }
    }

    fn past_tense(self) -> &'static str {
        match self {
            Self::Start => "started",
            Self::Stop => "stopped",
        }
    }
}

pub fn run(command: CvmCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        CvmCommand::List(args) => list(config, args, json),
        CvmCommand::InstanceTypes(args) => instance_types(config, args, json),
        CvmCommand::Launch(args) => launch(config, args, json),
        CvmCommand::Attach { target } => {
            match select_cvm(
                target.cvm_id.as_deref(),
                target.cvm.as_deref(),
                &[config.default_cvm.as_deref()],
                config,
            ) {
                Ok(cvm_id) => profile_mutation(config, &cvm_id, Mutation::Attach, json),
                Err(message) => {
                    style::eprintln_error(&message);
                    ExitStatus::Usage
                }
            }
        }
        CvmCommand::Detach { target } => {
            match select_cvm(
                target.cvm_id.as_deref(),
                target.cvm.as_deref(),
                &[config.default_cvm.as_deref()],
                config,
            ) {
                Ok(cvm_id) => profile_mutation(config, &cvm_id, Mutation::Detach, json),
                Err(message) => {
                    style::eprintln_error(&message);
                    ExitStatus::Usage
                }
            }
        }
        CvmCommand::Start { target } => {
            match select_cvm(
                target.cvm_id.as_deref(),
                target.cvm.as_deref(),
                &[config.default_cvm.as_deref()],
                config,
            ) {
                Ok(cvm_id) => lifecycle_action(config, &cvm_id, LifecycleAction::Start, json),
                Err(message) => {
                    style::eprintln_error(&message);
                    ExitStatus::Usage
                }
            }
        }
        CvmCommand::Stop { target } => {
            match select_cvm(target.cvm_id.as_deref(), target.cvm.as_deref(), &[], config) {
                Ok(cvm_id) => lifecycle_action(config, &cvm_id, LifecycleAction::Stop, json),
                Err(message) => {
                    style::eprintln_error(&message);
                    ExitStatus::Usage
                }
            }
        }
        CvmCommand::Update(args) => update(config, args, json),
        CvmCommand::Terminate(args) => terminate(config, args, json),
    }
}

fn list(config: &ResolvedConfig, args: CvmListArgs, json_output: bool) -> ExitStatus {
    let profile_id = match optional_profile_filter(config) {
        Ok(value) => value,
        Err(message) => {
            style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let (console_url, session) = try_or_eprintln!(crate::console::console_session(config));
    // Assemble the query string `?state=..&profile_id=..` from --state and the
    // global --profile. The Console does the filtering, not the CLI.
    let mut query = args.query_params();
    push_query(&mut query, "profile_id", &profile_id);
    let page: ListPage<Cvm> = try_or_eprintln!(fetch_json(
        console_url,
        &session,
        "/api/v1/cvms",
        &query,
        "list CVMs"
    ));
    let state_filter = args.state.map(wire);
    print_cvm_list(
        page,
        json_output,
        profile_id.as_deref(),
        state_filter.as_deref(),
    );
    ExitStatus::Ok
}

impl CvmListArgs {
    fn query_params(&self) -> Vec<(&'static str, String)> {
        let mut query: Vec<(&'static str, String)> = Vec::new();
        // No --state -> send no `state` param (the Console defaults to alive).
        // Otherwise send its lowercase value (incl. an explicit `--state alive`).
        if let Some(state) = self.state {
            query.push(("state", wire(state)));
        }
        query
    }
}

fn instance_types(
    config: &ResolvedConfig,
    args: CvmInstanceTypesArgs,
    json_output: bool,
) -> ExitStatus {
    let (console_url, session) = try_or_eprintln!(crate::console::console_session(config));
    let mut query: Vec<(&'static str, String)> = Vec::new();
    if args.refresh {
        query.push(("refresh", "true".to_string()));
    }
    let response: InstanceTypesResponse = try_or_eprintln!(fetch_json(
        console_url,
        &session,
        "/api/v1/instance-types",
        &query,
        "get instance types",
    ));
    if json_output {
        style::emit_json(&response);
        return ExitStatus::Ok;
    }
    if response.has_unknown_fields() {
        eprintln!("{}", style::unknown_fields_note());
    }
    let rows: Vec<style::InstanceTypeRow<'_>> = response
        .instance_types
        .iter()
        .map(|entry| style::InstanceTypeRow {
            name: &entry.name,
            family: entry.family.as_deref(),
            vcpu: entry.vcpu,
            memory_gb: entry.memory_gb,
            is_default: entry.default,
            launchable: entry.launchable,
        })
        .collect();
    println!("{}", style::instance_types_table(&rows));
    let note = style::catalog_note(&style::CatalogNote {
        source: &response.catalog.source,
        fetched_at: response.catalog.fetched_at.as_deref(),
        stale: response.catalog.stale,
        refresh_in_progress: response.catalog.refresh_in_progress,
        last_refresh_error_kind: response
            .catalog
            .last_refresh_error
            .as_ref()
            .map(|err| err.kind.as_str()),
        refresh_requested: args.refresh,
    });
    if let Some(note) = note {
        eprintln!("{note}");
    }
    let total = response.instance_types.len();
    for (field, &count) in &response.catalog.field_miss_counts {
        eprintln!("{}", style::field_miss_note(field, count, total));
    }
    ExitStatus::Ok
}

fn launch(config: &ResolvedConfig, args: CvmLaunchArgs, json_output: bool) -> ExitStatus {
    if let Some(nick) = args.alias.as_deref() {
        if args.wait.no_wait {
            style::eprintln_error(
                "[usage] --alias cannot be combined with --no-wait; the CVM id is not known until launch completes",
            );
            return ExitStatus::Usage;
        }
        // Fail fast on a bad/taken alias before launching anything.
        if let Err((status, message)) = alias::check_new_alias(config, nick) {
            style::eprintln_error(&message);
            return status;
        }
    }
    let (console_url, session) = try_or_eprintln!(crate::console::console_session(config));
    let launch = try_or_eprintln!(prepare_launch(config, console_url, &session, &args));
    let op = try_or_eprintln!(submit_launch(console_url, &session.access_token, &launch));
    let result: CvmLaunchResult = match try_or_eprintln!(operation::await_result(
        console_url,
        &session.access_token,
        op,
        &args.wait,
        json_output,
        true,
        "CVM launch",
    )) {
        Some(value) => value,
        None => return ExitStatus::Ok,
    };
    // Record the alias as soon as the CVM exists, so a later failure writing the
    // policy file or defaults cannot silently lose it.
    if let Some(nick) = args.alias.as_deref() {
        if let Err(message) =
            alias::record_resource_alias(config, alias::AliasKind::Cvm, &result.cvm.id, nick)
        {
            style::eprintln_warn(&format!(
                "[warn] CVM launched but alias not saved: {message}"
            ));
        }
    }
    let policy_file =
        match write_policy_file(&config.config_dir, &result.policy_bundle, &result.cvm.id) {
            Ok(value) => value,
            Err(message) => {
                style::eprintln_error(&message);
                return ExitStatus::Error;
            }
        };
    if let Err(message) = persist_launch_defaults(
        config,
        &result.cvm,
        &launch.profile_ids,
        launch.ssh_identity.as_deref(),
    ) {
        style::eprintln_error(&message);
        return ExitStatus::Error;
    }
    print_launch_result(result.cvm, policy_file, args.alias.as_deref(), json_output);
    ExitStatus::Ok
}

fn profile_mutation(
    config: &ResolvedConfig,
    cvm_id: &str,
    mutation: Mutation,
    json_output: bool,
) -> ExitStatus {
    if let Err(message) = validate_uuid("CVM_ID", cvm_id) {
        style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    let profile_id = try_or_eprintln!(selected_profile(config));
    let (console_url, session) = try_or_eprintln!(crate::console::console_session(config));
    let (_, etag) = try_or_eprintln!(fetch_cvm_with_etag(console_url, &session, cvm_id));
    let cvm = try_or_eprintln!(mutate_profile(
        console_url,
        &session.access_token,
        cvm_id,
        &etag,
        &profile_id,
        mutation,
    ))
    .0;
    if json_output {
        style::emit_json(&cvm);
    } else {
        // Sync mutation: render the section 6.4 confirm template. The verb
        // matches the requested action; the entity-noun is `profile`; the
        // identifier is the profile id (the verb's subject), and the cvm
        // appears as a detail row.
        let confirm =
            style::ConfirmBlock::new(format!("{}ed", mutation.as_str()), "profile", profile_id)
                .field("cvm", cvm.id.clone());
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn lifecycle_action(
    config: &ResolvedConfig,
    cvm_id: &str,
    action: LifecycleAction,
    json_output: bool,
) -> ExitStatus {
    if let Err(message) = validate_uuid("CVM_ID", cvm_id) {
        style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    let (console_url, session) = try_or_eprintln!(crate::console::console_session(config));
    let (_, etag) = try_or_eprintln!(fetch_cvm_with_etag(console_url, &session, cvm_id));
    let cvm = try_or_eprintln!(submit_lifecycle_action(
        console_url,
        &session.access_token,
        cvm_id,
        &etag,
        action
    ))
    .0;
    // Stopping a CVM kills its sessions (they live in the CVM's tmpfs `/run`);
    // drop their now-stale aliases, but keep the CVM's own alias — it can be
    // restarted. `start` leaves the store untouched.
    if matches!(action, LifecycleAction::Stop) {
        alias::prune_and_save(config, |a| a.prune(alias::Prune::CvmSessions(cvm_id)));
    }
    print_lifecycle_result(action, &cvm, json_output);
    ExitStatus::Ok
}

fn update(config: &ResolvedConfig, args: CvmUpdateArgs, json_output: bool) -> ExitStatus {
    let cvm_id = match select_cvm(
        args.target.cvm_id.as_deref(),
        args.target.cvm.as_deref(),
        &[config.default_cvm.as_deref()],
        config,
    ) {
        Ok(value) => value,
        Err(message) => {
            style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    if let Err(message) = validate_uuid("CVM_ID", &cvm_id) {
        style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    let (console_url, session) = try_or_eprintln!(crate::console::console_session(config));
    let (_, etag) = try_or_eprintln!(fetch_cvm_with_etag(console_url, &session, &cvm_id));
    let op = try_or_eprintln!(submit_update(
        console_url,
        &session.access_token,
        &cvm_id,
        &etag
    ));
    let result: CvmLaunchResult = match try_or_eprintln!(operation::await_result(
        console_url,
        &session.access_token,
        op,
        &args.wait,
        json_output,
        true,
        "CVM update",
    )) {
        Some(value) => value,
        None => return ExitStatus::Ok,
    };
    let (policy_file, policy_status) = match write_policy_file_after_update(
        &config.config_dir,
        &result.policy_bundle,
        &result.cvm.id,
        json_output,
    ) {
        Ok(value) => value,
        Err(message) => {
            style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    print_update_result(result.cvm, policy_file, policy_status, json_output);
    ExitStatus::Ok
}

fn terminate(config: &ResolvedConfig, args: CvmTerminateArgs, json_output: bool) -> ExitStatus {
    let cvm_id = match select_cvm(
        args.target.cvm_id.as_deref(),
        args.target.cvm.as_deref(),
        &[],
        config,
    ) {
        Ok(value) => value,
        Err(message) => {
            style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    if let Err(message) = validate_uuid("CVM_ID", &cvm_id) {
        style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    let (console_url, session) = try_or_eprintln!(crate::console::console_session(config));
    let (_, etag) = try_or_eprintln!(fetch_cvm_with_etag(console_url, &session, &cvm_id));
    let op = try_or_eprintln!(submit_terminate(
        console_url,
        &session.access_token,
        &cvm_id,
        &etag
    ));
    let cvm: Cvm = match try_or_eprintln!(operation::await_result(
        console_url,
        &session.access_token,
        op,
        &args.wait,
        json_output,
        true,
        "CVM",
    )) {
        Some(value) => value,
        // The teardown is only submitted, not confirmed complete (--no-wait), so
        // the alias is left in place — a later `alias prune` (or a waited
        // terminate) reconciles it once the CVM is actually gone.
        None => return ExitStatus::Ok,
    };
    // The CVM is now confirmed terminated; drop its alias and any session
    // aliases bound to it (best-effort, never fails the terminate).
    alias::prune_and_save(config, |a| a.prune(alias::Prune::Cvm(&cvm_id)));
    print_terminate_result(&cvm, json_output);
    ExitStatus::Ok
}

struct LaunchRequest {
    profile_ids: Vec<String>,
    ssh_key_ids: Vec<String>,
    ssh_identity: Option<PathBuf>,
    instance_type: Option<String>,
    region: Option<String>,
    disk_size_gb: Option<u32>,
}

fn prepare_launch(
    config: &ResolvedConfig,
    console_url: &str,
    session: &Session,
    args: &CvmLaunchArgs,
) -> Result<LaunchRequest, (ExitStatus, String)> {
    let profile_ids = selected_launch_profiles(config, console_url, session)?;
    if args.ssh_keys.len() > 16 {
        return Err((
            ExitStatus::Usage,
            "[usage] at most 16 --ssh-key values are supported".to_string(),
        ));
    }
    let (ssh_key_ids, ssh_identity) = selected_launch_ssh_keys(config, console_url, session, args)?;
    let instance_type = args
        .instance_type
        .clone()
        .or_else(|| config.default_instance_type.clone());
    let region = args
        .region
        .clone()
        .or_else(|| config.default_region.clone());
    if let Some(value) = instance_type.as_deref() {
        validate_cvm_config_value("--instance-type", value)
            .map_err(|message| (ExitStatus::Usage, message))?;
    }
    if let Some(value) = region.as_deref() {
        validate_cvm_config_value("--region", value)
            .map_err(|message| (ExitStatus::Usage, message))?;
    }
    Ok(LaunchRequest {
        profile_ids,
        ssh_key_ids,
        ssh_identity,
        instance_type,
        region,
        // Disk size has no CLI-side default: send only what the user passed and
        // let the Console apply DEV_CVM_DEFAULT_DISK_GB when omitted. clap has
        // already range-checked the flag value.
        disk_size_gb: args.disk_size,
    })
}

fn selected_launch_profiles(
    config: &ResolvedConfig,
    console_url: &str,
    session: &Session,
) -> Result<Vec<String>, (ExitStatus, String)> {
    let profiles = if config.profile_flags.is_empty() {
        match config.profile.clone() {
            Some(profile) => vec![profile],
            None => auto_select_profile(console_url, session)?,
        }
    } else {
        config.profile_flags.clone()
    };
    // Translate any profile aliases to UUIDs before validation. A raw UUID (or
    // an auto-selected id) passes through without touching the alias store.
    let profiles: Vec<String> = profiles
        .into_iter()
        .map(|profile| alias::resolve_or_passthrough(config, alias::AliasKind::Profile, &profile))
        .collect::<Result<_, _>>()
        .map_err(|message| (ExitStatus::Usage, message))?;
    if profiles.len() > 16 {
        return Err((
            ExitStatus::Usage,
            "[usage] at most 16 --profile values are supported for cvm launch".to_string(),
        ));
    }
    for profile_id in &profiles {
        validate_uuid("--profile", profile_id).map_err(|message| (ExitStatus::Usage, message))?;
    }
    Ok(profiles)
}

fn auto_select_profile(
    console_url: &str,
    session: &Session,
) -> Result<Vec<String>, (ExitStatus, String)> {
    let page = fetch_launch_profiles(console_url, session)?;
    let assigned = page
        .items
        .into_iter()
        .filter(|profile| profile.assigned)
        .collect::<Vec<_>>();
    match assigned.as_slice() {
        [profile] => {
            // Informational status note on stderr, styled per section 6.5
            // info_line (cyan, terse, never crosses into stdout). This is
            // NOT an error, NOT a confirm block -- just guidance during
            // auto-resolution of a single-value default.
            eprintln!(
                "{}",
                style::info_line(&format!("using profile {} ({})", profile.name, profile.id))
            );
            Ok(vec![profile.id.clone()])
        }
        [] => Err((
            ExitStatus::Usage,
            "[usage] no assigned profiles found; ask an admin to assign you a profile".to_string(),
        )),
        profiles => {
            eprintln!("{}", style::info_line("available profiles:"));
            for profile in profiles {
                eprintln!(
                    "{}",
                    style::info_line(&format!("  {} {}", profile.id, profile.name))
                );
            }
            Err((
                ExitStatus::Usage,
                "[usage] multiple assigned profiles found; rerun with --profile <PROFILE_ID>"
                    .to_string(),
            ))
        }
    }
}

fn selected_launch_ssh_keys(
    config: &ResolvedConfig,
    console_url: &str,
    session: &Session,
    args: &CvmLaunchArgs,
) -> Result<(Vec<String>, Option<PathBuf>), (ExitStatus, String)> {
    if !args.ssh_keys.is_empty() {
        // Translate any ssh-key aliases to UUIDs before validation. A raw UUID
        // passes through without touching the alias store.
        let ssh_keys: Vec<String> = args
            .ssh_keys
            .iter()
            .map(|id| alias::resolve_or_passthrough(config, alias::AliasKind::SshKey, id))
            .collect::<Result<_, _>>()
            .map_err(|message| (ExitStatus::Usage, message))?;
        for ssh_key_id in &ssh_keys {
            validate_uuid("--ssh-key", ssh_key_id)
                .map_err(|message| (ExitStatus::Usage, message))?;
        }
        let keys = fetch_launch_keys(console_url, session)?;
        let selected = keys
            .items
            .iter()
            .filter(|key| ssh_keys.iter().any(|id| id == &key.id))
            .collect::<Vec<_>>();
        let fingerprints = selected
            .iter()
            .map(|key| key.fingerprint.clone())
            .collect::<Vec<_>>();
        let identity = resolve_launch_identity(config, &selected)
            .or_else(|| ssh_identity::discover_private_key_for_fingerprints(&fingerprints));
        return Ok((ssh_keys, identity));
    }
    let keys = fetch_launch_keys(console_url, session)?;
    if !keys.items.is_empty() {
        let mut key_ids = keys
            .items
            .iter()
            .map(|key| key.id.clone())
            .collect::<Vec<_>>();
        let mut key_labels = keys
            .items
            .iter()
            .map(|key| format!("{} ({})", key.label, key.id))
            .collect::<Vec<_>>();
        let fingerprints = keys
            .items
            .iter()
            .map(|key| key.fingerprint.clone())
            .collect::<Vec<_>>();
        let selected = keys.items.iter().collect::<Vec<_>>();
        let mut identity = resolve_launch_identity(config, &selected)
            .or_else(|| ssh_identity::discover_private_key_for_fingerprints(&fingerprints));
        if identity.is_none() {
            let (private_key, public_key) = ensure_default_ssh_keypair(config)?;
            let key = create_launch_key(console_url, session, "default", &public_key)?;
            remember_launch_identity(config, &key.id, &private_key)?;
            eprintln!(
                "{}",
                style::info_line(&format!(
                    "created and registered SSH key default ({}) because no registered key matched a local private key",
                    key.id
                ))
            );
            if key_ids.len() >= 16 {
                eprintln!(
                    "{}",
                    style::info_line(
                        "registered SSH keys are at the launch limit; using the new local key for this CVM"
                    )
                );
                key_ids.clear();
                key_labels.clear();
            }
            key_ids.push(key.id);
            key_labels.push(format!(
                "default ({})",
                key_ids.last().expect("key id just pushed")
            ));
            identity = Some(private_key);
        }
        if key_ids.len() > 16 {
            return Err((
                ExitStatus::Usage,
                "[usage] launch would install more than 16 SSH keys; rerun with explicit --ssh-key values"
                    .to_string(),
            ));
        }
        eprintln!(
            "{}",
            style::info_line(&format!(
                "using registered SSH key{} {}",
                if key_ids.len() == 1 { "" } else { "s" },
                key_labels.join(", ")
            ))
        );
        return Ok((key_ids, identity));
    }
    let (private_key, public_key) = ensure_default_ssh_keypair(config)?;
    let key = create_launch_key(console_url, session, "default", &public_key)?;
    remember_launch_identity(config, &key.id, &private_key)?;
    eprintln!(
        "{}",
        style::info_line(&format!(
            "created and registered SSH key default ({})",
            key.id
        ))
    );
    Ok((vec![key.id], Some(private_key)))
}

fn remember_launch_identity(
    config: &ResolvedConfig,
    key_id: &str,
    identity_file: &Path,
) -> Result<(), (ExitStatus, String)> {
    ssh_identity_store::write_identity(&config.config_dir, key_id, &persistable_path(identity_file))
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to remember SSH identity path: {err}"),
            )
        })
}

fn resolve_launch_identity(config: &ResolvedConfig, keys: &[&ConsoleSshKey]) -> Option<PathBuf> {
    let stored = ssh_identity_store::read(&config.config_dir);
    for key in keys {
        let Some(path) = stored.get(&key.id) else {
            continue;
        };
        if path.is_file()
            && ssh_identity::private_key_matches_fingerprints(
                path,
                std::slice::from_ref(&key.fingerprint),
            )
        {
            return Some(path.clone());
        }
    }
    None
}

fn fetch_launch_profiles(
    console_url: &str,
    session: &Session,
) -> Result<ListPage<LaunchProfile>, (ExitStatus, String)> {
    let path = format!("/api/v1/entities/{}/profiles", session.entity.id);
    fetch_json(console_url, session, &path, &[], "list profiles")
}

fn fetch_launch_keys(
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

fn create_launch_key(
    console_url: &str,
    session: &Session,
    label: &str,
    public_key: &str,
) -> Result<ConsoleSshKey, (ExitStatus, String)> {
    post_json(
        console_url,
        &session.access_token,
        "/api/v1/me/keys",
        &json!({ "label": label, "public_key": public_key }),
        "add SSH key",
    )
}

fn ensure_default_ssh_keypair(
    config: &ResolvedConfig,
) -> Result<(PathBuf, String), (ExitStatus, String)> {
    let home = dirs::home_dir().ok_or_else(|| {
        (
            ExitStatus::Error,
            "[error] failed to locate home directory for SSH key generation".to_string(),
        )
    })?;
    let ssh_dir = home.join(".ssh");
    fs::create_dir_all(&ssh_dir).map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to create {}: {err}", ssh_dir.display()),
        )
    })?;
    #[cfg(unix)]
    {
        fs::set_permissions(&ssh_dir, fs::Permissions::from_mode(0o700)).map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to tighten {}: {err}", ssh_dir.display()),
            )
        })?;
    }
    let (private_key, public_key_path) = ssh_identity::default_ssh_key_paths(&ssh_dir)?;
    if !private_key.exists() {
        let comment = default_ssh_key_comment(config);
        let output = Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-C")
            .arg(comment)
            .arg("-f")
            .arg(&private_key)
            .arg("-N")
            .arg("")
            .stdin(Stdio::null())
            .output()
            .map_err(|err| {
                (
                    ExitStatus::Error,
                    format!("[error] failed to invoke ssh-keygen: {err}"),
                )
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let detail = if stderr.is_empty() {
                format!("{}", output.status)
            } else {
                format!("{}: {stderr}", output.status)
            };
            return Err((
                ExitStatus::Error,
                format!("[error] ssh-keygen exited with {detail}"),
            ));
        }
    } else if !public_key_path.exists() {
        let output = Command::new("ssh-keygen")
            .arg("-y")
            .arg("-f")
            .arg(&private_key)
            .stdin(Stdio::null())
            .output()
            .map_err(|err| {
                (
                    ExitStatus::Error,
                    format!("[error] failed to invoke ssh-keygen: {err}"),
                )
            })?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let detail = if stderr.is_empty() {
                format!("{}", output.status)
            } else {
                format!("{}: {stderr}", output.status)
            };
            return Err((
                ExitStatus::Error,
                format!("[error] ssh-keygen exited with {detail}"),
            ));
        }
        write_public_key_file(&public_key_path, &output.stdout)?;
    }
    let public_key_value = fs::read_to_string(&public_key_path).map_err(|err| {
        (
            ExitStatus::Error,
            format!(
                "[error] failed to read {}: {err}",
                public_key_path.display()
            ),
        )
    })?;
    let public_key_value = public_key_value.trim();
    if public_key_value.is_empty() {
        return Err((
            ExitStatus::Error,
            format!("[error] {} is empty", public_key_path.display()),
        ));
    }
    eprintln!(
        "{}",
        style::info_line(&format!("using local SSH key {}", private_key.display()))
    );
    Ok((private_key, public_key_value.to_string()))
}

fn write_public_key_file(path: &Path, data: &[u8]) -> Result<(), (ExitStatus, String)> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o644).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|err| {
        (
            ExitStatus::Error,
            format!(
                "[error] failed to create public key file {}: {err}",
                path.display()
            ),
        )
    })?;
    file.write_all(data)
        .and_then(|_| file.sync_all())
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to write public key file: {err}"),
            )
        })?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o644)).map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to set public key file permissions: {err}"),
            )
        })?;
    }
    Ok(())
}

fn default_ssh_key_comment(config: &ResolvedConfig) -> String {
    if let Ok(user) = env::var("USER") {
        if !user.is_empty() {
            return format!("{user}@concrete");
        }
    }
    config
        .console_url
        .as_deref()
        .map(|value| format!("concrete:{value}"))
        .unwrap_or_else(|| "concrete".to_string())
}

fn optional_profile_filter(config: &ResolvedConfig) -> Result<Option<String>, String> {
    if config.profile_flags.len() > 1 {
        return Err("[usage] expected at most one --profile for cvm list".to_string());
    }
    if let Some(raw) = config.profile_flags.first() {
        let profile_id = alias::resolve_or_passthrough(config, alias::AliasKind::Profile, raw)?;
        validate_uuid("--profile", &profile_id)?;
        Ok(Some(profile_id))
    } else {
        Ok(None)
    }
}

fn selected_profile(config: &ResolvedConfig) -> Result<String, (ExitStatus, String)> {
    let raw = config
        .require_profile()
        .map_err(|message| (ExitStatus::Usage, message))?;
    let profile_id = alias::resolve_or_passthrough(config, alias::AliasKind::Profile, raw)
        .map_err(|message| (ExitStatus::Usage, message))?;
    validate_uuid("--profile", &profile_id).map_err(|message| (ExitStatus::Usage, message))?;
    Ok(profile_id)
}

/// State by id for the caller's non-terminated CVMs, so `alias prune` can tell
/// a live/stopped CVM (keep its alias) from a terminated/absent one (stale).
pub(crate) fn alive_cvm_states(
    console_url: &str,
    session: &Session,
) -> Result<BTreeMap<String, String>, (ExitStatus, String)> {
    let page: ListPage<Cvm> = fetch_json(
        console_url,
        session,
        cvms_path(),
        &[("state", "alive".to_string())],
        "list CVMs",
    )?;
    Ok(page
        .items
        .into_iter()
        .map(|cvm| (cvm.id, cvm.state))
        .collect())
}

/// Whether a Dev CVM with `cvm_id` exists, for fail-fast alias creation. A 404
/// surfaces as an error via the shared response mapping.
pub(crate) fn cvm_exists(
    console_url: &str,
    session: &Session,
    cvm_id: &str,
) -> Result<(), (ExitStatus, String)> {
    fetch_cvm_with_etag(console_url, session, cvm_id).map(|_| ())
}

/// Path of the CVM list, the one source of truth shared by the fetcher and the
/// test mock (`MockConsole`) so the two never drift.
pub(crate) fn cvms_path() -> &'static str {
    "/api/v1/cvms"
}

/// Path of the single-CVM GET, the one source of truth shared by the fetcher
/// and the test mock (`MockConsole`) so the two never drift.
pub(crate) fn cvm_path(cvm_id: &str) -> String {
    format!("/api/v1/cvms/{cvm_id}")
}

/// Path of a CVM lifecycle action (`stop`/`start`/`terminate`/`update`), built
/// on top of [`cvm_path`] so the fetchers and the test mock share one source.
pub(crate) fn cvm_action_path(cvm_id: &str, action: &str) -> String {
    format!("{}/actions/{action}", cvm_path(cvm_id))
}

fn fetch_cvm_with_etag(
    console_url: &str,
    session: &Session,
    cvm_id: &str,
) -> Result<(Cvm, String), (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}{}", cvm_path(cvm_id)))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch CVM: {err}"),
            )
        })?;
    read_with_etag::<Cvm>(response, "fetch CVM")
}

fn submit_launch(
    console_url: &str,
    access_token: &str,
    launch: &LaunchRequest,
) -> Result<Operation, (ExitStatus, String)> {
    let mut body = Map::new();
    body.insert(
        "profile_ids".to_string(),
        Value::Array(
            launch
                .profile_ids
                .iter()
                .map(|value| Value::String(value.clone()))
                .collect(),
        ),
    );
    body.insert(
        "ssh_key_ids".to_string(),
        Value::Array(
            launch
                .ssh_key_ids
                .iter()
                .map(|value| Value::String(value.clone()))
                .collect(),
        ),
    );
    if let Some(value) = &launch.instance_type {
        body.insert("instance_type".to_string(), Value::String(value.clone()));
    }
    if let Some(value) = &launch.region {
        body.insert("region".to_string(), Value::String(value.clone()));
    }
    if let Some(value) = launch.disk_size_gb {
        body.insert("disk_size_gb".to_string(), Value::Number(value.into()));
    }
    post_json(
        console_url,
        access_token,
        "/api/v1/cvms",
        &Value::Object(body),
        "submit CVM launch",
    )
}

fn mutate_profile(
    console_url: &str,
    access_token: &str,
    cvm_id: &str,
    etag: &str,
    profile_id: &str,
    mutation: Mutation,
) -> Result<(Cvm, String), (ExitStatus, String)> {
    let client = Client::new();
    let request = match mutation {
        Mutation::Attach => client
            .post(format!("{console_url}/api/v1/cvms/{cvm_id}/profiles"))
            .json(&json!({ "profile_id": profile_id })),
        Mutation::Detach => client.delete(format!(
            "{console_url}/api/v1/cvms/{cvm_id}/profiles/{profile_id}"
        )),
    };
    let label = format!("{} CVM profile", mutation.as_str());
    let response = send(
        request
            .bearer_auth(access_token)
            .header(IF_MATCH, etag)
            .header("Idempotency-Key", Uuid::new_v4().to_string()),
        &label,
    )?;
    read_with_etag::<Cvm>(response, &label)
}

fn submit_lifecycle_action(
    console_url: &str,
    access_token: &str,
    cvm_id: &str,
    etag: &str,
    action: LifecycleAction,
) -> Result<(Cvm, String), (ExitStatus, String)> {
    let label = format!("{} CVM", action.as_str());
    let response = send(
        Client::new()
            .post(format!(
                "{console_url}{}",
                cvm_action_path(cvm_id, action.as_str())
            ))
            .bearer_auth(access_token)
            .header(IF_MATCH, etag)
            .header("Idempotency-Key", Uuid::new_v4().to_string()),
        &label,
    )?;
    read_with_etag::<Cvm>(response, &label)
}

fn submit_update(
    console_url: &str,
    access_token: &str,
    cvm_id: &str,
    etag: &str,
) -> Result<Operation, (ExitStatus, String)> {
    let response = send(
        Client::new()
            .post(format!(
                "{console_url}{}",
                cvm_action_path(cvm_id, "update")
            ))
            .bearer_auth(access_token)
            .header(IF_MATCH, etag)
            .header("Idempotency-Key", Uuid::new_v4().to_string()),
        "submit CVM update",
    )?;
    read_json_response(response, "submit CVM update")
}

fn submit_terminate(
    console_url: &str,
    access_token: &str,
    cvm_id: &str,
    etag: &str,
) -> Result<Operation, (ExitStatus, String)> {
    let response = send(
        Client::new()
            .post(format!(
                "{console_url}{}",
                cvm_action_path(cvm_id, "terminate")
            ))
            .bearer_auth(access_token)
            .header(IF_MATCH, etag)
            .header("Idempotency-Key", Uuid::new_v4().to_string()),
        "submit CVM termination",
    )?;
    read_json_response(response, "submit CVM termination")
}

pub(crate) fn write_policy_file(
    config_dir: &Path,
    bundle: &PolicyBundle,
    cvm_id: &str,
) -> Result<PathBuf, String> {
    let (target, data, _) = prepare_policy_file(config_dir, bundle, cvm_id)?;
    install_policy_file(&target, &data)?;
    Ok(target)
}

fn write_policy_file_after_update(
    config_dir: &Path,
    bundle: &PolicyBundle,
    cvm_id: &str,
    json_output: bool,
) -> Result<(PathBuf, PolicyWriteStatus), String> {
    let (target, data, document) = prepare_policy_file(config_dir, bundle, cvm_id)?;
    if !target.exists() {
        install_policy_file(&target, &data)?;
        return Ok((target, PolicyWriteStatus::Installed));
    }
    if policy_file_matches(&target, &document)? {
        tighten_policy_permissions(&target)?;
        return Ok((target, PolicyWriteStatus::Unchanged));
    }
    if !json_output && prompt_replace_policy(cvm_id, &target)? {
        install_policy_file(&target, &data)?;
        return Ok((target, PolicyWriteStatus::ReplacedAfterConfirmation));
    }
    Err(format!(
        "[error] Dev CVM update succeeded, but the local aTLS policy file was not changed. The new policy changes the measurement this CLI trusts. Current policy: {}. Re-run `concrete cvm update {}` from an interactive terminal and answer yes if you trust the new measurement.",
        target.display(),
        cvm_id
    ))
}

fn prepare_policy_file(
    config_dir: &Path,
    bundle: &PolicyBundle,
    cvm_id: &str,
) -> Result<(PathBuf, Vec<u8>, Value), String> {
    if bundle.cvm_id != cvm_id {
        return Err("[error] CVM policy bundle did not match CVM id".to_string());
    }
    let dir = config_dir.join("cvms");
    fs::create_dir_all(&dir)
        .map_err(|err| format!("[error] failed to create policy directory: {err}"))?;
    #[cfg(unix)]
    {
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|err| {
            format!("[error] failed to tighten policy directory permissions: {err}")
        })?;
    }
    let target = dir.join(format!("{cvm_id}.atls-policy.json"));
    let document = policy_document(bundle);
    let data = serde_json::to_vec_pretty(&document)
        .map_err(|err| format!("[error] failed to serialize aTLS policy: {err}"))?;
    Ok((target, data, document))
}

fn install_policy_file(target: &Path, data: &[u8]) -> Result<(), String> {
    crate::fsutil::write_atomic_file(target, data, 0o600)
        .map_err(|err| format!("[error] failed to write aTLS policy file: {err}"))
}

fn tighten_policy_permissions(target: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).map_err(|err| {
            format!("[error] failed to tighten aTLS policy file permissions: {err}")
        })?;
    }
    Ok(())
}

fn policy_file_matches(target: &Path, expected: &Value) -> Result<bool, String> {
    let data = fs::read(target)
        .map_err(|err| format!("[error] failed to read aTLS policy file: {err}"))?;
    match serde_json::from_slice::<Value>(&data) {
        Ok(actual) => Ok(&actual == expected),
        Err(_) => Ok(false),
    }
}

fn prompt_replace_policy(cvm_id: &str, target: &Path) -> Result<bool, String> {
    if !io::stdin().is_terminal() {
        return Ok(false);
    }
    eprintln!(
        "{}",
        style::info_line("The updated Dev CVM returned new aTLS trust material.")
    );
    eprintln!(
        "{}",
        style::info_line("This usually happens after a Security CVM update or Dev CVM rebind.")
    );
    eprintln!(
        "{}",
        style::info_line(
            "Your local policy file is the golden measurement this CLI trusts, so Concrete will not replace it automatically."
        )
    );
    eprint!(
        "{}",
        style::info_line(&format!(
            "Replace {} for CVM {}? [y/N] ",
            target.display(),
            cvm_id
        ))
    );
    io::stderr()
        .flush()
        .map_err(|err| format!("[error] failed to flush policy prompt: {err}"))?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|err| format!("[error] failed to read policy prompt response: {err}"))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn persist_launch_defaults(
    config: &ResolvedConfig,
    cvm: &Cvm,
    profile_ids: &[String],
    ssh_identity: Option<&Path>,
) -> Result<(), String> {
    let mut values = vec![("default_cvm", cvm.id.clone())];
    if config.profile.is_none() && profile_ids.len() == 1 {
        values.push(("default_profile", profile_ids[0].clone()));
    }
    if let Some(path) = ssh_identity {
        values.push((
            "default_ssh_identity",
            persistable_path(path).display().to_string(),
        ));
    }
    config::persist_string_values(&config.config_dir, &values)
}

fn policy_document(bundle: &PolicyBundle) -> Value {
    let mut app_compose = bundle
        .extra
        .get("app_compose_json")
        .and_then(Value::as_str)
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
        .and_then(|value| value.as_object().cloned())
        .or_else(|| {
            bundle
                .extra
                .get("app_compose")
                .and_then(|value| value.as_object())
                .cloned()
        })
        .unwrap_or_default();
    app_compose.insert(
        "docker_compose_file".to_string(),
        Value::String(bundle.compose_template.clone()),
    );
    app_compose
        .entry("allowed_envs".to_string())
        .or_insert_with(|| json!([]));
    app_compose
        .entry("manifest_version".to_string())
        .or_insert_with(|| json!(2));
    app_compose
        .entry("name".to_string())
        .or_insert_with(|| Value::String(format!("concrete-dev-{}", bundle.cvm_id)));
    app_compose
        .entry("runner".to_string())
        .or_insert_with(|| Value::String("docker-compose".to_string()));
    let policy = json!({
        "type": "dstack_tdx",
        "allowed_tcb_status": ["UpToDate"],
        "expected_bootchain": bundle.expected_bootchain.clone(),
        "os_image_hash": bundle.os_image_hash.clone(),
        "app_compose": Value::Object(app_compose),
        "rtmr3_binding": bundle.rtmr3_binding.clone(),
    });
    policy
}

fn print_cvm_list(
    page: ListPage<Cvm>,
    json_output: bool,
    profile_filter: Option<&str>,
    state_filter: Option<&str>,
) {
    if json_output {
        style::emit_json(&page.items);
        return;
    }
    let views: Vec<style::CvmView<'_>> = page
        .items
        .iter()
        .map(|cvm| style::CvmView {
            id: &cvm.id,
            state: &cvm.state,
            error_reason: cvm.error_reason.as_deref(),
            fqdn: cvm.fqdn.as_deref(),
            instance_type: cvm.instance_type.as_deref(),
            region: cvm.region.as_deref(),
            disk_size_gb: cvm.disk_size_gb,
            profile_names: cvm.profiles.iter().map(|p| p.name.clone()).collect(),
            ssh_key_labels: cvm.ssh_keys.iter().map(|k| k.label.clone()).collect(),
            owner_email: &cvm.owner.email,
            created_at: &cvm.created_at,
            updated_at: &cvm.updated_at,
            extra: &cvm.extra,
        })
        .collect();
    let filter = style::CvmListFilter {
        profile: profile_filter.map(str::to_string),
        state: state_filter.map(str::to_string),
    };
    println!("{}", style::cvm_list_cards(&views, &filter));
    if let Some(cursor) = page.next_cursor {
        eprintln!("{}", style::next_cursor_diagnostic(&cursor));
    }
}

fn print_launch_result(cvm: Cvm, policy_file: PathBuf, alias: Option<&str>, json_output: bool) {
    if json_output {
        let output = CvmLaunchOutput {
            cvm,
            policy_file_path: policy_file.display().to_string(),
            policy_file_status: None,
        };
        style::emit_json(&output);
    } else {
        let cvm_id = cvm.id.clone();
        // The next step and every later verb accept the alias, so prefer it;
        // the alias row shows "-" when the CVM was launched without one.
        let target = alias.unwrap_or(&cvm_id);
        let confirm = style::ConfirmBlock::new("launched", "cvm", cvm_id.clone())
            .field("fqdn", cvm.fqdn.clone().unwrap_or_else(|| "-".to_string()))
            .field("state", cvm.state.clone())
            .field("alias", alias.unwrap_or("-").to_string())
            .field("policy file", policy_file.display().to_string())
            .next_step(format!("concrete ssh {target}"));
        println!("{}", style::render_confirm(&confirm));
    }
}

fn print_lifecycle_result(action: LifecycleAction, cvm: &Cvm, json_output: bool) {
    if json_output {
        style::emit_json(cvm);
    } else {
        let confirm = style::ConfirmBlock::new(action.past_tense(), "cvm", cvm.id.clone());
        println!("{}", style::render_confirm(&confirm));
    }
}

fn print_update_result(
    cvm: Cvm,
    policy_file: PathBuf,
    policy_status: PolicyWriteStatus,
    json_output: bool,
) {
    if json_output {
        let output = CvmLaunchOutput {
            cvm,
            policy_file_path: policy_file.display().to_string(),
            policy_file_status: Some(policy_status.as_str().to_string()),
        };
        style::emit_json(&output);
    } else {
        let cvm_id = cvm.id.clone();
        let confirm = style::ConfirmBlock::new("updated", "cvm", cvm_id.clone())
            .field("fqdn", cvm.fqdn.clone().unwrap_or_else(|| "-".to_string()))
            .field("state", cvm.state.clone())
            .field("policy file", policy_file.display().to_string())
            .field("policy status", policy_status.as_str())
            .next_step(format!("concrete ssh {cvm_id}"));
        println!("{}", style::render_confirm(&confirm));
    }
}

fn print_terminate_result(cvm: &Cvm, json_output: bool) {
    if json_output {
        style::emit_json(cvm);
    } else {
        let confirm = style::ConfirmBlock::new("terminated", "cvm", cvm.id.clone())
            .field("state", cvm.state.clone());
        println!("{}", style::render_confirm(&confirm));
    }
}

fn validate_cvm_config_value(name: &str, value: &str) -> Result<(), String> {
    crate::console::validate_config_value(name, value, 64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::CvmStateFilter;
    use crate::test_support::{authenticated_config, MockConsole, Presence};
    use rstest::rstest;

    #[test]
    fn instance_types_response_captures_unknown_fields_without_leaking_to_json() {
        // A Console newer than this CLI: unknown fields at the top level, on an
        // entry, and in the catalog. They must be captured (drift detectable)
        // but excluded from `--json` (strict whitelist).
        let body = r#"{
            "instance_types": [
                {"name": "tdx.small", "vcpu": 1, "brand_new_field": 42}
            ],
            "catalog": {"source": "provider", "stale": false, "future_meta": true},
            "top_level_novelty": "x"
        }"#;
        let response: InstanceTypesResponse = serde_json::from_str(body).expect("deserializes");

        assert!(response.has_unknown_fields());
        let json = serde_json::to_string(&response).expect("serializes");
        assert!(!json.contains("brand_new_field"), "json={json}");
        assert!(!json.contains("future_meta"));
        assert!(!json.contains("top_level_novelty"));
        assert!(json.contains("tdx.small"));
    }

    #[test]
    fn catalog_field_miss_counts_round_trips_through_json() {
        // field_miss_counts is a real (non-skipped) field: it must survive --json
        // so scripts/tests can assert `.catalog.field_miss_counts == {}`.
        let body = r#"{
            "instance_types": [{"name": "tdx.small"}],
            "catalog": {"source": "provider", "stale": false, "field_miss_counts": {"memory_gb": 1}}
        }"#;
        let response: InstanceTypesResponse = serde_json::from_str(body).expect("deserializes");
        assert_eq!(
            response.catalog.field_miss_counts.get("memory_gb"),
            Some(&1)
        );
        let json = serde_json::to_string(&response).expect("serializes");
        assert!(json.contains("field_miss_counts"));
        assert!(json.contains("memory_gb"));
        // Absent field_miss_counts (older/clean Console) defaults to empty.
        let clean = r#"{"instance_types": [], "catalog": {"source": "provider", "stale": false}}"#;
        let clean: InstanceTypesResponse = serde_json::from_str(clean).expect("deserializes");
        assert!(clean.catalog.field_miss_counts.is_empty());
    }

    #[test]
    fn instance_types_response_reports_no_unknown_fields_for_a_known_shape() {
        let body = r#"{
            "instance_types": [
                {"name": "tdx.small", "family": "cpu", "vcpu": 1, "memory_gb": 2,
                 "hourly_rate": 0.058, "currency": "USD", "default": true, "launchable": true}
            ],
            "catalog": {"source": "provider", "fetched_at": null, "stale": false,
                        "refresh_in_progress": false, "last_refresh_error": null}
        }"#;
        let response: InstanceTypesResponse = serde_json::from_str(body).expect("deserializes");

        assert!(!response.has_unknown_fields());
        // A missing `launchable` (older Console) defaults to launchable, not "not supported yet".
        let older = r#"{"instance_types": [{"name": "tdx.small"}],
                        "catalog": {"source": "provider", "stale": false}}"#;
        let older: InstanceTypesResponse = serde_json::from_str(older).expect("deserializes");
        assert!(older.instance_types[0].launchable);
    }

    #[test]
    fn cvm_list_query_params_maps_state_flag() {
        // No --state -> empty query; Some -> one `state=<value>` pair carrying
        // clap's lowercase variant name.
        let cases = [
            (None, vec![]),
            (
                Some(CvmStateFilter::Alive),
                vec![("state", "alive".to_string())],
            ),
            (
                Some(CvmStateFilter::Terminated),
                vec![("state", "terminated".to_string())],
            ),
        ];
        for (state, expected) in cases {
            assert_eq!(CvmListArgs { state }.query_params(), expected);
        }
    }

    #[test]
    fn cvm_list_query_composes_state_with_profile_filter() {
        // Like `list()`: `--state` and the global `--profile` go into one query.
        let args = CvmListArgs {
            state: Some(CvmStateFilter::Running),
        };
        let mut query = args.query_params();
        let profile_id = Some("00000000-0000-4000-8000-000000000099".to_string());
        push_query(&mut query, "profile_id", &profile_id);
        assert_eq!(
            query,
            vec![
                ("state", "running".to_string()),
                (
                    "profile_id",
                    "00000000-0000-4000-8000-000000000099".to_string()
                ),
            ]
        );
    }

    #[test]
    fn policy_document_maps_policy_bundle_to_atls_policy() {
        let bundle = test_policy_bundle("00000000-0000-4000-8000-000000000001", &"e".repeat(64));

        let policy = policy_document(&bundle);

        assert_eq!(policy["type"], "dstack_tdx");
        assert!(policy.get("connect_host").is_none());
        assert_eq!(
            policy["app_compose"]["docker_compose_file"],
            Value::String("services: {}".to_string())
        );
        assert_eq!(
            policy["app_compose"]["features"],
            json!(["kms", "tproxy-net"])
        );
        assert!(serde_json::to_string(&policy["app_compose"])
            .expect("app_compose serializes")
            .starts_with(r#"{"allowed_envs":[],"docker_compose_file":"#));
        assert_eq!(policy["rtmr3_binding"]["security_cvm_proxy_port"], 8080);
    }

    #[test]
    fn update_policy_refuses_to_overwrite_changed_local_trust_in_json_mode() {
        let dir = std::env::temp_dir().join(format!("concrete-cvm-policy-test-{}", Uuid::new_v4()));
        let cvm_id = "00000000-0000-4000-8000-000000000001";
        let old_hash = "a".repeat(64);
        let new_hash = "b".repeat(64);
        write_policy_file(&dir, &test_policy_bundle(cvm_id, &old_hash), cvm_id)
            .expect("initial policy written");

        let err = write_policy_file_after_update(
            &dir,
            &test_policy_bundle(cvm_id, &new_hash),
            cvm_id,
            true,
        )
        .expect_err("changed local trust requires explicit confirmation");

        let policy_path = dir.join("cvms").join(format!("{cvm_id}.atls-policy.json"));
        let policy: Value = serde_json::from_slice(&fs::read(policy_path).expect("policy read"))
            .expect("policy parses");
        assert_eq!(policy["os_image_hash"], old_hash);
        assert!(err.contains("local aTLS policy file was not changed"));
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    #[test]
    fn update_policy_accepts_unchanged_local_trust() {
        let dir = std::env::temp_dir().join(format!("concrete-cvm-policy-test-{}", Uuid::new_v4()));
        let cvm_id = "00000000-0000-4000-8000-000000000001";
        write_policy_file(
            &dir,
            &test_policy_bundle(cvm_id, "same.example.com"),
            cvm_id,
        )
        .expect("initial policy written");

        let (_, status) = write_policy_file_after_update(
            &dir,
            &test_policy_bundle(cvm_id, "same.example.com"),
            cvm_id,
            true,
        )
        .expect("unchanged policy accepted");

        assert_eq!(status.as_str(), "unchanged");
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    fn test_policy_bundle(cvm_id: &str, os_image_hash: &str) -> PolicyBundle {
        PolicyBundle {
            cvm_id: cvm_id.to_string(),
            compose_template: "services: {}".to_string(),
            expected_bootchain: json!({
                "mrtd": "a".repeat(64),
                "rtmr0": "b".repeat(64),
                "rtmr1": "c".repeat(64),
                "rtmr2": "d".repeat(64),
            }),
            os_image_hash: os_image_hash.to_string(),
            rtmr3_binding: json!({
                "cvm_id": cvm_id,
                "security_cvm_fqdn": "sc.example.com",
                "security_cvm_proxy_port": 8080,
                "security_cvm_proxy_token_sha256": "f".repeat(64),
                "security_cvm_ca_cert_sha256": "0".repeat(64),
                "authorised_ssh_keys_sha256": "1".repeat(64),
            }),
            extra: {
                let mut extra = Map::new();
                extra.insert(
                    "app_compose".to_string(),
                    json!({
                        "allowed_envs": ["wrong"],
                        "docker_compose_file": "stale",
                        "features": ["wrong"],
                        "runner": "docker-compose"
                    }),
                );
                extra.insert(
                    "app_compose_json".to_string(),
                    Value::String(
                        r#"{"allowed_envs":[],"docker_compose_file":"stale","features":["kms","tproxy-net"],"runner":"docker-compose"}"#
                            .to_string(),
                    ),
                );
                extra
            },
        }
    }

    #[test]
    fn validate_cvm_config_value_rejects_spaces() {
        assert_eq!(
            validate_cvm_config_value("--region", "FR PARIS").expect_err("space rejected"),
            "[usage] --region may contain only letters, digits, '.', '_', and '-'"
        );
    }

    #[test]
    fn write_public_key_file_refuses_to_overwrite() {
        let dir = std::env::temp_dir().join(format!("concrete-cvm-key-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");
        let path = dir.join("id_ed25519.pub");
        fs::write(&path, "ssh-ed25519 existing\n").expect("public key written");

        assert!(write_public_key_file(&path, b"ssh-ed25519 new\n").is_err());
        assert_eq!(
            fs::read_to_string(&path).expect("public key readable"),
            "ssh-ed25519 existing\n"
        );
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    // --- Lifecycle prune wiring: the real `cvm stop` / `cvm terminate` commands
    // must call `prune_and_save` with the right `Prune` variant. These drive the
    // whole command against a mock Console and read the alias store back off
    // disk, so they cover the call-site wiring the pure `alias::prune` tests
    // cannot (see alias.rs `test_prune_and_save_persists_success`).

    const LIFECYCLE_CVM_ID: &str = "9a7f6b4a-1111-2222-3333-444444444444";
    const OTHER_CVM_ID: &str = "5d5d5d5d-6666-7777-8888-999999999999";
    const LIFECYCLE_PROFILE_ID: &str = "16286507-f87f-449e-a229-be04067fc23c";
    const LIFECYCLE_KEY_ID: &str = "3c4c2b64-b059-41a6-b925-3e4816ffee60";

    /// Seed the alias store in `config`'s dir spanning every kind: the target
    /// CVM's own alias, two session aliases bound to it, one session on a
    /// different CVM, plus an unrelated profile and ssh-key alias — so a prune
    /// can be shown to touch ONLY the box being acted on and leave the rest.
    fn seed_lifecycle_aliases(config: &ResolvedConfig) {
        let mut aliases = alias::Aliases::default();
        aliases.cvm.insert("box".into(), LIFECYCLE_CVM_ID.into());
        aliases
            .profile
            .insert("prof".into(), LIFECYCLE_PROFILE_ID.into());
        aliases
            .ssh_key
            .insert("key".into(), LIFECYCLE_KEY_ID.into());
        for (name, session, cvm) in [
            ("s1", "agent-1", LIFECYCLE_CVM_ID),
            ("s2", "agent-2", LIFECYCLE_CVM_ID),
            ("other", "agent-3", OTHER_CVM_ID),
        ] {
            aliases.session.insert(
                name.into(),
                alias::SessionAlias {
                    session: session.into(),
                    cvm: cvm.into(),
                },
            );
        }
        alias::save(&config.config_dir, &aliases).expect("seed alias store");
    }

    /// `cvm stop` (the real command) drops the stopped CVM's session aliases from
    /// the on-disk store — they die with the box's tmpfs — while KEEPING the
    /// CVM's own alias (it can be restarted) and another CVM's session. Proves
    /// the `Prune::CvmSessions` wiring. Run with the target given both as the raw
    /// UUID and as its alias `box`: the alias case also proves resolution through
    /// the real on-disk store, since the mock only answers for the resolved UUID.
    #[rstest]
    #[case::by_id(LIFECYCLE_CVM_ID)]
    #[case::by_alias("box")]
    fn test_cvm_stop_prune_success(#[case] target: &str) {
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        console.get_cvm(LIFECYCLE_CVM_ID, Presence::Present);
        console.cvm_lifecycle_action(LIFECYCLE_CVM_ID, "stop");
        seed_lifecycle_aliases(&config);

        let status = run(
            CvmCommand::Stop {
                target: crate::cli::CvmTarget {
                    cvm_id: Some(target.into()),
                    cvm: None,
                },
            },
            &config,
            false,
        );
        assert!(matches!(status, ExitStatus::Ok));

        let reloaded = alias::load(&config.config_dir).unwrap();
        assert!(reloaded.resolve_session("s1").is_none());
        assert!(reloaded.resolve_session("s2").is_none());
        assert_eq!(
            reloaded.resolve_alias(alias::AliasKind::Cvm, "box"),
            LIFECYCLE_CVM_ID
        );
        assert!(reloaded.resolve_session("other").is_some());
        // Unrelated kinds are never touched by a stop.
        assert!(reloaded.profile.contains_key("prof"));
        assert!(reloaded.ssh_key.contains_key("key"));
    }

    /// `cvm terminate` (the real command, waited) drops the CVM's own alias AND
    /// every session bound to it (cascade) only ONCE the operation has completed,
    /// leaving another CVM's session — the `Prune::Cvm` wiring end-to-end. The
    /// mock's operation is already `succeeded`, so the wait returns at once.
    #[test]
    fn test_cvm_terminate_prune_success() {
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        console.get_cvm(LIFECYCLE_CVM_ID, Presence::Present);
        console.terminate_cvm(LIFECYCLE_CVM_ID);
        seed_lifecycle_aliases(&config);

        let status = run(
            CvmCommand::Terminate(CvmTerminateArgs {
                target: crate::cli::CvmTarget {
                    cvm_id: Some(LIFECYCLE_CVM_ID.into()),
                    cvm: None,
                },
                wait: crate::cli::WaitArgs {
                    no_wait: false,
                    wait_timeout_seconds: 600,
                },
            }),
            &config,
            false,
        );
        assert!(matches!(status, ExitStatus::Ok));

        let reloaded = alias::load(&config.config_dir).unwrap();
        assert!(!reloaded.cvm.contains_key("box"));
        assert!(reloaded.resolve_session("s1").is_none());
        assert!(reloaded.resolve_session("s2").is_none());
        assert!(reloaded.resolve_session("other").is_some());
        // The cascade is scoped to the CVM: unrelated kinds survive.
        assert!(reloaded.profile.contains_key("prof"));
        assert!(reloaded.ssh_key.contains_key("key"));
    }

    /// `cvm terminate --no-wait` leaves the alias in place: the teardown is only
    /// submitted, not confirmed, so the store must not be pruned yet (a later
    /// `alias prune` reconciles it once the CVM is actually gone).
    #[test]
    fn test_cvm_terminate_no_wait_keeps_alias_success() {
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        console.get_cvm(LIFECYCLE_CVM_ID, Presence::Present);
        console.terminate_cvm(LIFECYCLE_CVM_ID);
        seed_lifecycle_aliases(&config);

        let status = run(
            CvmCommand::Terminate(CvmTerminateArgs {
                target: crate::cli::CvmTarget {
                    cvm_id: Some(LIFECYCLE_CVM_ID.into()),
                    cvm: None,
                },
                wait: crate::cli::WaitArgs {
                    no_wait: true,
                    wait_timeout_seconds: 600,
                },
            }),
            &config,
            false,
        );
        assert!(matches!(status, ExitStatus::Ok));

        let reloaded = alias::load(&config.config_dir).unwrap();
        assert!(
            reloaded.cvm.contains_key("box"),
            "alias kept until confirmed"
        );
        assert!(reloaded.resolve_session("s1").is_some());
    }

    /// `cvm launch --alias` writes NO alias when the launch fails: the alias is
    /// recorded only after the CVM exists, so a failed launch (here an empty mock
    /// Console that 404s the launch call) must leave the store empty. `no_wait`
    /// is false so the launch proceeds past the up-front alias check.
    #[test]
    fn test_cvm_launch_alias_failure() {
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        let status = run(
            CvmCommand::Launch(CvmLaunchArgs {
                ssh_keys: vec![],
                alias: Some("nick".into()),
                instance_type: None,
                region: None,
                disk_size: None,
                wait: crate::cli::WaitArgs {
                    no_wait: false,
                    wait_timeout_seconds: 600,
                },
            }),
            &config,
            false,
        );
        assert!(!matches!(status, ExitStatus::Ok));
        assert!(
            alias::load(&config.config_dir)
                .unwrap()
                .kind_of("nick")
                .is_none(),
            "a failed launch must not write an orphan alias"
        );
    }

    /// The global `--profile` accepts an alias, not just a UUID: with a profile
    /// alias in the store, the `cvm list` filter and the single-profile selector
    /// both resolve it to the underlying UUID.
    #[test]
    fn test_profile_flag_resolves_alias_success() {
        const PROFILE_ID: &str = "16286507-f87f-449e-a229-be04067fc23c";
        let dir = std::env::temp_dir().join(format!("concrete-profile-alias-{}", Uuid::new_v4()));
        let config = ResolvedConfig::resolve(crate::config::ConfigOverrides {
            config_dir: Some(dir),
            profile: vec!["team-prod".into()],
            ..Default::default()
        });
        let mut store = alias::Aliases::default();
        store.profile.insert("team-prod".into(), PROFILE_ID.into());
        alias::save(&config.config_dir, &store).expect("seed store");

        assert_eq!(
            optional_profile_filter(&config).unwrap(),
            Some(PROFILE_ID.to_string()),
            "the `cvm list` --profile filter must resolve the alias"
        );
        assert_eq!(
            selected_profile(&config).unwrap(),
            PROFILE_ID,
            "the single-profile selector must resolve the alias"
        );
    }
}
