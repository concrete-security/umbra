use std::{
    collections::BTreeMap,
    env,
    fs::{self, OpenOptions},
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use reqwest::{blocking::Client, header::IF_MATCH};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    cli::{CvmCommand, CvmLaunchArgs, CvmTerminateArgs, CvmUpdateArgs},
    config::{self, ResolvedConfig},
    console::{read_json_response, read_with_etag, validate_uuid},
    exit::ExitStatus,
    operation::{self, Operation},
    session::Session,
    ssh_identity::{self, persistable_path},
    style,
};

#[derive(Debug, Deserialize)]
struct CvmListPage {
    items: Vec<Cvm>,
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProfileListPage {
    items: Vec<LaunchProfile>,
}

#[derive(Debug, Deserialize)]
struct LaunchProfile {
    id: String,
    name: String,
    assigned: bool,
}

#[derive(Debug, Deserialize)]
struct KeyListPage {
    items: Vec<ConsoleSshKey>,
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
        CvmCommand::List => list(config, json),
        CvmCommand::Launch(args) => launch(config, args, json),
        CvmCommand::Attach { cvm_id } => profile_mutation(config, &cvm_id, Mutation::Attach, json),
        CvmCommand::Detach { cvm_id } => profile_mutation(config, &cvm_id, Mutation::Detach, json),
        CvmCommand::Start { cvm_id } => {
            lifecycle_action(config, &cvm_id, LifecycleAction::Start, json)
        }
        CvmCommand::Stop { cvm_id } => {
            lifecycle_action(config, &cvm_id, LifecycleAction::Stop, json)
        }
        CvmCommand::Update(args) => update(config, args, json),
        CvmCommand::Terminate(args) => terminate(config, args, json),
    }
}

fn list(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let profile_id = match optional_profile_filter(config) {
        Ok(value) => value,
        Err(message) => {
            style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let (console_url, session) = match crate::console::console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let page = match fetch_cvms(console_url, &session, profile_id.as_deref()) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    print_cvm_list(page, json_output, profile_id.as_deref());
    ExitStatus::Ok
}

fn launch(config: &ResolvedConfig, args: CvmLaunchArgs, json_output: bool) -> ExitStatus {
    let (console_url, session) = match crate::console::console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let launch = match prepare_launch(config, console_url, &session, &args) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let op = match submit_launch(console_url, &session.access_token, &launch) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    if args.no_wait {
        operation::print_operation(&op, json_output, false);
        return ExitStatus::Ok;
    }
    let op = match operation::wait_for_operation(
        console_url,
        &session.access_token,
        op,
        Duration::from_secs(u64::from(args.wait_timeout_seconds)),
        json_output,
        true,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            if !message.is_empty() {
                style::eprintln_error(&message);
            }
            return status;
        }
    };
    let result: CvmLaunchResult = match operation::extract_operation_result(&op, "CVM launch") {
        Ok(value) => value,
        Err(message) => {
            style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
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
    print_launch_result(result.cvm, policy_file, json_output);
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
    let profile_id = match selected_profile(config) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let (console_url, session) = match crate::console::console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let (_, etag) = match fetch_cvm_with_etag(console_url, &session, cvm_id) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let cvm = match mutate_profile(
        console_url,
        &session.access_token,
        cvm_id,
        &etag,
        profile_id,
        mutation,
    ) {
        Ok((cvm, _)) => cvm,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&cvm).expect("CVM output serializes")
        );
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
    let (console_url, session) = match crate::console::console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let (_, etag) = match fetch_cvm_with_etag(console_url, &session, cvm_id) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let cvm =
        match submit_lifecycle_action(console_url, &session.access_token, cvm_id, &etag, action) {
            Ok((cvm, _)) => cvm,
            Err((status, message)) => {
                style::eprintln_error(&message);
                return status;
            }
        };
    print_lifecycle_result(action, &cvm, json_output);
    ExitStatus::Ok
}

fn update(config: &ResolvedConfig, args: CvmUpdateArgs, json_output: bool) -> ExitStatus {
    if let Err(message) = validate_uuid("CVM_ID", &args.cvm_id) {
        style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    let (console_url, session) = match crate::console::console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let (_, etag) = match fetch_cvm_with_etag(console_url, &session, &args.cvm_id) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let op = match submit_update(console_url, &session.access_token, &args.cvm_id, &etag) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    if args.no_wait {
        operation::print_operation(&op, json_output, false);
        return ExitStatus::Ok;
    }
    let op = match operation::wait_for_operation(
        console_url,
        &session.access_token,
        op,
        Duration::from_secs(u64::from(args.wait_timeout_seconds)),
        json_output,
        true,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            if !message.is_empty() {
                style::eprintln_error(&message);
            }
            return status;
        }
    };
    let result: CvmLaunchResult = match operation::extract_operation_result(&op, "CVM update") {
        Ok(value) => value,
        Err(message) => {
            style::eprintln_error(&message);
            return ExitStatus::Error;
        }
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
    if let Err(message) = validate_uuid("CVM_ID", &args.cvm_id) {
        style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    let (console_url, session) = match crate::console::console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let (_, etag) = match fetch_cvm_with_etag(console_url, &session, &args.cvm_id) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    let op = match submit_terminate(console_url, &session.access_token, &args.cvm_id, &etag) {
        Ok(value) => value,
        Err((status, message)) => {
            style::eprintln_error(&message);
            return status;
        }
    };
    if args.no_wait {
        operation::print_operation(&op, json_output, false);
        return ExitStatus::Ok;
    }
    let op = match operation::wait_for_operation(
        console_url,
        &session.access_token,
        op,
        Duration::from_secs(u64::from(args.wait_timeout_seconds)),
        json_output,
        true,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            if !message.is_empty() {
                style::eprintln_error(&message);
            }
            return status;
        }
    };
    let cvm: Cvm = match operation::extract_operation_result(&op, "CVM") {
        Ok(value) => value,
        Err(message) => {
            style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    print_terminate_result(&cvm, json_output);
    ExitStatus::Ok
}

struct LaunchRequest {
    profile_ids: Vec<String>,
    ssh_key_ids: Vec<String>,
    ssh_identity: Option<PathBuf>,
    instance_type: Option<String>,
    region: Option<String>,
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
        for ssh_key_id in &args.ssh_keys {
            validate_uuid("--ssh-key", ssh_key_id)
                .map_err(|message| (ExitStatus::Usage, message))?;
        }
        let keys = fetch_launch_keys(console_url, session)?;
        let selected = keys
            .items
            .iter()
            .filter(|key| args.ssh_keys.iter().any(|id| id == &key.id))
            .collect::<Vec<_>>();
        let fingerprints = selected
            .iter()
            .map(|key| key.fingerprint.clone())
            .collect::<Vec<_>>();
        let identity = ssh_identity::discover_private_key_for_fingerprints(&fingerprints);
        return Ok((args.ssh_keys.clone(), identity));
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
        let mut identity = ssh_identity::discover_private_key_for_fingerprints(&fingerprints);
        if identity.is_none() {
            let (private_key, public_key) = ensure_default_ssh_keypair(config)?;
            let key = create_launch_key(console_url, session, "default", &public_key)?;
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
    eprintln!(
        "{}",
        style::info_line(&format!(
            "created and registered SSH key default ({})",
            key.id
        ))
    );
    Ok((vec![key.id], Some(private_key)))
}

fn fetch_launch_profiles(
    console_url: &str,
    session: &Session,
) -> Result<ProfileListPage, (ExitStatus, String)> {
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

fn fetch_launch_keys(
    console_url: &str,
    session: &Session,
) -> Result<KeyListPage, (ExitStatus, String)> {
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

fn create_launch_key(
    console_url: &str,
    session: &Session,
    label: &str,
    public_key: &str,
) -> Result<ConsoleSshKey, (ExitStatus, String)> {
    let response = Client::new()
        .post(format!("{console_url}/api/v1/me/keys"))
        .bearer_auth(&session.access_token)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(&json!({ "label": label, "public_key": public_key }))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to add SSH key: {err}"),
            )
        })?;
    read_json_response(response, "add SSH key")
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
    if let Some(profile_id) = config.profile_flags.first() {
        validate_uuid("--profile", profile_id)?;
        Ok(Some(profile_id.clone()))
    } else {
        Ok(None)
    }
}

fn selected_profile(config: &ResolvedConfig) -> Result<&str, (ExitStatus, String)> {
    let profile_id = config
        .require_profile()
        .map_err(|message| (ExitStatus::Usage, message))?;
    validate_uuid("--profile", profile_id).map_err(|message| (ExitStatus::Usage, message))?;
    Ok(profile_id)
}

fn fetch_cvms(
    console_url: &str,
    session: &Session,
    profile_id: Option<&str>,
) -> Result<CvmListPage, (ExitStatus, String)> {
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

fn fetch_cvm_with_etag(
    console_url: &str,
    session: &Session,
    cvm_id: &str,
) -> Result<(Cvm, String), (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/cvms/{cvm_id}"))
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
    let response = Client::new()
        .post(format!("{console_url}/api/v1/cvms"))
        .bearer_auth(access_token)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .json(&Value::Object(body))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to submit CVM launch: {err}"),
            )
        })?;
    read_json_response(response, "submit CVM launch")
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
    let response = request
        .bearer_auth(access_token)
        .header(IF_MATCH, etag)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to {} CVM profile: {err}", mutation.as_str()),
            )
        })?;
    read_with_etag::<Cvm>(response, mutation.as_str())
}

fn submit_lifecycle_action(
    console_url: &str,
    access_token: &str,
    cvm_id: &str,
    etag: &str,
    action: LifecycleAction,
) -> Result<(Cvm, String), (ExitStatus, String)> {
    let response = Client::new()
        .post(format!(
            "{console_url}/api/v1/cvms/{cvm_id}/actions/{}",
            action.as_str()
        ))
        .bearer_auth(access_token)
        .header(IF_MATCH, etag)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to {} CVM: {err}", action.as_str()),
            )
        })?;
    read_with_etag::<Cvm>(response, action.as_str())
}

fn submit_update(
    console_url: &str,
    access_token: &str,
    cvm_id: &str,
    etag: &str,
) -> Result<Operation, (ExitStatus, String)> {
    let response = Client::new()
        .post(format!("{console_url}/api/v1/cvms/{cvm_id}/actions/update"))
        .bearer_auth(access_token)
        .header(IF_MATCH, etag)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to submit CVM update: {err}"),
            )
        })?;
    read_json_response(response, "submit CVM update")
}

fn submit_terminate(
    console_url: &str,
    access_token: &str,
    cvm_id: &str,
    etag: &str,
) -> Result<Operation, (ExitStatus, String)> {
    let response = Client::new()
        .post(format!(
            "{console_url}/api/v1/cvms/{cvm_id}/actions/terminate"
        ))
        .bearer_auth(access_token)
        .header(IF_MATCH, etag)
        .header("Idempotency-Key", Uuid::new_v4().to_string())
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to submit CVM termination: {err}"),
            )
        })?;
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
    let dir = target
        .parent()
        .ok_or_else(|| "[error] failed to resolve policy directory".to_string())?;
    let stem = target
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("policy");
    let tmp = dir.join(format!(".{stem}.{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|err| format!("[error] failed to create temporary aTLS policy file: {err}"))?;
    file.write_all(data)
        .and_then(|_| file.sync_all())
        .map_err(|err| format!("[error] failed to write aTLS policy file: {err}"))?;
    fs::rename(&tmp, target)
        .map_err(|err| format!("[error] failed to install aTLS policy file: {err}"))?;
    tighten_policy_permissions(target)
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
    let mut policy = json!({
        "type": "dstack_tdx",
        "allowed_tcb_status": ["UpToDate"],
        "expected_bootchain": bundle.expected_bootchain.clone(),
        "os_image_hash": bundle.os_image_hash.clone(),
        "app_compose": Value::Object(app_compose),
        "rtmr3_binding": bundle.rtmr3_binding.clone(),
    });
    if let Some(connect_host) = bundle
        .extra
        .get("connect_host")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        policy["connect_host"] = Value::String(connect_host.to_string());
    }
    policy
}

fn print_cvm_list(page: CvmListPage, json_output: bool, profile_filter: Option<&str>) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&page.items).expect("CVM list output serializes")
        );
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
    };
    println!("{}", style::cvm_list_cards(&views, &filter));
    if let Some(cursor) = page.next_cursor {
        eprintln!("{}", style::next_cursor_diagnostic(&cursor));
    }
}

fn print_launch_result(cvm: Cvm, policy_file: PathBuf, json_output: bool) {
    if json_output {
        let output = CvmLaunchOutput {
            cvm,
            policy_file_path: policy_file.display().to_string(),
            policy_file_status: None,
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("CVM launch output serializes")
        );
    } else {
        let cvm_id = cvm.id.clone();
        let confirm = style::ConfirmBlock::new("launched", "cvm", cvm_id.clone())
            .field("fqdn", cvm.fqdn.clone().unwrap_or_else(|| "-".to_string()))
            .field("state", cvm.state.clone())
            .field("policy file", policy_file.display().to_string())
            .next_step(format!("concrete ssh {cvm_id}"));
        println!("{}", style::render_confirm(&confirm));
    }
}

fn print_lifecycle_result(action: LifecycleAction, cvm: &Cvm, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(cvm).expect("CVM output serializes")
        );
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
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("CVM update output serializes")
        );
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
        println!(
            "{}",
            serde_json::to_string_pretty(cvm).expect("CVM output serializes")
        );
    } else {
        let confirm = style::ConfirmBlock::new("terminated", "cvm", cvm.id.clone())
            .field("state", cvm.state.clone());
        println!("{}", style::render_confirm(&confirm));
    }
}

fn validate_cvm_config_value(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 64 {
        return Err(format!("[usage] {name} must be 1..64 characters"));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_document_maps_policy_bundle_to_atls_policy() {
        let bundle = test_policy_bundle(
            "00000000-0000-4000-8000-000000000001",
            "app-443s.dstack.example.com",
        );

        let policy = policy_document(&bundle);

        assert_eq!(policy["type"], "dstack_tdx");
        assert_eq!(
            policy["connect_host"],
            Value::String("app-443s.dstack.example.com".to_string())
        );
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
        write_policy_file(&dir, &test_policy_bundle(cvm_id, "old.example.com"), cvm_id)
            .expect("initial policy written");

        let err = write_policy_file_after_update(
            &dir,
            &test_policy_bundle(cvm_id, "new.example.com"),
            cvm_id,
            true,
        )
        .expect_err("changed local trust requires explicit confirmation");

        let policy_path = dir.join("cvms").join(format!("{cvm_id}.atls-policy.json"));
        let policy: Value = serde_json::from_slice(&fs::read(policy_path).expect("policy read"))
            .expect("policy parses");
        assert_eq!(policy["connect_host"], "old.example.com");
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

    fn test_policy_bundle(cvm_id: &str, connect_host: &str) -> PolicyBundle {
        PolicyBundle {
            cvm_id: cvm_id.to_string(),
            compose_template: "services: {}".to_string(),
            expected_bootchain: json!({
                "mrtd": "a".repeat(64),
                "rtmr0": "b".repeat(64),
                "rtmr1": "c".repeat(64),
                "rtmr2": "d".repeat(64),
            }),
            os_image_hash: "e".repeat(64),
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
                    "connect_host".to_string(),
                    Value::String(connect_host.to_string()),
                );
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
}
