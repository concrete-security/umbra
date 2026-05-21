use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use reqwest::{
    blocking::{Client, Response},
    header::{ETAG, IF_MATCH, RETRY_AFTER},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

use crate::{
    cli::{CvmCommand, CvmLaunchArgs, CvmTerminateArgs, CvmUpdateArgs},
    commands::{auth, operation_debug},
    config::{self, ResolvedConfig},
    exit::ExitStatus,
    session::Session,
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

#[derive(Debug)]
struct CvmWithEtag {
    cvm: Cvm,
    etag: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct Operation {
    id: String,
    kind: String,
    status: String,
    actor_id: Option<String>,
    target: OperationTarget,
    result: Option<Value>,
    error: Option<OperationError>,
    progress: Option<OperationProgress>,
    created_at: String,
    updated_at: String,
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OperationTarget {
    #[serde(rename = "type")]
    kind: String,
    id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OperationError {
    code: String,
    message: String,
    details: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
struct OperationProgress {
    step: String,
    percent: u8,
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
}

enum OperationPoll {
    Operation(Box<Operation>),
    RateLimited(Duration),
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
            eprintln!("{message}");
            return ExitStatus::Usage;
        }
    };
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let page = match fetch_cvms(console_url, &session, profile_id.as_deref()) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    print_cvm_list(page, json_output);
    ExitStatus::Ok
}

fn launch(config: &ResolvedConfig, args: CvmLaunchArgs, json_output: bool) -> ExitStatus {
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let launch = match prepare_launch(config, console_url, &session, &args) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let operation = match submit_launch(console_url, &session.access_token, &launch) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if args.no_wait {
        print_operation(&operation, json_output, false);
        return ExitStatus::Ok;
    }
    let operation = match wait_for_operation(
        console_url,
        &session.access_token,
        operation,
        Duration::from_secs(u64::from(args.wait_timeout_seconds)),
        json_output,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let result = match cvm_launch_result(&operation) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Error;
        }
    };
    let policy_file =
        match write_policy_file(&config.config_dir, &result.policy_bundle, &result.cvm.id) {
            Ok(value) => value,
            Err(message) => {
                eprintln!("{message}");
                return ExitStatus::Error;
            }
        };
    if let Err(message) = persist_launch_defaults(config, &result.cvm, &launch.profile_ids) {
        eprintln!("{message}");
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
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let profile_id = match selected_profile(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let current = match fetch_cvm_with_etag(console_url, &session, cvm_id) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let cvm = match mutate_profile(
        console_url,
        &session.access_token,
        cvm_id,
        &current.etag,
        profile_id,
        mutation,
    ) {
        Ok(value) => value.cvm,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&cvm).expect("CVM output serializes")
        );
    } else {
        println!(
            "{} profile {} {}",
            mutation.as_str(),
            profile_id,
            cvm_summary(&cvm)
        );
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
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let current = match fetch_cvm_with_etag(console_url, &session, cvm_id) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let cvm = match submit_lifecycle_action(
        console_url,
        &session.access_token,
        cvm_id,
        &current.etag,
        action,
    ) {
        Ok(value) => value.cvm,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    print_lifecycle_result(action, &cvm, json_output);
    ExitStatus::Ok
}

fn update(config: &ResolvedConfig, args: CvmUpdateArgs, json_output: bool) -> ExitStatus {
    if let Err(message) = validate_uuid("CVM_ID", &args.cvm_id) {
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let current = match fetch_cvm_with_etag(console_url, &session, &args.cvm_id) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let operation = match submit_update(
        console_url,
        &session.access_token,
        &args.cvm_id,
        &current.etag,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if args.no_wait {
        print_operation(&operation, json_output, false);
        return ExitStatus::Ok;
    }
    let operation = match wait_for_operation(
        console_url,
        &session.access_token,
        operation,
        Duration::from_secs(u64::from(args.wait_timeout_seconds)),
        json_output,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let result = match cvm_launch_result(&operation) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Error;
        }
    };
    let policy_file =
        match write_policy_file(&config.config_dir, &result.policy_bundle, &result.cvm.id) {
            Ok(value) => value,
            Err(message) => {
                eprintln!("{message}");
                return ExitStatus::Error;
            }
        };
    print_update_result(result.cvm, policy_file, json_output);
    ExitStatus::Ok
}

fn terminate(config: &ResolvedConfig, args: CvmTerminateArgs, json_output: bool) -> ExitStatus {
    if let Err(message) = validate_uuid("CVM_ID", &args.cvm_id) {
        eprintln!("{message}");
        return ExitStatus::Usage;
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let current = match fetch_cvm_with_etag(console_url, &session, &args.cvm_id) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let operation = match submit_terminate(
        console_url,
        &session.access_token,
        &args.cvm_id,
        &current.etag,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if args.no_wait {
        print_operation(&operation, json_output, false);
        return ExitStatus::Ok;
    }
    let operation = match wait_for_operation(
        console_url,
        &session.access_token,
        operation,
        Duration::from_secs(u64::from(args.wait_timeout_seconds)),
        json_output,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let cvm = match operation_cvm_result(&operation) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Error;
        }
    };
    print_terminate_result(&cvm, json_output);
    ExitStatus::Ok
}

struct LaunchRequest {
    profile_ids: Vec<String>,
    ssh_key_ids: Vec<String>,
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
    let ssh_key_ids = selected_launch_ssh_keys(config, console_url, session, args)?;
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
            eprintln!("using profile {} ({})", profile.name, profile.id);
            Ok(vec![profile.id.clone()])
        }
        [] => Err((
            ExitStatus::Usage,
            "[usage] no assigned profiles found; ask an admin to assign you a profile".to_string(),
        )),
        profiles => {
            eprintln!("available profiles:");
            for profile in profiles {
                eprintln!("  {} {}", profile.id, profile.name);
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
) -> Result<Vec<String>, (ExitStatus, String)> {
    if !args.ssh_keys.is_empty() {
        for ssh_key_id in &args.ssh_keys {
            validate_uuid("--ssh-key", ssh_key_id)
                .map_err(|message| (ExitStatus::Usage, message))?;
        }
        return Ok(args.ssh_keys.clone());
    }
    let keys = fetch_launch_keys(console_url, session)?;
    if !keys.items.is_empty() {
        if keys.items.len() > 16 {
            return Err((
                ExitStatus::Usage,
                "[usage] more than 16 registered SSH keys found; rerun with explicit --ssh-key values"
                    .to_string(),
            ));
        }
        let key_ids = keys
            .items
            .iter()
            .map(|key| key.id.clone())
            .collect::<Vec<_>>();
        eprintln!(
            "using registered SSH key{} {}",
            if key_ids.len() == 1 { "" } else { "s" },
            keys.items
                .iter()
                .map(|key| format!("{} ({})", key.label, key.id))
                .collect::<Vec<_>>()
                .join(", ")
        );
        return Ok(key_ids);
    }
    let public_key = ensure_default_ssh_public_key(config)?;
    let key = create_launch_key(console_url, session, "default", &public_key)?;
    eprintln!("created and registered SSH key default ({})", key.id);
    Ok(vec![key.id])
}

fn console_session(config: &ResolvedConfig) -> Result<(&str, Session), (ExitStatus, String)> {
    let console_url = config
        .require_console_url()
        .map_err(|message| (ExitStatus::Usage, message))?;
    let session = auth::session_for_console(config)?;
    Ok((console_url, session))
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

fn ensure_default_ssh_public_key(config: &ResolvedConfig) -> Result<String, (ExitStatus, String)> {
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
    let (private_key, public_key) = default_ssh_key_paths(&ssh_dir)?;
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
    } else if !public_key.exists() {
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
        write_public_key_file(&public_key, &output.stdout)?;
    }
    let public_key_value = fs::read_to_string(&public_key).map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to read {}: {err}", public_key.display()),
        )
    })?;
    let public_key_value = public_key_value.trim();
    if public_key_value.is_empty() {
        return Err((
            ExitStatus::Error,
            format!("[error] {} is empty", public_key.display()),
        ));
    }
    eprintln!("using local SSH key {}", public_key.display());
    Ok(public_key_value.to_string())
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

fn default_ssh_key_paths(ssh_dir: &Path) -> Result<(PathBuf, PathBuf), (ExitStatus, String)> {
    let preferred = ssh_dir.join("id_ed25519");
    let preferred_public = ssh_dir.join("id_ed25519.pub");
    if preferred.exists() || !preferred_public.exists() {
        return Ok((preferred, preferred_public));
    }
    for index in 0..100 {
        let name = if index == 0 {
            "concrete_ed25519".to_string()
        } else {
            format!("concrete_ed25519_{index}")
        };
        let private_key = ssh_dir.join(&name);
        let public_key = ssh_dir.join(format!("{name}.pub"));
        if !private_key.exists() && !public_key.exists() {
            return Ok((private_key, public_key));
        }
    }
    Err((
        ExitStatus::Error,
        format!(
            "[error] failed to find an unused SSH key path under {}",
            ssh_dir.display()
        ),
    ))
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
) -> Result<CvmWithEtag, (ExitStatus, String)> {
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
    read_cvm_with_etag(response, "fetch CVM")
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
) -> Result<CvmWithEtag, (ExitStatus, String)> {
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
    read_cvm_with_etag(response, mutation.as_str())
}

fn submit_lifecycle_action(
    console_url: &str,
    access_token: &str,
    cvm_id: &str,
    etag: &str,
    action: LifecycleAction,
) -> Result<CvmWithEtag, (ExitStatus, String)> {
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
    read_cvm_with_etag(response, action.as_str())
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

fn fetch_operation(
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
        return Ok(OperationPoll::RateLimited(retry_after(&response)));
    }
    read_json_response(response, "poll operation")
        .map(|operation| OperationPoll::Operation(Box::new(operation)))
}

fn wait_for_operation(
    console_url: &str,
    access_token: &str,
    mut operation: Operation,
    timeout: Duration,
    json_output: bool,
) -> Result<Operation, (ExitStatus, String)> {
    let started = Instant::now();
    let mut excluded = Duration::ZERO;
    loop {
        match operation.status.as_str() {
            "succeeded" => return Ok(operation),
            "failed" => return Err((ExitStatus::Error, operation_failure_message(&operation))),
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

fn read_cvm_with_etag(
    response: Response,
    action: &str,
) -> Result<CvmWithEtag, (ExitStatus, String)> {
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
    let cvm = response.json::<Cvm>().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] malformed {action} response: {err}"),
        )
    })?;
    Ok(CvmWithEtag { cvm, etag })
}

pub(crate) fn read_json_response<T: for<'de> Deserialize<'de>>(
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

fn retry_after(response: &Response) -> Duration {
    response
        .headers()
        .get(RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(|seconds| Duration::from_secs(seconds.max(1)))
        .unwrap_or_else(|| Duration::from_secs(1))
}

fn operation_failure_message(operation: &Operation) -> String {
    if let Some(error) = &operation.error {
        format!("[{}] {}", error.code, error.message)
    } else {
        "[error] operation failed".to_string()
    }
}

fn cvm_launch_result(operation: &Operation) -> Result<CvmLaunchResult, String> {
    let result = operation
        .result
        .clone()
        .ok_or_else(|| "[error] CVM launch operation succeeded without result".to_string())?;
    serde_json::from_value::<CvmLaunchResult>(result)
        .map_err(|err| format!("[error] malformed CVM launch result: {err}"))
}

fn operation_cvm_result(operation: &Operation) -> Result<Cvm, String> {
    let result = operation
        .result
        .clone()
        .ok_or_else(|| "[error] CVM operation succeeded without result".to_string())?;
    serde_json::from_value::<Cvm>(result)
        .map_err(|err| format!("[error] malformed CVM result: {err}"))
}

pub(crate) fn write_policy_file(
    config_dir: &Path,
    bundle: &PolicyBundle,
    cvm_id: &str,
) -> Result<PathBuf, String> {
    if bundle.cvm_id != cvm_id {
        return Err("[error] CVM launch result policy bundle did not match CVM id".to_string());
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
    let tmp = dir.join(format!(".{cvm_id}.{}.tmp", std::process::id()));
    let data = serde_json::to_vec_pretty(&policy_document(bundle))
        .map_err(|err| format!("[error] failed to serialize aTLS policy: {err}"))?;
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|err| format!("[error] failed to create temporary aTLS policy file: {err}"))?;
    file.write_all(&data)
        .and_then(|_| file.sync_all())
        .map_err(|err| format!("[error] failed to write aTLS policy file: {err}"))?;
    fs::rename(&tmp, &target)
        .map_err(|err| format!("[error] failed to install aTLS policy file: {err}"))?;
    #[cfg(unix)]
    {
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).map_err(|err| {
            format!("[error] failed to tighten aTLS policy file permissions: {err}")
        })?;
    }
    Ok(target)
}

fn persist_launch_defaults(
    config: &ResolvedConfig,
    cvm: &Cvm,
    profile_ids: &[String],
) -> Result<(), String> {
    let mut values = vec![("default_cvm", cvm.id.clone())];
    if config.profile.is_none() && profile_ids.len() == 1 {
        values.push(("default_profile", profile_ids[0].clone()));
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

fn error_for_response(response: Response, action: &str) -> (ExitStatus, String) {
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
    let message =
        console_error_message(&text).unwrap_or_else(|| format!("{action} failed: HTTP {status}"));
    let tag = if matches!(exit, ExitStatus::AuthRequired) {
        "auth_required"
    } else if matches!(exit, ExitStatus::Usage) {
        "usage"
    } else {
        "error"
    };
    (exit, format!("[{tag}] {message}"))
}

fn console_error_message(body: &str) -> Option<String> {
    let value: Value = serde_json::from_str(body).ok()?;
    let error = value.get("error")?;
    let message = error.get("message")?.as_str()?;
    let code = error.get("code").and_then(|value| value.as_str());
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
    let validation_type = details
        .and_then(|details| details.get("errors"))
        .and_then(|errors| errors.as_array())
        .and_then(|errors| errors.first())
        .and_then(|error| error.get("type"))
        .and_then(|value| value.as_str());
    Some(match (state, required, component, validation_type, code) {
        (Some(state), _, _, _, _) => format!("{message} ({state})"),
        (_, Some(required), _, _, _) => format!("{message} ({required})"),
        (_, _, Some(component), _, _) => format!("{message} ({component})"),
        (_, _, _, Some(validation_type), _) => format!("{message} ({validation_type})"),
        (_, _, _, _, Some(code)) if code != "UNAUTHORIZED" && code != "VALIDATION_ERROR" => {
            format!("{message} ({code})")
        }
        _ => message.to_string(),
    })
}

fn print_cvm_list(page: CvmListPage, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&page.items).expect("CVM list output serializes")
        );
    } else if page.items.is_empty() {
        println!("no cvms");
    } else {
        for cvm in &page.items {
            println!("{}", cvm_summary(cvm));
        }
        if let Some(cursor) = page.next_cursor {
            eprintln!("next cursor: {cursor}");
        }
    }
}

fn print_operation(operation: &Operation, json_output: bool, stderr: bool) {
    let text = if json_output {
        serde_json::to_string_pretty(operation).expect("operation output serializes")
    } else {
        format!(
            "operation {} kind={} status={} target={}/{}",
            operation.id,
            operation.kind,
            operation.status,
            operation.target.kind,
            operation.target.id.as_deref().unwrap_or("-")
        )
    };
    if stderr {
        eprintln!("{text}");
    } else {
        println!("{text}");
    }
}

fn print_launch_result(cvm: Cvm, policy_file: PathBuf, json_output: bool) {
    if json_output {
        let output = CvmLaunchOutput {
            cvm,
            policy_file_path: policy_file.display().to_string(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("CVM launch output serializes")
        );
    } else {
        println!(
            "launched {} policy_file={}",
            cvm_summary(&cvm),
            policy_file.display()
        );
    }
}

fn print_lifecycle_result(action: LifecycleAction, cvm: &Cvm, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(cvm).expect("CVM output serializes")
        );
    } else {
        println!("{} {}", action.past_tense(), cvm_summary(cvm));
    }
}

fn print_update_result(cvm: Cvm, policy_file: PathBuf, json_output: bool) {
    if json_output {
        let output = CvmLaunchOutput {
            cvm,
            policy_file_path: policy_file.display().to_string(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("CVM update output serializes")
        );
    } else {
        println!(
            "updated {} policy_file={}",
            cvm_summary(&cvm),
            policy_file.display()
        );
    }
}

fn print_terminate_result(cvm: &Cvm, json_output: bool) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(cvm).expect("CVM output serializes")
        );
    } else {
        println!("terminated {}", cvm_summary(cvm));
    }
}

fn cvm_summary(cvm: &Cvm) -> String {
    format!(
        "cvm {} state={} fqdn={} owner={} profiles={} ssh_keys={} updated_at={}",
        cvm.id,
        cvm.state,
        cvm.fqdn.as_deref().unwrap_or("-"),
        cvm.owner.email,
        cvm.profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect::<Vec<_>>()
            .join(","),
        cvm.ssh_keys
            .iter()
            .map(|key| key.label.as_str())
            .collect::<Vec<_>>()
            .join(","),
        cvm.updated_at
    )
}

fn validate_uuid(name: &str, value: &str) -> Result<(), String> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| format!("[usage] {name} must be a UUID"))
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
    fn console_error_message_includes_last_profile_state() {
        let body = r#"{"error":{"code":"CONFLICT","message":"cannot detach the last CVM profile","details":{"state":"last_profile"}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("cannot detach the last CVM profile (last_profile)")
        );
    }

    #[test]
    fn console_error_message_includes_required_membership() {
        let body = r#"{"error":{"code":"FORBIDDEN","message":"profile membership is required","details":{"required":"profile_member"}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("profile membership is required (profile_member)")
        );
    }

    #[test]
    fn console_error_message_includes_missing_component() {
        let body = r#"{"error":{"code":"SERVICE_UNAVAILABLE","message":"Dev CVM image is not configured","details":{"component":"dev_cvm_image"}}}"#;

        assert_eq!(
            console_error_message(body).as_deref(),
            Some("Dev CVM image is not configured (dev_cvm_image)")
        );
    }

    #[test]
    fn policy_document_maps_policy_bundle_to_atls_policy() {
        let bundle = PolicyBundle {
            cvm_id: "00000000-0000-4000-8000-000000000001".to_string(),
            compose_template: "services: {}".to_string(),
            expected_bootchain: json!({
                "mrtd": "a".repeat(64),
                "rtmr0": "b".repeat(64),
                "rtmr1": "c".repeat(64),
                "rtmr2": "d".repeat(64),
            }),
            os_image_hash: "e".repeat(64),
            rtmr3_binding: json!({
                "cvm_id": "00000000-0000-4000-8000-000000000001",
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
                    Value::String("app-443s.dstack.example.com".to_string()),
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
        };

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
    fn validate_cvm_config_value_rejects_spaces() {
        assert_eq!(
            validate_cvm_config_value("--region", "FR PARIS").expect_err("space rejected"),
            "[usage] --region may contain only letters, digits, '.', '_', and '-'"
        );
    }

    #[test]
    fn default_ssh_key_paths_prefers_id_ed25519_when_unused() {
        let dir = std::env::temp_dir().join(format!("concrete-cvm-key-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");

        let (private_key, public_key) = default_ssh_key_paths(&dir).expect("key paths resolved");

        assert_eq!(private_key, dir.join("id_ed25519"));
        assert_eq!(public_key, dir.join("id_ed25519.pub"));
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    #[test]
    fn default_ssh_key_paths_does_not_target_existing_public_key_without_private_key() {
        let dir = std::env::temp_dir().join(format!("concrete-cvm-key-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");
        fs::write(dir.join("id_ed25519.pub"), "ssh-ed25519 existing\n")
            .expect("public key written");

        let (private_key, public_key) = default_ssh_key_paths(&dir).expect("key paths resolved");

        assert_eq!(private_key, dir.join("concrete_ed25519"));
        assert_eq!(public_key, dir.join("concrete_ed25519.pub"));
        fs::remove_dir_all(dir).expect("temp dir removed");
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
