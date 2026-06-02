use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use chrono::Utc;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::{
    cli::{
        AgentSessionArgs, AliasArgs, CodeArgs, CursorArgs, SessionListArgs, SessionTargetArgs,
        SshArgs,
    },
    config::ResolvedConfig,
    console::console_session,
    exit::ExitStatus,
    session::Session,
    ssh_identity, ssh_identity_store, style,
};

#[derive(Debug, Deserialize)]
struct CvmSshKeyRef {
    id: String,
}

#[derive(Debug, Deserialize)]
struct MeSshKey {
    id: String,
    fingerprint: String,
}

#[derive(Debug, Deserialize)]
struct MeSshKeyListPage {
    items: Vec<MeSshKey>,
}

#[derive(Debug)]
struct InstalledSshKey {
    id: String,
    fingerprint: String,
}

#[derive(Debug, Deserialize)]
struct Cvm {
    id: String,
    state: String,
    fqdn: Option<String>,
    error_reason: Option<String>,
    ssh_keys: Vec<CvmSshKeyRef>,
}

struct SshInvocation<'a> {
    cvm_id: Option<&'a str>,
    identity_file: Option<&'a Path>,
    remote_command: String,
    allocate_tty: bool,
}

struct PreparedSsh {
    cvm_id: String,
    fqdn: String,
    proxy_command: String,
    identity_file: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct SessionRow {
    name: String,
    attached: bool,
    alias: Option<String>,
    created_at: String,
}

pub fn run(args: SshArgs, config: &ResolvedConfig) -> ExitStatus {
    if args.name.is_some() && args.command.is_some() {
        crate::style::eprintln_error("[usage] --name cannot be combined with --command");
        return ExitStatus::Usage;
    }
    let remote_command = match ssh_remote_command(&args) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    run_ssh(
        SshInvocation {
            cvm_id: args.cvm_id.as_deref(),
            identity_file: args.identity_file.as_deref(),
            remote_command,
            allocate_tty: args.command.is_none(),
        },
        config,
    )
}

pub fn run_agent(
    args: AgentSessionArgs,
    config: &ResolvedConfig,
    verb: &'static str,
) -> ExitStatus {
    let program = match verb {
        "claude" => "claude",
        "codex" => "codex",
        _ => {
            crate::style::eprintln_error(&format!("[error] unsupported agent session verb {verb}"));
            return ExitStatus::Error;
        }
    };
    if let Some(workspace) = args.workspace.as_deref() {
        if let Err(message) = validate_workspace_path(workspace) {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    }
    let cvm_id = match selected_cvm_id(args.cvm_id.as_deref(), config) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let workspace = resolve_workspace(args.workspace.as_deref(), config, &cvm_id);
    let program_command = agent_program_command(program, workspace.as_deref());
    let session_name = match session_name(args.name.as_deref(), program) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    run_ssh(
        SshInvocation {
            cvm_id: Some(&cvm_id),
            identity_file: args.identity_file.as_deref(),
            remote_command: dtach_remote_command(&session_name, &program_command),
            allocate_tty: true,
        },
        config,
    )
}

pub fn run_code(args: CodeArgs, config: &ResolvedConfig) -> ExitStatus {
    let bin = args.code_bin.unwrap_or_else(|| PathBuf::from("code"));
    run_editor(
        &bin,
        args.workspace.as_deref(),
        args.identity_file.as_deref(),
        config,
    )
}

pub fn run_cursor(args: CursorArgs, config: &ResolvedConfig) -> ExitStatus {
    let bin = args.cursor_bin.unwrap_or_else(|| PathBuf::from("cursor"));
    run_editor(
        &bin,
        args.workspace.as_deref(),
        args.identity_file.as_deref(),
        config,
    )
}

pub fn run_ps(args: SessionListArgs, config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let cvm_id = match selected_cvm_id(None, config) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let aliases = match aliases_by_session(&config.config_dir, &cvm_id) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    let output = match run_ssh_capture(
        SshInvocation {
            cvm_id: Some(&cvm_id),
            identity_file: args.identity_file.as_deref(),
            remote_command: ps_remote_command(),
            allocate_tty: false,
        },
        config,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let rows = match parse_session_rows(&output, &aliases) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    print_session_rows(&rows, json_output, &cvm_id);
    ExitStatus::Ok
}

pub fn run_attach(args: SessionTargetArgs, config: &ResolvedConfig) -> ExitStatus {
    let cvm_id = match selected_cvm_id(None, config) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let session_name = match resolve_target(&config.config_dir, &cvm_id, &args.target) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    run_ssh(
        SshInvocation {
            cvm_id: Some(&cvm_id),
            identity_file: args.identity_file.as_deref(),
            remote_command: attach_remote_command(&session_name),
            allocate_tty: true,
        },
        config,
    )
}

pub fn run_kill(args: SessionTargetArgs, config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let cvm_id = match selected_cvm_id(None, config) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let session_name = match resolve_target(&config.config_dir, &cvm_id, &args.target) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    match run_ssh_capture(
        SshInvocation {
            cvm_id: Some(&cvm_id),
            identity_file: args.identity_file.as_deref(),
            remote_command: kill_remote_command(&session_name),
            allocate_tty: false,
        },
        config,
    ) {
        Ok(_) => {
            if json_output {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "cvm_id": cvm_id,
                        "session_name": session_name,
                    }))
                    .expect("kill output serializes")
                );
            } else {
                // Section 7.30: identifier is the session name (the entity
                // being killed); detail row records the CVM the session was
                // running on.
                let confirm =
                    crate::style::ConfirmBlock::new("killed", "session", session_name.clone())
                        .field("cvm", cvm_id.clone());
                println!("{}", crate::style::render_confirm(&confirm));
            }
            ExitStatus::Ok
        }
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            status
        }
    }
}

pub fn run_alias(args: AliasArgs, config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let cvm_id = match selected_cvm_id(None, config) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    if let Err(message) = validate_session_name(&args.name) {
        crate::style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    if let Err(message) = validate_session_name(&args.alias) {
        crate::style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    let output = match run_ssh_capture(
        SshInvocation {
            cvm_id: Some(&cvm_id),
            identity_file: args.identity_file.as_deref(),
            remote_command: ps_remote_command(),
            allocate_tty: false,
        },
        config,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let rows = match parse_session_rows(&output, &BTreeMap::new()) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    if rows.iter().any(|row| row.name == args.alias) {
        crate::style::eprintln_error(&format!(
            "[error] alias {} collides with an existing dtach session name",
            args.alias
        ));
        return ExitStatus::Error;
    }
    if !rows.iter().any(|row| row.name == args.name) {
        crate::style::eprintln_error(&format!(
            "[error] session {} was not found on {}",
            args.name, cvm_id
        ));
        return ExitStatus::Error;
    }
    if let Err(message) = write_alias(&config.config_dir, &cvm_id, &args.name, &args.alias) {
        crate::style::eprintln_error(&message);
        return ExitStatus::Error;
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "cvm_id": cvm_id,
                "session_name": args.name,
                "alias": args.alias,
            }))
            .expect("alias output serializes")
        );
    } else {
        // Section 7.31: identifier is the new alias; detail rows record the
        // underlying session and the CVM the alias is scoped to.
        let confirm = crate::style::ConfirmBlock::new("aliased", "session", args.alias.clone())
            .field("session", args.name.clone())
            .field("cvm", cvm_id.clone());
        println!("{}", crate::style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn run_ssh(invocation: SshInvocation<'_>, config: &ResolvedConfig) -> ExitStatus {
    let prepared = match prepare_ssh(invocation.cvm_id, invocation.identity_file, config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let mut ssh = base_ssh_command(&prepared, invocation.allocate_tty);
    ssh.arg(invocation.remote_command);
    let result = ssh.status();
    // ssh has handed the terminal back; make sure the cursor is visible no
    // matter how the remote session (or a detached TUI) left it.
    restore_local_cursor(invocation.allocate_tty);
    match result {
        Ok(status) if status.success() => ExitStatus::Ok,
        Ok(status) => {
            crate::style::eprintln_error(&format!("[error] ssh exited with status {status}"));
            ExitStatus::Error
        }
        Err(err) => {
            crate::style::eprintln_error(&format!("[error] failed to invoke ssh: {err}"));
            ExitStatus::Error
        }
    }
}

fn run_editor(
    editor_bin: &Path,
    workspace_arg: Option<&str>,
    identity_file: Option<&Path>,
    config: &ResolvedConfig,
) -> ExitStatus {
    if let Some(value) = workspace_arg {
        if let Err(message) = validate_workspace_path(value) {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    }
    let prepared = match prepare_ssh(None, identity_file, config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let workspace = resolve_workspace(workspace_arg, config, &prepared.cvm_id);
    let launch = match write_editor_ssh_files(config, &prepared) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    let mut editor = Command::new(editor_bin);
    editor
        .arg("--folder-uri")
        .arg(editor_remote_uri(&launch.host_alias, workspace.as_deref()))
        .env("PATH", path_with_prefix(&launch.wrapper_dir))
        .stdin(Stdio::null())
        .stdout(Stdio::null());
    match editor.spawn() {
        Ok(_) => ExitStatus::Ok,
        Err(err) => {
            crate::style::eprintln_error(&format!(
                "[error] failed to launch editor binary {}: {err}",
                editor_bin.display()
            ));
            ExitStatus::Error
        }
    }
}

fn run_ssh_capture(
    invocation: SshInvocation<'_>,
    config: &ResolvedConfig,
) -> Result<String, (ExitStatus, String)> {
    let prepared = prepare_ssh(invocation.cvm_id, invocation.identity_file, config)?;
    let mut ssh = base_ssh_command(&prepared, invocation.allocate_tty);
    ssh.arg(invocation.remote_command);
    let output = ssh.output().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to invoke ssh: {err}"),
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let detail = if stderr.is_empty() {
            format!("{}", output.status)
        } else {
            format!("{}: {}", output.status, stderr)
        };
        return Err((
            ExitStatus::Error,
            format!("[error] ssh exited with {detail}"),
        ));
    }
    String::from_utf8(output.stdout).map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] SSH output was not UTF-8: {err}"),
        )
    })
}

fn prepare_ssh(
    cvm_id_arg: Option<&str>,
    explicit_identity: Option<&Path>,
    config: &ResolvedConfig,
) -> Result<PreparedSsh, (ExitStatus, String)> {
    let cvm_id = match selected_cvm_id(cvm_id_arg, config) {
        Ok(value) => value,
        Err(message) => {
            return Err((ExitStatus::Usage, message));
        }
    };
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            return Err((status, message));
        }
    };
    let cvm = match fetch_cvm(console_url, &session, &cvm_id) {
        Ok(value) => value,
        Err((status, message)) => {
            return Err((status, message));
        }
    };
    if cvm.state != "RUNNING" {
        return Err((
            ExitStatus::Error,
            format!(
                "[error] Dev CVM {} is in state {}, expected RUNNING",
                cvm.id, cvm.state
            ),
        ));
    }
    if cvm.error_reason.as_deref() == Some("SECURITY_CVM_REBIND_REQUIRED") {
        return Err((
            ExitStatus::Error,
            format!(
                "[error] Dev CVM {} needs an update after the Security CVM changed. Run `concrete cvm update {}`; if the local aTLS policy changes, the CLI will ask before replacing your trusted measurement.",
                cvm.id, cvm.id
            ),
        ));
    }
    let fqdn = match cvm.fqdn.as_deref() {
        Some(value) if !value.is_empty() => value.to_string(),
        _ => {
            return Err((
                ExitStatus::Error,
                format!("[error] Dev CVM {} does not have an FQDN yet", cvm.id),
            ));
        }
    };
    let policy_path = match resolve_policy_path(config, console_url, &session, &cvm.id) {
        Ok(value) => value,
        Err((status, message)) => {
            return Err((status, message));
        }
    };
    let proxy_command = match proxy_command(config, &policy_path, &fqdn) {
        Ok(value) => value,
        Err(message) => {
            return Err((ExitStatus::Error, message));
        }
    };
    let identity_file = if let Some(path) = explicit_identity {
        Some(ssh_identity::resolve_explicit_identity(path)?)
    } else {
        let installed_keys = match installed_keys(console_url, &session, &cvm) {
            Ok(value) => value,
            Err((status, message)) => {
                return Err((status, message));
            }
        };
        let fingerprints = installed_keys
            .iter()
            .map(|key| key.fingerprint.clone())
            .collect::<Vec<_>>();
        let identity = if let Some(identity) = resolve_stored_identity(config, &installed_keys) {
            Some(identity)
        } else {
            ssh_identity::resolve_session_identity(config, None, &fingerprints)?
        };
        if identity.is_none() && !fingerprints.is_empty() {
            eprintln!(
                "{}",
                style::info_line(
                    "no matching local SSH private key found for this CVM; falling back to ssh-agent/default identities"
                )
            );
        }
        identity
    };
    Ok(PreparedSsh {
        cvm_id: cvm.id,
        fqdn,
        proxy_command,
        identity_file,
    })
}

fn base_ssh_command(prepared: &PreparedSsh, allocate_tty: bool) -> Command {
    let mut ssh = Command::new("ssh");
    ssh.arg("-o")
        .arg(format!("ProxyCommand={}", prepared.proxy_command))
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-o")
        .arg(format!(
            "BatchMode={}",
            if allocate_tty && io::stdin().is_terminal() {
                "no"
            } else {
                "yes"
            }
        ))
        .arg("-o")
        .arg("ConnectTimeout=30");
    if let Some(identity_file) = prepared.identity_file.as_deref() {
        ssh.arg("-o").arg("IdentitiesOnly=yes");
        ssh.arg("-i").arg(identity_file);
    }
    if allocate_tty {
        ssh.arg("-t");
    }
    ssh.arg(format!("dev@{}", prepared.fqdn));
    ssh
}

fn selected_cvm_id(arg: Option<&str>, config: &ResolvedConfig) -> Result<String, String> {
    arg.map(ToString::to_string)
        .or_else(|| config.default_cvm.clone())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "[usage] missing CVM id; pass <CVM_ID> or set --cvm, CONCRETE_DEFAULT_CVM, or default_cvm"
                .to_string()
        })
}

fn fetch_cvm(
    console_url: &str,
    session: &Session,
    cvm_id: &str,
) -> Result<Cvm, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/cvms/{cvm_id}"))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch Dev CVM: {err}"),
            )
        })?;
    crate::console::read_json_response(response, "fetch Dev CVM")
}

fn installed_keys(
    console_url: &str,
    session: &Session,
    cvm: &Cvm,
) -> Result<Vec<InstalledSshKey>, (ExitStatus, String)> {
    if cvm.ssh_keys.is_empty() {
        return Ok(Vec::new());
    }
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
    let page: MeSshKeyListPage = crate::console::read_json_response(response, "list SSH keys")?;
    let installed_ids = cvm
        .ssh_keys
        .iter()
        .map(|key| key.id.as_str())
        .collect::<std::collections::HashSet<_>>();
    Ok(page
        .items
        .into_iter()
        .filter(|key| installed_ids.contains(key.id.as_str()))
        .map(|key| InstalledSshKey {
            id: key.id,
            fingerprint: key.fingerprint,
        })
        .collect())
}

fn resolve_stored_identity(
    config: &ResolvedConfig,
    installed_keys: &[InstalledSshKey],
) -> Option<PathBuf> {
    let stored = ssh_identity_store::read(&config.config_dir);
    for key in installed_keys {
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

fn resolve_policy_path(
    config: &ResolvedConfig,
    console_url: &str,
    session: &Session,
    cvm_id: &str,
) -> Result<PathBuf, (ExitStatus, String)> {
    let policy_path = per_cvm_policy_path(&config.config_dir, cvm_id);
    if policy_path.is_file() {
        return Ok(policy_path);
    }
    let bundle = fetch_policy_bundle(console_url, session, cvm_id)?;
    crate::commands::cvm::write_policy_file(&config.config_dir, &bundle, cvm_id)
        .map_err(|message| (ExitStatus::Error, message))
}

fn fetch_policy_bundle(
    console_url: &str,
    session: &Session,
    cvm_id: &str,
) -> Result<crate::commands::cvm::PolicyBundle, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/cvms/{cvm_id}/policy-bundle"))
        .bearer_auth(&session.access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to fetch Dev CVM policy bundle: {err}"),
            )
        })?;
    crate::console::read_json_response(response, "fetch Dev CVM policy bundle")
}

fn per_cvm_policy_path(config_dir: &Path, cvm_id: &str) -> PathBuf {
    config_dir
        .join("cvms")
        .join(format!("{cvm_id}.atls-policy.json"))
}

fn proxy_command(
    config: &ResolvedConfig,
    policy_path: &Path,
    fqdn: &str,
) -> Result<String, String> {
    let exe = env::current_exe()
        .map_err(|err| format!("[error] failed to resolve current executable: {err}"))?;
    let console_url = config
        .console_url
        .as_deref()
        .ok_or_else(|| "[usage] missing Console URL".to_string())?;
    Ok(format!(
        "{} --config {} --console-url {} --atls-policy {} tunnel {}",
        shell_quote(&exe.display().to_string()),
        shell_quote(&config.config_dir.display().to_string()),
        shell_quote(console_url),
        shell_quote(&policy_path.display().to_string()),
        shell_quote(fqdn),
    ))
}

struct EditorLaunch {
    host_alias: String,
    wrapper_dir: PathBuf,
}

fn render_editor_ssh_config(host_alias: &str, prepared: &PreparedSsh) -> Result<String, String> {
    let mut out = format!(
        "Host {host_alias}\n  HostName {}\n  User dev\n  ProxyCommand {}\n  StrictHostKeyChecking no\n  UserKnownHostsFile /dev/null\n  LogLevel ERROR\n  BatchMode yes\n  ConnectTimeout 30\n",
        prepared.fqdn, prepared.proxy_command,
    );
    if let Some(path) = prepared.identity_file.as_ref() {
        out.push_str(&format!(
            "  IdentityFile {}\n  IdentitiesOnly yes\n",
            ssh_config_quoted_path(path)?,
        ));
    }
    Ok(out)
}

fn write_editor_ssh_files(
    config: &ResolvedConfig,
    prepared: &PreparedSsh,
) -> Result<EditorLaunch, String> {
    validate_ssh_config_token(&prepared.fqdn, "Dev CVM FQDN")?;
    if prepared.proxy_command.contains(['\n', '\r']) {
        return Err("[error] tunnel ProxyCommand contains a newline".to_string());
    }
    let host_alias = editor_host_alias(&prepared.cvm_id);
    let base_dir = config.config_dir.join("editor-ssh").join(&host_alias);
    let wrapper_dir = base_dir.join("bin");
    fs::create_dir_all(&wrapper_dir)
        .map_err(|err| format!("[error] failed to create editor SSH config directory: {err}"))?;
    #[cfg(unix)]
    {
        fs::set_permissions(&base_dir, fs::Permissions::from_mode(0o700)).map_err(|err| {
            format!("[error] failed to tighten editor SSH config directory: {err}")
        })?;
        fs::set_permissions(&wrapper_dir, fs::Permissions::from_mode(0o700)).map_err(|err| {
            format!("[error] failed to tighten editor SSH wrapper directory: {err}")
        })?;
    }

    let config_path = base_dir.join("config");
    let ssh_config = render_editor_ssh_config(&host_alias, prepared)?;
    write_atomic_file(&config_path, ssh_config.as_bytes(), 0o600)?;

    let ssh_bin = find_ssh_binary()
        .ok_or_else(|| "[error] failed to find ssh on PATH for editor launch".to_string())?;
    let wrapper_path = wrapper_dir.join("ssh");
    let wrapper = format!(
        "#!/bin/sh\nexec {} -F {} \"$@\"\n",
        shell_quote(&ssh_bin.display().to_string()),
        shell_quote(&config_path.display().to_string()),
    );
    write_atomic_file(&wrapper_path, wrapper.as_bytes(), 0o700)?;

    Ok(EditorLaunch {
        host_alias,
        wrapper_dir,
    })
}

fn write_atomic_file(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "[error] editor SSH path has no parent directory".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("[error] failed to create editor SSH directory: {err}"))?;
    let tmp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("concrete"),
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(mode).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|err| format!("[error] failed to create temporary editor SSH file: {err}"))?;
    file.write_all(data)
        .and_then(|_| file.sync_all())
        .map_err(|err| format!("[error] failed to write editor SSH file: {err}"))?;
    fs::rename(&tmp, path)
        .map_err(|err| format!("[error] failed to install editor SSH file: {err}"))?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|err| format!("[error] failed to set editor SSH file mode: {err}"))?;
    }
    Ok(())
}

fn find_ssh_binary() -> Option<PathBuf> {
    env::var_os("PATH").and_then(|paths| {
        env::split_paths(&paths)
            .map(|path| path.join("ssh"))
            .find(|candidate| candidate.is_file() && is_executable(candidate))
    })
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        fs::metadata(path)
            .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        path.is_file()
    }
}

fn path_with_prefix(prefix: &Path) -> OsString {
    let mut paths = vec![prefix.to_path_buf()];
    if let Some(existing) = env::var_os("PATH") {
        paths.extend(env::split_paths(&existing));
    }
    env::join_paths(paths).unwrap_or_else(|_| prefix.as_os_str().to_os_string())
}

fn editor_host_alias(cvm_id: &str) -> String {
    let suffix: String = cvm_id
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') {
                byte as char
            } else {
                '-'
            }
        })
        .collect();
    let suffix = suffix.trim_matches('-');
    if suffix.is_empty() {
        "concrete-cvm".to_string()
    } else {
        format!("concrete-{suffix}")
    }
}

const DEV_REMOTE_HOME: &str = "/home/dev";

fn editor_remote_path(workspace: Option<&str>) -> String {
    let Some(value) = workspace else {
        return DEV_REMOTE_HOME.to_string();
    };
    if let Some(rest) = value.strip_prefix("~/") {
        format!("{DEV_REMOTE_HOME}/{rest}")
    } else if value.starts_with('/') {
        value.to_string()
    } else {
        format!("{DEV_REMOTE_HOME}/{value}")
    }
}

fn editor_remote_uri(host_alias: &str, workspace: Option<&str>) -> String {
    let path = editor_remote_path(workspace);
    format!("vscode-remote://ssh-remote+{host_alias}{path}")
}

fn resolve_workspace(
    explicit: Option<&str>,
    config: &ResolvedConfig,
    cvm_id: &str,
) -> Option<String> {
    if let Some(value) = explicit {
        let _ = crate::cvm_state::write_workspace(&config.config_dir, cvm_id, value);
        return Some(value.to_string());
    }
    crate::cvm_state::read(&config.config_dir, cvm_id).workspace
}

fn validate_ssh_config_token(value: &str, label: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(format!("[error] {label} is not safe for SSH config output"));
    }
    Ok(())
}

fn ssh_config_quoted_path(path: &Path) -> Result<String, String> {
    let value = path
        .to_str()
        .ok_or_else(|| "[error] SSH identity path is not valid UTF-8".to_string())?;
    if value
        .bytes()
        .any(|byte| byte < 0x20 || byte == 0x7f || matches!(byte, b'\n' | b'\r'))
    {
        return Err("[error] SSH identity path is not safe for SSH config output".to_string());
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

fn ssh_remote_command(args: &SshArgs) -> Result<String, String> {
    if let Some(command) = args.command.clone() {
        return Ok(command);
    }
    let session_name = session_name(args.name.as_deref(), "ssh")?;
    Ok(dtach_remote_command(&session_name, "bash -l"))
}

fn session_name(value: Option<&str>, prefix: &str) -> Result<String, String> {
    match value {
        Some(value) => Ok(validate_session_name(value)?.to_string()),
        None => Ok(default_session_name(prefix)),
    }
}

// CSI ? 25 h ensures the cursor is visible; CSI 1 SP q (DECSCUSR) selects a
// blinking block. dtach does not propagate the outer terminal's cursor mode
// when re-attaching, so we restore it explicitly on attach. New sessions pick
// the same state up from /etc/profile.d/concrete-env.sh.
const TERMINAL_CURSOR_RESTORE: &str = "printf '\\033[?25h\\033[1 q'; ";

// CSI ? 25 h shows the cursor on the *local* terminal. ssh restores termios on
// exit but not DECTCEM, and dtach (unlike tmux/screen) never saves or restores
// terminal state — so when a full-screen TUI inside the session is detached or
// dies with the cursor hidden, the local terminal is left cursorless and no
// later prompt brings it back. We emit the show-cursor sequence locally once
// ssh returns, regardless of how the remote left things. Visibility only: we
// never touch cursor shape (DECSCUSR) so we don't override the user's cursor.
const LOCAL_CURSOR_RESTORE: &str = "\x1b[?25h";

fn local_cursor_restore_sequence(allocate_tty: bool, stderr_is_tty: bool) -> Option<&'static str> {
    if allocate_tty && stderr_is_tty {
        Some(LOCAL_CURSOR_RESTORE)
    } else {
        None
    }
}

fn restore_local_cursor(allocate_tty: bool) {
    if let Some(sequence) = local_cursor_restore_sequence(allocate_tty, io::stderr().is_terminal())
    {
        let mut stderr = io::stderr();
        let _ = stderr.write_all(sequence.as_bytes());
        let _ = stderr.flush();
    }
}

fn dtach_remote_command(session_name: &str, program_command: &str) -> String {
    let socket = format!("/run/concrete/sessions/{session_name}.sock");
    format!(
        "mkdir -p /run/concrete/sessions && chmod 700 /run/concrete/sessions && exec dtach -A {} -r winch {}",
        shell_quote(&socket),
        program_command,
    )
}

fn agent_program_command(program: &str, workspace: Option<&str>) -> String {
    let workspace_cd = workspace.map(workspace_cd_command);
    if program != "claude" {
        return match workspace_cd {
            Some(cd) => format!("bash -lc {}", shell_quote(&format!("{cd}\nexec {program}"))),
            None => program.to_string(),
        };
    }
    let mut script = String::from(
        r#"mkdir -p "$HOME/.claude"
if [ -e "$HOME/.claude.json" ] && [ ! -L "$HOME/.claude.json" ]; then
  if [ ! -s "$HOME/.claude.json" ]; then
    printf '{}\n' >"$HOME/.claude.json"
    chmod 600 "$HOME/.claude.json"
  fi
else
  if [ ! -s "$HOME/.claude/.claude.json" ]; then
    printf '{}\n' >"$HOME/.claude/.claude.json"
    chmod 600 "$HOME/.claude/.claude.json"
  fi
  ln -sfn "$HOME/.claude/.claude.json" "$HOME/.claude.json"
fi
"#,
    );
    if let Some(cd) = workspace_cd {
        script.push_str(&cd);
        script.push('\n');
    }
    script.push_str("exec claude");
    format!("bash -lc {}", shell_quote(&script))
}

fn workspace_cd_command(workspace: &str) -> String {
    if let Some(rest) = workspace.strip_prefix("~/") {
        format!(r#"cd "$HOME/{rest}" || {{ echo "[error] workspace not found" >&2; exit 1; }}"#)
    } else if workspace.starts_with('/') {
        format!(r#"cd "{workspace}" || {{ echo "[error] workspace not found" >&2; exit 1; }}"#)
    } else {
        format!(
            r#"cd "$HOME/{workspace}" || {{ echo "[error] workspace not found" >&2; exit 1; }}"#
        )
    }
}

fn ps_remote_command() -> String {
    "dir=/run/concrete/sessions; [ -d \"$dir\" ] || exit 0; for sock in \"$dir\"/*.sock; do [ -e \"$sock\" ] || continue; name=${sock##*/}; name=${name%.sock}; if fuser \"$sock\" >/dev/null 2>&1 || lsof \"$sock\" >/dev/null 2>&1; then attached=true; else attached=false; fi; created=$(stat -c %Y \"$sock\" 2>/dev/null || stat -f %m \"$sock\"); printf '%s\\t%s\\t%s\\n' \"$name\" \"$attached\" \"$created\"; done".to_string()
}

fn attach_remote_command(session_name: &str) -> String {
    let socket = format!("/run/concrete/sessions/{session_name}.sock");
    format!(
        "sock={}; [ -S \"$sock\" ] || {{ echo \"missing session\" >&2; exit 1; }}; {TERMINAL_CURSOR_RESTORE}exec dtach -a \"$sock\" -r winch",
        shell_quote(&socket),
    )
}

fn kill_remote_command(session_name: &str) -> String {
    let socket = format!("/run/concrete/sessions/{session_name}.sock");
    format!(
        "sock={}; [ -S \"$sock\" ] || {{ echo \"missing session\" >&2; exit 1; }}; pids=$(fuser \"$sock\" 2>/dev/null || true); if [ -z \"$pids\" ] && command -v lsof >/dev/null 2>&1; then pids=$(lsof -t \"$sock\" 2>/dev/null || true); fi; if [ -n \"$pids\" ]; then kill -TERM $pids 2>/dev/null || true; sleep 1; for pid in $pids; do kill -0 \"$pid\" 2>/dev/null && kill -KILL \"$pid\" 2>/dev/null || true; done; fi; rm -f \"$sock\"",
        shell_quote(&socket),
    )
}

fn parse_session_rows(
    output: &str,
    aliases_by_session: &BTreeMap<String, String>,
) -> Result<Vec<SessionRow>, String> {
    let mut rows = Vec::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 3 {
            return Err("[error] malformed session listing returned by Dev CVM".to_string());
        }
        let created_epoch = parts[2].parse::<i64>().map_err(|_| {
            "[error] malformed session creation time returned by Dev CVM".to_string()
        })?;
        rows.push(SessionRow {
            name: parts[0].to_string(),
            attached: parts[1] == "true",
            alias: aliases_by_session.get(parts[0]).cloned(),
            created_at: format_epoch(created_epoch),
        });
    }
    rows.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(rows)
}

fn print_session_rows(rows: &[SessionRow], json_output: bool, cvm_id: &str) {
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(rows).expect("session rows serialize")
        );
        return;
    }
    let extra = std::collections::BTreeMap::new();
    let views: Vec<style::PsSessionView<'_>> = rows
        .iter()
        .map(|row| style::PsSessionView {
            name: &row.name,
            attached: row.attached,
            alias: row.alias.as_deref(),
            created_at: &row.created_at,
            extra: &extra,
        })
        .collect();
    let filter = style::PsFilter {
        cvm: cvm_id.to_string(),
    };
    println!("{}", style::ps_cards(&views, &filter));
}

fn format_epoch(value: i64) -> String {
    chrono::DateTime::<Utc>::from_timestamp(value, 0)
        .map(|timestamp| timestamp.to_rfc3339())
        .unwrap_or_else(|| value.to_string())
}

type AliasMap = BTreeMap<String, BTreeMap<String, String>>;

fn aliases_path(config_dir: &Path) -> PathBuf {
    config_dir.join("aliases.toml")
}

fn load_alias_file(config_dir: &Path) -> Result<AliasMap, String> {
    let path = aliases_path(config_dir);
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let data = fs::read_to_string(&path)
        .map_err(|err| format!("[error] failed to read aliases file: {err}"))?;
    toml::from_str(&data).map_err(|err| format!("[error] malformed aliases file: {err}"))
}

fn aliases_for_cvm(config_dir: &Path, cvm_id: &str) -> Result<BTreeMap<String, String>, String> {
    Ok(load_alias_file(config_dir)?
        .remove(cvm_id)
        .unwrap_or_default())
}

fn aliases_by_session(config_dir: &Path, cvm_id: &str) -> Result<BTreeMap<String, String>, String> {
    let mut by_session = BTreeMap::new();
    for (alias, session_name) in aliases_for_cvm(config_dir, cvm_id)? {
        by_session.entry(session_name).or_insert(alias);
    }
    Ok(by_session)
}

fn resolve_target(config_dir: &Path, cvm_id: &str, target: &str) -> Result<String, String> {
    validate_session_name(target)?;
    let aliases = aliases_for_cvm(config_dir, cvm_id)?;
    Ok(aliases
        .get(target)
        .cloned()
        .unwrap_or_else(|| target.to_string()))
}

fn write_alias(
    config_dir: &Path,
    cvm_id: &str,
    session_name: &str,
    alias: &str,
) -> Result<(), String> {
    let mut aliases = load_alias_file(config_dir)?;
    aliases
        .entry(cvm_id.to_string())
        .or_default()
        .insert(alias.to_string(), session_name.to_string());
    fs::create_dir_all(config_dir)
        .map_err(|err| format!("[error] failed to create config directory: {err}"))?;
    #[cfg(unix)]
    {
        fs::set_permissions(config_dir, fs::Permissions::from_mode(0o700)).map_err(|err| {
            format!("[error] failed to tighten config directory permissions: {err}")
        })?;
    }
    let data = toml::to_string_pretty(&aliases)
        .map_err(|err| format!("[error] failed to serialize aliases file: {err}"))?;
    let target = aliases_path(config_dir);
    let tmp = config_dir.join(format!(".aliases.{}.tmp", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&tmp)
        .map_err(|err| format!("[error] failed to create temporary aliases file: {err}"))?;
    file.write_all(data.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|err| format!("[error] failed to write aliases file: {err}"))?;
    fs::rename(&tmp, &target)
        .map_err(|err| format!("[error] failed to install aliases file: {err}"))?;
    #[cfg(unix)]
    {
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("[error] failed to tighten aliases file permissions: {err}"))?;
    }
    Ok(())
}

pub(crate) fn validate_workspace_path(value: &str) -> Result<&str, String> {
    if value.is_empty() {
        return Err("[usage] --workspace must not be empty".to_string());
    }
    if value.len() > 512 {
        return Err("[usage] --workspace must be at most 512 bytes".to_string());
    }
    if value.contains("..") {
        return Err("[usage] --workspace must not contain '..'".to_string());
    }
    if value.starts_with('~') && !value.starts_with("~/") && value != "~" {
        return Err("[usage] --workspace must use ~/ for home-relative paths".to_string());
    }
    let path_body = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix('/'))
        .unwrap_or(value);
    if path_body.is_empty() {
        return Err("[usage] --workspace must not be empty".to_string());
    }
    if !path_body
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return Err(
            "[usage] --workspace may only contain ASCII letters, digits, '/', '.', '_', and '-'"
                .to_string(),
        );
    }
    Ok(value)
}

fn validate_session_name(value: &str) -> Result<&str, String> {
    if value.is_empty() {
        return Err("[usage] --name must not be empty".to_string());
    }
    if value.len() > 128 {
        return Err("[usage] --name must be at most 128 bytes".to_string());
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(
            "[usage] --name may only contain ASCII letters, digits, '.', '_', and '-'".to_string(),
        );
    }
    Ok(value)
}

fn default_session_name(prefix: &str) -> String {
    format!("{}-{}", prefix, Utc::now().format("%Y%m%d-%H%M%S"))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, process::Command};

    #[test]
    fn shell_quote_wraps_and_escapes_single_quotes() {
        assert_eq!(shell_quote("abc"), "'abc'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn per_cvm_policy_path_uses_config_cvms_dir() {
        assert_eq!(
            per_cvm_policy_path(Path::new("/tmp/concrete"), "cvm-1"),
            PathBuf::from("/tmp/concrete/cvms/cvm-1.atls-policy.json")
        );
    }

    #[test]
    fn explicit_identity_file_disables_agent_key_fanout() {
        let prepared = PreparedSsh {
            cvm_id: "cvm-1".to_string(),
            fqdn: "cvm.example.com".to_string(),
            proxy_command: "concrete tunnel cvm.example.com".to_string(),
            identity_file: Some(PathBuf::from("/tmp/concrete-key")),
        };
        let ssh = base_ssh_command(&prepared, false);
        let args: Vec<String> = ssh
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert!(args
            .windows(2)
            .any(|pair| pair == ["-o", "IdentitiesOnly=yes"]));
        assert!(args
            .windows(2)
            .any(|pair| pair == ["-i", "/tmp/concrete-key"]));
    }

    #[test]
    fn editor_ssh_config_omits_identity_file_by_default() {
        let prepared = PreparedSsh {
            cvm_id: "cvm-1".to_string(),
            fqdn: "cvm.example.com".to_string(),
            proxy_command: "concrete tunnel cvm.example.com".to_string(),
            identity_file: None,
        };
        let config = render_editor_ssh_config("concrete-cvm-1", &prepared).unwrap();
        assert!(config.contains("Host concrete-cvm-1"));
        assert!(config.contains("HostName cvm.example.com"));
        assert!(config.contains("BatchMode yes"));
        assert!(!config.contains("IdentityFile"));
        assert!(!config.contains("IdentitiesOnly"));
    }

    #[test]
    fn editor_ssh_config_pins_identity_file_when_supplied() {
        let prepared = PreparedSsh {
            cvm_id: "cvm-1".to_string(),
            fqdn: "cvm.example.com".to_string(),
            proxy_command: "concrete tunnel cvm.example.com".to_string(),
            identity_file: Some(PathBuf::from("/home/u/.ssh/concrete_dev_ed25519")),
        };
        let config = render_editor_ssh_config("concrete-cvm-1", &prepared).unwrap();
        assert!(config.contains("IdentityFile \"/home/u/.ssh/concrete_dev_ed25519\""));
        assert!(config.contains("IdentitiesOnly yes"));
    }

    #[test]
    fn stored_identity_resolves_by_installed_key_id() {
        let dir = std::env::temp_dir().join(format!("concrete-ssh-store-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");
        let private_key = dir.join("registered_ed25519");
        let public_key = dir.join("registered_ed25519.pub");
        Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&private_key)
            .output()
            .expect("ssh-keygen succeeds");
        let fingerprint =
            ssh_identity::public_key_fingerprint(&public_key).expect("fingerprint parsed");
        ssh_identity_store::write_identity(&dir, "key-1", &private_key)
            .expect("identity path stored");
        let config = ResolvedConfig::resolve(crate::config::ConfigOverrides {
            config_dir: Some(dir.clone()),
            ..Default::default()
        });

        let resolved = resolve_stored_identity(
            &config,
            &[InstalledSshKey {
                id: "key-1".to_string(),
                fingerprint,
            }],
        )
        .expect("stored identity resolved");

        assert_eq!(resolved, private_key);
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    #[test]
    fn validate_session_name_rejects_shell_metacharacters() {
        assert_eq!(
            validate_session_name("ssh-20260516-120000"),
            Ok("ssh-20260516-120000")
        );
        assert!(validate_session_name("").is_err());
        assert!(validate_session_name("bad/name").is_err());
        assert!(validate_session_name("bad name").is_err());
        assert!(validate_session_name("bad;name").is_err());
    }

    #[test]
    fn claude_agent_command_repairs_empty_config() {
        let command = agent_program_command("claude", None);
        assert!(command.starts_with("bash -lc "));
        assert!(command.contains(".claude/.claude.json"));
        assert!(command.contains("printf"));
        assert!(command.contains("exec claude"));
        assert_eq!(agent_program_command("codex", None), "codex");
    }

    #[test]
    fn agent_command_changes_to_workspace_before_launch() {
        let claude = agent_program_command("claude", Some("~/workspaces/myrepo"));
        assert!(claude.contains(r#"cd "$HOME/workspaces/myrepo""#));
        assert!(claude.contains("exec claude"));

        let codex = agent_program_command("codex", Some("/home/dev/workspaces/myrepo"));
        assert!(codex.starts_with("bash -lc "));
        assert!(codex.contains(r#"cd "/home/dev/workspaces/myrepo""#));
        assert!(codex.contains("exec codex"));
    }

    #[test]
    fn validate_workspace_path_rejects_unsafe_values() {
        assert_eq!(
            validate_workspace_path("~/workspaces/myrepo"),
            Ok("~/workspaces/myrepo")
        );
        assert_eq!(
            validate_workspace_path("/home/dev/workspaces/myrepo"),
            Ok("/home/dev/workspaces/myrepo")
        );
        assert_eq!(
            validate_workspace_path("workspaces/myrepo"),
            Ok("workspaces/myrepo")
        );
        assert!(validate_workspace_path("").is_err());
        assert!(validate_workspace_path("~/workspaces/../etc").is_err());
        assert!(validate_workspace_path("~/workspaces/my repo").is_err());
        assert!(validate_workspace_path("~other/workspaces/myrepo").is_err());
        assert!(validate_workspace_path("~/workspaces/myrepo;rm").is_err());
    }

    #[test]
    fn attach_remote_command_restores_terminal_cursor() {
        let command = attach_remote_command("ssh-20260526-120000");
        assert!(command.contains("printf '\\033[?25h\\033[1 q'; "));
        assert!(command.contains("dtach -a \"$sock\" -r winch"));
    }

    #[test]
    fn local_cursor_restore_only_fires_for_interactive_ttys() {
        // Interactive session on a real terminal: emit show-cursor.
        assert_eq!(local_cursor_restore_sequence(true, true), Some("\x1b[?25h"));
        // Non-interactive (ps/kill/alias) or redirected stderr: stay silent so
        // we never write escape bytes into a pipe, file, or log.
        assert_eq!(local_cursor_restore_sequence(true, false), None);
        assert_eq!(local_cursor_restore_sequence(false, true), None);
        assert_eq!(local_cursor_restore_sequence(false, false), None);
    }

    #[test]
    fn local_cursor_restore_is_visibility_only() {
        // Show-cursor (DECTCEM) only — never DECSCUSR cursor shape — so we do
        // not override the user's configured cursor style.
        let sequence = local_cursor_restore_sequence(true, true).unwrap();
        assert_eq!(sequence, "\x1b[?25h");
        assert!(!sequence.contains(" q"));
    }

    #[test]
    fn editor_host_alias_sanitizes_cvm_ids() {
        assert_eq!(
            editor_host_alias("9a7f6b4a-1111-2222-3333-444444444444"),
            "concrete-9a7f6b4a-1111-2222-3333-444444444444"
        );
        assert_eq!(editor_host_alias("../bad id"), "concrete-bad-id");
        assert_eq!(editor_host_alias("///"), "concrete-cvm");
    }

    #[test]
    fn editor_remote_uri_targets_dev_home_without_workspace() {
        assert_eq!(
            editor_remote_uri("concrete-cvm-1", None),
            "vscode-remote://ssh-remote+concrete-cvm-1/home/dev"
        );
    }

    #[test]
    fn editor_remote_uri_appends_workspace_path() {
        assert_eq!(
            editor_remote_uri("concrete-cvm-1", Some("~/workspaces/myrepo")),
            "vscode-remote://ssh-remote+concrete-cvm-1/home/dev/workspaces/myrepo"
        );
    }

    #[test]
    fn editor_remote_path_resolves_workspace_variants() {
        assert_eq!(editor_remote_path(None), "/home/dev");
        assert_eq!(
            editor_remote_path(Some("~/repos/foo")),
            "/home/dev/repos/foo"
        );
        assert_eq!(editor_remote_path(Some("/srv/x")), "/srv/x");
        assert_eq!(editor_remote_path(Some("repos/foo")), "/home/dev/repos/foo");
    }
}
