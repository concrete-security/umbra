use std::{
    collections::BTreeMap,
    env,
    ffi::OsString,
    fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use crate::{
    cli::{AgentSessionArgs, CodeArgs, CursorArgs, SessionListArgs, SessionTargetArgs, SshArgs},
    commands::{alias, legacy_cvm_replacement_error, select_cvm},
    config::ResolvedConfig,
    console::{console_session, fetch_json, ListPage},
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
    cvm_id: &'a str,
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
    if args.alias.is_some() && args.command.is_some() {
        crate::style::eprintln_error(
            "[usage] --alias cannot be combined with --command (no session is created)",
        );
        return ExitStatus::Usage;
    }
    let cvm_id = match select_cvm(
        args.target.cvm_id.as_deref(),
        args.target.cvm.as_deref(),
        &[config.default_cvm.as_deref()],
        config,
    ) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    // A one-off `--command` has no dtach session; otherwise the session name is
    // computed once here so it matches what we alias and what dtach opens.
    let (remote_command, session_name) = match args.command.clone() {
        Some(command) => (command, None),
        None => match session_name(args.name.as_deref(), "ssh") {
            Ok(name) => (dtach_remote_command(&name, "bash -l"), Some(name)),
            Err(message) => {
                crate::style::eprintln_error(&message);
                return ExitStatus::Usage;
            }
        },
    };
    if let Some(name) = &session_name {
        if let Some(status) = record_launch_alias(
            config,
            args.alias.as_deref(),
            name,
            &cvm_id,
            args.identity_file.as_deref(),
        ) {
            return status;
        }
    }
    let status = run_ssh(
        SshInvocation {
            cvm_id: &cvm_id,
            identity_file: args.identity_file.as_deref(),
            remote_command,
            allocate_tty: args.command.is_none(),
        },
        config,
    );
    if !matches!(status, ExitStatus::Ok) {
        if let Some(name) = &session_name {
            drop_launch_alias(config, args.alias.as_deref(), name, &cvm_id);
        }
    }
    status
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
    let cvm_id = match select_cvm(
        args.target.cvm_id.as_deref(),
        args.target.cvm.as_deref(),
        &[config.default_cvm.as_deref()],
        config,
    ) {
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
    if let Some(status) = record_launch_alias(
        config,
        args.alias.as_deref(),
        &session_name,
        &cvm_id,
        args.identity_file.as_deref(),
    ) {
        return status;
    }
    let status = run_ssh(
        SshInvocation {
            cvm_id: &cvm_id,
            identity_file: args.identity_file.as_deref(),
            remote_command: dtach_remote_command(&session_name, &program_command),
            allocate_tty: true,
        },
        config,
    );
    if !matches!(status, ExitStatus::Ok) {
        drop_launch_alias(config, args.alias.as_deref(), &session_name, &cvm_id);
    }
    status
}

/// Record a `--alias` for a session about to be started (name + CVM are already
/// resolved). Returns `Some(status)` to abort the launch on a bad/taken alias,
/// or `None` to proceed. A no-alias invocation is a no-op. The alias is written
/// up front so it can be attached from another terminal while the session runs;
/// [`drop_launch_alias`] undoes it if the launch never establishes.
fn record_launch_alias(
    config: &ResolvedConfig,
    nickname: Option<&str>,
    session_name: &str,
    cvm_id: &str,
    identity_file: Option<&Path>,
) -> Option<ExitStatus> {
    let nickname = nickname?;
    // The target is known here — `dtach -A` re-attaches, so `--name` may well point at
    // a session that already has an alias — so check it BEFORE the SSH probe rather
    // than leaving it to the write, which would pay for the probe first.
    let target = alias::AliasTarget::Session(alias::SessionAlias {
        session: session_name.to_string(),
        cvm: cvm_id.to_string(),
    });
    if let Err((status, message)) = alias::validate_alias(config, nickname, Some(&target)) {
        crate::style::eprintln_error(&message);
        return Some(status);
    }
    // Resolution consults aliases first, so an alias that matches a live dtach
    // session name would shadow that session (unreachable by name). Probe the
    // CVM and reject the collision, as the direct `alias session` path does.
    match list_session_names(cvm_id, identity_file, config) {
        Ok(live) => {
            if let Some(message) = session_shadow_error(&live, nickname, cvm_id) {
                crate::style::eprintln_error(&message);
                return Some(ExitStatus::Error);
            }
        }
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return Some(status);
        }
    }
    if let Err(message) = alias::record_session_alias(config, session_name, cvm_id, nickname) {
        crate::style::eprintln_error(&message);
        return Some(ExitStatus::Error);
    }
    None
}

/// Undo the optimistic launch alias when the session never established (ssh
/// failed): a failed launch must not leave a dangling alias that then blocks
/// retrying the same name. A clean detach exits `Ok` and keeps the alias.
fn drop_launch_alias(config: &ResolvedConfig, nickname: Option<&str>, session: &str, cvm: &str) {
    let Some(nickname) = nickname else {
        return;
    };
    // Match the mapping this launch wrote: if another process rm'd and recreated
    // the same name to a different target between launch and this rollback, leave
    // that fresh mapping alone.
    let observed = alias::AliasTarget::Session(alias::SessionAlias {
        session: session.to_string(),
        cvm: cvm.to_string(),
    });
    alias::prune_and_save(config, |aliases| {
        aliases.remove_if_matches(nickname, &observed)
    });
}

pub fn run_code(args: CodeArgs, config: &ResolvedConfig) -> ExitStatus {
    let cvm_id = match select_cvm(
        args.target.cvm_id.as_deref(),
        args.target.cvm.as_deref(),
        &[config.default_cvm.as_deref()],
        config,
    ) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let bin = args.code_bin.unwrap_or_else(|| PathBuf::from("code"));
    run_editor(
        &bin,
        &cvm_id,
        args.workspace.as_deref(),
        args.identity_file.as_deref(),
        config,
    )
}

pub fn run_cursor(args: CursorArgs, config: &ResolvedConfig) -> ExitStatus {
    let cvm_id = match select_cvm(
        args.target.cvm_id.as_deref(),
        args.target.cvm.as_deref(),
        &[config.default_cvm.as_deref()],
        config,
    ) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    let bin = args.cursor_bin.unwrap_or_else(|| PathBuf::from("cursor"));
    run_editor(
        &bin,
        &cvm_id,
        args.workspace.as_deref(),
        args.identity_file.as_deref(),
        config,
    )
}

/// One CVM's `ps` outcome: its sessions, or the exit status + message of the
/// probe failure that stopped us reading them.
type PsGroup = (String, Result<Vec<SessionRow>, (ExitStatus, String)>);

/// The probe failure that aborts a `ps` run: only an explicit single target's
/// failure propagates; fleet mode (or a healthy target) yields `None`.
fn ps_failure_to_propagate(explicit: bool, groups: &[PsGroup]) -> Option<&(ExitStatus, String)> {
    match groups {
        [(_, Err(failure))] if explicit => Some(failure),
        _ => None,
    }
}

pub fn run_ps(args: SessionListArgs, config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, session) = try_or_eprintln!(console_session(config));
    // No explicit target -> every RUNNING Dev CVM of the caller (owner-scoped by
    // the Console); `ps` deliberately does not fall back to `default_cvm`. An
    // explicit positional/`--cvm` scopes to that one CVM. Either way we keep the
    // full `Cvm` records so the probe reuses them via `build_ssh` (no re-fetch).
    let cvms: Vec<Cvm> = match (args.target.cvm_id.as_deref(), args.target.cvm.as_deref()) {
        (None, None) => {
            try_or_eprintln!(fetch_json::<ListPage<Cvm>>(
                console_url,
                &session,
                "/api/v1/cvms",
                &[("state", "running".to_string())],
                "list CVMs",
            ))
            .items
        }
        (positional, flag) => {
            let cvm_id = match select_cvm(positional, flag, &[], config) {
                Ok(id) => id,
                Err(message) => {
                    crate::style::eprintln_error(&message);
                    return ExitStatus::Usage;
                }
            };
            vec![try_or_eprintln!(fetch_cvm(console_url, &session, &cvm_id))]
        }
    };

    // Alias config is a single local file shared by all CVMs: read it ONCE here,
    // not once per CVM. An unreadable store is reported once on stderr and marked
    // in each session's `alias` cell (`load_for_display`), never turned into a
    // failed listing: the sessions come from the Dev CVMs, not from this file — the
    // same policy the resource views apply (docs/specs/cli-style.md §7.9).
    let alias_store = alias::load_for_display(config);

    // `--identity-file` is a local, CVM-independent argument: a bad path fails
    // identically for every CVM, so validate it once here (fail fast) instead
    // of surfacing an identical probe error on each CVM while exiting 0.
    if let Some(path) = args.identity_file.as_deref() {
        if let Err((status, message)) = ssh_identity::resolve_explicit_identity(path) {
            crate::style::eprintln_error(&message);
            return status;
        }
    }

    // Probe each CVM independently: its sessions, or the error that stopped us
    // reading them. A probe failure is captured per CVM (with its exit status)
    // and never aborts the whole listing (`Result` is the sum type; no bespoke
    // struct needed). The `Cvm` records from the listing are reused via
    // `build_ssh`, so a fleet `ps` fetches once, not 1 + N times.
    let groups: Vec<PsGroup> = cvms
        .into_iter()
        .map(|cvm| {
            let cvm_id = cvm.id.clone();
            let aliases = alias_store
                .as_ref()
                .map(|aliases| aliases.session_names_on(&cvm_id))
                .unwrap_or_default();
            let sessions = build_ssh(
                console_url,
                &session,
                cvm,
                args.identity_file.as_deref(),
                config,
            )
            .and_then(|prepared| capture_prepared(&prepared, ps_remote_command()))
            .and_then(|output| {
                parse_session_rows(&output, &aliases)
                    .map_err(|message| (ExitStatus::Error, message))
            });
            (cvm_id, sessions)
        })
        .collect();

    // Explicit single target: propagate its probe failure (non-zero exit, no
    // stdout). In fleet mode a per-CVM failure stays in the payload and exit
    // stays 0.
    let explicit = args.target.cvm_id.is_some() || args.target.cvm.is_some();
    if let Some((status, message)) = ps_failure_to_propagate(explicit, &groups) {
        crate::style::eprintln_error(message);
        return *status;
    }

    print_ps(
        &groups,
        alias_store.as_ref().err().map(String::as_str),
        json_output,
    );
    ExitStatus::Ok
}

/// Resolve a session target — an alias or a raw session name — into the
/// umbra `(session_name, cvm_id)` to act on. A session alias carries its own
/// CVM, so it works without `--cvm`; an explicit `--cvm` overrides it (with a
/// warning), and a raw name resolves the CVM the usual way (`--cvm`/default,
/// alias-aware via [`select_cvm`]).
fn resolve_session_target(
    target: &str,
    cvm_flag: Option<&str>,
    config: &ResolvedConfig,
) -> Result<(String, String), (ExitStatus, String)> {
    let aliases =
        alias::load(&config.config_dir).map_err(|message| (ExitStatus::Error, message))?;
    if let Some(entry) = aliases.resolve_session(target) {
        let cvm_id = match cvm_flag {
            Some(flag) => {
                // Canonical: `select_cvm` hands a raw UUID straight through while the
                // store holds one canonical form, so comparing as typed would warn
                // about an "override" that names the very same CVM.
                let overridden = alias::canonical_id(
                    &select_cvm(None, Some(flag), &[config.default_cvm.as_deref()], config)
                        .map_err(|m| (ExitStatus::Usage, m))?,
                );
                if overridden != entry.cvm {
                    // Show the stored CVM by its alias when it has one (readable).
                    let stored = aliases.cvm_display(&entry.cvm);
                    crate::style::eprintln_warn(&format!(
                        "[warn] alias {target} targets CVM {stored}; --cvm forces {overridden}. See `umbra alias list`."
                    ));
                }
                overridden
            }
            None => entry.cvm.clone(),
        };
        Ok((entry.session.clone(), cvm_id))
    } else {
        validate_session_name(target).map_err(|m| (ExitStatus::Usage, m))?;
        let cvm_id = select_cvm(None, cvm_flag, &[config.default_cvm.as_deref()], config)
            .map_err(|m| (ExitStatus::Usage, m))?;
        Ok((target.to_string(), cvm_id))
    }
}

pub fn run_attach(args: SessionTargetArgs, config: &ResolvedConfig) -> ExitStatus {
    let (session_name, cvm_id) = try_or_eprintln!(resolve_session_target(
        &args.target,
        args.cvm.as_deref(),
        config
    ));
    run_ssh(
        SshInvocation {
            cvm_id: &cvm_id,
            identity_file: args.identity_file.as_deref(),
            remote_command: attach_remote_command(&session_name),
            allocate_tty: true,
        },
        config,
    )
}

pub fn run_kill(args: SessionTargetArgs, config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (session_name, cvm_id) = try_or_eprintln!(resolve_session_target(
        &args.target,
        args.cvm.as_deref(),
        config
    ));
    match run_ssh_capture(
        SshInvocation {
            cvm_id: &cvm_id,
            identity_file: args.identity_file.as_deref(),
            remote_command: kill_remote_command(&session_name),
            allocate_tty: false,
        },
        config,
    ) {
        Ok(_) => finish_kill(config, &session_name, &cvm_id, json_output),
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            status
        }
    }
}

/// Record a successful `kill` of `session_name` on `cvm_id`: drop any alias
/// bound to that session and print the confirmation. Split from [`run_kill`] so
/// the store-side auto-purge is testable without a live SSH session (the SSH
/// capture itself needs a real CVM).
fn finish_kill(
    config: &ResolvedConfig,
    session_name: &str,
    cvm_id: &str,
    json_output: bool,
) -> ExitStatus {
    // The session is gone; drop any alias that pointed at it.
    alias::prune_and_save(config, |a| {
        a.prune(alias::Prune::Session {
            session: session_name,
            cvm: cvm_id,
        })
    });
    if json_output {
        style::emit_json(&json!({
            "cvm_id": cvm_id,
            "session_name": session_name,
        }));
    } else {
        // Section 7.30: identifier is the session name (the entity being
        // killed); detail row records the CVM the session was running on.
        let confirm =
            crate::style::ConfirmBlock::new("killed", "session", session_name.to_string())
                .field("cvm", cvm_id.to_string());
        println!("{}", crate::style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

/// The live dtach session names on `cvm_id`. Used by `umbra alias session`
/// to fail-fast before recording an alias — both to confirm the target session
/// exists and to reject an alias that would shadow a real session name. Reuses
/// the same SSH `ps` probe as [`run_ps`].
pub(crate) fn list_session_names(
    cvm_id: &str,
    identity_file: Option<&Path>,
    config: &ResolvedConfig,
) -> Result<Vec<String>, (ExitStatus, String)> {
    let output = run_ssh_capture(
        SshInvocation {
            cvm_id,
            identity_file,
            remote_command: ps_remote_command(),
            allocate_tty: false,
        },
        config,
    )?;
    let rows = parse_session_rows(&output, &BTreeMap::new())
        .map_err(|message| (ExitStatus::Error, message))?;
    Ok(rows.into_iter().map(|row| row.name).collect())
}

/// The shadowing error if `name` matches a live dtach session in `live` on
/// `cvm_id`, else `None`. Resolution consults aliases first, so an alias named
/// like a real session would make that session unreachable by name. Shared by the
/// three sites that must reject the collision identically — `alias session`,
/// `ssh/claude/codex --alias`, and `alias rename` — so their check never drifts.
pub(crate) fn session_shadow_error(live: &[String], name: &str, cvm_id: &str) -> Option<String> {
    live.iter().any(|session| session == name).then(|| {
        format!("[error] alias {name} collides with an existing dtach session name on {cvm_id}")
    })
}

fn run_ssh(invocation: SshInvocation<'_>, config: &ResolvedConfig) -> ExitStatus {
    let prepared = try_or_eprintln!(prepare_ssh(
        invocation.cvm_id,
        invocation.identity_file,
        config
    ));
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
    cvm_id: &str,
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
    let prepared = try_or_eprintln!(prepare_ssh(cvm_id, identity_file, config));
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
    capture_prepared(&prepared, invocation.remote_command)
}

/// Run a remote command over an already-prepared SSH connection and capture its
/// stdout. Split from [`run_ssh_capture`] so `ps` can reuse a [`PreparedSsh`]
/// built from a pre-fetched CVM ([`build_ssh`]) without re-preparing.
fn capture_prepared(
    prepared: &PreparedSsh,
    remote_command: String,
) -> Result<String, (ExitStatus, String)> {
    // Capturing stdout never needs a TTY (the interactive path is `run_ssh`).
    let mut ssh = base_ssh_command(prepared, false);
    ssh.arg(remote_command);
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

/// Fetch the Dev CVM, then build its SSH connection ([`build_ssh`]).
/// Used by every SSH command that starts from just an id: `ssh`, `code`,
/// `cursor`, agent sessions. (`ps` already holds the CVM from its fleet listing
/// and calls [`build_ssh`] directly, avoiding a redundant fetch.)
fn prepare_ssh(
    cvm_id: &str,
    explicit_identity: Option<&Path>,
    config: &ResolvedConfig,
) -> Result<PreparedSsh, (ExitStatus, String)> {
    let (console_url, session) = console_session(config)?;
    let cvm = fetch_cvm(console_url, &session, cvm_id)?;
    build_ssh(console_url, &session, cvm, explicit_identity, config)
}

/// Build the SSH connection from an ALREADY-fetched Dev CVM: check the lifecycle
/// state/legacy replacement marker/FQDN, build the aTLS tunnel ProxyCommand, and
/// resolve the SSH key.
/// Does no Console fetch of the CVM, so a caller holding it (e.g. `ps` enumerating
/// the fleet) skips a redundant `GET /cvms/{id}`.
fn build_ssh(
    console_url: &str,
    session: &Session,
    cvm: Cvm,
    explicit_identity: Option<&Path>,
    config: &ResolvedConfig,
) -> Result<PreparedSsh, (ExitStatus, String)> {
    if cvm.state != "RUNNING" {
        return Err((
            ExitStatus::Error,
            format!(
                "[error] Dev CVM {} is in state {}, expected RUNNING",
                cvm.id, cvm.state
            ),
        ));
    }
    if let Some(message) = legacy_cvm_replacement_error(&cvm.id, cvm.error_reason.as_deref()) {
        return Err((ExitStatus::Error, message));
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
    let policy_path = resolve_policy_path(config, console_url, session, &cvm.id)?;
    let proxy_command = proxy_command(config, &policy_path, &fqdn)
        .map_err(|message| (ExitStatus::Error, message))?;
    let identity_file = if let Some(path) = explicit_identity {
        Some(ssh_identity::resolve_explicit_identity(path)?)
    } else {
        let installed_keys = installed_keys(console_url, session, &cvm)?;
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

fn fetch_cvm(
    console_url: &str,
    session: &Session,
    cvm_id: &str,
) -> Result<Cvm, (ExitStatus, String)> {
    fetch_json(
        console_url,
        session,
        &format!("/api/v1/cvms/{cvm_id}"),
        &[],
        "fetch Dev CVM",
    )
}

fn installed_keys(
    console_url: &str,
    session: &Session,
    cvm: &Cvm,
) -> Result<Vec<InstalledSshKey>, (ExitStatus, String)> {
    if cvm.ssh_keys.is_empty() {
        return Ok(Vec::new());
    }
    let page: ListPage<MeSshKey> = fetch_json(
        console_url,
        session,
        "/api/v1/me/keys",
        &[],
        "list SSH keys",
    )?;
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
    fetch_json(
        console_url,
        session,
        &format!("/api/v1/cvms/{cvm_id}/policy-bundle"),
        &[],
        "fetch Dev CVM policy bundle",
    )
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
    crate::fsutil::write_atomic_file(&config_path, ssh_config.as_bytes(), 0o600)
        .map_err(|err| format!("[error] failed to write editor SSH config: {err}"))?;

    let ssh_bin = find_ssh_binary()
        .ok_or_else(|| "[error] failed to find ssh on PATH for editor launch".to_string())?;
    let wrapper_path = wrapper_dir.join("ssh");
    let wrapper = format!(
        "#!/bin/sh\nexec {} -F {} \"$@\"\n",
        shell_quote(&ssh_bin.display().to_string()),
        shell_quote(&config_path.display().to_string()),
    );
    crate::fsutil::write_atomic_file(&wrapper_path, wrapper.as_bytes(), 0o700)
        .map_err(|err| format!("[error] failed to write editor SSH wrapper: {err}"))?;

    Ok(EditorLaunch {
        host_alias,
        wrapper_dir,
    })
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
        "umbra-cvm".to_string()
    } else {
        format!("umbra-{suffix}")
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

fn session_name(value: Option<&str>, prefix: &str) -> Result<String, String> {
    match value {
        Some(value) => Ok(validate_session_name(value)?.to_string()),
        None => Ok(default_session_name(prefix)),
    }
}

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
    let socket = format!("/run/umbra/sessions/{session_name}.sock");
    format!(
        "mkdir -p /run/umbra/sessions && chmod 700 /run/umbra/sessions && exec dtach -A {} -r winch {}",
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
    "dir=/run/umbra/sessions; [ -d \"$dir\" ] || exit 0; for sock in \"$dir\"/*.sock; do [ -e \"$sock\" ] || continue; name=${sock##*/}; name=${name%.sock}; if fuser \"$sock\" >/dev/null 2>&1 || lsof \"$sock\" >/dev/null 2>&1; then attached=true; else attached=false; fi; created=$(stat -c %Y \"$sock\" 2>/dev/null || stat -f %m \"$sock\"); printf '%s\\t%s\\t%s\\n' \"$name\" \"$attached\" \"$created\"; done".to_string()
}

fn attach_remote_command(session_name: &str) -> String {
    let socket = format!("/run/umbra/sessions/{session_name}.sock");
    format!(
        "sock={}; [ -S \"$sock\" ] || {{ echo \"missing session\" >&2; exit 1; }}; exec dtach -a \"$sock\" -r winch",
        shell_quote(&socket),
    )
}

fn kill_remote_command(session_name: &str) -> String {
    let socket = format!("/run/umbra/sessions/{session_name}.sock");
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

fn print_ps(groups: &[PsGroup], alias_store_error: Option<&str>, json_output: bool) {
    if json_output {
        // Per-CVM objects so a failed/empty CVM still appears; each row already
        // carries no CVM id, so the group provides it for unambiguous re-attach.
        let payload: Vec<Value> = groups
            .iter()
            .map(|(cvm_id, result)| match result {
                Ok(sessions) => {
                    json!({ "cvm_id": cvm_id, "error": Value::Null, "sessions": sessions })
                }
                Err((_, message)) => json!({ "cvm_id": cvm_id, "error": message, "sessions": [] }),
            })
            .collect();
        style::emit_json(&payload);
        return;
    }
    let extra = std::collections::BTreeMap::new();
    let view_groups: Vec<style::PsCvmGroup<'_>> = groups
        .iter()
        .map(|(cvm_id, result)| style::PsCvmGroup {
            cvm_id,
            error: result.as_ref().err().map(|(_, message)| message.as_str()),
            sessions: match result {
                Ok(rows) => rows
                    .iter()
                    .map(|row| style::PsSessionView {
                        name: &row.name,
                        attached: row.attached,
                        // The store error wins over the (then always empty) alias
                        // map, so the cell marks the fault instead of claiming the
                        // session has no alias.
                        alias: match alias_store_error {
                            Some(message) => Err(message),
                            None => Ok(row.alias.as_deref()),
                        },
                        created_at: &row.created_at,
                        extra: &extra,
                    })
                    .collect(),
                Err(_) => Vec::new(),
            },
        })
        .collect();
    println!("{}", style::ps_cards(&view_groups));
}

fn format_epoch(value: i64) -> String {
    chrono::DateTime::<Utc>::from_timestamp(value, 0)
        .map(|timestamp| timestamp.to_rfc3339())
        .unwrap_or_else(|| value.to_string())
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

pub(crate) fn validate_session_name(value: &str) -> Result<&str, String> {
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
    use crate::test_support::{authenticated_config, MockConsole};
    use rstest::rstest;
    use std::{fs, process::Command};

    #[test]
    fn shell_quote_wraps_and_escapes_single_quotes() {
        assert_eq!(shell_quote("abc"), "'abc'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    /// The shared anti-shadow guard used by `alias session`, `--alias`, and
    /// `alias rename`: a name that matches a live dtach session yields the collision
    /// error (naming the session and CVM); a name absent from the live set yields
    /// `None` so the alias is allowed.
    #[rstest]
    #[case::collides("agent-1", true)]
    #[case::free("agent-2", false)]
    fn test_session_shadow_error(#[case] name: &str, #[case] shadows: bool) {
        let live = vec!["agent-1".to_string(), "worker".to_string()];
        let result = session_shadow_error(&live, name, "cvm-x");
        assert_eq!(result.is_some(), shadows, "name={name}");
        if let Some(message) = result {
            assert!(message.contains("collides"), "message: {message}");
            assert!(
                message.contains(name) && message.contains("cvm-x"),
                "message: {message}"
            );
        }
    }

    #[test]
    fn per_cvm_policy_path_uses_config_cvms_dir() {
        assert_eq!(
            per_cvm_policy_path(Path::new("/tmp/umbra"), "cvm-1"),
            PathBuf::from("/tmp/umbra/cvms/cvm-1.atls-policy.json")
        );
    }

    #[test]
    fn explicit_identity_file_disables_agent_key_fanout() {
        let prepared = PreparedSsh {
            cvm_id: "cvm-1".to_string(),
            fqdn: "cvm.example.com".to_string(),
            proxy_command: "umbra tunnel cvm.example.com".to_string(),
            identity_file: Some(PathBuf::from("/tmp/umbra-key")),
        };
        let ssh = base_ssh_command(&prepared, false);
        let args: Vec<String> = ssh
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert!(args
            .windows(2)
            .any(|pair| pair == ["-o", "IdentitiesOnly=yes"]));
        assert!(args.windows(2).any(|pair| pair == ["-i", "/tmp/umbra-key"]));
    }

    #[test]
    fn editor_ssh_config_omits_identity_file_by_default() {
        let prepared = PreparedSsh {
            cvm_id: "cvm-1".to_string(),
            fqdn: "cvm.example.com".to_string(),
            proxy_command: "umbra tunnel cvm.example.com".to_string(),
            identity_file: None,
        };
        let config = render_editor_ssh_config("umbra-cvm-1", &prepared).unwrap();
        assert!(config.contains("Host umbra-cvm-1"));
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
            proxy_command: "umbra tunnel cvm.example.com".to_string(),
            identity_file: Some(PathBuf::from("/home/u/.ssh/umbra_dev_ed25519")),
        };
        let config = render_editor_ssh_config("umbra-cvm-1", &prepared).unwrap();
        assert!(config.contains("IdentityFile \"/home/u/.ssh/umbra_dev_ed25519\""));
        assert!(config.contains("IdentitiesOnly yes"));
    }

    #[test]
    fn stored_identity_resolves_by_installed_key_id() {
        let dir = std::env::temp_dir().join(format!("umbra-ssh-store-{}", uuid::Uuid::new_v4()));
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
    fn resolve_explicit_identity_missing_failure() {
        // `ps --identity-file <path>` validates the key up front, so a missing
        // path is a usage error rather than a per-CVM probe error that exits 0.
        let (status, message) =
            ssh_identity::resolve_explicit_identity(Path::new("/nonexistent/umbra-key"))
                .expect_err("missing identity file is rejected");
        assert!(matches!(status, ExitStatus::Usage));
        assert!(message.contains("identity file"));
    }

    #[test]
    fn test_umbra_ps_explicit_unreachable_failure() {
        // An explicit single target whose probe failed propagates that probe's
        // exit status (caller then prints the error and skips the listing).
        let groups: Vec<PsGroup> = vec![(
            "cvm-a".to_string(),
            Err((ExitStatus::Error, "aTLS handshake failed".to_string())),
        )];
        let (status, message) =
            ps_failure_to_propagate(true, &groups).expect("explicit failure propagates");
        assert!(matches!(status, ExitStatus::Error));
        assert_eq!(message, "aTLS handshake failed");
    }

    #[rstest]
    // Fleet mode: a per-CVM probe failure stays in the payload, nothing aborts.
    #[case::fleet_partial(false, vec![("cvm-a".into(), Ok(vec![])), ("cvm-b".into(), Err((ExitStatus::Error, "aTLS handshake failed".into())))])]
    // Fleet mode with a single failed CVM still exits 0 (failure is the payload).
    #[case::fleet_single_fail(false, vec![("cvm-a".into(), Err((ExitStatus::Error, "aTLS handshake failed".into())))])]
    // Explicit target that succeeded: nothing to propagate.
    #[case::explicit_ok(true, vec![("cvm-a".into(), Ok(vec![]))])]
    fn test_umbra_ps_no_propagation_success(#[case] explicit: bool, #[case] groups: Vec<PsGroup>) {
        // These are the cases where `ps` prints the listing and exits 0.
        assert!(ps_failure_to_propagate(explicit, &groups).is_none());
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
    fn attach_remote_command_is_plain_dtach_attach() {
        // Cursor restoration is handled locally by the CLI after ssh returns,
        // not injected into the remote attach command.
        let command = attach_remote_command("ssh-20260526-120000");
        assert!(!command.contains("printf"));
        assert!(!command.contains("?25h"));
        assert!(command.contains("exec dtach -a \"$sock\" -r winch"));
        assert!(command.contains("/run/umbra/sessions/ssh-20260526-120000.sock"));
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
            "umbra-9a7f6b4a-1111-2222-3333-444444444444"
        );
        assert_eq!(editor_host_alias("../bad id"), "umbra-bad-id");
        assert_eq!(editor_host_alias("///"), "umbra-cvm");
    }

    #[test]
    fn editor_remote_uri_targets_dev_home_without_workspace() {
        assert_eq!(
            editor_remote_uri("umbra-cvm-1", None),
            "vscode-remote://ssh-remote+umbra-cvm-1/home/dev"
        );
    }

    #[test]
    fn editor_remote_uri_appends_workspace_path() {
        assert_eq!(
            editor_remote_uri("umbra-cvm-1", Some("~/workspaces/myrepo")),
            "vscode-remote://ssh-remote+umbra-cvm-1/home/dev/workspaces/myrepo"
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

    /// A successful `kill` drops the alias bound to the killed session (matching
    /// on the dtach session name, not the alias name) and leaves the CVM's other
    /// session — the `Prune::Session` auto-purge wiring. Driven through
    /// `finish_kill`, the post-SSH half of `run_kill`; the SSH capture itself
    /// needs a live CVM and is out of unit scope.
    #[test]
    fn test_kill_prune_success() {
        const CVM_ID: &str = "9a7f6b4a-1111-2222-3333-444444444444";
        let dir = std::env::temp_dir().join(format!("umbra-kill-test-{}", uuid::Uuid::new_v4()));
        let config = ResolvedConfig::resolve(crate::config::ConfigOverrides {
            config_dir: Some(dir),
            ..Default::default()
        });
        let mut store = alias::Aliases::default();
        for (nick, session) in [("killed-one", "agent-1"), ("kept-one", "agent-2")] {
            store.session.insert(
                nick.into(),
                alias::SessionAlias {
                    session: session.into(),
                    cvm: CVM_ID.into(),
                },
            );
        }
        alias::save(&config.config_dir, &store).expect("seed store");

        let status = finish_kill(&config, "agent-1", CVM_ID, false);
        assert!(matches!(status, ExitStatus::Ok));

        let reloaded = alias::load(&config.config_dir).unwrap();
        assert!(
            reloaded.resolve_session("killed-one").is_none(),
            "the killed session's alias must be pruned"
        );
        assert!(
            reloaded.resolve_session("kept-one").is_some(),
            "the CVM's other session must survive"
        );
    }

    /// An explicit `--cvm` that names the alias's OWN CVM in another spelling is not an
    /// override: the resolved id is canonicalized before it is compared with the stored
    /// one, so the session resolves to that same CVM (and no `[warn] --cvm forces …` is
    /// emitted). Without it every non-canonical `--cvm` warns about forcing the CVM it
    /// already points at.
    #[test]
    fn test_resolve_session_target_non_canonical_success() {
        const CVM_ID: &str = "9a7f6b4a-1111-2222-3333-444444444444";
        let dir = std::env::temp_dir().join(format!("umbra-target-{}", uuid::Uuid::new_v4()));
        let config = ResolvedConfig::resolve(crate::config::ConfigOverrides {
            config_dir: Some(dir),
            ..Default::default()
        });
        let mut store = alias::Aliases::default();
        store.insert_session("work".into(), "agent-1".into(), CVM_ID.into());
        alias::save(&config.config_dir, &store).expect("seed store");

        let (session, cvm) =
            resolve_session_target("work", Some(&CVM_ID.to_ascii_uppercase()), &config)
                .expect("the alias resolves");
        assert_eq!(session, "agent-1");
        assert_eq!(cvm, CVM_ID, "the CVM must resolve to its canonical form");
    }

    /// `--alias` on a session that already carries one is refused BEFORE the SSH probe:
    /// `record_launch_alias` knows the `{session, cvm}` target at that point, and
    /// `dtach -A` re-attaches, so `--name` may well name an already-aliased session. The
    /// refusal returns a status, which aborts the launch (deliberate: a refused alias
    /// kills the session) — and it happens with no CVM to probe here, which is what pins
    /// that the check precedes `list_session_names`. The CVM is passed in a
    /// non-canonical spelling, the store holding the canonical one.
    #[test]
    fn test_record_launch_alias_second_name_failure() {
        const CVM_ID: &str = "9a7f6b4a-1111-2222-3333-444444444444";
        let dir = std::env::temp_dir().join(format!("umbra-launch-alias-{}", uuid::Uuid::new_v4()));
        let config = ResolvedConfig::resolve(crate::config::ConfigOverrides {
            config_dir: Some(dir),
            ..Default::default()
        });
        let mut store = alias::Aliases::default();
        store.insert_session("work".into(), "agent-1".into(), CVM_ID.into());
        alias::save(&config.config_dir, &store).expect("seed store");

        let status = record_launch_alias(
            &config,
            Some("work-2"),
            "agent-1",
            &CVM_ID.to_ascii_uppercase(),
            None,
        );
        assert_eq!(
            status.map(|status| status as u8),
            Some(ExitStatus::Error as u8),
            "an already-aliased session must abort the launch"
        );
        assert_eq!(
            alias::load(&config.config_dir).unwrap(),
            store,
            "the store must be left exactly as it was"
        );
    }

    /// A corrupt `aliases.toml` must NOT fail `ps`: the sessions come from the Dev
    /// CVMs, not from that local file, so the store error is reported once on stderr
    /// and marked in each `alias` cell while the listing still exits `0` — the same
    /// policy as the resource views (§7.2/7.9). Fleet mode is used because it is the
    /// mode whose exit status only a real failure can change: a per-CVM probe error
    /// (there is no reachable CVM here) stays in the payload. Before, the up-front
    /// `alias::load` check made this exit `1`.
    #[test]
    fn test_ps_malformed_aliases_failure() {
        const CVM_ID: &str = "9a7f6b4a-1111-2222-3333-444444444444";
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        console.list_cvms(Some("running"), &[CVM_ID]);
        fs::write(config.config_dir.join("aliases.toml"), "not = = valid toml")
            .expect("corrupt store written");

        let status = run_ps(
            SessionListArgs {
                target: crate::cli::CvmTarget {
                    cvm_id: None,
                    cvm: None,
                },
                identity_file: None,
            },
            &config,
            false,
        );
        assert!(
            matches!(status, ExitStatus::Ok),
            "a malformed alias file must not fail the listing"
        );
    }
}
