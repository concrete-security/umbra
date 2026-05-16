use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

use chrono::Utc;
use reqwest::blocking::Client;
use serde::Deserialize;

use crate::{
    cli::{AgentSessionArgs, SshArgs},
    commands::auth,
    config::ResolvedConfig,
    exit::ExitStatus,
    session::Session,
};

#[derive(Debug, Deserialize)]
struct Cvm {
    id: String,
    state: String,
    fqdn: Option<String>,
}

struct SshInvocation<'a> {
    cvm_id: Option<&'a str>,
    identity_file: Option<&'a Path>,
    remote_command: String,
    allocate_tty: bool,
}

pub fn run(args: SshArgs, config: &ResolvedConfig) -> ExitStatus {
    if args.name.is_some() && args.command.is_some() {
        eprintln!("[usage] --name cannot be combined with --command");
        return ExitStatus::Usage;
    }
    let remote_command = match ssh_remote_command(&args) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
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
            eprintln!("[error] unsupported agent session verb {verb}");
            return ExitStatus::Error;
        }
    };
    let session_name = match session_name(args.name.as_deref(), program) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Usage;
        }
    };
    run_ssh(
        SshInvocation {
            cvm_id: args.cvm_id.as_deref(),
            identity_file: args.identity_file.as_deref(),
            remote_command: dtach_remote_command(&session_name, program),
            allocate_tty: true,
        },
        config,
    )
}

fn run_ssh(invocation: SshInvocation<'_>, config: &ResolvedConfig) -> ExitStatus {
    let cvm_id = match selected_cvm_id(invocation.cvm_id, config) {
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
    let cvm = match fetch_cvm(console_url, &session, &cvm_id) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    if cvm.state != "RUNNING" {
        eprintln!(
            "[error] Dev CVM {} is in state {}, expected RUNNING",
            cvm.id, cvm.state
        );
        return ExitStatus::Error;
    }
    let fqdn = match cvm.fqdn.as_deref() {
        Some(value) if !value.is_empty() => value,
        _ => {
            eprintln!("[error] Dev CVM {} does not have an FQDN yet", cvm.id);
            return ExitStatus::Error;
        }
    };
    let policy_path = match resolve_policy_path(config, console_url, &session, &cvm.id) {
        Ok(value) => value,
        Err((status, message)) => {
            eprintln!("{message}");
            return status;
        }
    };
    let proxy_command = match proxy_command(config, &policy_path, fqdn) {
        Ok(value) => value,
        Err(message) => {
            eprintln!("{message}");
            return ExitStatus::Error;
        }
    };
    let mut ssh = Command::new("ssh");
    ssh.arg("-o")
        .arg(format!("ProxyCommand={proxy_command}"))
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("ConnectTimeout=30");
    if let Some(identity_file) = invocation.identity_file {
        ssh.arg("-i").arg(identity_file);
    }
    if invocation.allocate_tty {
        ssh.arg("-t");
    }
    ssh.arg(format!("dev@{fqdn}"));
    ssh.arg(invocation.remote_command);
    match ssh.status() {
        Ok(status) if status.success() => ExitStatus::Ok,
        Ok(status) => {
            eprintln!("[error] ssh exited with status {status}");
            ExitStatus::Error
        }
        Err(err) => {
            eprintln!("[error] failed to invoke ssh: {err}");
            ExitStatus::Error
        }
    }
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

fn console_session(config: &ResolvedConfig) -> Result<(&str, Session), (ExitStatus, String)> {
    let console_url = config
        .require_console_url()
        .map_err(|message| (ExitStatus::Usage, message))?;
    let session = auth::session_for_console(config)?;
    Ok((console_url, session))
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
    crate::commands::cvm::read_json_response(response, "fetch Dev CVM")
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
    crate::commands::cvm::read_json_response(response, "fetch Dev CVM policy bundle")
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

fn dtach_remote_command(session_name: &str, program_command: &str) -> String {
    let socket = format!("/run/concrete/sessions/{session_name}.sock");
    format!(
        "mkdir -p /run/concrete/sessions && chmod 700 /run/concrete/sessions && exec dtach -A {} -r winch {}",
        shell_quote(&socket),
        program_command,
    )
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
}
