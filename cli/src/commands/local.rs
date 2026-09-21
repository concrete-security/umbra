//! Project-aware local execution behind the existing Umbra CLI.
//!
//! The Python supervisor is a private installed runtime, not a second product
//! CLI. Explicit remote targets bypass local selection, including for the relay.
use std::{
    collections::HashSet,
    env,
    ffi::{OsStr, OsString},
    fs::{self, OpenOptions},
    io::{ErrorKind, Read},
    path::{Component, Path, PathBuf},
    process::{Command as Process, Stdio},
};

use serde::Deserialize;

use crate::{
    cli::{Command, CvmTarget, LocalStartArgs, StartCommand, StopCommand},
    config::{OutputFormat, ResolvedConfig},
    exit::ExitStatus,
    style,
};

const REGISTRY_LIMIT: u64 = 1024 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectRegistry {
    version: u8,
    projects: Vec<ProjectBinding>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProjectBinding {
    root: PathBuf,
    name: String,
}

fn select_binding(registry: ProjectRegistry, directory: &Path) -> Result<Option<PathBuf>, String> {
    if registry.version != 1 {
        return Err("[error] unsupported local project registry version".into());
    }
    let mut roots = HashSet::new();
    let mut names = HashSet::new();
    let mut selected: Option<PathBuf> = None;
    for binding in registry.projects {
        let bytes = binding.name.as_bytes();
        if !binding.root.is_absolute()
            || binding
                .root
                .components()
                .any(|part| matches!(part, Component::ParentDir))
            || binding.root.to_string_lossy().chars().any(char::is_control)
            || bytes.is_empty()
            || bytes.len() > 32
            || !bytes[0].is_ascii_lowercase()
            || bytes
                .iter()
                .any(|byte| !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && *byte != b'-')
            || !roots.insert(binding.root.clone())
            || !names.insert(binding.name)
        {
            return Err("[error] invalid local project registry; refusing cloud fallback".into());
        }
        if directory.starts_with(&binding.root)
            && selected
                .as_ref()
                .is_none_or(|root| binding.root.components().count() > root.components().count())
        {
            selected = Some(binding.root);
        }
    }
    Ok(selected)
}

fn project_root(config: &ResolvedConfig, directory: &Path) -> Result<Option<PathBuf>, String> {
    let path = config.config_dir.join("local-projects.json");
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => {
            return Err(
                "[error] cannot read local project registry; refusing cloud fallback".into(),
            )
        }
    };
    let metadata = file
        .metadata()
        .map_err(|_| "[error] cannot inspect local project registry")?;
    if !metadata.is_file() || metadata.len() > REGISTRY_LIMIT {
        return Err("[error] invalid local project registry; refusing cloud fallback".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid takes no pointers and has no preconditions.
        if metadata.mode() & 0o077 != 0 || metadata.uid() != unsafe { libc::geteuid() } {
            return Err(
                "[error] local project registry must be owner-only; refusing cloud fallback".into(),
            );
        }
    }
    let mut bytes = Vec::new();
    file.take(REGISTRY_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "[error] cannot read local project registry")?;
    if bytes.len() as u64 > REGISTRY_LIMIT {
        return Err("[error] local project registry exceeds the size limit".into());
    }
    let registry = serde_json::from_slice(&bytes)
        .map_err(|_| "[error] invalid local project registry; refusing cloud fallback")?;
    select_binding(registry, directory)
}

fn option(args: &mut Vec<OsString>, flag: &str, value: Option<&OsStr>) {
    if let Some(value) = value {
        args.push(flag.into());
        args.push(value.to_owned());
    }
}

fn text_option(args: &mut Vec<OsString>, flag: &str, value: Option<&str>) {
    option(args, flag, value.map(OsStr::new));
}

fn failure(message: &str) -> ExitStatus {
    style::eprintln_error(message);
    ExitStatus::Error
}

fn run_worker(config: &ResolvedConfig, args: Vec<OsString>, structured: bool) -> ExitStatus {
    if config.atls_policy_insecure_skip {
        return failure("[error] local execution does not allow an attestation bypass");
    }
    if !structured && config.output == OutputFormat::Json {
        return failure("[usage] --json is not supported for interactive or raw session output");
    }
    let python = config.config_dir.join("local-tools/bin/python3");
    if !python.is_file() {
        return failure("[error] local runtime is not installed; from this source checkout run local/install-runtime.sh, then retry umbra start local");
    }
    let executable = match env::current_exe() {
        Ok(path) => path,
        Err(_) => return failure("[error] cannot locate the running Umbra executable"),
    };
    let mut worker = Process::new(python);
    // -I rejects PYTHONPATH and the current project as Python import sources.
    worker
        .args(["-I", "-m", "umbra_local.cli", "--config"])
        .arg(&config.config_dir)
        .arg("--umbra")
        .arg(executable)
        .stderr(Stdio::inherit());
    if let Some(url) = &config.console_url {
        worker.arg("--console-url").arg(url);
    }
    if let Some(policy) = &config.atls_policy {
        worker.arg("--atls-policy").arg(policy);
    }
    if structured {
        worker.arg("--json").stdin(Stdio::null());
    }
    worker.args(args);
    if structured {
        match worker.output() {
            Ok(output) if output.status.success() => {
                let payload: serde_json::Value = match serde_json::from_slice(&output.stdout) {
                    Ok(payload) => payload,
                    Err(_) => return failure("[error] invalid response from local runtime"),
                };
                if config.output == OutputFormat::Json {
                    style::emit_json(&payload);
                } else {
                    println!("{}", style::local_workspace_card(&payload));
                }
                ExitStatus::Ok
            }
            Ok(_) => ExitStatus::Error,
            Err(_) => failure("[error] could not start the installed local runtime"),
        }
    } else {
        match worker.status() {
            Ok(status) if status.success() => ExitStatus::Ok,
            Ok(_) => ExitStatus::Error,
            Err(_) => failure("[error] could not start the installed local runtime"),
        }
    }
}

fn current_directory(path: Option<&Path>) -> Result<PathBuf, String> {
    let path = match path {
        Some(path) => path.to_owned(),
        None => env::current_dir()
            .map_err(|_| "[error] cannot resolve the current project directory")?,
    };
    let directory =
        fs::canonicalize(path).map_err(|_| "[error] project directory does not exist")?;
    if !directory.is_dir() {
        return Err("[error] project path must be a directory".into());
    }
    Ok(directory)
}

pub fn start(command: StartCommand, config: &ResolvedConfig) -> ExitStatus {
    let StartCommand::Local(args) = command;
    start_local(args, config)
}

fn start_local(args: LocalStartArgs, config: &ResolvedConfig) -> ExitStatus {
    let directory = match current_directory(args.path.as_deref()) {
        Ok(directory) => directory,
        Err(message) => return failure(&message),
    };
    let mut request = vec![
        "project-start".into(),
        "--path".into(),
        directory.into_os_string(),
    ];
    if args.preview {
        request.push("--preview".into());
    }
    for profile in &config.profiles {
        let resolved = match super::alias::resolve_or_passthrough(
            config,
            super::alias::AliasKind::Profile,
            profile,
        ) {
            Ok(value) => value,
            Err(message) => return failure(&message),
        };
        let flag = if config.profile_flags.is_empty() {
            "--default-profile"
        } else {
            "--profile"
        };
        text_option(&mut request, flag, Some(&resolved));
    }
    option(
        &mut request,
        "--bundle",
        args.bundle.as_deref().map(Path::as_os_str),
    );
    if let Some(cpus) = args.cpus {
        text_option(&mut request, "--cpus", Some(&cpus.to_string()));
    }
    if let Some(memory) = args.memory {
        text_option(&mut request, "--memory", Some(&memory.to_string()));
    }
    run_worker(config, request, true)
}

pub fn stop(command: StopCommand, config: &ResolvedConfig) -> ExitStatus {
    let StopCommand::Local(args) = command;
    let directory = match current_directory(args.path.as_deref()) {
        Ok(directory) => directory,
        Err(message) => return failure(&message),
    };
    run_worker(
        config,
        vec![
            "project-stop".into(),
            "--path".into(),
            directory.into_os_string(),
        ],
        true,
    )
}

fn explicit_remote(target: &CvmTarget) -> bool {
    target.cvm.is_some() || target.cvm_id.is_some()
}

/// None preserves the existing cloud path. An error is Some(Error), never None.
pub fn try_session(command: &Command, config: &ResolvedConfig) -> Option<ExitStatus> {
    let mut request = vec![OsString::from("project-session")];
    let (verb, invalid_option) = match command {
        Command::Ssh(args) if !explicit_remote(&args.target) => {
            text_option(&mut request, "--name", args.name.as_deref());
            text_option(&mut request, "--remote-command", args.command.as_deref());
            ("ssh", args.identity_file.is_some() || args.alias.is_some())
        }
        Command::Claude {
            command: None,
            session: args,
        }
        | Command::Codex {
            command: None,
            session: args,
        } if !explicit_remote(&args.target) => {
            text_option(&mut request, "--name", args.name.as_deref());
            text_option(&mut request, "--workspace", args.workspace.as_deref());
            let verb = if matches!(command, Command::Claude { .. }) {
                "claude"
            } else {
                "codex"
            };
            (verb, args.identity_file.is_some() || args.alias.is_some())
        }
        Command::Code(args) if !explicit_remote(&args.target) => {
            text_option(&mut request, "--workspace", args.workspace.as_deref());
            option(
                &mut request,
                "--editor-bin",
                args.code_bin.as_deref().map(Path::as_os_str),
            );
            ("code", args.identity_file.is_some())
        }
        Command::Cursor(args) if !explicit_remote(&args.target) => {
            text_option(&mut request, "--workspace", args.workspace.as_deref());
            option(
                &mut request,
                "--editor-bin",
                args.cursor_bin.as_deref().map(Path::as_os_str),
            );
            ("cursor", args.identity_file.is_some())
        }
        Command::Status => ("status", false),
        _ => return None,
    };
    let directory = match current_directory(None) {
        Ok(directory) => directory,
        Err(message) => return Some(failure(&message)),
    };
    match project_root(config, &directory) {
        Ok(None) => return None,
        Err(message) => return Some(failure(&message)),
        Ok(Some(_)) => {}
    }
    if invalid_option {
        return Some(failure("[usage] local workspaces use their own SSH identity and folder binding; --identity-file and --alias are not supported here"));
    }
    if verb == "status" {
        request[0] = "project-status".into();
    } else {
        text_option(&mut request, "--verb", Some(verb));
    }
    option(&mut request, "--path", Some(directory.as_os_str()));
    Some(run_worker(config, request, verb == "status"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;
    use rstest::rstest;

    /// Starting locally is part of the main clap command tree.
    #[test]
    fn main_cli_local_start_success() {
        let parsed = Cli::try_parse_from([
            "umbra",
            "start",
            "local",
            "--preview",
            "--profile",
            "profile",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Start(StartCommand::Local(_))
        ));
    }

    /// Explicit local stop is folder scoped and requires no invented VM name.
    #[test]
    fn main_cli_local_stop_success() {
        let parsed = Cli::try_parse_from(["umbra", "stop", "local"]).unwrap();
        assert!(matches!(
            parsed.command,
            Command::Stop(StopCommand::Local(_))
        ));
    }

    /// Descendants resolve to the nearest registered root, not a string prefix.
    #[rstest]
    #[case::root("/work/project", Some("/work/project"))]
    #[case::child("/work/project/src", Some("/work/project"))]
    #[case::nested("/work/project/nested/src", Some("/work/project/nested"))]
    #[case::sibling("/work/project-other", None)]
    fn project_selection_success(#[case] directory: &str, #[case] expected: Option<&str>) {
        let registry = ProjectRegistry {
            version: 1,
            projects: vec![
                ProjectBinding {
                    root: "/work/project".into(),
                    name: "p-first".into(),
                },
                ProjectBinding {
                    root: "/work/project/nested".into(),
                    name: "p-second".into(),
                },
            ],
        };
        assert_eq!(
            select_binding(registry, Path::new(directory)).unwrap(),
            expected.map(PathBuf::from)
        );
    }

    /// Malformed registry data cannot silently pick a cloud default.
    #[test]
    fn malformed_registry_failure() {
        let registry = ProjectRegistry {
            version: 1,
            projects: vec![ProjectBinding {
                root: "/work/project".into(),
                name: "../escape".into(),
            }],
        };
        assert!(select_binding(registry, Path::new("/work/project")).is_err());
    }

    /// Both explicit remote target forms bypass project selection for relays.
    #[rstest]
    #[case::positional(Some("relay"), None)]
    #[case::flag(None, Some("relay"))]
    fn explicit_remote_selection_success(
        #[case] positional: Option<&str>,
        #[case] flag: Option<&str>,
    ) {
        let target = CvmTarget {
            cvm_id: positional.map(str::to_owned),
            cvm: flag.map(str::to_owned),
        };
        assert!(explicit_remote(&target));
    }
}
