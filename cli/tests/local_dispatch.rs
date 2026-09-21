//! Exercise folder routing through the real binary and its private worker boundary.
#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

use rstest::rstest;
use serde_json::json;

struct Project {
    root: PathBuf,
    config: PathBuf,
    source: PathBuf,
}

impl Project {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("umbra-local-{}", uuid::Uuid::new_v4()));
        let config = root.join("config");
        let source = root.join("project");
        fs::create_dir_all(config.join("local-tools/bin")).unwrap();
        fs::write(
            config.join("config.toml"),
            "console_url = 'http://127.0.0.1:1'\n",
        )
        .unwrap();
        fs::create_dir_all(source.join("src")).unwrap();
        let source = source.canonicalize().unwrap();
        let registry = config.join("local-projects.json");
        fs::write(
            &registry,
            json!({"version": 1, "projects": [{"root": source, "name": "p-test"}]}).to_string(),
        )
        .unwrap();
        fs::set_permissions(registry, fs::Permissions::from_mode(0o600)).unwrap();
        let project = Self {
            root,
            config,
            source,
        };
        project.worker("printf '%s\\n' \"$@\"");
        project
    }

    fn worker(&self, body: &str) {
        let path = self.config.join("local-tools/bin/python3");
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_umbra"));
        for (key, _) in std::env::vars_os() {
            if key.to_string_lossy().starts_with("UMBRA_") {
                command.env_remove(key);
            }
        }
        command
            .current_dir(self.source.join("src"))
            .env("UMBRA_NO_UPDATE_CHECK", "1")
            .args(["--config", self.config.to_str().unwrap()])
            .args(args)
            .output()
            .unwrap()
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}

/// Every bare session verb selects the ancestor binding and isolated worker.
#[rstest]
#[case::ssh("ssh")]
#[case::claude("claude")]
#[case::codex("codex")]
#[case::code("code")]
#[case::cursor("cursor")]
fn local_session_dispatch_success(#[case] verb: &str) {
    let project = Project::new();
    let output = project.run(&[verb]);
    assert!(output.status.success(), "{:?}", output);
    let arguments = String::from_utf8(output.stdout).unwrap();
    assert!(arguments.starts_with("-I\n-m\numbra_local.cli\n"));
    assert!(arguments.contains(&format!(
        "project-session\n--verb\n{verb}\n--path\n{}\n",
        project.source.join("src").display()
    )));
}

/// The main CLI renders structured worker output as JSON for each lifecycle verb.
#[rstest]
#[case::status(&["--json", "status"])]
#[case::start(&["--json", "start", "local", "--preview"])]
#[case::stop(&["--json", "stop", "local"])]
fn local_structured_dispatch_success(#[case] args: &[&str]) {
    let project = Project::new();
    project.worker("printf '%s\\n' '{\"state\":\"stopped\",\"assurance\":\"local-preview\"}'");
    let output = project.run(args);
    assert!(output.status.success(), "{:?}", output);
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(payload["assurance"], "local-preview");
}

/// Failed worker output never leaks a partial structured success payload.
#[test]
fn local_structured_child_failure() {
    let project = Project::new();
    project.worker("printf 'partial output'; exit 42");
    let output = project.run(&["--json", "status"]);
    assert_eq!((output.status.code(), output.stdout), (Some(1), vec![]));
}

/// Invalid local state blocks implicit sessions instead of silently using cloud.
#[test]
fn local_corrupt_registry_failure() {
    let project = Project::new();
    fs::write(project.config.join("local-projects.json"), "invalid").unwrap();
    let output = project.run(&["ssh"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing cloud fallback"));
}

/// Explicit remote sessions bypass even corrupt local state and reach cloud auth.
#[rstest]
#[case::positional(&["ssh", "9a7f6b4a-1111-2222-3333-444444444444"])]
#[case::flag(&["ssh", "--cvm", "9a7f6b4a-1111-2222-3333-444444444444"])]
fn explicit_remote_dispatch_success(#[case] args: &[&str]) {
    let project = Project::new();
    fs::write(project.config.join("local-projects.json"), "invalid").unwrap();
    let output = project.run(args);
    assert_eq!(output.status.code(), Some(2), "{:?}", output);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("local project registry"));
}

/// Desktop selection reaches the worker without becoming a cloud session.
#[rstest]
#[case::codex("codex")]
#[case::claude("claude")]
fn local_desktop_dispatch_success(#[case] app: &str) {
    let project = Project::new();
    project.worker("printf '%s\\n' \"$@\" >&2; printf '%s\\n' '{}' ");
    let output = project.run(&["--json", "start", "local", "--app", app, "--preview"]);
    assert!(
        output.status.success()
            && String::from_utf8_lossy(&output.stderr).contains(&format!("--app\n{app}\n"))
    );
}
