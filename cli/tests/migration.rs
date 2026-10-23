//! Drive the installed CLI's first-use migration with an isolated home directory.

use std::{fs, path::PathBuf, process::Command};

use rstest::rstest;
use serde_json::Value;

struct Fixture {
    home: PathBuf,
    legacy: PathBuf,
    current: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let home = std::env::temp_dir().join(format!("umbra-migration-{}", uuid::Uuid::new_v4()));
        let legacy = home.join(".concrete");
        let current = home.join(".umbra");
        fs::create_dir_all(legacy.join("cvms")).unwrap();
        fs::write(
            legacy.join("config.toml"),
            "console_url = 'https://console.example.com'\ndefault_cvm = 'old-box'\nno_update_check = true\n",
        )
        .unwrap();
        Self {
            home,
            legacy,
            current,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_umbra"));
        for (key, _) in std::env::vars_os() {
            let name = key.to_string_lossy();
            if name.starts_with("UMBRA_") || name.starts_with("CONCRETE_") {
                command.env_remove(key);
            }
        }
        // HOME retains its normal meaning, scoped to this child process only.
        command
            .env("HOME", &self.home)
            .args(["--json", "config", "show"]);
        command
    }

    fn config(&self) -> Value {
        let output = self.command().output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}

/// First use imports durable Concrete state without copying disposable runtime files.
#[rstest]
#[case::absent(false)]
#[case::empty(true)]
fn first_use_preserves_concrete_state_success(#[case] empty_current: bool) {
    let fixture = Fixture::new();
    if empty_current {
        fs::create_dir(&fixture.current).unwrap();
    }
    let files = [
        ("session.json", "fake session bytes"),
        ("aliases.toml", "fake alias bytes"),
        ("ssh-identities.toml", "fake SSH identity mapping"),
        ("cvms/old-box.atls-policy.json", "fake pinned policy bytes"),
        (
            "cvms/old-box.state.toml",
            "workspace = '/home/dev/workspaces/repo'",
        ),
    ];
    for (name, contents) in files {
        fs::write(fixture.legacy.join(name), contents).unwrap();
    }
    fs::write(
        fixture.legacy.join("update-check.json"),
        "old release cache",
    )
    .unwrap();
    fs::create_dir(fixture.legacy.join("editor-ssh")).unwrap();

    assert_eq!(fixture.config()["default_cvm"]["value"], "old-box");
    for (name, contents) in files {
        assert_eq!(
            fs::read_to_string(fixture.current.join(name)).unwrap(),
            contents
        );
        assert_eq!(
            fs::read_to_string(fixture.legacy.join(name)).unwrap(),
            contents
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(fixture.current.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    assert!(!fixture.current.join("update-check.json").exists());
    assert!(!fixture.current.join("editor-ssh").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&fixture.current).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}

/// Existing Umbra state wins as a whole, so accounts and trust material cannot mix.
#[rstest]
#[case::config("config.toml", "default_cvm = 'new-box'")]
#[case::session("session.json", "fake other account")]
fn existing_umbra_state_is_preserved_success(#[case] name: &str, #[case] contents: &str) {
    let fixture = Fixture::new();
    fs::create_dir(&fixture.current).unwrap();
    fs::write(fixture.current.join(name), contents).unwrap();
    let config = fixture.config();
    assert_ne!(config["default_cvm"]["value"], "old-box");
    assert_eq!(
        fs::read_to_string(fixture.current.join(name)).unwrap(),
        contents
    );
}

/// The old environment prefix remains usable; the new prefix takes precedence.
#[rstest]
#[case::legacy_only(false, "legacy-env")]
#[case::current_wins(true, "current-env")]
fn renamed_environment_preserves_precedence_success(#[case] current: bool, #[case] expected: &str) {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    command.env("CONCRETE_DEFAULT_CVM", "legacy-env");
    if current {
        command.env("UMBRA_DEFAULT_CVM", "current-env");
    }
    let output = command.output().unwrap();
    assert!(output.status.success());
    let config: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(config["default_cvm"]["value"], expected);
    assert_eq!(config["default_cvm"]["source"], "env");
}

/// Explicit state directories bypass automatic home-directory migration.
#[rstest]
#[case::flag("flag")]
#[case::current_env("UMBRA_CONFIG_DIR")]
#[case::legacy_env("CONCRETE_CONFIG_DIR")]
fn explicit_config_directory_is_preserved_success(#[case] selector: &str) {
    let fixture = Fixture::new();
    let mut command = fixture.command();
    if selector == "flag" {
        command.arg("--config").arg(&fixture.legacy);
    } else {
        command.env(selector, &fixture.legacy);
    }
    let output = command.output().unwrap();
    assert!(output.status.success());
    let config: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(config["default_cvm"]["value"], "old-box");
    assert!(!fixture.current.exists());
}

/// A failed import cannot expose a partial Umbra store or follow a planted symlink.
#[cfg(unix)]
#[rstest]
#[case::file("session.json")]
#[case::directory("cvms")]
#[case::policy("cvms/old-box.atls-policy.json")]
fn migration_symlink_is_rejected_failure(#[case] name: &str) {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::new();
    let victim = fixture.home.join("outside");
    fs::write(&victim, "do not import this").unwrap();
    if name == "cvms" {
        fs::remove_dir(fixture.legacy.join(name)).unwrap();
    }
    symlink(&victim, fixture.legacy.join(name)).unwrap();
    let output = fixture.command().output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(!fixture.current.exists());
    assert_eq!(fs::read_to_string(victim).unwrap(), "do not import this");
}

/// A logout or removed session must not silently restore Concrete's credential copy.
#[test]
fn removed_session_stays_removed_success() {
    let fixture = Fixture::new();
    fs::write(fixture.legacy.join("session.json"), "fake old credential").unwrap();
    fixture.config();
    fs::remove_file(fixture.current.join("session.json")).unwrap();
    fixture.config();
    assert!(!fixture.current.join("session.json").exists());
}

/// Concurrent first invocations all observe the complete same migrated store.
#[test]
fn concurrent_first_use_success() {
    let fixture = Fixture::new();
    let children: Vec<_> = (0..4)
        .map(|_| {
            fixture
                .command()
                .stdout(std::process::Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    let outputs: Vec<_> = children
        .into_iter()
        .map(|child| child.wait_with_output().unwrap())
        .collect();
    for output in outputs {
        assert!(output.status.success());
        let config: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(config["default_cvm"]["value"], "old-box");
    }
}
