//! The `alias` cell of the read views, exercised through whole commands.
//!
//! These drive the REAL `concrete` binary as a child process against an in-process
//! mock Console, so one test covers the whole chain: argv parsing → config/session
//! resolution → Console call → alias-store load → cell source → card render →
//! payload on stdout → exit code.
//!
//! They live in `tests/` rather than beside the code for one reason: only an
//! integration test gets `CARGO_BIN_EXE_concrete`, which Cargo guarantees is BUILT
//! and UP TO DATE. A `cargo test` of the library alone never produces
//! `target/debug/concrete`, so an in-crate version of these tests failed on a clean
//! checkout (CI) and — worse — passed against a stale binary, testing code that was
//! no longer the source.

use std::path::{Path, PathBuf};
use std::process::Command;

use concrete_cli::test_support::{
    corrupt_alias_store, seed_resource_alias, temp_config_with_session, MockConsole, Presence,
};
use rstest::rstest;

// Real UUIDs: the CLI validates the shape of an id before using it.
const CVM_ID: &str = "9a7f6b4a-1111-2222-3333-444444444444";
const PROFILE_ID: &str = "16286507-f87f-449e-a229-be04067fc23c";
const KEY_ID: &str = "3c4c2b64-b059-41a6-b925-3e4816ffee60";

/// Run `concrete <args>` against `config_dir` and `console_url`, returning its exit
/// code, stdout and stderr.
///
/// The child inherits nothing that could steer it: every `CONCRETE_*` variable is
/// removed, so a developer shell holding `CONCRETE_OUTPUT=json` or
/// `CONCRETE_DEFAULT_PROFILE=…` cannot turn these tests red (or green) for the wrong
/// reason. stderr is returned, not dropped, so a failing assertion can show why.
fn run_cli(config_dir: &Path, console_url: &str, args: &[&str]) -> (i32, String, String) {
    let mut command = Command::new(Path::new(env!("CARGO_BIN_EXE_concrete")));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("CONCRETE_") {
            command.env_remove(key);
        }
    }
    let output = command
        .arg("--config")
        .arg(config_dir)
        .arg("--console-url")
        .arg(console_url)
        .args(args)
        .output()
        .expect("run the concrete binary");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// A mock Console plus a config directory with a valid session, seeded with the
/// listing this case's command reads.
fn scenario(seed: fn(&MockConsole)) -> (MockConsole, PathBuf) {
    let console = MockConsole::start();
    let config_dir = temp_config_with_session(&console);
    seed(&console);
    (console, config_dir)
}

/// The alias row of a rendered card, as the user sees it: the whitespace-split
/// tokens of the `alias` line (`["alias", "<value>"]`). Panics when the card has no
/// such row — the row is unconditional (§7.2/7.3/7.4/7.22).
fn alias_row(rendered: &str) -> Vec<&str> {
    rendered
        .lines()
        .find(|line| line.trim_start().starts_with("alias "))
        .unwrap_or_else(|| panic!("no alias row in the rendered card:\n{rendered}"))
        .split_whitespace()
        .collect()
}

/// With a readable `aliases.toml`, every read view renders the recorded name in the
/// record's `alias` row — the reverse of resolution, so a user can see which name to
/// type instead of the UUID.
#[rstest]
#[case::cvm(|c: &MockConsole| c.list_cvms(None, &[CVM_ID]), &["cvm", "list"], "cvm", CVM_ID)]
#[case::profile(
    |c: &MockConsole| c.list_profiles(&[PROFILE_ID]),
    &["profile", "list"], "profile", PROFILE_ID,
)]
#[case::ssh_key(
    |c: &MockConsole| c.list_keys(&[KEY_ID]),
    &["key", "list"], "ssh-key", KEY_ID,
)]
#[case::profile_show(
    |c: &MockConsole| c.get_profile(PROFILE_ID, Presence::Present),
    &["profile", "show", "--profile", PROFILE_ID], "profile", PROFILE_ID,
)]
fn test_read_view_alias_cell_success(
    #[case] seed: fn(&MockConsole),
    #[case] command: &[&str],
    #[case] kind: &str,
    #[case] id: &str,
) {
    let (console, config_dir) = scenario(seed);
    seed_resource_alias(&config_dir, kind, id, "nick");

    let (code, stdout, stderr) = run_cli(&config_dir, console.base_url(), command);

    assert_eq!(code, 0, "the command must succeed; stderr: {stderr}");
    assert_eq!(alias_row(&stdout), ["alias", "nick"]);
}

/// An unreadable `aliases.toml` must not fail a listing of Console truth, and must
/// not read as "this record has no alias" either: the command still exits `0`, the
/// cell is marked `unreadable` instead of `-`, and the full store error — whose
/// useful part `toml` puts on its LAST line — is reported once on stderr.
#[rstest]
#[case::cvm(|c: &MockConsole| c.list_cvms(None, &[CVM_ID]), &["cvm", "list"])]
#[case::profile(|c: &MockConsole| c.list_profiles(&[PROFILE_ID]), &["profile", "list"])]
#[case::ssh_key(|c: &MockConsole| c.list_keys(&[KEY_ID]), &["key", "list"])]
#[case::profile_show(
    |c: &MockConsole| c.get_profile(PROFILE_ID, Presence::Present),
    &["profile", "show", "--profile", PROFILE_ID],
)]
fn test_read_view_alias_cell_failure(#[case] seed: fn(&MockConsole), #[case] command: &[&str]) {
    let (console, config_dir) = scenario(seed);
    corrupt_alias_store(&config_dir);

    let (code, stdout, stderr) = run_cli(&config_dir, console.base_url(), command);

    assert_eq!(
        code, 0,
        "a broken local store must not fail the command; stderr: {stderr}"
    );
    assert_eq!(
        alias_row(&stdout),
        ["alias", "unreadable"],
        "the fault is marked in the cell, never rendered as `-`"
    );
    assert!(
        stderr.contains("alias names are not shown") && stderr.contains("malformed aliases file"),
        "the full store error belongs on stderr, once; stderr: {stderr}"
    );
}

/// A hand-written alias name cannot forge card structure. `aliases.toml` is an
/// editable local file and the card sanitiser deliberately keeps `\n` (multi-line
/// values need it), so a name carrying a newline plus padding would otherwise render
/// as an extra row — or a fake `> ID <uuid>` title, inventing a CVM that does not
/// exist. Escape sequences must likewise print literally rather than reach the
/// terminal.
#[test]
fn test_read_view_alias_name_cannot_forge_rows_failure() {
    let console = MockConsole::start();
    let config_dir = temp_config_with_session(&console);
    console.list_cvms(None, &[CVM_ID]);
    // Written directly: `alias cvm` rejects both names, only a hand edit can produce
    // them, and that is exactly the threat being pinned.
    std::fs::write(
        config_dir.join("aliases.toml"),
        format!(
            "[cvm]\n\"forged\\n      state          running\\n> ID {CVM_ID}\" = \"{CVM_ID}\"\n"
        ),
    )
    .expect("hand-written alias store");

    let (code, stdout, stderr) = run_cli(&config_dir, console.base_url(), &["cvm", "list"]);

    assert_eq!(code, 0, "stderr: {stderr}");
    // Only real card structure counts: a forged title would START a line. The
    // escaped payload keeps the same characters, but inert, inside one cell.
    assert_eq!(
        stdout
            .lines()
            .filter(|line| line.starts_with("> ID"))
            .count(),
        1,
        "a newline in a name must not forge a second card title:\n{stdout}"
    );
    let alias_lines = stdout
        .lines()
        .filter(|line| line.trim_start().starts_with("alias "))
        .count();
    assert_eq!(alias_lines, 1, "the cell must stay one line:\n{stdout}");
    assert!(
        alias_row(&stdout).join(" ").contains("\\n"),
        "the newline must be escaped and visible in the cell:\n{stdout}"
    );
    assert!(
        !stdout.contains('\x1b'),
        "no raw escape byte may reach the terminal:\n{stdout}"
    );
}
