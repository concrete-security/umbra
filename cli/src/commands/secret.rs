use std::{
    collections::BTreeMap,
    fs,
    io::{self, IsTerminal, Read},
    path::Path,
};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::{
    cli::{SecretCommand, SecretSetArgs},
    config::ResolvedConfig,
    console::{console_session, read_empty_response, read_json_response},
    exit::ExitStatus,
    style,
};

#[derive(Debug, Deserialize)]
struct SecretListPage {
    items: Vec<ConsoleUserSecret>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ConsoleUserSecret {
    name: String,
    allowed_hosts: Vec<String>,
    created_at: String,
    updated_at: String,

    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize)]
struct SecretRemoveOutput<'a> {
    name: &'a str,
}

pub fn run(command: SecretCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        SecretCommand::Set(args) => set(config, args, json),
        SecretCommand::List => list(config, json),
        SecretCommand::Remove { name } => remove(config, &name, json),
    }
}

fn set(config: &ResolvedConfig, args: SecretSetArgs, json_output: bool) -> ExitStatus {
    if !valid_secret_name(&args.name) {
        crate::style::eprintln_error(
            "[usage] NAME must be 1-100 characters of A-Z a-z 0-9 . _ : -",
        );
        return ExitStatus::Usage;
    }
    for host in &args.hosts {
        if !valid_secret_host_pattern(host) {
            crate::style::eprintln_error(&format!(
                "[usage] --host {host} is not a valid binding; use an exact lowercase host, a *.suffix wildcard, or *"
            ));
            return ExitStatus::Usage;
        }
    }
    let value = match read_secret_value(args.value_file.as_deref()) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let secret = match put_secret(
        console_url,
        &session.access_token,
        &args.name,
        &value,
        &args.hosts,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&secret).expect("secret set output serializes")
        );
    } else {
        let confirm = style::ConfirmBlock::new("set", "secret", secret.name.clone())
            .field("hosts", secret.allowed_hosts.join(", "))
            .field("updated", secret.updated_at.clone());
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn list(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let page = match fetch_secrets(console_url, &session.access_token) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&page.items).expect("secret list output serializes")
        );
    } else {
        let views: Vec<style::SecretView<'_>> = page
            .items
            .iter()
            .map(|secret| style::SecretView {
                name: &secret.name,
                allowed_hosts: &secret.allowed_hosts,
                created_at: &secret.created_at,
                updated_at: &secret.updated_at,
                extra: &secret.extra,
            })
            .collect();
        println!("{}", style::secret_list_cards(&views));
    }
    ExitStatus::Ok
}

fn remove(config: &ResolvedConfig, name: &str, json_output: bool) -> ExitStatus {
    if !valid_secret_name(name) {
        crate::style::eprintln_error(
            "[usage] NAME must be 1-100 characters of A-Z a-z 0-9 . _ : -",
        );
        return ExitStatus::Usage;
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    if let Err((status, message)) = delete_secret(console_url, &session.access_token, name) {
        crate::style::eprintln_error(&message);
        return status;
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&SecretRemoveOutput { name })
                .expect("secret remove output serializes")
        );
    } else {
        let confirm = style::ConfirmBlock::new("removed", "secret", name);
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

/// Read the secret value from `--value-file` or stdin. The value never
/// appears on argv (visible in `ps`/shell history) by design. Only trailing
/// newlines are stripped; inner whitespace is preserved verbatim.
fn read_secret_value(path: Option<&Path>) -> Result<Zeroizing<String>, String> {
    let mut raw = Zeroizing::new(String::new());
    if let Some(path) = path {
        *raw = fs::read_to_string(path)
            .map_err(|err| format!("[error] failed to read secret value file: {err}"))?;
    } else {
        if io::stdin().is_terminal() {
            eprintln!(
                "{}",
                style::info_line("reading secret value from stdin; end with Enter then Ctrl-D")
            );
        }
        io::stdin()
            .read_to_string(&mut raw)
            .map_err(|err| format!("[error] failed to read secret value from stdin: {err}"))?;
    }
    let trimmed = raw.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        return Err("[error] secret value is empty".to_string());
    }
    Ok(Zeroizing::new(trimmed.to_string()))
}

fn valid_secret_name(name: &str) -> bool {
    (1..=100).contains(&name.len())
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | ':' | '-'))
}

/// Client-side mirror of the Console's host-binding grammar
/// (`valid_secret_host_pattern` in console profile_secrets.py): `*`, an exact
/// lowercase DNS name of at least two labels, or a `*.suffix` wildcard.
fn valid_secret_host_pattern(host: &str) -> bool {
    if host == "*" {
        return true;
    }
    if host != host.to_lowercase() || host.ends_with('.') || host.len() > 253 {
        return false;
    }
    if let Some(suffix) = host.strip_prefix("*.") {
        return suffix.contains('.') && valid_dns_name(suffix);
    }
    valid_dns_name(host)
}

fn valid_dns_name(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2 && labels.iter().all(|label| valid_dns_label(label))
}

fn valid_dns_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label.starts_with(|ch: char| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        && label.ends_with(|ch: char| ch.is_ascii_lowercase() || ch.is_ascii_digit())
        && label
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
}

fn fetch_secrets(
    console_url: &str,
    access_token: &str,
) -> Result<SecretListPage, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/me/secrets"))
        .bearer_auth(access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to list secrets: {err}"),
            )
        })?;
    read_json_response(response, "list secrets")
}

fn put_secret(
    console_url: &str,
    access_token: &str,
    name: &str,
    value: &str,
    hosts: &[String],
) -> Result<ConsoleUserSecret, (ExitStatus, String)> {
    let response = Client::new()
        .put(format!("{console_url}/api/v1/me/secrets/{name}"))
        .bearer_auth(access_token)
        .json(&json!({ "value": value, "allowed_hosts": hosts }))
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to set secret: {err}"),
            )
        })?;
    read_json_response(response, "set secret")
}

fn delete_secret(
    console_url: &str,
    access_token: &str,
    name: &str,
) -> Result<(), (ExitStatus, String)> {
    let response = Client::new()
        .delete(format!("{console_url}/api/v1/me/secrets/{name}"))
        .bearer_auth(access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to remove secret: {err}"),
            )
        })?;
    read_empty_response(response, "remove secret")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_name_charset_and_length() {
        assert!(valid_secret_name("slack-user-token"));
        assert!(valid_secret_name("a.b:c_d-1"));
        assert!(!valid_secret_name(""));
        assert!(!valid_secret_name("bad name"));
        assert!(!valid_secret_name(&"x".repeat(101)));
    }

    #[test]
    fn host_pattern_grammar_matches_shared_vector() {
        // Cross-language verdict vector for the host-binding grammar. The Console's
        // `valid_secret_host_pattern` (console/src/concrete_console/profile_secrets.py)
        // is authoritative; the function above is a client-side pre-flight mirror.
        // The SAME fixture is asserted by the Python test
        // `test_host_pattern_shared_vector` (console/tests/test_profile_secrets.py),
        // so the two grammars cannot drift silently — change one and the fixture
        // verdict breaks the other side's test.
        #[derive(serde::Deserialize)]
        struct Vector {
            cases: Vec<Case>,
        }
        #[derive(serde::Deserialize)]
        struct Case {
            pattern: String,
            valid: bool,
        }

        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../testdata/secret_host_patterns.json");
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
        let vector: Vector = serde_json::from_str(&raw).expect("shared host-pattern vector parses");
        assert!(
            !vector.cases.is_empty(),
            "shared host-pattern vector is empty"
        );
        for case in &vector.cases {
            assert_eq!(
                valid_secret_host_pattern(&case.pattern),
                case.valid,
                "host pattern {:?} expected valid={}",
                case.pattern,
                case.valid,
            );
        }
    }

    #[test]
    fn secret_value_file_trims_only_trailing_newlines() {
        let dir = std::env::temp_dir().join(format!("concrete-secret-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir created");
        let path = dir.join("value.txt");
        std::fs::write(&path, "  xoxp token with spaces \r\n\n").expect("value written");

        let value = read_secret_value(Some(&path)).expect("value reads");

        assert_eq!(&*value, "  xoxp token with spaces ");
        std::fs::remove_dir_all(dir).expect("temp dir removed");
    }

    #[test]
    fn secret_value_file_rejects_empty() {
        let dir = std::env::temp_dir().join(format!("concrete-secret-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir created");
        let path = dir.join("empty.txt");
        std::fs::write(&path, "\n").expect("value written");

        let err = read_secret_value(Some(&path)).expect_err("empty rejected");

        assert!(err.contains("empty"));
        std::fs::remove_dir_all(dir).expect("temp dir removed");
    }
}
