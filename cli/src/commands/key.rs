use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    cli::{KeyAddArgs, KeyCommand},
    config::ResolvedConfig,
    console::{console_session, read_empty_response, read_json_response, ListPage},
    exit::ExitStatus,
    ssh_identity::{self, persistable_path},
    ssh_identity_store, style,
};

#[derive(Debug, Deserialize)]
struct ConsoleSshKey {
    id: String,
    label: String,
    fingerprint: String,
    public_key: String,
    created_at: String,

    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
}

#[derive(Debug, Serialize)]
struct SshKeyOutput {
    id: String,
    label: String,
    fingerprint: String,
    algorithm: String,
    created_at: String,
}

#[derive(Debug, Serialize)]
struct KeyRemoveOutput<'a> {
    key_id: &'a str,
}

pub fn run(command: KeyCommand, config: &ResolvedConfig, json: bool) -> ExitStatus {
    match command {
        KeyCommand::List => list(config, json),
        KeyCommand::Add(args) => add(config, args, json),
        KeyCommand::Remove { key_id } => remove(config, &key_id, json),
    }
}

fn list(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let page = match fetch_keys(console_url, &session.access_token) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let keys: Vec<_> = page.items.iter().map(key_output).collect();
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&keys).expect("key list output serializes")
        );
    } else {
        let views: Vec<style::KeyView<'_>> = page
            .items
            .iter()
            .zip(keys.iter())
            .map(|(raw, out)| style::KeyView {
                id: &out.id,
                label: &out.label,
                fingerprint: &out.fingerprint,
                algorithm: &out.algorithm,
                created_at: &out.created_at,
                extra: &raw.extra,
            })
            .collect();
        println!("{}", style::key_list_cards(&views));
        if let Some(cursor) = page.next_cursor {
            eprintln!("{}", style::next_cursor_diagnostic(&cursor));
        }
    }
    ExitStatus::Ok
}

fn add(config: &ResolvedConfig, args: KeyAddArgs, json_output: bool) -> ExitStatus {
    let public_key = match read_public_key(args.file.as_deref()) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    let identity = match resolve_key_add_identity(
        args.file.as_deref(),
        args.identity_file.as_deref(),
        &public_key,
    ) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    let key = match create_key(console_url, &session.access_token, &args.label, &public_key) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    if let Some(path) = identity.path.as_deref() {
        if let Err(err) =
            ssh_identity_store::write_identity(&config.config_dir, &key.id, &persistable_path(path))
        {
            crate::style::eprintln_error(&format!(
                "[error] failed to remember SSH identity path: {err}"
            ));
            return ExitStatus::Error;
        }
    } else if let Some(message) = identity.warning.as_deref() {
        eprintln!("{}", style::info_line(message));
    }
    let output = key_output(&key);
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).expect("key add output serializes")
        );
    } else {
        let confirm = style::ConfirmBlock::new("added", "key", output.label.clone())
            .field("id", output.id.clone())
            .field("fingerprint", output.fingerprint.clone())
            .field("algorithm", output.algorithm.clone());
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

#[derive(Debug)]
struct KeyAddIdentity {
    path: Option<PathBuf>,
    warning: Option<String>,
}

fn resolve_key_add_identity(
    public_key_path: Option<&Path>,
    explicit_identity: Option<&Path>,
    public_key: &str,
) -> Result<KeyAddIdentity, (ExitStatus, String)> {
    let Some(public_fingerprint) = ssh_identity::public_key_text_fingerprint(public_key) else {
        if explicit_identity.is_some() {
            return Err((
                ExitStatus::Error,
                "[error] public key is not a valid OpenSSH public key".to_string(),
            ));
        }
        return Ok(KeyAddIdentity {
            path: None,
            warning: None,
        });
    };
    if let Some(path) = explicit_identity {
        let path = ssh_identity::resolve_explicit_identity(path)?;
        let private_fingerprint =
            ssh_identity::private_key_fingerprint(&path).ok_or_else(|| {
                (
                    ExitStatus::Usage,
                    format!(
                        "[usage] SSH identity file {} is not a readable OpenSSH private key",
                        path.display()
                    ),
                )
            })?;
        if private_fingerprint != public_fingerprint {
            return Err((
                ExitStatus::Usage,
                format!(
                    "[usage] SSH identity file {} does not match the public key being registered",
                    path.display()
                ),
            ));
        }
        return Ok(KeyAddIdentity {
            path: Some(path),
            warning: None,
        });
    }

    let Some(public_key_path) = public_key_path else {
        return Ok(KeyAddIdentity {
            path: None,
            warning: Some(
                "registered SSH key, but no local private key path was provided; pass --identity-file to remember one"
                    .to_string(),
            ),
        });
    };
    let Some(candidate) = inferred_private_key_path(public_key_path) else {
        return Ok(KeyAddIdentity {
            path: None,
            warning: Some(format!(
                "registered SSH key, but could not infer a local private key from {}; pass --identity-file to remember one",
                public_key_path.display()
            )),
        });
    };
    if !candidate.is_file() {
        return Ok(KeyAddIdentity {
            path: None,
            warning: Some(format!(
                "registered SSH key, but inferred private key {} does not exist; pass --identity-file to remember one",
                candidate.display()
            )),
        });
    }
    let Some(private_fingerprint) = ssh_identity::private_key_fingerprint(&candidate) else {
        return Ok(KeyAddIdentity {
            path: None,
            warning: Some(format!(
                "registered SSH key, but inferred private key {} is not readable; pass --identity-file to remember one",
                candidate.display()
            )),
        });
    };
    if private_fingerprint != public_fingerprint {
        return Ok(KeyAddIdentity {
            path: None,
            warning: Some(format!(
                "registered SSH key, but inferred private key {} does not match; pass --identity-file to remember one",
                candidate.display()
            )),
        });
    }
    Ok(KeyAddIdentity {
        path: Some(candidate),
        warning: None,
    })
}

fn inferred_private_key_path(public_key_path: &Path) -> Option<PathBuf> {
    (public_key_path.extension().and_then(|ext| ext.to_str()) == Some("pub"))
        .then(|| public_key_path.with_extension(""))
}

fn remove(config: &ResolvedConfig, key_id: &str, json_output: bool) -> ExitStatus {
    if Uuid::parse_str(key_id).is_err() {
        crate::style::eprintln_error("[usage] KEY_ID must be a UUID");
        return ExitStatus::Usage;
    }
    let (console_url, session) = match console_session(config) {
        Ok(value) => value,
        Err((status, message)) => {
            crate::style::eprintln_error(&message);
            return status;
        }
    };
    if let Err((status, message)) = delete_key(console_url, &session.access_token, key_id) {
        crate::style::eprintln_error(&message);
        return status;
    }
    if json_output {
        println!(
            "{}",
            serde_json::to_string_pretty(&KeyRemoveOutput { key_id })
                .expect("key remove output serializes")
        );
    } else {
        let confirm = style::ConfirmBlock::new("removed", "key", key_id);
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn fetch_keys(
    console_url: &str,
    access_token: &str,
) -> Result<ListPage<ConsoleSshKey>, (ExitStatus, String)> {
    let response = Client::new()
        .get(format!("{console_url}/api/v1/me/keys"))
        .bearer_auth(access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to list SSH keys: {err}"),
            )
        })?;
    read_json_response(response, "list SSH keys")
}

fn create_key(
    console_url: &str,
    access_token: &str,
    label: &str,
    public_key: &str,
) -> Result<ConsoleSshKey, (ExitStatus, String)> {
    let response = Client::new()
        .post(format!("{console_url}/api/v1/me/keys"))
        .bearer_auth(access_token)
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

fn delete_key(
    console_url: &str,
    access_token: &str,
    key_id: &str,
) -> Result<(), (ExitStatus, String)> {
    let response = Client::new()
        .delete(format!("{console_url}/api/v1/me/keys/{key_id}"))
        .bearer_auth(access_token)
        .send()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to remove SSH key: {err}"),
            )
        })?;
    read_empty_response(response, "remove SSH key")
}

fn read_public_key(path: Option<&Path>) -> Result<String, String> {
    let mut value = String::new();
    if let Some(path) = path {
        value = fs::read_to_string(path)
            .map_err(|err| format!("[error] failed to read public key file: {err}"))?;
    } else {
        io::stdin()
            .read_to_string(&mut value)
            .map_err(|err| format!("[error] failed to read public key from stdin: {err}"))?;
    }
    let value = value.trim();
    if value.is_empty() {
        return Err("[error] public key is empty".to_string());
    }
    Ok(value.to_string())
}

fn key_output(key: &ConsoleSshKey) -> SshKeyOutput {
    SshKeyOutput {
        id: key.id.clone(),
        label: key.label.clone(),
        fingerprint: key.fingerprint.clone(),
        algorithm: ssh_key_algorithm(&key.public_key).to_string(),
        created_at: key.created_at.clone(),
    }
}

fn ssh_key_algorithm(public_key: &str) -> &str {
    public_key.split_whitespace().next().unwrap_or("unknown")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, process::Command};

    #[test]
    fn ssh_key_algorithm_uses_openssh_prefix() {
        assert_eq!(
            ssh_key_algorithm("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest user@example"),
            "ssh-ed25519"
        );
    }

    #[test]
    fn key_add_identity_infers_sibling_private_key() {
        let dir = std::env::temp_dir().join(format!("concrete-key-add-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");
        let private_key = dir.join("work_ed25519");
        let public_key_path = dir.join("work_ed25519.pub");
        Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&private_key)
            .output()
            .expect("ssh-keygen succeeds");
        let public_key = fs::read_to_string(&public_key_path).expect("public key readable");

        let identity = resolve_key_add_identity(Some(&public_key_path), None, &public_key)
            .expect("identity resolves");

        assert_eq!(identity.path, Some(private_key));
        assert!(identity.warning.is_none());
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    #[test]
    fn key_add_identity_rejects_explicit_mismatch() {
        let dir = std::env::temp_dir().join(format!("concrete-key-add-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");
        let first_private_key = dir.join("first_ed25519");
        let first_public_key = dir.join("first_ed25519.pub");
        let second_private_key = dir.join("second_ed25519");
        Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&first_private_key)
            .output()
            .expect("first ssh-keygen succeeds");
        Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&second_private_key)
            .output()
            .expect("second ssh-keygen succeeds");
        let public_key = fs::read_to_string(first_public_key).expect("public key readable");

        let err = resolve_key_add_identity(None, Some(&second_private_key), &public_key)
            .expect_err("mismatch rejected");

        assert!(matches!(err.0, ExitStatus::Usage));
        assert!(err.1.contains("does not match"));
        fs::remove_dir_all(dir).expect("temp dir removed");
    }
}
