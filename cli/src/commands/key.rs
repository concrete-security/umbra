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
    commands::alias,
    config::ResolvedConfig,
    console::{console_session, fetch_json, post_json, read_empty_response, send, ListPage},
    exit::ExitStatus,
    session::Session,
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
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let page = try_or_eprintln!(fetch_keys(console_url, &session));
    let keys: Vec<_> = page.items.iter().map(key_output).collect();
    if json_output {
        style::emit_json(&keys);
    } else {
        // Local alias names for the page, read once (human view only).
        let aliases = alias::load_for_display(config);
        let views: Vec<style::KeyView<'_>> = page
            .items
            .iter()
            .zip(keys.iter())
            .map(|(raw, out)| style::KeyView {
                id: &out.id,
                alias: alias::cell_source(&aliases, alias::AliasKind::SshKey, &out.id),
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
    // Fail fast on a bad/taken alias before registering anything.
    if let Some(nick) = args.alias.as_deref() {
        if let Err((status, message)) = crate::commands::alias::validate_alias(config, nick, None) {
            crate::style::eprintln_error(&message);
            return status;
        }
    }
    let public_key = match read_public_key(args.file.as_deref()) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    let identity = try_or_eprintln!(resolve_key_add_identity(
        args.file.as_deref(),
        args.identity_file.as_deref(),
        &public_key,
    ));
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let key = try_or_eprintln!(create_key(
        console_url,
        &session.access_token,
        &args.label,
        &public_key
    ));
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
    if let Some(nick) = args.alias.as_deref() {
        if let Err(message) = crate::commands::alias::record_resource_alias(
            config,
            crate::commands::alias::AliasKind::SshKey,
            &key.id,
            nick,
        ) {
            crate::style::eprintln_warn(&format!(
                "[warn] key added but alias not saved: {message}"
            ));
        }
    }
    let output = key_output(&key);
    if json_output {
        style::emit_json(&output);
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
    // Resolve an ssh-key alias to its id (a raw UUID passes straight through), so
    // `key remove <alias>` works as everywhere a key id is taken.
    let key_id = match crate::commands::alias::resolve_or_passthrough(
        config,
        crate::commands::alias::AliasKind::SshKey,
        key_id,
    ) {
        Ok(id) => id,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    let key_id = key_id.as_str();
    if Uuid::parse_str(key_id).is_err() {
        crate::style::eprintln_error("[usage] KEY_ID must be a UUID or a known alias");
        return ExitStatus::Usage;
    }
    let (console_url, session) = try_or_eprintln!(console_session(config));
    if let Err((status, message)) = delete_key(console_url, &session.access_token, key_id) {
        crate::style::eprintln_error(&message);
        return status;
    }
    // The key is gone from the Console; drop any alias pointing at it.
    crate::commands::alias::prune_and_save(config, |a| {
        a.prune(crate::commands::alias::Prune::Resource(
            crate::commands::alias::AliasKind::SshKey,
            key_id,
        ))
    });
    if json_output {
        style::emit_json(&KeyRemoveOutput { key_id });
    } else {
        let confirm = style::ConfirmBlock::new("removed", "key", key_id);
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

/// Confirm the caller owns a registered SSH key with `key_id`, erroring if it
/// is absent. The Console has no single-key GET, so this lists the caller's
/// keys and tests membership — used to fail-fast when aliasing a key. Mirrors
/// `cvm_exists` / `profile_exists` so alias creation dispatches uniformly.
pub(crate) fn key_exists(
    console_url: &str,
    session: &Session,
    key_id: &str,
) -> Result<(), (ExitStatus, String)> {
    let page = fetch_keys(console_url, session)?;
    if page.items.iter().any(|key| key.id == key_id) {
        Ok(())
    } else {
        Err((
            ExitStatus::Error,
            format!("[error] ssh-key {key_id} was not found"),
        ))
    }
}

/// Ids of the caller's registered SSH keys, for `alias prune` to drop aliases
/// whose key no longer exists.
pub(crate) fn key_ids(
    console_url: &str,
    session: &Session,
) -> Result<Vec<String>, (ExitStatus, String)> {
    Ok(fetch_keys(console_url, session)?
        .items
        .into_iter()
        .map(|key| key.id)
        .collect())
}

/// Path of the caller's registered-keys list, the one source of truth shared by
/// the fetcher and the test mock (`MockConsole`) so the two never drift.
pub(crate) fn keys_path() -> &'static str {
    "/api/v1/me/keys"
}

/// Path of the single-key `DELETE`, the one source of truth shared by the
/// remover and the test mock (`MockConsole`) so the two never drift.
pub(crate) fn key_path(key_id: &str) -> String {
    format!("{}/{key_id}", keys_path())
}

fn fetch_keys(
    console_url: &str,
    session: &Session,
) -> Result<ListPage<ConsoleSshKey>, (ExitStatus, String)> {
    fetch_json(console_url, session, keys_path(), &[], "list SSH keys")
}

fn create_key(
    console_url: &str,
    access_token: &str,
    label: &str,
    public_key: &str,
) -> Result<ConsoleSshKey, (ExitStatus, String)> {
    post_json(
        console_url,
        access_token,
        keys_path(),
        &json!({ "label": label, "public_key": public_key }),
        "add SSH key",
    )
}

fn delete_key(
    console_url: &str,
    access_token: &str,
    key_id: &str,
) -> Result<(), (ExitStatus, String)> {
    let response = send(
        Client::new()
            .delete(format!("{console_url}{}", key_path(key_id)))
            .bearer_auth(access_token),
        "remove SSH key",
    )?;
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
    use crate::commands::alias;
    use crate::test_support::{authenticated_config, MockConsole};
    use rstest::rstest;
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
        let dir = std::env::temp_dir().join(format!("umbra-key-add-{}", Uuid::new_v4()));
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
        let dir = std::env::temp_dir().join(format!("umbra-key-add-{}", Uuid::new_v4()));
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

    /// `key remove` (the real command) accepts the key by raw id OR by ssh-key
    /// alias (the alias resolves to the id like everywhere a key id is taken), then
    /// drops the alias pointing at the removed key while leaving unrelated aliases —
    /// the `Prune::Resource(SshKey, …)` auto-purge wiring, driven end-to-end against
    /// a mock Console `204`. The `by_alias` case is what the alias-resolution fix
    /// added; before it, `key remove laptop` failed with "KEY_ID must be a UUID".
    const KEY_ID: &str = "3c4c2b64-b059-41a6-b925-3e4816ffee60";

    #[rstest]
    #[case::by_id(KEY_ID)]
    #[case::by_alias("laptop")]
    fn test_key_remove_prune_success(#[case] target: &str) {
        const CVM_ID: &str = "9a7f6b4a-1111-2222-3333-444444444444";

        let console = MockConsole::start();
        let config = authenticated_config(&console);
        console.remove_key(KEY_ID);
        let mut store = alias::Aliases::default();
        store.ssh_key.insert("laptop".into(), KEY_ID.into());
        store.cvm.insert("box".into(), CVM_ID.into());
        alias::save(&config.config_dir, &store).expect("seed store");

        let status = run(
            KeyCommand::Remove {
                key_id: target.into(),
            },
            &config,
            false,
        );
        assert!(matches!(status, ExitStatus::Ok));

        let reloaded = alias::load(&config.config_dir).unwrap();
        assert!(
            reloaded.kind_of("laptop").is_none(),
            "the ssh-key alias must be pruned"
        );
        assert!(
            reloaded.kind_of("box").is_some(),
            "unrelated aliases must survive"
        );
    }

    /// `key add --alias` writes NO alias when the registration fails: the alias
    /// is recorded only after the Console accepts the key, so a failed add (here
    /// an empty mock Console that 404s the create call, with a real public key so
    /// we get past local validation) must leave the store empty.
    #[test]
    fn test_key_add_alias_failure() {
        let dir = std::env::temp_dir().join(format!("umbra-key-add-fail-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");
        let private_key = dir.join("id_ed25519");
        Command::new("ssh-keygen")
            .args(["-t", "ed25519", "-N", ""])
            .arg("-f")
            .arg(&private_key)
            .output()
            .expect("ssh-keygen succeeds");

        let console = MockConsole::start();
        let config = authenticated_config(&console);
        let status = run(
            KeyCommand::Add(KeyAddArgs {
                label: "laptop".into(),
                file: Some(private_key.with_extension("pub")),
                identity_file: None,
                alias: Some("nick".into()),
            }),
            &config,
            false,
        );
        assert!(!matches!(status, ExitStatus::Ok));
        assert!(
            alias::load(&config.config_dir)
                .unwrap()
                .kind_of("nick")
                .is_none(),
            "a failed add must not write an orphan alias"
        );
        fs::remove_dir_all(dir).expect("temp dir removed");
    }
}
