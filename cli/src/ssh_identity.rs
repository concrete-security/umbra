use std::{
    collections::HashSet,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use crate::{config::ResolvedConfig, exit::ExitStatus};

pub fn default_ssh_key_paths(ssh_dir: &Path) -> Result<(PathBuf, PathBuf), (ExitStatus, String)> {
    let preferred = ssh_dir.join("id_ed25519");
    let preferred_public = ssh_dir.join("id_ed25519.pub");
    if preferred.exists() || !preferred_public.exists() {
        return Ok((preferred, preferred_public));
    }
    for index in 0..100 {
        let name = if index == 0 {
            "concrete_ed25519".to_string()
        } else {
            format!("concrete_ed25519_{index}")
        };
        let private_key = ssh_dir.join(&name);
        let public_key = ssh_dir.join(format!("{name}.pub"));
        if !private_key.exists() && !public_key.exists() {
            return Ok((private_key, public_key));
        }
    }
    Err((
        ExitStatus::Error,
        format!(
            "[error] failed to find an unused SSH key path under {}",
            ssh_dir.display()
        ),
    ))
}

pub fn discover_private_key_for_fingerprints(fingerprints: &[String]) -> Option<PathBuf> {
    let ssh_dir = home::home_dir()?.join(".ssh");
    discover_private_key_for_fingerprints_in(&ssh_dir, fingerprints)
}

pub fn discover_private_key_for_fingerprints_in(
    ssh_dir: &Path,
    fingerprints: &[String],
) -> Option<PathBuf> {
    if fingerprints.is_empty() {
        return None;
    }
    let wanted: HashSet<&str> = fingerprints.iter().map(String::as_str).collect();
    let entries = fs::read_dir(ssh_dir).ok()?;
    let mut matches = Vec::new();
    for entry in entries.flatten() {
        let public_key = entry.path();
        if public_key.extension().and_then(|ext| ext.to_str()) != Some("pub") {
            continue;
        }
        let Some(fingerprint) = public_key_fingerprint(&public_key) else {
            continue;
        };
        if !wanted.contains(fingerprint.as_str()) {
            continue;
        }
        let Some(stem) = public_key.file_stem().and_then(|value| value.to_str()) else {
            continue;
        };
        let private_key = public_key.with_file_name(stem);
        if private_key.is_file() {
            matches.push(private_key);
        }
    }
    matches.sort();
    matches.into_iter().next()
}

pub fn resolve_session_identity(
    config: &ResolvedConfig,
    explicit: Option<&Path>,
    installed_key_fingerprints: &[String],
) -> Result<Option<PathBuf>, (ExitStatus, String)> {
    if let Some(path) = explicit {
        return resolve_explicit_identity(path).map(Some);
    }
    Ok(resolve_session_identity_in(
        home::home_dir().map(|home| home.join(".ssh")).as_deref(),
        config.default_ssh_identity.as_deref(),
        installed_key_fingerprints,
    ))
}

pub fn resolve_explicit_identity(path: &Path) -> Result<PathBuf, (ExitStatus, String)> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }
    Err((
        ExitStatus::Usage,
        format!(
            "[usage] SSH identity file {} does not exist or is not a file",
            path.display()
        ),
    ))
}

fn resolve_session_identity_in(
    ssh_dir: Option<&Path>,
    default_identity: Option<&Path>,
    installed_key_fingerprints: &[String],
) -> Option<PathBuf> {
    let wanted: HashSet<&str> = installed_key_fingerprints
        .iter()
        .map(String::as_str)
        .collect();
    if let Some(path) = default_identity {
        if path.is_file()
            && (wanted.is_empty() || private_key_matches_fingerprints_set(path, &wanted))
        {
            return Some(path.to_path_buf());
        }
    }
    ssh_dir
        .and_then(|dir| discover_private_key_for_fingerprints_in(dir, installed_key_fingerprints))
}

pub fn persistable_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

pub fn public_key_fingerprint(path: &Path) -> Option<String> {
    let output = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(path)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_fingerprint_line(&String::from_utf8_lossy(&output.stdout))
}

pub fn public_key_text_fingerprint(public_key: &str) -> Option<String> {
    let mut child = Command::new("ssh-keygen")
        .arg("-lf")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    {
        let mut stdin = child.stdin.take()?;
        stdin.write_all(public_key.as_bytes()).ok()?;
        if !public_key.ends_with('\n') {
            stdin.write_all(b"\n").ok()?;
        }
    }
    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_fingerprint_line(&String::from_utf8_lossy(&output.stdout))
}

pub fn private_key_fingerprint(private_key: &Path) -> Option<String> {
    let output = Command::new("ssh-keygen")
        .arg("-y")
        .arg("-f")
        .arg(private_key)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let public_key = String::from_utf8_lossy(&output.stdout);
    public_key_text_fingerprint(&public_key)
}

pub fn private_key_matches_fingerprints(private_key: &Path, fingerprints: &[String]) -> bool {
    let wanted: HashSet<&str> = fingerprints.iter().map(String::as_str).collect();
    private_key_matches_fingerprints_set(private_key, &wanted)
}

fn private_key_matches_fingerprints_set(private_key: &Path, wanted: &HashSet<&str>) -> bool {
    if wanted.is_empty() {
        return false;
    }
    private_key_fingerprint(private_key)
        .map(|fingerprint| wanted.contains(fingerprint.as_str()))
        .unwrap_or(false)
}

fn parse_fingerprint_line(line: &str) -> Option<String> {
    let fingerprint = line.split_whitespace().nth(1)?;
    fingerprint
        .starts_with("SHA256:")
        .then(|| fingerprint.to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        default_ssh_key_paths, discover_private_key_for_fingerprints_in, public_key_fingerprint,
        resolve_session_identity_in,
    };
    use std::{
        fs,
        path::PathBuf,
        process::{Command, Stdio},
    };
    use uuid::Uuid;

    #[test]
    fn default_ssh_key_paths_prefers_id_ed25519_when_unused() {
        let dir = std::env::temp_dir().join(format!("concrete-cvm-key-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");

        let (private_key, public_key) = default_ssh_key_paths(&dir).expect("key paths resolved");

        assert_eq!(private_key, dir.join("id_ed25519"));
        assert_eq!(public_key, dir.join("id_ed25519.pub"));
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    #[test]
    fn default_ssh_key_paths_does_not_target_existing_public_key_without_private_key() {
        let dir = std::env::temp_dir().join(format!("concrete-cvm-key-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");
        fs::write(dir.join("id_ed25519.pub"), "ssh-ed25519 existing\n")
            .expect("public key written");

        let (private_key, public_key) = default_ssh_key_paths(&dir).expect("key paths resolved");

        assert_eq!(private_key, dir.join("concrete_ed25519"));
        assert_eq!(public_key, dir.join("concrete_ed25519.pub"));
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    #[test]
    fn discover_private_key_matches_local_public_key_fingerprint() {
        let dir = std::env::temp_dir().join(format!("concrete-ssh-id-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");
        let private_key = dir.join("id_ed25519");
        let public_key = dir.join("id_ed25519.pub");
        Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&private_key)
            .stdin(Stdio::null())
            .output()
            .expect("ssh-keygen succeeds");
        let fingerprint =
            public_key_fingerprint(&public_key).expect("fingerprint parsed for generated key");
        let discovered =
            discover_private_key_for_fingerprints_in(&dir, std::slice::from_ref(&fingerprint))
                .expect("local private key discovered");
        assert_eq!(discovered, private_key);
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    #[test]
    fn discover_private_key_skips_malformed_public_keys() {
        let dir = std::env::temp_dir().join(format!("concrete-ssh-id-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");
        fs::write(dir.join("broken.pub"), "not an ssh public key\n").expect("broken key written");
        let private_key = dir.join("id_ed25519");
        let public_key = dir.join("id_ed25519.pub");
        Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&private_key)
            .stdin(Stdio::null())
            .output()
            .expect("ssh-keygen succeeds");
        let fingerprint =
            public_key_fingerprint(&public_key).expect("fingerprint parsed for generated key");
        let discovered =
            discover_private_key_for_fingerprints_in(&dir, std::slice::from_ref(&fingerprint))
                .expect("local private key discovered");

        assert_eq!(discovered, private_key);
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    #[test]
    fn resolve_session_identity_ignores_stale_default_identity() {
        let dir = std::env::temp_dir().join(format!("concrete-ssh-id-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");
        let stale_private_key = dir.join("stale_ed25519");
        Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&stale_private_key)
            .stdin(Stdio::null())
            .output()
            .expect("ssh-keygen succeeds");
        let matching_private_key = dir.join("matching_ed25519");
        let matching_public_key = dir.join("matching_ed25519.pub");
        Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&matching_private_key)
            .stdin(Stdio::null())
            .output()
            .expect("ssh-keygen succeeds");
        let fingerprint = public_key_fingerprint(&matching_public_key)
            .expect("fingerprint parsed for matching key");

        let resolved =
            resolve_session_identity_in(Some(&dir), Some(&stale_private_key), &[fingerprint])
                .expect("matching identity resolved");

        assert_eq!(resolved, matching_private_key);
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    #[test]
    fn resolve_session_identity_uses_matching_default_identity() {
        let dir = std::env::temp_dir().join(format!("concrete-ssh-id-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");
        let private_key = dir.join("default_ed25519");
        let public_key = dir.join("default_ed25519.pub");
        Command::new("ssh-keygen")
            .arg("-t")
            .arg("ed25519")
            .arg("-N")
            .arg("")
            .arg("-f")
            .arg(&private_key)
            .stdin(Stdio::null())
            .output()
            .expect("ssh-keygen succeeds");
        let fingerprint =
            public_key_fingerprint(&public_key).expect("fingerprint parsed for default key");

        let resolved = resolve_session_identity_in(Some(&dir), Some(&private_key), &[fingerprint])
            .expect("default identity resolved");

        assert_eq!(resolved, private_key);
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    #[test]
    fn resolve_session_identity_returns_none_without_local_match() {
        let dir = std::env::temp_dir().join(format!("concrete-ssh-id-test-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");

        let resolved = resolve_session_identity_in(
            Some(&dir),
            Some(&PathBuf::from("/missing/key")),
            &["SHA256:not-present".to_string()],
        );

        assert_eq!(resolved, None);
        fs::remove_dir_all(dir).expect("temp dir removed");
    }
}
