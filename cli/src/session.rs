use std::{
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entity {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub user_id: String,
    pub email: String,
    pub entity: Entity,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub refresh_expires_at: Option<DateTime<Utc>>,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.access_token.zeroize();
        if let Some(refresh_token) = &mut self.refresh_token {
            refresh_token.zeroize();
        }
    }
}

pub fn session_path(config_dir: &Path) -> PathBuf {
    config_dir.join("session.json")
}

pub fn load(config_dir: &Path) -> Result<Option<Session>, String> {
    let path = session_path(config_dir);
    if !path.exists() {
        return Ok(None);
    }
    let data = fs::read_to_string(&path)
        .map_err(|err| format!("[error] failed to read session file: {err}"))?;
    serde_json::from_str(&data)
        .map(Some)
        .map_err(|err| format!("[error] malformed session file: {err}"))
}

pub fn remove(config_dir: &Path) -> Result<bool, String> {
    let _lock = session_lock(config_dir)?;
    let path = session_path(config_dir);
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!("[error] failed to remove session file: {err}")),
    }
}

pub fn write_atomic(config_dir: &Path, session: &Session) -> Result<(), String> {
    let _lock = session_lock(config_dir)?;
    write_unlocked(config_dir, session)
}

/// Replace only the exact snapshot refreshed by this process; preserve another login.
pub(crate) fn replace_if_current(
    config_dir: &Path,
    expected: &Session,
    next: &Session,
) -> Result<bool, String> {
    let _lock = session_lock(config_dir)?;
    if load(config_dir)?.as_ref() != Some(expected) {
        return Ok(false);
    }
    write_unlocked(config_dir, next)?;
    Ok(true)
}

fn session_lock(config_dir: &Path) -> Result<crate::fsutil::StoreLock, String> {
    ensure_config_dir(config_dir)?;
    crate::fsutil::StoreLock::acquire(&config_dir.join("session.json.lock"))
        .map_err(|_| "[error] could not lock local session".to_string())
}

fn write_unlocked(config_dir: &Path, session: &Session) -> Result<(), String> {
    ensure_config_dir(config_dir)?;
    let target = session_path(config_dir);
    let data = Zeroizing::new(
        serde_json::to_vec_pretty(session)
            .map_err(|err| format!("[error] failed to serialize session: {err}"))?,
    );
    crate::fsutil::write_atomic_file(&target, &data, 0o600)
        .map_err(|err| format!("[error] failed to write session file: {err}"))?;
    Ok(())
}

pub fn mode_string(config_dir: &Path) -> Option<String> {
    let metadata = fs::symlink_metadata(session_path(config_dir)).ok()?;
    #[cfg(unix)]
    {
        Some(format!("{:04o}", metadata.permissions().mode() & 0o777))
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

fn ensure_config_dir(config_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(config_dir)
        .map_err(|err| format!("[error] failed to create config directory: {err}"))?;
    #[cfg(unix)]
    {
        fs::set_permissions(config_dir, fs::Permissions::from_mode(0o700)).map_err(|err| {
            format!("[error] failed to tighten config directory permissions: {err}")
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config_dir() -> PathBuf {
        std::env::temp_dir().join(format!("umbra-cli-test-{}", uuid::Uuid::new_v4()))
    }

    fn sample_session() -> Session {
        Session {
            access_token: "access-token".to_string(),
            refresh_token: Some("refresh-token".to_string()),
            user_id: "user-1".to_string(),
            email: "user@example.com".to_string(),
            entity: Entity {
                id: "entity-1".to_string(),
                name: "Example".to_string(),
            },
            expires_at: DateTime::parse_from_rfc3339("2026-05-15T17:00:00Z")
                .expect("valid timestamp")
                .with_timezone(&Utc),
            refresh_expires_at: Some(
                DateTime::parse_from_rfc3339("2026-05-16T17:00:00Z")
                    .expect("valid timestamp")
                    .with_timezone(&Utc),
            ),
        }
    }

    #[test]
    fn write_load_and_remove_session() {
        let config_dir = temp_config_dir();
        let session = sample_session();

        write_atomic(&config_dir, &session).expect("session write succeeds");
        let loaded = load(&config_dir)
            .expect("session read succeeds")
            .expect("session exists");

        assert_eq!(loaded.access_token, "access-token");
        assert_eq!(loaded.refresh_token.as_deref(), Some("refresh-token"));
        assert_eq!(loaded.email, "user@example.com");
        assert!(remove(&config_dir).expect("session remove succeeds"));
        assert!(!remove(&config_dir).expect("missing session remove succeeds"));

        fs::remove_dir_all(config_dir).expect("test config dir removed");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_sets_private_unix_modes() {
        let config_dir = temp_config_dir();
        let session = sample_session();

        write_atomic(&config_dir, &session).expect("session write succeeds");

        let dir_mode = fs::symlink_metadata(&config_dir)
            .expect("config dir metadata exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert_eq!(mode_string(&config_dir).as_deref(), Some("0600"));

        remove(&config_dir).expect("session remove succeeds");
        fs::remove_dir_all(config_dir).expect("test config dir removed");
    }

    /// A refresh may replace only the exact stored snapshot, under the shared lock.
    #[test]
    fn replace_current_snapshot_success() {
        let dir = temp_config_dir();
        let old = sample_session();
        write_atomic(&dir, &old).unwrap();
        let mut next = old.clone();
        next.access_token = "rotated-fixture".into();
        assert!(replace_if_current(&dir, &old, &next).unwrap());
        assert!(load(&dir).unwrap().as_ref() == Some(&next));
        fs::remove_dir_all(dir).unwrap();
    }

    /// A stale refresh must preserve another login or leave a removed session absent.
    #[rstest::rstest]
    #[case::login(false)]
    #[case::logout(true)]
    fn replace_changed_snapshot_preserves_current_failure(#[case] logout: bool) {
        let dir = temp_config_dir();
        let old = sample_session();
        write_atomic(&dir, &old).unwrap();
        let mut other = old.clone();
        other.access_token = "other-login-fixture".into();
        if logout {
            remove(&dir).unwrap();
        } else {
            write_atomic(&dir, &other).unwrap();
        }
        let mut next = old.clone();
        next.access_token = "stale-refresh-fixture".into();
        assert!(!replace_if_current(&dir, &old, &next).unwrap());
        assert!(if logout {
            load(&dir).unwrap().is_none()
        } else {
            load(&dir).unwrap().as_ref() == Some(&other)
        });
        fs::remove_dir_all(dir).unwrap();
    }

    /// Every session writer/remover must respect the lock used by conditional replacement.
    #[cfg(unix)]
    #[rstest::rstest]
    #[case::writer(false)]
    #[case::remover(true)]
    fn session_mutators_share_store_lock_success(#[case] removing: bool) {
        use std::{sync::mpsc, thread, time::Duration};
        let dir = temp_config_dir();
        let old = sample_session();
        write_atomic(&dir, &old).unwrap();
        let held = session_lock(&dir).unwrap();
        let target = dir.clone();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let child = thread::spawn(move || {
            ready_tx.send(()).unwrap();
            if removing {
                remove(&target).unwrap();
            } else {
                write_atomic(&target, &old).unwrap();
            }
            done_tx.send(()).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(held);
        done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        child.join().unwrap();
        assert_eq!(load(&dir).unwrap().is_none(), removing);
        fs::remove_dir_all(dir).unwrap();
    }
}
