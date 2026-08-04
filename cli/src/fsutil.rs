//! Filesystem primitives shared across the CLI's local-state writers.
//!
//! The CLI persists several small files under `~/.umbra` (config, session,
//! aliases, SSH identities, per-CVM state, aTLS policy). They all need the same
//! fail-closed write: create the file owner-only, never follow a symlink, and
//! replace the target atomically so a concurrent reader never sees a partial or
//! half-written file. This module is the single home of that sequence, so the
//! callers only build their bytes and name a mode.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

/// Write `data` to `path` atomically, owner-controlled at `mode`.
///
/// Creates the parent directory if missing, writes a sibling
/// `.<name>.<pid>.tmp` opened with `mode` + `O_NOFOLLOW`, fsyncs it, then
/// `rename`s it over `path` — so a reader sees either the old file or the whole
/// new one, never a truncated write. The parent directory's own permissions are
/// the caller's concern (some callers tighten it to `0700`); this only governs
/// the file. On non-unix the `mode`/`O_NOFOLLOW` hardening is skipped
/// (best-effort), as elsewhere in the CLI.
pub(crate) fn write_atomic_file(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    #[cfg(not(unix))]
    let _ = mode;
    let parent = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    fs::create_dir_all(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("umbra");
    let tmp = parent.join(format!(".{name}.{}.tmp", std::process::id()));

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(mode).custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    fs::rename(&tmp, path)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The write replaces the target atomically and, on unix, leaves it
    /// owner-only at the requested mode — the invariant every local-state file
    /// relies on. Also checks the temp file is not left behind.
    #[test]
    fn write_atomic_file_replaces_and_restricts_success() {
        let dir = std::env::temp_dir().join(format!("umbra-fsutil-{}", uuid::Uuid::new_v4()));
        let target = dir.join("state.toml");
        write_atomic_file(&target, b"old", 0o600).expect("first write");
        write_atomic_file(&target, b"new", 0o600).expect("replacing write");

        assert_eq!(fs::read(&target).expect("read back"), b"new");
        #[cfg(unix)]
        {
            let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "file must be owner-only rw");
        }
        // No leftover temp sibling.
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "temp file must be renamed away");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// The temp file is opened with `O_NOFOLLOW`, so a symlink pre-planted at the
    /// temp path cannot redirect the write: the open fails instead of following
    /// it, and the symlink's target is never created.
    #[cfg(unix)]
    #[test]
    fn write_atomic_file_rejects_symlinked_temp_failure() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("umbra-fsutil-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir");
        let target = dir.join("state.toml");
        // Reproduce write_atomic_file's temp name and pre-plant a symlink there,
        // pointing at a victim path that must never be written through.
        let tmp = dir.join(format!(".state.toml.{}.tmp", std::process::id()));
        let victim = dir.join("victim");
        symlink(&victim, &tmp).expect("plant symlink");

        assert!(
            write_atomic_file(&target, b"data", 0o600).is_err(),
            "O_NOFOLLOW must reject the symlinked temp"
        );
        assert!(!victim.exists(), "write must not have followed the symlink");
        fs::remove_dir_all(dir).expect("cleanup");
    }
}
