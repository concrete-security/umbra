//! Filesystem primitives shared across the CLI's local-state writers.
//!
//! The CLI persists several small files under `~/.umbra` (config, session,
//! aliases, SSH identities, per-CVM state, aTLS policy). They all need the same
//! fail-closed write: create the file owner-only, never follow a symlink, and
//! replace the target atomically so a concurrent reader never sees a partial or
//! half-written file. This module is the single home of that sequence, so the
//! callers only build their bytes and name a mode.
//!
//! Atomicity alone only protects a *reader*. A file that is updated by reloading
//! it, changing one key and writing it back also needs [`StoreLock`], or two
//! concurrent `umbra` processes each write a whole file built from the state
//! they read before the other one wrote.

use std::{
    fs::{self, OpenOptions},
    io::{self, Write},
    path::Path,
    time::{Duration, Instant},
};

#[cfg(unix)]
use std::os::unix::{
    fs::{OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};

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

/// How long to wait for another `umbra` process to release a store lock.
///
/// Bounded on purpose. A blocking `flock` with no deadline turns one stuck holder
/// into every later command hanging forever with no output at all — worse than a
/// clear failure. Every critical section this guards is pure local state
/// (microseconds), so reaching this bound means something is genuinely wrong.
const LOCK_WAIT: Duration = Duration::from_secs(10);

/// An exclusive advisory lock guarding one local-state file, held for the whole
/// read-modify-write so concurrent `umbra` processes cannot interleave their
/// load→mutate→save and clobber each other (last-writer-wins).
///
/// Taken on a dedicated `<name>.lock` sibling, never on the state file itself:
/// [`write_atomic_file`] replaces that inode by rename, which would drop a lock
/// held on it. Released when the guard drops. On non-unix it is a no-op
/// (best-effort), as with the mode hardening above.
pub(crate) struct StoreLock {
    #[cfg(unix)]
    file: fs::File,
}

impl StoreLock {
    /// Take the lock at `lock_path`, waiting up to [`LOCK_WAIT`] for a concurrent
    /// holder. Creates the parent directory and the (owner-only) lock file if
    /// absent.
    ///
    /// The parent's mode is repaired to `0700` **before** the lock file is opened:
    /// the open needs write permission on that directory, so a repair sequenced
    /// afterwards would sit behind the lock it cannot take. It also closes the window
    /// where `create_dir_all` leaves a fresh config directory at the caller's umask
    /// while a lock file is created inside it. Best-effort and skipped when the mode
    /// is already right — see the body for why neither is optional.
    pub(crate) fn acquire(lock_path: &Path) -> io::Result<Self> {
        if let Some(parent) = lock_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
            // Repaired only when the mode is not already exactly `0700`, and
            // best-effort — never `?`. Both halves matter: a directory that is too
            // TIGHT needs it as much as one that is too open, since the lock open
            // below needs owner-write; and a directory the caller does not own (a
            // shared `--config` path) cannot be repaired at all, where failing would
            // break commands that worked before this repair existed. Skipping the
            // already-correct case means the overwhelming majority of invocations
            // chmod nothing — `set_permissions` resolves symlinks, so a write nobody
            // asked for is worth avoiding. Confidentiality does not rest on this
            // either way: every file these stores write is `0600` regardless.
            #[cfg(unix)]
            if fs::metadata(parent)
                .map(|meta| meta.permissions().mode() & 0o777 != 0o700)
                .unwrap_or(false)
            {
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        #[cfg(unix)]
        {
            let mut options = OpenOptions::new();
            options.create(true).write(true).mode(0o600);
            // `O_NOFOLLOW` for the reason stated in this module's doc — and because
            // `write_atomic_file` above would be inconsistent otherwise. `O_NONBLOCK`
            // so a FIFO planted at this path fails instead of blocking in `open`
            // forever, which would wedge every write command with no diagnostic.
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            let file = options.open(lock_path)?;
            Self::lock_within(&file, LOCK_WAIT)?;
            Ok(Self { file })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }

    /// Poll for the exclusive lock until `budget` elapses.
    ///
    /// `LOCK_NB` rather than a blocking `LOCK_EX`: the blocking form cannot be
    /// bounded, and its failure mode is an indefinite silent hang.
    #[cfg(unix)]
    fn lock_within(file: &fs::File, budget: Duration) -> io::Result<()> {
        let deadline = Instant::now() + budget;
        loop {
            // SAFETY: `file` owns the fd and outlives the call.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(());
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::WouldBlock {
                return Err(err);
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    format!(
                        "another umbra process has held it for more than {}s",
                        budget.as_secs()
                    ),
                ));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

#[cfg(unix)]
impl Drop for StoreLock {
    fn drop(&mut self) {
        // Best-effort unlock; closing the fd would release it anyway.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

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

    fn is_locked(path: &Path) -> bool {
        let probe = fs::File::open(path).expect("lock file readable");
        // SAFETY: `probe` owns the fd for the duration of the call.
        let taken = unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
        if taken {
            unsafe { libc::flock(probe.as_raw_fd(), libc::LOCK_UN) };
        }
        !taken
    }

    /// The guard excludes others while alive and releases on drop, and the lock
    /// file and its directory are owner-only.
    ///
    /// Probed with `LOCK_NB`, never a blocking retake: the regression this guards
    /// against (a leaked fd, so the lock is never released) would make a blocking
    /// re-acquire hang, and `cargo test` has no per-test timeout — a hung CI run is
    /// far worse to diagnose than a failed assertion.
    #[cfg(unix)]
    #[test]
    fn store_lock_excludes_then_releases_success() {
        let dir = std::env::temp_dir().join(format!("umbra-fsutil-{}", uuid::Uuid::new_v4()));
        let lock_path = dir.join("state.lock");

        let guard = StoreLock::acquire(&lock_path).expect("lock taken");
        assert!(is_locked(&lock_path), "the guard must exclude others");
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&lock_path), 0o600, "lock file must be owner-only rw");
        assert_eq!(mode(&dir), 0o700, "acquire must tighten its directory");

        drop(guard);
        assert!(!is_locked(&lock_path), "dropping the guard must release it");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// A fresh directory for one hostile-path case, plus the lock path inside it.
    #[cfg(unix)]
    fn lock_dir() -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("umbra-fsutil-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir");
        (dir.clone(), dir.join("state.lock"))
    }

    /// The store directory ends at `0700` whatever it started as. Too TIGHT matters
    /// as much as too open: the lock file is opened inside it, so a `0500` directory
    /// would fail every write with the repair stuck behind the lock it cannot take.
    #[cfg(unix)]
    #[rstest]
    #[case::too_tight(0o500)]
    #[case::world_writable(0o777)]
    #[case::group_readable(0o750)]
    #[case::already_correct(0o700)]
    fn store_lock_repairs_directory_mode_success(#[case] initial: u32) {
        let (dir, lock_path) = lock_dir();
        fs::set_permissions(&dir, fs::Permissions::from_mode(initial)).expect("set mode");

        StoreLock::acquire(&lock_path).expect("lock taken whatever the mode was");

        let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "started at {initial:o}");
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// A FIFO where the lock file belongs must fail, not block. `open` on a FIFO
    /// waits for a peer, so without `O_NONBLOCK` every write command hangs forever
    /// with no diagnostic at all -- the worst failure mode available.
    #[cfg(unix)]
    #[test]
    fn store_lock_fifo_lock_path_failure() {
        let (dir, lock_path) = lock_dir();
        let name = std::ffi::CString::new(lock_path.as_os_str().as_encoded_bytes())
            .expect("path without NUL");
        assert_eq!(
            unsafe { libc::mkfifo(name.as_ptr(), 0o600) },
            0,
            "fifo made"
        );

        assert!(
            StoreLock::acquire(&lock_path).is_err(),
            "a FIFO must fail fast rather than block in open"
        );
        fs::remove_dir_all(dir).expect("cleanup");
    }

    /// A symlink where the lock file belongs must be refused, for the same reason
    /// [`write_atomic_file`] refuses one: it would take the lock on someone else's
    /// inode and create a file at a path the planter chose.
    #[cfg(unix)]
    #[test]
    fn store_lock_symlinked_lock_path_failure() {
        use std::os::unix::fs::symlink;
        let (dir, lock_path) = lock_dir();
        let victim = dir.join("victim");
        symlink(&victim, &lock_path).expect("plant symlink");

        assert!(
            StoreLock::acquire(&lock_path).is_err(),
            "O_NOFOLLOW must reject the symlinked lock path"
        );
        assert!(!victim.exists(), "nothing is created through the symlink");
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
