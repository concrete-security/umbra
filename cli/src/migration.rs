//! First-use import of Concrete's durable local state. Existing Umbra stores win.

use std::{
    fs::{self, OpenOptions},
    io::{self, Read},
    path::Path,
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use crate::{config, fsutil};

const STATE_FILES: &[&str] = &[
    "config.toml",
    "session.json",
    "aliases.toml",
    "ssh-identities.toml",
];

pub(crate) fn prepare(config_override: Option<&Path>) -> Result<(), String> {
    if config_override.is_some() || config::config_env_os("UMBRA_CONFIG_DIR").is_some() {
        return Ok(());
    }
    let Some(home) = home::home_dir() else {
        return Ok(());
    };
    migrate(&home).map_err(|err| {
        format!("[error] could not migrate Concrete state to ~/.umbra: {err}; original ~/.concrete state is retained")
    })
}

fn migrate(home: &Path) -> io::Result<()> {
    let legacy = home.join(".concrete");
    let current = home.join(".umbra");
    if !empty_or_absent(&current)? || !directory_exists(&legacy)? {
        return Ok(());
    }
    // Use a dedicated directory: StoreLock tightens its parent to 0700, so a
    // lock directly in HOME would change the user's home-directory permissions.
    let work = home.join(".umbra-migration");
    directory_exists(&work)?;
    let _lock = fsutil::StoreLock::acquire(&work.join("migration.lock"))?;
    if !empty_or_absent(&current)? {
        return Ok(());
    }
    let stage = work.join(format!("stage-{}", uuid::Uuid::new_v4()));
    create_private_dir(&stage)?;
    let result = (|| {
        for name in STATE_FILES {
            copy_state_file(&legacy.join(name), &stage.join(name))?;
        }
        let cvms = legacy.join("cvms");
        if directory_exists(&cvms)? {
            let target = stage.join("cvms");
            create_private_dir(&target)?;
            for entry in fs::read_dir(&cvms)? {
                let entry = entry?;
                let name = entry.file_name();
                let text = name.to_string_lossy();
                if text.ends_with(".atls-policy.json") || text.ends_with(".state.toml") {
                    copy_state_file(&entry.path(), &target.join(name))?;
                }
            }
        }
        // Import all files before exposing the store to command readers. Never
        // remove a populated destination, even if another process created it.
        if directory_exists(&current)? {
            fs::remove_dir(&current)?;
        }
        fs::rename(&stage, &current)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(stage);
    }
    result
}

fn directory_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => Ok(true),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "state directory must be a real directory",
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

fn empty_or_absent(path: &Path) -> io::Result<bool> {
    Ok(!directory_exists(path)? || fs::read_dir(path)?.next().is_none())
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(path)
}

fn copy_state_file(source: &Path, target: &Path) -> io::Result<()> {
    match fs::symlink_metadata(source) {
        Ok(metadata) if metadata.is_file() => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "state file must be a regular file",
            ));
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = match options.open(source) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "state file must be a regular file",
        ));
    }
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    fsutil::write_atomic_file(target, &data, 0o600)
}
