//! A final legacy update artifact whose command implementation is Umbra.
//!
//! Concrete 0.4.x executes the staged artifact with --version BEFORE renaming
//! it. That is the only hook available to prepare the new command in one update.

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::ExitCode,
};

#[cfg(unix)]
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};

use crate::{config, exit::ExitStatus, fsutil, migration, style};

pub(crate) const BRIDGE_VERSION: &str = "1.0.0";
const VERIFIER_NAME: &str = ".umbra-slsa-verifier-v2.7.1";
const VERIFIER: &[u8] = include_bytes!(env!("UMBRA_BRIDGE_VERIFIER_PATH"));
const INSTALL_ORIGIN: &str = env!("UMBRA_BRIDGE_INSTALL_BASE_URL");

pub(crate) fn run() -> ExitCode {
    let executable = match env::current_exe() {
        Ok(path) => path,
        Err(err) => {
            style::eprintln_error(&format!("[error] cannot locate migration bridge: {err}"));
            return ExitCode::from(ExitStatus::Error);
        }
    };
    let invoked_as_umbra = env::args_os()
        .next()
        .and_then(|arg| PathBuf::from(arg).file_name().map(|name| name == "umbra"))
        .unwrap_or(false);
    let version_probe = env::args_os().skip(1).collect::<Vec<_>>() == ["--version"];
    let staged = executable
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(".concrete-update.") && name.ends_with(".tmp"));
    if staged || !invoked_as_umbra {
        if let Err(err) = prepare(&executable, env::var_os("PATH")) {
            style::eprintln_error(&format!(
                "[error] Concrete-to-Umbra migration failed: {err}"
            ));
            return ExitCode::from(ExitStatus::Error);
        }
        if version_probe && staged {
            println!("concrete-update-bridge {BRIDGE_VERSION}");
            return ExitCode::SUCCESS;
        }
    }
    crate::run()
}

fn prepare(executable: &Path, search_path: Option<std::ffi::OsString>) -> io::Result<()> {
    let directory = executable.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "bridge has no parent directory",
        )
    })?;
    let concrete = directory.join("concrete");
    let concrete = fs::canonicalize(concrete)?;
    // The old updater resolves symlinks before replacing the executable. Find
    // the PATH-visible Concrete shim so the new name is visible there too.
    let search_directories = search_path
        .map(|path| env::split_paths(&path).collect::<Vec<_>>())
        .unwrap_or_default();
    let public_directory = search_directories
        .iter()
        .filter(|entry| entry.is_absolute())
        .find(|entry| fs::canonicalize(entry.join("concrete")).ok().as_ref() == Some(&concrete))
        .cloned()
        .unwrap_or_else(|| directory.to_path_buf());
    let umbra = public_directory.join("umbra");
    let alias_present = match fs::symlink_metadata(&umbra) {
        Ok(metadata)
            if metadata.file_type().is_symlink()
                && fs::read_link(&umbra)? == Path::new("concrete") =>
        {
            true
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "an existing Umbra command is preserved; update that installation separately",
            ))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => false,
        Err(err) => return Err(err),
    };
    // An alias in this directory must not hide another installation on PATH
    // or leave an earlier, unrelated Umbra command selected by the shell.
    for entry in &search_directories {
        let candidate = entry.join("umbra");
        if candidate != umbra
            && crate::commands::update::executable_file(&candidate)
            && fs::canonicalize(&candidate).ok().as_ref() != Some(&concrete)
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "an existing Umbra command is preserved; update that installation separately",
            ));
        }
    }
    install_verifier(&public_directory)?;
    migration::prepare(None).map_err(io::Error::other)?;
    let origin = url::Url::parse(INSTALL_ORIGIN).map_err(io::Error::other)?;
    if origin.scheme() != "https"
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "migration requires an approved HTTPS Umbra install origin",
        ));
    }
    let resolved = config::ResolvedConfig::resolve(config::ConfigOverrides::default());
    config::locked_update(&resolved.config_dir, |table| {
        if table.contains_key("install_base_url") {
            return Ok(false);
        }
        table.insert(
            "install_base_url".into(),
            toml::Value::String(INSTALL_ORIGIN.into()),
        );
        Ok(true)
    })
    .map_err(io::Error::other)?;
    if !alias_present {
        #[cfg(unix)]
        symlink("concrete", &umbra)?;
        #[cfg(not(unix))]
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "legacy bridge supports Linux and macOS",
        ));
    }
    Ok(())
}

fn install_verifier(directory: &Path) -> io::Result<()> {
    let destination = directory.join(VERIFIER_NAME);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) if metadata.is_file() => return check_existing_verifier(&destination),
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "an existing migration verifier has different contents",
            ))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let temporary = directory.join(format!(".umbra-verifier-{}", uuid::Uuid::new_v4()));
    fsutil::write_atomic_file(&temporary, VERIFIER, 0o755)?;
    // No-clobber publication: a concurrent installer cannot replace another
    // user's executable through a race between the check and the write.
    let published = fs::hard_link(&temporary, &destination);
    let _ = fs::remove_file(temporary);
    match published {
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            check_existing_verifier(&destination)
        }
        result => result,
    }
}

// Retry after an interrupted update must also restore executable permissions.
fn check_existing_verifier(path: &Path) -> io::Result<()> {
    use std::io::Read;

    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = options.open(path)?;
    let mut bytes = Vec::new();
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "migration verifier must be a regular file",
        ));
    }
    file.read_to_end(&mut bytes)?;
    if bytes != VERIFIER {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "an existing migration verifier has different contents",
        ));
    }
    #[cfg(unix)]
    if file.metadata()?.permissions().mode() & 0o777 != 0o755 {
        file.set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}
