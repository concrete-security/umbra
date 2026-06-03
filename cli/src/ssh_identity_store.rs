use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};

#[derive(Default, Deserialize)]
struct StoreFileIn {
    keys: Option<BTreeMap<String, String>>,
}

#[derive(Serialize)]
struct StoreFileOut<'a> {
    keys: &'a BTreeMap<String, String>,
}

pub fn store_path(config_dir: &Path) -> PathBuf {
    config_dir.join("ssh-identities.toml")
}

pub fn read(config_dir: &Path) -> BTreeMap<String, PathBuf> {
    let path = store_path(config_dir);
    let Ok(data) = fs::read_to_string(path) else {
        return BTreeMap::new();
    };
    let Ok(parsed) = toml::from_str::<StoreFileIn>(&data) else {
        return BTreeMap::new();
    };
    parsed
        .keys
        .unwrap_or_default()
        .into_iter()
        .map(|(key_id, path)| (key_id, PathBuf::from(path)))
        .collect()
}

pub fn write_identity(config_dir: &Path, key_id: &str, identity_file: &Path) -> io::Result<()> {
    fs::create_dir_all(config_dir)?;
    #[cfg(unix)]
    {
        fs::set_permissions(config_dir, fs::Permissions::from_mode(0o700))?;
    }

    let path = store_path(config_dir);
    let mut keys = read(config_dir)
        .into_iter()
        .map(|(key_id, path)| (key_id, path.display().to_string()))
        .collect::<BTreeMap<_, _>>();
    keys.insert(key_id.to_string(), identity_file.display().to_string());

    let body = toml::to_string_pretty(&StoreFileOut { keys: &keys }).map_err(io::Error::other)?;
    let tmp = config_dir.join(format!(".ssh-identities.{}.tmp", std::process::id()));
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts.open(&tmp)?;
    file.write_all(body.as_bytes())?;
    file.sync_all()?;
    fs::rename(&tmp, &path)?;
    #[cfg(unix)]
    {
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn write_identity_merges_existing_entries() {
        let dir = std::env::temp_dir().join(format!("concrete-ssh-store-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");

        write_identity(&dir, "key-1", Path::new("/tmp/key-1")).expect("first key written");
        write_identity(&dir, "key-2", Path::new("/tmp/key-2")).expect("second key written");

        let stored = read(&dir);
        assert_eq!(stored.get("key-1"), Some(&PathBuf::from("/tmp/key-1")));
        assert_eq!(stored.get("key-2"), Some(&PathBuf::from("/tmp/key-2")));
        fs::remove_dir_all(dir).expect("temp dir removed");
    }
}
