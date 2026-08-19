use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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

    let lock_path = config_dir.join("ssh-identities.lock");
    let _guard = crate::fsutil::StoreLock::acquire(&lock_path).map_err(|err| {
        io::Error::other(format!("failed to lock {}: {err}", lock_path.display()))
    })?;

    let path = store_path(config_dir);
    let mut keys = read(config_dir)
        .into_iter()
        .map(|(key_id, path)| (key_id, path.display().to_string()))
        .collect::<BTreeMap<_, _>>();
    keys.insert(key_id.to_string(), identity_file.display().to_string());

    let body = toml::to_string_pretty(&StoreFileOut { keys: &keys }).map_err(io::Error::other)?;
    crate::fsutil::write_atomic_file(&path, body.as_bytes(), 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn write_identity_merges_existing_entries() {
        let dir = std::env::temp_dir().join(format!("umbra-ssh-store-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");

        write_identity(&dir, "key-1", Path::new("/tmp/key-1")).expect("first key written");
        write_identity(&dir, "key-2", Path::new("/tmp/key-2")).expect("second key written");

        let stored = read(&dir);
        assert_eq!(stored.get("key-1"), Some(&PathBuf::from("/tmp/key-1")));
        assert_eq!(stored.get("key-2"), Some(&PathBuf::from("/tmp/key-2")));
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    #[test]
    fn write_identity_concurrent_success() {
        use std::sync::{Arc, Barrier};

        let dir = std::env::temp_dir().join(format!("umbra-ssh-store-{}", Uuid::new_v4()));
        let barrier = Arc::new(Barrier::new(8));
        let workers = (0..8)
            .map(|n| {
                let (dir, barrier) = (dir.clone(), Arc::clone(&barrier));
                std::thread::spawn(move || {
                    barrier.wait();
                    write_identity(&dir, &format!("key-{n}"), Path::new("/tmp/key"))
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().expect("worker done").expect("key written");
        }

        assert_eq!(read(&dir).len(), 8);
        fs::remove_dir_all(dir).expect("temp dir removed");
    }
}
