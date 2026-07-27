use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::commands::ssh::validate_workspace_path;

#[derive(Default, Debug, Clone)]
pub struct CvmState {
    pub workspace: Option<String>,
}

#[derive(Deserialize)]
struct StateFileIn {
    workspace: Option<String>,
}

#[derive(Serialize)]
struct StateFileOut<'a> {
    workspace: &'a str,
}

pub fn state_path(config_dir: &Path, cvm_id: &str) -> PathBuf {
    config_dir.join("cvms").join(format!("{cvm_id}.state.toml"))
}

pub fn read(config_dir: &Path, cvm_id: &str) -> CvmState {
    let path = state_path(config_dir, cvm_id);
    let Ok(data) = fs::read_to_string(&path) else {
        return CvmState::default();
    };
    let Ok(parsed) = toml::from_str::<StateFileIn>(&data) else {
        return CvmState::default();
    };
    let workspace = parsed
        .workspace
        .filter(|value| validate_workspace_path(value).is_ok());
    CvmState { workspace }
}

pub fn write_workspace(config_dir: &Path, cvm_id: &str, workspace: &str) -> io::Result<()> {
    let path = state_path(config_dir, cvm_id);
    let body = toml::to_string(&StateFileOut { workspace }).map_err(io::Error::other)?;
    crate::fsutil::write_atomic_file(&path, body.as_bytes(), 0o600)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use uuid::Uuid;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = env::temp_dir().join(format!("concrete-cvm-state-{}", Uuid::new_v4()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn read_returns_default_when_file_missing() {
        let dir = TempDir::new();
        let state = read(dir.path(), "missing-cvm");
        assert_eq!(state.workspace, None);
    }

    #[test]
    fn write_then_read_round_trips_workspace() {
        let dir = TempDir::new();
        write_workspace(dir.path(), "cvm-1", "workspaces/myrepo").unwrap();
        let state = read(dir.path(), "cvm-1");
        assert_eq!(state.workspace.as_deref(), Some("workspaces/myrepo"));
    }

    #[test]
    fn read_ignores_workspace_failing_validation() {
        let dir = TempDir::new();
        let path = state_path(dir.path(), "cvm-1");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, "workspace = \"../evil\"\n").unwrap();
        let state = read(dir.path(), "cvm-1");
        assert_eq!(state.workspace, None);
    }
}
