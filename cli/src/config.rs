use std::{
    env, fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
struct ConfigFile {
    console_url: Option<String>,
    default_profile: Option<String>,
    oidc_client_id: Option<String>,
    oidc_provider: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub config_dir: PathBuf,
    pub config_dir_source: ConfigSource,
    pub console_url: Option<String>,
    pub console_url_source: ConfigSource,
    pub profile: Option<String>,
    pub oidc_client_id: String,
    pub oidc_client_id_source: ConfigSource,
    pub oidc_provider: String,
    pub oidc_provider_source: ConfigSource,
}

#[derive(Debug, Clone, Copy)]
pub enum ConfigSource {
    Flag,
    Env,
    File,
    Default,
    Missing,
}

impl ConfigSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::Env => "env",
            Self::File => "file",
            Self::Default => "default",
            Self::Missing => "missing",
        }
    }
}

impl ResolvedConfig {
    pub fn resolve(
        config_dir_flag: Option<PathBuf>,
        console_url_flag: Option<String>,
        profile_flag: Option<String>,
    ) -> Self {
        let (config_dir, config_dir_source) = if let Some(value) = config_dir_flag {
            (value, ConfigSource::Flag)
        } else if let Some(value) = env::var_os("CONCRETE_CONFIG_DIR").map(PathBuf::from) {
            (value, ConfigSource::Env)
        } else {
            (default_config_dir(), ConfigSource::Default)
        };
        let file = read_config_file(&config_dir).unwrap_or_default();
        let (console_url, console_url_source) = if let Some(value) = console_url_flag {
            (Some(value), ConfigSource::Flag)
        } else if let Some(value) = env::var("CONCRETE_CONSOLE_URL")
            .ok()
            .filter(|value| !value.is_empty())
        {
            (Some(value), ConfigSource::Env)
        } else if let Some(value) = file.console_url {
            (Some(value), ConfigSource::File)
        } else {
            (None, ConfigSource::Missing)
        };
        let console_url = console_url.map(|value| value.trim_end_matches('/').to_string());

        let profile = if let Some(value) = profile_flag {
            Some(value)
        } else if let Some(value) = env::var("CONCRETE_DEFAULT_PROFILE")
            .ok()
            .filter(|value| !value.is_empty())
        {
            Some(value)
        } else {
            file.default_profile
        };

        let (oidc_client_id, oidc_client_id_source) = if let Some(value) =
            env::var("CONCRETE_OIDC_CLIENT_ID")
                .ok()
                .filter(|value| !value.is_empty())
        {
            (value, ConfigSource::Env)
        } else if let Some(value) = file.oidc_client_id {
            (value, ConfigSource::File)
        } else {
            ("concrete-cli-v1".to_string(), ConfigSource::Default)
        };
        let (oidc_provider, oidc_provider_source) = if let Some(value) =
            env::var("CONCRETE_OIDC_PROVIDER")
                .ok()
                .filter(|value| !value.is_empty())
        {
            (value, ConfigSource::Env)
        } else if let Some(value) = file.oidc_provider {
            (value, ConfigSource::File)
        } else {
            ("google".to_string(), ConfigSource::Default)
        };

        Self {
            config_dir,
            config_dir_source,
            console_url,
            console_url_source,
            profile,
            oidc_client_id,
            oidc_client_id_source,
            oidc_provider,
            oidc_provider_source,
        }
    }

    pub fn require_console_url(&self) -> Result<&str, String> {
        self.console_url.as_deref().ok_or_else(|| {
            "[usage] missing console_url; set --console-url, CONCRETE_CONSOLE_URL, or config.toml".to_string()
        })
    }

    pub fn require_profile(&self) -> Result<&str, String> {
        self.profile.as_deref().ok_or_else(|| {
            "[usage] missing profile; set --profile, CONCRETE_DEFAULT_PROFILE, or config.toml default_profile".to_string()
        })
    }
}

fn read_config_file(config_dir: &Path) -> Option<ConfigFile> {
    let path = config_dir.join("config.toml");
    let data = fs::read_to_string(path).ok()?;
    toml::from_str(&data).ok()
}

fn default_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("concrete")
}
