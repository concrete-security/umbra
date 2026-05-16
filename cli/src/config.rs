use std::{
    env, fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
struct ConfigFile {
    console_url: Option<String>,
    default_cvm: Option<String>,
    default_profile: Option<String>,
    atls_policy: Option<PathBuf>,
    atls_policy_insecure_skip: Option<bool>,
    default_instance_type: Option<String>,
    default_region: Option<String>,
    oidc_client_id: Option<String>,
    oidc_provider: Option<String>,
    request_id: Option<String>,
    force: Option<bool>,
    output: Option<String>,
    no_color: Option<bool>,
    log_level: Option<String>,
}

#[derive(Debug, Default)]
pub struct ConfigOverrides {
    pub config_dir: Option<PathBuf>,
    pub console_url: Option<String>,
    pub cvm: Option<String>,
    pub profile: Vec<String>,
    pub atls_policy: Option<PathBuf>,
    pub insecure_skip_atls_policy: bool,
    pub request_id: Option<String>,
    pub force: bool,
    pub json: bool,
    pub no_color: bool,
    pub verbose: u8,
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub config_dir: PathBuf,
    pub config_dir_source: ConfigSource,
    pub console_url: Option<String>,
    pub console_url_source: ConfigSource,
    pub default_cvm: Option<String>,
    pub default_cvm_source: ConfigSource,
    pub profile: Option<String>,
    pub profile_source: ConfigSource,
    pub profile_flags: Vec<String>,
    pub atls_policy: Option<PathBuf>,
    pub atls_policy_source: ConfigSource,
    pub atls_policy_insecure_skip: bool,
    pub atls_policy_insecure_skip_source: ConfigSource,
    pub default_instance_type: Option<String>,
    pub default_instance_type_source: ConfigSource,
    pub default_region: Option<String>,
    pub default_region_source: ConfigSource,
    pub oidc_client_id: String,
    pub oidc_client_id_source: ConfigSource,
    pub oidc_provider: String,
    pub oidc_provider_source: ConfigSource,
    pub request_id: String,
    pub request_id_source: ConfigSource,
    pub force: bool,
    pub force_source: ConfigSource,
    pub output: OutputFormat,
    pub output_source: ConfigSource,
    pub no_color: bool,
    pub no_color_source: ConfigSource,
    pub log_level: String,
    pub log_level_source: ConfigSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
}

impl OutputFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Json => "json",
        }
    }
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
    pub fn resolve(overrides: ConfigOverrides) -> Self {
        let (config_dir, config_dir_source) = if let Some(value) = overrides.config_dir {
            (value, ConfigSource::Flag)
        } else if let Some(value) = env::var_os("CONCRETE_CONFIG_DIR").map(PathBuf::from) {
            (value, ConfigSource::Env)
        } else {
            (default_config_dir(), ConfigSource::Default)
        };
        let file = read_config_file(&config_dir).unwrap_or_default();
        let (console_url, console_url_source) = if let Some(value) = overrides.console_url {
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

        let (default_cvm, default_cvm_source) = if let Some(value) = overrides.cvm {
            (Some(value), ConfigSource::Flag)
        } else if let Some(value) = env::var("CONCRETE_DEFAULT_CVM")
            .ok()
            .filter(|value| !value.is_empty())
        {
            (Some(value), ConfigSource::Env)
        } else if let Some(value) = file.default_cvm {
            (Some(value), ConfigSource::File)
        } else {
            (None, ConfigSource::Missing)
        };

        let (profile, profile_source) = if overrides.profile.len() == 1 {
            (Some(overrides.profile[0].clone()), ConfigSource::Flag)
        } else if overrides.profile.len() > 1 {
            (None, ConfigSource::Flag)
        } else if let Some(value) = env::var("CONCRETE_DEFAULT_PROFILE")
            .ok()
            .filter(|value| !value.is_empty())
        {
            (Some(value), ConfigSource::Env)
        } else if let Some(value) = file.default_profile {
            (Some(value), ConfigSource::File)
        } else {
            (None, ConfigSource::Missing)
        };

        let (atls_policy, atls_policy_source) = if let Some(value) = overrides.atls_policy {
            (Some(value), ConfigSource::Flag)
        } else if let Some(value) = env::var_os("CONCRETE_ATLS_POLICY").map(PathBuf::from) {
            (Some(value), ConfigSource::Env)
        } else if let Some(value) = file.atls_policy {
            (Some(value), ConfigSource::File)
        } else {
            (None, ConfigSource::Missing)
        };

        let (atls_policy_insecure_skip, atls_policy_insecure_skip_source) =
            if overrides.insecure_skip_atls_policy {
                (true, ConfigSource::Flag)
            } else if let Some(value) = env_bool("CONCRETE_ATLS_POLICY_INSECURE_SKIP") {
                (value, ConfigSource::Env)
            } else if let Some(value) = file.atls_policy_insecure_skip {
                (value, ConfigSource::File)
            } else {
                (false, ConfigSource::Default)
            };

        let (default_instance_type, default_instance_type_source) = if let Some(value) =
            env::var("CONCRETE_DEFAULT_INSTANCE_TYPE")
                .ok()
                .filter(|value| !value.is_empty())
        {
            (Some(value), ConfigSource::Env)
        } else if let Some(value) = file.default_instance_type {
            (Some(value), ConfigSource::File)
        } else {
            (None, ConfigSource::Missing)
        };
        let (default_region, default_region_source) = if let Some(value) =
            env::var("CONCRETE_DEFAULT_REGION")
                .ok()
                .filter(|value| !value.is_empty())
        {
            (Some(value), ConfigSource::Env)
        } else if let Some(value) = file.default_region {
            (Some(value), ConfigSource::File)
        } else {
            (None, ConfigSource::Missing)
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

        let (request_id, request_id_source) = if let Some(value) = overrides.request_id {
            (value, ConfigSource::Flag)
        } else if let Some(value) = env::var("CONCRETE_REQUEST_ID")
            .ok()
            .filter(|value| !value.is_empty())
        {
            (value, ConfigSource::Env)
        } else if let Some(value) = file.request_id {
            (value, ConfigSource::File)
        } else {
            (uuid::Uuid::new_v4().to_string(), ConfigSource::Default)
        };

        let (force, force_source) = if overrides.force {
            (true, ConfigSource::Flag)
        } else if let Some(value) = env_bool("CONCRETE_FORCE") {
            (value, ConfigSource::Env)
        } else if let Some(value) = file.force {
            (value, ConfigSource::File)
        } else {
            (false, ConfigSource::Default)
        };

        let (output, output_source) = if overrides.json {
            (OutputFormat::Json, ConfigSource::Flag)
        } else if let Some(value) = env::var("CONCRETE_OUTPUT")
            .ok()
            .filter(|value| !value.is_empty())
        {
            (
                parse_output(&value).unwrap_or(OutputFormat::Text),
                ConfigSource::Env,
            )
        } else if let Some(value) = file.output {
            (
                parse_output(&value).unwrap_or(OutputFormat::Text),
                ConfigSource::File,
            )
        } else {
            (OutputFormat::Text, ConfigSource::Default)
        };

        let (no_color, no_color_source) = if overrides.no_color {
            (true, ConfigSource::Flag)
        } else if let Some(value) = env_bool("CONCRETE_NO_COLOR") {
            (value, ConfigSource::Env)
        } else if env::var_os("NO_COLOR").is_some() {
            (true, ConfigSource::Env)
        } else if let Some(value) = file.no_color {
            (value, ConfigSource::File)
        } else {
            (false, ConfigSource::Default)
        };

        let (log_level, log_level_source) = if overrides.verbose > 0 {
            (
                verbose_log_level(overrides.verbose).to_string(),
                ConfigSource::Flag,
            )
        } else if let Some(value) = env::var("CONCRETE_LOG_LEVEL")
            .ok()
            .filter(|value| !value.is_empty())
        {
            (value, ConfigSource::Env)
        } else if let Some(value) = file.log_level {
            (value, ConfigSource::File)
        } else {
            ("warn".to_string(), ConfigSource::Default)
        };

        Self {
            config_dir,
            config_dir_source,
            console_url,
            console_url_source,
            default_cvm,
            default_cvm_source,
            profile,
            profile_source,
            profile_flags: overrides.profile,
            atls_policy,
            atls_policy_source,
            atls_policy_insecure_skip,
            atls_policy_insecure_skip_source,
            default_instance_type,
            default_instance_type_source,
            default_region,
            default_region_source,
            oidc_client_id,
            oidc_client_id_source,
            oidc_provider,
            oidc_provider_source,
            request_id,
            request_id_source,
            force,
            force_source,
            output,
            output_source,
            no_color,
            no_color_source,
            log_level,
            log_level_source,
        }
    }

    pub fn require_console_url(&self) -> Result<&str, String> {
        self.console_url.as_deref().ok_or_else(|| {
            "[usage] missing console_url; set --console-url, CONCRETE_CONSOLE_URL, or config.toml".to_string()
        })
    }

    pub fn require_profile(&self) -> Result<&str, String> {
        if self.profile_flags.len() > 1 {
            return Err(
                "[usage] expected exactly one profile for this command; repeat --profile only where supported"
                    .to_string(),
            );
        }
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

fn env_bool(name: &str) -> Option<bool> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .and_then(|value| parse_bool(&value))
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Some(true),
        "0" | "false" | "no" => Some(false),
        _ => None,
    }
}

fn parse_output(value: &str) -> Option<OutputFormat> {
    match value.trim().to_ascii_lowercase().as_str() {
        "text" => Some(OutputFormat::Text),
        "json" => Some(OutputFormat::Json),
        _ => None,
    }
}

fn verbose_log_level(verbose: u8) -> &'static str {
    match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_bool, parse_output, verbose_log_level, OutputFormat};

    #[test]
    fn parse_bool_accepts_spec_values() {
        assert_eq!(parse_bool("1"), Some(true));
        assert_eq!(parse_bool("true"), Some(true));
        assert_eq!(parse_bool("YES"), Some(true));
        assert_eq!(parse_bool("0"), Some(false));
        assert_eq!(parse_bool("false"), Some(false));
        assert_eq!(parse_bool("No"), Some(false));
        assert_eq!(parse_bool("maybe"), None);
    }

    #[test]
    fn parse_output_accepts_text_and_json() {
        assert_eq!(parse_output("text"), Some(OutputFormat::Text));
        assert_eq!(parse_output("JSON"), Some(OutputFormat::Json));
        assert_eq!(parse_output("yaml"), None);
    }

    #[test]
    fn verbose_flags_map_to_log_levels() {
        assert_eq!(verbose_log_level(0), "warn");
        assert_eq!(verbose_log_level(1), "info");
        assert_eq!(verbose_log_level(2), "debug");
        assert_eq!(verbose_log_level(3), "trace");
    }
}
