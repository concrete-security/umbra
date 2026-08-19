use std::{
    env, fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

/// `default_profile` takes a list because a Dev CVM attaches 1..16 profiles and
/// merges their policies, so "the profiles I always launch with" is a set, not a
/// single value. The bare-string form is kept — and listed first, so it is what a
/// one-element list round-trips to — because every `config.toml` already written
/// holds one, and a typed key that stopped accepting its own old value would make
/// the whole file unusable on upgrade.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged, expecting = "a name, or a list of names")]
enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

#[derive(Debug, Default, Deserialize)]
struct ConfigFile {
    console_url: Option<String>,
    default_cvm: Option<String>,
    default_profile: Option<OneOrMany>,
    default_ssh_identity: Option<PathBuf>,
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
    skill_auto_install: Option<toml::Value>,
    install_base_url: Option<String>,
    no_update_check: Option<bool>,
    #[serde(flatten)]
    unknown: toml::Table,
}

#[derive(Debug, Default)]
pub struct ConfigOverrides {
    pub config_dir: Option<PathBuf>,
    pub console_url: Option<String>,
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
    pub default_ssh_identity: Option<PathBuf>,
    pub default_ssh_identity_source: ConfigSource,
    pub profiles: Vec<String>,
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
    /// Whether `auth login` should install the agent skill: `Some(true)` opted
    /// in, `Some(false)` opted out (or `UMBRA_NO_SKILL`), `None` not asked.
    pub skill_auto_install: Option<bool>,
    pub install_base_url: Option<String>,
    pub install_base_url_source: ConfigSource,
    pub no_update_check: bool,
    pub no_update_check_source: ConfigSource,
    pub config_file_error: Option<String>,
    pub unknown_config_keys: Vec<String>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        } else if let Some(value) = env::var_os("UMBRA_CONFIG_DIR").map(PathBuf::from) {
            (value, ConfigSource::Env)
        } else {
            (default_config_dir(), ConfigSource::Default)
        };
        let (file, config_file_error) = read_config_file(&config_dir);
        let unknown_config_keys: Vec<String> = file.unknown.keys().cloned().collect();
        let (console_url, console_url_source) = if let Some(value) = overrides.console_url {
            (Some(value), ConfigSource::Flag)
        } else if let Some(value) = env::var("UMBRA_CONSOLE_URL")
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

        // `--cvm` is no longer a global override folded in here; it is a per-verb
        // target flag resolved at the command layer (see commands::select_cvm),
        // which sits above this default. So `default_cvm` only carries the env var
        // and config-file layers.
        let (default_cvm, default_cvm_source) = if let Some(value) = env::var("UMBRA_DEFAULT_CVM")
            .ok()
            .filter(|value| !value.is_empty())
        {
            (Some(value), ConfigSource::Env)
        } else if let Some(value) = file.default_cvm {
            (Some(value), ConfigSource::File)
        } else {
            (None, ConfigSource::Missing)
        };

        let (default_ssh_identity, default_ssh_identity_source) = if let Some(value) =
            env::var("UMBRA_DEFAULT_SSH_IDENTITY")
                .ok()
                .filter(|value| !value.is_empty())
        {
            (Some(PathBuf::from(value)), ConfigSource::Env)
        } else if let Some(value) = file.default_ssh_identity {
            (Some(value), ConfigSource::File)
        } else {
            (None, ConfigSource::Missing)
        };

        let (profiles, profile_source) = if !overrides.profile.is_empty() {
            (overrides.profile.clone(), ConfigSource::Flag)
        } else if let Some(values) = env::var("UMBRA_DEFAULT_PROFILE")
            .ok()
            .map(|value| split_list(&value))
            .filter(|values| !values.is_empty())
        {
            (values, ConfigSource::Env)
        } else if let Some(values) = file
            .default_profile
            .map(OneOrMany::into_vec)
            .filter(|values| !values.is_empty())
        {
            (values, ConfigSource::File)
        } else {
            (Vec::new(), ConfigSource::Missing)
        };

        let (atls_policy, atls_policy_source) = if let Some(value) = overrides.atls_policy {
            (Some(value), ConfigSource::Flag)
        } else if let Some(value) = env::var_os("UMBRA_ATLS_POLICY").map(PathBuf::from) {
            (Some(value), ConfigSource::Env)
        } else if let Some(value) = file.atls_policy {
            (Some(value), ConfigSource::File)
        } else {
            (None, ConfigSource::Missing)
        };

        let (atls_policy_insecure_skip, atls_policy_insecure_skip_source) =
            if overrides.insecure_skip_atls_policy {
                (true, ConfigSource::Flag)
            } else if let Some(value) = env_bool("UMBRA_ATLS_POLICY_INSECURE_SKIP") {
                (value, ConfigSource::Env)
            } else if let Some(value) = file.atls_policy_insecure_skip {
                (value, ConfigSource::File)
            } else {
                (false, ConfigSource::Default)
            };

        let (default_instance_type, default_instance_type_source) = if let Some(value) =
            env::var("UMBRA_DEFAULT_INSTANCE_TYPE")
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
            env::var("UMBRA_DEFAULT_REGION")
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
            env::var("UMBRA_OIDC_CLIENT_ID")
                .ok()
                .filter(|value| !value.is_empty())
        {
            (value, ConfigSource::Env)
        } else if let Some(value) = file.oidc_client_id {
            (value, ConfigSource::File)
        } else {
            ("umbra-cli-v1".to_string(), ConfigSource::Default)
        };
        let (oidc_provider, oidc_provider_source) = if let Some(value) =
            env::var("UMBRA_OIDC_PROVIDER")
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
        } else if let Some(value) = env::var("UMBRA_REQUEST_ID")
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
        } else if let Some(value) = env_bool("UMBRA_FORCE") {
            (value, ConfigSource::Env)
        } else if let Some(value) = file.force {
            (value, ConfigSource::File)
        } else {
            (false, ConfigSource::Default)
        };

        let (output, output_source) = if overrides.json {
            (OutputFormat::Json, ConfigSource::Flag)
        } else if let Some(value) = env::var("UMBRA_OUTPUT")
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
        } else if let Some(value) = env_bool("UMBRA_NO_COLOR") {
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
        } else if let Some(value) = env::var("UMBRA_LOG_LEVEL")
            .ok()
            .filter(|value| !value.is_empty())
        {
            (value, ConfigSource::Env)
        } else if let Some(value) = file.log_level {
            (value, ConfigSource::File)
        } else {
            ("warn".to_string(), ConfigSource::Default)
        };

        // UMBRA_NO_SKILL=1 is a hard opt-out; otherwise the persisted answer
        // from the first `auth login` prompt decides (None until first asked).
        let skill_auto_install = if env_bool("UMBRA_NO_SKILL") == Some(true) {
            Some(false)
        } else {
            file.skill_auto_install
                .as_ref()
                .and_then(|value| match value {
                    toml::Value::Boolean(flag) => Some(*flag),
                    toml::Value::String(text) => parse_bool(text),
                    _ => None,
                })
        };

        let (install_base_url, install_base_url_source) = if let Some(value) =
            env::var("UMBRA_INSTALL_BASE_URL")
                .ok()
                .filter(|value| !value.is_empty())
        {
            (Some(value), ConfigSource::Env)
        } else if let Some(value) = file.install_base_url {
            (Some(value), ConfigSource::File)
        } else {
            (None, ConfigSource::Missing)
        };
        let install_base_url =
            install_base_url.map(|value| value.trim_end_matches('/').to_string());

        let (no_update_check, no_update_check_source) =
            if let Some(value) = env_bool("UMBRA_NO_UPDATE_CHECK") {
                (value, ConfigSource::Env)
            } else if let Some(value) = file.no_update_check {
                (value, ConfigSource::File)
            } else {
                (false, ConfigSource::Default)
            };

        Self {
            config_dir,
            config_dir_source,
            console_url,
            console_url_source,
            default_cvm,
            default_cvm_source,
            default_ssh_identity,
            default_ssh_identity_source,
            profiles,
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
            skill_auto_install,
            install_base_url,
            install_base_url_source,
            no_update_check,
            no_update_check_source,
            config_file_error,
            unknown_config_keys,
        }
    }

    pub fn require_console_url(&self) -> Result<&str, String> {
        self.console_url.as_deref().ok_or_else(|| {
            "[usage] missing console_url; set --console-url, UMBRA_CONSOLE_URL, or config.toml"
                .to_string()
        })
    }

    pub fn require_profile(&self) -> Result<&str, String> {
        match self.profiles.as_slice() {
            [only] => Ok(only),
            [] => Err(
                "[usage] missing profile; set --profile, UMBRA_DEFAULT_PROFILE, or config.toml default_profile"
                    .to_string(),
            ),
            several => Err(format!(
                "[usage] this command takes exactly one profile but {} names {}; {}",
                match self.profile_source {
                    ConfigSource::Flag => "--profile",
                    ConfigSource::Env => "UMBRA_DEFAULT_PROFILE",
                    _ => "default_profile",
                },
                several.len(),
                match self.profile_source {
                    ConfigSource::Flag => {
                        "repeat --profile only where several are supported".to_string()
                    }
                    _ => "pass --profile to choose one".to_string(),
                }
            )),
        }
    }
}

pub(crate) fn locked_update(
    config_dir: &Path,
    mutate: impl FnOnce(&mut toml::Table) -> Result<bool, String>,
) -> Result<(), String> {
    let lock_path = config_dir.join("config.lock");
    let _guard = crate::fsutil::StoreLock::acquire(&lock_path)
        .map_err(|err| format!("[error] failed to lock {}: {err}", lock_path.display()))?;
    let target = config_dir.join("config.toml");
    let mut table = read_config_table(&target)?;
    if !mutate(&mut table)? {
        return Ok(());
    }
    let data = toml::to_string_pretty(&table)
        .map_err(|err| format!("[error] failed to serialize config: {err}"))?;
    crate::fsutil::write_atomic_file(&target, data.as_bytes(), 0o600)
        .map_err(|err| format!("[error] failed to write config file: {err}"))
}

pub(crate) fn persist_string_values(
    config_dir: &Path,
    values: &[(&str, String)],
) -> Result<(), String> {
    locked_update(config_dir, |table| {
        for (key, value) in values {
            table.insert((*key).to_string(), toml::Value::String(value.clone()));
        }
        Ok(!values.is_empty())
    })
}

fn read_config_table(target: &Path) -> Result<toml::Table, String> {
    let data = match fs::read_to_string(target) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(toml::Table::new()),
        Err(err) => {
            return Err(format!(
                "[error] failed to read existing config {}: {err}",
                crate::style::single_line(&target.display().to_string())
            ))
        }
    };
    let unusable = |err: &toml::de::Error| {
        format!(
            "[error] failed to parse existing config {}: {}",
            crate::style::single_line(&target.display().to_string()),
            toml_error_summary(err)
        )
    };
    let table = data.parse::<toml::Table>().map_err(|err| unusable(&err))?;
    toml::from_str::<ConfigFile>(&data).map_err(|err| unusable(&err))?;
    Ok(table)
}

fn toml_error_summary(err: &toml::de::Error) -> String {
    let text = err.to_string();
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let Some(first) = lines.next() else {
        return String::new();
    };
    match lines.next_back() {
        Some(last) if last != first => format!("{first}: {last}"),
        _ => first.to_string(),
    }
}

fn read_config_file(config_dir: &Path) -> (ConfigFile, Option<String>) {
    let path = config_dir.join("config.toml");
    let data = match fs::read_to_string(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return (ConfigFile::default(), None)
        }
        Err(err) => {
            return (
                ConfigFile::default(),
                Some(format!(
                    "{}: {err}",
                    crate::style::single_line(&path.display().to_string())
                )),
            )
        }
    };
    match toml::from_str::<ConfigFile>(&data) {
        Ok(file) => (file, None),
        Err(err) => (
            ConfigFile::default(),
            Some(format!(
                "{}: {}",
                crate::style::single_line(&path.display().to_string()),
                toml_error_summary(&err)
            )),
        ),
    }
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn default_config_dir() -> PathBuf {
    home::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".umbra")
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
    use super::{
        locked_update, parse_bool, parse_output, persist_string_values, verbose_log_level,
        ConfigOverrides, OutputFormat, ResolvedConfig,
    };
    use rstest::rstest;
    use std::fs;

    fn temp_config_dir() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("umbra-config-test-{}", uuid::Uuid::new_v4()))
    }

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

    #[test]
    fn persist_string_values_merges_existing_config() {
        let config_dir = temp_config_dir();
        fs::create_dir_all(&config_dir).expect("config dir created");
        fs::write(
            config_dir.join("config.toml"),
            "output = \"json\"\nconsole_url = \"https://old.example.com\"\n",
        )
        .expect("config written");

        persist_string_values(
            &config_dir,
            &[
                ("console_url", "https://console.example.com".to_string()),
                ("default_cvm", "cvm-1".to_string()),
            ],
        )
        .expect("config persisted");

        let data = fs::read_to_string(config_dir.join("config.toml")).expect("config readable");
        let table = data.parse::<toml::Table>().expect("valid toml");
        assert_eq!(
            table.get("console_url").and_then(toml::Value::as_str),
            Some("https://console.example.com")
        );
        assert_eq!(
            table.get("default_cvm").and_then(toml::Value::as_str),
            Some("cvm-1")
        );
        assert_eq!(
            table.get("output").and_then(toml::Value::as_str),
            Some("json")
        );

        fs::remove_dir_all(config_dir).expect("test config dir removed");
    }

    fn config_dir_with(contents: &str) -> std::path::PathBuf {
        let config_dir = temp_config_dir();
        fs::create_dir_all(&config_dir).expect("config dir created");
        if !contents.is_empty() {
            fs::write(config_dir.join("config.toml"), contents).expect("config written");
        }
        config_dir
    }

    fn resolve_in(config_dir: &std::path::Path, flags: &[&str]) -> ResolvedConfig {
        ResolvedConfig::resolve(ConfigOverrides {
            config_dir: Some(config_dir.to_path_buf()),
            profile: flags.iter().map(|flag| (*flag).to_string()).collect(),
            ..Default::default()
        })
    }

    #[rstest]
    #[case::one_bare_string("default_profile = \"celia-dev\"\n", vec!["celia-dev"])]
    #[case::a_list("default_profile = [\"celia-dev\", \"eng\"]\n", vec!["celia-dev", "eng"])]
    #[case::a_one_element_list("default_profile = [\"celia-dev\"]\n", vec!["celia-dev"])]
    #[case::absent("", vec![])]
    #[case::an_empty_list_is_not_configured("default_profile = []\n", vec![])]
    fn resolve_profiles_success(#[case] contents: &str, #[case] expected: Vec<&str>) {
        let config_dir = config_dir_with(contents);
        assert_eq!(resolve_in(&config_dir, &[]).profiles, expected);
        fs::remove_dir_all(config_dir).expect("cleanup");
    }

    #[rstest]
    #[case::several_in_the_file(&[], "default_profile = [\"a\", \"b\"]\n", "default_profile names 2")]
    #[case::several_flags(&["a", "b"], "", "--profile names 2")]
    #[case::none_anywhere(&[], "", "missing profile")]
    fn require_profile_failure(
        #[case] flags: &[&str],
        #[case] contents: &str,
        #[case] expected: &str,
    ) {
        let config_dir = config_dir_with(contents);
        let err = resolve_in(&config_dir, flags)
            .require_profile()
            .expect_err("not exactly one profile");
        assert!(err.contains(expected), "err={err}");
        fs::remove_dir_all(config_dir).expect("cleanup");
    }

    #[rstest]
    #[case::a_flag_overrides_a_list(&["flagged"], "default_profile = [\"a\", \"b\"]\n", "flagged")]
    #[case::a_one_element_list(&[], "default_profile = [\"listed\"]\n", "listed")]
    fn require_profile_success(
        #[case] flags: &[&str],
        #[case] contents: &str,
        #[case] expected: &str,
    ) {
        let config_dir = config_dir_with(contents);
        let config = resolve_in(&config_dir, flags);
        assert_eq!(config.require_profile().expect("exactly one"), expected);
        fs::remove_dir_all(config_dir).expect("cleanup");
    }

    #[test]
    fn locked_update_unusable_file_failure() {
        let config_dir = config_dir_with("default_profile = [");
        let err = locked_update(&config_dir, |_| Ok(true)).expect_err("truncated toml refused");
        assert!(err.contains("failed to parse existing config"), "err={err}");
        fs::remove_dir_all(config_dir).expect("cleanup");
    }
}
