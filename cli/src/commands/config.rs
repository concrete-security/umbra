use serde_json::{json, Map, Value};

use crate::{
    cli::ConfigCommand,
    config::{ConfigSource, ResolvedConfig},
    ExitStatus,
};

pub fn run(command: ConfigCommand, config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    match command {
        ConfigCommand::Show => show(config, json_output),
    }
}

fn show(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let entries = config_entries(config);
    if json_output {
        let mut output = Map::new();
        for entry in entries {
            output.insert(
                entry.key.to_string(),
                json!({
                    "value": entry.value,
                    "source": entry.source.as_str(),
                }),
            );
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&Value::Object(output))
                .expect("config show output serializes")
        );
    } else {
        for entry in entries {
            println!(
                "{:<28} {} ({})",
                entry.key,
                display_value(&entry.value),
                entry.source.as_str()
            );
        }
    }
    ExitStatus::Ok
}

struct ConfigEntry {
    key: &'static str,
    value: Value,
    source: ConfigSource,
}

fn config_entries(config: &ResolvedConfig) -> Vec<ConfigEntry> {
    vec![
        string_entry(
            "config_dir",
            Some(config.config_dir.display().to_string()),
            config.config_dir_source,
        ),
        string_entry(
            "console_url",
            config.console_url.clone(),
            config.console_url_source,
        ),
        string_entry(
            "default_cvm",
            config.default_cvm.clone(),
            config.default_cvm_source,
        ),
        string_entry(
            "default_profile",
            config.profile.clone(),
            config.profile_source,
        ),
        string_entry(
            "atls_policy",
            config
                .atls_policy
                .as_ref()
                .map(|path| path.display().to_string()),
            config.atls_policy_source,
        ),
        bool_entry(
            "atls_policy_insecure_skip",
            config.atls_policy_insecure_skip,
            config.atls_policy_insecure_skip_source,
        ),
        string_entry(
            "default_instance_type",
            config.default_instance_type.clone(),
            config.default_instance_type_source,
        ),
        string_entry(
            "default_region",
            config.default_region.clone(),
            config.default_region_source,
        ),
        string_entry(
            "oidc_provider",
            Some(config.oidc_provider.clone()),
            config.oidc_provider_source,
        ),
        string_entry(
            "oidc_client_id",
            Some(config.oidc_client_id.clone()),
            config.oidc_client_id_source,
        ),
        string_entry(
            "request_id",
            Some(config.request_id.clone()),
            config.request_id_source,
        ),
        bool_entry("force", config.force, config.force_source),
        string_entry(
            "output",
            Some(config.output.as_str().to_string()),
            config.output_source,
        ),
        bool_entry("no_color", config.no_color, config.no_color_source),
        string_entry(
            "log_level",
            Some(config.log_level.clone()),
            config.log_level_source,
        ),
    ]
}

fn string_entry(key: &'static str, value: Option<String>, source: ConfigSource) -> ConfigEntry {
    ConfigEntry {
        key,
        value: value.map(Value::String).unwrap_or(Value::Null),
        source,
    }
}

fn bool_entry(key: &'static str, value: bool, source: ConfigSource) -> ConfigEntry {
    ConfigEntry {
        key,
        value: Value::Bool(value),
        source,
    }
}

fn display_value(value: &Value) -> String {
    match value {
        Value::Null => "<unset>".to_string(),
        Value::String(value) => value.clone(),
        Value::Bool(value) => value.to_string(),
        _ => value.to_string(),
    }
}
