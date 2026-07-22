pub mod admin;
pub mod alias;
pub mod audit;
pub mod auth;
pub mod config;
pub mod cvm;
pub mod entity;
pub mod key;
pub(crate) mod operation_debug;
pub mod profile;
pub mod quota;
pub mod reconcile;
pub mod security_cvm;
pub mod skill;
pub mod ssh;
pub mod status;
pub mod traffic_logs;
pub mod tunnel;
pub mod user;
pub mod version;

use crate::config::ResolvedConfig;

/// Resolve the target Dev CVM for a verb that acts on a single CVM.
///
/// Chain: positional `<CVM_ID>` -> `--cvm` -> `CONCRETE_DEFAULT_CVM` -> `default_cvm`.
/// (`config.default_cvm` already folds the env var and config-file layers.)
pub(crate) fn resolve_cvm(
    positional: Option<&str>,
    flag: Option<&str>,
    config: &ResolvedConfig,
) -> Result<String, String> {
    let raw = positional
        .map(ToString::to_string)
        .or_else(|| flag.map(ToString::to_string))
        .or_else(|| config.default_cvm.clone())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "[usage] missing CVM id; pass <CVM_ID> or set --cvm, CONCRETE_DEFAULT_CVM, or default_cvm"
                .to_string()
        })?;
    resolve_cvm_alias(config, raw)
}

/// Translate a CVM alias to its UUID, leaving a raw id untouched. A raw UUID
/// never reads the alias store (so a corrupt store can't block a command driven
/// by a real id); only a non-UUID value consults it, surfacing a malformed
/// store rather than silently ignoring it.
fn resolve_cvm_alias(config: &ResolvedConfig, raw: String) -> Result<String, String> {
    alias::resolve_or_passthrough(config, alias::AliasKind::Cvm, &raw)
}

/// Resolve the target Dev CVM for a destructive verb (`cvm stop`, `cvm terminate`).
///
/// Only an explicit id counts: positional `<CVM_ID>` or `--cvm`. It deliberately
/// never falls back to `CONCRETE_DEFAULT_CVM` or `default_cvm`, so these verbs
/// cannot silently target a configured default.
pub(crate) fn resolve_cvm_explicit(
    positional: Option<&str>,
    flag: Option<&str>,
    config: &ResolvedConfig,
) -> Result<String, String> {
    let raw = positional
        .map(ToString::to_string)
        .or_else(|| flag.map(ToString::to_string))
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            "[usage] this command requires an explicit CVM id; pass <CVM_ID> or --cvm (it will not use CONCRETE_DEFAULT_CVM or default_cvm)"
                .to_string()
        })?;
    resolve_cvm_alias(config, raw)
}

#[cfg(test)]
mod tests {
    use super::{resolve_cvm, resolve_cvm_explicit};
    use crate::config::{ConfigOverrides, ResolvedConfig};

    /// A `ResolvedConfig` whose `default_cvm` is set directly, using a throwaway
    /// config dir so `resolve()` never reads the real `~/.concrete` and the result
    /// is independent of ambient `CONCRETE_DEFAULT_CVM`.
    fn config_with_default(default_cvm: Option<&str>) -> ResolvedConfig {
        let dir =
            std::env::temp_dir().join(format!("concrete-resolve-test-{}", uuid::Uuid::new_v4()));
        let mut config = ResolvedConfig::resolve(ConfigOverrides {
            config_dir: Some(dir),
            ..Default::default()
        });
        config.default_cvm = default_cvm.map(ToString::to_string);
        config
    }

    #[test]
    fn resolve_cvm_prefers_positional_then_flag_then_default() {
        let config = config_with_default(Some("default-cvm"));
        assert_eq!(
            resolve_cvm(Some("positional"), Some("flag"), &config).unwrap(),
            "positional"
        );
        assert_eq!(resolve_cvm(None, Some("flag"), &config).unwrap(), "flag");
        assert_eq!(resolve_cvm(None, None, &config).unwrap(), "default-cvm");
    }

    #[test]
    fn resolve_cvm_errors_without_any_source() {
        let config = config_with_default(None);
        assert!(resolve_cvm(None, None, &config).is_err());
    }

    #[test]
    fn resolve_cvm_explicit_ignores_configured_default() {
        // Only an explicit positional or --cvm satisfies a destructive verb.
        // The throwaway config dir has no alias store, so ids pass through.
        let config = config_with_default(Some("default-cvm"));
        assert_eq!(
            resolve_cvm_explicit(Some("positional"), None, &config).unwrap(),
            "positional"
        );
        assert_eq!(
            resolve_cvm_explicit(None, Some("flag"), &config).unwrap(),
            "flag"
        );
        assert_eq!(
            resolve_cvm_explicit(Some("positional"), Some("flag"), &config).unwrap(),
            "positional"
        );
        assert!(resolve_cvm_explicit(None, None, &config).is_err());
    }
}
