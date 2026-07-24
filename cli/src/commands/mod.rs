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

/// Select the target Dev CVM, then resolve its alias to a UUID.
///
/// The id is the first non-empty of, in order: `positional` `<CVM_ID>`, `flag`
/// (`--cvm`), then each entry of `fallback` (a raw UUID passes straight through
/// the alias resolver; a non-UUID consults the store). `fallback` carries the
/// softer defaults a command allows — pass `&[config.default_cvm.as_deref()]` for
/// the permissive verbs (`ssh`, `cvm show`, …). Pass an **empty** `fallback` for
/// destructive verbs (`cvm stop`/`terminate`) so they never silently target a
/// configured default. Order the slice to order the fallback (e.g.
/// `&[env_default, file_default]`).
///
/// Selection ≠ resolution: this picks *which* id from the available sources; the
/// alias→id translation is [`alias::resolve_or_passthrough`], the one resolver.
pub(crate) fn select_cvm(
    positional: Option<&str>,
    flag: Option<&str>,
    fallback: &[Option<&str>],
    config: &ResolvedConfig,
) -> Result<String, String> {
    let raw = [positional, flag]
        .into_iter()
        .chain(fallback.iter().copied())
        .filter_map(|candidate| candidate.filter(|value| !value.is_empty()))
        .next()
        .ok_or_else(|| {
            if fallback.is_empty() {
                "[usage] this command requires an explicit CVM id; pass <CVM_ID> or --cvm (it will not use CONCRETE_DEFAULT_CVM or default_cvm)".to_string()
            } else {
                "[usage] missing CVM id; pass <CVM_ID> or set --cvm, CONCRETE_DEFAULT_CVM, or default_cvm".to_string()
            }
        })?;
    alias::resolve_or_passthrough(config, alias::AliasKind::Cvm, raw)
}

#[cfg(test)]
mod tests {
    use super::select_cvm;
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

    /// With a non-empty `fallback` (the permissive verbs pass the configured
    /// default), selection walks positional → flag → fallback in order.
    #[test]
    fn select_cvm_prefers_positional_then_flag_then_fallback_success() {
        let config = config_with_default(Some("default-cvm"));
        let fallback = [config.default_cvm.as_deref()];
        assert_eq!(
            select_cvm(Some("positional"), Some("flag"), &fallback, &config).unwrap(),
            "positional"
        );
        assert_eq!(
            select_cvm(None, Some("flag"), &fallback, &config).unwrap(),
            "flag"
        );
        assert_eq!(
            select_cvm(None, None, &fallback, &config).unwrap(),
            "default-cvm"
        );
    }

    /// No source at all (and a fallback that only holds the absent default) is a
    /// usage error rather than an empty target.
    #[test]
    fn select_cvm_without_any_source_failure() {
        let config = config_with_default(None);
        assert!(select_cvm(None, None, &[config.default_cvm.as_deref()], &config).is_err());
    }

    /// An EMPTY `fallback` is the destructive-verb contract: only an explicit
    /// positional or `--cvm` counts; the configured default is ignored, so a
    /// bare invocation errors instead of silently targeting it.
    #[test]
    fn select_cvm_empty_fallback_ignores_default_success() {
        let config = config_with_default(Some("default-cvm"));
        assert_eq!(
            select_cvm(Some("positional"), None, &[], &config).unwrap(),
            "positional"
        );
        assert_eq!(
            select_cvm(None, Some("flag"), &[], &config).unwrap(),
            "flag"
        );
        assert!(select_cvm(None, None, &[], &config).is_err());
    }
}
