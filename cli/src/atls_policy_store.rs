//! Local aTLS trust store: one `<cvm-id>.atls-policy.json` per Dev CVM under
//! `<config_dir>/cvms/`, written on launch/update or lazily fetched by
//! ssh/tunnel. The file is the golden measurement this CLI trusts, so
//! replacing changed material requires explicit consent.

use std::{
    fs,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::{console::fetch_json, exit::ExitStatus, prompt, session::Session, style};

#[derive(Debug, Deserialize)]
pub struct PolicyBundle {
    pub(crate) cvm_id: String,
    pub(crate) compose_template: String,
    pub(crate) expected_bootchain: Value,
    pub(crate) os_image_hash: String,
    pub(crate) rtmr3_binding: Value,
    #[serde(flatten)]
    pub(crate) extra: Map<String, Value>,
}

#[derive(Clone, Copy, Debug)]
pub enum PolicyWriteStatus {
    Installed,
    Unchanged,
    ReplacedAfterConfirmation,
}

impl PolicyWriteStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Installed => "installed",
            Self::Unchanged => "unchanged",
            Self::ReplacedAfterConfirmation => "replaced_after_confirmation",
        }
    }
}

pub fn store_path(config_dir: &Path, cvm_id: &str) -> PathBuf {
    config_dir
        .join("cvms")
        .join(format!("{cvm_id}.atls-policy.json"))
}

pub fn cvm_id_from_path(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let cvm_id = name.strip_suffix(".atls-policy.json")?;
    if cvm_id.is_empty() {
        return None;
    }
    Some(cvm_id.to_string())
}

pub fn cvm_id_from_store_path(config_dir: &Path, path: &Path) -> Option<String> {
    let cvm_id = cvm_id_from_path(path)?;
    if path == store_path(config_dir, &cvm_id) {
        Some(cvm_id)
    } else {
        None
    }
}

pub fn fetch_bundle(
    console_url: &str,
    session: &Session,
    cvm_id: &str,
) -> Result<PolicyBundle, (ExitStatus, String)> {
    fetch_json(
        console_url,
        session,
        &format!("/api/v1/cvms/{cvm_id}/policy-bundle"),
        &[],
        "fetch Dev CVM policy bundle",
    )
}

pub fn write(config_dir: &Path, bundle: &PolicyBundle, cvm_id: &str) -> Result<PathBuf, String> {
    let (target, data, _) = prepare(config_dir, bundle, cvm_id)?;
    install(&target, &data)?;
    Ok(target)
}

pub fn write_after_update(
    config_dir: &Path,
    bundle: &PolicyBundle,
    cvm_id: &str,
    json_output: bool,
) -> Result<(PathBuf, PolicyWriteStatus), String> {
    let (target, data, document) = prepare(config_dir, bundle, cvm_id)?;
    if !target.exists() {
        install(&target, &data)?;
        return Ok((target, PolicyWriteStatus::Installed));
    }
    if matches_existing(&target, &document)? {
        tighten_permissions(&target)?;
        return Ok((target, PolicyWriteStatus::Unchanged));
    }
    if !json_output && prompt_replace(cvm_id, &target)? {
        install(&target, &data)?;
        return Ok((target, PolicyWriteStatus::ReplacedAfterConfirmation));
    }
    Err(format!(
        "[error] Dev CVM update succeeded, but the local aTLS policy file was not changed. The new policy changes the measurement this CLI trusts. Current policy: {}. Re-run `umbra cvm update {}` from an interactive terminal and answer yes if you trust the new measurement.",
        target.display(),
        cvm_id
    ))
}

fn prepare(
    config_dir: &Path,
    bundle: &PolicyBundle,
    cvm_id: &str,
) -> Result<(PathBuf, Vec<u8>, Value), String> {
    if bundle.cvm_id != cvm_id {
        return Err("[error] CVM policy bundle did not match CVM id".to_string());
    }
    // The tightened directory is always `<config_dir>/cvms`, never derived from
    // `target.parent()`: a Console-supplied cvm_id is not path-validated here, so a
    // separator in it must not move the chmod onto another directory.
    let dir = config_dir.join("cvms");
    fs::create_dir_all(&dir)
        .map_err(|err| format!("[error] failed to create policy directory: {err}"))?;
    #[cfg(unix)]
    {
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).map_err(|err| {
            format!("[error] failed to tighten policy directory permissions: {err}")
        })?;
    }
    let target = store_path(config_dir, cvm_id);
    let document = policy_document(bundle);
    let data = serde_json::to_vec_pretty(&document)
        .map_err(|err| format!("[error] failed to serialize aTLS policy: {err}"))?;
    Ok((target, data, document))
}

fn install(target: &Path, data: &[u8]) -> Result<(), String> {
    crate::fsutil::write_atomic_file(target, data, 0o600)
        .map_err(|err| format!("[error] failed to write aTLS policy file: {err}"))
}

fn tighten_permissions(target: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).map_err(|err| {
            format!("[error] failed to tighten aTLS policy file permissions: {err}")
        })?;
    }
    Ok(())
}

fn matches_existing(target: &Path, expected: &Value) -> Result<bool, String> {
    let data = fs::read(target)
        .map_err(|err| format!("[error] failed to read aTLS policy file: {err}"))?;
    match serde_json::from_slice::<Value>(&data) {
        Ok(actual) => Ok(&actual == expected),
        Err(_) => Ok(false),
    }
}

fn prompt_replace(cvm_id: &str, target: &Path) -> Result<bool, String> {
    if !io::stdin().is_terminal() {
        return Ok(false);
    }
    eprintln!(
        "{}",
        style::info_line("The updated Dev CVM returned new aTLS trust material.")
    );
    eprintln!(
        "{}",
        style::info_line("This usually happens after a Security CVM update or Dev CVM rebind.")
    );
    eprintln!(
        "{}",
        style::info_line(
            "Your local policy file is the golden measurement this CLI trusts, so Umbra will not replace it automatically."
        )
    );
    // No answer means keep the policy the CLI already trusts.
    Ok(
        prompt::confirm(&format!("Replace {} for CVM {}?", target.display(), cvm_id))
            .unwrap_or(false),
    )
}

fn policy_document(bundle: &PolicyBundle) -> Value {
    let mut app_compose = bundle
        .extra
        .get("app_compose_json")
        .and_then(Value::as_str)
        .and_then(|value| serde_json::from_str::<Value>(value).ok())
        .and_then(|value| value.as_object().cloned())
        .or_else(|| {
            bundle
                .extra
                .get("app_compose")
                .and_then(|value| value.as_object())
                .cloned()
        })
        .unwrap_or_default();
    app_compose.insert(
        "docker_compose_file".to_string(),
        Value::String(bundle.compose_template.clone()),
    );
    app_compose
        .entry("allowed_envs".to_string())
        .or_insert_with(|| json!([]));
    app_compose
        .entry("manifest_version".to_string())
        .or_insert_with(|| json!(2));
    app_compose
        .entry("name".to_string())
        .or_insert_with(|| Value::String(format!("umbra-dev-{}", bundle.cvm_id)));
    app_compose
        .entry("runner".to_string())
        .or_insert_with(|| Value::String("docker-compose".to_string()));
    let policy = json!({
        "type": "dstack_tdx",
        "allowed_tcb_status": ["UpToDate"],
        "expected_bootchain": bundle.expected_bootchain.clone(),
        "os_image_hash": bundle.os_image_hash.clone(),
        "app_compose": Value::Object(app_compose),
        "rtmr3_binding": bundle.rtmr3_binding.clone(),
    });
    policy
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn store_path_uses_config_cvms_dir() {
        assert_eq!(
            store_path(Path::new("/tmp/umbra"), "cvm-1"),
            PathBuf::from("/tmp/umbra/cvms/cvm-1.atls-policy.json")
        );
    }

    #[test]
    fn cvm_id_from_store_path_yields_cvm_id_only_for_canonical_path() {
        let config_dir = Path::new("/tmp/umbra");
        let canonical = config_dir
            .join("cvms")
            .join("cvm-s7oz4pkm2r3c5g6pta35gm5taq.atls-policy.json");
        assert_eq!(
            cvm_id_from_store_path(config_dir, &canonical).as_deref(),
            Some("cvm-s7oz4pkm2r3c5g6pta35gm5taq")
        );

        let custom = Path::new("/tmp/custom/cvm-s7oz4pkm2r3c5g6pta35gm5taq.atls-policy.json");
        assert_eq!(cvm_id_from_store_path(config_dir, custom), None);
    }

    #[test]
    fn policy_document_maps_policy_bundle_to_atls_policy() {
        let bundle = test_policy_bundle("00000000-0000-4000-8000-000000000001", &"e".repeat(64));

        let policy = policy_document(&bundle);

        assert_eq!(policy["type"], "dstack_tdx");
        assert!(policy.get("connect_host").is_none());
        assert_eq!(
            policy["app_compose"]["docker_compose_file"],
            Value::String("services: {}".to_string())
        );
        assert_eq!(
            policy["app_compose"]["features"],
            json!(["kms", "tproxy-net"])
        );
        assert!(serde_json::to_string(&policy["app_compose"])
            .expect("app_compose serializes")
            .starts_with(r#"{"allowed_envs":[],"docker_compose_file":"#));
        assert_eq!(policy["rtmr3_binding"]["security_cvm_proxy_port"], 8080);
    }

    #[test]
    fn update_policy_refuses_to_overwrite_changed_local_trust_in_json_mode() {
        let dir = std::env::temp_dir().join(format!("umbra-cvm-policy-test-{}", Uuid::new_v4()));
        let cvm_id = "00000000-0000-4000-8000-000000000001";
        let old_hash = "a".repeat(64);
        let new_hash = "b".repeat(64);
        write(&dir, &test_policy_bundle(cvm_id, &old_hash), cvm_id)
            .expect("initial policy written");

        let err = write_after_update(&dir, &test_policy_bundle(cvm_id, &new_hash), cvm_id, true)
            .expect_err("changed local trust requires explicit confirmation");

        let policy: Value =
            serde_json::from_slice(&fs::read(store_path(&dir, cvm_id)).expect("policy read"))
                .expect("policy parses");
        assert_eq!(policy["os_image_hash"], old_hash);
        assert!(err.contains("local aTLS policy file was not changed"));
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    #[test]
    fn update_policy_accepts_unchanged_local_trust() {
        let dir = std::env::temp_dir().join(format!("umbra-cvm-policy-test-{}", Uuid::new_v4()));
        let cvm_id = "00000000-0000-4000-8000-000000000001";
        write(
            &dir,
            &test_policy_bundle(cvm_id, "same.example.com"),
            cvm_id,
        )
        .expect("initial policy written");

        let (_, status) = write_after_update(
            &dir,
            &test_policy_bundle(cvm_id, "same.example.com"),
            cvm_id,
            true,
        )
        .expect("unchanged policy accepted");

        assert_eq!(status.as_str(), "unchanged");
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    fn test_policy_bundle(cvm_id: &str, os_image_hash: &str) -> PolicyBundle {
        PolicyBundle {
            cvm_id: cvm_id.to_string(),
            compose_template: "services: {}".to_string(),
            expected_bootchain: json!({
                "mrtd": "a".repeat(64),
                "rtmr0": "b".repeat(64),
                "rtmr1": "c".repeat(64),
                "rtmr2": "d".repeat(64),
            }),
            os_image_hash: os_image_hash.to_string(),
            rtmr3_binding: json!({
                "cvm_id": cvm_id,
                "security_cvm_fqdn": "sc.example.com",
                "security_cvm_proxy_port": 8080,
                "security_cvm_proxy_token_sha256": "f".repeat(64),
                "security_cvm_ca_cert_sha256": "0".repeat(64),
                "authorised_ssh_keys_sha256": "1".repeat(64),
            }),
            extra: {
                let mut extra = Map::new();
                extra.insert(
                    "app_compose".to_string(),
                    json!({
                        "allowed_envs": ["wrong"],
                        "docker_compose_file": "stale",
                        "features": ["wrong"],
                        "runner": "docker-compose"
                    }),
                );
                extra.insert(
                    "app_compose_json".to_string(),
                    Value::String(
                        r#"{"allowed_envs":[],"docker_compose_file":"stale","features":["kms","tproxy-net"],"runner":"docker-compose"}"#
                            .to_string(),
                    ),
                );
                extra
            },
        }
    }
}
