use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};

use atlas_rs::Policy;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct HelperError {
    message: String,
}

impl HelperError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for HelperError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for HelperError {}

pub type Result<T> = std::result::Result<T, HelperError>;

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectRequest {
    pub fqdn: String,
    pub connect_host: Option<String>,
    pub port: u16,
    pub policy_path: PathBuf,
    pub ca_cert_path: PathBuf,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct RelayResponse<'a> {
    pub host: &'a str,
    pub port: u16,
}

pub fn parse_request(input: &[u8]) -> Result<ConnectRequest> {
    let request: ConnectRequest = serde_json::from_slice(input)
        .map_err(|error| HelperError::new(format!("invalid helper request JSON: {error}")))?;
    validate_request(&request)?;
    Ok(request)
}

pub fn validate_request(request: &ConnectRequest) -> Result<()> {
    if request.fqdn.trim().is_empty() {
        return Err(HelperError::new("fqdn must not be empty"));
    }
    if request.fqdn.chars().any(|character| character.is_control()) {
        return Err(HelperError::new("fqdn must not contain control characters"));
    }
    if let Some(connect_host) = request.connect_host.as_deref() {
        if connect_host.trim().is_empty() {
            return Err(HelperError::new("connect_host must not be empty"));
        }
        if connect_host.chars().any(|character| character.is_control()) {
            return Err(HelperError::new(
                "connect_host must not contain control characters",
            ));
        }
    }
    if request.port == 0 {
        return Err(HelperError::new("port must be in 1..=65535"));
    }
    ensure_nonempty_file(&request.policy_path, "policy_path")?;
    ensure_nonempty_file(&request.ca_cert_path, "ca_cert_path")?;
    Ok(())
}

pub fn load_policy(path: &Path) -> Result<Policy> {
    let policy_bytes = fs::read(path)
        .map_err(|error| HelperError::new(format!("failed to read policy_path: {error}")))?;
    let policy: Policy = serde_json::from_slice(&policy_bytes)
        .map_err(|error| HelperError::new(format!("invalid aTLS policy JSON: {error}")))?;
    validate_policy(&policy)?;
    Ok(policy)
}

pub fn validate_policy(policy: &Policy) -> Result<()> {
    match policy {
        Policy::DstackTdx(tdx) => {
            if tdx.disable_runtime_verification {
                return Err(HelperError::new(
                    "aTLS policy must not disable runtime verification",
                ));
            }
            if tdx.expected_bootchain.is_none()
                || tdx.app_compose.is_none()
                || tdx.os_image_hash.is_none()
            {
                return Err(HelperError::new(
                    "aTLS policy is missing runtime verification fields",
                ));
            }
        }
    }
    Ok(())
}

pub fn ensure_nonempty_file(path: &Path, field_name: &str) -> Result<()> {
    let metadata = fs::metadata(path)
        .map_err(|error| HelperError::new(format!("{field_name} is not readable: {error}")))?;
    if !metadata.is_file() {
        return Err(HelperError::new(format!(
            "{field_name} must point to a file"
        )));
    }
    if metadata.len() == 0 {
        return Err(HelperError::new(format!("{field_name} must not be empty")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    fn strict_policy_json() -> &'static str {
        r#"{
            "type": "dstack_tdx",
            "expected_bootchain": {
                "mrtd": "aa",
                "rtmr0": "bb",
                "rtmr1": "cc",
                "rtmr2": "dd"
            },
            "app_compose": {
                "runner": "docker-compose",
                "docker_compose_file": "services: {}"
            },
            "os_image_hash": "ee",
            "allowed_tcb_status": ["UpToDate"]
        }"#
    }

    #[test]
    fn parses_and_validates_request() {
        let temp = tempdir().unwrap();
        let policy_path = temp.path().join("policy.json");
        let ca_path = temp.path().join("ca.pem");
        fs::write(&policy_path, strict_policy_json()).unwrap();
        fs::write(&ca_path, "-----BEGIN CERTIFICATE-----\nMIIB\n").unwrap();

        let request = parse_request(
            format!(
                r#"{{"fqdn":"sc.example.com","connect_host":"app-443s.dstack.example.com","port":443,"policy_path":{},"ca_cert_path":{}}}"#,
                serde_json::to_string(policy_path.to_str().unwrap()).unwrap(),
                serde_json::to_string(ca_path.to_str().unwrap()).unwrap()
            )
            .as_bytes(),
        )
        .unwrap();

        assert_eq!(request.fqdn, "sc.example.com");
        assert_eq!(
            request.connect_host.as_deref(),
            Some("app-443s.dstack.example.com")
        );
        assert_eq!(request.port, 443);
        assert!(load_policy(&request.policy_path).is_ok());
    }

    #[test]
    fn rejects_runtime_verification_bypass() {
        let policy: Policy =
            serde_json::from_str(r#"{"type":"dstack_tdx","disable_runtime_verification":true}"#)
                .unwrap();

        let error = validate_policy(&policy).unwrap_err();

        assert!(error.to_string().contains("must not disable"));
    }

    #[test]
    fn rejects_missing_runtime_verification_fields() {
        let policy: Policy = serde_json::from_str(r#"{"type":"dstack_tdx"}"#).unwrap();

        let error = validate_policy(&policy).unwrap_err();

        assert!(error
            .to_string()
            .contains("missing runtime verification fields"));
    }

    #[test]
    fn rejects_zero_port() {
        let request = ConnectRequest {
            fqdn: "sc.example.com".to_string(),
            connect_host: None,
            port: 0,
            policy_path: PathBuf::from("/tmp/policy.json"),
            ca_cert_path: PathBuf::from("/tmp/ca.pem"),
        };

        let error = validate_request(&request).unwrap_err();

        assert!(error.to_string().contains("port must be"));
    }

    #[test]
    fn rejects_invalid_connect_host() {
        let request = ConnectRequest {
            fqdn: "sc.example.com".to_string(),
            connect_host: Some("bad\nhost".to_string()),
            port: 443,
            policy_path: PathBuf::from("/tmp/policy.json"),
            ca_cert_path: PathBuf::from("/tmp/ca.pem"),
        };

        let error = validate_request(&request).unwrap_err();

        assert!(error.to_string().contains("connect_host must not contain"));
    }
}
