use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use atlas_rs::{AsyncByteStream, AtlsVerificationError, AtlsVerifier, Policy, Report};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

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
    // ===== CONCRETE TEMPORARY: SC aTLS image-policy check disabled (delete to re-enable) =====
    // The delivered policy is still validated above (strict, well-formed). Here we strip the
    // image/runtime pins so the Dev egress forwarder accepts any genuine SC TEE at the bound
    // FQDN regardless of its app image, avoiding fleet-wide Dev CVM updates on SC image bumps.
    // See docs/sc-policy-check-disabled.md.
    let policy = force_disable_sc_runtime_verification(policy);
    // ===== END CONCRETE TEMPORARY =====
    Ok(policy)
}

// ===== CONCRETE TEMPORARY: SC aTLS image-policy check disabled =====
// Forces runtime verification OFF on the loaded SC policy so the Dev egress forwarder accepts
// ANY genuine SC TEE at the bound FQDN, regardless of its app image. Genuine-TEE proof is
// retained by atlas-rs (DCAP quote, TCB status, cert-in-event-log binding, EKM anti-replay,
// RTMR replay); only bootchain/app_compose/os_image pinning is skipped.
// TO RE-ENABLE: delete this fn, its call site in load_policy() above, and the marked unit test
// (`temporarily_forces_runtime_verification_disabled`). validate_policy() already enforces the
// strict policy on the delivered input. See docs/sc-policy-check-disabled.md.
fn force_disable_sc_runtime_verification(mut policy: Policy) -> Policy {
    match &mut policy {
        Policy::DstackTdx(tdx) => {
            tdx.disable_runtime_verification = true;
            tdx.expected_bootchain = None;
            tdx.app_compose = None;
            tdx.os_image_hash = None;
        }
    }
    policy
}
// ===== END CONCRETE TEMPORARY =====

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

pub async fn atls_connect_with_route_sni<S>(
    stream: S,
    server_name: &str,
    route_server_name: &str,
    policy: Policy,
) -> std::result::Result<(TlsStream<S>, Report), AtlsVerificationError>
where
    S: AsyncByteStream + 'static,
{
    let (mut tls_stream, peer_cert, session_ekm) =
        tls_handshake_with_cert_name(stream, route_server_name, server_name).await?;
    let verifier = policy.into_verifier()?;
    let report = verifier
        .verify(&mut tls_stream, &peer_cert, &session_ekm, server_name)
        .await?;
    Ok((tls_stream, report))
}

async fn tls_handshake_with_cert_name<S>(
    stream: S,
    route_server_name: &str,
    cert_server_name: &str,
) -> std::result::Result<(TlsStream<S>, Vec<u8>, Vec<u8>), AtlsVerificationError>
where
    S: AsyncByteStream + 'static,
{
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let cert_name = ServerName::try_from(cert_server_name.to_owned())
        .map_err(|error| AtlsVerificationError::InvalidServerName(error.to_string()))?;
    let verifier = WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|error| {
            AtlsVerificationError::TlsHandshake(format!(
                "failed to build certificate verifier: {error}"
            ))
        })?;
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CertificateNameVerifier {
            inner: verifier,
            cert_name,
        }))
        .with_no_client_auth();
    let route_name = ServerName::try_from(route_server_name.to_owned())
        .map_err(|error| AtlsVerificationError::InvalidServerName(error.to_string()))?;
    let tls_stream = TlsConnector::from(Arc::new(config))
        .connect(route_name, stream)
        .await
        .map_err(|error| AtlsVerificationError::TlsHandshake(error.to_string()))?;
    let (_, connection) = tls_stream.get_ref();
    let peer_cert = connection
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .map(|certificate| certificate.as_ref().to_vec())
        .ok_or(AtlsVerificationError::MissingCertificate)?;
    let mut session_ekm = vec![0_u8; 32];
    connection
        .export_keying_material(&mut session_ekm, b"EXPORTER-Channel-Binding", None)
        .map_err(|error| {
            AtlsVerificationError::TlsHandshake(format!("failed to extract session EKM: {error}"))
        })?;
    Ok((tls_stream, peer_cert, session_ekm))
}

#[derive(Debug)]
struct CertificateNameVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    cert_name: ServerName<'static>,
}

impl ServerCertVerifier for CertificateNameVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        self.inner.verify_server_cert(
            end_entity,
            intermediates,
            &self.cert_name,
            ocsp_response,
            now,
        )
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
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

    // ===== CONCRETE TEMPORARY: SC aTLS image-policy check disabled =====
    // Verifies load_policy() strips the image/runtime pins from a strict delivered policy.
    // Delete this test when re-enabling. See docs/sc-policy-check-disabled.md.
    #[test]
    fn temporarily_forces_runtime_verification_disabled() {
        let temp = tempdir().unwrap();
        let policy_path = temp.path().join("policy.json");
        fs::write(&policy_path, strict_policy_json()).unwrap();

        match load_policy(&policy_path).unwrap() {
            Policy::DstackTdx(tdx) => {
                assert!(tdx.disable_runtime_verification);
                assert!(tdx.expected_bootchain.is_none());
                assert!(tdx.app_compose.is_none());
                assert!(tdx.os_image_hash.is_none());
            }
        }
    }
    // ===== END CONCRETE TEMPORARY =====

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
