use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::ClientConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use std::sync::{Arc, Mutex};

#[cfg(test)]
use x509_parser::prelude::{FromDer, X509Certificate};

#[cfg(not(target_arch = "wasm32"))]
use rustls::crypto::aws_lc_rs;

#[cfg(target_arch = "wasm32")]
use rustls::crypto::ring;

mod protocol;
mod tdx;

pub use tdx::TdxTcbPolicy;

#[cfg(not(target_arch = "wasm32"))]
pub mod platform {
    pub use std::time::SystemTime;
    pub use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    pub use tokio_rustls::client::TlsStream;
    pub use tokio_rustls::TlsConnector;
}

#[cfg(target_arch = "wasm32")]
pub mod platform {
    pub use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    pub use futures_rustls::client::TlsStream;
    pub use futures_rustls::TlsConnector;
    pub use web_time::SystemTime;
}

use platform::*;

/// Errors returned by the RA-TLS client.
#[derive(Debug, Error)]
pub enum RatlsError {
    #[error("io error: {0}")]
    Io(String),
    #[error("x509 parse error: {0}")]
    X509(String),
    #[error("policy violation: {0}")]
    Policy(String),
    #[error("vendor verification failed: {0}")]
    Vendor(String),
    #[error("unsupported tee type: {0}")]
    TeeUnsupported(String),
}

/// Supported TEE types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum TeeType {
    Tdx,
}

impl Default for TeeType {
    fn default() -> Self {
        TeeType::Tdx
    }
}

/// Attestation policy describing acceptable TEEs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default = "default_tee_type")]
    pub tee_type: TeeType,
    #[serde(default)]
    pub min_tdx_tcb: Option<TdxTcbPolicy>,
    #[serde(default = "default_allowed_tdx_status")]
    pub allowed_tdx_status: Vec<String>,
    #[serde(default = "default_pccs_url")]
    pub pccs_url: Option<String>,
}

const DEFAULT_PCCS_URL: &str = "https://pccs.phala.network/tdx/certification/v4";
const fn default_tee_type() -> TeeType {
    TeeType::Tdx
}

fn default_allowed_tdx_status() -> Vec<String> {
    vec!["UpToDate".to_string()]
}

fn default_pccs_url() -> Option<String> {
    Some(DEFAULT_PCCS_URL.to_string())
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            tee_type: default_tee_type(),
            min_tdx_tcb: None,
            allowed_tdx_status: default_allowed_tdx_status(),
            pccs_url: default_pccs_url(),
        }
    }
}

impl Policy {
    /// Relaxed defaults for local development where PCCS or platform status may be noisy.
    pub fn dev_tdx() -> Self {
        let mut policy = Policy::default();
        policy.allowed_tdx_status = vec![
            "UpToDate".into(),
            "UpToDateWithWarnings".into(),
            "OutOfDate".into(),
            "OutOfDateConfigurationNeeded".into(),
            "ConfigurationNeeded".into(),
            "SWHardeningNeeded".into(),
            "ConfigurationAndSWHardeningNeeded".into(),
        ];
        policy
    }

    /// Strict attestation policy intended for production use.
    pub fn strict_tdx() -> Self {
        Policy::default()
    }
}

/// Configure where and how the attestation request is sent after TLS is established.
#[derive(Debug, Clone)]
pub struct AttestationEndpoint {
    pub path: String,
    pub host: String,
    pub use_keep_alive: bool,
}

impl Default for AttestationEndpoint {
    fn default() -> Self {
        Self {
            path: "/tdx_quote".into(),
            host: "localhost".into(),
            use_keep_alive: true,
        }
    }
}

/// Result of the attestation and TLS handshake.
#[derive(Debug, Clone)]
pub struct AttestationResult {
    pub trusted: bool,
    pub tee_type: TeeType,
    pub measurement: Option<String>,
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
}

/// Trait alias for async byte streams on native targets.
#[cfg(not(target_arch = "wasm32"))]
pub trait AsyncByteStream: AsyncRead + AsyncWrite + Unpin + Send {}
#[cfg(not(target_arch = "wasm32"))]
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncByteStream for T {}

/// Trait alias for async byte streams on wasm, where `Send` is not required.
#[cfg(target_arch = "wasm32")]
pub trait AsyncByteStream: AsyncRead + AsyncWrite + Unpin {}
#[cfg(target_arch = "wasm32")]
impl<T: AsyncRead + AsyncWrite + Unpin> AsyncByteStream for T {}

/// Verifier that accepts any certificate but records the presented leaf.
#[derive(Debug, Clone, Default)]
struct PromiscuousVerifier {
    last_cert: Arc<Mutex<Option<Vec<u8>>>>,
}

impl PromiscuousVerifier {
    fn new() -> Self {
        Self {
            last_cert: Arc::new(Mutex::new(None)),
        }
    }

    fn take_cert(&self) -> Option<Vec<u8>> {
        self.last_cert.lock().ok()?.take()
    }
}

impl ServerCertVerifier for PromiscuousVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        if let Ok(mut guard) = self.last_cert.lock() {
            *guard = Some(end_entity.to_vec());
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn get_crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(aws_lc_rs::default_provider())
}

#[cfg(target_arch = "wasm32")]
fn get_crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(ring::default_provider())
}

fn build_client_config(
    verifier: Arc<PromiscuousVerifier>,
    alpn: Option<Vec<String>>,
) -> Arc<ClientConfig> {
    let provider = get_crypto_provider();
    let mut config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    if let Some(protocols) = alpn {
        config.alpn_protocols = protocols.into_iter().map(|s| s.into_bytes()).collect();
    }
    Arc::new(config)
}

/// Establish a TLS session with a promiscuous verifier and return the server's leaf certificate.
pub async fn tls_handshake<S>(
    stream: S,
    server_name: &str,
    alpn: Option<Vec<String>>,
) -> Result<(TlsStream<S>, Vec<u8>), RatlsError>
where
    S: AsyncByteStream + 'static,
{
    let verifier = Arc::new(PromiscuousVerifier::new());
    let config = build_client_config(verifier.clone(), alpn);
    let connector = TlsConnector::from(config);
    let server_name = ServerName::try_from(server_name.to_owned())
        .map_err(|e| RatlsError::Policy(e.to_string()))?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;

    let cert = verifier
        .take_cert()
        .ok_or_else(|| RatlsError::Policy("missing server certificate".into()))?;

    Ok((tls_stream, cert))
}

/// Verify attestation data over an existing TLS stream using the captured server certificate.
pub async fn verify_attestation_over_stream<S>(
    tls_stream: &mut TlsStream<S>,
    server_cert: &[u8],
    policy: &Policy,
    endpoint: &AttestationEndpoint,
) -> Result<AttestationResult, RatlsError>
where
    S: AsyncByteStream,
{
    protocol::verify_attestation_stream(tls_stream, server_cert, policy, endpoint).await
}

/// Establishes a TLS session, performs the attestation protocol, and returns a verified stream.
pub async fn tls_connect<S>(
    stream: S,
    server_name: &str,
    policy: Policy,
    alpn: Option<Vec<String>>,
) -> Result<(TlsStream<S>, AttestationResult), RatlsError>
where
    S: AsyncByteStream + 'static,
{
    let (mut tls_stream, cert) = tls_handshake(stream, server_name, alpn).await?;

    let attestation = verify_attestation_over_stream(
        &mut tls_stream,
        &cert,
        &policy,
        &AttestationEndpoint::default(),
    )
    .await?;

    Ok((tls_stream, attestation))
}

#[cfg(test)]
pub(crate) fn spki_from_cert(cert_der: &[u8]) -> Result<Vec<u8>, RatlsError> {
    let (_, cert) =
        X509Certificate::from_der(cert_der).map_err(|e| RatlsError::X509(format!("{e:?}")))?;
    Ok(cert.public_key().raw.to_vec())
}

/// Compute SHA2-256 over the provided data.
#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{Certificate, CertificateParams, DistinguishedName, DnType};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn spki_extraction() {
        let mut params = CertificateParams::new(vec!["example.com".into()]);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "example.com");
        let cert = Certificate::from_params(params).unwrap();
        let cert_der = cert.serialize_der().unwrap();
        let spki = spki_from_cert(&cert_der).unwrap();
        assert!(!spki.is_empty());
    }

    #[tokio::test]
    #[ignore]
    async fn promiscuous_verifier_records_cert() {
        let verifier = Arc::new(PromiscuousVerifier::new());
        let provider = get_crypto_provider();
        let mut config = ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        let connector = TlsConnector::from(config);

        // simple rustls server
        let server_cert = Certificate::from_params(CertificateParams::default()).unwrap();
        let cert = {
            let bytes = server_cert.serialize_der().unwrap().into_boxed_slice();
            CertificateDer::from_slice(Box::leak(bytes))
        };
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
            server_cert.serialize_private_key_der(),
        ));
        let server_config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(stream).await.unwrap();
            AsyncWriteExt::write_all(&mut tls, b"hi").await.unwrap();
        });

        let client_stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = connector
            .connect(ServerName::try_from("example.com").unwrap(), client_stream)
            .await
            .unwrap();
        let mut buf = [0u8; 2];
        AsyncReadExt::read_exact(&mut tls, &mut buf).await.unwrap();
        server.await.unwrap();

        assert!(verifier.take_cert().is_some());
    }
}
