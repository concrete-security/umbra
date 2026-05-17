use std::sync::Arc;

use atlas_rs::{AsyncByteStream, AtlsVerificationError, AtlsVerifier, Policy, Report};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;

pub async fn connect_with_route_sni<S>(
    stream: S,
    server_name: &str,
    route_server_name: &str,
    policy: Policy,
    alpn: Option<Vec<String>>,
) -> Result<(TlsStream<S>, Report), AtlsVerificationError>
where
    S: AsyncByteStream + 'static,
{
    let (mut tls_stream, peer_cert, session_ekm) =
        tls_handshake_with_cert_name(stream, route_server_name, server_name, alpn).await?;
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
    alpn: Option<Vec<String>>,
) -> Result<(TlsStream<S>, Vec<u8>, Vec<u8>), AtlsVerificationError>
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
    let mut config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(CertificateNameVerifier {
            inner: verifier,
            cert_name,
        }))
        .with_no_client_auth();
    if let Some(protocols) = alpn {
        config.alpn_protocols = protocols.into_iter().map(String::into_bytes).collect();
    }

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
    ) -> Result<ServerCertVerified, RustlsError> {
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
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
