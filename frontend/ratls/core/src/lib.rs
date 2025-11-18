//! ratls-core: TLS client attestation helpers (scaffold).
//! Implements SPKI hashing, DICE extension extraction, and CBOR evidence decode.

use sha2::{Digest, Sha256, Sha384};
use thiserror::Error;
use x509_parser::prelude::*;
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use rustls::{Certificate as RustlsCertificate, ClientConfig, Error as RustlsError, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// DICE tagged evidence OID (TCG DICE 2.23.133.5.4.9).
pub const DICE_OID: &[u64] = &[2, 23, 133, 5, 4, 9];
pub const DICE_OID_STR: &str = "2.23.133.5.4.9";

/// Hash algorithm used for binding TLS SPKI to evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PubkeyHashAlg {
    Sha256,
    Sha384,
}

impl PubkeyHashAlg {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "sha-256" => Some(Self::Sha256),
            "sha-384" => Some(Self::Sha384),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sha256 => "sha-256",
            Self::Sha384 => "sha-384",
        }
    }
}

/// Error type for parsing and validation steps.
#[derive(Debug, Error)]
pub enum RatlsError {
    #[error("x509 parse error: {0}")]
    X509(String),
    #[error("missing DICE evidence extension")]
    MissingDice,
    #[error("CBOR decode error: {0}")]
    Cbor(String),
    #[error("unknown tee type: {0}")]
    UnknownTee(String),
    #[error("policy violation: {0}")]
    Policy(String),
    #[error("key binding mismatch")]
    KeyBinding,
    #[error("clock error: {0}")]
    Clock(String),
}

/// Compute hash(subjectPublicKeyInfo) for the presented TLS key.
pub fn hash_spki_der(spki_der: &[u8], alg: PubkeyHashAlg) -> Vec<u8> {
    match alg {
        PubkeyHashAlg::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(spki_der);
            hasher.finalize().as_slice().to_vec()
        }
        PubkeyHashAlg::Sha384 => {
            let mut hasher = Sha384::new();
            hasher.update(spki_der);
            hasher.finalize().as_slice().to_vec()
        }
    }
}

/// Extract the DICE evidence extension payload from a DER-encoded certificate.
pub fn extract_dice_extension(cert_der: &[u8]) -> Result<Vec<u8>, RatlsError> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| RatlsError::X509(format!("{e:?}")))?;

    for ext in cert.extensions() {
        if ext.oid.to_id_string() == DICE_OID_STR {
            return Ok(ext.value.to_owned());
        }
    }

    Err(RatlsError::MissingDice)
}

/// Minimal evidence view for early testing.
#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq)]
pub struct DiceEvidence {
    pub fmt: String,
    #[serde(rename = "tee_type")]
    pub tee_type: String,
    #[serde(with = "serde_bytes")]
    pub quote: Vec<u8>,
    #[serde(default, with = "serde_bytes_opt")]
    pub endorsements: Option<Vec<u8>>,
    pub claims: serde_cbor::Value,
}

/// Supported TEE types in the evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeeType {
    Snp,
    Tdx,
    Sgx,
    Cca,
}

impl TeeType {
    pub fn from_str(s: &str) -> Result<Self, RatlsError> {
        match s {
            "snp" => Ok(Self::Snp),
            "tdx" => Ok(Self::Tdx),
            "sgx" => Ok(Self::Sgx),
            "cca" => Ok(Self::Cca),
            other => Err(RatlsError::UnknownTee(other.to_string())),
        }
    }
}

impl Default for TeeType {
    fn default() -> Self {
        TeeType::Tdx
    }
}

    /// Claims extracted from the evidence.
    #[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Clone)]
    pub struct EvidenceClaims {
        #[serde(rename = "pubkey_hash_alg")]
        pub pubkey_hash_alg: String,
    #[serde(rename = "pubkey_hash", with = "serde_bytes")]
    pub pubkey_hash: Vec<u8>,
    #[serde(default)]
    #[serde(rename = "workload_id")]
    pub workload_id: Option<String>,
    #[serde(default)]
    pub measurement: Option<serde_cbor::Value>,
    #[serde(default)]
    pub timestamp: Option<u64>,
        #[serde(default, with = "serde_bytes_opt")]
        pub nonce: Option<Vec<u8>>,
        #[serde(flatten)]
        pub extra: serde_cbor::Value,
    }

/// Strongly-typed evidence view.
#[derive(Debug, serde::Deserialize, serde::Serialize, PartialEq, Clone)]
pub struct DiceEvidenceTyped {
    pub fmt: String,
    #[serde(rename = "tee_type")]
    pub tee_type: String,
    #[serde(with = "serde_bytes")]
    pub quote: Vec<u8>,
    #[serde(default)]
    #[serde(with = "serde_bytes_opt")]
    pub endorsements: Option<Vec<u8>>,
    pub claims: EvidenceClaims,
}

/// Policy controlling acceptance.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    pub tee_type: TeeType,
    pub workload_ids: Option<Vec<String>>,
    pub measurements: Option<Vec<String>>,
    pub max_quote_age_secs: Option<u64>,
    pub min_tcb: Option<serde_json::Value>,
}

/// Decode CBOR evidence into typed structure.
pub fn decode_evidence_typed(cbor: &[u8]) -> Result<DiceEvidenceTyped, RatlsError> {
    serde_cbor::from_slice(cbor).map_err(|e| RatlsError::Cbor(e.to_string()))
}

/// Validate evidence against a minimal policy (TEE type + workload + measurement).
pub fn enforce_policy(evidence: &DiceEvidenceTyped, policy: &Policy) -> Result<(), RatlsError> {
    let tee = TeeType::from_str(&evidence.tee_type)?;
    if tee != policy.tee_type {
        return Err(RatlsError::Policy(format!(
            "unexpected tee_type {}, wanted {:?}",
            evidence.tee_type, policy.tee_type
        )));
    }
    if let Some(allowed) = &policy.workload_ids {
        if let Some(w) = &evidence.claims.workload_id {
            if !allowed.iter().any(|a| a == w) {
                return Err(RatlsError::Policy(format!(
                    "workload_id {w} not in allowlist"
                )));
            }
        } else {
            return Err(RatlsError::Policy("workload_id absent".into()));
        }
    }
    if let Some(allowed_meas) = &policy.measurements {
        if let Some(meas) = &evidence.claims.measurement {
            let meas_hex = match meas {
                serde_cbor::Value::Bytes(b) => hex::encode(b),
                serde_cbor::Value::Text(s) => s.clone(),
                _ => return Err(RatlsError::Policy("measurement type unsupported".into())),
            };
            if !allowed_meas.iter().any(|m| m.eq_ignore_ascii_case(&meas_hex)) {
                return Err(RatlsError::Policy(format!(
                    "measurement {} not allowed",
                    meas_hex
                )));
            }
        } else {
            return Err(RatlsError::Policy("measurement absent".into()));
        }
    }
    if let Some(min_tcb) = &policy.min_tcb {
        // Placeholder: vendor-specific TCB comparison would live here.
        if min_tcb.is_object() {
            // accept; real implementation will compare fields
        }
    }
    Ok(())
}

/// Enforce timestamp freshness against policy.max_quote_age_secs using evidence.claims.timestamp.
pub fn enforce_freshness(evidence: &DiceEvidenceTyped, policy: &Policy) -> Result<(), RatlsError> {
    if let Some(max_age) = policy.max_quote_age_secs {
        let ts = evidence
            .claims
            .timestamp
            .ok_or_else(|| RatlsError::Policy("timestamp absent".into()))?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| RatlsError::Clock(e.to_string()))?
            .as_secs();
        let age = now.saturating_sub(ts);
        if age > max_age {
            return Err(RatlsError::Policy(format!(
                "quote too old: {age}s > {max_age}s"
            )));
        }
    }
    Ok(())
}

/// Compare the SPKI hash in evidence with the certificate's SPKI hash.
pub fn verify_key_binding(cert_der: &[u8], evidence: &DiceEvidenceTyped) -> Result<(), RatlsError> {
    let alg = PubkeyHashAlg::from_str(&evidence.claims.pubkey_hash_alg)
        .ok_or_else(|| RatlsError::Policy("unsupported pubkey_hash_alg".into()))?;

    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| RatlsError::X509(format!("{e:?}")))?;
    let spki_der = cert.public_key().raw.to_owned();
    let computed = hash_spki_der(&spki_der, alg);
    if computed == evidence.claims.pubkey_hash {
        Ok(())
    } else {
        Err(RatlsError::KeyBinding)
    }
}

#[allow(dead_code)]
mod serde_bytes_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(data: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match data {
            Some(inner) => serde_bytes::serialize(inner, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<serde_bytes::ByteBuf> = Option::deserialize(deserializer)?;
        Ok(opt.map(|b| b.into_vec()))
    }
}

/// Decode tagged CBOR evidence from the DICE extension into a generic JSON-like view.
pub fn decode_evidence(cbor: &[u8]) -> Result<DiceEvidence, RatlsError> {
    serde_cbor::from_slice(cbor).map_err(|e| RatlsError::Cbor(e.to_string()))
}

/// Result of attestation verification exposed to callers.
#[derive(Debug, Clone, PartialEq)]
pub struct AttestationResult {
    pub trusted: bool,
    pub tee_type: TeeType,
    pub workload_id: Option<String>,
    pub measurement: Option<String>,
    pub not_after: Option<u64>,
    pub reason: Option<String>,
}

/// rustls server certificate verifier wiring RA checks.
pub struct RatlsVerifier {
    pub policy: Policy,
    latest: Mutex<Option<AttestationResult>>,
}

impl RatlsVerifier {
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            latest: Mutex::new(None),
        }
    }

    pub fn attestation(&self) -> Option<AttestationResult> {
        self.latest
            .lock()
            .ok()
            .and_then(|g| g.clone())
    }

    fn make_result(&self, trusted: bool, tee: TeeType, workload: Option<String>, measurement: Option<String>, reason: Option<String>) -> AttestationResult {
        AttestationResult {
            trusted,
            tee_type: tee,
            workload_id: workload,
            measurement,
            not_after: None,
            reason,
        }
    }

    fn verify_internal(&self, end_entity: &[u8]) -> Result<AttestationResult, RatlsError> {
        let evidence_bytes = extract_dice_extension(end_entity)?;
        let evidence = decode_evidence_typed(&evidence_bytes)?;
        enforce_policy(&evidence, &self.policy)?;
        enforce_freshness(&evidence, &self.policy)?;
        verify_key_binding(end_entity, &evidence)?;

        let tee = TeeType::from_str(&evidence.tee_type)?;
        let measurement = evidence
            .claims
            .measurement
            .as_ref()
            .and_then(|m| match m {
                serde_cbor::Value::Bytes(b) => Some(hex::encode(b)),
                serde_cbor::Value::Text(s) => Some(s.clone()),
                _ => None,
            });

        let result = self.make_result(
            true,
            tee,
            evidence.claims.workload_id.clone(),
            measurement,
            None,
        );
        if let Ok(mut guard) = self.latest.lock() {
            *guard = Some(result.clone());
        }
        Ok(result)
    }
}

impl ServerCertVerifier for RatlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &RustlsCertificate,
        _intermediates: &[RustlsCertificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        match self.verify_internal(&end_entity.0) {
            Ok(_) => Ok(ServerCertVerified::assertion()),
            Err(e) => Err(RustlsError::General(format!("{e}"))),
        }
    }
}

/// Pair of rustls client config and verifier handle to fetch attestation result post-handshake.
pub struct ClientConfigWithVerifier {
    pub config: Arc<ClientConfig>,
    pub verifier: Arc<RatlsVerifier>,
}

/// Build a rustls ClientConfig with the custom RA verifier attached.
pub fn build_client_config(policy: Policy, alpn: Option<Vec<String>>) -> ClientConfigWithVerifier {
    let verifier = Arc::new(RatlsVerifier::new(policy));
    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(verifier.clone())
        .with_no_client_auth();
    if let Some(protocols) = alpn {
        config.alpn_protocols = protocols
            .into_iter()
            .map(|s| s.into_bytes())
            .collect();
    }
    ClientConfigWithVerifier {
        config: Arc::new(config),
        verifier,
    }
}

/// Abstract async byte stream for transport adapters (direct TCP or tunneled).
pub trait AsyncByteStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncByteStream for T {}

/// Establish a TLS session over a provided byte stream using the RA verifier policy.
pub async fn tls_connect<S>(
    stream: S,
    server_name: &str,
    policy: Policy,
    alpn: Option<Vec<String>>,
) -> Result<(TlsStream<S>, AttestationResult), RatlsError>
where
    S: AsyncByteStream + 'static,
{
    let ClientConfigWithVerifier { config, verifier } = build_client_config(policy, alpn);
    let connector = TlsConnector::from(config);
    let server_name = ServerName::try_from(server_name).map_err(|e| RatlsError::Policy(e.to_string()))?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .map_err(|e| RatlsError::Policy(format!("tls connect: {e}")))?;
    let att = verifier.attestation().unwrap_or_else(|| AttestationResult {
        trusted: false,
        tee_type: TeeType::Snp,
        workload_id: None,
        measurement: None,
        not_after: None,
        reason: Some("attestation result unavailable".into()),
    });
    Ok((tls_stream, att))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use rcgen::{CertificateParams, CustomExtension, DistinguishedName, DnType, Error as RcgenError};
    use sha2::Sha256;

    fn build_test_cert_with_dice(ext_payload: &[u8]) -> Result<Vec<u8>, RcgenError> {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "ratls-test");
        params.distinguished_name = dn;
        let dice_ext = CustomExtension::from_oid_content(DICE_OID, ext_payload.to_vec());
        params.custom_extensions.push(dice_ext);
        let cert = rcgen::Certificate::from_params(params)?;
        cert.serialize_der()
    }

    #[test]
    fn hashes_spki_with_sha256_and_sha384() {
        // SPKI bytes from a sample rcgen-generated keypair.
        let spki_der = <Vec<u8>>::from_hex("3059301306072a8648ce3d020106082a8648ce3d030107034200046d720ebac1cfbe7932e7ad731040a1d25ba1103e79a874095e19da6c8d39d80af71acc97c7ee627c4c07da7cde17330fab2022933644d3d3acbb695b118c2f5b").unwrap();
        let sha256_expected = {
            let mut hasher = Sha256::new();
            hasher.update(&spki_der);
            hasher.finalize().as_slice().to_vec()
        };
        let sha384_expected = {
            let mut hasher = Sha384::new();
            hasher.update(&spki_der);
            hasher.finalize().as_slice().to_vec()
        };
        assert_eq!(sha256_expected, hash_spki_der(&spki_der, PubkeyHashAlg::Sha256));
        assert_eq!(sha384_expected, hash_spki_der(&spki_der, PubkeyHashAlg::Sha384));
    }

    #[test]
    fn extracts_dice_extension_and_decodes_cbor() {
        let evidence = DiceEvidenceTyped {
            fmt: "dice-ratls-v1".into(),
            tee_type: "snp".into(),
            quote: vec![0xde, 0xad],
            endorsements: None,
            claims: EvidenceClaims {
                pubkey_hash_alg: "sha-256".into(),
                pubkey_hash: vec![1, 2, 3],
                workload_id: None,
                measurement: None,
                timestamp: None,
                nonce: None,
                extra: serde_cbor::Value::Map(Default::default()),
            },
        };
        let example_claims = serde_cbor::to_vec(&evidence).unwrap();
        let cert_der = build_test_cert_with_dice(&example_claims).expect("cert build");
        let extracted = extract_dice_extension(&cert_der).expect("extract dice");
        assert_eq!(extracted, example_claims);

        let evidence = decode_evidence(&extracted).expect("decode cbor");
        assert_eq!(evidence.fmt, "dice-ratls-v1");
        assert_eq!(evidence.tee_type, "snp");
        assert_eq!(evidence.quote, vec![0xde, 0xad]);
    }

    #[test]
    fn typed_policy_and_binding_flow() {
        // Build a cert and embed evidence with a matching SPKI hash.
        let key_pair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
        let spki_der = key_pair.public_key_der();
        let spki_hash = hash_spki_der(&spki_der, PubkeyHashAlg::Sha256);

        let evidence_struct = DiceEvidenceTyped {
            fmt: "dice-ratls-v1".into(),
            tee_type: "snp".into(),
            quote: vec![0, 0],
            endorsements: None,
            claims: EvidenceClaims {
                pubkey_hash_alg: "sha-256".into(),
                pubkey_hash: spki_hash.clone(),
                workload_id: Some("mock-ai".into()),
                measurement: Some(serde_cbor::Value::Bytes(vec![0x10, 0x20])),
                timestamp: None,
                nonce: None,
                extra: serde_cbor::Value::Map(Default::default()),
            },
        };
        let evidence_cbor = serde_cbor::to_vec(&evidence_struct).unwrap();
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "ratls-typed");
        params.distinguished_name = dn;
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        params.key_pair = Some(key_pair);
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(DICE_OID, evidence_cbor.clone()));
        let cert = rcgen::Certificate::from_params(params).unwrap();
        let cert_der = cert.serialize_der().unwrap();

        // Extract and verify.
        let extracted = extract_dice_extension(&cert_der).expect("dice ext");
        let evidence = decode_evidence_typed(&extracted).expect("typed decode");

        let policy = Policy {
            tee_type: TeeType::Snp,
            workload_ids: Some(vec!["mock-ai".into()]),
            measurements: Some(vec!["1020".into()]),
            max_quote_age_secs: None,
            min_tcb: None,
        };
        enforce_policy(&evidence, &policy).expect("policy passes");
        verify_key_binding(&cert_der, &evidence).expect("key binding");
    }

    #[test]
    fn binding_failure_errors() {
        let key_pair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
        let spki_der = key_pair.public_key_der();
        let wrong_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&spki_der);
            let mut bytes = hasher.finalize().as_slice().to_vec();
            bytes[0] ^= 0xFF;
            bytes
        };
        let evidence_struct = DiceEvidenceTyped {
            fmt: "dice-ratls-v1".into(),
            tee_type: "snp".into(),
            quote: vec![],
            endorsements: None,
            claims: EvidenceClaims {
                pubkey_hash_alg: "sha-256".into(),
                pubkey_hash: wrong_hash,
                workload_id: None,
                measurement: None,
                timestamp: None,
                nonce: None,
                extra: serde_cbor::Value::Map(Default::default()),
            },
        };
        let evidence_cbor = serde_cbor::to_vec(&evidence_struct).unwrap();
        let mut params = CertificateParams::default();
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        params.key_pair = Some(key_pair);
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(DICE_OID, evidence_cbor.clone()));
        let cert = rcgen::Certificate::from_params(params).unwrap();
        let cert_der = cert.serialize_der().unwrap();

        let evidence = decode_evidence_typed(&extract_dice_extension(&cert_der).unwrap()).unwrap();
        let err = verify_key_binding(&cert_der, &evidence).unwrap_err();
        matches!(err, RatlsError::KeyBinding);
    }

    #[test]
    fn ratls_verifier_accepts_matching_evidence() {
        let key_pair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
        let spki_der = key_pair.public_key_der();
        let spki_hash = hash_spki_der(&spki_der, PubkeyHashAlg::Sha256);
        let evidence_struct = DiceEvidenceTyped {
            fmt: "dice-ratls-v1".into(),
            tee_type: "snp".into(),
            quote: vec![1, 2],
            endorsements: None,
            claims: EvidenceClaims {
                pubkey_hash_alg: "sha-256".into(),
                pubkey_hash: spki_hash,
                workload_id: Some("mock-ai".into()),
                measurement: Some(serde_cbor::Value::Bytes(vec![0xab, 0xcd])),
                timestamp: Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                ),
                nonce: None,
                extra: serde_cbor::Value::Map(Default::default()),
            },
        };
        let evidence_cbor = serde_cbor::to_vec(&evidence_struct).unwrap();

        let mut params = CertificateParams::default();
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        params.key_pair = Some(key_pair);
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(DICE_OID, evidence_cbor.clone()));
        let cert = rcgen::Certificate::from_params(params).unwrap();
        let cert_der = cert.serialize_der().unwrap();

        let verifier = RatlsVerifier::new(Policy {
            tee_type: TeeType::Snp,
            workload_ids: Some(vec!["mock-ai".into()]),
            measurements: Some(vec![hex::encode([0xab, 0xcd])]),
            max_quote_age_secs: Some(30),
            min_tcb: None,
        });
        let rustls_cert = RustlsCertificate(cert_der.clone());
        let res = verifier.verify_server_cert(
            &rustls_cert,
            &[],
            &ServerName::try_from("example.com").unwrap(),
            &mut std::iter::empty(),
            &[],
            SystemTime::now(),
        );
        assert!(res.is_ok());
        let att = verifier.attestation();
        assert!(att.is_some());
        let att = att.unwrap();
        assert!(att.trusted);
        assert_eq!(att.workload_id.as_deref(), Some("mock-ai"));
    }

    #[test]
    fn ratls_verifier_rejects_stale_quote() {
        let key_pair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
        let spki_hash = hash_spki_der(&key_pair.public_key_der(), PubkeyHashAlg::Sha256);
        let old_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 3600;
        let evidence_struct = DiceEvidenceTyped {
            fmt: "dice-ratls-v1".into(),
            tee_type: "snp".into(),
            quote: vec![],
            endorsements: None,
            claims: EvidenceClaims {
                pubkey_hash_alg: "sha-256".into(),
                pubkey_hash: spki_hash,
                workload_id: None,
                measurement: None,
                timestamp: Some(old_ts),
                nonce: None,
                extra: serde_cbor::Value::Map(Default::default()),
            },
        };
        let evidence_cbor = serde_cbor::to_vec(&evidence_struct).unwrap();

        let mut params = CertificateParams::default();
        params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
        params.key_pair = Some(key_pair);
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(DICE_OID, evidence_cbor.clone()));
        let cert = rcgen::Certificate::from_params(params).unwrap();
        let cert_der = cert.serialize_der().unwrap();

        let verifier = RatlsVerifier::new(Policy {
            tee_type: TeeType::Snp,
            workload_ids: None,
            measurements: None,
            max_quote_age_secs: Some(10),
            min_tcb: None,
        });
        let rustls_cert = RustlsCertificate(cert_der.clone());
        let res = verifier.verify_server_cert(
            &rustls_cert,
            &[],
            &ServerName::try_from("example.com").unwrap(),
            &mut std::iter::empty(),
            &[],
            SystemTime::now(),
        );
        assert!(res.is_err());
    }
}
