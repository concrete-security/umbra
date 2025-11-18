//! Live TDX quote verification against Intel PCS using dcap-qvl.
//! Requires network access; disabled by default.

#[tokio::test]
#[ignore]
async fn verify_live_tdx_quote_from_concrete_security() {
    let client = reqwest::Client::new();
    let resp = match client
        .post("https://vllm.concrete-security.com/tdx_quote")
        .json(&serde_json::json!({ "report_data": "deadbeefcafebabe" }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skipping live TDX quote verify due to fetch error: {e}");
            return;
        }
    };
    let status = resp.status();
    assert!(
        status.is_success(),
        "quote endpoint returned {status}"
    );
    let body: serde_json::Value = resp.json().await.expect("decode quote json");
    let quote_hex = body["quote"]["quote"]
        .as_str()
        .expect("missing quote field");
    let quote_bytes = hex::decode(quote_hex).expect("decode quote hex");

    let collateral = dcap_qvl::collateral::get_collateral_from_pcs(&quote_bytes)
        .await
        .expect("fetch collateral");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let _tcb = dcap_qvl::verify::verify(&quote_bytes, &collateral, now)
        .expect("tdx verify");
}

/// Fetch a live quote + collateral, embed into a cert, and exercise the rustls verifier (ignored, networked).
#[tokio::test]
#[ignore]
async fn tls_handshake_with_live_tdx_quote() {
    let client = reqwest::Client::new();
    let resp = match client
        .post("https://vllm.concrete-security.com/tdx_quote")
        .json(&serde_json::json!({ "report_data": "deadbeefcafebabe" }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            eprintln!("skipping live TDX handshake due to fetch error: {e}");
            return;
        }
    };
    let status = resp.status();
    assert!(status.is_success(), "quote endpoint returned {status}");
    let body: serde_json::Value = resp.json().await.expect("decode quote json");
    let quote_hex = body["quote"]["quote"].as_str().expect("missing quote");
    let quote_bytes = hex::decode(quote_hex).expect("decode quote hex");

    let collateral = dcap_qvl::collateral::get_collateral_from_pcs(&quote_bytes)
        .await
        .expect("fetch collateral");

    // Build evidence with key binding and TDX TCB claims.
    let key_pair = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).expect("key");
    let spki_der = key_pair.public_key_der();
    let spki_hash = ratls_core::hash_spki_der(&spki_der, ratls_core::PubkeyHashAlg::Sha256);

    let tdx_tcb = ratls_core::TdxTcbClaims {
        mrseam: None,
        mrtmrs: None,
        tcb_svn: None,
    };
    let evidence_struct = ratls_core::DiceEvidenceTyped {
        fmt: "dice-ratls-v1".into(),
        tee_type: "tdx".into(),
        quote: quote_bytes.clone(),
        endorsements: Some(serde_json::to_vec(&collateral).expect("encode collateral")),
        claims: ratls_core::EvidenceClaims {
            pubkey_hash_alg: "sha-256".into(),
            pubkey_hash: spki_hash.clone(),
            workload_id: Some("live-tdx".into()),
            measurement: None,
            timestamp: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            ),
            nonce: None,
            tdx_tcb: Some(tdx_tcb),
            extra: serde_cbor::Value::Map(Default::default()),
        },
    };
    let evidence_cbor = serde_cbor::to_vec(&evidence_struct).expect("cbor encode evidence");

    // Build cert with DICE extension.
    let mut params = rcgen::CertificateParams::default();
    params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    params.key_pair = Some(key_pair);
    params
        .custom_extensions
        .push(rcgen::CustomExtension::from_oid_content(ratls_core::DICE_OID, evidence_cbor));
    let cert = rcgen::Certificate::from_params(params).expect("cert params");
    let cert_der = cert.serialize_der().expect("cert der");
    let pk_der = cert.serialize_private_key_der();

    // Start a simple rustls server using the cert/key, and connect with our verifier.
    use tokio::{net::TcpListener, io::{AsyncReadExt, AsyncWriteExt}};
    use tokio_rustls::TlsAcceptor;
    use tokio_rustls::rustls::{self, PrivateKey, Certificate};

    let server_cfg = {
        let cert_chain = vec![Certificate(cert_der.clone())];
        let key = PrivateKey(pk_der.clone());
        let cfg = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .expect("server config");
        std::sync::Arc::new(cfg)
    };
    let acceptor = TlsAcceptor::from(server_cfg);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().unwrap();

    // Spawn server.
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let mut tls = acceptor.accept(stream).await.expect("tls accept");
        let mut buf = [0u8; 4];
        tls.read_exact(&mut buf).await.expect("read");
        tls.write_all(b"pong").await.expect("write");
    });

    // Client connect with RA verifier.
    let stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let policy = ratls_core::Policy {
        tee_type: ratls_core::TeeType::Tdx,
        workload_ids: Some(vec!["live-tdx".into()]),
        measurements: None,
        max_quote_age_secs: Some(3600),
        min_tdx_tcb: None,
    };
    let (mut tls_client, att) = ratls_core::tls_connect(stream, "example.com", policy, None)
        .await
        .expect("tls connect");
    assert!(att.trusted, "attestation should be trusted");
    tls_client.write_all(b"ping").await.expect("write ping");
    let mut buf = vec![0u8; 4];
    tls_client.read_exact(&mut buf).await.expect("read pong");
    assert_eq!(&buf, b"pong");

    server.await.expect("server join");
}
