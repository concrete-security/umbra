use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ratls_core::{tls_connect, Policy};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[tokio::test]
async fn verify_live_tdx_quote() {
    let client = reqwest::Client::new();
    let resp = match client
        .post("https://vllm.concrete-security.com/tdx_quote")
        .json(&serde_json::json!({ "report_data": "deadbeefcafebabe" }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(err) => {
            eprintln!("quote fetch failed: {err}");
            return;
        }
    };
    if !resp.status().is_success() {
        eprintln!("quote endpoint returned {}", resp.status());
        return;
    }
    let body: serde_json::Value = resp.json().await.expect("decode json");
    let quote_hex = match body["quote"]["quote"].as_str() {
        Some(v) => v,
        None => {
            eprintln!("missing quote field");
            return;
        }
    };
    let quote = match hex::decode(quote_hex) {
        Ok(v) => v,
        Err(err) => {
            eprintln!("invalid quote hex: {err}");
            return;
        }
    };

    let collateral = match dcap_qvl::collateral::get_collateral_from_pcs(&quote).await {
        Ok(c) => c,
        Err(err) => {
            eprintln!("failed to fetch collateral: {err}");
            return;
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    let res = dcap_qvl::verify::verify(&quote, &collateral, now);
    assert!(res.is_ok(), "live quote verification failed: {res:?}");
}

#[tokio::test]
async fn connect_to_vllm_with_ratls() {
    const HOST: &str = "vllm.concrete-security.com";
    let stream = TcpStream::connect((HOST, 443))
        .await
        .unwrap_or_else(|err| panic!("tcp connect to {HOST} failed: {err}"));

    let policy = Policy {
        allowed_tdx_status: vec![
            "UpToDate".into(),
            "UpToDateWithWarnings".into(),
            "ConfigurationNeeded".into(),
            "SWHardeningNeeded".into(),
            "ConfigurationAndSWHardeningNeeded".into(),
            "OutOfDate".into(),
            "OutOfDateConfigurationNeeded".into(),
        ],
        require_attestation: false,
        ..Policy::default()
    };

    let (mut tls, attestation) = tls_connect(stream, HOST, policy, None)
        .await
        .unwrap_or_else(|err| panic!("ratls tls_connect failed: {err}"));

    assert!(
        !attestation.trusted,
        "attestation unexpectedly marked trusted for {HOST}: {:?}",
        attestation
    );

    let request = format!("HEAD / HTTP/1.1\r\nHost: {HOST}\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes())
        .await
        .unwrap_or_else(|err| panic!("failed to send HEAD request to {HOST}: {err}"));

    let mut buf = vec![0u8; 512];
    let bytes = tls
        .read(&mut buf)
        .await
        .unwrap_or_else(|err| panic!("failed reading response from {HOST}: {err}"));
    assert!(
        bytes > 0,
        "no data received from {HOST} despite successful TLS connect"
    );
}
