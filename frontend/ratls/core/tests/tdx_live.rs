use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
