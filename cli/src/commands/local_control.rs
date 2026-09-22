//! Private control/transport workers. Credentials are carried only over pipes.
use std::io::{BufRead, Write};
use std::time::Duration;

use atlas_rs::Policy;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::{
    config::ResolvedConfig,
    console::{console_session, read_json_response, send},
    exit::ExitStatus,
    style,
};

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
enum ControlRequest {
    Create { profile_ids: Vec<uuid::Uuid> },
    Renew { id: uuid::Uuid },
    Revoke { id: uuid::Uuid },
}

fn read_line() -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::io::stdin()
        .lock()
        .take(1024 * 1024 + 1)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "[error] cannot read local worker request")?;
    if bytes.len() > 1024 * 1024 || bytes.last() != Some(&b'\n') {
        return Err("[error] invalid local worker request".into());
    }
    Ok(bytes)
}

fn control(config: &ResolvedConfig) -> Result<Value, String> {
    let request: ControlRequest = serde_json::from_slice(&read_line()?)
        .map_err(|_| "[error] invalid local control request")?;
    let (url, session) = console_session(config).map_err(|(_, error)| error)?;
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| "[error] cannot initialize Console client")?;
    let base = format!("{url}/api/v1/local-workspaces");
    let request = match request {
        ControlRequest::Create { profile_ids } => {
            client.post(base).json(&json!({"profile_ids": profile_ids}))
        }
        ControlRequest::Renew { id } => client.post(format!("{base}/{id}/renew")),
        ControlRequest::Revoke { id } => client.delete(format!("{base}/{id}")),
    }
    .bearer_auth(&session.access_token);
    let response = send(request, "authorize local workspace").map_err(|(_, error)| error)?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(json!({"revoked": true}));
    }
    read_json_response(response, "authorize local workspace").map_err(|(_, error)| error)
}

pub fn run(config: &ResolvedConfig) -> ExitStatus {
    match control(config) {
        Ok(value) => {
            println!("{value}");
            ExitStatus::Ok
        }
        Err(error) => {
            style::eprintln_error(&error);
            ExitStatus::Error
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelRequest {
    fqdn: String,
    atls_policy: Value,
}

fn strict_policy(value: Value) -> Result<Policy, String> {
    let policy: Policy =
        serde_json::from_value(value).map_err(|_| "invalid Security CVM policy")?;
    match &policy {
        Policy::DstackTdx(tdx) => {
            if tdx.disable_runtime_verification
                || tdx.expected_bootchain.is_none()
                || tdx.app_compose.is_none()
                || tdx.os_image_hash.is_none()
            {
                return Err(
                    "Security CVM policy must include complete runtime verification".into(),
                );
            }
        }
    }
    Ok(policy)
}

pub fn tunnel() -> ExitStatus {
    // Read exactly a newline without buffering subsequent proxy bytes from the pipe.
    let result = (|| -> Result<(), String> {
        let mut data = Vec::new();
        let mut stdin = std::io::stdin().lock();
        use std::io::Read;
        loop {
            let mut byte = [0];
            stdin
                .read_exact(&mut byte)
                .map_err(|_| "invalid local tunnel request")?;
            data.push(byte[0]);
            if data.len() > 1024 * 1024 {
                return Err("local tunnel request too large".into());
            }
            if byte[0] == b'\n' {
                break;
            }
        }
        drop(stdin);
        let request: TunnelRequest =
            serde_json::from_slice(&data).map_err(|_| "invalid local tunnel request")?;
        if request.fqdn.is_empty()
            || request.fqdn.len() > 253
            || !request
                .fqdn
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
        {
            return Err("invalid Security CVM hostname".into());
        }
        let policy = strict_policy(request.atls_policy)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|_| "cannot start local transport")?;
        runtime.block_on(async move {
            let tcp = tokio::net::TcpStream::connect((request.fqdn.as_str(), 443)).await
                .map_err(|_| "cannot connect to Security CVM")?;
            // Deliberately no Dev-side temporary runtime-policy exception here.
            let (mut tls, _) = atlas_rs::atls_connect(tcp, &request.fqdn, policy, None).await
                .map_err(|error| format!("Security CVM attestation failed; no sandbox traffic was sent: {error}"))?;
            tls.write_all(format!("GET /umbra/proxy HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: umbra-proxy\r\n\r\n", request.fqdn).as_bytes()).await
                .map_err(|_| "Security CVM tunnel upgrade failed")?;
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                if header.len() >= 16384 { return Err("Security CVM tunnel header too large".into()); }
                header.push(tls.read_u8().await.map_err(|_| "Security CVM tunnel closed")?);
            }
            let header = std::str::from_utf8(&header).map_err(|_| "invalid Security CVM tunnel response")?;
            let mut lines = header.split("\r\n");
            let status = lines.next().unwrap_or_default();
            let fields: Vec<_> = lines.filter_map(|s| s.split_once(':')).collect();
            if status.split_whitespace().nth(1) != Some("101")
                || !fields.iter().any(|(n,v)| n.eq_ignore_ascii_case("upgrade") && v.trim().eq_ignore_ascii_case("umbra-proxy")) {
                return Err("Security CVM rejected the proxy tunnel".into());
            }
            // A readiness record is consumed only by the host supervisor.
            println!("{{\"ready\":true}}");
            std::io::stdout().flush().map_err(|_| "local tunnel output failed")?;
            let (mut read, mut write) = tokio::io::split(tls);
            let mut input = tokio::io::stdin();
            let mut output = tokio::io::stdout();
            tokio::select! {
                result = tokio::io::copy(&mut input, &mut write) => { result.map_err(|_| "local tunnel input failed")?; },
                result = tokio::io::copy(&mut read, &mut output) => { result.map_err(|_| "local tunnel output failed")?; },
            }
            Ok(())
        })
    })();
    match result {
        Ok(()) => ExitStatus::Ok,
        Err(error) => {
            style::eprintln_error(&format!("[error] {error}"));
            ExitStatus::Error
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    /// Local transport cannot inherit the Dev transport's temporary policy exception.
    #[rstest]
    #[case::bypass(json!({"type":"dstack_tdx","disable_runtime_verification":true}))]
    #[case::missing_pins(json!({"type":"dstack_tdx"}))]
    fn local_strict_policy_failure(#[case] value: Value) {
        assert!(strict_policy(value).is_err());
    }
}
