use std::{
    fs,
    path::{Path, PathBuf},
};

use atlas_rs::{AtlsVerificationError, Policy};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde_json::Value;
use sha1::{Digest, Sha1};
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    atls_policy_store, config::ResolvedConfig, console::console_session, exit::ExitStatus, prompt,
    style,
};

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HANDSHAKE_BYTES: usize = 16 * 1024;
const RELAY_CHUNK_BYTES: usize = 16 * 1024;

enum TunnelError {
    Atls {
        host: String,
        detail: String,
        policy_mismatch: bool,
    },
    Unreachable {
        host: String,
        detail: String,
    },
    Other(String),
}

impl TunnelError {
    fn message(&self) -> String {
        match self {
            Self::Atls { host, detail, .. } => {
                format!("[error] aTLS verification failed for {host}: {detail}")
            }
            Self::Unreachable { host, detail } => format!(
                "[error] Could not reach Dev CVM {host} to start a secure session.\n\
                 [info] The connection was accepted but closed before the attested handshake completed; no SSH or agent traffic was sent.\n\
                 [info] This usually means the CVM is still booting or is not running.\n\
                 [info] Check `umbra cvm list`: if it is RUNNING, wait a few seconds and retry; otherwise start it with `umbra cvm start <cvm-id>`.\n\
                 [info] detail: {detail}"
            ),
            Self::Other(message) => message.clone(),
        }
    }
}

pub fn run(target: &str, config: &ResolvedConfig) -> ExitStatus {
    let host = match validate_target(target) {
        Ok(value) => value,
        Err(message) => {
            crate::style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    if config.atls_policy_insecure_skip {
        crate::style::eprintln_error(
            "[usage] umbra tunnel does not support --insecure-skip-atls-policy",
        );
        return ExitStatus::Usage;
    }
    let policy_path = match config.atls_policy.as_deref() {
        Some(value) => value,
        None => {
            crate::style::eprintln_error(
                "[usage] missing aTLS policy; set --atls-policy or UMBRA_ATLS_POLICY",
            );
            return ExitStatus::Usage;
        }
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(value) => value,
        Err(err) => {
            crate::style::eprintln_error(&format!("[error] failed to start async runtime: {err}"));
            return ExitStatus::Error;
        }
    };

    run_with_policy_refresh(
        policy_path,
        |policy| runtime.block_on(run_tunnel(host.clone(), policy)),
        |host, detail| refresh_policy_after_mismatch(config, policy_path, host, detail),
    )
}

fn run_with_policy_refresh(
    policy_path: &Path,
    mut connect: impl FnMut(Policy) -> Result<(), TunnelError>,
    mut refresh: impl FnMut(&str, &str) -> Result<RefreshDecision, (ExitStatus, String)>,
) -> ExitStatus {
    let mut refreshed = false;
    loop {
        let policy = match load_policy(policy_path) {
            Ok(value) => value,
            Err(message) => {
                crate::style::eprintln_error(&message);
                return ExitStatus::Usage;
            }
        };
        match connect(policy) {
            Ok(()) => return ExitStatus::Ok,
            Err(TunnelError::Atls {
                host: failed_host,
                detail,
                policy_mismatch: true,
            }) if !refreshed => match refresh(&failed_host, &detail) {
                Ok(RefreshDecision::Refreshed(path)) => {
                    refreshed = true;
                    eprintln!(
                        "{}",
                        style::info_line(&format!(
                            "refreshed local aTLS policy: {}",
                            path.display()
                        ))
                    );
                    eprintln!("{}", style::info_line("retrying aTLS verification"));
                }
                Ok(RefreshDecision::Declined(message)) => {
                    crate::style::eprintln_error(&message);
                    return ExitStatus::Error;
                }
                Err((status, message)) => {
                    crate::style::eprintln_error(&message);
                    return status;
                }
            },
            Err(err) => {
                crate::style::eprintln_error(&err.message());
                return ExitStatus::Error;
            }
        }
    }
}

fn validate_target(target: &str) -> Result<String, String> {
    let host = target.trim().trim_end_matches('.');
    if host.is_empty() {
        return Err("[usage] tunnel target must not be empty".to_string());
    }
    if host.contains("://") || host.contains('/') || host.contains(':') {
        return Err("[usage] tunnel target must be a Dev CVM FQDN".to_string());
    }
    if host.chars().any(char::is_control) {
        return Err("[usage] tunnel target must not contain control characters".to_string());
    }
    Ok(host.to_string())
}

fn load_policy(path: &Path) -> Result<Policy, String> {
    let data =
        fs::read(path).map_err(|err| format!("[usage] failed to read aTLS policy: {err}"))?;
    let mut document: Value = serde_json::from_slice(&data)
        .map_err(|err| format!("[usage] invalid aTLS policy JSON: {err}"))?;
    // aTLS is FQDN-only. Legacy local policy files may still carry a `connect_host` routing
    // hint; drop it so an old {"connect_host":"x",...} file still loads, with x ignored.
    if let Some(object) = document.as_object_mut() {
        object.remove("connect_host");
    }
    serde_json::from_value(document)
        .map_err(|err| format!("[usage] invalid aTLS policy JSON: {err}"))
}

async fn run_tunnel(host: String, policy: Policy) -> Result<(), TunnelError> {
    let tcp = TcpStream::connect((host.as_str(), 443))
        .await
        .map_err(|err| {
            TunnelError::Other(format!("[error] failed to connect to {host}:443: {err}"))
        })?;
    let (mut tls_stream, _report) = atlas_rs::atls_connect(tcp, &host, policy, None)
        .await
        .map_err(|err| classify_atls_error(host.clone(), err))?;
    websocket_handshake(&mut tls_stream, &host).await?;
    let (reader, writer) = io::split(tls_stream);
    relay_websocket(reader, writer).await.map_err(Into::into)
}

impl From<String> for TunnelError {
    fn from(value: String) -> Self {
        Self::Other(value)
    }
}

enum RefreshDecision {
    Refreshed(PathBuf),
    Declined(String),
}

fn refresh_policy_after_mismatch(
    config: &ResolvedConfig,
    policy_path: &Path,
    host: &str,
    detail: &str,
) -> Result<RefreshDecision, (ExitStatus, String)> {
    refresh_policy_with_confirmation(config, policy_path, host, detail, prompt::confirm)
}

fn refresh_policy_with_confirmation(
    config: &ResolvedConfig,
    policy_path: &Path,
    host: &str,
    detail: &str,
    confirm: impl FnOnce(&str) -> Option<bool>,
) -> Result<RefreshDecision, (ExitStatus, String)> {
    let Some(cvm_id) = atls_policy_store::cvm_id_from_store_path(&config.config_dir, policy_path)
    else {
        return Ok(RefreshDecision::Declined(friendly_mismatch_message(
            host,
            policy_path,
            None,
            detail,
            "This policy path does not look like a per-CVM policy file, so Umbra cannot refresh it automatically.",
        )));
    };
    let console_url = config
        .require_console_url()
        .map_err(|message| (ExitStatus::Usage, message))?;
    let previous: Value = serde_json::from_slice(&fs::read(policy_path).map_err(|_| {
        (
            ExitStatus::Error,
            "[error] could not read the existing local aTLS policy".to_string(),
        )
    })?)
    .map_err(|_| {
        (
            ExitStatus::Error,
            "[error] invalid existing local aTLS policy".to_string(),
        )
    })?;
    validate_policy_context(&previous["rtmr3_binding"], &cvm_id, console_url)
        .map_err(|message| (ExitStatus::Error, message))?;
    let question = friendly_mismatch_message(
        host,
        policy_path,
        Some(&cvm_id),
        detail,
        "Refresh this local policy file from Console and retry verification now?",
    );
    match confirm(&question) {
        Some(true) => {}
        Some(false) => {
            return Ok(RefreshDecision::Declined(
                "[error] local aTLS policy was not refreshed; connection cancelled".to_string(),
            ));
        }
        None => {
            return Ok(RefreshDecision::Declined(friendly_mismatch_message(
                host,
                policy_path,
                Some(&cvm_id),
                detail,
                "The refresh was not confirmed -- no terminal to ask on, no reply, or no usable answer. Re-run from a terminal and answer y if you trust the refreshed policy.",
            )));
        }
    }
    let (console_url, session) = console_session(config).map_err(|(status, message)| {
        (
            status,
            refresh_failed_message(host, policy_path, detail, &message),
        )
    })?;
    let cvm: Value = crate::console::fetch_json(
        console_url,
        &session,
        &format!("/api/v1/cvms/{cvm_id}"),
        &[],
        "check Dev CVM policy target",
    )?;
    if cvm["id"].as_str() != Some(cvm_id.as_str())
        || cvm["state"].as_str() != Some("RUNNING")
        || cvm["error_reason"].as_str() == Some("SECURITY_CVM_REBIND_REQUIRED")
        || !cvm["fqdn"]
            .as_str()
            .and_then(|value| validate_target(value).ok())
            .is_some_and(|value| value.eq_ignore_ascii_case(host))
    {
        return Err((ExitStatus::Error, "[error] Console CVM does not match the failed tunnel target; local policy was not changed".to_string()));
    }
    let bundle = atls_policy_store::fetch_bundle(console_url, &session, &cvm_id).map_err(
        |(status, message)| {
            (
                status,
                refresh_failed_message(host, policy_path, detail, &message),
            )
        },
    )?;
    validate_policy_context(&bundle.rtmr3_binding, &cvm_id, console_url)
        .map_err(|message| (ExitStatus::Error, message))?;
    let path =
        atls_policy_store::write(&config.config_dir, &bundle, &cvm_id).map_err(|message| {
            (
                ExitStatus::Error,
                refresh_failed_message(host, policy_path, detail, &message),
            )
        })?;
    Ok(RefreshDecision::Refreshed(path))
}

fn validate_policy_context(binding: &Value, cvm_id: &str, console_url: &str) -> Result<(), String> {
    let expected = crate::console::validate_console_url(console_url)?;
    let actual = binding["console_url"]
        .as_str()
        .and_then(|value| crate::console::validate_console_url(value).ok());
    if binding["cvm_id"].as_str() != Some(cvm_id) || actual.as_ref() != Some(&expected) {
        return Err("[error] aTLS policy does not match this CVM and Console context; local policy was not changed".to_string());
    }
    Ok(())
}

fn friendly_mismatch_message(
    host: &str,
    policy_path: &Path,
    cvm_id: Option<&str>,
    detail: &str,
    final_line: &str,
) -> String {
    let cvm = cvm_id.unwrap_or("unknown");
    format!(
        "[error] Umbra could not verify this Dev CVM.\n\
         [info] The CVM's measured bootchain, OS image, or app material does not match the local aTLS policy file.\n\
         [info] Console can provide the current policy for this CVM, but Umbra needs confirmation before replacing local trust material.\n\
         [info] CVM: {cvm}\n\
         [info] host: {host}\n\
         [info] policy file: {}\n\
         [info] verifier detail: {detail}\n\
         [info] No SSH or agent traffic has been sent.\n\
         {}",
        policy_path.display(),
        style::info_line(final_line)
    )
}

fn refresh_failed_message(host: &str, policy_path: &Path, detail: &str, reason: &str) -> String {
    format!(
        "{}\n{}",
        friendly_mismatch_message(
            host,
            policy_path,
            atls_policy_store::cvm_id_from_path(policy_path).as_deref(),
            detail,
            "Umbra could not refresh the local policy automatically.",
        ),
        reason
    )
}

fn classify_atls_error(host: String, err: AtlsVerificationError) -> TunnelError {
    let detail = err.to_string();
    if matches!(err, AtlsVerificationError::TlsHandshake(_))
        && is_transport_handshake_failure(&detail)
    {
        TunnelError::Unreachable { host, detail }
    } else {
        let policy_mismatch = is_refreshable_policy_mismatch(&err);
        TunnelError::Atls {
            host,
            detail,
            policy_mismatch,
        }
    }
}

// A TLS handshake that ends with the peer closing/refusing the connection means
// nothing is listening behind the relay yet (CVM still booting or stopped) — a
// reachability problem, not an attestation failure. Genuine verification
// mismatches (quote/RTMR/app_compose/report-data) occur only after a certificate
// is exchanged and stay classified as `Atls`.
fn is_transport_handshake_failure(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("tls handshake eof")
        || detail.contains("unexpected eof")
        || detail.contains("connection reset")
        || detail.contains("connection refused")
        || detail.contains("connection closed")
        || detail.contains("broken pipe")
        || detail.contains("timed out")
        || detail.contains("timeout")
}

fn is_refreshable_policy_mismatch(error: &AtlsVerificationError) -> bool {
    // Atlas 0.2.0 emits these only after quote, TLS binding, and RTMR replay pass.
    // Never infer trust-refresh eligibility from an error's diagnostic text.
    match error {
        AtlsVerificationError::AppComposeHashMismatch { .. }
        | AtlsVerificationError::OsImageHashMismatch {
            actual: Some(_), ..
        } => true,
        AtlsVerificationError::BootchainMismatch { field, .. } => {
            matches!(field.as_str(), "mrtd" | "rtmr0" | "rtmr1" | "rtmr2")
        }
        _ => false,
    }
}

async fn websocket_handshake<S>(stream: &mut S, host: &str) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut nonce = [0_u8; 16];
    getrandom::fill(&mut nonce)
        .map_err(|err| format!("[error] failed to generate WebSocket nonce: {err}"))?;
    let key = BASE64.encode(nonce);
    let request = format!(
        "GET /umbra/tunnel HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: {key}\r\n\
         \r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|err| format!("[error] failed to write WebSocket handshake: {err}"))?;
    stream
        .flush()
        .await
        .map_err(|err| format!("[error] failed to flush WebSocket handshake: {err}"))?;

    let response = read_http_headers(stream).await?;
    validate_websocket_response(&response, &key)
}

async fn read_http_headers<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::new();
    let mut byte = [0_u8; 1];
    while response.len() < MAX_HANDSHAKE_BYTES {
        let count = stream
            .read(&mut byte)
            .await
            .map_err(|err| format!("[error] failed to read WebSocket handshake: {err}"))?;
        if count == 0 {
            return Err("[error] WebSocket handshake closed early".to_string());
        }
        response.push(byte[0]);
        if response.ends_with(b"\r\n\r\n") {
            return Ok(response);
        }
    }
    Err("[error] WebSocket handshake response was too large".to_string())
}

fn validate_websocket_response(response: &[u8], key: &str) -> Result<(), String> {
    let text = std::str::from_utf8(response)
        .map_err(|_| "[error] WebSocket handshake response was not UTF-8".to_string())?;
    let mut lines = text.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.starts_with("HTTP/1.1 101 ") && status != "HTTP/1.1 101" {
        return Err(format!("[error] WebSocket upgrade failed: {status}"));
    }
    let expected_accept = websocket_accept(key);
    let mut saw_upgrade = false;
    let mut saw_connection = false;
    let mut saw_accept = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if name == "upgrade" && value.eq_ignore_ascii_case("websocket") {
            saw_upgrade = true;
        } else if name == "connection"
            && value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        {
            saw_connection = true;
        } else if name == "sec-websocket-accept" && value == expected_accept {
            saw_accept = true;
        }
    }
    if !saw_upgrade || !saw_connection || !saw_accept {
        return Err("[error] WebSocket upgrade response was incomplete".to_string());
    }
    Ok(())
}

fn websocket_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    BASE64.encode(hasher.finalize())
}

async fn relay_websocket<R, W>(mut reader: R, mut writer: W) -> Result<(), String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let stdin_to_ws = async {
        let mut stdin = io::stdin();
        let mut buffer = [0_u8; RELAY_CHUNK_BYTES];
        loop {
            let count = stdin
                .read(&mut buffer)
                .await
                .map_err(|err| format!("[error] failed to read stdin: {err}"))?;
            if count == 0 {
                write_client_frame(&mut writer, 0x8, &[]).await?;
                return Ok(());
            }
            write_client_frame(&mut writer, 0x2, &buffer[..count]).await?;
        }
    };

    let ws_to_stdout = async {
        let mut stdout = io::stdout();
        loop {
            let frame = read_server_frame(&mut reader).await?;
            match frame.opcode {
                0x0..=0x2 => {
                    stdout
                        .write_all(&frame.payload)
                        .await
                        .map_err(|err| format!("[error] failed to write stdout: {err}"))?;
                    stdout
                        .flush()
                        .await
                        .map_err(|err| format!("[error] failed to flush stdout: {err}"))?;
                }
                0x8 => return Ok(()),
                0x9 | 0xA => {}
                opcode => return Err(format!("[error] unsupported WebSocket opcode {opcode}")),
            }
        }
    };

    tokio::select! {
        result = stdin_to_ws => result,
        result = ws_to_stdout => result,
    }
}

async fn write_client_frame<W>(writer: &mut W, opcode: u8, payload: &[u8]) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let mut mask = [0_u8; 4];
    getrandom::fill(&mut mask)
        .map_err(|err| format!("[error] failed to generate WebSocket mask: {err}"))?;
    let mut header = vec![0x80 | (opcode & 0x0f)];
    let length = payload.len();
    if length < 126 {
        header.push(0x80 | length as u8);
    } else if length <= 0xffff {
        header.push(0x80 | 126);
        header.extend_from_slice(&(length as u16).to_be_bytes());
    } else {
        header.push(0x80 | 127);
        header.extend_from_slice(&(length as u64).to_be_bytes());
    }
    header.extend_from_slice(&mask);
    let mut masked = Vec::with_capacity(payload.len());
    for (index, byte) in payload.iter().enumerate() {
        masked.push(byte ^ mask[index % 4]);
    }
    writer
        .write_all(&header)
        .await
        .map_err(|err| format!("[error] failed to write WebSocket frame: {err}"))?;
    writer
        .write_all(&masked)
        .await
        .map_err(|err| format!("[error] failed to write WebSocket frame: {err}"))?;
    writer
        .flush()
        .await
        .map_err(|err| format!("[error] failed to write WebSocket frame: {err}"))
}

struct WebSocketFrame {
    opcode: u8,
    payload: Vec<u8>,
}

async fn read_server_frame<R>(reader: &mut R) -> Result<WebSocketFrame, String>
where
    R: AsyncRead + Unpin,
{
    let mut first_two = [0_u8; 2];
    reader
        .read_exact(&mut first_two)
        .await
        .map_err(|err| format!("[error] failed to read WebSocket frame: {err}"))?;
    let opcode = first_two[0] & 0x0f;
    let masked = first_two[1] & 0x80 != 0;
    if masked {
        return Err("[error] server WebSocket frames must not be masked".to_string());
    }
    let mut length = u64::from(first_two[1] & 0x7f);
    if length == 126 {
        let mut extended = [0_u8; 2];
        reader
            .read_exact(&mut extended)
            .await
            .map_err(|err| format!("[error] failed to read WebSocket frame length: {err}"))?;
        length = u64::from(u16::from_be_bytes(extended));
    } else if length == 127 {
        let mut extended = [0_u8; 8];
        reader
            .read_exact(&mut extended)
            .await
            .map_err(|err| format!("[error] failed to read WebSocket frame length: {err}"))?;
        length = u64::from_be_bytes(extended);
    }
    if length > 16 * 1024 * 1024 {
        return Err("[error] server WebSocket frame was too large".to_string());
    }
    let mut payload = vec![0_u8; length as usize];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|err| format!("[error] failed to read WebSocket frame payload: {err}"))?;
    Ok(WebSocketFrame { opcode, payload })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_accept_matches_rfc_example() {
        assert_eq!(
            websocket_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn validate_target_rejects_urls() {
        assert!(validate_target("https://cvm.example").is_err());
        assert!(validate_target("cvm.example/umbra/tunnel").is_err());
        assert_eq!(
            validate_target("cvm.example.").expect("fqdn accepted"),
            "cvm.example"
        );
    }

    #[test]
    fn load_policy_ignores_legacy_connect_host() {
        let path =
            std::env::temp_dir().join(format!("umbra-tunnel-policy-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{
                "type": "dstack_tdx",
                "connect_host": "app-443s.dstack.example.com",
                "allowed_tcb_status": ["UpToDate"]
            }"#,
        )
        .unwrap();

        // A legacy file carrying a connect_host key still loads; the key is ignored.
        assert!(load_policy(&path).is_ok());
        std::fs::remove_file(path).unwrap();
    }

    use crate::test_support::{authenticated_config, MockConsole};
    use rstest::rstest;
    use serde_json::json;

    const CVM_ID: &str = "00000000-0000-4000-8000-000000000001";
    const CVM_HOST: &str = "dev.example.com";

    fn bundle(console_url: &str, measurement: &str) -> Value {
        json!({
            "cvm_id": CVM_ID,
            "compose_template": "services: {}",
            "expected_bootchain": {"mrtd":measurement.repeat(96),"rtmr0":"1".repeat(96),
                "rtmr1":"2".repeat(96),"rtmr2":"3".repeat(96)},
            "os_image_hash": measurement.repeat(64),
            "rtmr3_binding": {"cvm_id":CVM_ID,"console_url":console_url},
            "app_compose": {"docker_compose_file":"services: {}"}
        })
    }

    struct PolicyFixture {
        console: MockConsole,
        config: ResolvedConfig,
        path: PathBuf,
    }

    impl Drop for PolicyFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.config.config_dir);
        }
    }

    fn policy_fixture() -> PolicyFixture {
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        let old = serde_json::from_value(bundle(console.base_url(), "a")).unwrap();
        let path = atls_policy_store::write(&config.config_dir, &old, CVM_ID).unwrap();
        console.reply_raw(
            &format!("/api/v1/cvms/{CVM_ID}"),
            200,
            &json!({"id":CVM_ID,"fqdn":CVM_HOST,"state":"RUNNING"}).to_string(),
        );
        console.reply_raw(
            &format!("/api/v1/cvms/{CVM_ID}/policy-bundle"),
            200,
            &bundle(console.base_url(), "b").to_string(),
        );
        PolicyFixture {
            console,
            config,
            path,
        }
    }

    fn bootchain_error(field: &str) -> AtlsVerificationError {
        AtlsVerificationError::BootchainMismatch {
            field: field.into(),
            expected: "a".repeat(96),
            actual: "b".repeat(96),
        }
    }

    /// Only policy comparisons emitted after integrity verification can refresh trust.
    #[rstest]
    #[case::compose(AtlsVerificationError::AppComposeHashMismatch{expected:"a".into(),actual:"b".into()})]
    #[case::mrtd(bootchain_error("mrtd"))]
    #[case::rtmr0(bootchain_error("rtmr0"))]
    #[case::rtmr1(bootchain_error("rtmr1"))]
    #[case::rtmr2(bootchain_error("rtmr2"))]
    #[case::os_image(AtlsVerificationError::OsImageHashMismatch{expected:"a".into(),actual:Some("b".into())})]
    fn recognized_policy_measurement_error_success(#[case] error: AtlsVerificationError) {
        assert!(matches!(
            classify_atls_error(CVM_HOST.into(), error),
            TunnelError::Atls {
                policy_mismatch: true,
                ..
            }
        ));
    }

    /// Integrity failures and misleading diagnostic text cannot trigger a trust prompt.
    #[rstest]
    #[case::quote(AtlsVerificationError::Quote("bootchain mismatch: mrtd".into()))]
    #[case::certificate(AtlsVerificationError::CertificateNotInEventLog)]
    #[case::missing_certificate(AtlsVerificationError::MissingCertificate)]
    #[case::event_log(AtlsVerificationError::EventLogParse("app compose hash mismatch".into()))]
    #[case::tee(AtlsVerificationError::TeeTypeMismatch("bootchain mismatch".into()))]
    #[case::tcb(AtlsVerificationError::TcbStatusNotAllowed{status:"Revoked".into(),allowed:vec!["UpToDate".into()]})]
    #[case::session_binding(AtlsVerificationError::ReportDataMismatch{expected:"a".into(),actual:"b".into()})]
    #[case::rtmr0_replay(AtlsVerificationError::RtmrMismatch{index:0,expected:"a".into(),actual:"b".into()})]
    #[case::rtmr3_replay(AtlsVerificationError::RtmrMismatch{index:3,expected:"a".into(),actual:"b".into()})]
    #[case::missing_os_measurement(AtlsVerificationError::OsImageHashMismatch{expected:"a".into(),actual:None})]
    #[case::unknown_bootchain(bootchain_error("rtmr3"))]
    #[case::tls(AtlsVerificationError::TlsHandshake("app compose hash mismatch".into()))]
    #[case::ekm_config(AtlsVerificationError::Configuration("session_ekm must be exactly 32 bytes".into()))]
    #[case::io(AtlsVerificationError::Io("OS image hash mismatch".into()))]
    #[case::other(AtlsVerificationError::Other(std::io::Error::other("app_compose_hash_mismatch").into()))]
    fn unsafe_attestation_error_never_refreshes_failure(#[case] error: AtlsVerificationError) {
        let fixture = policy_fixture();
        let previous = fs::read(&fixture.path).unwrap();
        let mut error = Some(error);
        let mut attempts = 0;
        let status = run_with_policy_refresh(
            &fixture.path,
            |_| {
                attempts += 1;
                Err(classify_atls_error(CVM_HOST.into(), error.take().unwrap()))
            },
            |_, _| panic!("unsafe errors must not offer policy refresh"),
        );
        assert_eq!(status as u8, ExitStatus::Error as u8);
        assert_eq!(attempts, 1);
        assert_eq!(fs::read(&fixture.path).unwrap(), previous);
    }

    /// An old cached OS policy gets one consented Console refresh and one complete verifier retry.
    #[test]
    fn cached_os_policy_refreshes_then_verifies_once_success() {
        let fixture = policy_fixture();
        let mut attempts = 0;
        let mut prompts = 0;
        let status = run_with_policy_refresh(
            &fixture.path,
            |policy| {
                attempts += 1;
                let value = serde_json::to_value(policy).unwrap();
                assert_eq!(value["allowed_tcb_status"], json!(["UpToDate"]));
                assert_eq!(value["disable_runtime_verification"], false);
                if attempts == 1 {
                    assert_eq!(value["expected_bootchain"]["mrtd"], "a".repeat(96));
                    Err(classify_atls_error(
                        CVM_HOST.into(),
                        bootchain_error("mrtd"),
                    ))
                } else {
                    assert_eq!(value["expected_bootchain"]["mrtd"], "b".repeat(96));
                    assert_eq!(value["os_image_hash"], "b".repeat(64));
                    assert!(value["app_compose"].is_object());
                    let installed: Value =
                        serde_json::from_slice(&fs::read(&fixture.path).unwrap()).unwrap();
                    assert_eq!(installed["rtmr3_binding"]["cvm_id"], CVM_ID);
                    Ok(())
                }
            },
            |host, detail| {
                refresh_policy_with_confirmation(
                    &fixture.config,
                    &fixture.path,
                    host,
                    detail,
                    |question| {
                        prompts += 1;
                        assert!(question.contains("before replacing local trust material"));
                        Some(true)
                    },
                )
            },
        );
        assert_eq!(status as u8, ExitStatus::Ok as u8);
        assert_eq!(attempts, 2);
        assert_eq!(prompts, 1);
    }

    /// A failed verified retry never prompts or fetches a second replacement policy.
    #[test]
    fn repeated_policy_mismatch_cannot_refresh_twice_failure() {
        let fixture = policy_fixture();
        let mut attempts = 0;
        let mut prompts = 0;
        let status = run_with_policy_refresh(
            &fixture.path,
            |_| {
                attempts += 1;
                Err(classify_atls_error(
                    CVM_HOST.into(),
                    bootchain_error("mrtd"),
                ))
            },
            |host, detail| {
                refresh_policy_with_confirmation(
                    &fixture.config,
                    &fixture.path,
                    host,
                    detail,
                    |_| {
                        prompts += 1;
                        Some(true)
                    },
                )
            },
        );
        assert_eq!(status as u8, ExitStatus::Error as u8);
        assert_eq!(attempts, 2);
        assert_eq!(prompts, 1);
    }

    /// Declining or lacking a terminal leaves the original file and tunnel unchanged.
    #[rstest]
    #[case::declined(Some(false))]
    #[case::no_terminal(None)]
    fn unconfirmed_policy_refresh_keeps_original_failure(#[case] answer: Option<bool>) {
        let fixture = policy_fixture();
        let previous = fs::read(&fixture.path).unwrap();
        let mut attempts = 0;
        let status = run_with_policy_refresh(
            &fixture.path,
            |_| {
                attempts += 1;
                Err(classify_atls_error(
                    CVM_HOST.into(),
                    bootchain_error("mrtd"),
                ))
            },
            |host, detail| {
                refresh_policy_with_confirmation(
                    &fixture.config,
                    &fixture.path,
                    host,
                    detail,
                    |_| answer,
                )
            },
        );
        assert_eq!(status as u8, ExitStatus::Error as u8);
        assert_eq!(attempts, 1);
        assert_eq!(fs::read(&fixture.path).unwrap(), previous);
    }

    /// Console must identify the same running CVM and FQDN before any local replacement.
    #[rstest]
    #[case::wrong_id("id",json!("another-cvm"))]
    #[case::wrong_host("fqdn",json!("other.example.com"))]
    #[case::missing_host("fqdn", Value::Null)]
    #[case::stopped("state",json!("STOPPED"))]
    #[case::legacy_rebind("error_reason",json!("SECURITY_CVM_REBIND_REQUIRED"))]
    fn refreshed_target_context_mismatch_failure(#[case] key: &str, #[case] value: Value) {
        let fixture = policy_fixture();
        let previous = fs::read(&fixture.path).unwrap();
        let mut cvm = json!({"id":CVM_ID,"fqdn":CVM_HOST,"state":"RUNNING"});
        cvm[key] = value;
        fixture
            .console
            .reply_raw(&format!("/api/v1/cvms/{CVM_ID}"), 200, &cvm.to_string());
        assert!(refresh_policy_with_confirmation(
            &fixture.config,
            &fixture.path,
            CVM_HOST,
            "mismatch",
            |_| Some(true)
        )
        .is_err());
        assert_eq!(fs::read(&fixture.path).unwrap(), previous);
    }

    /// A substituted returned bundle cannot change the selected CVM or Console context.
    #[rstest]
    #[case::bundle_id("cvm_id",json!("another-cvm"))]
    #[case::binding_id("binding-cvm",json!("another-cvm"))]
    #[case::binding_console("binding-console",json!("https://other.example.com"))]
    fn refreshed_bundle_context_mismatch_failure(#[case] field: &str, #[case] value: Value) {
        let fixture = policy_fixture();
        let previous = fs::read(&fixture.path).unwrap();
        let mut current = bundle(fixture.console.base_url(), "b");
        match field {
            "binding-cvm" => current["rtmr3_binding"]["cvm_id"] = value,
            "binding-console" => current["rtmr3_binding"]["console_url"] = value,
            _ => current[field] = value,
        }
        fixture.console.reply_raw(
            &format!("/api/v1/cvms/{CVM_ID}/policy-bundle"),
            200,
            &current.to_string(),
        );
        assert!(refresh_policy_with_confirmation(
            &fixture.config,
            &fixture.path,
            CVM_HOST,
            "mismatch",
            |_| Some(true)
        )
        .is_err());
        assert_eq!(fs::read(&fixture.path).unwrap(), previous);
    }

    /// Stored policies from another Console cannot prompt or refresh under the current session.
    #[test]
    fn stored_policy_context_mismatch_cannot_prompt_failure() {
        let fixture = policy_fixture();
        let old = serde_json::from_value(bundle("https://other.example.com", "a")).unwrap();
        atls_policy_store::write(&fixture.config.config_dir, &old, CVM_ID).unwrap();
        let previous = fs::read(&fixture.path).unwrap();
        assert!(refresh_policy_with_confirmation(
            &fixture.config,
            &fixture.path,
            CVM_HOST,
            "mismatch",
            |_| panic!("context must be checked before consent")
        )
        .is_err());
        assert_eq!(fs::read(&fixture.path).unwrap(), previous);
    }

    /// A custom policy path is never rewritten or offered an automatic refresh.
    #[test]
    fn custom_policy_path_cannot_refresh_failure() {
        let fixture = policy_fixture();
        let custom = fixture.config.config_dir.join("custom.json");
        fs::copy(&fixture.path, &custom).unwrap();
        let previous = fs::read(&custom).unwrap();
        assert!(matches!(
            refresh_policy_with_confirmation(
                &fixture.config,
                &custom,
                CVM_HOST,
                "mismatch",
                |_| panic!("custom path must not prompt")
            ),
            Ok(RefreshDecision::Declined(_))
        ));
        assert_eq!(fs::read(&custom).unwrap(), previous);
    }

    #[test]
    fn per_cvm_policy_path_yields_cvm_id_only_for_canonical_path() {
        let config_dir = Path::new("/tmp/umbra");
        let canonical = config_dir
            .join("cvms")
            .join("cvm-aaaaaaaaaaaaaaaaaaaaaaaaaa.atls-policy.json");
        assert_eq!(
            atls_policy_store::cvm_id_from_store_path(config_dir, &canonical).as_deref(),
            Some("cvm-aaaaaaaaaaaaaaaaaaaaaaaaaa")
        );

        let custom = Path::new("/tmp/custom/cvm-aaaaaaaaaaaaaaaaaaaaaaaaaa.atls-policy.json");
        assert_eq!(
            atls_policy_store::cvm_id_from_store_path(config_dir, custom),
            None
        );
    }
}
