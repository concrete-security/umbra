use napi::bindgen_prelude::*;
use napi_derive::napi;
use ratls_core::{platform::AsyncWriteExt, tls_connect, AttestationResult, Policy};
use std::net::ToSocketAddrs;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::task;

#[napi(object)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

#[napi(object)]
pub struct JsAttestation {
    pub trusted: bool,
    pub tee_type: String,
    pub measurement: Option<String>,
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
}

impl From<AttestationResult> for JsAttestation {
    fn from(value: AttestationResult) -> Self {
        Self {
            trusted: value.trusted,
            tee_type: format!("{:?}", value.tee_type).to_lowercase(),
            measurement: value.measurement,
            tcb_status: value.tcb_status,
            advisory_ids: value.advisory_ids,
        }
    }
}

#[napi(object)]
pub struct JsHttpResponse {
    pub attestation: JsAttestation,
    pub status: u16,
    pub status_text: String,
    pub headers: Vec<HeaderEntry>,
    pub body: Buffer,
}

fn normalize_path(path: &str) -> String {
    if path.trim().is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    }
}

#[napi]
pub async fn http_request(
    target_host: String,
    server_name: String,
    method: String,
    path: String,
    headers: Vec<HeaderEntry>,
    body: Option<Buffer>,
) -> napi::Result<JsHttpResponse> {
    let addr = target_host.clone();
    let tcp_addr = task::spawn_blocking(move || {
        addr.to_socket_addrs()
            .map_err(|err| Error::from_reason(format!("invalid target host: {err}")))?
            .next()
            .ok_or_else(|| Error::from_reason("unable to resolve target host"))
    })
    .await
    .map_err(|err| Error::from_reason(format!("resolver join error: {err}")))??;

    let tcp = TcpStream::connect(tcp_addr)
        .await
        .map_err(|err| Error::from_reason(format!("tcp connect failed: {err}")))?;

    let mut resolved_headers = headers;
    if !resolved_headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("host"))
    {
        resolved_headers.push(HeaderEntry {
            name: "Host".into(),
            value: server_name.clone(),
        });
    }
    if !resolved_headers
        .iter()
        .any(|h| h.name.eq_ignore_ascii_case("connection"))
    {
        resolved_headers.push(HeaderEntry {
            name: "Connection".into(),
            value: "close".into(),
        });
    }

    let body_bytes = body.unwrap_or_default();
    if !body_bytes.is_empty()
        && !resolved_headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("content-length"))
    {
        resolved_headers.push(HeaderEntry {
            name: "Content-Length".into(),
            value: body_bytes.len().to_string(),
        });
    }

    let normalized_path = normalize_path(&path);
    let mut request = format!(
        "{} {} HTTP/1.1\r\n",
        method.trim().to_uppercase(),
        normalized_path
    )
    .into_bytes();
    for HeaderEntry { name, value } in &resolved_headers {
        request.extend_from_slice(name.as_bytes());
        request.extend_from_slice(b": ");
        request.extend_from_slice(value.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    if !body_bytes.is_empty() {
        request.extend_from_slice(&body_bytes);
    }

    let (mut tls, attestation) =
        tls_connect(tcp, &server_name, Policy::default(), Some(vec!["http/1.1".into()]))
            .await
            .map_err(|err| Error::from_reason(format!("ratls handshake failed: {err}")))?;

    tls.write_all(&request)
        .await
        .map_err(|err| Error::from_reason(format!("write failed: {err}")))?;
    tls.flush()
        .await
        .map_err(|err| Error::from_reason(format!("flush failed: {err}")))?;

    let raw_headers = read_headers(&mut tls).await?;
    let (status, status_text, parsed_headers) = parse_headers(&raw_headers)?;
    let body = read_body(&mut tls, &parsed_headers).await?;

    Ok(JsHttpResponse {
        attestation: attestation.into(),
        status,
        status_text,
        headers: parsed_headers
            .iter()
            .map(|(name, value)| HeaderEntry {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        body: Buffer::from(body),
    })
}

async fn read_headers<T>(stream: &mut T) -> napi::Result<Vec<u8>>
where
    T: AsyncReadExt + Unpin,
{
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|err| Error::from_reason(format!("read header failed: {err}")))?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(Error::from_reason("HTTP headers too large"));
        }
    }
    Ok(buf)
}

fn parse_headers(raw: &[u8]) -> napi::Result<(u16, String, Vec<(String, String)>)> {
    let text = String::from_utf8(raw.to_vec())
        .map_err(|err| Error::from_reason(format!("invalid header bytes: {err}")))?;
    let mut lines = text.split("\r\n").filter(|l| !l.is_empty());
    let status_line = lines
        .next()
        .ok_or_else(|| Error::from_reason("missing status line"))?;
    let mut parts = status_line.splitn(3, ' ');
    let _http_version = parts.next().unwrap_or_default();
    let status: u16 = parts
        .next()
        .ok_or_else(|| Error::from_reason("missing status code"))?
        .parse()
        .map_err(|_| Error::from_reason("invalid status code"))?;
    let reason = parts.next().unwrap_or("").to_string();
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect::<Vec<_>>();
    Ok((status, reason, headers))
}

async fn read_body<T>(stream: &mut T, headers: &[(String, String)]) -> napi::Result<Vec<u8>>
where
    T: AsyncReadExt + Unpin,
{
    if let Some(len) = find_content_length(headers) {
        let mut body = vec![0u8; len];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|err| Error::from_reason(format!("read body failed: {err}")))?;
        return Ok(body);
    }

    if is_chunked(headers) {
        return read_chunked_body(stream).await;
    }

    let mut body = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let read = stream
            .read(&mut buf)
            .await
            .map_err(|err| Error::from_reason(format!("read body failed: {err}")))?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&buf[..read]);
    }
    Ok(body)
}

fn find_content_length(headers: &[(String, String)]) -> Option<usize> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse::<usize>().ok())
}

fn is_chunked(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("transfer-encoding")
            && value.to_ascii_lowercase().contains("chunked")
    })
}

async fn read_chunked_body<T>(stream: &mut T) -> napi::Result<Vec<u8>>
where
    T: AsyncReadExt + Unpin,
{
    let mut body = Vec::new();
    loop {
        let size_line = read_line(stream).await?;
        let size_str = size_line
            .split(';')
            .next()
            .map(str::trim)
            .unwrap_or_default();
        let chunk_size = usize::from_str_radix(size_str, 16)
            .map_err(|_| Error::from_reason("invalid chunk size"))?;

        if chunk_size == 0 {
            loop {
                let trailer = read_line(stream).await?;
                if trailer.is_empty() {
                    break;
                }
            }
            break;
        }

        let mut chunk = vec![0u8; chunk_size];
        stream
            .read_exact(&mut chunk)
            .await
            .map_err(|err| Error::from_reason(format!("read chunk failed: {err}")))?;
        body.extend_from_slice(&chunk);

        let mut crlf = [0u8; 2];
        stream
            .read_exact(&mut crlf)
            .await
            .map_err(|err| Error::from_reason(format!("read chunk trailer failed: {err}")))?;
    }
    Ok(body)
}

async fn read_line<T>(stream: &mut T) -> napi::Result<String>
where
    T: AsyncReadExt + Unpin,
{
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|err| Error::from_reason(format!("read line failed: {err}")))?;
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            buf.push(byte[0]);
        }
        if buf.len() > 8192 {
            return Err(Error::from_reason("line too long"));
        }
    }
    String::from_utf8(buf).map_err(|err| Error::from_reason(format!("invalid utf-8: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_prefixes_slash() {
        assert_eq!(normalize_path(""), "/");
        assert_eq!(normalize_path("foo"), "/foo");
        assert_eq!(normalize_path("/bar"), "/bar");
    }
}
