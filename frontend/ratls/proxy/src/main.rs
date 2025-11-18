//! Minimal WebSocket -> TCP forwarder for ratls tunnel testing.
//! Accepts binary WebSocket connections and pipes bytes to a configured TCP target.

use futures_util::{SinkExt, StreamExt};
use std::net::ToSocketAddrs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, TcpListener};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::accept_async;

async fn handle_ws(
    ws_stream: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    target: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws = ws_stream;
    let mut parts = target.split(':');
    let host = parts.next().unwrap_or("127.0.0.1");
    let port = parts.next().unwrap_or("443");
    let target_addr = format!("{host}:{port}");
    let mut addrs_iter = target_addr.to_socket_addrs()?;
    let addr = addrs_iter
        .next()
        .ok_or("no target address resolved")?;
    let tcp = TcpStream::connect(addr).await?;

    let (mut ws_sink, mut ws_stream) = ws.split();
    let (tcp_reader, tcp_writer) = tcp.into_split();

    // WS -> TCP
    let mut tcp_writer: OwnedWriteHalf = tcp_writer;
    let ws_to_tcp = async move {
        while let Some(msg) = ws_stream.next().await {
            let msg = msg?;
            if msg.is_binary() || msg.is_text() {
                let data = msg.into_data();
                tcp_writer.write_all(&data).await?;
            } else if msg.is_close() {
                break;
            }
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };

    // TCP -> WS
    let mut tcp_reader: OwnedReadHalf = tcp_reader;
    let tcp_to_ws = async move {
        let mut buf = [0u8; 4096];
        loop {
            let n = tcp_reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            ws_sink.send(Message::Binary(buf[..n].to_vec())).await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    };

    tokio::select! {
        res = ws_to_tcp => res?,
        res = tcp_to_ws => res?,
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listen_addr = std::env::var("RATLS_PROXY_LISTEN").unwrap_or_else(|_| "127.0.0.1:9000".to_string());
    let target = std::env::var("RATLS_PROXY_TARGET").unwrap_or_else(|_| "127.0.0.1:8443".to_string());
    let listener = TcpListener::bind(&listen_addr).await?;
    eprintln!("ratls-proxy listening on {listen_addr}, forwarding to {target}");

    loop {
        let (stream, peer) = listener.accept().await?;
        let target_clone = target.clone();
        tokio::spawn(async move {
            let ws_stream = match accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    eprintln!("handshake error from {peer}: {e}");
                    return;
                }
            };
            if let Err(e) = handle_ws(ws_stream, target_clone).await {
                eprintln!("pipe error from {peer}: {e}");
            }
        });
    }
}
