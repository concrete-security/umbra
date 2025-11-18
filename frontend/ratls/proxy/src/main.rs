//! Minimal TCP echo listener placeholder for the ratls proxy.
//! This does not implement WebSocket bridging yet; it is a stub to unblock early transport testing.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn handle_client(mut stream: TcpStream) -> std::io::Result<()> {
    let peer = stream.peer_addr().ok();
    let mut buf = [0u8; 4096];
    loop {
        let n = match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        stream.write_all(&buf[..n])?;
        stream.flush()?;
    }
    if let Some(addr) = peer {
        eprintln!("connection from {addr} closed");
    }
    Ok(())
}

fn main() -> std::io::Result<()> {
    let listen_addr = std::env::var("RATLS_PROXY_LISTEN").unwrap_or_else(|_| "127.0.0.1:9000".to_string());
    let listener = TcpListener::bind(&listen_addr)?;
    eprintln!("ratls-proxy (stub) listening on {listen_addr} (echo)");

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(|| {
                    if let Err(e) = handle_client(stream) {
                        eprintln!("client error: {e:?}");
                    }
                });
            }
            Err(e) => eprintln!("accept error: {e:?}"),
        }
    }
    Ok(())
}
