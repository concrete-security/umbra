use std::io::Write;

use concrete_atls_connect::{
    atls_connect_with_route_sni, load_policy, parse_request, HelperError, RelayResponse, Result,
};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

const MAX_STDIN_BYTES: u64 = 1024 * 1024;

#[tokio::main]
async fn main() {
    install_default_crypto_provider();

    if let Err(error) = run().await {
        eprintln!("concrete-atls-connect: {error}");
        std::process::exit(1);
    }
}

fn install_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

async fn run() -> Result<()> {
    let request = read_request().await?;
    let policy = load_policy(&request.policy_path)?;
    let connect_host = request.connect_host.as_deref().unwrap_or(&request.fqdn);
    let tcp = TcpStream::connect((connect_host, request.port))
        .await
        .map_err(|error| HelperError::new(format!("failed to connect to Security CVM: {error}")))?;
    let (mut tls_stream, _report) = if connect_host == request.fqdn {
        atlas_rs::atls_connect(tcp, &request.fqdn, policy, None).await
    } else {
        atls_connect_with_route_sni(tcp, &request.fqdn, connect_host, policy).await
    }
    .map_err(|error| HelperError::new(format!("aTLS verification failed: {error}")))?;

    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(|error| HelperError::new(format!("failed to bind loopback relay: {error}")))?;
    let port = listener
        .local_addr()
        .map_err(|error| {
            HelperError::new(format!("failed to read loopback relay address: {error}"))
        })?
        .port();
    write_response(port)?;

    let (mut local_stream, _peer) = listener.accept().await.map_err(|error| {
        HelperError::new(format!("failed to accept loopback relay client: {error}"))
    })?;
    tokio::io::copy_bidirectional(&mut local_stream, &mut tls_stream)
        .await
        .map_err(|error| HelperError::new(format!("relay failed: {error}")))?;
    Ok(())
}

async fn read_request() -> Result<concrete_atls_connect::ConnectRequest> {
    let mut input = Vec::new();
    tokio::io::stdin()
        .take(MAX_STDIN_BYTES + 1)
        .read_to_end(&mut input)
        .await
        .map_err(|error| HelperError::new(format!("failed to read helper request: {error}")))?;
    if input.len() > MAX_STDIN_BYTES as usize {
        return Err(HelperError::new("helper request is too large"));
    }
    parse_request(&input)
}

fn write_response(port: u16) -> Result<()> {
    let response = RelayResponse {
        host: "127.0.0.1",
        port,
    };
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    serde_json::to_writer(&mut stdout, &response)
        .map_err(|error| HelperError::new(format!("failed to write helper response: {error}")))?;
    writeln!(stdout)
        .map_err(|error| HelperError::new(format!("failed to write helper response: {error}")))?;
    stdout
        .flush()
        .map_err(|error| HelperError::new(format!("failed to flush helper response: {error}")))?;
    Ok(())
}
