use crate::platform::{AsyncReadExt, AsyncWriteExt, TlsStream};
use crate::tdx;
use crate::{spki_from_cert, AsyncByteStream, AttestationResult, Policy, RatlsError};
use dcap_qvl::QuoteCollateralV3;
use rand::rngs::OsRng;
use rand::RngCore;

pub async fn verify_attestation_stream<S>(
    stream: &mut TlsStream<S>,
    server_cert: &[u8],
    policy: &Policy,
) -> Result<AttestationResult, RatlsError>
where
    S: AsyncByteStream,
{
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    stream
        .write_all(&nonce)
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;

    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;
    let quote_len = u32::from_be_bytes(len_buf) as usize;
    let mut quote = vec![0u8; quote_len];
    stream
        .read_exact(&mut quote)
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;

    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;
    let collateral_len = u32::from_be_bytes(len_buf) as usize;
    let mut collateral_bytes = vec![0u8; collateral_len];
    stream
        .read_exact(&mut collateral_bytes)
        .await
        .map_err(|e| RatlsError::Io(e.to_string()))?;

    let collateral: QuoteCollateralV3 = serde_json::from_slice(&collateral_bytes)
        .map_err(|e| RatlsError::Vendor(format!("invalid collateral: {e}")))?;

    let spki = spki_from_cert(server_cert)?;
    tdx::verify_attestation(&quote, &collateral, &nonce, &spki, policy).await
}
