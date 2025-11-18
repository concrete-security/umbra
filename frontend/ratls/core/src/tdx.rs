//! TDX quote verification using dcap-qvl.

use crate::{DiceEvidenceTyped, RatlsError, TdxTcbPolicy};
use dcap_qvl::QuoteCollateralV3;

/// Verify a TDX quote and TCB against policy. Currently a stub with basic guards.
pub fn verify_tdx_quote(
    evidence: &DiceEvidenceTyped,
    policy: &Option<TdxTcbPolicy>,
) -> Result<(), RatlsError> {
    if evidence.quote.is_empty() {
        return Err(RatlsError::Vendor("tdx quote empty".into()));
    }
    if evidence.claims.tdx_tcb.is_none() {
        return Err(RatlsError::Vendor("tdx_tcb missing in claims".into()));
    }

    // Verify quote cryptographically against collateral (skip during tests).
    #[cfg(not(test))]
    {
        let collateral = evidence
            .endorsements
            .as_ref()
            .ok_or_else(|| RatlsError::Vendor("tdx collateral missing".into()))
            .and_then(|b| {
                serde_json::from_slice::<QuoteCollateralV3>(b).map_err(|e| {
                    RatlsError::Vendor(format!("tdx collateral decode failed: {e}"))
                })
            })?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| RatlsError::Clock(e.to_string()))?
            .as_secs();
        dcap_qvl::verify::verify(&evidence.quote, &collateral, now)
            .map_err(|e| RatlsError::Vendor(format!("tdx verify failed: {e}")))?;
    }

    if let Some(policy) = policy {
        // Basic comparison against MRSEAM/MRTMRS/TDCB_SVN if present.
        if let Some(policy_mrseam) = &policy.mrseam {
            if evidence
                .claims
                .tdx_tcb
                .as_ref()
                .and_then(|t| t.mrseam.clone())
                .as_ref()
                .map(|v| v != policy_mrseam)
                .unwrap_or(false)
            {
                return Err(RatlsError::Vendor("tdx mrseam mismatch".into()));
            }
        }
        if let Some(policy_mrtmrs) = &policy.mrtmrs {
            if evidence
                .claims
                .tdx_tcb
                .as_ref()
                .and_then(|t| t.mrtmrs.clone())
                .as_ref()
                .map(|v| v != policy_mrtmrs)
                .unwrap_or(false)
            {
                return Err(RatlsError::Vendor("tdx mrtmrs mismatch".into()));
            }
        }
        if let Some(min_svn) = policy.min_tcb_svn {
            if let Some(actual_svn) = evidence
                .claims
                .tdx_tcb
                .as_ref()
                .and_then(|t| t.tcb_svn)
            {
                if actual_svn < min_svn {
                    return Err(RatlsError::Vendor(format!(
                        "tdx tcb_svn {} below minimum {}",
                        actual_svn, min_svn
                    )));
                }
            }
        }
    }

    // TODO: full cryptographic verification of quote signature and collateral.
    Ok(())
}
