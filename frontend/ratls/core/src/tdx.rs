use crate::{platform::SystemTime, AttestationResult, Policy, RatlsError, TeeType};
use dcap_qvl::quote::{Report, TDReport10, TDReport15};
use dcap_qvl::QuoteCollateralV3;
use hex::encode;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Default)]
pub struct TdxTcbPolicy {
    pub mrseam: Option<Vec<u8>>,
    pub mrtmrs: Option<Vec<u8>>,
}

pub async fn verify_attestation(
    quote: &[u8],
    collateral: &QuoteCollateralV3,
    nonce: &[u8],
    spki_der: &[u8],
    policy: &Policy,
) -> Result<AttestationResult, RatlsError> {
    if policy.tee_type != TeeType::Tdx {
        return Err(RatlsError::TeeUnsupported(
            "only TDX attestation supported".into(),
        ));
    }

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| RatlsError::Policy(e.to_string()))?
        .as_secs();
    let verified = dcap_qvl::verify::verify(quote, collateral, now)
        .map_err(|e| RatlsError::Vendor(format!("tdx verify failed: {e}")))?;
    let status = verified.status.clone();
    if !policy
        .allowed_tdx_status
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&status))
    {
        return Err(RatlsError::Policy(format!(
            "tdx status {status} not allowed"
        )));
    }

    let report = match &verified.report {
        Report::TD10(report) => TdReportRef::Td10(&report),
        Report::TD15(report) => TdReportRef::Td15(&report),
        other => {
            return Err(RatlsError::TeeUnsupported(format!(
                "unsupported report type: {other:?}"
            )));
        }
    };

    let binding: Vec<u8> = {
        let mut hasher = Sha256::new();
        hasher.update(spki_der);
        hasher.update(nonce);
        hasher.finalize().to_vec()
    };

    let report_data = report.report_data();
    if report_data[..binding.len()] != binding[..] {
        return Err(RatlsError::Policy(
            "report data mismatch (nonce/pubkey binding)".into(),
        ));
    }

    if let Some(tcb_policy) = &policy.min_tdx_tcb {
        enforce_tcb_policy(report.as_td10(), tcb_policy)?;
    }

    let measurement = encode(report.as_td10().mr_td);

    Ok(AttestationResult {
        trusted: true,
        tee_type: TeeType::Tdx,
        measurement: Some(measurement),
        tcb_status: status,
        advisory_ids: verified.advisory_ids,
    })
}

fn enforce_tcb_policy(report: &TDReport10, policy: &TdxTcbPolicy) -> Result<(), RatlsError> {
    if let Some(expected) = &policy.mrseam {
        if report.mr_seam[..expected.len()] != expected[..] {
            return Err(RatlsError::Policy("mr_seam mismatch".into()));
        }
    }
    if let Some(expected) = &policy.mrtmrs {
        if report.rt_mr0[..expected.len()] != expected[..] {
            return Err(RatlsError::Policy("rt_mr0 mismatch".into()));
        }
    }
    Ok(())
}

enum TdReportRef<'a> {
    Td10(&'a TDReport10),
    Td15(&'a TDReport15),
}

impl<'a> TdReportRef<'a> {
    fn as_td10(&self) -> &TDReport10 {
        match self {
            TdReportRef::Td10(r) => r,
            TdReportRef::Td15(r) => &r.base,
        }
    }

    fn report_data(&self) -> &[u8; 64] {
        match self {
            TdReportRef::Td10(r) => &r.report_data,
            TdReportRef::Td15(r) => &r.base.report_data,
        }
    }
}
