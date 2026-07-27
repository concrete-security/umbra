use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    cli::ReconcileArgs,
    config::ResolvedConfig,
    console::{console_session, post_json},
    exit::ExitStatus,
};

#[derive(Debug, Deserialize, Serialize)]
struct ReconcileOutput {
    cvms_advanced: Vec<String>,
    security_cvms_advanced: Vec<String>,
    orphans_cleaned: Vec<String>,
}

pub fn run(args: ReconcileArgs, config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let (console_url, session) = try_or_eprintln!(console_session(config));
    let body = json!({"include_orphans": !args.no_orphans});
    let output: ReconcileOutput = try_or_eprintln!(post_json(
        console_url,
        &session.access_token,
        "/api/v1/admin/reconcile",
        &body,
        "run reconcile",
    ));
    if json_output {
        crate::style::emit_json(&output);
    } else {
        // Section 7.28: a reconcile run produces a single confirm block whose
        // header records the verb (`reconciled`), the noun (`run`) and a
        // synthetic identifier that summarises which sub-buckets the saga
        // advanced. Detail rows surface the per-bucket counts plus the
        // resolved id list (`-` when empty).
        let identifier = reconcile_identifier(&output, args.no_orphans);
        let confirm = crate::style::ConfirmBlock::new("reconciled", "run", identifier)
            .field(
                "cvms advanced",
                format!(
                    "{} ids={}",
                    output.cvms_advanced.len(),
                    format_ids(&output.cvms_advanced)
                ),
            )
            .field(
                "security cvms advanced",
                format!(
                    "{} ids={}",
                    output.security_cvms_advanced.len(),
                    format_ids(&output.security_cvms_advanced)
                ),
            )
            .field(
                "orphans cleaned",
                format!(
                    "{} ids={}",
                    output.orphans_cleaned.len(),
                    format_ids(&output.orphans_cleaned)
                ),
            );
        println!("{}", crate::style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn reconcile_identifier(output: &ReconcileOutput, no_orphans: bool) -> String {
    let total = output.cvms_advanced.len()
        + output.security_cvms_advanced.len()
        + output.orphans_cleaned.len();
    if total == 0 {
        return if no_orphans {
            "no advances".to_string()
        } else {
            "no advances or orphans".to_string()
        };
    }
    format!("{total} actions")
}

fn format_ids(values: &[String]) -> String {
    if values.is_empty() {
        "-".to_string()
    } else {
        values.join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_human_ids_render_dash() {
        assert_eq!(format_ids(&[]), "-");
    }
}
