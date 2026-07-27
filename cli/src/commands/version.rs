use serde_json::json;

use crate::{exit::ExitStatus, style};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_COMMIT: &str = env!("BUILD_COMMIT");
const BUILD_TARGET: &str = env!("BUILD_TARGET");
const BUILD_DATE: &str = env!("BUILD_DATE");

pub fn run(json_output: bool) -> ExitStatus {
    if json_output {
        let payload = json!({
            "version": VERSION,
            "commit": BUILD_COMMIT,
            "target": BUILD_TARGET,
            "build_date": BUILD_DATE,
        });
        style::emit_json(&payload);
    } else {
        println!(
            "{}",
            style::version_card(VERSION, BUILD_COMMIT, BUILD_TARGET, BUILD_DATE)
        );
    }
    ExitStatus::Ok
}
