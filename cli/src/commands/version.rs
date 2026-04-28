use crate::exit::ExitStatus;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_COMMIT: &str = env!("BUILD_COMMIT");
const BUILD_TARGET: &str = env!("BUILD_TARGET");
const BUILD_DATE: &str = env!("BUILD_DATE");

pub fn run(json: bool) -> ExitStatus {
    if json {
        println!(
            r#"{{"version":"{VERSION}","commit":"{BUILD_COMMIT}","target":"{BUILD_TARGET}","build_date":"{BUILD_DATE}"}}"#
        );
    } else {
        println!("concrete {VERSION}");
        println!("commit:     {BUILD_COMMIT}");
        println!("target:     {BUILD_TARGET}");
        println!("build_date: {BUILD_DATE}");
    }
    ExitStatus::Ok
}
