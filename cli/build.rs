use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");

    let target = std::env::var("TARGET").unwrap_or_else(|_| String::from("unknown"));
    println!("cargo:rustc-env=BUILD_TARGET={target}");

    let commit = git_short_sha().unwrap_or_else(|| String::from("unknown"));
    println!("cargo:rustc-env=BUILD_COMMIT={commit}");

    let date = build_date();
    println!("cargo:rustc-env=BUILD_DATE={date}");
}

fn build_date() -> String {
    let seconds = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(raw) => Some(
            raw.parse::<i64>()
                .expect("SOURCE_DATE_EPOCH must be an integer Unix timestamp"),
        ),
        Err(std::env::VarError::NotPresent) => git_output(&["show", "-s", "--format=%ct", "HEAD"])
            .and_then(|raw| raw.parse::<i64>().ok()),
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("SOURCE_DATE_EPOCH must be valid Unicode")
        }
    };

    seconds
        .and_then(|value| chrono::DateTime::<chrono::Utc>::from_timestamp(value, 0))
        .map(|date| date.format("%Y-%m-%dT%H:%M:%SZ").to_string())
        .unwrap_or_else(|| String::from("unknown"))
}

fn git_short_sha() -> Option<String> {
    let sha = git_output(&["rev-parse", "HEAD"])?;
    if sha.len() < 12 || !sha.is_ascii() || !sha.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some(sha[..12].to_string())
}

fn git_output(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8(out.stdout).ok()?;
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}
