use serde_json::Value;

const DEBUG_BODY_LIMIT: usize = 8192;
const REDACTED: &str = "<redacted>";

pub(crate) fn log_poll_decode_failure<T: std::fmt::Display>(action: &str, body: &[u8], error: T) {
    if action != "poll operation" || !poll_debug_enabled() {
        return;
    }
    eprintln!(
        "[debug] {action} decode failed: {error}; body_bytes={}; body={}",
        body.len(),
        debug_body(body)
    );
}

fn poll_debug_enabled() -> bool {
    match std::env::var("UMBRA_DEBUG_POLL") {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

fn debug_body(body: &[u8]) -> String {
    match serde_json::from_slice::<Value>(body) {
        Ok(mut value) => {
            redact_json(&mut value);
            truncate_debug_text(
                &serde_json::to_string(&value).unwrap_or_else(|_| escaped_body(body)),
            )
        }
        Err(_) => truncate_debug_text(&escaped_body(body)),
    }
}

fn escaped_body(body: &[u8]) -> String {
    String::from_utf8_lossy(body)
        .chars()
        .flat_map(char::escape_default)
        .collect()
}

fn redact_json(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if is_sensitive_key(key) {
                    *child = Value::String(REDACTED.to_string());
                } else {
                    redact_json(child);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                redact_json(item);
            }
        }
        _ => {}
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "authorization",
        "bearer",
        "token",
        "secret",
        "password",
        "private_key",
        "jwt",
        "device_code",
        "polling_secret",
        "ca_export",
        "ingest",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn truncate_debug_text(text: &str) -> String {
    if text.chars().count() <= DEBUG_BODY_LIMIT {
        return text.to_string();
    }
    format!(
        "{}...<truncated>",
        text.chars().take(DEBUG_BODY_LIMIT).collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_body_redacts_nested_token_fields() {
        let body = br#"{"result":{"ca_export_token":"secret","nested":{"access_token":"jwt","safe":"value"}}}"#;

        assert_eq!(
            debug_body(body),
            r#"{"result":{"ca_export_token":"<redacted>","nested":{"access_token":"<redacted>","safe":"value"}}}"#
        );
    }

    #[test]
    fn debug_body_escapes_non_json_bytes() {
        assert_eq!(debug_body(b"not\njson"), r#"not\njson"#);
    }
}
