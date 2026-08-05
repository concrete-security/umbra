pub(crate) fn log_poll_decode_failure(action: &str, body: &[u8]) {
    if let Some(message) = poll_decode_failure_message(action, body, poll_debug_enabled()) {
        eprintln!("{message}");
    }
}

fn poll_decode_failure_message(action: &str, body: &[u8], enabled: bool) -> Option<String> {
    if action != "poll operation" || !enabled {
        return None;
    }
    Some(format!(
        "[debug] poll operation decode failed; body_bytes={}; body_format={}",
        body.len(),
        debug_body_format(body)
    ))
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

fn debug_body_format(body: &[u8]) -> &'static str {
    if serde_json::from_slice::<serde_json::Value>(body).is_ok() {
        "json"
    } else {
        "non-json"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::json(
        r#"{"result":{"access_token":"must-not-be-logged"}}"#,
        "[debug] poll operation decode failed; body_bytes=48; body_format=json"
    )]
    #[case::non_json(
        "must-not-be-logged",
        "[debug] poll operation decode failed; body_bytes=18; body_format=non-json"
    )]
    /// Renders the actual debug line without reproducing attacker-controlled content.
    fn test_poll_decode_failure_message_success(#[case] body: &str, #[case] expected: &str) {
        let message = poll_decode_failure_message("poll operation", body.as_bytes(), true)
            .expect("debug is enabled for the poll seam");

        assert_eq!(message, expected);
        assert!(!message.contains("must-not-be-logged"));
    }
}
