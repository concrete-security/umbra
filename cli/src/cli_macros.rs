//! Tiny macros shared across `cli/src/commands/*`.

/// Unwrap a `Result<T, (ExitStatus, String)>`. On `Err`, print the message
/// via [`crate::style::eprintln_error`] and `return` the carried exit status
/// from the surrounding function.
///
/// Replaces the `match expr { Ok(v) => v, Err((status, msg)) => { ... } }`
/// boilerplate that appears ~50x across `commands/*.rs`.
macro_rules! try_or_eprintln {
    ($expr:expr) => {
        match $expr {
            Ok(value) => value,
            Err((status, message)) => {
                $crate::style::eprintln_error(&message);
                return status;
            }
        }
    };
}
