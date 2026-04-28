use std::process::ExitCode;

/// Numeric values are part of the CLI's public contract and are stable.
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum ExitStatus {
    Ok = 0,
    Error = 1,
    AuthRequired = 2,
    WaitTimeout = 3,
    Usage = 4,
}

impl From<ExitStatus> for ExitCode {
    fn from(value: ExitStatus) -> Self {
        ExitCode::from(value as u8)
    }
}
