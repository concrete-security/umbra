use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "concrete",
    version,
    about = "Command-line client for the Concrete platform",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Increase log verbosity (-v INFO, -vv DEBUG, -vvv TRACE; default WARN).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Disable ANSI color in stdout and stderr.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Emit JSON output for commands that emit a structured payload.
    #[arg(long, global = true)]
    pub json: bool,

    /// Override the Concrete config directory for this invocation.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Override the Console base URL for this invocation.
    #[arg(long, global = true)]
    pub console_url: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Authenticate and inspect the local Console session.
    #[command(subcommand)]
    Auth(AuthCommand),

    /// Query and verify Console audit records.
    #[command(subcommand)]
    Audit(AuditCommand),

    /// Print version, build commit, target triple, and build date.
    Version,
}

#[derive(Subcommand, Debug)]
pub enum AuditCommand {
    /// Query control-plane audit events.
    Events(AuditEventsArgs),
}

#[derive(clap::Args, Debug)]
pub struct AuditEventsArgs {
    /// Filter to events recorded by this user id.
    #[arg(long)]
    pub actor: Option<String>,

    /// Filter to events for this target type.
    #[arg(long)]
    pub target_type: Option<String>,

    /// Filter to events for this target id.
    #[arg(long)]
    pub target_id: Option<String>,

    /// Filter to a typed audit action.
    #[arg(long)]
    pub action: Option<String>,

    /// Filter to events created at or after this RFC3339 timestamp.
    #[arg(long = "from")]
    pub from: Option<String>,

    /// Filter to events created at or before this RFC3339 timestamp.
    #[arg(long)]
    pub to: Option<String>,

    /// Page size, 1..500.
    #[arg(long, default_value_t = 100)]
    pub limit: u16,

    /// Opaque pagination cursor from the previous response.
    #[arg(long)]
    pub cursor: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Authenticate against the Console.
    Login {
        /// OIDC provider to use. Only google is supported in v0.
        #[arg(long)]
        provider: Option<String>,

        /// Use the OAuth device flow.
        #[arg(long, conflicts_with = "no_browser")]
        device: bool,

        /// Alias for --device.
        #[arg(long = "no-browser")]
        no_browser: bool,
    },

    /// Delete the local session and notify the Console best-effort.
    Logout,

    /// Show local session status without a network call.
    Status,

    /// Force a refresh of the stored access token.
    Refresh,

    /// Print the current access token.
    Token,
}
