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

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Print version, build commit, target triple, and build date.
    Version,
}
