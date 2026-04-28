use std::process::ExitCode;

use clap::Parser;

mod cli;
mod commands;
mod exit;

pub use exit::ExitStatus;

pub fn run() -> ExitCode {
    let args = match cli::Cli::try_parse() {
        Ok(args) => args,
        Err(err) => {
            // clap routes --help / --version to stdout and exits 0; routes
            // genuine parse errors to stderr. Map the latter to our Usage
            // exit code so the CLI's contract is consistent.
            let _ = err.print();
            return if err.use_stderr() {
                ExitCode::from(ExitStatus::Usage)
            } else {
                ExitCode::SUCCESS
            };
        }
    };
    let status = match args.command {
        cli::Command::Version => commands::version::run(args.json),
    };
    ExitCode::from(status)
}
