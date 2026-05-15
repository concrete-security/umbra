use std::process::ExitCode;

use clap::Parser;

mod cli;
mod commands;
mod config;
mod exit;
mod session;

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
    let config = config::ResolvedConfig::resolve(
        args.config.clone(),
        args.console_url.clone(),
        args.profile.clone(),
    );
    let status = match args.command {
        cli::Command::Admin(command) => commands::admin::run(command, &config, args.json),
        cli::Command::Audit(command) => commands::audit::run(command, &config, args.json),
        cli::Command::Auth(command) => commands::auth::run(command, &config, args.json),
        cli::Command::Key(command) => commands::key::run(command, &config, args.json),
        cli::Command::Profile(command) => commands::profile::run(command, &config, args.json),
        cli::Command::Quota(command) => commands::quota::run(command, &config, args.json),
        cli::Command::SecurityCvm(command) => {
            commands::security_cvm::run(command, &config, args.json)
        }
        cli::Command::TrafficLogs(traffic_args) => {
            commands::traffic_logs::run(traffic_args, &config, args.json)
        }
        cli::Command::User(command) => commands::user::run(command, &config, args.json),
        cli::Command::Version => commands::version::run(args.json),
    };
    ExitCode::from(status)
}
