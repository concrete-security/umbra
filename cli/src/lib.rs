use std::{
    io::{self, ErrorKind, Write},
    process::ExitCode,
};

use clap::{CommandFactory, Parser};

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
    let config = config::ResolvedConfig::resolve(config::ConfigOverrides {
        config_dir: args.config.clone(),
        console_url: args.console_url.clone(),
        cvm: args.cvm.clone(),
        profile: args.profile.clone(),
        atls_policy: args.atls_policy.clone(),
        insecure_skip_atls_policy: args.insecure_skip_atls_policy,
        request_id: args.request_id.clone(),
        force: args.force,
        json: args.json,
        no_color: args.no_color,
        verbose: args.verbose,
    });
    let json_output = config.output == config::OutputFormat::Json;
    let status = match args.command {
        cli::Command::Admin(command) => commands::admin::run(command, &config, json_output),
        cli::Command::Audit(command) => commands::audit::run(command, &config, json_output),
        cli::Command::Auth(command) => commands::auth::run(command, &config, json_output),
        cli::Command::Completions { shell } => {
            let mut command = cli::Cli::command();
            let mut output = Vec::new();
            clap_complete::generate(shell, &mut command, "concrete", &mut output);
            match io::stdout().write_all(&output) {
                Ok(()) => ExitStatus::Ok,
                Err(err) if err.kind() == ErrorKind::BrokenPipe => ExitStatus::Ok,
                Err(err) => {
                    eprintln!("[error] failed to write completions: {err}");
                    ExitStatus::Error
                }
            }
        }
        cli::Command::Config(command) => commands::config::run(command, &config, json_output),
        cli::Command::Cvm(command) => commands::cvm::run(command, &config, json_output),
        cli::Command::Entity(command) => commands::entity::run(command, &config, json_output),
        cli::Command::Key(command) => commands::key::run(command, &config, json_output),
        cli::Command::Profile(command) => commands::profile::run(command, &config, json_output),
        cli::Command::Quota(command) => commands::quota::run(command, &config, json_output),
        cli::Command::Reconcile(reconcile_args) => {
            commands::reconcile::run(reconcile_args, &config, json_output)
        }
        cli::Command::SecurityCvm(command) => {
            commands::security_cvm::run(command, &config, json_output)
        }
        cli::Command::Status => commands::status::run(&config, json_output),
        cli::Command::TrafficLogs(traffic_args) => {
            commands::traffic_logs::run(traffic_args, &config, json_output)
        }
        cli::Command::User(command) => commands::user::run(command, &config, json_output),
        cli::Command::Version => commands::version::run(json_output),
    };
    ExitCode::from(status)
}
