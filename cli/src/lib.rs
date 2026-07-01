use std::{
    io::{self, ErrorKind, IsTerminal, Write},
    process::ExitCode,
};

use clap::{CommandFactory, Parser};

#[macro_use]
mod cli_macros;

mod atls;
mod cli;
mod commands;
mod config;
mod console;
mod cvm_state;
mod exit;
mod operation;
mod session;
mod ssh_identity;
mod ssh_identity_store;
mod style;

pub use exit::ExitStatus;

pub fn run() -> ExitCode {
    install_default_crypto_provider();

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
    style::init(
        !config.no_color
            && config.output != config::OutputFormat::Json
            && io::stdout().is_terminal(),
    );
    let status = match args.command {
        cli::Command::Admin(command) => commands::admin::run(command, &config, json_output),
        cli::Command::Alias(args) => commands::ssh::run_alias(args, &config, json_output),
        cli::Command::Attach(args) => commands::ssh::run_attach(args, &config),
        cli::Command::Audit(command) => commands::audit::run(command, &config, json_output),
        cli::Command::Auth(command) => commands::auth::run(command, &config, json_output),
        cli::Command::Claude(args) => commands::ssh::run_agent(args, &config, "claude"),
        cli::Command::Code(args) => commands::ssh::run_code(args, &config),
        cli::Command::Completions { shell } => {
            let mut command = cli::Cli::command();
            let mut output = Vec::new();
            clap_complete::generate(shell, &mut command, "concrete", &mut output);
            match io::stdout().write_all(&output) {
                Ok(()) => ExitStatus::Ok,
                Err(err) if err.kind() == ErrorKind::BrokenPipe => ExitStatus::Ok,
                Err(err) => {
                    style::eprintln_error(&format!("[error] failed to write completions: {err}"));
                    ExitStatus::Error
                }
            }
        }
        cli::Command::Codex(args) => commands::ssh::run_agent(args, &config, "codex"),
        cli::Command::Config(command) => commands::config::run(command, &config, json_output),
        cli::Command::Cvm(command) => commands::cvm::run(command, &config, json_output),
        cli::Command::Cursor(args) => commands::ssh::run_cursor(args, &config),
        cli::Command::Entity(command) => commands::entity::run(command, &config, json_output),
        cli::Command::Key(command) => commands::key::run(command, &config, json_output),
        cli::Command::Kill(args) => commands::ssh::run_kill(args, &config, json_output),
        cli::Command::Profile(command) => commands::profile::run(command, &config, json_output),
        cli::Command::Ps(args) => commands::ssh::run_ps(args, &config, json_output),
        cli::Command::Quota(command) => commands::quota::run(command, &config, json_output),
        cli::Command::Reconcile(reconcile_args) => {
            commands::reconcile::run(reconcile_args, &config, json_output)
        }
        cli::Command::SecurityCvm(command) => {
            commands::security_cvm::run(command, &config, json_output)
        }
        cli::Command::Skill(command) => commands::skill::run(command, &config, json_output),
        cli::Command::Ssh(args) => commands::ssh::run(args, &config),
        cli::Command::Status => commands::status::run(&config, json_output),
        cli::Command::TrafficLogs(traffic_args) => {
            commands::traffic_logs::run(traffic_args, &config, json_output)
        }
        cli::Command::Tunnel { target } => commands::tunnel::run(&target, &config),
        cli::Command::User(command) => commands::user::run(command, &config, json_output),
        cli::Command::Version => commands::version::run(json_output),
    };
    ExitCode::from(status)
}

fn install_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
