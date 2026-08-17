use std::{
    io::{self, ErrorKind, IsTerminal, Write},
    process::ExitCode,
};

use clap::{CommandFactory, FromArgMatches};

#[macro_use]
mod cli_macros;

mod atls_policy_store;
mod cli;
mod commands;
mod config;
mod console;
mod cvm_state;
mod exit;
mod fsutil;
mod help;
mod operation;
mod prompt;
mod session;
mod ssh_identity;
mod ssh_identity_store;
mod style;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

pub use exit::ExitStatus;

pub fn run() -> ExitCode {
    install_default_crypto_provider();

    // `help::command()` applies the grouped top-level help and per-command
    // Examples blocks; parsing semantics are identical to `Cli::try_parse()`.
    let args = match help::command().try_get_matches() {
        Ok(matches) => match cli::Cli::from_arg_matches(&matches) {
            Ok(args) => args,
            Err(err) => {
                let _ = err.print();
                return ExitCode::from(ExitStatus::Usage);
            }
        },
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
    let quiet_stderr = matches!(
        args.command,
        cli::Command::Completions { .. } | cli::Command::Tunnel { .. }
    );
    if let (false, Some(reason)) = (quiet_stderr, &config.config_file_error) {
        style::eprintln_warn(&format!(
            "[warn] ignoring config.toml: {reason}; every setting falls back to its environment variable or default -- fix that line, check the permissions, or delete the file"
        ));
    }
    if !quiet_stderr && !config.unknown_config_keys.is_empty() {
        const NAMED: usize = 8;
        let total = config.unknown_config_keys.len();
        let mut listed = config.unknown_config_keys[..total.min(NAMED)].join(", ");
        if total > NAMED {
            listed.push_str(&format!(", and {} more", total - NAMED));
        }
        style::eprintln_warn(&format!(
            "[warn] config.toml has {} this CLI ignores: {} -- check the spelling, or upgrade with `umbra update`",
            if total == 1 { "a key" } else { "keys" },
            style::single_line(&listed)
        ));
    }
    let update_notice_eligible = !quiet_stderr && !matches!(args.command, cli::Command::Update(_));
    if update_notice_eligible {
        commands::update::maybe_spawn_background_refresh(&config);
    }
    let status = match args.command {
        cli::Command::Admin(command) => commands::admin::run(command, &config, json_output),
        cli::Command::Alias(command) => commands::alias::run(command, &config, json_output),
        cli::Command::Attach(args) => commands::ssh::run_attach(args, &config),
        cli::Command::Audit(command) => commands::audit::run(command, &config, json_output),
        cli::Command::Auth(command) => commands::auth::run(command, &config, json_output),
        cli::Command::Claude { command, session } => match command {
            Some(cli::ClaudeCommand::Connect(connect_args)) => {
                commands::claude_connect::run_connect(connect_args, &config, json_output)
            }
            None => commands::ssh::run_agent(session, &config, "claude"),
        },
        cli::Command::Code(args) => commands::ssh::run_code(args, &config),
        cli::Command::Completions { shell } => {
            let mut command = cli::Cli::command();
            let mut output = Vec::new();
            clap_complete::generate(shell, &mut command, "umbra", &mut output);
            match io::stdout().write_all(&output) {
                Ok(()) => ExitStatus::Ok,
                Err(err) if err.kind() == ErrorKind::BrokenPipe => ExitStatus::Ok,
                Err(err) => {
                    style::eprintln_error(&format!("[error] failed to write completions: {err}"));
                    ExitStatus::Error
                }
            }
        }
        cli::Command::Codex { command, session } => match command {
            Some(cli::CodexCommand::Connect(connect_args)) => {
                commands::codex_connect::run_connect(connect_args, &config, json_output)
            }
            None => commands::ssh::run_agent(session, &config, "codex"),
        },
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
        cli::Command::Secret(command) => commands::secret::run(command, &config, json_output),
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
        cli::Command::Update(update_args) => {
            commands::update::run(update_args, &config, json_output)
        }
        cli::Command::User(command) => commands::user::run(command, &config, json_output),
        cli::Command::Version => commands::version::run(json_output),
    };
    if update_notice_eligible {
        commands::update::maybe_print_update_notice(&config);
    }
    ExitCode::from(status)
}

fn install_default_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
