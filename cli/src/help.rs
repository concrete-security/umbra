//! Grouped, per-level `concrete` help rendering.
//!
//! clap v4 lists every subcommand flat under one `Commands:` heading, repeats
//! every `global` flag in every subcommand's help, and cannot show a per-command
//! usage synopsis inside the commands list. This module replaces the help body
//! for three command shapes so each level shows exactly the right options:
//!
//! - **root** (`concrete --help`): subcommands bucketed into titled [`GROUPS`],
//!   then a `Global options:` block listing the shared flags.
//! - **group** (`concrete cvm --help`, any command with subcommands): a
//!   multi-line `Usage:` block listing every subcommand's invocation form (with
//!   its own args), then a `Commands:` list of name + description. Per-option
//!   detail lives at the leaf level.
//! - **leaf** (`concrete ssh --help`, `concrete cvm list --help`): an
//!   `Examples:` block, then hand-rendered `Arguments:` / `Options:` blocks
//!   showing ONLY the command's own args — each with a short description plus a
//!   `Default:` line and `[values: …]` where they apply.
//!
//! Every level is rendered by hand into `{before-help}`; clap's `{all-args}` is
//! never used, so the layout is fully ours. Global flags carry `hide = true` (in
//! `cli.rs`) — they still parse everywhere but are re-emitted by hand at the root
//! only, so levels 2 and 3 never repeat them. `-h/--help` is likewise hidden and
//! documented once at the root. The tables are guarded against drift by the tests.

use std::io::IsTerminal;

use clap::builder::styling::Style;
use clap::builder::Styles;
use clap::{Arg, ArgAction, Command, CommandFactory};

use crate::cli::Cli;

/// Section headings (`Commands:`, `Options:`, group titles, `Examples:`): bold +
/// underline, matching clap's `Usage:` heading.
fn heading_style() -> Style {
    Style::new().bold().underline()
}

/// A subcommand's one-line description: dim (grey), so it recedes behind the
/// command name and example.
fn about_style() -> Style {
    Style::new().dimmed()
}

/// Bold: the left "identifier" column — command names, option flags — plus the
/// example / synopsis lines, so they stand out against the dim descriptions.
fn bold_style() -> Style {
    Style::new().bold()
}

/// clap `Styles` with `Usage:` and section headers set to our heading style, so
/// clap-rendered headings (root `Usage:`, leaf `Options:`) match the ones this
/// module renders by hand.
fn clap_styles() -> Styles {
    Styles::styled()
        .usage(heading_style())
        .header(heading_style())
}

/// Whether ANSI styling should be emitted for the hand-rendered help sections.
/// Mirrors clap's `Auto` colour choice: a real terminal with `NO_COLOR` unset.
/// Help is rendered before `style::init`, so this cannot use `style.rs`.
fn color_enabled() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// Wrap `text` in `style`'s ANSI codes when colour is enabled, else return it bare.
fn paint(style: Style, text: &str) -> String {
    if color_enabled() {
        format!("{}{text}{}", style.render(), style.render_reset())
    } else {
        text.to_string()
    }
}

/// Ordered, titled groups for the top-level `concrete --help`. Every declared
/// subcommand MUST appear in exactly one group (guarded by
/// `test_help_level_1_root_matches_declared_success`, which checks the rendered
/// help lists exactly the declared commands).
const GROUPS: &[(&str, &[&str])] = &[
    ("Getting started", &["status", "auth"]),
    (
        "Sessions & access",
        &[
            "ssh", "code", "cursor", "claude", "codex", "ps", "attach", "kill", "tunnel",
        ],
    ),
    ("Manage sandboxes", &["cvm", "security-cvm"]),
    (
        "Org, policy & access",
        &["user", "profile", "key", "quota", "entity"],
    ),
    ("Observability", &["audit", "traffic-logs"]),
    (
        "Local tools",
        &["alias", "config", "skill", "completions", "version", "help"],
    ),
    ("Operator", &["admin", "reconcile"]),
];

/// Runnable examples shown in a leaf command's `Examples:` block, keyed by the
/// command path below `concrete` (space-joined; e.g. `"cvm launch"`). An
/// arg-bearing leaf MUST have an entry so its `Examples:` block renders (guarded
/// by `test_help_level_3_leaves_have_usage_and_examples_success`).
const EXAMPLES: &[(&str, &[&str])] = &[
    // Top-level leaves.
    (
        "ssh",
        &[
            "concrete ssh",
            "concrete ssh <CVM_ID|alias>",
            "concrete ssh --name build",
        ],
    ),
    (
        "code",
        &[
            "concrete code <CVM_ID|alias> --workspace ~/repo",
            "concrete code",
        ],
    ),
    (
        "cursor",
        &[
            "concrete cursor <CVM_ID|alias> --workspace ~/repo",
            "concrete cursor",
        ],
    ),
    (
        "claude",
        &[
            "concrete claude --workspace ~/repo",
            "concrete claude --name review",
        ],
    ),
    ("codex", &["concrete codex --workspace ~/repo"]),
    ("ps", &["concrete ps", "concrete ps <CVM_ID|alias>"]),
    (
        "attach",
        &[
            "concrete attach <SESSION|alias>",
            "concrete attach <SESSION|alias> --cvm <CVM_ID|alias>",
        ],
    ),
    ("kill", &["concrete kill <SESSION|alias>"]),
    ("tunnel", &["concrete tunnel <FQDN>"]),
    (
        "traffic-logs",
        &[
            "concrete traffic-logs --cvm <CVM_ID>",
            "concrete traffic-logs --from 2026-07-01T00:00:00Z",
        ],
    ),
    (
        "reconcile",
        &["concrete reconcile", "concrete reconcile --no-orphans"],
    ),
    (
        "completions",
        &["concrete completions bash", "concrete completions zsh"],
    ),
    // `cvm` group leaves.
    (
        "cvm list",
        &[
            "concrete cvm list --state running",
            "concrete cvm list --state all",
            "concrete cvm list",
        ],
    ),
    (
        "cvm instance-types",
        &[
            "concrete cvm instance-types --refresh",
            "concrete cvm instance-types",
        ],
    ),
    (
        "cvm launch",
        &[
            "concrete cvm launch --instance-type tdx.cpx41 --region eu-west-3",
            "concrete cvm launch --ssh-key <KEY_ID> --alias mybox",
            "concrete cvm launch --no-wait",
            "concrete cvm launch",
        ],
    ),
    (
        "cvm attach",
        &["concrete cvm attach <CVM_ID|alias> --profile <PROFILE_ID>"],
    ),
    (
        "cvm detach",
        &["concrete cvm detach <CVM_ID|alias> --profile <PROFILE_ID>"],
    ),
    ("cvm start", &["concrete cvm start <CVM_ID|alias>"]),
    ("cvm stop", &["concrete cvm stop <CVM_ID|alias>"]),
    ("cvm update", &["concrete cvm update <CVM_ID|alias>"]),
    (
        "cvm terminate",
        &[
            "concrete cvm terminate <CVM_ID|alias> --no-wait",
            "concrete cvm terminate <CVM_ID|alias>",
        ],
    ),
    // `auth` group.
    (
        "auth login",
        &[
            "concrete auth login",
            "concrete auth login https://console.example.com",
            "concrete auth login --device",
        ],
    ),
    // `security-cvm` group.
    (
        "security-cvm launch",
        &[
            "concrete security-cvm launch",
            "concrete security-cvm launch --instance-type tdx.medium --region eu-west-3",
        ],
    ),
    ("security-cvm update", &["concrete security-cvm update"]),
    (
        "security-cvm attestation",
        &[
            "concrete security-cvm attestation",
            "concrete security-cvm attestation --probe",
        ],
    ),
    // `user` group.
    (
        "user add",
        &[
            "concrete user add alice@example.com --permission CVM_LAUNCH",
            "concrete user add alice@example.com --name Alice",
        ],
    ),
    (
        "user list",
        &[
            "concrete user list",
            "concrete user list --status active",
            "concrete user list --assigned yes",
        ],
    ),
    ("user show", &["concrete user show <USER_ID>"]),
    ("user deactivate", &["concrete user deactivate <USER_ID>"]),
    ("user reactivate", &["concrete user reactivate <USER_ID>"]),
    ("user erase", &["concrete user erase <USER_ID>"]),
    (
        "user permissions list",
        &["concrete user permissions list <USER_ID>"],
    ),
    (
        "user permissions grant",
        &["concrete user permissions grant <USER_ID> CVM_MANAGE"],
    ),
    (
        "user permissions revoke",
        &["concrete user permissions revoke <USER_ID> CVM_MANAGE"],
    ),
    // `profile` group.
    (
        "profile create",
        &[
            "concrete profile create my-profile",
            "concrete profile create my-profile --alias myprof",
        ],
    ),
    (
        "profile list",
        &[
            "concrete profile list",
            "concrete profile list --assigned yes",
        ],
    ),
    (
        "profile configure",
        &[
            "concrete profile configure --policy-file policy.json",
            "concrete profile configure --name new-name",
        ],
    ),
    (
        "profile members add",
        &["concrete profile members add <USER_ID>"],
    ),
    (
        "profile members remove",
        &["concrete profile members remove <USER_ID>"],
    ),
    // `key` group.
    (
        "key add",
        &[
            "concrete key add --label laptop --file ~/.ssh/id_ed25519.pub",
            "concrete key add --label laptop --alias laptop",
        ],
    ),
    ("key remove", &["concrete key remove <KEY_ID>"]),
    // `quota` group.
    (
        "quota get",
        &["concrete quota get", "concrete quota get --user <USER_ID>"],
    ),
    (
        "quota set",
        &[
            "concrete quota set dev_cvms 10",
            "concrete quota set dev_cvms 10 --user <USER_ID>",
        ],
    ),
    ("quota clear", &["concrete quota clear dev_cvms"]),
    // `entity` group.
    (
        "entity add",
        &["concrete entity add example.com --name Example"],
    ),
    ("entity list", &["concrete entity list"]),
    // `audit` group.
    (
        "audit events",
        &[
            "concrete audit events --limit 20",
            "concrete audit events --action CVM_LAUNCHED",
            "concrete audit events --actor <USER_ID>",
        ],
    ),
    (
        "audit export",
        &[
            "concrete audit export --format ndjson",
            "concrete audit export --format csv --output audit.csv",
        ],
    ),
    // `alias` group.
    ("alias cvm", &["concrete alias cvm <CVM_ID> myvm"]),
    (
        "alias profile",
        &["concrete alias profile <PROFILE_ID> myprof"],
    ),
    ("alias ssh-key", &["concrete alias ssh-key <KEY_ID> laptop"]),
    (
        "alias session",
        &[
            "concrete alias session <SESSION> mysess",
            "concrete alias session <SESSION> mysess --cvm <CVM_ID|alias>",
        ],
    ),
    ("alias rm", &["concrete alias rm myvm"]),
    ("alias rename", &["concrete alias rename oldname newname"]),
    (
        "alias prune",
        &["concrete alias prune", "concrete alias prune --dry-run"],
    ),
    // `config` group.
    // `skill` group.
    (
        "skill install",
        &[
            "concrete skill install",
            "concrete skill install --agents claude",
        ],
    ),
    // `admin` group.
    (
        "admin sessions revoke",
        &[
            "concrete admin sessions revoke --user <USER_ID>",
            "concrete admin sessions revoke --entity <ENTITY_ID>",
        ],
    ),
    (
        "admin keys rotate",
        &["concrete admin keys rotate --new-kid <KID>"],
    ),
];

const HELP_ABOUT: &str = "Show help for a command or subcommand";

/// Global flags a command genuinely depends on (e.g. `cvm attach`/`detach` need
/// `--profile`). Referenced by long name; shown in BOTH the command's synopsis and
/// its Options block even though globals are otherwise hidden at those levels, so
/// an essential flag is never mentioned in an example without being documented.
const ESSENTIAL_GLOBALS: &[(&str, &[&str])] =
    &[("cvm attach", &["profile"]), ("cvm detach", &["profile"])];

/// The essential-global long names for a command path.
fn essential_globals(path: &str) -> &'static [&'static str] {
    ESSENTIAL_GLOBALS
        .iter()
        .find(|(key, _)| *key == path)
        .map(|(_, names)| *names)
        .unwrap_or(&[])
}

/// Look up a global flag's `Arg` (declared on the root) by long name, so its real
/// value name / help can be rendered where the flag is essential.
fn find_global_arg(long: &str) -> Option<Arg> {
    Cli::command()
        .get_arguments()
        .find(|arg| arg.get_long() == Some(long))
        .cloned()
}

/// Per-command note for the shared CVM target positional, since its "omitted"
/// behaviour is per-verb: most fall back to the persisted default CVM, while the
/// destructive `stop`/`terminate` require an explicit id. Keyed by command path.
const CVM_TARGET_NOTE: &[(&str, &str)] = &[
    ("cvm start", "Default: the persisted default CVM."),
    ("cvm update", "Default: the persisted default CVM."),
    ("cvm attach", "Default: the persisted default CVM."),
    ("cvm detach", "Default: the persisted default CVM."),
    ("cvm stop", "Required; no default CVM is used."),
    ("cvm terminate", "Required; no default CVM is used."),
    ("ssh", "Default: the persisted default CVM."),
    ("code", "Default: the persisted default CVM."),
    ("cursor", "Default: the persisted default CVM."),
    ("claude", "Default: the persisted default CVM."),
    ("codex", "Default: the persisted default CVM."),
];

fn cvm_target_note(path: &str) -> Option<&'static str> {
    CVM_TARGET_NOTE
        .iter()
        .find(|(key, _)| *key == path)
        .map(|(_, note)| *note)
}

/// Template for the root and leaf commands: clap's usage line is kept, the rest
/// of the body is rendered by hand into `{before-help}`; `{all-args}` is unused.
const CONTAINER_TEMPLATE: &str =
    "{about-with-newline}\n{usage-heading} {usage}\n\n{before-help}{after-help}";

/// Template for non-root group commands: the whole body — including a multi-line
/// `Usage:` block listing every subcommand form — is rendered by hand, so clap's
/// single-line usage is omitted.
const GROUP_TEMPLATE: &str = "{about-with-newline}\n{before-help}{after-help}";

/// Build the `concrete` command with per-level help applied. Parsing behaviour
/// is unchanged — this only customises help rendering.
pub fn command() -> Command {
    let root_meta = Cli::command();
    let root_body = format!(
        "{}\n{}",
        render_groups(&root_meta),
        render_global_options(&root_meta)
    );

    let root = Cli::command();
    let names = child_names(&root);
    let mut root = root;
    for name in names {
        let child_path = name.clone();
        root = root.mut_subcommand(name, move |sub| decorate(sub, child_path.clone()));
    }
    root.styles(clap_styles())
        .help_template(CONTAINER_TEMPLATE)
        .before_help(root_body)
}

/// Apply the group or leaf help shape to `cmd`, then recurse into its children.
fn decorate(cmd: Command, path: String) -> Command {
    let children = child_names(&cmd);

    // Hide the built-in `-h/--help` flag from levels 2 and 3: it is universal
    // (documented in the root `Global options:` block) and would otherwise be the
    // only non-own option repeated on every command. Replacing the auto flag with
    // a hidden one keeps `-h`/`--help` working everywhere, just not displayed.
    let cmd = cmd.styles(clap_styles()).disable_help_flag(true).arg(
        Arg::new("help")
            .short('h')
            .long("help")
            .action(ArgAction::Help)
            .help("Print help")
            .hide(true),
    );
    let mut cmd = if !children.is_empty() {
        let body = render_group_body(&cmd, &path);
        cmd.help_template(GROUP_TEMPLATE).before_help(body)
    } else {
        let body = render_leaf_body(&cmd, &path);
        if body.is_empty() {
            cmd
        } else {
            cmd.help_template(CONTAINER_TEMPLATE).before_help(body)
        }
    };

    for name in children {
        let child_path = format!("{path} {name}");
        cmd = cmd.mut_subcommand(name, move |sub| decorate(sub, child_path.clone()));
    }
    cmd
}

// --- command / option classification -------------------------------------

/// Declared subcommand names, excluding the clap-injected `help` pseudo-command.
fn child_names(cmd: &Command) -> Vec<String> {
    cmd.get_subcommands()
        .map(|sub| sub.get_name().to_string())
        .filter(|name| name != "help")
        .collect()
}

/// An argument that belongs to the command itself: not a propagated global flag,
/// and not the auto help/version actions.
fn is_own(arg: &Arg) -> bool {
    !arg.is_global_set()
        && !matches!(
            arg.get_action(),
            ArgAction::Help | ArgAction::HelpShort | ArgAction::HelpLong | ArgAction::Version
        )
}

/// Whether the command declares any argument of its own (excluding globals and
/// the auto help/version flags). Arg-less commands need no Examples block — their
/// usage line already shows the only possible invocation.
fn has_own_args(cmd: &Command) -> bool {
    cmd.get_arguments().any(is_own)
}

fn takes_value(arg: &Arg) -> bool {
    !matches!(
        arg.get_action(),
        ArgAction::SetTrue
            | ArgAction::SetFalse
            | ArgAction::Count
            | ArgAction::Help
            | ArgAction::HelpShort
            | ArgAction::HelpLong
            | ArgAction::Version
    )
}

/// The `<VALUE>` placeholder for an argument: the pipe-joined possible values
/// when `expand_choices` and the arg is an enum, else its value name, else its id.
fn value_placeholder(arg: &Arg, expand_choices: bool) -> String {
    if expand_choices {
        let choices: Vec<String> = arg
            .get_possible_values()
            .iter()
            .map(|value| value.get_name().to_string())
            .collect();
        if !choices.is_empty() {
            return choices.join("|");
        }
    }
    if let Some(name) = arg.get_value_names().and_then(|names| names.first()) {
        return name.to_string();
    }
    arg.get_id().as_str().to_uppercase()
}

// --- synopsis (group Commands lines) --------------------------------------

/// One argument in a usage synopsis: `<POS>` / `[POS]` for positionals,
/// `--flag <V>` / `[--flag <V>]` for options, bracketed when optional.
fn arg_token(arg: &Arg) -> String {
    if arg.is_positional() {
        let name = value_placeholder(arg, true);
        if arg.is_required_set() {
            format!("<{name}>")
        } else {
            format!("[{name}]")
        }
    } else {
        let long = arg.get_long().unwrap_or_default();
        let body = if takes_value(arg) {
            format!("--{long} <{}>", value_placeholder(arg, true))
        } else {
            format!("--{long}")
        };
        if arg.is_required_set() {
            body
        } else {
            format!("[{body}]")
        }
    }
}

/// The bracketed argument tokens for a subcommand's synopsis (positionals then
/// options then essential-global extras), excluding the `concrete <path>` prefix.
/// The shared `CvmTarget` exposes the same target twice — a positional `cvm_id`
/// and an equivalent `--cvm` flag. When the positional is present the `--cvm`
/// flag is redundant, so it is shown only once (as the positional) everywhere.
fn hides_cvm_flag(cmd: &Command) -> bool {
    cmd.get_arguments()
        .any(|arg| arg.is_positional() && arg.get_id() == "cvm_id")
}

fn synopsis_tokens(cmd: &Command, path: &str) -> Vec<String> {
    let hide_cvm = hides_cvm_flag(cmd);

    let mut positionals = Vec::new();
    let mut options = Vec::new();
    for arg in cmd.get_arguments() {
        if !is_own(arg) {
            continue;
        }
        if arg.is_positional() {
            positionals.push(arg_token(arg));
        } else if hide_cvm && arg.get_long() == Some("cvm") {
            continue;
        } else {
            options.push(arg_token(arg));
        }
    }
    let mut tokens: Vec<String> = positionals.into_iter().chain(options).collect();
    // Essential globals are shown unbracketed (they are needed, not optional).
    for long in essential_globals(path) {
        if let Some(arg) = find_global_arg(long) {
            tokens.push(format!("--{long} <{}>", value_placeholder(&arg, true)));
        }
    }
    tokens
}

/// Lay out a synopsis over one or more lines: `concrete <path>` plus its tokens,
/// wrapped at [`MAX_WIDTH`]; continuation lines align under the first argument
/// (just past the `concrete <path> ` prefix). Returns each line already indented.
fn render_synopsis(cmd: &Command, path: &str, first_indent: usize) -> Vec<String> {
    let prefix = format!("concrete {path}");
    // Continuation lines line up under the first token, right after the prefix.
    let cont_indent = first_indent + prefix.len() + 1;
    let mut lines = Vec::new();
    let mut indent = first_indent;
    let mut line = prefix.clone();

    for token in synopsis_tokens(cmd, path) {
        if indent + line.len() + 1 + token.len() > MAX_WIDTH && line != prefix {
            lines.push(format!("{}{line}", " ".repeat(indent)));
            indent = cont_indent;
            line = token;
        } else {
            line.push(' ');
            line.push_str(&token);
        }
    }
    lines.push(format!("{}{line}", " ".repeat(indent)));
    lines
}

// --- option rows (root Global options + leaf Arguments/Options) ------------

/// The flag column for an option row: `-x, --long <VALUE>`, or `--long <VALUE>`
/// when there is no short. Flags start at the same indent whether or not they have
/// a short form — no artificial short-column padding.
fn option_flags(arg: &Arg) -> String {
    let short = arg
        .get_short()
        .map(|c| format!("-{c}, "))
        .unwrap_or_default();
    let long = arg.get_long().map(|l| format!("--{l}")).unwrap_or_default();
    let repeat = if matches!(arg.get_action(), ArgAction::Count) {
        "..."
    } else {
        ""
    };
    let value = if takes_value(arg) {
        format!(" <{}>", value_placeholder(arg, false))
    } else {
        String::new()
    };
    format!("{short}{long}{repeat}{value}")
}

fn arg_help(arg: &Arg) -> String {
    arg.get_help()
        .map(|help| first_line(&help.to_string()))
        .unwrap_or_default()
}

/// Maximum rendered line width before wrapping (per cli-style §4).
const MAX_WIDTH: usize = 100;

/// Greedy word-wrap `text` into lines no wider than `width` (never breaks a word).
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > width {
            lines.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    lines.push(current);
    lines
}

/// Split an arg's help into a short description and an optional `Default: …`
/// clause authored inline in the doc comment (e.g. `"CVM region. Default: …"`).
fn split_help(help: &str) -> (String, Option<String>) {
    match help.find("Default:") {
        Some(idx) => (
            help[..idx].trim().to_string(),
            Some(help[idx..].trim().to_string()),
        ),
        None => (help.to_string(), None),
    }
}

/// The help lines for one row. `detailed` (leaf level) adds the `Default:` line
/// and a compact `[values: …]` line for enums; the overview level (root globals)
/// shows only the short description.
fn option_help_lines(arg: &Arg, detailed: bool) -> Vec<String> {
    let (desc, doc_defaults) = split_help(&arg_help(arg));
    if !detailed {
        return vec![desc];
    }
    let mut lines = vec![desc];
    // Prefer clap's real default value(s); fall back to a hand-written
    // `Default:` clause only for defaults resolved in code (e.g. `--state`
    // → alive), never for values the CLI does not actually hold.
    let clap_defaults: Vec<String> = arg
        .get_default_values()
        .iter()
        .map(|value| value.to_string_lossy().into_owned())
        .collect();
    if !clap_defaults.is_empty() {
        lines.push(format!("Default: {}", clap_defaults.join(", ")));
    } else if let Some(defaults) = doc_defaults {
        lines.push(defaults);
    }
    // Only value-taking args have a meaningful value set; a bool flag's
    // true/false is noise.
    if takes_value(arg) {
        let values: Vec<String> = arg
            .get_possible_values()
            .iter()
            .map(|value| value.get_name().to_string())
            .collect();
        if !values.is_empty() {
            lines.push(format!("[values: {}]", values.join(", ")));
        }
    }
    lines
}

/// Format a titled block of aligned rows. Each row is a bold flag/name column and
/// one or more help lines (description, then optional `Default:` / `[values: …]`).
/// Every help line wraps at [`MAX_WIDTH`], all continuations indented to the help
/// column.
fn format_option_block(title: &str, rows: &[(String, Vec<String>)]) -> String {
    let flag_width = rows.iter().map(|(flags, _)| flags.len()).max().unwrap_or(0);
    let help_col = 2 + flag_width + 2;
    let help_width = MAX_WIDTH.saturating_sub(help_col).max(20);

    let mut out = format!("{}\n", paint(heading_style(), title));
    for (flags, help_lines) in rows {
        out.push_str("  ");
        out.push_str(&paint(bold_style(), flags));

        let mut placed = false;
        for help in help_lines {
            if help.is_empty() {
                continue;
            }
            for chunk in wrap_text(help, help_width) {
                if placed {
                    out.push_str(&" ".repeat(help_col));
                } else {
                    for _ in flags.len()..flag_width {
                        out.push(' ');
                    }
                    out.push_str("  ");
                    placed = true;
                }
                out.push_str(&chunk);
                out.push('\n');
            }
        }
        if !placed {
            out.push('\n');
        }
    }
    out
}

/// Level 1: the shared/global flags, re-emitted by hand since they are hidden
/// from clap's automatic rendering.
fn render_global_options(root: &Command) -> String {
    let mut rows: Vec<(String, Vec<String>)> = root
        .get_arguments()
        .filter(|arg| arg.is_global_set())
        .map(|arg| (option_flags(arg), option_help_lines(arg, false)))
        .collect();
    rows.push(("-h, --help".to_string(), vec!["Show help".to_string()]));
    rows.push((
        "-V, --version".to_string(),
        vec!["Show version".to_string()],
    ));
    format_option_block("Global options:", &rows)
}

// --- group body (Usage synopses + Commands) --------------------------------

/// Level 2: a multi-line `Usage:` block (one invocation form per subcommand,
/// with its own args) followed by a `Commands:` list of name + description.
fn render_group_body(cmd: &Command, path: &str) -> String {
    let children: Vec<&Command> = cmd
        .get_subcommands()
        .filter(|sub| sub.get_name() != "help")
        .collect();

    // Usage block: `concrete <path> <COMMAND>`, then a synopsis per subcommand
    // aligned under the first `concrete` (past the `Usage: ` heading).
    let usage_indent = "Usage: ".len();
    let mut out = format!(
        "{} {}\n",
        paint(heading_style(), "Usage:"),
        paint(about_style(), &format!("concrete {path} <COMMAND>"))
    );
    for sub in &children {
        let sub_path = format!("{path} {}", sub.get_name());
        for line in render_synopsis(sub, &sub_path, usage_indent) {
            out.push_str(&paint(about_style(), &line));
            out.push('\n');
        }
    }

    // Commands block: name + description only (invocation forms live above).
    out.push('\n');
    out.push_str(&paint(heading_style(), "Commands:"));
    out.push('\n');
    let name_width = children
        .iter()
        .map(|sub| sub.get_name().len())
        .max()
        .unwrap_or(0);
    for sub in &children {
        let name = sub.get_name();
        out.push_str("  ");
        out.push_str(&paint(bold_style(), name));
        for _ in name.len()..name_width {
            out.push(' ');
        }
        out.push_str("  ");
        out.push_str(&about_of(sub));
        out.push('\n');
    }
    out
}

/// Level 1: the titled top-level groups, one line per command.
fn render_groups(meta: &Command) -> String {
    let name_width = GROUPS
        .iter()
        .flat_map(|(_, names)| names.iter())
        .map(|name| name.len())
        .max()
        .unwrap_or(0);

    let mut out = String::new();
    for (index, (title, names)) in GROUPS.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        out.push_str(&paint(heading_style(), &format!("{title}:")));
        out.push('\n');
        for name in *names {
            let about = meta
                .get_subcommands()
                .find(|sub| sub.get_name() == *name)
                .map(about_of)
                .unwrap_or_else(|| default_about(name).to_string());
            out.push_str("  ");
            out.push_str(name);
            for _ in name.len()..name_width {
                out.push(' ');
            }
            out.push_str("  ");
            out.push_str(&paint(about_style(), &about));
            out.push('\n');
        }
    }
    out
}

// --- leaf body (examples + arguments + options) ----------------------------

fn example_lines(path: &str) -> Option<&'static [&'static str]> {
    EXAMPLES
        .iter()
        .find(|(key, _)| *key == path)
        .map(|(_, lines)| *lines)
}

fn render_examples(lines: &[&str]) -> String {
    let mut out = format!("{}\n", paint(heading_style(), "Examples:"));
    for line in lines {
        out.push_str("  ");
        out.push_str(&paint(about_style(), line));
        out.push('\n');
    }
    out
}

/// Level 3: the leaf body — an `Examples:` block, then `Arguments:` (own
/// positionals) and `Options:` (own options), each argument showing its short
/// description plus a `Default:` line and `[values: …]` where they apply.
/// Blocks are separated by a blank line; global flags are excluded (they are
/// hidden and documented once at the root).
fn render_leaf_body(cmd: &Command, path: &str) -> String {
    let mut blocks: Vec<String> = Vec::new();

    // An arg-less command's only example equals its usage line, so the Examples
    // block would be pure redundancy — the `Usage:` line already says it all.
    if has_own_args(cmd) {
        if let Some(lines) = example_lines(path) {
            blocks.push(render_examples(lines));
        }
    }

    let positionals: Vec<&Arg> = cmd
        .get_arguments()
        .filter(|arg| is_own(arg) && arg.is_positional())
        .collect();
    if !positionals.is_empty() {
        let rows: Vec<(String, Vec<String>)> = positionals
            .iter()
            .map(|arg| {
                let mut lines = option_help_lines(arg, true);
                // The shared CVM target's default is per-verb; annotate it here.
                if arg.get_id() == "cvm_id" {
                    if let Some(note) = cvm_target_note(path) {
                        lines.push(note.to_string());
                    }
                }
                (arg_token(arg), lines)
            })
            .collect();
        blocks.push(format_option_block("Arguments:", &rows));
    }

    // The `--cvm` flag duplicates the positional target; drop it when present.
    let hide_cvm = hides_cvm_flag(cmd);
    let mut options: Vec<Arg> = cmd
        .get_arguments()
        .filter(|arg| {
            is_own(arg) && !arg.is_positional() && !(hide_cvm && arg.get_long() == Some("cvm"))
        })
        .cloned()
        .collect();
    // Append the essential globals this command depends on (e.g. --profile), so
    // they are documented here and not only mentioned in the synopsis.
    options.extend(
        essential_globals(path)
            .iter()
            .filter_map(|long| find_global_arg(long)),
    );
    if !options.is_empty() {
        let rows: Vec<(String, Vec<String>)> = options
            .iter()
            .map(|arg| (option_flags(arg), option_help_lines(arg, true)))
            .collect();
        blocks.push(format_option_block("Options:", &rows));
    }

    blocks.join("\n")
}

// --- small helpers ---------------------------------------------------------

fn about_of(cmd: &Command) -> String {
    cmd.get_about()
        .map(|styled| first_line(&styled.to_string()))
        .unwrap_or_default()
}

fn default_about(name: &str) -> &'static str {
    match name {
        "help" => HELP_ABOUT,
        _ => "",
    }
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    /// Detects whether a rendered line is a command/option entry (its head starts
    /// at column 2), as opposed to a section title or a wrapped continuation.
    /// e.g.
    ///   "  status   Show status"   -> true
    ///   "Getting started:"         -> false   (section title, column 0)
    ///   "          Default: 600"   -> false   (wrapped continuation)
    fn helper_is_entry_row(line: &str) -> bool {
        line.starts_with("  ") && line.chars().nth(2).is_some_and(|c| c != ' ')
    }

    /// Reads `  <head>  <description>` rows and glues each wrapped continuation
    /// line back onto the description above it.
    /// e.g.
    ///   "  --profile <..>  Use a different profile."
    ///   "                  Repeat for many profiles."   (continuation)
    ///     -> ("--profile <..>", "Use a different profile. Repeat for many profiles.")
    fn helper_extract_entries(lines: &[&str]) -> Vec<(String, String)> {
        let mut entries: Vec<(String, String)> = Vec::new();
        for line in lines {
            if helper_is_entry_row(line) {
                let trimmed = line.trim_start();
                let (head, desc) = trimmed.split_once("  ").unwrap_or((trimmed, ""));
                entries.push((head.trim().to_string(), desc.trim().to_string()));
            } else if line.starts_with(' ') && !line.trim().is_empty() {
                if let Some((_, desc)) = entries.last_mut() {
                    if !desc.is_empty() {
                        desc.push(' ');
                    }
                    desc.push_str(line.trim());
                }
            }
        }
        entries
    }

    /// Pulls the long flag out of a rendered flag column.
    /// e.g.
    ///   "-v, --verbose..."  -> "--verbose"
    ///   "--config <CONFIG>" -> "--config"
    fn helper_long_flag(flags: &str) -> String {
        flags
            .split_whitespace()
            .find(|token| token.starts_with("--"))
            .map(|token| token.trim_end_matches('.').to_string())
            .unwrap_or_else(|| flags.to_string())
    }

    /// Panics unless the entries shown in the help are exactly the declared ones —
    /// same keys, and the same description for each key. Success tests call it and
    /// expect no panic; failure tests call it under `#[should_panic]`.
    /// e.g.
    ///   shown = {"ssh": "Open a session"}, declared = {"ssh": "Open a session"}   -> ok
    ///   shown = {"ssh": "Open a session"}, declared = {"ssh": .., "cvm": "Launch"} -> panics
    fn helper_assert_shown_matches_declared(
        shown: &BTreeMap<String, String>,
        declared: &BTreeMap<String, String>,
        what: &str,
    ) {
        let shown_keys: BTreeSet<&String> = shown.keys().collect();
        let declared_keys: BTreeSet<&String> = declared.keys().collect();
        assert_eq!(
            shown_keys, declared_keys,
            "{what}: what the help shows differs from what is declared"
        );
        for (key, description) in shown {
            assert_eq!(
                description, &declared[key],
                "{what}: `{key}` has the wrong description"
            );
        }
    }

    /// Renders the `--help` text of a command path below `concrete`.
    /// e.g.
    ///   helper_render_help(&[])                -> `concrete --help`
    ///   helper_render_help(&["cvm", "launch"]) -> `concrete cvm launch --help`
    fn helper_render_help(path: &[&str]) -> String {
        fn descend(cmd: &Command, path: &[&str]) -> Command {
            match path.split_first() {
                None => cmd.clone(),
                Some((name, rest)) => {
                    let child = cmd
                        .get_subcommands()
                        .find(|sub| sub.get_name() == *name)
                        .unwrap_or_else(|| panic!("subcommand `{name}` exists"));
                    descend(child, rest)
                }
            }
        }
        descend(&command(), path).render_help().to_string()
    }

    /// A command's one-line description (its `about`).
    /// e.g.
    ///   helper_description_of(<ssh command>) -> "Open an SSH session to the selected Dev CVM"
    fn helper_description_of(cmd: &Command) -> String {
        cmd.get_about()
            .map(|about| first_line(&about.to_string()))
            .unwrap_or_default()
    }

    /// A group's declared subcommands as `name -> description` (`help` excluded).
    /// e.g.
    ///   helper_declared_subcommands(<cvm command>)
    ///     -> {"list": "List Dev CVMs…", "launch": "Launch a Dev CVM", …}
    fn helper_declared_subcommands(group: &Command) -> BTreeMap<String, String> {
        group
            .get_subcommands()
            .filter(|sub| sub.get_name() != "help")
            .map(|sub| (sub.get_name().to_string(), helper_description_of(sub)))
            .collect()
    }

    /// Pins that `concrete --help` (level 1) lists exactly the declared commands
    /// and global flags — each with its declared description — so the rendered
    /// help can never drift from the command tree without this test failing.
    #[test]
    fn test_help_level_1_root_matches_declared_success() {
        // 1. Ground truth — what the code declares.
        // real-structure: the top-level commands and their `about` text
        // (`help` is clap's built-in, absent from the declared enum — exempt it).
        let real_structure: BTreeMap<String, String> = Cli::command()
            .get_subcommands()
            .filter(|sub| sub.get_name() != "help")
            .map(|sub| (sub.get_name().to_string(), helper_description_of(sub)))
            .collect();
        // general-options: the declared global flags and their help text.
        let general_options: BTreeMap<String, String> = Cli::command()
            .get_arguments()
            .filter(|arg| arg.is_global_set())
            .filter_map(|arg| {
                arg.get_long().map(|long| {
                    let description = arg
                        .get_help()
                        .map(|help| first_line(&help.to_string()))
                        .unwrap_or_default();
                    (format!("--{long}"), description)
                })
            })
            .collect();

        // 2. What `concrete --help` actually renders, parsed back out.
        // Root help = the grouped commands, then the `Global options:` block.
        let help_output = command().render_help().to_string();
        let lines: Vec<&str> = help_output.lines().collect();
        let split = lines
            .iter()
            .position(|line| line.starts_with("Global options:"))
            .expect("root help has a Global options block");
        let shown_options: BTreeMap<String, String> = helper_extract_entries(&lines[split + 1..])
            .into_iter()
            .map(|(flags, description)| (helper_long_flag(&flags), description))
            // clap's -h/--help and -V/--version are not declared globals.
            .filter(|(long, _)| long != "--help" && long != "--version")
            .collect();
        let shown_commands: BTreeMap<String, String> = helper_extract_entries(&lines[..split])
            .into_iter()
            .filter(|(name, _)| name != "help")
            .collect();

        // 3. What the help shows must equal what the code declares.
        helper_assert_shown_matches_declared(&shown_options, &general_options, "global options");
        helper_assert_shown_matches_declared(&shown_commands, &real_structure, "commands");
    }

    /// Counterpart of the success test: if the rendered help drops a line (we
    /// remove one command it showed), the comparison must panic.
    #[test]
    #[should_panic(expected = "differs from what is declared")]
    fn test_help_level_1_root_matches_declared_failure() {
        // 1. Ground truth.
        let real_structure: BTreeMap<String, String> = Cli::command()
            .get_subcommands()
            .filter(|sub| sub.get_name() != "help")
            .map(|sub| (sub.get_name().to_string(), helper_description_of(sub)))
            .collect();

        // 2. Render + parse, then simulate the help losing a line.
        let help_output = command().render_help().to_string();
        let lines: Vec<&str> = help_output.lines().collect();
        let split = lines
            .iter()
            .position(|line| line.starts_with("Global options:"))
            .expect("root help has a Global options block");
        let mut shown_commands: BTreeMap<String, String> = helper_extract_entries(&lines[..split])
            .into_iter()
            .filter(|(name, _)| name != "help")
            .collect();
        let dropped = shown_commands
            .keys()
            .next()
            .cloned()
            .expect("help shows at least one command");
        shown_commands.remove(&dropped);

        // 3. The dropped command must make the comparison panic.
        helper_assert_shown_matches_declared(&shown_commands, &real_structure, "commands");
    }

    /// Pins that every group command's `--help` (level 2) has a `Usage:` and a
    /// `Commands:` section, and lists exactly that command's declared subcommands
    /// with their descriptions.
    #[test]
    fn test_help_level_2_groups_match_declared_success() {
        // 1. Ground truth — each declared group and its subcommands (name → about).
        let groups: Vec<(String, BTreeMap<String, String>)> = Cli::command()
            .get_subcommands()
            .filter(|cmd| cmd.get_subcommands().next().is_some())
            .map(|group| {
                (
                    group.get_name().to_string(),
                    helper_declared_subcommands(group),
                )
            })
            .collect();

        for (name, declared) in &groups {
            // 2. Render `concrete <group> --help` and parse its Commands block.
            let help = helper_render_help(&[name.as_str()]);
            let lines: Vec<&str> = help.lines().collect();
            let commands_start = lines
                .iter()
                .position(|line| line.starts_with("Commands:"))
                .unwrap_or_else(|| panic!("`{name} --help` is missing a Commands section"));
            let shown: BTreeMap<String, String> =
                helper_extract_entries(&lines[commands_start + 1..])
                    .into_iter()
                    .filter(|(sub, _)| sub != "help")
                    .collect();

            // 3. It must have a Usage section, and its commands == the declared ones.
            assert!(
                lines.iter().any(|line| line.starts_with("Usage:")),
                "`{name} --help` is missing a Usage section"
            );
            helper_assert_shown_matches_declared(
                &shown,
                declared,
                &format!("`{name}` subcommands"),
            );
        }
    }

    /// Counterpart: if a group's `--help` drops a subcommand it declared, the
    /// comparison must panic.
    #[test]
    #[should_panic(expected = "differs from what is declared")]
    fn test_help_level_2_groups_match_declared_failure() {
        // 1. Ground truth: cvm's declared subcommands.
        let cvm = Cli::command()
            .get_subcommands()
            .find(|cmd| cmd.get_name() == "cvm")
            .expect("cvm command declared")
            .clone();
        let declared = helper_declared_subcommands(&cvm);

        // 2. Render `cvm --help`, parse Commands, then drop one subcommand.
        let help = helper_render_help(&["cvm"]);
        let lines: Vec<&str> = help.lines().collect();
        let commands_start = lines
            .iter()
            .position(|line| line.starts_with("Commands:"))
            .expect("cvm help has a Commands section");
        let mut shown: BTreeMap<String, String> =
            helper_extract_entries(&lines[commands_start + 1..])
                .into_iter()
                .filter(|(sub, _)| sub != "help")
                .collect();
        let dropped = shown
            .keys()
            .next()
            .cloned()
            .expect("cvm shows at least one subcommand");
        shown.remove(&dropped);

        // 3. The dropped subcommand must make the comparison panic.
        helper_assert_shown_matches_declared(&shown, &declared, "cvm subcommands");
    }

    /// Pins that every group's arg-bearing leaf subcommand has, at level 3, a
    /// `Usage:` and an `Examples:` section. Arg-less leaves are skipped (they
    /// deliberately show Usage only); options aren't checked since some leaves
    /// have none.
    #[test]
    fn test_help_level_3_leaves_have_usage_and_examples_success() {
        let mut checked = 0;
        // For each group, for each of its leaf subcommands that take arguments…
        for group in Cli::command()
            .get_subcommands()
            .filter(|cmd| cmd.get_subcommands().next().is_some())
        {
            let group_name = group.get_name().to_string();
            for sub in group.get_subcommands() {
                let sub_name = sub.get_name();
                // …skip `help`, sub-groups, and arg-less leaves (Usage-only, no Examples).
                if sub_name == "help"
                    || sub.get_subcommands().next().is_some()
                    || !has_own_args(sub)
                {
                    continue;
                }
                // Render `concrete <group> <sub> --help`; it must show Usage + Examples.
                let help = helper_render_help(&[group_name.as_str(), sub_name]);
                assert!(
                    help.lines().any(|line| line.starts_with("Usage:")),
                    "`{group_name} {sub_name} --help` is missing a Usage section"
                );
                assert!(
                    help.lines().any(|line| line.starts_with("Examples:")),
                    "`{group_name} {sub_name} --help` is missing an Examples section"
                );
                checked += 1;
            }
        }
        assert!(checked > 0, "no arg-bearing leaf subcommand was checked");
    }

    /// Counterpart: an arg-less leaf (`security-cvm show`) shows Usage only, so
    /// asserting it has an Examples section must panic — proving the check is real.
    #[test]
    #[should_panic(expected = "missing an Examples section")]
    fn test_help_level_3_leaves_have_usage_and_examples_failure() {
        let help = helper_render_help(&["security-cvm", "show"]);
        assert!(
            help.lines().any(|line| line.starts_with("Examples:")),
            "`security-cvm show --help` is missing an Examples section"
        );
    }
}
