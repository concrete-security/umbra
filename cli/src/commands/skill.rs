use std::{
    fs, io,
    path::{Path, PathBuf},
};

use serde_json::json;

use crate::{
    cli::{SkillCommand, SkillInstallArgs},
    config::ResolvedConfig,
    exit::ExitStatus,
    style,
};

/// The user-facing skill shipped to AI coding agents, embedded at build time.
/// This file is generated from `skills/concrete-cli/SKILL.md` by
/// `ops/cli-release/render-skill.py` (run via `make skill`); edit that crib, not
/// the packaged asset. Keeping the asset inside `cli/` makes `cargo package`
/// self-contained.
const SKILL_BODY: &str = include_str!("../../assets/concrete-cli/SKILL.md");

/// Folder name the skill is installed under in every agent's skills directory.
const SKILL_NAME: &str = "concrete-cli";

/// A coding agent we know how to install the skill for. `detect_home` is a
/// directory under `$HOME` whose presence means the agent is installed;
/// `skill_parents` are the directories under `$HOME` that the agent scans for
/// skill folders (we drop a `concrete-cli` link into each).
struct Agent {
    key: &'static str,
    name: &'static str,
    detect_home: &'static str,
    skill_parents: &'static [&'static str],
}

const AGENTS: &[Agent] = &[
    Agent {
        key: "claude",
        name: "Claude Code",
        detect_home: ".claude",
        skill_parents: &[".claude/skills"],
    },
    Agent {
        // Codex's documented user-level skills path is ~/.agents/skills, but
        // released builds have also read ~/.codex/skills. Link both so the
        // skill resolves regardless of the installed Codex version.
        key: "codex",
        name: "Codex",
        detect_home: ".codex",
        skill_parents: &[".codex/skills", ".agents/skills"],
    },
];

struct AgentResult {
    name: &'static str,
    key: &'static str,
    detected: bool,
    status: &'static str,
    paths: Vec<String>,
}

enum Outcome {
    Linked,
    AlreadyLinked,
    SkippedExists,
}

pub fn run(command: SkillCommand, config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    match command {
        SkillCommand::Install(args) => install(args, config, json_output),
    }
}

struct Performed {
    canonical: PathBuf,
    home: PathBuf,
    results: Vec<AgentResult>,
    explicit: bool,
}

fn install(args: SkillInstallArgs, config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let performed = match perform(args.agents.as_deref(), config) {
        Ok(performed) => performed,
        Err(status) => return status,
    };
    if json_output {
        print_json(&performed.canonical, &performed.home, &performed.results);
    } else {
        print_text(
            &performed.canonical,
            &performed.home,
            &performed.results,
            performed.explicit,
        );
    }
    ExitStatus::Ok
}

/// Refresh the canonical skill and (re)link it into every detected agent.
/// Called from `auth login` once the user has opted in; best-effort, so a
/// failure never blocks login. When `quiet`, prints nothing on success.
pub fn install_on_login(config: &ResolvedConfig, quiet: bool) {
    let Ok(performed) = perform(None, config) else {
        return;
    };
    if quiet {
        return;
    }
    let linked: Vec<&str> = performed
        .results
        .iter()
        .filter(|result| !result.paths.is_empty())
        .map(|result| result.name)
        .collect();
    if !linked.is_empty() {
        eprintln!(
            "{}",
            style::info_line(&format!(
                "installed concrete-cli skill for {} - restart your agent session to load it",
                linked.join(", ")
            ))
        );
    }
}

/// Display names of agents detected on this machine (their home dir exists).
pub fn detected_agents() -> Vec<&'static str> {
    let Some(home) = dirs::home_dir() else {
        return Vec::new();
    };
    AGENTS
        .iter()
        .filter(|agent| home.join(agent.detect_home).is_dir())
        .map(|agent| agent.name)
        .collect()
}

/// Write the canonical skill and link it into the selected agents. Errors are
/// reported to stderr; the returned `ExitStatus` distinguishes usage from
/// runtime failures for the command path.
fn perform(agents: Option<&str>, config: &ResolvedConfig) -> Result<Performed, ExitStatus> {
    let Some(home) = dirs::home_dir() else {
        style::eprintln_error("[error] could not resolve home directory");
        return Err(ExitStatus::Error);
    };

    let explicit = agents.is_some();
    let selected = match select_agents(agents) {
        Ok(selected) => selected,
        Err(msg) => {
            style::eprintln_error(&msg);
            return Err(ExitStatus::Usage);
        }
    };

    // 1. Materialize the canonical copy under the config dir (source of truth).
    //    Refreshed from the embedded skill, so a CLI upgrade updates it.
    let canonical = config.config_dir.join("skills").join(SKILL_NAME);
    if let Err(err) = write_canonical(&canonical) {
        style::eprintln_error(&err);
        return Err(ExitStatus::Error);
    }

    // 2. Link the canonical dir into each agent's skills directory. Because the
    //    agent entries are symlinks back to the canonical dir, refreshing the
    //    canonical copy propagates to every agent with no re-link.
    let mut results = Vec::new();
    for agent in selected {
        let detected = home.join(agent.detect_home).is_dir();
        if !detected && !explicit {
            results.push(AgentResult {
                name: agent.name,
                key: agent.key,
                detected,
                status: "not detected",
                paths: Vec::new(),
            });
            continue;
        }
        let mut paths = Vec::new();
        let mut status = "linked";
        for parent in agent.skill_parents {
            let link = home.join(parent).join(SKILL_NAME);
            match materialize(&canonical, &link, config.force) {
                Ok(Outcome::Linked | Outcome::AlreadyLinked) => {
                    paths.push(display_home(&link, &home))
                }
                Ok(Outcome::SkippedExists) => status = "skipped (exists)",
                Err(err) => {
                    style::eprintln_error(&format!(
                        "[error] failed to install skill at {}: {err}",
                        link.display()
                    ));
                    return Err(ExitStatus::Error);
                }
            }
        }
        results.push(AgentResult {
            name: agent.name,
            key: agent.key,
            detected,
            status,
            paths,
        });
    }

    Ok(Performed {
        canonical,
        home,
        results,
        explicit,
    })
}

fn select_agents(spec: Option<&str>) -> Result<Vec<&'static Agent>, String> {
    let Some(spec) = spec else {
        return Ok(AGENTS.iter().collect());
    };
    let keys: Vec<&str> = spec
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .collect();
    if keys.is_empty() {
        return Err("[usage] --agents requires at least one agent key".to_string());
    }
    let mut selected = Vec::new();
    for key in keys {
        match AGENTS.iter().find(|agent| agent.key == key) {
            Some(agent) => selected.push(agent),
            None => {
                return Err(format!(
                    "[usage] unknown agent '{key}'; known agents: {}",
                    AGENTS
                        .iter()
                        .map(|agent| agent.key)
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            }
        }
    }
    Ok(selected)
}

/// Write the embedded skill into the canonical directory, skipping the write
/// when the on-disk copy already matches (avoids touching mtime needlessly).
fn write_canonical(dir: &Path) -> Result<(), String> {
    fs::create_dir_all(dir).map_err(|err| {
        format!(
            "[error] failed to create skill directory {}: {err}",
            dir.display()
        )
    })?;
    let target = dir.join("SKILL.md");
    if fs::read_to_string(&target)
        .map(|current| current == SKILL_BODY)
        .unwrap_or(false)
    {
        return Ok(());
    }
    let tmp = dir.join(format!(".SKILL.{}.tmp", std::process::id()));
    fs::write(&tmp, SKILL_BODY)
        .map_err(|err| format!("[error] failed to write skill file: {err}"))?;
    fs::rename(&tmp, &target)
        .map_err(|err| format!("[error] failed to install skill file: {err}"))?;
    Ok(())
}

/// Point `link` at the canonical skill dir. Idempotent: an existing link to the
/// canonical dir is left as-is; a stale link is repointed; a real directory or
/// file is preserved unless `force` is set.
fn materialize(canonical: &Path, link: &Path, force: bool) -> io::Result<Outcome> {
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::symlink_metadata(link) {
        Ok(meta) if meta.file_type().is_symlink() => {
            if fs::read_link(link).ok().as_deref() == Some(canonical) {
                Ok(Outcome::AlreadyLinked)
            } else {
                fs::remove_file(link)?;
                symlink_dir(canonical, link)?;
                Ok(Outcome::Linked)
            }
        }
        Ok(meta) => {
            if force {
                if meta.is_dir() {
                    fs::remove_dir_all(link)?;
                } else {
                    fs::remove_file(link)?;
                }
                symlink_dir(canonical, link)?;
                Ok(Outcome::Linked)
            } else {
                Ok(Outcome::SkippedExists)
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            symlink_dir(canonical, link)?;
            Ok(Outcome::Linked)
        }
        Err(err) => Err(err),
    }
}

#[cfg(unix)]
fn symlink_dir(target: &Path, link: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn symlink_dir(_target: &Path, link: &Path) -> io::Result<()> {
    // No symlink guarantee off unix: drop a standalone copy that `skill
    // install` refreshes on the next run.
    fs::create_dir_all(link)?;
    fs::write(link.join("SKILL.md"), SKILL_BODY)
}

fn display_home(path: &Path, home: &Path) -> String {
    match path.strip_prefix(home) {
        Ok(rest) => format!("~/{}", rest.display()),
        Err(_) => path.display().to_string(),
    }
}

fn print_text(canonical: &Path, home: &Path, results: &[AgentResult], explicit: bool) {
    let mut confirm = style::ConfirmBlock::new("installed", "skill", SKILL_NAME)
        .field("canonical", display_home(canonical, home));
    let mut linked_any = false;
    let mut not_detected: Vec<&str> = Vec::new();
    for result in results {
        match result.status {
            "not detected" => not_detected.push(result.key),
            "skipped (exists)" => {
                confirm = confirm.field(
                    result.name,
                    "skipped (folder exists; pass --force to replace)",
                );
            }
            _ => {
                linked_any = true;
                confirm = confirm.field(result.name, result.paths.join(", "));
            }
        }
    }
    println!("{}", style::render_confirm(&confirm));

    if linked_any {
        eprintln!(
            "{}",
            style::info_line("restart your agent session to load the skill")
        );
    }
    if !not_detected.is_empty() && !explicit {
        eprintln!(
            "{}",
            style::info_line(&format!(
                "no agent detected for: {}. Re-run with --agents {} to install anyway.",
                not_detected.join(", "),
                not_detected.join(",")
            ))
        );
    }
}

fn print_json(canonical: &Path, home: &Path, results: &[AgentResult]) {
    let agents: Vec<_> = results
        .iter()
        .map(|result| {
            json!({
                "name": result.name,
                "key": result.key,
                "detected": result.detected,
                "status": result.status,
                "paths": result.paths,
            })
        })
        .collect();
    let payload = json!({
        "skill": SKILL_NAME,
        "canonical": display_home(canonical, home),
        "agents": agents,
    });
    style::emit_json(&payload);
}
