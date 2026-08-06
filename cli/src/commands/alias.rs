//! Client-side aliases: short, human names for the long identifiers the CLI
//! otherwise demands. Four kinds live together in one `~/.umbra/aliases.toml`:
//! `cvm`/`profile`/`ssh-key` map an alias to a Console resource UUID, while
//! `session` maps an alias to a dtach session bound to a specific CVM.
//!
//! Resolution is a single funnel: [`Aliases::resolve_alias`] (UUID kinds) and
//! [`Aliases::resolve_session`] translate an alias to its target, and pass an
//! unknown value through unchanged so a raw UUID or session name still works.

use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::{
    fs::{OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    cli::{
        AliasCommand, AliasNameArgs, AliasPruneArgs, AliasRenameArgs, AliasResourceArgs,
        AliasSessionArgs,
    },
    commands::{cvm, key, profile, select_cvm, ssh},
    config::ResolvedConfig,
    console::{console_session, validate_uuid},
    exit::ExitStatus,
    style,
};

/// Which resource an alias points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AliasKind {
    Cvm,
    Profile,
    SshKey,
    Session,
}

impl AliasKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            AliasKind::Cvm => "cvm",
            AliasKind::Profile => "profile",
            AliasKind::SshKey => "ssh-key",
            AliasKind::Session => "session",
        }
    }
}

/// A session alias carries the CVM it lives on, so `umbra attach <alias>`
/// resolves to both the session name and its box without an explicit `--cvm`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SessionAlias {
    pub(crate) session: String,
    pub(crate) cvm: String,
}

/// What an auto-prune removes from the store — one variant per CLI lifecycle
/// action that leaves an alias stale. Passed to [`Aliases::prune`]. (The
/// reference reconciliation behind `alias prune` is separate — see `fn prune`.)
pub(crate) enum Prune<'a> {
    /// `cvm terminate`: the CVM's own alias **and** every session bound to it.
    Cvm(&'a str),
    /// `cvm stop`: the CVM's sessions only. Its alias survives (it can be
    /// restarted), but the sessions die with the box (tmpfs `/run`).
    CvmSessions(&'a str),
    /// `key remove`, or a stale `profile`/`ssh-key`: one resource alias by id.
    Resource(AliasKind, &'a str),
    /// `kill`: the single `(session, cvm)` pair that was torn down.
    Session { session: &'a str, cvm: &'a str },
}

/// What an alias points at, whichever kind it is. Two uses, both needing the whole
/// mapping rather than a bare name: the one-alias-per-resource step of
/// [`Aliases::validate_alias`], and the exact mapping a deferred cleanup observed so
/// it drops that alias only if it still points there
/// ([`Aliases::remove_if_matches`]). Owns its values (it outlives the network/SSH
/// phase that produced it).
pub(crate) enum AliasTarget {
    /// A `cvm`/`profile`/`ssh-key` alias pointing at this UUID.
    Resource(AliasKind, String),
    /// A `session` alias pointing at this `{ session, cvm }`.
    Session(SessionAlias),
}

/// The whole alias store: one flat table per kind, keyed by the alias name.
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Aliases {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) cvm: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) profile: BTreeMap<String, String>,
    #[serde(
        default,
        rename = "ssh-key",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub(crate) ssh_key: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) session: BTreeMap<String, SessionAlias>,
}

impl Aliases {
    /// The UUID-backed table for `kind` (`None` for `Session`, which stores a
    /// value-object rather than a bare id).
    fn resource_table(&self, kind: AliasKind) -> Option<&BTreeMap<String, String>> {
        match kind {
            AliasKind::Cvm => Some(&self.cvm),
            AliasKind::Profile => Some(&self.profile),
            AliasKind::SshKey => Some(&self.ssh_key),
            AliasKind::Session => None,
        }
    }

    /// Mutable counterpart of [`resource_table`](Self::resource_table).
    pub(crate) fn resource_table_mut(
        &mut self,
        kind: AliasKind,
    ) -> Option<&mut BTreeMap<String, String>> {
        match kind {
            AliasKind::Cvm => Some(&mut self.cvm),
            AliasKind::Profile => Some(&mut self.profile),
            AliasKind::SshKey => Some(&mut self.ssh_key),
            AliasKind::Session => None,
        }
    }

    /// Insert (or replace) a UUID-backed alias `name -> target` for `kind`. The
    /// single in-memory store mutation for cvm/profile/ssh-key, so the scattered
    /// `resource_table_mut(kind).expect(...)` lives in one place. Panics on
    /// `Session` (it stores a value-object, not a bare id — use
    /// [`insert_session`](Self::insert_session)).
    pub(crate) fn insert_resource(&mut self, kind: AliasKind, name: String, target: String) {
        self.resource_table_mut(kind)
            .expect("uuid-backed kind has a table")
            .insert(name, canonical_id(&target));
    }

    /// Insert (or replace) a session alias `name -> {session, cvm}`. The single
    /// in-memory mutation for the session kind.
    pub(crate) fn insert_session(&mut self, name: String, session: String, cvm: String) {
        let cvm = canonical_id(&cvm);
        self.session.insert(name, SessionAlias { session, cvm });
    }

    /// Translate an alias for a UUID-backed resource (cvm/profile/ssh-key) to
    /// its real id, or return `value` unchanged when it is not a known alias so
    /// a raw UUID passes straight through. Sessions use
    /// [`resolve_session`](Self::resolve_session).
    pub(crate) fn resolve_alias(&self, kind: AliasKind, value: &str) -> String {
        self.resource_table(kind)
            .and_then(|table| table.get(value))
            .cloned()
            .unwrap_or_else(|| value.to_string())
    }

    /// The `{ session, cvm }` an alias points at, if `alias` is a known session
    /// alias. A non-alias (raw session name) returns `None` and is used as-is.
    pub(crate) fn resolve_session(&self, alias: &str) -> Option<&SessionAlias> {
        self.session.get(alias)
    }

    /// The alias recorded for a resource id, if any — the reverse of
    /// [`resolve_alias`](Self::resolve_alias). Lets the read views label a Console
    /// record with the local name the user actually types (`cvm`/`profile`/`key
    /// list`, `profile show`). `None` for `Session`, whose targets are session
    /// names rather than ids.
    pub(crate) fn alias_of(&self, kind: AliasKind, id: &str) -> Option<&str> {
        let id = canonical_id(id);
        self.resource_table(kind)?
            .iter()
            .find(|(_, target)| *target == &id)
            .map(|(name, _)| name.as_str())
    }

    /// The display name for a CVM uuid: its recorded alias if one exists, else
    /// the uuid unchanged. Lets a session's bound CVM show readably (in
    /// `alias list` and the `--cvm` override warning).
    pub(crate) fn cvm_display<'a>(&'a self, uuid: &'a str) -> &'a str {
        self.alias_of(AliasKind::Cvm, uuid).unwrap_or(uuid)
    }

    /// Decide whether `name` may be recorded as an alias — the single gate every
    /// write path goes through, in three steps:
    ///
    /// 1. the name is well-formed: non-empty, at most 128 bytes, ASCII
    ///    letters/digits/`.`/`_`/`-`, and never a UUID (which would be
    ///    indistinguishable from a raw id and could never resolve, see
    ///    [`resolve_or_passthrough`]) — a usage error;
    /// 2. the name is free across ALL kinds: names are globally unique, so
    ///    `rm`/`rename` need only the name, no kind;
    /// 3. `target`, when given, has no alias yet: a resource carries at most ONE
    ///    alias, else the reverse display of the read views has to pick one of
    ///    several names arbitrarily. Repointing a name is what `rename` is for —
    ///    which is why `rename` passes `None`: it moves an alias whose target is
    ///    legitimately aliased already, by the very alias being moved. The
    ///    `--alias`-at-creation paths also pass `None` up front, their resource not
    ///    existing yet, and the real target once it does.
    ///
    /// Carries the [`ExitStatus`] alongside the message, so a caller needs not know
    /// which step failed. The live-session shadow check is deliberately NOT here: it
    /// is an SSH probe, which must not run under the store lock (`docs/specs/cli.md`
    /// §4.4) and whose failure is fatal at creation but only a warning at `rename`.
    pub(crate) fn validate_alias(
        &self,
        name: &str,
        target: Option<&AliasTarget>,
    ) -> Result<(), (ExitStatus, String)> {
        let usage = |message: &str| Err((ExitStatus::Usage, message.to_string()));
        if name.is_empty() {
            return usage("[usage] alias must not be empty");
        }
        if name.len() > 128 {
            return usage("[usage] alias must be at most 128 bytes");
        }
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return usage(
                "[usage] alias may only contain ASCII letters, digits, '.', '_', and '-'",
            );
        }
        if uuid::Uuid::parse_str(name).is_ok() {
            return usage(
                "[usage] alias must not be a UUID (it would be indistinguishable from a raw id)",
            );
        }
        if self.kind_of(name).is_some() {
            return Err((
                ExitStatus::Error,
                format!(
                    "[error] alias {name} is already taken; run `umbra alias list` and pick another"
                ),
            ));
        }
        let (what, aliased) = match target {
            None => return Ok(()),
            Some(AliasTarget::Resource(kind, id)) => {
                debug_assert!(
                    !matches!(kind, AliasKind::Session),
                    "a session target is AliasTarget::Session; Resource(Session, _) has no table to look in and would skip this step"
                );
                (format!("{} {id}", kind.as_str()), self.alias_of(*kind, id))
            }
            Some(AliasTarget::Session(target)) => {
                // Canonical on both sides, as `alias_of` does for the uuid kinds: the
                // pair is the identity, and its CVM half may arrive as typed.
                let cvm = canonical_id(&target.cvm);
                (
                    format!("session {} on {}", target.session, target.cvm),
                    self.session
                        .iter()
                        .find(|(_, entry)| entry.session == target.session && entry.cvm == cvm)
                        .map(|(alias, _)| alias.as_str()),
                )
            }
        };
        match aliased {
            Some(existing) => Err((
                ExitStatus::Error,
                format!(
                    "[error] {what} already has alias {existing}; rename it with \
                     `umbra alias rename {existing} {name}`"
                ),
            )),
            None => Ok(()),
        }
    }

    /// Remove an alias by name from whichever kind holds it (names are unique,
    /// so at most one does). Returns whether one was removed.
    pub(crate) fn remove_alias(&mut self, name: &str) -> bool {
        self.cvm.remove(name).is_some()
            || self.profile.remove(name).is_some()
            || self.ssh_key.remove(name).is_some()
            || self.session.remove(name).is_some()
    }

    /// Remove `name` ONLY if it still maps to `observed`. For the deferred cleanups
    /// that decide after a network/SSH phase (`alias prune`, launch rollback): the
    /// delete runs later, under the store lock, so a concurrent process could have
    /// rm'd `name` and recreated it pointing at a live target in between — a blind
    /// `remove_alias` would drop that fresh mapping. Matching the observed target
    /// leaves a recreated alias untouched. Returns whether it removed.
    pub(crate) fn remove_if_matches(&mut self, name: &str, observed: &AliasTarget) -> bool {
        match observed {
            AliasTarget::Resource(kind, id) => match self.resource_table_mut(*kind) {
                Some(table) if table.get(name) == Some(&canonical_id(id)) => {
                    table.remove(name);
                    true
                }
                _ => false,
            },
            AliasTarget::Session(expected) => {
                let expected = &SessionAlias {
                    session: expected.session.clone(),
                    cvm: canonical_id(&expected.cvm),
                };
                if self.session.get(name) == Some(expected) {
                    self.session.remove(name);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Remove the aliases named by `what`, returning whether anything went away
    /// (so callers can skip a needless write, and never create an empty store
    /// for a user with no aliases). The single entry point for every auto-prune
    /// a CLI lifecycle action triggers — see [`Prune`] for the cases.
    pub(crate) fn prune(&mut self, what: Prune) -> bool {
        match what {
            Prune::Cvm(id) => {
                let id = &canonical_id(id);
                let before = self.cvm.len();
                self.cvm.retain(|_, target| target != id);
                let cvm_removed = self.cvm.len() != before;
                // A terminated CVM takes its sessions with it.
                self.prune(Prune::CvmSessions(id)) || cvm_removed
            }
            Prune::CvmSessions(cvm) => {
                let cvm = &canonical_id(cvm);
                let before = self.session.len();
                self.session.retain(|_, entry| &entry.cvm != cvm);
                self.session.len() != before
            }
            Prune::Resource(kind, id) => {
                debug_assert!(
                    matches!(kind, AliasKind::Profile | AliasKind::SshKey),
                    "Prune::Resource is for profile/ssh-key; use Prune::Cvm for a CVM (it cascades to sessions)"
                );
                let id = &canonical_id(id);
                match self.resource_table_mut(kind) {
                    Some(table) => {
                        let before = table.len();
                        table.retain(|_, target| target != id);
                        table.len() != before
                    }
                    None => false, // `Session` has no id-keyed resource table.
                }
            }
            Prune::Session { session, cvm } => {
                let cvm = &canonical_id(cvm);
                let before = self.session.len();
                self.session
                    .retain(|_, entry| !(entry.session == session && &entry.cvm == cvm));
                self.session.len() != before
            }
        }
    }

    /// The `session_name -> alias` map for one CVM, for `umbra ps` to show
    /// the alias beside each live session.
    pub(crate) fn session_names_on(&self, cvm_id: &str) -> BTreeMap<String, String> {
        let mut by_session = BTreeMap::new();
        let cvm_id = canonical_id(cvm_id);
        for (alias, entry) in &self.session {
            if entry.cvm == cvm_id {
                by_session
                    .entry(entry.session.clone())
                    .or_insert_with(|| alias.clone());
            }
        }
        by_session
    }

    /// Which kind holds `name`, if any (names are globally unique). Lets `rm`
    /// and `update` act on a bare alias name.
    pub(crate) fn kind_of(&self, name: &str) -> Option<AliasKind> {
        if self.cvm.contains_key(name) {
            Some(AliasKind::Cvm)
        } else if self.profile.contains_key(name) {
            Some(AliasKind::Profile)
        } else if self.ssh_key.contains_key(name) {
            Some(AliasKind::SshKey)
        } else if self.session.contains_key(name) {
            Some(AliasKind::Session)
        } else {
            None
        }
    }
}

/// Path of the alias store inside the config directory.
fn store_path(config_dir: &Path) -> PathBuf {
    config_dir.join("aliases.toml")
}

/// Section keys of the current schema. Their presence marks a current-format
/// file; a non-empty file without any of them is the pre-alias-kinds layout.
const SECTIONS: [&str; 4] = ["cvm", "profile", "ssh-key", "session"];

/// Load the alias store, migrating the legacy layout on the fly. A missing file
/// is an empty store.
pub(crate) fn load(config_dir: &Path) -> Result<Aliases, String> {
    let data = match fs::read_to_string(store_path(config_dir)) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Aliases::default()),
        Err(err) => return Err(format!("[error] failed to read aliases file: {err}")),
    };
    let table: toml::Table =
        toml::from_str(&data).map_err(|err| format!("[error] malformed aliases file: {err}"))?;
    let store = if table.is_empty() || SECTIONS.iter().any(|section| table.contains_key(*section)) {
        toml::from_str::<Aliases>(&data)
            .map_err(|err| format!("[error] malformed aliases file: {err}"))?
    } else {
        migrate_legacy(&table)
    };
    // BOTH layouts are normalized: the legacy one carries its CVM as a TOML section
    // key, which is just as free to be non-canonical as a hand-written target.
    Ok(canonicalize_targets(store))
}

/// The canonical hyphenated lowercase form of a UUID, so an id compares equal
/// however it was written — `validate_uuid` accepts what `Uuid::parse_str` accepts:
/// uppercase, braced, `urn:uuid:`, unhyphenated. A value that is not a UUID is
/// returned unchanged (a session target is a session name, and a malformed id must
/// still be reported by the command that uses it, not silently rewritten here).
///
/// Every id entering the store goes through this, and so does every id compared
/// against it — otherwise an alias recorded as `9A7F…` matches no Console id (the
/// reverse lookup renders `-`, "no alias", and `prune` judges the target absent and
/// deletes the alias), and the one-alias-per-resource step of
/// [`Aliases::validate_alias`] misses the alias a resource already has, which is the
/// whole invariant.
pub(crate) fn canonical_id(value: &str) -> String {
    match uuid::Uuid::parse_str(value) {
        Ok(uuid) => uuid.hyphenated().to_string(),
        Err(_) => value.to_string(),
    }
}

/// Apply [`canonical_id`] to every UUID the store holds: the `cvm`/`profile`/
/// `ssh-key` targets, and the `cvm` a session is bound to. Runs on load, the single
/// funnel every consumer goes through, so a hand-edited or legacy file is normalized
/// as well as what the write paths record.
fn canonicalize_targets(mut aliases: Aliases) -> Aliases {
    for kind in [AliasKind::Cvm, AliasKind::Profile, AliasKind::SshKey] {
        if let Some(table) = aliases.resource_table_mut(kind) {
            for target in table.values_mut() {
                *target = canonical_id(target);
            }
        }
    }
    for entry in aliases.session.values_mut() {
        entry.cvm = canonical_id(&entry.cvm);
    }
    aliases
}

/// Fold the pre-alias-kinds layout — top-level `[<cvm_id>]` tables of
/// `alias = session_name` — into the current `session` table. A name reused
/// across CVMs (which the old per-CVM scoping allowed) keeps the last one, as
/// alias names are now globally unique.
fn migrate_legacy(table: &toml::Table) -> Aliases {
    let mut aliases = Aliases::default();
    for (cvm_id, entries) in table {
        let Some(entries) = entries.as_table() else {
            continue;
        };
        for (alias, session) in entries {
            if let Some(session) = session.as_str() {
                aliases.insert_session(alias.clone(), session.to_string(), cvm_id.clone());
            }
        }
    }
    aliases
}

/// Persist the alias store with the same fail-closed atomic write the CLI uses
/// for other local state: 0700 dir, 0600 temp with `O_NOFOLLOW`, then rename.
pub(crate) fn save(config_dir: &Path, aliases: &Aliases) -> Result<(), String> {
    fs::create_dir_all(config_dir)
        .map_err(|err| format!("[error] failed to create config directory: {err}"))?;
    #[cfg(unix)]
    fs::set_permissions(config_dir, fs::Permissions::from_mode(0o700))
        .map_err(|err| format!("[error] failed to tighten config directory permissions: {err}"))?;

    let data = toml::to_string_pretty(aliases)
        .map_err(|err| format!("[error] failed to serialize aliases file: {err}"))?;
    crate::fsutil::write_atomic_file(&store_path(config_dir), data.as_bytes(), 0o600)
        .map_err(|err| format!("[error] failed to write aliases file: {err}"))?;
    Ok(())
}

/// An exclusive advisory lock over the alias store, held for the duration of a
/// read-modify-write so concurrent `umbra` processes can't interleave their
/// load→mutate→save and clobber each other (last-writer-wins). Taken on a
/// dedicated `aliases.lock` — never on `aliases.toml`, whose inode is replaced by
/// [`save`]'s atomic rename, which would drop the lock. `flock` is released when
/// the guard drops. On non-unix it is a no-op (best-effort), as with the store's
/// permission tightening.
struct StoreLock {
    #[cfg(unix)]
    file: fs::File,
}

impl StoreLock {
    /// Block until this process holds the store lock. Creates the config dir and
    /// the lock file (owner-only) if absent.
    fn acquire(config_dir: &Path) -> Result<Self, String> {
        fs::create_dir_all(config_dir)
            .map_err(|err| format!("[error] failed to create config directory: {err}"))?;
        #[cfg(unix)]
        {
            let mut options = OpenOptions::new();
            options.create(true).write(true).mode(0o600);
            let file = options
                .open(config_dir.join("aliases.lock"))
                .map_err(|err| format!("[error] failed to open aliases lock: {err}"))?;
            // SAFETY: `file` owns the fd for the guard's lifetime; LOCK_EX blocks
            // until no other process holds the lock. Released in `Drop`.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(format!(
                    "[error] failed to lock aliases file: {}",
                    io::Error::last_os_error()
                ));
            }
            Ok(StoreLock { file })
        }
        #[cfg(not(unix))]
        Ok(StoreLock {})
    }
}

#[cfg(unix)]
impl Drop for StoreLock {
    fn drop(&mut self) {
        // Best-effort unlock; closing the fd would release it anyway.
        unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// The one serialized read-modify-write of the alias store: take the exclusive
/// lock, reload the store **under the lock**, run `mutate` against that fresh
/// state, then persist. `mutate` returns whether it changed anything — the store
/// is saved only on `Ok(true)`, so a no-op never rewrites the file (nor creates an
/// empty store for a user who has no aliases) — and may reject with `Err`. Slow
/// work (Console/SSH calls) MUST happen before calling this, never inside
/// `mutate`, so the lock is held only for the brief local critical section.
pub(crate) fn locked_update(
    config_dir: &Path,
    mutate: impl FnOnce(&mut Aliases) -> Result<bool, String>,
) -> Result<(), String> {
    let _guard = StoreLock::acquire(config_dir)?;
    let mut aliases = load(config_dir)?;
    if mutate(&mut aliases)? {
        save(config_dir, &aliases)?;
    }
    Ok(())
}

/// Best-effort, fail-open store maintenance run after a CLI action makes some
/// aliases stale: reload the store under the lock, apply `prune`, and persist
/// only if it removed something. A local-store hiccup must never fail the action
/// that triggered it, so any error is swallowed and nothing is written unless an
/// alias actually went away.
///
/// Each call site names what it drops with a [`Prune`] variant: `cvm terminate`
/// → `Prune::Cvm`, `cvm stop` → `Prune::CvmSessions`, `key remove` →
/// `Prune::Resource(SshKey, …)`, `kill` → `Prune::Session`.
pub(crate) fn prune_and_save(config: &ResolvedConfig, prune: impl FnOnce(&mut Aliases) -> bool) {
    let _ = locked_update(&config.config_dir, |aliases| Ok(prune(aliases)));
}

/// Load the alias store for a read view, reporting an unreadable store ONCE on
/// stderr with the full message, and returning it for the cell renderer.
///
/// Two channels, two jobs. The card cell only marks the fault (`unreadable`): it has
/// no room for a TOML parse error's caret art, and repeating the message in every
/// card of a 100-record page would drown the payload. stderr carries the whole
/// message, once — including the diagnostically useful part `toml` puts on its LAST
/// line (`invalid type: integer 42, expected a string`), and including the case
/// where the listing is EMPTY, which renders no card at all and would otherwise
/// leave no trace of the fault. The command still succeeds: the Console records are
/// intact, only the local decoration is missing.
pub(crate) fn load_for_display(config: &ResolvedConfig) -> Result<Aliases, String> {
    let store = load(&config.config_dir);
    if let Err(message) = &store {
        style::eprintln_warn(&format!(
            "[warn] alias names are not shown: {}; fix or remove {}",
            message.strip_prefix("[error] ").unwrap_or(message),
            store_path(&config.config_dir).display(),
        ));
    }
    store
}

/// The [`style::AliasCell`] for one record: the alias recorded for `id`, or the
/// store error carried through. A `Result` rather than an `Option` because an
/// unreadable local store must neither fail a listing of Console truth nor read as
/// "this record has no alias" — a caller cannot land on either by accident without
/// writing the arm. Borrows from `store`, which the caller loads once per page with
/// [`load_for_display`].
pub(crate) fn cell_source<'a>(
    store: &'a Result<Aliases, String>,
    kind: AliasKind,
    id: &str,
) -> style::AliasCell<'a> {
    match store {
        Ok(aliases) => Ok(aliases.alias_of(kind, id)),
        Err(message) => Err(message.as_str()),
    }
}

/// [`Aliases::validate_alias`] for a caller that does not hold the store: load it,
/// then apply the same rule. Its only job is that load — the whole rule lives in the
/// method. Call it at the command boundary, BEFORE creating the underlying resource
/// (`cvm launch`, `profile create`, `key add`, a session), so a bad or taken name
/// fails fast without leaving an orphan; the write itself re-runs the rule under the
/// store lock, which is the authoritative check (`docs/specs/cli.md` §4.4).
pub(crate) fn validate_alias(
    config: &ResolvedConfig,
    name: &str,
    target: Option<&AliasTarget>,
) -> Result<(), (ExitStatus, String)> {
    // The name's SHAPE owes nothing to the store, so judge it against an empty one
    // first: a malformed name stays the usage error (exit 4) it is even when
    // `aliases.toml` cannot be read, rather than being masked by the load error.
    Aliases::default().validate_alias(name, None)?;
    load(&config.config_dir)
        .map_err(|message| (ExitStatus::Error, message))?
        .validate_alias(name, target)
}

/// Record an alias for a UUID-backed resource that was just created. Assumes the
/// caller already cleared the NAME with [`validate_alias`] (its shape is what carries a
/// usage exit code; under the lock only `Error` is reachable, which is why the status is
/// dropped there).
pub(crate) fn record_resource_alias(
    config: &ResolvedConfig,
    kind: AliasKind,
    id: &str,
    name: &str,
) -> Result<(), String> {
    let target = AliasTarget::Resource(kind, id.to_string());
    locked_update(&config.config_dir, |aliases| {
        // Under the lock the status is fixed (nothing is created), so only the
        // message travels on; the pre-lock call at the command boundary is the one
        // that carries the usage vs. error distinction.
        aliases
            .validate_alias(name, Some(&target))
            .map_err(|(_, message)| message)?;
        aliases.insert_resource(kind, name.to_string(), id.to_string());
        Ok(true)
    })
}

/// Record an alias for a dtach session, binding it to the CVM it lives on.
pub(crate) fn record_session_alias(
    config: &ResolvedConfig,
    session: &str,
    cvm: &str,
    name: &str,
) -> Result<(), String> {
    let target = AliasTarget::Session(SessionAlias {
        session: session.to_string(),
        cvm: cvm.to_string(),
    });
    locked_update(&config.config_dir, |aliases| {
        aliases
            .validate_alias(name, Some(&target))
            .map_err(|(_, message)| message)?;
        aliases.insert_session(name.to_string(), session.to_string(), cvm.to_string());
        Ok(true)
    })
}

/// Resolve a possibly-aliased value for a UUID-backed kind. A value that is
/// already a UUID is returned untouched WITHOUT reading the store, so a corrupt
/// alias file never blocks a command driven by a raw id; only a non-UUID value
/// (a candidate alias) consults the store. Sound because alias names may not be
/// UUIDs (see [`Aliases::validate_alias`]).
pub(crate) fn resolve_or_passthrough(
    config: &ResolvedConfig,
    kind: AliasKind,
    value: &str,
) -> Result<String, String> {
    if uuid::Uuid::parse_str(value).is_ok() {
        return Ok(value.to_string());
    }
    Ok(load(&config.config_dir)?.resolve_alias(kind, value))
}

/// Fail-fast existence check against the Console for a UUID-backed kind, reusing
/// each resource module's own fetcher.
fn ensure_resource_exists(
    kind: AliasKind,
    config: &ResolvedConfig,
    id: &str,
) -> Result<(), (ExitStatus, String)> {
    let (console_url, session) = console_session(config)?;
    match kind {
        AliasKind::Cvm => cvm::cvm_exists(console_url, &session, id),
        AliasKind::Profile => profile::profile_exists(console_url, &session, id),
        AliasKind::SshKey => key::key_exists(console_url, &session, id),
        AliasKind::Session => {
            unreachable!("sessions are validated over SSH, not against a UUID endpoint")
        }
    }
}

pub(crate) fn run(command: AliasCommand, config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    match command {
        AliasCommand::Cvm(args) => create_resource(config, AliasKind::Cvm, args, json_output),
        AliasCommand::Profile(args) => {
            create_resource(config, AliasKind::Profile, args, json_output)
        }
        AliasCommand::SshKey(args) => create_resource(config, AliasKind::SshKey, args, json_output),
        AliasCommand::Session(args) => create_session(config, args, json_output),
        AliasCommand::List => list(config, json_output),
        AliasCommand::Rm(args) => remove(config, args, json_output),
        AliasCommand::Rename(args) => rename(config, args, json_output),
        AliasCommand::Prune(args) => prune(config, args, json_output),
    }
}

/// Create a `cvm`/`profile`/`ssh-key` alias: validate the id, confirm it exists
/// on the Console, ensure the name is free, then record and persist it.
fn create_resource(
    config: &ResolvedConfig,
    kind: AliasKind,
    args: AliasResourceArgs,
    json_output: bool,
) -> ExitStatus {
    if let Err(message) = validate_uuid(&format!("<{}-id>", kind.as_str()), &args.id) {
        style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    // Canonical for the Console request and the confirmation we echo: the id was
    // accepted in any form `Uuid::parse_str` takes, and what leaves the CLI should not
    // depend on how it was typed. The store normalizes on its own (`insert_resource`).
    let id = canonical_id(&args.id);
    let target = AliasTarget::Resource(kind, id.clone());
    // Cheap fail-fast before the Console round-trip; the same rule runs again under
    // the store lock, just before the write, which is the authoritative check.
    if let Err((status, message)) = validate_alias(config, &args.alias, Some(&target)) {
        style::eprintln_error(&message);
        return status;
    }
    if let Err((status, message)) = ensure_resource_exists(kind, config, &id) {
        style::eprintln_error(&message);
        return status;
    }
    if let Err(message) = locked_update(&config.config_dir, |aliases| {
        aliases
            .validate_alias(&args.alias, Some(&target))
            .map_err(|(_, message)| message)?;
        aliases.insert_resource(kind, args.alias.clone(), id.clone());
        Ok(true)
    }) {
        style::eprintln_error(&message);
        return ExitStatus::Error;
    }
    confirm_alias(kind, &args.alias, &id, None, json_output)
}

/// Create a `session` alias: validate names, resolve the target CVM, confirm the
/// session is live over SSH, then record `{ session, cvm }`.
fn create_session(
    config: &ResolvedConfig,
    args: AliasSessionArgs,
    json_output: bool,
) -> ExitStatus {
    if let Err(message) = ssh::validate_session_name(&args.name) {
        style::eprintln_error(&message);
        return ExitStatus::Usage;
    }
    let cvm_id = match select_cvm(
        None,
        args.cvm.as_deref(),
        &[config.default_cvm.as_deref()],
        config,
    ) {
        Ok(cvm_id) => cvm_id,
        Err(message) => {
            style::eprintln_error(&message);
            return ExitStatus::Usage;
        }
    };
    // The CVM is resolved first: a session's target is the `{ session, cvm }` pair,
    // so the one-alias-per-session step cannot be checked before it is known.
    let target = AliasTarget::Session(SessionAlias {
        session: args.name.clone(),
        cvm: cvm_id.clone(),
    });
    // Cheap fail-fast before the SSH probe; the same rule runs again under the store
    // lock, just before the write, which is the authoritative check.
    if let Err((status, message)) = validate_alias(config, &args.alias, Some(&target)) {
        style::eprintln_error(&message);
        return status;
    }
    let session_names = try_or_eprintln!(ssh::list_session_names(
        &cvm_id,
        args.identity_file.as_deref(),
        config
    ));
    if !session_names.iter().any(|name| name == &args.name) {
        style::eprintln_error(&format!(
            "[error] session {} was not found on {cvm_id}",
            args.name
        ));
        return ExitStatus::Error;
    }
    // Resolution consults aliases first, so an alias named like a real session
    // would make that session unreachable by name. Reject the shadowing up front.
    if let Some(message) = ssh::session_shadow_error(&session_names, &args.alias, &cvm_id) {
        style::eprintln_error(&message);
        return ExitStatus::Error;
    }
    if let Err(message) = locked_update(&config.config_dir, |aliases| {
        aliases
            .validate_alias(&args.alias, Some(&target))
            .map_err(|(_, message)| message)?;
        aliases.insert_session(args.alias.clone(), args.name.clone(), cvm_id.clone());
        Ok(true)
    }) {
        style::eprintln_error(&message);
        return ExitStatus::Error;
    }
    confirm_alias(
        AliasKind::Session,
        &args.alias,
        &args.name,
        Some(&cvm_id),
        json_output,
    )
}

fn list(config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    let aliases = match load(&config.config_dir) {
        Ok(aliases) => aliases,
        Err(message) => {
            style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    println!("{}", render_alias_list(&aliases, json_output));
    ExitStatus::Ok
}

/// Render what `alias list` prints: the pretty JSON payload with `--json`, else
/// the grouped human view. A session's CVM shows by its alias when one exists,
/// falling back to the raw UUID. Split from [`list`] so the output is testable
/// without capturing stdout.
fn render_alias_list(aliases: &Aliases, json_output: bool) -> String {
    if json_output {
        return serde_json::to_string_pretty(aliases).expect("alias list serializes");
    }
    let mut views: Vec<style::AliasView<'_>> = Vec::new();
    for (name, id) in &aliases.cvm {
        views.push(style::AliasView {
            name,
            kind: "cvm",
            target: id,
            cvm: None,
        });
    }
    for (name, id) in &aliases.profile {
        views.push(style::AliasView {
            name,
            kind: "profile",
            target: id,
            cvm: None,
        });
    }
    for (name, id) in &aliases.ssh_key {
        views.push(style::AliasView {
            name,
            kind: "ssh-key",
            target: id,
            cvm: None,
        });
    }
    for (name, entry) in &aliases.session {
        views.push(style::AliasView {
            name,
            kind: "session",
            target: &entry.session,
            cvm: Some(aliases.cvm_display(&entry.cvm)),
        });
    }
    style::alias_list_grouped(&views)
}

fn remove(config: &ResolvedConfig, args: AliasNameArgs, json_output: bool) -> ExitStatus {
    if let Err(message) = locked_update(&config.config_dir, |aliases| {
        if aliases.remove_alias(&args.alias) {
            Ok(true)
        } else {
            Err(format!(
                "[error] alias {} was not found; run `umbra alias list`",
                args.alias
            ))
        }
    }) {
        style::eprintln_error(&message);
        return ExitStatus::Error;
    }
    if json_output {
        style::emit_json(&json!({ "alias": args.alias }));
    } else {
        let confirm = style::ConfirmBlock::new("removed", "alias", args.alias.clone());
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

/// Rename an alias, keeping what it points at. The target itself is not
/// revalidated (it was valid when recorded); the kind is inferred from the old
/// name. Renaming a SESSION alias probes its bound CVM so the new name can't shadow
/// a live dtach session (the same guard the creation paths apply): a confirmed
/// collision is rejected, but a probe that can't run (CVM offline, transient/auth
/// failure — a rare case) only warns and proceeds rather than blocking the rename.
/// The other kinds stay purely local.
fn rename(config: &ResolvedConfig, args: AliasRenameArgs, json_output: bool) -> ExitStatus {
    // Shape first, store second — the same order the loading entry point uses, so a
    // malformed NEW is the usage error it is even when `aliases.toml` cannot be read.
    // An empty store can only fail on the name's shape (no name is taken in it, and no
    // target is given).
    if let Err((status, message)) = Aliases::default().validate_alias(&args.new, None) {
        style::eprintln_error(&message);
        return status;
    }
    // Read the current kind (and, for a session, its CVM) to drive the pre-lock
    // shadow probe; the authoritative move re-checks everything under the lock. The
    // store is loaded once here, so the rule is applied through the method rather
    // than through the loading entry point.
    let aliases = match load(&config.config_dir) {
        Ok(aliases) => aliases,
        Err(message) => {
            style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    // The alias being moved comes first: a typo in OLD must be reported as such, not
    // as whatever NEW happens to collide with.
    let (kind, session_cvm) = match aliases.kind_of(&args.old) {
        Some(kind) => {
            let cvm = aliases
                .session
                .get(&args.old)
                .map(|entry| entry.cvm.clone());
            (kind, cvm)
        }
        None => {
            style::eprintln_error(&format!(
                "[error] alias {} was not found; run `umbra alias list`",
                args.old
            ));
            return ExitStatus::Error;
        }
    };
    // No target: a rename moves an alias, so its target is legitimately aliased
    // already — by the very alias being moved.
    if let Err((status, message)) = aliases.validate_alias(&args.new, None) {
        style::eprintln_error(&message);
        return status;
    }
    // Anti-shadow for a session alias: probe the bound CVM (outside the store lock;
    // SSH is slow) and reject a confirmed collision. If the probe can't run — CVM
    // offline, or a transient/auth failure, a rare case — warn and rename anyway
    // rather than block; the residual risk of shadowing is small and reported.
    if let Some(cvm) = &session_cvm {
        match ssh::list_session_names(cvm, args.identity_file.as_deref(), config) {
            Ok(live) => {
                if let Some(message) = ssh::session_shadow_error(&live, &args.new, cvm) {
                    style::eprintln_error(&message);
                    return ExitStatus::Error;
                }
            }
            Err(_) => {
                style::eprintln_warn(&format!(
                    "[warn] could not check {cvm} for a live session named {}; renaming without the shadow check",
                    args.new
                ));
            }
        }
    }
    // Authoritative move under the store lock: re-find the alias, re-check the new
    // name is free against the fresh store, then move the entry (target untouched).
    if let Err(message) = locked_update(&config.config_dir, |aliases| {
        let Some(kind) = aliases.kind_of(&args.old) else {
            return Err(format!(
                "[error] alias {} was not found; run `umbra alias list`",
                args.old
            ));
        };
        aliases
            .validate_alias(&args.new, None)
            .map_err(|(_, message)| message)?;
        match kind {
            AliasKind::Session => {
                let entry = aliases
                    .session
                    .remove(&args.old)
                    .expect("kind_of reported a session alias");
                aliases.insert_session(args.new.clone(), entry.session, entry.cvm);
            }
            _ => {
                let target = aliases
                    .resource_table_mut(kind)
                    .expect("uuid-backed kind has a table")
                    .remove(&args.old)
                    .expect("kind_of reported this kind");
                aliases.insert_resource(kind, args.new.clone(), target);
            }
        }
        Ok(true)
    }) {
        style::eprintln_error(&message);
        return ExitStatus::Error;
    }
    if json_output {
        style::emit_json(&json!({
            "kind": kind.as_str(), "old": args.old, "new": args.new,
        }));
    } else {
        let confirm = style::ConfirmBlock::new("renamed", kind.as_str(), args.new.clone())
            .field("from", args.old.clone());
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

/// Reconcile the alias store against reality and drop the stale entries. Only
/// confirmed-absent targets are removed: a reference fetch that fails leaves
/// that kind untouched (we never prune on a guess). `--dry-run` reports the plan
/// without writing.
fn prune(config: &ResolvedConfig, args: AliasPruneArgs, json_output: bool) -> ExitStatus {
    let mut aliases = match load(&config.config_dir) {
        Ok(aliases) => aliases,
        Err(message) => {
            style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    };
    let (console_url, session) = try_or_eprintln!(console_session(config));

    // Best-effort reference sets. A fetch failure => that kind is left untouched
    // (and reported), so a network blip can never wrongly delete a good alias.
    let cvm_states = cvm::alive_cvm_states(console_url, &session).ok();
    let profile_ids = profile::profile_ids(console_url, &session).ok();
    let key_ids = key::key_ids(console_url, &session).ok();
    if cvm_states.is_none() {
        style::eprintln_warn(
            "[warn] could not list CVMs; cvm and session aliases were not checked",
        );
    }
    if profile_ids.is_none() {
        style::eprintln_warn("[warn] could not list profiles; profile aliases were not checked");
    }
    if key_ids.is_none() {
        style::eprintln_warn("[warn] could not list SSH keys; ssh-key aliases were not checked");
    }

    // (alias, kind, reason) for display, plus the observed mapping so the deferred
    // delete under the lock only drops an alias that hasn't been recreated since.
    let mut removed: Vec<(String, &'static str, &'static str)> = Vec::new();
    let mut to_remove: Vec<(String, AliasTarget)> = Vec::new();
    if let Some(states) = &cvm_states {
        aliases.cvm.retain(|name, uuid| {
            let live = states.contains_key(uuid);
            if !live {
                removed.push((name.clone(), "cvm", "CVM terminated or absent"));
                to_remove.push((
                    name.clone(),
                    AliasTarget::Resource(AliasKind::Cvm, uuid.clone()),
                ));
            }
            live
        });
    }
    if let Some(ids) = &profile_ids {
        aliases.profile.retain(|name, uuid| {
            let live = ids.iter().any(|id| id == uuid);
            if !live {
                removed.push((name.clone(), "profile", "profile absent"));
                to_remove.push((
                    name.clone(),
                    AliasTarget::Resource(AliasKind::Profile, uuid.clone()),
                ));
            }
            live
        });
    }
    if let Some(ids) = &key_ids {
        aliases.ssh_key.retain(|name, uuid| {
            let live = ids.iter().any(|id| id == uuid);
            if !live {
                removed.push((name.clone(), "ssh-key", "SSH key absent"));
                to_remove.push((
                    name.clone(),
                    AliasTarget::Resource(AliasKind::SshKey, uuid.clone()),
                ));
            }
            live
        });
    }
    if let Some(states) = &cvm_states {
        // One SSH probe per CVM that hosts session aliases. `None` marks a probe
        // we could not run (keep those sessions); `Some(list)` its live sessions.
        let mut probed: BTreeMap<String, Option<Vec<String>>> = BTreeMap::new();
        for entry in aliases.session.values() {
            if probed.contains_key(&entry.cvm) {
                continue;
            }
            let live = match states.get(&entry.cvm) {
                Some(state) if state.eq_ignore_ascii_case("running") => {
                    ssh::list_session_names(&entry.cvm, args.identity_file.as_deref(), config).ok()
                }
                // Not running, or CVM absent => it hosts no live sessions.
                _ => Some(Vec::new()),
            };
            probed.insert(entry.cvm.clone(), live);
        }
        aliases
            .session
            .retain(|name, entry| match probed.get(&entry.cvm) {
                Some(Some(live)) => {
                    let alive = live.iter().any(|session| session == &entry.session);
                    if !alive {
                        removed.push((name.clone(), "session", "session not running"));
                        to_remove.push((name.clone(), AliasTarget::Session(entry.clone())));
                    }
                    alive
                }
                // Probe failed => couldn't check => keep.
                _ => true,
            });
    }

    if !args.dry_run && !to_remove.is_empty() {
        // Re-apply the removals under the store lock against a fresh reload, rather
        // than saving the copy loaded before all the network work — otherwise a
        // create that ran concurrently would be clobbered. Each removal is matched
        // against the observed mapping, so an alias that was rm'd and recreated to a
        // new target in the meantime is left untouched.
        if let Err(message) = locked_update(&config.config_dir, |aliases| {
            for (name, observed) in &to_remove {
                aliases.remove_if_matches(name, observed);
            }
            Ok(true)
        }) {
            style::eprintln_error(&message);
            return ExitStatus::Error;
        }
    }

    if json_output {
        let payload = json!({
            "dry_run": args.dry_run,
            "removed": removed
                .iter()
                .map(|(alias, kind, reason)| json!({ "alias": alias, "kind": kind, "reason": reason }))
                .collect::<Vec<_>>(),
        });
        style::emit_json(&payload);
    } else if removed.is_empty() {
        println!("no stale aliases");
    } else {
        let width = removed
            .iter()
            .map(|(alias, ..)| alias.len())
            .max()
            .unwrap_or(0);
        let mut out = if args.dry_run {
            format!(
                "{} stale aliases (dry run — nothing changed):\n",
                removed.len()
            )
        } else {
            format!("removed {} stale aliases:\n", removed.len())
        };
        for (alias, kind, reason) in &removed {
            out.push_str(&format!("  {alias:<width$}  {kind:<7}  {reason}\n"));
        }
        print!("{out}");
    }
    ExitStatus::Ok
}

/// Render the confirmation for an alias creation. A session also shows its CVM.
fn confirm_alias(
    kind: AliasKind,
    alias: &str,
    target: &str,
    cvm: Option<&str>,
    json_output: bool,
) -> ExitStatus {
    if json_output {
        let payload = match cvm {
            Some(cvm) => json!({
                "kind": kind.as_str(), "alias": alias, "session": target, "cvm": cvm,
            }),
            None => json!({ "kind": kind.as_str(), "alias": alias, "target": target }),
        };
        style::emit_json(&payload);
    } else {
        let confirm = match cvm {
            Some(cvm) => style::ConfirmBlock::new("aliased", kind.as_str(), alias.to_string())
                .field("session", target.to_string())
                .field("cvm", cvm.to_string()),
            None => style::ConfirmBlock::new("aliased", kind.as_str(), alias.to_string())
                .field("target", target.to_string()),
        };
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{authenticated_config, MockConsole, Presence};
    use rstest::rstest;

    /// No alias file yet means an empty store, not an error.
    #[test]
    fn test_load_missing_file_success() {
        let dir = std::env::temp_dir().join(format!("umbra-alias-load-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");
        assert_eq!(
            load(&dir).expect("absent file is an empty store"),
            Aliases::default()
        );
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    /// A broken alias file errors instead of silently reading as "no aliases" —
    /// whether it is not valid TOML, or a kind holds the wrong shape. One case
    /// per kind, plus the not-TOML case; all report `malformed aliases file`.
    #[rstest]
    #[case::not_toml("not = = valid toml")]
    #[case::cvm_wrong_type("[cvm]\nnick = 42\n")]
    #[case::profile_wrong_type("[profile]\nnick = 42\n")]
    #[case::ssh_key_wrong_type("[ssh-key]\nnick = 42\n")]
    #[case::session_missing_field("[session.nick]\ncvm = \"c\"\n")]
    fn test_load_malformed_failure(#[case] contents: &str) {
        let dir = std::env::temp_dir().join(format!("umbra-alias-load-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("temp dir created");
        fs::write(store_path(&dir), contents).expect("alias file written");
        let err = load(&dir).expect_err("a malformed file must error");
        assert!(err.contains("malformed aliases file"), "err: {err}");
        fs::remove_dir_all(dir).expect("temp dir removed");
    }

    /// The pre-alias-kinds file (top-level `[<cvm_id>]` tables of
    /// `alias = session`) migrates on load into the current `session` kind, each
    /// alias bound to the CVM whose table it lived under. Only sessions existed
    /// back then, so no other kind is produced.
    #[test]
    fn test_load_migrates_legacy_success() {
        const CVM_B_ID: &str = "5d5d5d5d-6666-7777-8888-999999999999";
        let config = local_config();
        fs::create_dir_all(&config.config_dir).expect("temp dir created");
        // The first CVM is written in UPPERCASE: the legacy layout carries it as a TOML
        // section key, so migration must normalize it exactly like a stored target —
        // otherwise the migrated alias matches no Console id, the one-alias-per-session
        // rule misses it, and `alias prune` reads its CVM as absent and deletes it.
        let legacy = format!(
            "[{}]\nmy-agent = \"ssh-1\"\n\n[{CVM_B_ID}]\nother = \"session-two\"\n",
            CVM_ID.to_ascii_uppercase(),
        );
        fs::write(store_path(&config.config_dir), legacy).expect("legacy store written");

        let aliases = load(&config.config_dir).expect("legacy file loads");
        assert_eq!(
            aliases.resolve_session("my-agent"),
            Some(&SessionAlias {
                session: "ssh-1".into(),
                cvm: CVM_ID.into(),
            })
        );
        assert_eq!(
            aliases.resolve_session("other"),
            Some(&SessionAlias {
                session: "session-two".into(),
                cvm: CVM_B_ID.into(),
            })
        );
        // The old format only had sessions, so migration produces nothing else.
        assert!(aliases.cvm.is_empty());
        assert!(aliases.profile.is_empty());
        assert!(aliases.ssh_key.is_empty());
    }

    /// `remove_if_matches` drops an alias only when it still maps to the observed
    /// target. This is what makes the deferred cleanups (prune, launch rollback)
    /// race-safe: if the name was recreated to a DIFFERENT target since it was
    /// observed stale, it must be left alone. Covers both a resource and a session,
    /// each in the match (removed) and mismatch (kept) case.
    #[test]
    fn test_remove_if_matches() {
        // Resource: matching id removes; a recreated id is kept.
        let mut a = Aliases::default();
        a.cvm.insert("box".into(), CVM_ID.into());
        assert!(!a.remove_if_matches(
            "box",
            &AliasTarget::Resource(AliasKind::Cvm, "other".into())
        ));
        assert!(a.cvm.contains_key("box"), "a recreated target must be kept");
        assert!(a.remove_if_matches("box", &AliasTarget::Resource(AliasKind::Cvm, CVM_ID.into())));
        assert!(!a.cvm.contains_key("box"), "the observed target is removed");

        // Session: matches on the full {session, cvm} value-object.
        let mut a = Aliases::default();
        a.insert_session("dev".into(), "agent-1".into(), CVM_ID.into());
        let stale = SessionAlias {
            session: "agent-OLD".into(),
            cvm: CVM_ID.into(),
        };
        assert!(!a.remove_if_matches("dev", &AliasTarget::Session(stale)));
        assert!(a.session.contains_key("dev"), "a recreated session is kept");
        let observed = SessionAlias {
            session: "agent-1".into(),
            cvm: CVM_ID.into(),
        };
        assert!(a.remove_if_matches("dev", &AliasTarget::Session(observed)));
        assert!(
            !a.session.contains_key("dev"),
            "the observed session is removed"
        );
    }

    /// The store normalizes what it RECORDS, so the file never holds two spellings of one
    /// resource — the write-side counterpart of the lookup normalization below. Both write
    /// funnels are covered: a UUID target and a session's bound CVM.
    #[test]
    fn test_insert_canonicalizes_success() {
        let mut store = Aliases::default();
        store.insert_resource(AliasKind::Cvm, "box".into(), CVM_ID.to_ascii_uppercase());
        store.insert_session("dev".into(), "agent-1".into(), CVM_ID.to_ascii_uppercase());
        assert_eq!(store.cvm.get("box").map(String::as_str), Some(CVM_ID));
        assert_eq!(
            store.session.get("dev").map(|entry| entry.cvm.as_str()),
            Some(CVM_ID)
        );
    }

    /// Every lookup canonicalizes what it is HANDED, not just what it holds, so an id
    /// that reached the CLI in a non-canonical spelling still finds its alias. One case
    /// per lookup, because each is the sole guard of a user-visible behaviour and a
    /// failure must name which one broke: `alias_of` labels the record in the read views;
    /// the four `Prune` variants are the auto-purges of `cvm terminate` / `cvm stop` /
    /// `key remove` / `kill`, which would otherwise leave a stale alias behind;
    /// `remove_if_matches` is what makes `alias prune` and the `--alias` launch rollback
    /// drop the right entry; `session_names_on` labels the sessions in `ps`. Each closure
    /// answers "did the non-canonical id find something?" against [`list_store`], whose
    /// targets are canonical.
    #[rstest]
    #[case::alias_of(|s: &mut Aliases| s
        .alias_of(AliasKind::Cvm, &CVM_ID.to_ascii_uppercase())
        .is_some())]
    #[case::prune_cvm(|s: &mut Aliases| s.prune(Prune::Cvm(&CVM_ID.to_ascii_uppercase())))]
    #[case::prune_cvm_sessions(|s: &mut Aliases| s
        .prune(Prune::CvmSessions(&CVM_ID.to_ascii_uppercase())))]
    #[case::prune_profile(|s: &mut Aliases| s
        .prune(Prune::Resource(AliasKind::Profile, &PROFILE_ID.to_ascii_uppercase())))]
    #[case::prune_ssh_key(|s: &mut Aliases| s
        .prune(Prune::Resource(AliasKind::SshKey, &KEY_ID.to_ascii_uppercase())))]
    #[case::prune_session(|s: &mut Aliases| s.prune(Prune::Session {
        session: "agent-1",
        cvm: &CVM_ID.to_ascii_uppercase(),
    }))]
    #[case::remove_if_matches_resource(|s: &mut Aliases| s.remove_if_matches(
        "box",
        &AliasTarget::Resource(AliasKind::Cvm, CVM_ID.to_ascii_uppercase()),
    ))]
    #[case::remove_if_matches_session(|s: &mut Aliases| s.remove_if_matches(
        "dev",
        &AliasTarget::Session(SessionAlias {
            session: "agent-1".into(),
            cvm: CVM_ID.to_ascii_uppercase(),
        }),
    ))]
    #[case::session_names_on(|s: &mut Aliases| !s
        .session_names_on(&CVM_ID.to_ascii_uppercase())
        .is_empty())]
    fn test_non_canonical_lookup_success(#[case] lookup: fn(&mut Aliases) -> bool) {
        assert!(
            lookup(&mut list_store()),
            "a non-canonical id must find the alias its canonical form points at"
        );
    }

    /// A malformed name is the usage error it is (exit `4`) even when `aliases.toml`
    /// cannot be read: the shape is judged before the store is loaded. One case per entry
    /// point — a creation, which goes through the loading `validate_alias`, and `rename`,
    /// which loads the store itself. Without that order the load failure (exit `1`) masks
    /// a plain argv mistake.
    #[rstest]
    #[case::create(AliasCommand::Cvm(AliasResourceArgs {
        id: CVM_ID.into(),
        alias: "bad name".into(),
    }))]
    #[case::rename(AliasCommand::Rename(AliasRenameArgs {
        old: "box".into(),
        new: "bad name".into(),
        identity_file: None,
    }))]
    fn test_malformed_name_unreadable_store_failure(#[case] command: AliasCommand) {
        let config = local_config();
        fs::create_dir_all(&config.config_dir).unwrap();
        fs::write(store_path(&config.config_dir), "not valid toml @@@ {{{").unwrap();
        assert_eq!(run(command, &config, false) as u8, 4);
    }

    /// `save` locks the store down to the owner: the file is `0600` and the
    /// config dir `0700`, so no other user on the machine can read the aliases.
    #[cfg(unix)]
    #[test]
    fn test_save_permissions_success() {
        use std::os::unix::fs::PermissionsExt;
        let config = local_config();
        let mut store = Aliases::default();
        store.cvm.insert("box".into(), CVM_ID.into());
        save(&config.config_dir, &store).expect("save store");

        let file_mode = fs::metadata(store_path(&config.config_dir))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let dir_mode = fs::metadata(&config.config_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "aliases.toml must be owner-only rw");
        assert_eq!(dir_mode, 0o700, "config dir must be owner-only rwx");
    }

    /// Concurrent `umbra` invocations that each record a DIFFERENT alias must
    /// all survive: the store lock serializes their load→check→insert→save so none
    /// clobbers another (last-writer-wins). Twelve threads race on one config dir
    /// via `record_resource_alias`; without the lock, several aliases are lost.
    #[test]
    fn test_concurrent_record_all_survive_success() {
        const THREADS: usize = 12;
        let config = local_config();
        fs::create_dir_all(&config.config_dir).expect("temp dir created");
        let dir = config.config_dir.clone();

        let handles: Vec<_> = (0..THREADS)
            .map(|i| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let cfg =
                        crate::config::ResolvedConfig::resolve(crate::config::ConfigOverrides {
                            config_dir: Some(dir),
                            ..Default::default()
                        });
                    record_resource_alias(
                        &cfg,
                        AliasKind::Cvm,
                        &format!("id-{i:02}"),
                        &format!("name-{i:02}"),
                    )
                    .expect("record alias");
                })
            })
            .collect();
        for handle in handles {
            handle.join().expect("thread joins");
        }

        let store = load(&config.config_dir).expect("store loads");
        assert_eq!(
            store.cvm.len(),
            THREADS,
            "every concurrent alias must survive; got {:?}",
            store.cvm
        );
    }

    /// Concurrent invocations that all name the SAME resource: exactly ONE wins and
    /// every other is refused, because the rule is re-run against the store reloaded
    /// UNDER the lock. This is what makes one-alias-per-resource hold between
    /// processes and not merely single-threaded: with only the pre-lock check, all
    /// twelve would read an unaliased resource and all twelve would land.
    #[test]
    fn test_concurrent_record_one_target_failure() {
        const THREADS: usize = 12;
        let config = local_config();
        fs::create_dir_all(&config.config_dir).expect("temp dir created");
        let dir = config.config_dir.clone();

        let handles: Vec<_> = (0..THREADS)
            .map(|i| {
                let dir = dir.clone();
                std::thread::spawn(move || {
                    let cfg =
                        crate::config::ResolvedConfig::resolve(crate::config::ConfigOverrides {
                            config_dir: Some(dir),
                            ..Default::default()
                        });
                    record_resource_alias(&cfg, AliasKind::Cvm, CVM_ID, &format!("name-{i:02}"))
                })
            })
            .collect();
        let refused = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread joins"))
            .filter(Result::is_err)
            .count();

        assert_eq!(refused, THREADS - 1, "all but one record must be refused");
        let store = load(&config.config_dir).expect("store loads");
        assert_eq!(
            store.cvm.len(),
            1,
            "one resource must end up with exactly one alias; got {:?}",
            store.cvm
        );
    }

    /// The three steps of the rule accept: a well-formed name (the shapes the syntax
    /// step allows), free of every kind, whose target carries no alias yet — checked
    /// against a store that already holds one alias per kind ([`list_store`]), so a
    /// pass is not the trivial empty-store case. The two target cases pin what
    /// "unaliased" means: another CVM, and another SESSION ON THE ALREADY-ALIASED CVM
    /// (a session's identity is the `{ session, cvm }` pair, not its CVM).
    #[rstest]
    #[case::plain("prod-box", None)]
    #[case::underscore("team_prod", None)]
    #[case::single_char("a", None)]
    #[case::dotted("s1.1", None)]
    #[case::mixed_case("MixedCase9", None)]
    #[case::unaliased_resource(
        "fresh",
        Some(AliasTarget::Resource(AliasKind::Cvm, LIVE_CVM.into())),
    )]
    #[case::unaliased_session(
        "fresh",
        Some(AliasTarget::Session(SessionAlias { session: "agent-2".into(), cvm: CVM_ID.into() })),
    )]
    fn test_validate_alias_success(#[case] name: &str, #[case] target: Option<AliasTarget>) {
        assert!(
            list_store().validate_alias(name, target.as_ref()).is_ok(),
            "{name} should be accepted"
        );
    }

    /// The rule rejects, with the exit status each step owes (`docs/specs/cli.md`
    /// §3.4): a malformed name is a usage error (`4`), a name or a target already in
    /// the store an error (`1`). Cases, against [`list_store`]: empty / over-long
    /// (>128) / illegal-character / UUID-shaped names; a name already taken by EACH
    /// kind (names are globally unique across kinds, so none can be reused); and a
    /// target that already has an alias, for a resource and for a session — the
    /// one-alias-per-resource rule, which `rename` exists to work around.
    #[rstest]
    #[case::empty("".to_string(), None, 4)]
    #[case::too_long("x".repeat(129), None, 4)]
    #[case::space("has space".to_string(), None, 4)]
    #[case::slash("a/b".to_string(), None, 4)]
    #[case::uuid(CVM_ID.to_string(), None, 4)]
    #[case::name_taken_by_cvm("box".to_string(), None, 1)]
    #[case::name_taken_by_profile("prof".to_string(), None, 1)]
    #[case::name_taken_by_ssh_key("laptop".to_string(), None, 1)]
    #[case::name_taken_by_session("dev".to_string(), None, 1)]
    #[case::resource_already_aliased(
        "fresh".to_string(),
        Some(AliasTarget::Resource(AliasKind::Cvm, CVM_ID.into())),
        1,
    )]
    #[case::session_already_aliased(
        "fresh".to_string(),
        Some(AliasTarget::Session(SessionAlias { session: "agent-1".into(), cvm: CVM_ID.into() })),
        1,
    )]
    fn test_validate_alias_failure(
        #[case] name: String,
        #[case] target: Option<AliasTarget>,
        #[case] expected_code: u8,
    ) {
        let (status, message) = list_store()
            .validate_alias(&name, target.as_ref())
            .expect_err("a malformed or already-used alias must be rejected");
        assert_eq!(status as u8, expected_code, "message: {message}");
    }

    // Real UUIDs so `validate_uuid` on the `<id>` argument passes.
    const CVM_ID: &str = "9a7f6b4a-1111-2222-3333-444444444444";
    const PROFILE_ID: &str = "16286507-f87f-449e-a229-be04067fc23c";
    const KEY_ID: &str = "3c4c2b64-b059-41a6-b925-3e4816ffee60";

    /// `umbra alias <kind> <id> <alias>` records the alias when the Console
    /// confirms the resource exists — drives the whole command, one case per
    /// kind. `seed` stubs the matching endpoint as present.
    #[rstest]
    #[case::cvm(
        |c: &MockConsole| c.get_cvm(CVM_ID, Presence::Present),
        AliasCommand::Cvm(AliasResourceArgs { id: CVM_ID.into(), alias: "nick".into() }),
        AliasKind::Cvm, CVM_ID,
    )]
    #[case::profile(
        |c: &MockConsole| c.get_profile(PROFILE_ID, Presence::Present),
        AliasCommand::Profile(AliasResourceArgs { id: PROFILE_ID.into(), alias: "nick".into() }),
        AliasKind::Profile, PROFILE_ID,
    )]
    #[case::ssh_key(
        |c: &MockConsole| c.list_keys(&[KEY_ID]),
        AliasCommand::SshKey(AliasResourceArgs { id: KEY_ID.into(), alias: "nick".into() }),
        AliasKind::SshKey, KEY_ID,
    )]
    // An id typed in a non-canonical form (uppercase here; braced, `urn:uuid:` and
    // unhyphenated are equally accepted by `validate_uuid`) is recorded CANONICALLY,
    // so the file itself never holds two spellings of one resource.
    #[case::non_canonical(
        |c: &MockConsole| c.get_cvm(CVM_ID, Presence::Present),
        AliasCommand::Cvm(AliasResourceArgs {
            id: "9A7F6B4A-1111-2222-3333-444444444444".into(),
            alias: "nick".into(),
        }),
        AliasKind::Cvm, CVM_ID,
    )]
    fn test_alias_existing_resource_success(
        #[case] seed: fn(&MockConsole),
        #[case] command: AliasCommand,
        #[case] kind: AliasKind,
        #[case] id: &str,
    ) {
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        seed(&console);
        assert!(matches!(run(command, &config, false), ExitStatus::Ok));
        assert_eq!(
            load(&config.config_dir)
                .unwrap()
                .resolve_alias(kind, "nick"),
            id
        );
        // Read the FILE, not `load`, which canonicalizes on the way in and would hide a
        // non-canonical target having been written.
        let raw = fs::read_to_string(store_path(&config.config_dir)).unwrap();
        assert!(
            raw.contains(id),
            "the stored target must be the canonical id; file:\n{raw}"
        );
    }

    /// `umbra alias <kind> <id> <alias>` refuses and writes nothing when the
    /// Console does not have the resource (fail-fast). `seed` stubs the endpoint
    /// as absent (404 for cvm/profile, empty key list for ssh-key).
    #[rstest]
    #[case::cvm(
        |c: &MockConsole| c.get_cvm(CVM_ID, Presence::Absent),
        AliasCommand::Cvm(AliasResourceArgs { id: CVM_ID.into(), alias: "ghost".into() }),
    )]
    #[case::profile(
        |c: &MockConsole| c.get_profile(PROFILE_ID, Presence::Absent),
        AliasCommand::Profile(AliasResourceArgs { id: PROFILE_ID.into(), alias: "ghost".into() }),
    )]
    #[case::ssh_key(
        |c: &MockConsole| c.list_keys(&[]),
        AliasCommand::SshKey(AliasResourceArgs { id: KEY_ID.into(), alias: "ghost".into() }),
    )]
    fn test_alias_missing_resource_failure(
        #[case] seed: fn(&MockConsole),
        #[case] command: AliasCommand,
    ) {
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        seed(&console);
        assert!(!matches!(run(command, &config, false), ExitStatus::Ok));
        // Fail-fast: nothing was written to the store.
        assert_eq!(load(&config.config_dir).unwrap(), Aliases::default());
    }

    /// A resource that already has an alias refuses a second one, through the whole
    /// command: the Console HAS the resource and the new name is free, so only the
    /// one-alias-per-resource step can reject it — which pins that `create_resource`
    /// really hands its target to the rule, the wiring the bug was in. One case per
    /// kind, plus `non_canonical`: the same CVM typed in UPPERCASE, which the store
    /// holds canonically — without `canonical_id` the two spellings read as two
    /// resources and the second alias slips through (the Console GET also proves it
    /// is the canonical id that goes on the wire, since the mock only answers that
    /// path). The first alias must survive untouched, and the exit is `1` (`4` would
    /// mean the name, not the target, was rejected).
    #[rstest]
    #[case::cvm(
        |c: &MockConsole| c.get_cvm(CVM_ID, Presence::Present),
        AliasKind::Cvm, CVM_ID,
        AliasCommand::Cvm(AliasResourceArgs { id: CVM_ID.into(), alias: "box2".into() }),
    )]
    #[case::profile(
        |c: &MockConsole| c.get_profile(PROFILE_ID, Presence::Present),
        AliasKind::Profile, PROFILE_ID,
        AliasCommand::Profile(AliasResourceArgs { id: PROFILE_ID.into(), alias: "box2".into() }),
    )]
    #[case::ssh_key(
        |c: &MockConsole| c.list_keys(&[KEY_ID]),
        AliasKind::SshKey, KEY_ID,
        AliasCommand::SshKey(AliasResourceArgs { id: KEY_ID.into(), alias: "box2".into() }),
    )]
    #[case::non_canonical(
        |c: &MockConsole| c.get_cvm(CVM_ID, Presence::Present),
        AliasKind::Cvm, CVM_ID,
        AliasCommand::Cvm(AliasResourceArgs {
            id: "9A7F6B4A-1111-2222-3333-444444444444".into(),
            alias: "box2".into(),
        }),
    )]
    fn test_alias_second_name_for_one_resource_failure(
        #[case] seed: fn(&MockConsole),
        #[case] kind: AliasKind,
        #[case] id: &str,
        #[case] command: AliasCommand,
    ) {
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        seed(&console);
        let mut store = Aliases::default();
        store.insert_resource(kind, "box".into(), id.into());
        save(&config.config_dir, &store).expect("seed store");

        assert_eq!(run(command, &config, false) as u8, 1);
        assert_eq!(
            load(&config.config_dir).unwrap(),
            store,
            "the store must be left exactly as it was"
        );
    }

    /// The same refusal for a SESSION, whose target is the `{ session, cvm }` pair:
    /// `alias session` rejects before it probes the CVM (the pre-lock check runs ahead
    /// of `list_session_names`, and `select_cvm` is purely local), so this needs
    /// neither SSH nor a Console. `non_canonical` passes the SAME CVM in UPPERCASE
    /// through `--cvm`: `select_cvm` hands a raw UUID straight through, so without
    /// `canonical_id` the pair would not match the stored one.
    #[rstest]
    #[case::canonical(CVM_ID)]
    #[case::non_canonical("9A7F6B4A-1111-2222-3333-444444444444")]
    fn test_alias_session_second_name_failure(#[case] cvm: &str) {
        let config = local_config();
        let mut store = Aliases::default();
        store.insert_session("dev".into(), "agent-1".into(), CVM_ID.into());
        save(&config.config_dir, &store).expect("seed store");

        let status = run(
            AliasCommand::Session(AliasSessionArgs {
                name: "agent-1".into(),
                alias: "dev2".into(),
                cvm: Some(cvm.into()),
                identity_file: None,
            }),
            &config,
            false,
        );
        assert_eq!(status as u8, 1);
        assert_eq!(
            load(&config.config_dir).unwrap(),
            store,
            "the store must be left exactly as it was"
        );
    }

    /// The `--alias`-at-creation paths enforce the rule too, at their write: they are
    /// the ONLY place it runs for `cvm launch`/`profile create`/`key add --alias` and
    /// `ssh|claude|codex --alias`, since those check the name up front with no target
    /// (the resource does not exist yet). Both record helpers are exercised, each with
    /// a non-canonical id, and both must refuse without touching the store.
    #[test]
    fn test_record_alias_second_name_failure() {
        let config = local_config();
        let mut store = Aliases::default();
        store.insert_resource(AliasKind::Cvm, "box".into(), CVM_ID.into());
        store.insert_session("dev".into(), "agent-1".into(), CVM_ID.into());
        save(&config.config_dir, &store).expect("seed store");
        let shouty = CVM_ID.to_ascii_uppercase();

        assert!(record_resource_alias(&config, AliasKind::Cvm, &shouty, "box2").is_err());
        assert!(record_session_alias(&config, "agent-1", &shouty, "dev2").is_err());
        assert_eq!(
            load(&config.config_dir).unwrap(),
            store,
            "a refused record must not touch the store"
        );
    }

    /// The absent-resource failure carries a clear "not found" message. Checked
    /// at `ensure_resource_exists`, which returns it — `run` only prints it to
    /// stderr and returns the exit status, so it can't be read back from `run`.
    #[rstest]
    #[case::cvm(
        |c: &MockConsole| c.get_cvm(CVM_ID, Presence::Absent),
        AliasKind::Cvm, CVM_ID, "NOT_FOUND",
    )]
    #[case::profile(
        |c: &MockConsole| c.get_profile(PROFILE_ID, Presence::Absent),
        AliasKind::Profile, PROFILE_ID, "NOT_FOUND",
    )]
    #[case::ssh_key(
        |c: &MockConsole| c.list_keys(&[]),
        AliasKind::SshKey, KEY_ID, "was not found",
    )]
    fn test_missing_resource_error_message_failure(
        #[case] seed: fn(&MockConsole),
        #[case] kind: AliasKind,
        #[case] id: &str,
        #[case] expected: &str,
    ) {
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        seed(&console);
        let (_, message) = ensure_resource_exists(kind, &config, id).unwrap_err();
        assert!(message.contains(expected), "message: {message}");
    }

    // --- `alias prune` reconciliation (the real command) --------------------

    // One live + one dead target per Console-backed kind, plus an absent CVM
    // hosting the dangling session (so it prunes with NO SSH probe — a session
    // is only SSH-probed when its CVM is running). The mock returns only the
    // live ids, so every `*-dead` alias below is stale.
    const LIVE_CVM: &str = "11111111-1111-1111-1111-111111111111";
    const DEAD_CVM: &str = "22222222-2222-2222-2222-222222222222";
    const LIVE_PROFILE: &str = "33333333-3333-3333-3333-333333333333";
    const DEAD_PROFILE: &str = "44444444-4444-4444-4444-444444444444";
    const LIVE_KEY: &str = "55555555-5555-5555-5555-555555555555";
    const DEAD_KEY: &str = "66666666-6666-6666-6666-666666666666";
    const SESSION_CVM: &str = "77777777-7777-7777-7777-777777777777";

    /// Seed a rich `alias.toml` in `config`'s dir and register the matching mock
    /// live-sets: one live + one dead alias per kind, plus a session bound to an
    /// absent CVM. Returns the seeded store so a dry run can assert the file is
    /// byte-for-byte unchanged.
    fn seed_prune_scenario(console: &MockConsole, config: &ResolvedConfig) -> Aliases {
        let mut a = Aliases::default();
        a.cvm.insert("cvm-live".into(), LIVE_CVM.into());
        a.cvm.insert("cvm-dead".into(), DEAD_CVM.into());
        a.profile.insert("prof-live".into(), LIVE_PROFILE.into());
        a.profile.insert("prof-dead".into(), DEAD_PROFILE.into());
        a.ssh_key.insert("key-live".into(), LIVE_KEY.into());
        a.ssh_key.insert("key-dead".into(), DEAD_KEY.into());
        a.session.insert(
            "sess-dead".into(),
            SessionAlias {
                session: "agent-1".into(),
                cvm: SESSION_CVM.into(),
            },
        );
        save(&config.config_dir, &a).expect("seed store");
        console.list_cvms(Some("alive"), &[LIVE_CVM]);
        console.list_profiles(&[LIVE_PROFILE]);
        console.list_keys(&[LIVE_KEY]);
        a
    }

    /// `alias prune --dry-run` reports stale aliases but writes NOTHING: for
    /// every kind the stale `*-dead` alias is still on disk afterward and the
    /// store is byte-for-byte the seeded one.
    #[rstest]
    #[case::cvm("cvm-dead")]
    #[case::profile("prof-dead")]
    #[case::ssh_key("key-dead")]
    #[case::session("sess-dead")]
    fn test_alias_prune_dry_run_keeps_store_success(#[case] stale: &str) {
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        let original = seed_prune_scenario(&console, &config);
        let status = run(
            AliasCommand::Prune(AliasPruneArgs {
                dry_run: true,
                identity_file: None,
            }),
            &config,
            false,
        );
        assert!(matches!(status, ExitStatus::Ok));
        let reloaded = load(&config.config_dir).unwrap();
        assert!(
            reloaded.kind_of(stale).is_some(),
            "{stale} must survive a dry run"
        );
        assert_eq!(reloaded, original, "a dry run must not rewrite the store");
    }

    /// `alias prune` (no dry-run) removes exactly the stale `*-dead` alias of the
    /// tested kind and keeps that kind's live alias — the on-disk store reflects
    /// the reconciliation. The session case has no live counterpart: a live
    /// session needs a real SSH probe, which is out of unit-test scope.
    #[rstest]
    #[case::cvm("cvm-dead", Some("cvm-live"))]
    #[case::profile("prof-dead", Some("prof-live"))]
    #[case::ssh_key("key-dead", Some("key-live"))]
    #[case::session("sess-dead", None)]
    fn test_alias_prune_removes_stale_success(#[case] stale: &str, #[case] live: Option<&str>) {
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        let original = seed_prune_scenario(&console, &config);
        let status = run(
            AliasCommand::Prune(AliasPruneArgs {
                dry_run: false,
                identity_file: None,
            }),
            &config,
            false,
        );
        assert!(matches!(status, ExitStatus::Ok));
        let reloaded = load(&config.config_dir).unwrap();
        assert!(reloaded.kind_of(stale).is_none(), "{stale} must be pruned");
        assert_ne!(reloaded, original, "the store on disk must have changed");
        if let Some(live) = live {
            assert!(reloaded.kind_of(live).is_some(), "{live} must be kept");
        }
    }

    // --- `alias rename` --------------------

    /// A `ResolvedConfig` on a throwaway config dir with no Console — the fixture
    /// for the store-only commands (`rename`, `rm`) that never talk to the
    /// Console, so they need neither a `MockConsole` nor a written session.
    fn local_config() -> ResolvedConfig {
        let dir = std::env::temp_dir().join(format!("umbra-alias-test-{}", uuid::Uuid::new_v4()));
        crate::config::ResolvedConfig::resolve(crate::config::ConfigOverrides {
            config_dir: Some(dir),
            ..Default::default()
        })
    }

    /// `alias rename <old> <new>` moves a UUID-backed alias to the new name while
    /// keeping its target untouched. These kinds are purely local (no probe). Each
    /// `#[case]` seeds one alias of a kind under a given name; the resulting
    /// `aliases.toml` must be byte-for-byte the file you get by seeding the same
    /// alias directly under `new` — i.e. only the key changed and the target
    /// survived. (The session kind additionally probes its CVM, so it has its own
    /// test, [`test_alias_rename_session_success`].)
    #[rstest]
    #[case::cvm(|a: &mut Aliases, name: &str| {
        a.cvm.insert(name.into(), CVM_ID.into());
    })]
    #[case::profile(|a: &mut Aliases, name: &str| {
        a.profile.insert(name.into(), PROFILE_ID.into());
    })]
    #[case::ssh_key(|a: &mut Aliases, name: &str| {
        a.ssh_key.insert(name.into(), KEY_ID.into());
    })]
    fn test_alias_rename_success(#[case] seed: fn(&mut Aliases, &str)) {
        let config = local_config();
        let mut store = Aliases::default();
        seed(&mut store, "old-name");
        save(&config.config_dir, &store).expect("seed store");

        let status = run(
            AliasCommand::Rename(AliasRenameArgs {
                old: "old-name".into(),
                new: "new-name".into(),
                identity_file: None,
            }),
            &config,
            false,
        );
        assert!(matches!(status, ExitStatus::Ok));

        // Expected raw toml: the same alias seeded directly under the new name.
        let expected_config = local_config();
        let mut expected = Aliases::default();
        seed(&mut expected, "new-name");
        save(&expected_config.config_dir, &expected).expect("seed expected store");

        assert_eq!(
            fs::read_to_string(store_path(&config.config_dir)).unwrap(),
            fs::read_to_string(store_path(&expected_config.config_dir)).unwrap(),
            "rename must only change the key in the toml, keeping the target"
        );
    }

    /// Renaming a SESSION alias when the anti-shadow probe can't run (the CVM is
    /// unreachable — no SSH in a unit test) warns and proceeds rather than blocking:
    /// the rename succeeds and the session alias moves to the new name, target
    /// intact. (A successful probe that finds a real collision rejects instead — that
    /// path needs a live SSH session, out of unit-test scope.)
    #[test]
    fn test_alias_rename_session_success() {
        let console = MockConsole::start();
        let config = authenticated_config(&console);
        let mut store = Aliases::default();
        store.insert_session("old-name".into(), "agent-1".into(), CVM_ID.into());
        save(&config.config_dir, &store).expect("seed store");

        let status = run(
            AliasCommand::Rename(AliasRenameArgs {
                old: "old-name".into(),
                new: "new-name".into(),
                identity_file: None,
            }),
            &config,
            false,
        );
        assert!(matches!(status, ExitStatus::Ok));

        let reloaded = load(&config.config_dir).unwrap();
        assert!(reloaded.kind_of("old-name").is_none(), "old name is gone");
        assert_eq!(
            reloaded.resolve_session("new-name"),
            Some(&SessionAlias {
                session: "agent-1".into(),
                cvm: CVM_ID.into(),
            }),
            "the session alias moved to the new name, target untouched"
        );
    }

    /// `alias rename` refuses and writes NOTHING when `old` is unknown, when
    /// `new` is already taken by any kind, or when `new` is not a valid alias
    /// name (a UUID here). Each case seeds a store, then asserts the command
    /// fails and the on-disk store is byte-for-byte unchanged.
    #[rstest]
    #[case::old_not_found(
        |a: &mut Aliases| { a.cvm.insert("box".into(), CVM_ID.into()); },
        "ghost", "fresh",
    )]
    #[case::new_taken(
        |a: &mut Aliases| {
            a.cvm.insert("box".into(), CVM_ID.into());
            a.profile.insert("taken".into(), PROFILE_ID.into());
        },
        "box", "taken",
    )]
    #[case::new_is_uuid(
        |a: &mut Aliases| { a.cvm.insert("box".into(), CVM_ID.into()); },
        "box", "9a7f6b4a-1111-2222-3333-444444444444",
    )]
    fn test_alias_rename_failure(
        #[case] seed: fn(&mut Aliases),
        #[case] old: &str,
        #[case] new: &str,
    ) {
        let config = local_config();
        let mut store = Aliases::default();
        seed(&mut store);
        save(&config.config_dir, &store).expect("seed store");
        let toml = store_path(&config.config_dir);
        let before = fs::read_to_string(&toml).unwrap();

        let status = run(
            AliasCommand::Rename(AliasRenameArgs {
                old: old.into(),
                new: new.into(),
                identity_file: None,
            }),
            &config,
            false,
        );
        assert!(!matches!(status, ExitStatus::Ok));
        assert_eq!(
            fs::read_to_string(&toml).unwrap(),
            before,
            "a failed rename must not rewrite the toml"
        );
    }

    // --- `alias rm` ------------------------

    /// A rich `aliases.toml` on disk: one alias per kind (`kcvm`/`kprofile`/
    /// `kkey`/`ksession`) plus a `keeper` cvm alias that no `rm` case touches, so
    /// a removal can be shown to be targeted, not a wipe.
    fn seed_rm_store(config: &ResolvedConfig) {
        let mut store = Aliases::default();
        store.cvm.insert("kcvm".into(), CVM_ID.into());
        // A second CVM, not a second alias for the first: one resource, one alias.
        store.cvm.insert("keeper".into(), LIVE_CVM.into());
        store.profile.insert("kprofile".into(), PROFILE_ID.into());
        store.ssh_key.insert("kkey".into(), KEY_ID.into());
        store.session.insert(
            "ksession".into(),
            SessionAlias {
                session: "agent-1".into(),
                cvm: CVM_ID.into(),
            },
        );
        save(&config.config_dir, &store).expect("seed store");
    }

    /// `alias rm <name>` removes the named alias whatever its kind (names are
    /// globally unique). Read back the raw `aliases.toml`: the removed name is
    /// gone from the file and the untouched `keeper` alias is still there. One
    /// `#[case]` per kind.
    #[rstest]
    #[case::cvm("kcvm")]
    #[case::profile("kprofile")]
    #[case::ssh_key("kkey")]
    #[case::session("ksession")]
    fn test_alias_rm_success(#[case] victim: &str) {
        let config = local_config();
        seed_rm_store(&config);
        let toml = store_path(&config.config_dir);
        assert!(
            fs::read_to_string(&toml).unwrap().contains(victim),
            "fixture must contain {victim} before removal"
        );

        let status = run(
            AliasCommand::Rm(AliasNameArgs {
                alias: victim.into(),
            }),
            &config,
            false,
        );
        assert!(matches!(status, ExitStatus::Ok));

        let after = fs::read_to_string(&toml).unwrap();
        assert!(
            !after.contains(victim),
            "{victim} must be gone from the toml"
        );
        assert!(
            after.contains("keeper"),
            "untouched aliases must remain in the toml"
        );
    }

    /// `alias rm` on a name absent from the store fails and leaves the
    /// `aliases.toml` byte-for-byte unchanged.
    #[test]
    fn test_alias_rm_failure() {
        let config = local_config();
        seed_rm_store(&config);
        let toml = store_path(&config.config_dir);
        let before = fs::read_to_string(&toml).unwrap();

        let status = run(
            AliasCommand::Rm(AliasNameArgs {
                alias: "ghost".into(),
            }),
            &config,
            false,
        );
        assert!(!matches!(status, ExitStatus::Ok));
        assert_eq!(
            fs::read_to_string(&toml).unwrap(),
            before,
            "a failed rm must not rewrite the toml"
        );
    }

    // --- `alias list` (rendering) -------------------------------------------

    /// A store spanning every kind, so `alias list` rendering can be exercised
    /// across all sections. The session is bound to `box`'s CVM so the human view
    /// can be shown resolving the CVM to its alias.
    fn list_store() -> Aliases {
        let mut a = Aliases::default();
        a.cvm.insert("box".into(), CVM_ID.into());
        a.profile.insert("prof".into(), PROFILE_ID.into());
        a.ssh_key.insert("laptop".into(), KEY_ID.into());
        a.session.insert(
            "dev".into(),
            SessionAlias {
                session: "agent-1".into(),
                cvm: CVM_ID.into(),
            },
        );
        a
    }

    /// `alias list --json` emits the whole store as its pretty-JSON payload: it
    /// parses back into the identical `Aliases` and carries the renamed
    /// `ssh-key` wire key.
    #[test]
    fn test_alias_list_json_success() {
        let store = list_store();
        let json = render_alias_list(&store, true);
        assert!(
            json.contains("ssh-key"),
            "wire key must be `ssh-key`, json={json}"
        );
        assert_eq!(
            serde_json::from_str::<Aliases>(&json).unwrap(),
            store,
            "the --json payload must round-trip to the full store"
        );
    }

    /// `alias list` (human) groups by kind with `>`-prefixed section headers, the
    /// three-column session group carries an `alias  session  cvm` column header,
    /// and a session row resolves its CVM to that CVM's alias (`box`) rather than
    /// the raw UUID.
    #[test]
    fn test_alias_list_human_success() {
        style::init(false); // deterministic: no ANSI colour codes to match around
        let out = render_alias_list(&list_store(), false);
        for header in ["> cvm", "> profile", "> ssh-key", "> session"] {
            assert!(out.contains(header), "missing section {header}\n{out}");
        }
        // Only the session group is labelled; its column header sits between the
        // `> session` title and the first session row.
        let lines: Vec<&str> = out.lines().collect();
        let session_title = lines.iter().position(|l| *l == "> session").unwrap();
        assert_eq!(
            lines[session_title + 1]
                .split_whitespace()
                .collect::<Vec<_>>(),
            ["alias", "session", "cvm"],
            "session group must carry a column header row\n{out}"
        );
        // The session row shows the session name and resolves its CVM to that
        // CVM's alias (`box`), not the raw UUID. (The UUID does appear elsewhere,
        // as the `box` cvm row's target, so scope the check to the session line.)
        let session_line = out
            .lines()
            .find(|line| line.contains("dev"))
            .expect("session row present");
        assert!(session_line.contains("agent-1"), "line: {session_line}");
        assert!(session_line.contains("box"), "line: {session_line}");
        assert!(
            !session_line.contains(CVM_ID),
            "session CVM must show as its alias, not the UUID: {session_line}"
        );
    }

    /// `alias list` on an empty store renders the plain empty-state line.
    #[test]
    fn test_alias_list_empty_success() {
        style::init(false);
        assert_eq!(render_alias_list(&Aliases::default(), false), "no aliases");
    }

    // --- `resolve_or_passthrough` (alias -> id funnel) ----------------------

    /// With a valid store, a known alias resolves to its id and a raw UUID passes
    /// straight through untouched (even when the store holds other aliases). The
    /// `non_canonical_target` case pins `canonicalize_targets`: `alias <kind> <ID>`
    /// stores the id as typed and `validate_uuid` accepts uppercase / braced /
    /// unhyphenated forms, so without normalisation on load that alias would resolve
    /// to a string no Console id equals — and the reverse lookup behind the `alias`
    /// card row would render `-` ("no alias") for a record that has one.
    #[rstest]
    #[case::known_alias("box", CVM_ID)]
    #[case::raw_uuid(PROFILE_ID, PROFILE_ID)]
    #[case::non_canonical_target("shouty", LIVE_CVM)]
    fn test_resolve_or_passthrough_success(#[case] value: &str, #[case] expected: &str) {
        let config = local_config();
        let mut store = Aliases::default();
        store.cvm.insert("box".into(), CVM_ID.into());
        // A DIFFERENT CVM, written non-canonically: one resource still holds one alias.
        store
            .cvm
            .insert("shouty".into(), LIVE_CVM.to_ascii_uppercase());
        save(&config.config_dir, &store).expect("seed store");
        assert_eq!(
            resolve_or_passthrough(&config, AliasKind::Cvm, value).unwrap(),
            expected
        );
    }

    /// Guard-rail: a raw UUID is returned untouched WITHOUT reading the store, so
    /// a corrupt `aliases.toml` never blocks a command driven by a real id.
    #[test]
    fn test_resolve_or_passthrough_corrupt_store_success() {
        let config = local_config();
        fs::create_dir_all(&config.config_dir).unwrap();
        fs::write(store_path(&config.config_dir), "not valid toml @@@ {{{").unwrap();
        assert_eq!(
            resolve_or_passthrough(&config, AliasKind::Cvm, CVM_ID).unwrap(),
            CVM_ID
        );
    }

    /// A non-UUID value DOES consult the store, so a corrupt file surfaces as an
    /// error instead of being silently ignored.
    #[test]
    fn test_resolve_or_passthrough_corrupt_store_failure() {
        let config = local_config();
        fs::create_dir_all(&config.config_dir).unwrap();
        fs::write(store_path(&config.config_dir), "not valid toml @@@ {{{").unwrap();
        assert!(resolve_or_passthrough(&config, AliasKind::Cvm, "box").is_err());
    }
}
