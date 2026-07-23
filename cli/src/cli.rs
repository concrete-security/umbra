use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    name = "concrete",
    version,
    about = "Command-line client for the Concrete platform",
    subcommand_required = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Increase diagnostic logging on stderr (-v INFO, -vv DEBUG, -vvv TRACE; default WARN).
    #[arg(short, long, action = clap::ArgAction::Count, global = true, hide = true)]
    pub verbose: u8,

    /// Disable color output.
    #[arg(long, global = true, hide = true)]
    pub no_color: bool,

    /// Output JSON when supported by the command.
    #[arg(long, global = true, hide = true)]
    pub json: bool,

    /// Use a different Concrete config directory.
    #[arg(long, global = true, hide = true)]
    pub config: Option<PathBuf>,

    /// Use a different Console base URL.
    #[arg(long, global = true, hide = true)]
    pub console_url: Option<String>,

    /// Use a different profile for this command. Repeat for commands that accept many profiles.
    #[arg(long, global = true, hide = true, value_name = "PROFILE_ID|alias")]
    pub profile: Vec<String>,

    /// Set the request id sent to the Console.
    #[arg(long, global = true, hide = true)]
    pub request_id: Option<String>,

    /// Bypass concurrency checks on supported update commands.
    #[arg(long, global = true, hide = true)]
    pub force: bool,

    /// Use a different aTLS policy file for tunnels.
    #[arg(long, global = true, hide = true)]
    pub atls_policy: Option<PathBuf>,

    /// Skip aTLS policy verification for this command (dev only).
    #[arg(long, global = true, hide = true)]
    pub insecure_skip_atls_policy: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Run platform operator maintenance commands.
    #[command(subcommand)]
    Admin(AdminCommand),

    /// Manage local aliases for CVMs, profiles, SSH keys, and sessions.
    #[command(subcommand)]
    Alias(AliasCommand),

    /// Log in, log out, and inspect your local session.
    #[command(subcommand)]
    Auth(AuthCommand),

    /// Attach to a dtach session on a Dev CVM.
    Attach(SessionTargetArgs),

    /// Start or reopen a Claude session on a Dev CVM.
    Claude(AgentSessionArgs),

    /// Print a shell-completion script.
    Completions {
        /// Shell to generate completions for.
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },

    /// Start or reopen a Codex session on a Dev CVM.
    Codex(AgentSessionArgs),

    /// Open VS Code connected to the selected Dev CVM.
    Code(CodeArgs),

    /// Inspect resolved local configuration.
    #[command(subcommand)]
    Config(ConfigCommand),

    /// Query and verify Console audit records.
    #[command(subcommand)]
    Audit(AuditCommand),

    /// Manage tenant entities.
    #[command(subcommand)]
    Entity(EntityCommand),

    /// Launch and manage Dev CVMs.
    #[command(subcommand)]
    Cvm(CvmCommand),

    /// Open Cursor connected to the selected Dev CVM.
    Cursor(CursorArgs),

    /// Manage SSH public keys.
    #[command(subcommand)]
    Key(KeyCommand),

    /// Kill a dtach session on a Dev CVM.
    Kill(SessionTargetArgs),

    /// Manage profiles and profile membership.
    #[command(subcommand)]
    Profile(ProfileCommand),

    /// List active dtach sessions across your running Dev CVMs.
    Ps(SessionListArgs),

    /// Manage entity and user quotas.
    #[command(subcommand)]
    Quota(QuotaCommand),

    /// Run one Console reconciliation pass.
    Reconcile(ReconcileArgs),

    /// Inspect and manage the entity Security CVM.
    #[command(subcommand)]
    SecurityCvm(SecurityCvmCommand),

    /// Install the Concrete skill for local AI coding agents.
    #[command(subcommand)]
    Skill(SkillCommand),

    /// Show your current entity, session, and visible resources.
    Status,

    /// Open an SSH session to the selected Dev CVM.
    Ssh(SshArgs),

    /// Query egress traffic logs.
    TrafficLogs(TrafficLogsArgs),

    /// Open an attested tunnel to a Dev CVM.
    Tunnel {
        /// Dev CVM FQDN to connect to.
        #[arg(value_name = "FQDN")]
        target: String,
    },

    /// Manage users and user permissions.
    #[command(subcommand)]
    User(UserCommand),

    /// Print version and build information.
    Version,
}

#[derive(Subcommand, Debug)]
pub enum AdminCommand {
    /// Force-revoke Console sessions by predicate.
    #[command(subcommand)]
    Sessions(AdminSessionsCommand),

    /// Manage Console JWT signing keys.
    #[command(subcommand)]
    Keys(AdminKeysCommand),
}

#[derive(Subcommand, Debug)]
pub enum AdminSessionsCommand {
    /// Revoke sessions matching the supplied filters.
    Revoke(AdminSessionsRevokeArgs),
}

#[derive(clap::Args, Debug)]
pub struct AdminSessionsRevokeArgs {
    /// Revoke sessions for this user UUID only.
    #[arg(long)]
    pub user: Option<String>,

    /// Revoke sessions for this entity UUID only.
    #[arg(long)]
    pub entity: Option<String>,

    /// Revoke sessions issued before this RFC3339 timestamp.
    #[arg(long)]
    pub issued_before: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum AdminKeysCommand {
    /// Rotate the Console JWT signing key.
    Rotate(AdminKeysRotateArgs),
}

#[derive(Subcommand, Debug)]
pub enum ConfigCommand {
    /// Show the fully resolved configuration.
    Show,
}

#[derive(clap::Args, Debug)]
pub struct AdminKeysRotateArgs {
    /// New active JWT signing key id.
    #[arg(long)]
    pub new_kid: String,

    /// Seconds to retain the previous key for verification.
    #[arg(long, default_value_t = 3600, value_parser = clap::value_parser!(u32).range(0..=86400))]
    pub retire_old_after_seconds: u32,
}

#[derive(clap::Args, Debug)]
pub struct ReconcileArgs {
    /// Skip Cloudflare orphan cleanup during the pass.
    #[arg(long)]
    pub no_orphans: bool,
}

#[derive(Subcommand, Debug)]
pub enum AuditCommand {
    /// Query control-plane audit events.
    Events(AuditEventsArgs),

    /// Submit a bulk audit export.
    Export(AuditExportArgs),
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

#[derive(clap::Args, Debug)]
pub struct AuditExportArgs {
    /// Export format: csv or ndjson.
    #[arg(long)]
    pub format: String,

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

    /// Download the completed artifact to this path.
    #[arg(long)]
    pub output: Option<PathBuf>,

    #[command(flatten)]
    pub wait: WaitArgs,
}

#[derive(Subcommand, Debug)]
pub enum EntityCommand {
    /// Create a tenant entity.
    Add(EntityAddArgs),

    /// List tenant entities.
    List(EntityListArgs),
}

#[derive(clap::Args, Debug)]
pub struct EntityAddArgs {
    /// Entity domain.
    pub domain: String,

    /// Entity display name.
    #[arg(long)]
    pub name: String,
}

#[derive(clap::Args, Debug)]
pub struct EntityListArgs {
    /// Page size, 1..500.
    #[arg(long, default_value_t = 100)]
    pub limit: u16,

    /// Opaque pagination cursor from the previous response.
    #[arg(long)]
    pub cursor: Option<String>,
}

/// The `concrete cvm` subcommands. Each variant is one subcommand.
#[derive(Subcommand, Debug)]
pub enum CvmCommand {
    /// List Dev CVMs visible to the current user.
    List(CvmListArgs),

    /// List the launchable instance types (vCPU, memory, hourly rate).
    InstanceTypes(CvmInstanceTypesArgs),

    /// Launch a Dev CVM.
    Launch(CvmLaunchArgs),

    /// Attach a profile to a Dev CVM.
    Attach {
        #[command(flatten)]
        target: CvmTarget,
    },

    /// Detach a profile from a Dev CVM.
    Detach {
        #[command(flatten)]
        target: CvmTarget,
    },

    /// Start a stopped Dev CVM.
    Start {
        #[command(flatten)]
        target: CvmTarget,
    },

    /// Stop a running Dev CVM. Requires an explicit id (positional or --cvm).
    Stop {
        #[command(flatten)]
        target: CvmTarget,
    },

    /// Update an existing Dev CVM in place.
    Update(CvmUpdateArgs),

    /// Terminate a Dev CVM.
    Terminate(CvmTerminateArgs),
}

/// Arguments for the `concrete cvm list` subcommand. The `--state` flag is
/// optional: `concrete cvm list` lists all non-terminated CVMs, while
/// `concrete cvm list --state <STATE>` keeps only CVMs in that state.
#[derive(clap::Args, Debug)]
pub struct CvmListArgs {
    /// Show only CVMs in this lifecycle state. Default: alive (non-terminated).
    #[arg(long, value_enum)]
    pub state: Option<CvmStateFilter>,
}

/// Arguments for the `concrete cvm instance-types` subcommand. The normal read
/// is served from the Console catalog cache; `--refresh` asks the Console to
/// perform one explicit provider refresh (slower, may fail) before answering.
#[derive(clap::Args, Debug)]
pub struct CvmInstanceTypesArgs {
    /// Refresh the catalog from the provider before listing.
    #[arg(long)]
    pub refresh: bool,
}

/// The string clap accepts for a `--flag` enum value and the Console expects as
/// its query parameter -- clap's own lowercase variant name.
///
/// `wire(Assigned::Yes) -> "yes"`   `wire(CvmStateFilter::Terminated) -> "terminated"`
pub fn wire<T: ValueEnum>(value: T) -> String {
    value
        .to_possible_value()
        .expect("filter enums declare no `#[value(skip)]` variant")
        .get_name()
        .to_owned()
}

/// States accepted by the `concrete cvm list --state` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CvmStateFilter {
    Provisioning,
    Running,
    Stopped,
    Failed,
    Terminated,
    /// All non-terminated CVMs (the default).
    Alive,
    /// Every state, including terminated.
    All,
}

/// Values accepted by the `--assigned` flag on `concrete profile list` and
/// `concrete user list`. Shared because both filter on membership.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Assigned {
    Yes,
    No,
}

#[derive(clap::Args, Debug)]
pub struct CvmLaunchArgs {
    /// SSH key UUID to install; repeat for several.
    #[arg(long = "ssh-key")]
    pub ssh_keys: Vec<String>,

    /// Assign a local alias to the launched CVM.
    #[arg(long)]
    pub alias: Option<String>,

    /// Instance type (vCPU/RAM); see `concrete cvm instance-types`.
    #[arg(long)]
    pub instance_type: Option<String>,

    /// CVM region.
    #[arg(long)]
    pub region: Option<String>,

    /// Disk size in GB.
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1_048_576))]
    pub disk_size: Option<u32>,

    #[command(flatten)]
    pub wait: WaitArgs,
}

#[derive(clap::Args, Debug)]
pub struct CvmTerminateArgs {
    #[command(flatten)]
    pub target: CvmTarget,

    #[command(flatten)]
    pub wait: WaitArgs,
}

#[derive(clap::Args, Debug)]
pub struct CvmUpdateArgs {
    #[command(flatten)]
    pub target: CvmTarget,

    #[command(flatten)]
    pub wait: WaitArgs,
}

/// The Dev CVM a verb acts on: positional `<CVM_ID>` or `--cvm` (the positional
/// wins). Flattened into every verb that targets a single CVM so `<id>` and `--cvm`
/// mean the same thing everywhere. What "omitted" means is per-verb: most fall back
/// to `CONCRETE_DEFAULT_CVM`/`default_cvm`, `stop`/`terminate` require an explicit
/// id, and `ps` lists every running CVM.
#[derive(clap::Args, Debug)]
pub struct CvmTarget {
    /// Target Dev CVM, by UUID or alias (or use --cvm).
    #[arg(value_name = "CVM_ID|alias")]
    pub cvm_id: Option<String>,

    /// Target Dev CVM (UUID or alias); alternative to the positional.
    #[arg(long, value_name = "CVM_ID|alias")]
    pub cvm: Option<String>,
}

/// The `--no-wait` / `--wait-timeout-seconds` pair shared by every command that
/// submits an async Console Operation (`cvm launch`/`update`/`terminate`,
/// `audit export`, `security-cvm launch`/`update`). Flattened so the default and
/// range stay identical across all of them.
#[derive(clap::Args, Debug)]
pub struct WaitArgs {
    /// Return the operation handle without polling.
    #[arg(long)]
    pub no_wait: bool,

    /// Maximum seconds to wait for the operation.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u32).range(1..=86400))]
    pub wait_timeout_seconds: u32,
}

#[derive(clap::Args, Debug)]
pub struct SshArgs {
    #[command(flatten)]
    pub target: CvmTarget,

    /// Start or attach the named dtach session.
    #[arg(long)]
    pub name: Option<String>,

    /// Private SSH key to pass to ssh.
    #[arg(long)]
    pub identity_file: Option<PathBuf>,

    /// Remote command to execute directly instead of opening a dtach shell.
    #[arg(long)]
    pub command: Option<String>,

    /// Assign a local alias to the started session (see `concrete alias`).
    #[arg(long)]
    pub alias: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct AgentSessionArgs {
    #[command(flatten)]
    pub target: CvmTarget,

    /// Start or attach the named dtach session.
    #[arg(long)]
    pub name: Option<String>,

    /// Private SSH key to pass to ssh.
    #[arg(long)]
    pub identity_file: Option<PathBuf>,

    /// Working directory on the Dev CVM, for example ~/workspaces/myrepo.
    #[arg(long)]
    pub workspace: Option<String>,

    /// Save a local alias for the session.
    #[arg(long)]
    pub alias: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct CodeArgs {
    #[command(flatten)]
    pub target: CvmTarget,

    /// VS Code binary to invoke. Default: code (on PATH).
    #[arg(long)]
    pub code_bin: Option<PathBuf>,

    /// Working directory for the editor on the Dev CVM, for example ~/workspaces/myrepo.
    #[arg(long)]
    pub workspace: Option<String>,

    /// Private SSH key to pass to ssh as IdentityFile when launching the editor.
    #[arg(long)]
    pub identity_file: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct CursorArgs {
    #[command(flatten)]
    pub target: CvmTarget,

    /// Cursor binary to invoke. Default: cursor (on PATH).
    #[arg(long)]
    pub cursor_bin: Option<PathBuf>,

    /// Working directory for the editor on the Dev CVM, for example ~/workspaces/myrepo.
    #[arg(long)]
    pub workspace: Option<String>,

    /// Private SSH key to pass to ssh as IdentityFile when launching the editor.
    #[arg(long)]
    pub identity_file: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct SessionListArgs {
    #[command(flatten)]
    pub target: CvmTarget,

    /// Private SSH key to pass to ssh.
    #[arg(long)]
    pub identity_file: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct SessionTargetArgs {
    /// dtach session name or client-side alias.
    #[arg(value_name = "SESSION|alias")]
    pub target: String,

    /// Target Dev CVM (UUID or alias). Default: the persisted default CVM.
    #[arg(long)]
    pub cvm: Option<String>,

    /// Private SSH key to pass to ssh.
    #[arg(long)]
    pub identity_file: Option<PathBuf>,
}

/// `concrete alias <kind> ...` — give a short local name to a long identifier
/// and use it anywhere the CLI expects that identifier.
#[derive(clap::Subcommand, Debug)]
pub enum AliasCommand {
    /// Alias a Dev CVM UUID.
    Cvm(AliasResourceArgs),

    /// Alias a profile UUID.
    Profile(AliasResourceArgs),

    /// Alias a registered SSH key UUID.
    #[command(name = "ssh-key")]
    SshKey(AliasResourceArgs),

    /// Alias a dtach session on a Dev CVM.
    Session(AliasSessionArgs),

    /// List every alias.
    List,

    /// Remove an alias by name.
    Rm(AliasNameArgs),

    /// Rename an existing alias, keeping what it points at.
    Rename(AliasRenameArgs),

    /// Remove aliases whose target no longer exists (reconcile against reality).
    Prune(AliasPruneArgs),
}

#[derive(clap::Args, Debug)]
pub struct AliasResourceArgs {
    /// Resource UUID to alias.
    pub id: String,

    /// Alias to assign.
    pub alias: String,
}

#[derive(clap::Args, Debug)]
pub struct AliasSessionArgs {
    /// dtach session name as reported by concrete ps.
    pub name: String,

    /// Alias to assign.
    pub alias: String,

    /// Target Dev CVM (UUID or alias). Default: the persisted default CVM.
    #[arg(long)]
    pub cvm: Option<String>,

    /// Private SSH key to pass to ssh while checking the session exists.
    #[arg(long)]
    pub identity_file: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct AliasNameArgs {
    /// Alias name.
    pub alias: String,
}

#[derive(clap::Args, Debug)]
pub struct AliasRenameArgs {
    /// Existing alias name.
    pub old: String,

    /// New alias name.
    pub new: String,
}

#[derive(clap::Args, Debug)]
pub struct AliasPruneArgs {
    /// Show what would be removed without changing anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Private SSH key to pass to ssh while probing session aliases.
    #[arg(long)]
    pub identity_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum KeyCommand {
    /// List SSH public keys registered by the current user.
    List,

    /// Register an SSH public key.
    Add(KeyAddArgs),

    /// Deregister an SSH public key.
    Remove {
        /// Key UUID from `concrete key list`.
        key_id: String,
    },
}

#[derive(clap::Args, Debug)]
pub struct KeyAddArgs {
    /// Human-readable key label.
    #[arg(long)]
    pub label: String,

    /// Path to an OpenSSH public key file. Reads stdin when omitted.
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// Private SSH key file to remember locally for this registered public key.
    #[arg(long)]
    pub identity_file: Option<PathBuf>,

    /// Assign a local alias to the registered key (see `concrete alias`).
    #[arg(long)]
    pub alias: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ProfileCommand {
    /// Create a profile in the current entity.
    Create(ProfileCreateArgs),

    /// List profiles visible to the current user.
    List(ProfileListArgs),

    /// Show the selected profile.
    Show,

    /// Update the selected profile.
    Configure(ProfileConfigureArgs),

    /// Manage users assigned to the selected profile.
    #[command(subcommand)]
    Members(ProfileMembersCommand),
}

/// Arguments for the `concrete profile list` subcommand. The `--assigned` flag
/// is optional: `concrete profile list` lists every visible profile, while
/// `concrete profile list --assigned <yes|no>` keeps only the profiles you are
/// (or are not) a member of.
#[derive(clap::Args, Debug)]
pub struct ProfileListArgs {
    /// Show only profiles you are a member of, or only those you are not.
    #[arg(long, value_enum)]
    pub assigned: Option<Assigned>,
}

#[derive(clap::Args, Debug)]
pub struct ProfileCreateArgs {
    /// Human-readable profile name.
    pub name: String,

    /// Free-text profile description.
    #[arg(long)]
    pub description: Option<String>,

    /// Assign a local alias to the created profile (see `concrete alias`).
    #[arg(long)]
    pub alias: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct ProfileConfigureArgs {
    /// New profile name.
    #[arg(long)]
    pub name: Option<String>,

    /// New profile description.
    #[arg(long)]
    pub description: Option<String>,

    /// JSON policy file path. Use '-' to read stdin.
    #[arg(long)]
    pub policy_file: Option<PathBuf>,
}

#[derive(Subcommand, Debug)]
pub enum ProfileMembersCommand {
    /// List users assigned to the selected profile.
    List,

    /// Add a user to the selected profile.
    Add {
        /// User UUID to add to the profile.
        user_id: String,
    },

    /// Remove a user from the selected profile.
    Remove {
        /// User UUID to remove from the profile.
        user_id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum QuotaCommand {
    /// Read effective quotas.
    Get(QuotaScopeArgs),

    /// Set a quota override.
    Set(QuotaSetArgs),

    /// Clear a quota override.
    Clear(QuotaClearArgs),
}

#[derive(clap::Args, Debug)]
pub struct QuotaScopeArgs {
    /// Entity to read or mutate quotas for (UUID). Default: current session entity.
    #[arg(long, conflicts_with = "user")]
    pub entity: Option<String>,

    /// Read or mutate quotas for this user UUID.
    #[arg(long)]
    pub user: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct QuotaSetArgs {
    /// Quota resource.
    pub resource: String,

    /// New quota limit.
    pub limit: u64,

    #[command(flatten)]
    pub scope: QuotaScopeArgs,
}

#[derive(clap::Args, Debug)]
pub struct QuotaClearArgs {
    /// Quota resource.
    pub resource: String,

    #[command(flatten)]
    pub scope: QuotaScopeArgs,
}

#[derive(Subcommand, Debug)]
pub enum SecurityCvmCommand {
    /// Show the current entity Security CVM.
    Show,

    /// Launch the current entity Security CVM.
    Launch(SecurityCvmLaunchArgs),

    /// Update the current entity Security CVM in place.
    Update(SecurityCvmUpdateArgs),

    /// Terminate the current entity Security CVM.
    Terminate,

    /// Show the current entity Security CVM attestation diagnostic.
    Attestation(SecurityCvmAttestationArgs),
}

#[derive(clap::Args, Debug)]
pub struct SecurityCvmLaunchArgs {
    /// Instance type (vCPU/RAM); see `concrete cvm instance-types`.
    #[arg(long)]
    pub instance_type: Option<String>,

    /// Security CVM region.
    #[arg(long)]
    pub region: Option<String>,

    #[command(flatten)]
    pub wait: WaitArgs,
}

#[derive(clap::Args, Debug)]
pub struct SecurityCvmUpdateArgs {
    #[command(flatten)]
    pub wait: WaitArgs,
}

#[derive(clap::Args, Debug)]
pub struct SecurityCvmAttestationArgs {
    /// Request a fresh Console-side attestation probe instead of persisted state.
    #[arg(long)]
    pub probe: bool,
}

#[derive(Subcommand, Debug)]
pub enum SkillCommand {
    /// Install the Concrete skill for local AI coding agents.
    Install(SkillInstallArgs),
}

#[derive(clap::Args, Debug)]
pub struct SkillInstallArgs {
    /// Agents to target, comma-separated (claude, codex). Default: all detected agents.
    #[arg(long)]
    pub agents: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct TrafficLogsArgs {
    /// Filter to logs for this Dev CVM UUID.
    #[arg(long)]
    pub cvm: Option<String>,

    /// Filter to logs for this Security CVM UUID.
    #[arg(long)]
    pub security_cvm: Option<String>,

    /// Include logs at or after this RFC3339 timestamp.
    #[arg(long = "from")]
    pub from: Option<String>,

    /// Include logs at or before this RFC3339 timestamp.
    #[arg(long)]
    pub to: Option<String>,

    /// Page size, 1..1000.
    #[arg(long, default_value_t = 100)]
    pub limit: u16,

    /// Opaque pagination cursor from the previous response.
    #[arg(long)]
    pub cursor: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum UserCommand {
    /// Add a user to an entity.
    Add(UserAddArgs),

    /// List users in the current entity.
    List(UserListArgs),

    /// Show one user by ID.
    Show {
        /// User UUID.
        user_id: String,
    },

    /// Deactivate a user by ID.
    Deactivate {
        /// User UUID.
        user_id: String,
    },

    /// Reactivate a user by ID.
    Reactivate {
        /// User UUID.
        user_id: String,
    },

    /// Permanently erase a user by ID.
    Erase {
        /// User UUID.
        user_id: String,
    },

    /// Manage user permission grants.
    #[command(subcommand)]
    Permissions(UserPermissionsCommand),
}

/// Arguments for the `concrete user list` subcommand. Both flags are optional
/// and combine: `concrete user list` lists all non-erased users, `--status`
/// keeps only users in that account status, and `--assigned` keeps only users
/// who belong to at least one profile (or to none).
#[derive(clap::Args, Debug)]
pub struct UserListArgs {
    /// Show only users in this account status.
    #[arg(long, value_enum)]
    pub status: Option<UserStatus>,

    /// Show only users who belong to at least one profile, or only those who belong to none.
    #[arg(long, value_enum)]
    pub assigned: Option<Assigned>,
}

/// Account statuses accepted by the `concrete user list --status` flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum UserStatus {
    Active,
    Deactivated,
    Erased,
}

#[derive(clap::Args, Debug)]
pub struct UserAddArgs {
    /// User email address.
    pub email: String,

    /// Entity to add the user to (UUID). Default: current session entity.
    #[arg(long)]
    pub entity: Option<String>,

    /// User display name. Default: email local-part.
    #[arg(long)]
    pub name: Option<String>,

    /// Initial permission grant. Repeat for multiple permissions.
    #[arg(long = "permission")]
    pub permissions: Vec<String>,
}

#[derive(Subcommand, Debug)]
pub enum UserPermissionsCommand {
    /// List a user's permission grants.
    List {
        /// User UUID.
        user_id: String,
    },

    /// Grant one or more permissions.
    Grant {
        /// User UUID.
        user_id: String,

        /// Permission symbols to grant.
        #[arg(required = true)]
        permissions: Vec<String>,
    },

    /// Revoke one or more permissions.
    Revoke {
        /// User UUID.
        user_id: String,

        /// Permission symbols to revoke.
        #[arg(required = true)]
        permissions: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum AuthCommand {
    /// Log in to the Console.
    Login {
        /// Console URL to save before logging in, for example https://console.example.com.
        #[arg(value_name = "CONSOLE_URL")]
        login_url: Option<String>,

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

    /// Log out and delete all local sessions.
    Logout,

    /// Show local session status without a network call.
    Status,

    /// Refresh the stored access token.
    Refresh,

    /// Print the current access token.
    Token,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn command_tree_is_valid() {
        // Validates the whole arg tree (duplicate ids, flatten conflicts, ...).
        // Guards against a global --cvm ever colliding with a local --cvm again.
        Cli::command().debug_assert();
    }

    #[test]
    fn session_verbs_accept_positional_and_flag_target() {
        let ssh = match Cli::try_parse_from(["concrete", "ssh", "cvm-1"])
            .unwrap()
            .command
        {
            Command::Ssh(args) => args,
            other => panic!("expected ssh, got {other:?}"),
        };
        assert_eq!(ssh.target.cvm_id.as_deref(), Some("cvm-1"));
        assert_eq!(ssh.target.cvm.as_deref(), None);

        let ssh = match Cli::try_parse_from(["concrete", "ssh", "--cvm", "cvm-2"])
            .unwrap()
            .command
        {
            Command::Ssh(args) => args,
            other => panic!("expected ssh, got {other:?}"),
        };
        assert_eq!(ssh.target.cvm_id.as_deref(), None);
        assert_eq!(ssh.target.cvm.as_deref(), Some("cvm-2"));
    }

    #[test]
    fn code_verb_gained_positional_target() {
        let code = match Cli::try_parse_from(["concrete", "code", "cvm-1"])
            .unwrap()
            .command
        {
            Command::Code(args) => args,
            other => panic!("expected code, got {other:?}"),
        };
        assert_eq!(code.target.cvm_id.as_deref(), Some("cvm-1"));
    }

    #[test]
    fn cvm_lifecycle_verbs_take_optional_positional() {
        match Cli::try_parse_from(["concrete", "cvm", "start", "cvm-1"])
            .unwrap()
            .command
        {
            Command::Cvm(CvmCommand::Start { target }) => {
                assert_eq!(target.cvm_id.as_deref(), Some("cvm-1"));
            }
            other => panic!("expected cvm start, got {other:?}"),
        }
        // A destructive verb still parses with no id; the explicit-id requirement
        // is enforced at run time by resolve_cvm_explicit, not by the parser.
        match Cli::try_parse_from(["concrete", "cvm", "stop"])
            .unwrap()
            .command
        {
            Command::Cvm(CvmCommand::Stop { target }) => {
                assert_eq!(target.cvm_id, None);
                assert_eq!(target.cvm, None);
            }
            other => panic!("expected cvm stop, got {other:?}"),
        }
    }

    #[test]
    fn traffic_logs_keeps_independent_cvm_filters() {
        match Cli::try_parse_from([
            "concrete",
            "traffic-logs",
            "--cvm",
            "cvm-1",
            "--security-cvm",
            "sc-1",
        ])
        .unwrap()
        .command
        {
            Command::TrafficLogs(args) => {
                assert_eq!(args.cvm.as_deref(), Some("cvm-1"));
                assert_eq!(args.security_cvm.as_deref(), Some("sc-1"));
            }
            other => panic!("expected traffic-logs, got {other:?}"),
        }
    }

    #[test]
    fn cvm_flag_is_not_global() {
        // --cvm is scoped to CVM-targeting verbs, so a non-targeting command rejects it.
        assert!(Cli::try_parse_from(["concrete", "status", "--cvm", "cvm-1"]).is_err());
    }
}
