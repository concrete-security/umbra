use std::path::PathBuf;

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

    /// Override the Concrete config directory for this invocation.
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Override the Console base URL for this invocation.
    #[arg(long, global = true)]
    pub console_url: Option<String>,

    /// Override the default profile for this invocation. Repeat for commands that accept multiple profiles.
    #[arg(long, global = true)]
    pub profile: Vec<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Platform-operator maintenance commands.
    #[command(subcommand)]
    Admin(AdminCommand),

    /// Authenticate and inspect the local Console session.
    #[command(subcommand)]
    Auth(AuthCommand),

    /// Query and verify Console audit records.
    #[command(subcommand)]
    Audit(AuditCommand),

    /// Manage tenant entities.
    #[command(subcommand)]
    Entity(EntityCommand),

    /// Manage Dev CVMs.
    #[command(subcommand)]
    Cvm(CvmCommand),

    /// Manage SSH public keys registered with the Console.
    #[command(subcommand)]
    Key(KeyCommand),

    /// Manage profiles and profile membership.
    #[command(subcommand)]
    Profile(ProfileCommand),

    /// Manage entity and user quotas.
    #[command(subcommand)]
    Quota(QuotaCommand),

    /// Run a single Console reconciliation pass.
    Reconcile(ReconcileArgs),

    /// Inspect the entity Security CVM.
    #[command(subcommand)]
    SecurityCvm(SecurityCvmCommand),

    /// Show a summary of the current entity and visible resources.
    Status,

    /// Query egress traffic logs.
    TrafficLogs(TrafficLogsArgs),

    /// Manage users and user permissions.
    #[command(subcommand)]
    User(UserCommand),

    /// Print version, build commit, target triple, and build date.
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

    /// Submit the export and return the operation handle without polling.
    #[arg(long)]
    pub no_wait: bool,

    /// Maximum seconds to wait for export completion.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u32).range(1..=86400))]
    pub wait_timeout_seconds: u32,
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

#[derive(Subcommand, Debug)]
pub enum CvmCommand {
    /// List Dev CVMs visible to the current user.
    List,

    /// Launch a Dev CVM.
    Launch(CvmLaunchArgs),

    /// Attach a profile to a Dev CVM.
    Attach {
        /// Dev CVM UUID.
        cvm_id: String,
    },

    /// Detach a profile from a Dev CVM.
    Detach {
        /// Dev CVM UUID.
        cvm_id: String,
    },

    /// Start a stopped Dev CVM.
    Start {
        /// Dev CVM UUID.
        cvm_id: String,
    },

    /// Stop a running Dev CVM.
    Stop {
        /// Dev CVM UUID.
        cvm_id: String,
    },

    /// Terminate a Dev CVM.
    Terminate(CvmTerminateArgs),
}

#[derive(clap::Args, Debug)]
pub struct CvmLaunchArgs {
    /// SSH key UUID to install. Repeat for multiple keys.
    #[arg(long = "ssh-key", required = true)]
    pub ssh_keys: Vec<String>,

    /// Phala instance type. Defaults to config or Console defaults.
    #[arg(long)]
    pub instance_type: Option<String>,

    /// Phala region. Defaults to config or Console defaults.
    #[arg(long)]
    pub region: Option<String>,

    /// Submit the launch and return the operation handle without polling.
    #[arg(long)]
    pub no_wait: bool,

    /// Maximum seconds to wait for launch completion.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u32).range(1..=86400))]
    pub wait_timeout_seconds: u32,
}

#[derive(clap::Args, Debug)]
pub struct CvmTerminateArgs {
    /// Dev CVM UUID.
    pub cvm_id: String,

    /// Submit the terminate request and return the operation handle without polling.
    #[arg(long)]
    pub no_wait: bool,

    /// Maximum seconds to wait for termination completion.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u32).range(1..=86400))]
    pub wait_timeout_seconds: u32,
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
}

#[derive(Subcommand, Debug)]
pub enum ProfileCommand {
    /// List profiles visible to the current user.
    List,

    /// Show the selected profile.
    Show,

    /// Update the selected profile.
    Configure(ProfileConfigureArgs),

    /// Manage users assigned to the selected profile.
    #[command(subcommand)]
    Members(ProfileMembersCommand),
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
    /// Read or mutate quotas for this entity UUID. Defaults to the current session entity.
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

    /// Terminate the current entity Security CVM.
    Terminate,

    /// Show the current entity Security CVM attestation diagnostic.
    Attestation(SecurityCvmAttestationArgs),
}

#[derive(clap::Args, Debug)]
pub struct SecurityCvmLaunchArgs {
    /// Phala instance type. Defaults to the Console Security CVM default.
    #[arg(long)]
    pub instance_type: Option<String>,

    /// Phala region. Defaults to the Console Security CVM default.
    #[arg(long)]
    pub region: Option<String>,

    /// Submit the launch and return the operation handle without polling.
    #[arg(long)]
    pub no_wait: bool,

    /// Maximum seconds to wait for launch completion.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u32).range(1..=86400))]
    pub wait_timeout_seconds: u32,
}

#[derive(clap::Args, Debug)]
pub struct SecurityCvmAttestationArgs {
    /// Request a fresh Console-side attestation probe instead of persisted state.
    #[arg(long)]
    pub probe: bool,
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
    /// Add a user to the current entity.
    Add(UserAddArgs),

    /// List users in the current entity.
    List,

    /// Show one user.
    Show {
        /// User UUID.
        user_id: String,
    },

    /// Deactivate a user.
    Deactivate {
        /// User UUID.
        user_id: String,
    },

    /// Reactivate a user.
    Reactivate {
        /// User UUID.
        user_id: String,
    },

    /// Irreversibly erase a user.
    Erase {
        /// User UUID.
        user_id: String,
    },

    /// Manage user permission grants.
    #[command(subcommand)]
    Permissions(UserPermissionsCommand),
}

#[derive(clap::Args, Debug)]
pub struct UserAddArgs {
    /// User email address.
    pub email: String,

    /// User display name. Defaults to the email local-part.
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
    /// Authenticate against the Console.
    Login {
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

    /// Delete the local session and notify the Console best-effort.
    Logout,

    /// Show local session status without a network call.
    Status,

    /// Force a refresh of the stored access token.
    Refresh,

    /// Print the current access token.
    Token,
}
