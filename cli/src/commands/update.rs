//! `umbra update` -- self-update from the published release channel -- plus
//! the passive new-version check every other command surfaces.
//!
//! The install service (the same origin the verified installer uses) serves
//! `/releases/umbra-cli/<version|latest>/<target>/umbra` with a sibling
//! `umbra.sha256`, version-root `umbra-cli.intoto.jsonl`, and
//! `/releases/umbra-cli/latest/version` with the latest published version
//! string. `umbra update` downloads the immutable versioned artifact for
//! this build's target triple, verifies its checksum and signed SLSA
//! provenance, exec-checks the staged binary, and atomically renames it over
//! the running executable.
//!
//! The passive check keeps a small cache file (`update-check.json`) in the
//! config directory, refreshed at most once per [`CHECK_INTERVAL`] by a
//! detached re-invocation of `umbra update --refresh-cache`, and prints a
//! one-line stderr notice when the cache shows a newer published release.
//! Both halves are contract-bound by `docs/specs/cli.md` (section 3.6
//! `umbra update`, section 4.4 `update-check.json`).

use std::{
    cmp::Ordering,
    env, fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use url::{Host, Url};

use crate::{
    cli::UpdateArgs, commands::audit::sha256_hex, config::ResolvedConfig, exit::ExitStatus, style,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_TARGET: &str = env!("BUILD_TARGET");

/// Fixed release identity enforced by both the bootstrap installer and
/// self-update. The release workflow is `workflow_dispatch` on `main`, so its
/// signed provenance is branch- and input-bound rather than tag-triggered.
const SLSA_SOURCE_REPO: &str = "github.com/concrete-security/umbra";
const SLSA_SOURCE_BRANCH: &str = "main";
const SLSA_WORKFLOW_INPUT: &str = "dry_run=false";
const SLSA_BUILDER_ID: &str = "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0";
const SLSA_VERIFIER_ENV: &str = "UMBRA_SLSA_VERIFIER";

/// Cache file for the passive new-version check, under the config directory.
const CACHE_FILE: &str = "update-check.json";

/// Minimum age of the cache before a new background refresh is spawned.
const CHECK_INTERVAL: chrono::Duration = chrono::Duration::hours(24);

/// Environment marker distinguishing the detached background worker from the
/// intermediate stage of the double-spawn (see [`run_refresh_cache`]).
const WORKER_ENV: &str = "UMBRA_UPDATE_CHECK_WORKER";

/// Timeouts for the small version-metadata probe and the binary download.
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);

/// Refuse to buffer artifacts larger than this; released CLI binaries are a
/// few tens of MB, so anything near this size is a misconfigured server.
const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;

pub fn run(args: UpdateArgs, config: &ResolvedConfig, json_output: bool) -> ExitStatus {
    if args.refresh_cache {
        return run_refresh_cache(config);
    }
    match perform(&args, config, json_output) {
        Ok(status) => status,
        Err((status, message)) => {
            style::eprintln_error(&message);
            status
        }
    }
}

/// What the invocation asked to install.
enum Requested {
    /// Explicit `--version <V>`.
    Pinned(String),
    /// The latest published release, as reported by the version endpoint.
    Latest(String),
}

fn perform(
    args: &UpdateArgs,
    config: &ResolvedConfig,
    json_output: bool,
) -> Result<ExitStatus, (ExitStatus, String)> {
    let base_url = config.install_base_url.as_deref().ok_or_else(|| {
        (
            ExitStatus::Usage,
            "[usage] missing install_base_url; set UMBRA_INSTALL_BASE_URL or config.toml install_base_url to an approved HTTPS install origin".to_string(),
        )
    })?;
    validate_install_base_url(base_url)?;

    let requested = match &args.version {
        Some(version) => {
            let Some(version) = canonical_release_version(version) else {
                return Err((
                    ExitStatus::Usage,
                    format!(
                        "[usage] --version must be a canonical semantic version like 1.2.3 or 1.2.3-beta.1, got {version}"
                    ),
                ));
            };
            Requested::Pinned(version)
        }
        None => {
            let probe = http_client(PROBE_TIMEOUT)?;
            match fetch_latest_version(&probe, base_url)? {
                Some(version) => Requested::Latest(version),
                None => {
                    return Err((
                        ExitStatus::Error,
                        "[error] the install service did not publish version metadata; self-update requires an immutable versioned artifact -- use the verified installer in docs/quick-start.md"
                            .to_string(),
                    ))
                }
            }
        }
    };

    if args.check {
        return check_only(&requested, config, json_output);
    }

    // With version metadata available, decide before downloading anything.
    // The global --force reinstalls (or downgrades to) the published release;
    // an explicit --version pin installs without --force in either direction.
    if !config.force {
        match &requested {
            Requested::Latest(latest) => match compare_versions(CURRENT_VERSION, latest) {
                Some(Ordering::Equal) => {
                    // `latest` is authoritative here: remember it so the
                    // passive check stays quiet without a re-probe.
                    let _ = write_cache(&config.config_dir, Some(latest));
                    return Ok(report_up_to_date(json_output));
                }
                Some(Ordering::Greater) => {
                    let _ = write_cache(&config.config_dir, Some(latest));
                    return Ok(report_ahead(latest, json_output));
                }
                _ => {}
            },
            Requested::Pinned(pinned) => {
                if compare_versions(CURRENT_VERSION, pinned) == Some(Ordering::Equal) {
                    // Not authoritative for "latest" -- leave the cache alone.
                    return Ok(report_up_to_date(json_output));
                }
            }
        }
    }

    let slsa_verifier = resolve_slsa_verifier()?;
    let exe_path = current_exe_resolved()?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| {
            (
                ExitStatus::Error,
                format!(
                    "[error] cannot determine the directory of {}",
                    exe_path.display()
                ),
            )
        })?
        .to_path_buf();
    // Probe writability before any network work so a permission problem
    // fails fast with a actionable message instead of after the download.
    let mut staged = StagedBinary::create(&exe_dir)?;

    let version_segment = match &requested {
        Requested::Pinned(version) | Requested::Latest(version) => version.as_str(),
    };
    let client = http_client(DOWNLOAD_TIMEOUT)?;
    let artifact_url =
        format!("{base_url}/releases/umbra-cli/{version_segment}/{BUILD_TARGET}/umbra");
    let bytes = download(&client, &artifact_url)?.ok_or_else(|| {
        (
            ExitStatus::Error,
            format!(
                "[error] no published umbra binary for {BUILD_TARGET} at version {version_segment}"
            ),
        )
    })?;
    let checksum = download(&client, &format!("{artifact_url}.sha256"))?.ok_or_else(|| {
        (
            ExitStatus::Error,
            format!("[error] the install service did not publish a checksum for {BUILD_TARGET}"),
        )
    })?;
    let expected_digest = parse_checksum_file(&checksum)?;
    let actual_digest = sha256_hex(&bytes);
    if actual_digest != expected_digest {
        return Err((
            ExitStatus::Error,
            "[error] checksum mismatch for the downloaded umbra binary; retry later and report if it persists"
                .to_string(),
        ));
    }

    let provenance_url =
        format!("{base_url}/releases/umbra-cli/{version_segment}/umbra-cli.intoto.jsonl");
    let provenance = download(&client, &provenance_url)?.ok_or_else(|| {
        (
            ExitStatus::Error,
            format!(
                "[error] the install service did not publish SLSA provenance for umbra {version_segment}"
            ),
        )
    })?;

    staged.fill(&bytes)?;
    staged.verify_slsa(&provenance, &slsa_verifier)?;
    // Run the staged binary before touching the live one so a download that
    // cannot execute here (wrong libc, wrong arch) aborts with the current
    // install intact.
    let reported_version = exec_check(staged.path())?;
    let (Requested::Pinned(expected) | Requested::Latest(expected)) = &requested;
    if &reported_version != expected {
        return Err((
            ExitStatus::Error,
            format!(
                "[error] downloaded binary reports version {reported_version} but the release channel promised {expected}; the install service looks out of sync -- retry later"
            ),
        ));
    }
    staged.install_over(&exe_path)?;

    // Keep the passive check quiet about the version we just installed. A
    // pinned install is not authoritative for "latest", so leave the cache
    // alone there; the next background probe will refresh it.
    if !matches!(requested, Requested::Pinned(_)) {
        let _ = write_cache(&config.config_dir, Some(&reported_version));
    }

    if json_output {
        style::emit_json(&json!({
            "status": "updated",
            "previous_version": CURRENT_VERSION,
            "version": reported_version,
            "path": exe_path.display().to_string(),
        }));
    } else {
        let confirm = style::ConfirmBlock::new(
            "updated",
            "umbra",
            format!("{CURRENT_VERSION} -> {reported_version}"),
        )
        .field("path", exe_path.display().to_string())
        .field("target", BUILD_TARGET);
        println!("{}", style::render_confirm(&confirm));
    }
    Ok(ExitStatus::Ok)
}

/// `umbra update --check`: report whether a newer release is published,
/// without installing anything.
fn check_only(
    requested: &Requested,
    config: &ResolvedConfig,
    json_output: bool,
) -> Result<ExitStatus, (ExitStatus, String)> {
    let latest = match requested {
        Requested::Latest(latest) => latest,
        // clap declares the conflict; keep a typed error rather than a panic
        // in case the parser surface ever drifts.
        Requested::Pinned(_) => {
            return Err((
                ExitStatus::Usage,
                "[usage] --check cannot be combined with --version".to_string(),
            ))
        }
    };
    // The probe result is authoritative: remember it for the passive check.
    let _ = write_cache(&config.config_dir, Some(latest));
    match compare_versions(CURRENT_VERSION, latest) {
        Some(Ordering::Less) => {
            if json_output {
                print_check_json("update_available", Some(latest));
            } else {
                let confirm =
                    style::ConfirmBlock::new("update available:", "umbra", latest.clone())
                        .field("installed", CURRENT_VERSION)
                        .next_step("umbra update");
                println!("{}", style::render_confirm(&confirm));
            }
            Ok(ExitStatus::Ok)
        }
        Some(Ordering::Greater) => Ok(report_ahead(latest, json_output)),
        Some(Ordering::Equal) => Ok(report_up_to_date(json_output)),
        None => Err((
            ExitStatus::Error,
            format!("[error] cannot compare version {CURRENT_VERSION} with published {latest}"),
        )),
    }
}

fn print_check_json(status: &str, latest: Option<&str>) {
    let mut payload = json!({
        "status": status,
        "version": CURRENT_VERSION,
    });
    if let Some(latest) = latest {
        payload["latest_version"] = json!(latest);
    }
    style::emit_json(&payload);
}

fn report_up_to_date(json_output: bool) -> ExitStatus {
    if json_output {
        // No latest_version claim: this path is also reached from a
        // `--version` pin, where "latest" was never probed.
        print_check_json("up_to_date", None);
    } else {
        let confirm = style::ConfirmBlock::new("up to date:", "umbra", CURRENT_VERSION);
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn report_ahead(latest: &str, json_output: bool) -> ExitStatus {
    if json_output {
        print_check_json("ahead", Some(latest));
    } else {
        let confirm =
            style::ConfirmBlock::new("ahead of latest release:", "umbra", CURRENT_VERSION)
                .field("latest published", latest.to_string())
                .field(
                    "note",
                    "pass --force to install the published release anyway",
                );
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

// =========================================================================
// HTTP
// =========================================================================

/// Reject a remote install base URL without authenticated transport.
///
/// SLSA verification independently authenticates the release source, build
/// identity, and artifact digest, but HTTPS still protects version metadata,
/// availability, and download privacy. Over plaintext, a network attacker can
/// suppress or replay version advertisements even though they cannot make an
/// unsigned binary pass provenance verification.
///
/// So: `https` for anything remote. Plaintext is allowed only when the host is
/// loopback, where there is no network path to intercept -- that keeps local
/// mirrors and this repo's own release-tree tests working (the same carve-out
/// browsers make for `http://localhost` secure contexts).
fn validate_install_base_url(base_url: &str) -> Result<(), (ExitStatus, String)> {
    let parsed = Url::parse(base_url).map_err(|err| {
        (
            ExitStatus::Usage,
            format!("[usage] install_base_url is not a valid URL ({err}): {base_url}"),
        )
    })?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback(&parsed) => Ok(()),
        "http" => Err((
            ExitStatus::Usage,
            format!(
                "[usage] refusing to fetch release metadata and artifacts over plaintext http from {base_url}; use an https install_base_url (plaintext is allowed for loopback hosts only)"
            ),
        )),
        other => Err((
            ExitStatus::Usage,
            format!("[usage] install_base_url must use https, got scheme {other}: {base_url}"),
        )),
    }
}

/// Redirects may retain authenticated HTTPS transport. Plaintext is accepted
/// only when the request itself started on loopback HTTP and stays on loopback;
/// a remote HTTPS endpoint cannot redirect the updater into plaintext or SSRF a
/// local HTTP service.
fn redirect_target_allowed(initial: &Url, next: &Url) -> bool {
    next.scheme() == "https"
        || (initial.scheme() == "http"
            && is_loopback(initial)
            && next.scheme() == "http"
            && is_loopback(next))
}

/// Whether the URL's host is loopback. Matches on the parsed host so a
/// look-alike name (`http://127.0.0.1.example.com`) cannot pass as local.
fn is_loopback(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(addr)) => addr.is_loopback(),
        Some(Host::Ipv6(addr)) => addr.is_loopback(),
        // Not resolved: `localhost` is reserved for loopback (RFC 6761), any
        // other name could point anywhere.
        Some(Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn http_client(timeout: Duration) -> Result<reqwest::blocking::Client, (ExitStatus, String)> {
    reqwest::blocking::Client::builder()
        .connect_timeout(PROBE_CONNECT_TIMEOUT)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() > 10 {
                return attempt.error(io::Error::other("too many release-service redirects"));
            }
            match attempt.previous().first() {
                Some(initial) if redirect_target_allowed(initial, attempt.url()) => {
                    attempt.follow()
                }
                _ => attempt.error(io::Error::other(
                    "release-service redirect would weaken transport authentication",
                )),
            }
        }))
        .user_agent(format!("umbra-cli/{CURRENT_VERSION} ({BUILD_TARGET})"))
        .build()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to build HTTP client: {err}"),
            )
        })
}

/// GET `url`, returning `Ok(None)` on 404 so callers can distinguish "not
/// published" from transport and server failures.
fn download(
    client: &reqwest::blocking::Client,
    url: &str,
) -> Result<Option<Vec<u8>>, (ExitStatus, String)> {
    let response = client.get(url).send().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] cannot reach the install service: {err}"),
        )
    })?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !response.status().is_success() {
        return Err((
            ExitStatus::Error,
            format!(
                "[error] the install service returned HTTP {} for {url}",
                response.status().as_u16()
            ),
        ));
    }
    if let Some(length) = response.content_length() {
        if length > MAX_ARTIFACT_BYTES {
            return Err((
                ExitStatus::Error,
                format!("[error] install artifact is implausibly large ({length} bytes)"),
            ));
        }
    }
    let bytes = response.bytes().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] failed to download from the install service: {err}"),
        )
    })?;
    Ok(Some(bytes.to_vec()))
}

/// Fetch `/releases/umbra-cli/latest/version`. `Ok(None)` when the install
/// service predates the version-metadata file (404).
fn fetch_latest_version(
    client: &reqwest::blocking::Client,
    base_url: &str,
) -> Result<Option<String>, (ExitStatus, String)> {
    let url = format!("{base_url}/releases/umbra-cli/latest/version");
    let Some(bytes) = download(client, &url)? else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| {
            (
                ExitStatus::Error,
                "[error] the install service returned a non-UTF-8 version string".to_string(),
            )
        })?
        .lines()
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    let Some(version) = canonical_release_version(&text) else {
        return Err((
            ExitStatus::Error,
            "[error] the install service returned an unrecognized version string".to_string(),
        ));
    };
    Ok(Some(version))
}

/// Extract the digest from an `sha256sum`-format checksum file: first
/// whitespace-delimited token, 64 hex chars.
fn parse_checksum_file(bytes: &[u8]) -> Result<String, (ExitStatus, String)> {
    let malformed = || {
        (
            ExitStatus::Error,
            "[error] the install service returned a malformed checksum file".to_string(),
        )
    };
    let text = std::str::from_utf8(bytes).map_err(|_| malformed())?;
    let digest = text.split_whitespace().next().ok_or_else(malformed)?;
    if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(malformed());
    }
    Ok(digest.to_ascii_lowercase())
}

// =========================================================================
// Local install
// =========================================================================

/// Resolve the preinstalled verifier without a shell. An explicit override is
/// an absolute executable path; the default search accepts only absolute PATH
/// entries, so a repository-controlled current directory can never shadow the
/// trusted tool.
fn resolve_slsa_verifier() -> Result<PathBuf, (ExitStatus, String)> {
    let explicit = env::var_os(SLSA_VERIFIER_ENV).filter(|value| !value.is_empty());
    resolve_slsa_verifier_from(explicit, env::var_os("PATH"))
}

/// Pure resolver seam: keeping environment reads outside makes the trust-path
/// rules testable without process-global environment mutation races.
fn resolve_slsa_verifier_from(
    explicit: Option<std::ffi::OsString>,
    search_path: Option<std::ffi::OsString>,
) -> Result<PathBuf, (ExitStatus, String)> {
    let candidate = if let Some(value) = explicit {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err((
                ExitStatus::Error,
                format!("[error] {SLSA_VERIFIER_ENV} must be an absolute executable path"),
            ));
        }
        Some(path)
    } else {
        search_path.and_then(|path| {
            env::split_paths(&path)
                .filter(|dir| dir.is_absolute())
                .map(|dir| dir.join("slsa-verifier"))
                .find(|candidate| executable_file(candidate))
        })
    };

    candidate.filter(|path| executable_file(path)).ok_or_else(|| {
        (
            ExitStatus::Error,
            format!(
                "[error] slsa-verifier is required for self-update; install the pinned verifier described in docs/quick-start.md or set {SLSA_VERIFIER_ENV} to its absolute executable path"
            ),
        )
    })
}

fn executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// The running executable with symlinks resolved. Installer shims symlink a
/// PATH-visible name at the real binary; replacing the resolved target keeps
/// every shim pointing at the updated file, while renaming over the symlink
/// path itself would orphan them.
fn current_exe_resolved() -> Result<PathBuf, (ExitStatus, String)> {
    let exe = env::current_exe().map_err(|err| {
        (
            ExitStatus::Error,
            format!("[error] cannot determine the running executable path: {err}"),
        )
    })?;
    fs::canonicalize(&exe).map_err(|err| {
        (
            ExitStatus::Error,
            format!(
                "[error] cannot resolve the running executable path {}: {err}",
                exe.display()
            ),
        )
    })
}

/// A staged replacement binary next to the target executable (same
/// filesystem, so the final `rename` is atomic). Removed on drop unless the
/// install completed.
struct StagedBinary {
    path: PathBuf,
    provenance_path: PathBuf,
    installed: bool,
}

impl StagedBinary {
    fn create(dir: &Path) -> Result<Self, (ExitStatus, String)> {
        let path = dir.join(format!(".umbra-update.{}.tmp", std::process::id()));
        let provenance_path =
            dir.join(format!(".umbra-update.{}.intoto.jsonl", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o755);
        options.open(&path).map_err(|err| {
            (
                ExitStatus::Error,
                format!(
                    "[error] cannot write to {}: {err} -- re-run with sufficient privileges, or use the verified installer in docs/quick-start.md with UMBRA_INSTALL_BIN_DIR set to a writable directory",
                    dir.display()
                ),
            )
        })?;
        Ok(Self {
            path,
            provenance_path,
            installed: false,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn fill(&mut self, bytes: &[u8]) -> Result<(), (ExitStatus, String)> {
        let write = || -> io::Result<()> {
            let mut file = fs::OpenOptions::new().write(true).open(&self.path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            // The create-time mode passed through the process umask; pin the
            // canonical binary mode explicitly so a restrictive umask cannot
            // strip exec bits from a shared install directory.
            #[cfg(unix)]
            fs::set_permissions(&self.path, fs::Permissions::from_mode(0o755))?;
            Ok(())
        };
        write().map_err(|err| {
            (
                ExitStatus::Error,
                format!(
                    "[error] failed to write the staged binary {}: {err}",
                    self.path.display()
                ),
            )
        })
    }

    /// Verify the staged binary against signed release provenance before it is
    /// ever executed or moved over the trusted running binary.
    fn verify_slsa(&self, provenance: &[u8], verifier: &Path) -> Result<(), (ExitStatus, String)> {
        let write = || -> io::Result<()> {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&self.provenance_path)?;
            file.write_all(provenance)?;
            file.sync_all()
        };
        write().map_err(|err| {
            (
                ExitStatus::Error,
                format!(
                    "[error] failed to stage SLSA provenance at {}: {err}",
                    self.provenance_path.display()
                ),
            )
        })?;

        let output = Command::new(verifier)
            .arg("verify-artifact")
            .arg(&self.path)
            .arg("--provenance-path")
            .arg(&self.provenance_path)
            .arg("--source-uri")
            .arg(SLSA_SOURCE_REPO)
            .arg("--source-branch")
            .arg(SLSA_SOURCE_BRANCH)
            .arg("--build-workflow-input")
            .arg(SLSA_WORKFLOW_INPUT)
            .arg("--builder-id")
            .arg(SLSA_BUILDER_ID)
            .stdin(Stdio::null())
            .output()
            .map_err(|err| {
                (
                    ExitStatus::Error,
                    format!(
                        "[error] cannot run slsa-verifier ({err}); install the pinned verifier described in docs/quick-start.md or set {SLSA_VERIFIER_ENV} to its executable path"
                    ),
                )
            })?;
        if !output.status.success() {
            return Err((
                ExitStatus::Error,
                format!(
                    "[error] SLSA provenance verification failed for the downloaded umbra binary (verifier exited with {})",
                    output.status
                ),
            ));
        }
        Ok(())
    }

    fn install_over(&mut self, target: &Path) -> Result<(), (ExitStatus, String)> {
        fs::rename(&self.path, target).map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to install {}: {err}", target.display()),
            )
        })?;
        self.installed = true;
        Ok(())
    }
}

impl Drop for StagedBinary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.provenance_path);
        if !self.installed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Run `<staged> --version` and return the version token it reports. Proves
/// the artifact actually executes on this machine before it replaces the
/// running binary.
fn exec_check(path: &Path) -> Result<String, (ExitStatus, String)> {
    let output = Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] the downloaded binary failed to execute on this machine: {err}"),
            )
        })?;
    if !output.status.success() {
        return Err((
            ExitStatus::Error,
            format!(
                "[error] the downloaded binary exited with {} on --version",
                output.status
            ),
        ));
    }
    // clap prints `umbra <version>`.
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .last()
        .map(str::to_string)
        .filter(|token| Version::parse(token).is_some())
        .ok_or_else(|| {
            (
                ExitStatus::Error,
                "[error] the downloaded binary did not report a parseable version".to_string(),
            )
        })
}

// =========================================================================
// Passive new-version check (cache + background refresh + notice)
// =========================================================================

/// Cache of the last latest-version probe, at `<config_dir>/update-check.json`.
/// `latest_version` is `None` between the stamp that claims a refresh slot and
/// the worker writing the fetched result.
#[derive(Debug, Serialize, Deserialize)]
struct UpdateCheckCache {
    checked_at: DateTime<Utc>,
    latest_version: Option<String>,
}

fn cache_path(config_dir: &Path) -> PathBuf {
    config_dir.join(CACHE_FILE)
}

fn read_cache(config_dir: &Path) -> Option<UpdateCheckCache> {
    let data = fs::read_to_string(cache_path(config_dir)).ok()?;
    serde_json::from_str(&data).ok()
}

/// Atomically write the cache with `checked_at = now`. Same tmp-plus-rename
/// dance as `config::persist_string_values`, minus the TOML merge.
fn write_cache(config_dir: &Path, latest_version: Option<&str>) -> Result<(), String> {
    let cache = UpdateCheckCache {
        checked_at: Utc::now(),
        latest_version: latest_version.map(str::to_string),
    };
    let data = serde_json::to_string(&cache).map_err(|err| err.to_string())?;
    // This write may be the first thing to create the config directory on a
    // fresh machine; hold the section 4.5 directory mode, as
    // `config::persist_string_values` does (write_atomic_file governs the file,
    // not its parent).
    fs::create_dir_all(config_dir).map_err(|err| err.to_string())?;
    #[cfg(unix)]
    fs::set_permissions(config_dir, fs::Permissions::from_mode(0o700))
        .map_err(|err| err.to_string())?;
    crate::fsutil::write_atomic_file(&cache_path(config_dir), data.as_bytes(), 0o600)
        .map_err(|err| err.to_string())
}

fn cache_is_fresh(cache: &UpdateCheckCache, now: DateTime<Utc>) -> bool {
    // Absolute difference so a cache stamped by a badly skewed clock cannot
    // stay "fresh" forever.
    (now - cache.checked_at).abs() < CHECK_INTERVAL
}

/// Whether the passive check is active for this invocation: interactive
/// terminals only, and off entirely when the user opted out.
fn passive_check_enabled(config: &ResolvedConfig) -> bool {
    !config.no_update_check && io::stderr().is_terminal()
}

/// Spawn a detached background refresh of the latest-version cache when the
/// cache is stale. Called by `lib.rs` before eligible commands run; never
/// blocks on the network.
pub(crate) fn maybe_spawn_background_refresh(config: &ResolvedConfig) {
    if config.install_base_url.is_none() || !passive_check_enabled(config) {
        return;
    }
    let now = Utc::now();
    let previous = read_cache(&config.config_dir);
    if previous
        .as_ref()
        .is_some_and(|cache| cache_is_fresh(cache, now))
    {
        return;
    }
    // Claim the refresh slot before spawning so concurrent invocations inside
    // the interval do not stampede; a failed fetch just waits out the window.
    let previous_latest = previous.and_then(|cache| cache.latest_version);
    if write_cache(&config.config_dir, previous_latest.as_deref()).is_err() {
        return;
    }
    let Ok(exe) = env::current_exe() else {
        return;
    };
    let mut command = Command::new(exe);
    command
        .arg("update")
        .arg("--refresh-cache")
        .arg("--config")
        .arg(&config.config_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    unsafe {
        // Detach the intermediate (and everything it spawns) from our
        // controlling terminal and session; setsid(2) is async-signal-safe.
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
    if let Ok(mut child) = command.spawn() {
        // The intermediate re-spawns the detached worker and exits
        // immediately (see run_refresh_cache), so this wait is milliseconds
        // and leaves no zombie behind for long-lived sessions.
        let _ = child.wait();
    }
}

/// The hidden `umbra update --refresh-cache` entrypoint. Two stages so no
/// process is left for the interactive parent to reap: the first invocation
/// re-spawns itself with [`WORKER_ENV`] set and exits immediately (its parent
/// wait()s those few milliseconds); the orphaned worker is reparented to init
/// and does the actual fetch.
fn run_refresh_cache(config: &ResolvedConfig) -> ExitStatus {
    if env::var_os(WORKER_ENV).is_some() {
        refresh_cache_now(config);
        return ExitStatus::Ok;
    }
    let Ok(exe) = env::current_exe() else {
        return ExitStatus::Ok;
    };
    let _ = Command::new(exe)
        .arg("update")
        .arg("--refresh-cache")
        .arg("--config")
        .arg(&config.config_dir)
        .env(WORKER_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    ExitStatus::Ok
}

/// Fetch the latest published version and record it; silent and best-effort
/// (the worker's stdio is already detached).
///
/// Holds the same transport rule as the install path: an unauthenticated probe
/// would let a network attacker advertise a version and drive the user into an
/// update, so a non-https base URL simply yields no notice.
fn refresh_cache_now(config: &ResolvedConfig) {
    let Some(base_url) = config.install_base_url.as_deref() else {
        return;
    };
    if validate_install_base_url(base_url).is_err() {
        return;
    }
    let Ok(client) = http_client(PROBE_TIMEOUT) else {
        return;
    };
    if let Ok(Some(version)) = fetch_latest_version(&client, base_url) {
        let _ = write_cache(&config.config_dir, Some(&version));
    }
}

/// Print the one-line stderr notice when the cached probe shows a newer
/// published release. Called by `lib.rs` after eligible commands finish, so
/// the notice lands after the command's own output.
pub(crate) fn maybe_print_update_notice(config: &ResolvedConfig) {
    if !passive_check_enabled(config) {
        return;
    }
    let Some(cache) = read_cache(&config.config_dir) else {
        return;
    };
    let Some(latest) = cache.latest_version else {
        return;
    };
    if compare_versions(CURRENT_VERSION, &latest) == Some(Ordering::Less) {
        eprintln!("{}", style::update_notice(CURRENT_VERSION, &latest));
    }
}

// =========================================================================
// Version ordering
// =========================================================================

/// Compare two version strings; `None` when either does not parse.
fn compare_versions(a: &str, b: &str) -> Option<Ordering> {
    Some(Version::parse(a)?.cmp(&Version::parse(b)?))
}

/// A release path and the binary's reported version must use one canonical
/// spelling. The comparison parser is deliberately more tolerant for the
/// compile-time current version, but user/mirror input cannot retain a `v`
/// prefix, whitespace, or build metadata that would make URL and identity
/// checks disagree.
fn canonical_release_version(input: &str) -> Option<String> {
    let parsed = Version::parse(input)?;
    let canonical = parsed.canonical();
    (input == canonical).then_some(canonical)
}

/// Minimal semantic version for release-channel comparisons:
/// `MAJOR.MINOR.PATCH` with an optional pre-release suffix ordered per semver
/// precedence; build metadata (`+...`) is ignored. Parsing returns `None` for
/// anything else so callers fail closed on garbage (no notice, no skip).
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Version {
    release: (u64, u64, u64),
    pre: PreRelease,
}

/// Pre-release ordering: a final release outranks any pre-release of the same
/// core version, so `Final` must compare greater than `Pre(_)`.
#[derive(Debug, PartialEq, Eq)]
enum PreRelease {
    Pre(Vec<PreId>),
    Final,
}

#[derive(Debug, PartialEq, Eq)]
enum PreId {
    /// Numeric identifiers compare numerically and rank below alphanumerics.
    Num(u64),
    Alpha(String),
}

impl Version {
    fn parse_numeric_identifier(input: &str) -> Option<u64> {
        if input.is_empty() || (input.len() > 1 && input.starts_with('0')) {
            return None;
        }
        input.parse::<u64>().ok()
    }

    fn parse(input: &str) -> Option<Self> {
        let input = input.trim();
        let input = input.strip_prefix('v').unwrap_or(input);
        let input = input.split('+').next()?;
        let (core, pre) = match input.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (input, None),
        };
        let mut parts = core.split('.');
        let major = Self::parse_numeric_identifier(parts.next()?)?;
        let minor = Self::parse_numeric_identifier(parts.next()?)?;
        let patch = Self::parse_numeric_identifier(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        let pre = match pre {
            None => PreRelease::Final,
            Some(pre) => {
                if pre.is_empty() {
                    return None;
                }
                let ids = pre
                    .split('.')
                    .map(|id| {
                        if id.is_empty()
                            || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
                        {
                            return None;
                        }
                        if id.chars().all(|character| character.is_ascii_digit()) {
                            Some(PreId::Num(Self::parse_numeric_identifier(id)?))
                        } else {
                            Some(PreId::Alpha(id.to_string()))
                        }
                    })
                    .collect::<Option<Vec<_>>>()?;
                PreRelease::Pre(ids)
            }
        };
        Some(Self {
            release: (major, minor, patch),
            pre,
        })
    }

    fn canonical(&self) -> String {
        let (major, minor, patch) = self.release;
        let mut version = format!("{major}.{minor}.{patch}");
        if let PreRelease::Pre(identifiers) = &self.pre {
            version.push('-');
            for (index, identifier) in identifiers.iter().enumerate() {
                if index > 0 {
                    version.push('.');
                }
                match identifier {
                    PreId::Num(number) => version.push_str(&number.to_string()),
                    PreId::Alpha(text) => version.push_str(text),
                }
            }
        }
        version
    }
}

impl Ord for PreRelease {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Final, Self::Final) => Ordering::Equal,
            (Self::Final, Self::Pre(_)) => Ordering::Greater,
            (Self::Pre(_), Self::Final) => Ordering::Less,
            (Self::Pre(a), Self::Pre(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for PreRelease {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PreId {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Self::Num(a), Self::Num(b)) => a.cmp(b),
            (Self::Num(_), Self::Alpha(_)) => Ordering::Less,
            (Self::Alpha(_), Self::Num(_)) => Ordering::Greater,
            (Self::Alpha(a), Self::Alpha(b)) => a.cmp(b),
        }
    }
}

impl PartialOrd for PreId {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    fn version(input: &str) -> Version {
        Version::parse(input).unwrap_or_else(|| panic!("{input} should parse"))
    }

    /// A throwaway config dir, so a cache test never touches the real
    /// `~/.umbra`. Mirrors `config::tests::temp_config_dir`.
    fn temp_config_dir() -> PathBuf {
        std::env::temp_dir().join(format!("umbra-update-test-{}", uuid::Uuid::new_v4()))
    }

    #[cfg(unix)]
    fn fake_verifier(dir: &Path) -> PathBuf {
        let path = dir.join("slsa-verifier");
        fs::write(
            &path,
            format!(
                r#"#!/bin/sh
set -eu
[ "$#" -eq 12 ]
[ "$1" = verify-artifact ]
[ -s "$2" ]
[ "$3" = --provenance-path ]
[ "$(cat "$4")" = signed-provenance ]
[ "$5" = --source-uri ]
[ "$6" = {SLSA_SOURCE_REPO} ]
[ "$7" = --source-branch ]
[ "$8" = {SLSA_SOURCE_BRANCH} ]
[ "$9" = --build-workflow-input ]
[ "${{10}}" = {SLSA_WORKFLOW_INPUT} ]
[ "${{11}}" = --builder-id ]
[ "${{12}}" = {SLSA_BUILDER_ID} ]
"#
            ),
        )
        .expect("fake verifier written");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("fake verifier executable");
        path
    }

    /// No public install origin is assumed before launch approval, so an
    /// explicit update must fail before constructing an HTTP client.
    #[test]
    fn perform_missing_install_origin_failure() {
        let mut config = ResolvedConfig::resolve(crate::config::ConfigOverrides {
            config_dir: Some(temp_config_dir()),
            ..Default::default()
        });
        config.install_base_url = None;
        config.install_base_url_source = crate::config::ConfigSource::Missing;
        let args = UpdateArgs {
            check: true,
            version: None,
            refresh_cache: false,
        };

        let (status, message) = perform(&args, &config, false)
            .expect_err("update without an approved install origin must fail");

        assert!(matches!(status, ExitStatus::Usage));
        assert!(message.contains("missing install_base_url"));
        assert!(message.contains("UMBRA_INSTALL_BASE_URL"));
    }

    /// An override must name the trusted executable absolutely; a relative
    /// value could otherwise resolve differently after a directory change.
    #[cfg(unix)]
    #[test]
    fn resolve_slsa_verifier_relative_override_failure() {
        let (status, message) =
            resolve_slsa_verifier_from(Some(std::ffi::OsString::from("tools/slsa-verifier")), None)
                .expect_err("relative verifier override rejected");

        assert!(matches!(status, ExitStatus::Error));
        assert!(message.contains("absolute executable path"));
    }

    /// Relative PATH entries are ignored even when they contain an executable,
    /// so a repository-controlled directory cannot shadow the trusted tool.
    #[cfg(unix)]
    #[test]
    fn resolve_slsa_verifier_relative_path_shadow_failure() {
        let cwd = env::current_dir().expect("current directory available");
        let relative_dir = PathBuf::from(format!(
            ".umbra-update-resolver-test-{}",
            uuid::Uuid::new_v4()
        ));
        let dir = cwd.join(&relative_dir);
        fs::create_dir_all(&dir).expect("relative test directory created");
        fake_verifier(&dir);

        let result = resolve_slsa_verifier_from(None, Some(relative_dir.into_os_string()));

        fs::remove_dir_all(&dir).expect("relative test directory removed");
        let (status, message) = result.expect_err("relative PATH verifier ignored");
        assert!(matches!(status, ExitStatus::Error));
        assert!(message.contains("slsa-verifier is required"));
    }

    /// An absolute executable supplied by the trusted bootstrap is accepted.
    #[cfg(unix)]
    #[test]
    fn resolve_slsa_verifier_absolute_executable_success() {
        let dir = temp_config_dir();
        fs::create_dir_all(&dir).expect("test dir created");
        let verifier = fake_verifier(&dir);

        let resolved = resolve_slsa_verifier_from(Some(verifier.clone().into_os_string()), None)
            .expect("absolute executable accepted");

        assert_eq!(resolved, verifier);
        fs::remove_dir_all(&dir).expect("test dir removed");
    }

    /// Transport rule for the release channel: https anywhere, plaintext only
    /// for loopback (local mirrors and the release-tree tests).
    #[rstest]
    #[case::https("https://install.example.com")]
    #[case::https_with_path("https://mirror.example.com/umbra")]
    #[case::loopback_v4("http://127.0.0.1:18923")]
    #[case::loopback_v4_other("http://127.0.0.2:8080")]
    #[case::loopback_v6("http://[::1]:18923")]
    #[case::localhost("http://localhost:8080")]
    #[case::localhost_mixed_case("http://LocalHost")]
    fn validate_install_base_url_https_or_loopback_success(#[case] base_url: &str) {
        assert!(
            validate_install_base_url(base_url).is_ok(),
            "{base_url} should be accepted"
        );
    }

    /// Plaintext to a remote host would let a network attacker serve both the
    /// binary and its checksum, so it must be refused -- as must a look-alike
    /// loopback name, a non-http(s) scheme, and anything unparseable.
    #[rstest]
    #[case::plaintext_remote("http://install.example.com")]
    #[case::loopback_lookalike("http://127.0.0.1.evil.example.com")]
    #[case::localhost_lookalike("http://localhost.evil.example.com")]
    #[case::file_scheme("file:///tmp/payload")]
    #[case::ftp_scheme("ftp://install.example.com")]
    #[case::not_a_url("install.example.com")]
    #[case::empty("")]
    fn validate_install_base_url_plaintext_or_bad_scheme_failure(#[case] base_url: &str) {
        let (status, message) = validate_install_base_url(base_url)
            .expect_err(&format!("{base_url} should be rejected"));
        assert!(matches!(status, ExitStatus::Usage));
        assert!(message.starts_with("[usage]"));
    }

    /// Redirects preserve HTTPS, while an explicitly local HTTP mirror may
    /// redirect only to another loopback HTTP endpoint.
    #[rstest]
    #[case::https("https://install.example/start", "https://cdn.example/artifact")]
    #[case::loopback_http("http://localhost/start", "http://127.0.0.1/artifact")]
    #[case::loopback_to_https("http://localhost/start", "https://cdn.example/artifact")]
    fn redirect_target_authenticated_transport_success(#[case] initial: &str, #[case] next: &str) {
        assert!(redirect_target_allowed(
            &Url::parse(initial).expect("initial URL parsed"),
            &Url::parse(next).expect("redirect URL parsed")
        ));
    }

    /// A redirect cannot downgrade remote HTTPS or escape the loopback-only
    /// plaintext carve-out.
    #[rstest]
    #[case::remote_downgrade("https://install.example/start", "http://cdn.example/artifact")]
    #[case::https_to_loopback_http("https://install.example/start", "http://127.0.0.1/artifact")]
    #[case::loopback_to_remote_http("http://localhost/start", "http://cdn.example/artifact")]
    fn redirect_target_unauthenticated_transport_failure(
        #[case] initial: &str,
        #[case] next: &str,
    ) {
        assert!(!redirect_target_allowed(
            &Url::parse(initial).expect("initial URL parsed"),
            &Url::parse(next).expect("redirect URL parsed")
        ));
    }

    #[test]
    fn version_parse_accepts_release_and_prerelease() {
        assert_eq!(
            version("1.2.3"),
            Version {
                release: (1, 2, 3),
                pre: PreRelease::Final
            }
        );
        assert_eq!(
            version("0.3.0-beta.3"),
            Version {
                release: (0, 3, 0),
                pre: PreRelease::Pre(vec![PreId::Alpha("beta".into()), PreId::Num(3)])
            }
        );
        // Tolerated inputs: v-prefix, surrounding whitespace, build metadata.
        assert_eq!(version("v1.2.3"), version("1.2.3"));
        assert_eq!(version(" 1.2.3\n"), version("1.2.3"));
        assert_eq!(version("1.2.3+abc"), version("1.2.3"));
    }

    #[test]
    fn version_parse_rejects_garbage() {
        for input in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "1.2.x",
            "latest",
            "1.2.3-",
            "1.2.3-01",
            "1.2.3-a..b",
            "1.2.3-a_b",
        ] {
            assert!(Version::parse(input).is_none(), "{input} should not parse");
        }
    }

    /// Canonical stable and prerelease spellings can safely identify both the
    /// immutable URL and the version reported by the verified binary.
    #[rstest]
    #[case::stable("1.2.3")]
    #[case::prerelease("0.3.0-beta.3")]
    fn canonical_release_version_success(#[case] input: &str) {
        assert_eq!(canonical_release_version(input).as_deref(), Some(input));
    }

    /// Alternate spellings and build metadata are rejected so an accepted pin
    /// cannot download one path and compare against a different identity.
    #[rstest]
    #[case::v_prefix("v1.2.3")]
    #[case::whitespace(" 1.2.3 ")]
    #[case::build_metadata("1.2.3+build.7")]
    #[case::leading_zero("01.2.3")]
    fn canonical_release_version_failure(#[case] input: &str) {
        assert!(canonical_release_version(input).is_none());
    }

    #[test]
    fn version_ordering_follows_semver_precedence() {
        let ordered = [
            "0.3.0-alpha",
            "0.3.0-beta.3",
            "0.3.0-beta.10",
            "0.3.0-beta.rc",
            "0.3.0",
            "0.3.1",
            "0.4.0-alpha",
            "0.4.0",
            "1.0.0",
        ];
        for pair in ordered.windows(2) {
            assert!(
                version(pair[0]) < version(pair[1]),
                "{} should sort before {}",
                pair[0],
                pair[1]
            );
        }
        assert_eq!(compare_versions("1.2.3", "1.2.3"), Some(Ordering::Equal));
        assert_eq!(compare_versions("1.2.3", "junk"), None);
    }

    #[test]
    fn checksum_file_parses_sha256sum_format() {
        let digest = "a".repeat(64);
        assert_eq!(
            parse_checksum_file(format!("{digest}  umbra\n").as_bytes()).unwrap(),
            digest
        );
        assert_eq!(
            parse_checksum_file(digest.to_uppercase().as_bytes()).unwrap(),
            digest
        );
        assert!(parse_checksum_file(b"").is_err());
        assert!(parse_checksum_file(b"deadbeef  umbra").is_err());
        assert!(parse_checksum_file(&[0xff, 0xfe]).is_err());
    }

    /// The verifier receives every fixed release-identity constraint and a
    /// valid attestation permits the already-staged binary to proceed.
    #[cfg(unix)]
    #[test]
    fn verify_slsa_release_identity_success() {
        let dir = temp_config_dir();
        fs::create_dir_all(&dir).expect("test dir created");
        let verifier = fake_verifier(&dir);
        let mut staged = StagedBinary::create(&dir).expect("binary staged");
        staged.fill(b"authenticated binary").expect("binary filled");
        let provenance_path = staged.provenance_path.clone();

        staged
            .verify_slsa(b"signed-provenance", &verifier)
            .expect("fixed SLSA policy accepted");

        drop(staged);
        assert!(!provenance_path.exists(), "provenance temp file removed");
        fs::remove_dir_all(&dir).expect("test dir removed");
    }

    /// A same-origin payload with a matching checksum remains untrusted when
    /// provenance is missing, malformed, or for another build identity.
    #[cfg(unix)]
    #[rstest]
    #[case::missing(b"")]
    #[case::malformed(b"not-json")]
    #[case::wrong_identity(b"signed-for-another-build")]
    fn verify_slsa_untrusted_provenance_failure(#[case] provenance: &[u8]) {
        let dir = temp_config_dir();
        fs::create_dir_all(&dir).expect("test dir created");
        let verifier = fake_verifier(&dir);
        let trusted_path = dir.join("umbra");
        fs::write(&trusted_path, b"trusted current binary").expect("trusted binary written");
        let execution_marker = dir.join("malicious-executed");
        let malicious = format!("#!/bin/sh\ntouch '{}'\n", execution_marker.display());
        let checksum = format!("{}  umbra\n", sha256_hex(malicious.as_bytes()));
        assert_eq!(
            parse_checksum_file(checksum.as_bytes()).expect("matching checksum parsed"),
            sha256_hex(malicious.as_bytes())
        );
        let mut staged = StagedBinary::create(&dir).expect("binary staged");
        staged
            .fill(malicious.as_bytes())
            .expect("malicious binary staged");

        let (status, message) = staged
            .verify_slsa(provenance, &verifier)
            .expect_err("untrusted provenance rejected");

        assert!(matches!(status, ExitStatus::Error));
        assert!(message.contains("SLSA provenance verification failed"));
        assert_eq!(
            fs::read(&trusted_path).expect("trusted binary readable"),
            b"trusted current binary"
        );
        assert!(
            !execution_marker.exists(),
            "staged payload was not executed"
        );
        drop(staged);
        fs::remove_dir_all(&dir).expect("test dir removed");
    }

    /// A missing verifier fails closed before an unverified staged binary can
    /// execute or replace the running binary.
    #[cfg(unix)]
    #[test]
    fn verify_slsa_missing_verifier_failure() {
        let dir = temp_config_dir();
        fs::create_dir_all(&dir).expect("test dir created");
        let mut staged = StagedBinary::create(&dir).expect("binary staged");
        staged.fill(b"unverified binary").expect("binary filled");

        let (status, message) = staged
            .verify_slsa(b"signed-provenance", &dir.join("missing-verifier"))
            .expect_err("missing verifier rejected");

        assert!(matches!(status, ExitStatus::Error));
        assert!(message.contains("cannot run slsa-verifier"));
        drop(staged);
        fs::remove_dir_all(&dir).expect("test dir removed");
    }

    #[test]
    fn cache_round_trips_and_freshness_windows() {
        let dir = temp_config_dir();
        write_cache(&dir, Some("0.4.0")).expect("cache written");
        let cache = read_cache(&dir).expect("cache readable");
        assert_eq!(cache.latest_version.as_deref(), Some("0.4.0"));
        assert!(cache_is_fresh(&cache, Utc::now()));
        assert!(!cache_is_fresh(
            &cache,
            Utc::now() + chrono::Duration::hours(25)
        ));
        // A future-stamped cache (skewed clock) must not stay fresh forever.
        assert!(!cache_is_fresh(
            &cache,
            Utc::now() - chrono::Duration::hours(25)
        ));

        write_cache(&dir, None).expect("stamp written");
        assert_eq!(
            read_cache(&dir).expect("cache readable").latest_version,
            None
        );
        std::fs::remove_dir_all(&dir).expect("test cache dir removed");
    }

    #[test]
    fn unreadable_cache_is_ignored() {
        let dir = temp_config_dir();
        std::fs::create_dir_all(&dir).expect("dir created");
        std::fs::write(dir.join(CACHE_FILE), "not json").expect("cache written");
        assert!(read_cache(&dir).is_none());
        std::fs::remove_dir_all(&dir).expect("test cache dir removed");
    }
}
