//! `concrete update` -- self-update from the published release channel -- plus
//! the passive new-version check every other command surfaces.
//!
//! The install service (the same origin the curl installer uses) serves
//! `/releases/concrete-cli/<version|latest>/<target>/concrete` with a sibling
//! `concrete.sha256`, and `/releases/concrete-cli/latest/version` with the
//! latest published version string. `concrete update` downloads the artifact
//! for this build's target triple, verifies its checksum, exec-checks the
//! staged binary, and atomically renames it over the running executable.
//!
//! The passive check keeps a small cache file (`update-check.json`) in the
//! config directory, refreshed at most once per [`CHECK_INTERVAL`] by a
//! detached re-invocation of `concrete update --refresh-cache`, and prints a
//! one-line stderr notice when the cache shows a newer published release.
//! Both halves are contract-bound by `docs/specs/cli.md` (section 3.6
//! `concrete update`, section 4.4 `update-check.json`).

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

/// Cache file for the passive new-version check, under the config directory.
const CACHE_FILE: &str = "update-check.json";

/// Minimum age of the cache before a new background refresh is spawned.
const CHECK_INTERVAL: chrono::Duration = chrono::Duration::hours(24);

/// Environment marker distinguishing the detached background worker from the
/// intermediate stage of the double-spawn (see [`run_refresh_cache`]).
const WORKER_ENV: &str = "CONCRETE_UPDATE_CHECK_WORKER";

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
    /// The latest published release, but the install service predates the
    /// version-metadata endpoint (404). Fall back to comparing artifact
    /// checksums against the running binary.
    LatestUnknown,
}

fn perform(
    args: &UpdateArgs,
    config: &ResolvedConfig,
    json_output: bool,
) -> Result<ExitStatus, (ExitStatus, String)> {
    let base_url = config.install_base_url.as_str();
    validate_install_base_url(base_url)?;

    let requested = match &args.version {
        Some(version) => {
            if Version::parse(version).is_none() {
                return Err((
                    ExitStatus::Usage,
                    format!(
                        "[usage] --version must be a semantic version like 1.2.3, got {version}"
                    ),
                ));
            }
            Requested::Pinned(version.clone())
        }
        None => {
            let probe = http_client(PROBE_TIMEOUT)?;
            match fetch_latest_version(&probe, base_url)? {
                Some(version) => Requested::Latest(version),
                None => Requested::LatestUnknown,
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
            Requested::LatestUnknown => {}
        }
    }

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
        Requested::LatestUnknown => "latest",
    };
    let client = http_client(DOWNLOAD_TIMEOUT)?;
    let artifact_url =
        format!("{base_url}/releases/concrete-cli/{version_segment}/{BUILD_TARGET}/concrete");
    let bytes = download(&client, &artifact_url)?.ok_or_else(|| {
        (
            ExitStatus::Error,
            format!(
                "[error] no published concrete binary for {BUILD_TARGET} at version {version_segment}"
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
            "[error] checksum mismatch for the downloaded concrete binary; retry later and report if it persists"
                .to_string(),
        ));
    }

    // Without version metadata, "up to date" means "the published artifact is
    // byte-identical to the binary that is running".
    if matches!(requested, Requested::LatestUnknown) && !config.force {
        let current_bytes = fs::read(&exe_path).map_err(|err| {
            (
                ExitStatus::Error,
                format!("[error] failed to read {}: {err}", exe_path.display()),
            )
        })?;
        if sha256_hex(&current_bytes) == actual_digest {
            // The published latest is this very binary, so the running
            // version is authoritative for the passive-check cache.
            let _ = write_cache(&config.config_dir, Some(CURRENT_VERSION));
            return Ok(report_up_to_date(json_output));
        }
    }

    staged.fill(&bytes)?;
    // Run the staged binary before touching the live one so a download that
    // cannot execute here (wrong libc, wrong arch) aborts with the current
    // install intact.
    let reported_version = exec_check(staged.path())?;
    if let Requested::Pinned(expected) | Requested::Latest(expected) = &requested {
        if &reported_version != expected {
            return Err((
                ExitStatus::Error,
                format!(
                    "[error] downloaded binary reports version {reported_version} but the release channel promised {expected}; the install service looks out of sync -- retry later"
                ),
            ));
        }
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
            "concrete",
            format!("{CURRENT_VERSION} -> {reported_version}"),
        )
        .field("path", exe_path.display().to_string())
        .field("target", BUILD_TARGET);
        println!("{}", style::render_confirm(&confirm));
    }
    Ok(ExitStatus::Ok)
}

/// `concrete update --check`: report whether a newer release is published,
/// without installing anything.
fn check_only(
    requested: &Requested,
    config: &ResolvedConfig,
    json_output: bool,
) -> Result<ExitStatus, (ExitStatus, String)> {
    let latest = match requested {
        Requested::Latest(latest) => latest,
        Requested::LatestUnknown => {
            return Err((
                ExitStatus::Error,
                "[error] the install service did not publish version metadata; run `concrete update` to update by artifact checksum"
                    .to_string(),
            ))
        }
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
                    style::ConfirmBlock::new("update available:", "concrete", latest.clone())
                        .field("installed", CURRENT_VERSION)
                        .next_step("concrete update");
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
        // No latest_version claim: this path is also reached from a --version
        // pin and the checksum fallback, where "latest" was never probed.
        print_check_json("up_to_date", None);
    } else {
        let confirm = style::ConfirmBlock::new("up to date:", "concrete", CURRENT_VERSION);
        println!("{}", style::render_confirm(&confirm));
    }
    ExitStatus::Ok
}

fn report_ahead(latest: &str, json_output: bool) -> ExitStatus {
    if json_output {
        print_check_json("ahead", Some(latest));
    } else {
        let confirm =
            style::ConfirmBlock::new("ahead of latest release:", "concrete", CURRENT_VERSION)
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

/// Reject an install base URL that could hand us an unauthenticated binary.
///
/// The artifact and its `.sha256` are served by the same origin, so the checksum
/// only proves the transfer was not corrupted -- it cannot prove the bytes came
/// from us. TLS is therefore the *only* thing standing between `concrete update`
/// and attacker-supplied code that this command then executes and installs as
/// the user's `concrete`. Over plaintext, anyone on the network path (rogue
/// Wi-Fi, ARP/DNS spoofing, a hostile egress proxy) can serve both the payload
/// and a matching checksum; the passive version probe makes it worse by letting
/// them *advertise* a new version to trigger the update.
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
                "[usage] refusing to fetch a release binary over plaintext http from {base_url}; the published checksum comes from the same origin, so only https can prove the download is genuine -- use an https install_base_url (plaintext is allowed for loopback hosts only)"
            ),
        )),
        other => Err((
            ExitStatus::Usage,
            format!("[usage] install_base_url must use https, got scheme {other}: {base_url}"),
        )),
    }
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
        .user_agent(format!("concrete-cli/{CURRENT_VERSION} ({BUILD_TARGET})"))
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

/// Fetch `/releases/concrete-cli/latest/version`. `Ok(None)` when the install
/// service predates the version-metadata file (404).
fn fetch_latest_version(
    client: &reqwest::blocking::Client,
    base_url: &str,
) -> Result<Option<String>, (ExitStatus, String)> {
    let url = format!("{base_url}/releases/concrete-cli/latest/version");
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
    if Version::parse(&text).is_none() {
        return Err((
            ExitStatus::Error,
            "[error] the install service returned an unrecognized version string".to_string(),
        ));
    }
    Ok(Some(text))
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
    installed: bool,
}

impl StagedBinary {
    fn create(dir: &Path) -> Result<Self, (ExitStatus, String)> {
        let path = dir.join(format!(".concrete-update.{}.tmp", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o755);
        options.open(&path).map_err(|err| {
            (
                ExitStatus::Error,
                format!(
                    "[error] cannot write to {}: {err} -- re-run with sufficient privileges, or reinstall with the curl installer and CONCRETE_INSTALL_BIN_DIR set to a writable directory",
                    dir.display()
                ),
            )
        })?;
        Ok(Self {
            path,
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
    // clap prints `concrete <version>`.
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
    if !passive_check_enabled(config) {
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

/// The hidden `concrete update --refresh-cache` entrypoint. Two stages so no
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
    if validate_install_base_url(&config.install_base_url).is_err() {
        return;
    }
    let Ok(client) = http_client(PROBE_TIMEOUT) else {
        return;
    };
    if let Ok(Some(version)) = fetch_latest_version(&client, &config.install_base_url) {
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
    fn parse(input: &str) -> Option<Self> {
        let input = input.trim();
        let input = input.strip_prefix('v').unwrap_or(input);
        let input = input.split('+').next()?;
        let (core, pre) = match input.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (input, None),
        };
        let mut parts = core.split('.');
        let major = parts.next()?.parse::<u64>().ok()?;
        let minor = parts.next()?.parse::<u64>().ok()?;
        let patch = parts.next()?.parse::<u64>().ok()?;
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
                        Some(match id.parse::<u64>() {
                            Ok(number) => PreId::Num(number),
                            Err(_) => PreId::Alpha(id.to_string()),
                        })
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
    /// `~/.concrete`. Mirrors `config::tests::temp_config_dir`.
    fn temp_config_dir() -> PathBuf {
        std::env::temp_dir().join(format!("concrete-update-test-{}", uuid::Uuid::new_v4()))
    }

    /// Transport rule for the release channel: https anywhere, plaintext only
    /// for loopback (local mirrors and the release-tree tests).
    #[rstest]
    #[case::https("https://install.concrete-security.com")]
    #[case::https_with_path("https://mirror.example.com/concrete")]
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
    #[case::plaintext_remote("http://install.concrete-security.com")]
    #[case::loopback_lookalike("http://127.0.0.1.evil.example.com")]
    #[case::localhost_lookalike("http://localhost.evil.example.com")]
    #[case::file_scheme("file:///tmp/payload")]
    #[case::ftp_scheme("ftp://install.example.com")]
    #[case::not_a_url("install.concrete-security.com")]
    #[case::empty("")]
    fn validate_install_base_url_plaintext_or_bad_scheme_failure(#[case] base_url: &str) {
        let (status, message) = validate_install_base_url(base_url)
            .expect_err(&format!("{base_url} should be rejected"));
        assert!(matches!(status, ExitStatus::Usage));
        assert!(message.starts_with("[usage]"));
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
            "1.2.x",
            "latest",
            "1.2.3-",
            "1.2.3-a..b",
            "1.2.3-a_b",
        ] {
            assert!(Version::parse(input).is_none(), "{input} should not parse");
        }
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
            parse_checksum_file(format!("{digest}  concrete\n").as_bytes()).unwrap(),
            digest
        );
        assert_eq!(
            parse_checksum_file(digest.to_uppercase().as_bytes()).unwrap(),
            digest
        );
        assert!(parse_checksum_file(b"").is_err());
        assert!(parse_checksum_file(b"deadbeef  concrete").is_err());
        assert!(parse_checksum_file(&[0xff, 0xfe]).is_err());
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
