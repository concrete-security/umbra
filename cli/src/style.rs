//! Layer 1 + Layer 2 rendering primitives for the `umbra` CLI.
//!
//! See `docs/specs/cli-style.md` for the full contract. All command code MUST
//! call Layer 2 renderers; Layer 1 primitives and `anstyle` itself are private
//! to this module.

use std::{
    collections::BTreeMap,
    fmt::Display,
    io::{self, Write},
    sync::atomic::{AtomicBool, Ordering},
    time::Instant,
};

use anstyle::{AnsiColor, Color, Style};
use chrono::{DateTime, Utc};
use serde_json::Value;

static COLOR_ENABLED: AtomicBool = AtomicBool::new(false);

/// Configure the color toggle. MUST be called exactly once at process start,
/// after the resolved config is known. Subsequent calls overwrite the toggle.
pub fn init(enabled: bool) {
    COLOR_ENABLED.store(enabled, Ordering::Relaxed);
}

fn color_enabled() -> bool {
    COLOR_ENABLED.load(Ordering::Relaxed)
}

/// Emit a `--json` payload as pretty-printed JSON on stdout. The single home of
/// the `println!("{}", serde_json::to_string_pretty(&x).expect(...))` block that
/// every command's `--json` branch otherwise repeats. Serialization of the plain
/// payload structs / `Value`s the CLI emits cannot fail in practice, so a failure
/// is a programming error and panics.
pub(crate) fn emit_json<T: serde::Serialize + ?Sized>(value: &T) {
    println!(
        "{}",
        serde_json::to_string_pretty(value).expect("json payload serializes")
    );
}

fn paint(style: Style, s: impl Display) -> String {
    if color_enabled() {
        format!("{style}{s}{style:#}")
    } else {
        format!("{s}")
    }
}

// =========================================================================
// Layer 1 -- primitives (section 5)
// =========================================================================

fn label(s: impl Display) -> String {
    let style = Style::new().dimmed();
    paint(style, s)
}

fn value(s: impl Display) -> String {
    let style = Style::new().bold();
    paint(style, s)
}

fn muted(s: impl Display) -> String {
    let style = Style::new()
        .fg_color(Some(Color::Ansi(AnsiColor::BrightBlack)))
        .dimmed();
    paint(style, s)
}

fn success(s: impl Display) -> String {
    let style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green)));
    paint(style, s)
}

fn error_style(s: impl Display) -> String {
    let style = Style::new()
        .fg_color(Some(Color::Ansi(AnsiColor::Red)))
        .bold();
    paint(style, s)
}

fn warn(s: impl Display) -> String {
    let style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow)));
    paint(style, s)
}

fn info(s: impl Display) -> String {
    let style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Cyan)));
    paint(style, s)
}

fn header(s: impl Display) -> String {
    let style = Style::new().bold();
    paint(style, s)
}

fn bullet() -> String {
    info("> ")
}

// Cursor control. Used only by the steps renderer, and only when colors are on.
const CURSOR_UP: &str = "\x1b[A";
const CLEAR_LINE: &str = "\r\x1b[K";

// =========================================================================
// Sanitisation -- section 4 (printable ASCII only)
// =========================================================================

/// Strip / escape any byte that is not printable ASCII or whitespace.
///
/// Returns a `String` safe to print on any terminal. Console-controlled
/// strings (error envelope fields, the forward-compat `extra` bag, etc.) MUST
/// be passed through this helper before being routed to a renderer; otherwise
/// a malicious or compromised Console could inject ANSI escape sequences
/// (e.g. `\x1b[2J\x1b[H` to clear the screen, or hyperlink/OSC sequences) that
/// the terminal would interpret verbatim.
///
/// Behavior:
/// - Keep printable ASCII (`0x20..=0x7E`).
/// - Keep `\n` (`0x0A`) and `\t` (`0x09`).
/// - Replace every other byte with the literal escape form `\xHH` (lowercase
///   hex). The user sees the suspicious bytes spelled out as visible text
///   instead of having the terminal interpret them.
///
/// CLI-controlled string literals (`[error]`, `[OK]`, `running`, ...) MUST
/// NOT be passed through this function -- they are spec-controlled and
/// already known to be ASCII-safe; running them through the helper would be
/// a needless allocation.
/// Fold a value onto ONE line for a single-line card cell. [`sanitize_ascii`]
/// deliberately keeps `\n` and `\t` (multi-line values such as a pretty-printed
/// policy need them), which a one-line cell must not: a value carrying a newline
/// would forge extra card rows — even a fake `> ID <uuid>` title, inventing a
/// record that does not exist. Escaped rather than dropped, so the suspicious bytes
/// stay visible to the reader.
pub(crate) fn single_line(value: &str) -> String {
    value.replace('\n', "\\n").replace('\t', "\\t")
}

pub(crate) fn sanitize_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            0x20..=0x7E | b'\n' | b'\t' => out.push(b as char),
            _ => {
                use std::fmt::Write;
                let _ = write!(out, "\\x{b:02x}");
            }
        }
    }
    out
}

// =========================================================================
// Domain dispatch helpers
// =========================================================================

fn cvm_state(state: &str) -> String {
    match state.to_ascii_lowercase().as_str() {
        "running" => success(state),
        "stopped" => warn(state),
        "pending" | "provisioning" => warn(state),
        "error" | "failed" => error_style(state),
        "terminating" | "terminated" => muted(state),
        _ => muted(state),
    }
}

fn user_state(state: &str) -> String {
    match state.to_ascii_lowercase().as_str() {
        "active" => success(state),
        "disabled" | "deactivated" => error_style(state),
        "pending" => warn(state),
        _ => muted(state),
    }
}

fn yes_no(value_str: &str) -> String {
    match value_str {
        "yes" => success(value_str),
        "no" => muted(value_str),
        _ => value_str.to_string(),
    }
}

/// What a card's `alias` cell can hold: the alias recorded for the record, `None`
/// when it has none, or the local alias store's error when that store could not be
/// read at all. Produced by `commands::alias::cell_source`, rendered by
/// [`alias_cell`]. Named because five views carry it (§7.2/7.3/7.4/7.9/7.22).
pub type AliasCell<'a> = Result<Option<&'a str>, &'a str>;

/// The literal a card's `alias` cell shows when the local alias store could not be
/// read. Deliberately NOT `-` (that means "this record has no alias"), and
/// deliberately short: the full store error goes once to stderr, where diagnostics
/// belong, instead of being repeated in every card — see
/// `commands::alias::load_for_display`.
const ALIAS_STORE_UNREADABLE: &str = "unreadable";

/// The `alias` cell of a card, one arm per state of the local alias store: the
/// recorded name, `-` when the record has none, or [`ALIAS_STORE_UNREADABLE`] when
/// the store is unreadable. Reporting the fault in the cell is what keeps a broken
/// `aliases.toml` from silently reading as "no aliases anywhere", while never
/// failing a listing of Console truth.
///
/// The name is sanitised AND folded to one line because `aliases.toml` is a
/// hand-editable local file, not CLI-controlled text. Shared by the cvm / profile /
/// key / `profile show` / `ps` views so all five render the alias identically.
fn alias_cell(alias: AliasCell<'_>) -> String {
    match alias {
        Ok(Some(name)) => single_line(&sanitize_ascii(name)),
        Ok(None) => "-".to_string(),
        Err(_) => error_style(ALIAS_STORE_UNREADABLE),
    }
}

fn audit_action_style(action: &str) -> String {
    let upper = action.to_ascii_uppercase();
    if upper.ends_with("_LAUNCHED")
        || upper.ends_with("_ADDED")
        || upper.ends_with("_CREATED")
        || upper.ends_with("_GRANTED")
        || upper.ends_with("_REGISTERED")
        || upper.ends_with("_PROVISIONED")
        || upper.ends_with("_ISSUED")
        || upper.ends_with("_LINKED")
    {
        success(action)
    } else if upper.ends_with("_DENIED")
        || upper.ends_with("_FAILED")
        || upper.ends_with("_REVOKED")
        || upper.ends_with("_REJECTED")
        || upper.ends_with("_DRIFT")
        || upper.ends_with("_DETECTED")
        || upper.ends_with("_REFUSED")
    {
        error_style(action)
    } else if upper.ends_with("_DELETED")
        || upper.ends_with("_TERMINATED")
        || upper.ends_with("_REMOVED")
        || upper.ends_with("_DECOMMISSIONED")
        || upper.ends_with("_DEPROVISIONED")
        || upper.ends_with("_CLEARED")
    {
        warn(action)
    } else if upper.ends_with("_UPDATED")
        || upper.ends_with("_CHANGED")
        || upper.ends_with("_ROTATED")
        || upper.contains("_LOGIN")
        || upper.contains("_LOGOUT")
        || upper.ends_with("_REFRESHED")
        || upper.ends_with("_CONNECTED")
        || upper.ends_with("_VERIFIED")
        || upper.ends_with("_DISCLOSED")
        || upper.ends_with("_SET")
        || upper.ends_with("_ASSIGNED")
    {
        action.to_string()
    } else {
        muted(action)
    }
}

fn response_code_style(code: Option<u16>) -> String {
    match code {
        Some(c) if (200..300).contains(&c) => success(c.to_string()),
        Some(c) if (300..400).contains(&c) => info(c.to_string()),
        Some(c) if (400..500).contains(&c) => warn(c.to_string()),
        Some(c) if (500..600).contains(&c) => error_style(c.to_string()),
        Some(c) => muted(c.to_string()),
        None => error_style("-"),
    }
}

fn method_style(method: Option<&str>) -> String {
    match method {
        Some(m) => match m.to_ascii_uppercase().as_str() {
            "GET" | "HEAD" | "OPTIONS" | "POST" | "PUT" | "PATCH" => m.to_string(),
            "DELETE" => warn(m),
            _ => muted(m),
        },
        None => muted("-"),
    }
}

fn config_source_style(src: &str) -> String {
    match src {
        "flag" | "env" => info(src),
        "file" => src.to_string(),
        "default" => muted(src),
        "missing" => error_style(src),
        _ => src.to_string(),
    }
}

fn quota_source_style(src: &str) -> String {
    match src.to_ascii_lowercase().as_str() {
        "default" => muted(src),
        _ => src.to_string(),
    }
}

// =========================================================================
// Timestamp formatting (section 4.1)
// =========================================================================

/// Convert ISO 8601 / RFC 3339 (e.g. `2026-05-18T15:38:12Z`) to the absolute
/// UTC display form `YYYY-MM-DD HH:MM UTC`. Returns the input unchanged on
/// parse failure so unparseable strings are surfaced rather than silently
/// dropped.
pub fn format_timestamp(value: &str) -> String {
    match DateTime::parse_from_rfc3339(value) {
        Ok(dt) => dt
            .with_timezone(&Utc)
            .format("%Y-%m-%d %H:%M UTC")
            .to_string(),
        Err(_) => value.to_string(),
    }
}

fn format_optional_timestamp(value: Option<&str>) -> String {
    match value {
        Some(v) if !v.is_empty() => format_timestamp(v),
        _ => "-".to_string(),
    }
}

// =========================================================================
// Card / table helpers
// =========================================================================

/// A row in a card: a (label, value, value_style) tuple plus optional
/// continuation lines that share the value column.
struct CardRow {
    label_text: String,
    /// First line of the value, styled.
    primary: String,
    /// Additional lines, already styled, indented to the value column.
    continuations: Vec<String>,
}

impl CardRow {
    fn new(label_text: impl Into<String>, primary: impl Into<String>) -> Self {
        Self::with_continuations(label_text, primary, Vec::new())
    }

    fn with_continuations(
        label_text: impl Into<String>,
        primary: impl Into<String>,
        continuations: Vec<String>,
    ) -> Self {
        Self {
            label_text: label_text.into(),
            primary: primary.into(),
            continuations,
        }
    }
}

const OUTER_INDENT: usize = 6;

/// Render a card body (rows aligned to a common value column inside the card).
fn render_card_body(rows: &[CardRow]) -> String {
    let max_label = rows.iter().map(|r| r.label_text.len()).max().unwrap_or(0);
    let mut out = String::new();
    for row in rows {
        let pad = max_label - row.label_text.len();
        out.push_str(&" ".repeat(OUTER_INDENT));
        out.push_str(&label(&row.label_text));
        out.push_str(&" ".repeat(pad + 2));
        out.push_str(&row.primary);
        out.push('\n');
        let cont_indent = OUTER_INDENT + max_label + 2;
        for cont in &row.continuations {
            out.push_str(&" ".repeat(cont_indent));
            out.push_str(cont);
            out.push('\n');
        }
    }
    out
}

/// Append unknown `extra` fields (section 11.7) to a row list. Keys are
/// converted from `snake_case` to lowercase space-separated words.
///
/// Both the label (Console-supplied key) and the rendered value are passed
/// through [`sanitize_ascii`] so a hostile Console cannot inject ANSI escape
/// sequences via the forward-compat extra bag.
fn append_extra_rows(rows: &mut Vec<CardRow>, extra: &BTreeMap<String, Value>) {
    for (key, val) in extra {
        let lbl = sanitize_ascii(&key.replace('_', " "));
        let v = sanitize_ascii(&render_extra_value(val));
        rows.push(CardRow::new(lbl, v));
    }
}

fn render_extra_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "-".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Array(_) | Value::Object(_) => {
            serde_json::to_string(v).unwrap_or_else(|_| "?".to_string())
        }
    }
}

fn card_title_id(identifier: &str) -> String {
    format!("{}{}", bullet(), value(identifier))
}

fn card_title_uuid(uuid: &str) -> String {
    format!("{}ID {}", bullet(), value(uuid))
}

fn card_title_seq(seq: u64) -> String {
    format!("{}SEQ {}", bullet(), value(seq.to_string()))
}

fn card_title_section(name: &str) -> String {
    format!("{}{}", bullet(), header(name))
}

fn card_title_section_with_hint(name: &str, hint: &str) -> String {
    format!("{}{}  {}", bullet(), header(name), muted(hint))
}

/// Wrap a comma-separated list at a configured width so each continuation line
/// stays within the configured maximum line width.
fn wrap_comma_list(items: &[String], available_width: usize) -> (String, Vec<String>) {
    if items.is_empty() {
        return ("-".to_string(), Vec::new());
    }
    let mut lines: Vec<String> = Vec::new();
    let mut current = String::new();
    for (i, item) in items.iter().enumerate() {
        let suffix = if i + 1 < items.len() { "," } else { "" };
        let candidate = if current.is_empty() {
            format!("{item}{suffix}")
        } else {
            format!("{current} {item}{suffix}")
        };
        if !current.is_empty() && candidate.len() > available_width {
            lines.push(current);
            current = format!("{item}{suffix}");
        } else {
            current = candidate;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    let first = lines.remove(0);
    (first, lines)
}

/// Render the per-list footer line with singular/plural awareness (section 6.1).
/// When `n == 1`, the plural input (e.g. `cvms`) is reduced to its singular form
/// (`cvm`) by dropping the trailing `s`. When `n != 1`, the plural form is used
/// verbatim. The empty-state literal always uses the plural form via
/// [`empty_state`].
fn footer_line(n: usize, plural: &str) -> String {
    let word = if n == 1 {
        singularize(plural)
    } else {
        plural.to_string()
    };
    muted(format!("{n} {word}"))
}

fn singularize(plural: &str) -> String {
    if let Some(stem) = plural.strip_suffix("ies") {
        format!("{stem}y")
    } else if let Some(stripped) = plural.strip_suffix('s') {
        stripped.to_string()
    } else {
        plural.to_string()
    }
}

fn empty_state(word: &str) -> String {
    muted(format!("no {word}"))
}

// =========================================================================
// Filter context shapes (section 12.5)
// =========================================================================

#[derive(Default)]
pub struct CvmListFilter {
    pub profile: Option<String>,
    pub state: Option<String>,
}

#[derive(Default)]
pub struct UserListFilter {
    pub status: Option<String>,
    pub assigned: Option<String>,
}

#[derive(Default)]
pub struct ProfileListFilter {
    pub assigned: Option<String>,
}

#[derive(Default)]
pub struct AuditEventsFilter {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    /// Per spec section 6.2.1 + 7.5: shown in the Filter header when set.
    pub limit: Option<u32>,
    /// Per spec section 6.2.1 + 7.5: shown in the Filter header when set.
    pub cursor: Option<String>,
}

/// Filter context for `umbra traffic-logs`. Per spec section 7.6 the
/// rendered output is ALWAYS a single block (one Filter header + one table +
/// one footer). When `security_cvm` is `None` and the returned page carries
/// rows with multiple distinct `security_cvm_id` values, the SC value is
/// surfaced as an additional table column rather than emitted as multiple
/// blocks. This mirrors the existing `cvm` column variant.
#[derive(Default)]
pub struct TrafficLogsFilter {
    pub cvm: Option<String>,
    pub security_cvm: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    /// Per spec section 6.2.1 + 7.6: shown in the Filter header when set.
    pub limit: Option<u32>,
    /// Per spec section 6.2.1 + 7.6: shown in the Filter header when set.
    pub cursor: Option<String>,
}

#[derive(Default)]
pub struct QuotaListFilter {
    pub entity_id: Option<String>,
    pub user_id: Option<String>,
    /// Resolved human-readable name for the `--entity` filter (section 7.8).
    /// When `None`, the renderer falls back to the bare UUID.
    pub entity_name: Option<String>,
    /// Resolved human-readable email for the `--user` filter (section 7.8).
    /// When `None`, the renderer falls back to the bare UUID.
    pub user_email: Option<String>,
}

// =========================================================================
// Filter header (section 6.2.1)
// =========================================================================

/// Emit a `Filter:` block. Pairs are (label, value); already-styled values are
/// expected. If `pairs` is empty, returns the empty string.
fn render_filter_block(pairs: &[(String, String)]) -> String {
    if pairs.is_empty() {
        return String::new();
    }
    let max_label = pairs.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    let mut out = String::new();
    out.push_str(&header("Filter:"));
    out.push('\n');
    for (lbl, val) in pairs {
        let pad = max_label - lbl.len();
        out.push_str("  ");
        out.push_str(&label(lbl));
        out.push_str(&" ".repeat(pad + 2));
        out.push_str(val);
        out.push('\n');
    }
    out
}

/// The `Filter:` header for a list command, built from each filter's
/// (label, value). `None` values are dropped; with none left it is empty.
///
/// `[("status", Some("active")), ("assigned", None)] -> "Filter:\n  status  active\n\n"`
/// `[("assigned", None)] -> ""`
fn render_filter_header(pairs: &[(&str, Option<&str>)]) -> String {
    let active: Vec<(String, String)> = pairs
        .iter()
        .filter_map(|(label, value)| value.map(|v| (label.to_string(), v.to_string())))
        .collect();
    if active.is_empty() {
        return String::new();
    }
    let mut out = render_filter_block(&active);
    out.push('\n');
    out
}

// =========================================================================
// USER LIST (section 7.1)
// =========================================================================

pub struct UserView<'a> {
    pub id: &'a str,
    pub email: &'a str,
    pub state: &'a str,
    pub permissions: &'a [String],
    pub profile_names: Vec<String>,
    pub created_at: &'a str,
    pub extra: &'a BTreeMap<String, Value>,
}

pub fn user_list_cards(users: &[UserView<'_>], filter: &UserListFilter) -> String {
    if users.is_empty() {
        return empty_state("users");
    }
    let mut out = String::new();
    out.push_str(&render_filter_header(&[
        ("status", filter.status.as_deref()),
        ("assigned", filter.assigned.as_deref()),
    ]));

    for (i, u) in users.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&card_title_id(u.email));
        out.push('\n');

        let mut rows: Vec<CardRow> = Vec::new();
        rows.push(CardRow::new("id", u.id.to_string()));
        rows.push(CardRow::new("state", user_state(u.state)));
        let perms: Vec<String> = u.permissions.to_vec();
        let (first, conts) = wrap_comma_list(&perms, 80);
        rows.push(CardRow::with_continuations("permissions", first, conts));
        let prof_text = if u.profile_names.is_empty() {
            "-".to_string()
        } else {
            u.profile_names.join(", ")
        };
        rows.push(CardRow::new("profiles", prof_text));
        rows.push(CardRow::new("created", format_timestamp(u.created_at)));
        append_extra_rows(&mut rows, u.extra);

        out.push_str(&render_card_body(&rows));
    }
    out.push('\n');
    out.push_str(&footer_line(users.len(), "users"));
    out
}

// =========================================================================
// CVM LIST (section 7.2)
// =========================================================================

pub struct CvmView<'a> {
    pub id: &'a str,
    /// Local alias for this CVM — see [`AliasCell`].
    pub alias: AliasCell<'a>,
    pub state: &'a str,
    pub error_reason: Option<&'a str>,
    pub fqdn: Option<&'a str>,
    pub instance_type: Option<&'a str>,
    pub region: Option<&'a str>,
    pub disk_size_gb: Option<u64>,
    pub profile_names: Vec<String>,
    pub ssh_key_labels: Vec<String>,
    pub owner_email: &'a str,
    pub created_at: &'a str,
    pub updated_at: &'a str,
    pub extra: &'a BTreeMap<String, Value>,
}

pub fn cvm_list_cards(cvms: &[CvmView<'_>], filter: &CvmListFilter) -> String {
    if cvms.is_empty() {
        return empty_state("cvms");
    }
    let mut out = String::new();
    out.push_str(&render_filter_header(&[
        ("profile", filter.profile.as_deref()),
        ("state", filter.state.as_deref()),
    ]));

    for (i, c) in cvms.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&card_title_uuid(c.id));
        out.push('\n');

        let mut rows: Vec<CardRow> = Vec::new();
        // Directly under the title: the alias is the other identifier for this
        // record, and the one every later verb accepts in place of the UUID.
        rows.push(CardRow::new("alias", alias_cell(c.alias)));
        rows.push(CardRow::new("state", cvm_state(c.state)));
        if let Some(err) = c.error_reason {
            if !err.is_empty() {
                // Console-sourced free-form string; sanitise before render
                // (section 4 / ANSI hardening).
                rows.push(CardRow::new("error", error_style(sanitize_ascii(err))));
            }
        }
        let fqdn_val = match c.fqdn {
            Some(f) if !f.is_empty() => value(f),
            _ => "-".to_string(),
        };
        rows.push(CardRow::new("fqdn", fqdn_val));
        rows.push(CardRow::new(
            "instance type",
            c.instance_type.unwrap_or("-").to_string(),
        ));
        rows.push(CardRow::new("region", c.region.unwrap_or("-").to_string()));
        rows.push(CardRow::new(
            "disk",
            c.disk_size_gb
                .map(|g| format!("{g} GB"))
                .unwrap_or_else(|| "-".to_string()),
        ));
        if filter.profile.is_none() {
            let prof_text = if c.profile_names.is_empty() {
                "-".to_string()
            } else {
                c.profile_names.join(", ")
            };
            rows.push(CardRow::new("profiles", prof_text));
        }
        let ssh_text = if c.ssh_key_labels.is_empty() {
            "-".to_string()
        } else {
            c.ssh_key_labels.join(", ")
        };
        rows.push(CardRow::new("ssh keys", ssh_text));
        rows.push(CardRow::new("owner", c.owner_email.to_string()));
        rows.push(CardRow::new("created", format_timestamp(c.created_at)));
        rows.push(CardRow::new("updated", format_timestamp(c.updated_at)));
        append_extra_rows(&mut rows, c.extra);

        out.push_str(&render_card_body(&rows));
    }
    out.push('\n');
    out.push_str(&footer_line(cvms.len(), "cvms"));
    out
}

// =========================================================================
// PROFILE LIST (section 7.3)
// =========================================================================

pub struct ProfileView<'a> {
    pub id: &'a str,
    /// Local alias for this profile — see [`AliasCell`].
    pub alias: AliasCell<'a>,
    pub name: &'a str,
    pub assigned: bool,
    pub attached_cvm_count: u64,
    pub attached_cvm_ids: Vec<String>,
    pub created_at: &'a str,
    pub updated_at: &'a str,
    pub extra: &'a BTreeMap<String, Value>,
}

pub fn profile_list_cards(profiles: &[ProfileView<'_>], filter: &ProfileListFilter) -> String {
    if profiles.is_empty() {
        return empty_state("profiles");
    }
    let mut out = String::new();
    out.push_str(&render_filter_header(&[(
        "assigned",
        filter.assigned.as_deref(),
    )]));

    for (i, p) in profiles.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&card_title_id(p.name));
        out.push('\n');

        let mut rows: Vec<CardRow> = Vec::new();
        rows.push(CardRow::new("id", p.id.to_string()));
        rows.push(CardRow::new("alias", alias_cell(p.alias)));
        let assigned_text = if p.assigned { "yes" } else { "no" };
        rows.push(CardRow::new("assigned", yes_no(assigned_text)));
        let count_primary = p.attached_cvm_count.to_string();
        let continuations: Vec<String> = p.attached_cvm_ids.clone();
        rows.push(CardRow::with_continuations(
            "attached cvms",
            count_primary,
            continuations,
        ));
        rows.push(CardRow::new("created", format_timestamp(p.created_at)));
        rows.push(CardRow::new("updated", format_timestamp(p.updated_at)));
        append_extra_rows(&mut rows, p.extra);

        out.push_str(&render_card_body(&rows));
    }
    out.push('\n');
    out.push_str(&footer_line(profiles.len(), "profiles"));
    out
}

// =========================================================================
// KEY LIST (section 7.4)
// =========================================================================

pub struct KeyView<'a> {
    pub id: &'a str,
    /// Local alias for this SSH key — see [`AliasCell`].
    pub alias: AliasCell<'a>,
    pub label: &'a str,
    pub fingerprint: &'a str,
    pub algorithm: &'a str,
    pub created_at: &'a str,
    pub extra: &'a BTreeMap<String, Value>,
}

pub fn key_list_cards(keys: &[KeyView<'_>]) -> String {
    if keys.is_empty() {
        return empty_state("keys");
    }
    let mut out = String::new();
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&card_title_id(k.label));
        out.push('\n');

        let mut rows: Vec<CardRow> = vec![
            CardRow::new("id", k.id.to_string()),
            CardRow::new("alias", alias_cell(k.alias)),
            CardRow::new("fingerprint", k.fingerprint.to_string()),
            CardRow::new("algorithm", k.algorithm.to_string()),
            CardRow::new("created", format_timestamp(k.created_at)),
        ];
        append_extra_rows(&mut rows, k.extra);

        out.push_str(&render_card_body(&rows));
    }
    out.push('\n');
    out.push_str(&footer_line(keys.len(), "keys"));
    out
}

pub struct SecretView<'a> {
    pub name: &'a str,
    pub allowed_hosts: &'a [String],
    pub created_at: &'a str,
    pub updated_at: &'a str,
    pub extra: &'a BTreeMap<String, Value>,
}

pub fn secret_list_cards(secrets: &[SecretView<'_>]) -> String {
    if secrets.is_empty() {
        return empty_state("secrets");
    }
    let mut out = String::new();
    for (i, secret) in secrets.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&card_title_id(secret.name));
        out.push('\n');

        let mut rows: Vec<CardRow> = vec![
            CardRow::new("hosts", secret.allowed_hosts.join(", ")),
            CardRow::new("created", format_timestamp(secret.created_at)),
            CardRow::new("updated", format_timestamp(secret.updated_at)),
        ];
        append_extra_rows(&mut rows, secret.extra);

        out.push_str(&render_card_body(&rows));
    }
    out.push('\n');
    out.push_str(&footer_line(secrets.len(), "secrets"));
    out
}

// =========================================================================
// ALIASES (umbra alias list)
// =========================================================================

/// One local alias for rendering: the alias name, its kind, and its target
/// (`cvm` set only for session aliases, which carry the box they live on).
pub struct AliasView<'a> {
    pub name: &'a str,
    pub kind: &'a str,
    pub target: &'a str,
    pub cvm: Option<&'a str>,
}

/// Render `umbra alias list` grouped by kind: one `> <kind>` section header
/// (same idiom as `ps`, §7.9), then its aliases indented and column-aligned (a
/// session row also shows its CVM, under a dim `alias  session  cvm` column
/// header — the only three-column group, cryptic otherwise). Grouping keeps the
/// kind out of every row.
/// Sections are emitted in a fixed order and each kind is gathered explicitly,
/// so the output does not depend on the order of `aliases`.
pub fn alias_list_grouped(aliases: &[AliasView<'_>]) -> String {
    if aliases.is_empty() {
        return empty_state("aliases");
    }
    let mut out = String::new();
    let mut first = true;
    for kind in ["cvm", "profile", "ssh-key", "session"] {
        // Sanitise up front and align each column to its widest cell.
        let rows: Vec<(String, String, Option<String>)> = aliases
            .iter()
            .filter(|a| a.kind == kind)
            .map(|a| {
                (
                    sanitize_ascii(a.name),
                    sanitize_ascii(a.target),
                    a.cvm.map(sanitize_ascii),
                )
            })
            .collect();
        if rows.is_empty() {
            continue;
        }
        // Only the session group is three-column (`alias  session  cvm`) and so
        // cryptic without labels; it gets a dim column header. The two-column
        // groups (`alias  uuid`) read fine on their own and stay header-less.
        // The header labels join the width computation so data stays aligned.
        let header = (kind == "session").then_some(("alias", "session", "cvm"));
        let name_width = rows
            .iter()
            .map(|(name, ..)| name.len())
            .chain(header.map(|(name, ..)| name.len()))
            .max()
            .unwrap_or(0);
        let target_width = rows
            .iter()
            .filter(|(.., cvm)| cvm.is_some())
            .map(|(_, target, _)| target.len())
            .chain(header.map(|(_, target, _)| target.len()))
            .max()
            .unwrap_or(0);

        if !first {
            out.push('\n');
        }
        first = false;
        out.push_str(&card_title_section(kind));
        out.push('\n');
        if let Some((name, target, cvm)) = header {
            out.push_str(&label(format!(
                "  {name:<name_width$}  {target:<target_width$}  {cvm}"
            )));
            out.push('\n');
        }
        for (name, target, cvm) in &rows {
            match cvm {
                // Session: alias, session name, then the CVM it lives on.
                Some(cvm) => out.push_str(&format!(
                    "  {name:<name_width$}  {target:<target_width$}  {cvm}\n"
                )),
                None => out.push_str(&format!("  {name:<name_width$}  {target}\n")),
            }
        }
    }
    out.push('\n');
    out.push_str(&footer_line(aliases.len(), "aliases"));
    out
}

// =========================================================================
// AUDIT EVENTS (section 7.5)
// =========================================================================

pub struct AuditEventView<'a> {
    pub seq: u64,
    pub timestamp: &'a str,
    pub actor_email: Option<&'a str>,
    pub action: &'a str,
    pub target_type: &'a str,
    pub target_id: &'a str,
    pub description: &'a str,
    pub extra: &'a BTreeMap<String, Value>,
}

pub fn audit_events_cards(events: &[AuditEventView<'_>], filter: &AuditEventsFilter) -> String {
    if events.is_empty() {
        return empty_state("events");
    }
    let mut out = String::new();

    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Some(v) = &filter.actor {
        pairs.push(("actor".to_string(), v.clone()));
    }
    if let Some(v) = &filter.action {
        pairs.push(("action".to_string(), audit_action_style(v)));
    }
    let target_both = filter.target_type.is_some() && filter.target_id.is_some();
    if target_both {
        let t = format!(
            "{}/{}",
            filter.target_type.as_deref().unwrap_or(""),
            filter.target_id.as_deref().unwrap_or("")
        );
        pairs.push(("target".to_string(), t));
    } else {
        if let Some(v) = &filter.target_type {
            pairs.push(("target type".to_string(), v.clone()));
        }
        if let Some(v) = &filter.target_id {
            pairs.push(("target id".to_string(), v.clone()));
        }
    }
    if let Some(v) = &filter.from {
        pairs.push(("from".to_string(), format_timestamp(v)));
    }
    if let Some(v) = &filter.to {
        pairs.push(("to".to_string(), format_timestamp(v)));
    }
    if let Some(v) = filter.limit {
        pairs.push(("limit".to_string(), v.to_string()));
    }
    if let Some(v) = &filter.cursor {
        pairs.push(("cursor".to_string(), sanitize_ascii(v)));
    }
    if !pairs.is_empty() {
        out.push_str(&render_filter_block(&pairs));
        out.push('\n');
    }

    for (i, e) in events.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&card_title_seq(e.seq));
        out.push('\n');

        let mut rows: Vec<CardRow> = Vec::new();
        rows.push(CardRow::new("timestamp", format_timestamp(e.timestamp)));
        if filter.actor.is_none() {
            rows.push(CardRow::new(
                "actor",
                e.actor_email.unwrap_or("-").to_string(),
            ));
        }
        if filter.action.is_none() {
            rows.push(CardRow::new("action", audit_action_style(e.action)));
        }
        if !target_both {
            let target_val = format!("{}/{}", e.target_type, muted(e.target_id));
            rows.push(CardRow::new("target", target_val));
        }
        // Audit description is free-form Console-controlled text; sanitise.
        rows.push(CardRow::new("description", sanitize_ascii(e.description)));
        append_extra_rows(&mut rows, e.extra);

        out.push_str(&render_card_body(&rows));
    }
    out.push('\n');
    out.push_str(&footer_line(events.len(), "events"));
    out
}

// =========================================================================
// TRAFFIC LOGS (section 7.6)
// =========================================================================

pub struct TrafficLogView<'a> {
    pub timestamp: &'a str,
    pub cvm_id: Option<&'a str>,
    pub security_cvm_id: Option<&'a str>,
    pub method: Option<&'a str>,
    pub destination_host: Option<&'a str>,
    pub response_code: Option<u16>,
    pub decision: Option<&'a str>,
    pub bytes_transferred: u64,
    pub path: Option<&'a str>,
    /// Unknown wire fields. Currently not rendered (table form leaves no
    /// natural slot for per-row keys), but kept on the view so future
    /// revisions can surface them without breaking call sites.
    #[allow(dead_code)]
    pub extra: &'a BTreeMap<String, Value>,
}

pub fn traffic_logs_table(logs: &[TrafficLogView<'_>], filter: &TrafficLogsFilter) -> String {
    if logs.is_empty() {
        return empty_state("logs");
    }

    // Spec section 7.6: a `traffic-logs` page MUST always render as ONE
    // Filter header + ONE table + ONE footer, irrespective of how many
    // distinct `security_cvm_id` values the page contains. In the typical v0
    // case (at most one live SC per entity), all rows share the same SC and
    // the value is hoisted into the Filter header. When the page does carry
    // multiple SC ids AND the caller did not pin a value via
    // `--security-cvm`, the SC value is rendered as an additional column
    // (symmetric to the CVM column variant) instead of being hoisted.
    let distinct_sc: std::collections::BTreeSet<&str> =
        logs.iter().filter_map(|l| l.security_cvm_id).collect();

    let sc_varies = filter.security_cvm.is_none() && distinct_sc.len() >= 2;

    let pin_sc = if sc_varies {
        None
    } else {
        filter.security_cvm.clone().or_else(|| {
            logs.iter()
                .find_map(|l| l.security_cvm_id.map(str::to_string))
        })
    };

    render_traffic_logs_block(logs, filter, pin_sc.as_deref(), sc_varies)
}

fn render_traffic_logs_block(
    logs: &[TrafficLogView<'_>],
    filter: &TrafficLogsFilter,
    pin_sc: Option<&str>,
    include_sc_col: bool,
) -> String {
    let mut out = String::new();

    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Some(v) = &filter.cvm {
        pairs.push(("cvm".to_string(), v.clone()));
    }
    if let Some(v) = pin_sc {
        pairs.push(("security cvm".to_string(), v.to_string()));
    }
    if let Some(v) = &filter.from {
        pairs.push(("from".to_string(), format_timestamp(v)));
    }
    if let Some(v) = &filter.to {
        pairs.push(("to".to_string(), format_timestamp(v)));
    }
    if let Some(v) = filter.limit {
        pairs.push(("limit".to_string(), v.to_string()));
    }
    if let Some(v) = &filter.cursor {
        pairs.push(("cursor".to_string(), sanitize_ascii(v)));
    }
    if !pairs.is_empty() {
        out.push_str(&render_filter_block(&pairs));
        out.push('\n');
    }

    let include_cvm_col = filter.cvm.is_none();

    let mut raw_rows: Vec<Vec<String>> = Vec::new();
    let mut styled_rows: Vec<Vec<String>> = Vec::new();

    let mut headers: Vec<&'static str> = vec!["TIMESTAMP"];
    if include_cvm_col {
        headers.push("CVM");
    }
    if include_sc_col {
        headers.push("SECURITY CVM");
    }
    headers.extend(["METHOD", "HOST", "RESPONSE", "DECISION", "BYTES", "PATH"]);

    for log in logs {
        let ts = format_timestamp(log.timestamp);
        let method_raw = log.method.unwrap_or("-").to_string();
        let host_raw = log.destination_host.unwrap_or("-").to_string();
        let response_raw = log
            .response_code
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        let bytes_raw = log.bytes_transferred.to_string();
        let path_raw = log.path.unwrap_or("-").to_string();

        let mut raw: Vec<String> = vec![ts.clone()];
        let mut styled: Vec<String> = vec![muted(&ts)];

        if include_cvm_col {
            // Full UUID (no truncation) per section 7.6.
            let cvm_full = log.cvm_id.unwrap_or("-").to_string();
            raw.push(cvm_full.clone());
            styled.push(cvm_full);
        }
        if include_sc_col {
            // Full UUID (no truncation) -- symmetric with the CVM column.
            let sc_full = log.security_cvm_id.unwrap_or("-").to_string();
            raw.push(sc_full.clone());
            styled.push(sc_full);
        }
        raw.push(method_raw.clone());
        styled.push(method_style(log.method));

        raw.push(host_raw.clone());
        styled.push(if log.destination_host.is_some() {
            value(&host_raw)
        } else {
            "-".to_string()
        });

        raw.push(response_raw.clone());
        styled.push(response_code_style(log.response_code));

        let decision_raw = log.decision.unwrap_or("-").to_string();
        raw.push(decision_raw.clone());
        styled.push(if log.decision.is_some() {
            value(&decision_raw)
        } else {
            "-".to_string()
        });

        raw.push(bytes_raw.clone());
        styled.push(bytes_raw);

        raw.push(path_raw.clone());
        styled.push(path_raw);

        raw_rows.push(raw);
        styled_rows.push(styled);
    }

    let col_count = headers.len();
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &raw_rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() && cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }

    let mut header_line = String::new();
    for (i, h) in headers.iter().enumerate() {
        let mut cell = h.to_string();
        if i + 1 < col_count {
            let pad = widths[i].saturating_sub(cell.len());
            cell.push_str(&" ".repeat(pad));
        }
        if i > 0 {
            header_line.push(' ');
        }
        header_line.push_str(&header(cell));
    }
    out.push_str(&header_line);
    out.push('\n');

    for (raw, styled) in raw_rows.iter().zip(styled_rows.iter()) {
        let mut line = String::new();
        for (i, _) in styled.iter().enumerate() {
            if i > 0 {
                line.push(' ');
            }
            if i + 1 < col_count {
                let pad = widths[i].saturating_sub(raw[i].len());
                line.push_str(&styled[i]);
                line.push_str(&" ".repeat(pad));
            } else {
                line.push_str(&styled[i]);
            }
        }
        out.push_str(&line);
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&footer_line(logs.len(), "logs"));
    out
}

// =========================================================================
// ENTITY LIST (section 7.7)
// =========================================================================

pub struct EntityView<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub domain: &'a str,
    pub created_at: &'a str,
    pub extra: &'a BTreeMap<String, Value>,
}

pub fn entity_list_cards(entities: &[EntityView<'_>]) -> String {
    if entities.is_empty() {
        return empty_state("entities");
    }
    let mut out = String::new();
    for (i, e) in entities.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&card_title_id(e.name));
        out.push('\n');

        let mut rows: Vec<CardRow> = Vec::new();
        rows.push(CardRow::new("id", e.id.to_string()));
        rows.push(CardRow::new("domain", e.domain.to_string()));
        rows.push(CardRow::new("created", format_timestamp(e.created_at)));
        append_extra_rows(&mut rows, e.extra);

        out.push_str(&render_card_body(&rows));
    }
    out.push('\n');
    out.push_str(&footer_line(entities.len(), "entities"));
    out
}

// =========================================================================
// QUOTA LIST (section 7.8)
// =========================================================================

pub struct QuotaView<'a> {
    pub resource: &'a str,
    pub entity_id: Option<&'a str>,
    pub entity_name: Option<&'a str>,
    pub user_id: Option<&'a str>,
    pub user_email: Option<&'a str>,
    pub limit: u64,
    pub current_usage: u64,
    pub source: &'a str,
    pub set_by: Option<&'a str>,
    pub set_at: Option<&'a str>,
    pub extra: &'a BTreeMap<String, Value>,
}

/// Format a scope value per the section 7.8 resolution rule: `<noun>
/// <human-readable> <UUID>` with single spaces; falls back to `<noun> <UUID>`
/// when no human-readable label is available. No parens, no dash separator.
fn format_scope(noun: &str, human: Option<&str>, id: &str) -> String {
    match human.filter(|s| !s.is_empty() && *s != "-") {
        Some(name) => format!("{noun} {name} {id}"),
        None => format!("{noun} {id}"),
    }
}

/// Render a quota limit/usage value, suffixing " GB" for disk-size resources
/// whose values are expressed in GB (e.g. `disk_gb_per_cvm`).
fn quota_value(resource: &str, value: u64) -> String {
    if resource.starts_with("disk_gb_") {
        format!("{value} GB")
    } else {
        value.to_string()
    }
}

pub fn quota_get_cards(quotas: &[QuotaView<'_>], filter: &QuotaListFilter) -> String {
    if quotas.is_empty() {
        return empty_state("quotas");
    }
    let mut out = String::new();

    let scope_filtered = filter.entity_id.is_some() || filter.user_id.is_some();
    let mut pairs: Vec<(String, String)> = Vec::new();
    if let Some(id) = &filter.entity_id {
        pairs.push((
            "scope".to_string(),
            format_scope("entity", filter.entity_name.as_deref(), id),
        ));
    } else if let Some(id) = &filter.user_id {
        pairs.push((
            "scope".to_string(),
            format_scope("user", filter.user_email.as_deref(), id),
        ));
    }
    if !pairs.is_empty() {
        out.push_str(&render_filter_block(&pairs));
        out.push('\n');
    }

    for (i, q) in quotas.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&card_title_id(q.resource));
        out.push('\n');

        let mut rows: Vec<CardRow> = Vec::new();
        if !scope_filtered {
            let scope_text = if let Some(id) = q.entity_id {
                format_scope("entity", q.entity_name, id)
            } else if let Some(id) = q.user_id {
                format_scope("user", q.user_email, id)
            } else {
                "-".to_string()
            };
            rows.push(CardRow::new("scope", scope_text));
        }
        rows.push(CardRow::new("limit", quota_value(q.resource, q.limit)));
        rows.push(CardRow::new(
            "current usage",
            quota_value(q.resource, q.current_usage),
        ));
        rows.push(CardRow::new("source", quota_source_style(q.source)));
        rows.push(CardRow::new("set by", q.set_by.unwrap_or("-").to_string()));
        rows.push(CardRow::new("set at", format_optional_timestamp(q.set_at)));
        append_extra_rows(&mut rows, q.extra);

        out.push_str(&render_card_body(&rows));
    }
    out.push('\n');
    out.push_str(&footer_line(quotas.len(), "quotas"));
    out
}

/// Input arguments to [`quota_set_confirm`] (section 7.24).
pub struct QuotaSetConfirm<'a> {
    pub resource: &'a str,
    pub scope_noun: &'a str,
    pub scope_human: Option<&'a str>,
    pub scope_id: &'a str,
    pub limit: u64,
    pub previous_limit: Option<u64>,
    pub set_by: Option<&'a str>,
    pub next_step_flag: &'a str,
}

/// `quota set` confirm renderer (section 7.24).
pub fn quota_set_confirm(args: &QuotaSetConfirm<'_>) -> String {
    let confirm = ConfirmBlock {
        verb: "set".to_string(),
        entity_noun: "quota".to_string(),
        identifier: args.resource.to_string(),
        fields: vec![
            (
                "scope".to_string(),
                format_scope(args.scope_noun, args.scope_human, args.scope_id),
            ),
            ("limit".to_string(), quota_value(args.resource, args.limit)),
            (
                "previous limit".to_string(),
                args.previous_limit
                    .map(|v| quota_value(args.resource, v))
                    .unwrap_or_else(|| "-".to_string()),
            ),
            ("set by".to_string(), args.set_by.unwrap_or("-").to_string()),
        ],
        next_step: Some(format!(
            "umbra quota get --{} {}",
            args.next_step_flag, args.scope_id
        )),
    };
    render_confirm(&confirm)
}

/// Input arguments to [`quota_clear_confirm`] (section 7.24).
pub struct QuotaClearConfirm<'a> {
    pub resource: &'a str,
    pub scope_noun: &'a str,
    pub scope_human: Option<&'a str>,
    pub scope_id: &'a str,
    pub previous_limit: Option<u64>,
    pub next_step_flag: &'a str,
}

/// `quota clear` confirm renderer (section 7.24).
pub fn quota_clear_confirm(args: &QuotaClearConfirm<'_>) -> String {
    let confirm = ConfirmBlock {
        verb: "cleared".to_string(),
        entity_noun: "quota".to_string(),
        identifier: args.resource.to_string(),
        fields: vec![
            (
                "scope".to_string(),
                format_scope(args.scope_noun, args.scope_human, args.scope_id),
            ),
            (
                "previous limit".to_string(),
                args.previous_limit
                    .map(|v| quota_value(args.resource, v))
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ],
        next_step: Some(format!(
            "umbra quota get --{} {}",
            args.next_step_flag, args.scope_id
        )),
    };
    render_confirm(&confirm)
}

// =========================================================================
// PS (section 7.9)
// =========================================================================

pub struct PsSessionView<'a> {
    pub name: &'a str,
    pub attached: bool,
    /// Local alias of this session — see [`AliasCell`]. Same three states as the
    /// resource views: `ps` reports an unreadable store in the cell too, rather
    /// than failing the whole listing.
    pub alias: AliasCell<'a>,
    pub created_at: &'a str,
    pub extra: &'a BTreeMap<String, Value>,
}

/// One Dev CVM's group in `umbra ps`: its sessions, or the probe error that
/// replaces them. Rendered even when empty/errored so every running CVM shows.
pub struct PsCvmGroup<'a> {
    pub cvm_id: &'a str,
    pub error: Option<&'a str>,
    pub sessions: Vec<PsSessionView<'a>>,
}

/// Render dtach sessions grouped by Dev CVM (spec section 7.9). Each group is
/// titled by its CVM; its sessions, a one-line error, or `no sessions` are nested
/// one level under it (indentation, not colour, carries the hierarchy so it
/// survives the no-colour toggle). The footer counts sessions across all groups.
pub fn ps_cards(groups: &[PsCvmGroup<'_>]) -> String {
    if groups.is_empty() {
        return empty_state("sessions");
    }
    let mut out = String::new();
    let mut total = 0usize;
    for (i, group) in groups.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&card_title_section(group.cvm_id));
        out.push('\n');
        // One "content" block per group, then a single nesting pass for all three
        // branches (sessions / error / empty) -- one indent mechanism, not two.
        let content = if let Some(message) = group.error {
            format!("{}\n", error_style(format!("error  {message}")))
        } else if group.sessions.is_empty() {
            format!("{}\n", empty_state("sessions"))
        } else {
            total += group.sessions.len();
            group.sessions.iter().map(render_session_card).collect()
        };
        out.push_str(&indent_block(&content, GROUP_NEST_INDENT));
    }
    out.push('\n');
    out.push_str(&footer_line(total, "sessions"));
    out
}

/// Nesting indent for a `ps` session under its CVM group header.
const GROUP_NEST_INDENT: usize = 2;

/// Indent every non-empty line of `block` by `spaces`, preserving its newlines.
fn indent_block(block: &str, spaces: usize) -> String {
    let pad = " ".repeat(spaces);
    block
        .lines()
        .map(|line| {
            if line.is_empty() {
                "\n".to_string()
            } else {
                format!("{pad}{line}\n")
            }
        })
        .collect()
}

fn render_session_card(s: &PsSessionView<'_>) -> String {
    let mut out = card_title_id(s.name);
    out.push('\n');
    let attached = if s.attached { "yes" } else { "no" };
    let mut rows = vec![
        CardRow::new("attached", yes_no(attached)),
        CardRow::new("alias", alias_cell(s.alias)),
        CardRow::new("created", format_timestamp(s.created_at)),
    ];
    append_extra_rows(&mut rows, s.extra);
    out.push_str(&render_card_body(&rows));
    out
}

// =========================================================================
// STATUS (section 7.10)
// =========================================================================

pub struct StatusSecurityCvm<'a> {
    pub id: &'a str,
    pub state: &'a str,
    pub region: Option<&'a str>,
    pub instance_type: Option<&'a str>,
    pub policy_version: u64,
}

pub struct StatusProfileSummary<'a> {
    pub id: &'a str,
    pub name: &'a str,
    pub attached_cvm_count: u64,
}

pub struct StatusKeySummary<'a> {
    pub id: &'a str,
    pub label: &'a str,
    pub fingerprint: &'a str,
    pub algorithm: &'a str,
}

/// Compact Dev CVM row used in the `Dev CVMs by profile` section
/// (spec section 7.10). Each entry is one line under the parent profile.
pub struct StatusDevCvmRow<'a> {
    pub id: &'a str,
    pub state: &'a str,
    /// Tail value: `fqdn` when state is `running`, else `error_reason`
    /// (or `-` when neither is set).
    pub tail: &'a str,
}

/// One profile's grouped Dev CVMs for the `Dev CVMs by profile` section
/// (spec section 7.10). Profiles with zero attached CVMs render a
/// `none` line under the profile header.
pub struct StatusDevCvmsByProfile<'a> {
    pub profile_name: &'a str,
    pub cvms: Vec<StatusDevCvmRow<'a>>,
}

pub struct StatusView<'a> {
    pub user_email: &'a str,
    pub user_id: &'a str,
    pub entity_name: &'a str,
    pub entity_id: &'a str,
    pub console_url: Option<&'a str>,
    pub security_cvm: Option<StatusSecurityCvm<'a>>,
    /// When true, the entire `Security CVM` section MUST be omitted from
    /// the rendered output. This signals that the caller lacks the
    /// `SECURITY_CVM_CONFIGURE` permission required to read the SC record
    /// (Console returned HTTP 403). It is distinct from
    /// `security_cvm == None`, which means "no SC provisioned" and renders
    /// as a `none` body line. See spec section 7.10.
    pub security_cvm_hidden: bool,
    pub totals_profiles: usize,
    pub totals_dev_cvms: usize,
    pub totals_dev_cvms_state_breakdown: Vec<(String, usize)>,
    pub totals_ssh_keys: usize,
    /// Per-profile grouping of Dev CVMs, in the order to render. Section
    /// 7.10 places this section between Totals and Profiles. An empty Vec
    /// suppresses the whole section.
    pub dev_cvms_by_profile: Vec<StatusDevCvmsByProfile<'a>>,
    pub profiles: Vec<StatusProfileSummary<'a>>,
    pub ssh_keys: Vec<StatusKeySummary<'a>>,
}

/// Three-column card row (section 6.1.1). The slots are:
/// - `label` (left)
/// - `primary` (middle: human-readable identifier)
/// - `tail` (right: typically the entity UUID, or the literal `-` when no UUID
///   applies for that row, or any other tail-column text like a count summary)
///
/// Like the standard 2-column body, the renderer computes per-section column
/// widths from the longest label and longest primary value.
struct ThreeColRow {
    label_text: String,
    /// Raw (unstyled) primary value, used for width computation.
    primary_raw: String,
    /// Already-styled primary cell, emitted as-is.
    primary_styled: String,
    /// Tail-column cell, already styled.
    tail: String,
}

impl ThreeColRow {
    /// Construct a 3-column row by supplying every field explicitly. The
    /// caller is responsible for providing matched `primary_raw` (used for
    /// column-width math) and `primary_styled` (printed verbatim). This is
    /// the only constructor; there is no setter-style post-construction
    /// mutation API, so misaligned rows show up at construction time rather
    /// than as a silent layout bug downstream.
    fn new(
        label_text: impl Into<String>,
        primary_raw: impl Into<String>,
        primary_styled: impl Into<String>,
        tail: impl Into<String>,
    ) -> Self {
        Self {
            label_text: label_text.into(),
            primary_raw: primary_raw.into(),
            primary_styled: primary_styled.into(),
            tail: tail.into(),
        }
    }
}

fn render_three_col_body(rows: &[ThreeColRow]) -> String {
    let max_label = rows.iter().map(|r| r.label_text.len()).max().unwrap_or(0);
    let max_primary = rows.iter().map(|r| r.primary_raw.len()).max().unwrap_or(0);
    let mut out = String::new();
    for row in rows {
        let label_pad = max_label - row.label_text.len();
        let primary_pad = max_primary - row.primary_raw.len();
        out.push_str(&" ".repeat(OUTER_INDENT));
        out.push_str(&label(&row.label_text));
        out.push_str(&" ".repeat(label_pad + 2));
        out.push_str(&row.primary_styled);
        out.push_str(&" ".repeat(primary_pad + 2));
        out.push_str(&row.tail);
        out.push('\n');
    }
    out
}

pub fn status_multi_section(s: &StatusView<'_>) -> String {
    let mut out = String::new();

    // Section: Session (3-column variant).
    out.push_str(&card_title_section("Session"));
    out.push('\n');
    let console_primary_raw = s.console_url.unwrap_or("-").to_string();
    let console_primary_styled = match s.console_url {
        Some(u) => info(u),
        None => muted("-"),
    };
    let session_rows = vec![
        ThreeColRow::new(
            "user",
            s.user_email.to_string(),
            value(s.user_email),
            muted(s.user_id),
        ),
        ThreeColRow::new(
            "entity",
            s.entity_name.to_string(),
            value(s.entity_name),
            muted(s.entity_id),
        ),
        ThreeColRow::new(
            "console",
            console_primary_raw,
            console_primary_styled,
            "-".to_string(),
        ),
    ];
    out.push_str(&render_three_col_body(&session_rows));
    out.push('\n');

    // Section: Security CVM (standard 2-column rows). Omitted entirely
    // when the caller lacks SECURITY_CVM_CONFIGURE (per spec section 7.10).
    if !s.security_cvm_hidden {
        out.push_str(&card_title_section("Security CVM"));
        out.push('\n');
        match &s.security_cvm {
            Some(sc) => {
                let rows = vec![
                    CardRow::new("id", sc.id.to_string()),
                    CardRow::new("state", cvm_state(sc.state)),
                    CardRow::new("region", sc.region.unwrap_or("-").to_string()),
                    CardRow::new("instance", sc.instance_type.unwrap_or("-").to_string()),
                    CardRow::new("policy", format!("v{}", sc.policy_version)),
                ];
                out.push_str(&render_card_body(&rows));
            }
            None => {
                out.push_str(&" ".repeat(OUTER_INDENT));
                out.push_str(&error_style("none"));
                out.push('\n');
            }
        }
        out.push('\n');
    }

    // Section: Totals (standard 2-column rows).
    out.push_str(&card_title_section("Totals"));
    out.push('\n');
    let dev_cvms_text = if s.totals_dev_cvms_state_breakdown.is_empty() {
        s.totals_dev_cvms.to_string()
    } else {
        let breakdown = s
            .totals_dev_cvms_state_breakdown
            .iter()
            .map(|(state, count)| format!("{count} {state}"))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{}  ({})", s.totals_dev_cvms, breakdown)
    };
    let totals_rows = vec![
        CardRow::new("profiles", s.totals_profiles.to_string()),
        CardRow::new("dev cvms", dev_cvms_text),
        CardRow::new("ssh keys", s.totals_ssh_keys.to_string()),
    ];
    out.push_str(&render_card_body(&totals_rows));

    // Section: Dev CVMs by profile (spec section 7.10). Each profile gets a
    // header line; each attached CVM gets a compact one-liner under it.
    if !s.dev_cvms_by_profile.is_empty() {
        out.push('\n');
        out.push_str(&card_title_section("Dev CVMs by profile"));
        out.push('\n');
        // Column-align the CVM rows globally across all profiles for visual
        // consistency: UUIDs are fixed-width but state widths vary
        // (`running` vs `stopped` vs `error`).
        let max_state = s
            .dev_cvms_by_profile
            .iter()
            .flat_map(|group| group.cvms.iter().map(|cvm| cvm.state.len()))
            .max()
            .unwrap_or(0);
        let max_id = s
            .dev_cvms_by_profile
            .iter()
            .flat_map(|group| group.cvms.iter().map(|cvm| cvm.id.len()))
            .max()
            .unwrap_or(0);
        for group in &s.dev_cvms_by_profile {
            // Profile header: 6-space indent, bold name.
            out.push_str(&" ".repeat(OUTER_INDENT));
            out.push_str(&value(group.profile_name));
            out.push('\n');
            if group.cvms.is_empty() {
                // Empty-profile case: render the literal `none` under the
                // header so the operator knows it is intentional.
                out.push_str(&" ".repeat(OUTER_INDENT + 2));
                out.push_str(&muted("none"));
                out.push('\n');
                continue;
            }
            for cvm in &group.cvms {
                let id_pad = max_id - cvm.id.len();
                let state_pad = max_state - cvm.state.len();
                // CVM line: 8-space indent (2 deeper than the profile header).
                out.push_str(&" ".repeat(OUTER_INDENT + 2));
                out.push_str(&muted(cvm.id));
                out.push_str(&" ".repeat(id_pad + 2));
                out.push_str(&cvm_state(cvm.state));
                out.push_str(&" ".repeat(state_pad + 2));
                out.push_str(cvm.tail);
                out.push('\n');
            }
        }
    }

    // Section: Profiles (3-column variant; tail = "<N> cvm[s] attached").
    if !s.profiles.is_empty() {
        out.push('\n');
        out.push_str(&card_title_section_with_hint(
            "Profiles",
            "(use `umbra profile list` for detail)",
        ));
        out.push('\n');
        let mut rows: Vec<ThreeColRow> = Vec::new();
        for p in &s.profiles {
            let noun = if p.attached_cvm_count == 1 {
                "cvm attached"
            } else {
                "cvms attached"
            };
            // Section 7.10 spec example: `<name>  <uuid>  <N> cvm[s] attached`.
            // Profile rows have no leading field-label slot, so the label
            // column is empty. Primary = bolded name; tail packs the UUID and
            // cvm-count text together to stay within the 3-slot row API.
            rows.push(ThreeColRow::new(
                "".to_string(),
                p.name.to_string(),
                value(p.name),
                format!("{}  {} {noun}", muted(p.id), p.attached_cvm_count),
            ));
        }
        out.push_str(&render_three_col_body(&rows));
    }

    // Section: SSH Keys (3-column variant extended with fingerprint+algorithm).
    if !s.ssh_keys.is_empty() {
        out.push('\n');
        out.push_str(&card_title_section_with_hint(
            "SSH Keys",
            "(use `umbra key list` for detail)",
        ));
        out.push('\n');
        // Compute widths over (primary = label, middle = id, then fingerprint,
        // then algorithm).
        let max_primary = s.ssh_keys.iter().map(|k| k.label.len()).max().unwrap_or(0);
        let max_id = s.ssh_keys.iter().map(|k| k.id.len()).max().unwrap_or(0);
        let max_fp = s
            .ssh_keys
            .iter()
            .map(|k| k.fingerprint.len())
            .max()
            .unwrap_or(0);
        for k in &s.ssh_keys {
            let primary_pad = max_primary - k.label.len();
            let id_pad = max_id - k.id.len();
            let fp_pad = max_fp - k.fingerprint.len();
            out.push_str(&" ".repeat(OUTER_INDENT));
            out.push_str(&value(k.label));
            out.push_str(&" ".repeat(primary_pad + 2));
            out.push_str(&muted(k.id));
            out.push_str(&" ".repeat(id_pad + 2));
            out.push_str(k.fingerprint);
            out.push_str(&" ".repeat(fp_pad + 2));
            out.push_str(k.algorithm);
            out.push('\n');
        }
    }

    // Trim trailing newline (render_*_body always emits one).
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

// =========================================================================
// CONFIG SHOW (section 7.11)
// =========================================================================

pub struct ConfigEntryView<'a> {
    pub key: &'a str,
    pub value: Option<&'a str>,
    pub source: &'a str,
}

pub fn config_show_table(entries: &[ConfigEntryView<'_>]) -> String {
    if entries.is_empty() {
        return empty_state("config entries");
    }
    let headers = ["KEY", "VALUE", "SOURCE"];
    let mut raw: Vec<[String; 3]> = Vec::new();
    let mut styled: Vec<[String; 3]> = Vec::new();
    for e in entries {
        let key = e.key.to_string();
        let val_raw = match e.value {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => "(none)".to_string(),
        };
        let val_styled = match e.value {
            Some(v) if !v.is_empty() => v.to_string(),
            _ => muted("(none)"),
        };
        let src = e.source.to_string();
        let src_styled = config_source_style(e.source);
        raw.push([key.clone(), val_raw.clone(), src.clone()]);
        styled.push([key, val_styled, src_styled]);
    }
    let mut widths = headers.iter().map(|h| h.len()).collect::<Vec<_>>();
    for row in &raw {
        for (i, cell) in row.iter().enumerate() {
            if cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }
    let col_count = headers.len();
    let mut out = String::new();
    let mut line = String::new();
    for (i, h) in headers.iter().enumerate() {
        let mut cell = h.to_string();
        if i + 1 < col_count {
            let pad = widths[i].saturating_sub(cell.len());
            cell.push_str(&" ".repeat(pad));
        }
        if i > 0 {
            line.push_str("  ");
        }
        line.push_str(&header(cell));
    }
    out.push_str(&line);
    out.push('\n');
    for (raw_row, styled_row) in raw.iter().zip(styled.iter()) {
        let mut row_line = String::new();
        for i in 0..col_count {
            if i > 0 {
                row_line.push_str("  ");
            }
            if i + 1 < col_count {
                let pad = widths[i].saturating_sub(raw_row[i].len());
                row_line.push_str(&styled_row[i]);
                row_line.push_str(&" ".repeat(pad));
            } else {
                row_line.push_str(&styled_row[i]);
            }
        }
        out.push_str(&row_line);
        out.push('\n');
    }
    // Drop trailing newline.
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

// =========================================================================
// VERSION (section 7.12)
// =========================================================================

pub fn version_card(version: &str, commit: &str, target: &str, build_date: &str) -> String {
    let mut out = String::new();
    out.push_str(&card_title_id(&format!("umbra {version}")));
    out.push('\n');
    let rows = vec![
        CardRow::new("commit", commit.to_string()),
        CardRow::new("target", target.to_string()),
        CardRow::new("build date", build_date.to_string()),
    ];
    out.push_str(&render_card_body(&rows));
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

// =========================================================================
// SECURITY CVM SHOW (section 7.13)
// =========================================================================

pub struct SecurityCvmView<'a> {
    pub id: &'a str,
    pub state: &'a str,
    pub error_reason: Option<&'a str>,
    pub fqdn: &'a str,
    pub instance_type: Option<&'a str>,
    pub region: Option<&'a str>,
    pub policy_version: u64,
    pub attestation_verified_at: Option<&'a str>,
    pub created_at: &'a str,
    pub updated_at: &'a str,
    pub extra: &'a BTreeMap<String, Value>,
}

pub fn security_cvm_card(sc: &SecurityCvmView<'_>) -> String {
    let mut out = String::new();
    out.push_str(&card_title_section("Security CVM"));
    out.push('\n');
    let mut rows: Vec<CardRow> = Vec::new();
    rows.push(CardRow::new("id", sc.id.to_string()));
    rows.push(CardRow::new("state", cvm_state(sc.state)));
    if let Some(err) = sc.error_reason {
        if !err.is_empty() {
            // Console-sourced free-form string; sanitise before render
            // (section 4 / ANSI hardening).
            rows.push(CardRow::new("error", error_style(sanitize_ascii(err))));
        }
    }
    rows.push(CardRow::new("fqdn", value(sc.fqdn)));
    rows.push(CardRow::new(
        "instance",
        sc.instance_type.unwrap_or("-").to_string(),
    ));
    rows.push(CardRow::new("region", sc.region.unwrap_or("-").to_string()));
    rows.push(CardRow::new(
        "policy version",
        format!("v{}", sc.policy_version),
    ));
    rows.push(CardRow::new(
        "attested",
        format_optional_timestamp(sc.attestation_verified_at),
    ));
    rows.push(CardRow::new("created", format_timestamp(sc.created_at)));
    rows.push(CardRow::new("updated", format_timestamp(sc.updated_at)));
    append_extra_rows(&mut rows, sc.extra);

    out.push_str(&render_card_body(&rows));
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

// =========================================================================
// AUTH STATUS (section 7.21)
// =========================================================================

pub struct AuthStatusView<'a> {
    pub user_id: Option<&'a str>,
    pub user_email: Option<&'a str>,
    pub entity_id: Option<&'a str>,
    pub entity_name: Option<&'a str>,
    /// Access-token state: one of `valid`, `expired`, `missing`.
    pub access_token_state: &'a str,
    /// Access-token expiration timestamp (RFC 3339); None when missing.
    pub access_token_expires_at: Option<&'a str>,
    /// Refresh-token state: one of `valid`, `expired`, `missing`.
    pub refresh_token_state: &'a str,
    pub refresh_token_expires_at: Option<&'a str>,
    pub config_dir: &'a str,
    pub config_dir_source: &'a str,
    pub console_url: Option<&'a str>,
    pub console_url_source: &'a str,
    pub session_path: &'a str,
    pub session_permissions: Option<&'a str>,
}

fn token_state_style(state: &str) -> String {
    match state.to_ascii_lowercase().as_str() {
        "valid" | "available" => success(state),
        "expired" => warn(state),
        "missing" | "absent" => error_style(state),
        _ => state.to_string(),
    }
}

pub fn auth_status_card(s: &AuthStatusView<'_>) -> String {
    // Empty / unauthenticated short-circuit (per section 7.21 empty rule).
    if s.user_id.is_none() && s.user_email.is_none() && s.access_token_state == "missing" {
        return muted("no session");
    }
    let mut out = String::new();

    // Section: User
    out.push_str(&card_title_section("User"));
    out.push('\n');
    let user_rows = vec![
        CardRow::new("id", s.user_id.unwrap_or("-").to_string()),
        CardRow::new("email", value(s.user_email.unwrap_or("-"))),
    ];
    out.push_str(&render_card_body(&user_rows));
    out.push('\n');

    // Section: Entity
    out.push_str(&card_title_section("Entity"));
    out.push('\n');
    let entity_rows = vec![
        CardRow::new("id", s.entity_id.unwrap_or("-").to_string()),
        CardRow::new("name", value(s.entity_name.unwrap_or("-"))),
    ];
    out.push_str(&render_card_body(&entity_rows));
    out.push('\n');

    // Section: Tokens
    out.push_str(&card_title_section("Tokens"));
    out.push('\n');
    let access_text = match s.access_token_expires_at {
        Some(ts) if !ts.is_empty() => {
            format!(
                "{}    expires {}",
                token_state_style(s.access_token_state),
                format_timestamp(ts)
            )
        }
        _ => token_state_style(s.access_token_state),
    };
    let refresh_text = match s.refresh_token_expires_at {
        Some(ts) if !ts.is_empty() => {
            format!(
                "{}    expires {}",
                token_state_style(s.refresh_token_state),
                format_timestamp(ts)
            )
        }
        _ => token_state_style(s.refresh_token_state),
    };
    let tokens_rows = vec![
        CardRow::new("access token", access_text),
        CardRow::new("refresh token", refresh_text),
    ];
    out.push_str(&render_card_body(&tokens_rows));
    out.push('\n');

    // Section: Config
    out.push_str(&card_title_section("Config"));
    out.push('\n');
    let config_rows = vec![
        CardRow::new(
            "config dir",
            format!(
                "{}  ({})",
                s.config_dir,
                config_source_style(s.config_dir_source)
            ),
        ),
        CardRow::new(
            "console url",
            format!(
                "{}  ({})",
                s.console_url.unwrap_or("-"),
                config_source_style(s.console_url_source)
            ),
        ),
    ];
    out.push_str(&render_card_body(&config_rows));
    out.push('\n');

    // Section: Session file
    out.push_str(&card_title_section("Session file"));
    out.push('\n');
    let session_rows = vec![
        CardRow::new("path", s.session_path.to_string()),
        CardRow::new(
            "permissions",
            s.session_permissions.unwrap_or("-").to_string(),
        ),
    ];
    out.push_str(&render_card_body(&session_rows));

    if out.ends_with('\n') {
        out.pop();
    }
    out
}

// =========================================================================
// PROFILE SHOW (section 7.22)
// =========================================================================

pub struct ProfileShowView<'a> {
    pub id: &'a str,
    /// Local alias for this profile — see [`AliasCell`].
    pub alias: AliasCell<'a>,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub assigned: bool,
    pub attached_cvm_count: u64,
    pub attached_cvm_ids: Vec<String>,
    pub policy_pretty: &'a str,
    pub created_at: &'a str,
    pub updated_at: &'a str,
    pub extra: &'a BTreeMap<String, Value>,
}

pub fn profile_show_card(p: &ProfileShowView<'_>) -> String {
    let mut out = String::new();
    out.push_str(&card_title_id(p.name));
    out.push('\n');

    let mut rows: Vec<CardRow> = Vec::new();
    rows.push(CardRow::new("id", p.id.to_string()));
    rows.push(CardRow::new("alias", alias_cell(p.alias)));
    rows.push(CardRow::new(
        "description",
        match p.description {
            // Console-sourced free-form text; sanitise.
            Some(d) if !d.is_empty() => sanitize_ascii(d),
            _ => "-".to_string(),
        },
    ));
    let assigned_text = if p.assigned { "yes" } else { "no" };
    rows.push(CardRow::new("assigned", yes_no(assigned_text)));
    let count_primary = p.attached_cvm_count.to_string();
    let continuations: Vec<String> = p.attached_cvm_ids.clone();
    rows.push(CardRow::with_continuations(
        "attached cvms",
        count_primary,
        continuations,
    ));
    let mut policy_lines = p.policy_pretty.lines();
    let first = policy_lines.next().unwrap_or("").to_string();
    let conts: Vec<String> = policy_lines.map(str::to_string).collect();
    rows.push(CardRow::with_continuations("policy", first, conts));
    rows.push(CardRow::new("created", format_timestamp(p.created_at)));
    rows.push(CardRow::new("updated", format_timestamp(p.updated_at)));
    append_extra_rows(&mut rows, p.extra);

    out.push_str(&render_card_body(&rows));
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

// =========================================================================
// PROFILE MEMBERS LIST (section 7.23)
// =========================================================================

pub struct ProfileMemberView<'a> {
    pub user_id: &'a str,
    pub email: &'a str,
    pub added_at: &'a str,
    pub extra: &'a BTreeMap<String, Value>,
}

#[derive(Default)]
pub struct ProfileMembersFilter {
    /// Profile UUID (always set; the listing is scoped to one profile).
    pub profile_id: String,
    /// Resolved human-readable name when available.
    pub profile_name: Option<String>,
}

pub fn profile_members_list_cards(
    members: &[ProfileMemberView<'_>],
    filter: &ProfileMembersFilter,
) -> String {
    if members.is_empty() {
        return empty_state("members");
    }
    let mut out = String::new();
    let pairs = vec![(
        "scope".to_string(),
        format_scope(
            "profile",
            filter.profile_name.as_deref(),
            &filter.profile_id,
        ),
    )];
    out.push_str(&render_filter_block(&pairs));
    out.push('\n');

    for (i, m) in members.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&card_title_id(m.email));
        out.push('\n');
        let mut rows: Vec<CardRow> = Vec::new();
        rows.push(CardRow::new("user id", m.user_id.to_string()));
        rows.push(CardRow::new("added at", format_timestamp(m.added_at)));
        append_extra_rows(&mut rows, m.extra);
        out.push_str(&render_card_body(&rows));
    }
    out.push('\n');
    out.push_str(&footer_line(members.len(), "members"));
    out
}

// =========================================================================
// CONFIRM blocks (sections 6.4 + 7.14 .. 7.19)
// =========================================================================

pub struct ConfirmBlock {
    pub verb: String,
    pub entity_noun: String,
    pub identifier: String,
    pub fields: Vec<(String, String)>,
    pub next_step: Option<String>,
}

impl ConfirmBlock {
    /// Construct a confirm with the header parts only. Detail rows and the
    /// next-step suggestion are appended via [`Self::field`] /
    /// [`Self::next_step`].
    pub fn new(
        verb: impl Into<String>,
        entity_noun: impl Into<String>,
        identifier: impl Into<String>,
    ) -> Self {
        Self {
            verb: verb.into(),
            entity_noun: entity_noun.into(),
            identifier: identifier.into(),
            fields: Vec::new(),
            next_step: None,
        }
    }

    /// Append a detail row (`label: value`) to the confirm. Section 6.4 rules
    /// apply to label order and value styling.
    pub fn field(mut self, label: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.push((label.into(), value.into()));
        self
    }

    /// Attach a `next:` suggestion to the confirm. Replaces any earlier
    /// suggestion (last call wins).
    pub fn next_step(mut self, command: impl Into<String>) -> Self {
        self.next_step = Some(command.into());
        self
    }
}

/// Render the confirm block emitted by `--no-wait` async mutations
/// (cvm/security-cvm launch / terminate / update). The CLI dispatched the
/// operation, the Console accepted it, but the saga has not yet finished.
/// We expose the operation handle, the current status (pending / running),
/// and the affected target so the caller can resume tracking later.
///
/// Header verbs use the present continuous tense (`launching`, `terminating`,
/// `updating`) to signal the operation is in progress, not yet complete.
/// Unknown saga kinds fall back to `submitted <kind> <operation-id>`.
pub fn operation_handle_confirm(
    op_id: &str,
    kind: &str,
    status: &str,
    target_kind: &str,
    target_id: Option<&str>,
) -> String {
    let (verb, noun) = match kind {
        "cvm.launch" => ("launching", "cvm"),
        "cvm.terminate" => ("terminating", "cvm"),
        "cvm.update" => ("updating", "cvm"),
        "security_cvm.launch" => ("launching", "security cvm"),
        "security_cvm.terminate" => ("terminating", "security cvm"),
        "security_cvm.update" => ("updating", "security cvm"),
        _ => ("submitted", kind),
    };

    // Use target_id as the identifier when known (the natural primary
    // identifier of the affected resource); fall back to the operation id
    // for kinds where the target_id is not yet allocated.
    let identifier = target_id
        .map(|id| id.to_string())
        .unwrap_or_else(|| op_id.to_string());

    let mut fields = vec![("operation".to_string(), op_id.to_string())];
    if target_id.is_none() {
        // Surface the target type alone when the id is not yet set.
        fields.push(("target type".to_string(), target_kind.to_string()));
    }
    fields.push(("status".to_string(), status.to_string()));

    let block = ConfirmBlock {
        verb: verb.to_string(),
        entity_noun: noun.to_string(),
        identifier,
        fields,
        next_step: None,
    };
    render_confirm(&block)
}

/// Render a sequence of `(label, value)` rows aligned to a common value
/// column, each row prefixed with `indent` spaces. Used by [`render_confirm`]
/// and [`render_error`] to keep the body layout identical between the two.
///
/// Values are NOT sanitised here -- both callers sanitise inputs at the
/// boundary so a styled (ANSI-wrapped) value can pass through unchanged.
pub(crate) fn render_indented_label_rows(rows: &[(String, String)], indent: usize) -> String {
    let max_label = rows.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    let mut out = String::new();
    for (i, (lbl, val_text)) in rows.iter().enumerate() {
        let pad = max_label - lbl.len();
        out.push_str(&" ".repeat(indent));
        out.push_str(&label(lbl));
        out.push_str(&" ".repeat(pad + 2));
        out.push_str(val_text);
        if i + 1 < rows.len() {
            out.push('\n');
        }
    }
    out
}

pub fn render_confirm(c: &ConfirmBlock) -> String {
    let ok = success("[OK]");
    // Defense-in-depth: every confirm input may include Console-sourced text
    // (cvm.id, entity.name, profile.name, the next-step command suggested by
    // the Console, etc.). Section 4 mandates printable-ASCII output, so we
    // sanitise here as a backstop -- even though most callers already pass
    // CLI-controlled or already-validated strings.
    let verb = sanitize_ascii(&c.verb);
    let entity_noun = sanitize_ascii(&c.entity_noun);
    let identifier = sanitize_ascii(&c.identifier);
    // Build the header from non-empty parts only so confirms that omit
    // entity_noun (e.g., `auth login` -> "signed in as <email>") do not
    // produce a stray double space between the verb and the identifier.
    let mut parts: Vec<String> = Vec::with_capacity(4);
    parts.push(ok);
    if !verb.is_empty() {
        parts.push(verb);
    }
    if !entity_noun.is_empty() {
        parts.push(entity_noun);
    }
    if !identifier.is_empty() {
        parts.push(value(&identifier));
    }
    let head = parts.join(" ");
    if c.fields.is_empty() && c.next_step.is_none() {
        return head;
    }
    let mut rows: Vec<(String, String)> = c
        .fields
        .iter()
        .map(|(l, v)| (sanitize_ascii(l), sanitize_ascii(v)))
        .collect();
    if let Some(ns) = &c.next_step {
        rows.push(("next step".to_string(), info(sanitize_ascii(ns))));
    }
    let mut out = String::new();
    out.push_str(&head);
    out.push('\n');
    out.push_str(&render_indented_label_rows(&rows, 8));
    out
}

// =========================================================================
// Interactive prompts (section 7.18)
// =========================================================================

/// Render a single line of informational, non-error, non-mutation text
/// destined for stderr (e.g. the OIDC device-flow prompts emitted by
/// `umbra auth login --device`). Intentionally minimal -- no decoration,
/// no `[OK]`/`[error]` prefix, just the message styled in the same neutral
/// tone the rest of the spec uses for cyan informational text.
///
/// This is the Layer 2 entry point that command code routes prompts through
/// so the activation rules of section 3 still apply (no ANSI when colors
/// are off). Callers SHOULD pass already-trusted CLI-controlled strings; if
/// the prompt embeds Console-controlled data, run that data through
/// `sanitize_ascii` first.
pub fn info_line(message: &str) -> String {
    info(message)
}

/// Render a one-line stderr diagnostic showing the opaque pagination cursor
/// returned by the Console. Used by list / events / logs commands when the
/// response includes a non-null `next_cursor`. Always styled `muted()` (no
/// `[OK]` / `[error]` prefix). The Console-controlled cursor string is
/// passed through [`sanitize_ascii`] before being rendered.
///
/// Per `cli-style.md` section 6.1 (Footer / pagination notes): when a list
/// renderer's wire response includes a non-null `next_cursor`, the caller
/// MUST emit this auxiliary line on stderr immediately after the list body.
/// Format: `next cursor: <opaque>`.
pub fn next_cursor_diagnostic(cursor: &str) -> String {
    muted(format!("next cursor: {}", sanitize_ascii(cursor)))
}

/// Muted stderr note: the Console returned fields this CLI build does not model
/// (captured, not dropped), so the CLI is likely out of date.
pub fn unknown_fields_note() -> String {
    muted("note: the Console returned unrecognized fields; this CLI may be out of date")
}

/// Muted stderr line for one Console-side catalog parse warning (provider schema
/// drift): an expected field that failed to parse on `count` of `total` entries.
/// The wording lives here (the wire carries only the machine counts); the
/// Console-controlled field name passes through the section 4 sanitiser.
pub fn field_miss_note(field: &str, count: u64, total: usize) -> String {
    muted(format!(
        "catalog parse warning: expected field '{}' missing or invalid on {} of {} instance types",
        sanitize_ascii(field),
        count,
        total,
    ))
}

/// Render the one-line stderr notice emitted after a command when the cached
/// latest-version probe shows a newer published release (cli-style.md section
/// 7.35). Muted like [`next_cursor_diagnostic`] so it reads as an auxiliary
/// diagnostic, never part of the command payload. The latest version string
/// comes from the install service, so it is sanitised; the installed version
/// is compiled in and trusted.
pub fn update_notice(current: &str, latest: &str) -> String {
    muted(format!(
        "update available: umbra {} (installed {}) -- run `umbra update`",
        sanitize_ascii(latest),
        current,
    ))
}

// =========================================================================
// INSTANCE TYPES (section 7.34)
// =========================================================================

pub struct InstanceTypeRow<'a> {
    pub name: &'a str,
    pub family: Option<&'a str>,
    pub vcpu: Option<u64>,
    pub memory_gb: Option<f64>,
    pub is_default: bool,
    pub launchable: bool,
}

pub fn instance_types_table(rows: &[InstanceTypeRow<'_>]) -> String {
    if rows.is_empty() {
        return empty_state("instance types");
    }

    let headers: [&str; 5] = ["NAME", "FAMILY", "VCPU", "MEMORY", "NOTES"];

    let mut raw_rows: Vec<Vec<String>> = Vec::new();
    let mut styled_rows: Vec<Vec<String>> = Vec::new();
    for row in rows {
        let name = sanitize_ascii(row.name);
        let family = row.family.map(sanitize_ascii);
        let vcpu = row
            .vcpu
            .map(|v| v.to_string())
            .unwrap_or_else(|| "-".to_string());
        let memory = row
            .memory_gb
            .map(format_memory_gb)
            .unwrap_or_else(|| "-".to_string());
        let notes = instance_type_notes(row);

        raw_rows.push(vec![
            name.clone(),
            family.clone().unwrap_or_else(|| "-".to_string()),
            vcpu.clone(),
            memory.clone(),
            notes.clone(),
        ]);
        styled_rows.push(vec![
            value(&name),
            family.unwrap_or_else(|| "-".to_string()),
            vcpu,
            memory,
            if notes.is_empty() {
                notes
            } else {
                muted(notes)
            },
        ]);
    }

    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
    for row in &raw_rows {
        for (i, cell) in row.iter().enumerate() {
            if cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }

    let mut out = String::new();
    let mut header_line = String::new();
    for (i, h) in headers.iter().enumerate() {
        let mut cell = h.to_string();
        if i + 1 < headers.len() {
            cell.push_str(&" ".repeat(widths[i].saturating_sub(cell.len())));
        }
        if i > 0 {
            header_line.push(' ');
        }
        header_line.push_str(&header(cell));
    }
    out.push_str(&header_line);
    out.push('\n');

    for (raw, styled) in raw_rows.iter().zip(styled_rows.iter()) {
        let mut line = String::new();
        for i in 0..styled.len() {
            if i > 0 {
                line.push(' ');
            }
            line.push_str(&styled[i]);
            if i + 1 < styled.len() {
                line.push_str(&" ".repeat(widths[i].saturating_sub(raw[i].len())));
            }
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out.push('\n');
    out.push_str(&footer_line(rows.len(), "instance types"));
    out
}

fn instance_type_notes(row: &InstanceTypeRow<'_>) -> String {
    let mut notes: Vec<&str> = Vec::new();
    if row.is_default {
        notes.push("default");
    }
    // The Console owns the launchability rule (currently: GPU not launchable yet);
    // the CLI reads its `launchable` flag rather than re-deriving from family.
    if !row.launchable {
        notes.push("not supported yet");
    }
    notes.join(", ")
}

fn format_memory_gb(gb: f64) -> String {
    if gb.fract() == 0.0 {
        format!("{} GB", gb as u64)
    } else {
        format!("{gb} GB")
    }
}

/// Catalog freshness diagnostic for `cvm instance-types` (stderr, muted).
/// Returns `None` when the catalog needs no explaining -- fresh provider data.
/// All inputs are Console-controlled and pass through [`sanitize_ascii`].
pub struct CatalogNote<'a> {
    pub source: &'a str,
    pub fetched_at: Option<&'a str>,
    pub stale: bool,
    pub refresh_in_progress: bool,
    pub last_refresh_error_kind: Option<&'a str>,
    /// True when the user passed `--refresh` (an inline fetch was attempted).
    pub refresh_requested: bool,
}

pub fn catalog_note(note: &CatalogNote<'_>) -> Option<String> {
    let cause = note.last_refresh_error_kind.map(|kind| match kind {
        "provider_unreachable" => "phala unreachable".to_string(),
        "schema_drift" => "phala response could not be parsed (schema change?)".to_string(),
        other => sanitize_ascii(other),
    });
    // format_timestamp falls back to the raw input on parse failure, so the
    // Console-controlled string must still pass the section 4 sanitiser.
    let dated = note
        .fetched_at
        .map(|at| format!("cached list from {}", sanitize_ascii(&format_timestamp(at))))
        .unwrap_or_else(|| "built-in list".to_string());
    let action = if note.refresh_in_progress {
        "background refresh in progress"
    } else {
        "use --refresh to fetch now"
    };

    if note.refresh_requested {
        if let Some(cause) = &cause {
            return Some(muted(format!("refresh failed ({cause}); showing {dated}")));
        }
        // --refresh with no failure recorded: either it succeeded (fresh catalog,
        // the branches below stay silent) or the Console skipped it because a
        // background refresh was already in flight -- fall through so a still
        // stale/bootstrap catalog is explained rather than silently shown.
    }
    if note.source == "bootstrap_fallback" {
        let suffix = cause.map(|c| format!(" ({c})")).unwrap_or_default();
        return Some(muted(format!(
            "built-in bootstrap catalog; phala has never been reached{suffix} -- {action}"
        )));
    }
    if note.stale {
        let cause_suffix = cause
            .map(|c| format!("; {c} at last refresh"))
            .unwrap_or_default();
        return Some(muted(format!(
            "catalog is stale ({dated}{cause_suffix}); {action}"
        )));
    }
    None
}

// =========================================================================
// ERROR block (sections 6.5 + 7.20)
// =========================================================================

pub struct ErrorBlock {
    pub symbol: String,
    pub message: String,
    pub cause: Option<String>,
    pub details: Option<String>,
    pub fix: Option<String>,
    pub request_id: Option<String>,
}

impl ErrorBlock {
    /// Construct a single-line `ErrorBlock`. Inputs are passed through
    /// [`sanitize_ascii`] so a hostile Console error envelope or a stray
    /// control byte cannot end up rendered raw.
    fn single(symbol: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            symbol: sanitize_ascii(&symbol.into()),
            message: sanitize_ascii(&message.into()),
            cause: None,
            details: None,
            fix: None,
            request_id: None,
        }
    }

    /// Parse a `[<bracket>] <message>` string into an `ErrorBlock`. The
    /// bracket value is taken verbatim and used as the `symbol` field: per
    /// spec section 6.5 it is either a Console-typed `error.code` (e.g.
    /// `NOT_FOUND`, `VALIDATION_ERROR`) when the upstream emitter had a
    /// Console envelope, or a client-side fallback (`error`, `usage`,
    /// `auth_required`, `wait_timeout`). When the input does not match the
    /// `[...]` shape, falls back to a synthetic `[error]` bracket.
    pub fn parse_legacy(s: &str) -> Self {
        let trimmed = s.trim();
        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some(end) = rest.find(']') {
                let symbol = &rest[..end];
                let rest = &rest[end + 1..];
                let message = rest.trim_start().to_string();
                return Self::single(symbol.to_string(), message);
            }
        }
        Self::single("error", trimmed.to_string())
    }

    /// Try to parse a Console JSON error envelope of the form
    /// `{"error": {"code": ..., "message": ..., "details": ..., ...},
    ///   "request_id": ...}` into an `ErrorBlock`. Falls back to `None` when
    /// the body is not a recognized envelope. The mapping follows section
    /// 6.5 / 7.20:
    /// - `error.code` -> bracket value (verbatim, e.g. `NOT_FOUND`,
    ///   `VALIDATION_ERROR`, `FORBIDDEN`). When absent, falls back to
    ///   `error`.
    /// - `error.message` -> message
    /// - `error.cause` -> cause
    /// - `error.details` -> details (compact-JSON if non-string)
    /// - `error.fix` -> fix
    /// - top-level `request_id` -> request-id
    ///
    /// All string fields sourced from the envelope are passed through
    /// [`sanitize_ascii`] at construction time so the renderer never sees a
    /// Console-controlled byte sequence containing ANSI escapes.
    pub fn from_envelope(body: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(body).ok()?;
        let err = v.get("error")?;
        let message = sanitize_ascii(err.get("message")?.as_str()?);
        let symbol = err
            .get("code")
            .and_then(|c| c.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| "error".to_string());
        let symbol = sanitize_ascii(&symbol);
        let cause = err
            .get("cause")
            .and_then(|c| c.as_str())
            .map(sanitize_ascii);
        let details = err
            .get("details")
            .map(|v| sanitize_ascii(&stringify_envelope_value(v)));
        let fix = err.get("fix").and_then(|c| c.as_str()).map(sanitize_ascii);
        let request_id = v
            .get("request_id")
            .and_then(|c| c.as_str())
            .map(sanitize_ascii);
        Some(Self {
            symbol,
            message,
            cause,
            details,
            fix,
            request_id,
        })
    }

    /// Construct a client-side error block with a bracket `symbol` (e.g.
    /// `error`, `wait_timeout`, `auth_required`) and a headline `message`.
    /// Attach optional `cause` / `details` / `fix` rows with the builder
    /// setters below (section 6.5 multi-line form). All inputs are
    /// ASCII-sanitised, like [`Self::single`].
    pub fn new(symbol: impl Into<String>, message: impl Into<String>) -> Self {
        Self::single(symbol, message)
    }

    /// Attach the `cause` row (one-line reason). Last call wins.
    pub fn with_cause(mut self, cause: impl Into<String>) -> Self {
        self.cause = Some(sanitize_ascii(&cause.into()));
        self
    }

    /// Attach the `details` row (one-line elaboration). Last call wins.
    pub fn with_details(mut self, details: impl Into<String>) -> Self {
        self.details = Some(sanitize_ascii(&details.into()));
        self
    }

    /// Attach the `fix` row (one suggested command or action). Last call wins.
    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(sanitize_ascii(&fix.into()));
        self
    }
}

/// Build the non-terminal wait-timeout block (section 6.5). The CLI stopped
/// polling at the caller's `--wait-timeout-seconds`, but the Console saga
/// keeps running and reaches its terminal state on its own; this block
/// reports the last observed `operation_status` (`pending` or `running`)
/// instead of looking like a launch failure. `kind` is the operation kind
/// (`cvm.launch`, `security_cvm.update`, `audit.export`, ...); the check
/// command in the `fix` row is derived from its prefix. `target_id` is the
/// affected resource's id when the stub has been persisted (it usually has by
/// the time a launch can time out).
pub fn wait_timeout_block(
    op_id: &str,
    kind: &str,
    target_id: Option<&str>,
    operation_status: &str,
    timeout_secs: u64,
) -> ErrorBlock {
    let (noun, check) = match kind.split('.').next().unwrap_or("") {
        "cvm" => ("cvm", Some("umbra cvm list")),
        "security_cvm" => ("security cvm", Some("umbra security-cvm show")),
        "audit" => ("audit export", None),
        _ => ("operation", None),
    };
    let target = match target_id {
        Some(id) if !id.is_empty() => format!(", {noun} {id}"),
        _ => String::new(),
    };
    let block = ErrorBlock::new(
        "wait_timeout",
        format!(
            "stopped watching after {timeout_secs}s -- the {noun} operation is still {operation_status}"
        ),
    )
    .with_cause(format!(
        "the CLI stopped waiting, not the operation; status was '{operation_status}' (not terminal) at the timeout"
    ))
    .with_details(format!(
        "operation {op_id}{target}; the server finishes it on its own -- watch longer with --wait-timeout-seconds <n>, or skip waiting with --no-wait"
    ));
    match check {
        Some(cmd) => block.with_fix(cmd),
        None => block,
    }
}

/// Build the "the attested tunnel dropped" block shown when OpenSSH explicitly
/// reports that a previously established interactive connection exited 255.
/// `session_survived` is true only after a follow-up SSH probe found the exact
/// dtach session; the block promises survival and offers direct attach only in
/// that case. Otherwise its copy stays neutral and points at `ps`. Every
/// recovery command pins `cvm_id` so an explicit non-default target is
/// preserved.
pub fn ssh_disconnect_block(
    cvm_id: &str,
    session_name: Option<&str>,
    session_survived: bool,
) -> ErrorBlock {
    let mut block = ErrorBlock::new("error", format!("connection to dev cvm {cvm_id} dropped"))
        .with_cause(
            "the attested tunnel closed mid-session -- usually laptop sleep, a network change, or a VPN switch",
        );
    if session_survived {
        block = block.with_details(
            "the dtach session is still running on the cvm; reconnect to continue your work",
        );
    } else {
        block = block.with_details(
            "the CLI could not confirm that the dtach session is still running; check the cvm before reconnecting",
        );
    }
    match (session_name, session_survived) {
        (Some(name), true) => block.with_fix(format!("umbra attach {name} --cvm {cvm_id}")),
        _ => block.with_fix(format!(
            "umbra ps --cvm {cvm_id}   (then: umbra attach <session> --cvm {cvm_id})"
        )),
    }
}

/// Build the block shown when an interactive SSH / session command exits 255
/// before OpenSSH's successful-connection callback ran -- a connection-setup
/// failure rather than a mid-session drop.
pub fn ssh_connect_failed_block(cvm_id: &str) -> ErrorBlock {
    ErrorBlock::new("error", format!("could not connect to dev cvm {cvm_id}"))
        .with_cause(
            "the attested tunnel did not come up -- the cvm may not be RUNNING yet, or the ssh key was rejected",
        )
        .with_details("see ssh's output above for the specific reason; no interactive session was started")
        .with_fix("umbra cvm list   (confirm it is RUNNING, then retry)")
}

fn stringify_envelope_value(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "-".to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => serde_json::to_string(v).unwrap_or_else(|_| "?".to_string()),
    }
}

/// Print an error to stderr using the section 6.5 template. The argument is
/// either a legacy `[<symbol>] <message>` line, or a JSON Console error
/// envelope (a string starting with `{`). In the envelope case we parse it
/// into a structured `ErrorBlock` (cause/details/fix/request-id). Otherwise
/// the legacy shape is parsed into a single-line `ErrorBlock`.
pub fn eprintln_error(message: &str) {
    // The caller may pass an empty string to indicate that the error block
    // has already been emitted by a stateful renderer (e.g.
    // `StepsRenderer::finalize_error`). In that case we MUST NOT emit a
    // second block, so the function returns without writing.
    if message.is_empty() {
        return;
    }
    let trimmed = message.trim_start();
    let block = if trimmed.starts_with('{') {
        ErrorBlock::from_envelope(trimmed).unwrap_or_else(|| ErrorBlock::parse_legacy(message))
    } else {
        ErrorBlock::parse_legacy(message)
    };
    eprintln!("{}", render_error(&block));
}

/// Print a fully-built [`ErrorBlock`] to stderr via the section 6.5 template.
/// Use this from command code that has structured `cause` / `details` / `fix`
/// guidance to attach (built via [`ErrorBlock::new`] + the `with_*` setters).
/// [`eprintln_error`] remains the entry point for plain `[symbol] message`
/// strings and Console error envelopes.
pub fn eprintln_error_block(block: &ErrorBlock) {
    eprintln!("{}", render_error(block));
}

/// Emit a diagnostic warning to stderr. Unlike [`eprintln_error`] this does not
/// mark failure — the command still succeeds — so it is a plain `[warn]` line.
/// The message is sanitised so ids echoed back cannot smuggle ANSI escapes.
pub fn eprintln_warn(message: &str) {
    eprintln!("{}", sanitize_ascii(message));
}

pub fn render_error(e: &ErrorBlock) -> String {
    // Defense in depth: even though the constructors sanitise their inputs,
    // re-sanitise here so any future direct `ErrorBlock { ... }` literal
    // cannot accidentally pipe an ANSI escape from a Console payload through
    // to the terminal. Sanitising an already-sanitised string is a no-op.
    let safe_symbol = sanitize_ascii(&e.symbol);
    let safe_message = sanitize_ascii(&e.message);
    let head = format!(
        "{} {}",
        error_style(format!("[{safe_symbol}]")),
        safe_message
    );
    let safe_cause = e.cause.as_deref().map(sanitize_ascii);
    let safe_details = e.details.as_deref().map(sanitize_ascii);
    let safe_fix = e.fix.as_deref().map(sanitize_ascii);
    let safe_request_id = e.request_id.as_deref().map(sanitize_ascii);
    let mut rows: Vec<(&'static str, &str)> = Vec::new();
    if let Some(v) = &safe_cause {
        rows.push(("cause", v.as_str()));
    }
    if let Some(v) = &safe_details {
        rows.push(("details", v.as_str()));
    }
    if let Some(v) = &safe_fix {
        rows.push(("fix", v.as_str()));
    }
    if let Some(v) = &safe_request_id {
        rows.push(("request-id", v.as_str()));
    }
    if rows.is_empty() {
        return head;
    }
    // The shared helper consumes (String, String) so the static-str slices
    // here are cloned into owned strings. Cheap on the error path.
    let owned_rows: Vec<(String, String)> = rows
        .iter()
        .map(|(l, v)| ((*l).to_string(), (*v).to_string()))
        .collect();
    let mut out = String::new();
    out.push_str(&head);
    out.push('\n');
    out.push_str(&render_indented_label_rows(&owned_rows, 8));
    out
}

// =========================================================================
// STEPS template (section 6.3 + 12.4)
//
// The async-mutation steps renderer is the stateful Layer 2 entry point used
// by `cvm launch / terminate / update`, `security-cvm launch / update`, and
// `auth login`. All step lines are written to the supplied writer; section
// 12.8 mandates stderr in production. Cursor-control sequences are used only
// when colors are on; otherwise each step prints once at its final state.
// =========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
}

/// State of one observed saga step.
struct StepRecord {
    raw_name: String,
    display: String,
    started: Instant,
    finished: Option<Instant>,
    failed: bool,
}

/// Stateful renderer for the steps template (section 6.3). The writer is
/// hardcoded to `io::Stderr` -- callers cannot misroute step lines to stdout,
/// which would conflict with the `cli.md` section 2.3 stderr/stdout split.
/// Construct via [`new_stderr_steps`].
pub struct StepsRenderer {
    writer: io::Stderr,
    steps: Vec<StepRecord>,
    /// Last line refresh wall-clock; used to throttle live updates.
    last_refresh: Option<Instant>,
}

impl StepsRenderer {
    fn new(writer: io::Stderr) -> Self {
        Self {
            writer,
            steps: Vec::new(),
            last_refresh: None,
        }
    }

    fn step_display_name(raw: &str) -> String {
        raw.split('_')
            .filter(|s| !s.is_empty())
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    Some(first) => {
                        let mut s = String::new();
                        for c in first.to_uppercase() {
                            s.push(c);
                        }
                        for c in chars {
                            for lc in c.to_lowercase() {
                                s.push(lc);
                            }
                        }
                        s
                    }
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn format_elapsed(d: std::time::Duration) -> String {
        let secs = d.as_secs_f64();
        if secs < 10.0 {
            format!("{:.1}s", secs)
        } else if secs < 60.0 {
            format!("{:.0}s", secs)
        } else {
            let total = d.as_secs();
            let mins = total / 60;
            let s = total % 60;
            format!("{mins}m{s}s")
        }
    }

    fn step_line(index: usize, display: &str, elapsed_text: &str, kind: StepStyle) -> String {
        let raw = format!("[{}] {:<35} [{}]", index + 1, display, elapsed_text);
        match kind {
            StepStyle::Running => warn(raw),
            StepStyle::Done => success(raw),
            StepStyle::Failed => error_style(raw),
        }
    }

    /// Called from the polling loop on every Operation response. Idempotent
    /// across repeated polls of the same step.
    pub fn observe(&mut self, current_step: &str, status: OperationStatus) {
        if current_step.is_empty() {
            return;
        }
        let now = Instant::now();
        let live = color_enabled();

        let need_new = self
            .steps
            .last()
            .map(|s| s.raw_name != current_step)
            .unwrap_or(true);

        if need_new {
            // Mark previous step as done (color path) or print it (no-color path).
            if let Some(prev_idx) = self.steps.len().checked_sub(1) {
                // Borrow safely: read fields, then mutate.
                let prev_index = prev_idx;
                let prev_display = self.steps[prev_idx].display.clone();
                let prev_started = self.steps[prev_idx].started;
                let prev_finished = self.steps[prev_idx].finished;
                let prev_failed = self.steps[prev_idx].failed;
                if prev_finished.is_none() && !prev_failed {
                    self.steps[prev_idx].finished = Some(now);
                    let elapsed = now - prev_started;
                    let elapsed_text = Self::format_elapsed(elapsed);
                    if live {
                        // Rewrite the running line as done. The previous
                        // refresh left the cursor on the line BELOW the
                        // running line, so we must move up first.
                        let line = Self::step_line(
                            prev_index,
                            &prev_display,
                            &elapsed_text,
                            StepStyle::Done,
                        );
                        let _ = writeln!(self.writer, "{CURSOR_UP}{CLEAR_LINE}{line}");
                    } else {
                        // Print the now-finished step on its own line.
                        let line = Self::step_line(
                            prev_index,
                            &prev_display,
                            &elapsed_text,
                            StepStyle::Done,
                        );
                        let _ = writeln!(self.writer, "{line}");
                    }
                }
            }
            let display = Self::step_display_name(current_step);
            let new_index = self.steps.len();
            self.steps.push(StepRecord {
                raw_name: current_step.to_string(),
                display: display.clone(),
                started: now,
                finished: None,
                failed: false,
            });
            self.last_refresh = Some(now);
            if live {
                // Print the new step (yellow, live).
                let line = Self::step_line(new_index, &display, "0.0s", StepStyle::Running);
                let _ = writeln!(self.writer, "{line}");
            }
            // No-color path defers printing until the step finalizes.
            let _ = self.writer.flush();
        } else if live {
            // Refresh in place; throttle to once per second.
            let last_idx = self.steps.len() - 1;
            let started = self.steps[last_idx].started;
            let display = self.steps[last_idx].display.clone();
            let should_refresh = self
                .last_refresh
                .map(|prev| (now - prev) >= std::time::Duration::from_millis(950))
                .unwrap_or(true);
            if should_refresh {
                self.last_refresh = Some(now);
                let elapsed = now - started;
                let elapsed_text = Self::format_elapsed(elapsed);
                let line = Self::step_line(last_idx, &display, &elapsed_text, StepStyle::Running);
                let _ = writeln!(self.writer, "{CURSOR_UP}{CLEAR_LINE}{line}");
                let _ = self.writer.flush();
            }
        }
        // observe() does not act on Succeeded/Failed; callers must invoke
        // finalize_success or finalize_error so the trailing confirm/error
        // block is emitted correctly.
        let _ = status;
    }

    /// Mark the current step done and emit the confirm block on stdout. MUST
    /// be called once when the operation reaches `Succeeded`.
    pub fn finalize_success(mut self, confirm: &ConfirmBlock) {
        self.finalize_last_step(false);
        // Trailing blank line then the confirm block on stdout.
        println!();
        println!("{}", render_confirm(confirm));
    }

    /// Mark the current step failed and emit the error block on stderr. MUST
    /// be called once when the operation reaches `Failed`.
    pub fn finalize_error(mut self, err: &ErrorBlock) {
        self.finalize_last_step(true);
        eprintln!();
        eprintln!("{}", render_error(err));
    }

    /// Mark the current step done WITHOUT emitting any confirm block. Use
    /// this from callers that want to transition the last step's yellow
    /// "running" line to its final green "done" line but emit the success
    /// confirm separately (e.g. `cvm launch` / `security-cvm launch` where
    /// the confirm carries fqdn / policy file / next step rows built from
    /// the operation result). Consumes the renderer.
    pub fn close(mut self) {
        self.finalize_last_step(false);
    }

    /// Mark the current step done and emit the wait-timeout block on stderr.
    /// The saga is still running; this is not a failed step.
    pub fn finalize_timeout(mut self, block: &ErrorBlock) {
        self.finalize_last_step(false);
        eprintln!();
        eprintln!("{}", render_error(block));
    }

    fn finalize_last_step(&mut self, failed: bool) {
        if self.steps.is_empty() {
            return;
        }
        let last_idx = self.steps.len() - 1;
        if self.steps[last_idx].finished.is_some() {
            return;
        }
        let now = Instant::now();
        self.steps[last_idx].finished = Some(now);
        self.steps[last_idx].failed = failed;
        let started = self.steps[last_idx].started;
        let display = self.steps[last_idx].display.clone();
        let live = color_enabled();
        let elapsed = now - started;
        let elapsed_text = if failed {
            "FAILED".to_string()
        } else {
            Self::format_elapsed(elapsed)
        };
        let kind = if failed {
            StepStyle::Failed
        } else {
            StepStyle::Done
        };
        let line = Self::step_line(last_idx, &display, &elapsed_text, kind);
        if live {
            // The last refresh left the cursor on the line BELOW the running
            // line, so move up before rewriting the final form.
            let _ = writeln!(self.writer, "{CURSOR_UP}{CLEAR_LINE}{line}");
        } else {
            let _ = writeln!(self.writer, "{line}");
        }
        let _ = self.writer.flush();
    }
}

#[derive(Copy, Clone)]
enum StepStyle {
    Running,
    Done,
    Failed,
}

/// Helper for callers that want to drive the steps renderer against stderr
/// (the default destination, per section 12.8).
pub fn new_stderr_steps() -> StepsRenderer {
    StepsRenderer::new(io::stderr())
}

// =========================================================================
// USER SHOW CARD (section 7.27)
// =========================================================================

/// Input view for [`user_show_card`] (section 7.27). Mirrors the legacy
/// `print_user` payload field-for-field: id / email / name / entity /
/// state / permissions / profiles / last_login_at / deactivated_at /
/// created_at / deleted_at.
pub struct UserShowView<'a> {
    pub id: &'a str,
    pub email: &'a str,
    pub name: &'a str,
    pub entity_id: &'a str,
    pub entity_name: &'a str,
    pub state: &'a str,
    pub permissions: &'a [String],
    /// `(id, name)` tuples for the user's profile memberships.
    pub profiles: Vec<(String, String)>,
    pub last_login_at: Option<&'a str>,
    pub deactivated_at: Option<&'a str>,
    pub created_at: &'a str,
    pub deleted_at: Option<&'a str>,
    pub extra: &'a BTreeMap<String, Value>,
}

/// `umbra user show` single-section card (section 7.27). Title is the
/// user's email (matching the section 7.25 mutation confirms which also
/// surface email as the primary identifier). Fields preserve the legacy
/// ordering documented inline above.
pub fn user_show_card(u: &UserShowView<'_>) -> String {
    let mut out = String::new();
    out.push_str(&card_title_id(u.email));
    out.push('\n');

    let mut rows: Vec<CardRow> = Vec::new();
    rows.push(CardRow::new("id", u.id.to_string()));
    rows.push(CardRow::new("name", u.name.to_string()));
    rows.push(CardRow::new(
        "entity",
        format!("{} {}", u.entity_id, muted(u.entity_name)),
    ));
    rows.push(CardRow::new("state", user_state(u.state)));

    let perms: Vec<String> = u.permissions.to_vec();
    let (first, conts) = wrap_comma_list(&perms, 80);
    rows.push(CardRow::with_continuations("permissions", first, conts));

    if u.profiles.is_empty() {
        rows.push(CardRow::new("profiles", "-".to_string()));
    } else {
        let labels: Vec<String> = u
            .profiles
            .iter()
            .map(|(id, name)| format!("{} {}", muted(id), name))
            .collect();
        let (first, conts) = wrap_comma_list(&labels, 80);
        rows.push(CardRow::with_continuations("profiles", first, conts));
    }

    rows.push(CardRow::new(
        "last login",
        format_optional_timestamp(u.last_login_at),
    ));
    rows.push(CardRow::new(
        "deactivated",
        format_optional_timestamp(u.deactivated_at),
    ));
    rows.push(CardRow::new("created", format_timestamp(u.created_at)));
    rows.push(CardRow::new(
        "deleted",
        format_optional_timestamp(u.deleted_at),
    ));
    append_extra_rows(&mut rows, u.extra);

    out.push_str(&render_card_body(&rows));
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

// =========================================================================
// USER PERMISSIONS LIST (section 7.29)
// =========================================================================

/// `umbra user permissions list` -- compact one-permission-per-line
/// listing of the user's currently-granted permission tokens (section 7.29).
/// Each row renders the raw permission string styled via [`info`] to mirror
/// `cli.md`'s section for `user permissions list`. Empty state is the
/// canonical `no permissions` muted line.
pub fn user_permissions_list(permissions: &[String]) -> String {
    if permissions.is_empty() {
        return empty_state("permissions");
    }
    let mut out = String::new();
    for (i, p) in permissions.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&info(sanitize_ascii(p)));
    }
    out.push('\n');
    out.push_str(&footer_line(permissions.len(), "permissions"));
    out
}

// =========================================================================
// SECURITY-CVM ATTESTATION CARD (section 7.32)
// =========================================================================

/// Input view for [`security_cvm_attestation_card`] (section 7.32).
pub struct SecurityCvmAttestationView<'a> {
    pub security_cvm_id: &'a str,
    pub fqdn: &'a str,
    pub verified: bool,
    pub failure_reason: Option<&'a str>,
    pub expected_image_measurement: Option<&'a str>,
    pub image_measurement_seen: Option<&'a str>,
    pub rtmr3_digest_seen: Option<&'a str>,
    pub verified_at: Option<&'a str>,
}

/// `umbra security-cvm attestation` single-section card (section 7.32).
/// The verdict's `verified` boolean drives the value styling (success when
/// true, error when false). Image / rtmr digests are surfaced verbatim --
/// they are CLI-controlled fixed-format hex strings, not free-form Console
/// text.
pub fn security_cvm_attestation_card(v: &SecurityCvmAttestationView<'_>) -> String {
    let mut out = String::new();
    out.push_str(&card_title_section("Security CVM Attestation"));
    out.push('\n');

    let mut rows: Vec<CardRow> = Vec::new();
    rows.push(CardRow::new("security cvm", v.security_cvm_id.to_string()));
    rows.push(CardRow::new("fqdn", value(v.fqdn)));
    let verified_text = if v.verified {
        success("yes")
    } else {
        error_style("no")
    };
    rows.push(CardRow::new("verified", verified_text));
    if let Some(reason) = v.failure_reason {
        if !reason.is_empty() {
            rows.push(CardRow::new(
                "failure reason",
                error_style(sanitize_ascii(reason)),
            ));
        }
    }
    rows.push(CardRow::new(
        "expected image",
        v.expected_image_measurement.unwrap_or("-").to_string(),
    ));
    rows.push(CardRow::new(
        "image seen",
        v.image_measurement_seen.unwrap_or("-").to_string(),
    ));
    rows.push(CardRow::new(
        "rtmr3 seen",
        v.rtmr3_digest_seen.unwrap_or("-").to_string(),
    ));
    rows.push(CardRow::new(
        "verified at",
        format_optional_timestamp(v.verified_at),
    ));

    out.push_str(&render_card_body(&rows));
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_extra() -> BTreeMap<String, Value> {
        BTreeMap::new()
    }

    #[test]
    fn format_timestamp_converts_rfc3339_to_minute_precision() {
        assert_eq!(
            format_timestamp("2026-05-18T15:38:12.338269Z"),
            "2026-05-18 15:38 UTC"
        );
    }

    #[test]
    fn format_timestamp_returns_input_on_parse_failure() {
        assert_eq!(format_timestamp("not a date"), "not a date");
    }

    #[test]
    fn cvm_list_cards_renders_empty_state() {
        init(false);
        let s = cvm_list_cards(&[], &CvmListFilter::default());
        assert_eq!(s, "no cvms");
    }

    #[test]
    fn quota_value_suffixes_gb_for_disk_resources() {
        assert_eq!(quota_value("disk_gb_per_cvm", 200), "200 GB");
        assert_eq!(quota_value("disk_gb_total", 5000), "5000 GB");
        assert_eq!(quota_value("dev_cvms", 5), "5");
    }

    #[test]
    fn cvm_list_cards_renders_disk_size_in_gb() {
        init(false);
        let extra = empty_extra();
        let cvms = vec![CvmView {
            id: "id-1",
            alias: Ok(None),
            state: "running",
            error_reason: None,
            fqdn: None,
            instance_type: Some("tdx.small"),
            region: Some("eu-west-3"),
            disk_size_gb: Some(80),
            profile_names: vec!["dev".to_string()],
            ssh_key_labels: vec!["laptop".to_string()],
            owner_email: "user@example.com",
            created_at: "2026-05-18T15:38:00Z",
            updated_at: "2026-05-21T14:23:00Z",
            extra: &extra,
        }];
        let out = cvm_list_cards(&cvms, &CvmListFilter::default());
        assert!(out.contains("disk"));
        assert!(out.contains("80 GB"));
    }

    #[test]
    fn cvm_list_cards_renders_state_filter_header() {
        // When `--state` is set, its value appears in the `Filter:` header;
        // with no `--state`, there is no header line. Card body is unaffected.
        init(false);
        let extra = empty_extra();
        let cvms = vec![CvmView {
            id: "id-1",
            alias: Ok(None),
            state: "terminated",
            error_reason: None,
            fqdn: None,
            instance_type: Some("tdx.cpx41"),
            region: Some("eu-west-3"),
            disk_size_gb: Some(80),
            profile_names: vec!["dev".to_string()],
            ssh_key_labels: vec!["laptop".to_string()],
            owner_email: "user@example.com",
            created_at: "2026-05-18T15:38:00Z",
            updated_at: "2026-05-21T14:23:00Z",
            extra: &extra,
        }];

        let with_state = cvm_list_cards(
            &cvms,
            &CvmListFilter {
                profile: None,
                state: Some("terminated".to_string()),
            },
        );
        assert!(with_state.contains("Filter:"));
        assert!(with_state.contains("  state  terminated"));

        let without_state = cvm_list_cards(
            &cvms,
            &CvmListFilter {
                profile: None,
                state: None,
            },
        );
        assert!(!without_state.contains("Filter:"));
        // The `state` row in the card body still renders; only the Filter
        // header line is absent.
        assert!(!without_state.contains("  state  terminated"));
    }

    #[test]
    fn user_list_cards_renders_one_user() {
        init(false);
        let extra = empty_extra();
        let perms = vec!["CVM_LAUNCH".to_string()];
        let users = vec![UserView {
            id: "uuid-1",
            email: "alice@example.com",
            state: "active",
            permissions: &perms,
            profile_names: vec!["permissive-dev".to_string()],
            created_at: "2026-05-19T09:01:00Z",
            extra: &extra,
        }];
        let out = user_list_cards(&users, &UserListFilter::default());
        assert!(out.contains("> alice@example.com"));
        assert!(out.contains("id           uuid-1"));
        assert!(out.contains("state        active"));
        assert!(out.contains("permissions  CVM_LAUNCH"));
        assert!(out.contains("profiles     permissive-dev"));
        assert!(out.contains("2026-05-19 09:01 UTC"));
        // Singular form per section 6.1: count == 1 uses `1 user`, not `1 users`.
        assert!(out.contains("1 user"));
        assert!(!out.contains("1 users"));
    }

    #[test]
    fn user_list_cards_renders_status_and_assigned_filter_header() {
        // When `--status` / `--assigned` are set, their values appear in the
        // `Filter:` header; with neither set, there is no header line.
        init(false);
        let extra = empty_extra();
        let perms: Vec<String> = Vec::new();
        let users = vec![UserView {
            id: "uuid-1",
            email: "alice@example.com",
            state: "deactivated",
            permissions: &perms,
            profile_names: vec![],
            created_at: "2026-05-19T09:01:00Z",
            extra: &extra,
        }];

        let with_filter = user_list_cards(
            &users,
            &UserListFilter {
                status: Some("deactivated".to_string()),
                assigned: Some("no".to_string()),
            },
        );
        assert!(with_filter.contains("Filter:"));
        assert!(with_filter.contains("  status    deactivated"));
        assert!(with_filter.contains("  assigned  no"));

        let without_filter = user_list_cards(&users, &UserListFilter::default());
        assert!(!without_filter.contains("Filter:"));
    }

    #[test]
    fn confirm_block_single_line_when_no_fields() {
        init(false);
        let c = ConfirmBlock {
            verb: "removed".to_string(),
            entity_noun: "key".to_string(),
            identifier: "k-xxx".to_string(),
            fields: vec![],
            next_step: None,
        };
        assert_eq!(render_confirm(&c), "[OK] removed key k-xxx");
    }

    #[test]
    fn confirm_block_multi_line_with_fields() {
        init(false);
        let c = ConfirmBlock {
            verb: "added".to_string(),
            entity_noun: "key".to_string(),
            identifier: "laptop".to_string(),
            fields: vec![
                ("id".to_string(), "k-7f3a".to_string()),
                ("fingerprint".to_string(), "SHA256:abc".to_string()),
                ("algorithm".to_string(), "ed25519".to_string()),
            ],
            next_step: None,
        };
        let out = render_confirm(&c);
        assert!(out.starts_with("[OK] added key laptop\n"));
        assert!(out.contains("        id           k-7f3a"));
        assert!(out.contains("        fingerprint  SHA256:abc"));
        assert!(out.contains("        algorithm    ed25519"));
    }

    #[test]
    fn error_block_single_line_when_no_rows() {
        init(false);
        let e = ErrorBlock {
            symbol: "auth_required".to_string(),
            message: "session expired".to_string(),
            cause: None,
            details: None,
            fix: None,
            request_id: None,
        };
        assert_eq!(render_error(&e), "[auth_required] session expired");
    }

    #[test]
    fn error_block_multi_line_with_details() {
        init(false);
        let e = ErrorBlock {
            symbol: "error".to_string(),
            message: "failed to launch CVM".to_string(),
            cause: Some("timeout".to_string()),
            details: None,
            fix: None,
            request_id: Some("req-1".to_string()),
        };
        let out = render_error(&e);
        assert!(out.starts_with("[error] failed to launch CVM\n"));
        assert!(out.contains("        cause       timeout"));
        assert!(out.contains("        request-id  req-1"));
    }

    #[test]
    fn step_display_name_titlecases_each_word() {
        // The transformation is purely syntactic per cli-style.md section
        // 6.3: replace `_` with space, Title-Case each word. Neutral saga
        // step names render cleanly; provider-leaked names would render as
        // `Phala Deploy` / `Cf Txt Create` (spec drift, see TODO at top of
        // section 6.3).
        assert_eq!(StepsRenderer::step_display_name("validate"), "Validate");
        assert_eq!(
            StepsRenderer::step_display_name("persist_stub"),
            "Persist Stub"
        );
        assert_eq!(
            StepsRenderer::step_display_name("configure_dns_txt"),
            "Configure Dns Txt"
        );
        assert_eq!(
            StepsRenderer::step_display_name("verify_attestation"),
            "Verify Attestation"
        );
        assert_eq!(
            StepsRenderer::step_display_name("await_sc_pull"),
            "Await Sc Pull"
        );
    }

    #[test]
    fn config_show_table_marks_missing_source() {
        init(false);
        let entries = vec![
            ConfigEntryView {
                key: "console_url",
                value: Some("https://example"),
                source: "file",
            },
            ConfigEntryView {
                key: "atls_policy",
                value: None,
                source: "missing",
            },
        ];
        let out = config_show_table(&entries);
        assert!(out.contains("KEY"));
        assert!(out.contains("VALUE"));
        assert!(out.contains("SOURCE"));
        assert!(out.contains("(none)"));
        assert!(out.contains("missing"));
    }

    #[test]
    fn unknown_fields_render_alphabetically() {
        init(false);
        let mut extra: BTreeMap<String, Value> = BTreeMap::new();
        extra.insert("vlan_id".to_string(), Value::from(42));
        extra.insert("network_interface".to_string(), Value::from("eth0"));
        let cvms = vec![CvmView {
            id: "id-1",
            alias: Ok(None),
            state: "running",
            error_reason: None,
            fqdn: Some("cvm.example.com"),
            instance_type: Some("tdx.cpx41"),
            region: Some("eu-west-3"),
            disk_size_gb: Some(80),
            profile_names: vec!["dev".to_string()],
            ssh_key_labels: vec!["laptop".to_string()],
            owner_email: "user@example.com",
            created_at: "2026-05-18T15:38:00Z",
            updated_at: "2026-05-21T14:23:00Z",
            extra: &extra,
        }];
        let out = cvm_list_cards(&cvms, &CvmListFilter::default());
        let n_idx = out.find("network interface").expect("nw row present");
        let v_idx = out.find("vlan id").expect("vlan row present");
        assert!(n_idx < v_idx, "BTreeMap order: nw before vlan");
        assert!(out.contains("eth0"));
        assert!(out.contains("42"));
    }

    #[test]
    fn sanitize_ascii_passes_through_printable_text() {
        assert_eq!(
            sanitize_ascii("hello world 0123 !@#~ tab\there"),
            "hello world 0123 !@#~ tab\there"
        );
    }

    #[test]
    fn sanitize_ascii_keeps_newlines_and_tabs() {
        assert_eq!(sanitize_ascii("a\nb\tc"), "a\nb\tc");
    }

    #[test]
    fn sanitize_ascii_escapes_ansi_csi_sequence() {
        // ESC (0x1B) is the start of ANSI; bracket `[` is printable so it
        // survives, but the ESC byte itself MUST be neutered. The output
        // should be visibly different from raw ANSI and MUST NOT contain
        // the original 0x1B byte.
        let dangerous = "hello\x1b[2Jworld";
        let safe = sanitize_ascii(dangerous);
        assert!(!safe.contains('\x1b'), "ESC byte must not survive");
        assert_eq!(safe, "hello\\x1b[2Jworld");
    }

    #[test]
    fn sanitize_ascii_escapes_high_bytes() {
        assert_eq!(sanitize_ascii("a\u{0000}b\u{007f}c"), "a\\x00b\\x7fc");
    }

    #[test]
    fn render_error_does_not_pass_through_ansi_from_envelope() {
        init(false);
        // Simulate a Console-supplied envelope whose `message` carries an
        // ANSI clear-screen sequence. JSON forbids raw ESC bytes inside
        // strings, so the wire form encodes the ESC byte (0x1B) via the
        // \u001b unicode escape; serde decodes that back to the raw byte,
        // which the renderer MUST escape before printing.
        let envelope = "{\"error\":{\"code\":\"INTERNAL\",\"message\":\"boom\\u001b[2Jworld\"}}";
        let block = ErrorBlock::from_envelope(envelope).expect("envelope parses");
        let rendered = render_error(&block);
        assert!(!rendered.contains('\x1b'), "ESC must not leak to terminal");
        assert!(rendered.contains("boom\\x1b[2Jworld"));
    }

    #[test]
    fn from_envelope_uses_typed_error_code_in_bracket() {
        // Per cli-style.md section 6.5: the bracket holds the verbatim
        // Console `error.code` (e.g., NOT_FOUND, VALIDATION_ERROR), no
        // remapping to the exit-symbol vocabulary.
        init(false);
        let cases = [
            ("NOT_FOUND", "NOT_FOUND"),
            ("VALIDATION_ERROR", "VALIDATION_ERROR"),
            ("FORBIDDEN", "FORBIDDEN"),
            ("UNAUTHORIZED", "UNAUTHORIZED"),
            ("RATE_LIMITED", "RATE_LIMITED"),
        ];
        for (code, expected_bracket) in cases {
            let envelope = format!("{{\"error\":{{\"code\":\"{code}\",\"message\":\"m\"}}}}");
            let block = ErrorBlock::from_envelope(&envelope).expect("envelope parses");
            assert_eq!(block.symbol, expected_bracket, "code={code}");
            let rendered = render_error(&block);
            assert!(
                rendered.starts_with(&format!("[{expected_bracket}] m")),
                "rendered={rendered:?}"
            );
        }
    }

    fn sample_instance_type_rows() -> Vec<InstanceTypeRow<'static>> {
        vec![
            InstanceTypeRow {
                name: "tdx.small",
                family: Some("cpu"),
                vcpu: Some(1),
                memory_gb: Some(2.0),
                is_default: true,
                launchable: true,
            },
            InstanceTypeRow {
                name: "tdx.medium",
                family: Some("cpu"),
                vcpu: Some(2),
                memory_gb: Some(4.0),
                is_default: false,
                launchable: true,
            },
            InstanceTypeRow {
                name: "h200.small",
                family: Some("gpu"),
                vcpu: Some(24),
                memory_gb: Some(192.0),
                is_default: false,
                launchable: false,
            },
        ]
    }

    #[test]
    fn instance_types_table_renders_notes_and_footer() {
        init(false);
        let rendered = instance_types_table(&sample_instance_type_rows());
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines[0], "NAME       FAMILY VCPU MEMORY NOTES");
        assert_eq!(lines[1], "tdx.small  cpu    1    2 GB   default");
        assert_eq!(lines[2], "tdx.medium cpu    2    4 GB");
        assert_eq!(lines[3], "h200.small gpu    24   192 GB not supported yet");
        assert_eq!(lines[4], "");
        assert_eq!(lines[5], "3 instance types");
    }

    #[test]
    fn instance_types_table_handles_null_descriptive_fields_and_empty_state() {
        init(false);
        let rows = vec![InstanceTypeRow {
            name: "tdx.small",
            family: None,
            vcpu: None,
            memory_gb: None,
            is_default: false,
            launchable: true,
        }];
        let rendered = instance_types_table(&rows);
        // Missing descriptive fields degrade to `-`.
        assert!(
            rendered.contains("tdx.small -      -    -"),
            "rendered={rendered:?}"
        );
        assert!(rendered.contains("1 instance type"));
        assert_eq!(instance_types_table(&[]), "no instance types");
    }

    #[test]
    fn instance_types_table_sanitises_console_controlled_names() {
        init(false);
        let rows = vec![InstanceTypeRow {
            name: "tdx\x1b[31m.evil",
            family: Some("cpu\x1bX"),
            vcpu: None,
            memory_gb: None,
            is_default: false,
            launchable: true,
        }];
        let rendered = instance_types_table(&rows);
        assert!(!rendered.contains('\x1b'), "rendered={rendered:?}");
    }

    #[test]
    fn catalog_note_covers_every_useful_case_and_stays_silent_when_fresh() {
        init(false);
        // Fresh provider catalog: no note.
        assert_eq!(
            catalog_note(&CatalogNote {
                source: "provider",
                fetched_at: Some("2026-07-07T09:00:00Z"),
                stale: false,
                refresh_in_progress: false,
                last_refresh_error_kind: None,
                refresh_requested: false,
            }),
            None
        );
        // --refresh succeeded: also silent.
        assert_eq!(
            catalog_note(&CatalogNote {
                source: "provider",
                fetched_at: Some("2026-07-07T09:00:00Z"),
                stale: false,
                refresh_in_progress: false,
                last_refresh_error_kind: None,
                refresh_requested: true,
            }),
            None
        );
        // --refresh skipped by the Console (a background refresh was already in
        // flight, no failure recorded): the still-not-fresh catalog MUST be
        // explained, and the advice must reflect the in-flight refresh instead
        // of circularly suggesting the --refresh the user just ran.
        assert_eq!(
            catalog_note(&CatalogNote {
                source: "bootstrap_fallback",
                fetched_at: None,
                stale: true,
                refresh_in_progress: true,
                last_refresh_error_kind: None,
                refresh_requested: true,
            })
            .as_deref(),
            Some("built-in bootstrap catalog; phala has never been reached -- background refresh in progress")
        );
        // --refresh failed: cause + cached date.
        assert_eq!(
            catalog_note(&CatalogNote {
                source: "database",
                fetched_at: Some("2026-07-01T09:14:00Z"),
                stale: true,
                refresh_in_progress: false,
                last_refresh_error_kind: Some("provider_unreachable"),
                refresh_requested: true,
            })
            .as_deref(),
            Some(
                "refresh failed (phala unreachable); showing cached list from 2026-07-01 09:14 UTC"
            )
        );
        // Stale cache, drift cause, refresh running in background.
        assert_eq!(
            catalog_note(&CatalogNote {
                source: "database",
                fetched_at: Some("2026-07-01T09:14:00Z"),
                stale: true,
                refresh_in_progress: true,
                last_refresh_error_kind: Some("schema_drift"),
                refresh_requested: false,
            })
            .as_deref(),
            Some(
                "catalog is stale (cached list from 2026-07-01 09:14 UTC; phala response could \
                 not be parsed (schema change?) at last refresh); background refresh in progress"
            )
        );
        // Bootstrap fallback: provider never reached.
        assert_eq!(
            catalog_note(&CatalogNote {
                source: "bootstrap_fallback",
                fetched_at: None,
                stale: true,
                refresh_in_progress: false,
                last_refresh_error_kind: Some("provider_unreachable"),
                refresh_requested: false,
            })
            .as_deref(),
            Some(
                "built-in bootstrap catalog; phala has never been reached (phala unreachable) \
                 -- use --refresh to fetch now"
            )
        );
        // Hostile fetched_at (unparseable, carries ANSI) is sanitised even through
        // the format_timestamp passthrough fallback.
        let hostile = catalog_note(&CatalogNote {
            source: "database",
            fetched_at: Some("\x1b[2J\x1b[Hnot-a-date"),
            stale: true,
            refresh_in_progress: false,
            last_refresh_error_kind: None,
            refresh_requested: false,
        })
        .expect("stale catalog notes");
        assert!(!hostile.contains('\x1b'), "rendered={hostile:?}");
        // Unknown future error kind from the Console is sanitised, not trusted.
        let note = catalog_note(&CatalogNote {
            source: "database",
            fetched_at: Some("2026-07-01T09:14:00Z"),
            stale: true,
            refresh_in_progress: false,
            last_refresh_error_kind: Some("boom\x1bX"),
            refresh_requested: false,
        })
        .expect("stale catalog notes");
        assert!(!note.contains('\x1b'));
    }

    #[test]
    fn next_cursor_diagnostic_emits_muted_prefix() {
        init(false);
        // No-color mode: muted() is a no-op, so the rendered string is the
        // bare format. The Console-controlled token is passed through
        // sanitize_ascii so ESC bytes cannot reach the terminal.
        assert_eq!(
            next_cursor_diagnostic("opaque-cursor-7f3a"),
            "next cursor: opaque-cursor-7f3a"
        );
        let dangerous = "boom\x1bX";
        let safe = next_cursor_diagnostic(dangerous);
        assert!(!safe.contains('\x1b'));
        assert!(safe.contains("boom\\x1bX"));
    }

    #[test]
    fn render_error_sanitises_cause_and_details() {
        init(false);
        // Each Console-controlled string field carries an ESC byte via JSON
        // unicode escape. The renderer MUST scrub every one of them.
        let envelope = "{\"error\":{\"code\":\"INTERNAL\",\
            \"message\":\"m\\u001bX\",\
            \"cause\":\"c\\u001bX\",\
            \"details\":{\"k\":\"d\\u001bY\"},\
            \"fix\":\"f\\u001bZ\"},\
            \"request_id\":\"r\\u001bW\"}";
        let block = ErrorBlock::from_envelope(envelope).expect("envelope parses");
        let rendered = render_error(&block);
        assert!(!rendered.contains('\x1b'));
        assert!(rendered.contains("c\\x1bX"));
        assert!(rendered.contains("f\\x1bZ"));
        assert!(rendered.contains("r\\x1bW"));
    }

    #[test]
    fn operation_handle_confirm_emits_present_continuous_verb() {
        init(false);
        let rendered =
            operation_handle_confirm("op-1", "cvm.launch", "pending", "cvm", Some("cvm-target"));
        // Header includes the present-continuous verb and the target id.
        assert!(rendered.starts_with("[OK] launching cvm cvm-target"));
        assert!(rendered.contains("operation"));
        assert!(rendered.contains("op-1"));
        assert!(rendered.contains("status"));
        assert!(rendered.contains("pending"));
        // No target_type row when target_id is set (avoids duplication with header).
        assert!(!rendered.contains("target type"));

        // Unknown saga kind falls back to "submitted <kind>".
        let unknown = operation_handle_confirm("op-2", "audit.export", "running", "audit", None);
        assert!(unknown.starts_with("[OK] submitted audit.export"));
        // target_type row appears when target_id is None.
        assert!(unknown.contains("target type"));
        assert!(unknown.contains("audit"));
    }

    #[test]
    fn user_show_card_renders_required_rows() {
        init(false);
        let extra = BTreeMap::new();
        let perms = vec!["CVM_LAUNCH".to_string(), "AUDIT_VIEW".to_string()];
        let view = UserShowView {
            id: "u-1",
            email: "user@example.com",
            name: "Alice",
            entity_id: "e-1",
            entity_name: "acme",
            state: "active",
            permissions: &perms,
            profiles: vec![("p-1".to_string(), "dev".to_string())],
            last_login_at: Some("2026-05-21T14:23:45Z"),
            deactivated_at: None,
            created_at: "2026-05-01T09:00:00Z",
            deleted_at: None,
            extra: &extra,
        };
        let rendered = user_show_card(&view);
        // Title is the email (primary identifier per section 7.27).
        assert!(rendered.contains("user@example.com"));
        // Required rows present.
        for label in [
            "id",
            "name",
            "entity",
            "state",
            "permissions",
            "profiles",
            "created",
        ] {
            assert!(rendered.contains(label), "missing label: {label}");
        }
        // Comma-separated permission list with full list (never truncated).
        assert!(rendered.contains("CVM_LAUNCH"));
        assert!(rendered.contains("AUDIT_VIEW"));
        // Empty deactivated / deleted slots render `-`.
        assert!(rendered.contains("deactivated"));
        assert!(rendered.contains("deleted"));
    }

    #[test]
    fn user_permissions_list_handles_empty_and_populated() {
        init(false);
        // Empty list: canonical "no permissions" muted line.
        let empty = user_permissions_list(&[]);
        assert_eq!(empty, "no permissions");

        // Populated list ends with the singular-aware footer.
        let one = user_permissions_list(&["AUDIT_VIEW".to_string()]);
        assert!(one.contains("AUDIT_VIEW"));
        assert!(one.contains("1 permission"));

        let many = user_permissions_list(&[
            "AUDIT_VIEW".to_string(),
            "CVM_LAUNCH".to_string(),
            "USER_MANAGE".to_string(),
        ]);
        assert!(many.contains("3 permissions"));
    }

    #[test]
    fn security_cvm_attestation_card_distinguishes_verified_and_failed() {
        init(false);
        let verified = SecurityCvmAttestationView {
            security_cvm_id: "sc-1",
            fqdn: "sc-1.example.com",
            verified: true,
            failure_reason: None,
            expected_image_measurement: Some("expect-hash"),
            image_measurement_seen: Some("seen-hash"),
            rtmr3_digest_seen: Some("rtmr3-hash"),
            verified_at: Some("2026-05-21T14:23:45Z"),
        };
        let ok = security_cvm_attestation_card(&verified);
        // Section header explicit per spec 7.32.
        assert!(ok.contains("Security CVM Attestation"));
        assert!(ok.contains("sc-1"));
        assert!(ok.contains("sc-1.example.com"));
        // Verified state surfaced.
        assert!(ok.contains("verified"));

        let failed = SecurityCvmAttestationView {
            security_cvm_id: "sc-2",
            fqdn: "sc-2.example.com",
            verified: false,
            failure_reason: Some("image_measurement_mismatch"),
            expected_image_measurement: Some("expect-hash"),
            image_measurement_seen: Some("seen-hash"),
            rtmr3_digest_seen: None,
            verified_at: None,
        };
        let nok = security_cvm_attestation_card(&failed);
        // Failure surfaces the failure_reason row.
        assert!(nok.contains("image_measurement_mismatch"));
    }

    // ---------------------------------------------------------------------
    // Strict-JSON-output contract (section 11.7): `--json` must NOT leak the
    // `extra` BTreeMap on serialize.
    //
    // The wire structs (`Cvm`, `User`, `Profile`, ...) carry a forward-compat
    // `extra: BTreeMap<String, Value>` so the human renderer surfaces unknown
    // Console fields. The same field MUST NOT round-trip through `--json`:
    // a future sensitive Console field would otherwise leak until the CLI is
    // updated to declare it. The serde contract is
    // `#[serde(flatten, default, skip_serializing)]` -- this test pins it.
    // ---------------------------------------------------------------------
    #[test]
    fn cvm_wire_struct_does_not_leak_extra_on_serialize() {
        use serde::{Deserialize, Serialize};

        // Same shape and same serde attribute as the actual `Cvm` wire struct
        // in `commands/cvm.rs`. Kept local so this test runs in `style.rs`
        // without exposing the command-private wire struct.
        #[derive(Debug, Deserialize, Serialize)]
        struct CvmShape {
            id: String,
            state: String,
            #[serde(flatten, default, skip_serializing)]
            extra: BTreeMap<String, Value>,
        }

        let wire = r#"{"id":"cvm-1","state":"running","secret_token":"leak-me","new_field":42}"#;
        let parsed: CvmShape = serde_json::from_str(wire).expect("Cvm-shaped JSON parses");

        // Deserialize MUST capture the unknown fields into `extra` (human path
        // forward-compat).
        assert!(parsed.extra.contains_key("secret_token"));
        assert!(parsed.extra.contains_key("new_field"));

        // Serialize MUST skip the entire `extra` bag (strict --json
        // whitelist).
        let out = serde_json::to_string_pretty(&parsed).expect("CvmShape serializes");
        assert!(out.contains("\"id\""));
        assert!(out.contains("cvm-1"));
        assert!(
            !out.contains("secret_token"),
            "--json must not leak Console-side fields: {out}"
        );
        assert!(
            !out.contains("leak-me"),
            "--json must not leak Console-side values: {out}"
        );
        assert!(!out.contains("new_field"));
    }

    // ---------------------------------------------------------------------
    // Catalog coverage tests: every renderer in section 7 needs at least one
    // assertion that pins identifier visibility, footer/section header, and
    // ANSI sanitisation. Renderers that take a FilterContext also exercise
    // empty + populated filters per the section 6.2.1 filter-deduplication
    // rule.
    // ---------------------------------------------------------------------

    #[test]
    fn profile_list_cards_renders_basic_card_and_footer() {
        init(false);
        let extra = empty_extra();
        let profiles = vec![ProfileView {
            id: "prof-1",
            alias: Ok(None),
            name: "permissive-dev",
            assigned: true,
            attached_cvm_count: 2,
            attached_cvm_ids: vec!["cvm-a".to_string(), "cvm-b".to_string()],
            created_at: "2026-05-18T15:38:00Z",
            updated_at: "2026-05-21T14:23:00Z",
            extra: &extra,
        }];
        let out = profile_list_cards(&profiles, &ProfileListFilter::default());
        assert!(out.contains("permissive-dev"), "name must appear: {out}");
        assert!(out.contains("1 profile"), "singular footer: {out}");
        assert!(!out.contains('\x1b'), "no raw ANSI bytes");
        assert!(out.contains("prof-1"));
        assert!(out.contains("yes"));
        // No `--assigned` -> no Filter header line.
        assert!(!out.contains("Filter:"));
    }

    #[test]
    fn profile_list_cards_renders_assigned_filter_header() {
        // When `--assigned` is set, its value appears in the `Filter:` header.
        init(false);
        let extra = empty_extra();
        let profiles = vec![ProfileView {
            id: "prof-1",
            alias: Ok(None),
            name: "permissive-dev",
            assigned: false,
            attached_cvm_count: 0,
            attached_cvm_ids: vec![],
            created_at: "2026-05-18T15:38:00Z",
            updated_at: "2026-05-21T14:23:00Z",
            extra: &extra,
        }];
        let out = profile_list_cards(
            &profiles,
            &ProfileListFilter {
                assigned: Some("no".to_string()),
            },
        );
        assert!(out.contains("Filter:"));
        assert!(out.contains("  assigned  no"));
    }

    #[test]
    fn key_list_cards_renders_basic_card_and_footer() {
        init(false);
        let extra = empty_extra();
        let keys = vec![
            KeyView {
                id: "k-1",
                alias: Ok(None),
                label: "laptop",
                fingerprint: "SHA256:abc",
                algorithm: "ed25519",
                created_at: "2026-05-18T15:38:00Z",
                extra: &extra,
            },
            KeyView {
                id: "k-2",
                alias: Ok(None),
                label: "workstation",
                fingerprint: "SHA256:def",
                algorithm: "rsa",
                created_at: "2026-05-19T09:00:00Z",
                extra: &extra,
            },
        ];
        let out = key_list_cards(&keys);
        assert!(out.contains("laptop"), "label must appear: {out}");
        assert!(out.contains("2 keys"), "plural footer: {out}");
        assert!(!out.contains('\x1b'));
        assert!(out.contains("k-1"));
        assert!(out.contains("SHA256:abc"));
    }

    #[test]
    fn audit_events_cards_filter_header_and_column_dedup() {
        init(false);
        let extra = empty_extra();
        let events = vec![AuditEventView {
            seq: 7,
            timestamp: "2026-05-18T15:38:00Z",
            actor_email: Some("alice@example.com"),
            action: "cvm.launch",
            target_type: "cvm",
            target_id: "cvm-1",
            description: "launched cvm",
            extra: &extra,
        }];

        // Empty filter: no `Filter:` header, all per-row columns present.
        let empty = audit_events_cards(&events, &AuditEventsFilter::default());
        assert!(empty.contains("SEQ"), "seq title: {empty}");
        assert!(empty.contains("1 event"), "singular footer: {empty}");
        assert!(!empty.contains("Filter:"), "no filter header: {empty}");
        assert!(empty.contains("alice@example.com"), "actor row present");
        assert!(!empty.contains('\x1b'));

        // Populated filter: `Filter:` appears, the `actor` per-row column is
        // suppressed since it is hoisted into the header.
        let filtered = audit_events_cards(
            &events,
            &AuditEventsFilter {
                actor: Some("alice@example.com".to_string()),
                ..AuditEventsFilter::default()
            },
        );
        assert!(filtered.contains("Filter:"), "filter header: {filtered}");
        // alice still appears in the Filter header.
        assert!(filtered.contains("alice@example.com"));
        // The per-row `actor` label MUST be absent from the card body. The
        // Filter header also includes an `actor` label, so we partition the
        // output on the SEQ card boundary to scope the check to the body.
        let body_start = filtered.find("> SEQ").expect("seq card present");
        let body = &filtered[body_start..];
        assert!(
            !body.contains("actor"),
            "actor row should be suppressed in card body: {body}"
        );
    }

    #[test]
    fn traffic_logs_table_filter_header_and_cvm_column_dedup() {
        init(false);
        let extra = empty_extra();
        let logs = vec![TrafficLogView {
            timestamp: "2026-05-18T15:38:00Z",
            cvm_id: Some("cvm-aaa"),
            security_cvm_id: Some("sc-1"),
            method: Some("GET"),
            destination_host: Some("api.example.com"),
            response_code: Some(200),
            decision: Some("allowed"),
            bytes_transferred: 1234,
            path: Some("/v1/x"),
            extra: &extra,
        }];

        // Empty filter (no `cvm`): the CVM column appears in the table
        // header; no Filter header except the SC hoist for the single SC.
        let empty = traffic_logs_table(&logs, &TrafficLogsFilter::default());
        assert!(empty.contains("api.example.com"), "host row: {empty}");
        assert!(empty.contains("1 log"), "singular footer: {empty}");
        assert!(empty.contains("CVM"), "CVM column header: {empty}");
        assert!(!empty.contains('\x1b'));

        // Pinned `--cvm` filter: the CVM column is removed (single distinct
        // value moves into the Filter header) and `Filter:` appears.
        let filtered = traffic_logs_table(
            &logs,
            &TrafficLogsFilter {
                cvm: Some("cvm-aaa".to_string()),
                ..TrafficLogsFilter::default()
            },
        );
        assert!(filtered.contains("Filter:"));
        assert!(filtered.contains("cvm-aaa"));
        // Header line: " CVM " (column header) MUST NOT survive when the
        // column is removed.
        assert!(
            !filtered.contains(" CVM "),
            "CVM column should be removed when filter pins it: {filtered}"
        );
    }

    #[test]
    fn traffic_logs_table_renders_decision_column() {
        init(false);
        let extra = empty_extra();
        let logs = vec![TrafficLogView {
            timestamp: "2026-05-18T15:38:00Z",
            cvm_id: Some("cvm-aaa"),
            security_cvm_id: Some("sc-1"),
            method: Some("POST"),
            destination_host: Some("api.slack.com"),
            response_code: Some(403),
            decision: Some("secret_injection_unfulfilled"),
            bytes_transferred: 0,
            path: Some("/api/chat.postMessage"),
            extra: &extra,
        }];

        let out = traffic_logs_table(&logs, &TrafficLogsFilter::default());
        assert!(out.contains("DECISION"), "DECISION header present: {out}");
        assert!(
            out.contains("secret_injection_unfulfilled"),
            "block reason is legible in the decision column: {out}"
        );
    }

    #[test]
    fn entity_list_cards_renders_basic_card_and_footer() {
        init(false);
        let extra = empty_extra();
        let entities = vec![EntityView {
            id: "e-1",
            name: "acme",
            domain: "acme.example",
            created_at: "2026-05-18T15:38:00Z",
            extra: &extra,
        }];
        let out = entity_list_cards(&entities);
        assert!(out.contains("acme"), "name must appear: {out}");
        assert!(out.contains("1 entity"), "singular footer: {out}");
        assert!(out.contains("acme.example"));
        assert!(out.contains("e-1"));
        assert!(!out.contains('\x1b'));
    }

    #[test]
    fn test_umbra_ps_no_cvm_running_success() {
        // No running CVM at all -> the whole-command empty state `no sessions`.
        init(false);
        assert_eq!(ps_cards(&[]), "no sessions");
    }

    #[test]
    fn test_umbra_ps_many_cvms_with_sessions_success() {
        // Each CVM is its own group; session fields (name, alias) render and the
        // footer sums sessions across groups. The second group's session carries an
        // unreadable alias store, so it also pins that `ps` marks the fault in the
        // cell (never `-`, never a failed listing) like the resource views do.
        init(false);
        let extra = empty_extra();
        let groups = vec![
            PsCvmGroup {
                cvm_id: "cvm-aaa",
                error: None,
                sessions: vec![PsSessionView {
                    name: "ssh-1",
                    attached: true,
                    alias: Ok(Some("web")),
                    created_at: "2026-05-18T15:38:00Z",
                    extra: &extra,
                }],
            },
            PsCvmGroup {
                cvm_id: "cvm-bbb",
                error: None,
                sessions: vec![PsSessionView {
                    name: "ssh-2",
                    attached: false,
                    alias: Err("[error] malformed aliases file: boom"),
                    created_at: "2026-05-18T15:38:00Z",
                    extra: &extra,
                }],
            },
        ];
        let out = ps_cards(&groups);
        assert!(
            out.contains("cvm-aaa") && out.contains("cvm-bbb"),
            "both headers: {out}"
        );
        assert!(
            out.contains("ssh-1") && out.contains("ssh-2"),
            "both sessions: {out}"
        );
        assert!(out.contains("web"), "alias rendered: {out}");
        assert!(
            out.contains("unreadable") && !out.contains("malformed"),
            "an unreadable store is marked, not spelled out in the cell: {out}"
        );
        assert!(
            !out.contains("alias          -") && !out.contains("alias  -"),
            "the fault must not read as 'no alias': {out}"
        );
        assert!(out.contains("2 sessions"), "footer sums groups: {out}");
    }

    #[test]
    fn test_umbra_ps_cvm_without_sessions_success() {
        // A running CVM with no sessions still appears, with a `no sessions` note
        // under its header (distinct from the whole-command empty state).
        init(false);
        let groups = vec![PsCvmGroup {
            cvm_id: "cvm-aaa",
            error: None,
            sessions: vec![],
        }];
        let out = ps_cards(&groups);
        assert!(out.contains("cvm-aaa"), "cvm still listed: {out}");
        assert!(out.contains("no sessions"), "empty note: {out}");
        assert!(out.contains("0 sessions"), "footer: {out}");
    }

    #[test]
    fn test_umbra_ps_cvm_unreachable_success() {
        // A CVM whose probe failed shows an error line in place of its sessions,
        // while the other CVMs render normally and the footer counts only real
        // sessions (the errored CVM contributes none).
        init(false);
        let extra = empty_extra();
        let groups = vec![
            PsCvmGroup {
                cvm_id: "cvm-aaa",
                error: None,
                sessions: vec![PsSessionView {
                    name: "claude/main",
                    attached: true,
                    alias: Ok(Some("dev")),
                    created_at: "2026-05-18T15:38:00Z",
                    extra: &extra,
                }],
            },
            PsCvmGroup {
                cvm_id: "cvm-bbb",
                error: Some("aTLS handshake failed"),
                sessions: vec![],
            },
        ];
        let out = ps_cards(&groups);
        // Healthy CVM behaves normally.
        assert!(
            out.contains("cvm-aaa") && out.contains("claude/main"),
            "healthy group: {out}"
        );
        // Errored CVM is still listed, with its error in place of sessions.
        assert!(out.contains("cvm-bbb"), "errored cvm listed: {out}");
        assert!(
            out.contains("error") && out.contains("aTLS handshake failed"),
            "error line: {out}"
        );
        // Footer counts only real sessions (errored CVM contributes 0).
        assert!(
            out.contains("1 session"),
            "footer excludes errored cvm: {out}"
        );
    }

    #[test]
    fn status_multi_section_renders_required_sections() {
        init(false);
        let view = StatusView {
            user_email: "alice@example.com",
            user_id: "u-1",
            entity_name: "acme",
            entity_id: "e-1",
            console_url: Some("https://console.example"),
            security_cvm: Some(StatusSecurityCvm {
                id: "sc-1",
                state: "running",
                region: Some("eu-west-3"),
                instance_type: Some("tdx.cpx41"),
                policy_version: 7,
            }),
            security_cvm_hidden: false,
            totals_profiles: 2,
            totals_dev_cvms: 3,
            totals_dev_cvms_state_breakdown: vec![],
            totals_ssh_keys: 1,
            dev_cvms_by_profile: vec![],
            profiles: vec![],
            ssh_keys: vec![],
        };
        let out = status_multi_section(&view);
        // Primary identifier of the first section -- the user email.
        assert!(out.contains("alice@example.com"), "user email: {out}");
        // The section headers spec section 7.10 requires.
        assert!(out.contains("Session"));
        assert!(out.contains("Security CVM"));
        assert!(out.contains("Totals"));
        assert!(out.contains("sc-1"));
        assert!(!out.contains('\x1b'));
    }

    #[test]
    fn config_show_table_renders_header_and_value_columns() {
        init(false);
        let entries = vec![
            ConfigEntryView {
                key: "console_url",
                value: Some("https://console.example"),
                source: "file",
            },
            ConfigEntryView {
                key: "atls_policy",
                value: None,
                source: "missing",
            },
        ];
        let out = config_show_table(&entries);
        // Column headers MUST be present (the "footer phrase" for this
        // table-flavoured renderer; section 7.11 does not emit a count line).
        assert!(out.contains("KEY"));
        assert!(out.contains("VALUE"));
        assert!(out.contains("SOURCE"));
        // First row's primary identifier.
        assert!(out.contains("console_url"));
        assert!(out.contains("https://console.example"));
        // `None` renders as `(none)` per the section 7.11 contract.
        assert!(out.contains("(none)"));
        assert!(!out.contains('\x1b'));
    }

    #[test]
    fn version_card_renders_all_rows() {
        init(false);
        let out = version_card(
            "0.3.0-beta.1",
            "deadbeef0",
            "x86_64-unknown-linux-gnu",
            "2026-05-22",
        );
        // Primary identifier per section 7.12 is the version string in the
        // card title.
        assert!(out.contains("umbra 0.3.0-beta.1"), "title: {out}");
        // "Footer phrase" for this card is the section-7.12 row labels.
        assert!(out.contains("commit"));
        assert!(out.contains("target"));
        assert!(out.contains("build date"));
        assert!(out.contains("deadbeef0"));
        assert!(out.contains("x86_64-unknown-linux-gnu"));
        assert!(!out.contains('\x1b'));
    }

    #[test]
    fn auth_status_card_renders_required_sections() {
        init(false);
        let view = AuthStatusView {
            user_id: Some("u-1"),
            user_email: Some("alice@example.com"),
            entity_id: Some("e-1"),
            entity_name: Some("acme"),
            access_token_state: "valid",
            access_token_expires_at: Some("2026-05-25T15:38:00Z"),
            refresh_token_state: "valid",
            refresh_token_expires_at: Some("2026-06-25T15:38:00Z"),
            config_dir: "/home/alice/.config/umbra",
            config_dir_source: "default",
            console_url: Some("https://console.example"),
            console_url_source: "file",
            session_path: "/home/alice/.config/umbra/session.json",
            session_permissions: Some("rw-------"),
        };
        let out = auth_status_card(&view);
        // Primary identifier: the user email is the operator-facing handle.
        assert!(out.contains("alice@example.com"), "email: {out}");
        // Section 7.21 mandates these section headers.
        assert!(out.contains("User"));
        assert!(out.contains("Entity"));
        assert!(out.contains("Tokens"));
        assert!(out.contains("Config"));
        assert!(out.contains("Session file"));
        assert!(!out.contains('\x1b'));

        // Empty short-circuit: when fully unauthenticated, the canonical
        // `no session` line is emitted instead of any sections.
        let empty = AuthStatusView {
            user_id: None,
            user_email: None,
            entity_id: None,
            entity_name: None,
            access_token_state: "missing",
            access_token_expires_at: None,
            refresh_token_state: "missing",
            refresh_token_expires_at: None,
            config_dir: "/x",
            config_dir_source: "default",
            console_url: None,
            console_url_source: "missing",
            session_path: "/x",
            session_permissions: None,
        };
        assert_eq!(auth_status_card(&empty), "no session");
    }

    #[test]
    fn profile_show_card_renders_required_rows() {
        init(false);
        let extra = empty_extra();
        let view = ProfileShowView {
            id: "prof-1",
            alias: Ok(None),
            name: "permissive-dev",
            description: Some("Dev profile, all egress allowed."),
            assigned: true,
            attached_cvm_count: 1,
            attached_cvm_ids: vec!["cvm-a".to_string()],
            policy_pretty: "{\n  \"egress\": \"allow_all\"\n}",
            created_at: "2026-05-18T15:38:00Z",
            updated_at: "2026-05-21T14:23:00Z",
            extra: &extra,
        };
        let out = profile_show_card(&view);
        // Primary identifier per section 7.22: the profile name in the card
        // title.
        assert!(out.contains("permissive-dev"), "name: {out}");
        // Required rows per section 7.22.
        for label in [
            "id",
            "description",
            "assigned",
            "attached cvms",
            "policy",
            "created",
            "updated",
        ] {
            assert!(out.contains(label), "missing row: {label}");
        }
        assert!(out.contains("prof-1"));
        assert!(!out.contains('\x1b'));
    }

    #[test]
    fn profile_members_list_cards_filter_header_and_card() {
        init(false);
        let extra = empty_extra();
        let members = vec![ProfileMemberView {
            user_id: "u-1",
            email: "alice@example.com",
            added_at: "2026-05-18T15:38:00Z",
            extra: &extra,
        }];
        let filter = ProfileMembersFilter {
            profile_id: "prof-1".to_string(),
            profile_name: Some("permissive-dev".to_string()),
        };
        let out = profile_members_list_cards(&members, &filter);
        // Primary identifier per section 7.23: the member email in the card
        // title.
        assert!(out.contains("alice@example.com"), "email: {out}");
        assert!(out.contains("1 member"), "singular footer: {out}");
        // The Filter header is mandatory for this renderer (the listing is
        // always scoped to one profile, surfaced in the header).
        assert!(out.contains("Filter:"));
        assert!(out.contains("permissive-dev"));
        assert!(out.contains("prof-1"));
        assert!(!out.contains('\x1b'));
    }

    #[test]
    fn wait_timeout_block_reports_observed_status_success() {
        init(false);
        for operation_status in ["pending", "running"] {
            let block = wait_timeout_block(
                "op-123",
                "cvm.launch",
                Some("cvm-456"),
                operation_status,
                600,
            );
            let out = render_error(&block);
            assert!(out.starts_with("[wait_timeout] stopped watching after 600s"));
            assert!(out.contains(&format!("still {operation_status}")));
            assert!(out.contains(&format!("status was '{operation_status}'")));
            assert!(out.contains("not terminal"));
            assert!(out.contains("op-123"));
            assert!(out.contains("cvm cvm-456"));
            assert!(out.contains("--wait-timeout-seconds"));
            assert!(out.contains("--no-wait"));
            assert!(out.contains("        fix      umbra cvm list"));
        }
    }

    #[test]
    fn wait_timeout_block_uses_security_cvm_read_command() {
        init(false);
        let block = wait_timeout_block("op-9", "security_cvm.update", None, "running", 120);
        let out = render_error(&block);
        assert!(out.contains("the security cvm operation is still running"));
        assert!(out.contains("        fix      umbra security-cvm show"));
        assert!(!out.contains(", security cvm "));
    }

    #[test]
    fn wait_timeout_block_omits_fix_when_no_read_command() {
        init(false);
        let block = wait_timeout_block("op-1", "audit.export", None, "running", 600);
        let out = render_error(&block);
        assert!(out.contains("the audit export operation is still running"));
        assert!(!out.contains("        fix      "));
    }

    #[test]
    fn ssh_disconnect_block_names_cvm_and_generic_reconnect_when_session_unknown() {
        init(false);
        let out = render_error(&ssh_disconnect_block(
            "021b2dcc-d045-0c64-b509-000000000000",
            None,
            false,
        ));
        assert!(out.starts_with(
            "[error] connection to dev cvm 021b2dcc-d045-0c64-b509-000000000000 dropped\n"
        ));
        assert!(out.contains("dtach"));
        assert!(out.contains("could not confirm"));
        assert!(out.contains(
            "        fix      umbra ps --cvm 021b2dcc-d045-0c64-b509-000000000000   (then: umbra attach <session> --cvm 021b2dcc-d045-0c64-b509-000000000000)"
        ));
    }

    #[test]
    fn ssh_disconnect_block_gives_exact_attach_command_when_session_known() {
        init(false);
        let out = render_error(&ssh_disconnect_block(
            "cvm-abc123",
            Some("claude-20260702-101530"),
            true,
        ));
        assert!(out.starts_with("[error] connection to dev cvm cvm-abc123 dropped\n"));
        assert!(out.contains("still running"));
        assert!(
            out.contains("        fix      umbra attach claude-20260702-101530 --cvm cvm-abc123")
        );
        assert!(!out.contains("<session>"));
    }

    #[test]
    fn ssh_connect_failed_block_does_not_assert_a_surviving_session() {
        init(false);
        let out = render_error(&ssh_connect_failed_block(
            "021b2dcc-d045-0c64-b509-000000000000",
        ));
        assert!(out.starts_with(
            "[error] could not connect to dev cvm 021b2dcc-d045-0c64-b509-000000000000\n"
        ));
        assert!(out.contains("RUNNING yet"));
        assert!(!out.contains("still running"));
        assert!(out.contains("        fix      umbra cvm list"));
    }
}
