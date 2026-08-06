# Umbra CLI Style Spec

This document specifies the human-readable output formatting of the `umbra` CLI. It extends `cli.md` section 2.3 (Output formats) and defines the design pattern, color palette, output templates, and per-command rendering decisions.

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, MAY, and OPTIONAL in this document are used in the RFC 2119 / RFC 8174 sense.

**Status: ready for implementation.** Section 7 (per-command catalog) covers every list, show, status, and mutation command in scope. Future commands added to the CLI MUST extend section 7 before they ship. Open follow-ups (post-v0) are tracked in section 10.

**Definition of done.** The implementation is complete when, for every command listed in section 7, running the command against a live (or mocked at the wire level) Console produces output that matches the corresponding section 7 example, modulo the live data substitution (UUIDs, timestamps, hostnames). The 13 acceptance criteria in section 9 are the testable checklist; the section 7 examples are the visual ground truth.

## 1. Overview

The `umbra` CLI produces three kinds of output:
- human-readable rendering for interactive use (the subject of this document)
- structured JSON when `--json` is set (defined in `cli.md` section 2.3)
- error messages on stderr (defined in `cli.md` section 2.3).

This spec governs only the human-readable rendering. It does NOT change:

- the JSON output contract (byte-identical to today)
- the stderr / stdout split (`cli.md` section 2.3)
- the exit codes (`cli.md` section 2.4)
- the strict rule that on non-zero exit, stdout MUST be empty

### 1.1 Non-goals

Out of scope for this revision:

- arbitrary progress spinners (e.g., `indicatif`)
- bordered tables (e.g., `comfy-table`, `tabled`)
- internationalization, localization, theming, user-defined palettes
- pager integration

These MAY be added in future revisions.

**Limited exception** -- ANSI cursor-control codes (cursor up, line clear) are PERMITTED solely for the steps template (section 6.3) to support live in-place updates of step status. No other template MAY use cursor control. The cursor-control codes MUST be suppressed when the color toggle (section 3.2) is OFF; in that case the steps template degrades to progressive disclosure (each step printed on its own final line as it completes).

## 2. Design pattern: Facade

The CLI MUST consolidate all human-readable formatting in a single Rust module `cli/src/style.rs` exposing two layers of API:

- **Layer 1 (primitives)**: color / weight tokens with semantic names. See section 5.
- **Layer 2 (renderers)**: one or more functions per output entity. Each renderer composes Layer 1 primitives into the per-command layout defined in section 7.

Command implementations MUST call only Layer 2 renderers. They MUST NOT call Layer 1 primitives directly, and MUST NOT depend on `anstyle` or any other ANSI library. This guarantees:

- consistent palette across commands
- swapping the styling backend touches one file
- disabling styling requires no change at call sites (section 3)

## 3. Activation rules

Two independent toggles govern output.

### 3.1 Structure toggle

- Default structure is human-readable per section 6 and section 7.
- When `--json` is set or `config.output == Json`, output MUST be JSON only, with no ANSI codes, no decorative characters, and no informational lines outside the JSON payload.

### 3.2 Color toggle

Colors are ENABLED if and only if ALL of the following hold:

1. `config.output != Json`
2. `config.no_color == false` (covers the `--no-color` flag, `NO_COLOR=1`, `UMBRA_NO_COLOR=1`, and the `no_color` config-file key, resolved per `cli.md` section 4)
3. `std::io::stdout().is_terminal() == true` (stdout is a TTY)

When colors are DISABLED, every Layer 1 primitive MUST return its argument unchanged (Null Object behavior). **Structure is unaffected by the color toggle**: a card stays a card, a table stays a table; only the ANSI codes go away.

The activation result MUST be computed once per process at `style::init(...)` time, stored in a static `AtomicBool`, and read by every primitive.

## 4. Character set rules

Human-readable output MUST be printable ASCII (0x20-0x7E plus `\n` and `\t`) only. Unicode glyphs (triangles, check marks, crosses, arrows, ellipsis, box-drawing characters, emoji) MUST NOT be used.

Standard substitutions:

| Concept | ASCII token |
|---|---|
| Record block bullet | `> ` |
| Success marker | `[OK]` |
| Failure marker | `[FAIL]` |
| Warning marker | `[WARN]` |
| Progress arrow | `-> ` |
| Sub-line continuation | `\|_ ` |
| Ellipsis | `...` |
| Section separator | `---` |

Color carries semantic meaning. ASCII tokens MUST NOT be relied upon to differentiate states; for example, `running` and `stopped` differ by color, not by glyph.

### 4.1 Timestamp rendering

All timestamps in human-readable output MUST use the absolute UTC format `YYYY-MM-DD HH:MM UTC` (drop seconds and subseconds; never use the local timezone). Examples: `2026-05-18 15:38 UTC`, `2026-05-21 14:23 UTC`.

Relative formats (`5 days ago`, `2 hours ago`, `just now`) MUST NOT be used in any human-readable view governed by this spec.

The Console backend MUST be assumed to return ISO 8601 / RFC 3339 timestamps in UTC (e.g., `2026-05-18T15:38:12.338269Z`). The CLI converts the ISO string to the display format using `chrono`. JSON output is unaffected: with `--json`, timestamps MUST be emitted byte-identical to what the Console returned.

## 5. Style primitives (Layer 1)

The following primitives are normative. Implementations MUST NOT add to or rename this catalog without updating this document.

| Primitive | Color / weight | Usage |
|---|---|---|
| `label(s)` | dim / faint, no bold | record field keys (`state`, `fqdn`, ...) |
| `value(s)` | bold, default color | primary identifiers (`fqdn`, `email`, `name`) |
| `muted(s)` | dim gray | secondary metadata (timestamps, footer counts, truncated UUIDs) |
| `success(s)` | green | OK state values (`running`, `active`, `allowed`) |
| `error_style(s)` | red, bold | error state values (`error`, `failed`, `blocked`, `disabled`). Named `error_style` rather than `error` to avoid colliding with Rust's `Result::Err` / `error!` macro conventions. |
| `warn(s)` | yellow | transitional state values (`pending`, `stopped`) |
| `info(s)` | cyan | informational, not state-bearing (used for: `next step` values in confirm template, `console` URL in `status`, config `source = flag` / `env`, audit `_LOGIN` actions, traffic-logs 3xx responses) |
| `header(s)` | bold | section titles inside multi-section cards |
| `bullet()` | cyan | the leading `> ` in card title lines |

The implementation MAY factor a `state(domain, value)` helper that internally dispatches to `success / warn / error / muted / info` based on a per-domain table. This is an internal Layer 2 detail; the call surface for command code remains the entity renderer (`cvm_list_cards`, etc.). Each per-domain dispatch table MUST be declared in this document (see section 7 per-command notes), regardless of how the implementation factors the helper.

#### Case-insensitive dispatch rule

Domain dispatch lookups on state values MUST be case-insensitive. The renderer MUST lowercase the wire value before matching against the dispatch table. Dispatch tables in section 7 use lowercase keys by convention; both `RUNNING` and `running` MUST resolve to the same color. This rule applies globally to every dispatch table in section 7 -- the wire format frequently uses uppercase (`RUNNING`, `STOPPED`, `FAILED`) while the spec dispatch tables use lowercase for readability; the renderer reconciles the two via lowercasing.

## 6. Templates (Layer 2)

The following templates are normative shapes used by Layer 2 renderers. Section 7 says which template each command uses.

### 6.1 Card template

A record block introduced by a title line, followed by indented `label  value` rows.

#### Allowed title forms

The title line MUST follow one of these four patterns. Each section 7 entry declares which pattern its renderer uses.

| Pattern | Used when | Examples |
|---|---|---|
| `> <primary-identifier>` | the entity has a single human-meaningful unique key (email, name, label) | `> alice@example.com`, `> permissive-dev`, `> laptop`, `> dev_cvms` |
| `> ID <uuid>` | the entity is identified by a UUID with no shorter human key | `> ID 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9` |
| `> SEQ <number>` | the entity is identified by a monotone sequence number | `> SEQ 12345` |
| `> <SectionName>` | section-only card (no per-entity title; used for single-record cards and multi-section cards per 6.1.1) | `> Security CVM`, `> Session`, `> Totals` |

Style for the title:

- `bullet()` (cyan) + `value(<identifier>)` (bold), with the static prefix (`ID `, `SEQ `) rendered in normal text when present.
- For the `> <SectionName>` form: `bullet()` + `header(<section-name>)` (bold).

#### Layout rules

- outer indent: **6 spaces** before each label
- label area: padded with spaces so all values in the card align at a fixed column. The fixed column equals `6 + max-label-width + 2`, where `max-label-width` is the longest label inside the card.
- multi-line values: continuation lines are indented to the value column (no label repeat). Wrap MUST occur at a comma boundary when the value is a comma-separated list (e.g., permissions). Otherwise wrap occurs at the configured maximum line width (default 100 chars per section 4) without breaking words.
- conditional fields (e.g., `error`) appear only when present, placed right after `state`
- a blank line separates consecutive cards within a list
- a footer line `N <records>` follows the last card (see footer table below)

Style application:

- title: see "Allowed title forms" above
- labels: `label(name)` (dim)
- values: bare text, colored per the domain rules in section 7
- footer: `muted()`

#### Empty state

When the list contains zero records, the renderer MUST emit `no <records>` (literal) on a single line, styled `muted()`. No title, no footer. Example: `no cvms`, `no keys`.

#### Footer label words (per entity)

When the count is exactly 1, the footer MUST use the singular form. When >= 2 or 0, use the plural form. The footer table below gives both forms; the singular is obtained by removing the trailing `s` from the plural. The empty-state literal always uses the plural form.

| Section 7 entry | Plural / Singular | Empty state |
|---|---|---|
| 7.1 user list | `users` / `user` | `no users` |
| 7.2 cvm list | `cvms` / `cvm` | `no cvms` |
| 7.3 profile list | `profiles` / `profile` | `no profiles` |
| 7.4 key list | `keys` / `key` | `no keys` |
| 7.5 audit events | `events` / `event` | `no events` |
| 7.6 traffic-logs | `logs` / `log` | `no logs` |
| 7.7 entity list | `entities` / `entity` | `no entities` |
| 7.8 quota get | `quotas` / `quota` | `no quotas` |
| 7.9 ps | `sessions` / `session` | `no sessions` |
| 7.23 profile members list | `members` / `member` | `no members` |
| 7.34 cvm instance-types | `instance types` / `instance type` | `no instance types` |

Sections 7.10 (`status`), 7.11 (`config show`), 7.12 (`version`), 7.13 (`security-cvm show`), 7.21 (`auth status`), and 7.22 (`profile show`) do NOT render a footer because they are not lists: `status` and `auth status` are multi-section cards (section 6.1.1, no overall footer), `config show` is a single fixed-shape table (rows are not "records" of an entity), `version`, `security-cvm show`, and `profile show` are single-section cards. Mutation commands (7.14-7.19, 7.24-7.26) also have no footer; their closing block is the confirm template (section 6.4).

#### Footer / pagination notes

When the wire response for a list / events / logs command exposes a non-null `next_cursor`, the caller MUST emit a one-line auxiliary diagnostic on stderr immediately after the list body. The diagnostic is rendered through the Layer 2 helper `style::next_cursor_diagnostic(cursor: &str) -> String`, which formats it as `next cursor: <opaque>` styled `muted()`. The Console-controlled cursor string is passed through the section 4 ASCII sanitiser before rendering so a hostile envelope cannot inject ANSI sequences via the cursor token.

This applies uniformly to: `user list`, `cvm list`, `profile list`, `profile members list`, `key list`, `audit events`, `traffic-logs`, and any future list command that exposes pagination. Command code MUST NOT emit ad-hoc `next cursor: ...` strings via raw `eprintln!`; the helper is the only entry point.

Reference rendering (CVM card with UUID title):

```
> ID 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
      alias          prod-box
      state          running
      fqdn           cvm-aaaaaaaaaaaaaaaaaaaaaaaaaa.dev.example.com
      instance type  tdx.cpx41
      ...

> ID 9e1f4d8a-2b3c-4d5e-6f7a-8b9c0d1e2f3a
      alias          -
      state          stopped
      ...

N cvms
```

Reference rendering (User card with email title):

```
> alice@example.com
      id           5965ae0b-5e30-42e4-bff2-4b45b00cadb9
      state        active
      ...
```

### 6.1.1 Multi-section card

A multi-section card is a sequence of single-section cards rendered as one logical unit (no footer between sections). Used when one command summarizes several aspects of the caller's state in a single output (e.g., `umbra status`).

Rules:

- each section uses the `> <SectionName>` title form (section 6.1)
- each section computes its label alignment **independently** (the value column position is per-section, not global across sections; this keeps each section visually compact)
- a blank line separates consecutive sections
- there is no overall footer (no `N records` line)
- a section MAY append a parenthetical hint after its title, styled `muted()`, e.g., `> Profiles  (use \`umbra profile list\` for detail)`
- a section MAY render its body as a single literal line (e.g., `none`) instead of the indented rows form when the underlying data is empty or absent; that single line MUST be indented 6 spaces like a regular value and styled per the section 7 domain rule

#### Three-column row variant

A section MAY use a multi-column row format where each row is `label  primary  uuid` instead of the standard `label  value`. This variant exposes UUIDs in their own column instead of inline parens, keeping the primary value visually clean and copy-pasteable.

Layout of the 3-column row variant:

- outer indent: **6 spaces** before each label (same as standard rows)
- label area: padded so all `primary` values align to a fixed column (label width = longest label in the section + 2 separator spaces)
- `primary` area: padded so all `uuid` values align to a second fixed column (primary width = longest primary value in the section + 2 separator spaces)
- `uuid` slot: the bare UUID, or the literal `-` when no UUID applies for that row

The renderer chooses per-section whether to use the standard 2-column or the 3-column row variant; the decision is documented in section 7 for each section that uses it.

Reference rendering (3-column variant, mixing rows with and without UUIDs):

```
> Session
      user     alice@example.com                              28d76b77-a973-498d-a6a1-b9b58f298dbc
      entity   Example Corp                                   61b04bff-6378-430a-8236-4ed8bb2437ed
      console  https://console.example.com                    -
```

Reference rendering:

```
> Session
      user      ...
      entity    ...

> Security CVM
      none

> Totals
      profiles  2
      ...
```

### 6.2 Table template

A header row followed by aligned data rows.

Layout rules:

- header row: column names in uppercase, single space separator
- each data row: columns aligned to the header widths, padded with spaces
- the last column MAY be variable-width; if it overflows the terminal it wraps naturally without altering alignment of the other columns
- column widths are computed from the maximum value width in the page (no terminal probing)
- a blank line separates the table from the footer
- footer line: `N <records>` (e.g., `3 logs`)

Style application:

- headers: `header()` (bold)
- timestamp values: `muted()` (gray)
- primary identifier values (host, fqdn, email): `value()` (bold)
- other values: bare text, colored per the domain rules in section 7
- footer: `muted()`

#### Empty state

When the table contains zero data rows, the renderer MUST emit `no <records>` (literal) on a single line, styled `muted()`. No header row, no footer. Same shape as section 6.1 cards. The footer-word table in section 6.1 applies.

Reference rendering:

```
TIMESTAMP         METHOD  HOST                  RESPONSE  DECISION  BYTES    PATH
2026-05-21 14:23  GET     github.com            200       allowed   12345    /example/project
2026-05-21 14:23  POST    api.openai.com        200       allowed   45678    /v1/chat/completions

N logs
```

### 6.2.1 Filter deduplication rule

A flag that constrains a field to a single exact value (`--cvm <id>`, `--security-cvm <id>`, `--actor <id>`, `--target-id <id>`, `--action <name>`, etc.) MUST:

- Remove the corresponding column from the data rows (or field from the cards)
- Add the field to a `Filter:` header block displayed before the data, in `label  value` form with **2 spaces indent** (the Filter header is denser than card body so it does not visually compete with the data)

Range filters (`--from`, `--to`) and operational filters (`--limit`, `--cursor`) MUST appear in the `Filter:` header for context but MUST NOT alter the data columns.

When no filters are active, the `Filter:` header block MUST be omitted.

When a field is constant for an entity regardless of filters (e.g., `security_cvm_id` because v0 has one SC per entity), the field MAY be hoisted into the `Filter:` header by per-command decision documented in section 7.

The decision of WHICH filters are active is made by the CLI command code, not by the renderer. The renderer signature MUST accept a `FilterContext` struct passed by the caller; the renderer applies the rule mechanically based on which fields of the context are populated.

#### `FilterContext` definition

The `FilterContext` is **per-command** (not global). Each renderer in section 7 declares its own struct shape based on the filter fields it cares about. Example for `traffic-logs`:

```rust
pub struct TrafficLogsFilterContext {
    pub cvm:          Option<String>,
    pub security_cvm: Option<String>,
    pub from:         Option<String>,
    pub to:           Option<String>,
}
```

The implementation MAY use a generic `BTreeMap<&'static str, String>` as an alternative if it avoids boilerplate. The visible spec rule is only: the renderer takes one parameter that lists which filters are active, and decides display from there.

#### Conditional column / field

When a field varies across rows (no filter pins it) but COULD be pinned by a filter that the caller did not pass, the renderer MAY add the field back as an additional column (table) or row (card) per per-command rule. See section 7.6 for the canonical example (`cvm` column appears in `traffic-logs` only when `--cvm` is NOT set).

Reference rendering:

```
Filter:
  cvm           10103f98-fe7b-4299-b14c-82e313de209f
  security cvm  sc-aaaaaaaaaaaaaaaaaaaaaaaaaa

TIMESTAMP         METHOD  HOST                  RESPONSE  DECISION  BYTES    PATH
2026-05-21 14:23  GET     github.com            200       allowed   12345    /example/project
...
```

### 6.3 Steps template

> TODO (Console side, out of scope here): rename the saga step strings in `console.md` section 8.3 to provider-neutral names so the syntactic Title-Case transformation below never exposes `Phala` / `Cf` to the operator. The CLI does NOT remap; the cleanup MUST happen in the Console adapter.

Used for async mutations that execute a server-side saga. The CLI does NOT hardcode the saga step list. The Console reveals one step at a time via `progress.step` on the Operation polling response (`console.md` section 8.6). The CLI displays steps **progressively**: each step appears on its own line as soon as the Console reports it.

#### Information available to the CLI at moment t

At each poll, the CLI receives the current `progress.step` (a single string, the saga step name). It does NOT know:

- the total number of steps in the saga
- the names of steps that come next
- the duration each step will take

The CLI measures durations itself by recording the timestamp at which a new step name first appears in a poll response (start) and the timestamp at which a different step name takes over (end, => previous step duration).

#### Line format

Each step occupies one line:

```
[<step-index>] <Step Name>               [<elapsed>]
```

- step-index: 1-based, incremented as the CLI observes new step transitions. There is NO `/total` because total is unknown.
- Step Name: derived from the raw saga step name (`progress.step`, snake_case) by replacing each `_` with a space and Title-Casing the first character of each word (every other character lowercased). The transformation is purely syntactic; the CLI MUST NOT maintain a friendly-name mapping table or per-acronym exception list. Examples (neutral saga names): `validate` -> `Validate`, `persist_stub` -> `Persist Stub`, `provision` -> `Provision`, `configure_dns_a` -> `Configure Dns A`, `verify_attestation` -> `Verify Attestation`, `await_sc_pull` -> `Await Sc Pull`, `policy_push` -> `Policy Push`, `finalise` -> `Finalise`.

  Provider-specific names appearing in `progress.step` (e.g. `phala_deploy`, `cf_txt_create`) indicate a spec drift on the Console side and SHOULD be reported. The CLI renders whatever the Console emits but the Console adapter MUST hide provider names per `cli.md` section 3.6 -- providers stay behind Console adapters and never leak through the wire-level operation envelope.
- elapsed: time spent on this step. While in progress, the CLI MUST refresh the elapsed value at least once per second. Final form examples: `0.4s`, `12s`, `45.8s`, `2m4s`.

#### Status colors

| Status | Color | When |
|---|---|---|
| in progress | `warn` (yellow) | step is currently running; elapsed updates live |
| done | `success` (green) | step completed successfully; elapsed is the final duration |
| failed | `error` (red, bold) | step failed; elapsed slot renders the literal `[FAILED]` (not the duration) so the failure verb is visible at a glance |

There is NO pending status because future steps are not displayed. Color applies to the WHOLE line (index, name, elapsed) so the user perceives status at a glance.

**Exception to the no-hardcode rule.** When a saga is implemented CLI-side and never touches the Console (e.g., `umbra auth login`, see section 7.18), the step names MUST be declared by the CLI because there is no Console source to read them from. This exception is limited to CLI-internal sagas; Console-driven sagas (cvm launch, security-cvm launch, etc.) MUST NOT hardcode step lists.

#### Live in-place update

When the color toggle is ON (section 3.2):

1. On first poll where `progress.step` is known, the CLI prints the line for step 1 in in-progress (yellow) color with the current elapsed.
2. Each subsequent poll, while still on the same step, the CLI rewrites THAT line in place to refresh the elapsed value:
   - `\r` to return to column 0
   - `\x1b[K` to clear the line
   - reprint the line with the updated elapsed
3. When `progress.step` transitions to a new name:
   - the current line is rewritten one last time as done (green) with the final elapsed
   - a new line is printed below for the new step (yellow, live)
4. When the operation reaches `succeeded`, the current step's line is finalized as done (green). The CLI then prints a blank line and the final confirm block (section 6.4).
5. When the operation reaches `failed`, the current step's line is rewritten as failed (red) with the elapsed at failure. The CLI prints a blank line and the multi-line error block (section 6.5).

When the color toggle is OFF (section 3.2 false), the CLI MUST NOT emit cursor-control codes. Instead it prints each step line ONCE, only when the step transitions to its final state (done or failed) with its final elapsed. The current step's live elapsed is NOT shown. The final confirm or error block follows on a new line.

#### Reference rendering -- mid-run, color ON

The user is watching the screen at t = 1 minute. The first three steps have completed; the fourth is in progress.

```
[1] Validate                          [0.4s]     <- green
[2] Persist Stub                      [0.3s]     <- green
[3] Provision                         [45.8s]    <- green
[4] Configure Dns Txt                 [12s]      <- yellow (live, refreshes once per sec)
```

#### Reference rendering -- final, success

```
[1] Validate                          [0.4s]
[2] Persist Stub                      [0.3s]
[3] Provision                         [45.8s]
[4] Configure Dns Txt                 [0.5s]
[5] Configure Dns Cname               [0.4s]
[6] Verify Attestation                [28.1s]
[7] Await Sc Pull                     [2.0s]
[8] Policy Push                       [0.1s]
[9] Finalise                          [0.1s]

[OK] <confirm block from section 6.4>
```

#### Reference rendering -- failure mid-saga

```
[1] Validate                          [0.4s]
[2] Persist Stub                      [0.3s]
[3] Provision                         [FAILED]    <- red

[error] <multi-line error block from section 6.5>
```

### 6.4 Confirm template

Used for sync mutations (and as the closing block of async mutations after the steps template completes). The header line states the action; an optional indented detail block follows.

#### Single-line form (default for simple mutations)

```
[OK] <verb> <entity-noun> <identifier>
```

Examples: `[OK] added key laptop`, `[OK] removed key k-7f3a2b1c-...`, `[OK] created profile permissive-dev`.

#### Multi-line form (when details and/or a next-step hint apply)

```
[OK] <verb> <entity-noun> <identifier>
        <field>      <value>
        ...
        next step    <suggested command>
```

Layout rules for the multi-line form mirror the error template (section 6.5):

- header line: `[OK] <message>` on its own line
- follow-up rows: 8-space indent (same as error template), label area padded so all values align (label width = longest label in the block + 2 separator spaces)
- the `next step` row is OPTIONAL and rendered as the LAST row when a useful follow-up command exists
- the multi-line form MAY include any number of detail rows; section 7 declares which fields the renderer emits per command

Style:

- `[OK]` -- `success()` (green, bold)
- message -- normal, with entity name rendered with `value()` (bold)
- labels -- `label()` (dim)
- `next step` value -- `info()` (cyan), since it is a command the user can copy and run

Output goes to **stdout** (mutation success). On non-zero exit the error template (section 6.5) is used on stderr instead, and stdout MUST remain empty per `cli.md` section 2.3.

### 6.5 Error template

A single-line error or a multi-line block, always emitted to **stderr** (never stdout). Used by every command for non-zero exits, regardless of `--json` (per `cli.md` section 2.3, `--json` affects success output only).

Single-line form (default):

```
[<bracket>] <message>
```

Where `<bracket>` is the typed `error.code` value returned by the Console in the error envelope (e.g., `NOT_FOUND`, `VALIDATION_ERROR`, `FORBIDDEN`, `UNAUTHORIZED`, `RATE_LIMITED`, `CONFLICT`, `SERVICE_UNAVAILABLE`) per `cli.md` section 2.4. The bracket-prefixed code lets scripts branch on the reason without parsing JSON.

Sanitisation per section 4 applies to the bracketed code value: any non-printable-ASCII byte returned by the Console as `error.code` MUST be escaped at render time, so a hostile envelope cannot smuggle ANSI through the bracket. The bracket value MUST therefore never contain control bytes.

**Independence from the exit code.** The numeric exit code is still computed per the table in `cli.md` section 2.4 (1 / 2 / 3 / 4 / 0); only the shape of the bracketed display tag changes. A `401 UNAUTHORIZED` response still produces exit `2` regardless of whether the bracket holds `UNAUTHORIZED` or a fallback.

#### Client-side fallback table

When the error originates client-side (no Console envelope is available) the bracket value is derived from the exit-code symbol via the following table, NOT from the Console code (because there is none):

| Exit-code symbol (`cli.md` 2.4) | Bracket fallback | When |
|---|---|---|
| `usage` | `usage` | `--limit` out of range, malformed UUID, missing required flag, unknown subcommand, mutually-exclusive flag conflict. Argument-parser errors. |
| `auth_required` | `auth_required` | No session loaded, refresh token expired, session file unreadable. |
| `wait_timeout` | `wait_timeout` | `--wait-timeout-seconds` elapsed while polling a Console Operation. |
| `error` | `error` | Local I/O failure, transport error before the Console returned a body, malformed Console body (cannot parse the envelope). |

The fallback bracket value is rendered verbatim (lowercase) so a `[usage]` tag is visually distinct from a Console-sourced `[VALIDATION_ERROR]` tag. Scripts can therefore match on either form by case-insensitive prefix.

Multi-line form (when the Console returns a structured error envelope OR a request-id is available):

```
[<bracket>] <message>
        cause       <one-line reason>
        details     <one-line elaboration>
        fix         <one suggested command or action>
        request-id  <correlation id>
```

Layout rules for the multi-line form:

- header line: `[<bracket>] <message>` on its own line. The bracket value MUST NOT be duplicated as a parenthesised suffix on the message (the prior `(CODE)` form is dropped).
- follow-up rows: **8-space indent** (chosen to align visually under the message text -- `[error] ` is 8 characters, `[VALIDATION_ERROR] ` is 19; 8 is the minimum that works for the most common `[error]` case). Label area padded so all values align (label width = longest label inside the block + 2 separator spaces)
- each of `cause`, `details`, `fix`, `request-id` is OPTIONAL and rendered only when present
- if no follow-up rows would render, the single-line form is used

Style application:

- `[<bracket>]` -- `error()` (red, bold)
- message -- normal
- labels (`cause`, `details`, `fix`, `request-id`) -- `label()` (dim)
- values -- normal

On non-zero exit, stdout MUST remain empty per `cli.md` section 2.3; the error block goes to stderr only.

## 7. Per-command output catalog

This section is the registry of decided layouts. New commands MUST update this section. Each entry MUST include the chosen template, the field set rendered, and an ASCII example.

### 7.1 `umbra user list`

**Status: VALIDATED**

Template: card (section 6.1).

Filter context (per section 6.2.1):

- `status` -- from the `--status <active|deactivated|erased>` flag. Shown in the `Filter:` header **only when `--status` is explicitly supplied**. The rendered value is the literal flag value (`active` / `deactivated` / `erased`). Display-only: rows arrive already filtered from the Console (`docs/specs/console.md` §3.6), so `user_list_cards` MUST NOT add, drop, or reorder cards by status.
- `assigned` -- from the `--assigned <yes|no>` flag. Shown in the `Filter:` header **only when `--assigned` is explicitly supplied**. The rendered value is the literal flag value (`yes` / `no`). Display-only, same constraint as above. `UserListFilter` gains `status: Option<String>` and `assigned: Option<String>` fields used solely to render these header lines.

Primary identifier (title line): the user's `email`. The UUID is rendered as an `id` row inside the card.

Fields rendered (per `cli.md` and User struct):

- email (in title)
- id (UUID)
- state
- permissions (comma-separated, **always the full list, never truncated**; wraps to additional indented lines if it exceeds the terminal width)
- profiles (names, comma-separated)
- created (formatted `YYYY-MM-DD HH:MM UTC`, see section 4.1)

Domain dispatch:

- `state`: `active` -> `success`, `disabled` -> `error`, `pending` -> `warn`

Example:

```
$ umbra user list

> alice@example.com
      id           5965ae0b-5e30-42e4-bff2-4b45b00cadb9
      state        active
      permissions  CVM_LAUNCH
      profiles     permissive-dev
      created      2026-05-19 09:01 UTC

> bob@example.com
      id           28d76b77-a973-498d-a6a1-b9b58f298dbc
      state        active
      permissions  AUDIT_EXPORT, AUDIT_VIEW, CVM_LAUNCH, PERMISSION_MANAGE,
                   SECURITY_CVM_CONFIGURE, TRAFFIC_LOGS_VIEW, USER_MANAGE
      profiles     permissive-dev
      created      2026-05-19 06:58 UTC

> carol@example.com
      id           460e5cfb-43a3-4c82-bdb7-e1c1615d8650
      state        active
      permissions  AUDIT_EXPORT, AUDIT_VIEW, CVM_LAUNCH, CVM_MANAGE,
                   PERMISSION_MANAGE, PLATFORM_OPERATOR, SECURITY_CVM_CONFIGURE,
                   TRAFFIC_LOGS_VIEW, USER_MANAGE
      profiles     permissive-dev
      created      2026-05-18 15:38 UTC

3 users
```

### 7.2 `umbra cvm list`

**Status: VALIDATED**

Template: card (section 6.1).

Filter context (per section 6.2.1):

- `profile` -- from the global `--profile <PROFILE_ID>` flag. When set, the `profiles` field is hoisted to the `Filter:` header (it would otherwise be constant across all rendered cards) and removed from each card.
- `state` -- from the `--state <STATE>` flag. Shown in the `Filter:` header **only when `--state` is explicitly supplied**; a bare `umbra cvm list` (which defaults to `alive`) shows no `state` line, mirroring `--profile`. The rendered value is the literal flag value (`alive` / `all` / `provisioning` / `running` / `stopped` / `failed` / `terminated`). Display-only: rows arrive already filtered from the Console (`docs/specs/console.md` §3.6), so `cvm_list_cards` MUST NOT add, drop, or reorder cards by state. `CvmListFilter` gains a `state: Option<String>` field used solely to render this header line.

Fields rendered (per `cli.md` section 3.4 / `umbra cvm list` and the Cvm struct in `cli/src/commands/cvm.rs`):

- id (in title)
- alias (the caller's local alias for this CVM, or `-` when it has none). Rendered directly under the title: it is the record's other identifier, and the one every CVM-targeting verb accepts in place of the UUID. Sourced from the local `aliases.toml` (`cli.md` section 4.4), NOT from the Console record -- so it is human-view only and absent from `--json` (a script joins on `umbra alias list --json`).

  **Three states, one per state of the alias store** (the `AliasCell` contract, shared verbatim by sections 7.3, 7.4, 7.9 and 7.22):

  1. the recorded name;
  2. `-` when this record has no alias;
  3. the literal `unreadable`, styled `error`, when the store could not be read at all (malformed TOML, unreadable file).

  A local-state fault MUST NOT fail the command -- Console truth is intact, so exit stays `0` -- and MUST NOT render as `-`, which would claim the record has no alias. The **full** store error goes to **stderr, once per command**, never into the cells: a `toml` parse error carries caret art no cell can hold and puts its useful part on its LAST line, and repeating it in every card of a 100-record page would drown the payload. stderr also covers the case the cells cannot: a listing with **zero** records renders no card at all, and would otherwise leave no trace of the fault.

  The name is passed through the section 4 ASCII sanitiser AND folded onto one line (`\n` / `\t` escaped), because `aliases.toml` is a hand-editable local file: the sanitiser deliberately keeps newlines for multi-line values, which in a one-line cell would let a name forge extra card rows -- even a fake `> ID <uuid>` title, inventing a record that does not exist.

  ```
  $ umbra cvm list                        # unreadable ~/.umbra/aliases.toml
  [warn] alias names are not shown: malformed aliases file: TOML parse error at line 2, column 8
    |
  2 | nick = 42
    |        ^
  invalid type: integer `42`, expected a string; fix or remove /home/user/.umbra/aliases.toml
  ```
  ```
  > ID 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
        alias          unreadable
        state          running
        ...
  ```
  (the `[warn]` block on stderr, the card on stdout; exit `0`)
- state
- error (conditional, only when state is `error` or `failed`; sourced from `error_reason`)
- fqdn (or `-` if null)
- instance type
- region
- profiles (names only, comma-separated; UUIDs available in `--json`). **Removed from card when `--profile` filter is set; appears in `Filter:` header instead.**
- ssh keys (labels only, comma-separated; UUIDs available in `--json`)
- owner (email only; UUID available in `--json`)
- created (formatted `YYYY-MM-DD HH:MM UTC`)
- updated (formatted `YYYY-MM-DD HH:MM UTC`)

NOT exposed in this view (operator-internal, available in `--json`): `entity_id`, `expected_image_measurement`, `image_measurement`, `rtmr3_digest`, `attestation_verified_at`.

Domain dispatch:

- `state`: `running` -> `success`, `stopped` -> `warn` (yellow; actionable -- user can `start` it back), `pending` / `provisioning` -> `warn`, `error` / `failed` -> `error`, `terminating` / `terminated` -> `muted`
- `error` (the `error_reason` value) -> `error`
- `alias` -> plain when it holds a name or `-`; `error` on the `unreadable` marker (above)
- `fqdn` value -> `value` (bold; this is the copy-paste-for-ssh field)

Example:

```
$ umbra cvm list

> ID 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
      alias          prod-box
      state          running
      fqdn           cvm-aaaaaaaaaaaaaaaaaaaaaaaaaa.dev.example.com
      instance type  tdx.cpx41
      region         eu-west-3
      profiles       permissive-dev
      ssh keys       laptop
      owner          bob@example.com
      created        2026-05-18 15:38 UTC
      updated        2026-05-21 14:23 UTC

> ID 9e1f4d8a-2b3c-4d5e-6f7a-8b9c0d1e2f3a
      alias          -
      state          stopped
      fqdn           cvm-abc123def456ghi789jkl012m.dev.example.com
      instance type  tdx.cpx41
      region         eu-west-3
      profiles       permissive-dev
      ssh keys       laptop, desktop-home
      owner          bob@example.com
      created        2026-05-20 09:15 UTC
      updated        2026-05-20 11:45 UTC

> ID 3c8b7e2f-4d5e-6f7a-8b9c-0d1e2f3a4b5c
      alias          -
      state          error
      error          ssh_key_mismatch
      fqdn           -
      instance type  tdx.cpx41
      region         eu-west-3
      profiles       production-strict
      ssh keys       -
      owner          alice@example.com
      created        2026-05-21 14:18 UTC
      updated        2026-05-21 14:18 UTC

3 cvms
```

### 7.3 `umbra profile list`

**Status: VALIDATED**

Template: card (section 6.1).

Filter context (per section 6.2.1):

- `assigned` -- from the `--assigned <yes|no>` flag. Shown in the `Filter:` header **only when `--assigned` is explicitly supplied**. The rendered value is the literal flag value (`yes` / `no`). Display-only: rows arrive already filtered from the Console (`docs/specs/console.md` §3.6), so `profile_list_cards` MUST NOT add, drop, or reorder cards by membership. This is distinct from the per-card `assigned` row (the caller's membership, always rendered). `ProfileListFilter` gains an `assigned: Option<String>` field used solely to render this header line.

Primary identifier (title line): the profile `name` (e.g., `> permissive-dev`). UUID is rendered as an `id` row.

Fields rendered:

- name (in title)
- id (UUID)
- alias (the caller's local alias for this profile, or `-` when it has none). Same source and same three-state `AliasCell` contract as section 7.2: local `aliases.toml`, human-view only, `unreadable` (styled `error`) plus one stderr line when the store cannot be read, never a failed command.
- assigned (caller's membership: `yes` / `no`)
- attached cvms (count on the first line, then the full list of CVM UUIDs on subsequent lines indented to the value column; bare UUIDs, no `ID ` prefix)
- created (formatted `YYYY-MM-DD HH:MM UTC`)
- updated (formatted `YYYY-MM-DD HH:MM UTC`)

NOT rendered in this view:

- `entity_id` -- operator-internal; available in `--json` only.
- `description` -- omitted by explicit decision (kept available in `--json`).
- `policy` -- omitted in list view. Rationale: opaque JSON whose pretty-print form (~15-20 extra lines per profile) dominates the card and makes scanning multiple profiles painful. Users wanting policy detail run `umbra profile show <id>` (to be specified separately).

Rationale for full UUID list under `attached cvms`: per operational data, a profile in practice holds at most a small number of CVMs (single digits, rarely more). The full enumeration stays readable in that regime and removes the need for a follow-up `profile show` to see which CVMs are attached.

Domain dispatch:

- `assigned`: `yes` -> `success` (green), `no` -> `muted` (gray)
- `alias`: as section 7.2 (plain for a name or `-`, `error` on the `unreadable` marker)

Example (with realistic data from `umbra profile list`):

```
$ umbra profile list

> toto-dev
      id             f7670482-2466-4ecd-b0a8-89693ac5182a
      alias          -
      assigned       no
      attached cvms  1
                     7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
      created        2026-05-19 14:22 UTC
      updated        2026-05-21 10:04 UTC

> permissive-dev
      id             2148e3a2-0097-4580-9be8-e64396eda8d9
      alias          dev
      assigned       yes
      attached cvms  8
                     7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
                     9e1f4d8a-2b3c-4d5e-6f7a-8b9c0d1e2f3a
                     3c8b7e2f-4d5e-6f7a-8b9c-0d1e2f3a4b5c
                     2f9d1e3a-4d5e-6f7a-8b9c-0d1e2f3a4b5c
                     5a6b7c8d-9e0f-1a2b-3c4d-5e6f7a8b9c0d
                     1e2f3a4b-5c6d-7e8f-9a0b-1c2d3e4f5a6b
                     9c0d1e2f-3a4b-5c6d-7e8f-9a0b1c2d3e4f
                     7a8b9c0d-1e2f-3a4b-5c6d-7e8f9a0b1c2d
      created        2026-05-14 10:00 UTC
      updated        2026-05-21 09:56 UTC

2 profiles
```

### 7.4 `umbra key list`

**Status: VALIDATED**

Template: card (section 6.1).

Primary identifier (title line): the key `label` (e.g., `> laptop`). UUID is rendered as an `id` row.

Fields rendered:

- label (in title)
- id (UUID)
- alias (the caller's local alias for this SSH key, or `-` when it has none). Same source and same three-state `AliasCell` contract as section 7.2: local `aliases.toml`, human-view only, `unreadable` (styled `error`) plus one stderr line when the store cannot be read, never a failed command.
- fingerprint (SHA256 form, e.g., `SHA256:qXsuB4AHLRLPMzY7jfrNveIGM7Vo4S93sFtzRl1yHg8`, displayed in full -- always 50 chars, no truncation)
- algorithm (e.g., `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`; derived client-side from `public_key.split(' ').next()`, which returns the OpenSSH-prefixed form -- keep the `ssh-` prefix when present)
- created (formatted `YYYY-MM-DD HH:MM UTC`)

NOT rendered in this view:

- `public_key` (the raw OpenSSH-encoded key, 80-700+ chars) -- omitted from both human and `--json` output. Rationale: in a list view the fingerprint is sufficient to identify a key (matches `ssh-keygen -lf ~/.ssh/<key>.pub` on the user's side), while the public key itself is long, not useful without copying the entire value, and intentionally left to a future `umbra key show <id>` detail command. This matches the existing `SshKeyOutput` struct in `cli/src/commands/key.rs` which drops `public_key`.

Note on the security framing: SSH public keys are public material by design (distributing them is the whole point of asymmetric crypto). The choice to display the fingerprint rather than the public key is a usability decision -- compactness in a list view -- not a security one.

Domain dispatch:

- `alias`: as section 7.2 (plain for a name or `-`, `error` on the `unreadable` marker). No other dispatch: keys have no state field.

Example:

```
$ umbra key list

> laptop
      id           k-7f3a2b1c-1234-5678-9abc-def012345678
      alias        laptop-key
      fingerprint  SHA256:abc1234567890ABCDEFghijklmnopqrstuvwxyz12345
      algorithm    ssh-ed25519
      created      2026-04-15 09:30 UTC

> desktop-home
      id           k-8g4b3c2d-2345-6789-abcd-ef0123456789
      alias        -
      fingerprint  SHA256:def1234567890ABCDEFghijklmnopqrstuvwxyz23456
      algorithm    ssh-ed25519
      created      2026-04-20 14:22 UTC

> ci-runner
      id           k-9h5c4d3e-3456-789a-bcde-f01234567890
      alias        -
      fingerprint  SHA256:ghi1234567890ABCDEFghijklmnopqrstuvwxyz34567
      algorithm    ssh-rsa
      created      2026-05-01 08:15 UTC

3 keys
```

### 7.5 `umbra audit events`

**Status: VALIDATED**

Template: card (section 6.1).

Primary identifier (title line): the `seq` sequence number, prefixed by the static token `SEQ ` (e.g., `> SEQ 12345`). Sequence numbers are monotone within an entity and serve as the natural cursor reference.

Filter context (per section 6.2.1):

- `actor` -- from `--actor <USER_ID>`. When set, the `actor` field is constant; hoisted to `Filter:` header and removed from each card. The header value MUST use the user-resolution rule from section 7.8: format precisely as `user <resolved_email> <UUID>` when the email can be resolved (single spaces, no parens, no dash), and fall back to `user <UUID>` (no middle component) when resolution fails. The renderer SHOULD share the same user-resolution helper used by `quota get`.
- `action` -- from `--action <ACTION>`. When set, the `action` field is constant; hoisted to `Filter:` header and removed from each card.
- `target` -- from `--target-type <TYPE>` plus `--target-id <ID>`. When both are set, the `target` field is constant; hoisted to `Filter:` header and removed from each card. When only `--target-type` is set, the `target_type` portion is constant (still varying `target_id`); the entry MAY still be hoisted with a synthesized value `<type>/*` and the `target` field MAY be reduced to just the `target_id`. Implementation MAY simplify this to "hoist only when BOTH are set" for v0.
- `from` / `to` -- from `--from` / `--to`. Range filters; appear in `Filter:` header but do NOT alter card fields (per section 6.2.1).
- `limit` / `cursor` -- from `--limit` / `--cursor`. Operational filters; appear in `Filter:` header for context but do NOT alter card fields (per section 6.2.1).

Fields rendered:

- seq (in title)
- timestamp (formatted `YYYY-MM-DD HH:MM UTC`)
- actor (`actor_email`; falls back to `-` when null, e.g., system-emitted events). Removed when `--actor` is set.
- action (typed string, e.g., `CVM_LAUNCHED`, `PROFILE_POLICY_UPDATED`). Removed when `--action` is set.
- target (`target_type/target_id`, full UUID). Removed when `--target-type` and `--target-id` are both set.
- description (free-form string)

NOT rendered in this view (available in `--json`):

- `id` (the audit event's own UUID; the `seq` already identifies the row uniquely within the entity and is shorter to reference)
- `entity_id` (always the caller's entity; no information value in surfacing)
- `actor_id` (the UUID; `actor_email` is shown instead because it is human-readable)
- `before` / `after` (JSON snapshots of the affected resource before and after the mutation; often large or null; available via `--json` or a future `umbra audit show <seq>` command)
- `request_id` (correlation token for joining with Console-side logs; niche)
- `ip_address` (forensics-only)
- `prev_hash` / `row_hash` (the tamper-evidence hash chain; never read by humans during normal browsing)

Domain dispatch on `action`:

The action is parsed by suffix. Unrecognized actions fall through to `muted` per section 11.4.

| Suffix | Style | Examples |
|---|---|---|
| `_LAUNCHED`, `_ADDED`, `_CREATED`, `_GRANTED`, `_REGISTERED` | `success` (green) | `CVM_LAUNCHED`, `KEY_ADDED`, `PROFILE_CREATED` |
| `_DENIED`, `_FAILED`, `_REVOKED`, `_REJECTED` | `error` (red, bold) | `CVM_TERMINATE_DENIED`, `AUTH_FAILED` |
| `_DELETED`, `_TERMINATED`, `_REMOVED` | `warn` (yellow) | `KEY_REMOVED`, `CVM_TERMINATED` |
| `_UPDATED`, `_CHANGED`, `_ROTATED` | normal (no color) | `PROFILE_POLICY_UPDATED` |
| `_LOGIN`, `_LOGOUT`, `_REFRESHED`, `_CONNECTED` | normal | `AUTH_LOGIN`, `SSH_CONNECTED` |
| (other) | `muted` (per section 11.4 unknown-state fallback) | -- |

Domain dispatch on `target`:

The `target_type` is rendered in normal text, the `/` separator in `muted`, and `target_id` in `muted` (gray). The full UUID is shown without truncation; consistency with `cvm list` and `profile list` decisions.

Volume note:

The default `--limit` for `umbra audit events` is `100` per `cli.md` section 3.6, producing up to ~700 lines of human output (7 lines per card). Users requesting many pages SHOULD use `--limit` to scope the view, or fall back to `--json` for bulk consumption. This spec does not change the default `--limit`.

Example:

```
$ umbra audit events --limit 5

> SEQ 12345
      timestamp    2026-05-21 14:23 UTC
      actor        alice@example.com
      action       CVM_LAUNCHED
      target       cvm/7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
      description  Launched cvm in eu-west-3 with profile permissive-dev

> SEQ 12344
      timestamp    2026-05-21 14:21 UTC
      actor        alice@example.com
      action       KEY_ADDED
      target       key/k-7f3a2b1c-1234-5678-9abc-def012345678
      description  Added ssh key 'laptop' (ed25519)

> SEQ 12343
      timestamp    2026-05-21 14:18 UTC
      actor        alice@example.com
      action       AUTH_LOGIN
      target       user/28d76b77-a973-498d-a6a1-b9b58f298dbc
      description  Login via Google OIDC from 198.51.100.42

> SEQ 12342
      timestamp    2026-05-21 13:45 UTC
      actor        bob@example.com
      action       CVM_TERMINATE_DENIED
      target       cvm/3c8b7e2f-4d5e-6f7a-8b9c-0d1e2f3a4b5c
      description  Terminate denied: caller lacks CVM_MANAGE permission

> SEQ 12341
      timestamp    2026-05-21 13:30 UTC
      actor        carol@example.com
      action       PROFILE_POLICY_UPDATED
      target       profile/2148e3a2-0097-4580-9be8-e64396eda8d9
      description  Updated dlp.rules: added api_key, jwt patterns

5 events
```

### 7.6 `umbra traffic-logs`

**Status: VALIDATED**

Template: table (section 6.2) with mandatory `Filter:` header (section 6.2.1).

#### Single-block rendering

The renderer ALWAYS emits exactly one block: one `Filter:` header, one table, one footer. The implementation MUST NOT emit multiple table blocks, MUST NOT separate sub-groups with blank lines, MUST NOT add per-group headers. There is no defensive grouping path; the single-block invariant is normative.

Per `cli.md` and `v0_plan.md`, an entity has at most one live Security CVM, so every row returned by `GET /traffic-logs` for the caller's session typically shares the same `security_cvm_id`. The `security cvm` line in the `Filter:` header is populated either from the caller's `--security-cvm` flag or from the single constant value observed in the returned page.

If the returned page carries rows with multiple distinct `security_cvm_id` values AND the caller did not pin a value via `--security-cvm`, the SC value MUST NOT be hoisted into the `Filter:` header (it is not constant). Instead it MUST appear as an additional table column, symmetric to the CVM column variant described below. In the typical v0 case (one SC per entity), the SC always lands in the `Filter:` header and the column is absent.

Filter context fields (always shown in `Filter:` header when populated):

- `cvm` (from `--cvm`)
- `security cvm` (from `--security-cvm`, or the constant value observed across the returned rows)
- `from` (from `--from`, formatted to spec section 4.1)
- `to` (from `--to`, formatted to spec section 4.1)
- `limit` (from `--limit`, raw integer)
- `cursor` (from `--cursor`, opaque cursor string)

Table columns (7, in order):

| Column | Source | Notes |
|---|---|---|
| TIMESTAMP | `timestamp` | formatted `YYYY-MM-DD HH:MM UTC` |
| METHOD | `method` | `-` when null (non-HTTP traffic) |
| HOST | `destination_host` | `-` when null; rendered with `value()` (bold) |
| RESPONSE | `response_code` | `-` when null (non-HTTP or blocked) |
| DECISION | `decision` | SC enforcement decision: `allowed`, a block reason (e.g. `secret_injection_unfulfilled`, `dlp_secret_detected`), or `websocket_frame_dropped`; `-` when null (rows ingested before the field existed) |
| BYTES | `bytes_transferred` | raw integer, no humanization |
| PATH | `path` | last column; wraps naturally if long; `-` when null |

NOT rendered in this view (available in `--json`):

- `id` (the log row's UUID; rarely useful for daily browsing)
- `cvm_id` (moved to `Filter:` header when `--cvm` is set; included as an extra column when no filter)
- `security_cvm_id` (hoisted to `Filter:` header by default per the rule above)
- `source_ip` (constant per CVM; redundant when filtered)
- `destination_ip` (the resolved IP; less informative than `destination_host`)
- `port` (almost always 443)
- `protocol` (almost always `https`)

Domain dispatch on `response_code`:

| Value | Style |
|---|---|
| 2xx | `success` (green) |
| 3xx | `info` (cyan) |
| 4xx | `warn` (yellow) |
| 5xx | `error` (red, bold) |
| `-` (null, blocked / non-HTTP) | `error` (red, bold) |
| `blocked` (synthetic value when SC denied egress before any HTTP response) | `error` (red, bold) |

Domain dispatch on `method`:

| Value | Style |
|---|---|
| `GET`, `HEAD`, `OPTIONS` | normal |
| `POST`, `PUT`, `PATCH` | normal |
| `DELETE` | `warn` (yellow) |
| (other / null) | `muted` |

Variant -- no filter on `--cvm`:

When the caller does not pass `--cvm`, the `cvm` field varies across rows and is rendered as an additional column inserted between TIMESTAMP and METHOD, showing the **FULL UUID** (36 chars). It is NOT in the `Filter:` header. The table becomes wider (~225 chars total) and MAY exceed typical 80-column terminals; this is accepted as the price of unambiguous identification.

Variant -- no filter on `--security-cvm` AND multiple SC ids in the page:

By symmetry with the CVM column variant, when `--security-cvm` is not set AND the returned rows carry more than one distinct `security_cvm_id`, the SC value MUST be rendered as an additional `SECURITY CVM` column (full UUID), inserted after the optional CVM column and before METHOD. The `security cvm` line is then absent from the `Filter:` header (it is not constant). In the typical v0 case (one SC per entity), every row in the page shares the same SC and the column is absent; the SC lands in the `Filter:` header.

The same rule applies for any filter field that varies in the returned data set: if the field is not pinned to a single value, it MUST appear as a column rather than be hidden.

```
TIMESTAMP         CVM                                   METHOD  HOST                  RESPONSE  BYTES    PATH
2026-05-21 14:23  10103f98-fe7b-4299-b14c-82e313de209f  GET     github.com            200       12345    /example/project
2026-05-21 14:24  a7b9c2d4-1e2f-3a4b-5c6d-7e8f9a0b1c2d  POST    api.openai.com        200       45678    /v1/chat/completions
```

Example (with `--cvm` filter active):

```
$ umbra traffic-logs --cvm 10103f98-fe7b-4299-b14c-82e313de209f --limit 3

Filter:
  cvm           10103f98-fe7b-4299-b14c-82e313de209f
  security cvm  sc-aaaaaaaaaaaaaaaaaaaaaaaaaa
  limit         3

TIMESTAMP         METHOD  HOST                  RESPONSE  BYTES    PATH
2026-05-21 14:23  GET     github.com            200       12345    /example/project
2026-05-21 14:23  POST    api.openai.com        200       45678    /v1/chat/completions
2026-05-21 14:24  GET     malicious-site.com    blocked   0        /payload.bin

3 logs
```

Example (no `--cvm` filter -- CVM column appears, single SC block per v0 invariant):

```
$ umbra traffic-logs --limit 4

Filter:
  security cvm  3a1bb45c-1111-4111-8111-111111111111
  limit         4

TIMESTAMP         CVM                                   METHOD  HOST                  RESPONSE  BYTES    PATH
2026-05-21 14:23  10103f98-fe7b-4299-b14c-82e313de209f  GET     github.com            200       12345    /example/project
2026-05-21 14:23  10103f98-fe7b-4299-b14c-82e313de209f  POST    api.openai.com        200       45678    /v1/chat/completions
2026-05-21 14:24  a7b9c2d4-1e2f-3a4b-5c6d-7e8f9a0b1c2d  GET     malicious-site.com    blocked   0        /payload.bin
2026-05-21 14:25  a7b9c2d4-1e2f-3a4b-5c6d-7e8f9a0b1c2d  POST    api.openai.com        200       1024     /v1/messages

4 logs
```

### 7.7 `umbra entity list`

**Status: VALIDATED**

Template: card (section 6.1). Admin command (`PLATFORM_OPERATOR`).

Filter context (per section 6.2.1): NONE. `umbra entity list` accepts no filter flags in v0, so the renderer does not declare a `FilterContext` struct and never emits a `Filter:` header. The struct catalog in section 12.5 documents this explicitly.

Primary identifier (title line): the entity `name`.

Fields rendered (Entity struct in `cli/src/commands/entity.rs`):

- name (in title)
- id (UUID)
- domain
- created (formatted per section 4.1)

Domain dispatch: none.

Example:

```
$ umbra entity list

> example-corp
      id          a1b2c3d4-1234-5678-9abc-def012345678
      domain      example.com
      created     2026-05-01 09:00 UTC

> acme
      id          d4e5f6g7-2345-6789-abcd-ef0123456789
      domain      example.com
      created     2026-05-10 14:30 UTC

2 entities
```

### 7.8 `umbra quota get`

**Status: VALIDATED**

This is the read command for quotas. `quota get` reads / lists quotas. The mutation siblings `quota set` and `quota clear` are specified separately in section 7.24.

Template: card (section 6.1).

Primary identifier (title line): the `resource` name. Per `cli.md` section 3.13 the resource names are lowercase strings (`dev_cvms`, `ssh_keys`, `users`, `profiles` for entity scope; `dev_cvms`, `ssh_keys` for user scope).

Filter context (per section 6.2.1):

- `scope` -- synthesized from `--entity <ID>` or `--user <ID>`. When either is set, the `scope` field is constant across all returned quotas; hoisted to `Filter:` header (per the scope name resolution rule below) and removed from each card.

#### Scope name resolution

The `Filter:` header value for `--entity` and `--user` MUST resolve a human-readable name before falling back to the bare UUID. Format precisely: `<noun> <human-readable> <UUID>` with single spaces; no parens, no dash, no `id=` prefix. The fallback (no human-readable) just omits the middle component, yielding `<noun> <UUID>`.

- When `--entity <X>` is set:
  - If `X == session.entity.id`: render `entity <session.entity.name> <X>` (no extra API call).
  - Else: call `GET /entities/{X}` to resolve. On success: `entity <resolved_name> <X>`. On 404 / 403: fallback to `entity <X>`.
- When `--user <X>` is set:
  - If `X == session.user.id`: render `user <session.user.email> <X>` (no extra API call).
  - Else: call `GET /entities/{session.entity.id}/users/{X}` (the only user endpoint exposed; users are scoped to entity). On success: `user <resolved_email> <X>`. On 404 / 403: fallback to `user <X>`.

The same user-resolution helper SHOULD be reused by `umbra audit events --actor <X>` (section 7.5).

Fields rendered (Quota struct in `cli/src/commands/quota.rs`):

- resource (in title)
- scope (synthesized line, formatted per the scope name resolution rule above). Removed when `--entity` or `--user` is set.
- limit
- current usage
- source (e.g., `entity-override`, `user-override`, `default`)
- set by (email + UUID, or `-` when null / default)
- set at (formatted per section 4.1, or `-` when null)

Domain dispatch on `source`:

| Value | Style |
|---|---|
| `default` | `muted` |
| `entity-override`, `user-override` | normal |

Threshold dispatch (proposed): when `current_usage` is close to `limit` (>= 80%), the `current usage` row value MAY be styled `warn` (yellow). At >= 100% (over quota), `error` (red). Implementation MAY skip this in v0.

Example:

```
$ umbra quota get --entity a1b2c3d4-1234-5678-9abc-def012345678

Filter:
  scope  entity example-corp a1b2c3d4-1234-5678-9abc-def012345678

> dev_cvms
      limit          10
      current usage  3
      source         entity-override
      set by         alice@example.com (28d76b77-a973-498d-a6a1-b9b58f298dbc)
      set at         2026-05-15 11:00 UTC

> ssh_keys
      limit          10
      current usage  2
      source         default
      set by         -
      set at         -

2 quotas
```

### 7.9 `umbra ps`

**Status: ready for implementation.**

Template: per-CVM groups (section 6.1 cards, nested). No `Filter:` header — the CVM is a group title, not a filter.

`ps` lists dtach sessions **grouped by Dev CVM**. A bare `ps` covers every `RUNNING` Dev CVM of the caller; a `<CVM_ID>` positional or `--cvm` scopes to one (`cli.md` §3.4).

Each group renders a **title** (the CVM id, via the section-title primitive `> <cvm_id>`), then — **nested one level under it (2-space indent, so the hierarchy survives the no-color toggle per section 3.2)** — exactly one of:

- its **session cards**: primary identifier is the session `name`; fields `attached` (`yes`/`no`), `alias`, `created` (formatted per section 4.1). The `alias` cell follows the same three-state `AliasCell` contract as section 7.2 -- the recorded name, `-` when the session has none, or `unreadable` (styled `error`) plus one stderr line when `aliases.toml` cannot be read. An unreadable store MUST NOT fail `ps`: the sessions come from the Dev CVMs, not from that local file, so the listing still renders and exit is unchanged;
- a one-line `error  <message>` styled `error` when the CVM's SSH/aTLS probe failed;
- `no sessions` (muted) when the CVM is reachable but has none.

Domain dispatch on `attached`: `yes` -> `success` (green), `no` -> `muted`. On `alias`: as section 7.2.

Footer: total sessions across all groups (section 6.1 singular/plural). Whole-command empty state (caller has no `RUNNING` CVM): `no sessions`.

Example:

```
> cvm-9a7f6b4a-1111-2222-3333-444444444444
  > ssh-20260521-142312
        attached  yes
        alias     my-session
        created   2026-05-21 14:23 UTC
  > claude-20260521-130000
        attached  no
        alias     -
        created   2026-05-21 13:00 UTC

> cvm-8b2e5c3d-5555-6666-7777-888888888888
  error  aTLS handshake failed

2 sessions
```

### 7.10 `umbra status`

**Status: VALIDATED**

Template: multi-section card (section 6.1.1), using the 3-column row variant documented in section 6.1.1 for the `Session`, `Profiles`, and `SSH Keys` sections to expose UUIDs in their own column.

Each section uses the `> <SectionName>` title form (section 6.1) styled `bullet() + header()`. The `Profiles` and `SSH Keys` sections append a parenthetical hint after the title styled `muted()`, e.g., `> Profiles  (use \`umbra profile list\` for detail)`.

Sections rendered, in order (with the row format used):

1. **Session** -- 3-column variant. Rows: `user` (primary = email, uuid = user.id), `entity` (primary = entity name, uuid = entity.id), `console` (primary = URL from `config.console_url`, uuid = `-`).
2. **Security CVM** -- standard 2-column rows: `id`, `state`, `region`, `instance`, `policy` (version). The section's rendering depends on Console response:
   - HTTP 200 (SC exists, caller has `SECURITY_CVM_CONFIGURE`): rows rendered with SC data.
   - HTTP 404 (caller has `SECURITY_CVM_CONFIGURE`, no SC provisioned): the section body is the single literal line `none` (indented 6 spaces, styled `error_style()` -- red).
   - HTTP 403 (caller lacks `SECURITY_CVM_CONFIGURE`, common for dev users): the entire section -- title and body -- MUST be omitted from the output. The renderer skips silently. This makes `umbra status` usable by devs without inflating their permission surface.

The HTTP 403 path is the typical case for non-admin users. The CLI MUST NOT surface the 403 as an error block (which would crash `status` as a whole); it MUST treat the section as invisible.
3. **Totals** -- standard 2-column rows: `profiles` (count), `dev cvms` (count, with a parenthetical breakdown by state e.g. `3  (1 running, 1 stopped, 1 error)`), `ssh keys` (count).
4. **Dev CVMs by profile** -- per `cli.md` section 3.6, status groups Dev CVMs under the profiles the caller belongs to. Each profile contributes one indented header line (the profile name, styled `value()`), followed by one compact one-liner per attached CVM. Each CVM line uses the form `<uuid>  <state>  <fqdn-or-error-reason>`:
   - `uuid`: the full Dev CVM UUID, styled `muted()`.
   - `state`: the CVM state, dispatched via the same table as section 7.2 (`running` -> `success`, `stopped` -> `warn`, `error` -> `error`, etc.).
   - tail value: the `fqdn` when state is `running`, else the `error_reason` (or `-` when neither is set). Profiles with zero attached CVMs render a single `none` line (styled `muted()`) under the profile header. The whole section is omitted when the caller belongs to no profiles. Each line is indented 6 spaces like a card label row; the profile header line gets 6 spaces of indent and the CVM lines get 8 spaces of indent so the hierarchy is visually obvious.
5. **Profiles** -- 3-column variant. Rows: `<name>` (primary = profile name, uuid = profile.id), then a trailing column showing `<N> cvm[s] attached` (singular/plural per section 6.1). Trailing parenthetical hint `(use \`umbra profile list\` for detail)`. Note: the 3-column variant in this section places the cvm-count text into the right-hand slot that normally holds the UUID; the profile UUID is rendered in the middle column.
6. **SSH Keys** -- 3-column variant extended with two additional trailing columns (fingerprint, algorithm). Rows: `<label>` (primary = key.label, uuid = key.id), then `<fingerprint>`, then `<algorithm>`. Trailing parenthetical hint `(use \`umbra key list\` for detail)`.

The backticks visible in the rendered output (around `umbra profile list` / `umbra key list`) are **literal ASCII backticks** (0x60). They are not Markdown code spans; they reproduce the conventional way a CLI surfaces a command in prose, copyable as-is by the user.

Embedded list items use compact one-liners (not full cards) to avoid duplicating what `profile list` / `key list` already render in detail. Each section line is indented 6 spaces like a card label row.

Singular/plural for profile cvm counts uses correction 9 (section 6.1): `1 cvm attached` for exactly one, `N cvms attached` otherwise; `0 cvms attached` for zero (or the section body is replaced by `none` per the empty-body rule of 6.1.1).

Domain dispatch:

- Security CVM `state`: same as Cvm state (section 7.2)
- `console` URL value: `info()` (cyan)

Example:

```
$ umbra status

> Session
      user     alice@example.com                              28d76b77-a973-498d-a6a1-b9b58f298dbc
      entity   Example Corp                                   61b04bff-6378-430a-8236-4ed8bb2437ed
      console  https://console.example.com                    -

> Security CVM
      id        224dab85-8a12-4c50-a7ab-3aaa17d5fda1
      state     running
      region    eu-west-3
      instance  tdx.cpx41
      policy    v2.1.4

> Totals
      profiles  2
      dev cvms  3  (1 running, 1 stopped, 1 error)
      ssh keys  2

> Dev CVMs by profile
      permissive-dev
        7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9  running   cvm-h7ncvci.dev.example.com
        9e1f4d8a-2b3c-4d5e-6f7a-8b9c0d1e2f3a  stopped   cvm-abc123def.dev.example.com
      production-strict
        3c8b7e2f-4d5e-6f7a-8b9c-0d1e2f3a4b5c  error     ssh_key_mismatch

> Profiles  (use `umbra profile list` for detail)
      personal-dev    f7670482-2466-4ecd-b0a8-89693ac5182a  1 cvm attached
      permissive-dev  2148e3a2-0097-4580-9be8-e64396eda8d9  8 cvms attached

> SSH Keys  (use `umbra key list` for detail)
      test1-copy  k-7f3a2b1c-1234-5678-9abc-def012345678  SHA256:qXsuB4AHLRLPMzY7jfrNveIGM7Vo4S93sFtzRl1yHg8  ssh-ed25519
      test2       k-8g4b3c2d-2345-6789-abcd-ef0123456789  SHA256:Z9UvFyvytFJpHPVttjGMjUZg5zp3CMqj6HDeOjaiBXA  ssh-ed25519
```

### 7.11 `umbra config show`

**Status: VALIDATED**

Template: table (section 6.2). No `Filter:` header (no filter flags on this command).

Columns rendered (3, in order):

| Column | Source | Notes |
|---|---|---|
| KEY | the resolved config key name (e.g., `config_dir`, `console_url`, `default_cvm`) | |
| VALUE | the resolved value | `(none)` literal when unset |
| SOURCE | one of `flag`, `env`, `file`, `default`, `missing` | indicates where the value came from per `cli.md` section 4 |

Rows: one per resolved config key. The full list of keys is whatever `config_entries()` in `cli/src/commands/config.rs` returns -- this spec MUST follow that list, not duplicate it.

Domain dispatch on SOURCE:

| Value | Style |
|---|---|
| `flag` | `info` (cyan) |
| `env` | `info` (cyan) |
| `file` | normal |
| `default` | `muted` |
| `missing` | `error` (red) |

VALUE rendering:

- `(none)` literal when the resolved value is None: `muted`
- normal text otherwise

Example:

```
$ umbra config show

KEY                     VALUE                                         SOURCE
config_dir              /home/alice/.umbra                        default
console_url             https://console.example.com                file
default_cvm             7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9          env
default_profile         permissive-dev                                file
output                  text                                          default
no_color                true                                          flag
verbose                 0                                             default
atls_policy             (none)                                        missing
```

### 7.12 `umbra version`

**Status: VALIDATED**

Template: single-section card (section 6.1). Title is `> umbra <version>` where `<version>` is the semantic version (`env!("CARGO_PKG_VERSION")`).

Fields rendered:

- commit (full SHA-1, 40 chars, NOT truncated)
- target (build target triple, e.g. `aarch64-apple-darwin`)
- build date (formatted per section 4.1 when known, otherwise raw `BUILD_DATE`)

Styles:

- title (`> umbra 0.4.2`): `bullet()` + `value()` (bold)
- labels (`commit`, `target`, `build date`): `label()` (dim)
- values: bare text

Example:

```
$ umbra version

> umbra 0.4.2
      commit      e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2
      target      aarch64-apple-darwin
      build date  2026-05-19
```

### 7.13 `umbra security-cvm show`

**Status: VALIDATED**

Template: single-section card (section 6.1). Title is the literal `> Security CVM` (section style, no UUID in title since there is exactly one SC per entity).

Fields rendered:

- id (UUID)
- state
- error (conditional, only when `state` is `error` or `failed`; sourced from `error_reason`)
- fqdn
- instance
- region
- policy version
- attested (`attestation_verified_at`, formatted per section 4.1)
- created (formatted per section 4.1)
- updated (formatted per section 4.1)

NOT rendered in this view (available in `--json`):

- `entity_id` (always the caller's entity)
- `expected_image_measurement` (SHA-384 hex, ~96 chars; forensics only)
- `image_measurement` (SHA-384 hex; forensics only)
- `rtmr3_digest` (SHA-384 hex; forensics only)

Domain dispatch:

- `state`: `running` -> `success`, `stopped` -> `warn` (yellow; actionable -- user can `start` it back), `pending` / `provisioning` -> `warn`, `error` / `failed` -> `error`, `terminating` / `terminated` -> `muted`
- `error` (the `error_reason` value): `error`

Example:

```
$ umbra security-cvm show

> Security CVM
      id              sc-aaaaaaaaaaaaaaaaaaaaaaaaaa
      state           running
      fqdn            sc-aaaaaaaaaaaaaaaaaaaaaaaaaa.sc.example.com
      instance        tdx.cpx41
      region          eu-west-3
      policy version  v2.1.4
      attested        2026-05-21 14:22 UTC
      created         2026-05-14 09:00 UTC
      updated         2026-05-21 14:22 UTC
```

Error variant:

```
$ umbra security-cvm show

> Security CVM
      id              sc-aaaaaaaaaaaaaaaaaaaaaaaaaa
      state           error
      error           attestation_failed
      fqdn            sc-aaaaaaaaaaaaaaaaaaaaaaaaaa.sc.example.com
      instance        tdx.cpx41
      region          eu-west-3
      policy version  v2.1.4
      attested        -
      created         2026-05-14 09:00 UTC
      updated         2026-05-21 14:22 UTC
```

### 7.14 `umbra cvm launch`

**Status: VALIDATED**

Async mutation. Templates: steps (section 6.3) followed by confirm (section 6.4) on success or error (section 6.5) on failure.

The CLI submits `POST /cvms`, receives an Operation handle, and polls. Steps appear progressively per section 6.3 (no hardcoded list; the CLI derives Title-Cased names from `progress.step`).

On success, the confirm block fields:

- header: `[OK] launched cvm <cvm.id>` (cvm.id rendered with `value()` bold)
- `fqdn` -- the assigned FQDN
- `state` -- expected to be `running`
- `policy file` -- absolute path to the per-CVM aTLS policy file written under `config.config_dir/cvms/<cvm.id>.atls-policy.json`
- `next step` -- `umbra ssh <cvm.id>` (info, cyan)

On failure, the error block uses fields from the Operation envelope (section 7.20).

Example (success):

```
$ umbra cvm launch --profile permissive-dev --ssh-key laptop

[1] Validate                          [0.4s]
[2] Persist Stub                      [0.3s]
[3] Provision                         [45.8s]
[4] Configure Dns Txt                 [0.5s]
[5] Configure Dns Cname               [0.4s]
[6] Verify Attestation                [28.1s]
[7] Await Sc Pull                     [2.0s]
[8] Policy Push                       [0.1s]
[9] Finalise                          [0.1s]

[OK] launched cvm 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
        fqdn         cvm-aaaaaaaaaaaaaaaaaaaaaaaaaa.dev.example.com
        state        running
        policy file  /home/alice/.umbra/cvms/7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9.atls-policy.json
        next step    umbra ssh 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
```

Example (failure during step 3 -- provider provisioning timed out):

```
$ umbra cvm launch --profile permissive-dev --ssh-key laptop

[1] Validate                          [0.4s]
[2] Persist Stub                      [0.3s]
[3] Provision                         [FAILED]

[VALIDATION_ERROR] failed to launch CVM
        cause       provider deploy timed out after 120s
        details     operation never reached the running state
        request-id  req-7f3a2b1c
```

With `--no-wait`: the CLI prints the Operation handle as a multi-line confirm block (template 6.4), no steps block, and exits 0 immediately. The header verb uses present-continuous tense (`launching`, `terminating`, `updating`) to signal that the saga is in progress server-side. The renderer is `style::operation_handle_confirm` (section 8). Mapping from `operation.kind` to verb / entity-noun:

| `operation.kind` | header verb | entity noun |
|---|---|---|
| `cvm.launch` | `launching` | `cvm` |
| `cvm.terminate` | `terminating` | `cvm` |
| `cvm.update` | `updating` | `cvm` |
| `security_cvm.launch` | `launching` | `security cvm` |
| `security_cvm.terminate` | `terminating` | `security cvm` |
| `security_cvm.update` | `updating` | `security cvm` |
| (other) | `submitted` | the raw `operation.kind` string |

The identifier in the header is `operation.target.id` when set, otherwise `operation.id`. Detail rows: `operation` (the operation id), `status` (`pending` / `running`), and optionally `target type` when `operation.target.id` is null (i.e. the saga has not yet reached the step that allocates the target id).

Example (`cvm launch --no-wait`):

```
$ umbra cvm launch --profile ... --ssh-key ... --no-wait
[OK] launching cvm 5dda504b-b309-4ceb-88ec-412736213ef5
        operation  7ef84bc7-4f05-4a88-87cc-65456a815dc8
        status     pending
```

The same shape applies to `cvm terminate --no-wait`, `cvm update --no-wait`, `security-cvm launch --no-wait`, `security-cvm terminate --no-wait`, and `security-cvm update --no-wait` -- one helper (`style::operation_handle_confirm`) covers all six paths.

### 7.15 `umbra cvm terminate` / `stop` / `start` / `update`

**Status: VALIDATED**

- `cvm stop` and `cvm start` are synchronous on the Console (`console.md` section 8.3). Template: **confirm** (single-line).
- `cvm terminate` is async (saga). Template: **steps + confirm**, same shape as `cvm launch`.
- `cvm update` is async (saga). Template: **steps + confirm**, same shape as `cvm launch`.

Confirm header per action:

| Action | Header |
|---|---|
| stop | `[OK] stopped cvm <cvm.id>` |
| start | `[OK] started cvm <cvm.id>` |
| terminate | `[OK] terminated cvm <cvm.id>` |
| update | `[OK] updated cvm <cvm.id>` |

Multi-line detail for `update`: same fields as `launch`, plus `policy status`. The `policy status` value is `installed`, `unchanged`, or `replaced_after_confirmation`; `next step` is `umbra ssh <cvm.id>`. If the local policy file differs and the user does not confirm replacement, the command emits an error block instead of this success confirm.

Multi-line detail for `terminate`: `state  terminated` (single row). No next-step.

Single-line for `stop` / `start`: header only; the new state is implicit in the verb.

Example (`cvm stop`, success):

```
$ umbra cvm stop 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
[OK] stopped cvm 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
```

Example (`cvm terminate`, success):

```
$ umbra cvm terminate 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9

[1] Validate                          [0.2s]
[2] Configure Dns Cname               [0.4s]
[3] Configure Dns Txt                 [0.3s]
[4] Provision                         [8.1s]
[5] Soft Delete                       [0.1s]

[OK] terminated cvm 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
        state  terminated
```

Example (`cvm update`, success):

```
$ umbra cvm update 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9

[1] Provision                         [42.1s]
[2] Verify Attestation                [27.8s]
[3] Await Sc Pull                     [2.0s]
[4] Policy Push                       [0.1s]
[5] Finalise                          [0.1s]

[OK] updated cvm 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
        fqdn           cvm-aaaaaaaaaaaaaaaaaaaaaaaaaa.dev.example.com
        state          running
        policy file    /home/alice/.umbra/cvms/7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9.atls-policy.json
        policy status  replaced_after_confirmation
        next step      umbra ssh 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
```

### 7.16 `umbra profile create` / `configure` / `members add` / `members remove`

**Status: VALIDATED**

The real clap subcommands of `umbra profile` are: `create`, `list`, `show`, `configure`, `members`. There is no `update` (mutation is `configure`). There is no `delete`. The member sub-tree is `members` (plural, not singular), with sub-actions `members add` and `members remove`.

The profile id is selected via the global `--profile <PROFILE_ID>` flag, not as a positional argument. The profile `name` is the positional argument on `create`.

All synchronous. Template: **confirm**.

Headers and detail blocks per action:

| Action | Header | Detail rows |
|---|---|---|
| create | `[OK] created profile <name>` | `id`, `next step` -> `umbra profile members add <user-id> --profile <id>` |
| configure | `[OK] configured profile <name>` | `id`. Conditional `next step` -> `umbra cvm update <cvm-id>` when the Console response includes `requires_relaunch: true` (or equivalent flag indicating attached CVMs need to pick up the new policy). When the flag is absent or false, the `next step` row is omitted. |
| members add | `[OK] added user <email> to profile <name>` | `user id`, `profile id`, `next step` -> `umbra cvm launch --profile <profile-id> --ssh-key <key-id>` (the new member can now launch CVMs with this profile) |
| members remove | `[OK] removed user <email> from profile <name>` | (single-line, no detail) |

Examples:

```
$ umbra profile create permissive-dev
[OK] created profile permissive-dev
        id         2148e3a2-0097-4580-9be8-e64396eda8d9
        next step  umbra profile members add <user-id> --profile 2148e3a2-0097-4580-9be8-e64396eda8d9

$ umbra profile members add 28d76b77-a973-498d-a6a1-b9b58f298dbc --profile 2148e3a2-0097-4580-9be8-e64396eda8d9
[OK] added user alice@example.com to profile permissive-dev
        user id     28d76b77-a973-498d-a6a1-b9b58f298dbc
        profile id  2148e3a2-0097-4580-9be8-e64396eda8d9

$ umbra profile configure --profile 2148e3a2-0097-4580-9be8-e64396eda8d9 --policy ./policy.json
[OK] configured profile permissive-dev
        id  2148e3a2-0097-4580-9be8-e64396eda8d9
```

### 7.17 `umbra key add` / `remove`

**Status: VALIDATED**

Synchronous. Template: **confirm**.

| Action | Header | Detail rows |
|---|---|---|
| add | `[OK] added key <label>` | `id`, `fingerprint`, `algorithm` |
| remove | `[OK] removed key <key.id>` | (single-line, no detail) |

Examples:

```
$ umbra key add --label laptop --file ~/.ssh/id_ed25519.pub
[OK] added key laptop
        id           k-7f3a2b1c-1234-5678-9abc-def012345678
        fingerprint  SHA256:abc1234567890ABCDEFghijklmnopqrstuvwxyz12345
        algorithm    ed25519

$ umbra key remove k-7f3a2b1c-...
[OK] removed key k-7f3a2b1c-1234-5678-9abc-def012345678
```

### 7.18 `umbra auth login` / `logout` / `refresh`

**Status: VALIDATED**

- `auth login` is interactive (OIDC loopback or device flow). Template: **steps** for the polling phase, followed by **confirm** on success.
- `auth logout` and `auth refresh` are synchronous. Template: **confirm**.

`auth login` saga (CLI-side, no Console saga):

| Step | Description |
|---|---|
| `open_browser` | Opens the OIDC URL in the user's default browser |
| `await_callback` | Waits for the OIDC callback (loopback) or device-code polling |
| `exchange_tokens` | Exchanges authorization code for access + refresh tokens |
| `fetch_profile` | Fetches `/me` to populate session |

These step names are derived by the CLI (no Console source), so the CLI MAY hardcode the four labels here -- this is the one exception to the no-hardcode rule in section 6.3, because the saga lives CLI-side, not Console-side.

When `auth login --device` is used, the OIDC device-flow path emits a small set of interactive prompts on stderr (the verification URL, the user code, the optional completion URL, and an expiry-countdown notice) before the steps renderer takes over. These prompts are non-error, non-mutation, informational lines and MUST be routed through the Layer 2 helper `style::info_line(message: &str) -> String` so they obey the activation rules of section 3 (no ANSI when colors are off). The CLI MUST NOT emit them via raw `eprintln!` of an unstyled string.

Confirm block on `auth login` success:

```
[OK] signed in as alice@example.com
        entity      example-corp  (a1b2c3d4-1234-5678-9abc-def012345678)
        session     /home/alice/.umbra/session.json
        expires at  2026-06-04 09:00 UTC
```

`auth logout`:

```
[OK] signed out
        session  removed: /home/alice/.umbra/session.json
```

`auth refresh`:

```
[OK] refreshed session
        expires at  2026-06-04 09:00 UTC
```

Full example (`auth login`, success):

```
$ umbra auth login

[1] Open Browser                      [0.3s]
[2] Await Callback                    [12.4s]
[3] Exchange Tokens                   [0.5s]
[4] Fetch Profile                     [0.2s]

[OK] signed in as alice@example.com
        entity      example-corp  (a1b2c3d4-1234-5678-9abc-def012345678)
        session     /home/alice/.umbra/session.json
        expires at  2026-06-04 09:00 UTC
```

### 7.19 `umbra security-cvm launch` / `terminate` / `update`

**Status: VALIDATED**

Same shape as `cvm launch` / `terminate` / `update` (section 7.14, 7.15). The Console saga step names are different (per `console.md` section 8.4) but the spec applies the same syntactic transformation. The final confirm block fields:

- `launch`: `[OK] launched security cvm <sc.id>` with rows `fqdn`, `state`, `ca export token` (one-time secret displayed once -- per spec it MUST appear here and the user MUST be reminded that re-display is impossible), `next step` -> `umbra cvm launch --profile <profile-id> --ssh-key <key-id>` (operator can now launch Dev CVMs).
- `terminate`: `[OK] terminated security cvm <sc.id>` with row `state  terminated`. WARNING row added: `warning   any live Dev CVM in this entity will lose egress until the SC is re-launched`.
- `update`: `[OK] updated security cvm <sc.id>` with rows `fqdn`, `state`, `policy version`.

Example (`security-cvm launch`, success):

```
$ umbra security-cvm launch --region eu-west-3

[1] Validate                          [0.3s]
[2] Persist Stub                      [0.2s]
[3] Provision                         [62.4s]
[4] Configure Dns Txt                 [0.5s]
[5] Configure Dns Cname               [0.4s]
[6] Verify Attestation                [31.2s]
[7] Finalise                          [0.1s]

[OK] launched security cvm sc-aaaaaaaaaaaaaaaaaaaaaaaaaa
        fqdn              sc-aaaaaaaaaaaaaaaaaaaaaaaaaa.sc.example.com
        state             running
        ca export token   ca-Z2W3X4Y5Z6W7X8Y9Z0W1X2Y3Z4W5X6Y7Z8W9X0  (save now -- not recoverable)
        next step         umbra cvm launch --profile <profile-id> --ssh-key <key-id>
```

### 7.20 Universal error block

**Status: VALIDATED**

Template: error (section 6.5). Applies to all commands.

Single-line form is the baseline (matches existing CLI behavior in `cli.md` section 2.3). Multi-line form is used when the Console returns a structured error envelope (typed `code`, `details`, etc.) or when a request-id is available for correlation.

The bracket value follows the rule in section 6.5: for Console-sourced errors it is the typed `error.code` (e.g., `[NOT_FOUND]`, `[VALIDATION_ERROR]`, `[FORBIDDEN]`); for client-side errors it falls back to one of `[usage]` / `[auth_required]` / `[wait_timeout]` / `[error]` per the section 6.5 table. The previous `[error] <message> (CODE)` shape (with the code duplicated as a parenthesised suffix) is dropped.

Examples:

Single-line, client-side (no Console envelope):

```
$ umbra auth status
[auth_required] session expired - run umbra auth login
```

Single-line, Console envelope (typed code goes in the bracket):

```
$ umbra cvm update 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
[NOT_FOUND] cvm 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9 not found
```

Multi-line:

```
$ umbra cvm launch --profile production-strict --ssh-key laptop
[VALIDATION_ERROR] failed to launch CVM
        cause       profile production-strict requires ssh-key registration
        details     user alice@example.com has no key matching profile policy
        fix         umbra key add --label laptop --file ~/.ssh/id_ed25519.pub
        request-id  req-7f3a2b1c
```

The mapping from Console error envelope fields to template rows:

| Envelope field | Template row |
|---|---|
| `error.message` | header message |
| `error.code` (verbatim, uppercase) | header bracket value |
| `error.details` (one-line summary) | `details` |
| `error.cause` (when present) | `cause` |
| `error.fix` (when present) | `fix` |
| top-level `request_id` | `request-id` |

When the response is not a recognised Console envelope (network failure, malformed JSON, non-2xx with empty body), the bracket falls back to the client-side table in section 6.5, derived from the exit symbol the command would set.

### 7.21 `umbra auth status`

**Status: VALIDATED**

Template: multi-section card (section 6.1.1).

The command summarizes the current session state as loaded by `cli/src/commands/auth.rs::session_status` (the `StatusJson` struct fields drive the section composition).

Sections rendered, in order:

1. **User** -- `id` (UUID), `email`.
2. **Entity** -- `id` (UUID), `name`.
3. **Tokens** -- `access token` (state: `valid` + expiration timestamp, `expired` + expiration timestamp, or `missing`), `refresh token` (same state vocabulary).
4. **Config** -- `config dir` (path + source: `flag` / `env` / `file` / `default`), `console url` (value + source).
5. **Session file** -- `path` (absolute path to `session.json`), `permissions` (e.g., `0600`).

Domain dispatch:

- token `valid` -> `success` (green)
- token `expired` -> `warn` (yellow)
- token `missing` -> `error` (red)
- config `source` values: `flag` / `env` -> `info` (cyan); `file` -> normal; `default` -> `muted`

#### Empty / unauthenticated state

When no session is loaded (no `session.json` or it fails to parse): the renderer MUST emit a single line `no session` styled `muted()` -- no sections, no footer. The command's exit code is then driven by the caller (the auth_required error block, if any, is emitted by the error path, not this renderer).

Example (session present):

```
$ umbra auth status

> User
      id     28d76b77-a973-498d-a6a1-b9b58f298dbc
      email  alice@example.com

> Entity
      id    61b04bff-6378-430a-8236-4ed8bb2437ed
      name  Example Corp

> Tokens
      access token   valid    expires 2026-05-21 16:30 UTC
      refresh token  valid    expires 2026-06-04 09:00 UTC

> Config
      config dir   /home/alice/.umbra  (default)
      console url  https://console.example.com  (file)

> Session file
      path         /home/alice/.umbra/session.json
      permissions  0600
```

Example (no session):

```
$ umbra auth status
no session
```

### 7.22 `umbra profile show`

**Status: VALIDATED**

Template: single-section card (section 6.1).

Primary identifier (title line): the profile `name` (e.g., `> permissive-dev`), same convention as section 7.3 (`profile list`).

Fields rendered (same shape as section 7.3 with two additions for the detail view -- `description` and `policy`):

- name (in title)
- id (UUID)
- alias (the caller's local alias for this profile, or `-` when it has none, or `unreadable` when the store cannot be read) -- same row and same three-state `AliasCell` contract as section 7.3, so the list and detail views agree
- description (free-form string from the Profile struct, or `-` when null)
- assigned (caller's membership: `yes` / `no`)
- attached cvms (count on the first line, then the full list of CVM UUIDs on subsequent lines indented to the value column; bare UUIDs, no `ID ` prefix)
- policy (the full policy JSON, pretty-printed across multiple lines indented to the value column). Unlike section 7.3 (`profile list`), which intentionally omits `policy` to keep the list readable, the show command renders it because this is the detail view.
- created (formatted `YYYY-MM-DD HH:MM UTC`)
- updated (formatted `YYYY-MM-DD HH:MM UTC`)

Domain dispatch:

- `assigned`: `yes` -> `success` (green), `no` -> `muted` (gray)
- `alias`: as section 7.2 (plain for a name or `-`, `error` on the `unreadable` marker)

Example:

```
$ umbra profile show --profile 2148e3a2-0097-4580-9be8-e64396eda8d9

> permissive-dev
      id             2148e3a2-0097-4580-9be8-e64396eda8d9
      alias          dev
      description    Default developer profile -- broad egress, basic DLP
      assigned       yes
      attached cvms  2
                     7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
                     9e1f4d8a-2b3c-4d5e-6f7a-8b9c0d1e2f3a
      policy         {
                       "egress": {
                         "allow": ["github.com", "api.openai.com"],
                         "deny": []
                       },
                       "dlp": {
                         "rules": ["api_key", "jwt"]
                       }
                     }
      created        2026-05-14 10:00 UTC
      updated        2026-05-21 09:56 UTC
```

### 7.23 `umbra profile members list`

**Status: VALIDATED**

Template: card (section 6.1).

Lists members of a profile. The profile id is selected via the global `--profile <PROFILE_ID>` flag (required to scope the listing).

Primary identifier (title line): the member's `email`.

Filter context (always shown in `Filter:` header):

- `scope` -- the global `--profile <PROFILE_ID>` value, surfaced under the `scope` label (as in section 7.8, so the label never duplicates the value's noun). The header renders the resolved name when available: if the value equals `session.default_profile` and the session has the corresponding profile cached, render `profile <name> <UUID>`; otherwise render just `profile <UUID>`. Format: `<noun> <human-readable> <UUID>` with single spaces (same shape as section 7.8 scope resolution).

Fields rendered (per the `ProfileMember { user_id, email, added_at }` struct in `cli/src/commands/profile.rs`):

- email (in title)
- user id (UUID)
- added at (formatted per section 4.1)

Footer word: `members` / `member` (singular/plural per correction 9; see section 6.1 footer table).

Domain dispatch:

- none

Example:

```
$ umbra profile members list --profile 2148e3a2-0097-4580-9be8-e64396eda8d9

Filter:
  scope  profile permissive-dev 2148e3a2-0097-4580-9be8-e64396eda8d9

> alice@example.com
      user id   28d76b77-a973-498d-a6a1-b9b58f298dbc
      added at  2026-05-15 11:02 UTC

> bob@example.com
      user id   5965ae0b-5e30-42e4-bff2-4b45b00cadb9
      added at  2026-05-17 13:18 UTC

2 members
```

### 7.24 `umbra quota set` / `quota clear`

**Status: VALIDATED**

Mutation siblings of `quota get` (section 7.8). Synchronous. Template: **confirm** (section 6.4).

Per `cli.md` section 3.13, the synopsis is `quota set <RESOURCE> <LIMIT> [--entity <ENTITY_ID> | --user <USER_ID>]` and `quota clear <RESOURCE> [--entity <ENTITY_ID> | --user <USER_ID>]`. `<RESOURCE>` is positional and lowercase: for entity scope one of `dev_cvms`, `ssh_keys`, `users`, `profiles`; for user scope one of `dev_cvms`, `ssh_keys`. `<LIMIT>` on `set` is the second positional argument (an integer >= 0). The scope flags are mutually exclusive; when neither is provided, the default scope is the caller's session entity.

| Action | Header | Detail rows |
|---|---|---|
| set | `[OK] set quota <resource>` | `scope`, `limit`, `previous limit` (or `-` when no override existed), `set by`, `next step` -> `umbra quota get --<scope-flag> <id>` (omitted when the default session entity scope was used) |
| clear | `[OK] cleared quota <resource>` | `scope`, `previous limit`, `next step` -> `umbra quota get --<scope-flag> <id>` (omitted when the default session entity scope was used) |

The `scope` row value follows the same scope name resolution rule documented in section 7.8 (`<noun> <human-readable> <UUID>` when resolvable, fallback to `<noun> <UUID>`).

Examples:

```
$ umbra quota set dev_cvms 25
[OK] set quota dev_cvms
        scope           entity example-corp a1b2c3d4-1234-5678-9abc-def012345678
        limit           25
        previous limit  10
        set by          alice@example.com

$ umbra quota set ssh_keys 50 --user 28d76b77-a973-498d-a6a1-b9b58f298dbc
[OK] set quota ssh_keys
        scope           user alice@example.com 28d76b77-a973-498d-a6a1-b9b58f298dbc
        limit           50
        previous limit  -
        set by          alice@example.com
        next step       umbra quota get --user 28d76b77-a973-498d-a6a1-b9b58f298dbc

$ umbra quota clear dev_cvms
[OK] cleared quota dev_cvms
        scope           entity example-corp a1b2c3d4-1234-5678-9abc-def012345678
        previous limit  25

$ umbra quota clear ssh_keys --user 28d76b77-a973-498d-a6a1-b9b58f298dbc
[OK] cleared quota ssh_keys
        scope           user alice@example.com 28d76b77-a973-498d-a6a1-b9b58f298dbc
        previous limit  50
        next step       umbra quota get --user 28d76b77-a973-498d-a6a1-b9b58f298dbc
```

### 7.25 `umbra user add` / `deactivate` / `reactivate` / `erase`

**Status: VALIDATED**

Synchronous user-lifecycle mutations. Template: **confirm** (section 6.4). Mirrors the shape of section 7.17 (key add / remove): the identifier slot is the user's email when known (`add`, `deactivate`, `reactivate`), falling back to the user's UUID when the email is not available post-mutation (`erase`).

| Action | Header | Detail rows |
|---|---|---|
| add | `[OK] added user <email>` | `id`, `state` |
| deactivate | `[OK] deactivated user <email>` | `id`, `state` |
| reactivate | `[OK] reactivated user <email>` | `id`, `state` |
| erase | `[OK] erased user <user-id>` | (single-line, no detail) |

`erase` is irreversible and intentionally omits detail rows: the user record is deleted by the Console, so the CLI has no email to surface. The identifier slot uses the bare UUID. The corresponding wire status is `erased` (see `umbra user erase`).

Examples:

```
$ umbra user add alice@example.com
[OK] added user alice@example.com
        id     5965ae0b-5e30-42e4-bff2-4b45b00cadb9
        state  pending

$ umbra user deactivate 5965ae0b-5e30-42e4-bff2-4b45b00cadb9
[OK] deactivated user alice@example.com
        id     5965ae0b-5e30-42e4-bff2-4b45b00cadb9
        state  deactivated

$ umbra user reactivate 5965ae0b-5e30-42e4-bff2-4b45b00cadb9
[OK] reactivated user alice@example.com
        id     5965ae0b-5e30-42e4-bff2-4b45b00cadb9
        state  active

$ umbra user erase 5965ae0b-5e30-42e4-bff2-4b45b00cadb9
[OK] erased user 5965ae0b-5e30-42e4-bff2-4b45b00cadb9
```

### 7.26 `umbra audit export`

**Status: VALIDATED**

The `audit export` command submits a long-running export operation and, by default, blocks until the Console returns the export artifact (download URL, sha256, row count, byte size). Template: **confirm** (section 6.4) on success; **operation handle confirm** (section 12.4) on `--no-wait` and on `wait_timeout`.

| Mode | Renderer | Header | Detail rows |
|---|---|---|---|
| default (wait) | `style::render_confirm` | `[OK] exported audit events` | `download url`, `sha256`, `rows`, `bytes`, optional `path` (set only when `--output <FILE>` was passed and the local download succeeded) |
| `--no-wait` | `style::operation_handle_confirm` | `[OK] submitted audit.export <operation-id>` (verb / noun chosen by the helper from the saga kind) | `operation`, `target type`, `status` |
| `wait_timeout` | `style::operation_handle_confirm` (printed on stderr) | same as `--no-wait` | same as `--no-wait` |

Row order in the synchronous success block: `download url`, `sha256`, `rows`, `bytes`, `path`. `path` is conditional and appears last.

Examples:

```
$ umbra audit export --format csv --output ./audit.csv
[OK] exported audit events
        download url  https://console.example/api/v1/audit/export/abcd.csv
        sha256        9c1b5f8a...
        rows          12483
        bytes         482911
        path          ./audit.csv

$ umbra audit export --format ndjson
[OK] exported audit events
        download url  https://console.example/api/v1/audit/export/efgh.ndjson
        sha256        a4d3...
        rows          12483
        bytes         610228

$ umbra audit export --format csv --no-wait
[OK] submitted audit.export op-7f3a2b1c-1234-5678-9abc-def012345678
        operation    op-7f3a2b1c-1234-5678-9abc-def012345678
        target type  audit_export
        status       pending
```

### 7.27 `umbra user show`

**Status: VALIDATED**

Template: card (single-section, section 6.1). Renderer: `style::user_show_card`.

Title: `> <email>` (the user's primary identifier, matching the section 7.25 mutation confirms).

Fields rendered, in order:

- `id` -- user UUID
- `name` -- display name
- `entity` -- `<entity-id> <entity-name>` (id raw, name muted)
- `state` -- `active` / `disabled` / `deleted`; domain-dispatched via `user_state`
- `permissions` -- comma-separated list, wrapped per section 6.1; `-` when empty
- `profiles` -- comma-separated `<profile-id> <profile-name>` pairs, wrapped per section 6.1; `-` when empty
- `last login` -- formatted timestamp; `-` when null
- `deactivated` -- formatted timestamp; `-` when null
- `created` -- formatted timestamp
- `deleted` -- formatted timestamp; `-` when null

Unknown wire fields (`extra`) appear at the bottom per section 11.7.

Example:

```
$ umbra user show 5965ae0b-5e30-42e4-bff2-4b45b00cadb9

> alice@example.com
      id           5965ae0b-5e30-42e4-bff2-4b45b00cadb9
      name         Alice
      entity       61b04bff-6378-430a-8236-4ed8bb2437ed Example Corp
      state        active
      permissions  USER_ADMIN, CVM_LAUNCH
      profiles     7f3a2b1c-1234-5678-9abc-def012345678 permissive-dev
      last login   2026-05-21 14:23 UTC
      deactivated  -
      created      2026-05-18 15:38 UTC
      deleted      -
```

### 7.28 `umbra reconcile`

**Status: VALIDATED**

Template: confirm (section 6.4) via `style::render_confirm`.

Header verb / noun: `[OK] reconciled run <identifier>`. The identifier is a short synthetic summary of the run (either `<N> actions` when the saga advanced at least one record, `no advances` when invoked with `--no-orphans` and the result is empty, or `no advances or orphans` otherwise).

Detail rows render the three per-bucket counters returned by the Console reconcile endpoint:

- `cvms advanced` -- `<count> ids=<id1,id2,...>` (or `-` when the list is empty)
- `security cvms advanced` -- same format
- `orphans cleaned` -- same format

Example:

```
$ umbra reconcile
[OK] reconciled run 2 actions
        cvms advanced           1 ids=10103f98-fe7b-4299-b14c-82e313de209f
        security cvms advanced  1 ids=3a1bb45c-1111-4111-8111-111111111111
        orphans cleaned         0 ids=-
```

### 7.29 `umbra user permissions list / grant / revoke`

**Status: VALIDATED**

Template -- list: compact one-line listing via `style::user_permissions_list`. Each granted permission is rendered on its own line, styled with `info()` (cyan). Empty state is the canonical `no permissions` muted line. Footer follows section 6.1 (`<n> permissions`).

Template -- grant / revoke: confirm (section 6.4) via `style::render_confirm`. The mutation's primary identifier is the user UUID; the detail row carries the comma-separated list of permissions affected by the request.

| Verb | Header |
|---|---|
| grant | `[OK] granted permission <user-id>` |
| revoke | `[OK] revoked permission <user-id>` |

Detail row (both): `permissions <comma-separated list>`. The list comes from `permissions_join` so an empty list renders as `-`.

Examples:

```
$ umbra user permissions list 5965ae0b-5e30-42e4-bff2-4b45b00cadb9
USER_ADMIN
CVM_LAUNCH

2 permissions

$ umbra user permissions grant 5965ae0b-5e30-42e4-bff2-4b45b00cadb9 SECURITY_CVM_CONFIGURE
[OK] granted permission 5965ae0b-5e30-42e4-bff2-4b45b00cadb9
        permissions  USER_ADMIN,CVM_LAUNCH,SECURITY_CVM_CONFIGURE

$ umbra user permissions revoke 5965ae0b-5e30-42e4-bff2-4b45b00cadb9 CVM_LAUNCH
[OK] revoked permission 5965ae0b-5e30-42e4-bff2-4b45b00cadb9
        permissions  CVM_LAUNCH
```

### 7.30 `umbra kill`

**Status: VALIDATED**

Template: confirm (section 6.4) via `style::render_confirm`.

Header: `[OK] killed session <session-name>`. Detail row records the CVM the session was running on (so the operator can disambiguate when several CVMs share session names).

Example:

```
$ umbra kill build-1
[OK] killed session build-1
        cvm  10103f98-fe7b-4299-b14c-82e313de209f
```

### 7.31 `umbra alias`

**Status: VALIDATED**

Template: confirm (section 6.4) via `style::render_confirm`.

Header: `[OK] aliased session <alias>`. The primary identifier is the new alias label (the entity being created); detail rows record the underlying session name and the CVM the alias is scoped to.

Example:

```
$ umbra alias build dev
[OK] aliased session dev
        session  build
        cvm      10103f98-fe7b-4299-b14c-82e313de209f
```

### 7.32 `umbra security-cvm attestation`

**Status: VALIDATED**

Template: card (single-section, section 6.1). Renderer: `style::security_cvm_attestation_card`.

Title: `> Security CVM Attestation`.

Fields rendered, in order:

- `security cvm` -- SC UUID (raw, not styled)
- `fqdn` -- SC FQDN, rendered with `value()`
- `verified` -- `yes` (success) / `no` (error) per the verdict boolean
- `failure reason` -- only rendered when the verdict carries a non-empty failure reason; styled `error_style`, sanitised
- `expected image` -- expected RTMR3 image measurement digest, `-` when null
- `image seen` -- digest the prover observed on the live CVM, `-` when null
- `rtmr3 seen` -- raw RTMR3 digest, `-` when null
- `verified at` -- formatted timestamp, `-` when null

Example (verified):

```
$ umbra security-cvm attestation 3a1bb45c-1111-4111-8111-111111111111

> Security CVM Attestation
      security cvm    3a1bb45c-1111-4111-8111-111111111111
      fqdn            sc-aaaaaaaaaaaaaaaaaaaaaaaaaa.sc.example.com
      verified        yes
      expected image  a4d3...
      image seen      a4d3...
      rtmr3 seen      f0e1...
      verified at     2026-05-21 14:23 UTC
```

Example (failed):

```
> Security CVM Attestation
      security cvm    3a1bb45c-1111-4111-8111-111111111111
      fqdn            sc-aaaaaaaaaaaaaaaaaaaaaaaaaa.sc.example.com
      verified        no
      failure reason  image measurement mismatch
      expected image  a4d3...
      image seen      b9c7...
      rtmr3 seen      f0e1...
      verified at     2026-05-21 14:25 UTC
```

### 7.33 `umbra code` / `cursor` / `claude` / `codex`

**Status: VALIDATED (no renderer)**

Session passthrough commands. There is no human-readable renderer: the CLI transparently invokes a remote shell on the selected Dev CVM (over the aTLS-tunnelled SSH transport) and streams the agent's stdout/stderr back to the local terminal byte-for-byte. The CLI does not interpose any formatting; the agent's own output is the user-facing surface.

Per section 12.8, errors raised before the remote shell is reached (resolution, ssh launch, etc.) still go through `style::eprintln_error`, but no card / table / confirm renderer applies to the steady-state interactive flow.

### 7.34 `umbra cvm instance-types`

**Status: VALIDATED**

Template: table (section 6.2) via `style::instance_types_table`, plus an auxiliary stderr freshness note via `style::catalog_note`.

Columns: `NAME / FAMILY / VCPU / MEMORY / NOTES`.

The provider `hourly_rate` / `currency` are deliberately NOT rendered in the table (Phala's provider cost is not surfaced to CLI users); they remain in the `--json` payload (§3.1, and the `cli.md` §7.34 whitelist) for scripts.

Fields and domain dispatch:

- `NAME` -> `value()` (bold; this is the copy-paste-into-`--instance-type` field). Console-controlled, passed through the section 4 ASCII sanitiser.
- `FAMILY`, `VCPU`, `MEMORY` -> bare text; a null descriptive field renders as `-`. Memory renders as `<n> GB` (integer when whole).
- `NOTES` -> `muted()`. Composed values, comma-joined: `default` (the entry the Console flags as the Dev CVM server default) and `not supported yet` (every entry the Console marks `launchable: false` -- currently GPU families, catalogued and listed but not launchable yet). The CLI reads the Console `launchable` flag rather than re-deriving the rule from `family`.
- footer: `N instance types` per section 6.1; empty state `no instance types`.

#### Freshness note (stderr)

`style::catalog_note` renders a single muted stderr line from the response's `catalog` metadata (`source`, `fetched_at`, `stale`, `refresh_in_progress`, `last_refresh_error.kind`) plus whether `--refresh` was requested. It returns nothing for a fresh provider catalog (including after a successful `--refresh`) -- the note appears ONLY when the catalog needs explaining:

- `--refresh` failed: `refresh failed (<cause>); showing cached list from <ts>` (or `built-in list`).
- bootstrap fallback: `built-in bootstrap catalog; phala has never been reached (<cause>) -- <action>`; when no failure has been recorded yet (virgin boot, first fetch still pending) the `(<cause>)` parenthetical is omitted.
- stale cache: `catalog is stale (cached list from <ts>; <cause> at last refresh); <action>`.

`<action>` is `background refresh in progress` when one is running, else `use --refresh to fetch now` -- so the note never circularly advises the `--refresh` the user just ran while its single-flight skip is still in flight.

`<cause>` maps `provider_unreachable` -> `phala unreachable` and `schema_drift` -> `phala response could not be parsed (schema change?)`; any unknown future kind is passed through the section 4 sanitiser verbatim. Timestamps render through `format_timestamp` (`YYYY-MM-DD HH:MM UTC`). In `--json` mode no note is emitted (the metadata is already in the payload, section 3.1).

Separately, when the Console response carries fields this CLI build does not model (Console/CLI version skew, detected via the captured `extra` bags per section 11.7), a second muted stderr note is emitted before the freshness note: `note: the Console returned unrecognized fields; this CLI may be out of date`. Also suppressed in `--json` mode. For each `(field, count)` in the response's `catalog.field_miss_counts` (Console-side provider-schema drift: an expected provider field that failed to parse on `count` of the N entries), the CLI renders a muted `catalog parse warning: expected field '<field>' missing or invalid on <count> of <N> instance types` line on stderr (the field name passes the section 4 sanitiser; the wording lives in the CLI, the wire carries only the machine counts). An empty map emits nothing, and `--json` carries `field_miss_counts` in the payload for scripts to assert empty.

Example:

```
$ umbra cvm instance-types

NAME          FAMILY VCPU MEMORY  NOTES
tdx.small     cpu    1    2 GB    default
tdx.medium    cpu    2    4 GB
tdx.large     cpu    4    8 GB
tdx.xlarge    cpu    8    16 GB
tdx.2xlarge   cpu    16   32 GB
tdx.4xlarge   cpu    32   64 GB
tdx.8xlarge   cpu    64   128 GB
h200.small    gpu    24   192 GB  not supported yet
h200.16xlarge gpu    64   256 GB  not supported yet
h200.8x.large gpu    192  1536 GB not supported yet

10 instance types
```

Stale-cache example (stderr note after the table):

```
catalog is stale (cached list from 2026-07-01 09:14 UTC; phala unreachable at last refresh); use --refresh to fetch now
```

### 7.35 `umbra update` + passive update notice

**Status: VALIDATED**

Local mutation (no Console call). Template: confirm (section 6.4) on every terminal outcome; error (section 6.5) on failure. The version strings shown in the identifier and fields are CLI-compiled (`CARGO_PKG_VERSION`) or validated against the strict version grammar before rendering, so nothing the install service returns reaches a renderer unvalidated.

Confirm shapes:

- installed: header `[OK] updated umbra <old> -> <new>`, fields `path` (the replaced executable) and `target` (build target triple).
- already current: header `[OK] up to date: umbra <version>`, no fields.
- local build newer than the channel: header `[OK] ahead of latest release: umbra <version>`, fields `latest published` and a `note` naming `--force`.
- `--check` with an update available: header `[OK] update available: umbra <latest>`, field `installed`, and `next step` = `umbra update` (info, cyan).

Example:

```
$ umbra update

[OK] updated umbra 0.3.0-beta.3 -> 0.4.0
        path    /home/alice/.local/bin/umbra
        target  x86_64-unknown-linux-gnu
```

**Passive update notice.** Auxiliary stderr line (same class as the section 6.1 pagination note), emitted by eligible commands after their payload when the cached probe shows a newer published release. Rendered through `style::update_notice(current: &str, latest: &str) -> String`, styled `muted()`, one line, no `[OK]` prefix:

```
update available: umbra 0.4.0 (installed 0.3.0-beta.3) -- run `umbra update`
```

The latest-version string is install-service-controlled and passes through the section 4 ASCII sanitiser. The helper does not emit the line itself (the caller owns the `eprintln!`), and the notice never appears when stderr is not a terminal, in `update` / `completions` / `tunnel` invocations, or when the user opted out (`no_update_check`, `docs/specs/cli.md` section 4.1).

## 8. Implementation contract

Files to touch (relative to repo root):

- `cli/Cargo.toml` -- add direct dependency `anstyle = "1"` (currently transitive via clap). `chrono` is already declared (used for session expiration handling); no addition needed for the timestamp formatting of section 4.1.
- `cli/src/style.rs` -- new module; primitives (section 5) plus one renderer per validated entry in section 7. The implementation MAY also expose a `Display`-returning variant for use inside `format!`.
- `cli/src/lib.rs` -- declare `mod style;` and call `style::init(...)` once after `ResolvedConfig` resolution, with the three conditions of section 3.2.
- `cli/src/commands/<file>.rs` -- for each command listed in section 7, replace ad-hoc `format!` / `println!` rendering with a call to the matching Layer 2 renderer. Call sites MUST NOT contain ANSI codes or color helpers; the renderer is the only entry point.

#### Layer 2 renderer catalog (one row per section 7 entry)

| Section 7 entry | Renderer (suggested name) | Template | FilterContext fields |
|---|---|---|---|
| 7.1 user list | `style::user_list_cards` | card | `status`, `assigned` |
| 7.2 cvm list | `style::cvm_list_cards` | card | `profile`, `state` |
| 7.3 profile list | `style::profile_list_cards` | card | `assigned` |
| 7.4 key list | `style::key_list_cards` | card | (none) |
| 7.5 audit events | `style::audit_events_cards` | card | `actor`, `action`, `target_type`, `target_id`, `from`, `to`, `limit`, `cursor` |
| 7.6 traffic-logs | `style::traffic_logs_table` | table | `cvm`, `security_cvm`, `from`, `to`, `limit`, `cursor` |
| 7.7 entity list | `style::entity_list_cards` | card | (none) |
| 7.8 quota get | `style::quota_get_cards` | card | `entity_id`, `user_id` |
| 7.9 ps | `style::ps_cards` | card | `cvm` (always set) |
| 7.10 status | `style::status_multi_section` | multi-section card (3-column variant for Session/Profiles/SSH Keys) | (none) |
| 7.11 config show | `style::config_show_table` | table | (none) |
| 7.12 version | `style::version_card` | card (single section) | (none) |
| 7.13 security-cvm show | `style::security_cvm_card` | card (single section) | (none) |
| 7.14 cvm launch | `style::StepsRenderer` + `style::render_confirm` (default); `style::operation_handle_confirm` (`--no-wait`) | steps + confirm | (none) |
| 7.15 cvm stop/start/terminate/update | `style::render_confirm` (+ `style::StepsRenderer` for terminate/update); `style::operation_handle_confirm` for `--no-wait` paths | confirm (+ steps) | (none) |
| 7.16 profile mutations (create/configure/members add/members remove) | `style::render_confirm` | confirm | (none) |
| 7.17 key add/remove | `style::render_confirm` | confirm | (none) |
| 7.18 auth login/logout/refresh | `style::StepsRenderer` (login) + `style::render_confirm`; `style::info_line` for the device-flow prompts | steps + confirm / confirm | (none) |
| 7.19 security-cvm launch/terminate/update | `style::StepsRenderer` + `style::render_confirm` (default); `style::operation_handle_confirm` (`--no-wait`) | steps + confirm | (none) |
| 7.20 universal error | `style::render_error` | error | (none) |
| 7.21 auth status | `style::auth_status_card` | multi-section card | (none) |
| 7.22 profile show | `style::profile_show_card` | card (single section) | (none) |
| 7.23 profile members list | `style::profile_members_list_cards` | card | `profile` (always set) |
| 7.24 quota set / quota clear | `style::quota_set_confirm` / `style::quota_clear_confirm` (thin wrappers around `render_confirm`) | confirm | (none) |
| 7.25 user add / deactivate / reactivate / erase | `style::render_confirm` | confirm | (none) |
| 7.26 audit export | `style::render_confirm` (synchronous success) + `style::operation_handle_confirm` (`--no-wait`, `wait_timeout`) | confirm | (none) |
| 7.27 user show | `style::user_show_card` | card (single section) | (none) |
| 7.28 reconcile | `style::render_confirm` | confirm | (none) |
| 7.29 user permissions list/grant/revoke | `style::user_permissions_list` (list) + `style::render_confirm` (grant/revoke) | list + confirm | (none) |
| 7.30 kill | `style::render_confirm` | confirm | (none) |
| 7.31 alias | `style::render_confirm` | confirm | (none) |
| 7.32 security-cvm attestation | `style::security_cvm_attestation_card` | card (single section) | (none) |
| 7.33 code / cursor / claude / codex | (session passthrough; no renderer) | n/a | (none) |
| 7.34 cvm instance-types | `style::instance_types_table` + `style::catalog_note` (stderr freshness note) | table | (none) |
| 7.35 update (+ passive notice) | `style::render_confirm`; `style::update_notice` for the stderr notice | confirm | (none) |

Auxiliary helper: `style::next_cursor_diagnostic(cursor: &str) -> String`. Used by every list / events / logs command that exposes pagination (sections 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.23). The caller emits the rendered line on stderr immediately after the list body when the wire response's `next_cursor` is non-null. The helper applies `muted()` styling and runs the cursor token through the section 4 ASCII sanitiser; it does NOT emit the line itself (the caller owns the `eprintln!`).

Renderer names are suggestions; implementations MAY use a different naming convention as long as section 7 -> renderer mapping stays unambiguous.

#### Struct change required by section 11.7

To honor the forward-compatibility rule in section 11.7, every CLI struct backing a Layer 2 renderer MUST gain a catch-all field for unknown wire fields. Specifically:

- `cli/src/commands/cvm.rs` -- add `#[serde(flatten, default, skip_serializing)] extra: BTreeMap<String, serde_json::Value>` to `Cvm`.
- `cli/src/commands/user.rs` -- add to `User` (the struct backing `umbra user list`). Note: `cli/src/commands/auth.rs::Me` reads `/me` for the auth flow but is not a renderable list-row struct; it does not need an `extra` field.
- `cli/src/commands/profile.rs` -- add to `Profile`.
- `cli/src/commands/key.rs` -- add to `ConsoleSshKey` (or to `SshKeyOutput` if the wire struct is preferred to stay slim).
- `cli/src/commands/audit.rs` -- add to `AuditEvent`.
- `cli/src/commands/traffic_logs.rs` -- add to `TrafficLog`.
- `cli/src/commands/entity.rs` -- add to `Entity`.
- `cli/src/commands/quota.rs` -- add to `Quota`.
- `cli/src/commands/security_cvm.rs` -- add to `SecurityCvm`.
- `cli/src/session.rs` -- if the session-status renderer reads `User` / `Entity` from the session, add it there too.

The `extra` field MUST be `BTreeMap` (alphabetical, deterministic) per section 11.7. The renderer iterates it at the bottom of each card.

Rollout MAY proceed command by command in separate commits. Each commit MUST update both `cli/src/style.rs` (renderer added), the matching struct (`extra` field added), and the command file (call site swapped).

#### Error path sweep

The implementing agent MUST replace every ad-hoc `eprintln!("[<symbol>] ...")` call and every direct print of a Console error envelope JSON with a call to `style::render_error(&ErrorBlock { ... })` (section 12.3 / 12.4). This guarantees that section 6.5 (error template) is the single rendering point for all stderr errors.

Grep patterns to run from the repo root:

```bash
grep -rn 'eprintln!.*\[error\]' cli/src/
grep -rn 'eprintln!.*\[auth_required\]' cli/src/
grep -rn 'eprintln!.*\[wait_timeout\]' cli/src/
grep -rn 'eprintln!.*\[usage\]' cli/src/
```

In addition, audit any code path that takes the Console JSON error envelope (typed `code`, `message`, `details`, `cause`, `fix`, `request_id`) and prints it as-is. Every such site MUST be re-routed through `style::render_error`.

For each hit:

1. Parse the existing message into its `<symbol>` and `<message>` parts.
2. Construct an `ErrorBlock` with the parsed symbol and message, plus any structured envelope fields available at that call site (cause, details, fix, request-id).
3. Replace the `eprintln!` (or JSON dump) with `eprintln!("{}", style::render_error(&block))`.

The `cli/src/commands/auth.rs::session_status` helper and any other error-emitting helper that currently builds a `[<symbol>] <message>` string SHOULD be refactored into a single helper that returns an `ErrorBlock`. The single helper then routes through `style::render_error`. This concentrates the symbol-to-message mapping in one place and removes the per-call-site duplication that the current code base shows.

## 9. Acceptance criteria

For each command rolled out:

1. `cargo build -p umbra-cli` passes.
2. `cargo clippy -p umbra-cli --all-targets -- -D warnings` passes.
3. `cargo fmt --check` passes.
4. `cargo test -p umbra-cli` passes (existing tests adjusted only where the legacy plain-text output was asserted byte-for-byte).
5. The command produces colored output when run interactively on a TTY without `--no-color`.
6. The command produces uncolored ASCII output when run with `--no-color`, with `NO_COLOR=1`, with `UMBRA_NO_COLOR=1`, or piped (e.g., `cmd | cat`).
7. The command produces byte-identical JSON to today when run with `--json`.
8. On non-zero exit, stdout remains empty (no partial card, no truncated JSON).
9. Empty state renders as `no <records>` per the footer-word table in section 6.1.
10. For commands with filters (cvm list, audit events, traffic-logs, quota list, ps, ...): the filter dedup rule (section 6.2.1) is honored -- filtered fields appear in the `Filter:` header and NOT in each card / table row.
11. For mutation commands using the steps template (section 6.3): on a TTY, the elapsed value of the current step updates at least once per second; on a non-TTY, each step prints once on completion. No flicker, no double-printed lines.
12. For multi-section commands (`status`): each section computes its label alignment independently.
13. For every renderable struct: when the Console response includes a field the struct does not declare, the unknown field appears at the bottom of the card with default styling (section 11.7).

## 10. Open questions / future work

- Spinners (`indicatif`), bordered tables, and themes are out of scope here and will require a follow-up revision.
- A potential `caller_permissions` field on `Cvm` records (to display "your access" per CVM) is rejected for v0 to keep code changes minimal.
- A `umbra debug schema <entity>` command to list rendered vs non-rendered fields per entity is under consideration. See section 11.6 for the rationale.
- Console-side enrichment of the Operation envelope to expose the full saga step list and per-step timestamps (so the CLI no longer measures durations itself) -- nice-to-have, would simplify section 6.3. Not blocking v0.
- A stderr INFO log when an unknown field is encountered (section 11.7) -- deferred.

## 11. Maintenance / Evolution

When a Console-side data model changes, the following rules MUST be honored to keep the spec, the renderer, and the wire shape aligned.

### 11.1 Adding a field to a struct

When a new field is added to a CLI struct (`Cvm`, `User`, `Profile`, etc.):

1. The field is auto-exposed in `--json` output via serde. No action needed for the JSON contract.
2. To make the field appear in the human-readable view, the PR MUST update both:
   - the Layer 2 renderer in `cli/src/style.rs`
   - the matching subsection of section 7 (fields rendered, color rules, value column position)
3. If the field is intentionally NOT user-facing, the PR MUST add an explicit note to the section 7 subsection: `<field-name>: --json only, not user-facing because <reason>`.

A field added to a struct without either being rendered or being documented as JSON-only is a spec violation.

#### Default styling for new fields

A new field added to a card MUST inherit the default styling unless the PR explicitly opts in to a semantic style:

| Aspect | Default | Opt-in trigger |
|---|---|---|
| Label color | `label()` (dim / faint) | none -- always default |
| Value color | bare text, no color, no weight | declare a domain dispatch in section 7 (e.g., `state: running -> success, ...`) |
| Value weight | normal | mark the field as `value()` in section 7 (used for primary identifiers like `fqdn`, `email`, `name`) |
| Position in card | end of card, before timestamps | choose another position in section 7 |
| Multi-line wrap | continuation indented to the value column | none -- always default |
| Null / empty rendering | literal `-` | one, normative: an `alias` cell whose STORE could not be read renders `unreadable`, not `-` (sections 7.2/7.3/7.4/7.9/7.22). `-` states "this record has no alias", which would be a false claim; the distinction is the whole point of the exception |

This means a purely informational new field (e.g., `network_interface`) requires only that section 7 list the field name; no color rule needs to be added. Only fields that carry state-like or identifier semantics require explicit styling.

### 11.2 Removing a field

When a field is removed from a struct:

1. The Rust compiler rejects any renderer still referencing it. This is the primary safeguard.
2. The PR MUST drop the field from the Layer 2 renderer and from the section 7 entry.
3. The PR body MUST mention the removal so JSON consumers are aware (the field disappears from `--json` too).

### 11.3 Renaming a field

Treated as remove + add. Both sides of section 7 plus the renderer plus the struct MUST be updated atomically.

### 11.4 Adding a new state value (domain dispatch)

When a new enum-like value appears (e.g., a new CVM state `migrating`):

1. The dispatch table in the relevant section 7 subsection MUST be updated with the chosen color (`success`, `warn`, `error`, `muted`, or `info`).
2. Unrecognized values at runtime MUST be rendered with `muted()` (gray) as a fallback. This makes drift visible (the value will look "different" from known values) without causing a crash or a misleading color.

### 11.5 Reviewer checklist

Reviewers SHOULD verify, for any PR that touches a struct under `cli/src/commands/*.rs`:

- every field added is either rendered (with a section 7 update) or documented as `--json only`
- every field removed is dropped from both the renderer and section 7
- every new state value has a dispatch entry in section 7

### 11.6 Debug tooling (proposed, not yet implemented)

A hidden command `umbra debug schema <entity>` MAY be introduced to surface, for the requested entity, the list of fields exposed in `--json`, the subset rendered in the human-readable view, and the dispatch tables in effect. This command is a maintenance tool and MUST NOT appear in the default `umbra --help` output.

### 11.7 Forward compatibility: unknown fields

When the Console returns a field that the CLI struct does not declare (e.g., a new field added server-side before the CLI is updated), the field MUST be captured and surfaced in the **human-readable** output only. Forward compatibility never extends to `--json`.

Two output paths, two contracts:

- **Human path (Layer 2 renderers).** Forward-compatible. The unknown field is captured into the wire struct's `extra` bag, rendered alphabetically at the bottom of the card. Operators see new Console fields as soon as the Console emits them, with no CLI release required.
- **`--json` path.** Strict whitelist. ONLY fields the CLI struct explicitly declares are emitted. The `extra` bag is captured on deserialize but is `skip_serializing` on the wire struct, so a future Console-side sensitive field would NOT leak through `--json` until the CLI is updated to declare and review it.

Implementation requirement:

- Every CLI struct that backs a Layer 2 renderer MUST declare `#[serde(flatten, default, skip_serializing)] extra: BTreeMap<String, serde_json::Value>` (or equivalent) to capture unknown fields on deserialize while excluding them from serialize.
- The renderer MUST iterate `extra` AFTER all known fields and AFTER any timestamp rows, at the very bottom of the card.
- **Table renderers (section 6.2).** A table has no per-record bottom row to surface unknown fields, so a table-backing struct still carries the `extra` bag (unknown fields are captured, never silently dropped) but surfaces them as a single aggregate muted stderr note ("the Console returned unrecognized fields; this CLI may be out of date") rather than per-row. This keeps drift detectable without a per-row rendering. `umbra cvm instance-types` (section 7.34) uses this form.
- The card's `max_label_width` (section 6.1) MUST be computed AFTER expanding unknown field labels, so all values -- known and unknown -- align to the same value column. Adding a long unknown label (e.g., `network_interface` -> 17 chars) shifts the alignment of every existing field in that card. This is intentional: the card stays visually coherent.

Rendering conventions for an unknown field:

| Aspect | Rule |
|---|---|
| Label | convert the JSON key from `snake_case` to lowercased space-separated words. Example: `network_interface` -> `network interface`. **Note:** this differs from the step-name transformation in section 6.3 (which Title-Cases each word, e.g., `phala_deploy` -> `Phala Deploy`). The two transformations are intentionally different: step names are titles that visually anchor a line, whereas unknown field labels mimic the regular field labels that are always lowercase. |
| Value (string) | render verbatim |
| Value (number, boolean) | render the display form (`42`, `true`) |
| Value (object, array) | serialize with the compact JSON form (e.g., `{"foo":1}`, `["a","b"]`) |
| Style | default per section 11.1 (label `label()`, value bare text) |
| Visual marker | none -- no `(new)` suffix, no special color. The card stays clean. |

Iteration order MUST be deterministic. `BTreeMap` (alphabetical by key) is preferred over `HashMap` (random) so that successive runs of the same command produce the same byte sequence.

**Note on the verbose flags.** The CLI verbose flags `-v` / `-vv` / `-vvv` defined in `cli.md` section 2.2 govern **stderr log verbosity only**. They do NOT change the structure or content of the human-readable output governed by this spec. Section 7 (plus the unknown-field rule above) is the sole source of truth for what appears on stdout in human mode. To see additional fields beyond what section 7 documents, render the human output (which surfaces unknown fields automatically) or use the planned `umbra <entity> show <id>` detail command. `--json` only emits the fields the CLI struct explicitly declares; it does NOT round-trip unknown fields.

A future revision MAY add an optional stderr INFO log when an unknown field is encountered, so that running with `-v` surfaces the diagnostic. Until then, unknown fields appear only in the rendered human card.

Example -- the Console adds two new fields `network_interface` and `vlan_id` to the Cvm record without a CLI release:

```
$ umbra cvm list

> ID 7a3b2c4d-5e30-42e4-bff2-4b45b00cadb9
      alias              prod-box
      state              running
      fqdn               cvm-aaaaaaaaaaaaaaaaaaaaaaaaaa.dev.example.com
      instance type      tdx.cpx41
      region             eu-west-3
      profiles           permissive-dev
      ssh keys           laptop
      owner              alice@example.com
      created            2026-05-18 15:38 UTC
      updated            2026-05-21 14:23 UTC
      network interface  eth0
      vlan id            42

1 cvm
```

The two unknown fields appear at the bottom in alphabetical order, with default styling (label dim, value bare). No code change required for the values to surface in the human card. Note: the same two fields would NOT appear in `umbra cvm list --json` -- the `--json` payload is restricted to the fields the CLI struct explicitly declares, by design (see "Two output paths, two contracts" above).

## 12. Implementation skeleton

This section is normative for API shape and advisory for internals. It exists so that an implementing agent can write the module in one shot without re-deriving design choices already implicit in sections 1-11.

### 12.1 Module layout

`cli/src/style.rs` is one file. Internally it MAY be split into:

- a private `primitives` block (Layer 1 helpers from section 5)
- a public set of renderer fns (Layer 2 per section 7)
- a public `StepsRenderer` struct (section 12.4)
- public `ErrorBlock` and `ConfirmBlock` value types

### 12.2 Primitives signatures

```rust
// Layer 1 -- private to the module
pub fn init(enabled: bool);
fn label(s: impl Display) -> String;
fn value(s: impl Display) -> String;
fn muted(s: impl Display) -> String;
fn success(s: impl Display) -> String;
fn error_style(s: impl Display) -> String;
fn warn(s: impl Display) -> String;
fn info(s: impl Display) -> String;
fn header(s: impl Display) -> String;
fn bullet() -> &'static str;
```

When the color toggle is OFF, every primitive returns its argument as a plain `String` with no ANSI sequences.

### 12.3 Renderer signatures

All non-streaming renderers return `String`. The command code is responsible for emitting the string (typically `println!("{}", style::cvm_list_cards(&cvms, &filter))`).

```rust
// Card renderers
pub fn user_list_cards(users: &[User], filter: &UserListFilter) -> String;
pub fn cvm_list_cards(cvms: &[Cvm], filter: &CvmListFilter) -> String;
pub fn profile_list_cards(profiles: &[Profile], filter: &ProfileListFilter) -> String;
pub fn key_list_cards(keys: &[SshKeyOutput]) -> String;
pub fn audit_events_cards(events: &[AuditEvent], filter: &AuditEventsFilter) -> String;
pub fn entity_list_cards(entities: &[Entity]) -> String;
pub fn quota_get_cards(quotas: &[Quota], filter: &QuotaListFilter) -> String;
pub fn ps_cards(sessions: &[SessionRow], filter: &PsFilter) -> String;

// Single-section cards
pub fn version_card(version: &str, commit: &str, target: &str, build_date: &str) -> String;
pub fn security_cvm_card(sc: &SecurityCvm) -> String;
pub fn user_show_card(view: &UserShowView<'_>) -> String;
pub fn security_cvm_attestation_card(view: &SecurityCvmAttestationView<'_>) -> String;

// Compact list renderer (one-line-per-permission, section 7.29)
pub fn user_permissions_list(permissions: &[String]) -> String;

// Session passthroughs (section 7.33): `umbra code`, `umbra cursor`,
// `umbra claude`, `umbra codex` have no renderer -- the command
// transparently invokes a remote shell and streams the agent's stdout/stderr
// back without interposing any styling.

// Multi-section card
pub fn status_multi_section(status: &StatusOutput) -> String;

// Tables
pub fn traffic_logs_table(logs: &[TrafficLog], filter: &TrafficLogsFilter) -> String;
pub fn config_show_table(entries: &[ConfigEntry]) -> String;

// Confirm renderer (sync mutations and the trailing block of async sagas).
// Command code builds the `ConfirmBlock` value (see section 12.4 for its
// fields) and the single generic renderer produces the section 6.4 layout.
// Per-action shape (header text, detail rows, optional next-step hint) is
// data the caller fills in -- there is intentionally no per-action renderer
// function; the call-site clarity comes from the `ConfirmBlock` literal.
pub fn render_confirm(confirm: &ConfirmBlock) -> String;

// --no-wait operation-handle confirm (sections 7.14, 7.15, 7.19).
// Wraps an Operation snapshot as a ConfirmBlock with present-continuous verbs.
pub fn operation_handle_confirm(
    op_id: &str,
    kind: &str,
    status: &str,
    target_kind: &str,
    target_id: Option<&str>,
) -> String;

// Error block (universal)
pub fn render_error(err: &ErrorBlock) -> String;
pub fn eprintln_error(message: &str);
```

### 12.4 Steps template -- stateful renderer

The steps template is the only stateful renderer. It owns the cursor for in-place updates and the per-step timing state.

The struct is fixed to `io::Stderr`; it is NOT generic over `W: io::Write`. That is intentional: cursor-control escape sequences (`CURSOR_UP`, `CLEAR_LINE`) MUST be emitted on stderr only -- a generic over `W` would allow a caller to misroute them to stdout, where they would corrupt the machine-readable payload (or, on `--json`, the JSON itself). Fixing the type to `io::Stderr` removes that foot-gun at the type level.

The only public constructor is the free function `new_stderr_steps()` (NOT a method on `impl StepsRenderer`). It binds the writer to `io::stderr()` once and never exposes it. Callers cannot supply their own writer.

The polling loop has two mutually exclusive ways to finish on the success path:

- Call `finalize_success(&block)` when the renderer should emit the confirm block itself (used by `auth login` where the saga and the confirm are tightly coupled).
- Call `close()` when the caller wants to emit the confirm block itself from the Operation result (used by `cvm launch`, `cvm update`, `cvm terminate`, `security-cvm launch`, etc., where the confirm fields are built from the returned `<CVMResult>` / `<SecurityCvmProvisionResult>`).

In both cases the last step's yellow "running" line MUST transition to its final green "done" form before the confirm prints.

```rust
pub enum OperationStatus { Pending, Running, Succeeded, Failed }

pub struct StepsRenderer {
    writer: io::Stderr,
    // private: completed steps, current step start time, last printed line, etc.
}

impl StepsRenderer {
    /// Called from the polling loop on every Operation response.
    /// `current_step` is `operation.progress.step`.
    pub fn observe(&mut self, current_step: &str, status: OperationStatus);

    /// Called when the operation reaches `Succeeded` and the renderer
    /// should emit the confirm block. Consumes the renderer.
    pub fn finalize_success(self, confirm: &ConfirmBlock);

    /// Called when the operation reaches `Failed`. Marks the current
    /// step as [FAILED], emits the error block on stderr. Consumes
    /// the renderer.
    pub fn finalize_error(self, err: &ErrorBlock);

    /// Called when the operation reaches `Succeeded` and the caller
    /// will emit the confirm block itself. Transitions the last step
    /// from yellow to green. Consumes the renderer.
    pub fn close(self);
}

/// The only public constructor (free function, NOT a method).
pub fn new_stderr_steps() -> StepsRenderer;

pub struct ConfirmBlock {
    pub verb: String,                    // "launched", "terminated", "updated"
    pub entity_noun: String,             // "cvm", "security cvm"
    pub identifier: String,              // cvm.id
    pub fields: Vec<(String, String)>,   // (label, value) pairs
    pub next_step: Option<String>,
}

pub struct ErrorBlock {
    pub symbol: String,                  // "error", "auth_required", ...
    pub message: String,
    pub cause: Option<String>,
    pub details: Option<String>,
    pub fix: Option<String>,
    pub request_id: Option<String>,
}
```

Command-side usage pattern:

```rust
let mut steps = style::new_stderr_steps();
loop {
    let op = poll_operation(...)?;
    steps.observe(&op.progress.step, op.status);
    match op.status {
        OperationStatus::Pending | OperationStatus::Running => {
            thread::sleep(POLL_INTERVAL);
            continue;
        }
        OperationStatus::Succeeded => {
            steps.finalize_success(ConfirmBlock {
                verb: "launched".into(),
                entity_noun: "cvm".into(),
                identifier: op.result.cvm.id.clone(),
                fields: vec![
                    ("fqdn".into(), op.result.cvm.fqdn.clone()),
                    ("state".into(), op.result.cvm.state.clone()),
                    ("policy file".into(), policy_path.display().to_string()),
                ],
                next_step: Some(format!("umbra ssh {}", op.result.cvm.id)),
            });
            break;
        }
        OperationStatus::Failed => {
            steps.finalize_error(ErrorBlock { /* mapped from op.error */ });
            return ExitStatus::Error;
        }
    }
}
```

### 12.5 FilterContext shapes

One struct per filtered command. Snake_case fields, all `Option<String>` except where noted.

```rust
pub struct CvmListFilter {
    pub profile: Option<String>,
    pub state: Option<String>,
}

pub struct UserListFilter {
    pub status: Option<String>,
    pub assigned: Option<String>,
}

pub struct ProfileListFilter {
    pub assigned: Option<String>,
}

pub struct AuditEventsFilter {
    pub actor: Option<String>,
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

pub struct TrafficLogsFilter {
    pub cvm: Option<String>,
    pub security_cvm: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub limit: Option<u32>,
    pub cursor: Option<String>,
}

pub struct QuotaListFilter {
    pub entity_id: Option<String>,
    pub user_id: Option<String>,
}

pub struct PsFilter {
    pub cvm: String, // always set (resolved from --cvm flag or default_cvm config)
}
```

`AuditEventsFilter` and `TrafficLogsFilter` carry `limit` and `cursor` so the `Filter:` header surfaces operational filters per section 6.2.1. The renderer MUST emit a `limit` row (raw integer, no humanisation) when `limit.is_some()` and a `cursor` row (opaque string, sanitised per section 4) when `cursor.is_some()`.

`umbra entity list` (section 7.7) has no filter flags in v0; there is intentionally no `EntityListFilter` struct. If a future revision adds filters, this section MUST be updated with the new struct shape first.

### 12.6 Adding the `extra` field -- worked example

Existing struct (`cli/src/commands/cvm.rs`):

```rust
#[derive(Debug, Deserialize, Serialize)]
struct Cvm {
    id: String,
    state: String,
    fqdn: Option<String>,
    // ... 14 fields total ...
    created_at: String,
    updated_at: String,
}
```

After adding the catch-all:

```rust
use std::collections::BTreeMap;
use serde_json::Value;

#[derive(Debug, Deserialize, Serialize)]
struct Cvm {
    id: String,
    state: String,
    fqdn: Option<String>,
    // ... 14 fields total, unchanged ...
    created_at: String,
    updated_at: String,

    #[serde(flatten, default, skip_serializing)]
    extra: BTreeMap<String, Value>,
}
```

Notes:

- `flatten` makes unknown wire fields land in `extra` on deserialize.
- `default` lets the field be absent (deserialise from an object with zero unknown fields).
- `skip_serializing` enforces the strict-JSON-output contract from section 11.7: `--json` only emits the fields the CLI struct explicitly declares, so a future Console-side sensitive field never leaks through `--json` until the CLI is updated to declare and review it. The human renderer still surfaces the captured unknowns at the bottom of the card.
- The field is intentionally private (no `pub`) -- only the renderer in `cli/src/style.rs` consumes it.

### 12.7 Field rendering order

Cards MUST render fields in the order listed in the corresponding section 7 subsection. Inserting a new field at a different position is a spec violation -- update section 7 first.

### 12.8 Output destination

| Output | Destination |
|---|---|
| cards, tables, multi-section, confirm blocks, version, status | stdout |
| steps template lines (including cursor-control sequences) | stderr |
| error blocks | stderr |

Cursor-control sequences go to stderr so they do not pollute redirected stdout (`cmd > file.txt`). The steps lines remain visible to the user (who sees stderr in their terminal).

### 12.9 Empty state implementation

Implemented inside the SAME renderer function. No separate `cvm_list_empty` function; the renderer detects an empty slice and returns the `no <records>` line per the footer-word table in section 6.1.

```rust
pub fn cvm_list_cards(cvms: &[Cvm], _filter: &CvmListFilter) -> String {
    if cvms.is_empty() {
        return muted("no cvms");
    }
    // regular rendering
}
```

### 12.10 Test layout

- Per-renderer unit tests inside `cli/src/style.rs` `#[cfg(test)] mod tests`.
- Golden-file integration tests in `cli/tests/style/` -- one fixture file per (command, color-on/color-off) tuple. The test reads the fixture, calls the matching renderer with a hardcoded input, and asserts byte equality.
- The steps template test MAY use a `Vec<u8>` as the writer and assert against the cursor-control sequences it produced.
- Existing tests in `cli/src/commands/*.rs` that asserted on the legacy plain-text output need to be adjusted to either (a) call the new renderer directly, or (b) be replaced by golden-file tests in `cli/tests/style/`.
