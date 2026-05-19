// Pull requests: in-repo, ref-tracked, signable.
//
// PRs are stored just like issues — one ref per PR at refs/prs/<N>,
// pointing to a blob whose payload is canonical TOML. The schema is a
// superset of `issues::Issue` adding:
//
//   - source_ref  (the local branch being proposed, e.g. refs/heads/topic)
//   - target_ref  (where it should land, e.g. refs/heads/main)
//   - state       (open / closed / merged)
//   - new event kinds: merge, ci_run
//
// We keep this in a separate module rather than parameterising
// `Issue` so the on-disk schema is explicit and clippy-clean. Mention
// extraction, label/assignee lists, and CRUD wiring are duplicated
// (with the rationale documented in CLAUDE.md): a future merge of the
// two TOML decoders is a refactor, not a fix.

use crate::errors::{GytError, Result};
use crate::fs_util;
use crate::hash::ObjectId;
use crate::object;
use crate::object::ObjectKind;
use crate::refs;
use crate::repo::Repo;
use std::fmt::Write as _;
use std::path::Path;

pub const SCHEMA_VERSION: u32 = 1;
pub const PR_REFS_PREFIX: &str = "refs/prs";
const COUNTER_PATH: &str = "meta/prs_next";

// B15 limits — see src/issues.rs for the rationale (Debug-format
// produces `\u{X}` escapes the hand-rolled parser cannot read, and
// unbounded fields make a single rw push able to fill server disk
// or jam the per-issue timeline with i64::MAX timestamps).
const TS_MIN: i64 = 0;
const TS_MAX: i64 = 4_102_444_800;
const TITLE_MAX_BYTES: usize = 1024;
const BODY_MAX_BYTES: usize = 65_536;
const AUTHOR_MAX_BYTES: usize = 256;
const REASON_MAX_BYTES: usize = 1024;
const RESULT_MAX_BYTES: usize = 4096;
const REF_MAX_BYTES: usize = 255;
const ARRAY_ENTRY_MAX_BYTES: usize = 256;
const ARRAY_MAX_ENTRIES: usize = 256;
const MENTIONS_MAX_ENTRIES: usize = 1024;
const EVENTS_MAX: usize = 100_000;

fn check_text_field(name: &str, s: &str, max_bytes: usize) -> Result<()> {
    if s.len() > max_bytes {
        return Err(GytError::Refs(format!(
            "{name} too long: {} bytes (max {max_bytes})",
            s.len()
        )));
    }
    for (i, b) in s.as_bytes().iter().enumerate() {
        let bad = *b == b'\x7f' || (*b < 0x20 && !matches!(*b, b'\n' | b'\r' | b'\t'));
        if bad {
            return Err(GytError::Refs(format!(
                "{name} contains forbidden control byte 0x{b:02x} at offset {i}"
            )));
        }
    }
    Ok(())
}

fn check_ts(name: &str, ts: i64) -> Result<()> {
    if !(TS_MIN..=TS_MAX).contains(&ts) {
        return Err(GytError::Refs(format!(
            "{name} timestamp {ts} out of range [{TS_MIN}, {TS_MAX}]"
        )));
    }
    Ok(())
}

fn check_array(name: &str, xs: &[String], max_entries: usize, entry_max_bytes: usize) -> Result<()> {
    if xs.len() > max_entries {
        return Err(GytError::Refs(format!(
            "{name} too many entries: {} (max {max_entries})",
            xs.len()
        )));
    }
    for (i, s) in xs.iter().enumerate() {
        check_text_field(&format!("{name}[{i}]"), s, entry_max_bytes)?;
    }
    Ok(())
}

/// B15: validate a Pr's textual content is safely round-trippable and
/// references a valid ref namespace. Called from `write_locked` (so
/// we never emit a blob we couldn't read back) and `decode` (so a
/// crafted push bypassing our encoder hits the same wall).
pub fn validate(pr: &Pr) -> Result<()> {
    check_text_field("title", &pr.title, TITLE_MAX_BYTES)?;
    check_text_field("author", &pr.author, AUTHOR_MAX_BYTES)?;
    check_text_field("source_ref", &pr.source_ref, REF_MAX_BYTES)?;
    check_text_field("target_ref", &pr.target_ref, REF_MAX_BYTES)?;
    // B15: source_ref / target_ref must satisfy the same ref-name
    // validator the on-disk writer uses. Without this, a crafted
    // blob with `target_ref = "../../etc/passwd"` would be accepted
    // by decode() and later operations might join it onto gyt_dir.
    crate::refs::validate_ref_name(&pr.source_ref).map_err(|e| {
        GytError::Refs(format!("source_ref: {e}"))
    })?;
    crate::refs::validate_ref_name(&pr.target_ref).map_err(|e| {
        GytError::Refs(format!("target_ref: {e}"))
    })?;
    check_ts("created_ts", pr.created_ts)?;
    check_array("labels", &pr.labels, ARRAY_MAX_ENTRIES, ARRAY_ENTRY_MAX_BYTES)?;
    check_array("assignees", &pr.assignees, ARRAY_MAX_ENTRIES, ARRAY_ENTRY_MAX_BYTES)?;
    if pr.mentions.len() > MENTIONS_MAX_ENTRIES {
        return Err(GytError::Refs(format!(
            "mentions too long: {} (max {MENTIONS_MAX_ENTRIES})",
            pr.mentions.len()
        )));
    }
    if pr.events.len() > EVENTS_MAX {
        return Err(GytError::Refs(format!(
            "events too long: {} (max {EVENTS_MAX})",
            pr.events.len()
        )));
    }
    for (i, e) in pr.events.iter().enumerate() {
        check_text_field(&format!("event[{i}].author"), &e.author, AUTHOR_MAX_BYTES)?;
        check_text_field(&format!("event[{i}].body"), &e.body, BODY_MAX_BYTES)?;
        check_text_field(&format!("event[{i}].reason"), &e.reason, REASON_MAX_BYTES)?;
        check_text_field(&format!("event[{i}].result"), &e.result, RESULT_MAX_BYTES)?;
        check_ts(&format!("event[{i}].ts"), e.ts)?;
        check_array(
            &format!("event[{i}].add"),
            &e.add,
            ARRAY_MAX_ENTRIES,
            ARRAY_ENTRY_MAX_BYTES,
        )?;
        check_array(
            &format!("event[{i}].remove"),
            &e.remove,
            ARRAY_MAX_ENTRIES,
            ARRAY_ENTRY_MAX_BYTES,
        )?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrState {
    Open,
    Closed,
    Merged,
}

impl PrState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Merged => "merged",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "open" => Ok(Self::Open),
            "closed" => Ok(Self::Closed),
            "merged" => Ok(Self::Merged),
            other => Err(GytError::Refs(format!("unknown pr state: {other}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrEventKind {
    Open,
    Comment,
    Close,
    Reopen,
    Label,
    Assign,
    Merge,
    CiRun,
}

impl PrEventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Comment => "comment",
            Self::Close => "close",
            Self::Reopen => "reopen",
            Self::Label => "label",
            Self::Assign => "assign",
            Self::Merge => "merge",
            Self::CiRun => "ci_run",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "open" => Ok(Self::Open),
            "comment" => Ok(Self::Comment),
            "close" => Ok(Self::Close),
            "reopen" => Ok(Self::Reopen),
            "label" => Ok(Self::Label),
            "assign" => Ok(Self::Assign),
            "merge" => Ok(Self::Merge),
            "ci_run" => Ok(Self::CiRun),
            other => Err(GytError::Refs(format!("unknown pr event: {other}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrEvent {
    pub kind: PrEventKind,
    pub author: String,
    pub ts: i64,
    pub body: String,
    pub add: Vec<String>,
    pub remove: Vec<String>,
    pub reason: String,
    /// For Merge: target commit id that the merge produced (or the
    /// fast-forwarded tip). For CiRun: the result string ("pass" /
    /// "fail: <reason>"). Empty otherwise.
    pub result: String,
}

#[derive(Debug, Clone)]
pub struct Pr {
    pub number: u64,
    pub title: String,
    pub state: PrState,
    pub source_ref: String,
    pub target_ref: String,
    pub author: String,
    pub created_ts: i64,
    pub labels: Vec<String>,
    pub assignees: Vec<String>,
    pub mentions: Vec<u64>,
    pub events: Vec<PrEvent>,
}

// ─── Encoding ──────────────────────────────────────────────────────────

#[expect(
    clippy::unwrap_used,
    reason = "writeln! to String never fails; the Result is only present for io::Write compatibility"
)]
pub fn encode(pr: &Pr) -> Vec<u8> {
    let mut s = String::new();
    s.push_str("# generated by gyt; canonical ordering matters\n");
    writeln!(s, "schema_version = {SCHEMA_VERSION}").unwrap();
    writeln!(s, "kind = \"pr\"").unwrap();
    writeln!(s, "number = {}", pr.number).unwrap();
    writeln!(s, "title = {:?}", pr.title).unwrap();
    writeln!(s, "state = {:?}", pr.state.as_str()).unwrap();
    writeln!(s, "source_ref = {:?}", pr.source_ref).unwrap();
    writeln!(s, "target_ref = {:?}", pr.target_ref).unwrap();
    writeln!(s, "author = {:?}", pr.author).unwrap();
    writeln!(s, "created_ts = {}", pr.created_ts).unwrap();
    writeln!(s, "labels = {}", toml_string_array(&pr.labels)).unwrap();
    writeln!(s, "assignees = {}", toml_string_array(&pr.assignees)).unwrap();
    writeln!(s, "mentions = {}", toml_u64_array(&pr.mentions)).unwrap();
    s.push('\n');
    for e in &pr.events {
        s.push_str("[[event]]\n");
        writeln!(s, "kind = {:?}", e.kind.as_str()).unwrap();
        writeln!(s, "author = {:?}", e.author).unwrap();
        writeln!(s, "ts = {}", e.ts).unwrap();
        writeln!(s, "body = {:?}", e.body).unwrap();
        writeln!(s, "add = {}", toml_string_array(&e.add)).unwrap();
        writeln!(s, "remove = {}", toml_string_array(&e.remove)).unwrap();
        writeln!(s, "reason = {:?}", e.reason).unwrap();
        writeln!(s, "result = {:?}", e.result).unwrap();
        s.push('\n');
    }
    s.into_bytes()
}

pub fn decode(bytes: &[u8]) -> Result<Pr> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| GytError::Refs("pr blob is not valid utf-8".into()))?;

    let mut number: Option<u64> = None;
    let mut title = String::new();
    let mut state: Option<PrState> = None;
    let mut source_ref = String::new();
    let mut target_ref = String::new();
    let mut author = String::new();
    let mut created_ts: i64 = 0;
    let mut labels: Vec<String> = Vec::new();
    let mut assignees: Vec<String> = Vec::new();
    let mut mentions: Vec<u64> = Vec::new();
    let mut schema_seen = false;
    let mut kind_seen = false;

    let mut events: Vec<PrEvent> = Vec::new();
    let mut cur: Option<PrEvent> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[event]]" {
            if let Some(e) = cur.take() {
                events.push(e);
            }
            cur = Some(PrEvent {
                kind: PrEventKind::Comment,
                author: String::new(),
                ts: 0,
                body: String::new(),
                add: Vec::new(),
                remove: Vec::new(),
                reason: String::new(),
                result: String::new(),
            });
            continue;
        }
        let (key, val) = line
            .split_once('=')
            .ok_or_else(|| GytError::Refs(format!("pr blob: malformed line: {raw}")))?;
        let key = key.trim();
        let val = val.trim();
        if let Some(e) = cur.as_mut() {
            match key {
                "kind" => e.kind = PrEventKind::parse(&parse_toml_string(val)?)?,
                "author" => e.author = parse_toml_string(val)?,
                "ts" => e.ts = val.parse::<i64>().map_err(|_| invalid("event.ts"))?,
                "body" => e.body = parse_toml_string(val)?,
                "add" => e.add = parse_toml_string_array(val)?,
                "remove" => e.remove = parse_toml_string_array(val)?,
                "reason" => e.reason = parse_toml_string(val)?,
                "result" => e.result = parse_toml_string(val)?,
                other => return Err(invalid(&format!("unknown event field: {other}"))),
            }
        } else {
            match key {
                "schema_version" => {
                    let v: u32 = val.parse().map_err(|_| invalid("schema_version"))?;
                    if v != SCHEMA_VERSION {
                        return Err(GytError::Refs(format!("unsupported pr schema_version {v}")));
                    }
                    schema_seen = true;
                }
                "kind" => {
                    if parse_toml_string(val)? != "pr" {
                        return Err(invalid("kind must be \"pr\""));
                    }
                    kind_seen = true;
                }
                "number" => number = Some(val.parse().map_err(|_| invalid("number"))?),
                "title" => title = parse_toml_string(val)?,
                "state" => state = Some(PrState::parse(&parse_toml_string(val)?)?),
                "source_ref" => source_ref = parse_toml_string(val)?,
                "target_ref" => target_ref = parse_toml_string(val)?,
                "author" => author = parse_toml_string(val)?,
                "created_ts" => {
                    created_ts = val.parse::<i64>().map_err(|_| invalid("created_ts"))?;
                }
                "labels" => labels = parse_toml_string_array(val)?,
                "assignees" => assignees = parse_toml_string_array(val)?,
                "mentions" => mentions = parse_toml_u64_array(val)?,
                other => return Err(invalid(&format!("unknown pr field: {other}"))),
            }
        }
    }
    if let Some(e) = cur.take() {
        events.push(e);
    }
    if !schema_seen {
        return Err(invalid("missing schema_version"));
    }
    if !kind_seen {
        return Err(invalid("missing kind"));
    }
    let pr = Pr {
        number: number.ok_or_else(|| invalid("missing number"))?,
        title,
        state: state.ok_or_else(|| invalid("missing state"))?,
        source_ref,
        target_ref,
        author,
        created_ts,
        labels,
        assignees,
        mentions,
        events,
    };
    // B15: defense-in-depth — refuse blobs whose contents exceed
    // the caps or carry control bytes that would Debug-escape into
    // unparseable `\u{X}` forms on the next round-trip.
    validate(&pr)?;
    Ok(pr)
}

fn invalid(field: &str) -> GytError {
    GytError::Refs(format!("pr blob: invalid {field}"))
}

fn toml_string_array(xs: &[String]) -> String {
    if xs.is_empty() {
        return "[]".into();
    }
    let parts: Vec<String> = xs.iter().map(|s| format!("{s:?}")).collect();
    format!("[{}]", parts.join(", "))
}

fn toml_u64_array(xs: &[u64]) -> String {
    if xs.is_empty() {
        return "[]".into();
    }
    let parts: Vec<String> = xs.iter().map(u64::to_string).collect();
    format!("[{}]", parts.join(", "))
}
#[expect(
    clippy::string_slice,
    reason = "byte offsets used are at ASCII / char-boundary positions by construction"
)]
fn parse_toml_string(s: &str) -> Result<String> {
    let s = s.trim();
    if s.len() < 2 || !s.starts_with('"') || !s.ends_with('"') {
        return Err(GytError::Refs(format!("pr blob: not a quoted string: {s}")));
    }
    let inner = &s[1..s.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut iter = inner.chars();
    while let Some(c) = iter.next() {
        if c == '\\' {
            match iter.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some('0') => out.push('\0'),
                Some(other) => {
                    return Err(GytError::Refs(format!(
                        "pr blob: unsupported escape \\{other}"
                    )));
                }
                None => return Err(GytError::Refs("pr blob: trailing backslash".into())),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}
#[expect(
    clippy::string_slice,
    reason = "byte offsets used are at ASCII / char-boundary positions by construction"
)]
fn parse_toml_string_array(s: &str) -> Result<Vec<String>> {
    let s = s.trim();
    if s == "[]" {
        return Ok(Vec::new());
    }
    if !s.starts_with('[') || !s.ends_with(']') {
        return Err(GytError::Refs(format!("pr blob: not an array: {s}")));
    }
    let inner = &s[1..s.len() - 1];
    let mut out = Vec::new();
    let mut buf = String::new();
    let mut in_str = false;
    let mut escape = false;
    for c in inner.chars() {
        if escape {
            buf.push(c);
            escape = false;
            continue;
        }
        if in_str {
            buf.push(c);
            if c == '\\' {
                escape = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        if c == '"' {
            buf.push(c);
            in_str = true;
        } else if c == ',' {
            out.push(parse_toml_string(buf.trim())?);
            buf.clear();
        } else if !c.is_whitespace() {
            buf.push(c);
        }
    }
    if !buf.trim().is_empty() {
        out.push(parse_toml_string(buf.trim())?);
    }
    Ok(out)
}
#[expect(
    clippy::string_slice,
    reason = "byte offsets used are at ASCII / char-boundary positions by construction"
)]
fn parse_toml_u64_array(s: &str) -> Result<Vec<u64>> {
    let s = s.trim();
    if s == "[]" {
        return Ok(Vec::new());
    }
    if !s.starts_with('[') || !s.ends_with(']') {
        return Err(GytError::Refs(format!("pr blob: not an array: {s}")));
    }
    let inner = &s[1..s.len() - 1];
    let mut out = Vec::new();
    for tok in inner.split(',') {
        let t = tok.trim();
        if t.is_empty() {
            continue;
        }
        out.push(t.parse::<u64>().map_err(|_| invalid("u64 in array"))?);
    }
    Ok(out)
}

// ─── Storage ───────────────────────────────────────────────────────────

pub fn next_number_locked(repo: &Repo) -> Result<u64> {
    let p = repo.gyt_dir.join(COUNTER_PATH);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let next: u64 = if p.exists() {
        let body = fs_util::read_all(&p)?;
        let txt = std::str::from_utf8(&body)
            .map_err(|_| GytError::Refs("prs_next is not utf-8".into()))?;
        txt.trim()
            .parse::<u64>()
            .map_err(|_| GytError::Refs("prs_next is not a number".into()))?
    } else {
        1
    };
    // L16: checked_add for the same overflow safety.
    let bumped = next.checked_add(1).ok_or_else(|| {
        GytError::Refs("prs_next counter overflow (u64::MAX)".into())
    })?;
    fs_util::atomic_write(&p, format!("{bumped}\n").as_bytes())?;
    Ok(next)
}

/// Validate that `new` is a legitimate monotonic-append update to
/// `old`. See `issues::validate_extends` for full rationale (C3 /
/// F-D8-02). Adds PR-specific checks:
/// - `source_ref` and `target_ref` are immutable after creation.
/// - `state` transitions are constrained: open ↔ closed allowed any
///   time; open → merged allowed only if a matching `merge` event is
///   appended in this same update.
pub fn validate_extends(old: &Pr, new: &Pr) -> Result<()> {
    if new.number != old.number {
        return Err(GytError::Refs(format!(
            "pr rewind: number changed {} -> {}",
            old.number, new.number
        )));
    }
    if new.created_ts != old.created_ts {
        return Err(GytError::Refs("pr rewind: created_ts changed".into()));
    }
    if new.author != old.author {
        return Err(GytError::Refs("pr rewind: author changed".into()));
    }
    if new.title != old.title {
        return Err(GytError::Refs("pr rewind: title changed".into()));
    }
    if new.source_ref != old.source_ref {
        return Err(GytError::Refs("pr rewind: source_ref changed".into()));
    }
    if new.target_ref != old.target_ref {
        return Err(GytError::Refs("pr rewind: target_ref changed".into()));
    }
    if new.events.len() < old.events.len() {
        return Err(GytError::Refs(format!(
            "pr rewind: event count decreased {} -> {}",
            old.events.len(),
            new.events.len()
        )));
    }
    for (i, oe) in old.events.iter().enumerate() {
        if new.events.get(i) != Some(oe) {
            return Err(GytError::Refs(format!(
                "pr rewind: event #{i} was modified"
            )));
        }
    }
    // B4: timestamps must be non-decreasing across the chain. See
    // `issues::validate_extends` for the full rationale.
    for w in new.events.windows(2) {
        if let [a, b] = w
            && b.ts < a.ts
        {
            return Err(GytError::Refs(format!(
                "pr event ts not monotonic: {} -> {}",
                a.ts, b.ts
            )));
        }
    }
    // State transitions
    #[expect(
        clippy::unnested_or_patterns,
        reason = "explicit tuple-pattern enumeration is more readable here than nested or-patterns"
    )]
    match (old.state, new.state) {
        (PrState::Open, PrState::Open)
        | (PrState::Closed, PrState::Closed)
        | (PrState::Merged, PrState::Merged)
        | (PrState::Open, PrState::Closed)
        | (PrState::Closed, PrState::Open) => {}
        (PrState::Open, PrState::Merged) | (PrState::Closed, PrState::Merged) => {
            // A merge transition requires at least one new merge event
            // appended in this update. Without it, a client can set
            // `state = "merged"` without actually merging.
            let start = old.events.len();
            // Length already validated above (new.events.len() >= start).
            let appended = new.events.get(start..).unwrap_or(&[]);
            if !appended.iter().any(|e| e.kind == PrEventKind::Merge) {
                return Err(GytError::Refs(
                    "pr rewind: state -> merged requires a matching merge event".into(),
                ));
            }
        }
        (PrState::Merged, _) => {
            return Err(GytError::Refs(
                "pr rewind: cannot transition out of merged state".into(),
            ));
        }
    }
    Ok(())
}

pub fn ref_name(n: u64) -> String {
    format!("{PR_REFS_PREFIX}/{n}")
}

pub fn read(repo: &Repo, n: u64) -> Result<Pr> {
    let id = match refs::read_ref(&repo.gyt_dir, &ref_name(n)) {
        Ok(id) => id,
        Err(GytError::Refs(_)) => return Err(GytError::NotFound(format!("pr #{n}"))),
        Err(e) => return Err(e),
    };
    let pr = read_blob(&repo.gyt_dir, &id)?;
    // L17: cross-check on-disk number with the ref's N.
    if pr.number != n {
        return Err(GytError::Refs(format!(
            "pr blob at refs/prs/{n} claims number={}", pr.number
        )));
    }
    Ok(pr)
}

fn read_blob(repo_gyt: &Path, id: &ObjectId) -> Result<Pr> {
    let obj = object::store::read(repo_gyt, id)?;
    if obj.kind != ObjectKind::Blob {
        return Err(GytError::Refs(format!(
            "refs/prs blob expected, found {}",
            obj.kind.as_str()
        )));
    }
    decode(&obj.payload)
}

pub fn write_locked(repo: &Repo, pr: &Pr) -> Result<ObjectId> {
    // B15: reject blobs we'd be unable to read back, and reject
    // unsafe source_ref/target_ref names at the boundary.
    validate(pr)?;
    let bytes = encode(pr);
    let id = object::store::write_bytes(&repo.gyt_dir, ObjectKind::Blob, &bytes)?;
    refs::write_ref(&repo.gyt_dir, &ref_name(pr.number), &id)?;
    Ok(id)
}

pub fn list(repo: &Repo) -> Result<Vec<Pr>> {
    let refs_ = refs::list_refs(&repo.gyt_dir, PR_REFS_PREFIX)?;
    let mut out = Vec::with_capacity(refs_.len());
    for (_, id) in refs_ {
        if let Ok(p) = read_blob(&repo.gyt_dir, &id) {
            out.push(p);
        }
    }
    out.sort_by_key(|p| p.number);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;

    fn fixture() -> Pr {
        Pr {
            number: 7,
            title: "Add feature".into(),
            state: PrState::Open,
            source_ref: "refs/heads/topic".into(),
            target_ref: "refs/heads/main".into(),
            author: "Alice <a@x>".into(),
            created_ts: 1_715_000_000,
            labels: vec!["enh".into()],
            assignees: vec!["Bob <b@x>".into()],
            mentions: vec![3],
            events: vec![
                PrEvent {
                    kind: PrEventKind::Open,
                    author: "Alice <a@x>".into(),
                    ts: 1_715_000_000,
                    body: "ready for review".into(),
                    add: vec![],
                    remove: vec![],
                    reason: String::new(),
                    result: String::new(),
                },
                PrEvent {
                    kind: PrEventKind::CiRun,
                    author: "Alice <a@x>".into(),
                    ts: 1_715_000_100,
                    body: String::new(),
                    add: vec![],
                    remove: vec![],
                    reason: String::new(),
                    result: "pass".into(),
                },
                PrEvent {
                    kind: PrEventKind::Merge,
                    author: "Bob <b@x>".into(),
                    ts: 1_715_001_000,
                    body: String::new(),
                    add: vec![],
                    remove: vec![],
                    reason: String::new(),
                    result: "abcd".repeat(16),
                },
            ],
        }
    }

    #[test]
    fn pr_round_trip() {
        let pr = fixture();
        let bytes = encode(&pr);
        let back = decode(&bytes).unwrap();
        assert_eq!(back.number, pr.number);
        assert_eq!(back.title, pr.title);
        assert_eq!(back.state, pr.state);
        assert_eq!(back.source_ref, pr.source_ref);
        assert_eq!(back.target_ref, pr.target_ref);
        assert_eq!(back.events.len(), pr.events.len());
        for (a, b) in back.events.iter().zip(pr.events.iter()) {
            assert_eq!(a.kind, b.kind);
            assert_eq!(a.result, b.result);
        }
    }

    #[test]
    fn pr_encoded_form_is_canonical() {
        let a = encode(&fixture());
        let b = encode(&decode(&a).unwrap());
        assert_eq!(a, b);
    }

    #[test]
    fn pr_decode_rejects_wrong_kind() {
        let bytes = b"schema_version = 1\nkind = \"issue\"\nnumber = 1\n";
        assert!(decode(bytes).is_err());
    }

    #[test]
    fn pr_states_parse() {
        assert_eq!(PrState::parse("open").unwrap(), PrState::Open);
        assert_eq!(PrState::parse("closed").unwrap(), PrState::Closed);
        assert_eq!(PrState::parse("merged").unwrap(), PrState::Merged);
        assert!(PrState::parse("garbage").is_err());
    }

    // ── B4: ts monotonicity in validate_extends ──────────────────

    #[test]
    fn pr_validate_extends_rejects_non_monotonic_appended_event() {
        // The fixture has a Merge event at the tail; appending after
        // merged would already be rejected on the state-transition
        // rule. Build a fresh "open" PR with two events and try to
        // append an out-of-order event.
        let mut old = fixture();
        old.state = PrState::Open;
        old.events.truncate(2); // drop the Merge tail
        let mut new = old.clone();
        new.events.push(PrEvent {
            kind: PrEventKind::Comment,
            author: "Mallory <m@x>".into(),
            ts: 100, // before the prior event's ts
            body: "ts forged".into(),
            add: vec![],
            remove: vec![],
            reason: String::new(),
            result: String::new(),
        });
        let err = validate_extends(&old, &new).unwrap_err();
        assert!(
            matches!(&err, GytError::Refs(m) if m.contains("ts not monotonic")),
            "expected Refs(ts not monotonic ...), got: {err:?}"
        );
    }

    #[test]
    fn pr_validate_extends_accepts_monotonic_appended_event() {
        let mut old = fixture();
        old.state = PrState::Open;
        old.events.truncate(2);
        let mut new = old.clone();
        let last_ts = new.events.last().unwrap().ts;
        new.events.push(PrEvent {
            kind: PrEventKind::Comment,
            author: "Bob <b@x>".into(),
            ts: last_ts + 10,
            body: "later".into(),
            add: vec![],
            remove: vec![],
            reason: String::new(),
            result: String::new(),
        });
        validate_extends(&old, &new).unwrap();
    }
}
