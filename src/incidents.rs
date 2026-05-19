// Incidents: in-repo, ref-tracked operational events.
//
// Incidents are stored just like issues and PRs — one ref per incident
// at refs/incidents/<N>, pointing to a blob whose payload is canonical
// TOML. The schema is incident-specific:
//
//   - state       (detected / investigating / mitigated / resolved)
//   - severity    (sev1 = highest .. sev4 = lowest)
//   - incident_type (free-form string: "security", "outage", "bug",
//                   "data-loss", "performance", or anything custom)
//   - fields      (BTreeMap<String,String> for type-specific data
//                   like CVE / CWE / affected services)
//   - new event kinds: transition (state changes), severity (sev
//                   changes), set_field (upsert into `fields`)
//
// As with prs.rs we keep the schema in its own module rather than
// parameterising `Issue`: the on-disk shape is explicit, the
// validation rules (state machine) live next to the data, and a
// future merge of the three TOML decoders is a refactor.

use crate::errors::{GytError, Result};
use crate::fs_util;
use crate::hash::ObjectId;
use crate::object;
use crate::object::ObjectKind;
use crate::refs;
use crate::repo::Repo;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

pub const SCHEMA_VERSION: u32 = 1;
pub const INCIDENT_REFS_PREFIX: &str = "refs/incidents";
const COUNTER_PATH: &str = "meta/incidents_next";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncidentState {
    Detected,
    Investigating,
    Mitigated,
    Resolved,
}

impl IncidentState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Detected => "detected",
            Self::Investigating => "investigating",
            Self::Mitigated => "mitigated",
            Self::Resolved => "resolved",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "detected" => Ok(Self::Detected),
            "investigating" => Ok(Self::Investigating),
            "mitigated" => Ok(Self::Mitigated),
            "resolved" => Ok(Self::Resolved),
            other => Err(GytError::Refs(format!("unknown incident state: {other}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Sev1,
    Sev2,
    Sev3,
    Sev4,
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sev1 => "sev1",
            Self::Sev2 => "sev2",
            Self::Sev3 => "sev3",
            Self::Sev4 => "sev4",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "sev1" | "SEV1" | "1" => Ok(Self::Sev1),
            "sev2" | "SEV2" | "2" => Ok(Self::Sev2),
            "sev3" | "SEV3" | "3" => Ok(Self::Sev3),
            "sev4" | "SEV4" | "4" => Ok(Self::Sev4),
            other => Err(GytError::Refs(format!(
                "unknown severity: {other} (expected sev1..sev4)"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Open,
    Comment,
    Transition,
    Severity,
    Label,
    Assign,
    SetField,
    Resolve,
    Reopen,
}

impl EventKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Comment => "comment",
            Self::Transition => "transition",
            Self::Severity => "severity",
            Self::Label => "label",
            Self::Assign => "assign",
            Self::SetField => "set_field",
            Self::Resolve => "resolve",
            Self::Reopen => "reopen",
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "open" => Ok(Self::Open),
            "comment" => Ok(Self::Comment),
            "transition" => Ok(Self::Transition),
            "severity" => Ok(Self::Severity),
            "label" => Ok(Self::Label),
            "assign" => Ok(Self::Assign),
            "set_field" => Ok(Self::SetField),
            "resolve" => Ok(Self::Resolve),
            "reopen" => Ok(Self::Reopen),
            other => Err(GytError::Refs(format!("unknown incident event: {other}"))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub kind: EventKind,
    pub author: String,
    pub ts: i64,
    pub body: String,
    pub add: Vec<String>,
    pub remove: Vec<String>,
    pub reason: String,
    /// For Transition / Resolve / Reopen: the destination state.
    pub new_state: String,
    /// For Severity: the new severity.
    pub new_severity: String,
    /// For SetField: the key being set.
    pub field_key: String,
    /// For SetField: the value being set (empty string = unset/delete).
    pub field_value: String,
}

#[derive(Debug, Clone)]
pub struct Incident {
    pub number: u64,
    pub title: String,
    pub state: IncidentState,
    pub severity: Severity,
    pub incident_type: String,
    pub author: String,
    pub created_ts: i64,
    pub labels: Vec<String>,
    pub assignees: Vec<String>,
    pub mentions: Vec<u64>,
    pub fields: BTreeMap<String, String>,
    pub events: Vec<Event>,
}

// ─── Encoding ──────────────────────────────────────────────────────────

#[expect(
    clippy::unwrap_used,
    reason = "writeln! to String never fails; the Result is only present for io::Write compatibility"
)]
pub fn encode(inc: &Incident) -> Vec<u8> {
    let mut s = String::new();
    s.push_str("# generated by gyt; canonical ordering matters\n");
    writeln!(s, "schema_version = {SCHEMA_VERSION}").unwrap();
    writeln!(s, "kind = \"incident\"").unwrap();
    writeln!(s, "number = {}", inc.number).unwrap();
    writeln!(s, "title = {:?}", inc.title).unwrap();
    writeln!(s, "state = {:?}", inc.state.as_str()).unwrap();
    writeln!(s, "severity = {:?}", inc.severity.as_str()).unwrap();
    writeln!(s, "incident_type = {:?}", inc.incident_type).unwrap();
    writeln!(s, "author = {:?}", inc.author).unwrap();
    writeln!(s, "created_ts = {}", inc.created_ts).unwrap();
    writeln!(s, "labels = {}", toml_string_array(&inc.labels)).unwrap();
    writeln!(s, "assignees = {}", toml_string_array(&inc.assignees)).unwrap();
    writeln!(s, "mentions = {}", toml_u64_array(&inc.mentions)).unwrap();
    writeln!(s, "fields = {}", toml_string_map(&inc.fields)).unwrap();
    s.push('\n');
    for e in &inc.events {
        s.push_str("[[event]]\n");
        writeln!(s, "kind = {:?}", e.kind.as_str()).unwrap();
        writeln!(s, "author = {:?}", e.author).unwrap();
        writeln!(s, "ts = {}", e.ts).unwrap();
        writeln!(s, "body = {:?}", e.body).unwrap();
        writeln!(s, "add = {}", toml_string_array(&e.add)).unwrap();
        writeln!(s, "remove = {}", toml_string_array(&e.remove)).unwrap();
        writeln!(s, "reason = {:?}", e.reason).unwrap();
        writeln!(s, "new_state = {:?}", e.new_state).unwrap();
        writeln!(s, "new_severity = {:?}", e.new_severity).unwrap();
        writeln!(s, "field_key = {:?}", e.field_key).unwrap();
        writeln!(s, "field_value = {:?}", e.field_value).unwrap();
        s.push('\n');
    }
    s.into_bytes()
}

pub fn decode(bytes: &[u8]) -> Result<Incident> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| GytError::Refs("incident blob is not valid utf-8".into()))?;

    let mut number: Option<u64> = None;
    let mut title = String::new();
    let mut state: Option<IncidentState> = None;
    let mut severity: Option<Severity> = None;
    let mut incident_type = String::new();
    let mut author = String::new();
    let mut created_ts: i64 = 0;
    let mut labels: Vec<String> = Vec::new();
    let mut assignees: Vec<String> = Vec::new();
    let mut mentions: Vec<u64> = Vec::new();
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut schema_seen = false;
    let mut kind_seen = false;

    let mut events: Vec<Event> = Vec::new();
    let mut cur: Option<Event> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[event]]" {
            if let Some(e) = cur.take() {
                events.push(e);
            }
            cur = Some(Event {
                kind: EventKind::Comment,
                author: String::new(),
                ts: 0,
                body: String::new(),
                add: Vec::new(),
                remove: Vec::new(),
                reason: String::new(),
                new_state: String::new(),
                new_severity: String::new(),
                field_key: String::new(),
                field_value: String::new(),
            });
            continue;
        }
        let (key, val) = line
            .split_once('=')
            .ok_or_else(|| GytError::Refs(format!("incident blob: malformed line: {raw}")))?;
        let key = key.trim();
        let val = val.trim();
        if let Some(e) = cur.as_mut() {
            match key {
                "kind" => e.kind = EventKind::parse(&parse_toml_string(val)?)?,
                "author" => e.author = parse_toml_string(val)?,
                "ts" => e.ts = val.parse::<i64>().map_err(|_| invalid("event.ts"))?,
                "body" => e.body = parse_toml_string(val)?,
                "add" => e.add = parse_toml_string_array(val)?,
                "remove" => e.remove = parse_toml_string_array(val)?,
                "reason" => e.reason = parse_toml_string(val)?,
                "new_state" => e.new_state = parse_toml_string(val)?,
                "new_severity" => e.new_severity = parse_toml_string(val)?,
                "field_key" => e.field_key = parse_toml_string(val)?,
                "field_value" => e.field_value = parse_toml_string(val)?,
                other => return Err(invalid(&format!("unknown event field: {other}"))),
            }
        } else {
            match key {
                "schema_version" => {
                    let v: u32 = val.parse().map_err(|_| invalid("schema_version"))?;
                    if v != SCHEMA_VERSION {
                        return Err(GytError::Refs(format!(
                            "unsupported incident schema_version {v}"
                        )));
                    }
                    schema_seen = true;
                }
                "kind" => {
                    if parse_toml_string(val)? != "incident" {
                        return Err(invalid("kind must be \"incident\""));
                    }
                    kind_seen = true;
                }
                "number" => number = Some(val.parse().map_err(|_| invalid("number"))?),
                "title" => title = parse_toml_string(val)?,
                "state" => state = Some(IncidentState::parse(&parse_toml_string(val)?)?),
                "severity" => severity = Some(Severity::parse(&parse_toml_string(val)?)?),
                "incident_type" => incident_type = parse_toml_string(val)?,
                "author" => author = parse_toml_string(val)?,
                "created_ts" => {
                    created_ts = val.parse::<i64>().map_err(|_| invalid("created_ts"))?;
                }
                "labels" => labels = parse_toml_string_array(val)?,
                "assignees" => assignees = parse_toml_string_array(val)?,
                "mentions" => mentions = parse_toml_u64_array(val)?,
                "fields" => fields = parse_toml_string_map(val)?,
                other => return Err(invalid(&format!("unknown incident field: {other}"))),
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
    Ok(Incident {
        number: number.ok_or_else(|| invalid("missing number"))?,
        title,
        state: state.ok_or_else(|| invalid("missing state"))?,
        severity: severity.ok_or_else(|| invalid("missing severity"))?,
        incident_type,
        author,
        created_ts,
        labels,
        assignees,
        mentions,
        fields,
        events,
    })
}

fn invalid(field: &str) -> GytError {
    GytError::Refs(format!("incident blob: invalid {field}"))
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

fn toml_string_map(m: &BTreeMap<String, String>) -> String {
    if m.is_empty() {
        return "{}".into();
    }
    // BTreeMap iterates in key order — that's the canonical ordering.
    let parts: Vec<String> = m.iter().map(|(k, v)| format!("{k:?} = {v:?}")).collect();
    format!("{{ {} }}", parts.join(", "))
}

#[expect(
    clippy::string_slice,
    reason = "byte offsets used are at ASCII / char-boundary positions by construction"
)]
fn parse_toml_string(s: &str) -> Result<String> {
    let s = s.trim();
    if s.len() < 2 || !s.starts_with('"') || !s.ends_with('"') {
        return Err(GytError::Refs(format!(
            "incident blob: not a quoted string: {s}"
        )));
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
                        "incident blob: unsupported escape \\{other}"
                    )));
                }
                None => return Err(GytError::Refs("incident blob: trailing backslash".into())),
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
        return Err(GytError::Refs(format!("incident blob: not an array: {s}")));
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
        return Err(GytError::Refs(format!("incident blob: not an array: {s}")));
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

/// Parse an inline TOML table like `{ "key" = "val", "k2" = "v2" }`.
/// Empty form is `{}`. Both keys and values are quoted strings; we use
/// the same escape rules as `parse_toml_string`.
#[expect(
    clippy::string_slice,
    reason = "byte offsets used are at ASCII / char-boundary positions by construction"
)]
fn parse_toml_string_map(s: &str) -> Result<BTreeMap<String, String>> {
    let s = s.trim();
    if s == "{}" {
        return Ok(BTreeMap::new());
    }
    if !s.starts_with('{') || !s.ends_with('}') {
        return Err(GytError::Refs(format!("incident blob: not a table: {s}")));
    }
    let inner = &s[1..s.len() - 1];
    // Split top-level on commas; commas inside quoted strings don't count.
    let mut entries: Vec<String> = Vec::new();
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
            if !buf.trim().is_empty() {
                entries.push(buf.trim().to_owned());
            }
            buf.clear();
        } else {
            buf.push(c);
        }
    }
    if !buf.trim().is_empty() {
        entries.push(buf.trim().to_owned());
    }

    let mut out = BTreeMap::new();
    for ent in entries {
        let (k, v) = ent
            .split_once('=')
            .ok_or_else(|| GytError::Refs(format!("incident blob: bad table entry: {ent}")))?;
        let key = parse_toml_string(k.trim())?;
        let val = parse_toml_string(v.trim())?;
        out.insert(key, val);
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
            .map_err(|_| GytError::Refs("incidents_next is not utf-8".into()))?;
        txt.trim()
            .parse::<u64>()
            .map_err(|_| GytError::Refs("incidents_next is not a number".into()))?
    } else {
        1
    };
    let bumped = next.checked_add(1).ok_or_else(|| {
        GytError::Refs("incidents_next counter overflow (u64::MAX)".into())
    })?;
    fs_util::atomic_write(&p, format!("{bumped}\n").as_bytes())?;
    Ok(next)
}

/// Whether a state transition `old -> new` is permitted. Detected can
/// move to anywhere ahead; Investigating can roll back to Detected (a
/// misclassified alert) or forward; Mitigated can move to Resolved or
/// back to Investigating if the fix didn't stick; Resolved can be
/// reopened only into Investigating. Same-state moves are rejected by
/// the CLI (no-op), not here.
pub const fn is_allowed_transition(old: IncidentState, new: IncidentState) -> bool {
    use IncidentState::{Detected, Investigating, Mitigated, Resolved};
    matches!(
        (old, new),
        (Detected, Investigating | Mitigated | Resolved)
            | (Investigating, Detected | Mitigated | Resolved)
            | (Mitigated, Investigating | Resolved)
            | (Resolved, Investigating)
    )
}

pub fn validate_extends(old: &Incident, new: &Incident) -> Result<()> {
    if new.number != old.number {
        return Err(GytError::Refs(format!(
            "incident rewind: number changed {} -> {}",
            old.number, new.number
        )));
    }
    if new.created_ts != old.created_ts {
        return Err(GytError::Refs("incident rewind: created_ts changed".into()));
    }
    if new.author != old.author {
        return Err(GytError::Refs("incident rewind: author changed".into()));
    }
    if new.title != old.title {
        return Err(GytError::Refs("incident rewind: title changed".into()));
    }
    if new.incident_type != old.incident_type {
        return Err(GytError::Refs("incident rewind: incident_type changed".into()));
    }
    if new.events.len() < old.events.len() {
        return Err(GytError::Refs(format!(
            "incident rewind: event count decreased {} -> {}",
            old.events.len(),
            new.events.len()
        )));
    }
    for (i, oe) in old.events.iter().enumerate() {
        if new.events.get(i) != Some(oe) {
            return Err(GytError::Refs(format!(
                "incident rewind: event #{i} was modified"
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
                "incident event ts not monotonic: {} -> {}",
                a.ts, b.ts
            )));
        }
    }
    if old.state != new.state && !is_allowed_transition(old.state, new.state) {
        return Err(GytError::Refs(format!(
            "incident rewind: invalid state transition {} -> {}",
            old.state.as_str(),
            new.state.as_str()
        )));
    }
    Ok(())
}

pub fn ref_name(n: u64) -> String {
    format!("{INCIDENT_REFS_PREFIX}/{n}")
}

pub fn read(repo: &Repo, n: u64) -> Result<Incident> {
    let id = match refs::read_ref(&repo.gyt_dir, &ref_name(n)) {
        Ok(id) => id,
        Err(GytError::Refs(_)) => return Err(GytError::NotFound(format!("incident #{n}"))),
        Err(e) => return Err(e),
    };
    let inc = read_blob(&repo.gyt_dir, &id)?;
    if inc.number != n {
        return Err(GytError::Refs(format!(
            "incident blob at refs/incidents/{n} claims number={}",
            inc.number
        )));
    }
    Ok(inc)
}

fn read_blob(repo_gyt: &Path, id: &ObjectId) -> Result<Incident> {
    let obj = object::store::read(repo_gyt, id)?;
    if obj.kind != ObjectKind::Blob {
        return Err(GytError::Refs(format!(
            "refs/incidents blob expected, found {}",
            obj.kind.as_str()
        )));
    }
    decode(&obj.payload)
}

pub fn write_locked(repo: &Repo, inc: &Incident) -> Result<ObjectId> {
    let bytes = encode(inc);
    let id = object::store::write_bytes(&repo.gyt_dir, ObjectKind::Blob, &bytes)?;
    refs::write_ref(&repo.gyt_dir, &ref_name(inc.number), &id)?;
    Ok(id)
}

pub fn list(repo: &Repo) -> Result<Vec<Incident>> {
    let refs_ = refs::list_refs(&repo.gyt_dir, INCIDENT_REFS_PREFIX)?;
    let mut out = Vec::with_capacity(refs_.len());
    for (_, id) in refs_ {
        if let Ok(i) = read_blob(&repo.gyt_dir, &id) {
            out.push(i);
        }
    }
    out.sort_by_key(|i| i.number);
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;

    fn fixture() -> Incident {
        let mut fields = BTreeMap::new();
        fields.insert("cve".into(), "CVE-2026-1234".into());
        fields.insert("cwe".into(), "CWE-287".into());
        Incident {
            number: 7,
            title: "Auth bypass".into(),
            state: IncidentState::Investigating,
            severity: Severity::Sev1,
            incident_type: "security".into(),
            author: "Alice <a@x>".into(),
            created_ts: 1_715_000_000,
            labels: vec!["customer-impact".into()],
            assignees: vec!["Bob <b@x>".into()],
            mentions: vec![3],
            fields,
            events: vec![
                Event {
                    kind: EventKind::Open,
                    author: "Alice <a@x>".into(),
                    ts: 1_715_000_000,
                    body: "detected via WAF anomaly".into(),
                    add: vec![],
                    remove: vec![],
                    reason: String::new(),
                    new_state: String::new(),
                    new_severity: String::new(),
                    field_key: String::new(),
                    field_value: String::new(),
                },
                Event {
                    kind: EventKind::Transition,
                    author: "Alice <a@x>".into(),
                    ts: 1_715_000_100,
                    body: String::new(),
                    add: vec![],
                    remove: vec![],
                    reason: String::new(),
                    new_state: "investigating".into(),
                    new_severity: String::new(),
                    field_key: String::new(),
                    field_value: String::new(),
                },
                Event {
                    kind: EventKind::SetField,
                    author: "Alice <a@x>".into(),
                    ts: 1_715_000_200,
                    body: String::new(),
                    add: vec![],
                    remove: vec![],
                    reason: String::new(),
                    new_state: String::new(),
                    new_severity: String::new(),
                    field_key: "cve".into(),
                    field_value: "CVE-2026-1234".into(),
                },
            ],
        }
    }

    #[test]
    fn incident_round_trip() {
        let inc = fixture();
        let bytes = encode(&inc);
        let back = decode(&bytes).unwrap();
        assert_eq!(back.number, inc.number);
        assert_eq!(back.title, inc.title);
        assert_eq!(back.state, inc.state);
        assert_eq!(back.severity, inc.severity);
        assert_eq!(back.incident_type, inc.incident_type);
        assert_eq!(back.fields.get("cve").map(String::as_str), Some("CVE-2026-1234"));
        assert_eq!(back.events.len(), inc.events.len());
        for (a, b) in back.events.iter().zip(inc.events.iter()) {
            assert_eq!(a.kind, b.kind);
            assert_eq!(a.new_state, b.new_state);
            assert_eq!(a.field_key, b.field_key);
        }
    }

    #[test]
    fn incident_encoded_form_is_canonical() {
        let a = encode(&fixture());
        let b = encode(&decode(&a).unwrap());
        assert_eq!(a, b);
    }

    #[test]
    fn incident_decode_rejects_wrong_kind() {
        let bytes = b"schema_version = 1\nkind = \"issue\"\nnumber = 1\n";
        assert!(decode(bytes).is_err());
    }

    #[test]
    fn incident_states_parse() {
        assert_eq!(
            IncidentState::parse("detected").unwrap(),
            IncidentState::Detected
        );
        assert_eq!(
            IncidentState::parse("investigating").unwrap(),
            IncidentState::Investigating
        );
        assert_eq!(
            IncidentState::parse("mitigated").unwrap(),
            IncidentState::Mitigated
        );
        assert_eq!(
            IncidentState::parse("resolved").unwrap(),
            IncidentState::Resolved
        );
        assert!(IncidentState::parse("garbage").is_err());
    }

    #[test]
    fn severities_parse() {
        assert_eq!(Severity::parse("sev1").unwrap(), Severity::Sev1);
        assert_eq!(Severity::parse("SEV2").unwrap(), Severity::Sev2);
        assert_eq!(Severity::parse("3").unwrap(), Severity::Sev3);
        assert!(Severity::parse("sev5").is_err());
    }

    #[test]
    fn transition_rules() {
        use IncidentState::*;
        assert!(is_allowed_transition(Detected, Investigating));
        assert!(is_allowed_transition(Investigating, Mitigated));
        assert!(is_allowed_transition(Mitigated, Resolved));
        assert!(is_allowed_transition(Resolved, Investigating));
        // disallowed:
        assert!(!is_allowed_transition(Resolved, Mitigated));
        assert!(!is_allowed_transition(Resolved, Detected));
        assert!(!is_allowed_transition(Mitigated, Detected));
    }

    #[test]
    fn empty_fields_round_trip() {
        let mut inc = fixture();
        inc.fields.clear();
        let bytes = encode(&inc);
        let back = decode(&bytes).unwrap();
        assert!(back.fields.is_empty());
    }

    #[test]
    fn fields_with_quotes_escape_correctly() {
        let mut inc = fixture();
        inc.fields.clear();
        inc.fields.insert("note".into(), "has \"quoted\" text".into());
        let bytes = encode(&inc);
        let back = decode(&bytes).unwrap();
        assert_eq!(back.fields.get("note").map(String::as_str), Some("has \"quoted\" text"));
    }

    // ── B4: ts monotonicity in validate_extends ──────────────────

    #[test]
    fn incident_validate_extends_rejects_non_monotonic_appended_event() {
        let old = fixture();
        let mut new = old.clone();
        new.events.push(Event {
            kind: EventKind::Comment,
            author: "Mallory <m@x>".into(),
            ts: 100, // earlier than every prior event
            body: "ts forged".into(),
            add: vec![],
            remove: vec![],
            reason: String::new(),
            new_state: String::new(),
            new_severity: String::new(),
            field_key: String::new(),
            field_value: String::new(),
        });
        let err = validate_extends(&old, &new).unwrap_err();
        assert!(
            matches!(&err, GytError::Refs(m) if m.contains("ts not monotonic")),
            "expected Refs(ts not monotonic ...), got: {err:?}"
        );
    }

    #[test]
    fn incident_validate_extends_accepts_same_second_appended_event() {
        let old = fixture();
        let mut new = old.clone();
        let last_ts = new.events.last().unwrap().ts;
        new.events.push(Event {
            kind: EventKind::Comment,
            author: "Bob <b@x>".into(),
            ts: last_ts,
            body: "same second".into(),
            add: vec![],
            remove: vec![],
            reason: String::new(),
            new_state: String::new(),
            new_severity: String::new(),
            field_key: String::new(),
            field_value: String::new(),
        });
        validate_extends(&old, &new).unwrap();
    }
}
