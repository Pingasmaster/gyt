// gith1b REST API — serializable DTOs and JSON helpers.
//
// No serde dependency: we hand-roll JSON serialization. The types are
// simple enough that this is straightforward and keeps the dependency
// tree minimal, consistent with the project philosophy.

use crate::hash::ObjectId;

// ---------- JSON helpers ----------

pub fn json_string(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            // C0 controls — must be \uXXXX in JSON.
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            // U+2028/U+2029 are valid JSON but break naive JavaScript
            // <script> parsers; escape them defensively.
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            // U+007F DELETE — strictly not required to escape, but it's a
            // control char and confuses some tooling.
            '\u{007f}' => out.push_str("\\u007f"),
            // Anything else (including non-BMP) goes through as UTF-8.
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn json_array(items: &[String]) -> String {
    format!("[{}]", items.join(", "))
}

pub fn json_object(pairs: &[(&str, String)]) -> String {
    let fields: Vec<String> = pairs
        .iter()
        .map(|(k, v)| format!("{}: {}", json_string(k), v))
        .collect();
    format!("{{{}}}", fields.join(", "))
}

pub fn json_null() -> String {
    "null".to_string()
}

pub fn json_u64(n: u64) -> String {
    n.to_string()
}

pub fn json_bool(b: bool) -> String {
    b.to_string()
}

// ---------- API response types ----------

#[derive(Debug, Clone)]
pub struct RepoInfo {
    pub owner: String,
    pub name: String,
    pub description: String,
    pub default_branch: String,
    pub head_commit: Option<String>,
}

impl RepoInfo {
    pub fn to_json(&self) -> String {
        json_object(&[
            ("owner", json_string(&self.owner)),
            ("name", json_string(&self.name)),
            ("description", json_string(&self.description)),
            ("default_branch", json_string(&self.default_branch)),
            (
                "head_commit",
                self.head_commit
                    .as_deref().map_or_else(json_null, json_string),
            ),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct CommitInfo {
    pub sha: String,
    pub tree: String,
    pub parents: Vec<String>,
    pub authors: Vec<String>,
    pub committer: String,
    pub ai_assists: Vec<String>,
    pub reviewers: Vec<String>,
    pub message: String,
}

impl CommitInfo {
    pub fn to_json(&self) -> String {
        let parent_jsons: Vec<String> = self.parents.iter().map(|p| json_string(p)).collect();
        json_object(&[
            ("sha", json_string(&self.sha)),
            ("tree", json_string(&self.tree)),
            ("parents", json_array(&parent_jsons)),
            (
                "authors",
                json_array(
                    &self
                        .authors
                        .iter()
                        .map(|a| json_string(a))
                        .collect::<Vec<String>>(),
                ),
            ),
            ("committer", json_string(&self.committer)),
            (
                "ai_assists",
                json_array(
                    &self
                        .ai_assists
                        .iter()
                        .map(|a| json_string(a))
                        .collect::<Vec<String>>(),
                ),
            ),
            (
                "reviewers",
                json_array(
                    &self
                        .reviewers
                        .iter()
                        .map(|r| json_string(r))
                        .collect::<Vec<String>>(),
                ),
            ),
            ("message", json_string(&self.message)),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct TreeEntryInfo {
    pub name: String,
    pub mode: u32,
    pub kind: String,
    pub hash: String,
    pub size: Option<u64>,
}

impl TreeEntryInfo {
    pub fn to_json(&self) -> String {
        json_object(&[
            ("name", json_string(&self.name)),
            ("mode", format!("0o{:o}", self.mode)),
            ("kind", json_string(&self.kind)),
            ("hash", json_string(&self.hash)),
            ("size", self.size.map_or_else(json_null, json_u64)),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct DiffLine {
    pub old_no: Option<u64>,
    pub new_no: Option<u64>,
    pub kind: String,
    pub text: String,
}

impl DiffLine {
    pub fn to_json(&self) -> String {
        json_object(&[
            (
                "old_no",
                self.old_no.map_or_else(json_null, json_u64),
            ),
            (
                "new_no",
                self.new_no.map_or_else(json_null, json_u64),
            ),
            ("kind", json_string(&self.kind)),
            ("text", json_string(&self.text)),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct DiffHunkInfo {
    pub old_start: u64,
    pub old_count: u64,
    pub new_start: u64,
    pub new_count: u64,
    pub lines: Vec<DiffLine>,
}

impl DiffHunkInfo {
    pub fn to_json(&self) -> String {
        let lines_json: Vec<String> = self.lines.iter().map(DiffLine::to_json).collect();
        json_object(&[
            ("old_start", json_u64(self.old_start)),
            ("old_count", json_u64(self.old_count)),
            ("new_start", json_u64(self.new_start)),
            ("new_count", json_u64(self.new_count)),
            ("lines", json_array(&lines_json)),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct DiffFileInfo {
    pub path: String,
    pub hunks: Vec<DiffHunkInfo>,
}

impl DiffFileInfo {
    pub fn to_json(&self) -> String {
        let hunks_json: Vec<String> = self.hunks.iter().map(DiffHunkInfo::to_json).collect();
        json_object(&[
            ("path", json_string(&self.path)),
            ("hunks", json_array(&hunks_json)),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct RefInfo {
    pub name: String,
    pub commit: String,
    pub is_default: bool,
}

impl RefInfo {
    pub fn to_json(&self) -> String {
        json_object(&[
            ("name", json_string(&self.name)),
            ("commit", json_string(&self.commit)),
            ("is_default", json_bool(self.is_default)),
        ])
    }
}

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub kind: String,
    pub items: Vec<String>,
}

impl SearchResult {
    pub fn to_json(&self) -> String {
        json_object(&[
            ("kind", json_string(&self.kind)),
            ("items", json_array(&self.items)),
        ])
    }
}

// ---------- Paginated list response ----------

#[derive(Debug, Clone)]
pub struct Paginated<T> {
    pub items: Vec<T>,
    pub page: usize,
    pub per_page: usize,
    pub total: usize,
}

impl<T> Paginated<T>
where
    T: JsonSerialize,
{
    pub fn to_json(&self) -> String {
        let items_json: Vec<String> = self.items.iter().map(JsonSerialize::to_json).collect();
        json_object(&[
            ("items", json_array(&items_json)),
            ("page", json_u64(self.page as u64)),
            ("per_page", json_u64(self.per_page as u64)),
            ("total", json_u64(self.total as u64)),
        ])
    }
}

pub trait JsonSerialize {
    fn to_json(&self) -> String;
}

impl JsonSerialize for RepoInfo {
    fn to_json(&self) -> String {
        Self::to_json(self)
    }
}

impl JsonSerialize for CommitInfo {
    fn to_json(&self) -> String {
        Self::to_json(self)
    }
}

impl JsonSerialize for TreeEntryInfo {
    fn to_json(&self) -> String {
        Self::to_json(self)
    }
}

impl JsonSerialize for RefInfo {
    fn to_json(&self) -> String {
        Self::to_json(self)
    }
}

impl JsonSerialize for DiffFileInfo {
    fn to_json(&self) -> String {
        Self::to_json(self)
    }
}

impl JsonSerialize for SearchResult {
    fn to_json(&self) -> String {
        Self::to_json(self)
    }
}

// ---------- Blob response ----------

#[derive(Debug, Clone)]
pub struct BlobInfo {
    pub path: String,
    pub hash: String,
    pub content: String,
    pub size: u64,
}

impl BlobInfo {
    pub fn to_json(&self) -> String {
        json_object(&[
            ("path", json_string(&self.path)),
            ("hash", json_string(&self.hash)),
            ("content", json_string(&self.content)),
            ("size", json_u64(self.size)),
        ])
    }
}

impl JsonSerialize for BlobInfo {
    fn to_json(&self) -> String {
        Self::to_json(self)
    }
}

// ---------- Utility: parse ObjectId from hex with error message ----------

pub fn parse_object_id(hex: &str) -> Result<ObjectId, String> {
    ObjectId::from_hex(hex).map_err(|e| format!("invalid hash: {e}"))
}

// ---------- URL parsing helpers ----------

pub fn parse_page(params: &[(String, String)], default: usize) -> usize {
    // H10: cap at 1M. Without a cap, an attacker can inject 1M unique
    // `?page=N` cache keys, flushing hot entries via the random-eviction
    // policy in cache.rs. Anything past 1M pages is nonsensical anyway
    // (a billion-commit repo at per_page=100 is 10M pages).
    const MAX_PAGE: usize = 1_000_000;
    let v = params
        .iter()
        .find(|(k, _)| k == "page")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(default);
    v.min(MAX_PAGE)
}

pub fn parse_per_page(params: &[(String, String)], default: usize, max: usize) -> usize {
    let val = params
        .iter()
        .find(|(k, _)| k == "per_page")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(default);
    val.min(max)
}
