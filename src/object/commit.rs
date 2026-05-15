// Commit object format (utf-8 text). Header is line-based; message follows
// a single blank line.
//
//   tree     <hex>
//   parent   <hex>                                       0+ lines
//   author   <name> <email> <unix-secs> <tz-offset>      1+ lines (multi-author)
//   committer <name> <email> <unix-secs> <tz-offset>     exactly 1
//   ai       <model-or-tool-id>                          0+ lines
//   reviewer <name> <email>                              0+ lines
//   <blank line>
//   <message bytes>
//
// `ai` records that an AI assistant materially contributed to the change;
// the value is a free-form identifier (e.g. "claude-opus-4-7" or "auto:rustfmt").
// Empty list means no AI assistance applied.
// `reviewer` records human reviewers who signed off before the commit landed.

use crate::errors::{GytError, Result};
use crate::hash::{HEX_LEN, ObjectId};
use crate::object::{ObjectKind, store};
use std::fmt::Write;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub tree: ObjectId,
    pub parents: Vec<ObjectId>,
    pub authors: Vec<String>,
    pub committer: String,
    pub ai_assists: Vec<String>,
    pub reviewers: Vec<String>,
    pub signature: Option<String>, // base64-encoded ed25519 sig; None = unsigned
    pub message: String,
}

impl Commit {
    pub fn primary_author(&self) -> &str {
        self.authors.first().map_or("", String::as_str)
    }
}

#[expect(
    clippy::unwrap_used,
    reason = "writeln! to String never fails; the Result is only present for io::Write compatibility"
)]
pub fn encode(c: &Commit) -> Vec<u8> {
    let mut s = String::new();
    writeln!(s, "tree {}", c.tree).unwrap();
    for p in &c.parents {
        writeln!(s, "parent {p}").unwrap();
    }
    for a in &c.authors {
        writeln!(s, "author {a}").unwrap();
    }
    writeln!(s, "committer {}", c.committer).unwrap();
    for ai in &c.ai_assists {
        writeln!(s, "ai {ai}").unwrap();
    }
    for r in &c.reviewers {
        writeln!(s, "reviewer {r}").unwrap();
    }
    if let Some(ref sig) = c.signature {
        writeln!(s, "signature {sig}").unwrap();
    }
    s.push('\n');
    s.push_str(&c.message);
    s.into_bytes()
}

/// The header sections of a commit, in their canonical on-disk order.
/// Decode rejects any out-of-order line so that signatures bind to a
/// single byte representation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Section {
    Tree = 0,
    Parent = 1,
    Author = 2,
    Committer = 3,
    Ai = 4,
    Reviewer = 5,
    Signature = 6,
}

fn advance_section(cur: &mut Section, next: Section, name: &str) -> Result<()> {
    if next < *cur {
        return Err(GytError::Object(format!(
            "commit: header {name} out of canonical order"
        )));
    }
    *cur = next;
    Ok(())
}

pub fn decode(payload: &[u8]) -> Result<Commit> {
    let text =
        std::str::from_utf8(payload).map_err(|_| GytError::Object("commit: non-utf8".into()))?;
    let (header, message) = text
        .split_once("\n\n")
        .ok_or_else(|| GytError::Object("commit: missing blank line before message".into()))?;

    let mut cur_section = Section::Tree;
    let mut tree: Option<ObjectId> = None;
    let mut parents = Vec::new();
    let mut authors = Vec::new();
    let mut committer: Option<String> = None;
    let mut ai_assists = Vec::new();
    let mut reviewers = Vec::new();
    let mut signature: Option<String> = None;
    for line in header.lines() {
        if let Some(rest) = line.strip_prefix("tree ") {
            if tree.is_some() {
                return Err(GytError::Object("commit: multiple tree lines".into()));
            }
            advance_section(&mut cur_section, Section::Tree, "tree")?;
            if rest.len() != HEX_LEN {
                return Err(GytError::Object("commit: bad tree hash length".into()));
            }
            tree = Some(ObjectId::from_hex(rest)?);
        } else if let Some(rest) = line.strip_prefix("parent ") {
            advance_section(&mut cur_section, Section::Parent, "parent")?;
            parents.push(ObjectId::from_hex(rest)?);
        } else if let Some(rest) = line.strip_prefix("author ") {
            advance_section(&mut cur_section, Section::Author, "author")?;
            authors.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("committer ") {
            if committer.is_some() {
                return Err(GytError::Object("commit: multiple committer lines".into()));
            }
            advance_section(&mut cur_section, Section::Committer, "committer")?;
            committer = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("ai ") {
            advance_section(&mut cur_section, Section::Ai, "ai")?;
            ai_assists.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("reviewer ") {
            advance_section(&mut cur_section, Section::Reviewer, "reviewer")?;
            reviewers.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("signature ") {
            if signature.is_some() {
                return Err(GytError::Object("commit: multiple signature lines".into()));
            }
            advance_section(&mut cur_section, Section::Signature, "signature")?;
            signature = Some(rest.to_string());
        } else {
            return Err(GytError::Object(format!("commit: unknown line {line:?}")));
        }
    }
    if authors.is_empty() {
        return Err(GytError::Object("commit: missing author".into()));
    }
    let commit = Commit {
        tree: tree.ok_or_else(|| GytError::Object("commit: missing tree".into()))?,
        parents,
        authors,
        committer: committer.ok_or_else(|| GytError::Object("commit: missing committer".into()))?,
        ai_assists,
        reviewers,
        signature,
        message: message.to_string(),
    };
    // Defense in depth: re-encoding must reproduce the input. This catches
    // any field-ordering or whitespace anomaly the section walk might miss
    // and guarantees commit IDs and signatures bind to a unique byte form.
    let re_encoded = encode(&commit);
    if re_encoded != payload {
        return Err(GytError::Object(
            "commit: non-canonical encoding (re-encode differs from input)".into(),
        ));
    }
    Ok(commit)
}

pub fn write(repo: &Path, c: &Commit) -> Result<ObjectId> {
    store::write_bytes(repo, ObjectKind::Commit, &encode(c))
}

pub fn read(repo: &Path, id: &ObjectId) -> Result<Commit> {
    let obj = store::read(repo, id)?;
    if obj.kind != ObjectKind::Commit {
        return Err(GytError::Object(format!(
            "expected commit, got {}",
            obj.kind.as_str()
        )));
    }
    decode(&obj.payload)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::hash;

    fn make(authors: Vec<&str>) -> Commit {
        Commit {
            tree: hash::hash_bytes(b"t"),
            parents: vec![],
            authors: authors.into_iter().map(String::from).collect(),
            committer: "Alice <a@x> 1700000000 +0000".into(),
            ai_assists: vec![],
            reviewers: vec![],
            signature: None,
            message: "msg".into(),
        }
    }

    #[test]
    fn round_trip_commit_minimal() {
        let c = make(vec!["Alice <a@x> 1700000000 +0000"]);
        assert_eq!(decode(&encode(&c)).unwrap(), c);
    }

    #[test]
    fn round_trip_commit_with_parents_authors_ai_reviewers() {
        let c = Commit {
            tree: hash::hash_bytes(b"t"),
            parents: vec![hash::hash_bytes(b"p1"), hash::hash_bytes(b"p2")],
            authors: vec![
                "Alice <a@x> 1700000000 +0000".into(),
                "Bob <b@x> 1700000000 +0000".into(),
            ],
            committer: "Alice <a@x> 1700000000 +0000".into(),
            ai_assists: vec!["claude-opus-4-7".into(), "auto:rustfmt".into()],
            reviewers: vec!["Carol <c@x>".into()],
            signature: None,
            message: "init\n\nbody line\n".into(),
        };
        assert_eq!(decode(&encode(&c)).unwrap(), c);
    }

    #[test]
    fn root_commit_has_no_parents() {
        let c = make(vec!["A <a@x> 1 +0000"]);
        let back = decode(&encode(&c)).unwrap();
        assert!(back.parents.is_empty());
    }

    #[test]
    fn rejects_missing_author() {
        let bytes =
            b"tree 0000000000000000000000000000000000000000000000000000000000000000\ncommitter A <a@x> 1 +0000\n\nm".to_vec();
        // tree hex length is correct, but no author lines -> reject
        assert!(decode(&bytes).is_err());
    }

    #[test]
    fn rejects_bad_lines() {
        let bad = b"tree 0000\n\nmsg";
        assert!(decode(bad).is_err());
    }
}
