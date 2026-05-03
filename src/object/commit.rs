// Commit object format (utf-8 text):
//   tree <hex>
//   parent <hex>           (zero or more lines)
//   author <name> <email> <unix-secs> <tz-offset>
//   committer <name> <email> <unix-secs> <tz-offset>
//   <blank line>
//   <message bytes>
//
// We keep the line shape close to git's so the structure is familiar,
// but hashes are 64-char BLAKE3 hex.

use crate::errors::{GytError, Result};
use crate::hash::{HEX_LEN, ObjectId};
use crate::object::{ObjectKind, store};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub tree: ObjectId,
    pub parents: Vec<ObjectId>,
    pub author: String,
    pub committer: String,
    pub message: String,
}

pub fn encode(c: &Commit) -> Vec<u8> {
    let mut s = String::new();
    s.push_str(&format!("tree {}\n", c.tree));
    for p in &c.parents {
        s.push_str(&format!("parent {p}\n"));
    }
    s.push_str(&format!("author {}\n", c.author));
    s.push_str(&format!("committer {}\n", c.committer));
    s.push('\n');
    s.push_str(&c.message);
    s.into_bytes()
}

pub fn decode(payload: &[u8]) -> Result<Commit> {
    let text =
        std::str::from_utf8(payload).map_err(|_| GytError::Object("commit: non-utf8".into()))?;
    let (header, message) = text
        .split_once("\n\n")
        .ok_or_else(|| GytError::Object("commit: missing blank line before message".into()))?;
    let mut tree: Option<ObjectId> = None;
    let mut parents = Vec::new();
    let mut author: Option<String> = None;
    let mut committer: Option<String> = None;
    for line in header.lines() {
        if let Some(rest) = line.strip_prefix("tree ") {
            if rest.len() != HEX_LEN {
                return Err(GytError::Object("commit: bad tree hash length".into()));
            }
            tree = Some(ObjectId::from_hex(rest)?);
        } else if let Some(rest) = line.strip_prefix("parent ") {
            parents.push(ObjectId::from_hex(rest)?);
        } else if let Some(rest) = line.strip_prefix("author ") {
            author = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("committer ") {
            committer = Some(rest.to_string());
        } else {
            return Err(GytError::Object(format!("commit: unknown line {line:?}")));
        }
    }
    Ok(Commit {
        tree: tree.ok_or_else(|| GytError::Object("commit: missing tree".into()))?,
        parents,
        author: author.ok_or_else(|| GytError::Object("commit: missing author".into()))?,
        committer: committer.ok_or_else(|| GytError::Object("commit: missing committer".into()))?,
        message: message.to_string(),
    })
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
    use super::*;
    use crate::hash;

    #[test]
    fn round_trip_commit() {
        let c = Commit {
            tree: hash::hash_bytes(b"t"),
            parents: vec![hash::hash_bytes(b"p1"), hash::hash_bytes(b"p2")],
            author: "Alice <a@x> 1700000000 +0000".into(),
            committer: "Alice <a@x> 1700000000 +0000".into(),
            message: "init\n\nbody line\n".into(),
        };
        let bytes = encode(&c);
        assert_eq!(decode(&bytes).unwrap(), c);
    }

    #[test]
    fn root_commit_has_no_parents() {
        let c = Commit {
            tree: hash::hash_bytes(b"t"),
            parents: vec![],
            author: "A <a@x> 1 +0000".into(),
            committer: "A <a@x> 1 +0000".into(),
            message: "first".into(),
        };
        let back = decode(&encode(&c)).unwrap();
        assert!(back.parents.is_empty());
    }

    #[test]
    fn rejects_bad_lines() {
        let bad = b"tree 0000\n\nmsg";
        assert!(decode(bad).is_err());
    }
}
