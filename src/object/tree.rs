// Tree object format (binary):
//   for each entry, sorted by name (lexicographic byte order):
//     <mode-decimal-ascii> ' ' <name-bytes> '\0' <32-byte hash>
//
// Modes (gyt-defined subset):
//   0o100644  regular file
//   0o100755  executable file
//   0o120000  symlink
//   0o040000  subtree (directory)
//
// We deliberately do not support gitlinks or other esoteric modes.

use crate::errors::{GytError, Result};
use crate::hash::{HASH_LEN, ObjectId};
use crate::object::{ObjectKind, store};
use std::path::Path;

pub const MODE_FILE: u32 = 0o100_644;
pub const MODE_EXEC: u32 = 0o100_755;
pub const MODE_SYMLINK: u32 = 0o120_000;
pub const MODE_DIR: u32 = 0o040_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: u32,
    pub name: Vec<u8>,
    pub hash: ObjectId,
}

pub fn encode(entries: &[TreeEntry]) -> Vec<u8> {
    let mut sorted: Vec<&TreeEntry> = entries.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let mut out = Vec::with_capacity(sorted.len() * 64);
    for e in sorted {
        out.extend_from_slice(format!("{:o} ", e.mode).as_bytes());
        out.extend_from_slice(&e.name);
        out.push(0);
        out.extend_from_slice(&e.hash.0);
    }
    out
}

pub fn decode(payload: &[u8]) -> Result<Vec<TreeEntry>> {
    let mut entries = Vec::new();
    let mut i = 0;
    while i < payload.len() {
        let space = payload[i..]
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| GytError::Object("tree: missing space after mode".into()))?;
        let mode_s = std::str::from_utf8(&payload[i..i + space])
            .map_err(|_| GytError::Object("tree: non-utf8 mode".into()))?;
        let mode = u32::from_str_radix(mode_s, 8)
            .map_err(|_| GytError::Object(format!("tree: bad mode {mode_s:?}")))?;
        i += space + 1;
        let nul = payload[i..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| GytError::Object("tree: missing NUL after name".into()))?;
        let name = payload[i..i + nul].to_vec();
        i += nul + 1;
        if i + HASH_LEN > payload.len() {
            return Err(GytError::Object("tree: truncated hash".into()));
        }
        let hash = ObjectId::from_bytes(&payload[i..i + HASH_LEN])?;
        i += HASH_LEN;
        entries.push(TreeEntry { mode, name, hash });
    }
    Ok(entries)
}

pub fn write(repo: &Path, entries: &[TreeEntry]) -> Result<ObjectId> {
    let bytes = encode(entries);
    store::write_bytes(repo, ObjectKind::Tree, &bytes)
}

pub fn read(repo: &Path, id: &ObjectId) -> Result<Vec<TreeEntry>> {
    let obj = store::read(repo, id)?;
    if obj.kind != ObjectKind::Tree {
        return Err(GytError::Object(format!(
            "expected tree, got {}",
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
    fn round_trip_tree() {
        let entries = vec![
            TreeEntry {
                mode: MODE_FILE,
                name: b"README.md".to_vec(),
                hash: hash::hash_bytes(b"a"),
            },
            TreeEntry {
                mode: MODE_DIR,
                name: b"src".to_vec(),
                hash: hash::hash_bytes(b"b"),
            },
        ];
        let bytes = encode(&entries);
        let back = decode(&bytes).unwrap();
        // sort to compare since encode sorts
        let mut expected = entries;
        expected.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(back, expected);
    }

    #[test]
    fn entries_are_sorted() {
        let entries = vec![
            TreeEntry {
                mode: MODE_FILE,
                name: b"z".to_vec(),
                hash: hash::hash_bytes(b"z"),
            },
            TreeEntry {
                mode: MODE_FILE,
                name: b"a".to_vec(),
                hash: hash::hash_bytes(b"a"),
            },
        ];
        let back = decode(&encode(&entries)).unwrap();
        assert_eq!(back[0].name, b"a");
        assert_eq!(back[1].name, b"z");
    }
}
