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

/// Hard cap on entries in a single tree object. A legitimate gyt tree
/// represents one directory; even pathological monorepos rarely break
/// 100k entries. The cap bounds memory of `decode` against malicious
/// payloads that would otherwise allocate one `TreeEntry` (≈80 bytes
/// resident) per declared entry.
pub const MAX_TREE_ENTRIES: usize = 1_000_000;

/// Maximum byte length of a single tree-entry name. Filesystems differ
/// (ext4=255, NTFS=255, APFS=255) so 255 is the lowest-common-denominator.
pub const MAX_NAME_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub mode: u32,
    pub name: Vec<u8>,
    pub hash: ObjectId,
}

const fn is_known_mode(m: u32) -> bool {
    matches!(m, MODE_FILE | MODE_EXEC | MODE_SYMLINK | MODE_DIR)
}

/// Validate one tree-entry name against the canonical-form rules. This
/// is the single chokepoint that closes the path-traversal-via-tree-name
/// class. Every site that materializes tree entries to disk
/// (cmd::merge, cmd::switch, cmd::worktree, cmd::stash, cmd::rebase,
/// cmd::cherry_pick, cmd::clone) relies on it.
pub fn validate_entry_name(name: &[u8]) -> Result<()> {
    if name.is_empty() {
        return Err(GytError::Object("tree: empty entry name".into()));
    }
    if name.len() > MAX_NAME_LEN {
        return Err(GytError::Object(format!(
            "tree: entry name length {} exceeds {MAX_NAME_LEN}",
            name.len()
        )));
    }
    if name == b"." || name == b".." {
        return Err(GytError::Object("tree: entry name is '.' or '..'".into()));
    }
    // .gyt (any ASCII case) would shadow repo metadata on checkout. The
    // tree-entry-name is a single path component (no '/' allowed by the
    // checks below), so a case-insensitive equality is sufficient.
    if name.len() == 4
        && name.iter().zip(b".gyt").all(|(a, b)| a.eq_ignore_ascii_case(b))
    {
        return Err(GytError::Object("tree: entry name is .gyt".into()));
    }
    for &b in name {
        if b == b'/' {
            return Err(GytError::Object(
                "tree: entry name contains '/' (must be a single path component)".into(),
            ));
        }
        if b == b'\\' {
            return Err(GytError::Object(
                "tree: entry name contains backslash".into(),
            ));
        }
        if b < 0x20 || b == 0x7f {
            return Err(GytError::Object(
                "tree: entry name contains control byte".into(),
            ));
        }
    }
    Ok(())
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

#[expect(
    clippy::indexing_slicing,
    reason = "payload[i..] is gated by `while i < payload.len()`; payload[i..i+space] / [i..i+nul] / [i..i+HASH_LEN] are gated by `space`/`nul` coming from position() on payload[i..] (so they fit) and an explicit `i + HASH_LEN > payload.len()` early return"
)]
pub fn decode(payload: &[u8]) -> Result<Vec<TreeEntry>> {
    let mut entries: Vec<TreeEntry> = Vec::new();
    let mut prev_name: Option<Vec<u8>> = None;
    let mut i = 0;
    while i < payload.len() {
        if entries.len() >= MAX_TREE_ENTRIES {
            return Err(GytError::Object(format!(
                "tree: entry count exceeds {MAX_TREE_ENTRIES}"
            )));
        }
        let space = payload[i..]
            .iter()
            .position(|&b| b == b' ')
            .ok_or_else(|| GytError::Object("tree: missing space after mode".into()))?;
        let mode_s = std::str::from_utf8(&payload[i..i + space])
            .map_err(|_| GytError::Object("tree: non-utf8 mode".into()))?;
        let mode = u32::from_str_radix(mode_s, 8)
            .map_err(|_| GytError::Object(format!("tree: bad mode {mode_s:?}")))?;
        // M37: reject leading-zero / non-canonical octal modes
        // (e.g. `0100644`, `00100644`). encode() emits the
        // strip-leading-zero form `{mode:o}`; without this check, two
        // distinct on-disk byte sequences decode to the same logical
        // tree and produce distinct hashes — a malicious server can
        // plant N hash-distinct variants of the same tree.
        if mode_s != format!("{mode:o}") {
            return Err(GytError::Object(format!(
                "tree: non-canonical mode token {mode_s:?}"
            )));
        }
        if !is_known_mode(mode) {
            return Err(GytError::Object(format!(
                "tree: mode {mode:o} is not in the gyt whitelist"
            )));
        }
        i += space + 1;
        let nul = payload[i..]
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| GytError::Object("tree: missing NUL after name".into()))?;
        let name = payload[i..i + nul].to_vec();
        validate_entry_name(&name)?;
        // Strict-ascending sort + uniqueness. encode() sorts but is
        // stable, so duplicates would round-trip; checking here makes
        // canonicality bidirectional.
        if let Some(prev) = &prev_name
            && name <= *prev
        {
            return Err(GytError::Object(
                "tree: entries not strictly ascending by name (unsorted or duplicate)".into(),
            ));
        }
        prev_name = Some(name.clone());
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
    #![expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
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
