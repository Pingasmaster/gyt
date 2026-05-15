// Three-way merge primitives.
//
// Two layers:
//
//   1. `merge_lines` — line-level three-way merge of `base`, `ours`, `theirs`.
//      Returns a Vec<MergeChunk> describing matched regions and conflicts.
//      When `ours` or `theirs` agrees with `base`, the other side wins
//      automatically; if both sides changed the same region differently, a
//      `Conflict` chunk is emitted carrying both versions for the caller to
//      render conflict markers.
//
//   2. `merge_trees` — tree-level three-way merge. Given base/ours/theirs
//      trees (each a path -> (mode, blob-hash) map), it produces a merged
//      tree plus a list of unresolved conflicts.
//
// The output uses the standard `<<<<<<<` / `=======` / `>>>>>>>` markers
// at conflict boundaries. The caller decides whether to write conflict-
// marker blobs into the workdir, fail the merge, or pause for interactive
// resolution.
//
// Implementation note: the line-level engine is built on top of the same
// Myers diff already used by `gyt diff`. We compute (base→ours) and
// (base→theirs) diffs, walk them in parallel, and reconcile region-by-
// region. This is the same approach RCS/diff3 take; it has subtle edge
// cases around adjacent edits but produces sensible output for the cases
// that actually occur in development workflows.

use crate::diff;
use std::collections::{BTreeMap, BTreeSet};

/// A chunk of the merged output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeChunk {
    /// Lines copied straight from `base`/`ours`/`theirs` (they agree).
    Unchanged(Vec<Vec<u8>>),
    /// Both sides edited the region; values carried separately for marker
    /// rendering. `base_lines` is what the region looked like at the merge
    /// base — useful for diff3-style output but otherwise ignorable.
    Conflict {
        ours: Vec<Vec<u8>>,
        base_lines: Vec<Vec<u8>>,
        theirs: Vec<Vec<u8>>,
    },
}

/// Output of `merge_lines`: the reconciled chunks plus a "clean" flag that
/// is `false` if any `Conflict` chunk was produced.
pub struct LineMerge {
    pub chunks: Vec<MergeChunk>,
    pub clean: bool,
}

/// Three-way merge at the line level.
#[expect(
    clippy::indexing_slicing,
    reason = "base_lines[i] / base_lines[i..i+del] are gated by `while i < base_lines.len()`; del = max(ours_del, theirs_del) is bounded by edit-map invariant that no edit goes past base_lines.len()"
)]
pub fn merge_lines(base: &[u8], ours: &[u8], theirs: &[u8]) -> LineMerge {
    // Fast paths.
    if ours == theirs {
        let lines = diff::split_lines(ours)
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
        return LineMerge {
            chunks: vec![MergeChunk::Unchanged(lines)],
            clean: true,
        };
    }
    if base == ours {
        // Only theirs changed.
        let lines = diff::split_lines(theirs)
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
        return LineMerge {
            chunks: vec![MergeChunk::Unchanged(lines)],
            clean: true,
        };
    }
    if base == theirs {
        // Only ours changed.
        let lines = diff::split_lines(ours)
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();
        return LineMerge {
            chunks: vec![MergeChunk::Unchanged(lines)],
            clean: true,
        };
    }

    let base_lines: Vec<&[u8]> = diff::split_lines(base);
    let ours_lines: Vec<&[u8]> = diff::split_lines(ours);
    let theirs_lines: Vec<&[u8]> = diff::split_lines(theirs);

    let ops_ours = diff::myers(&base_lines, &ours_lines);
    let ops_theirs = diff::myers(&base_lines, &theirs_lines);

    // Build per-base-line "hunks" indicating where each side diverges from
    // base. The walk produces, for each base line index, the set of
    // (deletes-from-base, inserts-on-this-side) attached to that line.
    let ours_edits = walk_edits(&ops_ours);
    let theirs_edits = walk_edits(&ops_theirs);

    let mut chunks: Vec<MergeChunk> = Vec::new();
    let mut buf_unchanged: Vec<Vec<u8>> = Vec::new();
    let mut i: usize = 0;

    let mut clean = true;
    while i < base_lines.len() {
        let (ours_del, ours_ins) = ours_edits.get(&i).cloned().unwrap_or_default();
        let (theirs_del, theirs_ins) = theirs_edits.get(&i).cloned().unwrap_or_default();

        let neither_changed = ours_del == 0 && ours_ins.is_empty() && theirs_del == 0 && theirs_ins.is_empty();
        if neither_changed {
            buf_unchanged.push(base_lines[i].to_vec());
            i += 1;
            continue;
        }

        // Flush pending unchanged region.
        if !buf_unchanged.is_empty() {
            chunks.push(MergeChunk::Unchanged(std::mem::take(&mut buf_unchanged)));
        }

        // Region resolution. If only one side changed, take that side.
        let only_ours = (theirs_del == 0 && theirs_ins.is_empty()) && !(ours_del == 0 && ours_ins.is_empty());
        let only_theirs = (ours_del == 0 && ours_ins.is_empty()) && !(theirs_del == 0 && theirs_ins.is_empty());

        // The region length on the base side is max(ours_del, theirs_del).
        let del = ours_del.max(theirs_del);

        if only_ours {
            chunks.push(MergeChunk::Unchanged(ours_ins.clone()));
            i += del;
            continue;
        }
        if only_theirs {
            chunks.push(MergeChunk::Unchanged(theirs_ins.clone()));
            i += del;
            continue;
        }

        // Both sides changed. If both produced exactly the same content,
        // accept it; otherwise conflict.
        if ours_ins == theirs_ins && ours_del == theirs_del {
            chunks.push(MergeChunk::Unchanged(ours_ins.clone()));
            i += del;
            continue;
        }

        let base_region: Vec<Vec<u8>> = base_lines[i..i + del]
            .iter()
            .map(|b| b.to_vec())
            .collect();
        chunks.push(MergeChunk::Conflict {
            ours: ours_ins,
            base_lines: base_region,
            theirs: theirs_ins,
        });
        clean = false;
        i += del;
    }
    if !buf_unchanged.is_empty() {
        chunks.push(MergeChunk::Unchanged(buf_unchanged));
    }

    // Trailing inserts: both sides may have appended new lines past the end
    // of base. Handle as a final "region at the tail".
    let ours_tail = ours_edits
        .get(&base_lines.len())
        .cloned()
        .unwrap_or_default()
        .1;
    let theirs_tail = theirs_edits
        .get(&base_lines.len())
        .cloned()
        .unwrap_or_default()
        .1;
    match (ours_tail.is_empty(), theirs_tail.is_empty()) {
        (true, true) => {}
        (false, true) => chunks.push(MergeChunk::Unchanged(ours_tail)),
        (true, false) => chunks.push(MergeChunk::Unchanged(theirs_tail)),
        (false, false) => {
            if ours_tail == theirs_tail {
                chunks.push(MergeChunk::Unchanged(ours_tail));
            } else {
                chunks.push(MergeChunk::Conflict {
                    ours: ours_tail,
                    base_lines: Vec::new(),
                    theirs: theirs_tail,
                });
                clean = false;
            }
        }
    }

    LineMerge { chunks, clean }
}

/// For each base line index, how many lines were deleted starting there,
/// plus the list of replacement lines that take their place.
type EditMap = BTreeMap<usize, (usize, Vec<Vec<u8>>)>;

/// Walk a (base → side) Myers op list and produce an EditMap keyed by base
/// line position. Equal ops advance the cursor without recording anything;
/// runs of Delete/Insert at the same base position get bundled.
#[expect(
    clippy::indexing_slicing,
    reason = "ops[i] is gated by the `while i < ops.len()` loop header and the nested inner while-loop"
)]
fn walk_edits(ops: &[diff::DiffOp<'_>]) -> EditMap {
    let mut out: EditMap = BTreeMap::new();
    let mut base_pos = 0usize;
    let mut i = 0;
    while i < ops.len() {
        match &ops[i] {
            diff::DiffOp::Equal(_) => {
                base_pos += 1;
                i += 1;
            }
            _ => {
                let start = base_pos;
                let mut del = 0usize;
                let mut ins: Vec<Vec<u8>> = Vec::new();
                while i < ops.len() {
                    match &ops[i] {
                        diff::DiffOp::Delete(_) => {
                            del += 1;
                            base_pos += 1;
                            i += 1;
                        }
                        diff::DiffOp::Insert(line) => {
                            ins.push((*line).to_vec());
                            i += 1;
                        }
                        diff::DiffOp::Equal(_) => break,
                    }
                }
                out.insert(start, (del, ins));
            }
        }
    }
    out
}

/// Render the merge chunks back to a byte buffer using conflict markers.
/// `ours_label`/`theirs_label` are used in the marker lines.
///
/// Each chunk's lines are stored *without* their trailing newlines (that's
/// how `diff::split_lines` produces them). On render, we add a `\n` after
/// each line unless it already has one. This means the output of merging
/// two newline-terminated inputs is newline-terminated, which matches what
/// callers expect.
fn emit_line(out: &mut Vec<u8>, line: &[u8]) {
    out.extend_from_slice(line);
    if !line.ends_with(b"\n") {
        out.push(b'\n');
    }
}

pub fn render_with_markers(merge: &LineMerge, ours_label: &str, theirs_label: &str) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for chunk in &merge.chunks {
        match chunk {
            MergeChunk::Unchanged(lines) => {
                for l in lines {
                    emit_line(&mut out, l);
                }
            }
            MergeChunk::Conflict {
                ours,
                base_lines: _,
                theirs,
            } => {
                out.extend_from_slice(b"<<<<<<< ");
                out.extend_from_slice(ours_label.as_bytes());
                out.push(b'\n');
                for l in ours {
                    emit_line(&mut out, l);
                }
                out.extend_from_slice(b"=======\n");
                for l in theirs {
                    emit_line(&mut out, l);
                }
                out.extend_from_slice(b">>>>>>> ");
                out.extend_from_slice(theirs_label.as_bytes());
                out.push(b'\n');
            }
        }
    }
    out
}

/// Three-way merge at the tree level.
///
/// Each input map is path -> (mode, blob-hash). The merged map is returned
/// alongside a list of (path, kind) conflicts: kind names the failure mode
/// — "add/add" when both sides created the same path with different
/// content, "modify/delete" when one side deleted and the other modified,
/// "content" when both sides modified the same file and their changes
/// can't be auto-merged at the line level, and "mode" when both sides
/// changed mode differently.
///
/// For "content" conflicts, the caller can resolve them at the byte level
/// using `merge_lines` and `render_with_markers`.
pub struct TreeMerge {
    pub merged: BTreeMap<PathLike, (u32, BlobHash)>,
    pub conflicts: Vec<TreeConflict>,
}

pub type PathLike = std::path::PathBuf;
pub type BlobHash = crate::hash::ObjectId;

#[derive(Debug, Clone)]
pub struct TreeConflict {
    pub path: PathLike,
    pub kind: ConflictKind,
    // Reason: these three fields are part of the public API surface for
    // tools that render conflict UIs (TUI, web). They're read in the wire
    // protocol body of a future "conflict report" endpoint; today's
    // callers only branch on `kind`, so the lint complains.
    pub base: Option<(u32, BlobHash)>,
    pub ours: Option<(u32, BlobHash)>,
    pub theirs: Option<(u32, BlobHash)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConflictKind {
    /// Both sides created the same path with different content.
    AddAdd,
    /// One side modified the file; the other deleted it.
    ModifyDelete,
    /// Both sides modified the same file; line-level merge didn't resolve.
    Content,
    /// Both sides changed mode incompatibly.
    Mode,
}

pub fn merge_trees(
    base: &BTreeMap<PathLike, (u32, BlobHash)>,
    ours: &BTreeMap<PathLike, (u32, BlobHash)>,
    theirs: &BTreeMap<PathLike, (u32, BlobHash)>,
    mut resolve_content: impl FnMut(&PathLike, (u32, &BlobHash), (u32, &BlobHash), Option<(u32, &BlobHash)>) -> ContentResult,
) -> TreeMerge {
    let mut all_paths: BTreeSet<PathLike> = BTreeSet::new();
    for p in base.keys().chain(ours.keys()).chain(theirs.keys()) {
        all_paths.insert(p.clone());
    }

    let mut merged: BTreeMap<PathLike, (u32, BlobHash)> = BTreeMap::new();
    let mut conflicts: Vec<TreeConflict> = Vec::new();

    for path in &all_paths {
        let b = base.get(path).copied();
        let o = ours.get(path).copied();
        let t = theirs.get(path).copied();

        match (b, o, t) {
            (None, None, None) => {}
            (_, Some(o), Some(t)) if o == t => {
                // Both sides agree — including identical adds.
                merged.insert(path.clone(), o);
            }
            (Some(b), Some(o), Some(t)) if b == o => {
                // Only theirs changed.
                merged.insert(path.clone(), t);
            }
            (Some(b), Some(o), Some(t)) if b == t => {
                // Only ours changed.
                merged.insert(path.clone(), o);
            }
            (None, Some(o), Some(t)) if o != t => {
                // Add/add with different content.
                conflicts.push(TreeConflict {
                    path: path.clone(),
                    kind: ConflictKind::AddAdd,
                    base: None,
                    ours: Some(o),
                    theirs: Some(t),
                });
            }
            (Some(b), Some(o), None) if b == o => {
                // Theirs deleted, ours unchanged → take the delete.
            }
            (Some(b), None, Some(t)) if b == t => {
                // Ours deleted, theirs unchanged → take the delete.
            }
            (Some(b), Some(o), None) if b != o => {
                // Ours modified, theirs deleted.
                conflicts.push(TreeConflict {
                    path: path.clone(),
                    kind: ConflictKind::ModifyDelete,
                    base: Some(b),
                    ours: Some(o),
                    theirs: None,
                });
            }
            (Some(b), None, Some(t)) if b != t => {
                // Ours deleted, theirs modified.
                conflicts.push(TreeConflict {
                    path: path.clone(),
                    kind: ConflictKind::ModifyDelete,
                    base: Some(b),
                    ours: None,
                    theirs: Some(t),
                });
            }
            (None, Some(o), None) => {
                merged.insert(path.clone(), o);
            }
            (None, None, Some(t)) => {
                merged.insert(path.clone(), t);
            }
            (Some(_), None, None) => {
                // Both sides deleted.
            }
            (Some(b), Some(o), Some(t)) => {
                // Both sides changed. Mode collisions first.
                if o.0 != t.0 && o.0 != b.0 && t.0 != b.0 {
                    conflicts.push(TreeConflict {
                        path: path.clone(),
                        kind: ConflictKind::Mode,
                        base: Some(b),
                        ours: Some(o),
                        theirs: Some(t),
                    });
                    continue;
                }
                let mode = if o.0 == b.0 { t.0 } else { o.0 };
                match resolve_content(path, (o.0, &o.1), (t.0, &t.1), Some((b.0, &b.1))) {
                    ContentResult::Resolved(hash) => {
                        merged.insert(path.clone(), (mode, hash));
                    }
                    ContentResult::Conflict { ours_hash, theirs_hash } => {
                        conflicts.push(TreeConflict {
                            path: path.clone(),
                            kind: ConflictKind::Content,
                            base: Some(b),
                            ours: Some((o.0, ours_hash)),
                            theirs: Some((t.0, theirs_hash)),
                        });
                    }
                }
            }
            _ => {
                // All other combinations were handled above; fall through to
                // a content conflict as a safe default.
                conflicts.push(TreeConflict {
                    path: path.clone(),
                    kind: ConflictKind::Content,
                    base: b,
                    ours: o,
                    theirs: t,
                });
            }
        }
    }

    TreeMerge { merged, conflicts }
}

/// Outcome of a per-file content merge attempt.
pub enum ContentResult {
    Resolved(BlobHash),
    Conflict {
        ours_hash: BlobHash,
        theirs_hash: BlobHash,
    },
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;

    fn lines_of(s: &str) -> Vec<Vec<u8>> {
        diff::split_lines(s.as_bytes())
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect()
    }

    #[test]
    fn identical_sides_are_clean() {
        let m = merge_lines(b"a\nb\nc\n", b"a\nb\nc\n", b"a\nb\nc\n");
        assert!(m.clean);
    }

    #[test]
    fn only_ours_wins() {
        let m = merge_lines(b"a\nb\nc\n", b"a\nB\nc\n", b"a\nb\nc\n");
        assert!(m.clean);
        let merged = render_with_markers(&m, "ours", "theirs");
        assert_eq!(merged, b"a\nB\nc\n");
    }

    #[test]
    fn only_theirs_wins() {
        let m = merge_lines(b"a\nb\nc\n", b"a\nb\nc\n", b"a\nb\nC\n");
        assert!(m.clean);
        let merged = render_with_markers(&m, "ours", "theirs");
        assert_eq!(merged, b"a\nb\nC\n");
    }

    #[test]
    fn disjoint_changes_merge_cleanly() {
        let m = merge_lines(
            b"line1\nline2\nline3\nline4\n",
            b"OURS\nline2\nline3\nline4\n",
            b"line1\nline2\nline3\nTHEIRS\n",
        );
        assert!(m.clean, "{:?}", m.chunks);
        let merged = render_with_markers(&m, "o", "t");
        assert_eq!(merged, b"OURS\nline2\nline3\nTHEIRS\n");
    }

    #[test]
    fn overlapping_change_conflicts() {
        let m = merge_lines(b"a\n", b"A\n", b"X\n");
        assert!(!m.clean);
        let merged = render_with_markers(&m, "ours", "theirs");
        let s = std::str::from_utf8(&merged).unwrap();
        assert!(s.contains("<<<<<<< ours"));
        assert!(s.contains("======="));
        assert!(s.contains(">>>>>>> theirs"));
        assert!(s.contains('A'));
        assert!(s.contains('X'));
    }

    #[test]
    fn appended_lines_clean() {
        let m = merge_lines(b"a\n", b"a\nB\n", b"a\nC\n");
        // Same insertion site — conflicts.
        assert!(!m.clean);
    }

    #[test]
    fn deleted_by_both_clean() {
        let m = merge_lines(b"a\nb\nc\n", b"a\nc\n", b"a\nc\n");
        assert!(m.clean);
        let merged = render_with_markers(&m, "o", "t");
        assert_eq!(merged, b"a\nc\n");
    }

    fn id(b: u8) -> BlobHash {
        crate::hash::ObjectId([b; 32])
    }

    fn entries(items: &[(&str, u32, BlobHash)]) -> BTreeMap<PathLike, (u32, BlobHash)> {
        let mut m = BTreeMap::new();
        for (p, mode, h) in items {
            m.insert(std::path::PathBuf::from(p), (*mode, *h));
        }
        m
    }

    #[test]
    fn tree_merge_disjoint_paths_clean() {
        let base = entries(&[("a", 0o100_644, id(1))]);
        let ours = entries(&[("a", 0o100_644, id(1)), ("b", 0o100_644, id(2))]);
        let theirs = entries(&[("a", 0o100_644, id(1)), ("c", 0o100_644, id(3))]);
        let tm = merge_trees(&base, &ours, &theirs, |_, _, _, _| {
            ContentResult::Conflict {
                ours_hash: id(0),
                theirs_hash: id(0),
            }
        });
        assert!(tm.conflicts.is_empty(), "{:?}", tm.conflicts);
        assert_eq!(tm.merged.len(), 3);
    }

    #[test]
    fn tree_merge_add_add_conflict() {
        let base = entries(&[]);
        let ours = entries(&[("x", 0o100_644, id(1))]);
        let theirs = entries(&[("x", 0o100_644, id(2))]);
        let tm = merge_trees(&base, &ours, &theirs, |_, _, _, _| {
            ContentResult::Conflict {
                ours_hash: id(1),
                theirs_hash: id(2),
            }
        });
        assert_eq!(tm.conflicts.len(), 1);
        assert!(matches!(tm.conflicts[0].kind, ConflictKind::AddAdd));
    }

    #[test]
    fn tree_merge_modify_delete_conflict() {
        let base = entries(&[("x", 0o100_644, id(1))]);
        let ours = entries(&[("x", 0o100_644, id(2))]);
        let theirs = entries(&[]);
        let tm = merge_trees(&base, &ours, &theirs, |_, _, _, _| {
            ContentResult::Conflict {
                ours_hash: id(2),
                theirs_hash: id(0),
            }
        });
        assert_eq!(tm.conflicts.len(), 1);
        assert!(matches!(tm.conflicts[0].kind, ConflictKind::ModifyDelete));
    }

    #[test]
    fn tree_merge_calls_resolver_for_content_overlap() {
        let base = entries(&[("x", 0o100_644, id(1))]);
        let ours = entries(&[("x", 0o100_644, id(2))]);
        let theirs = entries(&[("x", 0o100_644, id(3))]);
        let resolved = id(99);
        let tm = merge_trees(&base, &ours, &theirs, |_, _, _, _| {
            ContentResult::Resolved(resolved)
        });
        assert!(tm.conflicts.is_empty());
        assert_eq!(tm.merged.get(std::path::Path::new("x")).copied().unwrap(),
                   (0o100_644, resolved));
        let _ = lines_of;
    }
}
