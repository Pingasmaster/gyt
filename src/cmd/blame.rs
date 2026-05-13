// `gyt blame <path>` — line-by-line authorship report.
//
// Algorithm: starting from HEAD, walk the first-parent chain. For each
// commit, compute the line-level diff between the commit's version of
// <path> and its parent's version. Lines that are *inserted* by that
// commit are attributed to it; lines that survived from the parent
// continue to be attributed to whatever the parent walk decides.
//
// We walk from HEAD backward, carrying a vector of "pending" lines (each
// tagged with the commit that first introduced it as far as we know).
// When a commit changes a line, the line is marked done with that commit
// as its source. When we reach a root or run out of parents, any still-
// pending lines are attributed to the earliest commit we saw them in.
//
// This implementation uses the existing Myers diff. It's O(commits × diff)
// — fine for typical-size files. Renames are not followed; once the file
// disappears in a parent we stop the walk.

use crate::cmd::util;
use crate::diff;
use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::object::{blob, commit};
use crate::refs;
use crate::repo::Repo;
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> Result<()> {
    let mut rev: Option<String> = None;
    let mut path: Option<String> = None;
    let mut after_dashes = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if after_dashes {
            if path.is_some() {
                return Err(GytError::InvalidArgument(
                    "blame: at most one <path> argument".into(),
                ));
            }
            path = Some(a.clone());
        } else {
            match a.as_str() {
                "-h" | "--help" => {
                    println!(
                        "gyt blame [<rev>] [--] <path>\n\n\
                         Show, for each line of <path> at <rev> (default HEAD),\n\
                         the commit and author that last modified it."
                    );
                    return Ok(());
                }
                "--" => after_dashes = true,
                other if !other.starts_with('-') => {
                    // First positional that's a path-existing file wins as
                    // <path>; an earlier positional becomes <rev>.
                    if path.is_some() && rev.is_some() {
                        return Err(GytError::InvalidArgument(
                            "blame: too many positional arguments".into(),
                        ));
                    }
                    // Greedy: treat the *last* positional as the path so
                    // `gyt blame HEAD~5 src/main.rs` works.
                    if rev.is_none() && path.is_some() {
                        // We already have a path; demote it to rev and take
                        // the new one as path.
                        rev = path.take();
                    }
                    if path.is_none() {
                        path = Some(other.to_string());
                    } else {
                        rev = Some(other.to_string());
                    }
                }
                other => {
                    return Err(GytError::InvalidArgument(format!(
                        "blame: unknown flag {other}"
                    )));
                }
            }
        }
        i += 1;
    }
    let path = path.ok_or_else(|| GytError::InvalidArgument("blame: <path> is required".into()))?;
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    let start = match rev {
        Some(r) => util::resolve_rev(&repo, &r)?,
        None => {
            let head = refs::read_head(&repo.gyt_dir)?;
            refs::resolve(&repo.gyt_dir, &head)?
                .ok_or_else(|| GytError::Repo("blame: HEAD has no commits".into()))?
        }
    };
    let lines = blame(&repo, &start, Path::new(&path))?;
    print_blame(&lines);
    Ok(())
}

/// One line of blame output.
pub struct BlameLine {
    pub commit: ObjectId,
    pub author: String,
    pub timestamp: i64,
    pub line: Vec<u8>,
}

/// Compute blame for `path` at the tree of `start`. Returns one entry per
/// line of the file, in file order.
pub fn blame(repo: &Repo, start: &ObjectId, path: &Path) -> Result<Vec<BlameLine>> {
    // 1. Read the file at <start>.
    let start_commit = commit::read(&repo.gyt_dir, start)?;
    let start_tree = util::flatten_tree(repo, &start_commit.tree)?;
    let (_mode, blob_id) = start_tree
        .get(&PathBuf::from(path))
        .copied()
        .ok_or_else(|| GytError::Repo(format!("blame: {} not in tree at {}", path.display(), start.to_hex())))?;
    let bytes = blob::read(&repo.gyt_dir, &blob_id)?;
    let cur_lines: Vec<Vec<u8>> = diff::split_lines(&bytes)
        .into_iter()
        .map(<[u8]>::to_vec)
        .collect();

    // `attribution[orig_idx]` is the commit that introduced original
    // line `orig_idx`. We carry a separate `cur_to_orig` map so the diff
    // walk can update the right slot even as we change coordinate
    // systems each iteration. Initially each current-side index maps to
    // the same original-side index.
    let mut attribution: Vec<Option<ObjectId>> = vec![None; cur_lines.len()];
    let mut cur_to_orig: Vec<usize> = (0..cur_lines.len()).collect();

    let mut cur_commit_id = *start;
    let mut cur_blob_lines = cur_lines.clone();
    loop {
        let c = commit::read(&repo.gyt_dir, &cur_commit_id)?;
        let Some(parent_id) = c.parents.first().copied() else {
            // Root commit reached. Any still-unattributed line was first
            // introduced in this commit.
            for slot in &mut attribution {
                if slot.is_none() {
                    *slot = Some(cur_commit_id);
                }
            }
            break;
        };
        let pc = commit::read(&repo.gyt_dir, &parent_id)?;
        let parent_tree = util::flatten_tree(repo, &pc.tree)?;
        let parent_blob = parent_tree.get(&PathBuf::from(path)).copied();
        let parent_bytes = match parent_blob {
            Some((_, h)) => blob::read(&repo.gyt_dir, &h).unwrap_or_default(),
            None => Vec::new(),
        };
        let parent_lines: Vec<Vec<u8>> = diff::split_lines(&parent_bytes)
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect();

        // Diff parent → current.
        let cur_refs: Vec<&[u8]> = cur_blob_lines.iter().map(Vec::as_slice).collect();
        let parent_refs: Vec<&[u8]> = parent_lines.iter().map(Vec::as_slice).collect();
        let ops = diff::myers(&parent_refs, &cur_refs);

        // Walk ops:
        //   Insert at current[n_idx]: line introduced by `cur_commit_id`;
        //                              pin attribution[cur_to_orig[n_idx]].
        //   Equal at current[n_idx]:  line survives from parent; carry its
        //                              cur_to_orig mapping into the new
        //                              parent-side cur_to_orig vector.
        //   Delete at parent[p_idx]: not in current — irrelevant for blame.
        let mut new_cur_to_orig: Vec<usize> = Vec::with_capacity(parent_lines.len());
        let mut p_idx = 0usize;
        let mut n_idx = 0usize;
        for op in &ops {
            match op {
                diff::DiffOp::Equal(_) => {
                    if n_idx < cur_to_orig.len() {
                        new_cur_to_orig.push(cur_to_orig[n_idx]);
                    }
                    p_idx += 1;
                    n_idx += 1;
                }
                diff::DiffOp::Insert(_) => {
                    if n_idx < cur_to_orig.len() {
                        let orig = cur_to_orig[n_idx];
                        if attribution[orig].is_none() {
                            attribution[orig] = Some(cur_commit_id);
                        }
                    }
                    n_idx += 1;
                }
                diff::DiffOp::Delete(_) => {
                    p_idx += 1;
                }
            }
        }
        let _ = p_idx;

        if parent_blob.is_none() {
            // Parent lacks the file; everything still unattributed must
            // have been introduced by `cur_commit_id`.
            for slot in &mut attribution {
                if slot.is_none() {
                    *slot = Some(cur_commit_id);
                }
            }
            break;
        }

        cur_commit_id = parent_id;
        cur_blob_lines = parent_lines;
        cur_to_orig = new_cur_to_orig;
    }
    // Final fallback: any line we never managed to attribute (shouldn't
    // happen in practice) gets pinned to `start` so output is well-formed.
    for slot in &mut attribution {
        if slot.is_none() {
            *slot = Some(*start);
        }
    }
    let attribution: Vec<ObjectId> =
        attribution.into_iter().map(Option::unwrap).collect();

    // Pre-fetch author/timestamp for each unique commit id.
    let mut info: std::collections::HashMap<ObjectId, (String, i64)> =
        std::collections::HashMap::new();
    for id in &attribution {
        if info.contains_key(id) {
            continue;
        }
        let c = commit::read(&repo.gyt_dir, id)?;
        let author = c.authors.first().cloned().unwrap_or_default();
        let ts = parse_committer_ts(&c.committer).unwrap_or(0);
        info.insert(*id, (author, ts));
    }

    let mut out = Vec::with_capacity(cur_lines.len());
    for (i, line) in cur_lines.into_iter().enumerate() {
        let commit_id = attribution[i];
        let (author, ts) = info.get(&commit_id).cloned().unwrap_or_default();
        out.push(BlameLine {
            commit: commit_id,
            author,
            timestamp: ts,
            line,
        });
    }
    Ok(out)
}

fn parse_committer_ts(s: &str) -> Option<i64> {
    let parts: Vec<&str> = s.rsplitn(3, ' ').collect();
    parts.get(1)?.parse().ok()
}

fn print_blame(lines: &[BlameLine]) {
    // Width of the longest author name, capped at 20 to keep output sane.
    let author_w = lines
        .iter()
        .map(|l| short_author(&l.author).len())
        .max()
        .unwrap_or(0)
        .min(20);
    for (i, l) in lines.iter().enumerate() {
        let hex = l.commit.to_hex();
        let short = &hex[..hex.len().min(8)];
        let author = truncate(&short_author(&l.author), 20);
        let text = String::from_utf8_lossy(&l.line);
        println!(
            "{short} ({author:<author_w$} {ts}) {n}: {text}",
            ts = l.timestamp,
            n = i + 1,
            author_w = author_w,
        );
    }
}

fn short_author(a: &str) -> String {
    // "Name <email> <ts> <tz>" → "Name"
    if let Some((name, _)) = a.split_once(" <") {
        return name.to_string();
    }
    a.to_string()
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    s.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test_support::TestRepo;
    use crate::cmd::util::test_helpers::lock;

    #[test]
    fn blame_attributes_initial_line_to_initial_commit() {
        let _g = lock();
        let r = TestRepo::new("gyt-blame-init");
        let repo = r.open();
        let head = refs::read_head(&repo.gyt_dir).unwrap();
        let head_id = refs::resolve(&repo.gyt_dir, &head).unwrap().unwrap();
        let lines = blame(&repo, &head_id, Path::new("hello.txt")).unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].commit, head_id);
        assert!(String::from_utf8_lossy(&lines[0].line).starts_with("hello"));
    }

    #[test]
    fn blame_attributes_new_line_to_later_commit() {
        let _g = lock();
        let r = TestRepo::new("gyt-blame-grow");
        let repo = r.open();
        let initial = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        // Append a second line in a follow-up commit.
        let (second, _) = r.commit_next(&[("hello.txt", b"hello\nworld\n", false)]);
        let lines = blame(&repo, &second, Path::new("hello.txt")).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0].commit, initial, "first line from initial");
        assert_eq!(lines[1].commit, second, "second line from second");
    }
}
