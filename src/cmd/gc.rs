// `gyt gc` — garbage collect unreachable objects.
//
// Walks all refs (heads, tags, remotes) to compute reachable objects,
// then removes any loose object file whose hash is not reachable.

use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::object::{commit, store, tag, tree};
use crate::refs;
use crate::repo::Repo;
use std::collections::{HashSet, VecDeque};
use std::path::Path;

pub fn run(args: &[String]) -> Result<()> {
    // Default: expire reflog entries older than 90 days (matches git's
    // gc.reflogExpire default). Without this, commits referenced *only*
    // by the reflog stay reachable forever and gc reclaims nothing for
    // the common amend/reset/switch case.
    let mut expire_days: Option<u64> = Some(90);
    let mut pack = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                println!(
                    "gyt gc [--expire-reflog <days>] [--keep-reflog] [--pack]\n\n\
                     Prune unreachable loose objects from .gyt/objects.\n\n\
                     Reachability roots include every ref (heads, tags, remotes,\n\
                     stash), the detached HEAD if any, any in-progress merge /\n\
                     rebase / cherry-pick state, AND every reflog entry that is\n\
                     not yet expired.\n\n\
                     By default reflog entries older than 90 days are dropped\n\
                     before computing reachability, so commits kept alive only\n\
                     by the reflog (e.g. commit-amend orphans) eventually get\n\
                     reclaimed.\n\n\
                     --expire-reflog <days>   Drop reflog entries older than\n\
                                              <days> instead of the default 90.\n\
                                              Use 0 to wipe the whole reflog.\n\
                     --keep-reflog            Don't drop any reflog entries\n\
                                              (everything in the reflog stays\n\
                                              reachable; gc only reclaims\n\
                                              objects unreachable from any ref).\n\
                     --pack                   After pruning, batch the remaining\n\
                                              loose objects into a single pack\n\
                                              under .gyt/objects/pack/ and delete\n\
                                              the original loose files. Reads\n\
                                              after this still resolve those\n\
                                              objects (store.rs checks packs\n\
                                              when no loose file is present)."
                );
                return Ok(());
            }
            "--expire-reflog" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("--expire-reflog needs a value".into())
                })?;
                expire_days = Some(v.parse().map_err(|_| {
                    GytError::InvalidArgument(format!("--expire-reflog: not a number: {v}"))
                })?);
            }
            "--keep-reflog" => {
                expire_days = None;
            }
            "--pack" => {
                pack = true;
            }
            other if other.starts_with('-') => {
                return Err(GytError::InvalidArgument(format!(
                    "gc: unknown flag {other}"
                )));
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "gc: unexpected argument {other}"
                )));
            }
        }
        i += 1;
    }

    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;

    let expired = if let Some(days) = expire_days {
        expire_reflog(&repo.gyt_dir, days)
    } else {
        0
    };
    let count = gc(&repo.gyt_dir);
    let packed = if pack {
        pack_loose_objects(&repo.gyt_dir)?
    } else {
        0
    };
    if expired > 0 {
        println!("gc: expired {expired} reflog entries");
    }
    if count > 0 {
        println!("gc: pruned {count} unreachable objects");
    } else {
        println!("gc: no unreachable objects found");
    }
    if packed > 0 {
        println!("gc: packed {packed} loose objects");
    }
    Ok(())
}

/// Collect every loose object under `<gyt>/objects/<2>/<62>`, write
/// them into a single new pack file, then delete the loose files.
/// Returns the number of objects packed. Errors during deletion are
/// swallowed (the pack is what readers will look at next; a leftover
/// loose copy is harmless duplication, not corruption).
fn pack_loose_objects(gyt_dir: &Path) -> Result<usize> {
    use crate::object::pack::{PackEntry, write_pack};
    let objects_dir = gyt_dir.join("objects");
    let Ok(top) = std::fs::read_dir(&objects_dir) else {
        return Ok(0);
    };
    let mut entries: Vec<PackEntry> = Vec::new();
    let mut loose_paths: Vec<std::path::PathBuf> = Vec::new();
    for d in top.flatten() {
        let dir_path = d.path();
        if !dir_path.is_dir() {
            continue;
        }
        // Skip the pack subdirectory itself.
        if dir_path.file_name().and_then(|s| s.to_str()) == Some("pack") {
            continue;
        }
        let Ok(files) = std::fs::read_dir(&dir_path) else {
            continue;
        };
        for f in files.flatten() {
            let fp = f.path();
            if !fp.is_file() {
                continue;
            }
            let dir_name = dir_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let file_name = fp
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let hex = format!("{dir_name}{file_name}");
            if hex.len() != 64 {
                continue;
            }
            let Ok(id) = ObjectId::from_hex(&hex) else {
                continue;
            };
            let Ok(on_disk) = std::fs::read(&fp) else {
                continue;
            };
            // We need the kind for the entry; decode just enough.
            let raw = match crate::compress::decode(&on_disk) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let Ok((kind, _payload)) = crate::object::store::parse_raw(&raw) else {
                continue;
            };
            entries.push(PackEntry {
                id,
                kind,
                on_disk,
            });
            loose_paths.push(fp);
        }
    }
    if entries.is_empty() {
        return Ok(0);
    }
    let packed = entries.len();
    write_pack(gyt_dir, entries)?;
    // Only after the pack is durably on disk do we delete the loose
    // copies; if the rename fails, the loose objects stay readable.
    for p in &loose_paths {
        let _ = std::fs::remove_file(p);
    }
    Ok(packed)
}

/// Drop every reflog entry whose timestamp is older than `days` days.
/// `days == 0` truncates every reflog. Returns the number of entries
/// removed (across all refs). Best-effort: per-ref I/O errors are skipped.
fn expire_reflog(gyt_dir: &Path, days: u64) -> usize {
    let Ok(all) = crate::reflog::list_all(gyt_dir) else {
        return 0;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0i64, |d| d.as_secs() as i64);
    let cutoff = now.saturating_sub(days as i64 * 86_400);
    let mut removed = 0usize;
    for (refname, entries) in all {
        let keep: Vec<_> = entries.iter().filter(|e| e.timestamp >= cutoff).collect();
        let dropped = entries.len() - keep.len();
        if dropped == 0 {
            continue;
        }
        // Re-serialize the kept entries. Format must match `reflog::record`.
        let mut body = String::new();
        for e in &keep {
            use std::fmt::Write as _;
            let old_hex = match e.old {
                Some(o) => o.to_hex(),
                None => "0".repeat(64),
            };
            let _ = writeln!(
                body,
                "{old_hex}\t{}\t{}\t{}\t{}\t{}",
                e.new.to_hex(),
                e.who,
                e.timestamp,
                e.tz_offset,
                e.message
            );
        }
        let path = gyt_dir.join("logs").join(&refname);
        if body.is_empty() {
            let _ = std::fs::remove_file(&path);
        } else {
            let _ = crate::fs_util::atomic_write(&path, body.as_bytes());
        }
        removed += dropped;
    }
    removed
}

/// Run garbage collection: returns the number of objects pruned.
fn gc(gyt_dir: &Path) -> usize {
    // 1. Compute reachable set from all refs
    let reachable = compute_reachable(gyt_dir);

    // 2. Scan all loose objects
    let objects_dir = gyt_dir.join("objects");
    if !objects_dir.is_dir() {
        return 0;
    }

    let mut pruned = 0usize;

    let Ok(entries) = std::fs::read_dir(&objects_dir) else {
        return 0;
    };

    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // The file name is the hex suffix (everything after the first 2 chars).
        let dir_name = path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let hex = format!("{dir_name}{file_name}");
        if hex.len() != 64 {
            continue;
        }
        if let Ok(id) = ObjectId::from_hex(&hex)
            && !reachable.contains(&id)
        {
            let _ = std::fs::remove_file(&path);
            pruned += 1;
        }
    }

    pruned
}

/// Walk every "anchor" that proves an object is alive — branch tips,
/// tag tips, remote-tracking refs, the stash chain, a detached HEAD,
/// and any in-progress merge/cherry-pick/rebase state — then close
/// over the parent/tree/blob graph. Anything not in the resulting
/// set is fair game for pruning.
fn compute_reachable(gyt_dir: &Path) -> HashSet<ObjectId> {
    let mut reachable: HashSet<ObjectId> = HashSet::new();

    let mut seeds: Vec<ObjectId> = Vec::new();

    // refs/heads/, refs/tags/, refs/remotes/, refs/stash (single ref).
    for prefix in ["refs/heads", "refs/tags", "refs/remotes"] {
        if let Ok(rs) = refs::list_refs(gyt_dir, prefix) {
            for (_, id) in rs {
                seeds.push(id);
            }
        }
    }
    if let Ok(id) = refs::read_ref(gyt_dir, "refs/stash") {
        seeds.push(id);
    }

    // Detached HEAD: if HEAD points at a commit directly rather than at
    // a branch ref, that commit is otherwise unanchored.
    if let Ok(head) = refs::read_head(gyt_dir)
        && let refs::Head::Detached(id) = head
    {
        seeds.push(id);
    }

    // In-progress operations have their own short-lived "tip refs"
    // stored as plain hex files at the gyt_dir root. Treat anything
    // mentioned in them as reachable so an interrupted merge/rebase
    // can't be GC'd out from under the user.
    for sticky in ["MERGE_HEAD", "CHERRY_PICK_HEAD", "REBASE_HEAD", "REBASE_ONTO"] {
        if let Ok(s) = std::fs::read_to_string(gyt_dir.join(sticky))
            && let Ok(id) = ObjectId::from_hex(s.trim())
        {
            seeds.push(id);
        }
    }
    if let Ok(text) = std::fs::read_to_string(gyt_dir.join("REBASE_TODO")) {
        for line in text.lines() {
            if let Ok(id) = ObjectId::from_hex(line.trim()) {
                seeds.push(id);
            }
        }
    }

    // Reflog entries also reference commits; we treat reflog targets as
    // reachable so `gyt reflog`/recovery still works after gc.
    if let Ok(all) = crate::reflog::list_all(gyt_dir) {
        for (_, entries) in all {
            for e in entries {
                if let Some(old) = e.old {
                    seeds.push(old);
                }
                seeds.push(e.new);
            }
        }
    }

    // Walk closure from all seeds
    let mut queue: VecDeque<ObjectId> = seeds.into_iter().collect();
    while let Some(id) = queue.pop_front() {
        if !reachable.insert(id) {
            continue;
        }
        if !store::exists(gyt_dir, &id) {
            continue;
        }
        let Ok(obj) = store::read(gyt_dir, &id) else {
            continue;
        };
        match obj.kind {
            crate::object::ObjectKind::Blob => {}
            crate::object::ObjectKind::Commit => {
                if let Ok(c) = commit::decode(&obj.payload) {
                    queue.push_back(c.tree);
                    for p in &c.parents {
                        queue.push_back(*p);
                    }
                }
            }
            crate::object::ObjectKind::Tree => {
                if let Ok(entries) = tree::decode(&obj.payload) {
                    for e in &entries {
                        queue.push_back(e.hash);
                    }
                }
            }
            crate::object::ObjectKind::Tag => {
                if let Ok(t) = tag::decode(&obj.payload) {
                    queue.push_back(t.target);
                }
            }
        }
    }

    reachable
}