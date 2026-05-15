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
    // We hold *two* locks during gc:
    //   - refs.lock: serialises us against `gyt commit`, local `gyt push`,
    //     ref-update wire calls, and every other code path that mutates
    //     refs. The reachability walk is consistent with refs as of
    //     acquisition.
    //   - objects.lock (acquired inside `gc`): serialises us against the
    //     server's `wire_objects_have` so the *prune* step never observes
    //     a half-written upload.
    // Plus a "walk-started" grace inside the prune itself: any loose
    // object whose mtime is later than the moment we sampled the refs
    // is kept, regardless of reachability — we never had a chance to
    // see what could be about to reference it.
    let _lock = repo.lock()?;

    let expired = if let Some(days) = expire_days {
        expire_reflog(&repo.gyt_dir, days)
    } else {
        0
    };
    let count = gc(&repo)?;
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

/// Collect every loose object under `<gyt>/objects/<2>/<62>`, group
/// them into target-sized packs (default 4 MiB, override via
/// `GYT_PACK_TARGET_BYTES`), write each pack, then delete the loose
/// files for objects that successfully landed in a pack. Returns the
/// total number of objects packed.
///
/// Why multiple packs instead of one huge pack:
///
/// - At 1M objects per repo a single pack would be hundreds of MiB,
///   forcing readers to keep an O(1M) idx in memory and making
///   incremental pack rotation impossible (you'd have to rewrite the
///   whole pack every time you wanted to evict).
/// - Filesystem-level optimisations (ZFS recordsize, page-cache
///   prefetch, archival snapshots) favour packs sized to one
///   filesystem record. 4 MiB matches the recommended `recordsize=4M`
///   for ZFS-on-spinners with large-blob workloads.
/// - Inode pressure is what we're solving: N loose → N/(target_avg)
///   packs. For target=4 MiB and ~4 KiB average compressed object
///   that's a ~1000× inode reduction, which is the bottleneck the
///   1M-user audit identified.
///
/// `GYT_PACK_TARGET_BYTES=0` falls back to "one giant pack" — useful
/// for batch initial-import workflows where the operator wants the
/// fewest files possible.
fn pack_loose_objects(gyt_dir: &Path) -> Result<usize> {
    pack_loose_objects_at_target(gyt_dir, pack_target_bytes())
}

fn pack_loose_objects_at_target(gyt_dir: &Path, target: usize) -> Result<usize> {
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

    // Sort by id so the grouping is deterministic. Two `gyt gc --pack`
    // runs on the same object set produce identical packs (mod the
    // pack-content-hash filename, which is itself derived from those
    // bytes — so even the filenames match).
    let mut pairs: Vec<(PackEntry, std::path::PathBuf)> =
        entries.into_iter().zip(loose_paths).collect();
    pairs.sort_by_key(|(e, _)| e.id);

    let total_objects = pairs.len();

    // Group entries into batches summing to ≤ target compressed bytes.
    // target == 0 → one giant batch (legacy behaviour).
    let mut batches: Vec<Vec<(PackEntry, std::path::PathBuf)>> = Vec::new();
    let mut current: Vec<(PackEntry, std::path::PathBuf)> = Vec::new();
    let mut current_bytes: usize = 0;
    for pair in pairs {
        let sz = pair.0.on_disk.len();
        if target > 0 && !current.is_empty() && current_bytes + sz > target {
            batches.push(std::mem::take(&mut current));
            current_bytes = 0;
        }
        current.push(pair);
        current_bytes += sz;
    }
    if !current.is_empty() {
        batches.push(current);
    }

    let mut packed = 0usize;
    for batch in batches {
        let (batch_entries, batch_paths): (Vec<PackEntry>, Vec<std::path::PathBuf>) =
            batch.into_iter().unzip();
        let n = batch_entries.len();
        // Best-effort: if a single batch fails, abort the run but
        // leave already-packed loose copies alone. Their bytes are
        // safely duplicated in the corresponding new pack.
        write_pack(gyt_dir, batch_entries)?;
        for p in &batch_paths {
            let _ = std::fs::remove_file(p);
        }
        packed += n;
    }
    debug_assert_eq!(packed, total_objects);
    Ok(packed)
}

/// Read the operator-configured target pack size from
/// `GYT_PACK_TARGET_BYTES`. 0 disables splitting (single giant pack
/// — the pre-multi-pack behaviour). Default 4 MiB matches a typical
/// ZFS `recordsize=4M` deployment.
fn pack_target_bytes() -> usize {
    std::env::var("GYT_PACK_TARGET_BYTES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4 * 1024 * 1024)
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
        // Special-case days=0: drop every entry unconditionally, so the
        // documented "use 0 to wipe the whole reflog" behavior isn't
        // hostage to whether entries happened in the same wall-clock
        // second as gc itself.
        let keep: Vec<_> = if days == 0 {
            Vec::new()
        } else {
            entries.iter().filter(|e| e.timestamp >= cutoff).collect()
        };
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
/// Grace period: a loose object whose mtime is within this many seconds
/// of "now" is never pruned. The point is to give an in-flight push the
/// time to complete its refs/update after objects/have. objects.lock
/// closes the synchronous race; this closes the cross-request race
/// where objects/have completes, the connection ends, gc starts, gc
/// observes "no ref points here" — but refs/update is about to land.
///
/// 60s is a vast over-budget for an HTTP request pair on a healthy
/// network; an operator who needs to reclaim recently-orphaned objects
/// immediately can set GYT_GC_GRACE_SECS=0 in the environment.
const DEFAULT_GC_GRACE_SECS: u64 = 60;

fn gc_grace_secs() -> u64 {
    std::env::var("GYT_GC_GRACE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_GC_GRACE_SECS)
}

fn gc(repo: &Repo) -> Result<usize> {
    let gyt_dir = &repo.gyt_dir;
    // Acquire objects.lock for the duration of walk + prune. This
    // blocks concurrent wire_objects_have writes during the critical
    // section, so the walk's view of the object store is consistent
    // with disk. Combined with the time-based grace below, this closes
    // the documented gc / objects/have race in both its synchronous
    // (during) and cross-request (between objects/have and refs/update)
    // forms.
    let _objects_lock = repo.objects_lock()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let grace = std::time::Duration::from_secs(gc_grace_secs());
    let reachable = compute_reachable(gyt_dir);
    let objects_dir = gyt_dir.join("objects");
    if !objects_dir.is_dir() {
        return Ok(0);
    }

    let mut pruned = 0usize;
    // Loose objects live at `objects/<2-hex>/<62-hex>` — two-level sharding.
    // Earlier versions of this loop read only the top-level entries and
    // checked `is_file`, which silently skipped every loose object (they
    // are directories at that level) so gc had been a no-op. Walk the
    // shard directories explicitly. The `pack/` subdirectory and any
    // future non-shard child are recognised by their non-2-hex name.
    let Ok(top) = std::fs::read_dir(&objects_dir) else {
        return Ok(0);
    };
    for shard in top.flatten() {
        let shard_path = shard.path();
        if !shard_path.is_dir() {
            continue;
        }
        let shard_name = match shard_path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n,
            None => continue,
        };
        if shard_name.len() != 2 || !shard_name.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let Ok(files) = std::fs::read_dir(&shard_path) else {
            continue;
        };
        for f in files.flatten() {
            let fp = f.path();
            if !fp.is_file() {
                continue;
            }
            let file_name = match fp.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            if file_name.len() != 62 || !file_name.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            let hex = format!("{shard_name}{file_name}");
            let Ok(id) = ObjectId::from_hex(&hex) else {
                continue;
            };
            if !reachable.contains(&id) {
                // Grace: keep any object whose mtime is at-or-after
                // the moment we started the reachability walk. Those
                // objects can't legitimately be classified as orphan
                // because we never sampled the refs they might be
                // about to be referenced from. Combined with the
                // objects.lock held by both this prune and every
                // wire_objects_have call, the result is airtight:
                //
                //   walk_started=T0
                //   gc walks refs (sees state-at-T0)
                //   gc acquires objects.lock
                //     -- any concurrent wire_objects_have is either
                //        finished (object visible to gc) or queued
                //        behind the lock (object created at T1 > T0)
                //   for each loose object O:
                //     if reachable: keep
                //     else if mtime(O) >= T0: keep (race window)
                //     else: prune (was orphan before the walk)
                //
                // The pure-local case (operator runs `gyt gc` to
                // reclaim orphans they just created) is unaffected,
                // because the orphan-producing op finished before
                // walk_started.
                if let Ok(meta) = std::fs::metadata(&fp)
                    && let Ok(mtime) = meta.modified()
                    && let Ok(since_epoch) = mtime.duration_since(std::time::UNIX_EPOCH)
                    && now.saturating_sub(since_epoch) < grace
                {
                    continue;
                }
                let _ = std::fs::remove_file(&fp);
                pruned += 1;
            }
        }
    }
    Ok(pruned)
}

/// Walk every "anchor" that proves an object is alive — branch tips,
/// tag tips, remote-tracking refs, the stash chain, a detached HEAD,
/// and any in-progress merge/cherry-pick/rebase state — then close
/// over the parent/tree/blob graph. Anything not in the resulting
/// set is fair game for pruning.
fn compute_reachable(gyt_dir: &Path) -> HashSet<ObjectId> {
    let mut reachable: HashSet<ObjectId> = HashSet::new();
    // Commits listed in `.gyt/shallow` are the boundary of a shallow
    // clone — their parents are intentionally absent on disk. We treat
    // them as walk roots so the BFS doesn't try (and fail) to descend
    // through their missing parents. The boundary commits themselves
    // stay reachable through their normal ref ancestry.
    let shallow = read_shallow(gyt_dir);

    let mut seeds: Vec<ObjectId> = Vec::new();

    // Every user-visible ref namespace anchors its tips against pruning.
    //
    // refs/heads/, refs/tags/, refs/remotes/ are the version-control
    // namespaces. refs/issues/ and refs/prs/ are the metadata namespaces
    // (issues, discussions, pull requests) — without them in this list,
    // gc would silently delete every issue/PR blob. refs/stash is a
    // single ref outside any of these prefixes.
    for prefix in [
        "refs/heads",
        "refs/tags",
        "refs/remotes",
        "refs/issues",
        "refs/prs",
    ] {
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
                    // Stop descending past shallow boundary commits.
                    // Their parents weren't fetched and there's nothing
                    // to mark reachable on disk.
                    if !shallow.contains(&id) {
                        for p in &c.parents {
                            queue.push_back(*p);
                        }
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

/// Read `.gyt/shallow` into a set of boundary commit ids. The file is
/// written by `gyt clone --depth`; if it doesn't exist (a normal full
/// clone) we return an empty set.
fn read_shallow(gyt_dir: &Path) -> HashSet<ObjectId> {
    let Ok(text) = std::fs::read_to_string(gyt_dir.join("shallow")) else {
        return HashSet::new();
    };
    let mut out = HashSet::new();
    for line in text.lines() {
        if let Ok(id) = ObjectId::from_hex(line.trim()) {
            out.insert(id);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{ObjectKind, store};

    fn tmp_gyt(prefix: &str) -> std::path::PathBuf {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::create_dir_all(p.join("objects")).unwrap();
        p
    }

    #[test]
    fn pack_target_size_produces_multiple_packs() {
        let gyt = tmp_gyt("gyt-pack-target");
        // Write 12 loose objects with varied payloads so the
        // compressed sizes aren't all identical.
        let mut ids = Vec::new();
        for i in 0..12usize {
            let payload = vec![b'a' + (i as u8 % 26); 256 + i * 100];
            let id = store::write_bytes(&gyt, ObjectKind::Blob, &payload).unwrap();
            ids.push(id);
        }
        // Target 512 bytes per pack ⇒ several packs.
        let n_packed = pack_loose_objects_at_target(&gyt, 512).unwrap();
        assert_eq!(n_packed, 12);

        // Multiple packs expected.
        let pack_count = std::fs::read_dir(gyt.join("objects").join("pack"))
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.path().extension().and_then(|s| s.to_str()) == Some("pack")
            })
            .count();
        assert!(
            pack_count >= 2,
            "expected >=2 packs at 512-byte target, got {pack_count}"
        );

        // Every object still readable via store::read (which falls
        // through to the pack reader after a loose miss).
        for id in &ids {
            let obj = store::read(&gyt, id).expect("read after pack");
            assert_eq!(obj.id, *id);
        }

        // Loose copies removed.
        for id in &ids {
            let hex = id.to_hex();
            let p = gyt
                .join("objects")
                .join(&hex[..2])
                .join(&hex[2..]);
            assert!(!p.exists(), "loose copy not deleted: {}", p.display());
        }
        let _ = std::fs::remove_dir_all(&gyt);
    }

    #[test]
    fn pack_target_zero_yields_single_pack() {
        let gyt = tmp_gyt("gyt-pack-zero");
        for i in 0..8usize {
            let payload = format!("blob-{i}");
            let _ = store::write_bytes(&gyt, ObjectKind::Blob, payload.as_bytes()).unwrap();
        }
        let n = pack_loose_objects_at_target(&gyt, 0).unwrap();
        assert_eq!(n, 8);
        let pack_count = std::fs::read_dir(gyt.join("objects").join("pack"))
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                e.path().extension().and_then(|s| s.to_str()) == Some("pack")
            })
            .count();
        assert_eq!(pack_count, 1, "target=0 should produce one pack");
        let _ = std::fs::remove_dir_all(&gyt);
    }
}