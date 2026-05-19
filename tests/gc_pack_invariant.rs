// Audit 2026-05: pin the documented gc-pack invariants.
//
// `gyt gc`'s prune loop walks `<2hex>/<62hex>` directories only, skipping
// `pack/`. Pack-only unreachable objects are therefore RETAINED. We pin:
//   1. Objects packed into `.gyt/objects/pack/` are NOT pruned by gc.
//   2. A pack containing both reachable and unreachable objects survives.
//   3. Loose unreachable objects past the 60s grace are pruned.
//   4. Loose unreachable objects within the grace window are kept.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::duration_suboptimal_units,
    reason = "tests panic on failure"
)]

#[path = "common/mod.rs"]
mod common;

use common::Env;
use std::path::Path;
use std::time::{Duration, SystemTime};

fn count_pack_files(repo: &Path) -> usize {
    let pack_dir = repo.join(".gyt").join("objects").join("pack");
    let Ok(rd) = std::fs::read_dir(&pack_dir) else {
        return 0;
    };
    rd.flatten()
        .filter(|e| {
            e.path().is_file()
                && e.path()
                    .extension()
                    .and_then(|s| s.to_str())
                    .is_some_and(|s| s == "pack")
        })
        .count()
}

fn set_mtime(p: &Path, t: SystemTime) {
    let f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
    let times = std::fs::FileTimes::new().set_modified(t).set_accessed(t);
    f.set_times(times).unwrap();
}

// ─── 1. gc skips objects/pack/ entirely ─────────────────────────────

#[test]
fn gc_does_not_prune_objects_inside_packs() {
    let env = Env::new("gc-pack-skip");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);

    // Make several commits so we have loose objects to pack.
    for i in 0..3 {
        let name = format!("f{i}.txt");
        std::fs::write(repo.join(&name), format!("v{i}\n")).unwrap();
        env.ok_in(&repo, &["add", &name]);
        env.ok_in(&repo, &["commit", "-m", &format!("c{i}")]);
    }

    // Pack everything (and prune old loose).
    env.ok_in(&repo, &["gc", "--pack"]);
    let packs_after_pack = count_pack_files(&repo);
    assert!(
        packs_after_pack >= 1,
        "expected at least one .pack file after `gyt gc --pack`"
    );

    // Now make some content unreachable. Delete a branch / reset to
    // earlier — simplest: reset HEAD to first commit, dropping the
    // newer two. Then run gc again WITHOUT --pack and verify the
    // pack file still exists. The pack file may contain objects that
    // are now unreachable, but gc's prune loop does not enter pack/.
    let log = env.ok_in(&repo, &["log", "--oneline"]);
    // Find the very first commit hash from the log; it's the last
    // line of `log --oneline`.
    let first = log.lines().last().unwrap().split_whitespace().next().unwrap().to_string();
    env.ok_in(&repo, &["reset", "--hard", &first]);

    env.ok_in(&repo, &["gc"]);
    let packs_after_gc = count_pack_files(&repo);
    assert_eq!(
        packs_after_gc, packs_after_pack,
        "gc must not delete files inside .gyt/objects/pack/"
    );
}

// ─── 2. mixed-reachability pack survives prune ──────────────────────

#[test]
fn gc_pack_with_reachable_object_preserved() {
    let env = Env::new("gc-pack-mixed");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);

    for i in 0..4 {
        let name = format!("f{i}.txt");
        std::fs::write(repo.join(&name), format!("data {i}\n")).unwrap();
        env.ok_in(&repo, &["add", &name]);
        env.ok_in(&repo, &["commit", "-m", &format!("c{i}")]);
    }

    // Pack.
    env.ok_in(&repo, &["gc", "--pack"]);
    let n_packs = count_pack_files(&repo);
    assert!(n_packs >= 1);

    // Drop the tip — earlier commits + their trees + blobs are still
    // reachable from the new HEAD; the most-recent commit is now
    // unreachable. After gc the pack must still be on disk.
    let log = env.ok_in(&repo, &["log", "--oneline"]);
    // Pick the second-most-recent commit by line count.
    let lines: Vec<&str> = log.lines().collect();
    assert!(lines.len() >= 2);
    let second = lines[1].split_whitespace().next().unwrap().to_string();
    env.ok_in(&repo, &["reset", "--hard", &second]);

    env.ok_in(&repo, &["gc"]);
    assert_eq!(
        count_pack_files(&repo),
        n_packs,
        "pack containing reachable+unreachable mix must survive gc"
    );

    // And the reachable history must still be readable through `log`.
    let log_after = env.ok_in(&repo, &["log", "--oneline"]);
    assert!(
        log_after.lines().count() >= 1,
        "history reachable from HEAD must still be readable post-gc"
    );
}

// ─── 3. loose past grace → pruned ───────────────────────────────────

#[test]
fn gc_prunes_loose_unreachable_past_grace() {
    let env = Env::new("gc-loose-past-grace");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);
    std::fs::write(repo.join("a.txt"), b"x").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "first"]);

    // Place an unreachable loose blob and backdate it past grace.
    let shard = repo.join(".gyt").join("objects").join("cd");
    std::fs::create_dir_all(&shard).unwrap();
    let fpath = shard.join("e".repeat(62));
    std::fs::write(&fpath, b"orphan-bytes-not-decoded").unwrap();
    set_mtime(&fpath, SystemTime::now() - Duration::from_secs(60 * 60));

    env.ok_in(&repo, &["gc"]);
    assert!(
        !fpath.exists(),
        "loose unreachable object older than GC_GRACE_SECS must be pruned"
    );
}

// ─── 4. loose within grace → kept ───────────────────────────────────

#[test]
fn gc_keeps_loose_unreachable_within_grace() {
    let env = Env::new("gc-loose-within-grace");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);
    std::fs::write(repo.join("a.txt"), b"x").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "first"]);

    let shard = repo.join(".gyt").join("objects").join("ef");
    std::fs::create_dir_all(&shard).unwrap();
    let fpath = shard.join("0".repeat(62));
    std::fs::write(&fpath, b"recent-orphan").unwrap();
    // Mtime in the future so even under clock skew it's clearly within
    // the grace window (mirrors gc_race.rs).
    set_mtime(&fpath, SystemTime::now() + Duration::from_secs(5));

    env.ok_in(&repo, &["gc"]);
    assert!(
        fpath.exists(),
        "loose unreachable object within GC_GRACE_SECS must survive gc"
    );
}

// ─── 5. B2: orphan .pack (no matching .idx) past grace → swept ──────
//
// `object::pack::write_pack` writes `pack-<hex>.pack` first, then
// `pack-<hex>.idx`. A crash between the two leaves a `.pack` that no
// reader will ever consult. Before the gc fix these accumulated as
// pure disk waste; after, gc reaps them once past GC_GRACE_SECS.

#[test]
fn gc_sweeps_orphan_pack_files_past_grace() {
    let env = Env::new("gc-orphan-pack-past");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);
    std::fs::write(repo.join("a.txt"), b"x").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "first"]);

    // Drop a `pack-<hex>.pack` with no matching `.idx`, backdated past
    // the grace window. Contents don't have to be a valid pack stream;
    // gc only inspects metadata + filename, never opens the bytes.
    let pack_dir = repo.join(".gyt").join("objects").join("pack");
    std::fs::create_dir_all(&pack_dir).unwrap();
    let stem = format!("pack-{}", "a".repeat(64));
    let orphan = pack_dir.join(format!("{stem}.pack"));
    std::fs::write(&orphan, b"not-a-real-pack-just-bytes").unwrap();
    set_mtime(&orphan, SystemTime::now() - Duration::from_secs(60 * 60));

    env.ok_in(&repo, &["gc"]);
    assert!(
        !orphan.exists(),
        "orphan .pack older than GC_GRACE_SECS must be swept by gc"
    );
}

#[test]
fn gc_keeps_orphan_pack_within_grace() {
    // Symmetric to above: a `.pack` without an `.idx` whose mtime is
    // within the grace window MUST be left alone — its `.idx` may
    // still be in flight from a concurrent write_pack call.
    let env = Env::new("gc-orphan-pack-within");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);
    std::fs::write(repo.join("a.txt"), b"x").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "first"]);

    let pack_dir = repo.join(".gyt").join("objects").join("pack");
    std::fs::create_dir_all(&pack_dir).unwrap();
    let stem = format!("pack-{}", "b".repeat(64));
    let orphan = pack_dir.join(format!("{stem}.pack"));
    std::fs::write(&orphan, b"in-flight-bytes").unwrap();
    // Mtime in the future puts it clearly inside the grace window.
    set_mtime(&orphan, SystemTime::now() + Duration::from_secs(5));

    env.ok_in(&repo, &["gc"]);
    assert!(
        orphan.exists(),
        "orphan .pack within GC_GRACE_SECS must survive gc"
    );
}

#[test]
fn gc_does_not_sweep_pack_with_matching_idx() {
    // Sanity-pin: a .pack with a sibling .idx is the normal case and
    // must NOT be touched by the new sweep.
    let env = Env::new("gc-pack-with-idx");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);
    std::fs::write(repo.join("a.txt"), b"x").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "first"]);

    let pack_dir = repo.join(".gyt").join("objects").join("pack");
    std::fs::create_dir_all(&pack_dir).unwrap();
    let stem = format!("pack-{}", "c".repeat(64));
    let pack = pack_dir.join(format!("{stem}.pack"));
    let idx = pack_dir.join(format!("{stem}.idx"));
    std::fs::write(&pack, b"pack-bytes").unwrap();
    std::fs::write(&idx, b"idx-bytes").unwrap();
    // Backdate both well past grace so age alone wouldn't save them.
    set_mtime(&pack, SystemTime::now() - Duration::from_secs(60 * 60));
    set_mtime(&idx, SystemTime::now() - Duration::from_secs(60 * 60));

    env.ok_in(&repo, &["gc"]);
    assert!(
        pack.exists(),
        ".pack with matching .idx must not be swept by gc"
    );
    assert!(
        idx.exists(),
        ".idx must not be swept by gc"
    );
}
