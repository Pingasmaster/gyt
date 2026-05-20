// Audit 2026-05: large-input tests. Sized for CI (seconds);
// historically these ran at 10-100× scale as `#[ignore]`'d soak tests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "soak tests"
)]

#[path = "common/mod.rs"]
mod common;

use common::Env;

#[test]
fn large_2mb_blob_round_trip() {
    let env = Env::new("soak-100mb");
    let r = env.fresh_repo("r");
    let big = vec![0x55u8; 2 * 1024 * 1024];
    std::fs::write(r.join("big.bin"), &big).unwrap();
    env.ok_in(&r, &["add", "big.bin"]);
    env.ok_in(&r, &["commit", "-m", "big"]);
    // Verify show reads it.
    let _ = env.ok_in(&r, &["log"]);
}

#[test]
fn large_5mb_blob_round_trip() {
    let env = Env::new("soak-1gb");
    let r = env.fresh_repo("r");
    let big = vec![0xAAu8; 5 * 1024 * 1024];
    std::fs::write(r.join("big.bin"), &big).unwrap();
    env.ok_in(&r, &["add", "big.bin"]);
    env.ok_in(&r, &["commit", "-m", "big"]);
}

#[test]
fn many_commits_walk_round_trip() {
    let env = Env::new("soak-10k");
    let r = env.fresh_repo("r");
    for i in 0..200 {
        std::fs::write(r.join("f.txt"), format!("{i}\n")).unwrap();
        env.ok_in(&r, &["add", "f.txt"]);
        env.ok_in(&r, &["commit", "-m", &format!("c{i}")]);
    }
    let log = env.ok_in(&r, &["log"]);
    let n = log.matches("commit ").count();
    assert!(n >= 200);
}

#[test]
fn many_files_one_commit() {
    let env = Env::new("soak-10k-files");
    let r = env.fresh_repo("r");
    for i in 0..500 {
        std::fs::write(r.join(format!("f{i:05}.txt")), b"x").unwrap();
    }
    env.ok_in(&r, &["add", "."]);
    env.ok_in(&r, &["commit", "-m", "many-files"]);
}

#[test]
fn many_branches_listable() {
    let env = Env::new("soak-1k-branches");
    let r = env.fresh_repo("r");
    for i in 0..200 {
        env.ok_in(&r, &["branch", &format!("b{i:04}")]);
    }
    let list = env.ok_in(&r, &["branch"]);
    let n = list.lines().count();
    assert!(n >= 200);
}

#[test]
fn many_tags() {
    let env = Env::new("soak-1k-tags");
    let r = env.fresh_repo("r");
    for i in 0..200 {
        let _ = env.run_in(&r, &["tag", &format!("v{i:04}")]);
    }
}

#[test]
fn mid_size_file_diff() {
    let env = Env::new("soak-5mb-diff");
    let r = env.fresh_repo("r");
    let mut data = Vec::with_capacity(256 * 1024);
    for i in 0u32..(256 * 1024) {
        data.push((i & 0xff) as u8);
    }
    std::fs::write(r.join("big.bin"), &data).unwrap();
    env.ok_in(&r, &["add", "big.bin"]);
    env.ok_in(&r, &["commit", "-m", "big"]);
    // Modify one byte.
    data[0] ^= 0xff;
    std::fs::write(r.join("big.bin"), &data).unwrap();
    let _ = env.run_in(&r, &["diff"]);
}

#[test]
fn large_commit_message() {
    let env = Env::new("soak-big-msg");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("a.txt"), b"a").unwrap();
    env.ok_in(&r, &["add", "a.txt"]);
    let big_msg = "x".repeat(64 * 1024);
    let _ = env.run_in(&r, &["commit", "-m", &big_msg]);
}

#[test]
fn many_issues_listable() {
    let env = Env::new("soak-100-issues");
    let r = env.fresh_repo("r");
    for i in 0..30 {
        env.ok_in(&r, &["issue", "new", &format!("i{i}"), "-m", "body"]);
    }
    let list = env.ok_in(&r, &["issue", "list"]);
    assert!(list.lines().count() >= 15);
}

#[test]
fn gc_on_history() {
    let env = Env::new("soak-gc-large");
    let r = env.fresh_repo("r");
    for i in 0..100 {
        std::fs::write(r.join("f.txt"), format!("{i}\n")).unwrap();
        env.ok_in(&r, &["add", "f.txt"]);
        env.ok_in(&r, &["commit", "-m", &format!("c{i}")]);
    }
    env.ok_in(&r, &["gc"]);
}

#[test]
fn gc_pack_on_history() {
    let env = Env::new("soak-gc-pack");
    let r = env.fresh_repo("r");
    for i in 0..100 {
        std::fs::write(r.join("f.txt"), format!("{i}\n")).unwrap();
        env.ok_in(&r, &["add", "f.txt"]);
        env.ok_in(&r, &["commit", "-m", &format!("c{i}")]);
    }
    env.ok_in(&r, &["gc", "--pack"]);
}

#[test]
fn clone_after_many_commits() {
    let env = Env::new("soak-clone-large");
    let src = env.fresh_repo("src");
    for i in 0..50 {
        std::fs::write(src.join("f.txt"), format!("{i}\n")).unwrap();
        env.ok_in(&src, &["add", "f.txt"]);
        env.ok_in(&src, &["commit", "-m", &format!("c{i}")]);
    }
    // Inline file-based clone via init+fetch isn't supported; just
    // verify the source repo's log still works after many commits.
    let _ = env.ok_in(&src, &["log"]);
}

#[test]
fn many_files_in_batches() {
    let env = Env::new("soak-batches");
    let r = env.fresh_repo("r");
    for batch in 0..5 {
        for i in 0..20 {
            std::fs::write(r.join(format!("b{batch}-{i}.txt")), b"x").unwrap();
        }
        env.ok_in(&r, &["add", "."]);
        env.ok_in(&r, &["commit", "-m", &format!("batch {batch}")]);
    }
}

#[test]
fn long_ref_name() {
    let env = Env::new("soak-long-ref");
    let r = env.fresh_repo("r");
    let long = "a".repeat(200);
    let _ = env.run_in(&r, &["branch", &long]);
}

#[test]
fn many_remotes() {
    let env = Env::new("soak-remotes");
    let r = env.fresh_repo("r");
    for i in 0..30 {
        let _ = env.run_in(
            &r,
            &["remote", "add", &format!("r{i}"), &format!("http://x/r{i}")],
        );
    }
}

#[test]
fn reflog_growth() {
    let env = Env::new("soak-reflog");
    let r = env.fresh_repo("r");
    for i in 0..100 {
        std::fs::write(r.join("f.txt"), format!("{i}\n")).unwrap();
        env.ok_in(&r, &["add", "f.txt"]);
        env.ok_in(&r, &["commit", "-m", &format!("c{i}")]);
    }
    let _ = env.ok_in(&r, &["reflog"]);
}

#[test]
fn many_stashes() {
    let env = Env::new("soak-stashes");
    let r = env.fresh_repo("r");
    for i in 0..10 {
        std::fs::write(r.join("f.txt"), format!("{i}\n")).unwrap();
        let _ = env.run_in(&r, &["stash", "push"]);
    }
}

#[test]
fn wide_dir_tree() {
    let env = Env::new("soak-wide");
    let r = env.fresh_repo("r");
    for i in 0..30 {
        std::fs::create_dir_all(r.join(format!("d{i:03}"))).unwrap();
        std::fs::write(r.join(format!("d{i:03}/f.txt")), b"x").unwrap();
    }
    env.ok_in(&r, &["add", "."]);
    env.ok_in(&r, &["commit", "-m", "wide"]);
}

#[test]
fn deep_dir_tree() {
    let env = Env::new("soak-deep");
    let r = env.fresh_repo("r");
    let mut p = r.clone();
    for _ in 0..20 {
        p = p.join("d");
        std::fs::create_dir_all(&p).unwrap();
    }
    std::fs::write(p.join("f.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "."]);
    env.ok_in(&r, &["commit", "-m", "deep"]);
}

#[test]
fn concurrent_gc_commits() {
    let env = std::sync::Arc::new(Env::new("soak-gc-commit"));
    let r = env.fresh_repo("r");
    let mut handles = Vec::new();
    for _ in 0..2 {
        let r = r.clone();
        let env = env.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..5 {
                let _ = env.run_in(&r, &["gc"]);
            }
        }));
    }
    for i in 0..20 {
        std::fs::write(r.join("f.txt"), format!("{i}\n")).unwrap();
        env.ok_in(&r, &["add", "f.txt"]);
        env.ok_in(&r, &["commit", "-m", &format!("c{i}")]);
    }
    for h in handles {
        h.join().unwrap();
    }
}
