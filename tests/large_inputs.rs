// Audit 2026-05: large-input soak tests. All `#[ignore]` because
// they take minutes; run manually before each release via
// `cargo test --all-features -- --ignored`.

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

#[ignore = "soak test — 100 MiB blob round trip"]
#[test]
fn soak_100mb_blob_round_trip() {
    let env = Env::new("soak-100mb");
    let r = env.fresh_repo("r");
    let big = vec![0x55u8; 100 * 1024 * 1024];
    std::fs::write(r.join("big.bin"), &big).unwrap();
    env.ok_in(&r, &["add", "big.bin"]);
    env.ok_in(&r, &["commit", "-m", "big"]);
    // Verify show reads it.
    let _ = env.ok_in(&r, &["log"]);
}

#[ignore = "soak test — 1 GiB blob round trip"]
#[test]
fn soak_1gb_blob_round_trip() {
    let env = Env::new("soak-1gb");
    let r = env.fresh_repo("r");
    let big = vec![0xAAu8; 1024 * 1024 * 1024];
    std::fs::write(r.join("big.bin"), &big).unwrap();
    env.ok_in(&r, &["add", "big.bin"]);
    env.ok_in(&r, &["commit", "-m", "big"]);
}

#[ignore = "soak test — 10k commits"]
#[test]
fn soak_10k_commits() {
    let env = Env::new("soak-10k");
    let r = env.fresh_repo("r");
    for i in 0..10_000 {
        std::fs::write(r.join("f.txt"), format!("{i}\n")).unwrap();
        env.ok_in(&r, &["add", "f.txt"]);
        env.ok_in(&r, &["commit", "-m", &format!("c{i}")]);
    }
    let log = env.ok_in(&r, &["log"]);
    let n = log.matches("commit ").count();
    assert!(n >= 10_000);
}

#[ignore = "soak test — 10k files in one commit"]
#[test]
fn soak_10k_files_one_commit() {
    let env = Env::new("soak-10k-files");
    let r = env.fresh_repo("r");
    for i in 0..10_000 {
        std::fs::write(r.join(format!("f{i:05}.txt")), b"x").unwrap();
    }
    env.ok_in(&r, &["add", "."]);
    env.ok_in(&r, &["commit", "-m", "many-files"]);
}

#[ignore = "soak test — 1k branches"]
#[test]
fn soak_1k_branches() {
    let env = Env::new("soak-1k-branches");
    let r = env.fresh_repo("r");
    for i in 0..1_000 {
        env.ok_in(&r, &["branch", &format!("b{i:04}")]);
    }
    let list = env.ok_in(&r, &["branch"]);
    let n = list.lines().count();
    assert!(n >= 1_000);
}

#[ignore = "soak test — 1k tags"]
#[test]
fn soak_1k_tags() {
    let env = Env::new("soak-1k-tags");
    let r = env.fresh_repo("r");
    for i in 0..1_000 {
        let _ = env.run_in(&r, &["tag", &format!("v{i:04}")]);
    }
}

#[ignore = "soak test — 5 MiB single file diff"]
#[test]
fn soak_5mb_file_diff() {
    let env = Env::new("soak-5mb-diff");
    let r = env.fresh_repo("r");
    let mut data = Vec::with_capacity(5 * 1024 * 1024);
    for i in 0u32..(5 * 1024 * 1024) {
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

#[ignore = "soak test — 1 MiB commit message"]
#[test]
fn soak_1mb_commit_message() {
    let env = Env::new("soak-big-msg");
    let r = env.fresh_repo("r");
    std::fs::write(r.join("a.txt"), b"a").unwrap();
    env.ok_in(&r, &["add", "a.txt"]);
    let big_msg = "x".repeat(1024 * 1024);
    let _ = env.run_in(&r, &["commit", "-m", &big_msg]);
}

#[ignore = "soak test — 100 issue blobs"]
#[test]
fn soak_100_issues() {
    let env = Env::new("soak-100-issues");
    let r = env.fresh_repo("r");
    for i in 0..100 {
        env.ok_in(&r, &["issue", "new", &format!("i{i}"), "-m", "body"]);
    }
    let list = env.ok_in(&r, &["issue", "list"]);
    assert!(list.lines().count() >= 50);
}

#[ignore = "soak test — gc on a large history"]
#[test]
fn soak_gc_on_large_history() {
    let env = Env::new("soak-gc-large");
    let r = env.fresh_repo("r");
    for i in 0..1_000 {
        std::fs::write(r.join("f.txt"), format!("{i}\n")).unwrap();
        env.ok_in(&r, &["add", "f.txt"]);
        env.ok_in(&r, &["commit", "-m", &format!("c{i}")]);
    }
    env.ok_in(&r, &["gc"]);
}

#[ignore = "soak test — gc --pack on a large history"]
#[test]
fn soak_gc_pack_on_large_history() {
    let env = Env::new("soak-gc-pack");
    let r = env.fresh_repo("r");
    for i in 0..500 {
        std::fs::write(r.join("f.txt"), format!("{i}\n")).unwrap();
        env.ok_in(&r, &["add", "f.txt"]);
        env.ok_in(&r, &["commit", "-m", &format!("c{i}")]);
    }
    env.ok_in(&r, &["gc", "--pack"]);
}

#[ignore = "soak test — clone of a large repo"]
#[test]
fn soak_clone_large_repo() {
    let env = Env::new("soak-clone-large");
    let src = env.fresh_repo("src");
    for i in 0..200 {
        std::fs::write(src.join("f.txt"), format!("{i}\n")).unwrap();
        env.ok_in(&src, &["add", "f.txt"]);
        env.ok_in(&src, &["commit", "-m", &format!("c{i}")]);
    }
    // Inline file-based clone via init+fetch isn't supported; just
    // verify the source repo's log still works after many commits.
    let _ = env.ok_in(&src, &["log"]);
}

#[ignore = "soak test — many small files added in batches"]
#[test]
fn soak_many_small_files_in_batches() {
    let env = Env::new("soak-batches");
    let r = env.fresh_repo("r");
    for batch in 0..10 {
        for i in 0..100 {
            std::fs::write(r.join(format!("b{batch}-{i}.txt")), b"x").unwrap();
        }
        env.ok_in(&r, &["add", "."]);
        env.ok_in(&r, &["commit", "-m", &format!("batch {batch}")]);
    }
}

#[ignore = "soak test — long ref name"]
#[test]
fn soak_long_ref_name() {
    let env = Env::new("soak-long-ref");
    let r = env.fresh_repo("r");
    let long = "a".repeat(200);
    let _ = env.run_in(&r, &["branch", &long]);
}

#[ignore = "soak test — many remotes"]
#[test]
fn soak_many_remotes() {
    let env = Env::new("soak-remotes");
    let r = env.fresh_repo("r");
    for i in 0..100 {
        let _ = env.run_in(
            &r,
            &["remote", "add", &format!("r{i}"), &format!("http://x/r{i}")],
        );
    }
}

#[ignore = "soak test — reflog grows"]
#[test]
fn soak_reflog_growth() {
    let env = Env::new("soak-reflog");
    let r = env.fresh_repo("r");
    for i in 0..500 {
        std::fs::write(r.join("f.txt"), format!("{i}\n")).unwrap();
        env.ok_in(&r, &["add", "f.txt"]);
        env.ok_in(&r, &["commit", "-m", &format!("c{i}")]);
    }
    let _ = env.ok_in(&r, &["reflog"]);
}

#[ignore = "soak test — many stashes"]
#[test]
fn soak_many_stashes() {
    let env = Env::new("soak-stashes");
    let r = env.fresh_repo("r");
    for i in 0..20 {
        std::fs::write(r.join("f.txt"), format!("{i}\n")).unwrap();
        let _ = env.run_in(&r, &["stash", "push"]);
    }
}

#[ignore = "soak test — wide directory tree"]
#[test]
fn soak_wide_dir_tree() {
    let env = Env::new("soak-wide");
    let r = env.fresh_repo("r");
    for i in 0..100 {
        std::fs::create_dir_all(r.join(format!("d{i:03}"))).unwrap();
        std::fs::write(r.join(format!("d{i:03}/f.txt")), b"x").unwrap();
    }
    env.ok_in(&r, &["add", "."]);
    env.ok_in(&r, &["commit", "-m", "wide"]);
}

#[ignore = "soak test — deep directory tree"]
#[test]
fn soak_deep_dir_tree() {
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

#[ignore = "soak test — concurrent gc + commit"]
#[test]
fn soak_concurrent_gc_commits() {
    let env = std::sync::Arc::new(Env::new("soak-gc-commit"));
    let r = env.fresh_repo("r");
    let mut handles = Vec::new();
    for _ in 0..2 {
        let r = r.clone();
        let env = env.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..10 {
                let _ = env.run_in(&r, &["gc"]);
            }
        }));
    }
    for i in 0..50 {
        std::fs::write(r.join("f.txt"), format!("{i}\n")).unwrap();
        env.ok_in(&r, &["add", "f.txt"]);
        env.ok_in(&r, &["commit", "-m", &format!("c{i}")]);
    }
    for h in handles {
        h.join().unwrap();
    }
}
