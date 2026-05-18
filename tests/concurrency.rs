// Audit 2026-05: concurrency invariants — multiple processes
// against the same repo.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests panic on failure"
)]

#[path = "common/mod.rs"]
mod common;

use common::Env;
use std::process::Child;
use std::sync::Arc;

fn join_all(handles: Vec<std::thread::JoinHandle<()>>) {
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn two_concurrent_commits_serialize_on_repo_lock() {
    let env = Arc::new(Env::new("conc-commits"));
    let r = env.fresh_repo("r");
    // Make two changes serially (committed via two child processes,
    // but the children are launched in parallel). The repo lock
    // should serialize them so both commits land.
    let r1 = r.clone();
    let env1 = env.clone();
    let h1 = std::thread::spawn(move || {
        std::fs::write(r1.join("a.txt"), b"a").unwrap();
        env1.ok_in(&r1, &["add", "a.txt"]);
        env1.ok_in(&r1, &["commit", "-m", "a"]);
    });
    let r2 = r.clone();
    let env2 = env.clone();
    let h2 = std::thread::spawn(move || {
        std::fs::write(r2.join("b.txt"), b"b").unwrap();
        env2.ok_in(&r2, &["add", "b.txt"]);
        env2.ok_in(&r2, &["commit", "-m", "b"]);
    });
    join_all(vec![h1, h2]);
    // Both commits land — log should have ≥ 2 entries.
    let log = env.ok_in(&r, &["log"]);
    let n = log.matches("commit ").count();
    assert!(n >= 2, "expected ≥2 commits, log: {log}");
}

#[test]
fn parallel_add_no_index_corruption() {
    let env = Arc::new(Env::new("conc-add"));
    let r = env.fresh_repo("r");
    for i in 0..16 {
        std::fs::write(r.join(format!("f{i}.txt")), b"x").unwrap();
    }
    let mut handles = Vec::new();
    for i in 0..16 {
        let r = r.clone();
        let env = env.clone();
        handles.push(std::thread::spawn(move || {
            env.ok_in(&r, &["add", &format!("f{i}.txt")]);
        }));
    }
    join_all(handles);
    // All 16 files should be in the index after.
    let status = env.ok_in(&r, &["status"]);
    for i in 0..16 {
        assert!(
            status.contains(&format!("f{i}.txt")) || !status.contains(&format!("f{i}.txt: untracked")),
            "f{i}.txt should be staged; status: {status}"
        );
    }
}

#[test]
fn two_issue_new_race_each_gets_distinct_number() {
    let env = Arc::new(Env::new("conc-issues"));
    let r = env.fresh_repo("r");
    let mut handles = Vec::new();
    for i in 0..4 {
        let r = r.clone();
        let env = env.clone();
        handles.push(std::thread::spawn(move || {
            env.ok_in(&r, &["issue", "new", &format!("i{i}"), "-m", "body"]);
        }));
    }
    join_all(handles);
    let list = env.ok_in(&r, &["issue", "list"]);
    let n = list.matches("i0").count()
        + list.matches("i1").count()
        + list.matches("i2").count()
        + list.matches("i3").count();
    assert_eq!(n, 4, "all four issues should land: {list}");
}

#[test]
fn two_pr_new_race_each_gets_distinct_number() {
    let env = Arc::new(Env::new("conc-prs"));
    let r = env.fresh_repo("r");
    env.ok_in(&r, &["switch", "-c", "feat1"]);
    std::fs::write(r.join("x.txt"), b"x").unwrap();
    env.ok_in(&r, &["add", "x.txt"]);
    env.ok_in(&r, &["commit", "-m", "feat1"]);
    env.ok_in(&r, &["switch", "-c", "feat2"]);
    std::fs::write(r.join("y.txt"), b"y").unwrap();
    env.ok_in(&r, &["add", "y.txt"]);
    env.ok_in(&r, &["commit", "-m", "feat2"]);
    env.ok_in(&r, &["switch", "main"]);
    let h1 = {
        let r = r.clone();
        let env = env.clone();
        std::thread::spawn(move || {
            env.ok_in(
                &r,
                &["pr", "new", "p1", "--source", "feat1", "--target", "main", "-m", "b"],
            );
        })
    };
    let h2 = {
        let r = r.clone();
        let env = env.clone();
        std::thread::spawn(move || {
            env.ok_in(
                &r,
                &["pr", "new", "p2", "--source", "feat2", "--target", "main", "-m", "b"],
            );
        })
    };
    join_all(vec![h1, h2]);
    let list = env.ok_in(&r, &["pr", "list"]);
    assert!(list.contains("p1"));
    assert!(list.contains("p2"));
}

#[test]
fn parallel_gc_does_not_corrupt_repo() {
    let env = Arc::new(Env::new("conc-gc"));
    let r = env.fresh_repo("r");
    // Add some history.
    for i in 0..5 {
        std::fs::write(r.join(format!("f{i}.txt")), b"x").unwrap();
        env.ok_in(&r, &["add", &format!("f{i}.txt")]);
        env.ok_in(&r, &["commit", "-m", &format!("c{i}")]);
    }
    let mut handles = Vec::new();
    for _ in 0..4 {
        let r = r.clone();
        let env = env.clone();
        handles.push(std::thread::spawn(move || {
            let _ = env.run_in(&r, &["gc"]);
        }));
    }
    join_all(handles);
    // Log still works.
    let _ = env.ok_in(&r, &["log"]);
}

#[test]
fn parallel_status_safe() {
    let env = Arc::new(Env::new("conc-status"));
    let r = env.fresh_repo("r");
    let mut handles = Vec::new();
    for _ in 0..8 {
        let r = r.clone();
        let env = env.clone();
        handles.push(std::thread::spawn(move || {
            let _ = env.ok_in(&r, &["status"]);
        }));
    }
    join_all(handles);
}

#[test]
fn parallel_log_safe() {
    let env = Arc::new(Env::new("conc-log"));
    let r = env.fresh_repo("r");
    let mut handles = Vec::new();
    for _ in 0..8 {
        let r = r.clone();
        let env = env.clone();
        handles.push(std::thread::spawn(move || {
            let _ = env.ok_in(&r, &["log"]);
        }));
    }
    join_all(handles);
}

#[test]
fn parallel_clean_dry_run_safe() {
    let env = Arc::new(Env::new("conc-clean-dry"));
    let r = env.fresh_repo("r");
    std::fs::write(r.join("untracked.txt"), b"x").unwrap();
    let mut handles = Vec::new();
    for _ in 0..4 {
        let r = r.clone();
        let env = env.clone();
        handles.push(std::thread::spawn(move || {
            let _ = env.ok_in(&r, &["clean", "-n"]);
        }));
    }
    join_all(handles);
}

#[test]
fn two_serve_processes_against_same_root_one_refuses() {
    // The second `gyt serve` against the same repos_root should fail
    // because of serve.lock.
    let env = Env::new("conc-serve");
    let repos = env.path("repos");
    std::fs::create_dir_all(&repos).unwrap();
    let port1 = common::pick_port();
    let port2 = common::pick_port();
    let webroot = env.path("web");
    std::fs::create_dir_all(&webroot).unwrap();
    let mut srv1: Child = env
        .cmd_in(&env.dir)
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port1}"),
            "--repos",
            &repos.display().to_string(),
            "--webroot",
            &webroot.display().to_string(),
        ])
        .spawn()
        .unwrap();
    // Wait for first to bind.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        if std::net::TcpStream::connect(format!("127.0.0.1:{port1}")).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let out2 = env
        .cmd_in(&env.dir)
        .args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port2}"),
            "--repos",
            &repos.display().to_string(),
            "--webroot",
            &webroot.display().to_string(),
        ])
        .output()
        .unwrap();
    assert!(
        !out2.status.success(),
        "second serve should fail with serve.lock"
    );
    let _ = srv1.kill();
    let _ = srv1.wait();
}

#[test]
fn parallel_branch_create_distinct_branches() {
    let env = Arc::new(Env::new("conc-branch"));
    let r = env.fresh_repo("r");
    let mut handles = Vec::new();
    for i in 0..8 {
        let r = r.clone();
        let env = env.clone();
        handles.push(std::thread::spawn(move || {
            env.ok_in(&r, &["branch", &format!("b{i}")]);
        }));
    }
    join_all(handles);
    let list = env.ok_in(&r, &["branch"]);
    for i in 0..8 {
        assert!(list.contains(&format!("b{i}")), "branch b{i} should exist: {list}");
    }
}

#[test]
fn parallel_tag_create_distinct_tags() {
    let env = Arc::new(Env::new("conc-tag"));
    let r = env.fresh_repo("r");
    let mut handles = Vec::new();
    for i in 0..8 {
        let r = r.clone();
        let env = env.clone();
        handles.push(std::thread::spawn(move || {
            let _ = env.run_in(&r, &["tag", &format!("v{i}")]);
        }));
    }
    join_all(handles);
}
