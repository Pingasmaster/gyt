// Clone-side ref-namespace whitelist guard.
//
// CLAUDE.md (Issues / PRs / Incidents are in-repo refs) carves out a small,
// fixed set of `refs/<prefix>/...` namespaces that travel over the wire:
//   refs/heads/* refs/tags/* refs/issues/* refs/prs/* refs/incidents/*
// Anything else advertised by a (potentially hostile) server must be
// DROPPED by `gyt clone` — this is the namespace-injection guard called
// out in CLAUDE.md and implemented by `is_user_visible_ref` in
// `src/cmd/clone.rs`. These tests pin that contract end-to-end against
// the production `gyt serve` binary.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::zombie_processes,
    reason = "tests panic on failure; ServerGuard reaps the spawned child on drop"
)]

#[path = "common/mod.rs"]
mod common;

use common::{Env, pick_port};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

// ─── server scaffold (mirrors tests/server_hardening.rs:104-135) ─────

fn start_server(env: &Env, repos_root: &Path) -> (Child, u16) {
    let port = pick_port();
    let addr = format!("127.0.0.1:{port}");
    let webroot = env.path("web");
    std::fs::create_dir_all(&webroot).unwrap();
    let child = env
        .cmd_in(&env.dir)
        .args([
            "serve",
            "--listen",
            &addr,
            "--repos",
            &repos_root.display().to_string(),
            "--webroot",
            &webroot.display().to_string(),
        ])
        .env("GYT_SERVE_RATE_IP_CAPACITY", "0")
        .env("GYT_SERVE_RATE_ACTOR_CAPACITY", "0")
        .env("GYT_SERVE_CACHE_TTL_MS", "0")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(&addr).is_ok() {
            return (child, port);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("server didn't start");
}

struct ServerGuard(Child);
impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// ─── helpers ────────────────────────────────────────────────────────

/// Initialise a bare server repo seeded with one commit on `main`.
/// Returns (server-repo-dir, commit-id-hex) — the hex is reused as the
/// value of every planted ref so they all point at a real object.
fn seeded_bare(env: &Env, repos_root: &Path, name: &str) -> (PathBuf, String) {
    // Seed a working repo first; copy its `.gyt/` into the bare so we
    // have at least one real commit + its closure on disk.
    let seed = env.path(&format!("seed-{name}"));
    std::fs::create_dir_all(&seed).unwrap();
    env.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("a.txt"), b"hello\n").unwrap();
    env.ok_in(&seed, &["add", "a.txt"]);
    env.ok_in(&seed, &["commit", "-m", "first"]);
    let commit = std::fs::read_to_string(seed.join(".gyt/refs/heads/main"))
        .unwrap()
        .trim()
        .to_string();

    let bare = repos_root.join(name);
    std::fs::create_dir_all(&bare).unwrap();
    env.ok_in(&bare, &["init", "--bare"]);
    // Push the seed into the bare via local fs copy so the bare really
    // has the object closure (no network involved at this stage).
    copy_dir_recursive(&seed.join(".gyt/objects"), &bare.join(".gyt/objects"));
    // Write refs/heads/main directly so the bare's HEAD is consistent.
    plant_ref(&bare, "refs/heads/main", &commit);
    (bare, commit)
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    if !src.exists() {
        return;
    }
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

fn plant_ref(bare: &Path, name: &str, commit_hex: &str) {
    let p = bare.join(".gyt").join(name);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, format!("{commit_hex}\n")).unwrap();
}

// ─── 1. unwhitelisted server refs are dropped ────────────────────────

#[test]
fn clone_drops_unwhitelisted_server_refs() {
    let env = Env::new("clone-wl-drop");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(&repos_root).unwrap();
    let (bare, commit) = seeded_bare(&env, &repos_root, "r");

    // Plant out-of-whitelist refs on the server. All point at a real
    // commit so the server doesn't 500 when serving /info/refs.
    plant_ref(&bare, "refs/secret/x", &commit);
    plant_ref(&bare, "refs/notes/y", &commit);
    plant_ref(&bare, "refs/internal/z", &commit);

    let (srv, port) = start_server(&env, &repos_root);
    let _guard = ServerGuard(srv);
    let url = format!("http://127.0.0.1:{port}/r");

    let clone_dir = env.path("clone");
    env.ok_in(
        &env.dir,
        &["clone", "--insecure", &url, &clone_dir.display().to_string()],
    );

    // Whitelisted ref made it across.
    let cloned_main = clone_dir.join(".gyt/refs/heads/main");
    assert!(
        cloned_main.exists(),
        "expected refs/heads/main to be present after clone"
    );
    let got = std::fs::read_to_string(&cloned_main).unwrap();
    assert_eq!(got.trim(), commit, "cloned main does not point at server tip");

    // Out-of-whitelist refs MUST NOT have crossed.
    for bad in ["refs/secret/x", "refs/notes/y", "refs/internal/z"] {
        let p = clone_dir.join(".gyt").join(bad);
        assert!(
            !p.exists(),
            "namespace-injection guard failed: {bad} leaked into the clone at {}",
            p.display()
        );
    }
    // Also make sure nothing dumped an empty `refs/secret/` directory.
    for dir in ["refs/secret", "refs/notes", "refs/internal"] {
        let p = clone_dir.join(".gyt").join(dir);
        assert!(
            !p.exists(),
            "clone created an unwhitelisted namespace dir {dir}"
        );
    }
}

// ─── 2. whitelisted metadata namespaces ARE replicated ───────────────

#[test]
fn clone_replicates_issues_prs_incidents() {
    let env = Env::new("clone-wl-meta");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(&repos_root).unwrap();
    let (bare, commit) = seeded_bare(&env, &repos_root, "r");

    // All three metadata namespaces are whitelisted. We don't care
    // here that the value happens to be a commit id rather than a
    // blob id — the whitelist test is about the *ref name*, and
    // clone's reachability walk happily fetches the commit closure
    // and writes the ref verbatim.
    plant_ref(&bare, "refs/issues/1", &commit);
    plant_ref(&bare, "refs/prs/2", &commit);
    plant_ref(&bare, "refs/incidents/3", &commit);

    let (srv, port) = start_server(&env, &repos_root);
    let _guard = ServerGuard(srv);
    let url = format!("http://127.0.0.1:{port}/r");

    let clone_dir = env.path("clone");
    env.ok_in(
        &env.dir,
        &["clone", "--insecure", &url, &clone_dir.display().to_string()],
    );

    for want in [
        "refs/heads/main",
        "refs/issues/1",
        "refs/prs/2",
        "refs/incidents/3",
    ] {
        let p = clone_dir.join(".gyt").join(want);
        assert!(p.exists(), "expected {want} to replicate; missing at {}", p.display());
        let got = std::fs::read_to_string(&p).unwrap();
        assert_eq!(got.trim(), commit, "{want} not pointing at expected id");
    }
}

// ─── 3. empty server repo clones cleanly ─────────────────────────────

#[test]
fn clone_with_empty_server_repo() {
    let env = Env::new("clone-empty");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(repos_root.join("r")).unwrap();
    env.ok_in(&repos_root.join("r"), &["init", "--bare"]);

    let (srv, port) = start_server(&env, &repos_root);
    let _guard = ServerGuard(srv);
    let url = format!("http://127.0.0.1:{port}/r");

    let clone_dir = env.path("clone");
    env.ok_in(
        &env.dir,
        &["clone", "--insecure", &url, &clone_dir.display().to_string()],
    );

    // Valid `.gyt/` was created.
    let gyt = clone_dir.join(".gyt");
    assert!(gyt.is_dir(), "expected .gyt/ to be created");
    assert!(gyt.join("HEAD").is_file(), "expected .gyt/HEAD");
    assert!(gyt.join("refs").is_dir(), "expected .gyt/refs/");
    assert!(gyt.join("objects").is_dir(), "expected .gyt/objects/");

    // Origin remote was recorded. Config lives at `.gyt/config.toml`.
    let cfg = std::fs::read_to_string(gyt.join("config.toml")).unwrap_or_default();
    assert!(
        cfg.contains("origin") && cfg.contains(&url),
        "expected origin remote {url} in config.toml:\n{cfg}"
    );

    // No workdir files were materialised — only the dotdir exists.
    let mut workdir_files = Vec::new();
    for entry in std::fs::read_dir(&clone_dir).unwrap() {
        let e = entry.unwrap();
        let n = e.file_name().to_string_lossy().into_owned();
        if n != ".gyt" {
            workdir_files.push(n);
        }
    }
    assert!(
        workdir_files.is_empty(),
        "empty-server clone left workdir entries: {workdir_files:?}"
    );

    // Nothing got planted under refs/heads/ or any metadata namespace.
    for ns in ["refs/heads", "refs/tags", "refs/issues", "refs/prs", "refs/incidents"] {
        let p = gyt.join(ns);
        if p.is_dir() {
            let kids: Vec<_> = std::fs::read_dir(&p).unwrap().collect();
            assert!(
                kids.is_empty(),
                "{ns} should be empty after cloning an empty repo, found {} entries",
                kids.len()
            );
        }
    }
}
