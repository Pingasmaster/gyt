// `gyt push --force-with-lease` end-to-end behaviour.
//
// Lease semantics (see `src/cmd/push.rs:152+` and
// `src/net/refs_policy.rs::evaluate_with_mode`):
//
//   * The `old` value sent on the wire is the LOCAL cached tracking ref
//     `refs/remotes/<remote>/<branch>` — NOT the server's current tip.
//   * The server compares its on-disk tip against that `old`. If they
//     differ, the server returns 409 and the client surfaces a
//     lease-check error mentioning that the remote has moved.
//   * `--force` and `--force-with-lease` are mutually exclusive at the
//     CLI; passing both is `InvalidArgument`.

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

fn start_server_allow_force(env: &Env, repos_root: &Path) -> (Child, u16) {
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
            "--allow-force",
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

// ─── helpers ─────────────────────────────────────────────────────────

fn fresh_repo_with_one_commit(env: &Env, name: &str) -> PathBuf {
    let r = env.path(name);
    std::fs::create_dir_all(&r).unwrap();
    env.ok_in(&r, &["init"]);
    std::fs::write(r.join("seed.txt"), b"seed\n").unwrap();
    env.ok_in(&r, &["add", "seed.txt"]);
    env.ok_in(&r, &["commit", "-m", "seed"]);
    r
}

fn add_commit(env: &Env, repo: &Path, file: &str, body: &str, msg: &str) {
    std::fs::write(repo.join(file), body.as_bytes()).unwrap();
    env.ok_in(repo, &["add", file]);
    env.ok_in(repo, &["commit", "-m", msg]);
}

fn server_tip(server_repo: &Path) -> String {
    // Bare repos store refs directly at <root>/refs/heads/...; non-bare
    // repos under <root>/.gyt/refs/heads/...  Try both.
    let candidates = [
        server_repo.join("refs/heads/main"),
        server_repo.join(".gyt/refs/heads/main"),
    ];
    for c in &candidates {
        if let Ok(s) = std::fs::read_to_string(c) {
            return s.trim().to_string();
        }
    }
    panic!("no refs/heads/main found under {}", server_repo.display());
}

// ─── 1. happy path: lease holds, FF advance lands ────────────────────

#[test]
fn force_with_lease_happy_path() {
    let env = Env::new("lease-happy");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(repos_root.join("r")).unwrap();
    env.ok_in(&repos_root.join("r"), &["init", "--bare"]);
    let bare = repos_root.join("r");

    let (srv, port) = start_server_allow_force(&env, &repos_root);
    let _guard = ServerGuard(srv);
    let url = format!("http://127.0.0.1:{port}/r");

    let local = fresh_repo_with_one_commit(&env, "local");
    env.ok_in(&local, &["remote", "add", "origin", &url]);
    env.ok_in(&local, &["push", "--insecure", "origin", "main"]);

    // Fetch so the tracking ref is populated — `--force-with-lease`
    // reads it as the wire `old`.
    env.ok_in(&local, &["fetch", "--insecure", "origin"]);
    let tip_before = server_tip(&bare);

    // Linear FF advance.
    add_commit(&env, &local, "a.txt", "alpha\n", "advance");
    let local_tip = std::fs::read_to_string(local.join(".gyt/refs/heads/main"))
        .unwrap()
        .trim()
        .to_string();
    assert_ne!(local_tip, tip_before);

    env.ok_in(
        &local,
        &["push", "--insecure", "--force-with-lease", "origin", "main"],
    );

    let tip_after = server_tip(&bare);
    assert_eq!(
        tip_after, local_tip,
        "server should have advanced to the local tip; before={tip_before}, after={tip_after}"
    );
}

// ─── 2. stale lease: server moved out-of-band, push rejected ─────────

#[test]
fn force_with_lease_stale_rejected() {
    let env = Env::new("lease-stale");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(repos_root.join("r")).unwrap();
    env.ok_in(&repos_root.join("r"), &["init", "--bare"]);
    let bare = repos_root.join("r");

    let (srv, port) = start_server_allow_force(&env, &repos_root);
    let _guard = ServerGuard(srv);
    let url = format!("http://127.0.0.1:{port}/r");

    // Pusher A: initial commit, push, fetch (tracking = A).
    let alice = fresh_repo_with_one_commit(&env, "alice");
    env.ok_in(&alice, &["remote", "add", "origin", &url]);
    env.ok_in(&alice, &["push", "--insecure", "origin", "main"]);
    env.ok_in(&alice, &["fetch", "--insecure", "origin"]);
    let alice_tracking = std::fs::read_to_string(
        alice.join(".gyt/refs/remotes/origin/main"),
    )
    .unwrap()
    .trim()
    .to_string();

    // Pusher B (second local repo): clone, add commit, push.
    let bob = env.path("bob");
    env.ok_in(
        &env.dir,
        &["clone", "--insecure", &url, &bob.display().to_string()],
    );
    add_commit(&env, &bob, "b.txt", "bob\n", "bob-advance");
    env.ok_in(&bob, &["push", "--insecure", "origin", "main"]);
    let server_after_bob = server_tip(&bare);
    assert_ne!(
        server_after_bob, alice_tracking,
        "server should have moved past Alice's cached tracking ref"
    );

    // Alice (unaware) makes her own divergent commit and tries
    // --force-with-lease. Her tracking ref still says A but the
    // server is at B's tip → lease check must fail.
    add_commit(&env, &alice, "a.txt", "alpha\n", "alice-advance");
    let (_out, err) = env.fail_in(
        &alice,
        &["push", "--insecure", "--force-with-lease", "origin", "main"],
    );
    let lower = err.to_lowercase();
    assert!(
        lower.contains("lease")
            || lower.contains("remote has moved")
            || lower.contains("non-fast-forward")
            || err.contains("409"),
        "expected a lease-check error mentioning the remote moved; got:\n{err}"
    );

    // Server must still be at Bob's tip (NOT rolled back to Alice).
    let tip_now = server_tip(&bare);
    assert_eq!(
        tip_now, server_after_bob,
        "stale lease push must NOT have overwritten Bob's tip; \
         expected {server_after_bob}, got {tip_now}"
    );
}

// ─── 3. --force and --force-with-lease are mutually exclusive ────────

#[test]
fn force_and_force_with_lease_mutually_exclusive() {
    let env = Env::new("lease-mutex");
    let local = fresh_repo_with_one_commit(&env, "local");
    // Need a remote registered or the validator could short-circuit on
    // the unknown-remote error before parsing flags.
    env.ok_in(
        &local,
        &["remote", "add", "origin", "http://127.0.0.1:1/never"],
    );
    let (_out, err) = env.fail_in(
        &local,
        &[
            "push",
            "--insecure",
            "--force",
            "--force-with-lease",
            "origin",
            "main",
        ],
    );
    let lower = err.to_lowercase();
    assert!(
        lower.contains("mutually exclusive")
            || (lower.contains("--force") && lower.contains("--force-with-lease")),
        "expected a mutual-exclusion error; got:\n{err}"
    );
}
