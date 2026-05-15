// End-to-end tests for the `gyt pr` subcommand.

#![allow(clippy::too_many_lines)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::zombie_processes)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

fn find_binary() -> PathBuf {
    if let Ok(p) = std::env::var("GYT_BIN") {
        return PathBuf::from(p);
    }
    if let Some(p) = option_env!("CARGO_BIN_EXE_gyt") {
        return PathBuf::from(p);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for d in &["target/release/gyt", "target/debug/gyt"] {
        let c = root.join(d);
        if c.is_file() {
            return c;
        }
    }
    panic!("gyt binary not found");
}

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    l.local_addr().unwrap().port()
}

struct Env {
    bin: PathBuf,
    dir: PathBuf,
}

impl Env {
    fn new(label: &str) -> Self {
        let bin = find_binary();
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let dir = std::env::temp_dir().join(format!("gyt-prs-{label}-{pid}-{id}-{nanos}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self { bin, dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn cmd_in(&self, cwd: &Path) -> Command {
        let mut c = Command::new(&self.bin);
        c.current_dir(cwd)
            .env("GYT_AUTHOR_NAME", "Test User")
            .env("GYT_AUTHOR_EMAIL", "test@example.com")
            .env("HOME", &self.dir)
            .env_remove("XDG_CONFIG_HOME");
        c
    }

    fn run_in(&self, cwd: &Path, args: &[&str]) -> Output {
        self.cmd_in(cwd).args(args).output().unwrap()
    }

    #[track_caller]
    fn ok_in(&self, cwd: &Path, args: &[&str]) -> String {
        let o = self.run_in(cwd, args);
        assert!(
            o.status.success(),
            "gyt {} failed:\nstdout: {}\nstderr: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr),
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    #[track_caller]
    fn fail_in(&self, cwd: &Path, args: &[&str]) -> (String, String) {
        let o = self.run_in(cwd, args);
        assert!(!o.status.success(), "expected failure: gyt {}", args.join(" "));
        (
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn fresh_repo_with_branches(env: &Env, name: &str) -> PathBuf {
    let p = env.path(name);
    std::fs::create_dir_all(&p).unwrap();
    env.ok_in(&p, &["init"]);
    std::fs::write(p.join("a.txt"), b"hello").unwrap();
    env.ok_in(&p, &["add", "a.txt"]);
    env.ok_in(&p, &["commit", "-m", "first"]);
    // Create a topic branch with a divergent commit.
    env.ok_in(&p, &["switch", "-c", "topic"]);
    std::fs::write(p.join("b.txt"), b"feature").unwrap();
    env.ok_in(&p, &["add", "b.txt"]);
    env.ok_in(&p, &["commit", "-m", "feature"]);
    env.ok_in(&p, &["switch", "main"]);
    p
}

// ─── CRUD ────────────────────────────────────────────────────────────

#[test]
fn pr_new_requires_existing_source_and_target() {
    let env = Env::new("missing-ref");
    let repo = fresh_repo_with_branches(&env, "r");
    env.fail_in(
        &repo,
        &["pr", "new", "Add X", "--source", "no-such", "--target", "main"],
    );
    env.fail_in(
        &repo,
        &["pr", "new", "Add X", "--source", "topic", "--target", "no-such"],
    );
}

#[test]
fn pr_new_lists_and_shows() {
    let env = Env::new("new-list-show");
    let repo = fresh_repo_with_branches(&env, "r");
    let out = env.ok_in(
        &repo,
        &[
            "pr",
            "new",
            "Add feature",
            "--source",
            "topic",
            "--target",
            "main",
            "-m",
            "body refs #2",
        ],
    );
    assert!(out.contains("pr #1"), "got: {out}");

    let list = env.ok_in(&repo, &["pr", "list"]);
    assert!(list.contains("Add feature"));
    assert!(list.contains("topic"));
    assert!(list.contains("main"));

    let show = env.ok_in(&repo, &["pr", "show", "1"]);
    assert!(show.contains("source:"));
    assert!(show.contains("target:"));
    assert!(show.contains("body refs #2"));
    // mention extraction
    assert!(show.contains("#2"));
}

#[test]
fn pr_close_and_reopen() {
    let env = Env::new("close-reopen");
    let repo = fresh_repo_with_branches(&env, "r");
    env.ok_in(
        &repo,
        &["pr", "new", "x", "--source", "topic", "--target", "main", "-m", "b"],
    );
    env.ok_in(&repo, &["pr", "close", "1"]);
    let s = env.ok_in(&repo, &["pr", "show", "1"]);
    assert!(s.contains("[closed]"));
    env.ok_in(&repo, &["pr", "reopen", "1"]);
    let s2 = env.ok_in(&repo, &["pr", "show", "1"]);
    assert!(s2.contains("[open]"));
}

#[test]
fn pr_merge_ff_updates_target_and_marks_merged() {
    let env = Env::new("merge-ff");
    let repo = fresh_repo_with_branches(&env, "r");
    env.ok_in(
        &repo,
        &["pr", "new", "x", "--source", "topic", "--target", "main", "-m", "b"],
    );
    env.ok_in(&repo, &["pr", "merge", "1"]);
    let show = env.ok_in(&repo, &["pr", "show", "1"]);
    assert!(show.contains("[merged]"));
    // Target ref must now point at the topic tip.
    let log = env.ok_in(&repo, &["log", "--oneline"]);
    assert!(log.contains("feature"), "main should now contain feature commit: {log}");
}

#[test]
fn pr_merge_already_merged_blocks_close() {
    let env = Env::new("merged-close-blocked");
    let repo = fresh_repo_with_branches(&env, "r");
    env.ok_in(
        &repo,
        &["pr", "new", "x", "--source", "topic", "--target", "main", "-m", "b"],
    );
    env.ok_in(&repo, &["pr", "merge", "1"]);
    env.fail_in(&repo, &["pr", "close", "1"]);
    env.fail_in(&repo, &["pr", "reopen", "1"]);
}

#[test]
fn pr_source_target_must_differ() {
    let env = Env::new("same");
    let repo = fresh_repo_with_branches(&env, "r");
    env.fail_in(
        &repo,
        &["pr", "new", "x", "--source", "main", "--target", "main", "-m", "b"],
    );
}

#[test]
fn pr_state_filter() {
    let env = Env::new("state-filter");
    let repo = fresh_repo_with_branches(&env, "r");
    env.ok_in(&repo, &["pr", "new", "A", "--source", "topic", "--target", "main", "-m", "x"]);
    env.ok_in(&repo, &["pr", "close", "1"]);
    let open = env.ok_in(&repo, &["pr", "list"]);
    assert!(!open.contains("#   1"));
    let closed = env.ok_in(&repo, &["pr", "list", "--state", "closed"]);
    assert!(closed.contains("A"));
    let all = env.ok_in(&repo, &["pr", "list", "--state", "all"]);
    assert!(all.contains("A"));
}

#[test]
fn pr_labels_and_assignees() {
    let env = Env::new("labels-asg");
    let repo = fresh_repo_with_branches(&env, "r");
    env.ok_in(&repo, &["pr", "new", "x", "--source", "topic", "--target", "main", "-m", "b"]);
    env.ok_in(&repo, &["pr", "label", "1", "--add", "review,blocked"]);
    env.ok_in(&repo, &["pr", "assign", "1", "--add", "Reviewer <r@x>"]);
    let s = env.ok_in(&repo, &["pr", "show", "1"]);
    assert!(s.contains("review"));
    assert!(s.contains("Reviewer"));
}

// ─── ci-run ───────────────────────────────────────────────────────────

#[test]
fn pr_ci_run_records_pass_when_wasm_succeeds() {
    let env = Env::new("ci-pass");
    let repo = fresh_repo_with_branches(&env, "r");
    env.ok_in(&repo, &["pr", "new", "x", "--source", "topic", "--target", "main", "-m", "b"]);
    // Drop a trivial pass-wasm into .gyt-ci/
    let ci = repo.join(".gyt-ci");
    std::fs::create_dir_all(&ci).unwrap();
    std::fs::write(
        ci.join("noop.wat"),
        r#"(module (func (export "_start") (result i32) i32.const 0))"#,
    )
    .unwrap();
    // Rename .wat -> .wasm because gyt only globs .wasm extensions.
    std::fs::rename(ci.join("noop.wat"), ci.join("noop.wasm")).unwrap();
    env.ok_in(&repo, &["pr", "ci-run", "1"]);
    let s = env.ok_in(&repo, &["pr", "show", "1"]);
    assert!(s.contains("ci-run") && s.contains("pass"), "ci pass not recorded: {s}");
}

#[test]
fn pr_ci_run_records_fail_when_wasm_fails() {
    let env = Env::new("ci-fail");
    let repo = fresh_repo_with_branches(&env, "r");
    env.ok_in(&repo, &["pr", "new", "x", "--source", "topic", "--target", "main", "-m", "b"]);
    let ci = repo.join(".gyt-ci");
    std::fs::create_dir_all(&ci).unwrap();
    // Module that exits non-zero.
    std::fs::write(
        ci.join("fail.wasm"),
        r#"(module (func (export "_start") (result i32) i32.const 1))"#,
    )
    .unwrap();
    let (_, err) = env.fail_in(&repo, &["pr", "ci-run", "1"]);
    assert!(err.contains("fail") || err.contains("exit"));
    let s = env.ok_in(&repo, &["pr", "show", "1"]);
    assert!(s.contains("fail"), "ci fail not recorded: {s}");
}

#[test]
fn pr_ci_run_blocked_when_no_wasm() {
    let env = Env::new("ci-no-wasm");
    let repo = fresh_repo_with_branches(&env, "r");
    env.ok_in(&repo, &["pr", "new", "x", "--source", "topic", "--target", "main", "-m", "b"]);
    let (_, err) = env.fail_in(&repo, &["pr", "ci-run", "1"]);
    assert!(err.contains("no .wasm") || err.contains("no .gyt-ci"), "got: {err}");
}

// ─── push/clone ───────────────────────────────────────────────────────

fn start_server_with_acl(env: &Env, repos_root: &Path, acl_file: Option<&Path>) -> (Child, u16) {
    let port = pick_port();
    let addr = format!("127.0.0.1:{port}");
    let webroot = env.path("web");
    std::fs::create_dir_all(&webroot).unwrap();
    let mut cmd = env.cmd_in(&env.dir);
    cmd.args([
        "serve",
        "--listen",
        &addr,
        "--repos",
        &repos_root.display().to_string(),
        "--webroot",
        &webroot.display().to_string(),
    ])
    .env("GYT_SERVE_RATE_IP_CAPACITY", "0")
    .env("GYT_SERVE_RATE_ACTOR_CAPACITY", "0");
    if let Some(a) = acl_file {
        cmd.args(["--auth-tokens", &a.display().to_string()]);
    }
    let child = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if std::net::TcpStream::connect(&addr).is_ok() {
            return (child, port);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("server didn't start");
}

#[test]
fn pr_pushed_and_cloned_round_trip() {
    let env = Env::new("push-clone");
    let repos_root = env.path("server_repos");
    std::fs::create_dir_all(repos_root.join("r1")).unwrap();
    env.ok_in(&repos_root.join("r1"), &["init", "--bare"]);
    let (mut srv, port) = start_server_with_acl(&env, &repos_root, None);
    let url = format!("http://127.0.0.1:{port}/r1");

    let local = fresh_repo_with_branches(&env, "local");
    env.ok_in(
        &local,
        &["pr", "new", "Add X", "--source", "topic", "--target", "main", "-m", "see #5"],
    );
    env.ok_in(&local, &["pr", "comment", "1", "-m", "ping"]);
    env.ok_in(&local, &["remote", "add", "origin", &url]);
    env.ok_in(&local, &["push", "--insecure", "origin", "--all"]);

    let clone = env.path("clone");
    env.ok_in(
        &env.dir,
        &["clone", "--insecure", &url, &clone.display().to_string()],
    );
    let s = env.ok_in(&clone, &["pr", "show", "1"]);
    assert!(s.contains("Add X"));
    assert!(s.contains("see #5"));
    assert!(s.contains("ping"));

    let _ = srv.kill();
    let _ = srv.wait();
}

#[test]
fn pr_ro_client_blocked_from_pushing_ci_run_event() {
    // The "rw-only" trigger guarantee on PR-CI: the server's existing
    // refs/update ACL gate refuses a ro token from writing refs/prs/*.
    // We test by pushing the ci_run event with a ro token and expecting
    // a wire error.
    let env = Env::new("acl-ro");
    let repos_root = env.path("server_repos");
    std::fs::create_dir_all(repos_root.join("r1")).unwrap();
    env.ok_in(&repos_root.join("r1"), &["init", "--bare"]);
    // ACL: alice has rw, bob has ro
    let acl_path = env.path("acl.tsv");
    std::fs::write(
        &acl_path,
        "rw-token\tr1\trw\nro-token\tr1\tro\n",
    )
    .unwrap();
    let (mut srv, port) = start_server_with_acl(&env, &repos_root, Some(&acl_path));
    let url_rw = format!("http://rw-token@127.0.0.1:{port}/r1");
    let url_ro = format!("http://ro-token@127.0.0.1:{port}/r1");

    // Step 1: rw user pushes the initial PR.
    let alice = fresh_repo_with_branches(&env, "alice");
    env.ok_in(
        &alice,
        &["pr", "new", "x", "--source", "topic", "--target", "main", "-m", "b"],
    );
    env.ok_in(&alice, &["remote", "add", "origin", &url_rw]);
    env.ok_in(&alice, &["push", "--insecure", "origin", "--all"]);

    // Step 2: ro user clones, runs CI locally, attempts to push the
    // ci_run event back — must fail.
    let bob = env.path("bob");
    env.ok_in(
        &env.dir,
        &["clone", "--insecure", &url_ro, &bob.display().to_string()],
    );
    // Run CI locally
    let ci = bob.join(".gyt-ci");
    std::fs::create_dir_all(&ci).unwrap();
    std::fs::write(
        ci.join("noop.wasm"),
        r#"(module (func (export "_start") (result i32) i32.const 0))"#,
    )
    .unwrap();
    env.ok_in(&bob, &["pr", "ci-run", "1"]);
    let (_, err) = env.fail_in(&bob, &["push", "--insecure", "origin", "--all"]);
    assert!(
        err.contains("401")
            || err.contains("403")
            || err.contains("403")
            || err.to_lowercase().contains("forbid")
            || err.to_lowercase().contains("auth")
            || err.contains("status 401")
            || err.contains("status 403"),
        "expected auth failure, got: {err}"
    );

    let _ = srv.kill();
    let _ = srv.wait();
}
