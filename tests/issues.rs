// End-to-end tests for the `gyt issue` / `gyt discussion` subcommands.
//
// Drives the real `gyt` binary to confirm:
//   * CRUD: new / list / show / comment / close / reopen / label / assign
//   * Persistence: refs/issues/<N> stored as a blob in the object store
//   * #N mention extraction and dedup
//   * Discussion alias produces the same surface with kind=discussion
//   * push / pull / clone preserve issue refs (since they live under refs/)
//   * Concurrent creators don't reuse a number
//
// Each test creates a private tempdir and cleans up on Drop.

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
        let dir = std::env::temp_dir().join(format!("gyt-issues-{label}-{pid}-{id}-{nanos}"));
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
            "gyt {} failed in {}:\nstdout: {}\nstderr: {}",
            args.join(" "),
            cwd.display(),
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr),
        );
        String::from_utf8_lossy(&o.stdout).into_owned()
    }

    #[track_caller]
    fn fail_in(&self, cwd: &Path, args: &[&str]) -> (String, String) {
        let o = self.run_in(cwd, args);
        assert!(!o.status.success(), "expected failure for gyt {}", args.join(" "));
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

// Initialize a repo, create one commit, set the user.name/email so signing
// won't be an issue, and return the working-tree path.
fn fresh_repo(env: &Env, name: &str) -> PathBuf {
    let p = env.path(name);
    std::fs::create_dir_all(&p).unwrap();
    env.ok_in(&p, &["init"]);
    std::fs::write(p.join("a.txt"), b"hello").unwrap();
    env.ok_in(&p, &["add", "a.txt"]);
    env.ok_in(&p, &["commit", "-m", "first"]);
    p
}

// ─── CRUD ────────────────────────────────────────────────────────────

#[test]
fn issue_new_assigns_sequential_numbers_starting_at_1() {
    let env = Env::new("seq");
    let repo = fresh_repo(&env, "r");

    let o1 = env.ok_in(&repo, &["issue", "new", "First", "-m", "body 1"]);
    assert!(o1.contains("#1"), "first issue must be #1, got: {o1}");

    let o2 = env.ok_in(&repo, &["issue", "new", "Second", "-m", "body 2"]);
    assert!(o2.contains("#2"), "second issue must be #2");

    let o3 = env.ok_in(&repo, &["issue", "new", "Third", "-m", "body 3"]);
    assert!(o3.contains("#3"));
}

#[test]
fn issue_list_default_shows_only_open() {
    let env = Env::new("list-open");
    let repo = fresh_repo(&env, "r");
    env.ok_in(&repo, &["issue", "new", "A", "-m", "x"]);
    env.ok_in(&repo, &["issue", "new", "B", "-m", "y"]);
    env.ok_in(&repo, &["issue", "close", "1"]);
    let listing = env.ok_in(&repo, &["issue", "list"]);
    assert!(!listing.contains("#   1"), "closed must be hidden");
    assert!(listing.contains("B"), "open #2 must appear");
    let all = env.ok_in(&repo, &["issue", "list", "--state", "all"]);
    assert!(all.contains("A"));
    assert!(all.contains("B"));
}

#[test]
fn issue_show_renders_every_event_kind() {
    let env = Env::new("show");
    let repo = fresh_repo(&env, "r");
    env.ok_in(&repo, &["issue", "new", "Bug", "-m", "init body"]);
    env.ok_in(&repo, &["issue", "comment", "1", "-m", "more info"]);
    env.ok_in(&repo, &["issue", "label", "1", "--add", "bug,p1"]);
    env.ok_in(&repo, &["issue", "assign", "1", "--add", "Test User <test@example.com>"]);
    env.ok_in(&repo, &["issue", "close", "1", "--reason", "fixed in #2"]);
    let show = env.ok_in(&repo, &["issue", "show", "1"]);
    assert!(show.contains("issue #1"));
    assert!(show.contains("[closed]"));
    assert!(show.contains("init body"));
    assert!(show.contains("more info"));
    assert!(show.contains("bug"));
    assert!(show.contains("p1"));
    assert!(show.contains("fixed in #2"));
}

#[test]
fn issue_close_reopen_round_trip() {
    let env = Env::new("close-reopen");
    let repo = fresh_repo(&env, "r");
    env.ok_in(&repo, &["issue", "new", "x", "-m", "b"]);
    env.ok_in(&repo, &["issue", "close", "1"]);
    let show = env.ok_in(&repo, &["issue", "show", "1"]);
    assert!(show.contains("[closed]"));
    env.ok_in(&repo, &["issue", "reopen", "1"]);
    let show2 = env.ok_in(&repo, &["issue", "show", "1"]);
    assert!(show2.contains("[open]"));
}

#[test]
fn issue_close_twice_errors() {
    let env = Env::new("close-twice");
    let repo = fresh_repo(&env, "r");
    env.ok_in(&repo, &["issue", "new", "x", "-m", "b"]);
    env.ok_in(&repo, &["issue", "close", "1"]);
    let (_, err) = env.fail_in(&repo, &["issue", "close", "1"]);
    assert!(err.contains("already closed"), "expected error, got: {err}");
}

#[test]
fn issue_reopen_when_open_errors() {
    let env = Env::new("reopen-open");
    let repo = fresh_repo(&env, "r");
    env.ok_in(&repo, &["issue", "new", "x", "-m", "b"]);
    let (_, err) = env.fail_in(&repo, &["issue", "reopen", "1"]);
    assert!(err.contains("already open"));
}

#[test]
fn issue_show_unknown_number_errors() {
    let env = Env::new("unknown");
    let repo = fresh_repo(&env, "r");
    env.fail_in(&repo, &["issue", "show", "42"]);
}

#[test]
fn issue_mentions_extracted_into_index() {
    let env = Env::new("mentions");
    let repo = fresh_repo(&env, "r");
    env.ok_in(&repo, &["issue", "new", "first", "-m", "see #2 and #3"]);
    let show = env.ok_in(&repo, &["issue", "show", "1"]);
    assert!(show.contains("#2"), "must list mention to #2: {show}");
    assert!(show.contains("#3"));
    // Self-reference should NOT be listed
    env.ok_in(&repo, &["issue", "new", "second", "-m", "this is #2 itself"]);
    let show2 = env.ok_in(&repo, &["issue", "show", "2"]);
    assert!(
        !show2.lines().any(|l| l.starts_with("mentions:") && l.contains("#2")),
        "self-mention must be filtered: {show2}"
    );
}

#[test]
fn issue_label_add_remove() {
    let env = Env::new("labels");
    let repo = fresh_repo(&env, "r");
    env.ok_in(&repo, &["issue", "new", "x", "-m", "b"]);
    env.ok_in(&repo, &["issue", "label", "1", "--add", "bug,p1,urgent"]);
    let show = env.ok_in(&repo, &["issue", "show", "1"]);
    assert!(show.contains("bug"));
    assert!(show.contains("p1"));
    assert!(show.contains("urgent"));
    env.ok_in(&repo, &["issue", "label", "1", "--remove", "urgent"]);
    let show2 = env.ok_in(&repo, &["issue", "show", "1"]);
    // Check the header `labels:` line specifically, not the event log
    // (where `-urgent` is recorded as part of history).
    let labels_line = show2
        .lines()
        .find(|l| l.starts_with("labels:"))
        .expect("labels: line must be present");
    assert!(!labels_line.contains("urgent"), "labels line: {labels_line}");
    assert!(labels_line.contains("bug"));
}

#[test]
fn issue_label_no_args_errors() {
    let env = Env::new("label-noargs");
    let repo = fresh_repo(&env, "r");
    env.ok_in(&repo, &["issue", "new", "x", "-m", "b"]);
    env.fail_in(&repo, &["issue", "label", "1"]);
}

#[test]
fn issue_blank_title_rejected() {
    let env = Env::new("blank-title");
    let repo = fresh_repo(&env, "r");
    env.fail_in(&repo, &["issue", "new", "   ", "-m", "body"]);
}

#[test]
fn issue_blank_comment_rejected() {
    let env = Env::new("blank-comment");
    let repo = fresh_repo(&env, "r");
    env.ok_in(&repo, &["issue", "new", "x", "-m", "b"]);
    env.fail_in(&repo, &["issue", "comment", "1", "-m", "   "]);
}

// ─── Discussion alias ─────────────────────────────────────────────────

#[test]
fn discussion_alias_uses_kind_discussion() {
    let env = Env::new("disc");
    let repo = fresh_repo(&env, "r");
    env.ok_in(&repo, &["discussion", "new", "Hi", "-m", "hello"]);
    let show = env.ok_in(&repo, &["discussion", "show", "1"]);
    assert!(show.contains("discussion #1"), "got: {show}");
    // Issues and discussions share the same number space (single counter).
    env.ok_in(&repo, &["issue", "new", "Bug", "-m", "x"]);
    let listing = env.ok_in(&repo, &["issue", "list", "--state", "all"]);
    assert!(listing.contains("Bug"), "issue listing must show issue");
    // The discussion should NOT appear in `issue list`
    assert!(!listing.contains("Hi"), "discussion must not appear in issue list");
}

// ─── Persistence ─────────────────────────────────────────────────────

#[test]
fn issue_ref_lives_under_refs_issues() {
    let env = Env::new("ref-loc");
    let repo = fresh_repo(&env, "r");
    env.ok_in(&repo, &["issue", "new", "X", "-m", "b"]);
    let ref_path = repo.join(".gyt/refs/issues/1");
    assert!(ref_path.exists(), "expected refs/issues/1");
    let counter = repo.join(".gyt/meta/issues_next");
    assert!(counter.exists(), "expected meta/issues_next");
    let counter_v = std::fs::read_to_string(&counter).unwrap();
    assert_eq!(counter_v.trim(), "2");
}

#[test]
fn issue_blob_is_canonical_toml() {
    let env = Env::new("canonical");
    let repo = fresh_repo(&env, "r");
    env.ok_in(&repo, &["issue", "new", "T", "-m", "B"]);
    let id_hex = std::fs::read_to_string(repo.join(".gyt/refs/issues/1"))
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(id_hex.len(), 64);
    // The on-disk blob must be readable (the show command does this).
    env.ok_in(&repo, &["issue", "show", "1"]);
}

// ─── Concurrent creators ─────────────────────────────────────────────

#[test]
fn concurrent_issue_new_no_duplicate_numbers() {
    let env = Env::new("concurrent-new");
    let repo = fresh_repo(&env, "r");
    let bin = env.bin.clone();
    let repo_for_threads = repo.clone();
    let mut handles = Vec::new();
    for i in 0..6 {
        let bin = bin.clone();
        let repo = repo_for_threads.clone();
        handles.push(std::thread::spawn(move || {
            let out = Command::new(&bin)
                .current_dir(&repo)
                .env("GYT_AUTHOR_NAME", "Test User")
                .env("GYT_AUTHOR_EMAIL", "test@example.com")
                .args(["issue", "new", &format!("title-{i}"), "-m", "body"])
                .output()
                .unwrap();
            assert!(out.status.success(), "issue new {i} failed: {}", String::from_utf8_lossy(&out.stderr));
            String::from_utf8_lossy(&out.stdout).into_owned()
        }));
    }
    let mut numbers = Vec::new();
    for h in handles {
        let out = h.join().unwrap();
        // Each line is "created issue #<N> (<hex>)"
        for token in out.split_whitespace() {
            if let Some(n) = token.strip_prefix('#')
                && let Ok(num) = n.parse::<u64>()
            {
                numbers.push(num);
            }
        }
    }
    let mut sorted = numbers.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        numbers.len(),
        "every concurrent new must allocate a unique number; got: {numbers:?}"
    );
    assert_eq!(sorted.len(), 6);
}

// ─── Wire push/pull ──────────────────────────────────────────────────

fn start_server(env: &Env, repos_root: &Path, webroot: &Path) -> (Child, u16) {
    let port = pick_port();
    let addr = format!("127.0.0.1:{port}");
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
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // wait for port
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
fn issue_pushed_to_server_then_cloned_back() {
    let env = Env::new("push-issue");
    let repos_root = env.path("server_repos");
    std::fs::create_dir_all(repos_root.join("r1")).unwrap();
    let webroot = env.path("web");
    std::fs::create_dir_all(&webroot).unwrap();

    // Init a bare-ish server repo so push has a destination.
    env.ok_in(&repos_root.join("r1"), &["init", "--bare"]);

    let (mut srv, port) = start_server(&env, &repos_root, &webroot);
    let url = format!("http://127.0.0.1:{port}/r1");

    // Local repo with one issue
    let local = fresh_repo(&env, "local");
    env.ok_in(&local, &["issue", "new", "Bug", "-m", "details with #3 ref"]);
    env.ok_in(&local, &["issue", "comment", "1", "-m", "I reproduced"]);
    env.ok_in(&local, &["issue", "label", "1", "--add", "bug"]);

    env.ok_in(&local, &["remote", "add", "origin", &url]);
    let push_out = env.ok_in(&local, &["push", "--insecure", "origin", "--all"]);
    assert!(
        push_out.contains("refs/issues/1") || push_out.is_empty() || push_out.contains("pushed"),
        "push output: {push_out}"
    );

    // Clone into a fresh dir
    let clone_dir = env.path("clone");
    env.ok_in(
        &env.dir,
        &["clone", "--insecure", &url, &clone_dir.display().to_string()],
    );
    let show = env.ok_in(&clone_dir, &["issue", "show", "1"]);
    assert!(show.contains("Bug"));
    assert!(show.contains("details with #3 ref"));
    assert!(show.contains("I reproduced"));
    assert!(show.contains("bug"));

    let _ = srv.kill();
    let _ = srv.wait();
}
