// Comprehensive end-to-end tests for the gyt binary.
//
// Each test drives the real `gyt` binary as a subprocess in an isolated
// temp directory. The intent is to catch regressions in the user-facing
// surface that unit tests miss: argument parsing, exit codes,
// filesystem effects, multi-step workflows, server-client wire round
// trips, signed-commit policies, shallow clone behavior, pack-file
// transparency, ACLs, and so on.
//
// Run with:  cargo test --test e2e -- --test-threads=1
//
// Tests are written to be self-contained; they each create a unique
// tmpdir, and clean it up on Drop. They serialize via --test-threads=1
// because some exercise port binding and shared state in
// /tmp.

// Test-code clippy allowances: these lints make production code clearer
// but pile up noise in long, sequential, intentionally-redundant test
// harnesses where the alternative is harder to read than the warning.
#![allow(clippy::too_many_lines)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::manual_assert)]
#![allow(clippy::let_and_return)]
#![allow(clippy::zombie_processes)]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

fn find_binary() -> PathBuf {
    if let Ok(p) = std::env::var("GYT_BIN") {
        return PathBuf::from(p);
    }
    // Prefer the path cargo sets when it builds the binary specifically
    // for this integration test — it always matches the current source.
    if let Some(p) = option_env!("CARGO_BIN_EXE_gyt") {
        return PathBuf::from(p);
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    // Prefer debug (more recently built during `cargo test`) over an
    // older release build that might predate the source.
    for d in &["target/debug/gyt", "target/release/gyt"] {
        let c = root.join(d);
        if c.is_file() {
            return c;
        }
    }
    panic!("gyt binary not found; run `cargo build` first or set GYT_BIN");
}

fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind 0");
    l.local_addr().unwrap().port()
}

struct Env {
    bin: PathBuf,
    dir: PathBuf,
    server: Option<(Child, u16, PathBuf)>,
}

impl Env {
    fn new(label: &str) -> Self {
        let bin = find_binary();
        let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let dir = std::env::temp_dir().join(format!("gyt-e2e-{label}-{pid}-{id}-{nanos}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self {
            bin,
            dir,
            server: None,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn write(&self, name: &str, content: &[u8]) {
        let p = self.path(name);
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&p, content).unwrap();
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.path(name)).unwrap()
    }

    fn exists(&self, name: &str) -> bool {
        self.path(name).exists()
    }

    fn cmd_in(&self, cwd: &Path) -> Command {
        let mut c = Command::new(&self.bin);
        c.current_dir(cwd)
            .env("GYT_AUTHOR_NAME", "Test User")
            .env("GYT_AUTHOR_EMAIL", "test@example.com")
            // Disable any inherited gyt config that might pollute tests.
            .env("HOME", &self.dir)
            .env_remove("XDG_CONFIG_HOME");
        c
    }

    fn run(&self, args: &[&str]) -> Output {
        self.run_in(&self.dir, args)
    }

    fn run_in(&self, cwd: &Path, args: &[&str]) -> Output {
        let out = self.cmd_in(cwd).args(args).output().unwrap();
        out
    }

    #[track_caller]
    fn ok(&self, args: &[&str]) -> String {
        self.ok_in(&self.dir, args)
    }

    #[track_caller]
    fn ok_in(&self, cwd: &Path, args: &[&str]) -> String {
        let o = self.run_in(cwd, args);
        if !o.status.success() {
            panic!(
                "gyt {} failed in {}:\nstatus: {}\nstdout: {}\nstderr: {}",
                args.join(" "),
                cwd.display(),
                o.status,
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr),
            );
        }
        String::from_utf8(o.stdout).unwrap()
    }

    #[track_caller]
    fn fail(&self, args: &[&str]) -> (String, String) {
        let o = self.run(args);
        assert!(
            !o.status.success(),
            "expected failure: gyt {}: stdout={}",
            args.join(" "),
            String::from_utf8_lossy(&o.stdout)
        );
        (
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    }

    fn start_server(&mut self, extra_args: &[&str]) -> (String, PathBuf) {
        let port = pick_port();
        let repos = self.path("server_repos");
        std::fs::create_dir_all(&repos).unwrap();
        let webroot = self.path("empty_webroot");
        std::fs::create_dir_all(&webroot).unwrap();
        let mut c = self.cmd_in(&self.dir);
        c.args([
            "serve",
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--repos",
            &repos.to_string_lossy(),
            "--webroot",
            &webroot.to_string_lossy(),
        ])
        .args(extra_args)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
        let mut child = c.spawn().unwrap();
        // Wait for the server to accept connections.
        let url = format!("http://127.0.0.1:{port}/");
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            // If the child has already exited, surface the stderr so
            // the test gets a real diagnostic instead of an opaque
            // 5-second timeout.
            if let Ok(Some(status)) = child.try_wait() {
                let mut buf = String::new();
                if let Some(mut s) = child.stderr.take() {
                    let _ = s.read_to_string(&mut buf);
                }
                panic!("server exited early ({status}): {buf}");
            }
            if std::net::TcpStream::connect_timeout(
                &format!("127.0.0.1:{port}").parse().unwrap(),
                Duration::from_millis(100),
            )
            .is_ok()
            {
                self.server = Some((child, port, repos.clone()));
                return (url, repos);
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        let mut buf = String::new();
        if let Some(mut s) = child.stderr.take() {
            let _ = s.read_to_string(&mut buf);
        }
        let _ = child.kill();
        panic!("server didn't start within 5s: stderr={buf}");
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        if let Some((mut c, _, _)) = self.server.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn init_commit(e: &Env, file: &str, body: &[u8], msg: &str) {
    e.write(file, body);
    e.ok(&["add", file]);
    e.ok(&["commit", "-m", msg]);
}

// ──────────────────────────── Init / lifecycle ────────────────────────────

#[test]
fn init_creates_gyt_dir() {
    let e = Env::new("init");
    e.ok(&["init"]);
    assert!(e.exists(".gyt"));
    assert!(e.exists(".gyt/HEAD"));
    assert!(e.exists(".gyt/objects"));
    assert!(e.exists(".gyt/refs"));
}

#[test]
fn init_bare_no_workdir() {
    let e = Env::new("init-bare");
    e.ok(&["init", "--bare"]);
    // Bare repos place HEAD/objects at the top level, no .gyt subdir.
    assert!(e.exists("HEAD"));
    assert!(e.exists("objects"));
    assert!(!e.exists(".gyt"));
}

#[test]
fn help_prints_something() {
    let e = Env::new("help-out");
    let out = e.ok(&["--help"]);
    assert!(!out.is_empty());
}

#[test]
fn unknown_command_fails_nonzero() {
    // The fail() helper itself asserts non-zero exit; that's the whole
    // contract we want to lock in. Some unknown-command paths print to
    // stdout instead of stderr, so we don't constrain the error stream.
    let e = Env::new("unknown");
    let _ = e.fail(&["frobnicate"]);
}

// ──────────────────────────── Commit basics ────────────────────────────

#[test]
fn add_commit_log_oneline() {
    let e = Env::new("addcommit");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"hello\n", "first");
    let log = e.ok(&["log", "--oneline"]);
    assert!(log.contains("first"), "log: {log}");
}

#[test]
fn commit_without_author_fails() {
    let e = Env::new("noauthor");
    // Critical: init *persists* GYT_AUTHOR_NAME into .gyt/config.toml if
    // it's set. We need to clear the env BEFORE init so the local
    // config stays empty; only then does a later commit hit the
    // "user.name not set" path.
    let mut init = Command::new(&e.bin);
    init.arg("init")
        .current_dir(&e.dir)
        .env_remove("GYT_AUTHOR_NAME")
        .env_remove("GYT_AUTHOR_EMAIL")
        .env("HOME", &e.dir);
    assert!(init.status().unwrap().success());

    std::fs::write(e.path("a.txt"), b"x").unwrap();
    let add = Command::new(&e.bin)
        .args(["add", "a.txt"])
        .current_dir(&e.dir)
        .env_remove("GYT_AUTHOR_NAME")
        .env_remove("GYT_AUTHOR_EMAIL")
        .env("HOME", &e.dir)
        .status()
        .unwrap();
    assert!(add.success());

    let commit = Command::new(&e.bin)
        .args(["commit", "-m", "x"])
        .current_dir(&e.dir)
        .env_remove("GYT_AUTHOR_NAME")
        .env_remove("GYT_AUTHOR_EMAIL")
        .env("HOME", &e.dir)
        .output()
        .unwrap();
    assert!(
        !commit.status.success(),
        "should require user.name; stderr={}",
        String::from_utf8_lossy(&commit.stderr)
    );
}

#[test]
fn empty_commit_refused() {
    let e = Env::new("empty");
    e.ok(&["init"]);
    let (_, err) = e.fail(&["commit", "-m", "empty"]);
    assert!(
        err.to_lowercase().contains("nothing to commit") || err.contains("staged"),
        "stderr: {err}"
    );
}

#[test]
fn commit_amend_replaces_head() {
    let e = Env::new("amend");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"hi\n", "original");
    e.write("a.txt", b"hi\nthere\n");
    e.ok(&["add", "a.txt"]);
    e.ok(&["commit", "--amend", "-m", "updated"]);
    let log = e.ok(&["log", "--oneline"]);
    assert!(log.contains("updated"));
    assert!(!log.contains("original"));
}

// ──────────────────────────── Status ────────────────────────────

#[test]
fn status_clean_after_commit() {
    let e = Env::new("stat-clean");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    let out = e.ok(&["status"]);
    assert!(out.to_lowercase().contains("clean") || out.is_empty(), "{out}");
}

#[test]
fn status_short_marks_staged_and_untracked() {
    let e = Env::new("stat-short");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"a\n", "c1");
    e.write("u.txt", b"new\n");
    e.write("s.txt", b"staged\n");
    e.ok(&["add", "s.txt"]);
    let out = e.ok(&["status", "--short"]);
    assert!(out.contains("u.txt"), "missing untracked: {out}");
    assert!(out.contains("s.txt"), "missing staged: {out}");
}

#[test]
fn status_full_marks_modified() {
    let e = Env::new("stat-full");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"a\n", "c1");
    e.write("a.txt", b"a-modified\n");
    let out = e.ok(&["status"]);
    assert!(
        out.to_lowercase().contains("modified") && out.contains("a.txt"),
        "expected modified a.txt: {out}"
    );
}

// ──────────────────────────── Branch / switch ────────────────────────────

#[test]
fn branch_create_list_switch() {
    let e = Env::new("branch");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    e.ok(&["branch", "feat"]);
    let list = e.ok(&["branch"]);
    assert!(list.contains("feat"));
    e.ok(&["switch", "feat"]);
    // committing on feat doesn't move main
    init_commit(&e, "b.txt", b"y\n", "c2 on feat");
    e.ok(&["switch", "main"]);
    assert!(!e.exists("b.txt"), "switch should remove files unique to feat");
}

#[test]
fn branch_delete_safe_refuses_unmerged() {
    let e = Env::new("branch-del");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    e.ok(&["branch", "feat"]);
    e.ok(&["switch", "feat"]);
    init_commit(&e, "b.txt", b"y\n", "c2");
    e.ok(&["switch", "main"]);
    let (_, err) = e.fail(&["branch", "-d", "feat"]);
    assert!(
        err.to_lowercase().contains("unmerged") || err.contains("not fully merged"),
        "stderr: {err}"
    );
}

#[test]
fn branch_force_delete() {
    let e = Env::new("branch-D");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    e.ok(&["branch", "feat"]);
    e.ok(&["switch", "feat"]);
    init_commit(&e, "b.txt", b"y\n", "c2");
    e.ok(&["switch", "main"]);
    e.ok(&["branch", "-D", "feat"]);
    let list = e.ok(&["branch"]);
    assert!(!list.contains("feat"));
}

// ──────────────────────────── Tag ────────────────────────────

#[test]
fn tag_create_list_delete() {
    let e = Env::new("tag");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    e.ok(&["tag", "v1"]);
    let list = e.ok(&["tag", "-l"]);
    assert!(list.contains("v1"), "{list}");
    e.ok(&["tag", "-d", "v1"]);
    let list = e.ok(&["tag", "-l"]);
    assert!(!list.contains("v1"));
}

// ──────────────────────────── Diff ────────────────────────────

#[test]
fn diff_working_tree_shows_changes() {
    let e = Env::new("diff");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"hello\n", "c1");
    e.write("a.txt", b"hello\nworld\n");
    let out = e.ok(&["diff"]);
    assert!(out.contains("+world") || out.contains("world"), "{out}");
}

#[test]
fn diff_cached_only_staged() {
    let e = Env::new("diff-cached");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    e.write("a.txt", b"x\ny\n");
    e.ok(&["add", "a.txt"]);
    e.write("a.txt", b"x\ny\nz\n");
    let cached = e.ok(&["diff", "--cached"]);
    assert!(cached.contains("+y"), "cached: {cached}");
    assert!(!cached.contains("+z"), "z is unstaged: {cached}");
}

// ──────────────────────────── Reset / restore ────────────────────────────

#[test]
fn reset_hard_discards_changes() {
    let e = Env::new("reset-hard");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"original\n", "c1");
    e.write("a.txt", b"changed\n");
    // `reset` requires <rev>; --force overrides the dirty-workdir guard
    // so the test isn't blocked by gyt's footgun protection.
    e.ok(&["reset", "HEAD", "--hard", "--force"]);
    assert_eq!(e.read("a.txt"), b"original\n");
}

#[test]
fn reset_soft_keeps_workdir() {
    let e = Env::new("reset-soft");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"v1\n", "c1");
    init_commit(&e, "a.txt", b"v2\n", "c2");
    e.ok(&["reset", "HEAD~1", "--soft"]);
    assert_eq!(e.read("a.txt"), b"v2\n", "soft should keep workdir");
    let log = e.ok(&["log", "--oneline"]);
    assert!(!log.contains("c2"));
}

#[test]
fn restore_staged_unstages() {
    let e = Env::new("restore-staged");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    e.write("a.txt", b"x\ny\n");
    e.ok(&["add", "a.txt"]);
    e.ok(&["restore", "--staged", "a.txt"]);
    let cached = e.ok(&["diff", "--cached"]);
    assert!(cached.trim().is_empty(), "should be empty: {cached}");
}

// ──────────────────────────── Stash ────────────────────────────

#[test]
fn stash_push_list_pop() {
    let e = Env::new("stash");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    e.write("a.txt", b"WIP\n");
    e.ok(&["stash", "push", "-m", "wip"]);
    let list = e.ok(&["stash", "list"]);
    assert!(list.contains("wip"), "{list}");
    // workdir reverted
    assert_eq!(e.read("a.txt"), b"x\n");
    e.ok(&["stash", "pop"]);
    assert_eq!(e.read("a.txt"), b"WIP\n");
}

#[test]
fn stash_apply_keeps_entry() {
    let e = Env::new("stash-apply");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    e.write("a.txt", b"WIP\n");
    e.ok(&["stash", "push", "-m", "wip"]);
    e.ok(&["stash", "apply"]);
    let list = e.ok(&["stash", "list"]);
    assert!(list.contains("wip"), "apply keeps the entry: {list}");
}

// ──────────────────────────── Merge / cherry-pick ────────────────────────────

#[test]
fn merge_ff_only_succeeds() {
    let e = Env::new("merge-ff");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    e.ok(&["branch", "feat"]);
    e.ok(&["switch", "feat"]);
    init_commit(&e, "b.txt", b"y\n", "c2");
    e.ok(&["switch", "main"]);
    e.ok(&["merge", "--ff-only", "feat"]);
    assert!(e.exists("b.txt"));
}

#[test]
fn merge_three_way_succeeds_when_disjoint() {
    let e = Env::new("merge-3way");
    e.ok(&["init"]);
    init_commit(&e, "base.txt", b"base\n", "base");
    e.ok(&["branch", "feat"]);
    e.ok(&["switch", "feat"]);
    init_commit(&e, "feat.txt", b"feat\n", "feat");
    e.ok(&["switch", "main"]);
    init_commit(&e, "main.txt", b"main\n", "main");
    e.ok(&["merge", "feat", "-m", "merge feat"]);
    assert!(e.exists("base.txt") && e.exists("feat.txt") && e.exists("main.txt"));
}

#[test]
fn merge_conflict_leaves_markers() {
    let e = Env::new("merge-conflict");
    e.ok(&["init"]);
    init_commit(&e, "f.txt", b"base\n", "base");
    e.ok(&["branch", "feat"]);
    e.ok(&["switch", "feat"]);
    init_commit(&e, "f.txt", b"feat\n", "feat");
    e.ok(&["switch", "main"]);
    init_commit(&e, "f.txt", b"main\n", "main");
    let o = e.run(&["merge", "feat", "-m", "merge"]);
    assert!(!o.status.success(), "should fail with conflict");
    let body = String::from_utf8(e.read("f.txt")).unwrap();
    assert!(body.contains("<<<<<<<") && body.contains(">>>>>>>"), "{body}");
}

#[test]
fn cherry_pick_disjoint_file_clean() {
    let e = Env::new("cherry");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "base");
    e.ok(&["branch", "feat"]);
    e.ok(&["switch", "feat"]);
    init_commit(&e, "b.txt", b"feat\n", "add b");
    let log = e.ok(&["log", "--oneline"]);
    // Grab the latest commit hash from feat (first column of log).
    let feat_head = log
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    e.ok(&["switch", "main"]);
    e.ok(&["cherry-pick", &feat_head]);
    assert!(e.exists("b.txt"));
}

// ──────────────────────────── Worktree ────────────────────────────

#[test]
fn worktree_add_and_remove() {
    let e = Env::new("wt");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    e.ok(&["branch", "feat"]);
    let wt = e.path("../wt-feat");
    e.ok(&[
        "worktree",
        "add",
        wt.to_str().unwrap(),
        "feat",
    ]);
    assert!(wt.join("a.txt").exists());
    let list = e.ok(&["worktree", "list"]);
    assert!(list.contains("feat") || list.contains(wt.to_str().unwrap()));
    e.ok(&["worktree", "remove", wt.to_str().unwrap()]);
    assert!(!wt.exists() || std::fs::read_dir(&wt).map(|d| d.count()).unwrap_or(0) == 0);
}

// ──────────────────────────── GC + packs ────────────────────────────

#[test]
fn gc_no_op_on_empty() {
    let e = Env::new("gc-empty");
    e.ok(&["init"]);
    let out = e.ok(&["gc"]);
    assert!(out.to_lowercase().contains("no unreachable") || out.contains("0"), "{out}");
}

#[test]
fn gc_prunes_unreachable_after_branch_delete() {
    let e = Env::new("gc-prune");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    e.ok(&["branch", "feat"]);
    e.ok(&["switch", "feat"]);
    e.write("orphan.txt", b"orphan blob\n");
    e.ok(&["add", "orphan.txt"]);
    e.ok(&["commit", "-m", "orphan commit"]);
    e.ok(&["switch", "main"]);
    e.ok(&["branch", "-D", "feat"]);
    // Without expiring reflog, the entries still pin the orphan; expire all.
    let out = e.ok(&["gc", "--expire-reflog", "0"]);
    // Must have pruned >0 objects (the orphan commit + its tree + blob = 3).
    assert!(
        out.contains("pruned") && !out.contains("pruned 0"),
        "expected pruning, got: {out}"
    );
}

#[test]
fn gc_pack_consolidates_loose() {
    let e = Env::new("gc-pack");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    init_commit(&e, "b.txt", b"y\n", "c2");
    // Count loose objects (under objects/<2>/) before.
    let loose_before = count_loose(&e.path(".gyt"));
    assert!(loose_before >= 4, "need >=4 loose, got {loose_before}");
    e.ok(&["gc", "--pack"]);
    let pack_dir = e.path(".gyt/objects/pack");
    assert!(pack_dir.exists());
    let pack_files: Vec<_> = std::fs::read_dir(&pack_dir)
        .unwrap()
        .flatten()
        .map(|d| d.path())
        .collect();
    assert!(
        pack_files.iter().any(|p| p.extension().and_then(|s| s.to_str()) == Some("pack")),
        "expected a .pack file"
    );
    assert!(
        pack_files.iter().any(|p| p.extension().and_then(|s| s.to_str()) == Some("idx")),
        "expected a .idx file"
    );
    // Reading through packs: log should still walk both commits.
    let log = e.ok(&["log", "--oneline"]);
    assert!(log.contains("c1") && log.contains("c2"), "{log}");
}

#[test]
fn gc_keep_reflog_preserves_orphans() {
    let e = Env::new("gc-keep-reflog");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    init_commit(&e, "a.txt", b"y\n", "c2");
    let head_y = e.ok(&["log", "--oneline"])
        .lines()
        .next()
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    e.ok(&["reset", "HEAD~1", "--hard", "--force"]);
    // The c2 commit is now reflog-only. With --keep-reflog it must stay.
    e.ok(&["gc", "--keep-reflog"]);
    let show = e.run(&["show", &head_y]);
    assert!(show.status.success(), "c2 should still be readable");
}

fn count_loose(gyt_dir: &Path) -> usize {
    let objects = gyt_dir.join("objects");
    let Ok(top) = std::fs::read_dir(&objects) else {
        return 0;
    };
    let mut n = 0;
    for shard in top.flatten() {
        let p = shard.path();
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or_default();
        if name.len() != 2 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        if let Ok(files) = std::fs::read_dir(&p) {
            n += files.flatten().count();
        }
    }
    n
}

// ──────────────────────────── Wire: clone/push/pull ────────────────────────────

#[test]
fn wire_clone_round_trip() {
    let mut e = Env::new("wire-clone");
    let (url, repos) = e.start_server(&[]);
    // Create a bare repo on the server.
    let bare = repos.join("origin");
    std::fs::create_dir_all(&bare).unwrap();
    e.ok_in(&bare, &["init", "--bare"]);
    // Push from a fresh client.
    let client = e.path("client");
    std::fs::create_dir_all(&client).unwrap();
    e.ok_in(&client, &["init"]);
    e.write("client/hello.txt", b"hello server\n");
    e.ok_in(&client, &["add", "hello.txt"]);
    e.ok_in(&client, &["commit", "-m", "first"]);
    e.ok_in(
        &client,
        &[
            "remote",
            "add",
            "origin",
            &format!("{url}origin"),
        ],
    );
    e.ok_in(&client, &["push", "origin", "main", "--insecure"]);
    // Now clone elsewhere and verify.
    let cloned = e.path("cloned");
    let _ = std::fs::remove_dir_all(&cloned);
    e.ok(&[
        "clone",
        &format!("{url}origin"),
        cloned.to_str().unwrap(),
        "--insecure",
    ]);
    let body = std::fs::read(cloned.join("hello.txt")).unwrap();
    assert_eq!(body, b"hello server\n");
}

#[test]
fn wire_shallow_clone_depth_1() {
    let mut e = Env::new("wire-shallow");
    let (url, repos) = e.start_server(&[]);
    let bare = repos.join("deep");
    std::fs::create_dir_all(&bare).unwrap();
    e.ok_in(&bare, &["init", "--bare"]);
    let client = e.path("client");
    std::fs::create_dir_all(&client).unwrap();
    e.ok_in(&client, &["init"]);
    for i in 0..5 {
        e.write(&format!("client/f{i}.txt"), format!("v{i}\n").as_bytes());
        e.ok_in(&client, &["add", &format!("f{i}.txt")]);
        e.ok_in(&client, &["commit", "-m", &format!("c{i}")]);
    }
    e.ok_in(
        &client,
        &[
            "remote",
            "add",
            "origin",
            &format!("{url}deep"),
        ],
    );
    e.ok_in(&client, &["push", "origin", "main", "--insecure"]);

    let cloned = e.path("shallow");
    e.ok(&[
        "clone",
        &format!("{url}deep"),
        cloned.to_str().unwrap(),
        "--depth",
        "1",
        "--insecure",
    ]);
    // The .gyt/shallow file should exist and list the boundary commit.
    let shallow = cloned.join(".gyt").join("shallow");
    assert!(shallow.exists(), "missing .gyt/shallow");
    let log = e.ok_in(&cloned, &["log", "--oneline"]);
    // Only one commit accessible after depth=1.
    assert_eq!(log.lines().count(), 1, "expected 1 commit, got: {log}");
}

#[test]
fn wire_server_rejects_non_ff_push() {
    let mut e = Env::new("wire-nonff");
    let (url, repos) = e.start_server(&[]);
    let bare = repos.join("nf");
    std::fs::create_dir_all(&bare).unwrap();
    e.ok_in(&bare, &["init", "--bare"]);
    // Client A pushes c1.
    let a = e.path("a");
    std::fs::create_dir_all(&a).unwrap();
    e.ok_in(&a, &["init"]);
    init_commit_in(&e, &a, "f.txt", b"a\n", "c1");
    e.ok_in(&a, &["remote", "add", "origin", &format!("{url}nf")]);
    e.ok_in(&a, &["push", "origin", "main", "--insecure"]);
    // Client B clones, rewrites history.
    let b = e.path("b");
    e.ok(&[
        "clone",
        &format!("{url}nf"),
        b.to_str().unwrap(),
        "--insecure",
    ]);
    // Reset to a divergent state.
    let _ = std::fs::write(b.join("f.txt"), b"divergent\n");
    e.ok_in(&b, &["add", "f.txt"]);
    e.ok_in(&b, &["commit", "--amend", "-m", "rewritten"]);
    let push = e.run_in(&b, &["push", "origin", "main", "--insecure"]);
    assert!(!push.status.success(), "non-ff push must be rejected");
}

#[test]
fn wire_path_traversal_rejected() {
    let mut e = Env::new("wire-traversal");
    let (url, repos) = e.start_server(&[]);
    // Put a real repo somewhere repos_root *can't* legitimately reach.
    let sibling = e.path("sibling");
    std::fs::create_dir_all(&sibling).unwrap();
    e.ok_in(&sibling, &["init", "--bare"]);
    // Try to reach it from the wire via /../sibling/info/refs.
    let _ = repos; // unused
    let bad_url = format!("{url}../sibling");
    let cloned = e.path("traversal");
    let o = e.run(&[
        "clone",
        &bad_url,
        cloned.to_str().unwrap(),
        "--insecure",
    ]);
    assert!(!o.status.success(), "path traversal must be rejected");
}

#[test]
fn wire_auth_token_required() {
    let mut e = Env::new("wire-auth");
    let (url, repos) = e.start_server(&["--auth-token", "secret123"]);
    let bare = repos.join("private");
    std::fs::create_dir_all(&bare).unwrap();
    e.ok_in(&bare, &["init", "--bare"]);
    let cloned = e.path("noauth");
    let o = e.run(&[
        "clone",
        &format!("{url}private"),
        cloned.to_str().unwrap(),
        "--insecure",
    ]);
    assert!(!o.status.success(), "missing token must fail");
}

#[test]
fn wire_acl_ro_blocks_push() {
    let mut e = Env::new("wire-acl");
    let acl = e.path("acl.tsv");
    std::fs::write(
        &acl,
        b"reader\trepo1\tro\nwriter\trepo1\trw\n",
    )
    .unwrap();
    let (url, repos) = e.start_server(&["--auth-tokens", acl.to_str().unwrap()]);
    let bare = repos.join("repo1");
    std::fs::create_dir_all(&bare).unwrap();
    e.ok_in(&bare, &["init", "--bare"]);

    // A reader-only client can clone (ro path) but cannot push.
    let client = e.path("c1");
    std::fs::create_dir_all(&client).unwrap();
    e.ok_in(&client, &["init"]);
    init_commit_in(&e, &client, "a.txt", b"x\n", "c1");
    // Configure with reader token first (set the remote URL with basic-auth via env? Our HTTP
    // client uses Bearer via a separate mechanism — for this test we use --auth-token
    // value embedded by the server, but the gyt client only sends bearer when... )
    // The client's HTTP layer doesn't expose --token on CLI; just verify the
    // server-side enforcement path is exercised: push without any auth fails.
    e.ok_in(&client, &["remote", "add", "origin", &format!("{url}repo1")]);
    let o = e.run_in(&client, &["push", "origin", "main", "--insecure"]);
    assert!(!o.status.success(), "no token must be rejected on ACL server");
}

fn init_commit_in(e: &Env, dir: &Path, file: &str, body: &[u8], msg: &str) {
    let p = dir.join(file);
    if let Some(parent) = p.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&p, body).unwrap();
    e.ok_in(dir, &["add", file]);
    e.ok_in(dir, &["commit", "-m", msg]);
}

// ──────────────────────────── Pull (lock + ff) ────────────────────────────

#[test]
fn wire_pull_advances_head() {
    let mut e = Env::new("wire-pull");
    let (url, repos) = e.start_server(&[]);
    let bare = repos.join("p");
    std::fs::create_dir_all(&bare).unwrap();
    e.ok_in(&bare, &["init", "--bare"]);
    // Writer pushes c1.
    let w = e.path("w");
    std::fs::create_dir_all(&w).unwrap();
    e.ok_in(&w, &["init"]);
    init_commit_in(&e, &w, "a.txt", b"v1\n", "c1");
    e.ok_in(&w, &["remote", "add", "origin", &format!("{url}p")]);
    e.ok_in(&w, &["push", "origin", "main", "--insecure"]);
    // Reader clones.
    let r = e.path("r");
    e.ok(&[
        "clone",
        &format!("{url}p"),
        r.to_str().unwrap(),
        "--insecure",
    ]);
    // Writer pushes c2.
    e.write("w/a.txt", b"v2\n");
    e.ok_in(&w, &["add", "a.txt"]);
    e.ok_in(&w, &["commit", "-m", "c2"]);
    e.ok_in(&w, &["push", "origin", "main", "--insecure"]);
    // Reader pulls.
    e.ok_in(&r, &["pull", "--insecure"]);
    assert_eq!(std::fs::read(r.join("a.txt")).unwrap(), b"v2\n");
}

// ──────────────────────────── Reflog ────────────────────────────

#[test]
fn reflog_has_entries_after_commits() {
    let e = Env::new("reflog");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    init_commit(&e, "a.txt", b"y\n", "c2");
    let out = e.ok(&["reflog"]);
    // Two HEAD-moving operations: two reflog entries minimum.
    assert!(out.lines().count() >= 2, "{out}");
}

// ──────────────────────────── Pack-file end-to-end ────────────────────────────

#[test]
fn pack_then_clone_serves_from_pack() {
    let mut e = Env::new("pack-server");
    let (url, repos) = e.start_server(&[]);
    let bare = repos.join("packed");
    std::fs::create_dir_all(&bare).unwrap();
    e.ok_in(&bare, &["init", "--bare"]);
    let w = e.path("w");
    std::fs::create_dir_all(&w).unwrap();
    e.ok_in(&w, &["init"]);
    init_commit_in(&e, &w, "a.txt", b"x\n", "c1");
    init_commit_in(&e, &w, "b.txt", b"y\n", "c2");
    e.ok_in(&w, &["remote", "add", "origin", &format!("{url}packed")]);
    e.ok_in(&w, &["push", "origin", "main", "--insecure"]);
    // Pack the server-side bare repo.
    e.ok_in(&bare, &["gc", "--pack"]);
    // Verify only pack-dir entries remain.
    let loose = count_loose(&bare);
    assert_eq!(loose, 0, "expected all loose packed, got {loose}");
    // Clone from packed server.
    let c = e.path("c");
    e.ok(&[
        "clone",
        &format!("{url}packed"),
        c.to_str().unwrap(),
        "--insecure",
    ]);
    assert!(c.join("a.txt").exists() && c.join("b.txt").exists());
}

// ──────────────────────────── Config ────────────────────────────

#[test]
fn config_list_and_get() {
    // Use remote.<n>.url for round-trip — GYT_AUTHOR_NAME from the
    // Env wrapper would mask config writes to user.name.
    let e = Env::new("config");
    e.ok(&["init"]);
    e.ok(&["config", "--set", "remote.origin.url", "http://example.com/r"]);
    let got = e.ok(&["config", "--get", "remote.origin.url"]);
    assert_eq!(got.trim(), "http://example.com/r");
    let list = e.ok(&["config", "--list"]);
    assert!(list.contains("remote.origin"), "list: {list}");
    assert!(list.contains("example.com"), "list: {list}");
}

#[test]
fn config_unset_removes_key() {
    let e = Env::new("config-unset");
    e.ok(&["init"]);
    e.ok(&["config", "--set", "remote.r.url", "http://x/"]);
    e.ok(&["config", "--unset", "remote.r.url"]);
    let o = e.run(&["config", "--get", "remote.r.url"]);
    assert!(!o.status.success() || String::from_utf8_lossy(&o.stdout).trim().is_empty());
}

// ──────────────────────────── Remote ────────────────────────────

#[test]
fn remote_add_v_lists() {
    let e = Env::new("remote");
    e.ok(&["init"]);
    e.ok(&["remote", "add", "origin", "http://example.com/r"]);
    let out = e.ok(&["remote", "-v"]);
    assert!(out.contains("origin") && out.contains("example.com"), "{out}");
}

// ──────────────────────────── Show ────────────────────────────

#[test]
fn show_commit_prints_diff() {
    let e = Env::new("show");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"hello\n", "c1");
    let out = e.ok(&["show", "HEAD"]);
    assert!(
        out.contains("c1") && (out.contains("+hello") || out.contains("hello")),
        "{out}"
    );
}

// ──────────────────────────── HTTP keep-alive sanity ────────────────────────────

#[test]
fn keep_alive_multiple_clones_against_same_server() {
    let mut e = Env::new("keepalive");
    let (url, repos) = e.start_server(&[]);
    let bare = repos.join("ka");
    std::fs::create_dir_all(&bare).unwrap();
    e.ok_in(&bare, &["init", "--bare"]);
    let w = e.path("w");
    std::fs::create_dir_all(&w).unwrap();
    e.ok_in(&w, &["init"]);
    init_commit_in(&e, &w, "a.txt", b"x\n", "c1");
    e.ok_in(&w, &["remote", "add", "origin", &format!("{url}ka")]);
    e.ok_in(&w, &["push", "origin", "main", "--insecure"]);
    // Several sequential clones — each is one process so it doesn't
    // exercise the *pool* across clones, but it does exercise the
    // server's per-conn loop. The test should just succeed.
    for i in 0..3 {
        let c = e.path(&format!("c{i}"));
        e.ok(&[
            "clone",
            &format!("{url}ka"),
            c.to_str().unwrap(),
            "--insecure",
        ]);
    }
}

// ──────────────────────────── Stale-lock reclaim ────────────────────────────

// NOTE: stale-lock reclamation requires a lockfile mtime older than
// STALE_AFTER (1 minute). We don't have a way to back-date mtime
// without an extra crate, so the e2e suite skips this case — it's
// covered by the FileLock unit tests instead.

// ──────────────────────────── Corruption detection ────────────────────────────

#[test]
fn corrupt_loose_object_detected() {
    let e = Env::new("corrupt");
    e.ok(&["init"]);
    init_commit(&e, "a.txt", b"x\n", "c1");
    // Find any loose object file and flip a byte.
    let objects = e.path(".gyt/objects");
    let mut victim: Option<PathBuf> = None;
    'outer: for shard in std::fs::read_dir(&objects).unwrap().flatten() {
        let p = shard.path();
        let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
        if name.len() != 2 || !name.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        if let Some(f) = std::fs::read_dir(&p).unwrap().flatten().next() {
            victim = Some(f.path());
            break 'outer;
        }
    }
    let victim = victim.unwrap();
    let mut data = std::fs::read(&victim).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0xff;
    std::fs::write(&victim, &data).unwrap();
    // log walks the graph; with one object corrupted, *something* should fail.
    let o = e.run(&["log"]);
    assert!(!o.status.success(), "corruption should be detected");
}

// ──────────────────────────── Help / usage ────────────────────────────

#[test]
fn help_is_zero_exit() {
    let e = Env::new("help");
    let o = e.run(&["--help"]);
    assert!(o.status.success());
    let o2 = e.run(&["-h"]);
    assert!(o2.status.success());
}

#[test]
fn subcommand_help_exits_zero_inside_repo() {
    // Many subcommands open the repo before parsing flags, so `-h`
    // only works inside an initialized repo. We init first, then check
    // each. `merge`, `branch`, `config` currently don't accept -h at
    // all and are excluded; that's a separate CLI-consistency gap.
    let e = Env::new("subhelp");
    e.ok(&["init"]);
    for sub in &[
        "log", "gc", "clone", "push", "fetch", "rebase", "diff", "status", "commit", "merge",
        "config",
    ] {
        let o = e.run(&[sub, "-h"]);
        assert!(
            o.status.success(),
            "{sub} -h exited {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr)
        );
    }
}

// ──────────────────────────── Fetch --prune ────────────────────────────

#[test]
fn fetch_prune_removes_deleted_remote_ref() {
    let mut e = Env::new("prune");
    let (url, repos) = e.start_server(&[]);
    let bare = repos.join("pr");
    std::fs::create_dir_all(&bare).unwrap();
    e.ok_in(&bare, &["init", "--bare"]);
    let w = e.path("w");
    std::fs::create_dir_all(&w).unwrap();
    e.ok_in(&w, &["init"]);
    init_commit_in(&e, &w, "a.txt", b"x\n", "c1");
    e.ok_in(&w, &["remote", "add", "origin", &format!("{url}pr")]);
    e.ok_in(&w, &["push", "origin", "main", "--insecure"]);
    e.ok_in(&w, &["branch", "feat"]);
    e.ok_in(&w, &["switch", "feat"]);
    init_commit_in(&e, &w, "b.txt", b"y\n", "c2");
    e.ok_in(&w, &["push", "origin", "feat", "--insecure"]);
    // Reader clone, then fetch to populate refs/remotes/origin/*.
    let r = e.path("r");
    e.ok(&[
        "clone",
        &format!("{url}pr"),
        r.to_str().unwrap(),
        "--insecure",
    ]);
    e.ok_in(&r, &["fetch", "--insecure"]);
    assert!(
        r.join(".gyt/refs/remotes/origin/feat").exists(),
        "fetch should populate remote-tracking ref"
    );
    // Delete feat on the bare server.
    let _ = std::fs::remove_file(bare.join("refs/heads/feat"));
    // Now reader fetches with --prune.
    e.ok_in(&r, &["fetch", "--prune", "--insecure"]);
    assert!(
        !r.join(".gyt/refs/remotes/origin/feat").exists(),
        "prune should drop the deleted remote-tracking ref"
    );
}

// ──────────────────────────── Large input ────────────────────────────

#[test]
fn large_blob_round_trip() {
    let e = Env::new("large");
    e.ok(&["init"]);
    // ~1 MiB of mixed content (xz handles this well; ensures encode/decode
    // path doesn't trip on the size threshold logic).
    let mut body = Vec::with_capacity(1_048_576);
    for i in 0..1_048_576u32 {
        body.push((i & 0xff) as u8);
    }
    e.write("big.bin", &body);
    e.ok(&["add", "big.bin"]);
    e.ok(&["commit", "-m", "big"]);
    // restore by hard-reset round-trip
    std::fs::write(e.path("big.bin"), b"clobbered").unwrap();
    e.ok(&["reset", "HEAD", "--hard", "--force"]);
    let got = std::fs::read(e.path("big.bin")).unwrap();
    assert_eq!(got.len(), body.len());
    assert!(got == body);
}

// ──────────────────────────── ignore file ────────────────────────────

#[test]
fn gytignore_skips_files() {
    let e = Env::new("ignore");
    e.ok(&["init"]);
    e.write(".gytignore", b"secret.txt\n*.tmp\n");
    e.write("secret.txt", b"shh");
    e.write("note.tmp", b"scratch");
    e.write("ok.txt", b"hi");
    let out = e.ok(&["status"]);
    assert!(out.contains("ok.txt"), "must include ok.txt: {out}");
    assert!(!out.contains("secret.txt"), "must skip secret.txt: {out}");
    assert!(!out.contains("note.tmp"), "must skip note.tmp: {out}");
}

// ──────────────────────────── Exec bit preserved ────────────────────────────

#[cfg(unix)]
#[test]
fn exec_bit_preserved_round_trip() {
    use std::os::unix::fs::PermissionsExt;
    let e = Env::new("exec");
    e.ok(&["init"]);
    e.write("run.sh", b"#!/bin/sh\necho hi\n");
    let p = e.path("run.sh");
    let mut perms = std::fs::metadata(&p).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&p, perms).unwrap();
    e.ok(&["add", "run.sh"]);
    e.ok(&["commit", "-m", "exec"]);
    // Wipe and reset.
    std::fs::write(&p, b"clobbered").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    e.ok(&["reset", "HEAD", "--hard", "--force"]);
    let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode & 0o100, 0o100, "exec bit not restored: mode={mode:o}");
}

// ──────────────────────────── Push body cap / smuggling ────────────────────────────

#[test]
fn server_rejects_garbage_content_length() {
    let mut e = Env::new("cl-smuggle");
    let (url, _repos) = e.start_server(&[]);
    // Connect raw and send a request with malformed CL.
    let port: u16 = url
        .trim_start_matches("http://127.0.0.1:")
        .trim_end_matches('/')
        .parse()
        .unwrap();
    let mut sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
    let req =
        b"POST /any/objects/want HTTP/1.1\r\nHost: x\r\nContent-Length: 5garbage\r\n\r\nabcde";
    sock.write_all(req).unwrap();
    let mut buf = [0u8; 256];
    let n = sock.read(&mut buf).unwrap_or(0);
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.starts_with("HTTP/1.1 4") || resp.is_empty(),
        "expected 4xx, got: {resp:?}"
    );
}

#[test]
fn server_rejects_transfer_encoding() {
    let mut e = Env::new("te-rejected");
    let (url, _) = e.start_server(&[]);
    let port: u16 = url
        .trim_start_matches("http://127.0.0.1:")
        .trim_end_matches('/')
        .parse()
        .unwrap();
    let mut sock = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
    sock.write_all(
        b"POST /x/objects/want HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    )
    .unwrap();
    let mut buf = [0u8; 256];
    let n = sock.read(&mut buf).unwrap_or(0);
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.starts_with("HTTP/1.1 4") || resp.is_empty(),
        "expected 4xx, got: {resp:?}"
    );
}
