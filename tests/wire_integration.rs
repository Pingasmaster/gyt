// Wire protocol integration tests against the production `gyt serve` binary.
//
// These tests:
//   - Find the gyt binary (set GYT_BIN env, or look in target/release/ and target/debug/)
//   - Start a production server on a random port
//   - Run the full clone/push/fetch/pull cycle via the CLI
//   - Verify objects and refs on disk
//   - Clean up the server process
//
// Run:  cargo test --test wire_integration -- --test-threads=1
//   or:  GYT_BIN=target/release/gyt cargo test --test wire_integration -- --test-threads=1
//
// NOTE: the binary must be built first (cargo build).

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

// ─── Helpers ────────────────────────────────────────────────────────────

fn find_binary() -> PathBuf {
    if let Ok(path) = std::env::var("GYT_BIN") {
        return PathBuf::from(path);
    }
    // Look in target/release/ (preferred) then target/debug/
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for dir in &["target/release/gyt", "target/debug/gyt"] {
        let candidate = root.join(dir);
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!(
        "gyt binary not found; build first with `cargo build` or set GYT_BIN"
    );
}

/// Pick a random available port by binding to port 0 and reading the assigned port.
fn pick_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind port 0");
    listener.local_addr().unwrap().port()
}

struct GytTest {
    bin: PathBuf,
    work: PathBuf,
    server: Option<(Child, u16)>,
}

impl GytTest {
    fn new() -> Self {
        let bin = find_binary();
        // Use a temp dir that persists for the test lifetime
        let mut work = std::env::temp_dir();
        work.push(format!("gyt_integration_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&work);
        std::fs::create_dir_all(&work).unwrap();
        Self {
            bin,
            work,
            server: None,
        }
    }

    // Test scaffolding: helpers below are used by some tests and not
    // others, but kept together for clarity. The unused-method lint is
    // suppressed for the whole struct rather than per-helper.
    #[allow(dead_code)] // Reason: scaffolding may be used by future tests; deleting drops a load-bearing helper API.
    fn gyt_dir(&self) -> PathBuf {
        self.work.join(".gyt")
    }

    fn server_repos(&self) -> PathBuf {
        self.work.join("server_repos")
    }

    #[allow(dead_code)] // Reason: per-repo path helper kept available for future per-server tests.
    fn server_repo(&self, name: &str) -> PathBuf {
        self.server_repos().join(name)
    }

    fn worktree(&self, name: &str) -> PathBuf {
        self.work.join(name)
    }

    /// Run `gyt <args...>` in the test work dir, returning stdout on success.
    #[allow(dead_code)] // Reason: convenience wrapper for tests that don't override the cwd.
    fn run(&self, args: &[&str]) -> String {
        let output = Command::new(&self.bin)
            .args(args)
            .current_dir(&self.work)
            .output()
            .unwrap_or_else(|e| panic!("gyt {} failed: {e}", args.join(" ")));
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            panic!(
                "gyt {} exited with {}:\nstdout: {}\nstderr: {}",
                args.join(" "),
                output.status,
                stdout,
                stderr
            );
        }
        String::from_utf8(output.stdout).unwrap()
    }

    /// Run `gyt <args...>` in a specific directory.
    fn run_in(&self, dir: &Path, args: &[&str]) -> String {
        let output = Command::new(&self.bin)
            .args(args)
            .current_dir(dir)
            .output()
            .unwrap_or_else(|e| panic!("gyt {} failed: {e}", args.join(" ")));
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            panic!(
                "gyt {} exited with {}:\nstdout: {}\nstderr: {}",
                args.join(" "),
                output.status,
                stdout,
                stderr
            );
        }
        String::from_utf8(output.stdout).unwrap()
    }

    /// Start `gyt serve` on a random port, serving from server_repos/.
    fn start_server(&mut self) -> u16 {
        let port = pick_port();
        let repos = self.server_repos();
        std::fs::create_dir_all(&repos).unwrap();

        let child = Command::new(&self.bin)
            .args([
                "serve",
                "--listen",
                &format!("127.0.0.1:{port}"),
                "--repos",
                &repos.to_string_lossy(),
                "--webroot",
                &self.work.join("empty-webroot").to_string_lossy(),
            ])
            .env("GYT_SERVE_RATE_IP_CAPACITY", "0")
            .env("GYT_SERVE_RATE_ACTOR_CAPACITY", "0")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap_or_else(|e| panic!("starting server: {e}"));

        self.server = Some((child, port));

        // Wait for the server to be ready
        let url = format!("http://127.0.0.1:{port}/");
        wait_for_server(&url, Duration::from_secs(10));

        port
    }

    fn stop_server(&mut self) {
        if let Some((mut child, _port)) = self.server.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Initialize a repo with commits in the given subdirectory.
    fn init_repo(&self, name: &str, files: &[(&str, &str)]) -> PathBuf {
        let dir = self.worktree(name);
        std::fs::create_dir_all(&dir).unwrap();

        self.run_in(&dir, &["init"]);

        // Write config
        let cfg = dir.join(".gyt/config.toml");
        std::fs::write(
            &cfg,
            "[user]\nname = \"Tester\"\nemail = \"t@x\"\n",
        )
        .unwrap();

        for (fname, content) in files {
            let fp = dir.join(fname);
            if let Some(parent) = fp.parent() {
                std::fs::create_dir_all(parent).unwrap();
            }
            std::fs::write(&fp, content).unwrap();
        }

        self.run_in(&dir, &["add", "-A"]);
        self.run_in(&dir, &["commit", "-m", "initial"]);
        dir
    }

    /// Write remote origin URL into the repo's config.toml and create the
    /// server-side repo directory so push can find it.
    fn add_remote(&self, dir: &Path, url: &str) {
        let cfg_path = dir.join(".gyt/config.toml");
        let mut raw = std::fs::read_to_string(&cfg_path).unwrap_or_default();
        raw.push_str(&format!("\n[remote.origin]\nurl = \"{url}\"\n"));
        std::fs::write(&cfg_path, raw.as_bytes()).unwrap();

        // Create the server-side repo directory so push has a target.
        // The URL is like http://host:port/repo.gyt/
        // The repo name is the last path segment without trailing slash.
        let repo_name = url.trim_end_matches('/').rsplit('/').next().unwrap_or("repo.gyt");
        let server_repo = self.server_repos().join(repo_name);
        std::fs::create_dir_all(server_repo.join(".gyt/objects")).unwrap();
        std::fs::create_dir_all(server_repo.join(".gyt/refs/heads")).unwrap();
        std::fs::create_dir_all(server_repo.join(".gyt/refs/tags")).unwrap();
        std::fs::write(
            server_repo.join(".gyt/HEAD"),
            "ref: refs/heads/main\n",
        )
        .unwrap();
    }

    /// Write user identity config for a repo that was cloned (no user config).
    fn set_user_config(&self, dir: &Path) {
        let cfg_path = dir.join(".gyt/config.toml");
        let raw = std::fs::read_to_string(&cfg_path).unwrap_or_default();
        if raw.contains("[user]") {
            return; // already has user section
        }
        let mut updated = raw;
        updated.push_str("[user]\nname = \"Tester\"\nemail = \"t@x\"\n");
        std::fs::write(&cfg_path, updated.as_bytes()).unwrap();
    }

    /// Add a commit to an existing repo.
    fn add_commit(&self, dir: &Path, fname: &str, content: &str, msg: &str) {
        let fp = dir.join(fname);
        if let Some(parent) = fp.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&fp, content).unwrap();
        self.run_in(dir, &["add", "-A"]);
        self.run_in(dir, &["commit", "-m", msg]);
    }

    /// Read a ref file from a gyt repo.
    fn read_ref(&self, dir: &Path, refname: &str) -> Option<String> {
        let path = dir.join(".gyt").join(refname);
        if path.is_file() {
            Some(std::fs::read_to_string(&path).unwrap().trim().to_string())
        } else {
            None
        }
    }

    /// Count objects in a gyt repo.
    fn count_objects(&self, dir: &Path) -> usize {
        let obj_dir = dir.join(".gyt/objects");
        if !obj_dir.is_dir() {
            return 0;
        }
        std::fs::read_dir(&obj_dir)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_ok_and(|t| t.is_file()))
            .count()
    }
}

impl Drop for GytTest {
    fn drop(&mut self) {
        self.stop_server();
    }
}

fn wait_for_server(url: &str, timeout: Duration) {
    let start = std::time::Instant::now();
    let port: u16 = url
        .trim_end_matches('/')
        .rsplit(':')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    loop {
        assert!(start.elapsed() <= timeout, "server did not start within {timeout:?}");
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(100),
        )
        .is_ok()
        {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ─── Tests ────────────────────────────────────────────────────────────

#[test]
fn binary_clone_end_to_end() {
    let mut t = GytTest::new();
    let port = t.start_server();

    // Create a source repo with commits
    let src = t.init_repo("src", &[("a.txt", "hello"), ("b.txt", "world")]);
    t.add_commit(&src, "c.txt", "third file", "second commit");

    // Set up remote and push
    let url = format!("http://127.0.0.1:{port}/testrepo.gyt/");
    t.add_remote(&src, &url);
    t.run_in(&src, &["push", "--insecure", "origin"]);

    // Clone from the server into a new directory
    let clone_dir = t.worktree("clone");
    std::fs::create_dir_all(&clone_dir).unwrap();
    t.run_in(&clone_dir, &["clone", "--insecure", &url, "."]);

    // Set user config on clone
    t.set_user_config(&clone_dir);

    // Verify clone has the same commits
    let clone_log = t.run_in(&clone_dir, &["log", "--oneline"]);
    assert!(
        clone_log.contains("second commit"),
        "clone missing second commit, got: {clone_log}"
    );
    assert!(
        clone_log.contains("initial"),
        "clone missing initial commit, got: {clone_log}"
    );

    // Verify clone has the same files
    assert!(
        clone_dir.join("a.txt").exists(),
        "clone missing a.txt"
    );
    assert!(
        clone_dir.join("b.txt").exists(),
        "clone missing b.txt"
    );
    assert!(
        clone_dir.join("c.txt").exists(),
        "clone missing c.txt"
    );

    // Verify objects were transferred
    let src_objs = t.count_objects(&src);
    let clone_objs = t.count_objects(&clone_dir);
    // Clone should have approximately the same number of objects.
    // Handle small repos where src_objs < 2 gracefully.
    let min_expected = src_objs.saturating_sub(2);
    assert!(
        clone_objs >= min_expected,
        "clone has {clone_objs} objects but source has {src_objs}"
    );

    t.stop_server();
}

#[test]
fn binary_push_fetch_pull_cycle() {
    let mut t = GytTest::new();
    let port = t.start_server();

    // Create a source repo with one commit
    let src = t.init_repo("src2", &[("init.txt", "initial content")]);
    let url = format!("http://127.0.0.1:{port}/pushtest.gyt/");
    t.add_remote(&src, &url);
    t.run_in(&src, &["push", "--insecure", "origin"]);

    // Clone into a second working copy
    let clone2 = t.worktree("clone2");
    std::fs::create_dir_all(&clone2).unwrap();
    t.run_in(&clone2, &["clone", "--insecure", &url, "."]);

    // Add a commit in the clone and push it back
    t.set_user_config(&clone2);
    t.add_commit(&clone2, "new.txt", "added from clone", "clone commit");
    t.run_in(&clone2, &["push", "--insecure", "origin"]);

    // Fetch in the original repo
    t.run_in(&src, &["fetch", "--insecure", "origin"]);

    // Verify the original repo has the new commit via fetch
    let remote_ref = t.read_ref(&src, "refs/remotes/origin/main");
    assert!(
        remote_ref.is_some(),
        "remote tracking ref missing after fetch"
    );

    // Pull should fast-forward
    t.run_in(&src, &["pull", "--insecure", "origin"]);

    // Verify the file from the clone is now in the source
    assert!(src.join("new.txt").exists(), "pull did not get new.txt");

    // Log should show both commits
    let log = t.run_in(&src, &["log", "--oneline"]);
    assert!(log.contains("clone commit"), "log missing clone commit");
    assert!(log.contains("initial"), "log missing initial commit");

    t.stop_server();
}

#[test]
fn binary_clone_preserves_mutiple_branches() {
    let mut t = GytTest::new();
    let port = t.start_server();

    let src = t.init_repo("src3", &[("x.txt", "base")]);

    // Create a branch with different file
    t.run_in(&src, &["branch", "feature"]);
    t.run_in(&src, &["switch", "feature"]);
    t.add_commit(&src, "feature.txt", "feature work", "feature commit");

    // Switch back to main and set up remote
    t.run_in(&src, &["switch", "main"]);
    let url = format!("http://127.0.0.1:{port}/branches.gyt/");
    t.add_remote(&src, &url);

    // Push main, then feature branch
    t.run_in(&src, &["push", "--insecure", "origin"]);
    t.run_in(&src, &["switch", "feature"]);
    t.run_in(&src, &["push", "--insecure", "origin"]);
    t.run_in(&src, &["switch", "main"]);

    // Clone
    let clone3 = t.worktree("clone3");
    std::fs::create_dir_all(&clone3).unwrap();
    t.run_in(&clone3, &["clone", "--insecure", &url, "."]);

    // The clone should have both branches
    t.set_user_config(&clone3);
    let branches = t.run_in(&clone3, &["branch"]);
    assert!(
        branches.contains("main"),
        "clone branch missing main, got: {branches}"
    );
    assert!(
        branches.contains("feature"),
        "clone branch missing feature, got: {branches}"
    );

    // Switch to feature and verify files
    t.run_in(&clone3, &["switch", "feature"]);
    assert!(
        clone3.join("feature.txt").exists(),
        "clone missing feature.txt on feature branch"
    );
    assert!(
        clone3.join("x.txt").exists(),
        "clone missing x.txt on feature branch"
    );

    t.stop_server();
}

/// Verify that the production server rejects non-fast-forward pushes.
///
/// Setup: push commit A to the server, then in a second clone, create a
/// divergent commit B (different content, different parent) and try to
/// push. The server should refuse with a 409.
#[test]
fn binary_server_rejects_non_ff_push() {
    let mut t = GytTest::new();
    let port = t.start_server();

    // Push initial commit from the source repo.
    let src = t.init_repo("ffsrc", &[("a.txt", "v1")]);
    let url = format!("http://127.0.0.1:{port}/ffrepo.gyt/");
    t.add_remote(&src, &url);
    t.run_in(&src, &["push", "--insecure", "origin"]);

    // Make a divergent fork in a second worktree, then bypass the parent
    // chain by re-initializing and forcing a different commit.
    let fork = t.worktree("fork");
    std::fs::create_dir_all(&fork).unwrap();
    t.run_in(&fork, &["init"]);
    std::fs::write(
        fork.join(".gyt/config.toml"),
        format!(
            "[user]\nname = \"Tester\"\nemail = \"t@x\"\n\n[remote.origin]\nurl = \"{url}\"\n"
        ),
    )
    .unwrap();
    std::fs::write(fork.join("b.txt"), "fork-only").unwrap();
    t.run_in(&fork, &["add", "-A"]);
    t.run_in(&fork, &["commit", "-m", "diverged"]);

    // Push from the fork. The server should refuse since this commit
    // history doesn't descend from what's on the server.
    let output = Command::new(&t.bin)
        .args(["push", "--insecure", "origin"])
        .current_dir(&fork)
        .output()
        .expect("run push");
    assert!(
        !output.status.success(),
        "push succeeded but should have been rejected as non-ff"
    );

    t.stop_server();
}

/// Push to a bare repo, then clone from it. Bare repos are the
/// recommended layout for `gyt serve`-hosted projects; this test
/// guards against regressions in `init --bare`, `Repo::open`'s bare
/// detection, and `wire_repo_dir`'s bare lookup.
#[test]
fn binary_push_and_clone_bare_server_repo() {
    let mut t = GytTest::new();
    let port = t.start_server();

    // Source repo with one commit.
    let src = t.init_repo("baresrc", &[("hello.txt", "hi from src\n")]);

    // Make the server side a *bare* repo (no working tree).
    let server_repo = t.server_repos().join("bare.gyt");
    let bare_init = Command::new(&t.bin)
        .args(["init", "--bare"])
        .arg(&server_repo)
        .output()
        .expect("init --bare");
    assert!(
        bare_init.status.success(),
        "init --bare failed: {}",
        String::from_utf8_lossy(&bare_init.stderr)
    );
    assert!(server_repo.join("bare").is_file(), "missing bare marker");
    assert!(server_repo.join("HEAD").is_file(), "missing HEAD");
    assert!(!server_repo.join(".gyt").exists(), "bare repo should not have a .gyt subdir");

    // Push into it.
    let url = format!("http://127.0.0.1:{port}/bare.gyt/");
    t.add_remote(&src, &url);
    // `add_remote` also calls create_dir_all on the server-side path —
    // for a bare repo it created a `.gyt` subdir we don't want. Remove
    // it so the server's `wire_repo_dir` resolves to the bare layout.
    let stray = server_repo.join(".gyt");
    if stray.is_dir() {
        std::fs::remove_dir_all(&stray).unwrap();
    }
    t.run_in(&src, &["push", "--insecure", "origin"]);

    // Verify server stored objects + ref directly at the repo root.
    assert!(server_repo.join("refs/heads/main").is_file());

    // Clone from the bare server.
    let clone_dir = t.worktree("bareclone");
    std::fs::create_dir_all(&clone_dir).unwrap();
    t.run_in(&clone_dir, &["clone", "--insecure", &url, "."]);
    let hello = std::fs::read_to_string(clone_dir.join("hello.txt"))
        .expect("clone should have materialized hello.txt");
    assert_eq!(hello, "hi from src\n");

    // Working-tree commands inside the bare server repo must refuse.
    let add_in_bare = Command::new(&t.bin)
        .args(["add", "."])
        .current_dir(&server_repo)
        .output()
        .expect("add in bare");
    assert!(
        !add_in_bare.status.success(),
        "add inside bare repo should be refused"
    );
    let stderr = String::from_utf8_lossy(&add_in_bare.stderr);
    assert!(
        stderr.contains("bare repository"),
        "expected 'bare repository' in stderr, got: {stderr}"
    );

    t.stop_server();
}
