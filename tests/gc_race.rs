// Regression tests for the gc-vs-objects/have race (closed by
// commit "gc: objects.lock + grace + issue/PR ref seeding").
//
// What we verify here:
//   1. A loose object written within the grace window survives gc even
//      if no ref points to it. This is the property that closes the
//      "uploaded but not yet ref-updated" hole.
//   2. The issue and PR ref namespaces are reachable seeds — gc no
//      longer prunes the blobs that back refs/issues/* and refs/prs/*.
//   3. A concurrent push + gc round trip: 20 sequential pushes run
//      against a server while a background loop runs `gyt gc` on the
//      server repo; every pushed commit is observable on a final
//      clone. This is the end-to-end shape of the race.

#![allow(clippy::too_many_lines)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::single_char_pattern)]
#![allow(clippy::zombie_processes)]
#![allow(clippy::duration_suboptimal_units)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
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
        let dir = std::env::temp_dir().join(format!("gyt-gcrace-{label}-{pid}-{id}-{nanos}"));
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
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

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

#[allow(dead_code)]
fn count_loose_objects(repo: &Path) -> usize {
    let objects = repo.join(".gyt").join("objects");
    let mut n = 0;
    let Ok(top) = std::fs::read_dir(&objects) else {
        return 0;
    };
    for shard in top.flatten() {
        let p = shard.path();
        if !p.is_dir() {
            continue;
        }
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if name.len() != 2 {
            continue;
        }
        if let Ok(files) = std::fs::read_dir(&p) {
            n += files.filter_map(|f| f.ok()).filter(|f| f.path().is_file()).count();
        }
    }
    n
}

// ─── grace window ─────────────────────────────────────────────────────

#[test]
fn unreachable_object_written_after_walk_start_survives_gc() {
    // The race we're closing: a push uploads a loose object via
    // wire_objects_have *after* gc sampled refs but *before* gc's
    // refs/update lands. Such objects have mtime > walk_started; gc
    // must keep them.
    //
    // We simulate the race by writing an unreachable loose object with
    // mtime set to "now" right before invoking gc. Since gc samples
    // walk_started just before the reachability walk, our written
    // object's mtime is >= walk_started.
    let env = Env::new("walk-grace");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);
    std::fs::write(repo.join("a.txt"), b"x").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "first"]);

    let objects = repo.join(".gyt").join("objects");
    let shard = objects.join("aa");
    std::fs::create_dir_all(&shard).unwrap();
    let fpath = shard.join("0".repeat(62));
    std::fs::write(&fpath, b"some bytes that don't decode").unwrap();
    // Bump mtime to the future to model "written after gc samples
    // walk_started" — clock skew on a real distributed system could
    // produce equivalent mtimes.
    set_mtime(&fpath, std::time::SystemTime::now() + Duration::from_secs(5));

    env.ok_in(&repo, &["gc"]);
    assert!(
        fpath.exists(),
        "loose object with mtime after walk_started must survive gc"
    );
}

#[test]
fn unreachable_object_older_than_walk_start_is_pruned() {
    // Counterpoint to the test above: an unreachable object whose
    // mtime is strictly earlier than walk_started is fair game — the
    // operator's intent (`gyt gc` after a branch delete) is preserved.
    let env = Env::new("walk-prune");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);
    std::fs::write(repo.join("a.txt"), b"x").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "first"]);

    let objects = repo.join(".gyt").join("objects");
    let shard = objects.join("ab");
    std::fs::create_dir_all(&shard).unwrap();
    let fpath = shard.join("0".repeat(62));
    std::fs::write(&fpath, b"older orphan").unwrap();
    // Backdate so it's definitely older than the wall clock at gc time.
    set_mtime(&fpath, std::time::SystemTime::now() - Duration::from_secs(60 * 60));

    env.ok_in(&repo, &["gc"]);
    assert!(
        !fpath.exists(),
        "pre-walk orphan loose object must be pruned"
    );
}

// ─── issue + PR refs are reachable seeds ──────────────────────────────

#[test]
fn issue_blob_survives_gc() {
    let env = Env::new("issue-survives");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);
    std::fs::write(repo.join("a.txt"), b"x").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "first"]);

    env.ok_in(&repo, &["issue", "new", "Bug", "-m", "details"]);
    let ref_path = repo.join(".gyt").join("refs").join("issues").join("1");
    let issue_hex = std::fs::read_to_string(&ref_path).unwrap().trim().to_string();

    // Wait past the grace window so the blob is gc-eligible if not seeded.
    // Use file_touch with an old mtime instead of actual sleep.
    let objects = repo.join(".gyt").join("objects");
    let shard = objects.join(&issue_hex[..2]);
    let fpath = shard.join(&issue_hex[2..]);
    assert!(fpath.exists(), "issue blob must exist: {fpath:?}");
    // Set mtime in the past so the grace window can't save it — we
    // want to prove the *reachability seeding* keeps it alive.
    set_mtime(&fpath, std::time::SystemTime::now() - Duration::from_secs(60 * 60));

    env.ok_in(&repo, &["gc"]);
    assert!(fpath.exists(), "issue blob must survive gc (seeded as reachable)");
}

#[test]
fn pr_blob_survives_gc() {
    let env = Env::new("pr-survives");
    let repo = env.path("r");
    std::fs::create_dir_all(&repo).unwrap();
    env.ok_in(&repo, &["init"]);
    std::fs::write(repo.join("a.txt"), b"x").unwrap();
    env.ok_in(&repo, &["add", "a.txt"]);
    env.ok_in(&repo, &["commit", "-m", "first"]);
    env.ok_in(&repo, &["switch", "-c", "topic"]);
    std::fs::write(repo.join("b.txt"), b"y").unwrap();
    env.ok_in(&repo, &["add", "b.txt"]);
    env.ok_in(&repo, &["commit", "-m", "feature"]);
    env.ok_in(&repo, &["switch", "main"]);

    env.ok_in(
        &repo,
        &["pr", "new", "Add X", "--source", "topic", "--target", "main", "-m", "ready"],
    );
    let ref_path = repo.join(".gyt").join("refs").join("prs").join("1");
    let pr_hex = std::fs::read_to_string(&ref_path).unwrap().trim().to_string();
    let objects = repo.join(".gyt").join("objects");
    let fpath = objects.join(&pr_hex[..2]).join(&pr_hex[2..]);
    assert!(fpath.exists());
    set_mtime(&fpath, std::time::SystemTime::now() - Duration::from_secs(60 * 60));

    env.ok_in(&repo, &["gc"]);
    assert!(fpath.exists(), "pr blob must survive gc (seeded as reachable)");
}

fn set_mtime(p: &Path, t: std::time::SystemTime) {
    // utime equivalent. Use std::fs::OpenOptions to touch + set time
    // via libc-free path: open and write to set ctime; for mtime, use
    // the file_times API.
    let f = std::fs::OpenOptions::new().write(true).open(p).unwrap();
    let times = std::fs::FileTimes::new().set_modified(t).set_accessed(t);
    f.set_times(times).unwrap();
}

// ─── concurrent push + gc soak ────────────────────────────────────────

#[test]
fn concurrent_push_while_gc_runs_no_data_loss() {
    let env = Env::new("push-gc");
    let repos = env.path("server_repos");
    let server_repo = repos.join("r1");
    std::fs::create_dir_all(&server_repo).unwrap();
    env.ok_in(&server_repo, &["init", "--bare"]);
    let (mut srv, port) = start_server(&env, &repos);
    let url = format!("http://127.0.0.1:{port}/r1");

    // Seed the server with one commit so subsequent pushes are ff.
    let seed = env.path("seed");
    std::fs::create_dir_all(&seed).unwrap();
    env.ok_in(&seed, &["init"]);
    std::fs::write(seed.join("a.txt"), b"0").unwrap();
    env.ok_in(&seed, &["add", "a.txt"]);
    env.ok_in(&seed, &["commit", "-m", "seed"]);
    env.ok_in(&seed, &["remote", "add", "origin", &url]);
    env.ok_in(&seed, &["push", "--insecure", "origin", "main"]);

    // Background: run gc on the server repo continuously while the
    // foreground pushes commits.
    let stop = Arc::new(AtomicBool::new(false));
    let stop_clone = stop.clone();
    let server_repo_clone = server_repo.clone();
    let bin = env.bin.clone();
    let dir = env.dir.clone();
    let gc_thread = std::thread::spawn(move || {
        let mut gc_runs = 0;
        while !stop_clone.load(Ordering::Relaxed) {
            let out = Command::new(&bin)
                .current_dir(&server_repo_clone)
                .env("GYT_AUTHOR_NAME", "Test User")
                .env("GYT_AUTHOR_EMAIL", "test@example.com")
                .env("HOME", &dir)
                .args(["gc"])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "gc must always succeed (could time out on objects.lock; current cap is 30s): {}",
                String::from_utf8_lossy(&out.stderr)
            );
            gc_runs += 1;
            std::thread::sleep(Duration::from_millis(20));
        }
        gc_runs
    });

    // 20 sequential commits + pushes.
    let mut pushed_commits = Vec::new();
    for i in 0..20 {
        std::fs::write(seed.join("a.txt"), format!("{i}")).unwrap();
        env.ok_in(&seed, &["add", "a.txt"]);
        env.ok_in(&seed, &["commit", "-m", &format!("c{i}")]);
        let log = env.ok_in(&seed, &["log", "--oneline", "-n", "1"]);
        let hex = log.split_whitespace().next().unwrap().to_string();
        pushed_commits.push(hex);
        env.ok_in(&seed, &["push", "--insecure", "origin", "main"]);
    }

    stop.store(true, Ordering::Relaxed);
    let gc_runs = gc_thread.join().unwrap();
    assert!(gc_runs > 0, "background gc never ran");

    // Final clone and verify every pushed commit is reachable.
    let clone = env.path("clone");
    env.ok_in(
        &env.dir,
        &["clone", "--insecure", &url, &clone.display().to_string()],
    );
    let log = env.ok_in(&clone, &["log", "--oneline"]);
    for hex in &pushed_commits {
        assert!(
            log.contains(hex.as_str()),
            "clone is missing commit {hex} after concurrent gc + push:\nlog:\n{log}"
        );
    }

    let _ = srv.kill();
    let _ = srv.wait();
}
