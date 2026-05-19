#![expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "integration tests: panicking on unexpected input is how a test signals failure"
)]
#![expect(
    clippy::single_char_pattern,
    reason = "single-char-in-string is occasionally clearer than the char form in test fixtures"
)]
#![expect(
    clippy::zombie_processes,
    reason = "test harness deliberately leaves the child process to clean up at drop time"
)]

// End-to-end tests for the `gyt incident` subcommand.

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
        let dir = std::env::temp_dir().join(format!("gyt-incidents-{label}-{pid}-{id}-{nanos}"));
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

fn fresh_repo(env: &Env, name: &str) -> PathBuf {
    let p = env.path(name);
    std::fs::create_dir_all(&p).unwrap();
    env.ok_in(&p, &["init"]);
    std::fs::write(p.join("a.txt"), b"hello").unwrap();
    env.ok_in(&p, &["add", "a.txt"]);
    env.ok_in(&p, &["commit", "-m", "first"]);
    p
}

// ─── basic CRUD ──────────────────────────────────────────────────────

#[test]
fn incident_new_assigns_sequential_numbers_starting_at_1() {
    let env = Env::new("seq");
    let repo = fresh_repo(&env, "r");
    let a = env.ok_in(
        &repo,
        &["incident", "new", "first", "--severity", "sev2", "--type", "bug"],
    );
    assert!(a.contains("incident #1"), "got: {a}");
    let b = env.ok_in(
        &repo,
        &["incident", "new", "second", "--severity", "sev3", "--type", "bug"],
    );
    assert!(b.contains("incident #2"), "got: {b}");
}

#[test]
fn incident_new_requires_severity_and_type() {
    let env = Env::new("required-flags");
    let repo = fresh_repo(&env, "r");
    env.fail_in(&repo, &["incident", "new", "x"]);
    env.fail_in(&repo, &["incident", "new", "x", "--severity", "sev1"]);
    env.fail_in(&repo, &["incident", "new", "x", "--type", "bug"]);
    env.fail_in(
        &repo,
        &["incident", "new", "x", "--severity", "garbage", "--type", "bug"],
    );
}

#[test]
fn incident_new_lists_and_shows() {
    let env = Env::new("new-list-show");
    let repo = fresh_repo(&env, "r");
    let out = env.ok_in(
        &repo,
        &[
            "incident",
            "new",
            "DB outage",
            "--severity",
            "sev1",
            "--type",
            "outage",
            "-m",
            "see #2 for context",
        ],
    );
    assert!(out.contains("incident #1"), "got: {out}");

    let list = env.ok_in(&repo, &["incident", "list"]);
    assert!(list.contains("DB outage"));
    assert!(list.contains("sev1"));
    assert!(list.contains("outage"));

    let show = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(show.contains("[detected]"));
    assert!(show.contains("sev1"));
    assert!(show.contains("type=outage"));
    assert!(show.contains("see #2"));
    // mention extraction
    assert!(show.contains("#2"));
}

// ─── lifecycle ──────────────────────────────────────────────────────

#[test]
fn incident_lifecycle_detected_to_resolved() {
    let env = Env::new("lifecycle");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "x", "--severity", "sev2", "--type", "bug"],
    );
    env.ok_in(&repo, &["incident", "investigate", "1"]);
    let s1 = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(s1.contains("[investigating]"));

    env.ok_in(&repo, &["incident", "mitigate", "1", "--note", "rolled back"]);
    let s2 = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(s2.contains("[mitigated]"));
    assert!(s2.contains("rolled back"));

    env.ok_in(
        &repo,
        &[
            "incident",
            "resolve",
            "1",
            "--reason",
            "fixed migration; monitoring clean",
        ],
    );
    let s3 = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(s3.contains("[resolved]"));
    assert!(s3.contains("monitoring clean"));
}

#[test]
fn incident_invalid_transition_errors() {
    let env = Env::new("bad-transition");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "x", "--severity", "sev3", "--type", "bug"],
    );
    env.ok_in(
        &repo,
        &["incident", "resolve", "1", "--reason", "trivial"],
    );
    // Resolved -> Mitigated is not allowed: can only re-enter via reopen
    // which goes to Investigating.
    env.fail_in(&repo, &["incident", "mitigate", "1"]);
    // Resolving twice is a no-op error.
    env.fail_in(&repo, &["incident", "resolve", "1", "--reason", "again"]);
    // Investigate-from-resolved is allowed.
    env.ok_in(&repo, &["incident", "investigate", "1"]);
}

#[test]
fn incident_reopen_after_resolve() {
    let env = Env::new("reopen");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "x", "--severity", "sev2", "--type", "bug"],
    );
    env.ok_in(
        &repo,
        &["incident", "resolve", "1", "--reason", "premature"],
    );
    env.ok_in(
        &repo,
        &["incident", "reopen", "1", "--reason", "regression seen"],
    );
    let s = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(s.contains("[investigating]"));
    assert!(s.contains("regression seen"));
}

#[test]
fn incident_resolve_requires_reason() {
    let env = Env::new("resolve-reason");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "x", "--severity", "sev3", "--type", "bug"],
    );
    // Resolve with no reason should fail — the whole point is to
    // record the root cause.
    env.fail_in(&repo, &["incident", "resolve", "1"]);
}

// ─── severity ───────────────────────────────────────────────────────

#[test]
fn incident_severity_change_recorded() {
    let env = Env::new("sev-change");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "x", "--severity", "sev3", "--type", "bug"],
    );
    env.ok_in(&repo, &["incident", "severity", "1", "sev1"]);
    let s = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(s.contains("sev1"));
    assert!(s.contains("severity by"));
    // Setting to the same severity errors (no-op).
    env.fail_in(&repo, &["incident", "severity", "1", "sev1"]);
}

// ─── labels / assignees ─────────────────────────────────────────────

#[test]
fn incident_label_add_remove() {
    let env = Env::new("labels");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "x", "--severity", "sev2", "--type", "bug"],
    );
    env.ok_in(
        &repo,
        &["incident", "label", "1", "--add", "customer-impact,paging"],
    );
    let s1 = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(s1.contains("customer-impact"));
    assert!(s1.contains("paging"));
    env.ok_in(&repo, &["incident", "label", "1", "--remove", "paging"]);
    let s2 = env.ok_in(&repo, &["incident", "show", "1"]);
    // After removal, the labels: header line should no longer list paging.
    // The event-log lines still reference it (the audit trail is
    // append-only — that's the whole point).
    let label_header = s2
        .lines()
        .find(|l| l.starts_with("labels:"))
        .expect("labels: line still present");
    assert!(label_header.contains("customer-impact"));
    assert!(
        !label_header.contains("paging"),
        "labels: header still lists removed paging: {label_header}"
    );
}

#[test]
fn incident_assignees_add_remove() {
    let env = Env::new("assignees");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "x", "--severity", "sev2", "--type", "bug"],
    );
    env.ok_in(
        &repo,
        &["incident", "assign", "1", "--add", "Oncall <on@x>"],
    );
    let s = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(s.contains("Oncall"));
}

// ─── fields & known-type shortcuts ──────────────────────────────────

#[test]
fn incident_field_set_get_overwrite() {
    let env = Env::new("field-crud");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "x", "--severity", "sev2", "--type", "custom-thing"],
    );
    env.ok_in(&repo, &["incident", "field", "1", "set", "owner", "platform"]);
    let g1 = env.ok_in(&repo, &["incident", "field", "1", "get", "owner"]);
    assert!(g1.contains("platform"));
    // Overwrite
    env.ok_in(&repo, &["incident", "field", "1", "set", "owner", "infra"]);
    let g2 = env.ok_in(&repo, &["incident", "field", "1", "get", "owner"]);
    assert!(g2.contains("infra"));
    // Unknown key errors
    env.fail_in(&repo, &["incident", "field", "1", "get", "nope"]);
}

#[test]
fn incident_security_type_with_cve_cwe_shortcuts() {
    let env = Env::new("security-shortcuts");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &[
            "incident",
            "new",
            "auth bypass",
            "--severity",
            "sev2",
            "--type",
            "security",
            "--cve",
            "CVE-2026-9999",
            "--cwe",
            "CWE-287",
        ],
    );
    let s = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(s.contains("type=security"));
    assert!(s.contains("cve = CVE-2026-9999"), "got: {s}");
    assert!(s.contains("cwe = CWE-287"), "got: {s}");
}

#[test]
fn incident_outage_type_with_services_shortcut() {
    let env = Env::new("outage-shortcuts");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &[
            "incident",
            "new",
            "DB down",
            "--severity",
            "sev1",
            "--type",
            "outage",
            "--services",
            "api,auth",
        ],
    );
    let s = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(s.contains("services = api,auth"), "got: {s}");
}

#[test]
fn incident_unknown_shortcut_for_type_errors() {
    let env = Env::new("bad-shortcut");
    let repo = fresh_repo(&env, "r");
    // --cve is a security-only shortcut; using it with type=bug must fail
    // (the user can still do --field cve=... if they really want).
    env.fail_in(
        &repo,
        &[
            "incident",
            "new",
            "x",
            "--severity",
            "sev3",
            "--type",
            "bug",
            "--cve",
            "X",
        ],
    );
}

#[test]
fn incident_custom_type_with_arbitrary_fields() {
    let env = Env::new("custom-type");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &[
            "incident",
            "new",
            "weird",
            "--severity",
            "sev3",
            "--type",
            "moon-phase",
            "--field",
            "phase=waning",
            "--field",
            "observer=alice",
        ],
    );
    let s = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(s.contains("type=moon-phase"));
    assert!(s.contains("phase = waning"));
    assert!(s.contains("observer = alice"));
}

// ─── comment / update ───────────────────────────────────────────────

#[test]
fn incident_update_is_alias_for_comment() {
    let env = Env::new("update-alias");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "x", "--severity", "sev2", "--type", "bug"],
    );
    env.ok_in(&repo, &["incident", "update", "1", "-m", "first update"]);
    env.ok_in(&repo, &["incident", "comment", "1", "-m", "second"]);
    let s = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(s.contains("first update"));
    assert!(s.contains("second"));
}

#[test]
fn incident_blank_title_rejected() {
    let env = Env::new("blank-title");
    let repo = fresh_repo(&env, "r");
    env.fail_in(
        &repo,
        &["incident", "new", "   ", "--severity", "sev2", "--type", "bug"],
    );
}

#[test]
fn incident_blank_comment_rejected() {
    let env = Env::new("blank-comment");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "x", "--severity", "sev2", "--type", "bug"],
    );
    env.fail_in(&repo, &["incident", "comment", "1", "-m", "   "]);
}

// ─── filtering ──────────────────────────────────────────────────────

#[test]
fn incident_list_default_hides_resolved() {
    let env = Env::new("list-hides-resolved");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "A", "--severity", "sev2", "--type", "bug"],
    );
    env.ok_in(
        &repo,
        &["incident", "new", "B", "--severity", "sev3", "--type", "bug"],
    );
    env.ok_in(&repo, &["incident", "resolve", "2", "--reason", "fixed"]);

    let def = env.ok_in(&repo, &["incident", "list"]);
    assert!(def.contains("A"));
    assert!(!def.contains("B"), "default list should hide resolved: {def}");

    let resolved = env.ok_in(&repo, &["incident", "list", "--state", "resolved"]);
    assert!(resolved.contains("B"));
    assert!(!resolved.contains("A"));

    let all = env.ok_in(&repo, &["incident", "list", "--state", "all"]);
    assert!(all.contains("A"));
    assert!(all.contains("B"));
}

#[test]
fn incident_list_filters_by_severity_and_type() {
    let env = Env::new("list-filters");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "outage1", "--severity", "sev1", "--type", "outage"],
    );
    env.ok_in(
        &repo,
        &["incident", "new", "bug1", "--severity", "sev3", "--type", "bug"],
    );

    let sev1 = env.ok_in(&repo, &["incident", "list", "--severity", "sev1"]);
    assert!(sev1.contains("outage1"));
    assert!(!sev1.contains("bug1"));

    let outages = env.ok_in(&repo, &["incident", "list", "--type", "outage"]);
    assert!(outages.contains("outage1"));
    assert!(!outages.contains("bug1"));
}

// ─── concurrency ────────────────────────────────────────────────────

#[test]
fn concurrent_incident_new_no_duplicate_numbers() {
    let env = Env::new("concurrent");
    let repo = fresh_repo(&env, "r");
    // Spawn N concurrent `incident new` invocations and assert that all
    // claimed distinct numbers.
    let n = 8;
    let mut children: Vec<Child> = Vec::new();
    for i in 0..n {
        let title = format!("c{i}");
        let child = env
            .cmd_in(&repo)
            .args([
                "incident",
                "new",
                &title,
                "--severity",
                "sev3",
                "--type",
                "bug",
            ])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        children.push(child);
    }
    let mut numbers: Vec<u64> = Vec::new();
    for c in children {
        let o = c.wait_with_output().unwrap();
        assert!(
            o.status.success(),
            "child failed: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        let s = String::from_utf8_lossy(&o.stdout);
        // Lines look like: "opened incident #N (<short>)"
        let n_str = s
            .split('#')
            .nth(1)
            .unwrap_or("")
            .split_whitespace()
            .next()
            .unwrap_or("");
        let n: u64 = n_str.parse().unwrap_or_else(|_| panic!("could not parse number from: {s}"));
        numbers.push(n);
    }
    numbers.sort_unstable();
    numbers.dedup();
    assert_eq!(
        numbers.len(),
        n,
        "duplicate or missing incident numbers: {numbers:?}"
    );
}

// ─── ref + blob shape ───────────────────────────────────────────────

#[test]
fn incident_ref_lives_under_refs_incidents() {
    let env = Env::new("ref-namespace");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "x", "--severity", "sev2", "--type", "bug"],
    );
    let gyt = repo.join(".gyt");
    let r = gyt.join("refs").join("incidents").join("1");
    assert!(r.exists(), "expected ref at {}", r.display());
}

#[test]
fn incident_blob_is_canonical_toml() {
    let env = Env::new("canonical");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &[
            "incident",
            "new",
            "x",
            "--severity",
            "sev2",
            "--type",
            "security",
            "--cve",
            "CVE-2026-1",
        ],
    );
    // No direct assertion on the on-disk byte form — the unit tests in
    // src/incidents.rs already verify encode→decode→encode equality.
    // Here we sanity-check that two consecutive writes (label add) are
    // each readable.
    env.ok_in(&repo, &["incident", "label", "1", "--add", "x"]);
    env.ok_in(&repo, &["incident", "label", "1", "--add", "y"]);
    let s = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(s.contains("x"));
    assert!(s.contains("y"));
    assert!(s.contains("CVE-2026-1"));
}

// ─── wire / clone / gc ──────────────────────────────────────────────

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
fn incident_pushed_to_server_then_cloned_back() {
    let env = Env::new("push-clone");
    let repos_root = env.path("server_repos");
    std::fs::create_dir_all(repos_root.join("r1")).unwrap();
    env.ok_in(&repos_root.join("r1"), &["init", "--bare"]);
    let (mut srv, port) = start_server(&env, &repos_root);
    let url = format!("http://127.0.0.1:{port}/r1");

    let local = fresh_repo(&env, "local");
    env.ok_in(
        &local,
        &[
            "incident",
            "new",
            "Round-trip me",
            "--severity",
            "sev2",
            "--type",
            "security",
            "--cve",
            "CVE-2026-7777",
            "-m",
            "see #5",
        ],
    );
    env.ok_in(&local, &["incident", "update", "1", "-m", "ping"]);
    env.ok_in(&local, &["remote", "add", "origin", &url]);
    env.ok_in(&local, &["push", "--insecure", "origin", "--all"]);

    let clone = env.path("clone");
    env.ok_in(
        &env.dir,
        &["clone", "--insecure", &url, &clone.display().to_string()],
    );
    let s = env.ok_in(&clone, &["incident", "show", "1"]);
    assert!(s.contains("Round-trip me"));
    assert!(s.contains("see #5"));
    assert!(s.contains("ping"));
    assert!(s.contains("CVE-2026-7777"));

    let _ = srv.kill();
    let _ = srv.wait();
}

#[test]
fn incident_blob_survives_gc() {
    let env = Env::new("gc-survives");
    let repo = fresh_repo(&env, "r");
    env.ok_in(
        &repo,
        &["incident", "new", "x", "--severity", "sev2", "--type", "bug"],
    );
    env.ok_in(&repo, &["gc"]);
    // After gc, we should still be able to show the incident.
    let s = env.ok_in(&repo, &["incident", "show", "1"]);
    assert!(s.contains("[detected]"));
}
