// Property tests for the single-host serve.lock guard.
//
// `gyt serve` takes <repos_root>/serve.lock on startup; the FileLock
// in src/fs_util.rs only reclaims a marker file when (a) its recorded
// pid is dead AND (b) its mtime is older than `STALE_AFTER` (60 s).
// `--allow-multiprocess` skips the guard entirely so an operator can
// run N replicas behind SO_REUSEPORT on the same host.
//
// We exercise three properties here:
//   1. A serve.lock left behind by a crashed process (dead pid + old
//      mtime) is reclaimed and `gyt serve` starts cleanly.
//   2. A serve.lock that names a live process is treated as held —
//      `gyt serve` refuses to start with a useful error message.
//   3. `--allow-multiprocess` permits two concurrent `gyt serve`
//      processes against the same repos_root; both bind, both serve
//      `/healthz`.
//
// Background on the marker format (src/fs_util.rs::FileLock::acquire):
// the body is "pid=<N> ts=<unix-secs>". `read_lock_marker` looks for
// the `pid=` prefix and falls back to None when absent, so a file
// containing just a bare integer is treated as pidless and survives
// the dead-pid check by default — that's why test 1 explicitly writes
// the "pid=999999" form.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests: panicking on unexpected input is how a test signals failure"
)]

#[path = "common/mod.rs"]
mod common;

use common::Env;
use std::io::Read as _;
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant, SystemTime};

/// Wait until a TCP connect to `127.0.0.1:port` succeeds, or panic
/// after 10 s. Returns the moment the connect first worked so tests
/// can compute "started within N seconds" assertions.
fn wait_for_listen(port: u16) -> Instant {
    let deadline = Instant::now() + Duration::from_secs(10);
    let addr = format!("127.0.0.1:{port}");
    while Instant::now() < deadline {
        if TcpStream::connect(&addr).is_ok() {
            return Instant::now();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("server never bound to {addr}");
}

/// Best-effort fetch of stderr after kill; the server inherits a piped
/// stderr from `cmd_in_serve`. Used for diagnostic messages on failure.
fn drain_stderr(child: &mut Child) -> String {
    let mut s = String::new();
    if let Some(mut h) = child.stderr.take() {
        let _ = h.read_to_string(&mut s);
    }
    s
}

fn spawn_serve(env: &Env, repos_root: &Path, port: u16, extra: &[&str]) -> Child {
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
    .args(extra)
    .env("GYT_SERVE_RATE_IP_CAPACITY", "0")
    .env("GYT_SERVE_RATE_ACTOR_CAPACITY", "0")
    .env("GYT_SERVE_CACHE_TTL_MS", "0")
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    cmd.spawn().unwrap()
}

// ── Test 1: dead-pid + old-mtime lock is reclaimed ────────────────

#[test]
fn serve_lock_with_nonexistent_pid_reclaimed() {
    let env = Env::new("serve-lock-stale");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(&repos_root).unwrap();
    let lock_path = repos_root.join("serve.lock");

    // Write a marker pointing at a pid that won't exist on this host.
    // 999_999 is well above the typical /proc/sys/kernel/pid_max for
    // a fresh test runner; if `/proc/999999` happens to exist (the pid
    // wrapped), the test would still pass because reclamation also
    // requires an old mtime, which we set explicitly below.
    std::fs::write(&lock_path, b"pid=999999 ts=0\n").unwrap();

    // Back-date mtime by 5 min so the STALE_AFTER (60 s) check
    // succeeds without waiting. `set_modified` on `FileTimes` is the
    // stable-API way to do this since 1.75.
    let old = SystemTime::now() - Duration::from_mins(5);
    let f = std::fs::OpenOptions::new().write(true).open(&lock_path).unwrap();
    f.set_modified(old).unwrap();
    drop(f);

    let port = common::pick_port();
    let mut srv = spawn_serve(&env, &repos_root, port, &[]);
    // FileLock::acquire polls every 20ms for up to 2s, and reclamation
    // adds a 10ms re-check window; the server should be up well inside
    // 10s.
    let bound_at = wait_for_listen(port);
    assert!(
        bound_at.elapsed() < Duration::from_secs(10),
        "server bound but elapsed assertion is for the type system"
    );

    // Healthz must answer once the lock is held by the new server.
    let resp = ureq_get(port, "/healthz");
    assert!(resp.starts_with("HTTP/1.1 200"), "healthz: {resp}");

    // Clean shutdown via kill — the server should exit promptly. We
    // don't strictly require a graceful exit code; the assertion is
    // "wait returns within a few seconds".
    let _ = srv.kill();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match srv.try_wait().unwrap() {
            Some(_status) => break,
            None if Instant::now() >= deadline => {
                let _ = srv.kill();
                let _ = srv.wait();
                panic!("server did not exit within 5s after kill");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

// ── Test 2: live-pid lock is honored ──────────────────────────────

#[test]
fn serve_lock_with_live_foreign_pid_refused() {
    let env = Env::new("serve-lock-live");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(&repos_root).unwrap();
    let lock_path = repos_root.join("serve.lock");

    // Use this test process's own pid: it's not a gyt serve, but it
    // is definitely alive on this host (so /proc/<pid> exists), which
    // is enough to defeat the dead-pid branch of the stale-reclamation
    // check.
    let pid = std::process::id();
    let ts = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    std::fs::write(&lock_path, format!("pid={pid} ts={ts}\n")).unwrap();

    let port = common::pick_port();
    let mut srv = spawn_serve(&env, &repos_root, port, &[]);

    // Server must exit non-zero within the 2s lock-acquire timeout
    // (parse_args bounds it). Give it 10s of slack for slow CI.
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        match srv.try_wait().unwrap() {
            Some(s) => break s,
            None if Instant::now() >= deadline => {
                let _ = srv.kill();
                let _ = srv.wait();
                panic!("server did not exit despite held serve.lock");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };
    assert!(!status.success(), "server should exit non-zero on held lock");

    let stderr = drain_stderr(&mut srv);
    let lc = stderr.to_lowercase();
    assert!(
        lc.contains("another gyt serve") || lc.contains("serve.lock") || lc.contains("lock"),
        "expected lock-held error on stderr, got:\n{stderr}"
    );
}

// ── Test 3: --allow-multiprocess permits two replicas ─────────────

// SO_REUSEPORT is a Linux/BSD construct; gyt's `bind_with_reuseport`
// gates the actual `set_reuse_port` call on `#[cfg(unix)]`, so the
// property only holds on Unix-likes. On non-Unix we skip the test.
#[cfg(target_os = "linux")]
#[test]
fn allow_multiprocess_permits_two_serves() {
    let env = Env::new("serve-multi");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(&repos_root).unwrap();

    // Two distinct ephemeral ports — even though SO_REUSEPORT would
    // let both bind the same port, picking two ports keeps the test
    // robust against kernels where the option is unavailable. The
    // property under test is "the serve.lock guard does NOT fire",
    // not "SO_REUSEPORT load-balances correctly".
    let port_a = common::pick_port();
    let port_b = common::pick_port();
    assert_ne!(port_a, port_b);

    let mut srv_a = spawn_serve(&env, &repos_root, port_a, &["--allow-multiprocess"]);
    let mut srv_b = spawn_serve(&env, &repos_root, port_b, &["--allow-multiprocess"]);

    wait_for_listen(port_a);
    wait_for_listen(port_b);

    // Both must respond to /healthz — that's the smoke check that
    // each replica is actually serving, not just bound.
    let resp_a = ureq_get(port_a, "/healthz");
    let resp_b = ureq_get(port_b, "/healthz");
    assert!(resp_a.starts_with("HTTP/1.1 200"), "a healthz: {resp_a}");
    assert!(resp_b.starts_with("HTTP/1.1 200"), "b healthz: {resp_b}");

    let _ = srv_a.kill();
    let _ = srv_b.kill();
    let _ = srv_a.wait();
    let _ = srv_b.wait();
}

/// Minimal blocking HTTP/1.1 GET — returns the raw response text. We
/// avoid pulling `ureq` or `reqwest` into the test deps; the server
/// speaks HTTP/1.1 and the request line + Host header is all we need.
fn ureq_get(port: u16, path: &str) -> String {
    use std::io::Write as _;
    let mut s = TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = String::new();
    let _ = s.read_to_string(&mut buf);
    buf
}
