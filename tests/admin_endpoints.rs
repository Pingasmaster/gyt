// Property tests for the operator admin endpoints:
//   - POST /admin/shutdown   — auth-gated, rw-only, requires TLS or
//                              explicit GYT_SERVE_ALLOW_PLAIN_ADMIN=1
//   - GET  /metrics          — auth-gated when ACLs are configured
//                              (H11: previously unauth, exposed
//                              probing/amplification surface)
//   - GET  /healthz          — always unauth (operator probe)
//
// All tests bind loopback and configure auth via --auth-tokens with
// two entries:
//     ro   *   ro
//     rw   *   rw
// On loopback the server permits plain HTTP without
// --allow-plaintext-auth; we then opt in to admin-over-plain via
// GYT_SERVE_ALLOW_PLAIN_ADMIN=1 for the shutdown tests that need it,
// and deliberately omit it for the "plain HTTP blocked" test.

#![expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "integration tests: panicking on unexpected input is how a test signals failure"
)]

#[path = "common/mod.rs"]
mod common;

use common::Env;
use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Stdio};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// Admin endpoint tests each spawn a server, pick an ephemeral port,
/// and exchange a handful of HTTP/1.1 messages. Under `--test-threads=16`
/// the port-picker race (kernel reassigns a freed ephemeral port to a
/// sibling test between `pick_port`'s drop and gyt's bind) makes the
/// shutdown drain test reliably flake (sees `code == 0` on the first
/// POST). Serializing the file's tests eliminates the race without
/// changing test-process parallelism for the rest of the suite.
static SERIAL: Mutex<()> = Mutex::new(());

fn serialize() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

struct Server {
    child: Child,
    port: u16,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_tokens_file(env: &Env) -> std::path::PathBuf {
    let p = env.path("tokens");
    // TSV: <token>\t<pattern>\t<rw|ro>. Pattern `*` is the only one
    // that authorizes non-wire routes like /admin/shutdown — those
    // have no per-repo segment in the URL.
    std::fs::write(&p, b"ro\t*\tro\nrw\t*\trw\n").unwrap();
    p
}

fn spawn_server(env: &Env, repos_root: &Path, tokens: &Path, allow_plain_admin: bool) -> Server {
    let port = common::pick_port();
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
        "--auth-tokens",
        &tokens.display().to_string(),
    ])
    // Disable rate limits + caches: every test issues at most a few
    // requests, and we don't want a stray ratelimit to flake a 401
    // assertion into a 429.
    .env("GYT_SERVE_RATE_IP_CAPACITY", "0")
    .env("GYT_SERVE_RATE_ACTOR_CAPACITY", "0")
    .env("GYT_SERVE_CACHE_TTL_MS", "0")
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    if allow_plain_admin {
        cmd.env("GYT_SERVE_ALLOW_PLAIN_ADMIN", "1");
    } else {
        cmd.env_remove("GYT_SERVE_ALLOW_PLAIN_ADMIN");
    }
    let mut child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        // TCP connect is not enough — the kernel queues a SYN before the
        // accept loop is wired up, so connect can succeed against a
        // server whose request pipeline isn't yet live. Probe the actual
        // HTTP path: /healthz is always unauth and returns 200 once the
        // server is processing requests. Without this hardening, tests
        // see `code == 0` on the first POST when the server is still
        // initialising — and the port may also have been re-assigned to
        // a different test by the kernel between `pick_port`'s drop and
        // gyt's bind.
        if let Ok(mut s) = TcpStream::connect(&addr) {
            let _ = s.set_read_timeout(Some(Duration::from_secs(1)));
            let _ = s.write_all(
                b"GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
            );
            let mut buf = String::new();
            let _ = s.read_to_string(&mut buf);
            if buf.starts_with("HTTP/1.1 200") {
                return Server { child, port };
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Reap before panicking so we don't leak a zombie.
    let _ = child.kill();
    let _ = child.wait();
    panic!("server didn't start");
}

/// Build + send a raw HTTP/1.1 request and parse the status line.
/// Returns (status_code, full_response_text). We hand-roll this to
/// avoid pulling in an HTTP client crate just for the test suite.
///
/// Retries once on a code==0 (parse failure / connection torn before
/// response landed). The retry guards against the rare case where the
/// server has bound but isn't yet servicing requests on the freshly-
/// accepted socket; the retry path waits 100 ms then re-opens the
/// connection. The first call is still cheap on the happy path.
fn http_request(port: u16, method: &str, path: &str, headers: &[(&str, &str)]) -> (u16, String) {
    for attempt in 0..2 {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(100));
        }
        let Ok(mut s) = TcpStream::connect(format!("127.0.0.1:{port}")) else {
            continue;
        };
        let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
        let mut req = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("Content-Length: 0\r\n\r\n");
        if s.write_all(req.as_bytes()).is_err() {
            continue;
        }
        let mut body = String::new();
        let _ = s.read_to_string(&mut body);
        let code = body
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);
        if code != 0 {
            return (code, body);
        }
    }
    (0, String::new())
}

// ── /admin/shutdown unauth path ───────────────────────────────────

#[test]
fn admin_shutdown_unauth_returns_401_or_403() {
    let _serial = serialize();
    let env = Env::new("admin-unauth");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(&repos_root).unwrap();
    let tokens = write_tokens_file(&env);
    let mut srv = spawn_server(&env, &repos_root, &tokens, true);
    let (code, _) = http_request(srv.port, "POST", "/admin/shutdown", &[]);
    // No bearer header → authorize() returns false → dispatch_request
    // emits 401. We accept 403 too in case the policy gate is moved
    // ahead of the auth gate in the future.
    assert!(code == 401 || code == 403, "expected 401/403, got {code}");
    let _ = srv.child.kill();
    let _ = srv.child.wait();
}

#[test]
fn admin_shutdown_ro_token_403() {
    let _serial = serialize();
    let env = Env::new("admin-ro");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(&repos_root).unwrap();
    let tokens = write_tokens_file(&env);
    let mut srv = spawn_server(&env, &repos_root, &tokens, true);
    // RO token is valid but its ACL entry has write=false; admin
    // shutdown is in the route_needs_write set, so the entry's
    // perm_ok=false and authorize() denies. Returns 401 today (we
    // accept 403 for forward-compat).
    let (code, _) = http_request(
        srv.port,
        "POST",
        "/admin/shutdown",
        &[("Authorization", "Bearer ro")],
    );
    assert!(code == 401 || code == 403, "expected 401/403, got {code}");
    let _ = srv.child.kill();
    let _ = srv.child.wait();
}

#[test]
fn admin_shutdown_rw_token_202_and_drains() {
    let _serial = serialize();
    let env = Env::new("admin-rw");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(&repos_root).unwrap();
    let tokens = write_tokens_file(&env);
    let mut srv = spawn_server(&env, &repos_root, &tokens, true);

    let (code, body) = http_request(
        srv.port,
        "POST",
        "/admin/shutdown",
        &[("Authorization", "Bearer rw")],
    );
    // The server flips the shutdown flag and notifies *all* connection
    // tasks — including the one that just emitted the 202 — to call
    // `graceful_shutdown`. With some scheduling orders the response is
    // torn before the test reads its status line (code==0). The
    // observable invariant the operator cares about is "shutdown
    // happened"; we assert that below by waiting for the child to exit.
    // Either 202 or a torn response (code==0) is consistent with that.
    assert!(
        code == 202 || code == 0,
        "rw shutdown expected 202 or torn response, got {code}: {body}",
    );

    // The handler flips the shutdown flag and self-connects to break
    // accept(). The accept loop and connection tasks then drain; the
    // SHUTDOWN_TIMEOUT_SECS in src/net/server.rs is 30 s but in
    // practice with no in-flight requests it's milliseconds.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match srv.child.try_wait().unwrap() {
            Some(status) => {
                // Graceful exits return 0 on success.
                assert!(status.success(), "shutdown should exit 0, got {status:?}");
                return;
            }
            None if Instant::now() >= deadline => {
                let _ = srv.child.kill();
                let _ = srv.child.wait();
                panic!("server did not exit within 15s of /admin/shutdown");
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

#[test]
fn admin_shutdown_plain_http_blocked() {
    let _serial = serialize();
    let env = Env::new("admin-plain");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(&repos_root).unwrap();
    let tokens = write_tokens_file(&env);
    // Crucially: DO NOT pass GYT_SERVE_ALLOW_PLAIN_ADMIN=1. Even with
    // a valid rw token, plain HTTP /admin/shutdown must be refused so
    // an on-path attacker who lifted the token (only possible on
    // plaintext) can't drain the server.
    let mut srv = spawn_server(&env, &repos_root, &tokens, false);
    let (code, body) = http_request(
        srv.port,
        "POST",
        "/admin/shutdown",
        &[("Authorization", "Bearer rw")],
    );
    assert_eq!(code, 403, "plain-HTTP shutdown should be 403, got {code}: {body}");
    let _ = srv.child.kill();
    let _ = srv.child.wait();
}

// ── /metrics is auth-gated; /healthz is not ───────────────────────

#[test]
fn metrics_requires_auth_when_configured() {
    let _serial = serialize();
    let env = Env::new("admin-metrics");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(&repos_root).unwrap();
    let tokens = write_tokens_file(&env);
    let mut srv = spawn_server(&env, &repos_root, &tokens, true);
    // H11: /metrics used to be in the unauth-probe set. Confirm it
    // now requires a bearer token when ACLs are configured.
    let (code, _) = http_request(srv.port, "GET", "/metrics", &[]);
    assert_eq!(code, 401, "unauth /metrics should be 401, got {code}");
    let _ = srv.child.kill();
    let _ = srv.child.wait();
}

#[test]
fn healthz_no_auth_required() {
    let _serial = serialize();
    let env = Env::new("admin-healthz");
    let repos_root = env.path("repos");
    std::fs::create_dir_all(&repos_root).unwrap();
    let tokens = write_tokens_file(&env);
    let mut srv = spawn_server(&env, &repos_root, &tokens, true);
    // /healthz must stay reachable for k8s/LB probes regardless of
    // auth config (route_is_unauth_probe returns true for it).
    let (code, body) = http_request(srv.port, "GET", "/healthz", &[]);
    assert_eq!(code, 200, "unauth /healthz should be 200, got {code}: {body}");
    let _ = srv.child.kill();
    let _ = srv.child.wait();
}
