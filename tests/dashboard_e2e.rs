// Audit 2026-05: end-to-end dashboard / operator endpoints.
//
// Spawns `gyt serve` and exercises:
//   - /metrics returns text/plain Prometheus-format with `# TYPE`.
//   - /metrics has no duplicate `# TYPE <name>` lines (strict
//     OpenMetrics).
//   - /healthz returns 200 with no auth required.
//   - When --auth-tokens is configured, /metrics and /api/repos return
//     401 to unauthenticated requests.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::zombie_processes,
    reason = "tests panic on failure; server children are reaped in Drop"
)]

#[path = "common/mod.rs"]
mod common;

use common::{Env, pick_port};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Child;
use std::time::{Duration, Instant};

struct ServerHandle {
    child: Child,
    port: u16,
}

impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_server(env: &Env, repos_root: &Path, extra: &[&str]) -> ServerHandle {
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
    .args(extra)
    .env("GYT_SERVE_RATE_IP_CAPACITY", "0")
    .env("GYT_SERVE_RATE_ACTOR_CAPACITY", "0")
    .env("GYT_SERVE_CACHE_TTL_MS", "0")
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());
    let child = cmd.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if TcpStream::connect(&addr).is_ok() {
            return ServerHandle { child, port };
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("server didn't start on {addr}");
}

struct HttpResp {
    status: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

fn http_request(addr: &str, method: &str, path: &str, auth: Option<&str>) -> HttpResp {
    let mut s = TcpStream::connect(addr).unwrap();
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n"
    );
    if let Some(tok) = auth {
        req.push_str(&format!("Authorization: Bearer {tok}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    // Split header / body on the first \r\n\r\n.
    let split = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("response has no header/body separator");
    let head = &buf[..split];
    let body = buf[split + 4..].to_vec();
    let head_str = String::from_utf8_lossy(head);
    let mut lines = head_str.lines();
    let status_line = lines.next().expect("no status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("non-numeric HTTP status");
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    HttpResp {
        status,
        headers,
        body,
    }
}

fn init_bare(env: &Env, repos_root: &Path, name: &str) {
    let p = repos_root.join(name);
    std::fs::create_dir_all(&p).unwrap();
    env.ok_in(&p, &["init", "--bare"]);
}

// ─── 1. /metrics is Prometheus text format ─────────────────────────

#[test]
fn metrics_endpoint_responds_with_prometheus_format() {
    let env = Env::new("dash-metrics-fmt");
    let repos = env.path("repos");
    init_bare(&env, &repos, "r1");
    let srv = start_server(&env, &repos, &[]);
    let addr = format!("127.0.0.1:{}", srv.port);
    let r = http_request(&addr, "GET", "/metrics", None);
    assert_eq!(r.status, 200, "GET /metrics must succeed on un-auth server");
    let ct = r
        .headers
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    assert!(
        ct.starts_with("text/plain"),
        "metrics content-type must be text/plain (got {ct:?})"
    );
    let body = String::from_utf8_lossy(&r.body);
    assert!(
        body.contains("# TYPE "),
        "Prometheus output must include `# TYPE` lines; body: {body}"
    );
    // At least one known counter must appear.
    assert!(
        body.contains("gyt_requests_total"),
        "expected `gyt_requests_total` in metrics output"
    );
}

// ─── 2. each metric name appears in `# TYPE` exactly once ──────────

#[test]
fn metrics_no_duplicate_type_lines() {
    let env = Env::new("dash-metrics-uniq");
    let repos = env.path("repos");
    init_bare(&env, &repos, "r1");
    let srv = start_server(&env, &repos, &[]);
    let addr = format!("127.0.0.1:{}", srv.port);
    let r = http_request(&addr, "GET", "/metrics", None);
    assert_eq!(r.status, 200);
    let body = String::from_utf8_lossy(&r.body);
    let mut counts: HashMap<String, u32> = HashMap::new();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("# TYPE ") {
            // `# TYPE <metric_name> <type>`
            if let Some((name, _ty)) = rest.split_once(' ') {
                *counts.entry(name.to_string()).or_insert(0) += 1;
            }
        }
    }
    assert!(!counts.is_empty(), "no `# TYPE` lines found in /metrics");
    for (name, n) in &counts {
        assert_eq!(
            *n, 1,
            "metric {name:?} appears in {n} `# TYPE` lines (must be exactly 1)"
        );
    }
}

// ─── 3. /healthz responds 200 without auth ─────────────────────────

#[test]
fn healthz_returns_200_no_auth() {
    let env = Env::new("dash-healthz");
    let repos = env.path("repos");
    init_bare(&env, &repos, "r1");
    let srv = start_server(&env, &repos, &[]);
    let addr = format!("127.0.0.1:{}", srv.port);
    let r = http_request(&addr, "GET", "/healthz", None);
    assert_eq!(
        r.status, 200,
        "/healthz must be 200 even without auth; body: {}",
        String::from_utf8_lossy(&r.body)
    );
}

// ─── 4. /metrics is 401 when auth is configured ────────────────────

#[test]
fn metrics_requires_auth_when_token_set() {
    let env = Env::new("dash-metrics-401");
    let repos = env.path("repos");
    init_bare(&env, &repos, "r1");

    // ACL grants tokenA rw on r1 — no admin/wildcard permission to
    // hit operator endpoints.
    let acl = env.path("acl.tsv");
    std::fs::write(&acl, b"tokenA\tr1\trw\n").unwrap();
    let srv = start_server(
        &env,
        &repos,
        &["--auth-tokens", acl.to_str().unwrap()],
    );
    let addr = format!("127.0.0.1:{}", srv.port);
    let r = http_request(&addr, "GET", "/metrics", None);
    assert_eq!(
        r.status, 401,
        "/metrics without Authorization must be 401 when --auth-tokens is set; body: {}",
        String::from_utf8_lossy(&r.body)
    );

    // /healthz remains open even with auth configured.
    let h = http_request(&addr, "GET", "/healthz", None);
    assert_eq!(
        h.status, 200,
        "/healthz must stay 200 even with auth configured; got {}",
        h.status
    );
}

// ─── 5. /api/repos is 401 unauth when auth is configured ───────────

#[test]
fn api_repos_endpoint_requires_auth_when_configured() {
    let env = Env::new("dash-api-401");
    let repos = env.path("repos");
    init_bare(&env, &repos, "r1");

    let acl = env.path("acl.tsv");
    std::fs::write(&acl, b"tokenA\tr1\trw\n").unwrap();
    let srv = start_server(
        &env,
        &repos,
        &["--auth-tokens", acl.to_str().unwrap()],
    );
    let addr = format!("127.0.0.1:{}", srv.port);
    let r = http_request(&addr, "GET", "/api/repos", None);
    assert_eq!(
        r.status, 401,
        "/api/repos without auth must be 401 when --auth-tokens is set; body: {}",
        String::from_utf8_lossy(&r.body)
    );
}
