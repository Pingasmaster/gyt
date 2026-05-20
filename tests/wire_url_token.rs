// Audit 2026-05: URL-embedded bearer tokens.
//
// `https://<token>@host/repo` is parsed by `src/net/http.rs` (lines
// 124-145) into an `Authorization: Bearer <token>` header. This is
// the GitHub/GitLab idiom and the project's recommended way to embed
// a token in a stored remote URL. The parser also rejects raw control
// bytes (CR/LF/etc.) anywhere in the authority — including the token
// — so a malicious URL cannot inject header lines.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "tests panic on failure"
)]
#![expect(
    clippy::zombie_processes,
    reason = "test harness lets the child be cleaned up at drop time"
)]

#[path = "common/mod.rs"]
mod common;

use std::net::TcpStream;
use std::path::Path;
use std::process::Child;
use std::time::{Duration, Instant};

use common::{Env, pick_port};

fn start_server_with_acl(env: &Env, repos_root: &Path, acl_file: &Path) -> (Child, u16) {
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
            "--auth-tokens",
            &acl_file.display().to_string(),
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
        if TcpStream::connect(&addr).is_ok() {
            return (child, port);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("server didn't start");
}

// ─── 1. URL-token becomes Bearer auth ────────────────────────────────
//
// `http://tokenA@127.0.0.1:N/repo` MUST be treated the same as an
// explicit `Authorization: Bearer tokenA` header on the wire. Pin this
// by serving a repo that only `tokenA` is allowed to read; clone with
// the token in the URL must succeed, clone without any token must fail.

#[test]
fn url_token_becomes_bearer_auth() {
    let env = Env::new("url-tok-bearer");
    let repos_root = env.path("server_repos");
    std::fs::create_dir_all(repos_root.join("r1")).unwrap();
    env.ok_in(&repos_root.join("r1"), &["init", "--bare"]);

    // ACL: tokenA gets rw on r1; nothing else has any access.
    let acl = env.path("acl.tsv");
    std::fs::write(&acl, b"tokenA\tr1\trw\n").unwrap();

    let (mut srv, port) = start_server_with_acl(&env, &repos_root, &acl);

    // First push some content so `clone` has something to fetch.
    let seed = env.fresh_repo("seed");
    let push_url = format!("http://tokenA@127.0.0.1:{port}/r1");
    env.ok_in(&seed, &["remote", "add", "origin", &push_url]);
    env.ok_in(&seed, &["push", "--insecure", "origin", "--all"]);

    // Clone WITH token in URL → must succeed.
    let with_tok = env.path("with-tok");
    let url_with = format!("http://tokenA@127.0.0.1:{port}/r1");
    env.ok_in(
        &env.dir,
        &["clone", "--insecure", &url_with, &with_tok.display().to_string()],
    );

    // Clone WITHOUT token → must fail (401/403 from server).
    let without = env.path("without-tok");
    let url_without = format!("http://127.0.0.1:{port}/r1");
    let (_out, err) = env.fail_in(
        &env.dir,
        &["clone", "--insecure", &url_without, &without.display().to_string()],
    );
    assert!(
        err.contains("401") || err.contains("403") || err.to_ascii_lowercase().contains("auth"),
        "expected auth-related error without token, got: {err}"
    );

    let _ = srv.kill();
    let _ = srv.wait();
}

// ─── 2. CR/LF in URL token rejected before connect ───────────────────
//
// A token containing a literal CR byte must be rejected by the URL
// parser before any socket is opened — otherwise it would `format!`
// into the Authorization header and inject downstream HTTP headers.
// Note: the parser checks RAW bytes, not percent-decoded; we therefore
// embed a literal `\r` byte. (A `%0D` would pass the check because
// `%`, `0`, `D` are all printable.)

#[test]
fn url_token_with_cr_lf_rejected() {
    let env = Env::new("url-tok-crlf");
    let r = env.fresh_repo("r");
    // Literal \r in the token. Pass via command line — `gyt` reads
    // os args as raw bytes (lossily via String, but \r survives).
    let bad_url = "http://to\rken@127.0.0.1:1/no-such-repo";
    env.ok_in(&r, &["remote", "add", "origin", bad_url]);
    let out = env.run_in(&r, &["fetch", "--insecure", "origin"]);
    assert!(
        !out.status.success(),
        "fetch with CR-in-token must fail before connecting"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // Two ways this can surface:
    //   - the URL parser ("control byte 0x0d in authority")
    //   - earlier sanitisation in remote-add or arg-parse
    assert!(
        stderr.to_ascii_lowercase().contains("control byte")
            || stderr.to_ascii_lowercase().contains("invalid")
            || stderr.to_ascii_lowercase().contains("url"),
        "expected URL-validation error, got: {stderr}"
    );
}

// ─── 3. Bare `@host` (empty user) ────────────────────────────────────
//
// `http://@host/repo` — the authority is `@host`, rsplit_once('@')
// yields ("", "host"). The parser currently stores `Some("".to_string())`
// as the bearer token. The control-byte loop accepts the empty string.
// Pin this behavior: the URL must be accepted (no crash, no auth
// error from the client). Whether the server then accepts the empty
// bearer is a separate concern — we only pin that the client doesn't
// reject the URL itself.

#[test]
fn url_token_empty_at_host() {
    let env = Env::new("url-tok-empty");
    let repos_root = env.path("server_repos");
    std::fs::create_dir_all(repos_root.join("r1")).unwrap();
    env.ok_in(&repos_root.join("r1"), &["init", "--bare"]);

    // No auth required on the server — anyone can clone /r1.
    // Start a plain (no-ACL) serve.
    let port = pick_port();
    let addr = format!("127.0.0.1:{port}");
    let webroot = env.path("web");
    std::fs::create_dir_all(&webroot).unwrap();
    let mut srv = env
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
        if TcpStream::connect(&addr).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Seed the bare repo so clone has refs to fetch.
    let seed = env.fresh_repo("seed");
    let push_url = format!("http://127.0.0.1:{port}/r1");
    env.ok_in(&seed, &["remote", "add", "origin", &push_url]);
    env.ok_in(&seed, &["push", "--insecure", "origin", "--all"]);

    // `http://@host/repo`: empty token before the `@`. Pin: the URL
    // is accepted by the parser (no "missing host", no crash). The
    // request may succeed or fail depending on whether the server
    // tolerates an empty bearer — we don't assert on that.
    let target = env.path("via-at");
    let url_at = format!("http://@127.0.0.1:{port}/r1");
    let out = env.run_in(
        &env.dir,
        &["clone", "--insecure", &url_at, &target.display().to_string()],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The URL parser must NOT reject this as "missing host" or
    // "control byte". Other server-side errors are acceptable.
    assert!(
        !stderr.contains("missing host"),
        "empty-user URL wrongly treated as missing host: {stderr}"
    );
    assert!(
        !stderr.contains("control byte"),
        "empty-user URL wrongly flagged as control byte: {stderr}"
    );

    let _ = srv.kill();
    let _ = srv.wait();
}
