// Production HTTP/1.1 server for the gith1b API.
//
// Serves:
//   - REST JSON API under /api/
//   - Static files for the frontend from a configurable webroot
//   - The gyt wire protocol under /info/refs, /objects/want, etc.
//
// The server is single-threaded per connection with graceful shutdown
// support. Multi-repo: the `repos_root` directory contains
// `:owner/:name/` directories, each a gyt worktree (with .gyt inside).

use crate::cmd::util;
use crate::diff;
use crate::errors::Result;
use crate::hash::ObjectId;
use crate::net::api::{
    self, BlobInfo, CommitInfo, DiffFileInfo, DiffHunkInfo, DiffLine, RefInfo, RepoInfo,
    TreeEntryInfo,
};
use crate::net::metrics::Metrics;
use crate::net::refs_policy;
use crate::net::router::{self, Handler};
use crate::object::{commit, tree};
use crate::refs;
use std::io::{BufRead, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

/// Hard cap on request body size. Anything over this is refused before
/// the server tries to allocate a buffer for it.
const MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Maximum number of concurrent connection workers. 256 is sized for
/// a single multi-tenant host serving CI runners + clones; raise via
/// recompile if a deployment justifies more. Each worker is a real
/// OS thread; values past ~1000 start to lose to scheduler overhead.
const MAX_WORKERS: usize = 256;

/// Body the server writes when it refuses a connection due to pool
/// exhaustion. Sent before the socket is dropped so clients see a
/// real HTTP response instead of a TCP RST.
const POOL_FULL_RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
Connection: close\r\n\
Retry-After: 1\r\n\
Content-Length: 24\r\n\
Content-Type: text/plain\r\n\
\r\n\
server pool exhausted\r\n";

pub struct ServeConfig {
    pub listen_addr: String,
    pub repos_root: PathBuf,
    pub webroot: PathBuf,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub auth_token: Option<String>,
    /// Path to a TSV ACL file. Each non-blank, non-comment line is
    /// `<token>\t<repo-pattern>\t<rw|ro>`. When set, this replaces the
    /// single-token `auth_token` mode: every request must present a
    /// bearer token that matches at least one ACL entry whose pattern
    /// covers the requested repo and whose perm is sufficient for the
    /// operation (writes require `rw`; reads accept either).
    pub auth_tokens_file: Option<PathBuf>,
    /// Path to an allowed_signers file used by *every* repo this server
    /// hosts. Takes precedence over a per-repo `<gyt>/allowed_signers` so
    /// a pusher with write access to a repo can't bootstrap trust by
    /// editing their own key into the list.
    pub signers_file: Option<PathBuf>,
    /// Path to a server-side policy TOML that overrides per-repo
    /// `[commit].sign_required`. Format mirrors the in-repo config; only
    /// the `[commit].sign_required` boolean is currently consulted. The
    /// motivation is the same as `signers_file`: a pusher with write
    /// access to `.gyt/config.toml` could otherwise flip the flag off
    /// for their own next push.
    pub policy_config: Option<PathBuf>,
}

struct Request {
    method: String,
    target: String,
    body: Vec<u8>,
    auth_header: Option<String>,
    /// True iff the request sent `Connection: close`. We default to
    /// HTTP/1.1 keep-alive otherwise and reuse the connection for the
    /// next request from the same client.
    client_wants_close: bool,
}

/// Maximum number of requests served on one keep-alive connection.
/// After this we close so a single client can't pin a worker forever.
const MAX_REQUESTS_PER_CONN: u32 = 256;

pub fn serve(config: &ServeConfig) -> Result<()> {
    // Fail fast: if the operator passed `--signers <file>` but the file
    // doesn't exist, the previous behavior was to silently fall back to
    // the in-repo `.gyt/allowed_signers` — a trust downgrade triggered
    // by a typo. Refuse to start instead.
    if let Some(p) = &config.signers_file
        && !p.exists()
    {
        return Err(crate::errors::GytError::InvalidArgument(format!(
            "--signers {} does not exist; refusing to start (would silently fall back to per-repo trust)",
            p.display()
        )));
    }
    // Likewise for --policy-config: if specified, it must exist.
    if let Some(p) = &config.policy_config
        && !p.exists()
    {
        return Err(crate::errors::GytError::InvalidArgument(format!(
            "--policy-config {} does not exist; refusing to start",
            p.display()
        )));
    }

    let listener = TcpListener::bind(&config.listen_addr)?;
    let addr = listener.local_addr()?;

    let tls_config = match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => Some(crate::net::tls::server_config(cert, key)?),
        (None, None) => None,
        _ => {
            return Err(crate::errors::GytError::InvalidArgument(
                "--cert and --key must be provided together".into(),
            ));
        }
    };

    if tls_config.is_some() {
        eprintln!("gyt serve: listening on https://{addr}");
    } else {
        eprintln!("gyt serve: listening on http://{addr}");
    }

    let auth_acl = match &config.auth_tokens_file {
        Some(p) => Some(load_acl(p)?),
        None => None,
    };

    let state = Arc::new(ServerState {
        repos_root: config.repos_root.clone(),
        webroot: config.webroot.clone(),
        auth_token: config.auth_token.clone(),
        auth_acl,
        signers_file: config.signers_file.clone(),
        policy_config: config.policy_config.clone(),
        shutdown: Mutex::new(false),
        metrics: Metrics::default(),
        listen_addr: addr,
    });
    let workers = Arc::new(WorkerLimiter::new(MAX_WORKERS));

    // Install signal handlers. SIGTERM / SIGINT flip the shutdown flag
    // and then poke our own listen socket once so the blocking accept
    // returns. Without the self-connect, the accept loop would only
    // exit on the next *real* incoming connection — k8s / systemd
    // would hit their hard-kill grace.
    install_shutdown_signals(state.clone(), addr);

    for stream in listener.incoming() {
        let st = state.clone();
        let tls = tls_config.clone();
        if *state.shutdown.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
            break;
        }
        match stream {
            Ok(mut s) => {
                state.metrics.accepts_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let _ = s.set_read_timeout(Some(std::time::Duration::from_secs(30)));
                let _ = s.set_write_timeout(Some(std::time::Duration::from_secs(30)));
                // Non-blocking permit: if the worker pool is full,
                // send a 503 with Retry-After and drop the
                // connection rather than wedging the accept loop on
                // a Condvar. Stalling the accept thread is what
                // turns a transient spike into a multi-minute
                // outage: the kernel backlog fills, new SYNs are
                // dropped by the listener, and every load balancer
                // marks us dead before our existing workers finish.
                let permit = match workers.clone().try_acquire() {
                    Some(p) => p,
                    None => {
                        // Best-effort 503 — failures (peer reset,
                        // timeout) just close the socket.
                        use std::io::Write as _;
                        state
                            .metrics
                            .pool_exhausted_total
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let _ = s.write_all(POOL_FULL_RESPONSE);
                        let _ = s.shutdown(std::net::Shutdown::Both);
                        continue;
                    }
                };
                thread::spawn(move || {
                    let _hold = permit;
                    // Catch any panic that escapes a handler. A bug
                    // in handler code that unwinds the worker thread
                    // could otherwise leave a Mutex on `state.shutdown`
                    // poisoned, degrading every subsequent connection.
                    // `AssertUnwindSafe` is appropriate here because
                    // `s` is local to this thread and `st` (Arc) is
                    // immutable from a panic-safety standpoint —
                    // panicked code can't observe a partial mutation
                    // through a shared reference because there is none.
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if let Some(cfg) = &tls {
                            match crate::net::tls::accept_tls(s, cfg) {
                                Ok(tls_stream) => {
                                    let _ = handle_tls_conn(tls_stream, &st);
                                }
                                Err(e) => {
                                    eprintln!("gyt serve: tls accept error: {e}");
                                }
                            }
                        } else {
                            let _ = handle_conn(s, &st);
                        }
                    }));
                    if let Err(payload) = result {
                        let msg = downcast_panic_payload(&payload);
                        eprintln!("gyt serve: worker panic (request dropped): {msg}");
                    }
                });
            }
            Err(_) => break,
        }
    }
    Ok(())
}

/// Spawn a thread that watches for SIGTERM / SIGINT / SIGQUIT, flips
/// `state.shutdown`, then opens a single self-connection so the
/// blocking `listener.incoming()` returns immediately. Without that
/// self-poke the accept loop would only exit on the next real client
/// connection — under k8s `terminationGracePeriodSeconds` the pod
/// would be SIGKILLed mid-flight.
fn install_shutdown_signals(state: Arc<ServerState>, listen_addr: std::net::SocketAddr) {
    thread::spawn(move || {
        let mut signals = match signal_hook::iterator::Signals::new([
            signal_hook::consts::SIGTERM,
            signal_hook::consts::SIGINT,
            signal_hook::consts::SIGQUIT,
        ]) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("gyt serve: could not install signal handlers: {e}");
                return;
            }
        };
        if let Some(sig) = signals.forever().next() {
            eprintln!("gyt serve: received signal {sig}; beginning graceful shutdown");
            if let Ok(mut g) = state.shutdown.lock() {
                *g = true;
            }
            // Self-connect to unblock accept(). Connect-then-drop is
            // enough; we don't need to write or read.
            let _ = std::net::TcpStream::connect_timeout(
                &listen_addr,
                std::time::Duration::from_secs(1),
            );
        }
    });
}

struct ServerState {
    repos_root: PathBuf,
    webroot: PathBuf,
    auth_token: Option<String>,
    /// Parsed ACL entries. None means no per-repo ACL configured (fall
    /// back to the simple `auth_token` model). An empty Some(_) means
    /// the file existed but contained no entries — every request is
    /// denied, because anything else would be a surprising upgrade
    /// from "ACL configured" to "wide open".
    auth_acl: Option<Vec<AclEntry>>,
    signers_file: Option<PathBuf>,
    policy_config: Option<PathBuf>,
    shutdown: Mutex<bool>,
    metrics: Metrics,
    /// Bound local address. Stored so the admin-shutdown handler can
    /// self-connect to unblock accept() — the signal handler does the
    /// same trick.
    listen_addr: std::net::SocketAddr,
}

/// One row in the `--auth-tokens` TSV. A token may appear in multiple
/// rows to grant separate scopes (e.g. rw on one repo, ro on others).
struct AclEntry {
    /// Bearer token as presented by the client (plain string compared
    /// in constant time). Stored plaintext — the ACL file is read at
    /// startup and is expected to be owner-readable only.
    token: String,
    /// Single-segment repo pattern. Either an exact name, `prefix*` for
    /// starts-with, or `*` for any repo.
    pattern: String,
    /// True iff this entry permits writes (objects/have, refs/update).
    /// False means read-only (info/refs, objects/want).
    write: bool,
}

impl AclEntry {
    fn matches_repo(&self, repo: &str) -> bool {
        if self.pattern == "*" {
            return true;
        }
        if let Some(prefix) = self.pattern.strip_suffix('*') {
            return repo.starts_with(prefix);
        }
        self.pattern == repo
    }
}

/// Parse a `--auth-tokens` file. Lines that are blank or start with `#`
/// are ignored. Other lines must have exactly three TAB-separated
/// fields: `token`, `pattern`, `rw|ro`. Anything else is a hard error
/// because silently dropping a malformed line could downgrade trust.
fn load_acl(path: &std::path::Path) -> Result<Vec<AclEntry>> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        crate::errors::GytError::InvalidArgument(format!("read {}: {e}", path.display()))
    })?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() != 3 {
            return Err(crate::errors::GytError::InvalidArgument(format!(
                "{}: line {}: expected <token>\\t<pattern>\\t<rw|ro>",
                path.display(),
                i + 1
            )));
        }
        let token = parts[0].trim().to_string();
        let pattern = parts[1].trim().to_string();
        let perm = parts[2].trim();
        let write = match perm {
            "rw" => true,
            "ro" => false,
            other => {
                return Err(crate::errors::GytError::InvalidArgument(format!(
                    "{}: line {}: perm must be `rw` or `ro`, got {other:?}",
                    path.display(),
                    i + 1
                )));
            }
        };
        if token.is_empty() || pattern.is_empty() {
            return Err(crate::errors::GytError::InvalidArgument(format!(
                "{}: line {}: token and pattern must be non-empty",
                path.display(),
                i + 1
            )));
        }
        out.push(AclEntry {
            token,
            pattern,
            write,
        });
    }
    Ok(out)
}

/// Bounded-concurrency limiter. Each accepted connection acquires a permit
/// that is released when its handler thread exits. Connections beyond the
/// cap block in `accept` until a permit frees up.
struct WorkerLimiter {
    inner: Mutex<usize>,
    cv: Condvar,
    cap: usize,
}

impl WorkerLimiter {
    const fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(0),
            cv: Condvar::new(),
            cap,
        }
    }

    fn acquire(self: Arc<Self>) -> WorkerPermit {
        let mut n = self.inner.lock().unwrap();
        while *n >= self.cap {
            n = self.cv.wait(n).unwrap();
        }
        *n += 1;
        drop(n);
        WorkerPermit {
            limiter: self.clone(),
        }
    }

    /// Non-blocking variant: returns None when at capacity instead of
    /// stalling the accept thread on a Condvar. Used to bound the
    /// accept loop's latency under load — if every worker is busy we
    /// send a 503 immediately rather than letting connections pile
    /// up in the kernel backlog.
    fn try_acquire(self: Arc<Self>) -> Option<WorkerPermit> {
        let mut n = self.inner.lock().unwrap();
        if *n >= self.cap {
            return None;
        }
        *n += 1;
        drop(n);
        Some(WorkerPermit {
            limiter: self.clone(),
        })
    }
}

struct WorkerPermit {
    limiter: Arc<WorkerLimiter>,
}

impl Drop for WorkerPermit {
    fn drop(&mut self) {
        {
            let mut n = self.limiter.inner.lock().unwrap();
            *n = n.saturating_sub(1);
        }
        self.limiter.cv.notify_one();
    }
}

/// Best-effort string for a panic payload that came back from
/// `catch_unwind`. Panics are usually `&'static str` or `String`;
/// we fall back to a generic marker if neither downcast succeeds.
fn downcast_panic_payload(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&'static str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "<non-string panic payload>".to_string()
    }
}

fn handle_conn(stream: std::net::TcpStream, state: &ServerState) -> std::io::Result<()> {
    let mut reader = std::io::BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    for _ in 0..MAX_REQUESTS_PER_CONN {
        // Respect graceful shutdown: a keep-alive worker waiting for
        // the next request must drop out promptly when serve() flips
        // the shutdown flag. Without this check a single client could
        // hold a worker for the whole MAX_REQUESTS_PER_CONN × timeout
        // window after the operator asked us to exit.
        if *state.shutdown.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
            break;
        }
        if !serve_one(&mut reader, &mut writer, state)? {
            break;
        }
    }
    Ok(())
}

/// Serve one HTTP request on a plain (non-TLS) connection. Returns
/// `Ok(true)` if the connection may be reused for another request,
/// `Ok(false)` if it should be closed (client requested close, parse
/// error, or auth failure).
fn serve_one<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    state: &ServerState,
) -> std::io::Result<bool> {
    let req = match read_request(reader) {
        Ok(r) => r,
        Err(_) => {
            // EOF or read timeout: just close. No 400 — the client may
            // have walked away mid-keep-alive, which is normal.
            return Ok(false);
        }
    };

    let (path, query) = match req.target.find('?') {
        Some(i) => (&req.target[..i], Some(&req.target[i + 1..])),
        None => (req.target.as_str(), None),
    };

    let params = router::query_params(query);
    let route = router::route(&req.method, path);

    state.metrics.requests_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    state
        .metrics
        .request_body_bytes_total
        .fetch_add(req.body.len() as u64, std::sync::atomic::Ordering::Relaxed);
    state.metrics.record_handler(route.handler);

    if !authorize_with_metric(state, &req, &route) {
        write_response(writer, 401, "Unauthorized", "text/plain", b"unauthorized\n")?;
        return Ok(false);
    }

    let actor = actor_for(&req);
    let (status, reason, body, ctype) =
        dispatch(&route, &params, query, &req.body, state, actor.as_deref());

    state
        .metrics
        .response_bytes_total
        .fetch_add(body.len() as u64, std::sync::atomic::Ordering::Relaxed);

    let keep_alive = !req.client_wants_close;
    write_response_keepalive(writer, status, &reason, &ctype, &body, keep_alive)?;
    Ok(keep_alive)
}

/// Wrapper around `authorize` that bumps the unauthorized counter on
/// deny. Keeps `authorize` itself free of side effects so test code
/// can call it without metric pollution.
fn authorize_with_metric(state: &ServerState, req: &Request, route: &router::RouteMatch) -> bool {
    let ok = authorize(state, req, route);
    if !ok {
        state
            .metrics
            .requests_unauthorized_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    ok
}

/// Derive an audit-log actor identifier for the request. We fingerprint
/// the presented bearer token with full-strength BLAKE3 (32 bytes →
/// 64 hex chars) so two distinct tokens are distinguishable AND a
/// forensic adversary can't feasibly brute-force a target fingerprint
/// to forge audit entries. Anonymous requests get None → the audit
/// path records "anon".
fn actor_for(req: &Request) -> Option<String> {
    let header = req.auth_header.as_deref()?;
    let token = header.strip_prefix("Bearer ")?;
    let h = blake3::hash(token.as_bytes());
    let bytes = h.as_bytes();
    let mut hex = String::with_capacity(64);
    for &b in bytes {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    Some(format!("token:{hex}"))
}

/// Handle a TLS-wrapped connection.
fn handle_tls_conn(
    stream: crate::net::tls::ServerTlsStream,
    state: &ServerState,
) -> std::io::Result<()> {
    let mut reader = std::io::BufReader::new(stream);
    for _ in 0..MAX_REQUESTS_PER_CONN {
        if *state.shutdown.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
            break;
        }
        if !serve_one_tls(&mut reader, state)? {
            break;
        }
    }
    Ok(())
}

fn serve_one_tls(
    reader: &mut std::io::BufReader<crate::net::tls::ServerTlsStream>,
    state: &ServerState,
) -> std::io::Result<bool> {
    let req = match read_request(reader) {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };

    let (path, query) = match req.target.find('?') {
        Some(i) => (&req.target[..i], Some(&req.target[i + 1..])),
        None => (req.target.as_str(), None),
    };

    let params = router::query_params(query);
    let route = router::route(&req.method, path);

    state.metrics.requests_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    state
        .metrics
        .request_body_bytes_total
        .fetch_add(req.body.len() as u64, std::sync::atomic::Ordering::Relaxed);
    state.metrics.record_handler(route.handler);

    if !authorize_with_metric(state, &req, &route) {
        let writer = reader.get_mut();
        write_response(writer, 401, "Unauthorized", "text/plain", b"unauthorized\n")?;
        return Ok(false);
    }

    let actor = actor_for(&req);
    let (status, reason, body, ctype) =
        dispatch(&route, &params, query, &req.body, state, actor.as_deref());

    state
        .metrics
        .response_bytes_total
        .fetch_add(body.len() as u64, std::sync::atomic::Ordering::Relaxed);

    let keep_alive = !req.client_wants_close;
    let writer = reader.get_mut();
    write_response_keepalive(writer, status, &reason, &ctype, &body, keep_alive)?;
    Ok(keep_alive)
}

/// Authorize a request. Resolution order:
///
/// 1. `auth_acl` set → must present a bearer token matching at least
///    one entry whose pattern covers the requested repo (or whose entry
///    is global) and whose perm is sufficient for the route (writes
///    need `rw`).
/// 2. `auth_token` set → must present that exact token; full rw on every
///    route (legacy single-token mode).
/// 3. Neither set → open server. Reads and writes accepted.
fn authorize(state: &ServerState, req: &Request, route: &router::RouteMatch) -> bool {
    if route_is_unauth_probe(route) {
        return true;
    }
    if let Some(acl) = &state.auth_acl {
        let Some(token) = req
            .auth_header
            .as_deref()
            .and_then(|h| h.strip_prefix("Bearer "))
        else {
            return false;
        };
        let needs_write = route_needs_write(route);
        let repo = wire_repo_name(route);
        // Walk every entry so a non-matching prefix doesn't short-circuit
        // and leak whether *some* row had the same token. The bool is
        // accumulated; we never return early on a mismatch.
        let mut allowed = false;
        for entry in acl {
            let token_ok = constant_time_eq(token.as_bytes(), entry.token.as_bytes());
            let scope_ok = match repo {
                Some(r) => entry.matches_repo(r),
                // Non-wire routes (REST API, static files): only a
                // global `*` pattern grants access.
                None => entry.pattern == "*",
            };
            let perm_ok = !needs_write || entry.write;
            if token_ok && scope_ok && perm_ok {
                allowed = true;
            }
        }
        return allowed;
    }

    if let Some(ref token) = state.auth_token {
        return check_auth(req, token);
    }

    true
}

/// True iff this route mutates server-side state. Writes need `rw`
/// permission under the ACL; reads can satisfy with `ro`. Admin
/// shutdown is treated as a write — `ro` tokens cannot drain the
/// server.
const fn route_needs_write(route: &router::RouteMatch) -> bool {
    matches!(
        route.handler,
        Handler::ObjectsHave | Handler::RefsUpdate | Handler::AdminShutdown
    )
}

/// True iff this route is an operator probe that should be reachable
/// without authentication so probes from k8s / a load balancer don't
/// have to know the bearer token. `AdminShutdown` is deliberately not
/// in this set — it must always be auth-gated.
const fn route_is_unauth_probe(route: &router::RouteMatch) -> bool {
    matches!(
        route.handler,
        Handler::Healthz | Handler::Readyz | Handler::Metrics
    )
}

/// Extract the wire repo name from a route's params, if any. Wire
/// routes carry a single `repo` segment; REST/static routes don't, so
/// they can't be scoped per-repo.
fn wire_repo_name(route: &router::RouteMatch) -> Option<&str> {
    if !matches!(
        route.handler,
        Handler::InfoRefs
            | Handler::ObjectsWant
            | Handler::ObjectsHave
            | Handler::RefsUpdate
    ) {
        return None;
    }
    router::get_param(&route.params, "repo")
}

/// Check the request's Authorization header against the expected bearer token.
///
/// The comparison runs in time linear in `max(len(presented), len(expected))`
/// — explicitly *not* a short-circuit `==` — so a timing oracle cannot leak
/// the token byte-by-byte. We compare lengths into the same accumulator so
/// even a wrong-length input still costs the full XOR pass.
fn check_auth(req: &Request, expected_token: &str) -> bool {
    match &req.auth_header {
        Some(val) => {
            // Expect "Bearer <token>"
            if let Some(token) = val.strip_prefix("Bearer ") {
                constant_time_eq(token.as_bytes(), expected_token.as_bytes())
            } else {
                false
            }
        }
        None => false,
    }
}

/// Constant-time byte-slice equality. Returns false if lengths differ, but
/// still walks both buffers up to `max(a.len(), b.len())` so the time taken
/// does not branch on the position of the first mismatch.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len = a.len().max(b.len());
    let mut acc: u8 = u8::from(a.len() != b.len());
    for i in 0..len {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        acc |= x ^ y;
    }
    acc == 0
}

/// Concatenate two param lists. Used by REST API dispatch to combine
/// URL-path parameters (route.params: owner, name, ref, sha) with
/// query-string parameters (params: page, per_page) — the handlers
/// expect a single flat lookup table.
fn merge_params(a: &[(String, String)], b: &[(String, String)]) -> Vec<(String, String)> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    out.extend_from_slice(a);
    out.extend_from_slice(b);
    out
}

fn dispatch(
    route: &router::RouteMatch,
    params: &[(String, String)],
    raw_query: Option<&str>,
    body: &[u8],
    state: &ServerState,
    actor: Option<&str>,
) -> (u16, String, Vec<u8>, String) {
    match route.handler {
        // Wire protocol handlers use route.params (repo from URL path), not query params
        Handler::InfoRefs => wire_info_refs(state, &route.params),
        Handler::ObjectsWant => wire_objects_want(state, &route.params, body),
        Handler::ObjectsHave => wire_objects_have(state, &route.params, body),
        Handler::RefsUpdate => wire_refs_update(state, &route.params, raw_query, body, actor),
        // REST API handlers need *both* the path-extracted params
        // (owner / name / ref / sha / path) AND the query string
        // (page, per_page). Merge them — path entries first so a
        // future query parameter with the same key cannot override
        // an authoritative URL segment.
        Handler::RepoList => repo_list(state, params),
        Handler::RepoInfo => repo_info(state, &merge_params(&route.params, params)),
        Handler::CommitList => commit_list(state, &merge_params(&route.params, params)),
        Handler::CommitDetail => commit_detail(state, &merge_params(&route.params, params)),
        Handler::TreeBrowse => tree_browse(state, &merge_params(&route.params, params)),
        Handler::RefsList => refs_list(state, &merge_params(&route.params, params)),
        Handler::DiffRevs => diff_revs(state, &merge_params(&route.params, params)),
        Handler::Search => search(state, &merge_params(&route.params, params)),
        Handler::Healthz => healthz_handler(state),
        Handler::Readyz => readyz_handler(state),
        Handler::Metrics => metrics_handler(state),
        Handler::AdminShutdown => admin_shutdown_handler(state),
        Handler::StaticFile => static_file(state, params),
        Handler::NotFound => (
            404,
            "Not Found".into(),
            b"not found".to_vec(),
            "text/plain".into(),
        ),
    }
}

fn write_response(
    w: &mut impl Write,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    write_response_keepalive(w, status, reason, content_type, body, false)
}

/// Like `write_response` but lets the caller mark the connection as
/// reusable. We always emit an explicit `Connection:` header so the
/// client doesn't have to guess against HTTP/1.1 defaults.
fn write_response_keepalive(
    w: &mut impl Write,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
    keep_alive: bool,
) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(256 + body.len());
    out.extend_from_slice(format!("HTTP/1.1 {status} {reason}\r\n").as_bytes());
    if keep_alive {
        out.extend_from_slice(b"Connection: keep-alive\r\n");
    } else {
        out.extend_from_slice(b"Connection: close\r\n");
    }
    out.extend_from_slice(b"Access-Control-Allow-Origin: *\r\n");
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    w.write_all(&out)?;
    w.flush()
}

fn read_request<R: BufRead>(reader: &mut R) -> std::io::Result<Request> {
    let mut header_buf = Vec::with_capacity(4096);
    loop {
        let n_before = header_buf.len();
        let n = reader.read_until(b'\n', &mut header_buf)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof in request",
            ));
        }
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buf.len() == n_before {
            return Err(std::io::Error::other("no progress"));
        }
        if header_buf.len() > 64 * 1024 {
            return Err(std::io::Error::other("headers too large"));
        }
    }
    let header_str =
        std::str::from_utf8(&header_buf).map_err(|_| std::io::Error::other("non-utf8 headers"))?;
    let mut lines = header_str.split("\r\n");
    let req_line = lines
        .next()
        .ok_or_else(|| std::io::Error::other("no request line"))?;
    let mut parts = req_line.splitn(3, ' ');
    let method = parts
        .next()
        .ok_or_else(|| std::io::Error::other("bad request line"))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| std::io::Error::other("bad request line"))?
        .to_string();

    let mut content_length: Option<usize> = None;
    let mut auth_header: Option<String> = None;
    let mut client_wants_close = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let k_trim = k.trim();
        let v_trim = v.trim();
        if k_trim.eq_ignore_ascii_case("content-length") {
            // Reject malformed lengths instead of silently falling
            // back to 0 — on a keep-alive connection a "0-length"
            // request with a body fed in afterwards would let the
            // body bytes be parsed as the *next* request, the
            // classic CL-smuggling pattern. A duplicate header is
            // also a smuggling signal per RFC 7230 §3.3.2.
            if content_length.is_some() {
                return Err(std::io::Error::other("duplicate Content-Length header"));
            }
            let parsed: usize = v_trim
                .parse()
                .map_err(|_| std::io::Error::other(format!("bad Content-Length: {v_trim:?}")))?;
            content_length = Some(parsed);
        } else if k_trim.eq_ignore_ascii_case("transfer-encoding") {
            // We don't implement chunked request decoding. Refuse so a
            // client can't smuggle bytes past the body cap by sending
            // them as a chunked stream we'd otherwise leave unread.
            return Err(std::io::Error::other(
                "Transfer-Encoding header not supported by server",
            ));
        } else if k_trim.eq_ignore_ascii_case("authorization") {
            auth_header = Some(v_trim.to_string());
        } else if k_trim.eq_ignore_ascii_case("connection")
            && v_trim
                .split(',')
                .any(|t| t.trim().eq_ignore_ascii_case("close"))
        {
            client_wants_close = true;
        }
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_BODY_BYTES {
        return Err(std::io::Error::other(format!(
            "request body too large: {content_length} bytes (max {MAX_BODY_BYTES})"
        )));
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    Ok(Request {
        method,
        target,
        body,
        auth_header,
        client_wants_close,
    })
}

// ---------- Operator handlers: health / readiness / metrics / shutdown ----------

fn healthz_handler(_state: &ServerState) -> (u16, String, Vec<u8>, String) {
    (200, "OK".into(), b"ok\n".to_vec(), "text/plain".into())
}

fn readyz_handler(state: &ServerState) -> (u16, String, Vec<u8>, String) {
    let draining = *state
        .shutdown
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if draining {
        (
            503,
            "Service Unavailable".into(),
            b"draining\n".to_vec(),
            "text/plain".into(),
        )
    } else {
        (200, "OK".into(), b"ready\n".to_vec(), "text/plain".into())
    }
}

fn metrics_handler(state: &ServerState) -> (u16, String, Vec<u8>, String) {
    let body = state.metrics.render_prometheus();
    (
        200,
        "OK".into(),
        body.into_bytes(),
        "text/plain; version=0.0.4".into(),
    )
}

/// POST /admin/shutdown — flips the shutdown flag and self-connects
/// so the accept loop returns immediately. The actor that fires this
/// is auth-gated (same as a write route): you need an `rw` token if
/// ACLs are configured, the full `--auth-token` if single-token, or
/// nothing if the server runs open.
fn admin_shutdown_handler(state: &ServerState) -> (u16, String, Vec<u8>, String) {
    if let Ok(mut g) = state.shutdown.lock() {
        *g = true;
    }
    // Best-effort self-connect to break accept(). Failure means the
    // listener already had something queued — accept will still
    // observe the flag on its next iteration.
    let _ = std::net::TcpStream::connect_timeout(
        &state.listen_addr,
        std::time::Duration::from_secs(1),
    );
    (
        202,
        "Accepted".into(),
        b"shutting down\n".to_vec(),
        "text/plain".into(),
    )
}

// ---------- Helper: resolve owner/name to .gyt path ----------

fn repo_path(state: &ServerState, owner: &str, name: &str) -> Option<PathBuf> {
    // Match both non-bare (`<owner>/<name>/.gyt/`) and bare
    // (`<owner>/<name>/HEAD` directly) layouts so the REST API can
    // serve a bare server-side repo. The wire path already handles
    // both — without this the API silently 404s on every bare repo
    // (which is the only layout `gyt serve` actually accepts at scale).
    let candidate = state.repos_root.join(owner).join(name);
    if candidate.join(".gyt").is_dir() {
        return Some(candidate);
    }
    if candidate.join("HEAD").is_file() {
        return Some(candidate);
    }
    None
}

fn open_repo(state: &ServerState, owner: &str, name: &str) -> Option<crate::repo::Repo> {
    let path = repo_path(state, owner, name)?;
    crate::repo::Repo::open(&path).ok()
}

fn json_response(body: &str) -> (u16, String, Vec<u8>, String) {
    (
        200,
        "OK".into(),
        body.as_bytes().to_vec(),
        "application/json".into(),
    )
}

fn error_response(status: u16, msg: &str) -> (u16, String, Vec<u8>, String) {
    let json = format!(r#"{{"error":{}}}"#, api::json_string(msg));
    (
        status,
        if status == 404 { "Not Found" } else { "Error" }.into(),
        json.into_bytes(),
        "application/json".into(),
    )
}

// ---------- Handler: repo list ----------

fn repo_list(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let page = api::parse_page(params, 1);
    let per_page = api::parse_per_page(params, 30, 100);

    let mut repos: Vec<(String, String)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&state.repos_root) {
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let owner = entry.file_name().to_string_lossy().into_owned();
            if let Ok(sub) = std::fs::read_dir(entry.path()) {
                for se in sub.flatten() {
                    if !se.file_type().is_ok_and(|t| t.is_dir()) {
                        continue;
                    }
                    if se.path().join(".gyt").is_dir() {
                        let name = se.file_name().to_string_lossy().into_owned();
                        repos.push((owner.clone(), name));
                    }
                }
            }
        }
    }
    repos.sort();

    let total = repos.len();
    let start = (page.saturating_sub(1)) * per_page;
    let page_repos: Vec<_> = repos.into_iter().skip(start).take(per_page).collect();

    let items: Vec<String> = page_repos
        .iter()
        .map(|(owner, name)| {
            let info = repo_info_from(state, owner, name);
            info.to_json()
        })
        .collect();

    let body = format!(
        r#"{{"items":[{}],"page":{},"per_page":{},"total":{}}}"#,
        items.join(","),
        page,
        per_page,
        total,
    );
    json_response(&body)
}

fn repo_info_from(state: &ServerState, owner: &str, name: &str) -> RepoInfo {
    let default_branch = if let Some(repo) = open_repo(state, owner, name) {
        match refs::read_head(&repo.gyt_dir) {
            Ok(refs::Head::Symbolic(b)) => b.trim_start_matches("refs/heads/").to_string(),
            _ => "main".to_string(),
        }
    } else {
        "main".to_string()
    };

    let head_commit = open_repo(state, owner, name).and_then(|repo| {
        let head = refs::read_head(&repo.gyt_dir).ok()?;
        refs::resolve(&repo.gyt_dir, &head)
            .ok()
            .flatten()
            .map(super::super::hash::ObjectId::to_hex)
    });

    RepoInfo {
        owner: owner.to_string(),
        name: name.to_string(),
        description: String::new(),
        default_branch,
        head_commit,
    }
}

// ---------- Handler: repo info ----------

fn repo_info(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");

    if repo_path(state, owner, name).is_none() {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    }

    let info = repo_info_from(state, owner, name);
    json_response(&info.to_json())
}

// ---------- Handler: commit list ----------

/// DoS bound for `commit_list`'s parent walk. A million-commit history
/// must not be able to pin a worker thread before the first byte hits
/// the wire. Pagination beyond 10k requires re-anchoring the request
/// at an earlier `?ref=<sha>`.
const MAX_ANCESTORS: usize = 10_000;

/// Per-file size cap when a REST handler reads blob payloads into
/// memory (tree_browse blob view, diff_revs Myers input). Anything
/// over this is returned/diffed as a stub: the client can still see
/// "this file is 250 MB" without the server allocating it.
const MAX_INLINE_BLOB_BYTES: u64 = 8 * 1024 * 1024;

/// Total bytes a single `diff_revs` request is allowed to allocate
/// across all changed files. We stop adding diffs once we cross
/// this; the response carries a `truncated` flag so the client knows
/// to ask for narrower base..head ranges.
const MAX_DIFF_BYTES: usize = 32 * 1024 * 1024;

/// Maximum number of files diff_revs will produce. Beyond this we
/// also truncate. Trees with millions of files would otherwise OOM
/// the worker before Myers diff produces its first byte.
const MAX_DIFF_FILES: usize = 5_000;

/// Per-request file-walk cap shared by `search_code` and `diff_revs`.
/// flatten_tree is recursive and unbounded in the on-disk schema; an
/// adversarial repo can build a tree with millions of entries.
const MAX_FLATTEN_ENTRIES: usize = 200_000;

/// Cap on tree_browse children listed in a single response. Combined
/// with the size lookup skipping large blobs (see MAX_INLINE_BLOB_BYTES)
/// this keeps a directory listing O(MAX_TREE_LIST_ENTRIES).
const MAX_TREE_LIST_ENTRIES: usize = 5_000;

/// Byte budget for a single search_code request. Stops a never-matching
/// query from rescanning a multi-GiB working tree.
const SEARCH_BYTE_BUDGET: usize = 64 * 1024 * 1024;

fn commit_list(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");

    let Some(repo) = open_repo(state, owner, name) else {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    };

    let rev = router::get_param(params, "ref").unwrap_or("HEAD");
    let Ok(start_id) = util::resolve_rev(&repo, rev) else {
        return error_response(404, &format!("revision {rev} not found"));
    };

    let page = api::parse_page(params, 1);
    let per_page = api::parse_per_page(params, 30, 100);

    let mut commits = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cur = Some(start_id);

    while let Some(id) = cur {
        if seen.contains(&id) || commits.len() >= MAX_ANCESTORS {
            break;
        }
        seen.insert(id);
        match commit::read(&repo.gyt_dir, &id) {
            Ok(c) => {
                cur = c.parents.first().copied();
                commits.push(CommitInfo {
                    sha: id.to_hex(),
                    tree: c.tree.to_hex(),
                    parents: c.parents.iter().map(|p| p.to_hex()).collect(),
                    authors: c.authors,
                    committer: c.committer,
                    ai_assists: c.ai_assists,
                    reviewers: c.reviewers,
                    message: c.message,
                });
            }
            Err(_) => break,
        }
    }

    let total = commits.len();
    let start_idx = (page.saturating_sub(1)) * per_page;
    let page_commits: Vec<_> = commits.into_iter().skip(start_idx).take(per_page).collect();

    let items: Vec<String> = page_commits
        .iter()
        .map(super::api::CommitInfo::to_json)
        .collect();
    let body = format!(
        r#"{{"items":[{}],"page":{},"per_page":{},"total":{}}}"#,
        items.join(","),
        page,
        per_page,
        total,
    );
    json_response(&body)
}

// ---------- Handler: commit detail ----------

fn commit_detail(
    state: &ServerState,
    params: &[(String, String)],
) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");
    let sha = router::get_param(params, "sha").unwrap_or("");

    let Some(repo) = open_repo(state, owner, name) else {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    };

    let id = match ObjectId::from_hex(sha) {
        Ok(id) => id,
        Err(e) => return error_response(400, &format!("invalid hash: {e}")),
    };

    let c = match commit::read(&repo.gyt_dir, &id) {
        Ok(c) => c,
        Err(e) => return error_response(404, &format!("commit not found: {e}")),
    };

    let info = CommitInfo {
        sha: id.to_hex(),
        tree: c.tree.to_hex(),
        parents: c.parents.iter().map(|p| p.to_hex()).collect(),
        authors: c.authors,
        committer: c.committer,
        ai_assists: c.ai_assists,
        reviewers: c.reviewers,
        message: c.message,
    };

    json_response(&info.to_json())
}

// ---------- Handler: tree / blob browse ----------

fn tree_browse(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");
    let r#ref = router::get_param(params, "ref").unwrap_or("HEAD");
    let path = router::get_param(params, "path").unwrap_or("");

    let Some(repo) = open_repo(state, owner, name) else {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    };

    let tree_id = match util::resolve_tree(&repo, r#ref) {
        Ok(id) => id,
        Err(e) => return error_response(404, &format!("ref {ref} not found: {e}")),
    };

    if path.is_empty() {
        return list_tree(&repo, &tree_id);
    }

    let segments: Vec<&str> = path.split('/').collect();
    let mut current_tree = tree_id;
    for (i, segment) in segments.iter().enumerate() {
        let entries = match tree::read(&repo.gyt_dir, &current_tree) {
            Ok(e) => e,
            Err(e) => return error_response(500, &format!("tree read error: {e}")),
        };
        let found = entries.iter().find(|e| {
            let name = std::str::from_utf8(&e.name).unwrap_or("");
            name == *segment
        });
        let Some(entry) = found else {
            return error_response(404, &format!("path {path} not found"));
        };

        if entry.mode == tree::MODE_DIR {
            current_tree = entry.hash;
            continue;
        }

        if i == segments.len() - 1 {
            if entry.mode == tree::MODE_DIR {
                return list_tree(&repo, &entry.hash);
            }

            let payload = match crate::object::blob::read(&repo.gyt_dir, &entry.hash) {
                Ok(p) => p,
                Err(e) => return error_response(500, &format!("blob read error: {e}")),
            };
            let size = payload.len() as u64;
            // Refuse to materialize huge blobs into a JSON response —
            // the client gets a placeholder so the UI can decide
            // whether to ask for raw bytes via a different route.
            let content = if size > MAX_INLINE_BLOB_BYTES {
                format!("<blob too large to inline: {size} bytes>")
            } else {
                String::from_utf8_lossy(&payload).into_owned()
            };
            let info = BlobInfo {
                path: path.to_string(),
                hash: entry.hash.to_hex(),
                content,
                size,
            };
            return json_response(&info.to_json());
        }

        return error_response(404, &format!("path {path} not found"));
    }

    list_tree(&repo, &current_tree)
}

fn list_tree(repo: &crate::repo::Repo, tree_id: &ObjectId) -> (u16, String, Vec<u8>, String) {
    let entries = match tree::read(&repo.gyt_dir, tree_id) {
        Ok(e) => e,
        Err(e) => return error_response(500, &format!("tree read error: {e}")),
    };

    // Hard cap: never decompress more than MAX_TREE_LIST_ENTRIES blobs
    // for a single directory listing. The pre-cap was unbounded — a
    // directory with 10k children meant 10k xz decompressions per
    // GET. Note that we still need a `size: None` placeholder for
    // entries past the cap so the listing stays a complete tree
    // snapshot (just without size info).
    let items: Vec<String> = entries
        .iter()
        .enumerate()
        .map(|(idx, e)| {
            let name = std::str::from_utf8(&e.name)
                .unwrap_or("<invalid>")
                .to_string();
            let kind = if e.mode == tree::MODE_DIR {
                "tree"
            } else {
                "blob"
            };
            let size = if e.mode == tree::MODE_DIR || idx >= MAX_TREE_LIST_ENTRIES {
                None
            } else {
                crate::object::blob::read(&repo.gyt_dir, &e.hash)
                    .map(|b| b.len() as u64)
                    .ok()
            };
            let info = TreeEntryInfo {
                name,
                mode: e.mode,
                kind: kind.to_string(),
                hash: e.hash.to_hex(),
                size,
            };
            info.to_json()
        })
        .collect();

    let body = format!("[{}]", items.join(","));
    json_response(&body)
}

// ---------- Handler: refs list ----------

fn refs_list(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");

    let Some(repo) = open_repo(state, owner, name) else {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    };

    let default_branch = match refs::read_head(&repo.gyt_dir) {
        Ok(refs::Head::Symbolic(b)) => Some(b),
        _ => None,
    };

    let mut all_refs = Vec::new();

    if let Ok(branches) = refs::list_refs(&repo.gyt_dir, "refs/heads") {
        for (bname, bid) in &branches {
            let short = bname.trim_start_matches("refs/heads/");
            all_refs.push(RefInfo {
                name: short.to_string(),
                commit: bid.to_hex(),
                is_default: default_branch.as_deref() == Some(bname),
            });
        }
    }

    if let Ok(tags) = refs::list_refs(&repo.gyt_dir, "refs/tags") {
        for (tname, tid) in &tags {
            let short = tname.trim_start_matches("refs/tags/");
            all_refs.push(RefInfo {
                name: short.to_string(),
                commit: tid.to_hex(),
                is_default: false,
            });
        }
    }

    let items: Vec<String> = all_refs.iter().map(super::api::RefInfo::to_json).collect();
    let body = format!("[{}]", items.join(","));
    json_response(&body)
}

// ---------- Handler: diff two revs ----------

fn diff_revs(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");
    let base = router::get_param(params, "base").unwrap_or("");
    let head = router::get_param(params, "head").unwrap_or("");

    let Some(repo) = open_repo(state, owner, name) else {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    };

    let base_tree_id = match util::resolve_tree(&repo, base) {
        Ok(id) => id,
        Err(e) => return error_response(404, &format!("base ref {base} not found: {e}")),
    };
    let head_tree_id = match util::resolve_tree(&repo, head) {
        Ok(id) => id,
        Err(e) => return error_response(404, &format!("head ref {head} not found: {e}")),
    };

    let base_files = match util::flatten_tree(&repo, &base_tree_id) {
        Ok(f) => f,
        Err(e) => return error_response(500, &format!("base tree error: {e}")),
    };
    let head_files = match util::flatten_tree(&repo, &head_tree_id) {
        Ok(f) => f,
        Err(e) => return error_response(500, &format!("head tree error: {e}")),
    };

    // Combined-tree size cap: a repo with 10M paths on each side
    // would build a 20M-entry HashSet before we even start reading
    // blobs. Refuse early.
    if base_files.len() + head_files.len() > MAX_FLATTEN_ENTRIES {
        return error_response(
            413,
            "diff: trees too large to diff in one request; narrow the range",
        );
    }

    let mut files: Vec<DiffFileInfo> = Vec::new();
    let mut total_diff_bytes: usize = 0;
    let mut truncated = false;
    let mut all_paths: Vec<PathBuf> = base_files
        .keys()
        .chain(head_files.keys())
        .cloned()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    all_paths.sort();

    for path in &all_paths {
        if files.len() >= MAX_DIFF_FILES || total_diff_bytes >= MAX_DIFF_BYTES {
            truncated = true;
            break;
        }
        let path_str = path.to_string_lossy().into_owned();

        let old_blob = base_files
            .get(path)
            .and_then(|(_, id)| crate::object::blob::read(&repo.gyt_dir, id).ok());
        let new_blob = head_files
            .get(path)
            .and_then(|(_, id)| crate::object::blob::read(&repo.gyt_dir, id).ok());

        let old_size = old_blob.as_ref().map_or(0, Vec::len) as u64;
        let new_size = new_blob.as_ref().map_or(0, Vec::len) as u64;

        // Either side over the per-file cap: emit a stub instead of
        // running Myers diff (which is O(N+M+D²) — pathological on
        // large binaries). We still count the bytes we already
        // decompressed against `total_diff_bytes` so a series of
        // giant-files-each-just-under-the-cap can't burn unlimited
        // memory across the request.
        let pair_bytes = old_size.saturating_add(new_size) as usize;
        total_diff_bytes = total_diff_bytes.saturating_add(pair_bytes);
        if old_size > MAX_INLINE_BLOB_BYTES || new_size > MAX_INLINE_BLOB_BYTES {
            files.push(DiffFileInfo {
                path: path_str,
                hunks: vec![DiffHunkInfo {
                    old_start: 0,
                    old_count: 0,
                    new_start: 0,
                    new_count: 0,
                    lines: vec![DiffLine {
                        old_no: None,
                        new_no: None,
                        kind: "binary".to_string(),
                        text: format!(
                            "<file too large to diff: old={old_size} new={new_size}>"
                        ),
                    }],
                }],
            });
            continue;
        }

        let old_lines: Vec<&[u8]> = match &old_blob {
            Some(b) => diff::split_lines(b),
            None => vec![],
        };
        let new_lines: Vec<&[u8]> = match &new_blob {
            Some(b) => diff::split_lines(b),
            None => vec![],
        };

        let ops = diff::myers(&old_lines, &new_lines);
        if ops.iter().all(|op| matches!(op, diff::DiffOp::Equal(_))) {
            continue;
        }

        let hunks = build_hunks(&ops);
        files.push(DiffFileInfo {
            path: path_str,
            hunks,
        });
    }

    let items: Vec<String> = files
        .iter()
        .map(super::api::DiffFileInfo::to_json)
        .collect();
    let body = format!(
        r#"{{"files":[{}],"truncated":{}}}"#,
        items.join(","),
        truncated
    );
    json_response(&body)
}

fn build_hunks(ops: &[diff::DiffOp<'_>]) -> Vec<DiffHunkInfo> {
    let mut hunks: Vec<DiffHunkInfo> = Vec::new();
    let mut old_no: u64 = 0;
    let mut new_no: u64 = 0;
    let mut current_lines: Vec<DiffLine> = Vec::new();
    let mut hunk_old_start: u64 = 0;
    let mut hunk_new_start: u64 = 0;
    let mut in_hunk = false;

    for op in ops {
        match op {
            diff::DiffOp::Equal(_line) => {
                if in_hunk && !current_lines.is_empty() {
                    hunks.push(DiffHunkInfo {
                        old_start: hunk_old_start,
                        old_count: old_no - hunk_old_start,
                        new_start: hunk_new_start,
                        new_count: new_no - hunk_new_start,
                        lines: std::mem::take(&mut current_lines),
                    });
                }
                old_no += 1;
                new_no += 1;
                in_hunk = false;
            }
            diff::DiffOp::Delete(line) => {
                if !in_hunk {
                    hunk_old_start = old_no;
                    hunk_new_start = new_no;
                    in_hunk = true;
                }
                current_lines.push(DiffLine {
                    old_no: Some(old_no),
                    new_no: None,
                    kind: "delete".to_string(),
                    text: String::from_utf8_lossy(line).into_owned(),
                });
                old_no += 1;
            }
            diff::DiffOp::Insert(line) => {
                if !in_hunk {
                    hunk_old_start = old_no;
                    hunk_new_start = new_no;
                    in_hunk = true;
                }
                current_lines.push(DiffLine {
                    old_no: None,
                    new_no: Some(new_no),
                    kind: "insert".to_string(),
                    text: String::from_utf8_lossy(line).into_owned(),
                });
                new_no += 1;
            }
        }
    }

    if !current_lines.is_empty() {
        hunks.push(DiffHunkInfo {
            old_start: hunk_old_start,
            old_count: old_no - hunk_old_start,
            new_start: hunk_new_start,
            new_count: new_no - hunk_new_start,
            lines: current_lines,
        });
    }

    hunks
}

// ---------- Handler: search ----------

fn search(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");

    let query = router::get_param(params, "q").unwrap_or("").to_string();
    let kind = router::get_param(params, "kind")
        .unwrap_or("commits")
        .to_string();

    if query.is_empty() {
        return json_response(r#"{"kind":"none","items":[]}"#);
    }

    let Some(repo) = open_repo(state, owner, name) else {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    };

    match kind.as_str() {
        "commits" => search_commits(&repo, &query),
        "code" => search_code(&repo, &query),
        _ => json_response(r#"{"kind":"none","items":[]}"#),
    }
}

fn search_commits(repo: &crate::repo::Repo, query: &str) -> (u16, String, Vec<u8>, String) {
    let Ok(head) = refs::read_head(&repo.gyt_dir) else {
        return json_response(r#"{"kind":"commits","items":[]}"#);
    };
    let Ok(Some(start)) = refs::resolve(&repo.gyt_dir, &head) else {
        return json_response(r#"{"kind":"commits","items":[]}"#);
    };

    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cur = Some(start);
    let query_lower = query.to_ascii_lowercase();

    while let Some(id) = cur {
        if seen.contains(&id) {
            break;
        }
        seen.insert(id);
        if let Ok(c) = commit::read(&repo.gyt_dir, &id) {
            if c.message.to_ascii_lowercase().contains(&query_lower) {
                results.push(api::json_string(&id.to_hex()));
            }
            cur = c.parents.first().copied();
        } else {
            break;
        }
        if results.len() >= 20 {
            break;
        }
    }

    let body = format!(r#"{{"kind":"commits","items":[{}]}}"#, results.join(","));
    json_response(&body)
}

fn search_code(repo: &crate::repo::Repo, query: &str) -> (u16, String, Vec<u8>, String) {
    let Ok(head) = refs::read_head(&repo.gyt_dir) else {
        return json_response(r#"{"kind":"code","items":[]}"#);
    };
    let Ok(Some(_)) = refs::resolve(&repo.gyt_dir, &head) else {
        return json_response(r#"{"kind":"code","items":[]}"#);
    };
    let Ok(tree_id) = util::resolve_tree(repo, "HEAD") else {
        return json_response(r#"{"kind":"code","items":[]}"#);
    };

    let Ok(files) = util::flatten_tree(repo, &tree_id) else {
        return json_response(r#"{"kind":"code","items":[]}"#);
    };

    // Refuse to walk a million-file tree just because the operator
    // typed a search query. The pre-cap was unbounded — every search
    // request decompressed every blob on HEAD.
    if files.len() > MAX_FLATTEN_ENTRIES {
        return error_response(
            413,
            "search: repo too large to scan in one request; narrow with a smaller subtree query",
        );
    }

    let query_lower = query.to_ascii_lowercase();
    let mut results = Vec::new();
    // Hard wall-budget on bytes scanned. 20 matches is the result cap;
    // the byte cap is what stops a query that simply doesn't appear in
    // any blob from re-scanning the whole repo. After hitting it we
    // surface the partial result with `truncated:true`.
    let mut bytes_scanned: usize = 0;
    let mut truncated = false;

    for (path, (_, id)) in &files {
        if results.len() >= 20 {
            break;
        }
        if bytes_scanned >= SEARCH_BYTE_BUDGET {
            truncated = true;
            break;
        }
        if let Ok(blob) = crate::object::blob::read(&repo.gyt_dir, id) {
            // Skip huge blobs — they're almost always binary anyway,
            // and decompressing them just to grep is the dominant
            // cost of an unfiltered query.
            if blob.len() as u64 > MAX_INLINE_BLOB_BYTES {
                continue;
            }
            bytes_scanned = bytes_scanned.saturating_add(blob.len());
            let content = String::from_utf8_lossy(&blob);
            if content.to_ascii_lowercase().contains(&query_lower) {
                results.push(api::json_string(&path.to_string_lossy()));
            }
        }
    }

    let body = format!(
        r#"{{"kind":"code","items":[{}],"truncated":{truncated}}}"#,
        results.join(","),
    );
    json_response(&body)
}

// ---------- Handler: static file ----------

fn static_file(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let raw_path = router::get_param(params, "path").unwrap_or("");
    if raw_path.is_empty() || raw_path == "/" {
        if let Ok(data) = std::fs::read(state.webroot.join("index.html")) {
            return (200, "OK".into(), data, "text/html; charset=utf-8".into());
        }
        return (
            200,
            "OK".into(),
            b"<h1>gith1b</h1>".to_vec(),
            "text/html".into(),
        );
    }

    let rel = raw_path.trim_start_matches('/');
    let file_path = state.webroot.join(rel);

    if file_path.starts_with(&state.webroot)
        && file_path.exists()
        && file_path.is_file()
        && let Ok(data) = std::fs::read(&file_path)
    {
        let ctype = guess_content_type(rel);
        return (200, "OK".into(), data, ctype);
    }

    (
        404,
        "Not Found".into(),
        b"not found".to_vec(),
        "text/plain".into(),
    )
}

fn guess_content_type(path: &str) -> String {
    match path.rsplit_once('.') {
        Some((_, "html")) => "text/html; charset=utf-8",
        Some((_, "css")) => "text/css; charset=utf-8",
        Some((_, "js")) => "application/javascript; charset=utf-8",
        Some((_, "json")) => "application/json",
        Some((_, "svg")) => "image/svg+xml",
        Some((_, "png")) => "image/png",
        Some((_, "ico")) => "image/x-icon",
        Some((_, "wasm")) => "application/wasm",
        _ => "application/octet-stream",
    }
    .into()
}

// ═══════════════════════════════════════════════════════════════════
// Wire protocol handlers (gyt-protocol v1)
// Used by gyt clone, fetch, push against this server.
// ═══════════════════════════════════════════════════════════════════

/// Extract a repo path from wire protocol params: repos_root / {repo_name}
/// Resolve the URL `:repo` path component to the *gyt directory* (the dir
/// holding `HEAD`, `objects/`, etc.). Accepts both non-bare repos
/// (`<repos_root>/<repo>/.gyt`) and bare repos (`<repos_root>/<repo>`
/// where the gyt layout lives directly inside `<repo>`).
fn wire_repo_dir(state: &ServerState, params: &[(String, String)]) -> Option<std::path::PathBuf> {
    let repo = router::get_param(params, "repo")?;
    // Hard-reject anything that could escape repos_root or alias to a
    // different on-disk location: `..`, embedded path separators, NUL,
    // names starting with `.` (would hide), or empty names. PathBuf::join
    // does not canonicalize; without this check, `/../neighbour/info/refs`
    // would resolve to a sibling repo the operator never published.
    if !is_safe_repo_segment(repo) {
        return None;
    }
    let p = state.repos_root.join(repo);
    // Non-bare: `<p>/.gyt/HEAD` exists.
    if p.join(".gyt").is_dir() {
        return Some(p.join(".gyt"));
    }
    // Bare: `<p>/HEAD` exists directly.
    if p.join("HEAD").is_file() {
        return Some(p);
    }
    None
}

/// True iff `s` is safe to join under `repos_root` as a single segment.
/// The wire URL `/{repo}/...` uses one path component, so the repo name
/// must NOT contain anything that would either escape (`..`, `/`, `\`)
/// or alias to a hidden / special name. We also bound the length to
/// keep paths reasonable. This is the only checkpoint between an
/// attacker-controlled URL and `Path::join`.
fn is_safe_repo_segment(s: &str) -> bool {
    if s.is_empty() || s.len() > 255 {
        return false;
    }
    if s == "." || s == ".." {
        return false;
    }
    if s.starts_with('.') {
        return false;
    }
    !s.bytes()
        .any(|b| b == b'/' || b == b'\\' || b == 0 || b == b':')
}

/// GET /{repo}/info/refs - list all refs as tab-separated text
fn wire_info_refs(
    state: &ServerState,
    params: &[(String, String)],
) -> (u16, String, Vec<u8>, String) {
    let dir = match wire_repo_dir(state, params) {
        Some(d) => d,
        None => {
            return (
                404,
                "Not Found".into(),
                b"repo not found".to_vec(),
                "text/plain".into(),
            );
        }
    };
    let Ok(refs) = crate::refs::list_refs(&dir, "refs") else {
        return (
            500,
            "Internal Error".into(),
            b"failed to list refs".to_vec(),
            "text/plain".into(),
        );
    };
    let mut body = Vec::new();
    for (name, oid) in &refs {
        writeln!(body, "{oid}\t{name}").ok();
    }
    (200, "OK".into(), body, "text/plain".into())
}

/// POST /{repo}/objects/want - given list of object IDs, return the compressed objects
fn wire_objects_want(
    state: &ServerState,
    params: &[(String, String)],
    body: &[u8],
) -> (u16, String, Vec<u8>, String) {
    let gyt_dir = match wire_repo_dir(state, params) {
        Some(d) => d,
        None => {
            return (
                404,
                "Not Found".into(),
                b"repo not found".to_vec(),
                "text/plain".into(),
            );
        }
    };
    // Body is newline-separated object IDs (hex)
    let ids: Vec<String> = String::from_utf8_lossy(body)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    // Read each object, reconstruct on-disk bytes, then packfile them
    let mut entries = Vec::new();
    for id_str in &ids {
        let Ok(id) = ObjectId::from_hex(id_str) else {
            continue;
        };
        let Ok(obj) = crate::object::store::read(&gyt_dir, &id) else {
            continue;
        };
        let raw = crate::object::store::build_raw(obj.kind, &obj.payload);
        let on_disk = crate::compress::encode(&raw);
        entries.push(crate::net::protocol::PackEntry {
            id,
            bytes: on_disk,
        });
    }
    let out = crate::net::protocol::encode_packfile(&entries);
    (200, "OK".into(), out, "application/octet-stream".into())
}

/// POST /{repo}/objects/have - receive objects from client, store them
/// Body is pack format (see `encode_pack` in protocol.rs):
///   [u32 LE len][on-disk compressed bytes]...
fn wire_objects_have(
    state: &ServerState,
    params: &[(String, String)],
    body: &[u8],
) -> (u16, String, Vec<u8>, String) {
    let gyt_dir = match wire_repo_dir(state, params) {
        Some(d) => d,
        None => {
            return (
                404,
                "Not Found".into(),
                b"repo not found".to_vec(),
                "text/plain".into(),
            );
        }
    };
    // Parse body as packfile format
    let entries = match crate::net::protocol::parse_packfile(body) {
        Ok(e) => e,
        Err(e) => {
            return (
                400,
                "Bad Request".into(),
                format!("invalid pack: {e}").into_bytes(),
                "text/plain".into(),
            );
        }
    };
    // Hold the object-store lock for the duration of the upload so a
    // concurrent gc cannot prune objects we've written but not yet
    // referenced. The lock is short — every entry is a single
    // decompress + canonicality check + write — so contention is
    // negligible in practice.
    let _objects_lock = match crate::fs_util::FileLock::acquire(
        &gyt_dir.join("objects.lock"),
        std::time::Duration::from_secs(30),
    ) {
        Ok(l) => l,
        Err(e) => {
            return (
                503,
                "Service Unavailable".into(),
                format!("objects.lock: {e}").into_bytes(),
                "text/plain".into(),
            );
        }
    };
    let mut n_stored = 0u32;
    let mut n_skipped = 0u32;
    for entry in &entries {
        // Decompress on-disk bytes to get raw: "<kind> <size>\0<payload>"
        let Ok(raw) = crate::compress::decode(&entry.bytes) else {
            n_skipped += 1;
            continue;
        };
        let Ok((kind, payload)) = crate::object::store::parse_raw(&raw) else {
            n_skipped += 1;
            continue;
        };
        // Canonical-encoding check for commits and tags: refuse to accept
        // objects whose stored bytes don't match `encode(decode(bytes))`.
        // Without this a malicious pusher can poison the repo with a
        // non-canonical commit that every future reader fails to decode.
        if kind == crate::object::ObjectKind::Commit
            && crate::object::commit::decode(&payload).is_err()
        {
            n_skipped += 1;
            continue;
        }
        if kind == crate::object::ObjectKind::Tag
            && crate::object::tag::decode(&payload).is_err()
        {
            n_skipped += 1;
            continue;
        }
        // Canonical-encoding check for trees: the wire bytes must
        // re-encode to themselves. Without this, a pusher could
        // upload a tree with unsorted entries or duplicate names —
        // the BLAKE3 still matches the stored bytes (which is what
        // we hash), but every consumer that assumes sortedness
        // (diff, status, walk) would misbehave. Mirrors the commit
        // and tag gates above.
        if kind == crate::object::ObjectKind::Tree {
            match crate::object::tree::decode(&payload) {
                Ok(entries) => {
                    if crate::object::tree::encode(&entries) != payload {
                        n_skipped += 1;
                        continue;
                    }
                }
                Err(_) => {
                    n_skipped += 1;
                    continue;
                }
            }
        }
        match crate::object::store::write_bytes(&gyt_dir, kind, &payload) {
            Ok(_) => n_stored += 1,
            Err(_) => n_skipped += 1,
        }
    }
    let body = format!("stored={n_stored} skipped={n_skipped}");
    (200, "OK".into(), body.into_bytes(), "text/plain".into())
}

/// POST /{repo}/refs/update - update refs on the server
/// Body is tab-separated "OLD_HEX\tNEW_HEX\tREFNAME\n" entries.
/// Enforces fast-forward (unless `?force=1`) and, when the repo config has
/// `sign_required = true`, verifies every new commit against the allowed
/// signers listed in `.gyt/allowed_signers`. Audit lines are appended to
/// `.gyt/audit.log` for successful updates.
fn wire_refs_update(
    state: &ServerState,
    params: &[(String, String)],
    raw_query: Option<&str>,
    body: &[u8],
    actor: Option<&str>,
) -> (u16, String, Vec<u8>, String) {
    let gyt_dir = match wire_repo_dir(state, params) {
        Some(d) => d,
        None => {
            return (
                404,
                "Not Found".into(),
                b"repo not found".to_vec(),
                "text/plain".into(),
            );
        }
    };
    let updates = match crate::net::protocol::parse_ref_updates(body) {
        Ok(u) => u,
        Err(e) => {
            return (
                400,
                "Bad Request".into(),
                format!("invalid ref updates: {e}").into_bytes(),
                "text/plain".into(),
            );
        }
    };

    let force = raw_query
        .is_some_and(|q| q.split('&').any(|p| p == "force=1"));
    let force_with_lease = raw_query
        .is_some_and(|q| q.split('&').any(|p| p == "force-with-lease=1"));

    // Per-repo lock: hold for the entire evaluate+write sequence to
    // prevent two concurrent pushes from both passing the FF check (which
    // reads the on-disk ref) and then both writing — silently losing one
    // pusher's history. The lock is a cross-process file lock so concurrent
    // CLI commits inside the repo also serialize.
    let lock_path = gyt_dir.join("refs.lock");
    let _lock = match crate::fs_util::FileLock::acquire(
        &lock_path,
        std::time::Duration::from_secs(10),
    ) {
        Ok(l) => l,
        Err(e) => {
            return (
                503,
                "Service Unavailable".into(),
                format!("could not acquire refs lock: {e}\n").into_bytes(),
                "text/plain".into(),
            );
        }
    };

    let (sign_required, allowed) = refs_policy::server_policy_with_overrides(
        &gyt_dir,
        state.signers_file.as_deref(),
        state.policy_config.as_deref(),
    );
    let mode = if force {
        refs_policy::Mode::Force
    } else if force_with_lease {
        refs_policy::Mode::ForceWithLease
    } else {
        refs_policy::Mode::FastForward
    };
    let eval = refs_policy::evaluate_with_mode(&gyt_dir, &updates, mode, sign_required, &allowed);
    if !eval.is_clean() {
        let mut msg = String::new();
        for (refname, err) in &eval.blocked {
            msg.push_str(&format!("{refname}: {}\n", err.user_message()));
        }
        return (409, "Conflict".into(), msg.into_bytes(), "text/plain".into());
    }

    let mut n_updated = 0u32;
    let mut n_failed = 0u32;
    for update in &updates {
        let ref_path = gyt_dir.join(&update.name);
        if let Some(parent) = ref_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match std::fs::write(&ref_path, format!("{}\n", update.new).as_bytes()) {
            Ok(()) => {
                n_updated += 1;
                refs_policy::append_audit(&gyt_dir, update, actor);
                crate::reflog::record(
                    &gyt_dir,
                    &update.name,
                    update.old.as_ref(),
                    &update.new,
                    actor.unwrap_or("anon"),
                    "wire: refs/update",
                );
            }
            Err(_) => n_failed += 1,
        }
    }
    let body = format!("updated={n_updated} failed={n_failed}");
    (200, "OK".into(), body.into_bytes(), "text/plain".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::init;
    use crate::config::Config;
    use crate::net::router;
    use std::fs;
    use std::sync::{Mutex, MutexGuard};

    static GLOBAL_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        GLOBAL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn create_test_repo(
        owner: &str,
        name: &str,
        repos_root: &std::path::Path,
    ) -> std::path::PathBuf {
        let dir = repos_root.join(owner).join(name);
        std::fs::create_dir_all(&dir).unwrap();
        init::init_at(&dir).unwrap();
        let cfg = Config {
            user_name: Some("Test User".into()),
            user_email: Some("test@example.com".into()),
            ..Config::default()
        };
        cfg.write(&dir.join(".gyt")).unwrap();
        dir
    }

    fn make_state(repos_root: &std::path::Path, webroot: &std::path::Path) -> Arc<ServerState> {
        Arc::new(ServerState {
            repos_root: repos_root.to_path_buf(),
            webroot: webroot.to_path_buf(),
            auth_token: None,
            auth_acl: None,
            signers_file: None,
            policy_config: None,
            shutdown: Mutex::new(false),
            metrics: Metrics::default(),
            listen_addr: "127.0.0.1:0".parse().unwrap(),
        })
    }

    fn body_str(body: &[u8]) -> String {
        String::from_utf8_lossy(body).into_owned()
    }

    #[test]
    fn repo_info_not_found() {
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let _dir = create_test_repo("alice", "myrepo", repos.path());
        let state = make_state(repos.path(), webroot.path());
        let params = vec![
            ("owner".to_string(), "bob".to_string()),
            ("name".to_string(), "nonexist".to_string()),
        ];
        let (status, _reason, _body, ctype) = repo_info(&state, &params);
        assert_eq!(status, 404);
        assert_eq!(ctype, "application/json");
    }

    #[test]
    fn repo_info_found() {
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let _dir = create_test_repo("alice", "myrepo", repos.path());
        let state = make_state(repos.path(), webroot.path());
        let params = vec![
            ("owner".to_string(), "alice".to_string()),
            ("name".to_string(), "myrepo".to_string()),
        ];
        let (status, reason, body, ctype) = repo_info(&state, &params);
        assert_eq!(status, 200);
        assert_eq!(reason, "OK");
        assert_eq!(ctype, "application/json");
        assert!(body_str(&body).contains("alice"));
        assert!(body_str(&body).contains("myrepo"));
    }

    #[test]
    fn repo_list_lists_repos() {
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let _dir = create_test_repo("alice", "myrepo", repos.path());
        let state = make_state(repos.path(), webroot.path());
        let (status, _reason, body, ctype) = repo_list(&state, &[]);
        assert_eq!(status, 200);
        assert_eq!(ctype, "application/json");
        assert!(body_str(&body).contains("alice"));
        assert!(body_str(&body).contains("myrepo"));
    }

    #[test]
    fn refs_lists_branches() {
        let _g = lock();
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let dir = create_test_repo("alice", "myrepo", repos.path());

        fs::write(dir.join("hello.txt"), b"hello").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "initial".to_string()]).unwrap();
        std::env::set_current_dir(&prev).unwrap();

        let state = make_state(repos.path(), webroot.path());
        let params = vec![
            ("owner".to_string(), "alice".to_string()),
            ("name".to_string(), "myrepo".to_string()),
        ];
        let (status, _reason, body, ctype) = refs_list(&state, &params);
        assert_eq!(status, 200);
        assert_eq!(ctype, "application/json");
        assert!(body_str(&body).contains("main"));
    }

    #[test]
    fn commit_list_returns_commits() {
        let _g = lock();
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let dir = create_test_repo("alice", "myrepo", repos.path());

        fs::write(dir.join("hello.txt"), b"hello").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "initial commit".to_string()]).unwrap();
        std::env::set_current_dir(&prev).unwrap();

        let state = make_state(repos.path(), webroot.path());
        let params = vec![
            ("owner".to_string(), "alice".to_string()),
            ("name".to_string(), "myrepo".to_string()),
            ("ref".to_string(), "HEAD".to_string()),
        ];
        let (status, _reason, body, ctype) = commit_list(&state, &params);
        assert_eq!(status, 200);
        assert_eq!(ctype, "application/json");
        assert!(body_str(&body).contains("initial commit"));
    }

    #[test]
    fn tree_browse_root() {
        let _g = lock();
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let dir = create_test_repo("alice", "myrepo", repos.path());

        fs::write(dir.join("hello.txt"), b"hello world").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "initial".to_string()]).unwrap();
        std::env::set_current_dir(&prev).unwrap();

        let state = make_state(repos.path(), webroot.path());
        let params = vec![
            ("owner".to_string(), "alice".to_string()),
            ("name".to_string(), "myrepo".to_string()),
            ("ref".to_string(), "HEAD".to_string()),
            ("path".to_string(), String::new()),
        ];
        let (status, _reason, body, ctype) = tree_browse(&state, &params);
        assert_eq!(status, 200);
        assert_eq!(ctype, "application/json");
        assert!(body_str(&body).contains("hello.txt"));
    }

    #[test]
    fn static_file_returns_index_html() {
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        fs::write(webroot.path().join("index.html"), b"<h1>gith1b</h1>").unwrap();

        let state = make_state(repos.path(), webroot.path());
        let params = vec![("path".to_string(), "/".to_string())];
        let (status, _reason, body, ctype) = static_file(&state, &params);
        assert_eq!(status, 200);
        assert_eq!(ctype, "text/html; charset=utf-8");
        assert!(body.starts_with(b"<h1>gith1b</h1>"));
    }

    #[test]
    fn static_file_404_for_missing() {
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let state = make_state(repos.path(), webroot.path());
        let params = vec![("path".to_string(), "/nonexistent.css".to_string())];
        let (status, _reason, _body, _ctype) = static_file(&state, &params);
        assert_eq!(status, 404);
    }

    #[test]
    fn search_empty_query_returns_empty() {
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let state = make_state(repos.path(), webroot.path());
        let params = vec![
            ("owner".to_string(), "alice".to_string()),
            ("name".to_string(), "myrepo".to_string()),
            ("q".to_string(), String::new()),
        ];
        let (status, _reason, body, _ctype) = search(&state, &params);
        assert_eq!(status, 200);
        assert!(body_str(&body).contains(r#""kind":"none""#));
    }

    #[test]
    fn router_tests_from_api_module() {
        let m = router::route("GET", "/api/repos/alice/myrepo");
        assert_eq!(m.handler, router::Handler::RepoInfo);
        assert_eq!(router::get_param(&m.params, "owner"), Some("alice"));
        assert_eq!(router::get_param(&m.params, "name"), Some("myrepo"));

        let m = router::route("GET", "/api/repos");
        assert_eq!(m.handler, router::Handler::RepoList);

        let m = router::route("GET", "/api/repos/alice/myrepo/commits");
        assert_eq!(m.handler, router::Handler::CommitList);

        let m = router::route("GET", "/api/repos/alice/myrepo/commits/abc123");
        assert_eq!(m.handler, router::Handler::CommitDetail);

        let m = router::route("GET", "/api/repos/alice/myrepo/tree/main");
        assert_eq!(m.handler, router::Handler::TreeBrowse);

        let m = router::route("GET", "/api/repos/alice/myrepo/refs");
        assert_eq!(m.handler, router::Handler::RefsList);

        let m = router::route("GET", "/api/repos/alice/myrepo/diff/main..feature");
        assert_eq!(m.handler, router::Handler::DiffRevs);

        let m = router::route("GET", "/api/repos/alice/myrepo/search");
        assert_eq!(m.handler, router::Handler::Search);

        let m = router::route("GET", "/css/base.css");
        assert_eq!(m.handler, router::Handler::StaticFile);
    }

    #[test]
    fn api_json_escaping() {
        let info = RepoInfo {
            owner: "alice".into(),
            name: "my/repo".into(),
            description: "has \"quotes\" and\nnewlines".into(),
            default_branch: "main".into(),
            head_commit: None,
        };
        let json = info.to_json();
        assert!(json.contains(r#"\"quotes\""#));
        assert!(json.contains("\\n"));
    }
}
