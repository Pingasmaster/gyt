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
use crate::net::cache::ResponseCache;
use crate::net::metrics::Metrics;
use crate::net::rate_limit::{LimitConfig, RateLimiter};
use crate::net::repo_index::RepoIndex;
use crate::net::refs_policy;
use crate::net::router::{self, Handler};
use crate::object::{commit, tree};
use crate::refs;
use std::io::Write;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

/// Hard cap on request body size. Anything over this is refused before
/// the server tries to allocate a buffer for it.
const MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Upper bound on how long shutdown waits for in-flight tokio tasks
/// to finish before tearing the runtime down. Tokio's `Runtime::Drop`
/// blocks indefinitely; that's fine for batch programs but unsafe for
/// a server under a finite SIGTERM grace period (k8s default 30 s,
/// systemd `TimeoutStopSec` default 90 s). A single stalled task —
/// slow-loris peer in the middle of a body read, h2 stream awaiting
/// a WINDOW_UPDATE that never comes — would otherwise hold shutdown
/// until SIGKILL fires and the runtime's threads are killed without
/// any chance to flush. 30 s is the lowest common grace period; pick
/// the smaller of "what your orchestrator gives you" and this number
/// at deployment time.
const SHUTDOWN_TIMEOUT_SECS: u64 = 30;

/// Number of tokio worker threads for the *async* runtime. The async
/// runtime needs only a small handful of threads (one per CPU is the
/// usual rule); blocking work (disk I/O, xz, BLAKE3) goes to the
/// blocking pool, which is sized separately via
/// `GYT_SERVE_BLOCKING_THREADS`.
fn configured_async_workers() -> usize {
    std::env::var("GYT_SERVE_ASYNC_WORKERS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map_or(4, std::num::NonZeroUsize::get)
                .min(16)
        })
}

/// Maximum threads in the blocking pool. Every request lands on one
/// of these via `spawn_blocking` to call our sync disk-touching
/// handlers (`dispatch_request` ultimately reads object files,
/// runs xz, hashes blobs). The default is generous because tokio's
/// blocking pool only allocates threads on demand and lets idle
/// threads expire on their own.
///
/// Pre-async, this was capped at 256 OS threads with 512 KiB stacks.
/// Tokio's default stack for blocking threads is 2 MiB; you can drop
/// it via the env if memory pressure shows up.
fn configured_blocking_threads() -> usize {
    std::env::var("GYT_SERVE_BLOCKING_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(2048)
}

/// Maximum concurrent in-flight connections accepted before the
/// listener returns 503. With async I/O each connection is just a
/// tokio task — far cheaper than the old OS-thread-per-conn model
/// — so the default is bumped 40× from the pre-async cap.
fn configured_max_inflight() -> usize {
    std::env::var("GYT_SERVE_MAX_INFLIGHT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(10_000)
}

/// Per-IP rate-limit config, overridable via env so tests and
/// reverse-proxy deployments (where every request appears to come
/// from 127.0.0.1) can raise the cap. Setting capacity to 0 disables
/// the IP bucket entirely.
fn configured_ip_limit() -> LimitConfig {
    let cap = std::env::var("GYT_SERVE_RATE_IP_CAPACITY")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(LimitConfig::DEFAULT_IP.capacity);
    let rps = std::env::var("GYT_SERVE_RATE_IP_RPS")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(LimitConfig::DEFAULT_IP.refill_per_sec);
    LimitConfig {
        capacity: cap,
        refill_per_sec: rps,
    }
}

/// Response-cache TTL in milliseconds. Default 2000 (2 s). Setting
/// to 0 disables the cache entirely (every read endpoint hits its
/// origin handler). Used by tests that manipulate refs at the FS
/// layer and need the next /info/refs read to see the change.
fn configured_response_cache_ttl() -> std::time::Duration {
    let ms = std::env::var("GYT_SERVE_CACHE_TTL_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(2000);
    std::time::Duration::from_millis(ms)
}

/// Per-actor (per bearer-token) rate-limit config. Same env-knob
/// shape as the per-IP version.
fn configured_actor_limit() -> LimitConfig {
    let cap = std::env::var("GYT_SERVE_RATE_ACTOR_CAPACITY")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(LimitConfig::DEFAULT_ACTOR.capacity);
    let rps = std::env::var("GYT_SERVE_RATE_ACTOR_RPS")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(LimitConfig::DEFAULT_ACTOR.refill_per_sec);
    LimitConfig {
        capacity: cap,
        refill_per_sec: rps,
    }
}

pub struct ServeConfig {
    pub listen_addr: String,
    /// Optional dedicated HTTP/2 listener address. When set, gyt
    /// brings up a tokio + hyper-based HTTP/2 server in parallel
    /// with the HTTP/1.1 listener. ALPN advertises both h2 and
    /// http/1.1 so a single client can pick. Defaults to None —
    /// HTTP/2 is opt-in because it requires the tokio runtime and
    /// adds 50+ transitive crates worth of attack surface.
    pub h2_listen_addr: Option<String>,
    /// Optional HTTP/3-over-QUIC listener address. UDP-bound. Like
    /// h2_listen_addr, opt-in because the QUIC stack is large.
    pub h3_listen_addr: Option<String>,
    pub repos_root: PathBuf,
    pub webroot: PathBuf,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Path to a hex-encoded TLS session-ticket key file (current key
    /// on line 1; optional previous key on line 2 for one-rotation
    /// tolerance). When None, rustls auto-generates a per-process
    /// rotating ticket key — fine for a single host, but means
    /// resumption tickets from replica A won't decrypt on replica B.
    /// Multi-replica deployments behind a non-sticky LB should set
    /// this to the same file on every replica.
    pub tls_ticket_key: Option<PathBuf>,
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
    /// When true, skip the `repos_root/serve.lock` single-instance
    /// guard so multiple `gyt serve` processes can run against the
    /// same repos_root. Pair with SO_REUSEPORT (always enabled) to
    /// get operator-level horizontal scaling on one host. Per-process
    /// state (caches, rate-limit map, metrics) is then independent
    /// per replica — the file-level locks (refs.lock, objects.lock,
    /// audit-rotate.lock) keep the on-disk data correct.
    pub allow_multiprocess: bool,
    /// When true, accept the `?force=1` and `?force-with-lease=1`
    /// query parameters on `/refs/update`. When false (default), both
    /// query parameters are ignored — every push runs in strict
    /// FastForward mode regardless of what the client requests.
    ///
    /// F-D4-03: previously every `rw` token implicitly carried force-
    /// push capability across every ref it could write. The ACL had
    /// no `force` bit. Operators who want to keep that behavior must
    /// now opt in by passing `--allow-force` to `gyt serve`.
    pub allow_force: bool,
}
#[expect(
    clippy::expect_used,
    clippy::unwrap_in_result,
    reason = "the invariant guarded by this expect cannot fail (verified at the call site); the invariant guarded by this unwrap cannot fail (verified at the call site)"
)]
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

    // Best-effort mkdir so the serve.lock acquire doesn't fail on a
    // first run where the operator hasn't created repos_root yet.
    // Errors here surface naturally when the lock acquire tries to
    // open the path.
    let _ = std::fs::create_dir_all(&config.repos_root);

    // Single-instance guard: take an exclusive lock on
    // <repos_root>/serve.lock so two `gyt serve` processes cannot
    // race against each other on the same repository directory.
    //
    // Two server processes on the *same host* sharing repos_root is a
    // genuine data-corruption risk: every per-repo refs.lock /
    // objects.lock survives across the boundary, but the audit-log
    // rotation Mutex, the rate-limiter map, the response cache, and
    // the pack cache are all per-process and would silently diverge.
    //
    // Two server processes on *different hosts* sharing a network FS
    // (NFS, GlusterFS, ceph-fuse) is NOT prevented by this lock — the
    // stale-reclamation in FileLock relies on /proc, which is per-
    // host. Multi-host serving of one repo is out of scope today;
    // shard your repos across hosts and route at the LB.
    let serve_lock = if config.allow_multiprocess {
        // Multi-process mode: skip the single-instance lock. Caller
        // is opting into running N gyt serve processes on the same
        // repos_root, with SO_REUSEPORT distributing accepts.
        None
    } else {
        Some(crate::fs_util::FileLock::acquire(
            &config.repos_root.join("serve.lock"),
            std::time::Duration::from_secs(2),
        )
        .map_err(|e| crate::errors::GytError::Repo(format!(
            "another gyt serve appears to be running on {} ({e}); refusing to start. \
             Pass --allow-multiprocess to run multiple processes (kernel SO_REUSEPORT \
             will distribute accepts) or remove {}/serve.lock after confirming no \
             gyt process holds it.",
            config.repos_root.display(),
            config.repos_root.display(),
        )))?)
    };

    // Bind synchronously via std so we can fail fast with a clean
    // error. SO_REUSEPORT (Linux/BSD) is set so multiple `gyt serve`
    // processes can share the same port — the kernel hashes incoming
    // connections across the bound sockets, giving operator-level
    // horizontal scaling on one host. SO_REUSEPORT is a no-op when
    // only one process binds, so we always set it.
    //
    // We construct via std socket → set option → bind → listen so we
    // don't need a separate dep (tokio::net::TcpSocket would also
    // work but adds an async step before the runtime is built).
    let parsed: std::net::SocketAddr = config
        .listen_addr
        .parse()
        .map_err(|e| crate::errors::GytError::InvalidArgument(format!(
            "--listen {}: {e}", config.listen_addr,
        )))?;
    let listener_std = bind_with_reuseport(parsed)?;
    let addr = listener_std.local_addr()?;
    listener_std.set_nonblocking(true)?;

    let tls_config = match (&config.tls_cert, &config.tls_key) {
        (Some(cert), Some(key)) => {
            let base =
                crate::net::tls::server_config(cert, key, config.tls_ticket_key.as_deref())?;
            // Main listener supports both h1 and h2 via ALPN. The base
            // config sets ALPN to http/1.1 only; clone and re-set so
            // h2-capable clients can land on the same socket. (HTTP/3
            // remains on its own UDP port.)
            let mut new_cfg: rustls::ServerConfig = (*base).clone();
            new_cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            Some(Arc::new(new_cfg))
        }
        (None, None) => None,
        _ => {
            return Err(crate::errors::GytError::InvalidArgument(
                "--cert and --key must be provided together".into(),
            ));
        }
    };

    if tls_config.is_some() {
        eprintln!("gyt serve: listening on https://{addr} (h1+h2 via ALPN)");
    } else {
        eprintln!("gyt serve: listening on http://{addr} (h1)");
    }

    let auth_acl = match &config.auth_tokens_file {
        Some(p) => Some(load_acl(p)?),
        None => None,
    };

    // Pre-build the Alt-Svc value. RFC 7838 format:
    //   h3=":<port>"; ma=86400
    // Port is parsed from --listen-h3 (it's the QUIC UDP port). 24-hour
    // max-age matches Cloudflare's default and is long enough that
    // a client's next visit hits the h3 fast path even if it's hours
    // away.
    let alt_svc_value = config.h3_listen_addr.as_ref().and_then(|a| {
        a.parse::<std::net::SocketAddr>().ok().map(|sa| {
            format!(r#"h3=":{}"; ma=86400"#, sa.port())
        })
    });

    let state = Arc::new(ServerState {
        repos_root: config.repos_root.clone(),
        webroot: config.webroot.clone(),
        auth_token: config.auth_token.clone(),
        auth_acl,
        signers_file: config.signers_file.clone(),
        policy_config: config.policy_config.clone(),
        allow_force: config.allow_force,
        shutdown: Mutex::new(false),
        metrics: Metrics::default(),
        listen_addr: addr,
        rate_limiter: RateLimiter::new(configured_ip_limit(), configured_actor_limit()),
        response_cache: ResponseCache::new(configured_response_cache_ttl(), 10_000),
        pack_cache: ResponseCache::new(std::time::Duration::from_hours(1), 256),
        repo_index: RepoIndex::build(&config.repos_root),
        alt_svc_value,
        tls_enabled: tls_config.is_some(),
    });

    // Periodic rescan: catches operator-side `gyt init` that bypasses
    // the wire protocol (e.g. ops mkdir'd a new repo by hand). 5 min
    // is conservative; a 1M-repo scan completes in ~30 s on a warm
    // page cache, so this is well under 10% of one CPU.
    {
        let st = state.clone();
        let repos_root = config.repos_root.clone();
        thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_mins(5));
            if *st.shutdown.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
                break;
            }
            st.repo_index.rescan(&repos_root);
        });
    }

    // Background GC for idle rate-limit buckets. Without this the
    // server leaks one bucket per (unique IP × token) seen over its
    // lifetime — at 1M users that's a meaningful resident set.
    {
        let st = state.clone();
        thread::spawn(move || loop {
            std::thread::sleep(std::time::Duration::from_mins(1));
            if *st.shutdown.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
                break;
            }
            st.rate_limiter.gc_idle(std::time::Duration::from_mins(5));
        });
    }
    // Install signal handlers. SIGTERM / SIGINT flip the shutdown flag
    // and then poke our own listen socket once so the blocking accept
    // returns. Without the self-connect, the accept loop would only
    // exit on the next *real* incoming connection — k8s / systemd
    // would hit their hard-kill grace.
    install_shutdown_signals(state.clone(), addr);

    // HTTP/2 listener on its own port, if configured. It runs an
    // independent tokio runtime in a dedicated thread; the shared
    // ServerState gives it access to the same metrics, ACL,
    // rate-limiter, and caches as the HTTP/1.1 path.
    let h2_thread = if let (Some(h2_addr), Some(cert), Some(key)) = (
        config.h2_listen_addr.clone(),
        config.tls_cert.clone(),
        config.tls_key.clone(),
    ) {
        let st = state.clone();
        let tk = config.tls_ticket_key.clone();
        Some(
            thread::Builder::new()
                .name("gyt-h2".into())
                .spawn(move || {
                    if let Err(e) = crate::net::h2_server::run_h2(
                        &h2_addr,
                        &cert,
                        &key,
                        tk.as_deref(),
                        st,
                    ) {
                        eprintln!("gyt serve: h2 listener exited: {e}");
                    }
                })
                .expect("spawn h2 thread"),
        )
    } else {
        None
    };

    // HTTP/3 listener (over QUIC) on its own UDP port.
    let h3_thread = if let (Some(h3_addr), Some(cert), Some(key)) = (
        config.h3_listen_addr.clone(),
        config.tls_cert.clone(),
        config.tls_key.clone(),
    ) {
        let st = state.clone();
        let tk = config.tls_ticket_key.clone();
        Some(
            thread::Builder::new()
                .name("gyt-h3".into())
                .spawn(move || {
                    if let Err(e) = crate::net::h3_server::run_h3(
                        &h3_addr,
                        &cert,
                        &key,
                        tk.as_deref(),
                        st,
                    ) {
                        eprintln!("gyt serve: h3 listener exited: {e}");
                    }
                })
                .expect("spawn h3 thread"),
        )
    } else {
        None
    };

    // Tokio runtime. Async workers are sized for I/O multiplexing
    // (small — one per core suffices); the blocking pool absorbs
    // sync handler work via spawn_blocking and is sized much larger.
    // Both dimensions are env-tunable for operators tuning a real
    // deployment.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(configured_async_workers())
        .max_blocking_threads(configured_blocking_threads())
        .thread_name("gyt-rt")
        .enable_all()
        .build()
        .map_err(|e| crate::errors::GytError::Net(format!("build runtime: {e}")))?;

    let accept_state = state.clone();
    let accept_tls = tls_config.clone();
    runtime.block_on(async move {
        let listener = match tokio::net::TcpListener::from_std(listener_std) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("gyt serve: from_std listener: {e}");
                return;
            }
        };
        let inflight = Arc::new(tokio::sync::Semaphore::new(configured_max_inflight()));

        loop {
            if *accept_state
                .shutdown
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
            {
                break;
            }
            // Race accept against a 1 s timeout so we recheck the
            // shared shutdown flag at most once per second — the
            // signal handler self-connects so accept normally returns
            // immediately, but the timeout is a belt + suspenders.
            let accept = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                listener.accept(),
            )
            .await;
            let (stream, peer) = match accept {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    eprintln!("gyt serve: accept: {e}");
                    continue;
                }
                Err(_) => continue, // 1 s tick — re-check shutdown
            };

            accept_state
                .metrics
                .accepts_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            // try_acquire so an overload doesn't queue up sockets in
            // the kernel backlog (which would cause LBs to time out).
            // Past the cap, return 503 inline.
            let permit = match inflight.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    accept_state
                        .metrics
                        .pool_exhausted_total
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    tokio::spawn(async move {
                        use tokio::io::AsyncWriteExt as _;
                        let mut s = stream;
                        let _ = s.write_all(POOL_FULL_RESPONSE).await;
                        let _ = s.shutdown().await;
                    });
                    continue;
                }
            };

            let peer_ip = peer.ip();
            let st = accept_state.clone();
            let tls = accept_tls.clone();
            tokio::spawn(async move {
                let _permit = permit; // released when this task ends
                if let Some(cfg) = tls {
                    let acceptor = tokio_rustls::TlsAcceptor::from(cfg);
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => serve_conn_tls(tls_stream, st, peer_ip).await,
                        Err(e) => eprintln!("gyt serve: tls accept: {e}"),
                    }
                } else {
                    serve_conn_plain(stream, st, peer_ip).await;
                }
            });
        }
        eprintln!("gyt serve: main listener draining");
    });

    // Wait for the h2/h3 listeners (if any) to drain. They poll the
    // same shutdown flag we just observed, so they'll exit shortly.
    if let Some(h) = h2_thread {
        let _ = h.join();
    }
    if let Some(h) = h3_thread {
        let _ = h.join();
    }

    // Bounded shutdown. `Runtime::Drop` blocks indefinitely; the
    // timeout variant gives in-flight tasks a window to drain, then
    // returns even if a stuck task (slow peer, stalled h2 stream)
    // would otherwise hold us forever. See SHUTDOWN_TIMEOUT_SECS.
    runtime.shutdown_timeout(std::time::Duration::from_secs(SHUTDOWN_TIMEOUT_SECS));

    // Hold the serve lock until after the workers have drained so a
    // restart can't race in mid-shutdown.
    drop(serve_lock);
    Ok(())
}

/// Serve a single plain-TCP HTTP/1.1 connection. Uses hyper's http1
/// builder directly — no h2c, no ALPN.
async fn serve_conn_plain(
    stream: tokio::net::TcpStream,
    state: Arc<ServerState>,
    peer_ip: std::net::IpAddr,
) {
    let io = hyper_util::rt::TokioIo::new(stream);
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let st = state.clone();
        async move { handle_async_request(req, st, peer_ip).await }
    });
    let mut builder = hyper::server::conn::http1::Builder::new();
    // 60 s header-read budget. Headers are typically <2 KiB, which
    // is sub-second even on a sad EDGE connection at ~50 kbit/s.
    // The 60 s ceiling is for pathological cases: high jitter,
    // packet loss bursts, captive-portal interception, a peer
    // whose process is paged out mid-write. We want "bad network"
    // to succeed eventually, not 408 in the user's face. Anything
    // shorter punishes real users with bad links; anything longer
    // hands slow-loris attackers a bigger window. 60 s is the
    // Caddy / nginx common default for the same reason.
    //
    // Body reads have no timeout — hyper streams them; the only
    // body bounds are the 256 MiB size cap and the per-request
    // rate limiter. A user pulling a 50 MiB pack at 100 kbit/s
    // (~1.5 hours) is fine.
    //
    // max_buf_size caps the per-connection buffer hyper uses for
    // headers + body framing. Set tight (64 KiB) so a single
    // oversized-header request can't allocate a multi-MB buffer.
    // Bodies that exceed 64 KiB are streamed past this buffer in
    // chunks, so the cap only constrains header parsing.
    builder
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_mins(1))
        .max_buf_size(64 * 1024);
    // No `.with_upgrades()` — gyt's git wire protocol does not use
    // HTTP Upgrade (no WebSocket, no h2c, no CONNECT). The matching
    // TLS path already omits it; the plain listener carried it for
    // no reason and only added Upgrade-header parser surface.
    if let Err(e) = builder.serve_connection(io, service).await {
        let _ = e; // peer reset / slow-loris not actionable
    }
}

/// Serve a single TLS connection. Uses hyper-util's auto::Builder
/// which dispatches to either h1 or h2 based on the ALPN value the
/// TLS layer negotiated.
async fn serve_conn_tls(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    state: Arc<ServerState>,
    peer_ip: std::net::IpAddr,
) {
    let io = hyper_util::rt::TokioIo::new(stream);
    let service = hyper::service::service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let st = state.clone();
        async move { handle_async_request(req, st, peer_ip).await }
    });
    let mut builder = hyper_util::server::conn::auto::Builder::new(
        hyper_util::rt::TokioExecutor::new(),
    );
    builder
        .http1()
        .timer(hyper_util::rt::TokioTimer::new())
        .header_read_timeout(std::time::Duration::from_mins(1))
        .max_buf_size(64 * 1024);
    configure_h2(builder.http2());
    if let Err(e) = builder.serve_connection(io, service).await {
        let _ = e;
    }
}

/// Shared HTTP/2 SETTINGS tuning for both the main TLS listener and
/// the dedicated --listen-h2 listener.
///
/// hyper's defaults are conservative — designed for a generic web
/// server returning small responses. Our workload is **big pack
/// files**: an `objects/want` response can be hundreds of MiB on one
/// stream. The relevant settings:
///
/// - `initial_stream_window_size = 4 MiB`. Default 64 KiB means the
///   server must wait for a WINDOW_UPDATE every 64 KiB sent. On a
///   100 ms RTT link, a 100 MiB body takes 160 s of pure RTT latency
///   added to the actual transfer. 4 MiB makes that 2.5 s. Cap is
///   2 GiB (2^31 − 1) but 4 MiB is a reasonable balance vs. per-
///   stream memory (one allocation per active stream).
/// - `initial_connection_window_size = 16 MiB`. Connection-level
///   flow control is separate; same problem at the connection scope.
///   16 MiB is the practical max ("near-max" — 2 GiB is technically
///   allowed but pointless for our workload).
/// - `max_frame_size = 32 KiB`. Default 16 KiB; doubling halves the
///   per-frame 9-byte header overhead without inflating per-stream
///   memory or worsening head-of-line blocking under packet loss.
///   IETF consensus value for high-throughput HTTP/2 servers; larger
///   frames are RFC-legal but stop helping once the 4 MiB stream
///   window dominates the per-frame fixed cost.
/// - `max_concurrent_streams = 200`. Default 100; we don't gain by
///   going much higher because each stream still spawn_blocking's
///   into the same sync handler pool. 200 absorbs the occasional
///   burst from a parallel-clone client.
/// - `keep_alive_interval = 30s` + `keep_alive_timeout = 30s`.
///   Sends PING frames on idle to detect dead peers before the
///   client's next stream hits a stale connection. 30 s PONG
///   window (up from gRPC's 20 s default) so a busy client on a
///   bad link — one that's actively receiving a big response and
///   slow to schedule the PONG reply — isn't closed mid-transfer.
///   PONG is an 8-byte payload; the only thing that delays it
///   meaningfully is scheduling, not bandwidth.
/// - Explicit `enable_connect_protocol` — future-proofs against
///   CONNECT-method clients (h2 RFC 8441). Cheap to set.
/// - `max_pending_accept_reset_streams = 30` + `max_local_error_reset_streams
///   = 100`. CVE-2023-44487 ("HTTP/2 Rapid Reset") lets a peer open and
///   immediately RST_STREAM each stream so the per-stream cap above
///   becomes irrelevant — work proceeds out-of-order on streams the
///   peer has already cancelled. The pending-accept cap triggers a
///   GOAWAY once a peer queues more than 30 freshly-reset streams
///   awaiting our accept; the local-error cap bounds protocol-error
///   resets we send back. Both numbers are conservative for legitimate
///   clients (a parallel-clone can hit ~10 inflight; 30/100 leaves
///   headroom for jitter).
/// - `max_header_list_size = 256 KiB`. hyper-util's auto::Builder
///   inherits hyper's permissive default for incoming header frames;
///   without an explicit cap a peer can fragment a single oversized
///   header list across many CONTINUATION frames (CVE-2024-27316
///   class) and force the server to allocate megabytes of HPACK state
///   *before* the 256 MiB body cap can apply. Real gyt requests carry
///   a handful of small headers (Authorization, Content-Type, a
///   user-agent), so 256 KiB is a tight cap with comfortable headroom.
pub(crate) fn configure_h2(
    mut b: hyper_util::server::conn::auto::Http2Builder<'_, hyper_util::rt::TokioExecutor>,
) {
    b.timer(hyper_util::rt::TokioTimer::new())
        .initial_stream_window_size(4 * 1024 * 1024)
        .initial_connection_window_size(16 * 1024 * 1024)
        .max_frame_size(32 * 1024)
        .max_concurrent_streams(200)
        .max_pending_accept_reset_streams(Some(30))
        .max_local_error_reset_streams(Some(100))
        .max_header_list_size(256 * 1024)
        .keep_alive_interval(Some(std::time::Duration::from_secs(30)))
        .keep_alive_timeout(std::time::Duration::from_secs(30))
        .enable_connect_protocol();
}

/// Per-request async handler shared by every protocol path on the
/// main listener (plain HTTP/1.1, TLS HTTP/1.1, TLS HTTP/2). Buffers
/// the request body up to MAX_BODY_BYTES, then hands the parsed
/// fields to `dispatch_request` on the blocking pool so disk I/O,
/// xz, and BLAKE3 don't stall the async runtime.
async fn handle_async_request(
    req: hyper::Request<hyper::body::Incoming>,
    state: Arc<ServerState>,
    peer_ip: std::net::IpAddr,
) -> std::result::Result<hyper::Response<http_body_util::Full<bytes::Bytes>>, std::convert::Infallible>
{
    use http_body_util::{BodyExt, Limited};

    let method = req.method().as_str().to_string();
    let uri = req.uri().clone();
    let target = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let auth_header = req
        .headers()
        .get(hyper::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Read the request body straight into a `Bytes`. The previous
    // shape did `.to_bytes().to_vec()` which allocated a full
    // body-sized Vec and copied — for a 256 MiB push that's an
    // unnecessary 256 MiB alloc + memcpy on every request.
    //
    // `Bytes` is Send+Sync (atomic refcounted), derefs to `[u8]`,
    // and moves cheaply across the spawn_blocking boundary.
    // dispatch_request already takes `&[u8]`; we just pass
    // `&body_bytes` and let Bytes::deref handle the slice view.
    let body_bytes: bytes::Bytes = {
        let limited = Limited::new(req.into_body(), MAX_BODY_BYTES);
        match limited.collect().await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                let mut resp = build_response(
                    413,
                    format!("body too large or read error: {e}").into_bytes(),
                    "text/plain",
                );
                apply_protocol_headers(resp.headers_mut(), &state);
                return Ok(resp);
            }
        }
    };

    let st_blocking = state.clone();
    let auth_clone = auth_header.clone();
    let result = tokio::task::spawn_blocking(move || {
        dispatch_request(
            &st_blocking,
            &method,
            &target,
            &body_bytes,
            auth_clone.as_deref(),
            Some(peer_ip),
        )
    })
    .await;

    let (status, _reason, body, ctype) = match result {
        Ok(t) => t,
        Err(e) => (
            500u16,
            "Internal Server Error".to_string(),
            format!("dispatch panicked: {e}").into_bytes(),
            "text/plain".to_string(),
        ),
    };

    let mut resp = build_response(status, body, &ctype);
    apply_protocol_headers(resp.headers_mut(), &state);
    Ok(resp)
}

fn build_response(
    status: u16,
    body: Vec<u8>,
    content_type: &str,
) -> hyper::Response<http_body_util::Full<bytes::Bytes>> {
    let mut resp = hyper::Response::new(http_body_util::Full::new(bytes::Bytes::from(body)));
    *resp.status_mut() = hyper::StatusCode::from_u16(status)
        .unwrap_or(hyper::StatusCode::INTERNAL_SERVER_ERROR);
    if let Ok(v) = hyper::header::HeaderValue::from_str(content_type) {
        resp.headers_mut().insert(hyper::header::CONTENT_TYPE, v);
    }
    resp.headers_mut().insert(
        hyper::header::HeaderName::from_static("access-control-allow-origin"),
        hyper::header::HeaderValue::from_static("*"),
    );
    resp
}

/// Append the operator-level response headers we want on every
/// outbound message: Alt-Svc (advertises HTTP/3) and HSTS (forces
/// HTTPS-only on browser clients). Both are independent of the
/// handler's content, so this lives in one place instead of being
/// remembered at every response site.
pub(crate) fn apply_protocol_headers(
    headers: &mut hyper::HeaderMap,
    state: &ServerState,
) {
    if let Some(v) = state.alt_svc_value.as_deref()
        && let Ok(val) = hyper::header::HeaderValue::from_str(v)
    {
        // Alt-Svc tells the client "this origin also speaks h3 at
        // this port for `ma` seconds." Without it, browsers never
        // try HTTP/3 even if our --listen-h3 port is reachable.
        headers.insert(
            hyper::header::HeaderName::from_static("alt-svc"),
            val,
        );
    }
    if state.tls_enabled {
        // HSTS: 1 year, all subdomains. Sending over plain HTTP is
        // a no-op per RFC 6797 §7.2, but we condition on tls_enabled
        // anyway so plain-HTTP test fixtures don't see noise.
        headers.insert(
            hyper::header::HeaderName::from_static("strict-transport-security"),
            hyper::header::HeaderValue::from_static(
                "max-age=31536000; includeSubDomains",
            ),
        );
    }
}

/// 503 body sent inline by the accept loop when the in-flight cap is
/// exhausted. Plain-HTTP/1.1-only — even TLS connections get this if
/// the cap fires before the handshake starts. Includes Retry-After:1
/// so a reasonable LB or client backs off promptly.
const POOL_FULL_RESPONSE: &[u8] = b"HTTP/1.1 503 Service Unavailable\r\n\
Connection: close\r\n\
Retry-After: 1\r\n\
Content-Length: 24\r\n\
Content-Type: text/plain\r\n\
\r\n\
server pool exhausted\r\n";

/// Bind a TCP listener with SO_REUSEADDR + SO_REUSEPORT. Listen
/// backlog is sized generously (1024) so the kernel can absorb a
/// burst of SYNs while the async accept loop is busy.
///
/// SO_REUSEADDR alone lets you re-bind after a fast restart (skip the
/// TIME_WAIT window). SO_REUSEPORT additionally lets multiple
/// processes bind the same port simultaneously — the kernel
/// distributes incoming connections across them by a 4-tuple hash.
/// That's the horizontal-scale story for a single host: run N
/// `gyt serve` processes on the same `--listen` and the kernel
/// load-balances. Pre-this, all accept traffic funnelled through
/// one socket and one accept loop.
fn bind_with_reuseport(addr: std::net::SocketAddr) -> Result<TcpListener> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .map_err(|e| crate::errors::GytError::Net(format!("socket(): {e}")))?;
    socket
        .set_reuse_address(true)
        .map_err(|e| crate::errors::GytError::Net(format!("SO_REUSEADDR: {e}")))?;
    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .map_err(|e| crate::errors::GytError::Net(format!("SO_REUSEPORT: {e}")))?;
    socket
        .bind(&SockAddr::from(addr))
        .map_err(|e| crate::errors::GytError::Net(format!("bind {addr}: {e}")))?;
    socket
        .listen(1024)
        .map_err(|e| crate::errors::GytError::Net(format!("listen(): {e}")))?;
    Ok(socket.into())
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

pub(crate) struct ServerState {
    pub(crate) repos_root: PathBuf,
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
    /// Mirrors `ServeConfig::allow_force`. When false (default),
    /// `?force=1` / `?force-with-lease=1` on `/refs/update` are
    /// ignored — every push runs in strict FastForward mode.
    allow_force: bool,
    pub(crate) shutdown: Mutex<bool>,
    metrics: Metrics,
    /// Bound local address. Stored so the admin-shutdown handler can
    /// self-connect to unblock accept() — the signal handler does the
    /// same trick.
    listen_addr: std::net::SocketAddr,
    rate_limiter: RateLimiter,
    /// Short-TTL cache for cheap read endpoints. Sized for ~10k
    /// distinct keys; entries expire in 2 s by default and are
    /// invalidated explicitly on refs/update.
    response_cache: ResponseCache,
    /// Long-TTL cache for `objects/want` responses. Keyed by repo +
    /// BLAKE3 of the sorted want-set. Invalidated on push so a fresh
    /// clone never observes stale objects. Sized small (256 entries)
    /// because each entry can be hundreds of MB.
    pack_cache: ResponseCache,
    /// In-memory index of every repo under `repos_root`. Built at
    /// startup; updated on refs/update and by a periodic rescan
    /// thread. Backs /api/repos so pagination is O(per_page) instead
    /// of O(total).
    repo_index: RepoIndex,
    /// Pre-built `Alt-Svc` header value, e.g. `h3=":443"; ma=86400`.
    /// `None` when no HTTP/3 listener is configured. Emitted on every
    /// HTTPS response so browsers discover the h3 endpoint without a
    /// DNS HTTPS RR fallback. RFC 7838.
    pub(crate) alt_svc_value: Option<String>,
    /// True when --cert/--key are configured, which is when HSTS
    /// makes sense. HSTS sent over plain HTTP is ignored by clients
    /// per RFC 6797 §7.2, so emitting it conditionally is purely
    /// to avoid noise in plain-HTTP test fixtures.
    pub(crate) tls_enabled: bool,
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
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
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

/// Protocol-agnostic request handler. Takes the already-parsed
/// request fields and the peer's IP (when known) and returns the
/// response tuple. This is the shared entry point: the HTTP/1.1 sync
/// path here, the HTTP/2 async path (`h2_server.rs`), and the HTTP/3
/// async path (`h3_server.rs`) all funnel through it so they share
/// metrics, rate limiting, auth, and caching.
///
/// Returns `(status, reason, body, content_type, rate_limited)` —
/// the `rate_limited` flag lets the caller know whether to keep the
/// connection alive (we deliberately keep it alive for 429 so a
/// reasonable client can retry on the same connection).
#[expect(
    clippy::string_slice,
    reason = "byte offsets used are at ASCII / char-boundary positions by construction"
)]
pub(crate) fn dispatch_request(
    state: &ServerState,
    method: &str,
    target: &str,
    body: &[u8],
    auth_header: Option<&str>,
    peer_ip: Option<std::net::IpAddr>,
) -> (u16, String, Vec<u8>, String) {
    let (path, query) = match target.find('?') {
        Some(i) => (&target[..i], Some(&target[i + 1..])),
        None => (target, None),
    };

    let params = router::query_params(query);
    let route = router::route(method, path);

    state.metrics.requests_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    state
        .metrics
        .request_body_bytes_total
        .fetch_add(body.len() as u64, std::sync::atomic::Ordering::Relaxed);
    state.metrics.record_handler(route.handler);

    let actor = actor_for(auth_header);

    if !route_is_unauth_probe(&route)
        && !state.rate_limiter.allow(peer_ip, actor.as_deref())
    {
        state
            .metrics
            .requests_rate_limited_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return (
            429,
            "Too Many Requests".into(),
            b"rate limited\n".to_vec(),
            "text/plain".into(),
        );
    }

    if !authorize_with_metric(state, auth_header, &route) {
        return (
            401,
            "Unauthorized".into(),
            b"unauthorized\n".to_vec(),
            "text/plain".into(),
        );
    }

    let (status, reason, resp_body, ctype) =
        dispatch(&route, &params, query, body, state, actor.as_deref());

    state
        .metrics
        .response_bytes_total
        .fetch_add(resp_body.len() as u64, std::sync::atomic::Ordering::Relaxed);

    (status, reason, resp_body, ctype)
}

/// Wrapper around `authorize` that bumps the unauthorized counter on
/// deny. Keeps `authorize` itself free of side effects so test code
/// can call it without metric pollution.
fn authorize_with_metric(
    state: &ServerState,
    auth_header: Option<&str>,
    route: &router::RouteMatch,
) -> bool {
    let ok = authorize(state, auth_header, route);
    if !ok {
        state
            .metrics
            .requests_unauthorized_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    ok
}

/// Per-process key for audit-log token fingerprinting. Random,
/// initialized once on first use, never persisted. Same token gives
/// the same fingerprint within one server lifetime; across restarts
/// the fingerprint changes — that's acceptable for incident-scoped
/// forensic correlation and removes the offline brute force vector
/// that an unkeyed BLAKE3 of a short token would have allowed.
fn audit_fingerprint_key() -> &'static [u8; 32] {
    use rand::RngCore as _;
    static K: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    K.get_or_init(|| {
        let mut buf = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        buf
    })
}

/// Derive an audit-log actor identifier for the request. We
/// fingerprint the presented bearer token with **keyed** BLAKE3 so an
/// attacker who later reads the audit log cannot precompute
/// blake3(candidate) over the plausible token space to recover the
/// raw token. The 32-byte key is per-process (see
/// audit_fingerprint_key) — log entries are correlatable within one
/// server lifetime and shed forensic value across restarts; that's
/// the right tradeoff vs. the offline brute force risk of an unkeyed
/// hash on short tokens.
fn actor_for(auth_header: Option<&str>) -> Option<String> {
    let header = auth_header?;
    let token = header.strip_prefix("Bearer ")?;
    let h = blake3::keyed_hash(audit_fingerprint_key(), token.as_bytes());
    let bytes = h.as_bytes();
    let mut hex = String::with_capacity(64);
    for &b in bytes {
        use std::fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    Some(format!("token:{hex}"))
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
fn authorize(
    state: &ServerState,
    auth_header: Option<&str>,
    route: &router::RouteMatch,
) -> bool {
    if route_is_unauth_probe(route) {
        return true;
    }
    if let Some(acl) = &state.auth_acl {
        let Some(token) = auth_header.and_then(|h| h.strip_prefix("Bearer ")) else {
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
        return check_auth(auth_header, token);
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
fn check_auth(auth_header: Option<&str>, expected_token: &str) -> bool {
    match auth_header {
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
        // StaticFile pulls `path` out of `route.params` — the router
        // built it from the URL when nothing else matched. We had been
        // passing query params here, which yielded raw_path="" → an
        // unconditional 200 for any otherwise-unrouted method+path
        // combination. The hand-rolled sync parser hid this by
        // rejecting smuggling attempts before dispatch; hyper accepts
        // them and reveals the bug.
        Handler::StaticFile => static_file(state, &route.params),
        Handler::NotFound => (
            404,
            "Not Found".into(),
            b"not found".to_vec(),
            "text/plain".into(),
        ),
    }
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
    //
    // Path-traversal guard: validate every URL-derived segment before
    // joining it. A URL like `/api/repos/../foo/bar` would parse the
    // owner as `..` and slip out of repos_root — pre-this, the
    // existence check at the bottom of this function was the only
    // thing standing between the attacker and a file named `.gyt`
    // anywhere on the host. The wire path already validates via
    // `is_safe_repo_segment`; the REST path now does the same so
    // there's one validation surface for the whole server.
    if !is_safe_repo_segment(owner) || !is_safe_repo_segment(name) {
        return None;
    }
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
    let cache_key = format!("repo_list:p={page}:pp={per_page}");
    if let Some((body, ctype)) = state.response_cache.get(&cache_key) {
        return (200, "OK".into(), body, ctype);
    }

    // Index-backed: the page lookup is a Vec slice, total is cached
    // in-memory. Pre-index, this walked `repos_root` (1M read_dir
    // entries) and opened each repo twice on every uncached hit.
    let (entries, total) = state.repo_index.list(page, per_page);
    let items: Vec<String> = entries
        .iter()
        .map(|e| {
            let info = RepoInfo {
                owner: e.owner.clone(),
                name: e.name.clone(),
                description: String::new(),
                default_branch: e.default_branch.clone(),
                head_commit: e.head_commit.clone(),
            };
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
    let body_bytes = body.into_bytes();
    state.response_cache.insert(
        cache_key,
        body_bytes.clone(),
        "application/json".into(),
    );
    (200, "OK".into(), body_bytes, "application/json".into())
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

    let cache_key = format!("api_refs:{owner}/{name}");
    if let Some((body, ctype)) = state.response_cache.get(&cache_key) {
        return (200, "OK".into(), body, ctype);
    }

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
    let body_bytes = body.into_bytes();
    state.response_cache.insert(
        cache_key,
        body_bytes.clone(),
        "application/json".into(),
    );
    (200, "OK".into(), body_bytes, "application/json".into())
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

    // Path-traversal defense. Apply the same segment validator the
    // wire / REST paths use to every component of the static path,
    // then canonicalize and verify the resolved file is still under
    // webroot. The per-segment validator handles ~22 attack classes
    // (Unicode normalization, control chars, Windows reserved
    // device names, double-encoding, etc.); canonicalize + starts_with
    // closes the symlink escape that segments alone can't catch.
    //
    // We also reject path lengths > 4096 bytes pre-emptively (Linux
    // PATH_MAX) so an obscenely-long URL can't push the OS error
    // path before we get a chance to deny it cleanly.
    if rel.len() > 4096 {
        return (
            414,
            "URI Too Long".into(),
            b"path too long".to_vec(),
            "text/plain".into(),
        );
    }
    for seg in rel.split('/') {
        if seg.is_empty() {
            // Consecutive `//` produce empty segments — harmless on
            // disk, but reject for cleanliness.
            return (
                404,
                "Not Found".into(),
                b"not found".to_vec(),
                "text/plain".into(),
            );
        }
        if !is_safe_repo_segment(seg) {
            return (
                404,
                "Not Found".into(),
                b"not found".to_vec(),
                "text/plain".into(),
            );
        }
    }

    let file_path = state.webroot.join(rel);
    let webroot_canon = state.webroot.canonicalize().ok();
    let file_canon = file_path.canonicalize().ok();
    let in_webroot = match (webroot_canon.as_ref(), file_canon.as_ref()) {
        (Some(w), Some(f)) => f.starts_with(w),
        _ => false,
    };

    if in_webroot
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
///
/// The wire URL `/{repo}/...` and the REST `/api/repos/:owner/:name`
/// path both eventually feed a single segment into `Path::join`. This
/// is the only validation point between attacker-controlled bytes and
/// the filesystem; it has to cover the full modern attack surface.
///
/// Defended attack classes (with the validator rule that catches each):
///
/// 1.  Classic `..` / `.`                        — exact-match deny.
/// 2.  All-dots segments (`...`, `....`, …)     — `chars.all(=='.')`.
/// 3.  Path separators `/` `\`                  — byte deny.
/// 4.  Drive separator `:` (also NTFS streams)  — byte deny.
/// 5.  NUL injection (`%00` after decode)       — byte deny.
/// 6.  Other control chars (C0 + DEL)           — byte deny.
/// 7.  Non-ASCII bytes                          — wholesale deny.
///     This is the single biggest defense: it closes Unicode
///     normalization (fullwidth `．．` → `..` under NFKC), combining
///     marks, bidi controls (U+200E/U+202E), zero-width invisibles,
///     overlong UTF-8 (Rust `str` already rejects but defense-in-
///     depth), and Latin/Cyrillic/script-g confusables for `.gyt`,
///     `.git`, `.ssh`, etc. If a future deployment legitimately
///     needs Unicode repo names, do it through an explicit
///     allow-list, not by relaxing this rule.
/// 8.  Surviving `%` (double-encoding)          — byte deny.
///     If a segment still contains `%` after HTTP decode, something
///     upstream skipped its decoder pass. Don't double-decode here;
///     refuse the request. (Apache Tomcat CVE-2025-55752 pattern.)
/// 9.  Trailing dot or trailing space (Windows) — suffix deny.
///     Win32 silently strips these (`secret.txt.` → `secret.txt`),
///     defeating any extension-based deny-list. Apply on every
///     platform because the server might be deployed on Windows or
///     read by a Windows-hosted indexer over SMB.
/// 10. Leading space                            — prefix deny.
/// 11. Length > 255 bytes / empty               — length bounds.
/// 12. Windows reserved device names            — stem case-fold deny.
///     `CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9` —
///     including with a `.ext` suffix (Win32 opens the device
///     regardless of extension). Case-insensitive ASCII compare on
///     the part before the first dot.
///
/// What this deliberately allows (verified non-escaping):
///   - leading dot: `.config`, `.well-known`, `.dotfiles`
///   - `..` as substring: `my..repo`, `foo..bar..baz`
///   - dots, dashes, underscores, digits anywhere in the middle
///
/// What this DOES NOT defend (handled elsewhere):
///   - Symlink traversal where the resolved path escapes — see
///     `repo_path`, which canonicalizes and checks `starts_with`.
///   - TOCTOU races between canonicalize and open — addressed at a
///     deeper layer (would need `openat2(RESOLVE_BENEATH)`).
///   - Total path length (PATH_MAX 4096 on Linux) — per-segment
///     255 caps each segment, but a deeply-nested URL chain could
///     overshoot. Caller is the right place to bound segment count.
#[expect(
    clippy::indexing_slicing,
    reason = "stem.as_bytes()[3] is gated by the `stem.len() == 4` check on the same expression"
)]
pub(crate) fn is_safe_repo_segment(s: &str) -> bool {
    // 1. Length bounds.
    if s.is_empty() || s.len() > 255 {
        return false;
    }
    // 2. ASCII-only. Closes the entire Unicode attack surface in one
    //    rule (see above).
    if !s.is_ascii() {
        return false;
    }
    // 3. All-dots segments. Catches "." and ".." (classic) plus
    //    "...", "....", etc. (Windows trailing-dot canaries).
    if s.bytes().all(|b| b == b'.') {
        return false;
    }
    // 4. Reject path separators, drive separator, NUL, and any byte
    //    that survives percent-decoding (double-encoding indicator).
    if s.bytes().any(|b| matches!(b, b'/' | b'\\' | 0 | b':' | b'%')) {
        return false;
    }
    // 5. Reject C0 controls (0x00..=0x1F) and DEL (0x7F).
    if s.bytes().any(|b| b < 0x20 || b == 0x7F) {
        return false;
    }
    // 6. Trailing dot or trailing space (Windows path normalization
    //    silently strips these). Leading space is also rare and
    //    typo-aliasing-prone.
    if s.ends_with('.') || s.ends_with(' ') || s.starts_with(' ') {
        return false;
    }
    // 7. Windows reserved device names. Case-insensitive ASCII
    //    compare on the stem (part before first '.'). Matches
    //    plain `CON` and `CON.txt`/`con.tar.gz` alike — Win32 opens
    //    the device regardless of extension.
    let stem_upper: String = s
        .split('.')
        .next()
        .unwrap_or("")
        .to_ascii_uppercase();
    let stem = stem_upper.as_str();
    if matches!(stem, "CON" | "PRN" | "AUX" | "NUL") {
        return false;
    }
    if stem.len() == 4
        && (stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.as_bytes()[3].is_ascii_digit()
    {
        return false;
    }
    true
}

/// GET /{repo}/info/refs - list all refs as tab-separated text
fn wire_info_refs(
    state: &ServerState,
    params: &[(String, String)],
) -> (u16, String, Vec<u8>, String) {
    let repo = router::get_param(params, "repo").unwrap_or("");
    let cache_key = format!("wire_info_refs:{repo}");
    if let Some((body, ctype)) = state.response_cache.get(&cache_key) {
        return (200, "OK".into(), body, ctype);
    }

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
    state
        .response_cache
        .insert(cache_key, body.clone(), "text/plain".into());
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

    // Cache key: BLAKE3 of the sorted want-set. Sorting normalizes
    // permutations (same wants in different order = same key); the
    // hash gives a fixed-size key regardless of how many wants the
    // client asked for. We collide-check the resulting cache hit
    // implicitly: if two distinct want-sets ever hashed the same,
    // the BLAKE3 birthday bound would make this the smallest of our
    // problems.
    let repo = router::get_param(params, "repo").unwrap_or("");
    let cache_key = {
        let mut sorted = ids.clone();
        sorted.sort();
        let joined = sorted.join("\n");
        let h = blake3::hash(joined.as_bytes());
        format!("pack:{repo}:{}", h.to_hex())
    };

    if let Some((body, ctype)) = state.pack_cache.get(&cache_key) {
        // Account served-objects against the hot path too — without
        // this the counter would understate the actual work the
        // server saved a client (encoding-equivalent cost).
        state.metrics.objects_served_total.fetch_add(
            ids.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        return (200, "OK".into(), body, ctype);
    }

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
    state.metrics.objects_served_total.fetch_add(
        entries.len() as u64,
        std::sync::atomic::Ordering::Relaxed,
    );
    state
        .pack_cache
        .insert(cache_key, out.clone(), "application/octet-stream".into());
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
    // Pushing new objects doesn't *change* what an existing
    // (sorted-wants) cache key resolves to — the BLAKE3 of the
    // want-set is content-keyed, so the same wants will continue to
    // resolve to the same bytes. But a new push can extend reachability
    // such that the next `objects/want` arrives with a different
    // want-set that overlaps with cached entries' object IDs. Those
    // older cache entries are still bit-for-bit correct (they
    // packfile the same on-disk objects), so we do NOT invalidate
    // here — wire_refs_update is the right place for that, and it
    // does invalidate the pack cache by repo prefix.
    state.metrics.objects_stored_total.fetch_add(
        u64::from(n_stored),
        std::sync::atomic::Ordering::Relaxed,
    );

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

    // F-D4-03: query-string force flags are now gated behind a server-
    // wide opt-in. Default off — any `rw` token could otherwise rewind
    // every ref it could write. Operators who want git-style "rw
    // implies force" must pass `--allow-force` to `gyt serve`.
    let force = state.allow_force
        && raw_query.is_some_and(|q| q.split('&').any(|p| p == "force=1"));
    let force_with_lease = state.allow_force
        && raw_query.is_some_and(|q| q.split('&').any(|p| p == "force-with-lease=1"));

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
    // Invalidate every cached response that depended on this repo's
    // refs — wire info/refs, the REST refs list, the per-page repo
    // listings (head commit included), and any packfile cache entry
    // for this repo. A pushed-then-pulled-back fetch must observe
    // the new objects on the next clone.
    if n_updated > 0 {
        let repo = router::get_param(params, "repo").unwrap_or("");
        state.response_cache.invalidate_prefix(&format!("wire_info_refs:{repo}"));
        state.response_cache.invalidate_prefix("api_refs:");
        state.response_cache.invalidate_prefix("repo_list:");
        state.pack_cache.invalidate_prefix(&format!("pack:{repo}:"));
    }

    state
        .metrics
        .refs_updated_total
        .fetch_add(u64::from(n_updated), std::sync::atomic::Ordering::Relaxed);

    let body = format!("updated={n_updated} failed={n_failed}");
    (200, "OK".into(), body.into_bytes(), "text/plain".into())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
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
            rate_limiter: RateLimiter::new(
                LimitConfig::DEFAULT_IP,
                LimitConfig::DEFAULT_ACTOR,
            ),
            response_cache: ResponseCache::new(std::time::Duration::from_secs(2), 1000),
            pack_cache: ResponseCache::new(std::time::Duration::from_hours(1), 16),
            repo_index: RepoIndex::build(repos_root),
            alt_svc_value: None,
            tls_enabled: false,
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

    #[test]
    fn segment_validator_attack_catalog() {
        // ────────────── ALLOWED (legitimate names) ──────────────
        // Repo / file names that look unusual but cannot escape.
        // The validator must NOT punish these.
        for ok in [
            "myrepo",
            "my.repo",
            "release-1.0",
            "foo.bar.baz",
            "Helvetica.ttf",
            "style.min.css",
            ".config",
            ".well-known",
            ".dotfiles",
            "my..repo",        // ".." as substring is legal
            "foo..bar..baz",
            "..foo",           // leading double-dot, more chars
            "x",
            "a",
            &"x".repeat(255),
            "with-hyphens",
            "with_underscores",
            "v1.0.0-beta",
            "123-numeric-start",
        ] {
            assert!(
                is_safe_repo_segment(ok),
                "should accept {ok:?}"
            );
        }

        // ────────────── REJECTED (attack catalog) ──────────────
        // One assertion per attack class so a regression in any
        // single rule is immediately attributable.

        // CLASS 1 — classic traversal
        assert!(!is_safe_repo_segment("."), "classic .");
        assert!(!is_safe_repo_segment(".."), "classic ..");

        // CLASS 2 — all-dots canary (Windows trailing-dot strip, …)
        assert!(!is_safe_repo_segment("..."), "three dots");
        assert!(!is_safe_repo_segment("...."), "four dots");
        assert!(!is_safe_repo_segment("....."), "five dots");

        // CLASS 3 — path separators
        assert!(!is_safe_repo_segment("a/b"), "forward slash");
        assert!(!is_safe_repo_segment("a\\b"), "backslash");
        assert!(!is_safe_repo_segment("/foo"), "leading slash");
        assert!(!is_safe_repo_segment("foo/"), "trailing slash");

        // CLASS 4 — drive separator + NTFS streams
        assert!(!is_safe_repo_segment("C:foo"), "drive separator");
        assert!(!is_safe_repo_segment("foo:stream"), "NTFS ADS");
        assert!(!is_safe_repo_segment("foo:$DATA"), "NTFS $DATA stream");

        // CLASS 5 — NUL injection
        assert!(!is_safe_repo_segment("foo\0.html"), "NUL truncation");
        assert!(!is_safe_repo_segment("\0"), "bare NUL");

        // CLASS 6 — control characters
        assert!(!is_safe_repo_segment("foo\nbar"), "newline");
        assert!(!is_safe_repo_segment("foo\rbar"), "carriage return");
        assert!(!is_safe_repo_segment("foo\tbar"), "tab");
        assert!(!is_safe_repo_segment("foo\x1Bbar"), "ESC");
        assert!(!is_safe_repo_segment("foo\x7Fbar"), "DEL");

        // CLASS 7 — non-ASCII: closes the entire Unicode surface.
        // Each of these has a documented attack vector (see the
        // catalog comment above the validator).
        assert!(!is_safe_repo_segment("café"), "Latin Extended");
        assert!(!is_safe_repo_segment("．．"), "fullwidth dots → '..'");
        assert!(!is_safe_repo_segment("。。"), "ideographic dots");
        assert!(!is_safe_repo_segment("..／foo"), "fullwidth solidus");
        assert!(!is_safe_repo_segment("..⁄foo"), "fraction slash");
        assert!(!is_safe_repo_segment("..∕foo"), "division slash");
        assert!(!is_safe_repo_segment("foo\u{200B}bar"), "zero-width space");
        assert!(!is_safe_repo_segment("foo\u{202E}bar"), "RTL override");
        assert!(!is_safe_repo_segment("foo\u{FEFF}"), "BOM");
        assert!(!is_safe_repo_segment(".ɡyt"), "script-g confusable for .gyt");
        assert!(!is_safe_repo_segment("ｐａｓｓｗｄ"), "fullwidth ASCII");

        // CLASS 8 — double-encoding signal (% surviving HTTP decode)
        assert!(!is_safe_repo_segment("%2e%2e"), "encoded ..");
        assert!(!is_safe_repo_segment("%252e%252e"), "double-encoded ..");
        assert!(!is_safe_repo_segment("foo%00bar"), "encoded NUL");
        assert!(!is_safe_repo_segment("foo%2Fbar"), "encoded /");

        // CLASS 9 — Windows trailing-dot / trailing-space alias
        assert!(!is_safe_repo_segment("secret.txt."), "trailing dot");
        assert!(!is_safe_repo_segment("config."), "trailing dot");
        assert!(!is_safe_repo_segment("foo "), "trailing space");
        assert!(!is_safe_repo_segment("foo. "), "trailing dot+space");

        // CLASS 10 — leading space
        assert!(!is_safe_repo_segment(" foo"), "leading space");

        // CLASS 11 — length bounds
        assert!(!is_safe_repo_segment(""), "empty");
        assert!(!is_safe_repo_segment(&"x".repeat(256)), "256 bytes");
        assert!(!is_safe_repo_segment(&"x".repeat(4096)), "huge");

        // CLASS 12 — Windows reserved device names (any case, any ext)
        assert!(!is_safe_repo_segment("CON"), "CON");
        assert!(!is_safe_repo_segment("con"), "con (lowercase)");
        assert!(!is_safe_repo_segment("Con"), "Con (mixed case)");
        assert!(!is_safe_repo_segment("CON.txt"), "CON.txt");
        assert!(!is_safe_repo_segment("con.tar.gz"), "con.tar.gz");
        assert!(!is_safe_repo_segment("PRN"), "PRN");
        assert!(!is_safe_repo_segment("AUX"), "AUX");
        assert!(!is_safe_repo_segment("NUL"), "NUL");
        assert!(!is_safe_repo_segment("nul.dat"), "nul.dat");
        assert!(!is_safe_repo_segment("COM1"), "COM1");
        assert!(!is_safe_repo_segment("COM9"), "COM9");
        assert!(!is_safe_repo_segment("com0"), "com0 (Win11 expanded)");
        assert!(!is_safe_repo_segment("LPT1"), "LPT1");
        assert!(!is_safe_repo_segment("LPT9.png"), "LPT9.png");

        // CLASS-NOT-COVERED-BY-VALIDATOR (handled by canonicalize +
        // starts_with elsewhere): symlink escape, TOCTOU. Not unit-
        // testable at this layer.
    }

    #[test]
    fn repo_path_rejects_traversal_in_owner_or_name() {
        let repos = TempDir::new("gyt-traversal");
        let webroot = TempDir::new("gyt-traversal-web");
        let state = make_state(repos.path(), webroot.path());
        // Plant a real .gyt outside repos_root so a successful
        // traversal would actually find it. (Otherwise the
        // existence check at the bottom of repo_path would hide
        // the bug.)
        let outside = repos.path().parent().unwrap().join("outside-victim");
        std::fs::create_dir_all(outside.join(".gyt")).unwrap();

        // The attacker-controlled URL segments climb the tree.
        assert_eq!(repo_path(&state, "..", "outside-victim"), None);
        assert_eq!(repo_path(&state, ".", "anything"), None);
        assert_eq!(repo_path(&state, "alice", ".."), None);
        assert_eq!(repo_path(&state, "alice", "../outside-victim"), None);

        // Sanity: a legitimately-named repo (including one with a
        // leading dot) still resolves when it exists.
        let dotted = repos.path().join("alice").join(".dotfiles");
        std::fs::create_dir_all(dotted.join(".gyt")).unwrap();
        assert!(repo_path(&state, "alice", ".dotfiles").is_some());

        let _ = std::fs::remove_dir_all(&outside);
    }
}
