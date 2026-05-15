// HTTP/2 listener for `gyt serve`. Runs on its own tokio
// multi-thread runtime in a dedicated OS thread so the sync HTTP/1.1
// server keeps its existing behaviour unchanged.
//
// Wire shape:
// - Bound on a separate TCP port (--listen-h2).
// - TLS-only (no h2c, no plaintext h2). ALPN advertises h2 first,
//   then http/1.1 so hyper's `auto` server can downgrade if needed.
// - Per-request: parse method/path/headers/body, hand off to the
//   shared `dispatch_request` via `spawn_blocking`. Our handlers
//   are sync (disk I/O, xz, BLAKE3) and would block the runtime if
//   we tried to run them inline.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::path::Path;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};

use crate::errors::{GytError, Result};
use crate::net::server::{ServerState, dispatch_request};

/// Hard cap on h2 request body size; matches the HTTP/1.1 server.
const H2_MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Build a tokio runtime and run the HTTP/2 listener on it. Blocks
/// until `state.shutdown` is set, at which point it stops accepting
/// new connections and waits for in-flight requests to drain.
pub(crate) fn run_h2(
    listen_addr: &str,
    cert_path: &Path,
    key_path: &Path,
    ticket_key: Option<&Path>,
    state: Arc<ServerState>,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("gyt-h2")
        .enable_all()
        .build()
        .map_err(|e| GytError::Net(format!("h2: build runtime: {e}")))?;

    let server_config = build_tls_config(cert_path, key_path, ticket_key)?;
    let addr: SocketAddr = listen_addr
        .parse()
        .map_err(|e| GytError::Net(format!("h2: parse {listen_addr}: {e}")))?;

    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| GytError::Net(format!("h2: bind {addr}: {e}")))?;
        eprintln!("gyt serve: h2 listening on https://{addr}");
        let acceptor = tokio_rustls::TlsAcceptor::from(server_config);

        loop {
            // Cooperative shutdown: each accept loop iteration peeks
            // at the shared shutdown flag. The HTTP/1.1 server's
            // SIGTERM handler flips it; we observe it here too.
            if *state.shutdown.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
                eprintln!("gyt serve: h2 listener draining");
                break;
            }

            // accept() doesn't have a built-in deadline; race it
            // against a short sleep so we re-check the shutdown
            // flag at least once per second.
            let accept = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                listener.accept(),
            );
            let (stream, peer) = match accept.await {
                Ok(Ok(pair)) => pair,
                Ok(Err(e)) => {
                    eprintln!("gyt serve: h2 accept error: {e}");
                    continue;
                }
                Err(_) => continue, // timeout, recheck shutdown
            };

            let acceptor = acceptor.clone();
            let st = state.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(stream).await {
                    Ok(t) => t,
                    Err(e) => {
                        eprintln!("gyt serve: h2 tls handshake: {e}");
                        return;
                    }
                };
                let io = TokioIo::new(tls);
                let service = hyper::service::service_fn(move |req| {
                    let st = st.clone();
                    async move { handle_request(req, st, peer.ip()).await }
                });
                let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                // Same h2 tuning as the main listener (see
                // server::configure_h2 docstring). Without this hyper
                // ships 64 KiB stream windows that throttle our pack
                // responses to one WINDOW_UPDATE per 64 KiB.
                crate::net::server::configure_h2(builder.http2());
                if let Err(e) = builder.serve_connection(io, service).await {
                    // Connection-level errors (client reset, slow loris timeout)
                    // are not actionable — log and move on.
                    eprintln!("gyt serve: h2 conn: {e}");
                }
            });
        }
        // Drop the listener so no new sockets enter the accept queue.
        drop(listener);
        Ok::<(), GytError>(())
    })?;

    Ok(())
}

/// Turn a hyper Request into a dispatch_request call. The body is
/// fully buffered before dispatch (matches HTTP/1.1 server, which
/// also buffers); a future change could stream large bodies through
/// directly, but every existing handler reads `body: &[u8]` so
/// buffering is the right thing for now.
async fn handle_request(
    req: Request<Incoming>,
    state: Arc<ServerState>,
    peer_ip: std::net::IpAddr,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
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

    // Drain body with a size cap.
    let body_bytes = match buffer_body(req.into_body()).await {
        Ok(b) => b,
        Err(msg) => {
            let mut resp = build_response(
                413,
                "Payload Too Large",
                msg.into_bytes(),
                "text/plain",
            );
            crate::net::server::apply_protocol_headers(resp.headers_mut(), &state);
            return Ok(resp);
        }
    };

    // Move into a blocking thread so disk I/O and xz don't stall
    // the runtime.
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

    let (status, reason, body, ctype) = match result {
        Ok(t) => t,
        Err(e) => (
            500,
            "Internal Server Error".to_string(),
            format!("h2 dispatch panicked: {e}").into_bytes(),
            "text/plain".to_string(),
        ),
    };

    let mut resp = build_response(status, &reason, body, &ctype);
    crate::net::server::apply_protocol_headers(resp.headers_mut(), &state);
    Ok(resp)
}

async fn buffer_body(body: Incoming) -> std::result::Result<Vec<u8>, String> {
    // Limited rejects with an error once total bytes pass the cap.
    let limited = Limited::new(body, H2_MAX_BODY_BYTES);
    let collected = limited
        .collect()
        .await
        .map_err(|e| format!("body read: {e}"))?;
    Ok(collected.to_bytes().to_vec())
}

fn build_response(
    status: u16,
    _reason: &str,
    body: Vec<u8>,
    content_type: &str,
) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from(body)));
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

/// Same TLS shape as the sync server: rustls-ring, TLS 1.3 only,
/// session resumption with ticketer, but with ALPN advertising
/// h2 first and http/1.1 second so a client can negotiate either.
fn build_tls_config(
    cert_path: &Path,
    key_path: &Path,
    ticket_key: Option<&Path>,
) -> Result<Arc<rustls::ServerConfig>> {
    // Reuse the existing TLS loader, then mutate ALPN. We can't share
    // the Arc directly because we need a different ALPN list — alpn_protocols
    // is set inside server_config() to http/1.1 only.
    let base = crate::net::tls::server_config(cert_path, key_path, ticket_key)?;
    let mut cfg: rustls::ServerConfig = (*base).clone();
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}
