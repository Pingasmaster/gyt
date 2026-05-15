// Async HTTPS engine for the gyt CLI client.
//
// Wraps hyper's HTTP/1.1 + HTTP/2 client behind a sync API so the
// existing CLI call sites (clone / fetch / push / pull) can adopt
// HTTP/2 without becoming async themselves. ALPN negotiates h1 vs
// h2 at TLS handshake time — when the server advertises h2 (our
// `gyt serve` does, via `alpn_protocols = ["h2", "http/1.1"]`), the
// client lands on h2.
//
// Why HTTP/2 in the client matters less than it sounds:
//
// - `gyt clone` is mostly *serial*: GET /info/refs → POST
//   /objects/want → done. HTTP/2 multiplexing helps parallel
//   requests on one connection; serial requests don't gain.
// - The dominant cost of a clone is the giant `objects/want`
//   response (hundreds of MiB). For a single big response, HTTP/1.1
//   without per-stream flow control can be *faster* than badly-tuned
//   HTTP/2 — but with our server's 4 MiB stream window + 16 MiB
//   conn window, h2 is on par.
// - The real h2 wins come from HPACK header compression (small)
//   and TLS-handshake amortization (we already get this from h1
//   keep-alive too).
//
// So this is mostly future-proofing: the server speaks h2, the
// client now speaks h2, and we don't lose perf for any workload
// we care about. A future change that fans out parallel
// `objects/want` shards would actually exploit the multiplexing.
//
// Plain HTTP stays on the existing sync code in `http.rs`. Tests
// that exercise raw HTTP/1.1 framing depend on the exact byte-level
// semantics there; rewriting them through hyper would be a much
// bigger blast radius.

use std::sync::Arc;
use std::sync::OnceLock;

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::runtime::Runtime;

use crate::errors::{GytError, Result};
use crate::net::http::HttpResponse;

/// Max body size accepted from the server. Same cap as the
/// server-side enforces in the opposite direction.
const MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

/// Dedicated tokio runtime for the HTTPS client. Single-threaded
/// because the CLI is fundamentally one request at a time — a
/// multi-thread runtime would just add scheduler overhead for
/// `block_on`. Built lazily on first use.
fn rt() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .thread_name("gyt-client")
            .build()
            .expect("build client runtime")
    })
}

/// Shared rustls config for the client. ALPN advertises both h2 and
/// http/1.1 so the server picks. webpki-roots gives us the same
/// trust anchors the sync client already uses (see net::tls).
fn client_tls_config() -> Arc<rustls::ClientConfig> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let roots: rustls::RootCertStore =
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Arc::new(cfg)
    })
    .clone()
}

/// Send a single HTTPS request. Synchronous wrapper around an async
/// hyper client. The server's ALPN choice (h2 or http/1.1)
/// transparently determines the wire format; from the caller's
/// view it's just "make HTTPS request, get response."
///
/// The TLS connection is built fresh per call. This trades the
/// connection-reuse perf of the sync `HttpClient::pool` for
/// simplicity — most gyt clone flows make 1–3 requests total, so
/// the win from pooling is at most 1–2 TLS handshakes amortized.
/// TLS 1.3 session-ticket resumption (which both the server's
/// rustls config and webpki-roots' default support) keeps repeat
/// handshakes cheap.
pub fn send(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    headers: &[(&str, &str)],
) -> Result<HttpResponse> {
    let host = host.to_string();
    let method = method.to_string();
    let path = path.to_string();
    let body_owned = body.map(<[u8]>::to_vec);
    let headers_owned: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();

    rt().block_on(async move {
        send_async(&host, port, &method, &path, body_owned.as_deref(), &headers_owned).await
    })
}

async fn send_async(
    host: &str,
    port: u16,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    headers: &[(String, String)],
) -> Result<HttpResponse> {
    // TCP → TLS → hyper handshake. Each request opens a fresh
    // connection. tokio-rustls handles ALPN negotiation.
    let tcp = tokio::net::TcpStream::connect((host, port))
        .await
        .map_err(|e| GytError::Net(format!("tcp connect {host}:{port}: {e}")))?;
    let connector = tokio_rustls::TlsConnector::from(client_tls_config());
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| GytError::Net(format!("invalid server name {host:?}: {e}")))?;
    let tls = connector
        .connect(server_name, tcp)
        .await
        .map_err(|e| GytError::Net(format!("tls handshake: {e}")))?;

    let negotiated = tls
        .get_ref()
        .1
        .alpn_protocol()
        .map(<[u8]>::to_vec);
    let is_h2 = negotiated.as_deref() == Some(b"h2");

    // Build the request. hyper's API works for both h1 and h2; the
    // executor selects the protocol per the underlying connection.
    let req_body = body.map_or_else(
        || Full::new(Bytes::new()),
        |b| Full::new(Bytes::copy_from_slice(b)),
    );
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header("host", host)
        .header(
            "user-agent",
            concat!("gyt/", env!("CARGO_PKG_VERSION")),
        );
    for (k, v) in headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let req = builder
        .body(req_body)
        .map_err(|e| GytError::Net(format!("build request: {e}")))?;

    let io = TokioIo::new(tls);
    let resp = if is_h2 {
        // HTTP/2 connection: handshake yields (SendRequest, Connection).
        // Drive the connection in the background; send the request on
        // the SendRequest handle.
        let (mut sender, conn) = hyper::client::conn::http2::Builder::new(TokioExecutor::new())
            .handshake::<_, Full<Bytes>>(io)
            .await
            .map_err(|e| GytError::Net(format!("h2 client handshake: {e}")))?;
        let drive = tokio::spawn(async move {
            let _ = conn.await;
        });
        let r = sender
            .send_request(req)
            .await
            .map_err(|e| GytError::Net(format!("h2 send_request: {e}")))?;
        // Drop the sender so the connection task can complete after
        // we receive the response body. (Otherwise it sits waiting
        // for another request that never comes.)
        drop(sender);
        let response = collect_response(r).await?;
        drive.abort();
        response
    } else {
        // HTTP/1.1 client.
        let (mut sender, conn) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, Full<Bytes>>(io)
            .await
            .map_err(|e| GytError::Net(format!("h1 client handshake: {e}")))?;
        let drive = tokio::spawn(async move {
            let _ = conn.await;
        });
        let r = sender
            .send_request(req)
            .await
            .map_err(|e| GytError::Net(format!("h1 send_request: {e}")))?;
        drop(sender);
        let response = collect_response(r).await?;
        drive.abort();
        response
    };

    Ok(resp)
}

async fn collect_response(
    resp: hyper::Response<hyper::body::Incoming>,
) -> Result<HttpResponse> {
    let status = resp.status().as_u16();
    let reason = resp.status().canonical_reason().unwrap_or("").to_string();
    let mut headers: Vec<(String, String)> = Vec::with_capacity(resp.headers().len());
    for (k, v) in resp.headers() {
        if let Ok(vs) = v.to_str() {
            headers.push((k.to_string(), vs.to_string()));
        }
    }
    let body_stream = Limited::new(resp.into_body(), MAX_BODY_BYTES);
    let collected = body_stream
        .collect()
        .await
        .map_err(|e| GytError::Net(format!("read body: {e}")))?;
    let body = collected.to_bytes().to_vec();
    Ok(HttpResponse {
        status,
        reason,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unreachable_host_returns_net_error_not_panic() {
        // Port 1 is reserved (tcpmux); nothing should be listening.
        // We just want to verify the engine fails cleanly via the
        // Result path instead of panicking inside the tokio runtime.
        let r = send("127.0.0.1", 1, "GET", "/", None, &[]);
        assert!(r.is_err(), "expected error on unreachable host");
        if let Err(GytError::Net(msg)) = r {
            assert!(
                msg.contains("tcp connect") || msg.contains("Connection refused"),
                "unexpected error wording: {msg}"
            );
        } else {
            panic!("expected GytError::Net");
        }
    }

    #[test]
    fn engine_runtime_reused_across_calls() {
        // Two back-to-back calls on the OnceLock runtime — the
        // second must not panic with "another runtime already
        // running" or anything similar.
        let _ = send("127.0.0.1", 1, "GET", "/", None, &[]);
        let _ = send("127.0.0.1", 1, "GET", "/", None, &[]);
    }
}
