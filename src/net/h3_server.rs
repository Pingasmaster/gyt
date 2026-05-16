// HTTP/3-over-QUIC listener for `gyt serve`. UDP-bound. Runs in its
// own tokio multi-thread runtime in a dedicated OS thread, alongside
// the HTTP/1.1 sync server and the optional HTTP/2 listener.
//
// QUIC stack: quinn for the transport, h3 for the HTTP/3 framing,
// h3-quinn as the glue. TLS material is the same cert+key the
// HTTP/1.1 and HTTP/2 paths load — the only ALPN value we accept is
// "h3" (the standard final-RFC token).

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::BodyExt;
use http_body_util::Full;
use http::Response;

use crate::errors::{GytError, Result};
use crate::net::server::{ServerState, dispatch_request};

const H3_MAX_BODY_BYTES: usize = 256 * 1024 * 1024;

pub(crate) fn run_h3(
    listen_addr: &str,
    cert_path: &Path,
    key_path: &Path,
    ticket_key: Option<&Path>,
    state: Arc<ServerState>,
) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("gyt-h3")
        .enable_all()
        .build()
        .map_err(|e| GytError::Net(format!("h3: build runtime: {e}")))?;

    let addr: SocketAddr = listen_addr
        .parse()
        .map_err(|e| GytError::Net(format!("h3: parse {listen_addr}: {e}")))?;

    let server_config = build_quic_server_config(cert_path, key_path, ticket_key)?;

    runtime.block_on(async move {
        let endpoint = quinn::Endpoint::server(server_config, addr)
            .map_err(|e| GytError::Net(format!("h3: bind {addr}: {e}")))?;
        eprintln!("gyt serve: h3 listening on https://{addr} (QUIC/UDP)");

        loop {
            if *state.shutdown.lock().unwrap_or_else(std::sync::PoisonError::into_inner) {
                eprintln!("gyt serve: h3 listener draining");
                break;
            }
            // Race the accept future against a short sleep so we re-
            // check shutdown at most once per second.
            let accept = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                endpoint.accept(),
            );
            let incoming = match accept.await {
                Ok(Some(i)) => i,
                Ok(None) => break,  // endpoint closed
                Err(_) => continue, // timeout
            };

            let st = state.clone();
            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("gyt serve: h3 conn handshake: {e}");
                        return;
                    }
                };
                let peer_ip = conn.remote_address().ip();
                let h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(conn))
                    .await
                {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("gyt serve: h3 connect: {e}");
                        return;
                    }
                };
                serve_h3_connection(h3_conn, st, peer_ip).await;
            });
        }
        endpoint.close(0u32.into(), b"shutdown");
        endpoint.wait_idle().await;
        Ok::<(), GytError>(())
    })?;
    Ok(())
}

async fn serve_h3_connection(
    mut conn: h3::server::Connection<h3_quinn::Connection, Bytes>,
    state: Arc<ServerState>,
    peer_ip: std::net::IpAddr,
) {
    loop {
        match conn.accept().await {
            Ok(Some(resolver)) => {
                let st = state.clone();
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            handle_h3_request(req, stream, st, peer_ip).await;
                        }
                        Err(e) => {
                            eprintln!("gyt serve: h3 resolve_request: {e}");
                        }
                    }
                });
            }
            Ok(None) => break,
            Err(e) => {
                // h3 reports a normal client-go-away as an error here;
                // not actionable, just exit the loop.
                eprintln!("gyt serve: h3 accept: {e}");
                break;
            }
        }
    }
}

async fn handle_h3_request(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    state: Arc<ServerState>,
    peer_ip: std::net::IpAddr,
) {
    let method = req.method().as_str().to_string();
    let uri = req.uri().clone();
    let target = uri
        .path_and_query()
        .map_or_else(|| uri.path().to_string(), |pq| pq.as_str().to_string());
    let auth_header = req
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);

    // Drain request body. h3 streams the body as a sequence of Bytes
    // chunks; we buffer with a hard size cap matching the HTTP/1.1
    // and HTTP/2 paths, AND a wall-clock deadline matching them
    // (F-D1-02: slowloris-on-body would otherwise pin a QUIC stream
    // task indefinitely under the byte cap — quinn's 60 s idle
    // timeout resets on every single byte).
    let body_buf: Vec<u8> = match tokio::time::timeout(
        std::time::Duration::from_secs(crate::net::server::BODY_READ_TIMEOUT_SECS),
        async {
            let mut buf: Vec<u8> = Vec::new();
            loop {
                match stream.recv_data().await {
                    Ok(Some(mut chunk)) => {
                        use bytes::Buf as _;
                        while chunk.has_remaining() {
                            let next = chunk.chunk();
                            if buf.len() + next.len() > H3_MAX_BODY_BYTES {
                                return Err("body too large");
                            }
                            buf.extend_from_slice(next);
                            let n = next.len();
                            chunk.advance(n);
                        }
                    }
                    Ok(None) => return Ok(buf),
                    Err(e) => {
                        eprintln!("gyt serve: h3 body recv: {e}");
                        return Err("h3 body recv");
                    }
                }
            }
        },
    )
    .await
    {
        Ok(Ok(buf)) => buf,
        Ok(Err(msg)) => {
            let status = if msg == "body too large" { 413 } else { 400 };
            let _ = write_h3_simple(&mut stream, status, msg.as_bytes(), "text/plain", &state).await;
            return;
        }
        Err(_) => {
            let _ = write_h3_simple(
                &mut stream,
                408,
                b"h3 body read timeout",
                "text/plain",
                &state,
            )
            .await;
            return;
        }
    };

    let st_blocking = state.clone();
    let auth_clone = auth_header.clone();
    let result = tokio::task::spawn_blocking(move || {
        dispatch_request(
            &st_blocking,
            &method,
            &target,
            &body_buf,
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
            format!("h3 dispatch panicked: {e}").into_bytes(),
            "text/plain".to_string(),
        ),
    };

    let _ = write_h3_response(&mut stream, status, body, &ctype, &state).await;
}

async fn write_h3_response(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: u16,
    body: Vec<u8>,
    content_type: &str,
    state: &ServerState,
) -> std::result::Result<(), String> {
    let mut builder = Response::builder()
        .status(status)
        .header("content-type", content_type)
        .header("access-control-allow-origin", "*");
    // Alt-Svc on an h3 response is technically redundant (the client
    // is already speaking h3), but it refreshes the ma= window so
    // subsequent connections from the same client keep the h3
    // fast-path even after the previous Alt-Svc expires.
    if let Some(alt) = state.alt_svc_value.as_deref() {
        builder = builder.header("alt-svc", alt);
    }
    // QUIC is always TLS-encrypted, so HSTS is always meaningful here.
    builder = builder.header(
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    );
    let resp = builder
        .body(())
        .map_err(|e| format!("h3 build response: {e}"))?;
    stream
        .send_response(resp)
        .await
        .map_err(|e| format!("h3 send_response: {e}"))?;
    if !body.is_empty() {
        stream
            .send_data(Bytes::from(body))
            .await
            .map_err(|e| format!("h3 send_data: {e}"))?;
    }
    stream
        .finish()
        .await
        .map_err(|e| format!("h3 finish: {e}"))?;
    let _ = Full::<Bytes>::new(Bytes::new()).boxed(); // keep BodyExt linked
    Ok(())
}

async fn write_h3_simple(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: u16,
    body: &[u8],
    ctype: &str,
    state: &ServerState,
) -> std::result::Result<(), String> {
    write_h3_response(stream, status, body.to_vec(), ctype, state).await
}

/// Build a quinn ServerConfig with our cert+key and ALPN=h3. We
/// share the rustls TLS material loader with the HTTP/1.1 server so
/// `chmod 600` enforcement and TLS-1.3-only stay in one place.
#[expect(
    clippy::expect_used,
    clippy::unwrap_in_result,
    reason = "60s is a hard-coded constant well within the QUIC u62 idle-timeout range; the conversion cannot fail"
)]
fn build_quic_server_config(
    cert_path: &Path,
    key_path: &Path,
    ticket_key: Option<&Path>,
) -> Result<quinn::ServerConfig> {
    let rustls_cfg = crate::net::tls::server_config(cert_path, key_path, ticket_key)?;
    let mut cfg: rustls::ServerConfig = (*rustls_cfg).clone();
    // h3 is the standardized ALPN token for HTTP/3 (RFC 9114).
    cfg.alpn_protocols = vec![b"h3".to_vec()];
    // QUIC requires the rustls config to be wrapped in a quinn-
    // specific crypto provider. The rustls feature on quinn handles
    // this; we just hand it the prepared ServerConfig.
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(cfg)
        .map_err(|e| GytError::Net(format!("h3: rustls→quic: {e}")))?;
    let mut quic_cfg = quinn::ServerConfig::with_crypto(Arc::new(crypto));

    // QUIC transport tuning. Mirrors the HTTP/2 SETTINGS rationale —
    // pack responses are big and the default windows throttle them.
    //
    // - `stream_receive_window = 4 MiB`. Per-stream receive window
    //   the *server* advertises for incoming data (push uploads).
    //   Same scale as h2's initial_stream_window_size.
    // - `receive_window = 16 MiB`. Connection-level receive window;
    //   same as h2's initial_connection_window_size.
    // - `send_window = 16 MiB`. How much in-flight data we'll buffer
    //   before applying backpressure. Sized for pack-response bursts.
    // - `max_concurrent_bidi_streams = 200`. Mirrors h2's
    //   max_concurrent_streams. Each stream still spawn_blocking's
    //   into the sync handler pool so going higher doesn't help.
    // - `max_concurrent_uni_streams = 10`. HTTP/3 only needs a few
    //   uni streams (QPACK encoder/decoder + the control stream);
    //   10 is generous, blocks resource exhaustion via stream floods.
    // - `max_idle_timeout = 60s`. RFC-typical max-idle is 30 s on
    //   the conservative end; we go to 60 s so a flaky link with
    //   packet-loss bursts (cellular handover, marginal Wi-Fi,
    //   satellite weather fade) doesn't get closed mid-transfer.
    //   Active flows reset the timer on every packet so this is
    //   the silence-tolerance budget, not a hard transfer cap.
    //
    // These are static; not env-tunable today. The "right" value at
    // 1M-user scale will come from load testing — current numbers
    // are the IETF-blog / Cloudflare-blog consensus for HTTP-over-
    // QUIC at production scale.
    let mut tp = quinn::TransportConfig::default();
    tp.stream_receive_window(quinn::VarInt::from_u32(4 * 1024 * 1024));
    tp.receive_window(quinn::VarInt::from_u32(16 * 1024 * 1024));
    tp.send_window(16 * 1024 * 1024);
    tp.max_concurrent_bidi_streams(quinn::VarInt::from_u32(200));
    tp.max_concurrent_uni_streams(quinn::VarInt::from_u32(10));
    tp.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(std::time::Duration::from_mins(1))
            .expect("60s within QUIC limits"),
    ));
    // Refuse incoming QUIC datagrams. gyt's HTTP/3 path is streams-
    // only; leaving datagram support at the quinn default exposes
    // an unused frame parser to every connection. None denies them
    // entirely (the peer's DATAGRAM frames are dropped at the
    // transport layer).
    tp.datagram_receive_buffer_size(None);
    // Pin the congestion controller explicitly. quinn's default is
    // CUBIC today but undocumented and may shift between 0.11.x
    // patch releases; an unannounced switch to e.g. BBRv2 could
    // change our pack-response latency profile under load. Lock it
    // in.
    tp.congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
    quic_cfg.transport_config(Arc::new(tp));
    Ok(quic_cfg)
}
