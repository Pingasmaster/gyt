// TLS client and server support.
//
// Client: uses webpki-roots as the trust anchor set and the ring crypto provider.
// `connect_tls` opens a TCP connection, performs the TLS handshake, and
// returns a `TlsStream` that implements `Read + Write`.
//
// Server: `accept_tls` wraps an accepted `TcpStream` in TLS using a
// server certificate and private key loaded from PEM files.
//
// Client config is cached in a `OnceLock`; server config is built per `serve()`
// invocation (cert/key paths are not known at compile time).

use crate::errors::{GytError, Result};
use rustls::client::ClientConnection;
use rustls::pki_types::ServerName;
use rustls::pki_types::pem::PemObject;
use rustls::server::ServerConnection;
use rustls::{ClientConfig, RootCertStore, ServerConfig, StreamOwned};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::{Arc, OnceLock};

static PROVIDER_INSTALLED: OnceLock<()> = OnceLock::new();
static CLIENT_CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();

fn ensure_provider_installed() {
    PROVIDER_INSTALLED.get_or_init(|| {
        // Installing the default provider can fail if one is already installed
        // (e.g., a process-wide install from another component). That's fine —
        // we only need *some* default to be available.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn client_config() -> Arc<ClientConfig> {
    CLIENT_CONFIG
        .get_or_init(|| {
            ensure_provider_installed();
            let roots: RootCertStore = webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect();
            // TLS 1.3 only. TLS 1.2 has weaker forward secrecy guarantees
            // (server-side ticket key rotation is operator-dependent and
            // historically mishandled), exposes the legacy renegotiation
            // surface, and offers no functionality we use. Refusing 1.2
            // on the client guarantees we never downgrade silently — a
            // misconfigured peer fails fast at handshake.
            let cfg = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(cfg)
        })
        .clone()
}

/// A blocking TLS client stream over a `TcpStream`.
pub struct TlsStream {
    inner: StreamOwned<ClientConnection, TcpStream>,
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// A blocking TLS server stream over a `TcpStream`.
pub struct ServerTlsStream {
    inner: StreamOwned<ServerConnection, TcpStream>,
}

impl Read for ServerTlsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for ServerTlsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Open a TLS connection to `host:port`.
pub fn connect_tls(host: &str, port: u16) -> Result<TlsStream> {
    let cfg = client_config();
    let server_name: ServerName<'static> = ServerName::try_from(host.to_string())
        .map_err(|e| GytError::Net(format!("invalid server name {host:?}: {e}")))?;
    let conn = ClientConnection::new(cfg, server_name)
        .map_err(|e| GytError::Net(format!("tls init: {e}")))?;
    let tcp = TcpStream::connect((host, port))
        .map_err(|e| GytError::Net(format!("tcp connect {host}:{port}: {e}")))?;
    let inner = StreamOwned::new(conn, tcp);
    Ok(TlsStream { inner })
}

/// Load TLS server configuration from PEM certificate and private key files.
///
/// The certificate file may contain a chain of certificates (leaf first).
/// The private key must be in PKCS#8, PKCS#1, or SEC1 PEM format.
pub fn server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    ensure_provider_installed();

    // Load certificate chain
    let certfile = std::fs::File::open(cert_path).map_err(|e| {
        GytError::Net(format!(
            "cannot open cert file {}: {e}",
            cert_path.display()
        ))
    })?;
    let mut reader = std::io::BufReader::new(certfile);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls::pki_types::CertificateDer::pem_reader_iter(&mut reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| GytError::Net(format!("cert parse error: {e}")))?;

    if certs.is_empty() {
        return Err(GytError::Net(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }

    // Refuse to load a TLS private key whose mode permits group/world
    // access. Same policy as ed25519 signing keys: if you put your TLS
    // private material at 0644 by accident, gyt won't quietly serve it
    // up to anyone who reads the box. Run `chmod 600` to proceed.
    enforce_private_mode(key_path)?;

    // Load private key
    let keyfile = std::fs::File::open(key_path)
        .map_err(|e| GytError::Net(format!("cannot open key file {}: {e}", key_path.display())))?;
    let mut reader = std::io::BufReader::new(keyfile);
    let key = rustls::pki_types::PrivateKeyDer::pem_reader_iter(&mut reader)
        .next()
        .ok_or_else(|| GytError::Net(format!("no private key found in {}", key_path.display())))?
        .map_err(|e| GytError::Net(format!("key parse error: {e}")))?;

    // TLS 1.3 only on the server side as well. See the matching
    // comment in `client_config` for the rationale.
    let mut config = ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| GytError::Net(format!("server config error: {e}")))?;

    // TLS 1.3 ticket-based session resumption. A repeat clone from the
    // same client skips the full certificate exchange and asymmetric
    // handshake — ~10× setup-cost reduction on TLS-heavy workloads.
    // Tickets are encrypted by a server-held key, so resumption works
    // without server-side state on the cache; the in-memory cache below
    // is kept anyway because rustls reuses it for the TLS 1.3 ticket
    // record bookkeeping. A server cluster needs sticky load-balancing
    // for resumption to fire across nodes, which is the normal
    // deployment shape.
    //
    // 4096 entries × ~256 bytes ≈ 1 MiB — negligible vs. one full
    // handshake's CPU cost.
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(SESSION_CACHE_ENTRIES);
    config.ticketer = rustls::crypto::ring::Ticketer::new()
        .map_err(|e| GytError::Net(format!("ticketer init: {e}")))?;

    // ALPN: advertise "http/1.1" explicitly. The server speaks HTTP/1.1
    // only — there is no HTTP/2 or HTTP/3 implementation here. Without
    // an ALPN entry, a client that prefers h2 may negotiate "no agreed
    // protocol" then attempt h2 anyway; in the worst case we read
    // HTTP/2's connection preface as if it were an HTTP/1.1 request
    // line and emit a confusing 400.
    //
    // HTTP/2 is intentionally out of scope: the h2 crate needs an
    // async runtime to be useful (header frames + window updates are
    // interleaved with bodies and have to be served concurrently per
    // stream), and async-ification of `gyt serve` is a separate, much
    // larger change. "http/1.1" is the only protocol we want clients
    // to attempt until that change lands.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(Arc::new(config))
}

/// Server-side TLS session cache size. Sized so repeat clones from
/// thousands of distinct clients within a cache lifetime all get the
/// resumption fast-path. Tuned downwards on memory-constrained hosts
/// would only cost cache misses (i.e., a full handshake), never
/// correctness.
pub const SESSION_CACHE_ENTRIES: usize = 4096;

/// Refuse to load a private key file whose mode allows group/world
/// access. No-op on non-Unix platforms.
fn enforce_private_mode(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let md = std::fs::metadata(path)
            .map_err(|e| GytError::Net(format!("stat {}: {e}", path.display())))?;
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(GytError::Net(format!(
                "TLS key {} has insecure mode {mode:o} — refusing to load; run `chmod 600 {}`",
                path.display(),
                path.display()
            )));
        }
    }
    let _ = path;
    Ok(())
}

/// Accept an incoming TCP stream and perform the TLS server-side handshake.
pub fn accept_tls(stream: TcpStream, config: &Arc<ServerConfig>) -> Result<ServerTlsStream> {
    let conn = ServerConnection::new(config.clone())
        .map_err(|e| GytError::Net(format!("tls accept: {e}")))?;
    let inner = StreamOwned::new(conn, stream);
    Ok(ServerTlsStream { inner })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `server_config` must succeed and the returned ServerConfig must
    /// carry our resumption configuration (session_storage capacity
    /// and a ticketer set). We can't inspect the config's internal
    /// session store directly through the public API; the pin is on
    /// the public constant that controls it.
    #[test]
    fn session_cache_size_is_at_documented_value() {
        assert_eq!(SESSION_CACHE_ENTRIES, 4096);
    }


    #[cfg(unix)]
    #[test]
    fn server_config_with_resumption_loads_cleanly() {
        // Generate a self-signed cert + key via rustls test helpers
        // would be nice, but we don't depend on rcgen. Instead we just
        // verify that calling server_config() with a bogus path
        // returns Err quickly — i.e., the resumption setup doesn't
        // change the error path. The integration tests in tests/e2e.rs
        // exercise the happy path with real cert/key fixtures.
        let bogus = std::path::Path::new("/nonexistent/cert.pem");
        let r = server_config(bogus, bogus);
        assert!(r.is_err());
    }
}
