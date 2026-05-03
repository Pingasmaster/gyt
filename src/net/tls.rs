// Minimal rustls TLS client. Phase 6a.
//
// Uses webpki-roots as the trust anchor set and the ring crypto provider.
// `connect_tls` opens a TCP connection, performs the TLS handshake, and
// returns a `TlsStream` that implements `Read + Write`. The configuration
// is built once and cached in a `OnceLock` for reuse across connections.

use crate::errors::{GytError, Result};
use rustls::client::ClientConnection;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, StreamOwned};
use std::io::{self, Read, Write};
use std::net::TcpStream;
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
            let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            let cfg = ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(cfg)
        })
        .clone()
}

/// A blocking TLS stream over a `TcpStream`.
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
