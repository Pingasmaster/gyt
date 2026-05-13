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
            let cfg = ClientConfig::builder()
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

    // Load private key
    let keyfile = std::fs::File::open(key_path)
        .map_err(|e| GytError::Net(format!("cannot open key file {}: {e}", key_path.display())))?;
    let mut reader = std::io::BufReader::new(keyfile);
    let key = rustls::pki_types::PrivateKeyDer::pem_reader_iter(&mut reader)
        .next()
        .ok_or_else(|| GytError::Net(format!("no private key found in {}", key_path.display())))?
        .map_err(|e| GytError::Net(format!("key parse error: {e}")))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| GytError::Net(format!("server config error: {e}")))?;

    Ok(Arc::new(config))
}

/// Accept an incoming TCP stream and perform the TLS server-side handshake.
pub fn accept_tls(stream: TcpStream, config: &Arc<ServerConfig>) -> Result<ServerTlsStream> {
    let conn = ServerConnection::new(config.clone())
        .map_err(|e| GytError::Net(format!("tls accept: {e}")))?;
    let inner = StreamOwned::new(conn, stream);
    Ok(ServerTlsStream { inner })
}
