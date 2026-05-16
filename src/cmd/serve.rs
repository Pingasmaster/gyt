use crate::errors::Result;
use crate::net::server::{ServeConfig, serve};
use std::path::PathBuf;
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
pub fn parse_args(args: &[String]) -> Result<ServeConfig> {
    let mut listen = "127.0.0.1:8080".to_string();
    let mut h2_listen: Option<String> = None;
    let mut h3_listen: Option<String> = None;
    let mut repos_root = PathBuf::from(".");
    let mut webroot = PathBuf::from("site");
    let mut tls_cert: Option<PathBuf> = None;
    let mut tls_key: Option<PathBuf> = None;
    let mut tls_ticket_key: Option<PathBuf> = None;
    let mut auth_token: Option<String> = None;
    let mut auth_tokens_file: Option<PathBuf> = None;
    let mut signers_file: Option<PathBuf> = None;
    let mut policy_config: Option<PathBuf> = None;
    let mut allow_multiprocess = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!("Usage: gyt serve [options]");
                println!();
                println!("Options:");
                println!("  --listen <addr>       Listen address (default: 127.0.0.1:8080)");
                println!("  --repos <dir>         Repositories root directory (default: .)");
                println!("  --webroot <dir>       Static file webroot (default: site)");
                println!("  --cert <file>         TLS certificate PEM file");
                println!("  --key <file>          TLS private key PEM file");
                println!("  --auth-token <token>  Single bearer token, granting rw on every repo");
                println!(
                    "  --auth-tokens <file>  TSV file: <token>\\t<repo-pattern>\\t<rw|ro>"
                );
                println!("                        Pattern is a single segment, optionally with a");
                println!("                        trailing `*` (`*` alone matches every repo).");
                println!("                        Mutually exclusive with --auth-token.");
                println!("  --signers <file>      Trusted allowed_signers file (overrides per-repo)");
                println!(
                    "  --policy-config <f>   Server-side TOML overriding per-repo [commit].sign_required"
                );
                println!(
                    "  --listen-h2 <addr>    Optional HTTP/2 listen address (requires --cert/--key)"
                );
                println!(
                    "  --listen-h3 <addr>    Optional HTTP/3 (UDP/QUIC) listen address (requires --cert/--key)"
                );
                println!(
                    "  --tls-ticket-key <f>  Hex-encoded shared TLS session-ticket key file.\n\
                     \x20                      Line 1 = current key (32-byte hex), optional line 2 = previous key.\n\
                     \x20                      Use the same file on every replica for cross-replica resumption."
                );
                println!(
                    "  --allow-multiprocess  Skip the single-instance serve.lock so multiple\n\
                     \x20                      gyt serve processes can share the same repos_root\n\
                     \x20                      and the same --listen port (SO_REUSEPORT distributes\n\
                     \x20                      accepts). On-disk locks keep data correct; per-process\n\
                     \x20                      caches and rate-limit buckets diverge per replica."
                );
                return Ok(ServeConfig {
                    listen_addr: listen,
                    h2_listen_addr: h2_listen,
                    h3_listen_addr: h3_listen,
                    repos_root,
                    webroot,
                    tls_cert,
                    tls_key,
                    tls_ticket_key,
                    auth_token,
                    auth_tokens_file,
                    signers_file,
                    policy_config,
                    allow_multiprocess,
                });
            }
            "--listen" => {
                i += 1;
                listen = args.get(i).cloned().ok_or_else(|| {
                    crate::errors::GytError::InvalidArgument("--listen requires an address".into())
                })?;
            }
            "--repos" => {
                i += 1;
                let s = args.get(i).cloned().ok_or_else(|| {
                    crate::errors::GytError::InvalidArgument("--repos requires a directory".into())
                })?;
                repos_root = PathBuf::from(s);
            }
            "--webroot" => {
                i += 1;
                let s = args.get(i).cloned().ok_or_else(|| {
                    crate::errors::GytError::InvalidArgument(
                        "--webroot requires a directory".into(),
                    )
                })?;
                webroot = PathBuf::from(s);
            }
            "--cert" => {
                i += 1;
                let s = args.get(i).cloned().ok_or_else(|| {
                    crate::errors::GytError::InvalidArgument("--cert requires a file path".into())
                })?;
                tls_cert = Some(PathBuf::from(s));
            }
            "--key" => {
                i += 1;
                let s = args.get(i).cloned().ok_or_else(|| {
                    crate::errors::GytError::InvalidArgument("--key requires a file path".into())
                })?;
                tls_key = Some(PathBuf::from(s));
            }
            "--auth-token" => {
                i += 1;
                let s = args.get(i).cloned().ok_or_else(|| {
                    crate::errors::GytError::InvalidArgument(
                        "--auth-token requires a token string".into(),
                    )
                })?;
                auth_token = Some(s);
            }
            "--auth-tokens" => {
                i += 1;
                let s = args.get(i).cloned().ok_or_else(|| {
                    crate::errors::GytError::InvalidArgument(
                        "--auth-tokens requires a file path".into(),
                    )
                })?;
                auth_tokens_file = Some(PathBuf::from(s));
            }
            "--signers" => {
                i += 1;
                let s = args.get(i).cloned().ok_or_else(|| {
                    crate::errors::GytError::InvalidArgument(
                        "--signers requires a file path".into(),
                    )
                })?;
                signers_file = Some(PathBuf::from(s));
            }
            "--policy-config" => {
                i += 1;
                let s = args.get(i).cloned().ok_or_else(|| {
                    crate::errors::GytError::InvalidArgument(
                        "--policy-config requires a file path".into(),
                    )
                })?;
                policy_config = Some(PathBuf::from(s));
            }
            "--listen-h2" => {
                i += 1;
                let s = args.get(i).cloned().ok_or_else(|| {
                    crate::errors::GytError::InvalidArgument(
                        "--listen-h2 requires an address".into(),
                    )
                })?;
                h2_listen = Some(s);
            }
            "--listen-h3" => {
                i += 1;
                let s = args.get(i).cloned().ok_or_else(|| {
                    crate::errors::GytError::InvalidArgument(
                        "--listen-h3 requires an address".into(),
                    )
                })?;
                h3_listen = Some(s);
            }
            "--tls-ticket-key" => {
                i += 1;
                let s = args.get(i).cloned().ok_or_else(|| {
                    crate::errors::GytError::InvalidArgument(
                        "--tls-ticket-key requires a file path".into(),
                    )
                })?;
                tls_ticket_key = Some(PathBuf::from(s));
            }
            "--allow-multiprocess" => {
                allow_multiprocess = true;
            }
            other => {
                return Err(crate::errors::GytError::InvalidArgument(format!(
                    "serve: unknown flag {other}"
                )));
            }
        }
        i += 1;
    }

    // Validate that cert and key are provided together
    if tls_cert.is_some() != tls_key.is_some() {
        return Err(crate::errors::GytError::InvalidArgument(
            "--cert and --key must be provided together".into(),
        ));
    }
    if auth_token.is_some() && auth_tokens_file.is_some() {
        return Err(crate::errors::GytError::InvalidArgument(
            "--auth-token and --auth-tokens are mutually exclusive".into(),
        ));
    }

    if (h2_listen.is_some() || h3_listen.is_some()) && tls_cert.is_none() {
        return Err(crate::errors::GytError::InvalidArgument(
            "--listen-h2 / --listen-h3 require --cert and --key".into(),
        ));
    }

    if tls_ticket_key.is_some() && tls_cert.is_none() {
        return Err(crate::errors::GytError::InvalidArgument(
            "--tls-ticket-key requires --cert and --key (it's only useful for TLS resumption)".into(),
        ));
    }

    // F-D9-03: refuse to start an open server bound to a non-loopback
    // address. With neither --auth-token nor --auth-tokens, every
    // request is authorized — that's only safe on a loopback bind. An
    // operator typo (forgetting --auth-tokens after copy/paste) must
    // not silently expose anonymous push/pull to the network.
    if auth_token.is_none() && auth_tokens_file.is_none() {
        for addr in std::iter::once(listen.as_str())
            .chain(h2_listen.as_deref())
            .chain(h3_listen.as_deref())
        {
            if !is_loopback_listen_addr(addr) {
                return Err(crate::errors::GytError::InvalidArgument(format!(
                    "--listen {addr:?} binds a non-loopback address but no \
                     --auth-token / --auth-tokens is set — refusing to start \
                     an open server. Either bind to 127.0.0.1 / [::1], or \
                     configure auth."
                )));
            }
        }
    }

    Ok(ServeConfig {
        listen_addr: listen,
        h2_listen_addr: h2_listen,
        h3_listen_addr: h3_listen,
        repos_root,
        webroot,
        tls_cert,
        tls_key,
        tls_ticket_key,
        auth_token,
        auth_tokens_file,
        signers_file,
        policy_config,
        allow_multiprocess,
    })
}

pub fn run(args: &[String]) -> Result<()> {
    let config = parse_args(args)?;
    serve(&config)
}

/// Is the given `host:port` string a loopback bind? Used by parse_args
/// to refuse open (unauthenticated) servers on non-loopback addresses.
///
/// Accepts:
/// - `127.0.0.0/8` (the IPv4 loopback block)
/// - `::1`
/// - `localhost`
///
/// Rejects everything else, including `0.0.0.0` (any-IPv4) and `::`
/// (any-IPv6).
fn is_loopback_listen_addr(addr: &str) -> bool {
    // Strip the trailing `:port` (works for both IPv4 host:port and
    // bracketed `[ipv6]:port`). Empty / malformed → not loopback.
    let host = if let Some(stripped) = addr.strip_prefix('[')
        && let Some(end) = stripped.find(']')
    {
        &stripped[..end]
    } else if let Some(idx) = addr.rfind(':') {
        &addr[..idx]
    } else {
        addr
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        return v4.is_loopback();
    }
    if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
        return v6.is_loopback();
    }
    false
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};
    use crate::errors::GytError;

    #[test]
    fn serve_help_returns_default_config() {
        let _g = lock();
        let config = parse_args(&["--help".into()]).unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.repos_root, PathBuf::from("."));
        assert_eq!(config.webroot, PathBuf::from("site"));
        assert_eq!(config.tls_cert, None);
        assert_eq!(config.tls_key, None);
        assert_eq!(config.auth_token, None);
    }

    #[test]
    fn serve_short_help_returns_default_config() {
        let _g = lock();
        let config = parse_args(&["-h".into()]).unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:8080");
    }

    #[test]
    fn serve_default_args_yields_defaults() {
        let _g = lock();
        let config = parse_args(&[]).unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:8080");
        assert_eq!(config.repos_root, PathBuf::from("."));
        assert_eq!(config.webroot, PathBuf::from("site"));
    }

    #[test]
    fn serve_listen_without_value_errors() {
        let _g = lock();
        let result = parse_args(&["--listen".into()]);
        assert!(result.is_err());
        if let Err(GytError::InvalidArgument(msg)) = result {
            assert!(msg.contains("--listen requires an address"));
        } else {
            panic!("expected InvalidArgument");
        }
    }

    #[test]
    fn serve_repos_without_value_errors() {
        let _g = lock();
        let result = parse_args(&["--repos".into()]);
        assert!(result.is_err());
        if let Err(GytError::InvalidArgument(msg)) = result {
            assert!(msg.contains("--repos requires a directory"));
        } else {
            panic!("expected InvalidArgument");
        }
    }

    #[test]
    fn serve_webroot_without_value_errors() {
        let _g = lock();
        let result = parse_args(&["--webroot".into()]);
        assert!(result.is_err());
        if let Err(GytError::InvalidArgument(msg)) = result {
            assert!(msg.contains("--webroot requires a directory"));
        } else {
            panic!("expected InvalidArgument");
        }
    }

    #[test]
    fn serve_unknown_flag_errors() {
        let _g = lock();
        let result = parse_args(&["--badopt".into()]);
        assert!(result.is_err());
        if let Err(GytError::InvalidArgument(msg)) = result {
            assert!(msg.contains("unknown flag"));
        } else {
            panic!("expected InvalidArgument");
        }
    }

    #[test]
    fn serve_custom_listen_addr() {
        let _g = lock();
        let config = parse_args(&["--listen".into(), "0.0.0.0:3000".into()]).unwrap();
        assert_eq!(config.listen_addr, "0.0.0.0:3000");
    }

    #[test]
    fn serve_custom_repos_root() {
        let _g = lock();
        let config = parse_args(&["--repos".into(), "/data/repos".into()]).unwrap();
        assert_eq!(config.repos_root, PathBuf::from("/data/repos"));
    }

    #[test]
    fn serve_custom_webroot() {
        let _g = lock();
        let config = parse_args(&["--webroot".into(), "static".into()]).unwrap();
        assert_eq!(config.webroot, PathBuf::from("static"));
    }

    #[test]
    fn serve_all_custom_flags() {
        let _g = lock();
        let tmp = tmp_dir("gyt-serve-multi");
        let config = parse_args(&[
            "--listen".into(),
            "127.0.0.1:9999".into(),
            "--repos".into(),
            tmp.to_str().unwrap().into(),
            "--webroot".into(),
            "custom_site".into(),
        ])
        .unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:9999");
        assert_eq!(config.repos_root, tmp);
        assert_eq!(config.webroot, PathBuf::from("custom_site"));
        assert_eq!(config.tls_cert, None);
        assert_eq!(config.tls_key, None);
        assert_eq!(config.auth_token, None);
    }

    #[test]
    fn serve_tls_flags() {
        let _g = lock();
        let config = parse_args(&[
            "--cert".into(),
            "/tmp/cert.pem".into(),
            "--key".into(),
            "/tmp/key.pem".into(),
        ])
        .unwrap();
        assert_eq!(config.tls_cert, Some(PathBuf::from("/tmp/cert.pem")));
        assert_eq!(config.tls_key, Some(PathBuf::from("/tmp/key.pem")));
    }

    #[test]
    fn serve_cert_without_key_errors() {
        let _g = lock();
        let result = parse_args(&["--cert".into(), "/tmp/cert.pem".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn serve_key_without_cert_errors() {
        let _g = lock();
        let result = parse_args(&["--key".into(), "/tmp/key.pem".into()]);
        assert!(result.is_err());
    }

    #[test]
    fn serve_cert_without_value_errors() {
        let _g = lock();
        let result = parse_args(&["--cert".into()]);
        assert!(result.is_err());
        if let Err(GytError::InvalidArgument(msg)) = result {
            assert!(msg.contains("--cert requires a file path"));
        } else {
            panic!("expected InvalidArgument");
        }
    }

    #[test]
    fn serve_key_without_value_errors() {
        let _g = lock();
        let result = parse_args(&["--key".into()]);
        assert!(result.is_err());
        if let Err(GytError::InvalidArgument(msg)) = result {
            assert!(msg.contains("--key requires a file path"));
        } else {
            panic!("expected InvalidArgument");
        }
    }

    #[test]
    fn serve_auth_token() {
        let _g = lock();
        let config = parse_args(&["--auth-token".into(), "my-secret-token".into()]).unwrap();
        assert_eq!(config.auth_token, Some("my-secret-token".to_string()));
    }

    #[test]
    fn serve_auth_token_without_value_errors() {
        let _g = lock();
        let result = parse_args(&["--auth-token".into()]);
        assert!(result.is_err());
        if let Err(GytError::InvalidArgument(msg)) = result {
            assert!(msg.contains("--auth-token requires a token string"));
        } else {
            panic!("expected InvalidArgument");
        }
    }

    #[test]
    fn serve_multiple_listen_last_wins() {
        let _g = lock();
        let config = parse_args(&[
            "--listen".into(),
            "127.0.0.1:8080".into(),
            "--listen".into(),
            "127.0.0.1:9090".into(),
        ])
        .unwrap();
        assert_eq!(config.listen_addr, "127.0.0.1:9090");
    }
}
