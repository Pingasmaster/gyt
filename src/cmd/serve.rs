use crate::errors::Result;
use crate::net::server::{ServeConfig, serve};
use std::path::PathBuf;

pub fn parse_args(args: &[String]) -> Result<ServeConfig> {
    let mut listen = "127.0.0.1:8080".to_string();
    let mut repos_root = PathBuf::from(".");
    let mut webroot = PathBuf::from("site");
    let mut tls_cert: Option<PathBuf> = None;
    let mut tls_key: Option<PathBuf> = None;
    let mut auth_token: Option<String> = None;
    let mut signers_file: Option<PathBuf> = None;
    let mut policy_config: Option<PathBuf> = None;

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
                println!("  --auth-token <token>  Bearer token required on all requests");
                println!("  --signers <file>      Trusted allowed_signers file (overrides per-repo)");
                println!(
                    "  --policy-config <f>   Server-side TOML overriding per-repo [commit].sign_required"
                );
                return Ok(ServeConfig {
                    listen_addr: listen,
                    repos_root,
                    webroot,
                    tls_cert,
                    tls_key,
                    auth_token,
                    signers_file,
                    policy_config,
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

    Ok(ServeConfig {
        listen_addr: listen,
        repos_root,
        webroot,
        tls_cert,
        tls_key,
        auth_token,
        signers_file,
        policy_config,
    })
}

pub fn run(args: &[String]) -> Result<()> {
    let config = parse_args(args)?;
    serve(&config)
}

#[cfg(test)]
mod tests {
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
