use crate::errors::Result;
use crate::net::server::{serve, ServeConfig};
use std::path::PathBuf;

pub fn parse_args(args: &[String]) -> Result<ServeConfig> {
    let mut listen = "127.0.0.1:8080".to_string();
    let mut repos_root = PathBuf::from(".");
    let mut webroot = PathBuf::from("site");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!("gyt serve [--listen <addr>] [--repos <dir>] [--webroot <dir>]");
                return Ok(ServeConfig {
                    listen_addr: listen,
                    repos_root,
                    webroot,
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
            other => {
                return Err(crate::errors::GytError::InvalidArgument(format!(
                    "serve: unknown flag {other}"
                )));
            }
        }
        i += 1;
    }

    Ok(ServeConfig {
        listen_addr: listen,
        repos_root,
        webroot,
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
