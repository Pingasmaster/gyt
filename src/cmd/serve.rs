use crate::errors::Result;
use crate::net::server::{ServeConfig, serve};
use std::path::PathBuf;

pub fn run(args: &[String]) -> Result<()> {
    let mut listen = "127.0.0.1:8080".to_string();
    let mut repos_root = PathBuf::from(".");
    let mut webroot = PathBuf::from("site");

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!("gyt serve [--listen <addr>] [--repos <dir>] [--webroot <dir>]");
                return Ok(());
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

    let config = ServeConfig {
        listen_addr: listen,
        repos_root,
        webroot,
    };
    serve(&config)
}
