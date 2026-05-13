// gyt keygen — generate an ed25519 signing keypair.
//
// Usage: gyt keygen [--priv <path>] [--pub <path>]
//
// Defaults:  ~/.config/gyt/gyt-signing-key  and  ~/.config/gyt/gyt-signing-pub
// Override with GYT_SIGNING_KEY and GYT_SIGNING_PUB env.

use crate::errors::{GytError, Result};
use std::fmt::Write;

pub fn run(args: &[String]) -> Result<()> {
    let mut priv_path: Option<std::path::PathBuf> = None;
    let mut pub_path: Option<std::path::PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!("Usage: gyt keygen [--priv <path>] [--pub <path>]");
                println!();
                println!("Generate an ed25519 signing keypair for signed commits.");
                println!("Default signing key:  ~/.config/gyt/gyt-signing-key");
                println!("Default public key:   ~/.config/gyt/gyt-signing-pub");
                println!("Overridable via GYT_SIGNING_KEY and GYT_SIGNING_PUB env vars.");
                return Ok(());
            }
            "--priv" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("keygen: --priv requires a path".into())
                })?;
                priv_path = Some(std::path::PathBuf::from(v));
            }
            "--pub" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("keygen: --pub requires a path".into())
                })?;
                pub_path = Some(std::path::PathBuf::from(v));
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "keygen: unexpected argument {other}"
                )));
            }
        }
        i += 1;
    }

    let priv_p = priv_path
        .or_else(|| {
            std::env::var("GYT_SIGNING_KEY")
                .ok()
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(crate::cmd::signing::default_key_path);

    let pub_p = pub_path
        .or_else(|| {
            std::env::var("GYT_SIGNING_PUB")
                .ok()
                .map(std::path::PathBuf::from)
        })
        .unwrap_or_else(crate::cmd::signing::default_pub_path);

    let pub_bytes = crate::cmd::signing::generate_keys(&priv_p, &pub_p)?;

    println!("Generated ed25519 signing keypair");
    println!("  private key: {}", priv_p.display());
    println!("  public key:  {}", pub_p.display());

    // Show public key in hex for easy copying
    let mut hex = String::with_capacity(pub_bytes.len() * 2);
    for b in &pub_bytes {
        write!(hex, "{b:02x}").unwrap();
    }
    println!("  public hex:  {hex}");

    Ok(())
}
