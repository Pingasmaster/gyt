// gyt verify — verify a signed commit's signature.
//
// Usage: gyt verify [--pub <path>] <commit-id>
//
// If no commit-id is given, verifies HEAD.
// If --pub is not given, uses the default public key path or GYT_SIGNING_PUB env.

use crate::errors::{GytError, Result};
use crate::object::commit;
use crate::refs;
use crate::repo::Repo;

#[expect(
    clippy::indexing_slicing,
    reason = "args[i] is gated by the `while i < args.len()` loop header"
)]
pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    let mut pub_key_path: Option<std::path::PathBuf> = None;
    let mut commit_ref: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!("Usage: gyt verify [--pub <path>] [<commit-id>]");
                println!();
                println!("Verify the ed25519 signature on a commit.");
                println!("If no commit-id is given, verifies HEAD.");
                println!(
                    "If --pub is not given, uses GYT_SIGNING_PUB env or ~/.config/gyt/gyt-signing-pub"
                );
                return Ok(());
            }
            "--pub" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("verify: --pub requires a path".into())
                })?;
                pub_key_path = Some(std::path::PathBuf::from(v));
            }
            other => {
                if commit_ref.is_some() {
                    return Err(GytError::InvalidArgument(format!(
                        "verify: unexpected extra argument {other}"
                    )));
                }
                commit_ref = Some(other.to_string());
            }
        }
        i += 1;
    }

    // Resolve the commit to verify
    let commit_id = match commit_ref {
        Some(r) => crate::hash::ObjectId::from_hex(&r)
            .map_err(|_| GytError::InvalidArgument(format!("verify: invalid commit id {r:?}")))?,
        None => {
            let head = refs::read_head(&repo.gyt_dir)?;
            refs::resolve(&repo.gyt_dir, &head)?
                .ok_or_else(|| GytError::Repo("HEAD has no commit yet".into()))?
        }
    };

    let c = commit::read(&repo.gyt_dir, &commit_id)?;

    match &c.signature {
        None => {
            println!("commit {} is NOT SIGNED", commit_id.to_hex());
            return Ok(());
        }
        Some(b64_sig) => {
            // Reconstruct the payload without the signature line
            let payload = crate::cmd::signing::commit_payload_without_sig(&c);

            // Resolve the public key
            let pub_path = pub_key_path
                .or_else(|| {
                    std::env::var("GYT_SIGNING_PUB")
                        .ok()
                        .map(std::path::PathBuf::from)
                })
                .unwrap_or_else(crate::cmd::signing::default_pub_path);

            match crate::cmd::signing::verify_signature(&payload, b64_sig, Some(&pub_path)) {
                Ok(true) => {
                    println!("commit {}: GOOD SIGNATURE", commit_id.to_hex());
                    println!("  public key: {}", pub_path.display());
                }
                Ok(false) => {
                    println!("commit {}: BAD SIGNATURE", commit_id.to_hex());
                    return Err(GytError::Ci("signature verification failed".into()));
                }
                Err(e) => {
                    println!("commit {}: SIGNATURE CHECK FAILED", commit_id.to_hex());
                    return Err(e);
                }
            }
        }
    }

    Ok(())
}
