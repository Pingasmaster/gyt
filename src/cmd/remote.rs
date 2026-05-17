// `gyt remote add <name> <url>` and `gyt remote -v`

use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::repo::Repo;
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    // M30: `add` mutates per-repo config; reading the *merged*
    // global+repo+env config and writing it back persists the
    // operator's global identity (and global URL credentials) into
    // the per-repo `config.toml`. For listing (-v) the merged view
    // is fine; for the mutating `add` path we re-load only the
    // per-repo file below.
    let cfg = Config::load(&repo)?;

    if args.is_empty() || args[0] == "--help" {
        eprintln!("usage: gyt remote -v");
        eprintln!("       gyt remote add <name> <url>");
        return Ok(());
    }

    match args[0].as_str() {
        "-v" => {
            // M27: redact any `https://<token>@host` bearer token from
            // the printed URL so terminal scrollback / piped output
            // doesn't leak credentials.
            for (name, url) in &cfg.remotes {
                println!("{name}\t{}", redact_bearer_in_url(url));
            }
        }
        "add" => {
            if args.len() < 3 {
                return Err(GytError::InvalidArgument(
                    "usage: gyt remote add <name> <url>".into(),
                ));
            }
            let name = &args[1];
            let url = &args[2];
            if cfg.remotes.contains_key(name) {
                return Err(GytError::InvalidArgument(format!(
                    "remote '{name}' already exists"
                )));
            }
            // M30: read the per-repo config alone, mutate, write back.
            // Don't persist merged global state into the repo.
            let mut repo_cfg = load_repo_only(&repo)?;
            // Store the URL verbatim — stripping the bearer would
            // break subsequent fetch/pull. Print is redacted (M27).
            repo_cfg.remotes.insert(name.clone(), url.clone());
            repo_cfg.write(&repo.gyt_dir)?;
            // M27: same redaction on the add-confirmation line.
            println!("added remote {name} -> {}", redact_bearer_in_url(url));
        }
        other => {
            return Err(GytError::InvalidArgument(format!(
                "unknown remote subcommand: {other}"
            )));
        }
    }
    Ok(())
}

/// M30: read the per-repo `.gyt/config.toml` alone, NOT the merged
/// global+repo view. `Config::load(&repo)` merges global into per-repo
/// in memory; writing that back would silently persist the operator's
/// global identity (and any global URL credentials) into the per-repo
/// file.
fn load_repo_only(repo: &Repo) -> Result<Config> {
    let p = repo.gyt_dir.join("config.toml");
    if !p.exists() {
        return Ok(Config::default());
    }
    let bytes = crate::fs_util::read_all(&p)?;
    crate::config::parse(&bytes)
}

/// Replace any `<scheme>://<userinfo>@<host>...` with
/// `<scheme>://<REDACTED>@<host>...`. Keeps the URL recognizable
/// (host, path, query) while making the bearer token unloggable.
pub fn redact_bearer_in_url(url: &str) -> String {
    let Some(scheme_end) = url.find("://") else {
        return url.to_string();
    };
    let after_start = scheme_end + 3;
    let Some(after) = url.get(after_start..) else {
        return url.to_string();
    };
    // userinfo is everything before the first '/', '?', '#' AND the
    // first '@' before that delimiter.
    let stop = after
        .find(['/', '?', '#'])
        .unwrap_or(after.len());
    let Some(authority) = after.get(..stop) else {
        return url.to_string();
    };
    let Some(at_idx) = authority.find('@') else {
        return url.to_string();
    };
    let Some(scheme) = url.get(..scheme_end) else {
        return url.to_string();
    };
    let Some(rest) = after.get(at_idx + 1..) else {
        return url.to_string();
    };
    format!("{scheme}://<REDACTED>@{rest}")
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};
    use crate::config::Config;

    #[test]
    fn remote_v_lists_remotes() {
        let _g = lock();
        let dir = tmp_dir("gyt-remote");
        crate::cmd::init::init_at(&dir).unwrap();
        let mut cfg = Config::load(&Repo::open(&dir).unwrap()).unwrap();
        cfg.remotes
            .insert("origin".into(), "https://example.com/repo.git".into());
        cfg.write(&dir.join(".gyt")).unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let r = run(&["-v".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn remote_add_adds_remote() {
        let _g = lock();
        let dir = tmp_dir("gyt-remote-add");
        crate::cmd::init::init_at(&dir).unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        run(&["add".to_string(), "origin".to_string(), "http://x.gyt/".to_string()]).unwrap();
        std::env::set_current_dir(&prev).unwrap();

        let repo = Repo::open(&dir).unwrap();
        let cfg = Config::load(&repo).unwrap();
        assert_eq!(cfg.remotes.get("origin").map(String::as_str), Some("http://x.gyt/"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}