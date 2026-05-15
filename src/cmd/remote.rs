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
    let mut cfg = Config::load(&repo)?;

    if args.is_empty() || args[0] == "--help" {
        eprintln!("usage: gyt remote -v");
        eprintln!("       gyt remote add <name> <url>");
        return Ok(());
    }

    match args[0].as_str() {
        "-v" => {
            for (name, url) in &cfg.remotes {
                println!("{name}\t{url}");
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
            cfg.remotes.insert(name.clone(), url.clone());
            cfg.write(&repo.gyt_dir)?;
            println!("added remote {name} -> {url}");
        }
        other => {
            return Err(GytError::InvalidArgument(format!(
                "unknown remote subcommand: {other}"
            )));
        }
    }
    Ok(())
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