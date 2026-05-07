use crate::cmd::util;
use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::index::Index;
use crate::object::commit::{self, Commit};
use crate::refs::{self, Head};
use crate::repo::Repo;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn run(args: &[String]) -> Result<()> {
    let mut message: Option<String> = None;
    let mut ai_assists: Vec<String> = Vec::new();
    let mut co_authors: Vec<String> = Vec::new();
    let mut reviewers: Vec<String> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--help" | "-h" => {
                println!(
                    "gyt commit -m <msg> [--ai <id>]... [--co-author <Name <email>>]... [--reviewer <Name <email>>]..."
                );
                return Ok(());
            }
            "-m" | "--message" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| GytError::InvalidArgument("commit: -m requires a value".into()))?
                    .clone();
                message = Some(v);
            }
            "--ai" => {
                i += 1;
                ai_assists.push(
                    args.get(i)
                        .ok_or_else(|| {
                            GytError::InvalidArgument("commit: --ai requires a value".into())
                        })?
                        .clone(),
                );
            }
            "--co-author" => {
                i += 1;
                co_authors.push(
                    args.get(i)
                        .ok_or_else(|| {
                            GytError::InvalidArgument("commit: --co-author requires a value".into())
                        })?
                        .clone(),
                );
            }
            "--reviewer" => {
                i += 1;
                reviewers.push(
                    args.get(i)
                        .ok_or_else(|| {
                            GytError::InvalidArgument("commit: --reviewer requires a value".into())
                        })?
                        .clone(),
                );
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "commit: unexpected argument {other}"
                )));
            }
        }
        i += 1;
    }

    let message =
        message.ok_or_else(|| GytError::InvalidArgument("commit: -m <msg> is required".into()))?;

    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    let cfg = Config::load(&repo)?;
    let identity = cfg.identity()?;

    let index = Index::read(&repo.index_path())?;
    if index.entries.is_empty() {
        return Err(GytError::Repo("nothing to commit".into()));
    }

    // Build tree.
    let tree_id = util::build_tree_from_index(&repo, &index)?;

    // Resolve HEAD.
    let head = refs::read_head(&repo.gyt_dir)?;
    let parent = refs::resolve(&repo.gyt_dir, &head)?;
    let parents = parent.into_iter().collect::<Vec<_>>();

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let stamped = format!("{identity} {secs} +0000");
    let mut authors = vec![stamped.clone()];
    authors.extend(co_authors);

    let c = Commit {
        tree: tree_id,
        parents,
        authors,
        committer: stamped,
        ai_assists,
        reviewers,
        message,
    };

    let id = commit::write(&repo.gyt_dir, &c)?;

    // Update the symbolic HEAD's ref (or detached HEAD).
    let branch_label = match &head {
        Head::Symbolic(name) => {
            refs::write_ref(&repo.gyt_dir, name, &id)?;
            short_branch(name)
        }
        Head::Detached(_) => {
            refs::write_head(&repo.gyt_dir, &Head::Detached(id))?;
            "HEAD".to_string()
        }
    };

    let hex = id.to_hex();
    let short = &hex[..hex.len().min(8)];
    let first_line = c.message.lines().next().unwrap_or("");
    println!("[{branch_label} {short}] {first_line}");

    Ok(())
}

fn short_branch(refname: &str) -> String {
    refname
        .strip_prefix("refs/heads/")
        .map(std::string::ToString::to_string)
        .unwrap_or_else(|| refname.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};
    use crate::config::Config;
    use std::fs;
    use std::path::Path;

    fn write_identity_config(gyt_dir: &Path) {
        let cfg = Config {
            user_name: Some("Test".into()),
            user_email: Some("t@x".into()),
            ..Config::default()
        };
        cfg.write(gyt_dir).unwrap();
    }

    #[test]
    fn commit_root_creates_branch() {
        let _g = lock();
        let dir = tmp_dir("gyt-commit-root");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));
        fs::write(dir.join("hi.txt"), b"hi\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        let r = run(&["-m".to_string(), "init".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        let repo = Repo::open(&dir).unwrap();
        let main = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        let _ = commit::read(&repo.gyt_dir, &main).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn commit_empty_index_errors() {
        let _g = lock();
        let dir = tmp_dir("gyt-commit-empty");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let r = run(&["-m".to_string(), "x".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        assert!(r.is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn commit_records_ai_and_reviewers() {
        let _g = lock();
        let dir = tmp_dir("gyt-commit-ai");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));
        fs::write(dir.join("a.txt"), b"a\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        let r = run(&[
            "-m".to_string(),
            "msg".to_string(),
            "--ai".to_string(),
            "claude-opus-4-7".to_string(),
            "--reviewer".to_string(),
            "Carol <c@x>".to_string(),
        ]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        let repo = Repo::open(&dir).unwrap();
        let id = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        let c = commit::read(&repo.gyt_dir, &id).unwrap();
        assert_eq!(c.ai_assists, vec!["claude-opus-4-7".to_string()]);
        assert_eq!(c.reviewers, vec!["Carol <c@x>".to_string()]);
        fs::remove_dir_all(&dir).unwrap();
    }
}
