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
    let mut amend = false;
    let mut allow_empty = false;
    let mut sign = false;

    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        match a.as_str() {
            "--help" | "-h" => {
                println!(
                    "gyt commit -m <msg> [--amend] [--allow-empty] [--sign|-S] [--ai <id>]... [--co-author <Name <email>>]... [--reviewer <Name <email>>]..."
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
            "--amend" => {
                amend = true;
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
            "--allow-empty" => {
                allow_empty = true;
            }
            "--sign" | "-S" => {
                sign = true;
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "commit: unexpected argument {other}"
                )));
            }
        }
        i += 1;
    }

    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    let _lock = repo.lock()?;
    let cfg = Config::load(&repo)?;
    let identity = cfg.identity()?;

    let index = Index::read(&repo.index_path())?;
    // Refuse to create an unchanged commit. An empty index is "nothing
    // to commit" *only* when HEAD's tree is also empty (i.e. the initial
    // commit case). If HEAD has a non-empty tree, an empty index
    // legitimately represents "remove everything" — that's a real
    // change and must be allowed through.
    if !allow_empty && !amend && index.entries.is_empty() {
        let head_tree_empty = match util::resolve_tree(&repo, "HEAD") {
            Ok(id) => crate::object::tree::read(&repo.gyt_dir, &id)
                .map_or(true, |e| e.is_empty()),
            Err(_) => true,
        };
        if head_tree_empty {
            return Err(GytError::Repo("nothing to commit".into()));
        }
    }

    // Build tree.
    let tree_id = if index.entries.is_empty() && allow_empty {
        // Empty index with --allow-empty: use HEAD's tree if available,
        // or create a root commit with an empty tree.
        match util::resolve_tree(&repo, "HEAD") {
            Ok(id) => id,
            Err(_) => crate::object::tree::write(&repo.gyt_dir, &[])?,
        }
    } else {
        util::build_tree_from_index(&repo, &index)?
    };

    // Resolve HEAD.
    let head = refs::read_head(&repo.gyt_dir)?;
    let parent = refs::resolve(&repo.gyt_dir, &head)?;

    let (parents, commit_message) = if amend {
        let prev_id =
            parent.ok_or_else(|| GytError::Repo("cannot amend: HEAD has no commit yet".into()))?;
        let prev = commit::read(&repo.gyt_dir, &prev_id)?;
        let msg = message.unwrap_or(prev.message);
        (prev.parents, msg)
    } else {
        let msg = message
            .ok_or_else(|| GytError::InvalidArgument("commit: -m <msg> is required".into()))?;
        (parent.into_iter().collect::<Vec<_>>(), msg)
    };

    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());

    let stamped = format!("{identity} {secs} +0000");
    let mut authors = vec![stamped.clone()];
    authors.extend(co_authors);

    if cfg.sign_required && !sign {
        return Err(GytError::Repo(
            "this repository requires signed commits; use --sign (-S)".into(),
        ));
    }

    let c = Commit {
        tree: tree_id,
        parents,
        authors,
        committer: stamped,
        ai_assists,
        reviewers,
        signature: None,
        message: commit_message,
    };

    let id = if sign {
        let payload = super::signing::commit_payload_without_sig(&c);
        let key_path =
            crate::cmd::signing::resolve_key_path(std::env::var("GYT_SIGNING_KEY").ok().as_deref());
        let b64_sig = super::signing::sign_commit(&payload, &key_path)?;
        let signed = Commit {
            signature: Some(b64_sig),
            ..c.clone()
        };
        commit::write(&repo.gyt_dir, &signed)?
    } else {
        commit::write(&repo.gyt_dir, &c)?
    };

    // Update the symbolic HEAD's ref (or detached HEAD).
    let prev_for_log = parent;
    let first_line_for_log = c.message.lines().next().unwrap_or("").to_string();
    let reflog_msg = if amend {
        format!("commit (amend): {first_line_for_log}")
    } else if prev_for_log.is_none() {
        format!("commit (initial): {first_line_for_log}")
    } else {
        format!("commit: {first_line_for_log}")
    };
    let branch_label = match &head {
        Head::Symbolic(name) => {
            refs::write_ref(&repo.gyt_dir, name, &id)?;
            crate::reflog::record(
                &repo.gyt_dir,
                name,
                prev_for_log.as_ref(),
                &id,
                &identity,
                &reflog_msg,
            );
            crate::reflog::record(
                &repo.gyt_dir,
                "HEAD",
                prev_for_log.as_ref(),
                &id,
                &identity,
                &reflog_msg,
            );
            short_branch(name)
        }
        Head::Detached(_) => {
            refs::write_head(&repo.gyt_dir, &Head::Detached(id))?;
            crate::reflog::record(
                &repo.gyt_dir,
                "HEAD",
                prev_for_log.as_ref(),
                &id,
                &identity,
                &reflog_msg,
            );
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
        .strip_prefix("refs/heads/").map_or_else(|| refname.to_string(), std::string::ToString::to_string)
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

    #[test]
    fn commit_amend_without_message_reuses_previous() {
        let _g = lock();
        let dir = tmp_dir("gyt-commit-amend-msg");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));
        fs::write(dir.join("a.txt"), b"a\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        run(&["-m".to_string(), "first commit".to_string()]).unwrap();
        let repo = Repo::open(&dir).unwrap();
        let id1 = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        let c1 = commit::read(&repo.gyt_dir, &id1).unwrap();
        assert_eq!(c1.message, "first commit");
        assert!(c1.parents.is_empty());
        // Amend without -m: reuses previous message.
        fs::write(dir.join("a.txt"), b"b\n").unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        run(&["--amend".to_string()]).unwrap();
        let id2 = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        assert_ne!(id1, id2, "amend should produce a new commit id");
        let c2 = commit::read(&repo.gyt_dir, &id2).unwrap();
        assert_eq!(c2.message, "first commit", "should reuse previous message");
        assert!(
            c2.parents.is_empty(),
            "root commit parents should stay empty"
        );
        // Tree should reflect the new index content.
        assert_ne!(c2.tree, c1.tree, "tree should reflect new index");
        std::env::set_current_dir(&prev).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn commit_amend_with_new_message() {
        let _g = lock();
        let dir = tmp_dir("gyt-commit-amend-newmsg");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));
        fs::write(dir.join("a.txt"), b"a\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        run(&["-m".to_string(), "old msg".to_string()]).unwrap();
        // Amend with new -m.
        fs::write(dir.join("b.txt"), b"b\n").unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        run(&[
            "--amend".to_string(),
            "-m".to_string(),
            "new msg".to_string(),
        ])
        .unwrap();
        let repo = Repo::open(&dir).unwrap();
        let id = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        let c = commit::read(&repo.gyt_dir, &id).unwrap();
        assert_eq!(c.message, "new msg");
        std::env::set_current_dir(&prev).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn commit_amend_on_unborn_head_errors() {
        let _g = lock();
        let dir = tmp_dir("gyt-commit-amend-unborn");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));
        fs::write(dir.join("a.txt"), b"a\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        // No initial commit yet - amend should fail.
        let r = run(&["--amend".to_string()]);
        assert!(r.is_err(), "amend should fail on unborn HEAD");
        std::env::set_current_dir(&prev).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn commit_allow_empty_creates_commit_with_no_changes() {
        let _g = lock();
        let dir = tmp_dir("gyt-commit-allow-empty-root");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let r = run(&[
            "-m".to_string(),
            "empty root".to_string(),
            "--allow-empty".to_string(),
        ]);
        r.unwrap();
        let repo = Repo::open(&dir).unwrap();
        let id = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        let c = commit::read(&repo.gyt_dir, &id).unwrap();
        assert_eq!(c.message, "empty root");
        assert!(c.parents.is_empty(), "should be root commit");
        std::env::set_current_dir(&prev).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn commit_allow_empty_with_files_works_normally() {
        let _g = lock();
        let dir = tmp_dir("gyt-commit-allow-empty-with-files");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));
        fs::write(dir.join("a.txt"), b"hello\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        let r = run(&[
            "-m".to_string(),
            "normal".to_string(),
            "--allow-empty".to_string(),
        ]);
        r.unwrap();
        let repo = Repo::open(&dir).unwrap();
        let id = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        let c = commit::read(&repo.gyt_dir, &id).unwrap();
        assert_eq!(c.message, "normal");
        // The tree should have entries since we added a file
        let entries = crate::object::tree::read(&repo.gyt_dir, &c.tree).unwrap();
        assert!(!entries.is_empty(), "tree should contain the staged file");
        std::env::set_current_dir(&prev).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn commit_still_fails_without_allow_empty_if_index_empty() {
        let _g = lock();
        let dir = tmp_dir("gyt-commit-no-allow-empty");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let r = run(&["-m".to_string(), "nope".to_string()]);
        assert!(
            r.is_err(),
            "should fail without --allow-empty on empty index"
        );
        std::env::set_current_dir(&prev).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
