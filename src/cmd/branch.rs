use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::object::{ObjectKind, commit as commit_obj, store};
use crate::refs::{self, Head};
use crate::repo::Repo;
use crate::term;
use std::collections::HashSet;
use std::path::Path;

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return list(repo);
    }
    // From here every subcommand (-d / -D / -m / create) mutates refs.
    let _lock = repo.lock()?;
    match args[0].as_str() {
        "-d" | "--delete" => {
            if args.len() != 2 {
                return Err(GytError::InvalidArgument(
                    "branch -d <name>: expected one branch name".into(),
                ));
            }
            delete(repo, &args[1], false)
        }
        "-D" | "--force" => {
            if args.len() != 2 {
                return Err(GytError::InvalidArgument(
                    "branch -D <name>: expected one branch name".into(),
                ));
            }
            delete(repo, &args[1], true)
        }
        "-m" | "--rename" => {
            if args.len() != 3 {
                return Err(GytError::InvalidArgument(
                    "branch -m <old> <new>: expected two names".into(),
                ));
            }
            rename(repo, &args[1], &args[2])
        }
        name if !name.starts_with('-') => {
            if args.len() != 1 {
                return Err(GytError::InvalidArgument(
                    "branch <name>: extra arguments".into(),
                ));
            }
            create(repo, name)
        }
        other => Err(GytError::InvalidArgument(format!(
            "branch: unknown option {other}"
        ))),
    }
}

/// Validate a branch name: only [A-Za-z0-9_./-], not "HEAD" or "..".
pub fn validate_branch_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(GytError::InvalidArgument(
            "branch name must not be empty".into(),
        ));
    }
    if name == "HEAD" || name == ".." {
        return Err(GytError::InvalidArgument(format!(
            "branch name {name:?} is reserved"
        )));
    }
    if name.contains("..") {
        return Err(GytError::InvalidArgument(format!(
            "branch name must not contain '..': {name:?}"
        )));
    }
    for ch in name.chars() {
        let ok = ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '/' | '-');
        if !ok {
            return Err(GytError::InvalidArgument(format!(
                "branch name has illegal character {ch:?}: {name:?}"
            )));
        }
    }
    Ok(())
}

pub fn current_branch(gyt_dir: &Path) -> Result<Option<String>> {
    let head = refs::read_head(gyt_dir)?;
    match head {
        Head::Symbolic(name) => Ok(name.strip_prefix("refs/heads/").map(String::from)),
        Head::Detached(_) => Ok(None),
    }
}

fn list(repo: &Repo) -> Result<()> {
    let current = current_branch(&repo.gyt_dir)?;
    let heads = refs::list_refs(&repo.gyt_dir, "refs/heads")?;
    let use_color = term::use_color();
    for (full, _id) in &heads {
        let short = full
            .strip_prefix("refs/heads/")
            .unwrap_or(full.as_str())
            .to_string();
        // F-D10-01: refnames from disk can contain bytes that bypass
        // the wire-side validator if the server's refs/* directory
        // was edited out-of-band; sanitize before terminal output.
        let short_safe = term::s(&short);
        let is_current = current.as_deref() == Some(short.as_str());
        if is_current {
            let line = format!("* {short_safe}");
            println!("{}", term::paint_when(use_color, term::GREEN, &line));
        } else {
            println!("  {short_safe}");
        }
    }
    Ok(())
}

fn create(repo: &Repo, name: &str) -> Result<()> {
    validate_branch_name(name)?;
    let head = refs::read_head(&repo.gyt_dir)?;
    let id = refs::resolve(&repo.gyt_dir, &head)?
        .ok_or_else(|| GytError::Refs("HEAD is unborn; cannot create branch".into()))?;
    let ref_name = format!("refs/heads/{name}");
    if refs::read_ref(&repo.gyt_dir, &ref_name).is_ok() {
        return Err(GytError::Refs(format!("branch {name} already exists")));
    }
    refs::write_ref(&repo.gyt_dir, &ref_name, &id)?;
    Ok(())
}

fn delete(repo: &Repo, name: &str, force: bool) -> Result<()> {
    // M10: a clone can land a refname that `validate_ref_name` accepts
    // but `validate_branch_name` rejects (e.g. unicode like `épée`).
    // For delete, accept anything `validate_ref_name` accepts so the
    // user can clean up whatever they actually have on disk.
    if let Err(stricter_err) = validate_branch_name(name) {
        let ref_name = format!("refs/heads/{name}");
        if crate::refs::validate_ref_name(&ref_name).is_err() {
            return Err(stricter_err);
        }
        // Permissive path: only allow delete (not create), and only
        // when the ref actually exists, so we don't widen the
        // create surface.
        if refs::read_ref(&repo.gyt_dir, &ref_name).is_err() {
            return Err(stricter_err);
        }
        return refs::delete_ref(&repo.gyt_dir, &ref_name);
    }
    if let Some(cur) = current_branch(&repo.gyt_dir)?
        && cur == name
    {
        return Err(GytError::Refs(format!(
            "cannot delete the current branch: {name}"
        )));
    }
    if !force {
        // Check merge safety: refuse to delete if the branch is not fully merged
        // into HEAD or another ref.
        let ref_name = format!("refs/heads/{name}");
        let branch_id = refs::read_ref(&repo.gyt_dir, &ref_name)?;
        let head = refs::read_head(&repo.gyt_dir)?;
        if let Some(head_id) = refs::resolve(&repo.gyt_dir, &head)?
            && !is_ancestor(&repo.gyt_dir, &branch_id, &head_id)?
        {
            return Err(GytError::Refs(format!(
                "branch {name} is not fully merged; refusing to delete \
                 (use -D to force-delete)"
            )));
        }
    }
    let ref_name = format!("refs/heads/{name}");
    refs::delete_ref(&repo.gyt_dir, &ref_name)
}

fn rename(repo: &Repo, old: &str, new: &str) -> Result<()> {
    validate_branch_name(old)?;
    validate_branch_name(new)?;
    if old == new {
        return Ok(());
    }
    // M9: the caller (`run_in`) already holds the repo lock. We just
    // need to journal the three writes (new ref, old delete, HEAD
    // update) in a safe order so a mid-rename crash leaves a
    // recoverable state. New order below.
    let old_ref = format!("refs/heads/{old}");
    let new_ref = format!("refs/heads/{new}");
    if refs::read_ref(&repo.gyt_dir, &new_ref).is_ok() {
        return Err(GytError::Refs(format!("branch {new} already exists")));
    }
    let id = refs::read_ref(&repo.gyt_dir, &old_ref)?;
    // Ordering: HEAD-update first if it's the current branch, then
    // new-ref-write, then old-ref-delete. If we crash between
    // write_new and delete_old, both refs exist (recoverable). If
    // we crash before HEAD-update, HEAD still references the old
    // ref, which still exists (recoverable).
    let head_points_at_old = match refs::read_head(&repo.gyt_dir)? {
        Head::Symbolic(name) => name == old_ref,
        Head::Detached(_) => false,
    };
    refs::write_ref(&repo.gyt_dir, &new_ref, &id)?;
    if head_points_at_old {
        refs::write_head(&repo.gyt_dir, &Head::Symbolic(new_ref))?;
    }
    refs::delete_ref(&repo.gyt_dir, &old_ref)?;
    Ok(())
}

/// Walk the full parent DAG from `descendant` backwards, checking whether
/// `ancestor` is reachable.  Returns `true` if they are the same commit.
fn is_ancestor(gyt_dir: &Path, ancestor: &ObjectId, descendant: &ObjectId) -> Result<bool> {
    let mut seen = HashSet::new();
    let mut stack = vec![*descendant];

    while let Some(id) = stack.pop() {
        if id == *ancestor {
            return Ok(true);
        }
        if !seen.insert(id) {
            continue;
        }
        let obj = store::read(gyt_dir, &id)?;
        if obj.kind == ObjectKind::Commit {
            let commit = commit_obj::read(gyt_dir, &id)?;
            for parent in &commit.parents {
                stack.push(*parent);
            }
        }
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::cmd::test_support::TestRepo;

    #[test]
    fn branch_list_marks_current() {
        let r = TestRepo::new("gyt-branch-list");
        let repo = r.open();
        run_in(&repo, &["feature".into()]).unwrap();
        // exercise list path; output goes to stdout, just ensure no error.
        run_in(&repo, &[]).unwrap();
    }

    #[test]
    fn branch_create_and_delete() {
        let r = TestRepo::new("gyt-branch-cd");
        let repo = r.open();
        run_in(&repo, &["feature".into()]).unwrap();
        let id = refs::read_ref(&repo.gyt_dir, "refs/heads/feature").unwrap();
        let head_id = refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir).unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(id, head_id);

        // duplicate creation rejected
        assert!(run_in(&repo, &["feature".into()]).is_err());

        run_in(&repo, &["-d".into(), "feature".into()]).unwrap();
        assert!(refs::read_ref(&repo.gyt_dir, "refs/heads/feature").is_err());

        // cannot delete current branch
        assert!(run_in(&repo, &["-d".into(), "main".into()]).is_err());
    }

    #[test]
    fn branch_delete_rejects_unmerged() {
        let r = TestRepo::new("gyt-branch-unmerged");
        let repo = r.open();

        // Create a branch from main
        run_in(&repo, &["unmerged".into()]).unwrap();

        // Switch to the new branch and advance it with a new commit
        refs::write_head(&repo.gyt_dir, &Head::Symbolic("refs/heads/unmerged".into())).unwrap();
        r.commit_next(&[("new.txt", b"content\n", false)]);

        // Switch back to main
        refs::write_head(&repo.gyt_dir, &Head::Symbolic("refs/heads/main".into())).unwrap();
        let repo = Repo::open(&r.root).unwrap();

        // Deleting unmerged branch with -d should be rejected
        let err = run_in(&repo, &["-d".into(), "unmerged".into()]);
        assert!(err.is_err(), "expected error deleting unmerged branch");
        assert!(
            err.unwrap_err().to_string().contains("not fully merged"),
            "error should mention merge safety"
        );

        // Force delete with -D should work
        run_in(&repo, &["-D".into(), "unmerged".into()]).unwrap();
        assert!(refs::read_ref(&repo.gyt_dir, "refs/heads/unmerged").is_err());
    }

    #[test]
    fn branch_rename_updates_head_when_pointing_at_old() {
        let r = TestRepo::new("gyt-branch-rename");
        let repo = r.open();
        run_in(&repo, &["-m".into(), "main".into(), "trunk".into()]).unwrap();
        assert!(refs::read_ref(&repo.gyt_dir, "refs/heads/main").is_err());
        let _ = refs::read_ref(&repo.gyt_dir, "refs/heads/trunk").unwrap();
        match refs::read_head(&repo.gyt_dir).unwrap() {
            Head::Symbolic(s) => assert_eq!(s, "refs/heads/trunk"),
            other @ Head::Detached(_) => panic!("expected symbolic, got {other:?}"),
        }
    }

    #[test]
    fn branch_invalid_name_rejected() {
        let r = TestRepo::new("gyt-branch-invalid");
        let repo = r.open();
        assert!(run_in(&repo, &["bad name".into()]).is_err());
        assert!(run_in(&repo, &["HEAD".into()]).is_err());
        assert!(run_in(&repo, &["foo..bar".into()]).is_err());
    }
}
