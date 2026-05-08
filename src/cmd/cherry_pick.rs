use crate::cmd::util::resolve_rev;
use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::index::{Index, IndexEntry};
use crate::object::{ObjectKind, blob, commit as commit_obj, store};
use crate::refs::{self, Head};
use crate::repo::Repo;
use std::fs;
use std::path::PathBuf;

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    let mut rev: Option<String> = None;

    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("gyt cherry-pick <commit>");
                return Ok(());
            }
            other if !other.starts_with('-') => {
                if rev.is_some() {
                    return Err(GytError::InvalidArgument(
                        "cherry-pick: at most one revision".into(),
                    ));
                }
                rev = Some(other.to_string());
            }
            _ => {
                return Err(GytError::InvalidArgument(format!(
                    "cherry-pick: unknown flag {arg}"
                )));
            }
        }
    }

    let rev =
        rev.ok_or_else(|| GytError::InvalidArgument("cherry-pick: <commit> is required".into()))?;

    let target_id = resolve_rev(repo, &rev)?;
    let target_obj = store::read(&repo.gyt_dir, &target_id)?;
    if target_obj.kind != ObjectKind::Commit {
        return Err(GytError::InvalidArgument(format!(
            "cherry-pick: {rev} is not a commit"
        )));
    }

    let target_commit = commit_obj::read(&repo.gyt_dir, &target_id)?;

    // Check if already applied
    let head = refs::read_head(&repo.gyt_dir)?;
    if let (Head::Symbolic(_name), Some(head_id)) = (&head, refs::resolve(&repo.gyt_dir, &head)?) {
        let head_commit = commit_obj::read(&repo.gyt_dir, &head_id)?;
        if head_commit.tree == target_commit.tree && head_commit.authors == target_commit.authors {
            return Err(GytError::Repo(
                "HEAD is up to date: commit already applied".into(),
            ));
        }
    }

    // Build new commit with target tree, current HEAD as parent
    let parents = match refs::read_head(&repo.gyt_dir)? {
        Head::Symbolic(_) => match refs::resolve(&repo.gyt_dir, &head)? {
            Some(id) => vec![id],
            None => vec![],
        },
        Head::Detached(id) => vec![id],
    };

    let cfg = Config::load(repo)?;
    let identity = cfg.identity()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let stamped = format!("{identity} {now} +0000");
    let authors = vec![stamped.clone()];

    let new_commit = commit_obj::Commit {
        tree: target_commit.tree,
        parents,
        authors,
        committer: stamped,
        ai_assists: Vec::new(),
        reviewers: Vec::new(),
        message: target_commit.message.clone(),
    };

    let new_id = commit_obj::write(&repo.gyt_dir, &new_commit)?;

    // Update HEAD ref
    match refs::read_head(&repo.gyt_dir)? {
        Head::Symbolic(name) => {
            refs::write_ref(&repo.gyt_dir, &name, &new_id)?;
        }
        Head::Detached(_) => {
            refs::write_head(&repo.gyt_dir, &Head::Detached(new_id))?;
        }
    }

    // Update index and working tree to match target
    let files = flatten_tree(repo, &target_commit.tree)?;
    let mut idx = Index::new();
    for (p, (m, h)) in &files {
        idx.insert(IndexEntry {
            ctime_secs: 0,
            mtime_secs: 0,
            size: 0,
            mode: *m,
            hash: *h,
            path: p.clone(),
        });
    }
    idx.write(&repo.index_path())?;

    for (p, (m, h)) in &files {
        let abs = repo.workdir.join(p);
        if let Some(parent) = abs.parent() {
            fs::create_dir_all(parent)?;
        }
        let payload = blob::read(&repo.gyt_dir, h)?;
        fs::write(&abs, &payload)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = if m & 0o111 != 0 {
                std::fs::Permissions::from_mode(0o755)
            } else {
                std::fs::Permissions::from_mode(0o644)
            };
            std::fs::set_permissions(&abs, perms)?;
        }
    }

    // Remove extra files from working tree
    let current_index = Index::read(&repo.index_path())?;
    for entry in &current_index.entries {
        if !files.contains_key(&entry.path) {
            let abs = repo.workdir.join(&entry.path);
            if abs.exists() {
                let _ = fs::remove_file(&abs);
            }
        }
    }

    let hex = new_id.to_hex();
    let short = &hex[..hex.len().min(8)];
    let first_line = new_commit.message.lines().next().unwrap_or("");
    println!("[{short}] {first_line}");

    Ok(())
}

fn flatten_tree(
    repo: &Repo,
    tree_id: &ObjectId,
) -> Result<std::collections::BTreeMap<PathBuf, (u32, ObjectId)>> {
    crate::cmd::util::flatten_tree(repo, tree_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test_support::TestRepo;
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
    fn cherry_pick_applies_commit() {
        let r = TestRepo::new("gyt-cherry-pick");
        write_identity_config(&r.gyt_dir());
        let mut repo = r.open();
        let first_commit_id = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();

        // Create a second commit
        r.commit_next(&[("hello.txt", b"v2\n", false)]);

        // Re-open to see the new state
        repo = Repo::open(&r.root).unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&repo.workdir).unwrap();

        let result = run_in(&repo, &[first_commit_id.to_hex()]);
        std::env::set_current_dir(&prev).unwrap();

        result.unwrap();

        // Verify the commit was created
        let _head_id = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();
        // It should be a new commit

        // Verify the content is from first commit
        let content = fs::read_to_string(repo.workdir.join("hello.txt")).unwrap();
        assert_eq!(content, "hello\n");
    }
}
