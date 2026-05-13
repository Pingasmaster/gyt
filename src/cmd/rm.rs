use crate::errors::{GytError, Result};
use crate::index::Index;
use crate::repo::Repo;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let mut force = false;
    let mut paths: Vec<String> = Vec::new();

    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => {
                println!(
                    "gyt rm [-f|--force] <path>...\n\n\
                     Remove files from the index and working tree. Use `.` to remove all staged files."
                );
                return Ok(());
            }
            "-f" | "--force" => force = true,
            other if other.starts_with('-') => {
                return Err(GytError::InvalidArgument(format!(
                    "rm: unknown flag {other}"
                )));
            }
            other => paths.push(other.to_string()),
        }
    }

    if paths.is_empty() {
        return Err(GytError::InvalidArgument(
            "rm: at least one path required".into(),
        ));
    }

    let mut index = Index::read(&repo.index_path())?;
    let mut removed: Vec<PathBuf> = Vec::new();

    for arg in &paths {
        if arg == "." {
            // Remove all staged files.
            let to_remove: Vec<PathBuf> = index.entries.iter().map(|e| e.path.clone()).collect();
            for p in &to_remove {
                let abs = repo.workdir.join(p);
                if abs.exists() {
                    fs::remove_file(&abs)?;
                }
                index.remove(p);
                removed.push(p.clone());
            }
            continue;
        }

        // Resolve relative to cwd, then relative to workdir.
        let abs = if Path::new(arg).is_absolute() {
            PathBuf::from(arg)
        } else {
            cwd.join(arg)
        };

        let rel = abs.strip_prefix(&repo.workdir).map_err(|_| {
            GytError::InvalidArgument(format!("path {arg} is outside the repository"))
        })?;

        // Check if file is in the index (staged) before checking existence.
        // A staged file that's missing from the worktree should error with "staged",
        // not "not found".
        if index.find(rel).is_some() {
            if !abs.exists() {
                // Staged but missing from worktree.
                if !force {
                    return Err(GytError::InvalidArgument(format!(
                        "gyt rm: '{arg}' is staged; use -f to force remove"
                    )));
                }
                // Force: remove from index only.
                index.remove(rel);
                removed.push(rel.to_path_buf());
                continue;
            }
            // File exists in worktree and is in index - just remove it.
            let abs = abs.canonicalize()?;
            if abs.is_dir() {
                return Err(GytError::InvalidArgument(format!(
                    "gyt rm: '{arg}' is a directory (use `gyt add` to unstage, then remove contents manually)"
                )));
            }
            fs::remove_file(&abs)?;
            index.remove(rel);
            removed.push(rel.to_path_buf());
            continue;
        }

        if !abs.exists() {
            if !force {
                return Err(GytError::NotFound(format!(
                    "path {arg}: not found (use -f to remove from index anyway)"
                )));
            }
            // Not in index, not in worktree, but force: just remove from index if present.
            if index.remove(rel) {
                removed.push(rel.to_path_buf());
            }
            continue;
        }

        let abs = abs.canonicalize()?;
        // Not staged, file exists: remove from worktree.
        if abs.is_dir() {
            return Err(GytError::InvalidArgument(format!(
                "gyt rm: '{arg}' is a directory (use `gyt add` to unstage, then remove contents manually)"
            )));
        }

        fs::remove_file(&abs)?;
        index.remove(rel);
        removed.push(rel.to_path_buf());
    }

    index.write(&repo.index_path())?;

    for p in &removed {
        println!("rm {}", forward_slash(p));
    }

    // NB: a previous version of this code deleted `refs/heads/<current>`
    // when the index emptied out, on the reasoning that the branch was
    // "unborn again". That's wrong — there can be committed objects on
    // the branch already, and silently nuking the ref left users with
    // a phantom-deleted branch they had to recover via reflog. We now
    // never touch refs from rm. Use `gyt branch -d <name>` to delete a
    // branch.

    Ok(())
}

fn forward_slash(p: &Path) -> String {
    let mut s = String::new();
    let mut first = true;
    for comp in p.components() {
        let part = comp.as_os_str().to_string_lossy();
        if !first {
            s.push('/');
        }
        first = false;
        s.push_str(part.as_ref());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};
    use std::fs;

    fn write_identity_config(gyt_dir: &Path) {
        use crate::config::Config;
        let cfg = Config {
            user_name: Some("Test".into()),
            user_email: Some("t@x".into()),
            ..Config::default()
        };
        cfg.write(gyt_dir).unwrap();
    }

    #[test]
    fn rm_single_file() {
        let _g = lock();
        let dir = tmp_dir("gyt-rm-single");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));
        fs::write(dir.join("a.txt"), b"hello\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "first".to_string()]).unwrap();

        fs::write(dir.join("a.txt"), b"modified\n").unwrap();
        let r = run(&["a.txt".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();

        assert!(!dir.join("a.txt").exists());
        let repo = Repo::open(&dir).unwrap();
        let idx = Index::read(&repo.index_path()).unwrap();
        assert!(idx.entries.is_empty());
    }

    #[test]
    fn rm_staged_without_force_refuses() {
        let _g = lock();
        let dir = tmp_dir("gyt-rm-staged");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));
        fs::write(dir.join("a.txt"), b"hello\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        crate::cmd::add::run(&[".".to_string()]).unwrap();
        // File is staged. Now delete it from worktree so it's "staged but missing".
        fs::remove_file(dir.join("a.txt")).unwrap();
        let r = run(&["a.txt".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("staged"));
    }

    #[test]
    fn rm_force_staged() {
        let _g = lock();
        let dir = tmp_dir("gyt-rm-force");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));
        fs::write(dir.join("a.txt"), b"hello\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        crate::cmd::add::run(&[".".to_string()]).unwrap();
        let r = run(&["-f".to_string(), "a.txt".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();

        assert!(!dir.join("a.txt").exists());
        let repo = Repo::open(&dir).unwrap();
        let idx = Index::read(&repo.index_path()).unwrap();
        assert!(idx.entries.is_empty());
    }

    #[test]
    fn rm_no_args() {
        let _g = lock();
        let dir = tmp_dir("gyt-rm-no-args");
        crate::cmd::init::init_at(&dir).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let r = run(&[]);
        std::env::set_current_dir(&prev).unwrap();
        assert!(r.is_err());
        assert!(r.unwrap_err().to_string().contains("path required"));
    }
}
