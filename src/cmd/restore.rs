use crate::errors::{GytError, Result};
use crate::index::{Index, IndexEntry};
use crate::object::blob;
use crate::repo::Repo;
use std::path::PathBuf;

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return Err(GytError::InvalidArgument(
            "restore: at least one path required (or '.')".into(),
        ));
    }
    let idx = Index::read(&repo.index_path())?;

    let targets: Vec<PathBuf> = if args.len() == 1 && args[0] == "." {
        idx.entries.iter().map(|e| e.path.clone()).collect()
    } else {
        args.iter().map(PathBuf::from).collect()
    };

    for path in &targets {
        match idx.find(path) {
            Some(entry) => restore_one(repo, entry)?,
            None => {
                eprintln!(
                    "gyt restore: {}: not in the index, skipping",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

fn restore_one(repo: &Repo, entry: &IndexEntry) -> Result<()> {
    use crate::object::tree;
    let abs = repo.workdir.join(&entry.path);
    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = blob::read(&repo.gyt_dir, &entry.hash)?;
    if entry.mode == tree::MODE_SYMLINK {
        let target = std::str::from_utf8(&bytes)
            .map_err(|_| GytError::Object("symlink target is not utf-8".into()))?;
        let _ = std::fs::remove_file(&abs);
        #[cfg(unix)]
        std::os::unix::fs::symlink(target, &abs)?;
        #[cfg(not(unix))]
        {
            let _ = target;
            return Err(GytError::Unsupported(
                "symlinks not supported on this platform".into(),
            ));
        }
    } else {
        if let Ok(md) = std::fs::symlink_metadata(&abs)
            && md.file_type().is_symlink()
        {
            std::fs::remove_file(&abs)?;
        }
        std::fs::write(&abs, &bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let want = if entry.mode == tree::MODE_EXEC {
                0o755
            } else {
                0o644
            };
            let mut perms = std::fs::metadata(&abs)?.permissions();
            perms.set_mode(want);
            std::fs::set_permissions(&abs, perms)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test_support::TestRepo;

    #[test]
    fn restore_recreates_from_index() {
        let r = TestRepo::new("gyt-restore-rt");
        let repo = r.open();
        let p = repo.workdir.join("hello.txt");
        // Local edit.
        std::fs::write(&p, b"corrupted\n").unwrap();
        run_in(&repo, &["hello.txt".into()]).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"hello\n");
    }

    #[test]
    fn restore_dot_restores_all_tracked() {
        let r = TestRepo::new("gyt-restore-dot");
        let repo = r.open();
        std::fs::write(repo.workdir.join("hello.txt"), b"junk\n").unwrap();
        run_in(&repo, &[".".into()]).unwrap();
        assert_eq!(
            std::fs::read(repo.workdir.join("hello.txt")).unwrap(),
            b"hello\n"
        );
    }

    #[test]
    fn restore_skips_unknown_paths() {
        let r = TestRepo::new("gyt-restore-skip");
        let repo = r.open();
        // No error, just a warning.
        run_in(&repo, &["nope.txt".into()]).unwrap();
    }
}
