use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::index::Index;
use crate::refs::{self, Head};
use crate::repo::GYT_DIR;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> Result<()> {
    let mut path: Option<PathBuf> = None;
    let mut bare = false;
    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            "--bare" => bare = true,
            other if other.starts_with('-') => {
                return Err(GytError::InvalidArgument(format!(
                    "init: unknown flag {other}"
                )));
            }
            other => {
                if path.is_some() {
                    return Err(GytError::InvalidArgument(
                        "init: at most one path argument".into(),
                    ));
                }
                path = Some(PathBuf::from(other));
            }
        }
    }
    let target = path.unwrap_or_else(|| PathBuf::from("."));
    if bare {
        init_bare_at(&target)
    } else {
        init_at(&target)
    }
}

fn print_usage() {
    println!(
        "gyt init [path] [--bare]\n\n\
         Initialize a new gyt repository.\n\
           --bare   Lay out the gyt directory directly in <path> with no\n\
                    working tree. Use this for repos hosted by `gyt serve`."
    );
}

pub fn init_at(target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    let abs = target.canonicalize()?;
    let gyt = abs.join(GYT_DIR);
    if gyt.exists() {
        return Err(GytError::Repo(format!("{} already exists", gyt.display())));
    }
    populate_gyt_layout(&gyt)?;
    println!("initialized empty gyt repository in {}", gyt.display());
    Ok(())
}

/// Initialize a *bare* repository: the layout (objects/, refs/, HEAD, …)
/// goes directly in `target` with no enclosing working tree. Servers use
/// these so they don't accumulate working-tree files they never read.
pub fn init_bare_at(target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    let abs = target.canonicalize()?;
    if abs.join("HEAD").exists() || abs.join("objects").exists() {
        return Err(GytError::Repo(format!(
            "{} already looks like a bare repo",
            abs.display()
        )));
    }
    if abs.join(GYT_DIR).exists() {
        return Err(GytError::Repo(format!(
            "{} has a non-bare .gyt directory; refuse to overwrite",
            abs.display()
        )));
    }
    populate_gyt_layout(&abs)?;
    // Marker file so tools can tell at a glance.
    fs::write(abs.join("bare"), b"true\n")?;
    println!("initialized bare gyt repository in {}", abs.display());
    Ok(())
}

fn populate_gyt_layout(gyt: &Path) -> Result<()> {
    fs::create_dir_all(gyt.join("objects"))?;
    fs::create_dir_all(gyt.join("refs/heads"))?;
    fs::create_dir_all(gyt.join("refs/tags"))?;
    fs::create_dir_all(gyt.join("refs/remotes"))?;
    fs::create_dir_all(gyt.join("worktrees"))?;
    refs::write_head(gyt, &Head::Symbolic("refs/heads/main".to_string()))?;
    let idx = Index::new();
    idx.write(&gyt.join("index"))?;
    let mut cfg = Config::default();
    if let Ok(v) = std::env::var("GYT_AUTHOR_NAME") {
        cfg.user_name = Some(v);
    }
    if let Ok(v) = std::env::var("GYT_AUTHOR_EMAIL") {
        cfg.user_email = Some(v);
    }
    cfg.write(gyt)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};

    #[test]
    fn init_creates_layout() {
        let _g = lock();
        let dir = tmp_dir("gyt-init");
        let arg = dir.to_string_lossy().into_owned();
        run(&[arg]).unwrap();
        assert!(dir.join(".gyt").is_dir());
        assert!(dir.join(".gyt/objects").is_dir());
        assert!(dir.join(".gyt/refs/heads").is_dir());
        assert!(dir.join(".gyt/refs/tags").is_dir());
        assert!(dir.join(".gyt/refs/remotes").is_dir());
        assert!(dir.join(".gyt/worktrees").is_dir());
        assert!(dir.join(".gyt/HEAD").is_file());
        assert!(dir.join(".gyt/index").is_file());
        let head = std::fs::read_to_string(dir.join(".gyt/HEAD")).unwrap();
        assert_eq!(head, "ref: refs/heads/main\n");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn init_refuses_existing_repo() {
        let _g = lock();
        let dir = tmp_dir("gyt-init-exists");
        let arg = dir.to_string_lossy().into_owned();
        run(std::slice::from_ref(&arg)).unwrap();
        let err = run(std::slice::from_ref(&arg)).unwrap_err();
        match err {
            GytError::Repo(_) => {}
            other => panic!("expected Repo error, got {other:?}"),
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
