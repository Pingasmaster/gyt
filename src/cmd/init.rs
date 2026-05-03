use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::index::Index;
use crate::refs::{self, Head};
use crate::repo::GYT_DIR;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> Result<()> {
    let mut path: Option<PathBuf> = None;
    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
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
    init_at(&target)
}

fn print_usage() {
    println!("gyt init [path]\n\nInitialize a new gyt repository.");
}

pub fn init_at(target: &Path) -> Result<()> {
    fs::create_dir_all(target)?;
    let abs = target.canonicalize()?;
    let gyt = abs.join(GYT_DIR);
    if gyt.exists() {
        return Err(GytError::Repo(format!("{} already exists", gyt.display())));
    }
    fs::create_dir_all(gyt.join("objects"))?;
    fs::create_dir_all(gyt.join("refs/heads"))?;
    fs::create_dir_all(gyt.join("refs/tags"))?;
    fs::create_dir_all(gyt.join("refs/remotes"))?;
    fs::create_dir_all(gyt.join("worktrees"))?;

    refs::write_head(&gyt, &Head::Symbolic("refs/heads/main".to_string()))?;

    let idx = Index::new();
    idx.write(&gyt.join("index"))?;

    // Starter config: pick up any env-var identity, otherwise empty file.
    let mut cfg = Config::default();
    if let Ok(v) = std::env::var("GYT_AUTHOR_NAME") {
        cfg.user_name = Some(v);
    }
    if let Ok(v) = std::env::var("GYT_AUTHOR_EMAIL") {
        cfg.user_email = Some(v);
    }
    cfg.write(&gyt)?;

    println!("initialized empty gyt repository in {}", gyt.display());
    Ok(())
}

#[cfg(test)]
mod tests {
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
