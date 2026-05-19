use crate::errors::{GytError, Result};
use crate::ignore::IgnoreSet;
use crate::index::Index;
use crate::repo::Repo;
use crate::workdir;
use std::fs;
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> Result<()> {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

fn print_help() {
    println!(
        "gyt clean [-n|--dry-run]\n\n\
         Remove untracked files from the working tree."
    );
}

fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    // M5: take the repo lock so a concurrent `gyt add` between our
    // walk and the unlink can't have its newly-staged file removed
    // from the workdir.
    let _lock = repo.lock()?;
    let mut dry_run = false;
    let mut force = false;

    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => {
                println!(
                    "gyt clean [-n|--dry-run] [-f|--force]\n\n\
                     Remove untracked files from the working tree.\n\
                     Pass -n/--dry-run to preview, or -f/--force to actually delete."
                );
                return Ok(());
            }
            "-n" | "--dry-run" => dry_run = true,
            "-f" | "--force" => force = true,
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "clean: unknown flag {other}"
                )));
            }
        }
    }
    // B31: refuse to delete unless the operator explicitly opted in
    // via --force OR asked for a dry-run preview. Matches git's
    // default — `git clean` errors without `-f`. Without this gate,
    // a bare `gyt clean` silently destroys hours of un-staged work.
    if !dry_run && !force {
        return Err(GytError::InvalidArgument(
            "clean: refusing to delete without -f/--force (or -n/--dry-run to preview)"
                .into(),
        ));
    }

    let ignore = IgnoreSet::load_from_root(&repo.workdir)?;
    let walk = workdir::walk(&repo.workdir, &ignore)?;
    let index = Index::read(&repo.index_path())?;

    // Build a set of tracked index paths for fast lookup.
    let tracked: std::collections::BTreeSet<&PathBuf> =
        index.entries.iter().map(|e| &e.path).collect();

    // Collect untracked files (files that exist in workdir but not in index).
    let mut untracked: Vec<PathBuf> = Vec::new();
    for ent in &walk {
        if ent.is_dir {
            continue;
        }
        if !tracked.contains(&ent.path) {
            untracked.push(ent.path.clone());
        }
    }

    // Sort for deterministic output.
    untracked.sort();

    if dry_run {
        for p in &untracked {
            println!("would remove {}", forward_slash(p));
        }
    } else {
        for p in &untracked {
            let abs = repo.workdir.join(p);
            // Safety: only remove files, not directories.
            if abs.is_file() || abs.is_symlink() {
                fs::remove_file(&abs)?;
                println!("rm {}", forward_slash(p));
            }
        }
    }

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
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
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
    fn clean_removes_untracked_files() {
        let _g = lock();
        let dir = tmp_dir("gyt-clean-untracked");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));

        // Create a tracked file.
        fs::write(dir.join("tracked.txt"), b"tracked\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "first".to_string()]).unwrap();

        // Create an untracked file.
        fs::write(dir.join("untracked.txt"), b"untracked\n").unwrap();
        assert!(dir.join("untracked.txt").exists());

        let r = run(&[]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();

        // Untracked file should be removed.
        assert!(!dir.join("untracked.txt").exists());
        // Tracked file should still exist.
        assert!(dir.join("tracked.txt").exists());
    }

    #[test]
    fn clean_does_not_touch_tracked_or_modified() {
        let _g = lock();
        let dir = tmp_dir("gyt-clean-tracked");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));

        fs::write(dir.join("a.txt"), b"a\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "first".to_string()]).unwrap();

        // Modify the tracked file.
        fs::write(dir.join("a.txt"), b"modified\n").unwrap();

        // Create an untracked file.
        fs::write(dir.join("untracked.txt"), b"untracked\n").unwrap();

        let r = run(&[]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();

        // Tracked (modified) file should still exist.
        assert!(dir.join("a.txt").exists());
        assert_eq!(fs::read_to_string(dir.join("a.txt")).unwrap(), "modified\n");
        // Untracked file should be removed.
        assert!(!dir.join("untracked.txt").exists());
    }

    #[test]
    fn clean_dry_run_prints_but_does_not_remove() {
        let _g = lock();
        let dir = tmp_dir("gyt-clean-dry");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        // Create an untracked file.
        fs::write(dir.join("untracked.txt"), b"untracked\n").unwrap();

        let r = run(&["-n".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();

        // File should still exist (dry run).
        assert!(dir.join("untracked.txt").exists());
    }

    #[test]
    fn clean_no_untracked_files_is_noop() {
        let _g = lock();
        let dir = tmp_dir("gyt-clean-noop");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));

        fs::write(dir.join("tracked.txt"), b"tracked\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "first".to_string()]).unwrap();

        let r = run(&[]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();

        // Tracked file should still exist.
        assert!(dir.join("tracked.txt").exists());
    }

    #[test]
    fn clean_respects_dot_gytignore() {
        let _g = lock();
        let dir = tmp_dir("gyt-clean-ignore");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));

        // Create a .gytignore that ignores *.log files.
        fs::write(dir.join(".gytignore"), b"*.log\n").unwrap();
        // Create an ignored file.
        fs::write(dir.join("ignored.log"), b"ignored\n").unwrap();
        // Create a non-ignored untracked file.
        fs::write(dir.join("cleanme.txt"), b"cleanme\n").unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let r = run(&[]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();

        // The ignored file should NOT have been removed (walk never saw it via ignore).
        assert!(dir.join("ignored.log").exists());
        // The non-ignored untracked file should be removed.
        assert!(!dir.join("cleanme.txt").exists());
    }

    #[test]
    fn clean_skips_dot_gyt_directory() {
        let _g = lock();
        let dir = tmp_dir("gyt-clean-dotgyt");
        crate::cmd::init::init_at(&dir).unwrap();
        write_identity_config(&dir.join(".gyt"));

        // Create a file directly inside .gyt (walk skips this dir).
        fs::write(
            dir.join(".gyt").join("custom_file"),
            b"should not be touched\n",
        )
        .unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();

        let r = run(&[]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();

        // .gyt internal files must not be removed.
        assert!(dir.join(".gyt").join("custom_file").exists());
    }
}
