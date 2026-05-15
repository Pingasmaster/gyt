use crate::errors::{GytError, Result};
use crate::ignore::IgnoreSet;
use crate::index::{Index, IndexEntry};
use crate::object::blob;
use crate::repo::Repo;
use crate::workdir::{self, WorkdirEntry};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> Result<()> {
    let mut paths: Vec<String> = Vec::new();
    let mut all = false;
    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => {
                println!(
                    "gyt add <path>...\n\nStage files into the index. Use `.` to stage all non-ignored files.\n\
                     Use `-A` / `--all` to stage all files (including removals)."
                );
                return Ok(());
            }
            "-A" | "--all" => all = true,
            other if other.starts_with('-') => {
                return Err(GytError::InvalidArgument(format!(
                    "add: unknown flag {other}"
                )));
            }
            other => paths.push(other.to_string()),
        }
    }

    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    repo.require_worktree()?;
    // Hold the repo lock for the entire index read-modify-write so
    // two parallel `gyt add` runs can't race and silently drop one
    // another's entries. Without this, both adds read the same
    // index, each appends its file, and the second writer's
    // atomic_write rename wipes the first writer's change.
    let _lock = repo.lock()?;
    let workdir = repo.workdir.clone();
    let ignore = IgnoreSet::load_from_root(&workdir)?;
    let mut index = Index::read(&repo.index_path())?;

    let mut staged: Vec<PathBuf> = Vec::new();
    let mut removed: Vec<PathBuf> = Vec::new();

    if all {
        // Stage all workdir files (same as `add .`).
        let entries = workdir::walk(&workdir, &ignore)?;
        for ent in &entries {
            stage_one(&repo, &workdir, ent, &mut index, &mut staged)?;
        }
        // Remove index entries for files that no longer exist in workdir
        // (files that were in the index but have been deleted).
        let to_remove: Vec<PathBuf> = index
            .entries
            .iter()
            .filter(|e| !workdir.join(&e.path).exists())
            .map(|e| e.path.clone())
            .collect();
        for p in &to_remove {
            index.remove(p);
            removed.push(p.clone());
        }
        index.write(&repo.index_path())?;
        for p in &staged {
            println!("added: {}", forward_slash(p));
        }
        for p in &removed {
            println!("removed: {}", forward_slash(p));
        }
        return Ok(());
    }

    if paths.is_empty() {
        return Err(GytError::InvalidArgument(
            "add: at least one path required".into(),
        ));
    }

    for arg in &paths {
        if arg == "." {
            // Walk the entire workdir, excluding ignored.
            let entries = workdir::walk(&workdir, &ignore)?;
            for ent in entries {
                stage_one(&repo, &workdir, &ent, &mut index, &mut staged)?;
            }
            continue;
        }

        // Resolve relative to cwd, then relative to workdir.
        let arg_path = Path::new(arg);
        let abs = if arg_path.is_absolute() {
            arg_path.to_path_buf()
        } else {
            cwd.join(arg_path)
        };
        if !abs.exists() {
            return Err(GytError::NotFound(format!("path {arg}")));
        }
        let abs = abs.canonicalize()?;
        let rel = abs.strip_prefix(&workdir).map_err(|_| {
            GytError::InvalidArgument(format!("path {arg} is outside the repository"))
        })?;

        let md = fs::symlink_metadata(&abs)?;
        if md.is_dir() {
            // Walk this subtree and stage all non-ignored files.
            let entries = workdir::walk(&workdir, &ignore)?;
            let rel_string = forward_slash(rel);
            for ent in entries {
                let p = forward_slash(&ent.path);
                let in_subtree = if rel_string.is_empty() {
                    true
                } else {
                    p == rel_string || p.starts_with(&format!("{rel_string}/"))
                };
                if in_subtree {
                    stage_one(&repo, &workdir, &ent, &mut index, &mut staged)?;
                }
            }
        } else {
            // Single file/symlink. Check if ignored.
            let rel_str = forward_slash(rel);
            if ignore.matched(&rel_str, false) {
                // A pattern matched but .gytignore may not exist yet —
                // give the user an interactive prompt.
                if let Some(decision) = prompt_ignored(&rel_str, &workdir) {
                    match decision {
                        IgnoredDecision::Skip => continue,
                        IgnoredDecision::Add => {
                            // Stage it anyway.
                        }
                        IgnoredDecision::GetDefault => {
                            // Write the default .gytignore, then re-check.
                            if write_default_gytignore(&workdir).is_err() {
                                eprintln!("warning: could not write default .gytignore");
                            }
                            // Reload ignore set so the file now passes.
                            let ignore2 = IgnoreSet::load_from_root(&workdir)?;
                            if ignore2.matched(&rel_str, false) {
                                eprintln!(
                                    "{rel_str} is still ignored after loading defaults, skipping"
                                );
                                continue;
                            }
                        }
                    }
                } else {
                    continue;
                }
            }
            let mode = mode_for(&md);
            let ent = WorkdirEntry {
                path: rel.to_path_buf(),
                is_dir: false,
                mode,
            };
            stage_one(&repo, &workdir, &ent, &mut index, &mut staged)?;
        }
    }

    index.write(&repo.index_path())?;

    for p in &staged {
        println!("added: {}", forward_slash(p));
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

const MODE_REGULAR: u32 = 0o100_644;
const MODE_EXEC: u32 = 0o100_755;
const MODE_SYMLINK: u32 = 0o120_000;

fn mode_for(meta: &fs::Metadata) -> u32 {
    let ft = meta.file_type();
    if ft.is_symlink() {
        return MODE_SYMLINK;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perm = meta.permissions().mode();
        if perm & 0o111 != 0 {
            return MODE_EXEC;
        }
    }
    MODE_REGULAR
}

fn stage_one(
    repo: &Repo,
    workdir: &Path,
    ent: &WorkdirEntry,
    index: &mut Index,
    staged: &mut Vec<PathBuf>,
) -> Result<()> {
    if ent.is_dir {
        return Ok(());
    }
    let abs = workdir.join(&ent.path);
    let md = fs::symlink_metadata(&abs)?;

    let hash = if md.file_type().is_symlink() {
        // Hash the link target as a blob.
        let target = fs::read_link(&abs)?;
        let bytes = target.to_string_lossy().into_owned().into_bytes();
        blob::write(&repo.gyt_dir, &bytes)?
    } else {
        let bytes = fs::read(&abs)?;
        blob::write(&repo.gyt_dir, &bytes)?
    };

    let (mtime_secs, ctime_secs) = times(&md);
    let entry = IndexEntry {
        ctime_secs,
        mtime_secs,
        size: md.len(),
        mode: ent.mode,
        hash,
        path: ent.path.clone(),
    };

    let changed = match index.find(&ent.path) {
        Some(existing) => existing.hash != entry.hash || existing.mode != entry.mode,
        None => true,
    };
    index.insert(entry);
    if changed {
        staged.push(ent.path.clone());
    }
    Ok(())
}

fn times(md: &fs::Metadata) -> (i64, i64) {
    use std::time::UNIX_EPOCH;
    let mtime = md
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs() as i64);
    #[cfg(unix)]
    let ctime = {
        use std::os::unix::fs::MetadataExt;
        md.ctime()
    };
    #[cfg(not(unix))]
    let ctime = mtime;
    (mtime, ctime)
}

/// Decision returned by the interactive ignored-file prompt.
enum IgnoredDecision {
    /// Skip this file (don't stage it).
    Skip,
    /// Force-stage this file despite it matching ignore patterns.
    Add,
    /// Write the default .gytignore template and re-check.
    GetDefault,
}

/// Interactive prompt shown when the user tries to `gyt add` a file
/// matching a pattern in `.gytignore`.
fn prompt_ignored(path: &str, workdir: &Path) -> Option<IgnoredDecision> {
    // If there's no .gytignore yet, the ignore set is empty so we
    // shouldn't be here — unless the ignore set was loaded and found
    // patterns. In that case, offer to create the default template.
    let gytignore_path = workdir.join(".gytignore");
    let no_existing = !gytignore_path.exists();

    let prompt = if no_existing {
        format!(
            "\n{path} matches built-in ignore rules.\n\
             No .gytignore file exists yet.\n\
             1) Add it anyway\n\
             2) Skip it\n\
             3) Create default .gytignore and re-check\n\
             Choice [1/2/3] "
        )
    } else {
        format!(
            "\n{path} matches ignore rules in .gytignore.\n\
             1) Add it anyway\n\
             2) Skip it\n\
             Choice [1/2] "
        )
    };

    io::stdout().write_all(prompt.as_bytes()).ok()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf).ok()?;
    let choice = buf.trim();

    match choice {
        "1" => Some(IgnoredDecision::Add),
        "3" if no_existing => Some(IgnoredDecision::GetDefault),
        _ => Some(IgnoredDecision::Skip),
    }
}

/// Write the embedded default .gytignore template to the workdir root.
fn write_default_gytignore(workdir: &Path) -> Result<()> {
    use crate::fs_util;
    use include_dir::{Dir, include_dir};

    static DEFAULT_GYTIGNORE_DIR: Dir = include_dir!("$CARGO_MANIFEST_DIR/src/cmd");

    let bytes = DEFAULT_GYTIGNORE_DIR
        .get_file("default_gytignore.txt")
        .map(|f| f.contents().to_vec())
        .unwrap_or_default();

    fs_util::atomic_write(&workdir.join(".gytignore"), &bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};

    #[test]
    fn add_dot_stages_all_files() {
        let _g = lock();
        let dir = tmp_dir("gyt-add-dot");
        crate::cmd::init::init_at(&dir).unwrap();
        fs::write(dir.join("a.txt"), b"hello").unwrap();
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/b.txt"), b"world").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let r = run(&[".".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        let repo = Repo::open(&dir).unwrap();
        let idx = Index::read(&repo.index_path()).unwrap();
        let paths: Vec<String> = idx.entries.iter().map(|e| forward_slash(&e.path)).collect();
        assert!(paths.contains(&"a.txt".to_string()));
        assert!(paths.contains(&"sub/b.txt".to_string()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn add_all_stages_and_removes() {
        let _g = lock();
        let dir = tmp_dir("gyt-add-all");
        crate::cmd::init::init_at(&dir).unwrap();
        fs::write(dir.join("a.txt"), b"hello").unwrap();
        fs::write(dir.join("b.txt"), b"world").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        // Stage and commit initial files.
        let r = run(&[".".to_string()]);
        r.unwrap();
        let cfg = crate::config::Config {
            user_name: Some("T".into()),
            user_email: Some("t@x".into()),
            ..crate::config::Config::default()
        };
        cfg.write(&dir.join(".gyt")).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "init".to_string()]).unwrap();
        // Delete b.txt, create c.txt
        fs::remove_file(dir.join("b.txt")).unwrap();
        fs::write(dir.join("c.txt"), b"new").unwrap();
        // Run add -A
        let r = run(&["-A".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        let repo = Repo::open(&dir).unwrap();
        let idx = Index::read(&repo.index_path()).unwrap();
        assert!(
            idx.find(Path::new("a.txt")).is_some(),
            "a.txt should be staged"
        );
        assert!(
            idx.find(Path::new("b.txt")).is_none(),
            "b.txt should be removed from index"
        );
        assert!(
            idx.find(Path::new("c.txt")).is_some(),
            "c.txt should be staged"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn add_all_no_files_is_ok() {
        let _g = lock();
        let dir = tmp_dir("gyt-add-all-empty");
        crate::cmd::init::init_at(&dir).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let r = run(&["-A".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn add_all_flag_long_form() {
        let _g = lock();
        let dir = tmp_dir("gyt-add-all-long");
        crate::cmd::init::init_at(&dir).unwrap();
        fs::write(dir.join("x.txt"), b"data").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let r = run(&["--all".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        let repo = Repo::open(&dir).unwrap();
        let idx = Index::read(&repo.index_path()).unwrap();
        assert!(idx.find(Path::new("x.txt")).is_some());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn add_specific_file() {
        let _g = lock();
        let dir = tmp_dir("gyt-add-specific");
        crate::cmd::init::init_at(&dir).unwrap();
        fs::write(dir.join("only.txt"), b"yo").unwrap();
        fs::write(dir.join("other.txt"), b"nope").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let r = run(&["only.txt".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        let repo = Repo::open(&dir).unwrap();
        let idx = Index::read(&repo.index_path()).unwrap();
        assert_eq!(idx.entries.len(), 1);
        assert_eq!(forward_slash(&idx.entries[0].path), "only.txt");
        fs::remove_dir_all(&dir).unwrap();
    }
}
