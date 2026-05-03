use crate::cmd::util;
use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::ignore::IgnoreSet;
use crate::index::Index;
use crate::refs;
use crate::repo::Repo;
use crate::term;
use crate::workdir;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> Result<()> {
    if let Some(a) = args.first() {
        match a.as_str() {
            "--help" | "-h" => {
                println!("gyt status\n\nShow staged, modified, and untracked changes.");
                return Ok(());
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "status: unexpected argument {other}"
                )));
            }
        }
    }

    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    let workdir_path = repo.workdir.clone();
    let ignore = IgnoreSet::load_from_root(&workdir_path)?;
    let walk = workdir::walk(&workdir_path, &ignore)?;
    let index = Index::read(&repo.index_path())?;

    // Build HEAD path -> hash map.
    let head_map: BTreeMap<PathBuf, (u32, ObjectId)> = match refs::read_head(&repo.gyt_dir) {
        Ok(head) => match refs::resolve(&repo.gyt_dir, &head)? {
            Some(commit_id) => {
                let obj = crate::object::store::read(&repo.objects_dir(), &commit_id)?;
                if obj.kind == crate::object::ObjectKind::Commit {
                    let c = crate::object::commit::decode(&obj.payload)?;
                    util::flatten_tree(&repo, &c.tree)?
                } else {
                    BTreeMap::new()
                }
            }
            None => BTreeMap::new(),
        },
        Err(_) => BTreeMap::new(),
    };

    // Build index lookup.
    let mut index_map: BTreeMap<PathBuf, (u32, ObjectId)> = BTreeMap::new();
    for e in &index.entries {
        index_map.insert(e.path.clone(), (e.mode, e.hash));
    }

    let mut staged: Vec<(PathBuf, &'static str)> = Vec::new();
    let mut modified: Vec<PathBuf> = Vec::new();
    let mut untracked: Vec<PathBuf> = Vec::new();

    let mut seen_in_workdir: BTreeSet<PathBuf> = BTreeSet::new();

    for ent in &walk {
        if ent.is_dir {
            continue;
        }
        seen_in_workdir.insert(ent.path.clone());
        let abs = workdir_path.join(&ent.path);
        let wd_hash = workdir::hash_blob(&abs)?;

        let in_index = index_map.get(&ent.path).copied();
        let in_head = head_map.get(&ent.path).copied();

        match (in_index, in_head) {
            (None, _) => {
                untracked.push(ent.path.clone());
            }
            (Some((_, idx_hash)), head_entry) => {
                let head_hash = head_entry.map(|(_, h)| h);
                let idx_vs_head = head_hash != Some(idx_hash);
                let wd_vs_idx = wd_hash != idx_hash;
                if idx_vs_head {
                    let label = if head_hash.is_none() {
                        "new file"
                    } else {
                        "modified"
                    };
                    staged.push((ent.path.clone(), label));
                }
                if wd_vs_idx {
                    modified.push(ent.path.clone());
                }
            }
        }
    }

    // Files in index or HEAD but missing from workdir.
    let mut all_tracked: BTreeSet<PathBuf> = BTreeSet::new();
    for k in index_map.keys() {
        all_tracked.insert(k.clone());
    }
    for k in head_map.keys() {
        all_tracked.insert(k.clone());
    }
    for p in all_tracked {
        if seen_in_workdir.contains(&p) {
            continue;
        }
        let in_index = index_map.contains_key(&p);
        let in_head = head_map.contains_key(&p);
        if in_index && in_head {
            modified.push(p);
        } else if !in_index && in_head {
            staged.push((p, "deleted"));
        } else if in_index && !in_head {
            staged.push((p.clone(), "new file"));
            modified.push(p);
        }
    }

    let use_color = term::use_color();
    print_status(&staged, &modified, &untracked, use_color);
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

fn print_status(
    staged: &[(PathBuf, &'static str)],
    modified: &[PathBuf],
    untracked: &[PathBuf],
    use_color: bool,
) {
    if !staged.is_empty() {
        println!("Staged for commit:");
        let mut sorted: Vec<&(PathBuf, &'static str)> = staged.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for (p, label) in sorted {
            let line = format!("  {label}: {}", forward_slash(p));
            println!("{}", term::paint_when(use_color, term::GREEN, &line));
        }
        println!();
    }
    if !modified.is_empty() {
        println!("Modified, not staged:");
        let mut sorted: Vec<&PathBuf> = modified.iter().collect();
        sorted.sort();
        sorted.dedup();
        for p in sorted {
            let line = format!("  modified: {}", forward_slash(p));
            println!("{}", term::paint_when(use_color, term::YELLOW, &line));
        }
        println!();
    }
    if !untracked.is_empty() {
        println!("Untracked:");
        let mut sorted: Vec<&PathBuf> = untracked.iter().collect();
        sorted.sort();
        for p in sorted {
            let line = format!("  {}", forward_slash(p));
            println!("{}", term::paint_when(use_color, term::RED, &line));
        }
        println!();
    }
    if staged.is_empty() && modified.is_empty() && untracked.is_empty() {
        println!("clean");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};
    use std::fs;

    #[test]
    fn status_runs_clean_after_init() {
        let _g = lock();
        let dir = tmp_dir("gyt-status-clean");
        crate::cmd::init::init_at(&dir).unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let r = run(&[]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn status_classifies_untracked_modified_staged() {
        let _g = lock();
        let dir = tmp_dir("gyt-status-cls");
        crate::cmd::init::init_at(&dir).unwrap();
        let cfg = crate::config::Config {
            user_name: Some("T".into()),
            user_email: Some("t@x".into()),
            ..crate::config::Config::default()
        };
        cfg.write(&dir.join(".gyt")).unwrap();

        fs::write(dir.join("a.txt"), b"a").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "i".to_string()]).unwrap();
        fs::write(dir.join("a.txt"), b"AA").unwrap();
        fs::write(dir.join("new.txt"), b"new").unwrap();
        let r = run(&[]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
