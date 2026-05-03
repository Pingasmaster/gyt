use crate::cmd::util;
use crate::diff;
use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::index::Index;
use crate::object::blob;
use crate::repo::Repo;
use crate::term;
use crate::workdir;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub fn run(args: &[String]) -> Result<()> {
    let mut revs: Vec<String> = Vec::new();
    for a in args {
        match a.as_str() {
            "--help" | "-h" => {
                println!(
                    "gyt diff [<rev>] [<rev>]\n\nWith 0 revs: workdir vs index.\nWith 1 rev: index vs that tree.\nWith 2 revs: rev1 tree vs rev2 tree."
                );
                return Ok(());
            }
            other if other.starts_with("--") => {
                return Err(GytError::InvalidArgument(format!(
                    "diff: unknown flag {other}"
                )));
            }
            other => revs.push(other.to_string()),
        }
    }
    if revs.len() > 2 {
        return Err(GytError::InvalidArgument(
            "diff: at most two rev arguments".into(),
        ));
    }

    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    let use_color = term::use_color();

    match revs.len() {
        0 => diff_workdir_vs_index(&repo, use_color),
        1 => diff_index_vs_tree(&repo, &revs[0], use_color),
        2 => diff_tree_vs_tree(&repo, &revs[0], &revs[1], use_color),
        _ => unreachable!(),
    }
}

fn diff_workdir_vs_index(repo: &Repo, use_color: bool) -> Result<()> {
    let index = Index::read(&repo.index_path())?;
    let mut idx_map: BTreeMap<PathBuf, (u32, ObjectId)> = BTreeMap::new();
    for e in &index.entries {
        idx_map.insert(e.path.clone(), (e.mode, e.hash));
    }

    let ignore = crate::ignore::IgnoreSet::load_from_root(&repo.workdir)?;
    let walk = workdir::walk(&repo.workdir, &ignore)?;
    let mut wd_paths: BTreeSet<PathBuf> = BTreeSet::new();
    for ent in &walk {
        if !ent.is_dir {
            wd_paths.insert(ent.path.clone());
        }
    }

    let mut all: BTreeSet<PathBuf> = BTreeSet::new();
    for k in idx_map.keys() {
        all.insert(k.clone());
    }
    for p in &wd_paths {
        all.insert(p.clone());
    }

    for p in all {
        let idx_hash = idx_map.get(&p).map(|(_, h)| *h);
        let wd_present = wd_paths.contains(&p);
        let wd_bytes: Vec<u8> = if wd_present {
            std::fs::read(repo.workdir.join(&p))?
        } else {
            Vec::new()
        };
        let idx_bytes: Vec<u8> = match idx_hash {
            Some(h) => blob::read(&repo.gyt_dir, &h)?,
            None => Vec::new(),
        };
        if idx_bytes == wd_bytes {
            continue;
        }
        let header = forward_slash(&p);
        let out = diff::render_unified(&idx_bytes, &wd_bytes, &header, &header, 3, use_color);
        print!("{out}");
    }
    Ok(())
}

fn diff_index_vs_tree(repo: &Repo, rev: &str, use_color: bool) -> Result<()> {
    let tree_id = util::resolve_tree(repo, rev)?;
    let tree_map = util::flatten_tree(repo, &tree_id)?;
    let index = Index::read(&repo.index_path())?;
    let mut idx_map: BTreeMap<PathBuf, (u32, ObjectId)> = BTreeMap::new();
    for e in &index.entries {
        idx_map.insert(e.path.clone(), (e.mode, e.hash));
    }
    print_pair_diff(repo, &tree_map, &idx_map, use_color)
}

fn diff_tree_vs_tree(repo: &Repo, a: &str, b: &str, use_color: bool) -> Result<()> {
    let ta = util::resolve_tree(repo, a)?;
    let tb = util::resolve_tree(repo, b)?;
    let am = util::flatten_tree(repo, &ta)?;
    let bm = util::flatten_tree(repo, &tb)?;
    print_pair_diff(repo, &am, &bm, use_color)
}

fn print_pair_diff(
    repo: &Repo,
    a: &BTreeMap<PathBuf, (u32, ObjectId)>,
    b: &BTreeMap<PathBuf, (u32, ObjectId)>,
    use_color: bool,
) -> Result<()> {
    let mut all: BTreeSet<&PathBuf> = BTreeSet::new();
    for k in a.keys() {
        all.insert(k);
    }
    for k in b.keys() {
        all.insert(k);
    }
    for p in all {
        let ah = a.get(p).map(|(_, h)| *h);
        let bh = b.get(p).map(|(_, h)| *h);
        if ah == bh {
            continue;
        }
        let abytes = match ah {
            Some(h) => blob::read(&repo.gyt_dir, &h)?,
            None => Vec::new(),
        };
        let bbytes = match bh {
            Some(h) => blob::read(&repo.gyt_dir, &h)?,
            None => Vec::new(),
        };
        let header = forward_slash(p);
        let out = diff::render_unified(&abytes, &bbytes, &header, &header, 3, use_color);
        print!("{out}");
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
    use super::*;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};
    use std::fs;

    #[test]
    fn diff_workdir_vs_index_runs() {
        let _g = lock();
        let dir = tmp_dir("gyt-diff");
        crate::cmd::init::init_at(&dir).unwrap();
        let cfg = crate::config::Config {
            user_name: Some("T".into()),
            user_email: Some("t@x".into()),
            ..crate::config::Config::default()
        };
        cfg.write(&dir.join(".gyt")).unwrap();
        fs::write(dir.join("a.txt"), b"a\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        // modify workdir
        fs::write(dir.join("a.txt"), b"AA\n").unwrap();
        let r = run(&[]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
