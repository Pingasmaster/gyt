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
    let mut short = false;
    for a in args {
        match a.as_str() {
            "--help" | "-h" => {
                println!(
                    "gyt status [--short|--porcelain]\n\nShow staged, modified, and untracked changes."
                );
                return Ok(());
            }
            "--short" | "--porcelain" => short = true,
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "status: unexpected argument {other}"
                )));
            }
        }
    }

    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    repo.require_worktree()?;
    let workdir_path = repo.workdir.clone();
    let ignore = IgnoreSet::load_from_root(&workdir_path)?;
    let walk = workdir::walk(&workdir_path, &ignore)?;
    let index = Index::read(&repo.index_path())?;

    // Branch label + ahead/behind vs remote-tracking ref. Printed before
    // the per-file status block so the user sees their branch state at
    // the top, the way they expect from years of `git status`.
    if !short {
        print_branch_status(&repo);
    }

    // Build HEAD path -> hash map.
    let head_map: BTreeMap<PathBuf, (u32, ObjectId)> = match refs::read_head(&repo.gyt_dir) {
        Ok(head) => match refs::resolve(&repo.gyt_dir, &head)? {
            Some(commit_id) => {
                let obj = crate::object::store::read(&repo.gyt_dir, &commit_id)?;
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

    let mut staged: Vec<(PathBuf, String)> = Vec::new();
    let mut modified: Vec<PathBuf> = Vec::new();
    let mut untracked: Vec<PathBuf> = Vec::new();
    let mut staged_set: BTreeSet<PathBuf> = BTreeSet::new();
    let mut modified_set: BTreeSet<PathBuf> = BTreeSet::new();

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
                        "new file".to_string()
                    } else {
                        "modified".to_string()
                    };
                    staged.push((ent.path.clone(), label));
                    staged_set.insert(ent.path.clone());
                }
                if wd_vs_idx {
                    modified.push(ent.path.clone());
                    modified_set.insert(ent.path.clone());
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
            modified.push(p.clone());
            modified_set.insert(p);
        } else if !in_index && in_head {
            staged.push((p.clone(), "deleted".to_string()));
            staged_set.insert(p);
        } else if in_index && !in_head {
            staged.push((p.clone(), "new file".to_string()));
            staged_set.insert(p.clone());
            modified.push(p.clone());
            modified_set.insert(p);
        }
    }

    // Rename detection: turn a (deleted X, new-file Y) pair with matching
    // content hash into a single "renamed: X -> Y" entry. The deleted path
    // is dropped from the staged list (and any associated sets) once a
    // partner is found. We pair greedily by traversal order.
    detect_renames(&mut staged, &mut staged_set, &mut modified, &mut modified_set, &head_map, &index_map);

    if short {
        print_short_status(&staged, &untracked);
    } else {
        let use_color = term::use_color();
        print_status(&staged, &modified, &untracked, use_color);
    }
    Ok(())
}

fn detect_renames(
    staged: &mut Vec<(PathBuf, String)>,
    staged_set: &mut BTreeSet<PathBuf>,
    modified: &mut Vec<PathBuf>,
    modified_set: &mut BTreeSet<PathBuf>,
    head_map: &BTreeMap<PathBuf, (u32, ObjectId)>,
    index_map: &BTreeMap<PathBuf, (u32, ObjectId)>,
) {
    use std::collections::HashMap;
    // Build hash -> deleted-path list, and hash -> new-file path list.
    let mut deleted_by_hash: HashMap<ObjectId, Vec<PathBuf>> = HashMap::new();
    let mut new_by_hash: HashMap<ObjectId, Vec<PathBuf>> = HashMap::new();
    for (path, label) in staged.iter() {
        match label.as_str() {
            "deleted" => {
                if let Some((_, h)) = head_map.get(path) {
                    deleted_by_hash.entry(*h).or_default().push(path.clone());
                }
            }
            "new file" => {
                if let Some((_, h)) = index_map.get(path) {
                    new_by_hash.entry(*h).or_default().push(path.clone());
                }
            }
            _ => {}
        }
    }
    // Walk hashes shared by both maps; pair them off.
    let mut rename_pairs: Vec<(PathBuf, PathBuf)> = Vec::new();
    for (hash, dels) in &mut deleted_by_hash {
        let Some(news) = new_by_hash.get_mut(hash) else {
            continue;
        };
        let pairs = dels.len().min(news.len());
        for _ in 0..pairs {
            let from = dels.remove(0);
            let to = news.remove(0);
            rename_pairs.push((from, to));
        }
    }
    if rename_pairs.is_empty() {
        return;
    }
    // Drop the "deleted" entries that got paired; rewrite the "new file"
    // entries into "renamed: from -> to" entries.
    let mut paired_deletes: BTreeSet<PathBuf> = BTreeSet::new();
    let mut rename_for_new: HashMap<PathBuf, PathBuf> = HashMap::new();
    for (from, to) in &rename_pairs {
        paired_deletes.insert(from.clone());
        rename_for_new.insert(to.clone(), from.clone());
    }
    let mut out: Vec<(PathBuf, String)> = Vec::with_capacity(staged.len());
    for (path, label) in staged.drain(..) {
        if label == "deleted" && paired_deletes.contains(&path) {
            staged_set.remove(&path);
            continue;
        }
        if label == "new file"
            && let Some(from) = rename_for_new.get(&path)
        {
            let new_label = format!("renamed: {} -> {}", forward_slash(from), forward_slash(&path));
            out.push((path.clone(), new_label));
            modified.retain(|p| p != &path);
            modified_set.remove(&path);
            continue;
        }
        out.push((path, label));
    }
    *staged = out;
}

/// Print "On branch X" and an ahead/behind summary vs the first remote
/// that has a tracking ref for X. Quietly skips both lines if there's no
/// HEAD branch or no matching remote-tracking ref — we never invent
/// information.
fn print_branch_status(repo: &Repo) {
    let Ok(head) = refs::read_head(&repo.gyt_dir) else {
        return;
    };
    let branch_name = match &head {
        refs::Head::Symbolic(name) => name.strip_prefix("refs/heads/").map(str::to_string),
        refs::Head::Detached(_) => None,
    };
    let Some(branch) = branch_name else {
        // Detached HEAD: just print where we are.
        if let Ok(refs::Head::Detached(id)) = refs::read_head(&repo.gyt_dir) {
            let hex = id.to_hex();
            println!("HEAD detached at {}", &hex[..hex.len().min(8)]);
            println!();
        }
        return;
    };
    println!("On branch {branch}");

    // Walk every refs/remotes/<remote>/<branch> looking for a match.
    let head_id = refs::resolve(&repo.gyt_dir, &head).ok().flatten();
    let remotes_root = repo.gyt_dir.join("refs/remotes");
    if !remotes_root.is_dir() {
        println!();
        return;
    }
    let Ok(entries) = std::fs::read_dir(&remotes_root) else {
        println!();
        return;
    };
    for entry in entries.flatten() {
        let remote = entry.file_name().to_string_lossy().into_owned();
        let candidate = format!("refs/remotes/{remote}/{branch}");
        let Ok(remote_id) = refs::read_ref(&repo.gyt_dir, &candidate) else {
            continue;
        };
        let Some(local_id) = head_id else {
            println!();
            return;
        };
        let (ahead, behind) = ahead_behind(repo, &local_id, &remote_id);
        match (ahead, behind) {
            (0, 0) => println!("Your branch is up to date with '{remote}/{branch}'."),
            (a, 0) => println!("Your branch is ahead of '{remote}/{branch}' by {a} commit(s)."),
            (0, b) => println!(
                "Your branch is behind '{remote}/{branch}' by {b} commit(s); fast-forward possible."
            ),
            (a, b) => println!(
                "Your branch and '{remote}/{branch}' have diverged ({a} local, {b} remote)."
            ),
        }
        println!();
        return;
    }
    println!();
}

/// Count commits reachable from `local` but not `remote` (ahead), and
/// reachable from `remote` but not `local` (behind). Uses set-difference
/// over the parent DAG; for normal-sized histories this is fast enough.
fn ahead_behind(repo: &Repo, local: &crate::hash::ObjectId, remote: &crate::hash::ObjectId) -> (usize, usize) {
    if local == remote {
        return (0, 0);
    }
    let local_set = reachable(repo, local);
    let remote_set = reachable(repo, remote);
    let ahead = local_set.iter().filter(|c| !remote_set.contains(c)).count();
    let behind = remote_set.iter().filter(|c| !local_set.contains(c)).count();
    (ahead, behind)
}

fn reachable(repo: &Repo, tip: &crate::hash::ObjectId) -> std::collections::HashSet<crate::hash::ObjectId> {
    use std::collections::HashSet;
    let mut out: HashSet<crate::hash::ObjectId> = HashSet::new();
    let mut stack = vec![*tip];
    while let Some(id) = stack.pop() {
        if !out.insert(id) {
            continue;
        }
        if let Ok(c) = crate::object::commit::read(&repo.gyt_dir, &id) {
            for p in c.parents {
                stack.push(p);
            }
        }
    }
    out
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
    staged: &[(PathBuf, String)],
    modified: &[PathBuf],
    untracked: &[PathBuf],
    use_color: bool,
) {
    if !staged.is_empty() {
        println!("Staged for commit:");
        let mut sorted: Vec<&(PathBuf, String)> = staged.iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        for (p, label) in sorted {
            // Renamed labels already include source and target; print as-is.
            let line = if label.starts_with("renamed:") {
                format!("  {label}")
            } else {
                format!("  {label}: {}", forward_slash(p))
            };
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

fn print_short_status(staged: &[(PathBuf, String)], untracked: &[PathBuf]) {
    use std::collections::BTreeMap as Map;
    // We need a single line per path showing the staged status code.
    // Codes: 'A' new, 'M' modified, 'D' deleted, 'R' renamed.
    let mut codes: Map<PathBuf, char> = Map::new();
    let mut renames: Vec<(PathBuf, PathBuf)> = Vec::new();
    for (path, label) in staged {
        if label == "deleted" {
            codes.insert(path.clone(), 'D');
        } else if label == "modified" {
            codes.insert(path.clone(), 'M');
        } else if label == "new file" {
            codes.insert(path.clone(), 'A');
        } else if let Some(rest) = label.strip_prefix("renamed: ") {
            // "renamed: from -> to"
            if let Some((from, to)) = rest.split_once(" -> ") {
                renames.push((PathBuf::from(from), PathBuf::from(to)));
            }
            codes.insert(path.clone(), 'R');
        }
    }
    for (path, code) in &codes {
        if *code == 'R'
            && let Some((from, to)) = renames.iter().find(|(_, t)| t == path)
        {
            println!("R  {} -> {}", forward_slash(from), forward_slash(to));
            continue;
        }
        println!("{}  {}", code, forward_slash(path));
    }
    for p in untracked {
        println!("?? {}", forward_slash(p));
    }
    if codes.is_empty() && untracked.is_empty() {
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
