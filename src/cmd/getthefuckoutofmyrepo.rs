use crate::errors::{GytError, Result};
use crate::hash::{HEX_LEN, ObjectId};
use crate::index::Index;
use crate::object::commit::{self as commit_obj, Commit};
use crate::object::tree::{self, MODE_DIR, TreeEntry};
use crate::object::{ObjectKind, store};
use crate::refs;
use crate::repo::Repo;
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

fn is_null(oid: &ObjectId) -> bool {
    oid.0.iter().all(|&b| b == 0)
}

/// `gyt getthefuckoutofmyrepo <path>...`
///
/// Removes files from the working directory, the index, and the entire
/// history of the repository. This is the nuclear option.
///
/// The command requires double interactive confirmation before proceeding.
pub fn run(args: &[String]) -> Result<()> {
    let mut paths: Vec<String> = Vec::new();
    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => {
                print_usage();
                return Ok(());
            }
            other if other.starts_with('-') => {
                return Err(GytError::InvalidArgument(format!(
                    "getthefuckoutofmyrepo: unknown flag {other}"
                )));
            }
            other => paths.push(other.to_string()),
        }
    }

    if paths.is_empty() {
        return Err(GytError::InvalidArgument(
            "getthefuckoutofmyrepo: at least one path required".into(),
        ));
    }

    let repo = Repo::open(&std::env::current_dir()?)?;
    let cwd = repo.workdir.clone();

    let mut resolved: Vec<PathBuf> = Vec::new();
    for p in &paths {
        let abs = cwd.join(p);
        if !abs.exists() {
            return Err(GytError::NotFound(format!("path {p} does not exist")));
        }
        resolved.push(abs.canonicalize()?);
    }

    let summary: Vec<String> = resolved
        .iter()
        .map(|p| {
            let rel = p.strip_prefix(&cwd).unwrap_or(p);
            if p.is_dir() {
                format!("  {} (directory)", fs_path(rel))
            } else {
                format!("  {}", fs_path(rel))
            }
        })
        .collect();

    let display = if summary.len() <= 10 {
        summary.join("\n")
    } else {
        format!(
            "{} file(s)/directory(ies):\n{}\n  ...and {} more",
            summary.len(),
            summary[..10].join("\n"),
            summary.len() - 10
        )
    };

    eprintln!("This will PERMANENTLY REMOVE the following from your repository:");
    eprintln!("  - The files/directories from the working directory");
    eprintln!("  - Staging records from the index");
    eprintln!("  - ALL historical references in every commit and tree");
    eprintln!();
    eprintln!("Path(s) to destroy:\n{display}");
    eprintln!();

    eprint!("Type 'DESTROY' to confirm: ");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    if input.trim() != "DESTROY" {
        eprintln!("Aborted.");
        return Ok(());
    }

    eprint!("Final confirmation — type 'DESTROY' again: ");
    io::stdout().flush()?;
    let mut input2 = String::new();
    io::stdin().read_line(&mut input2)?;
    if input2.trim() != "DESTROY" {
        eprintln!("Aborted.");
        return Ok(());
    }

    for p in &resolved {
        if p.is_dir() {
            fs::remove_dir_all(p)?;
            eprintln!(
                "removed (dir): {}",
                fs_path(p.strip_prefix(&cwd).unwrap_or(p))
            );
        } else {
            fs::remove_file(p)?;
            eprintln!("removed: {}", fs_path(p.strip_prefix(&cwd).unwrap_or(p)));
        }
    }

    let mut index = Index::read(&repo.index_path())?;
    let mut to_remove: Vec<std::path::PathBuf> = Vec::new();
    for p in &resolved {
        let rel = p.strip_prefix(&cwd).unwrap_or(p).to_path_buf();
        to_remove.push(rel);
    }
    let mut removed_from_index: Vec<PathBuf> = Vec::new();
    for rel in &to_remove {
        if index.find(rel).is_some() {
            removed_from_index.push(rel.clone());
        }
    }
    index.entries.retain(|e| !to_remove.contains(&e.path));
    index.write(&repo.index_path())?;

    for p in &removed_from_index {
        eprintln!("unstage: {}", fs_path(p));
    }

    eprintln!("rewriting history...");

    let mut head_refs: Vec<(String, ObjectId)> = Vec::new();

    if let Ok(head) = refs::read_head(&repo.gyt_dir) {
        match head {
            refs::Head::Symbolic(ref sym) => {
                if let Ok(target) = refs::read_ref(&repo.gyt_dir, sym) {
                    head_refs.push((sym.clone(), target));
                }
            }
            refs::Head::Detached(oid) => {
                head_refs.push(("HEAD".to_string(), oid));
            }
        }
    }

    for (name, oid) in refs::list_refs(&repo.gyt_dir, "refs/heads/")? {
        head_refs.push((name, oid));
    }
    for (name, oid) in refs::list_refs(&repo.gyt_dir, "refs/tags/")? {
        head_refs.push((name, oid));
    }

    let mut commits: HashMap<ObjectId, Commit> = HashMap::new();
    let mut queue: Vec<ObjectId> = Vec::new();
    let mut visited: std::collections::HashSet<ObjectId> = std::collections::HashSet::new();

    for (_, head) in &head_refs {
        if is_null(head) {
            continue;
        }
        queue.push(*head);
    }

    while let Some(oid) = queue.pop() {
        if !visited.insert(oid) {
            continue;
        }
        match store::read(&repo.gyt_dir, &oid) {
            Ok(obj) if obj.kind == ObjectKind::Commit => {
                if let Ok(c) = commit_obj::decode(&obj.payload) {
                    commits.insert(oid, c.clone());
                    queue.extend(c.parents);
                }
            }
            Ok(obj) if obj.kind == ObjectKind::Tag => {
                let target_oid = if obj.payload.len() >= HEX_LEN {
                    let hex = String::from_utf8_lossy(&obj.payload[..HEX_LEN]).to_string();
                    ObjectId::from_hex(&hex).ok()
                } else {
                    None
                };
                if let Some(target_oid) = target_oid {
                    queue.push(target_oid);
                }
            }
            _ => {}
        }
    }

    let mut seen: HashMap<ObjectId, ObjectId> = HashMap::new();
    let mut stack: Vec<ObjectId> = commits.keys().copied().collect();
    let mut depth = 0;
    let max_depth = 10000;

    while let Some(oid) = stack.pop() {
        depth += 1;
        if depth > max_depth {
            eprintln!("warning: hit max rewrite depth, stopping");
            break;
        }
        if seen.contains_key(&oid) {
            continue;
        }
        if let Some(c) = commits.get(&oid) {
            let new_tree =
                rewrite_tree_entries(&repo.gyt_dir, &c.tree, &resolved, &cwd, &mut seen)?;

            let new_parents: Vec<ObjectId> = c
                .parents
                .iter()
                .map(|p| seen.get(p).copied().unwrap_or(*p))
                .collect();

            let new_commit = Commit {
                tree: new_tree,
                parents: new_parents,
                authors: c.authors.clone(),
                committer: c.committer.clone(),
                ai_assists: c.ai_assists.clone(),
                reviewers: c.reviewers.clone(),
                signature: c.signature.clone(),
                message: c.message.clone(),
            };

            let new_oid = commit_obj::write(&repo.gyt_dir, &new_commit)?;
            seen.insert(oid, new_oid);
            for p in &c.parents {
                if !seen.contains_key(p) {
                    stack.push(*p);
                }
            }
        }
    }

    for (name, old_oid) in &head_refs {
        if let Some(&new_oid) = seen.get(old_oid) {
            refs::write_ref(&repo.gyt_dir, name, &new_oid)?;
            eprintln!("updated ref {name}: {old_oid} -> {new_oid}");
        }
    }

    eprintln!("history rewritten. {} commit(s) affected.", seen.len());
    eprintln!("WARNING: hard-reset your working directory: gyt reset --hard HEAD");

    Ok(())
}

fn rewrite_tree_entries(
    repo_path: &Path,
    tree_oid: &ObjectId,
    targets: &[PathBuf],
    cwd: &Path,
    seen: &mut HashMap<ObjectId, ObjectId>,
) -> Result<ObjectId> {
    if is_null(tree_oid) {
        return Ok(*tree_oid);
    }
    if let Some(&new_oid) = seen.get(tree_oid) {
        return Ok(new_oid);
    }

    let entries = tree::read(repo_path, tree_oid)?;

    let new_entries: Vec<TreeEntry> = entries
        .into_iter()
        .filter(|e| {
            let target_path = cwd.join(fs_bytes(&e.name));
            !targets.iter().any(|t| t == &target_path)
        })
        .map(|mut e| {
            if e.mode == MODE_DIR {
                e.hash = rewrite_tree_entries(repo_path, &e.hash, targets, cwd, seen)
                    .ok()
                    .unwrap_or(e.hash);
            }
            e
        })
        .collect();

    let new_oid = tree::write(repo_path, &new_entries)?;
    Ok(new_oid)
}

fn fs_bytes(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn fs_path(p: &Path) -> String {
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

fn print_usage() {
    println!(
        "gyt getthefuckoutofmyrepo <path>...\n\n\
         Permanently remove files from the working directory, index, and ALL history.\n\n\
         This command requires double confirmation before proceeding.\n\
         It rewrites every commit in the repository to erase the specified paths."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_no_args() {
        let r = run(&[]);
        assert!(r.is_err());
        let err = format!("{:?}", r.unwrap_err());
        assert!(err.contains("at least one path required"));
    }
}
