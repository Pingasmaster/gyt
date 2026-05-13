// `gyt gc` — garbage collect unreachable objects.
//
// Walks all refs (heads, tags, remotes) to compute reachable objects,
// then removes any loose object file whose hash is not reachable.

use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::object::{commit, store, tag, tree};
use crate::refs;
use crate::repo::Repo;
use std::collections::{HashSet, VecDeque};
use std::path::Path;

pub fn run(args: &[String]) -> Result<()> {
    for a in args {
        if a == "-h" || a == "--help" {
            println!("gyt gc");
            return Ok(());
        }
        if a.starts_with('-') {
            return Err(GytError::InvalidArgument(format!("gc: unknown flag {a}")));
        }
    }

    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;

    let count = gc(&repo.gyt_dir);
    if count > 0 {
        println!("gc: pruned {count} unreachable objects");
    } else {
        println!("gc: no unreachable objects found");
    }
    Ok(())
}

/// Run garbage collection: returns the number of objects pruned.
fn gc(gyt_dir: &Path) -> usize {
    // 1. Compute reachable set from all refs
    let reachable = compute_reachable(gyt_dir);

    // 2. Scan all loose objects
    let objects_dir = gyt_dir.join("objects");
    if !objects_dir.is_dir() {
        return 0;
    }

    let mut pruned = 0usize;

    let Ok(entries) = std::fs::read_dir(&objects_dir) else {
        return 0;
    };

    for entry in entries {
        let Ok(entry) = entry else {
            continue;
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        // The file name is the hex suffix (everything after the first 2 chars).
        let dir_name = path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let hex = format!("{dir_name}{file_name}");
        if hex.len() != 64 {
            continue;
        }
        if let Ok(id) = ObjectId::from_hex(&hex)
            && !reachable.contains(&id)
        {
            let _ = std::fs::remove_file(&path);
            pruned += 1;
        }
    }

    pruned
}

/// Walk all refs (heads, tags, remotes) and return the set of reachable object ids.
fn compute_reachable(gyt_dir: &Path) -> HashSet<ObjectId> {
    let mut reachable: HashSet<ObjectId> = HashSet::new();

    // Collect seeds from all refs
    let mut seeds: Vec<ObjectId> = Vec::new();

    // refs/heads/
    if let Ok(refs) = refs::list_refs(gyt_dir, "refs/heads") {
        for (_, id) in refs {
            seeds.push(id);
        }
    }

    // refs/tags/
    if let Ok(refs) = refs::list_refs(gyt_dir, "refs/tags") {
        for (_, id) in refs {
            seeds.push(id);
        }
    }

    // refs/remotes/
    if let Ok(refs) = refs::list_refs(gyt_dir, "refs/remotes") {
        for (_, id) in refs {
            seeds.push(id);
        }
    }

    // Walk closure from all seeds
    let mut queue: VecDeque<ObjectId> = seeds.into_iter().collect();
    while let Some(id) = queue.pop_front() {
        if !reachable.insert(id) {
            continue;
        }
        if !store::exists(gyt_dir, &id) {
            continue;
        }
        let Ok(obj) = store::read(gyt_dir, &id) else {
            continue;
        };
        match obj.kind {
            crate::object::ObjectKind::Blob => {}
            crate::object::ObjectKind::Commit => {
                if let Ok(c) = commit::decode(&obj.payload) {
                    queue.push_back(c.tree);
                    for p in &c.parents {
                        queue.push_back(*p);
                    }
                }
            }
            crate::object::ObjectKind::Tree => {
                if let Ok(entries) = tree::decode(&obj.payload) {
                    for e in &entries {
                        queue.push_back(e.hash);
                    }
                }
            }
            crate::object::ObjectKind::Tag => {
                if let Ok(t) = tag::decode(&obj.payload) {
                    queue.push_back(t.target);
                }
            }
        }
    }

    reachable
}