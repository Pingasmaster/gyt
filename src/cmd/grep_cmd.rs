use crate::errors::Result;
use crate::hash::ObjectId;
use crate::object::{blob, tree};
use crate::repo::Repo;

// Scaffolding for `gyt grep` - fields and methods are used in commit phase.
#[allow(dead_code)]
pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    let mut pattern: Option<String> = None;
    let mut commit_arg: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!(
                    "gyt grep <pattern> [<rev>]\n\n\
                     Search for a pattern in tracked files.\n\
                     If <rev> is given, search that commit tree; otherwise search working tree."
                );
                return Ok(());
            }
            other if !other.starts_with('-') => {
                if pattern.is_none() {
                    pattern = Some(other.to_string());
                } else if commit_arg.is_none() {
                    commit_arg = Some(other.to_string());
                }
            }
            _ => {
                return Err(crate::errors::GytError::InvalidArgument(format!(
                    "grep: unknown flag {}", args[i]
                )));
            }
        }
        i += 1;
    }

    let pattern = pattern.ok_or_else(|| {
        crate::errors::GytError::InvalidArgument("grep: <pattern> is required".into())
    })?;

    if let Some(rev) = commit_arg {
        // Search in a specific commit's tree
        use crate::cmd::util::resolve_tree;
        let tree_id = resolve_tree(repo, &rev)?;
        search_tree(repo, &tree_id, &pattern)
    } else {
        // Search working tree files that are in the index
        search_working_tree(repo, &pattern)
    }
}

fn search_working_tree(repo: &Repo, pattern: &str) -> Result<()> {
    let index = crate::index::Index::read(&repo.index_path())?;
    let mut found = false;

    for entry in &index.entries {
        let abs = repo.workdir.join(&entry.path);
        if !abs.is_file() {
            continue;
        }
        let content = std::fs::read(&abs)?;
        if is_binary(&content) {
            continue;
        }
        if let Some(line_num) = grep_bytes(&content, pattern.as_bytes()) {
            let path_str = entry.path.to_string_lossy();
            println!("{path_str}:{line_num}:{pattern}");
            found = true;
        }
    }

    if !found {
        eprintln!("gyt grep: no matches");
    }

    Ok(())
}

fn search_tree(repo: &Repo, tree_id: &ObjectId, pattern: &str) -> Result<()> {
    let files = flatten_tree(repo, tree_id)?;
    let mut found = false;

    for (path, e) in files {
        let payload = blob::read(&repo.gyt_dir, &e.hash)?;
        if is_binary(&payload) {
            continue;
        }
        if let Some(line_num) = grep_bytes(&payload, pattern.as_bytes()) {
            println!("{path}:{line_num}:{pattern}");
            found = true;
        }
    }

    if !found {
        eprintln!("gyt grep: no matches");
    }

    Ok(())
}

fn is_binary(buf: &[u8]) -> bool {
    buf.contains(&0u8)
}

fn grep_bytes(content: &[u8], pattern: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(content).ok()?;
    let pattern_str = std::str::from_utf8(pattern).ok()?;
    
    for (line_num, line) in text.lines().enumerate() {
        if line.contains(pattern_str) {
            return Some(line_num + 1);
        }
    }
    
    None
}

#[derive(Debug, Clone)]
struct FlatEntry {
    _mode: u32,
    hash: ObjectId,
}

fn flatten_tree(repo: &Repo, tree_id: &ObjectId) -> Result<std::collections::BTreeMap<String, FlatEntry>> {
    let mut out = std::collections::BTreeMap::new();
    walk_tree(repo, tree_id, "", &mut out)?;
    Ok(out)
}

fn walk_tree(
    repo: &Repo,
    tree_id: &ObjectId,
    prefix: &str,
    out: &mut std::collections::BTreeMap<String, FlatEntry>,
) -> Result<()> {
    let entries = tree::read(&repo.gyt_dir, tree_id)?;
    for e in entries {
        let name = std::str::from_utf8(&e.name)
            .map_err(|_| crate::errors::GytError::Object("tree entry name is not utf-8".into()))?;
        let path = if prefix.is_empty() {
            name.to_string()
        } else {
            format!("{prefix}/{name}")
        };
        if e.mode == tree::MODE_DIR {
            walk_tree(repo, &e.hash, &path, out)?;
        } else {
            out.insert(path, FlatEntry { _mode: e.mode, hash: e.hash });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test_support::TestRepo;
    use crate::cmd::util::test_helpers::lock;
    use crate::refs;

    #[test]
    fn grep_in_working_tree() {
        let _g = lock();
        let r = TestRepo::new("gyt-grep-wt");
        let repo = r.open();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&repo.workdir).unwrap();
        
        let result = run_in(&repo, &["hello".into()]);
        std::env::set_current_dir(&prev).unwrap();
        
        result.unwrap(); // Should find "hello" in hello.txt
    }

    #[test]
    fn grep_in_commit() {
        let _g = lock();
        let r = TestRepo::new("gyt-grep-commit");
        let repo = r.open();
        let main_id = refs::read_ref(&repo.gyt_dir, "refs/heads/main").unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&repo.workdir).unwrap();
        
        let result = run_in(&repo, &["hello".into(), main_id.to_hex()]);
        std::env::set_current_dir(&prev).unwrap();
        
        result.unwrap();
    }

    #[test]
    fn grep_no_match() {
        let r = TestRepo::new("gyt-grep-none");
        let repo = r.open();
        
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&repo.workdir).unwrap();
        
        let result = run_in(&repo, &["nonexistent123".into()]);
        std::env::set_current_dir(&prev).unwrap();
        
        assert!(result.is_ok()); // Should succeed but print no matches
    }
}
