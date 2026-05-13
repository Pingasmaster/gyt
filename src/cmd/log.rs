use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::object::commit::{self, Commit};
use crate::refs;
use crate::repo::Repo;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;

struct Options {
    oneline: bool,
    graph: bool,
    all: bool,
    author: Option<String>,
    grep: Option<String>,
    since: Option<i64>,
    until: Option<i64>,
    max_count: Option<usize>,
    paths: Vec<String>,
}

impl Options {
    const fn new() -> Self {
        Self {
            oneline: false,
            graph: false,
            all: false,
            author: None,
            grep: None,
            since: None,
            until: None,
            max_count: None,
            paths: Vec::new(),
        }
    }
}

pub fn run(args: &[String]) -> Result<()> {
    let mut opts = Options::new();
    let mut after_dashes = false;
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if after_dashes {
            opts.paths.push(a.clone());
            i += 1;
            continue;
        }
        match a.as_str() {
            "--" => {
                after_dashes = true;
            }
            "--help" | "-h" => {
                println!(
                    "gyt log [--oneline] [--graph] [--all]\n\
                            [--author <pattern>] [--grep <pattern>]\n\
                            [--since <unix-secs>] [--until <unix-secs>]\n\
                            [-n <N>|--max-count <N>] [-- <path>...]\n\n\
                     Show commit history.\n\n\
                       --oneline       Short format: short hash + first line\n\
                       --graph         Real ASCII graph (branch lanes + merge points)\n\
                       --all           Show commits from all refs, not just current HEAD\n\
                       --author PAT    Only commits whose author contains PAT\n\
                       --grep PAT      Only commits whose message contains PAT\n\
                       --since SEC     Only commits at or after this unix timestamp\n\
                       --until SEC     Only commits at or before this unix timestamp\n\
                       -n N            Limit to N commits"
                );
                return Ok(());
            }
            "--oneline" => opts.oneline = true,
            "--graph" => opts.graph = true,
            "--all" => opts.all = true,
            "--author" => {
                i += 1;
                opts.author = Some(
                    args.get(i)
                        .ok_or_else(|| GytError::InvalidArgument("--author needs a value".into()))?
                        .clone(),
                );
            }
            "--grep" => {
                i += 1;
                opts.grep = Some(
                    args.get(i)
                        .ok_or_else(|| GytError::InvalidArgument("--grep needs a value".into()))?
                        .clone(),
                );
            }
            "--since" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| GytError::InvalidArgument("--since needs a value".into()))?;
                opts.since = Some(v.parse().map_err(|_| {
                    GytError::InvalidArgument(format!("--since: not a unix timestamp: {v}"))
                })?);
            }
            "--until" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| GytError::InvalidArgument("--until needs a value".into()))?;
                opts.until = Some(v.parse().map_err(|_| {
                    GytError::InvalidArgument(format!("--until: not a unix timestamp: {v}"))
                })?);
            }
            "-n" | "--max-count" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| GytError::InvalidArgument("-n needs a value".into()))?;
                opts.max_count = Some(v.parse().map_err(|_| {
                    GytError::InvalidArgument(format!("-n: not a number: {v}"))
                })?);
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "log: unexpected argument {other}"
                )));
            }
        }
        i += 1;
    }

    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    let out = format_log(&repo, &opts)?;
    print!("{out}");
    Ok(())
}

/// Walked commit metadata.
struct Node {
    id: ObjectId,
    parents: Vec<ObjectId>,
    timestamp: i64,
    author: String,
    message: String,
    tree: ObjectId,
}

fn format_log(repo: &Repo, opts: &Options) -> Result<String> {
    let gyt_dir = &repo.gyt_dir;

    let mut roots = Vec::new();
    if opts.all {
        roots.extend(all_ref_tips(gyt_dir)?);
        if let refs::Head::Detached(id) = refs::read_head(gyt_dir)? {
            roots.push(id);
        }
    } else {
        let head = refs::read_head(gyt_dir)?;
        let Some(cur_id) = refs::resolve(gyt_dir, &head)? else {
            return Ok("(no commits yet)\n".to_string());
        };
        roots.push(cur_id);
    }

    let nodes = walk(gyt_dir, &roots)?;
    if nodes.is_empty() {
        return Ok(String::new());
    }
    let order = topo_order(&nodes);
    let kept: Vec<&Node> = order
        .iter()
        .filter_map(|id| nodes.get(id))
        .filter(|n| node_matches(n, opts, repo))
        .collect();

    let mut out = String::new();
    if opts.graph {
        render_graph(&kept, opts, &mut out);
    } else {
        render_plain(&kept, opts, &mut out);
    }
    Ok(out)
}

fn node_matches(n: &Node, opts: &Options, repo: &Repo) -> bool {
    if let Some(a) = &opts.author
        && !n.author.contains(a)
    {
        return false;
    }
    if let Some(g) = &opts.grep
        && !n.message.contains(g)
    {
        return false;
    }
    if let Some(s) = opts.since
        && n.timestamp < s
    {
        return false;
    }
    if let Some(u) = opts.until
        && n.timestamp > u
    {
        return false;
    }
    if !opts.paths.is_empty() && !commit_touches_paths(repo, n, &opts.paths) {
        return false;
    }
    true
}

/// True if this commit changed at least one of `paths` relative to its first
/// parent. Root commits are considered to "touch" any path that exists in
/// their tree. Path matching is prefix-based (so "src/foo" matches a file
/// "src/foo/bar.rs").
fn commit_touches_paths(repo: &Repo, n: &Node, paths: &[String]) -> bool {
    let cur_files = crate::cmd::util::flatten_tree(repo, &n.tree).unwrap_or_default();
    let parent_files = if let Some(p) = n.parents.first() {
        let pc = match commit::read(&repo.gyt_dir, p) {
            Ok(c) => c,
            Err(_) => return true,
        };
        crate::cmd::util::flatten_tree(repo, &pc.tree).unwrap_or_default()
    } else {
        std::collections::BTreeMap::new()
    };

    for (path, (_, hash)) in &cur_files {
        let path_s = path.to_string_lossy();
        if !paths.iter().any(|p| path_under(&path_s, p)) {
            continue;
        }
        match parent_files.get(path) {
            None => return true,
            Some((_, ph)) if ph != hash => return true,
            _ => {}
        }
    }
    for path in parent_files.keys() {
        let path_s = path.to_string_lossy();
        if !paths.iter().any(|p| path_under(&path_s, p)) {
            continue;
        }
        if !cur_files.contains_key(path) {
            return true;
        }
    }
    false
}

fn path_under(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn walk(gyt_dir: &std::path::Path, roots: &[ObjectId]) -> Result<HashMap<ObjectId, Node>> {
    let mut nodes: HashMap<ObjectId, Node> = HashMap::new();
    let mut stack: Vec<ObjectId> = roots.to_vec();
    while let Some(id) = stack.pop() {
        if nodes.contains_key(&id) {
            continue;
        }
        let c = commit::read(gyt_dir, &id)?;
        let ts = parse_timestamp(&c.committer).unwrap_or(0);
        let author = c.authors.first().cloned().unwrap_or_default();
        for p in &c.parents {
            stack.push(*p);
        }
        nodes.insert(
            id,
            Node {
                id,
                parents: c.parents.clone(),
                timestamp: ts,
                author,
                message: c.message,
                tree: c.tree,
            },
        );
    }
    Ok(nodes)
}

/// Topological order: parents come after children (DAG reverse-topo).
/// Ties broken by descending timestamp.
fn topo_order(nodes: &HashMap<ObjectId, Node>) -> Vec<ObjectId> {
    // Kahn's algorithm on the child->parent edges, but emitting in
    // child-first order: a commit is emitted only after every commit that
    // has it as a parent has already been emitted.
    let mut indegree: HashMap<ObjectId, usize> = HashMap::new();
    for id in nodes.keys() {
        indegree.entry(*id).or_insert(0);
    }
    for n in nodes.values() {
        for p in &n.parents {
            if nodes.contains_key(p) {
                *indegree.entry(*p).or_insert(0) += 1;
            }
        }
    }
    let mut ready: Vec<ObjectId> = indegree
        .iter()
        .filter(|(_, c)| **c == 0)
        .map(|(id, _)| *id)
        .collect();
    ready.sort_by_key(|id| std::cmp::Reverse(nodes[id].timestamp));

    let mut out = Vec::with_capacity(nodes.len());
    while let Some(id) = ready.pop() {
        out.push(id);
        let n = &nodes[&id];
        for p in &n.parents {
            if let Some(c) = indegree.get_mut(p) {
                *c -= 1;
                if *c == 0 {
                    // Insert in ready in correct timestamp order.
                    let pos = ready
                        .binary_search_by(|x| nodes[x].timestamp.cmp(&nodes[p].timestamp))
                        .unwrap_or_else(|e| e);
                    ready.insert(pos, *p);
                }
            }
        }
    }
    out
}

fn render_plain(nodes: &[&Node], opts: &Options, out: &mut String) {
    let limit = opts.max_count.unwrap_or(usize::MAX);
    for n in nodes.iter().take(limit) {
        write_commit(out, n, opts.oneline, "");
    }
}

/// Real ASCII graph renderer with branch lanes.
///
/// The lanes are stable across the output: each commit owns a column. When a
/// commit has multiple parents (merge), the additional parent becomes a new
/// lane to the right that continues until that parent is rendered. When two
/// lanes share a parent (their child branches converged), the lanes collapse.
///
/// Output looks like:
///
/// ```text
/// * abcd1234 message              (single commit)
/// *-. abcd1234 merge of foo/bar   (merge: pulls in lanes)
/// |\
/// | * 1234abcd parent on the left
/// * | 5678ef02 parent on the right
/// |/
/// * 9abcdef0 common ancestor
/// ```
fn render_graph(nodes: &[&Node], opts: &Options, out: &mut String) {
    // `lanes` is the list of pending commit ids in column order. The leftmost
    // lane is the "main" thread of the walk.
    let mut lanes: Vec<Option<ObjectId>> = Vec::new();
    let limit = opts.max_count.unwrap_or(usize::MAX);

    for n in nodes.iter().take(limit) {
        // Find this commit's column. If absent, append to the right (a fresh
        // branch tip).
        let col = match lanes.iter().position(|l| *l == Some(n.id)) {
            Some(c) => c,
            None => {
                lanes.push(Some(n.id));
                lanes.len() - 1
            }
        };

        // Build the commit-row prefix.
        let mut row = String::new();
        for (i, lane) in lanes.iter().enumerate() {
            if i > 0 {
                row.push(' ');
            }
            if i == col {
                row.push('*');
            } else if lane.is_some() {
                row.push('|');
            } else {
                row.push(' ');
            }
        }
        let _ = write!(out, "{row} ");
        write_commit_oneline_after_marker(out, n, opts.oneline);

        // Replace this column with the first parent (or empty if none).
        // Append any extra parents as new columns. After this, optionally
        // emit a `|\` continuation row for merges.
        let mut new_lanes = lanes.clone();
        let extra_parents: Vec<ObjectId> = n.parents.iter().skip(1).copied().collect();
        new_lanes[col] = n.parents.first().copied();
        for ep in &extra_parents {
            new_lanes.push(Some(*ep));
        }
        if !extra_parents.is_empty() {
            // Continuation: emit `\` chars for each new column to the right
            // of `col`.
            let mut cont = String::new();
            for (i, lane) in new_lanes.iter().enumerate() {
                if i > 0 {
                    cont.push(' ');
                }
                if i <= col {
                    cont.push(if lane.is_some() { '|' } else { ' ' });
                } else {
                    cont.push('\\');
                }
            }
            let _ = writeln!(out, "{cont}");
        }
        // Compact: drop dead trailing lanes; merge duplicate adjacent lanes.
        lanes = compact_lanes(&new_lanes);
    }
}

fn compact_lanes(lanes: &[Option<ObjectId>]) -> Vec<Option<ObjectId>> {
    // Merge any duplicate lane targets (two branches converging on the same
    // parent collapse into one); preserve order; trim trailing Nones.
    let mut out: Vec<Option<ObjectId>> = Vec::new();
    let mut seen: HashSet<ObjectId> = HashSet::new();
    for &l in lanes {
        match l {
            Some(id) => {
                if seen.insert(id) {
                    out.push(Some(id));
                }
            }
            None => out.push(None),
        }
    }
    while matches!(out.last(), Some(None)) {
        out.pop();
    }
    out
}

fn write_commit_oneline_after_marker(out: &mut String, n: &Node, oneline: bool) {
    let hex = n.id.to_hex();
    let short = &hex[..hex.len().min(8)];
    let first_line = n.message.lines().next().unwrap_or("");
    if oneline {
        let _ = writeln!(out, "{short} {first_line}");
    } else {
        let _ = writeln!(out, "commit {hex}");
        let _ = writeln!(out, "Author: {}", primary_author_name(&n.author));
        if n.timestamp > 0 {
            let _ = writeln!(out, "Date:   {}", n.timestamp);
        }
        out.push('\n');
        for line in n.message.lines() {
            let _ = writeln!(out, "    {line}");
        }
        out.push('\n');
    }
}

fn write_commit(out: &mut String, n: &Node, oneline: bool, prefix: &str) {
    let hex = n.id.to_hex();
    let short = &hex[..hex.len().min(8)];
    let first_line = n.message.lines().next().unwrap_or("");
    if oneline {
        let _ = writeln!(out, "{prefix}{short} {first_line}");
    } else {
        let _ = writeln!(out, "{prefix}commit {hex}");
        let _ = writeln!(out, "{prefix}Author: {}", primary_author_name(&n.author));
        if n.timestamp > 0 {
            let _ = writeln!(out, "{prefix}Date:   {}", n.timestamp);
        }
        out.push('\n');
        for line in n.message.lines() {
            let _ = writeln!(out, "{prefix}    {line}");
        }
        out.push('\n');
    }
}

fn all_ref_tips(gyt_dir: &std::path::Path) -> Result<Vec<ObjectId>> {
    let mut ids = Vec::new();
    let dirs = ["refs/heads", "refs/tags", "refs/remotes"];
    for d in &dirs {
        let p = gyt_dir.join(d);
        if !p.is_dir() {
            continue;
        }
        if let Ok(entries) = std::fs::read_dir(&p) {
            ids.extend(entries.flatten().filter_map(|entry| {
                if entry.file_type().is_ok_and(|t| t.is_file()) {
                    let ref_name = format!("{d}/{}", entry.file_name().to_string_lossy());
                    refs::read_ref(gyt_dir, &ref_name).ok()
                } else {
                    None
                }
            }));
        }
    }
    Ok(ids)
}

fn parse_timestamp(s: &str) -> Option<i64> {
    let parts: Vec<&str> = s.rsplitn(3, ' ').collect();
    if parts.len() >= 2 {
        parts.get(1)?.parse().ok()
    } else {
        None
    }
}

fn primary_author_name(a: &str) -> String {
    if let Some(idx) = a.rfind('>') {
        return a[..=idx].to_string();
    }
    a.to_string()
}

// Silence unused-import warnings (Commit is used through commit::read).
#[allow(dead_code)]
fn _suppress_unused(_: Commit) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};
    use crate::config::Config;
    use std::fs;

    fn setup_log_repo(prefix: &str) -> (std::path::PathBuf, Repo) {
        let dir = tmp_dir(prefix);
        crate::cmd::init::init_at(&dir).unwrap();
        let cfg = Config {
            user_name: Some("T".into()),
            user_email: Some("t@x".into()),
            ..Config::default()
        };
        cfg.write(&dir.join(".gyt")).unwrap();
        (dir.clone(), Repo::open(&dir).unwrap())
    }

    fn make_commit(dir: &std::path::Path, msg: &str) {
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), msg.to_string()]).unwrap();
        std::env::set_current_dir(&prev).unwrap();
    }

    fn opts_simple(oneline: bool, graph: bool, all: bool) -> Options {
        let mut o = Options::new();
        o.oneline = oneline;
        o.graph = graph;
        o.all = all;
        o
    }

    #[test]
    fn log_walks_history() {
        let _g = lock();
        let (dir, repo) = setup_log_repo("gyt-log");
        fs::write(dir.join("a.txt"), b"a").unwrap();
        make_commit(&dir, "first");
        fs::write(dir.join("a.txt"), b"aa").unwrap();
        make_commit(&dir, "second");
        let out = format_log(&repo, &opts_simple(false, false, false)).unwrap();
        assert!(out.contains("first"), "should contain first msg: {out:?}");
        assert!(out.contains("second"), "should contain second msg: {out:?}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn log_oneline_works() {
        let _g = lock();
        let (dir, repo) = setup_log_repo("gyt-log-oneline");
        fs::write(dir.join("a.txt"), b"a").unwrap();
        make_commit(&dir, "test");
        let out = format_log(&repo, &opts_simple(true, false, false)).unwrap();
        assert!(out.contains("test"), "oneline should show message: {out:?}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn log_graph_emits_marker_per_commit() {
        let _g = lock();
        let (dir, repo) = setup_log_repo("gyt-log-graph");
        fs::write(dir.join("a.txt"), b"a").unwrap();
        make_commit(&dir, "first");
        let out = format_log(&repo, &opts_simple(true, true, false)).unwrap();
        // First non-empty line should begin with the lane marker '*'.
        let first_line = out.lines().next().unwrap_or("");
        assert!(
            first_line.starts_with('*'),
            "graph output line should start with '*': {out:?}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn log_all_shows_multiple_branches() {
        let _g = lock();
        let (dir, _repo) = setup_log_repo("gyt-log-all");
        fs::write(dir.join("a.txt"), b"a").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "root".to_string()]).unwrap();
        crate::cmd::branch::run(&["feature".to_string()]).unwrap();
        crate::cmd::switch::run(&["feature".to_string()]).unwrap();
        fs::write(dir.join("b.txt"), b"b").unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "feat".to_string()]).unwrap();
        crate::cmd::switch::run(&["main".to_string()]).unwrap();
        std::env::set_current_dir(&prev).unwrap();

        let out = format_log(&Repo::open(&dir).unwrap(), &opts_simple(true, false, true)).unwrap();
        assert!(out.contains("root"), "should contain 'root': {out:?}");
        assert!(out.contains("feat"), "should contain 'feat': {out:?}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn log_no_commits_shows_message() {
        let _g = lock();
        let (dir, repo) = setup_log_repo("gyt-log-empty");
        let out = format_log(&repo, &opts_simple(false, false, false)).unwrap();
        assert!(
            out.contains("no commits"),
            "should show no-commits msg: {out:?}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn log_grep_filters_messages() {
        let _g = lock();
        let (dir, repo) = setup_log_repo("gyt-log-grep");
        fs::write(dir.join("a.txt"), b"a").unwrap();
        make_commit(&dir, "fix: thing");
        fs::write(dir.join("a.txt"), b"aa").unwrap();
        make_commit(&dir, "feat: other");
        let mut opts = opts_simple(true, false, false);
        opts.grep = Some("fix".into());
        let out = format_log(&repo, &opts).unwrap();
        assert!(out.contains("fix: thing"), "{out:?}");
        assert!(!out.contains("feat: other"), "grep didn't filter: {out:?}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn log_n_limits_count() {
        let _g = lock();
        let (dir, repo) = setup_log_repo("gyt-log-n");
        fs::write(dir.join("a.txt"), b"1").unwrap();
        make_commit(&dir, "first");
        fs::write(dir.join("a.txt"), b"2").unwrap();
        make_commit(&dir, "second");
        fs::write(dir.join("a.txt"), b"3").unwrap();
        make_commit(&dir, "third");
        let mut opts = opts_simple(true, false, false);
        opts.max_count = Some(2);
        let out = format_log(&repo, &opts).unwrap();
        // Newest first ⇒ "third" and "second", not "first".
        assert!(out.contains("third"));
        assert!(out.contains("second"));
        assert!(!out.contains("first"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn log_path_filter_skips_untouched_commits() {
        let _g = lock();
        let (dir, repo) = setup_log_repo("gyt-log-path");
        fs::write(dir.join("a.txt"), b"a").unwrap();
        make_commit(&dir, "touches-a");
        fs::write(dir.join("b.txt"), b"b").unwrap();
        make_commit(&dir, "touches-b");
        let mut opts = opts_simple(true, false, false);
        opts.paths.push("a.txt".to_string());
        let out = format_log(&repo, &opts).unwrap();
        assert!(out.contains("touches-a"), "{out:?}");
        assert!(!out.contains("touches-b"), "{out:?}");
        fs::remove_dir_all(&dir).unwrap();
    }
}
