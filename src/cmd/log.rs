use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::object::commit;
use crate::refs;
use crate::repo::Repo;
use std::collections::{HashMap, HashSet};
use std::fmt::Write;

// Reason: these are four independent CLI flags (oneline, graph, all,
// show_signature). Bundling them into an enum would force users to
// remember mutually-exclusive combinations, which is contrary to how the
// flags behave (any subset is legal). The struct shape mirrors the CLI
// surface and is the clearest representation.
#[expect(clippy::struct_excessive_bools, reason = "discrete capability flags read independently at use sites — collapsing into a state machine would obscure intent")]
struct Options {
    oneline: bool,
    graph: bool,
    all: bool,
    show_signature: bool,
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
            show_signature: false,
            author: None,
            grep: None,
            since: None,
            until: None,
            max_count: None,
            paths: Vec::new(),
        }
    }
}
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
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
            "--show-signature" => opts.show_signature = true,
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
    tz_offset: String,
    author: String,
    message: String,
    tree: ObjectId,
    /// Raw `Commit` re-fetched on demand for signature verification.
    /// Filled lazily by the render path when `--show-signature` is set;
    /// avoids paying the BLAKE3 + ed25519 cost during the topo walk for
    /// the common case where signatures aren't being displayed.
    signature_b64: Option<String>,
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

fn read_shallow_set(gyt_dir: &std::path::Path) -> std::collections::HashSet<ObjectId> {
    let mut out = std::collections::HashSet::new();
    let Ok(text) = std::fs::read_to_string(gyt_dir.join("shallow")) else {
        return out;
    };
    for line in text.lines() {
        if let Ok(id) = ObjectId::from_hex(line.trim()) {
            out.insert(id);
        }
    }
    out
}

fn path_under(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    path == prefix || path.starts_with(&format!("{prefix}/"))
}

fn walk(gyt_dir: &std::path::Path, roots: &[ObjectId]) -> Result<HashMap<ObjectId, Node>> {
    // Shallow clones leave parent commits absent on disk by design. We
    // consult `.gyt/shallow` so we can distinguish "this commit is an
    // intentional boundary" from "this commit is missing because the
    // store is corrupt or a pack file is truncated" — silently swallowing
    // the latter would let data loss go unnoticed.
    let shallow = read_shallow_set(gyt_dir);
    let mut nodes: HashMap<ObjectId, Node> = HashMap::new();
    let mut stack: Vec<ObjectId> = roots.to_vec();
    while let Some(id) = stack.pop() {
        if nodes.contains_key(&id) {
            continue;
        }
        if shallow.contains(&id) {
            // Intentional shallow boundary: stop walking past this
            // commit. The boundary commit itself is still recorded.
            // Read it so its metadata appears in the log output.
            let c = match commit::read(gyt_dir, &id) {
                Ok(c) => c,
                Err(_) => continue,
            };
            let (ts, tz) = parse_timestamp_tz(&c.committer);
            let author = c.authors.first().cloned().unwrap_or_default();
            nodes.insert(
                id,
                Node {
                    id,
                    parents: Vec::new(),
                    timestamp: ts.unwrap_or(0),
                    tz_offset: tz,
                    author,
                    signature_b64: c.signature.clone(),
                    message: c.message,
                    tree: c.tree,
                },
            );
            continue;
        }
        let c = commit::read(gyt_dir, &id)?;
        let (ts, tz) = parse_timestamp_tz(&c.committer);
        let author = c.authors.first().cloned().unwrap_or_default();
        for p in &c.parents {
            stack.push(*p);
        }
        nodes.insert(
            id,
            Node {
                id,
                parents: c.parents.clone(),
                timestamp: ts.unwrap_or(0),
                tz_offset: tz,
                author,
                signature_b64: c.signature.clone(),
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
        write_commit(out, n, opts, "");
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
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
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
        write_commit_oneline_after_marker(out, n, opts);

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
#[expect(
    clippy::string_slice,
    reason = "byte offsets used are at ASCII / char-boundary positions by construction"
)]
fn write_commit_oneline_after_marker(out: &mut String, n: &Node, opts: &Options) {
    let hex = n.id.to_hex();
    let short = &hex[..hex.len().min(8)];
    let first_line = n.message.lines().next().unwrap_or("");
    if opts.oneline {
        if opts.show_signature {
            let _ = writeln!(out, "{short} [{}] {first_line}", short_sig_status(n));
        } else {
            let _ = writeln!(out, "{short} {first_line}");
        }
    } else {
        let _ = writeln!(out, "commit {hex}");
        let _ = writeln!(out, "Author: {}", primary_author_name(&n.author));
        if n.timestamp > 0 {
            let _ = writeln!(out, "Date:   {}", format_iso8601(n.timestamp, &n.tz_offset));
        }
        if opts.show_signature {
            let _ = writeln!(out, "Signature: {}", verbose_sig_status(n));
        }
        out.push('\n');
        for line in n.message.lines() {
            let _ = writeln!(out, "    {line}");
        }
        out.push('\n');
    }
}
#[expect(
    clippy::string_slice,
    reason = "byte offsets used are at ASCII / char-boundary positions by construction"
)]
fn write_commit(out: &mut String, n: &Node, opts: &Options, prefix: &str) {
    let hex = n.id.to_hex();
    let short = &hex[..hex.len().min(8)];
    let first_line = n.message.lines().next().unwrap_or("");
    if opts.oneline {
        if opts.show_signature {
            let _ = writeln!(
                out,
                "{prefix}{short} [{}] {first_line}",
                short_sig_status(n)
            );
        } else {
            let _ = writeln!(out, "{prefix}{short} {first_line}");
        }
    } else {
        let _ = writeln!(out, "{prefix}commit {hex}");
        let _ = writeln!(out, "{prefix}Author: {}", primary_author_name(&n.author));
        if n.timestamp > 0 {
            let _ = writeln!(
                out,
                "{prefix}Date:   {}",
                format_iso8601(n.timestamp, &n.tz_offset)
            );
        }
        if opts.show_signature {
            let _ = writeln!(out, "{prefix}Signature: {}", verbose_sig_status(n));
        }
        out.push('\n');
        for line in n.message.lines() {
            let _ = writeln!(out, "{prefix}    {line}");
        }
        out.push('\n');
    }
}

fn short_sig_status(n: &Node) -> &'static str {
    match verify_node(n) {
        SigStatus::Unsigned => "U",
        SigStatus::Good => "G",
        SigStatus::Bad => "B",
    }
}

fn verbose_sig_status(n: &Node) -> &'static str {
    match verify_node(n) {
        SigStatus::Unsigned => "unsigned",
        SigStatus::Good => "good ed25519 signature",
        SigStatus::Bad => "BAD signature",
    }
}

enum SigStatus {
    Unsigned,
    Good,
    Bad,
}

fn verify_node(n: &Node) -> SigStatus {
    let Some(b64) = &n.signature_b64 else {
        return SigStatus::Unsigned;
    };
    // Re-read the commit so we have the canonical payload bytes — we
    // already buffered `tree`, `parents`, etc. on Node, but not the raw
    // committer/author strings in the on-disk canonical form. The cost is
    // one extra object read per signed commit shown.
    // (Skipped if no signature.)
    // Implementation note: gyt verify uses `commit_payload_without_sig`
    // which reconstructs canonical bytes from a Commit struct, so we
    // need to reconstruct a Commit. Easier: re-read from disk.
    // We deliberately don't keep this on Node by default because most log
    // invocations don't need signatures and this would slow down the
    // common case.
    // Pass-through to the same path `gyt show --show-signature` uses.
    // Errors are treated as Bad so the user sees something visibly wrong.
    let dummy = crate::object::commit::Commit {
        tree: n.tree,
        parents: n.parents.clone(),
        authors: vec![n.author.clone()],
        // Best-effort fields — only the ones from the canonical payload
        // matter. The signing payload built by `commit_payload_without_sig`
        // walks all author lines, the committer line, ai/reviewer lines
        // and the message; without re-reading we can't reproduce them
        // exactly. So in the common, signed case we DO re-read the
        // commit object from disk to get the canonical struct.
        committer: String::new(),
        ai_assists: vec![],
        reviewers: vec![],
        signature: None,
        message: n.message.clone(),
    };
    // Re-read from disk to get the exact canonical encoding for verify.
    let _ = dummy; // Placeholder so the closure compiles when called from log.rs.
    // We need access to a repo path here. The function is called from
    // render which already opened the repo; rather than threading it
    // through, just compute by re-reading the object via store::read.
    // The Node's `id` lets us look it up.
    let bytes = match find_repo_root_via_cwd().and_then(|gyt| {
        crate::object::commit::read(&gyt, &n.id).ok().map(|c| (gyt, c))
    }) {
        Some((_gyt, c)) => crate::cmd::signing::commit_payload_without_sig(&c),
        None => return SigStatus::Bad,
    };
    match crate::cmd::signing::verify_signature(&bytes, b64, None) {
        Ok(true) => SigStatus::Good,
        _ => SigStatus::Bad,
    }
}

/// Locate the active `.gyt` directory by walking up from the cwd. Falls
/// back to None if not inside a repo (which shouldn't happen during `log`,
/// but we don't want to panic from a status-rendering helper).
fn find_repo_root_via_cwd() -> Option<std::path::PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    crate::repo::Repo::open(&cwd).ok().map(|r| r.gyt_dir)
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

/// Parse "<name> <email> <unix-secs> <tz-offset>" → (timestamp, tz_offset).
/// Returns "+0000" as the default TZ if missing or malformed.
fn parse_timestamp_tz(s: &str) -> (Option<i64>, String) {
    let parts: Vec<&str> = s.rsplitn(3, ' ').collect();
    let tz = parts.first().map_or_else(|| "+0000".to_string(), |s| (*s).to_string());
    let ts = parts.get(1).and_then(|t| t.parse::<i64>().ok());
    (ts, tz)
}

/// Render a unix timestamp + "+HHMM" tz offset as a human ISO-8601 string,
/// e.g. `2026-05-13 14:30:00 +0000`. Uses the proleptic Gregorian calendar
/// via Howard Hinnant's `civil_from_days` algorithm — pure arithmetic, no
/// external date library, valid for all `i64` second counts that fit in a
/// reasonable era window (effectively all of human history).
#[expect(
    clippy::integer_division,
    clippy::modulo_arithmetic,
    reason = "intentional truncating integer division; operands are non-negative by construction"
)]
fn format_iso8601(unix_secs: i64, tz_offset: &str) -> String {
    // Apply the tz offset to display local time then re-tag the printed
    // offset. Format of tz_offset: "+HHMM" or "-HHMM".
    let (sign, off_h, off_m) = parse_tz(tz_offset);
    let shifted = unix_secs + i64::from(sign) * (i64::from(off_h) * 3600 + i64::from(off_m) * 60);
    let day = shifted.div_euclid(86_400);
    let sec_of_day = shifted.rem_euclid(86_400);
    let (y, mo, d) = civil_from_days(day);
    let h = sec_of_day / 3600;
    let mi = (sec_of_day % 3600) / 60;
    let s = sec_of_day % 60;
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02} {tz_offset}")
}
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
fn parse_tz(tz: &str) -> (i32, u32, u32) {
    // Accept "+HHMM" / "-HHMM"; default to UTC on parse failure.
    let bytes = tz.as_bytes();
    if bytes.len() != 5 {
        return (1, 0, 0);
    }
    let sign = match bytes[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return (1, 0, 0),
    };
    let h: u32 = std::str::from_utf8(&bytes[1..3])
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let m: u32 = std::str::from_utf8(&bytes[3..5])
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (sign, h, m)
}

/// Howard Hinnant's `civil_from_days`: convert a count of days since the
/// Unix epoch (1970-01-01) to (year, month, day) in the proleptic
/// Gregorian calendar. See
/// <https://howardhinnant.github.io/date_algorithms.html>.
#[expect(clippy::cast_possible_wrap, reason = "era arithmetic stays within i64 even at the extremes; widening would only hide that")] // Reason: era arithmetic stays within i64 even at the extremes; widening to i128 would only hide that.
#[expect(
    clippy::integer_division,
    reason = "intentional truncating integer division"
)]
const fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // 0..146_096
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // 0..399
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // 0..365
    let mp = (5 * doy + 2) / 153; // 0..11
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // 1..31
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // 1..12
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
#[expect(
    clippy::string_slice,
    reason = "byte offsets used are at ASCII / char-boundary positions by construction"
)]
fn primary_author_name(a: &str) -> String {
    if let Some(idx) = a.rfind('>') {
        return a[..=idx].to_string();
    }
    a.to_string()
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
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
