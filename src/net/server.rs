// Production HTTP/1.1 server for the gith1b API.
//
// Serves:
//   - REST JSON API under /api/
//   - Static files for the frontend from a configurable webroot
//   - The gyt wire protocol under /info/refs, /objects/want, etc.
//
// The server is single-threaded per connection with graceful shutdown
// support. Multi-repo: the `repos_root` directory contains
// `:owner/:name/` directories, each a gyt worktree (with .gyt inside).

use crate::cmd::util;
use crate::diff;
use crate::errors::Result;
use crate::hash::ObjectId;
use crate::net::api::{
    self, BlobInfo, CommitInfo, DiffFileInfo, DiffHunkInfo, DiffLine, RefInfo, RepoInfo,
    TreeEntryInfo,
};
use crate::net::router::{self, Handler};
use crate::object::{commit, tree};
use crate::refs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

pub struct ServeConfig {
    pub listen_addr: String,
    pub repos_root: PathBuf,
    pub webroot: PathBuf,
}

struct Request {
    method: String,
    target: String,
    body: Vec<u8>,
}

pub fn serve(config: &ServeConfig) -> Result<()> {
    let listener = TcpListener::bind(&config.listen_addr)?;
    let addr = listener.local_addr()?;
    eprintln!("gyt serve: listening on http://{addr}");

    let state = Arc::new(ServerState {
        repos_root: config.repos_root.clone(),
        webroot: config.webroot.clone(),
        shutdown: Mutex::new(false),
    });

    for stream in listener.incoming() {
        let st = state.clone();
        if *state.shutdown.lock().unwrap() {
            break;
        }
        match stream {
            Ok(s) => {
                thread::spawn(move || {
                    let _ = handle_conn(s, &st);
                });
            }
            Err(_) => break,
        }
    }
    Ok(())
}

struct ServerState {
    repos_root: PathBuf,
    webroot: PathBuf,
    shutdown: Mutex<bool>,
}

fn handle_conn(stream: std::net::TcpStream, state: &ServerState) -> std::io::Result<()> {
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;

    let req = match read_request(&mut reader) {
        Ok(r) => r,
        Err(e) => {
            write_response(
                &mut writer,
                400,
                "Bad Request",
                "text/plain",
                e.to_string().as_bytes(),
            )?;
            return Ok(());
        }
    };

    let (path, query) = match req.target.find('?') {
        Some(i) => (&req.target[..i], Some(&req.target[i + 1..])),
        None => (req.target.as_str(), None),
    };

    let params = router::query_params(query);
    let route = router::route(&req.method, path);

    let (status, reason, body, ctype) = dispatch(route, &params, &req.body, state);

    write_response(&mut writer, status, &reason, &ctype, &body)
}

fn dispatch(
    route: router::RouteMatch,
    params: &[(String, String)],
    _body: &[u8],
    state: &ServerState,
) -> (u16, String, Vec<u8>, String) {
    match route.handler {
        Handler::RepoList => repo_list(state, params),
        Handler::RepoInfo => repo_info(state, params),
        Handler::CommitList => commit_list(state, params),
        Handler::CommitDetail => commit_detail(state, params),
        Handler::TreeBrowse => tree_browse(state, params),
        Handler::RefsList => refs_list(state, params),
        Handler::DiffRevs => diff_revs(state, params),
        Handler::Search => search(state, params),
        Handler::StaticFile => static_file(state, params),
        Handler::NotFound => (
            404,
            "Not Found".into(),
            b"not found".to_vec(),
            "text/plain".into(),
        ),
    }
}

fn write_response(
    w: &mut impl Write,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let mut out = Vec::with_capacity(256 + body.len());
    out.extend_from_slice(format!("HTTP/1.1 {status} {reason}\r\n").as_bytes());
    out.extend_from_slice(b"Connection: close\r\n");
    out.extend_from_slice(b"Access-Control-Allow-Origin: *\r\n");
    out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    out.extend_from_slice(format!("Content-Type: {content_type}\r\n").as_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    w.write_all(&out)?;
    w.flush()
}

fn read_request<R: BufRead>(reader: &mut R) -> std::io::Result<Request> {
    let mut header_buf = Vec::with_capacity(4096);
    loop {
        let n_before = header_buf.len();
        let n = reader.read_until(b'\n', &mut header_buf)?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof in request",
            ));
        }
        if header_buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if header_buf.len() == n_before {
            return Err(std::io::Error::other("no progress"));
        }
        if header_buf.len() > 64 * 1024 {
            return Err(std::io::Error::other("headers too large"));
        }
    }
    let header_str =
        std::str::from_utf8(&header_buf).map_err(|_| std::io::Error::other("non-utf8 headers"))?;
    let mut lines = header_str.split("\r\n");
    let req_line = lines
        .next()
        .ok_or_else(|| std::io::Error::other("no request line"))?;
    let mut parts = req_line.splitn(3, ' ');
    let method = parts
        .next()
        .ok_or_else(|| std::io::Error::other("bad request line"))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| std::io::Error::other("bad request line"))?
        .to_string();

    let mut content_length: usize = 0;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("content-length")
        {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }
    Ok(Request {
        method,
        target,
        body,
    })
}

// ---------- Helper: resolve owner/name to .gyt path ----------

fn repo_path(state: &ServerState, owner: &str, name: &str) -> Option<PathBuf> {
    let candidate = state.repos_root.join(owner).join(name);
    if candidate.join(".gyt").is_dir() {
        Some(candidate)
    } else {
        None
    }
}

fn open_repo(state: &ServerState, owner: &str, name: &str) -> Option<crate::repo::Repo> {
    let path = repo_path(state, owner, name)?;
    crate::repo::Repo::open(&path).ok()
}

fn json_response(body: &str) -> (u16, String, Vec<u8>, String) {
    (
        200,
        "OK".into(),
        body.as_bytes().to_vec(),
        "application/json".into(),
    )
}

fn error_response(status: u16, msg: &str) -> (u16, String, Vec<u8>, String) {
    let json = format!(r#"{{"error":{}}}"#, api::json_string(msg));
    (
        status,
        if status == 404 { "Not Found" } else { "Error" }.into(),
        json.into_bytes(),
        "application/json".into(),
    )
}

// ---------- Handler: repo list ----------

fn repo_list(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let page = api::parse_page(params, 1);
    let per_page = api::parse_per_page(params, 30, 100);

    let mut repos: Vec<(String, String)> = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&state.repos_root) {
        for entry in entries.flatten() {
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let owner = entry.file_name().to_string_lossy().into_owned();
            if let Ok(sub) = std::fs::read_dir(entry.path()) {
                for se in sub.flatten() {
                    if !se.file_type().is_ok_and(|t| t.is_dir()) {
                        continue;
                    }
                    if se.path().join(".gyt").is_dir() {
                        let name = se.file_name().to_string_lossy().into_owned();
                        repos.push((owner.clone(), name));
                    }
                }
            }
        }
    }
    repos.sort();

    let total = repos.len();
    let start = (page.saturating_sub(1)) * per_page;
    let page_repos: Vec<_> = repos.into_iter().skip(start).take(per_page).collect();

    let items: Vec<String> = page_repos
        .iter()
        .map(|(owner, name)| {
            let info = repo_info_from(state, owner, name);
            info.to_json()
        })
        .collect();

    let body = format!(
        r#"{{"items":[{}],"page":{},"per_page":{},"total":{}}}"#,
        items.join(","),
        page,
        per_page,
        total,
    );
    json_response(&body)
}

fn repo_info_from(state: &ServerState, owner: &str, name: &str) -> RepoInfo {
    let default_branch = if let Some(repo) = open_repo(state, owner, name) {
        match refs::read_head(&repo.gyt_dir) {
            Ok(refs::Head::Symbolic(b)) => b.trim_start_matches("refs/heads/").to_string(),
            _ => "main".to_string(),
        }
    } else {
        "main".to_string()
    };

    let head_commit = open_repo(state, owner, name).and_then(|repo| {
        let head = refs::read_head(&repo.gyt_dir).ok()?;
        refs::resolve(&repo.gyt_dir, &head)
            .ok()
            .flatten()
            .map(super::super::hash::ObjectId::to_hex)
    });

    RepoInfo {
        owner: owner.to_string(),
        name: name.to_string(),
        description: String::new(),
        default_branch,
        head_commit,
    }
}

// ---------- Handler: repo info ----------

fn repo_info(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");

    if repo_path(state, owner, name).is_none() {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    }

    let info = repo_info_from(state, owner, name);
    json_response(&info.to_json())
}

// ---------- Handler: commit list ----------

fn commit_list(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");

    let Some(repo) = open_repo(state, owner, name) else {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    };

    let rev = router::get_param(params, "ref").unwrap_or("HEAD");
    let Ok(start_id) = util::resolve_rev(&repo, rev) else {
        return error_response(404, &format!("revision {rev} not found"));
    };

    let page = api::parse_page(params, 1);
    let per_page = api::parse_per_page(params, 30, 100);

    let mut commits = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cur = Some(start_id);

    while let Some(id) = cur {
        if seen.contains(&id) {
            break;
        }
        seen.insert(id);
        match commit::read(&repo.gyt_dir, &id) {
            Ok(c) => {
                cur = c.parents.first().copied();
                commits.push(CommitInfo {
                    sha: id.to_hex(),
                    tree: c.tree.to_hex(),
                    parents: c.parents.iter().map(|p| p.to_hex()).collect(),
                    authors: c.authors,
                    committer: c.committer,
                    ai_assists: c.ai_assists,
                    reviewers: c.reviewers,
                    message: c.message,
                });
            }
            Err(_) => break,
        }
    }

    let total = commits.len();
    let start_idx = (page.saturating_sub(1)) * per_page;
    let page_commits: Vec<_> = commits.into_iter().skip(start_idx).take(per_page).collect();

    let items: Vec<String> = page_commits.iter().map(super::api::CommitInfo::to_json).collect();
    let body = format!(
        r#"{{"items":[{}],"page":{},"per_page":{},"total":{}}}"#,
        items.join(","),
        page,
        per_page,
        total,
    );
    json_response(&body)
}

// ---------- Handler: commit detail ----------

fn commit_detail(
    state: &ServerState,
    params: &[(String, String)],
) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");
    let sha = router::get_param(params, "sha").unwrap_or("");

    let Some(repo) = open_repo(state, owner, name) else {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    };

    let id = match ObjectId::from_hex(sha) {
        Ok(id) => id,
        Err(e) => return error_response(400, &format!("invalid hash: {e}")),
    };

    let c = match commit::read(&repo.gyt_dir, &id) {
        Ok(c) => c,
        Err(e) => return error_response(404, &format!("commit not found: {e}")),
    };

    let info = CommitInfo {
        sha: id.to_hex(),
        tree: c.tree.to_hex(),
        parents: c.parents.iter().map(|p| p.to_hex()).collect(),
        authors: c.authors,
        committer: c.committer,
        ai_assists: c.ai_assists,
        reviewers: c.reviewers,
        message: c.message,
    };

    json_response(&info.to_json())
}

// ---------- Handler: tree / blob browse ----------

fn tree_browse(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");
    let r#ref = router::get_param(params, "ref").unwrap_or("HEAD");
    let path = router::get_param(params, "path").unwrap_or("");

    let Some(repo) = open_repo(state, owner, name) else {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    };

    let tree_id = match util::resolve_tree(&repo, r#ref) {
        Ok(id) => id,
        Err(e) => return error_response(404, &format!("ref {ref} not found: {e}")),
    };

    if path.is_empty() {
        return list_tree(&repo, &tree_id);
    }

    let segments: Vec<&str> = path.split('/').collect();
    let mut current_tree = tree_id;
    for (i, segment) in segments.iter().enumerate() {
        let entries = match tree::read(&repo.gyt_dir, &current_tree) {
            Ok(e) => e,
            Err(e) => return error_response(500, &format!("tree read error: {e}")),
        };
        let found = entries.iter().find(|e| {
            let name = std::str::from_utf8(&e.name).unwrap_or("");
            name == *segment
        });
        let Some(entry) = found else {
            return error_response(404, &format!("path {path} not found"));
        };

        if entry.mode == tree::MODE_DIR {
            current_tree = entry.hash;
            continue;
        }

        if i == segments.len() - 1 {
            if entry.mode == tree::MODE_DIR {
                return list_tree(&repo, &entry.hash);
            }

            let payload = match crate::object::blob::read(&repo.gyt_dir, &entry.hash) {
                Ok(p) => p,
                Err(e) => return error_response(500, &format!("blob read error: {e}")),
            };
            let content = String::from_utf8_lossy(&payload).into_owned();
            let size = payload.len() as u64;
            let info = BlobInfo {
                path: path.to_string(),
                hash: entry.hash.to_hex(),
                content,
                size,
            };
            return json_response(&info.to_json());
        }

        return error_response(404, &format!("path {path} not found"));
    }

    list_tree(&repo, &current_tree)
}

fn list_tree(repo: &crate::repo::Repo, tree_id: &ObjectId) -> (u16, String, Vec<u8>, String) {
    let entries = match tree::read(&repo.gyt_dir, tree_id) {
        Ok(e) => e,
        Err(e) => return error_response(500, &format!("tree read error: {e}")),
    };

    let items: Vec<String> = entries
        .iter()
        .map(|e| {
            let name = std::str::from_utf8(&e.name)
                .unwrap_or("<invalid>")
                .to_string();
            let kind = if e.mode == tree::MODE_DIR {
                "tree"
            } else {
                "blob"
            };
            let size = if e.mode == tree::MODE_DIR {
                None
            } else {
                crate::object::blob::read(&repo.gyt_dir, &e.hash)
                    .map(|b| b.len() as u64)
                    .ok()
            };
            let info = TreeEntryInfo {
                name,
                mode: e.mode,
                kind: kind.to_string(),
                hash: e.hash.to_hex(),
                size,
            };
            info.to_json()
        })
        .collect();

    let body = format!("[{}]", items.join(","));
    json_response(&body)
}

// ---------- Handler: refs list ----------

fn refs_list(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");

    let Some(repo) = open_repo(state, owner, name) else {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    };

    let default_branch = match refs::read_head(&repo.gyt_dir) {
        Ok(refs::Head::Symbolic(b)) => Some(b),
        _ => None,
    };

    let mut all_refs = Vec::new();

    if let Ok(branches) = refs::list_refs(&repo.gyt_dir, "refs/heads") {
        for (bname, bid) in &branches {
            let short = bname.trim_start_matches("refs/heads/");
            all_refs.push(RefInfo {
                name: short.to_string(),
                commit: bid.to_hex(),
                is_default: default_branch.as_deref() == Some(bname),
            });
        }
    }

    if let Ok(tags) = refs::list_refs(&repo.gyt_dir, "refs/tags") {
        for (tname, tid) in &tags {
            let short = tname.trim_start_matches("refs/tags/");
            all_refs.push(RefInfo {
                name: short.to_string(),
                commit: tid.to_hex(),
                is_default: false,
            });
        }
    }

    let items: Vec<String> = all_refs.iter().map(super::api::RefInfo::to_json).collect();
    let body = format!("[{}]", items.join(","));
    json_response(&body)
}

// ---------- Handler: diff two revs ----------

fn diff_revs(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");
    let base = router::get_param(params, "base").unwrap_or("");
    let head = router::get_param(params, "head").unwrap_or("");

    let Some(repo) = open_repo(state, owner, name) else {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    };

    let base_tree_id = match util::resolve_tree(&repo, base) {
        Ok(id) => id,
        Err(e) => return error_response(404, &format!("base ref {base} not found: {e}")),
    };
    let head_tree_id = match util::resolve_tree(&repo, head) {
        Ok(id) => id,
        Err(e) => return error_response(404, &format!("head ref {head} not found: {e}")),
    };

    let base_files = match util::flatten_tree(&repo, &base_tree_id) {
        Ok(f) => f,
        Err(e) => return error_response(500, &format!("base tree error: {e}")),
    };
    let head_files = match util::flatten_tree(&repo, &head_tree_id) {
        Ok(f) => f,
        Err(e) => return error_response(500, &format!("head tree error: {e}")),
    };

    let mut files: Vec<DiffFileInfo> = Vec::new();
    let mut all_paths: Vec<PathBuf> = base_files
        .keys()
        .chain(head_files.keys())
        .cloned()
        .collect::<std::collections::HashSet<_>>()
        .into_iter()
        .collect();
    all_paths.sort();

    for path in &all_paths {
        let path_str = path.to_string_lossy().into_owned();
        let old_blob = base_files
            .get(path)
            .and_then(|(_, id)| crate::object::blob::read(&repo.gyt_dir, id).ok());
        let new_blob = head_files
            .get(path)
            .and_then(|(_, id)| crate::object::blob::read(&repo.gyt_dir, id).ok());

        let old_lines: Vec<&[u8]> = match &old_blob {
            Some(b) => diff::split_lines(b),
            None => vec![],
        };
        let new_lines: Vec<&[u8]> = match &new_blob {
            Some(b) => diff::split_lines(b),
            None => vec![],
        };

        let ops = diff::myers(&old_lines, &new_lines);
        if ops.iter().all(|op| matches!(op, diff::DiffOp::Equal(_))) {
            continue;
        }

        let hunks = build_hunks(&ops);
        files.push(DiffFileInfo {
            path: path_str,
            hunks,
        });
    }

    let items: Vec<String> = files.iter().map(super::api::DiffFileInfo::to_json).collect();
    let body = format!("[{}]", items.join(","));
    json_response(&body)
}

fn build_hunks(ops: &[diff::DiffOp<'_>]) -> Vec<DiffHunkInfo> {
    let mut hunks: Vec<DiffHunkInfo> = Vec::new();
    let mut old_no: u64 = 0;
    let mut new_no: u64 = 0;
    let mut current_lines: Vec<DiffLine> = Vec::new();
    let mut hunk_old_start: u64 = 0;
    let mut hunk_new_start: u64 = 0;
    let mut in_hunk = false;

    for op in ops {
        match op {
            diff::DiffOp::Equal(_line) => {
                if in_hunk && !current_lines.is_empty() {
                    hunks.push(DiffHunkInfo {
                        old_start: hunk_old_start,
                        old_count: old_no - hunk_old_start,
                        new_start: hunk_new_start,
                        new_count: new_no - hunk_new_start,
                        lines: std::mem::take(&mut current_lines),
                    });
                }
                old_no += 1;
                new_no += 1;
                in_hunk = false;
            }
            diff::DiffOp::Delete(line) => {
                if !in_hunk {
                    hunk_old_start = old_no;
                    hunk_new_start = new_no;
                    in_hunk = true;
                }
                current_lines.push(DiffLine {
                    old_no: Some(old_no),
                    new_no: None,
                    kind: "delete".to_string(),
                    text: String::from_utf8_lossy(line).into_owned(),
                });
                old_no += 1;
            }
            diff::DiffOp::Insert(line) => {
                if !in_hunk {
                    hunk_old_start = old_no;
                    hunk_new_start = new_no;
                    in_hunk = true;
                }
                current_lines.push(DiffLine {
                    old_no: None,
                    new_no: Some(new_no),
                    kind: "insert".to_string(),
                    text: String::from_utf8_lossy(line).into_owned(),
                });
                new_no += 1;
            }
        }
    }

    if !current_lines.is_empty() {
        hunks.push(DiffHunkInfo {
            old_start: hunk_old_start,
            old_count: old_no - hunk_old_start,
            new_start: hunk_new_start,
            new_count: new_no - hunk_new_start,
            lines: current_lines,
        });
    }

    hunks
}

// ---------- Handler: search ----------

fn search(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let owner = router::get_param(params, "owner").unwrap_or("");
    let name = router::get_param(params, "name").unwrap_or("");

    let query = router::get_param(params, "q").unwrap_or("").to_string();
    let kind = router::get_param(params, "kind")
        .unwrap_or("commits")
        .to_string();

    if query.is_empty() {
        return json_response(r#"{"kind":"none","items":[]}"#);
    }

    let Some(repo) = open_repo(state, owner, name) else {
        return error_response(404, &format!("repo {owner}/{name} not found"));
    };

    match kind.as_str() {
        "commits" => search_commits(&repo, &query),
        "code" => search_code(&repo, &query),
        _ => json_response(r#"{"kind":"none","items":[]}"#),
    }
}

fn search_commits(repo: &crate::repo::Repo, query: &str) -> (u16, String, Vec<u8>, String) {
    let head = match refs::read_head(&repo.gyt_dir) {
        Ok(h) => h,
        Err(_) => return json_response(r#"{"kind":"commits","items":[]}"#),
    };
    let start = match refs::resolve(&repo.gyt_dir, &head) {
        Ok(Some(id)) => id,
        _ => return json_response(r#"{"kind":"commits","items":[]}"#),
    };

    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut cur = Some(start);
    let query_lower = query.to_ascii_lowercase();

    while let Some(id) = cur {
        if seen.contains(&id) {
            break;
        }
        seen.insert(id);
        if let Ok(c) = commit::read(&repo.gyt_dir, &id) {
            if c.message.to_ascii_lowercase().contains(&query_lower) {
                results.push(api::json_string(&id.to_hex()));
            }
            cur = c.parents.first().copied();
        } else {
            break;
        }
        if results.len() >= 20 {
            break;
        }
    }

    let body = format!(r#"{{"kind":"commits","items":[{}]}}"#, results.join(","));
    json_response(&body)
}

fn search_code(repo: &crate::repo::Repo, query: &str) -> (u16, String, Vec<u8>, String) {
    let head = match refs::read_head(&repo.gyt_dir) {
        Ok(h) => h,
        Err(_) => return json_response(r#"{"kind":"code","items":[]}"#),
    };
    let _start = match refs::resolve(&repo.gyt_dir, &head) {
        Ok(Some(id)) => id,
        _ => return json_response(r#"{"kind":"code","items":[]}"#),
    };
    let tree_id = match util::resolve_tree(repo, "HEAD") {
        Ok(id) => id,
        Err(_) => return json_response(r#"{"kind":"code","items":[]}"#),
    };

    let files = match util::flatten_tree(repo, &tree_id) {
        Ok(f) => f,
        Err(_) => return json_response(r#"{"kind":"code","items":[]}"#),
    };

    let query_lower = query.to_ascii_lowercase();
    let mut results = Vec::new();

    for (path, (_, id)) in &files {
        if results.len() >= 20 {
            break;
        }
        if let Ok(blob) = crate::object::blob::read(&repo.gyt_dir, id) {
            let content = String::from_utf8_lossy(&blob);
            if content.to_ascii_lowercase().contains(&query_lower) {
                results.push(api::json_string(&path.to_string_lossy()));
            }
        }
    }

    let body = format!(r#"{{"kind":"code","items":[{}]}}"#, results.join(","));
    json_response(&body)
}

// ---------- Handler: static file ----------

fn static_file(state: &ServerState, params: &[(String, String)]) -> (u16, String, Vec<u8>, String) {
    let raw_path = router::get_param(params, "path").unwrap_or("");
    if raw_path.is_empty() || raw_path == "/" {
        if let Ok(data) = std::fs::read(state.webroot.join("index.html")) {
            return (200, "OK".into(), data, "text/html; charset=utf-8".into());
        }
        return (
            200,
            "OK".into(),
            b"<h1>gith1b</h1>".to_vec(),
            "text/html".into(),
        );
    }

    let rel = raw_path.trim_start_matches('/');
    let file_path = state.webroot.join(rel);

    if file_path.starts_with(&state.webroot)
        && file_path.exists()
        && file_path.is_file()
        && let Ok(data) = std::fs::read(&file_path)
    {
        let ctype = guess_content_type(rel);
        return (200, "OK".into(), data, ctype);
    }

    (
        404,
        "Not Found".into(),
        b"not found".to_vec(),
        "text/plain".into(),
    )
}

fn guess_content_type(path: &str) -> String {
    match path.rsplit_once('.') {
        Some((_, "html")) => "text/html; charset=utf-8",
        Some((_, "css")) => "text/css; charset=utf-8",
        Some((_, "js")) => "application/javascript; charset=utf-8",
        Some((_, "json")) => "application/json",
        Some((_, "svg")) => "image/svg+xml",
        Some((_, "png")) => "image/png",
        Some((_, "ico")) => "image/x-icon",
        Some((_, "wasm")) => "application/wasm",
        _ => "application/octet-stream",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::init;
    use crate::config::Config;
    use crate::net::router;
    use std::fs;
    use std::sync::{Mutex, MutexGuard};

    static GLOBAL_LOCK: Mutex<()> = Mutex::new(());

    fn lock() -> MutexGuard<'static, ()> {
        GLOBAL_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(prefix: &str) -> Self {
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn create_test_repo(
        owner: &str,
        name: &str,
        repos_root: &std::path::Path,
    ) -> std::path::PathBuf {
        let dir = repos_root.join(owner).join(name);
        std::fs::create_dir_all(&dir).unwrap();
        init::init_at(&dir).unwrap();
        let cfg = Config {
            user_name: Some("Test User".into()),
            user_email: Some("test@example.com".into()),
            ..Config::default()
        };
        cfg.write(&dir.join(".gyt")).unwrap();
        dir
    }

    fn make_state(repos_root: &std::path::Path, webroot: &std::path::Path) -> Arc<ServerState> {
        Arc::new(ServerState {
            repos_root: repos_root.to_path_buf(),
            webroot: webroot.to_path_buf(),
            shutdown: Mutex::new(false),
        })
    }

    fn body_str(body: &[u8]) -> String {
        String::from_utf8_lossy(body).into_owned()
    }

    #[test]
    fn repo_info_not_found() {
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let _dir = create_test_repo("alice", "myrepo", repos.path());
        let state = make_state(repos.path(), webroot.path());
        let params = vec![
            ("owner".to_string(), "bob".to_string()),
            ("name".to_string(), "nonexist".to_string()),
        ];
        let (status, _reason, _body, ctype) = repo_info(&state, &params);
        assert_eq!(status, 404);
        assert_eq!(ctype, "application/json");
    }

    #[test]
    fn repo_info_found() {
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let _dir = create_test_repo("alice", "myrepo", repos.path());
        let state = make_state(repos.path(), webroot.path());
        let params = vec![
            ("owner".to_string(), "alice".to_string()),
            ("name".to_string(), "myrepo".to_string()),
        ];
        let (status, reason, body, ctype) = repo_info(&state, &params);
        assert_eq!(status, 200);
        assert_eq!(reason, "OK");
        assert_eq!(ctype, "application/json");
        assert!(body_str(&body).contains("alice"));
        assert!(body_str(&body).contains("myrepo"));
    }

    #[test]
    fn repo_list_lists_repos() {
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let _dir = create_test_repo("alice", "myrepo", repos.path());
        let state = make_state(repos.path(), webroot.path());
        let (status, _reason, body, ctype) = repo_list(&state, &[]);
        assert_eq!(status, 200);
        assert_eq!(ctype, "application/json");
        assert!(body_str(&body).contains("alice"));
        assert!(body_str(&body).contains("myrepo"));
    }

    #[test]
    fn refs_lists_branches() {
        let _g = lock();
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let dir = create_test_repo("alice", "myrepo", repos.path());

        fs::write(dir.join("hello.txt"), b"hello").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "initial".to_string()]).unwrap();
        std::env::set_current_dir(&prev).unwrap();

        let state = make_state(repos.path(), webroot.path());
        let params = vec![
            ("owner".to_string(), "alice".to_string()),
            ("name".to_string(), "myrepo".to_string()),
        ];
        let (status, _reason, body, ctype) = refs_list(&state, &params);
        assert_eq!(status, 200);
        assert_eq!(ctype, "application/json");
        assert!(body_str(&body).contains("main"));
    }

    #[test]
    fn commit_list_returns_commits() {
        let _g = lock();
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let dir = create_test_repo("alice", "myrepo", repos.path());

        fs::write(dir.join("hello.txt"), b"hello").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "initial commit".to_string()]).unwrap();
        std::env::set_current_dir(&prev).unwrap();

        let state = make_state(repos.path(), webroot.path());
        let params = vec![
            ("owner".to_string(), "alice".to_string()),
            ("name".to_string(), "myrepo".to_string()),
            ("ref".to_string(), "HEAD".to_string()),
        ];
        let (status, _reason, body, ctype) = commit_list(&state, &params);
        assert_eq!(status, 200);
        assert_eq!(ctype, "application/json");
        assert!(body_str(&body).contains("initial commit"));
    }

    #[test]
    fn tree_browse_root() {
        let _g = lock();
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let dir = create_test_repo("alice", "myrepo", repos.path());

        fs::write(dir.join("hello.txt"), b"hello world").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "initial".to_string()]).unwrap();
        std::env::set_current_dir(&prev).unwrap();

        let state = make_state(repos.path(), webroot.path());
        let params = vec![
            ("owner".to_string(), "alice".to_string()),
            ("name".to_string(), "myrepo".to_string()),
            ("ref".to_string(), "HEAD".to_string()),
            ("path".to_string(), String::new()),
        ];
        let (status, _reason, body, ctype) = tree_browse(&state, &params);
        assert_eq!(status, 200);
        assert_eq!(ctype, "application/json");
        assert!(body_str(&body).contains("hello.txt"));
    }

    #[test]
    fn static_file_returns_index_html() {
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        fs::write(webroot.path().join("index.html"), b"<h1>gith1b</h1>").unwrap();

        let state = make_state(repos.path(), webroot.path());
        let params = vec![("path".to_string(), "/".to_string())];
        let (status, _reason, body, ctype) = static_file(&state, &params);
        assert_eq!(status, 200);
        assert_eq!(ctype, "text/html; charset=utf-8");
        assert!(body.starts_with(b"<h1>gith1b</h1>"));
    }

    #[test]
    fn static_file_404_for_missing() {
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let state = make_state(repos.path(), webroot.path());
        let params = vec![("path".to_string(), "/nonexistent.css".to_string())];
        let (status, _reason, _body, _ctype) = static_file(&state, &params);
        assert_eq!(status, 404);
    }

    #[test]
    fn search_empty_query_returns_empty() {
        let repos = TempDir::new("gyt-server-test");
        let webroot = TempDir::new("gyt-server-web");
        let state = make_state(repos.path(), webroot.path());
        let params = vec![
            ("owner".to_string(), "alice".to_string()),
            ("name".to_string(), "myrepo".to_string()),
            ("q".to_string(), String::new()),
        ];
        let (status, _reason, body, _ctype) = search(&state, &params);
        assert_eq!(status, 200);
        assert!(body_str(&body).contains(r#""kind":"none""#));
    }

    #[test]
    fn router_tests_from_api_module() {
        let m = router::route("GET", "/api/repos/alice/myrepo");
        assert_eq!(m.handler, router::Handler::RepoInfo);
        assert_eq!(router::get_param(&m.params, "owner"), Some("alice"));
        assert_eq!(router::get_param(&m.params, "name"), Some("myrepo"));

        let m = router::route("GET", "/api/repos");
        assert_eq!(m.handler, router::Handler::RepoList);

        let m = router::route("GET", "/api/repos/alice/myrepo/commits");
        assert_eq!(m.handler, router::Handler::CommitList);

        let m = router::route("GET", "/api/repos/alice/myrepo/commits/abc123");
        assert_eq!(m.handler, router::Handler::CommitDetail);

        let m = router::route("GET", "/api/repos/alice/myrepo/tree/main");
        assert_eq!(m.handler, router::Handler::TreeBrowse);

        let m = router::route("GET", "/api/repos/alice/myrepo/refs");
        assert_eq!(m.handler, router::Handler::RefsList);

        let m = router::route("GET", "/api/repos/alice/myrepo/diff/main..feature");
        assert_eq!(m.handler, router::Handler::DiffRevs);

        let m = router::route("GET", "/api/repos/alice/myrepo/search");
        assert_eq!(m.handler, router::Handler::Search);

        let m = router::route("GET", "/css/base.css");
        assert_eq!(m.handler, router::Handler::StaticFile);
    }

    #[test]
    fn api_json_escaping() {
        let info = RepoInfo {
            owner: "alice".into(),
            name: "my/repo".into(),
            description: "has \"quotes\" and\nnewlines".into(),
            default_branch: "main".into(),
            head_commit: None,
        };
        let json = info.to_json();
        assert!(json.contains(r#"\"quotes\""#));
        assert!(json.contains("\\n"));
    }
}
