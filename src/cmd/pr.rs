// `gyt pr` — CLI for in-repo pull requests.
//
// Subcommands:
//   new <title> --source <branch> --target <branch> [-m body]
//   list   [--state open|closed|merged|all]
//   show <N>
//   comment <N> -m <body>
//   close <N> [--reason ...]
//   reopen <N>
//   merge <N> [--no-ff]
//   ci-run <N>          run .gyt-ci/*.wasm on the source ref and record result
//   label <N> --add a,b --remove c
//   assign <N> --add "Name <email>" --remove ...
//
// All writes take repo.lock(). The merge subcommand only modifies the
// TARGET ref locally — the user pushes it to publish. The server's
// existing fast-forward gate on refs/heads/* is what enforces merge
// safety on the wire.

use crate::ci_wasm::{collect_wasm_scripts, run_ci_wasm};
use crate::cmd::merge as merge_cmd;
use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::issues;
use crate::prs::{self, Pr, PrEvent, PrEventKind, PrState};
use crate::refs;
use crate::repo::Repo;
use std::io::Read as _;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn run(args: &[String]) -> Result<()> {
    let Some((sub, rest)) = args.split_first() else {
        print_usage();
        return Ok(());
    };
    match sub.as_str() {
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        "new" => cmd_new(rest),
        "list" | "ls" => cmd_list(rest),
        "show" => cmd_show(rest),
        "comment" => cmd_comment(rest),
        "close" => cmd_close(rest),
        "reopen" => cmd_reopen(rest),
        "merge" => cmd_merge(rest),
        "ci-run" => cmd_ci_run(rest),
        "label" => cmd_label(rest),
        "assign" => cmd_assign(rest),
        other => Err(GytError::InvalidArgument(format!(
            "pr: unknown subcommand {other}"
        ))),
    }
}

fn print_usage() {
    println!(
        "gyt pr <subcommand>

SUBCOMMANDS
    new <title> --source <branch> --target <branch> [-m <body>]
    list [--state open|closed|merged|all]
    show <N>
    comment <N> -m <body>
    close <N> [--reason <text>] | reopen <N>
    merge <N> [--no-ff]
    ci-run <N>                run sandboxed .gyt-ci/*.wasm on source_ref,
                              record the result. Pushing this requires
                              an rw ACL on the server (the existing
                              refs/update gate).
    label <N> [--add l1,l2] [--remove l3]
    assign <N> [--add \"Name <email>\"] [--remove ...]

PRs live at refs/prs/<N> and travel with `clone`, `fetch`, and `push`."
    );
}

fn open_repo() -> Result<Repo> {
    Repo::open(&std::env::current_dir()?)
}

fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

fn identity(repo: &Repo) -> Result<String> {
    Config::load(repo)?.identity()
}

fn parse_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn parse_n(args: &[String], sub: &str) -> Result<u64> {
    let raw = args
        .first()
        .ok_or_else(|| GytError::InvalidArgument(format!("{sub}: pr number required")))?;
    let s = raw.strip_prefix('#').unwrap_or(raw);
    s.parse::<u64>().map_err(|_| {
        GytError::InvalidArgument(format!("{sub}: not a valid pr number: {raw}"))
    })
}

#[expect(
    clippy::indexing_slicing,
    reason = "parse_n returns Err if args is empty, so the &args[1..] here is on a non-empty slice — guaranteed in-bounds"
)]
fn take_n<'a>(args: &'a [String], sub: &str) -> Result<(u64, &'a [String])> {
    let n = parse_n(args, sub)?;
    Ok((n, &args[1..]))
}

fn read_stdin() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

// ─── new ───────────────────────────────────────────────────────────────

#[expect(
    clippy::indexing_slicing,
    clippy::string_slice,
    reason = "args[i] is gated by the `while i < args.len()` loop header; ObjectId::to_hex returns ASCII hex so [..12] is a char-boundary slice"
)]
fn cmd_new(args: &[String]) -> Result<()> {
    let mut title: Option<String> = None;
    let mut body: Option<String> = None;
    let mut source: Option<String> = None;
    let mut target: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-m" | "--message" => {
                i += 1;
                body = Some(
                    args.get(i)
                        .ok_or_else(|| GytError::InvalidArgument("pr new: -m needs a value".into()))?
                        .clone(),
                );
            }
            "--stdin" => body = Some(read_stdin()?),
            "--source" => {
                i += 1;
                source = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            GytError::InvalidArgument("pr new: --source needs a value".into())
                        })?
                        .clone(),
                );
            }
            "--target" => {
                i += 1;
                target = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            GytError::InvalidArgument("pr new: --target needs a value".into())
                        })?
                        .clone(),
                );
            }
            other => {
                if title.is_some() {
                    return Err(GytError::InvalidArgument(format!(
                        "pr new: unexpected arg {other}"
                    )));
                }
                title = Some(other.to_owned());
            }
        }
        i += 1;
    }
    let title = title.ok_or_else(|| GytError::InvalidArgument("pr new: title required".into()))?;
    if title.trim().is_empty() {
        return Err(GytError::InvalidArgument("pr new: title must not be blank".into()));
    }
    let source = source
        .ok_or_else(|| GytError::InvalidArgument("pr new: --source required".into()))?;
    let target = target
        .ok_or_else(|| GytError::InvalidArgument("pr new: --target required".into()))?;
    let source_full = normalise_branch(&source);
    let target_full = normalise_branch(&target);
    if source_full == target_full {
        return Err(GytError::InvalidArgument(
            "pr new: source and target must differ".into(),
        ));
    }

    let repo = open_repo()?;
    // Verify both refs exist locally — pushing a PR pointing at a
    // missing source/target wouldn't validate on the receiving side
    // and would just confuse the reviewer.
    refs::read_ref(&repo.gyt_dir, &source_full)
        .map_err(|_| GytError::Refs(format!("source ref {source_full} not found")))?;
    refs::read_ref(&repo.gyt_dir, &target_full)
        .map_err(|_| GytError::Refs(format!("target ref {target_full} not found")))?;

    let me = identity(&repo)?;
    let body = body.unwrap_or_default();
    let _lock = repo.lock()?;
    let number = prs::next_number_locked(&repo)?;
    let mut mentions: Vec<u64> = Vec::new();
    issues::merge_mentions(&mut mentions, &issues::extract_mentions(&body), number);
    let now = now_ts();
    let pr = Pr {
        number,
        title,
        state: PrState::Open,
        source_ref: source_full,
        target_ref: target_full,
        author: me.clone(),
        created_ts: now,
        labels: Vec::new(),
        assignees: Vec::new(),
        mentions,
        events: vec![PrEvent {
            kind: PrEventKind::Open,
            author: me,
            ts: now,
            body,
            add: Vec::new(),
            remove: Vec::new(),
            reason: String::new(),
            result: String::new(),
        }],
    };
    let id = prs::write_locked(&repo, &pr)?;
    let short = &id.to_hex()[..12];
    println!("opened pr #{number} ({short})");
    Ok(())
}

fn normalise_branch(name: &str) -> String {
    if name.starts_with("refs/") {
        name.to_owned()
    } else {
        format!("refs/heads/{name}")
    }
}

// ─── list / show ──────────────────────────────────────────────────────

#[expect(
    clippy::indexing_slicing,
    reason = "args[i] is gated by the `while i < args.len()` loop header"
)]
fn cmd_list(args: &[String]) -> Result<()> {
    let mut state_filter: Option<PrState> = Some(PrState::Open);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--state" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| GytError::InvalidArgument("list: --state needs a value".into()))?
                    .as_str();
                state_filter = match v {
                    "all" => None,
                    "open" => Some(PrState::Open),
                    "closed" => Some(PrState::Closed),
                    "merged" => Some(PrState::Merged),
                    other => {
                        return Err(GytError::InvalidArgument(format!(
                            "list: --state must be open|closed|merged|all, got {other}"
                        )));
                    }
                };
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "list: unexpected arg {other}"
                )));
            }
        }
        i += 1;
    }
    let repo = open_repo()?;
    let mut shown = 0;
    for pr in prs::list(&repo)? {
        if let Some(want) = state_filter
            && pr.state != want
        {
            continue;
        }
        println!(
            "#{:>4} {:<6} {}  {}  ({} -> {})",
            pr.number,
            pr.state.as_str(),
            short_author(&pr.author),
            pr.title,
            short_ref(&pr.source_ref),
            short_ref(&pr.target_ref),
        );
        shown += 1;
    }
    if shown == 0 {
        println!("(no prs match)");
    }
    Ok(())
}

fn short_author(a: &str) -> String {
    a.split('<').next().unwrap_or(a).trim().to_owned()
}

fn short_ref(r: &str) -> &str {
    r.strip_prefix("refs/heads/").unwrap_or(r)
}

fn cmd_show(args: &[String]) -> Result<()> {
    let n = parse_n(args, "show")?;
    let repo = open_repo()?;
    let pr = prs::read(&repo, n)?;
    println!("pr #{}  [{}]", pr.number, pr.state.as_str());
    println!("title:    {}", pr.title);
    println!("source:   {}", pr.source_ref);
    println!("target:   {}", pr.target_ref);
    println!("author:   {}", pr.author);
    println!("created:  {}", pr.created_ts);
    if !pr.labels.is_empty() {
        println!("labels:   {}", pr.labels.join(", "));
    }
    if !pr.assignees.is_empty() {
        println!("assignees: {}", pr.assignees.join(", "));
    }
    if !pr.mentions.is_empty() {
        let ms: Vec<String> = pr.mentions.iter().map(|n| format!("#{n}")).collect();
        println!("mentions: {}", ms.join(", "));
    }
    println!();
    for e in &pr.events {
        match e.kind {
            PrEventKind::Open | PrEventKind::Comment => {
                println!("--- {} by {} @ {}", e.kind.as_str(), e.author, e.ts);
                if !e.body.is_empty() {
                    println!("{}", e.body);
                }
            }
            PrEventKind::Close => {
                if e.reason.is_empty() {
                    println!("--- closed by {} @ {}", e.author, e.ts);
                } else {
                    println!("--- closed by {} @ {}: {}", e.author, e.ts, e.reason);
                }
            }
            PrEventKind::Reopen => println!("--- reopened by {} @ {}", e.author, e.ts),
            PrEventKind::Merge => {
                println!(
                    "--- merged by {} @ {} into target tip {}",
                    e.author, e.ts, e.result
                );
            }
            PrEventKind::CiRun => {
                println!("--- ci-run by {} @ {}: {}", e.author, e.ts, e.result);
            }
            PrEventKind::Label | PrEventKind::Assign => {
                let mut parts = Vec::new();
                if !e.add.is_empty() {
                    parts.push(format!("+{}", e.add.join(",")));
                }
                if !e.remove.is_empty() {
                    parts.push(format!("-{}", e.remove.join(",")));
                }
                println!(
                    "--- {} by {} @ {}: {}",
                    e.kind.as_str(),
                    e.author,
                    e.ts,
                    parts.join(" ")
                );
            }
        }
        println!();
    }
    Ok(())
}

// ─── comment / close / reopen ────────────────────────────────────────

#[expect(
    clippy::indexing_slicing,
    clippy::string_slice,
    reason = "rest[i] is gated by the `while i < rest.len()` loop header; ObjectId::to_hex returns ASCII hex so [..12] is a char-boundary slice"
)]
fn cmd_comment(args: &[String]) -> Result<()> {
    let (n, rest) = take_n(args, "comment")?;
    let mut body: Option<String> = None;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "-m" | "--message" => {
                i += 1;
                body = Some(
                    rest.get(i)
                        .ok_or_else(|| {
                            GytError::InvalidArgument("comment: -m needs a value".into())
                        })?
                        .clone(),
                );
            }
            "--stdin" => body = Some(read_stdin()?),
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "comment: unexpected arg {other}"
                )));
            }
        }
        i += 1;
    }
    let body =
        body.ok_or_else(|| GytError::InvalidArgument("comment: -m <body> required".into()))?;
    if body.trim().is_empty() {
        return Err(GytError::InvalidArgument(
            "comment: body must not be blank".into(),
        ));
    }
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let mut pr = prs::read(&repo, n)?;
    issues::merge_mentions(&mut pr.mentions, &issues::extract_mentions(&body), pr.number);
    pr.events.push(PrEvent {
        kind: PrEventKind::Comment,
        author: me,
        ts: now_ts(),
        body,
        add: Vec::new(),
        remove: Vec::new(),
        reason: String::new(),
        result: String::new(),
    });
    let id = prs::write_locked(&repo, &pr)?;
    let short = &id.to_hex()[..12];
    println!("commented on pr #{n} ({short})");
    Ok(())
}

#[expect(
    clippy::indexing_slicing,
    reason = "rest[i] is gated by the `while i < rest.len()` loop header"
)]
fn cmd_close(args: &[String]) -> Result<()> {
    let (n, rest) = take_n(args, "close")?;
    let mut reason = String::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--reason" => {
                i += 1;
                reason.clone_from(rest.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("close: --reason needs a value".into())
                })?);
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "close: unexpected arg {other}"
                )));
            }
        }
        i += 1;
    }
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let mut pr = prs::read(&repo, n)?;
    if pr.state == PrState::Closed {
        return Err(GytError::InvalidArgument(format!("pr #{n} already closed")));
    }
    if pr.state == PrState::Merged {
        return Err(GytError::InvalidArgument(format!(
            "pr #{n} already merged; cannot close"
        )));
    }
    pr.state = PrState::Closed;
    pr.events.push(PrEvent {
        kind: PrEventKind::Close,
        author: me,
        ts: now_ts(),
        body: String::new(),
        add: Vec::new(),
        remove: Vec::new(),
        reason,
        result: String::new(),
    });
    prs::write_locked(&repo, &pr)?;
    println!("closed pr #{n}");
    Ok(())
}

fn cmd_reopen(args: &[String]) -> Result<()> {
    let n = parse_n(args, "reopen")?;
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let mut pr = prs::read(&repo, n)?;
    if pr.state == PrState::Open {
        return Err(GytError::InvalidArgument(format!("pr #{n} already open")));
    }
    if pr.state == PrState::Merged {
        return Err(GytError::InvalidArgument(format!(
            "pr #{n} is merged; cannot reopen"
        )));
    }
    pr.state = PrState::Open;
    pr.events.push(PrEvent {
        kind: PrEventKind::Reopen,
        author: me,
        ts: now_ts(),
        body: String::new(),
        add: Vec::new(),
        remove: Vec::new(),
        reason: String::new(),
        result: String::new(),
    });
    prs::write_locked(&repo, &pr)?;
    println!("reopened pr #{n}");
    Ok(())
}

// ─── merge ─────────────────────────────────────────────────────────────

#[expect(
    clippy::indexing_slicing,
    reason = "rest[i] is gated by the `while i < rest.len()` loop header"
)]
fn cmd_merge(args: &[String]) -> Result<()> {
    let (n, rest) = take_n(args, "merge")?;
    let mut no_ff = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--no-ff" => no_ff = true,
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "merge: unexpected arg {other}"
                )));
            }
        }
        i += 1;
    }
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let pr = prs::read(&repo, n)?;
    if pr.state != PrState::Open {
        return Err(GytError::InvalidArgument(format!(
            "pr #{n} is not open"
        )));
    }
    // Delegate to the existing merge implementation. We re-shell to
    // `gyt merge` semantics by switching to target_ref, then merging
    // source_ref. The merge command takes its own lock.
    let target_short = pr
        .target_ref
        .strip_prefix("refs/heads/")
        .unwrap_or(&pr.target_ref);
    let source_short = pr
        .source_ref
        .strip_prefix("refs/heads/")
        .unwrap_or(&pr.source_ref);

    // Switch local HEAD to target.
    crate::cmd::switch::run(&[target_short.to_string()])?;
    let mut merge_args = vec![source_short.to_string()];
    if no_ff {
        merge_args.push("--no-ff".into());
    } else {
        merge_args.push("--ff-only".into());
    }
    merge_cmd::run(&merge_args)?;
    let merged_tip = refs::read_ref(&repo.gyt_dir, &pr.target_ref)?;

    // Record the merge event on the PR.
    let _lock = repo.lock()?;
    let mut pr = prs::read(&repo, n)?;
    pr.state = PrState::Merged;
    pr.events.push(PrEvent {
        kind: PrEventKind::Merge,
        author: me,
        ts: now_ts(),
        body: String::new(),
        add: Vec::new(),
        remove: Vec::new(),
        reason: String::new(),
        result: merged_tip.to_hex(),
    });
    prs::write_locked(&repo, &pr)?;
    println!("merged pr #{n}");
    Ok(())
}

// ─── ci-run ────────────────────────────────────────────────────────────

#[expect(
    clippy::unwrap_used,
    reason = "PathBuf::file_name on a path produced by walk_dir over .gyt-ci/ is always Some (the path always has a final component)"
)]
fn cmd_ci_run(args: &[String]) -> Result<()> {
    let n = parse_n(args, "ci-run")?;
    let repo = open_repo()?;
    let me = identity(&repo)?;

    // Take a snapshot of the PR, then run CI without holding the lock —
    // CI runs can be long and we don't want to block all other writers
    // for minutes.
    let pr = prs::read(&repo, n)?;
    if pr.state == PrState::Closed {
        return Err(GytError::InvalidArgument(format!(
            "pr #{n} is closed; not running CI"
        )));
    }
    // We deliberately run on the *workspace as it stands today* rather
    // than checking out the source ref into a sandbox. Server-side CI
    // execution would require checking out into a tempdir; for v1 the
    // client decides what workspace to run on (and the result event
    // records it).
    let ci_dir = repo.workdir.join(".gyt-ci");
    if !ci_dir.is_dir() {
        return Err(GytError::Ci(format!(
            "pr #{n}: no .gyt-ci/ directory; nothing to run"
        )));
    }
    let out_dir = repo.workdir.join(".gyt-ci-output");
    // C5: refuse output dir if it's a symlink (malicious-clone RCE precursor).
    if let Ok(meta) = std::fs::symlink_metadata(&out_dir) {
        if meta.file_type().is_symlink() {
            return Err(GytError::Ci(format!(
                "pr #{n}: output dir {} is a symlink; refusing",
                out_dir.display()
            )));
        }
    } else {
        std::fs::create_dir_all(&out_dir)?;
    }

    let wasms = collect_wasm_scripts(&ci_dir);
    if wasms.is_empty() {
        return Err(GytError::Ci(format!(
            "pr #{n}: no .wasm scripts in .gyt-ci/"
        )));
    }
    let mut result = String::from("pass");
    for w in &wasms {
        if let Err(e) = run_ci_wasm(w, &repo.workdir, &out_dir) {
            let name = w.file_name().unwrap().to_string_lossy();
            result = format!("fail: {name}: {e}");
            break;
        }
    }

    let _lock = repo.lock()?;
    let mut pr = prs::read(&repo, n)?;
    pr.events.push(PrEvent {
        kind: PrEventKind::CiRun,
        author: me,
        ts: now_ts(),
        body: String::new(),
        add: Vec::new(),
        remove: Vec::new(),
        reason: String::new(),
        result: result.clone(),
    });
    prs::write_locked(&repo, &pr)?;
    println!("ci-run pr #{n}: {result}");
    if result.starts_with("fail") {
        return Err(GytError::Ci(result));
    }
    Ok(())
}

// ─── label / assign ───────────────────────────────────────────────────

fn cmd_label(args: &[String]) -> Result<()> {
    let (n, rest) = take_n(args, "label")?;
    let (add, remove) = parse_add_remove(rest, "label")?;
    if add.is_empty() && remove.is_empty() {
        return Err(GytError::InvalidArgument(
            "label: pass --add and/or --remove".into(),
        ));
    }
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let mut pr = prs::read(&repo, n)?;
    for l in &add {
        if !pr.labels.contains(l) {
            pr.labels.push(l.clone());
        }
    }
    pr.labels.retain(|l| !remove.contains(l));
    pr.labels.sort();
    pr.labels.dedup();
    pr.events.push(PrEvent {
        kind: PrEventKind::Label,
        author: me,
        ts: now_ts(),
        body: String::new(),
        add,
        remove,
        reason: String::new(),
        result: String::new(),
    });
    prs::write_locked(&repo, &pr)?;
    println!("updated labels on pr #{n}");
    Ok(())
}

fn cmd_assign(args: &[String]) -> Result<()> {
    let (n, rest) = take_n(args, "assign")?;
    let (add, remove) = parse_add_remove(rest, "assign")?;
    if add.is_empty() && remove.is_empty() {
        return Err(GytError::InvalidArgument(
            "assign: pass --add and/or --remove".into(),
        ));
    }
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let mut pr = prs::read(&repo, n)?;
    for who in &add {
        if !pr.assignees.contains(who) {
            pr.assignees.push(who.clone());
        }
    }
    pr.assignees.retain(|w| !remove.contains(w));
    pr.assignees.sort();
    pr.assignees.dedup();
    pr.events.push(PrEvent {
        kind: PrEventKind::Assign,
        author: me,
        ts: now_ts(),
        body: String::new(),
        add,
        remove,
        reason: String::new(),
        result: String::new(),
    });
    prs::write_locked(&repo, &pr)?;
    println!("updated assignees on pr #{n}");
    Ok(())
}

#[expect(
    clippy::indexing_slicing,
    reason = "args[i] is gated by the `while i < args.len()` loop header"
)]
fn parse_add_remove(args: &[String], sub: &str) -> Result<(Vec<String>, Vec<String>)> {
    let mut add: Vec<String> = Vec::new();
    let mut remove: Vec<String> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--add" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| {
                        GytError::InvalidArgument(format!("{sub}: --add needs a value"))
                    })?
                    .clone();
                add.extend(parse_csv(&v));
            }
            "--remove" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| {
                        GytError::InvalidArgument(format!("{sub}: --remove needs a value"))
                    })?
                    .clone();
                remove.extend(parse_csv(&v));
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "{sub}: unexpected arg {other}"
                )));
            }
        }
        i += 1;
    }
    Ok((add, remove))
}
