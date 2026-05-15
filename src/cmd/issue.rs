// `gyt issue` and `gyt discussion` — CLI surface for the in-repo
// issue/discussion store. Both subcommands share this implementation;
// the only difference is the default `kind` they pass in (Issue vs.
// Discussion). All write paths take repo.lock() to serialise concurrent
// writers, including the `next_number_locked` allocation.

use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::issues::{self, Event, EventKind, Issue, IssueKind, IssueState};
use crate::repo::Repo;
use std::io::Read as _;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn run_issue(args: &[String]) -> Result<()> {
    dispatch(args, IssueKind::Issue)
}

pub fn run_discussion(args: &[String]) -> Result<()> {
    dispatch(args, IssueKind::Discussion)
}

fn dispatch(args: &[String], kind: IssueKind) -> Result<()> {
    let Some((sub, rest)) = args.split_first() else {
        print_usage(kind);
        return Ok(());
    };
    match sub.as_str() {
        "--help" | "-h" | "help" => {
            print_usage(kind);
            Ok(())
        }
        "new" => cmd_new(rest, kind),
        "list" | "ls" => cmd_list(rest, kind),
        "show" => cmd_show(rest, kind),
        "comment" => cmd_comment(rest, kind),
        "close" => cmd_close(rest, kind),
        "reopen" => cmd_reopen(rest, kind),
        "label" => cmd_label(rest, kind),
        "assign" => cmd_assign(rest, kind),
        other => Err(GytError::InvalidArgument(format!(
            "{}: unknown subcommand {other}",
            kind.as_str()
        ))),
    }
}

fn print_usage(kind: IssueKind) {
    let k = kind.as_str();
    println!(
        "gyt {k} <subcommand>

SUBCOMMANDS
    new <title> [-m <body>]
    list [--state open|closed|all]
    show <N>
    comment <N> -m <body>
    close <N> [--reason <text>]
    reopen <N>
    label <N> [--add <l1,l2,...>] [--remove <l1,l2,...>]
    assign <N> [--add <\"Name <email>\",...>] [--remove ...]

All commands operate on refs/issues/<N> in the current repository. The
refs travel with `clone`, `fetch`, and `push` without additional flags."
    );
}

fn open_repo() -> Result<Repo> {
    let cwd = std::env::current_dir()?;
    Repo::open(&cwd)
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

fn read_stdin_to_string() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    Ok(s)
}

// ─── new ───────────────────────────────────────────────────────────────

fn cmd_new(args: &[String], kind: IssueKind) -> Result<()> {
    let mut title: Option<String> = None;
    let mut body: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-m" | "--message" => {
                i += 1;
                body = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            GytError::InvalidArgument(format!(
                                "{} new: -m requires a value",
                                kind.as_str()
                            ))
                        })?
                        .clone(),
                );
            }
            "--stdin" => {
                body = Some(read_stdin_to_string()?);
            }
            other => {
                if title.is_some() {
                    return Err(GytError::InvalidArgument(format!(
                        "{} new: unexpected arg {other}",
                        kind.as_str()
                    )));
                }
                title = Some(other.to_owned());
            }
        }
        i += 1;
    }
    let title = title.ok_or_else(|| {
        GytError::InvalidArgument(format!("{} new: title required", kind.as_str()))
    })?;
    if title.trim().is_empty() {
        return Err(GytError::InvalidArgument(format!(
            "{} new: title must not be blank",
            kind.as_str()
        )));
    }
    let body = body.unwrap_or_default();

    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let number = issues::next_number_locked(&repo)?;
    let mentions = issues::extract_mentions(&body);
    let now = now_ts();
    let issue = Issue {
        number,
        kind,
        title,
        state: IssueState::Open,
        author: me.clone(),
        created_ts: now,
        labels: Vec::new(),
        assignees: Vec::new(),
        mentions: {
            let mut v = Vec::new();
            issues::merge_mentions(&mut v, &mentions, number);
            v
        },
        events: vec![Event {
            kind: EventKind::Open,
            author: me,
            ts: now,
            body,
            add: Vec::new(),
            remove: Vec::new(),
            reason: String::new(),
        }],
    };
    let id = issues::write_locked(&repo, &issue)?;
    println!(
        "created {} #{} ({})",
        kind.as_str(),
        number,
        &id.to_hex()[..12]
    );
    Ok(())
}

// ─── list ──────────────────────────────────────────────────────────────

fn cmd_list(args: &[String], kind: IssueKind) -> Result<()> {
    let mut state_filter: Option<IssueState> = Some(IssueState::Open);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--state" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| GytError::InvalidArgument("list: --state requires a value".into()))?
                    .as_str();
                state_filter = match v {
                    "all" => None,
                    "open" => Some(IssueState::Open),
                    "closed" => Some(IssueState::Closed),
                    other => {
                        return Err(GytError::InvalidArgument(format!(
                            "list: --state must be open|closed|all, got {other}"
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
    for issue in issues::list(&repo)? {
        if issue.kind != kind {
            continue;
        }
        if let Some(want) = state_filter
            && issue.state != want
        {
            continue;
        }
        println!(
            "#{:>4} {:<6} {}  {}",
            issue.number,
            issue.state.as_str(),
            short_author(&issue.author),
            issue.title,
        );
        shown += 1;
    }
    if shown == 0 {
        println!("(no {}s match)", kind.as_str());
    }
    Ok(())
}

fn short_author(a: &str) -> String {
    // "Name <email>" → "Name"
    a.split('<').next().unwrap_or(a).trim().to_owned()
}

// ─── show ──────────────────────────────────────────────────────────────

fn cmd_show(args: &[String], _kind: IssueKind) -> Result<()> {
    let n = parse_n(args, "show")?;
    let repo = open_repo()?;
    let issue = issues::read(&repo, n)?;
    println!("{} #{}  [{}]", issue.kind.as_str(), issue.number, issue.state.as_str());
    println!("title:    {}", issue.title);
    println!("author:   {}", issue.author);
    println!("created:  {}", issue.created_ts);
    if !issue.labels.is_empty() {
        println!("labels:   {}", issue.labels.join(", "));
    }
    if !issue.assignees.is_empty() {
        println!("assignees: {}", issue.assignees.join(", "));
    }
    if !issue.mentions.is_empty() {
        let ms: Vec<String> = issue.mentions.iter().map(|n| format!("#{n}")).collect();
        println!("mentions: {}", ms.join(", "));
    }
    println!();
    for e in &issue.events {
        match e.kind {
            EventKind::Open | EventKind::Comment => {
                println!("--- {} by {} @ {}", e.kind.as_str(), e.author, e.ts);
                if !e.body.is_empty() {
                    println!("{}", e.body);
                }
            }
            EventKind::Close => {
                if e.reason.is_empty() {
                    println!("--- closed by {} @ {}", e.author, e.ts);
                } else {
                    println!("--- closed by {} @ {}: {}", e.author, e.ts, e.reason);
                }
            }
            EventKind::Reopen => println!("--- reopened by {} @ {}", e.author, e.ts),
            EventKind::Label => {
                let mut parts = Vec::new();
                if !e.add.is_empty() {
                    parts.push(format!("+{}", e.add.join(",")));
                }
                if !e.remove.is_empty() {
                    parts.push(format!("-{}", e.remove.join(",")));
                }
                println!("--- label by {} @ {}: {}", e.author, e.ts, parts.join(" "));
            }
            EventKind::Assign => {
                let mut parts = Vec::new();
                if !e.add.is_empty() {
                    parts.push(format!("+{}", e.add.join(",")));
                }
                if !e.remove.is_empty() {
                    parts.push(format!("-{}", e.remove.join(",")));
                }
                println!(
                    "--- assign by {} @ {}: {}",
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

// ─── comment ──────────────────────────────────────────────────────────

fn cmd_comment(args: &[String], _kind: IssueKind) -> Result<()> {
    let (n, rest) = take_n(args, "comment")?;
    let body = parse_message(rest, "comment")?;
    if body.trim().is_empty() {
        return Err(GytError::InvalidArgument(
            "comment: body must not be blank".into(),
        ));
    }
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let mut issue = issues::read(&repo, n)?;
    let new_mentions = issues::extract_mentions(&body);
    issues::merge_mentions(&mut issue.mentions, &new_mentions, issue.number);
    issue.events.push(Event {
        kind: EventKind::Comment,
        author: me,
        ts: now_ts(),
        body,
        add: Vec::new(),
        remove: Vec::new(),
        reason: String::new(),
    });
    let id = issues::write_locked(&repo, &issue)?;
    let short = &id.to_hex()[..12];
    println!("commented on #{n} ({short})");
    Ok(())
}

// ─── close / reopen ───────────────────────────────────────────────────

fn cmd_close(args: &[String], _kind: IssueKind) -> Result<()> {
    let (n, rest) = take_n(args, "close")?;
    let mut reason = String::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--reason" => {
                i += 1;
                reason.clone_from(
                    rest.get(i).ok_or_else(|| {
                        GytError::InvalidArgument("close: --reason needs a value".into())
                    })?,
                );
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
    let mut issue = issues::read(&repo, n)?;
    if issue.state == IssueState::Closed {
        return Err(GytError::InvalidArgument(format!(
            "#{n} is already closed"
        )));
    }
    issue.state = IssueState::Closed;
    if !reason.is_empty() {
        let new_mentions = issues::extract_mentions(&reason);
        issues::merge_mentions(&mut issue.mentions, &new_mentions, issue.number);
    }
    issue.events.push(Event {
        kind: EventKind::Close,
        author: me,
        ts: now_ts(),
        body: String::new(),
        add: Vec::new(),
        remove: Vec::new(),
        reason,
    });
    issues::write_locked(&repo, &issue)?;
    println!("closed #{n}");
    Ok(())
}

fn cmd_reopen(args: &[String], _kind: IssueKind) -> Result<()> {
    let n = parse_n(args, "reopen")?;
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let mut issue = issues::read(&repo, n)?;
    if issue.state == IssueState::Open {
        return Err(GytError::InvalidArgument(format!(
            "#{n} is already open"
        )));
    }
    issue.state = IssueState::Open;
    issue.events.push(Event {
        kind: EventKind::Reopen,
        author: me,
        ts: now_ts(),
        body: String::new(),
        add: Vec::new(),
        remove: Vec::new(),
        reason: String::new(),
    });
    issues::write_locked(&repo, &issue)?;
    println!("reopened #{n}");
    Ok(())
}

// ─── label ─────────────────────────────────────────────────────────────

fn cmd_label(args: &[String], _kind: IssueKind) -> Result<()> {
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
    let mut issue = issues::read(&repo, n)?;
    for l in &add {
        if !issue.labels.contains(l) {
            issue.labels.push(l.clone());
        }
    }
    issue.labels.retain(|l| !remove.contains(l));
    issue.labels.sort();
    issue.labels.dedup();
    issue.events.push(Event {
        kind: EventKind::Label,
        author: me,
        ts: now_ts(),
        body: String::new(),
        add,
        remove,
        reason: String::new(),
    });
    issues::write_locked(&repo, &issue)?;
    println!("updated labels on #{n}");
    Ok(())
}

fn cmd_assign(args: &[String], _kind: IssueKind) -> Result<()> {
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
    let mut issue = issues::read(&repo, n)?;
    for who in &add {
        if !issue.assignees.contains(who) {
            issue.assignees.push(who.clone());
        }
    }
    issue.assignees.retain(|w| !remove.contains(w));
    issue.assignees.sort();
    issue.assignees.dedup();
    issue.events.push(Event {
        kind: EventKind::Assign,
        author: me,
        ts: now_ts(),
        body: String::new(),
        add,
        remove,
        reason: String::new(),
    });
    issues::write_locked(&repo, &issue)?;
    println!("updated assignees on #{n}");
    Ok(())
}

// ─── arg helpers ──────────────────────────────────────────────────────

fn parse_n(args: &[String], sub: &str) -> Result<u64> {
    let raw = args
        .first()
        .ok_or_else(|| GytError::InvalidArgument(format!("{sub}: issue number required")))?;
    parse_number(raw, sub)
}

fn take_n<'a>(args: &'a [String], sub: &str) -> Result<(u64, &'a [String])> {
    let n = parse_n(args, sub)?;
    Ok((n, &args[1..]))
}

fn parse_number(raw: &str, sub: &str) -> Result<u64> {
    let s = raw.strip_prefix('#').unwrap_or(raw);
    s.parse::<u64>().map_err(|_| {
        GytError::InvalidArgument(format!("{sub}: not a valid issue number: {raw}"))
    })
}

fn parse_message(args: &[String], sub: &str) -> Result<String> {
    let mut body: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-m" | "--message" => {
                i += 1;
                body = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            GytError::InvalidArgument(format!("{sub}: -m requires a value"))
                        })?
                        .clone(),
                );
            }
            "--stdin" => {
                body = Some(read_stdin_to_string()?);
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "{sub}: unexpected arg {other}"
                )));
            }
        }
        i += 1;
    }
    body.ok_or_else(|| GytError::InvalidArgument(format!("{sub}: -m <body> required")))
}

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
                        GytError::InvalidArgument(format!("{sub}: --add requires a value"))
                    })?
                    .clone();
                add.extend(parse_csv(&v));
            }
            "--remove" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| {
                        GytError::InvalidArgument(format!("{sub}: --remove requires a value"))
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
