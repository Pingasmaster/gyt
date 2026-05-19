// `gyt incident` — CLI for in-repo operational incidents.
//
// Subcommands:
//   new <title> --severity sev1..sev4 --type TYPE [--field K=V ...]
//                                                 [shortcut flags per type]
//                                                 [--label l1,l2]
//                                                 [--assign "Name <e>",...]
//                                                 [-m body]
//   list   [--state detected|investigating|mitigated|resolved|open|all]
//          [--severity sev1..sev4] [--type T] [--label L]
//   show <N>
//   comment | update <N> -m <body>
//   investigate <N> | mitigate <N> [--note ...] | resolve <N> --reason R
//   reopen <N> [--reason R]
//   severity <N> sev1..sev4
//   label <N> [--add ...] [--remove ...]
//   assign <N> [--add ...] [--remove ...]
//   field <N> set KEY VALUE | field <N> get KEY
//
// All writes take repo.lock(). State transitions are validated against
// the rules in incidents::is_allowed_transition.
//
// Known incident-type registry: shortcut flags (--cve, --cwe, --services,
// etc.) are expanded into the `fields` map. Custom types just use the
// generic --field K=V mechanism — storage is identical.

use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::incidents::{
    self, EventKind, Incident, IncidentState, Severity, is_allowed_transition,
};
use crate::issues;
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
        "comment" | "update" => cmd_comment(rest),
        "investigate" => cmd_transition(rest, IncidentState::Investigating, "investigate"),
        "mitigate" => cmd_mitigate(rest),
        "resolve" => cmd_resolve(rest),
        "reopen" => cmd_reopen(rest),
        "severity" => cmd_severity(rest),
        "label" => cmd_label(rest),
        "assign" => cmd_assign(rest),
        "field" => cmd_field(rest),
        other => Err(GytError::InvalidArgument(format!(
            "incident: unknown subcommand {other}"
        ))),
    }
}

fn print_usage() {
    println!(
        "gyt incident <subcommand>

SUBCOMMANDS
    new <title> --severity sev1|sev2|sev3|sev4 --type TYPE
        [--field KEY=VAL ...] [type-specific shortcuts]
        [--label l1,l2] [--assign \"Name <email>\"] [-m <body>]
    list [--state detected|investigating|mitigated|resolved|open|all]
         [--severity sev1..sev4] [--type T] [--label L]
    show <N>
    comment <N> -m <body>      (alias: update <N> -m <body>)
    investigate <N>            detected/mitigated -> investigating
    mitigate <N> [--note T]    -> mitigated (impact stopped)
    resolve <N> --reason T     -> resolved (root cause closed)
    reopen <N> [--reason T]    resolved/mitigated -> investigating
    severity <N> sev1|sev2|sev3|sev4
    label <N> [--add l1,l2] [--remove l3]
    assign <N> [--add \"Name <email>\"] [--remove ...]
    field <N> set KEY VAL
    field <N> get KEY

KNOWN TYPES (shortcut flags populate the `fields` map)
    security    --cve VAL --cwe VAL --vector VAL --disclosure VAL
    outage      --services VAL --start-ts VAL --customer-impact VAL
    bug         --affected-version VAL --regressed-in VAL --repro VAL
    data-loss   --scope VAL --recovery-path VAL
    performance --metric VAL --baseline VAL --degraded-value VAL
    (any other) --field KEY=VAL only — fully free-form

Incidents live at refs/incidents/<N> and travel with `clone`,
`fetch`, and `push`."
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
        .ok_or_else(|| GytError::InvalidArgument(format!("{sub}: incident number required")))?;
    let s = raw.strip_prefix('#').unwrap_or(raw);
    s.parse::<u64>().map_err(|_| {
        GytError::InvalidArgument(format!("{sub}: not a valid incident number: {raw}"))
    })
}

#[expect(
    clippy::indexing_slicing,
    reason = "parse_n returns Err if args is empty, so &args[1..] is on a non-empty slice — guaranteed in-bounds"
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

const fn empty_event(kind: EventKind, author: String, ts: i64) -> incidents::Event {
    incidents::Event {
        kind,
        author,
        ts,
        body: String::new(),
        add: Vec::new(),
        remove: Vec::new(),
        reason: String::new(),
        new_state: String::new(),
        new_severity: String::new(),
        field_key: String::new(),
        field_value: String::new(),
    }
}

/// For a known incident type, map a CLI flag like "--cve" to the
/// `fields` key it sets ("cve"). Returns Some(key) only for flags
/// recognised for that type. Unknown flags fall through to the
/// generic --field K=V path.
fn type_shortcut(incident_type: &str, flag: &str) -> Option<&'static str> {
    let known: &[(&str, &[(&str, &str)])] = &[
        (
            "security",
            &[
                ("--cve", "cve"),
                ("--cwe", "cwe"),
                ("--vector", "vector"),
                ("--disclosure", "disclosure"),
            ],
        ),
        (
            "outage",
            &[
                ("--services", "services"),
                ("--start-ts", "start_ts"),
                ("--customer-impact", "customer_impact"),
            ],
        ),
        (
            "bug",
            &[
                ("--affected-version", "affected_version"),
                ("--regressed-in", "regressed_in"),
                ("--repro", "repro"),
            ],
        ),
        (
            "data-loss",
            &[("--scope", "scope"), ("--recovery-path", "recovery_path")],
        ),
        (
            "performance",
            &[
                ("--metric", "metric"),
                ("--baseline", "baseline"),
                ("--degraded-value", "degraded_value"),
            ],
        ),
    ];
    let table = known.iter().find(|(t, _)| *t == incident_type)?.1;
    table.iter().find(|(f, _)| *f == flag).map(|(_, k)| *k)
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
    let mut severity: Option<Severity> = None;
    let mut incident_type: Option<String> = None;
    let mut labels: Vec<String> = Vec::new();
    let mut assignees: Vec<String> = Vec::new();
    let mut explicit_fields: Vec<(String, String)> = Vec::new();
    // Shortcut flags can be specified before --type is parsed; defer
    // their interpretation until we know the type. We capture them as
    // (raw_flag, value).
    let mut deferred_shortcuts: Vec<(String, String)> = Vec::new();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-m" | "--message" => {
                i += 1;
                body = Some(
                    args.get(i)
                        .ok_or_else(|| {
                            GytError::InvalidArgument("incident new: -m needs a value".into())
                        })?
                        .clone(),
                );
            }
            "--stdin" => body = Some(read_stdin()?),
            "--severity" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("incident new: --severity needs a value".into())
                })?;
                severity = Some(Severity::parse(v)?);
            }
            "--type" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("incident new: --type needs a value".into())
                })?;
                let t = v.trim().to_owned();
                if t.is_empty() {
                    return Err(GytError::InvalidArgument(
                        "incident new: --type must not be blank".into(),
                    ));
                }
                incident_type = Some(t);
            }
            "--field" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("incident new: --field needs a value".into())
                })?;
                let (k, val) = v.split_once('=').ok_or_else(|| {
                    GytError::InvalidArgument(format!(
                        "incident new: --field expects KEY=VAL, got {v}"
                    ))
                })?;
                explicit_fields.push((k.trim().to_owned(), val.trim().to_owned()));
            }
            "--label" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("incident new: --label needs a value".into())
                })?;
                labels.extend(parse_csv(v));
            }
            "--assign" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("incident new: --assign needs a value".into())
                })?;
                assignees.extend(parse_csv(v));
            }
            // Recognised "shortcut" flags for known types. We accept any
            // that *might* be valid; we validate against the chosen type
            // after the loop.
            flag if flag.starts_with("--")
                && !matches!(
                    flag,
                    "-m" | "--message"
                        | "--stdin"
                        | "--severity"
                        | "--type"
                        | "--field"
                        | "--label"
                        | "--assign"
                ) =>
            {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument(format!("incident new: {flag} needs a value"))
                })?;
                deferred_shortcuts.push((flag.to_owned(), v.clone()));
            }
            other => {
                if title.is_some() {
                    return Err(GytError::InvalidArgument(format!(
                        "incident new: unexpected arg {other}"
                    )));
                }
                title = Some(other.to_owned());
            }
        }
        i += 1;
    }

    let title =
        title.ok_or_else(|| GytError::InvalidArgument("incident new: title required".into()))?;
    if title.trim().is_empty() {
        return Err(GytError::InvalidArgument(
            "incident new: title must not be blank".into(),
        ));
    }
    let severity = severity.ok_or_else(|| {
        GytError::InvalidArgument(
            "incident new: --severity sev1|sev2|sev3|sev4 required".into(),
        )
    })?;
    let incident_type = incident_type
        .ok_or_else(|| GytError::InvalidArgument("incident new: --type required".into()))?;

    // Expand shortcuts against the chosen type.
    let mut fields: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (flag, val) in deferred_shortcuts {
        let key = type_shortcut(&incident_type, &flag).ok_or_else(|| {
            GytError::InvalidArgument(format!(
                "incident new: unknown flag {flag} for type {incident_type} (use --field KEY=VAL)"
            ))
        })?;
        fields.insert(key.to_owned(), val);
    }
    for (k, v) in explicit_fields {
        if k.is_empty() {
            return Err(GytError::InvalidArgument(
                "incident new: --field key must not be empty".into(),
            ));
        }
        fields.insert(k, v);
    }

    let repo = open_repo()?;
    let me = identity(&repo)?;
    let body = body.unwrap_or_default();
    let _lock = repo.lock()?;
    let number = incidents::next_number_locked(&repo)?;
    let mut mentions: Vec<u64> = Vec::new();
    issues::merge_mentions(&mut mentions, &issues::extract_mentions(&body), number);
    let now = now_ts();
    labels.sort();
    labels.dedup();
    assignees.sort();
    assignees.dedup();
    let inc = Incident {
        number,
        title,
        state: IncidentState::Detected,
        severity,
        incident_type,
        author: me.clone(),
        created_ts: now,
        labels,
        assignees,
        mentions,
        fields,
        events: vec![incidents::Event {
            kind: EventKind::Open,
            author: me,
            ts: now,
            body,
            add: Vec::new(),
            remove: Vec::new(),
            reason: String::new(),
            new_state: String::new(),
            new_severity: String::new(),
            field_key: String::new(),
            field_value: String::new(),
        }],
    };
    let id = incidents::write_locked(&repo, &inc)?;
    let short = &id.to_hex()[..12];
    println!("opened incident #{number} ({short})");
    Ok(())
}

// ─── list / show ──────────────────────────────────────────────────────

#[expect(
    clippy::indexing_slicing,
    reason = "args[i] is gated by the `while i < args.len()` loop header"
)]
fn cmd_list(args: &[String]) -> Result<()> {
    // Default filter: anything not resolved (i.e. detected ∪ investigating ∪ mitigated).
    let mut state_filter: Vec<IncidentState> = vec![
        IncidentState::Detected,
        IncidentState::Investigating,
        IncidentState::Mitigated,
    ];
    let mut severity_filter: Option<Severity> = None;
    let mut type_filter: Option<String> = None;
    let mut label_filter: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--state" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| {
                        GytError::InvalidArgument("list: --state needs a value".into())
                    })?
                    .as_str();
                state_filter = match v {
                    "all" => Vec::new(),
                    "open" => vec![
                        IncidentState::Detected,
                        IncidentState::Investigating,
                        IncidentState::Mitigated,
                    ],
                    "detected" => vec![IncidentState::Detected],
                    "investigating" => vec![IncidentState::Investigating],
                    "mitigated" => vec![IncidentState::Mitigated],
                    "resolved" => vec![IncidentState::Resolved],
                    other => {
                        return Err(GytError::InvalidArgument(format!(
                            "list: --state must be detected|investigating|mitigated|resolved|open|all, got {other}"
                        )));
                    }
                };
            }
            "--severity" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("list: --severity needs a value".into())
                })?;
                severity_filter = Some(Severity::parse(v)?);
            }
            "--type" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("list: --type needs a value".into())
                })?;
                type_filter = Some(v.clone());
            }
            "--label" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("list: --label needs a value".into())
                })?;
                label_filter = Some(v.clone());
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
    let mut incs = incidents::list(&repo)?;
    // Sort: severity ascending (sev1 first) then by number.
    incs.sort_by(|a, b| a.severity.cmp(&b.severity).then(a.number.cmp(&b.number)));
    let mut shown = 0;
    for inc in incs {
        if !state_filter.is_empty() && !state_filter.contains(&inc.state) {
            continue;
        }
        if let Some(s) = severity_filter
            && inc.severity != s
        {
            continue;
        }
        if let Some(ref t) = type_filter
            && &inc.incident_type != t
        {
            continue;
        }
        if let Some(ref l) = label_filter
            && !inc.labels.iter().any(|x| x == l)
        {
            continue;
        }
        println!(
            "#{:>4} {:<5} {:<13} {:<11} {}  {}",
            inc.number,
            inc.severity.as_str(),
            inc.state.as_str(),
            inc.incident_type,
            short_author(&inc.author),
            inc.title,
        );
        shown += 1;
    }
    if shown == 0 {
        println!("(no incidents match)");
    }
    Ok(())
}

fn short_author(a: &str) -> String {
    a.split('<').next().unwrap_or(a).trim().to_owned()
}

fn cmd_show(args: &[String]) -> Result<()> {
    let n = parse_n(args, "show")?;
    let repo = open_repo()?;
    let inc = incidents::read(&repo, n)?;
    println!(
        "incident #{}  [{}]  {}  type={}",
        inc.number,
        inc.state.as_str(),
        inc.severity.as_str(),
        inc.incident_type
    );
    println!("title:    {}", inc.title);
    println!("author:   {}", inc.author);
    println!("created:  {}", inc.created_ts);
    if !inc.labels.is_empty() {
        println!("labels:   {}", inc.labels.join(", "));
    }
    if !inc.assignees.is_empty() {
        println!("assignees: {}", inc.assignees.join(", "));
    }
    if !inc.mentions.is_empty() {
        let ms: Vec<String> = inc.mentions.iter().map(|n| format!("#{n}")).collect();
        println!("mentions: {}", ms.join(", "));
    }
    if !inc.fields.is_empty() {
        println!("fields:");
        for (k, v) in &inc.fields {
            println!("  {k} = {v}");
        }
    }
    println!();
    for e in &inc.events {
        match e.kind {
            EventKind::Open | EventKind::Comment => {
                println!("--- {} by {} @ {}", e.kind.as_str(), e.author, e.ts);
                if !e.body.is_empty() {
                    println!("{}", e.body);
                }
            }
            EventKind::Transition => {
                println!(
                    "--- transition by {} @ {} -> {}",
                    e.author, e.ts, e.new_state
                );
                if !e.body.is_empty() {
                    println!("{}", e.body);
                }
            }
            EventKind::Severity => {
                println!(
                    "--- severity by {} @ {} -> {}",
                    e.author, e.ts, e.new_severity
                );
            }
            EventKind::Resolve => {
                if e.reason.is_empty() {
                    println!("--- resolved by {} @ {}", e.author, e.ts);
                } else {
                    println!("--- resolved by {} @ {}: {}", e.author, e.ts, e.reason);
                }
            }
            EventKind::Reopen => {
                if e.reason.is_empty() {
                    println!("--- reopened by {} @ {}", e.author, e.ts);
                } else {
                    println!("--- reopened by {} @ {}: {}", e.author, e.ts, e.reason);
                }
            }
            EventKind::SetField => {
                println!(
                    "--- set_field by {} @ {}: {} = {}",
                    e.author, e.ts, e.field_key, e.field_value
                );
            }
            EventKind::Label | EventKind::Assign => {
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

// ─── comment / update ─────────────────────────────────────────────────

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
    let mut inc = incidents::read(&repo, n)?;
    issues::merge_mentions(
        &mut inc.mentions,
        &issues::extract_mentions(&body),
        inc.number,
    );
    let mut ev = empty_event(EventKind::Comment, me, now_ts());
    ev.body = body;
    inc.events.push(ev);
    let id = incidents::write_locked(&repo, &inc)?;
    let short = &id.to_hex()[..12];
    println!("commented on incident #{n} ({short})");
    Ok(())
}

// ─── state transitions ───────────────────────────────────────────────

fn cmd_transition(args: &[String], target: IncidentState, sub: &str) -> Result<()> {
    let n = parse_n(args, sub)?;
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let mut inc = incidents::read(&repo, n)?;
    if inc.state == target {
        return Err(GytError::InvalidArgument(format!(
            "incident #{n} already {}",
            target.as_str()
        )));
    }
    if !is_allowed_transition(inc.state, target) {
        return Err(GytError::InvalidArgument(format!(
            "incident #{n}: cannot transition {} -> {}",
            inc.state.as_str(),
            target.as_str()
        )));
    }
    inc.state = target;
    let mut ev = empty_event(EventKind::Transition, me, now_ts());
    target.as_str().clone_into(&mut ev.new_state);
    inc.events.push(ev);
    incidents::write_locked(&repo, &inc)?;
    println!("incident #{n} -> {}", target.as_str());
    Ok(())
}

#[expect(
    clippy::indexing_slicing,
    reason = "rest[i] is gated by the `while i < rest.len()` loop header"
)]
fn cmd_mitigate(args: &[String]) -> Result<()> {
    let (n, rest) = take_n(args, "mitigate")?;
    let mut note = String::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--note" => {
                i += 1;
                note.clone_from(rest.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("mitigate: --note needs a value".into())
                })?);
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "mitigate: unexpected arg {other}"
                )));
            }
        }
        i += 1;
    }
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let mut inc = incidents::read(&repo, n)?;
    let target = IncidentState::Mitigated;
    if inc.state == target {
        return Err(GytError::InvalidArgument(format!(
            "incident #{n} already mitigated"
        )));
    }
    if !is_allowed_transition(inc.state, target) {
        return Err(GytError::InvalidArgument(format!(
            "incident #{n}: cannot transition {} -> mitigated",
            inc.state.as_str()
        )));
    }
    inc.state = target;
    let mut ev = empty_event(EventKind::Transition, me, now_ts());
    target.as_str().clone_into(&mut ev.new_state);
    ev.body = note;
    inc.events.push(ev);
    incidents::write_locked(&repo, &inc)?;
    println!("incident #{n} -> mitigated");
    Ok(())
}

#[expect(
    clippy::indexing_slicing,
    reason = "rest[i] is gated by the `while i < rest.len()` loop header"
)]
fn cmd_resolve(args: &[String]) -> Result<()> {
    let (n, rest) = take_n(args, "resolve")?;
    let mut reason = String::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--reason" => {
                i += 1;
                reason.clone_from(rest.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("resolve: --reason needs a value".into())
                })?);
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "resolve: unexpected arg {other}"
                )));
            }
        }
        i += 1;
    }
    if reason.trim().is_empty() {
        return Err(GytError::InvalidArgument(
            "resolve: --reason \"<text>\" required (record the root cause / fix)".into(),
        ));
    }
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let mut inc = incidents::read(&repo, n)?;
    let target = IncidentState::Resolved;
    if inc.state == target {
        return Err(GytError::InvalidArgument(format!(
            "incident #{n} already resolved"
        )));
    }
    if !is_allowed_transition(inc.state, target) {
        return Err(GytError::InvalidArgument(format!(
            "incident #{n}: cannot transition {} -> resolved",
            inc.state.as_str()
        )));
    }
    inc.state = target;
    let mut ev = empty_event(EventKind::Resolve, me, now_ts());
    ev.reason = reason;
    target.as_str().clone_into(&mut ev.new_state);
    inc.events.push(ev);
    incidents::write_locked(&repo, &inc)?;
    println!("incident #{n} -> resolved");
    Ok(())
}

#[expect(
    clippy::indexing_slicing,
    reason = "rest[i] is gated by the `while i < rest.len()` loop header"
)]
fn cmd_reopen(args: &[String]) -> Result<()> {
    let (n, rest) = take_n(args, "reopen")?;
    let mut reason = String::new();
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--reason" => {
                i += 1;
                reason.clone_from(rest.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("reopen: --reason needs a value".into())
                })?);
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "reopen: unexpected arg {other}"
                )));
            }
        }
        i += 1;
    }
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let mut inc = incidents::read(&repo, n)?;
    let target = IncidentState::Investigating;
    if inc.state == target {
        return Err(GytError::InvalidArgument(format!(
            "incident #{n} is already investigating; nothing to reopen"
        )));
    }
    if !is_allowed_transition(inc.state, target) {
        return Err(GytError::InvalidArgument(format!(
            "incident #{n}: cannot reopen from {}",
            inc.state.as_str()
        )));
    }
    inc.state = target;
    let mut ev = empty_event(EventKind::Reopen, me, now_ts());
    ev.reason = reason;
    target.as_str().clone_into(&mut ev.new_state);
    inc.events.push(ev);
    incidents::write_locked(&repo, &inc)?;
    println!("incident #{n} reopened -> investigating");
    Ok(())
}

// ─── severity ────────────────────────────────────────────────────────

fn cmd_severity(args: &[String]) -> Result<()> {
    let (n, rest) = take_n(args, "severity")?;
    let raw = rest.first().ok_or_else(|| {
        GytError::InvalidArgument("severity: new severity required (sev1..sev4)".into())
    })?;
    let new_sev = Severity::parse(raw)?;
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let mut inc = incidents::read(&repo, n)?;
    if inc.severity == new_sev {
        return Err(GytError::InvalidArgument(format!(
            "incident #{n} already {}",
            new_sev.as_str()
        )));
    }
    inc.severity = new_sev;
    let mut ev = empty_event(EventKind::Severity, me, now_ts());
    new_sev.as_str().clone_into(&mut ev.new_severity);
    inc.events.push(ev);
    incidents::write_locked(&repo, &inc)?;
    println!("incident #{n} severity -> {}", new_sev.as_str());
    Ok(())
}

// ─── label / assign ──────────────────────────────────────────────────

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
    let mut inc = incidents::read(&repo, n)?;
    for l in &add {
        if !inc.labels.contains(l) {
            inc.labels.push(l.clone());
        }
    }
    inc.labels.retain(|l| !remove.contains(l));
    inc.labels.sort();
    inc.labels.dedup();
    let mut ev = empty_event(EventKind::Label, me, now_ts());
    ev.add = add;
    ev.remove = remove;
    inc.events.push(ev);
    incidents::write_locked(&repo, &inc)?;
    println!("updated labels on incident #{n}");
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
    let mut inc = incidents::read(&repo, n)?;
    for who in &add {
        if !inc.assignees.contains(who) {
            inc.assignees.push(who.clone());
        }
    }
    inc.assignees.retain(|w| !remove.contains(w));
    inc.assignees.sort();
    inc.assignees.dedup();
    let mut ev = empty_event(EventKind::Assign, me, now_ts());
    ev.add = add;
    ev.remove = remove;
    inc.events.push(ev);
    incidents::write_locked(&repo, &inc)?;
    println!("updated assignees on incident #{n}");
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

// ─── field set/get ────────────────────────────────────────────────────

fn cmd_field(args: &[String]) -> Result<()> {
    let (n, rest) = take_n(args, "field")?;
    let (op, rest) = rest.split_first().ok_or_else(|| {
        GytError::InvalidArgument("field: subcommand required (set|get)".into())
    })?;
    match op.as_str() {
        "set" => cmd_field_set(n, rest),
        "get" => cmd_field_get(n, rest),
        other => Err(GytError::InvalidArgument(format!(
            "field: unknown subcommand {other} (use set|get)"
        ))),
    }
}

fn cmd_field_set(n: u64, rest: &[String]) -> Result<()> {
    let key = rest
        .first()
        .ok_or_else(|| GytError::InvalidArgument("field set: KEY required".into()))?;
    let val = rest
        .get(1)
        .ok_or_else(|| GytError::InvalidArgument("field set: VALUE required".into()))?;
    if key.trim().is_empty() {
        return Err(GytError::InvalidArgument(
            "field set: KEY must not be blank".into(),
        ));
    }
    let repo = open_repo()?;
    let me = identity(&repo)?;
    let _lock = repo.lock()?;
    let mut inc = incidents::read(&repo, n)?;
    inc.fields.insert(key.clone(), val.clone());
    let mut ev = empty_event(EventKind::SetField, me, now_ts());
    ev.field_key.clone_from(key);
    ev.field_value.clone_from(val);
    inc.events.push(ev);
    incidents::write_locked(&repo, &inc)?;
    println!("incident #{n}: {key} = {val}");
    Ok(())
}

fn cmd_field_get(n: u64, rest: &[String]) -> Result<()> {
    let key = rest
        .first()
        .ok_or_else(|| GytError::InvalidArgument("field get: KEY required".into()))?;
    let repo = open_repo()?;
    let inc = incidents::read(&repo, n)?;
    match inc.fields.get(key) {
        Some(v) => {
            println!("{v}");
            Ok(())
        }
        None => Err(GytError::NotFound(format!(
            "incident #{n}: no field {key}"
        ))),
    }
}
