// `gyt reflog` — show the audit log of ref movements.
//
// Default form: `gyt reflog` shows HEAD's reflog. `gyt reflog <ref>` shows
// the named ref's log. `gyt reflog --all` shows every known reflog.

use crate::errors::{GytError, Result};
use crate::reflog;
use crate::repo::Repo;

#[expect(
    clippy::indexing_slicing,
    reason = "args[i] is gated by the `while i < args.len()` loop header"
)]
pub fn run(args: &[String]) -> Result<()> {
    let mut refname: Option<String> = None;
    let mut all = false;
    let mut max: Option<usize> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                println!(
                    "gyt reflog [<refname>] [--all] [-n <N>]\n\n\
                     Show ref movement history. Default <refname> is HEAD.\n\
                       --all     Show all known reflogs\n\
                       -n N      Limit to the most recent N entries per ref"
                );
                return Ok(());
            }
            "--all" => all = true,
            "-n" | "--max-count" => {
                i += 1;
                let v = args
                    .get(i)
                    .ok_or_else(|| GytError::InvalidArgument("-n needs a value".into()))?;
                max = Some(v.parse().map_err(|_| {
                    GytError::InvalidArgument(format!("-n: not a number: {v}"))
                })?);
            }
            other if !other.starts_with('-') => {
                if refname.is_some() {
                    return Err(GytError::InvalidArgument(
                        "reflog: at most one refname argument".into(),
                    ));
                }
                refname = Some(other.to_string());
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "reflog: unknown flag {other}"
                )));
            }
        }
        i += 1;
    }

    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;

    if all {
        let logs = reflog::list_all(&repo.gyt_dir)?;
        if logs.is_empty() {
            println!("(no reflog entries)");
            return Ok(());
        }
        for (name, entries) in logs {
            println!("== {name} ==");
            print_entries(&entries, max);
            println!();
        }
        return Ok(());
    }

    let name = refname.unwrap_or_else(|| "HEAD".to_string());
    let entries = reflog::entries(&repo.gyt_dir, &name)?;
    if entries.is_empty() {
        println!("(no reflog for {name})");
        return Ok(());
    }
    print_entries(&entries, max);
    Ok(())
}

#[expect(
    clippy::string_slice,
    reason = "ObjectId::to_hex returns ASCII hex; every byte boundary is a char boundary"
)]
fn print_entries(entries: &[reflog::Entry], max: Option<usize>) {
    let take = max.unwrap_or(entries.len());
    // Newest first.
    for (i, e) in entries.iter().rev().take(take).enumerate() {
        let short_new = &e.new.to_hex()[..8];
        let short_old = e.old.map(|o| o.to_hex()[..8].to_string());
        match short_old {
            Some(s) => println!(
                "{short_new} {s}..{short_new} {ts} {who}\t{msg}",
                ts = e.timestamp,
                who = e.who,
                msg = e.message
            ),
            None => println!(
                "{short_new} (create) {ts} {who}\t{msg}",
                ts = e.timestamp,
                who = e.who,
                msg = e.message
            ),
        }
        let _ = i;
    }
}
