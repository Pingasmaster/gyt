use crate::cmd::util;
use crate::errors::{GytError, Result};
use crate::object::commit;
use crate::repo::Repo;
use crate::term;
use std::collections::HashSet;

pub fn run(args: &[String]) -> Result<()> {
    let mut full = false;
    let mut rev: Option<String> = None;
    for a in args {
        match a.as_str() {
            "--help" | "-h" => {
                println!("gyt log [<rev>] [--full]");
                return Ok(());
            }
            "--full" => full = true,
            other if other.starts_with("--") => {
                return Err(GytError::InvalidArgument(format!(
                    "log: unknown flag {other}"
                )));
            }
            other => {
                if rev.is_some() {
                    return Err(GytError::InvalidArgument(
                        "log: at most one rev argument".into(),
                    ));
                }
                rev = Some(other.to_string());
            }
        }
    }

    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    let start = util::resolve_rev(&repo, rev.as_deref().unwrap_or("HEAD"))?;

    let use_color = term::use_color();
    let mut seen: HashSet<crate::hash::ObjectId> = HashSet::new();
    let mut cur = Some(start);
    while let Some(id) = cur {
        if !seen.insert(id) {
            break;
        }
        let c = commit::read(&repo.objects_dir(), &id)?;
        let hex = id.to_hex();
        let short = &hex[..8];
        let first = c.message.lines().next().unwrap_or("");
        let author_name = primary_author_name(c.primary_author());
        let line = format!(
            "{}  {}     {}",
            term::paint_when(use_color, term::YELLOW, short),
            first,
            term::paint_when(use_color, term::CYAN, &author_name)
        );
        println!("{line}");

        if full {
            for p in &c.parents {
                println!("parent {p}");
            }
            for a in &c.authors {
                println!("author {a}");
            }
            println!("committer {}", c.committer);
            for ai in &c.ai_assists {
                println!("ai {ai}");
            }
            for r in &c.reviewers {
                println!("reviewer {r}");
            }
            println!();
            println!("{}", c.message);
            println!();
        }

        cur = c.parents.first().copied();
    }
    Ok(())
}

/// Pull the "Name <email>" portion out of an author line that looks like
/// "Name <email> <secs> +tz". Falls back to the whole string.
fn primary_author_name(a: &str) -> String {
    if let Some(idx) = a.rfind('>') {
        return a[..=idx].to_string();
    }
    a.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};
    use std::fs;

    #[test]
    fn log_walks_history() {
        let _g = lock();
        let dir = tmp_dir("gyt-log");
        crate::cmd::init::init_at(&dir).unwrap();
        let cfg = crate::config::Config {
            user_name: Some("T".into()),
            user_email: Some("t@x".into()),
            ..crate::config::Config::default()
        };
        cfg.write(&dir.join(".gyt")).unwrap();
        fs::write(dir.join("a.txt"), b"a").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "first".to_string()]).unwrap();
        fs::write(dir.join("a.txt"), b"aa").unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "second".to_string()]).unwrap();
        let r = run(&[]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
