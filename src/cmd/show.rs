use crate::cmd::util;
use crate::diff;
use crate::errors::{GytError, Result};
use crate::hash::ObjectId;
use crate::object::{ObjectKind, blob, commit, store, tag, tree};
use crate::repo::Repo;
use crate::term;
use std::collections::BTreeMap;
use std::path::PathBuf;

pub fn run(args: &[String]) -> Result<()> {
    let mut rev: Option<String> = None;
    let mut show_sig = false;
    for a in args {
        match a.as_str() {
            "--help" | "-h" => {
                println!("gyt show [--show-signature] <rev>");
                return Ok(());
            }
            "--show-signature" => show_sig = true,
            other => {
                if rev.is_some() {
                    return Err(GytError::InvalidArgument(
                        "show: at most one rev argument".into(),
                    ));
                }
                rev = Some(other.to_string());
            }
        }
    }
    let rev = rev.ok_or_else(|| GytError::InvalidArgument("show: <rev> is required".into()))?;

    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    let id = util::resolve_rev(&repo, &rev)?;
    show(&repo, &id, show_sig)
}

fn show(repo: &Repo, id: &ObjectId, show_sig: bool) -> Result<()> {
    let obj = store::read(&repo.gyt_dir, id)?;
    match obj.kind {
        ObjectKind::Blob => {
            let bytes = blob::read(&repo.gyt_dir, id)?;
            match std::str::from_utf8(&bytes) {
                Ok(s) => print!("{s}"),
                Err(_) => println!("<binary, {} bytes>", bytes.len()),
            }
        }
        ObjectKind::Tree => {
            let entries = tree::read(&repo.gyt_dir, id)?;
            for e in entries {
                let name = String::from_utf8_lossy(&e.name);
                println!("{:06o} {}  {name}", e.mode, e.hash);
            }
        }
        ObjectKind::Commit => {
            let c = commit::decode(&obj.payload)?;
            let use_color = term::use_color();
            println!(
                "{} {}",
                term::paint_when(use_color, term::YELLOW, "commit"),
                term::paint_when(use_color, term::YELLOW, &id.to_hex())
            );
            for p in &c.parents {
                println!("parent {p}");
            }
            // F-D10-01: every attacker-controlled string field is
            // routed through `term::s` (a wrapper for safe_display)
            // before output. Otherwise a commit message / author
            // containing `\x1b]0;PWNED\x07` rewrites the operator's
            // terminal title on every `gyt show`.
            for a in &c.authors {
                println!("author {}", term::s(a));
            }
            println!("committer {}", term::s(&c.committer));
            for ai in &c.ai_assists {
                println!("ai {}", term::s(ai));
            }
            for r in &c.reviewers {
                println!("reviewer {}", term::s(r));
            }
            if show_sig {
                print_signature_status(&c, use_color);
            }
            println!();
            print!("{}", term::s(&c.message));
            if !c.message.ends_with('\n') {
                println!();
            }
            println!();

            // Diff against first parent (or empty tree).
            let new_map = util::flatten_tree(repo, &c.tree)?;
            let old_map: BTreeMap<PathBuf, (u32, ObjectId)> =
                if let Some(parent) = c.parents.first() {
                    let pc = commit::read(&repo.gyt_dir, parent)?;
                    util::flatten_tree(repo, &pc.tree)?
                } else {
                    BTreeMap::new()
                };
            print_tree_diff(repo, &old_map, &new_map, use_color)?;
        }
        ObjectKind::Tag => {
            let t = tag::decode(&obj.payload)?;
            println!("tag {}", term::s(&t.name));
            println!("Tagger: {}", term::s(&t.tagger));
            println!("target {} ({})", t.target, t.kind.as_str());
            println!();
            print!("{}", term::s(&t.message));
            if !t.message.ends_with('\n') {
                println!();
            }
            println!();
            // Recurse into the target.
            show(repo, &t.target, show_sig)?;
        }
    }
    Ok(())
}

/// Verify the commit's signature against the default verifying key and
/// print a one-line status. Mirrors what `gyt verify` reports, but inline
/// in `gyt show` / `gyt log --show-signature` so users can audit signing
/// while browsing history.
fn print_signature_status(c: &commit::Commit, use_color: bool) {
    let Some(b64) = &c.signature else {
        let line = "signature: (unsigned)";
        println!("{}", term::paint_when(use_color, term::YELLOW, line));
        return;
    };
    let payload = crate::cmd::signing::commit_payload_without_sig(c);
    match crate::cmd::signing::verify_signature(&payload, b64, None) {
        Ok(true) => {
            let line = "signature: good ed25519 signature";
            println!("{}", term::paint_when(use_color, term::GREEN, line));
        }
        Ok(false) => {
            let line = "signature: BAD ed25519 signature";
            println!("{}", term::paint_when(use_color, term::RED, line));
        }
        Err(e) => {
            let line = format!("signature: verification error ({e})");
            println!("{}", term::paint_when(use_color, term::RED, &line));
        }
    }
}

pub fn print_tree_diff(
    repo: &Repo,
    old_map: &BTreeMap<PathBuf, (u32, ObjectId)>,
    new_map: &BTreeMap<PathBuf, (u32, ObjectId)>,
    use_color: bool,
) -> Result<()> {
    let mut all: std::collections::BTreeSet<&PathBuf> = std::collections::BTreeSet::new();
    for k in old_map.keys() {
        all.insert(k);
    }
    for k in new_map.keys() {
        all.insert(k);
    }
    for p in all {
        let old = old_map.get(p);
        let new = new_map.get(p);
        if old.map(|(_, h)| h) == new.map(|(_, h)| h) {
            continue;
        }
        let old_bytes = match old {
            Some((_, h)) => blob::read(&repo.gyt_dir, h)?,
            None => Vec::new(),
        };
        let new_bytes = match new {
            Some((_, h)) => blob::read(&repo.gyt_dir, h)?,
            None => Vec::new(),
        };
        let header = forward_slash(p);
        let out = diff::render_unified(&old_bytes, &new_bytes, &header, &header, 3, use_color);
        print!("{out}");
    }
    Ok(())
}

fn forward_slash(p: &std::path::Path) -> String {
    let mut s = String::new();
    let mut first = true;
    for comp in p.components() {
        let part = comp.as_os_str().to_string_lossy();
        if !first {
            s.push('/');
        }
        first = false;
        s.push_str(part.as_ref());
    }
    s
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};
    use std::fs;

    #[test]
    fn show_commit_runs() {
        let _g = lock();
        let dir = tmp_dir("gyt-show");
        crate::cmd::init::init_at(&dir).unwrap();
        let cfg = crate::config::Config {
            user_name: Some("T".into()),
            user_email: Some("t@x".into()),
            ..crate::config::Config::default()
        };
        cfg.write(&dir.join(".gyt")).unwrap();
        fs::write(dir.join("a.txt"), b"hello\n").unwrap();
        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        crate::cmd::add::run(&[".".to_string()]).unwrap();
        crate::cmd::commit::run(&["-m".to_string(), "init".to_string()]).unwrap();
        let r = run(&["HEAD".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
