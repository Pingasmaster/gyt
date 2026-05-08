use crate::cmd::branch as branch_cmd;
use crate::cmd::util::resolve_rev;
use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::object::tag::Tag;
use crate::object::{store, tag as tag_obj};
use crate::refs;
use crate::repo::Repo;

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    run_in(&repo, args)
}

fn run_in(repo: &Repo, args: &[String]) -> Result<()> {
    if args.is_empty() {
        return list(repo);
    }
    // Early-return for --list / -l.
    if args.iter().any(|a| a == "--list" || a == "-l") {
        return list(repo);
    }
    // Parse flags.
    let mut annotated = false;
    let mut delete = false;
    let mut message: Option<String> = None;
    let mut name: Option<String> = None;
    let mut rev: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-a" => {
                annotated = true;
                i += 1;
            }
            "-m" => {
                i += 1;
                let m = args
                    .get(i)
                    .ok_or_else(|| GytError::InvalidArgument("tag -m <msg>".into()))?;
                message = Some(m.clone());
                i += 1;
            }
            "-d" => {
                delete = true;
                i += 1;
            }
            other if !other.starts_with('-') => {
                if name.is_none() {
                    name = Some(other.to_string());
                } else if rev.is_none() {
                    rev = Some(other.to_string());
                } else {
                    return Err(GytError::InvalidArgument(
                        "tag: too many positional arguments".into(),
                    ));
                }
                i += 1;
            }
            other => {
                return Err(GytError::InvalidArgument(format!(
                    "tag: unknown option {other}"
                )));
            }
        }
    }

    let name = name.ok_or_else(|| GytError::InvalidArgument("tag: name required".into()))?;
    branch_cmd::validate_branch_name(&name)?;

    if delete {
        if annotated || message.is_some() || rev.is_some() {
            return Err(GytError::InvalidArgument(
                "tag -d <name>: no other options".into(),
            ));
        }
        return refs::delete_ref(&repo.gyt_dir, &format!("refs/tags/{name}"));
    }

    let target = match &rev {
        Some(r) => resolve_rev(repo, r)?,
        None => resolve_rev(repo, "HEAD")?,
    };

    let ref_name = format!("refs/tags/{name}");
    if refs::read_ref(&repo.gyt_dir, &ref_name).is_ok() {
        return Err(GytError::Refs(format!("tag {name} already exists")));
    }

    if annotated {
        let msg =
            message.ok_or_else(|| GytError::InvalidArgument("tag -a requires -m <msg>".into()))?;
        let cfg = Config::load(repo)?;
        let identity = cfg.identity()?;
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let tagger = format!("{identity} {secs} +0000");
        let target_obj = store::read(&repo.gyt_dir, &target)?;
        let tag = Tag {
            target,
            kind: target_obj.kind,
            name: name.clone(),
            tagger,
            message: msg,
        };
        let tag_id = tag_obj::write(&repo.gyt_dir, &tag)?;
        refs::write_ref(&repo.gyt_dir, &ref_name, &tag_id)?;
    } else {
        if message.is_some() {
            return Err(GytError::InvalidArgument(
                "tag: -m only valid with -a".into(),
            ));
        }
        refs::write_ref(&repo.gyt_dir, &ref_name, &target)?;
    }
    Ok(())
}

fn list(repo: &Repo) -> Result<()> {
    let tags = refs::list_refs(&repo.gyt_dir, "refs/tags")?;
    for (full, _id) in tags {
        let short = full.strip_prefix("refs/tags/").unwrap_or(full.as_str());
        println!("{short}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::test_support::TestRepo;
    use crate::object::ObjectKind;
    use crate::object::tag::Tag;

    fn write_test_config(repo: &Repo) {
        let cfg = Config {
            user_name: Some("Tester".into()),
            user_email: Some("t@x".into()),
            ..Default::default()
        };
        cfg.write(&repo.gyt_dir).unwrap();
    }

    #[test]
    fn tag_lightweight_create() {
        let r = TestRepo::new("gyt-tag-lw");
        let repo = r.open();
        let head_id = refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir).unwrap())
            .unwrap()
            .unwrap();
        run_in(&repo, &["v1.0".into()]).unwrap();
        let tag_id = refs::read_ref(&repo.gyt_dir, "refs/tags/v1.0").unwrap();
        // Lightweight: tag ref points at the commit directly.
        assert_eq!(tag_id, head_id);

        // Duplicate rejected.
        assert!(run_in(&repo, &["v1.0".into()]).is_err());
    }

    #[test]
    fn tag_annotated_create() {
        let r = TestRepo::new("gyt-tag-ann");
        let repo = r.open();
        write_test_config(&repo);

        let head_id = refs::resolve(&repo.gyt_dir, &refs::read_head(&repo.gyt_dir).unwrap())
            .unwrap()
            .unwrap();
        run_in(
            &repo,
            &[
                "-a".into(),
                "v1.0".into(),
                "-m".into(),
                "first release".into(),
            ],
        )
        .unwrap();

        let tag_obj_id = refs::read_ref(&repo.gyt_dir, "refs/tags/v1.0").unwrap();
        // It should NOT equal the commit id, it points at a Tag object.
        assert_ne!(tag_obj_id, head_id);

        let obj = store::read(&repo.gyt_dir, &tag_obj_id).unwrap();
        assert_eq!(obj.kind, ObjectKind::Tag);
        let parsed: Tag = crate::object::tag::decode(&obj.payload).unwrap();
        assert_eq!(parsed.target, head_id);
        assert_eq!(parsed.kind, ObjectKind::Commit);
        assert_eq!(parsed.name, "v1.0");
        assert_eq!(parsed.message, "first release");
        assert!(parsed.tagger.contains("Tester"));
        assert!(parsed.tagger.contains("+0000"));
    }

    #[test]
    fn tag_delete() {
        let r = TestRepo::new("gyt-tag-del");
        let repo = r.open();
        run_in(&repo, &["v1.0".into()]).unwrap();
        run_in(&repo, &["-d".into(), "v1.0".into()]).unwrap();
        assert!(refs::read_ref(&repo.gyt_dir, "refs/tags/v1.0").is_err());
    }

    #[test]
    fn tag_list() {
        let r = TestRepo::new("gyt-tag-list");
        let repo = r.open();
        run_in(&repo, &["v1.0".into()]).unwrap();
        run_in(&repo, &["v1.1".into()]).unwrap();
        // List doesn't error.
        run_in(&repo, &[]).unwrap();
        let tags = refs::list_refs(&repo.gyt_dir, "refs/tags").unwrap();
        assert_eq!(tags.len(), 2);
    }
}
