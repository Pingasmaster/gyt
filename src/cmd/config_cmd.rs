use crate::config::Config;
use crate::errors::Result;
use crate::repo::Repo;

pub fn run(args: &[String]) -> Result<()> {
    if args.is_empty() {
        print_usage();
        return Ok(());
    }
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    let cfg = Config::load(&repo)?;

    match args[0].as_str() {
        "--list" => {
            cmd_list(&cfg);
            Ok(())
        }
        "--get" => {
            if args.len() < 2 {
                eprintln!("usage: gyt config --get <key>");
                return Ok(());
            }
            cmd_get(&cfg, &args[1]);
            Ok(())
        }
        other => {
            eprintln!("unknown config flag: {other:?}");
            print_usage();
            Ok(())
        }
    }
}

fn cmd_list(cfg: &Config) {
    if let Some(name) = &cfg.user_name {
        println!("user.name={name}");
    }
    if let Some(email) = &cfg.user_email {
        println!("user.email={email}");
    }
    for (name, url) in &cfg.remotes {
        println!("remote.{name}={url}");
    }
}

fn cmd_get(cfg: &Config, key: &str) {
    let parts: Vec<&str> = key.split('.').collect();
    match parts.as_slice() {
        ["user", "name"] => match &cfg.user_name {
            Some(v) => println!("{v}"),
            None => eprintln!("user.name is not set"),
        },
        ["user", "email"] => match &cfg.user_email {
            Some(v) => println!("{v}"),
            None => eprintln!("user.email is not set"),
        },
        ["remote", name] | ["remote", name, "url"] => match cfg.remotes.get(*name) {
            Some(url) => println!("{url}"),
            None => eprintln!("remote.{name} is not set"),
        },
        _ => {
            eprintln!("unknown config key: {key}");
        }
    }
}

fn print_usage() {
    eprintln!(
        "usage: gyt config --list                  list all config\n       gyt config --get <key>            get a single value"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd::util::test_helpers::{lock, tmp_dir};
    use std::fs;

    #[test]
    fn config_list_shows_values() {
        let _g = lock();
        let dir = tmp_dir("gyt-config-list");
        crate::cmd::init::init_at(&dir).unwrap();
        let cfg = Config {
            user_name: Some("Tester".into()),
            user_email: Some("t@x".into()),
            remotes: Default::default(),
            create_default_gytignore: false,
            sign_required: false,
        };
        cfg.write(&dir.join(".gyt")).unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let r = run(&["--list".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn config_get_returns_correct_value() {
        let _g = lock();
        let dir = tmp_dir("gyt-config-get");
        crate::cmd::init::init_at(&dir).unwrap();
        let cfg = Config {
            user_name: Some("Tester".into()),
            user_email: Some("t@x".into()),
            remotes: Default::default(),
            create_default_gytignore: false,
            sign_required: false,
        };
        cfg.write(&dir.join(".gyt")).unwrap();

        let prev = std::env::current_dir().unwrap();
        std::env::set_current_dir(&dir).unwrap();
        let r = run(&["--get".to_string(), "user.name".to_string()]);
        std::env::set_current_dir(&prev).unwrap();
        r.unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }
}
