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
        "usage: gyt config --list                  list all config
       gyt config --get <key>            get a single value"
    );
}
