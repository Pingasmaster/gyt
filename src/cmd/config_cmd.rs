use crate::config::Config;
use crate::errors::{GytError, Result};
use crate::repo::Repo;

pub fn run(args: &[String]) -> Result<()> {
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_usage();
        return Ok(());
    }
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    let cfg = Config::load(&repo)?;

    let mut global = false;
    let mut positional: Vec<&str> = Vec::new();
    for a in args {
        match a.as_str() {
            "--global" => global = true,
            other => positional.push(other),
        }
    }

    match positional.as_slice() {
        ["--list"] => {
            cmd_list(&cfg);
            Ok(())
        }
        ["--get", key] => {
            cmd_get(&cfg, key);
            Ok(())
        }
        ["--set", key, value] => cmd_set(&repo, global, key, value),
        ["--unset", key] => cmd_unset(&repo, global, key),
        [other, ..] => {
            eprintln!("unknown config flag: {other:?}");
            print_usage();
            Ok(())
        }
        [] => {
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

fn cmd_set(repo: &Repo, global: bool, key: &str, value: &str) -> Result<()> {
    let target_dir = config_target_dir(repo, global)?;
    let mut cfg = read_target(&target_dir)?;
    apply_key(&mut cfg, key, Some(value))?;
    cfg.write(&target_dir)?;
    println!("{key} = {value:?} (in {})", target_dir.display());
    Ok(())
}

fn cmd_unset(repo: &Repo, global: bool, key: &str) -> Result<()> {
    let target_dir = config_target_dir(repo, global)?;
    let mut cfg = read_target(&target_dir)?;
    apply_key(&mut cfg, key, None)?;
    cfg.write(&target_dir)?;
    println!("{key} unset (in {})", target_dir.display());
    Ok(())
}

/// Where to write the config file. Without --global: the repo's
/// `.gyt/config.toml`. With --global: `$GYT_CONFIG_HOME/config.toml` or
/// `$HOME/.config/gyt/config.toml`.
fn config_target_dir(repo: &Repo, global: bool) -> Result<std::path::PathBuf> {
    if global {
        let path = crate::config::global_config_path().ok_or_else(|| {
            GytError::Repo("global config: HOME / GYT_CONFIG_HOME not set".into())
        })?;
        // global_config_path returns "<dir>/config.toml"; Config::write expects the *directory*.
        let dir = path
            .parent()
            .ok_or_else(|| GytError::Repo("global config path has no parent".into()))?
            .to_path_buf();
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    } else {
        Ok(repo.gyt_dir.clone())
    }
}

/// Read the config that lives directly inside `dir` (looks for
/// `<dir>/config.toml`). Returns Config::default() if the file doesn't
/// exist yet so that --set on a fresh global config works.
fn read_target(dir: &std::path::Path) -> Result<Config> {
    let path = dir.join("config.toml");
    if !path.exists() {
        return Ok(Config::default());
    }
    let bytes = crate::fs_util::read_all(&path)?;
    crate::config::parse(&bytes)
}

fn apply_key(cfg: &mut Config, key: &str, value: Option<&str>) -> Result<()> {
    let parts: Vec<&str> = key.split('.').collect();
    match parts.as_slice() {
        ["user", "name"] => cfg.user_name = value.map(str::to_string),
        ["user", "email"] => cfg.user_email = value.map(str::to_string),
        ["remote", name, "url"] | ["remote", name] => match value {
            Some(v) => {
                cfg.remotes.insert((*name).to_string(), v.to_string());
            }
            None => {
                cfg.remotes.remove(*name);
            }
        },
        ["commit", "sign_required"] => {
            cfg.sign_required = matches!(value, Some(v) if v.eq_ignore_ascii_case("true"));
        }
        ["init", "create_default_gytignore"] => {
            cfg.create_default_gytignore = matches!(value, Some(v) if v.eq_ignore_ascii_case("true"));
        }
        _ => {
            return Err(GytError::InvalidArgument(format!(
                "config: unknown key {key:?} (supported: user.name, user.email, \
                 remote.<name>[.url], commit.sign_required, init.create_default_gytignore)"
            )));
        }
    }
    Ok(())
}

fn print_usage() {
    eprintln!(
        "usage:\n\
            gyt config --list                       list all config\n\
            gyt config --get <key>                  get a single value\n\
            gyt config --set <key> <value> [--global]\n\
            gyt config --unset <key>       [--global]\n\
        Supported keys: user.name, user.email, remote.<n>.url,\n\
                        commit.sign_required, init.create_default_gytignore"
    );
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
            ci_mode: Default::default(),
            ci_job_modes: Default::default(),
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
            ci_mode: Default::default(),
            ci_job_modes: Default::default(),
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
