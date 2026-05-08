use crate::config::Config;
use crate::errors::Result;
use crate::repo::Repo;

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let repo = Repo::open(&cwd)?;
    let cfg = Config::load(&repo)?;

    let is_verbose = args == ["-v"];
    if !is_verbose {
        eprintln!("usage: gyt remote -v");
        return Ok(());
    }

    for (name, url) in &cfg.remotes {
        println!("{name}\t{url}");
    }
    Ok(())
}
