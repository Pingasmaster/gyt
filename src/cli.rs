use crate::errors::{GytError, Result};

pub fn dispatch(args: &[String]) -> Result<()> {
    let Some((cmd, rest)) = args.split_first() else {
        print_usage();
        return Ok(());
    };
    match cmd.as_str() {
        "--help" | "-h" | "help" => {
            print_usage();
            Ok(())
        }
        "--version" | "-V" | "version" => {
            println!("gyt {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "init" => crate::cmd::init::run(rest),
        "add" => crate::cmd::add::run(rest),
        "status" => crate::cmd::status::run(rest),
        "commit" => crate::cmd::commit::run(rest),
        "log" => crate::cmd::log::run(rest),
        "show" => crate::cmd::show::run(rest),
        "diff" => crate::cmd::diff::run(rest),
        "branch" => crate::cmd::branch::run(rest),
        "switch" => crate::cmd::switch::run(rest),
        "restore" => crate::cmd::restore::run(rest),
        "reset" => crate::cmd::reset::run(rest),
        "rm" => crate::cmd::rm::run(rest),
        "tag" => crate::cmd::tag::run(rest),
        "cherry-pick" => crate::cmd::cherry_pick::run(rest),
        "rebase" => crate::cmd::rebase::run(rest),
        "grep" => crate::cmd::grep_cmd::run(rest),
        "stash" => crate::cmd::stash::run(rest),
        "worktree" => crate::cmd::worktree::run(rest),
        "clone" => crate::cmd::clone::run(rest),
        "config" => crate::cmd::config_cmd::run(rest),
        "fetch" => crate::cmd::fetch::run(rest),
        "pull" => crate::cmd::pull::run(rest),
        "push" => crate::cmd::push::run(rest),
        "remote" => crate::cmd::remote::run(rest),
        "merge" => crate::cmd::merge::run(rest),
        "serve" => crate::cmd::serve::run(rest),
        "getthefuckoutofmyrepo" | "filter" => crate::cmd::getthefuckoutofmyrepo::run(rest),
        other => Err(GytError::InvalidArgument(format!(
            "unknown command: {other}"
        ))),
    }
}

fn print_usage() {
    println!(
        "gyt {} -- a small modern version-control tool

USAGE:
    gyt <command> [args]

COMMANDS:
    init                 create a new repository
    add <path>...        stage files
    status               show working tree status
    commit -m <msg>      record staged changes
    log                  show commit history
    show <rev>           show a commit or object
    diff [<rev>]         show changes
    branch [<name>]      list or create branches
    switch <branch>      switch to a branch
    restore <path>...    discard unstaged changes
    reset [--soft|--mixed] <rev>
    tag <name> [<rev>]   create a tag
    stash {{push|pop|list|drop}}
    worktree {{add|list|remove}}
    clone <url> [<dir>]
    fetch [<remote>]
    pull   [<remote>]
    push   [<remote>]
    merge --ff-only <rev>
    serve [--listen <addr>] [--repos <dir>] [--webroot <dir>]
",
        env!("CARGO_PKG_VERSION")
    );
}
