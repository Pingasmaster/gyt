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
        "blame" => crate::cmd::blame::run(rest),
        "keygen" => crate::cmd::keygen::run(rest),
        "verify" => crate::cmd::verify::run(rest),
        "add" => crate::cmd::add::run(rest),
        "status" => crate::cmd::status::run(rest),
        "commit" => crate::cmd::commit::run(rest),
        "log" => crate::cmd::log::run(rest),
        "show" => crate::cmd::show::run(rest),
        "diff" => crate::cmd::diff::run(rest),
        "branch" => crate::cmd::branch::run(rest),
        "clean" => crate::cmd::clean::run(rest),
        "switch" => crate::cmd::switch::run(rest),
        "restore" => crate::cmd::restore::run(rest),
        "reset" => crate::cmd::reset::run(rest),
        "rm" => crate::cmd::rm::run(rest),
        "tag" => crate::cmd::tag::run(rest),
        "cherry-pick" => crate::cmd::cherry_pick::run(rest),
        "rebase" => crate::cmd::rebase::run(rest),
        "reflog" => crate::cmd::reflog_cmd::run(rest),
        "grep" => crate::cmd::grep_cmd::run(rest),
        "gc" => crate::cmd::gc::run(rest),
        "stash" => crate::cmd::stash::run(rest),
        "worktree" => crate::cmd::worktree::run(rest),
        "clone" => crate::cmd::clone::run(rest),
        "config" => crate::cmd::config_cmd::run(rest),
        "fetch" => crate::cmd::fetch::run(rest),
        "pull" => crate::cmd::pull::run(rest),
        "push" => crate::cmd::push::run(rest),
        "remote" => crate::cmd::remote::run(rest),
        "merge" => crate::cmd::merge::run(rest),
        "ci" => crate::cmd::ci::run(rest),
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
    keygen               generate ed25519 signing keypair
    verify [<commit>]    verify a signed commit's signature
    add <path>...|[-A]   stage files (use -A to also stage removals)
    status               show working tree status
    clean [-n]           remove untracked files (dry-run with -n)
    commit -m <msg> [--allow-empty] [--sign|-S]
    log [--oneline] [--graph] [--all]
    show <rev>           show a commit or object
    diff [<rev>] [--cached|--staged] [--stat]
    branch [<name>]      list or create branches
    switch <branch>      switch to a branch
    restore <path>...    discard unstaged changes
    reset [--soft|--mixed|--hard] <rev>
    reflog [<ref>] [--all] [-n N]  show ref-movement history
    tag <name> [<rev>]   create a tag
    rm <path>...         remove files
    grep <pattern>       search content
    gc                   garbage collect unreachable objects
    cherry-pick <commit> apply a commit's changes
    rebase <branch>      fast-forward rebase
    merge --ff-only <rev>  fast-forward merge
    pull   [<remote>]    fetch + merge
    push   [<remote>]    push to remote
    fetch  [<remote>]    fetch from remote
    clone  <url> [<dir>] clone a repository
    remote -v            list remotes
    config --list|--get <key>
    stash {{push|pop|list|drop}}
    worktree {{add|list|remove}}
    serve [--listen <addr>] [--repos <dir>] [--webroot <dir>]
    getthefuckoutofmyrepo  clear repo metadata
",
        env!("CARGO_PKG_VERSION")
    );
}
