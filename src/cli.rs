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
        "issue" => crate::cmd::issue::run_issue(rest),
        "discussion" => crate::cmd::issue::run_discussion(rest),
        "pr" => crate::cmd::pr::run(rest),
        "incident" => crate::cmd::incident::run(rest),
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

REPOSITORY
    init [<path>] [--bare]       create a new repository
    clone <url> [<dir>] [--insecure]
                                 clone a repository
    config --list | --get <key>
    config --set <key> <val> [--global]
    config --unset <key> [--global]
    remote -v | add <name> <url>

WORKING TREE
    status [--short|--porcelain] show working tree status (incl. ahead/behind)
    add <path>... | [-A]         stage files (use -A to also stage removals)
    rm [-f] <path>...            remove files
    clean [-n]                   remove untracked files (dry-run with -n)
    restore [--staged] [--worktree] [--source=<rev>] <path>...
                                 restore files from HEAD / index / arbitrary rev

HISTORY
    commit -m <msg> [--amend] [--allow-empty] [--sign|-S]
                                 create a commit
    log [--oneline] [--graph] [--all] [--show-signature]
        [--author PAT] [--grep PAT] [--since TS] [--until TS]
        [-n N] [-- <path>...]    show commit history
    show [--show-signature] <rev>
                                 show a commit / tag / tree / blob
    diff [<rev>] [<rev>] [--cached|--staged] [--stat]
    blame [<rev>] [--] <path>    line-by-line authorship
    reflog [<ref>] [--all] [-n N]
                                 show ref-movement history

BRANCHES & MERGING
    branch [<name>] | -d <name> | -D <name> | -m <old> <new>
    switch [-c] <branch>         switch to a branch
    reset [--soft|--mixed|--hard [--force]] <rev>
    merge [<rev>] [--ff-only] [--no-ff] [-m <msg>]
                                 real three-way merge
    rebase [--ff-only] [--abort] [--continue] <upstream>
    cherry-pick <commit>         apply a commit's changes (three-way)
    tag [<name> [<rev>]] | -a <name> -m <msg> | -d <name> | -l
    stash {{push [-m <msg>] | pop | apply | list | drop}}
    worktree {{add [-b <branch>] <path> | list | remove <path>}}

REMOTE
    fetch [<remote>] [<ref>] [--insecure] [--prune|-p]
    pull  [<remote>] [--insecure]
    push  [<remote>] [<branch>] [--force | --force-with-lease] [--insecure] [--all]

SIGNING
    keygen [--priv <path>] [--pub <path>]
    verify [--pub <path>] [<commit-id>]

SERVER & CI
    serve [--listen <addr>] [--repos <dir>] [--webroot <dir>]
          [--cert <f> --key <f>] [--auth-token <t>]
          [--signers <f>] [--policy-config <f>]
    ci [--list] [--output <dir>]
                                 run sandboxed .wasm CI scripts from .gyt-ci/
    ci secret {{init | set <name> | list | remove <name>}}
    ci env    {{set <name> <val> | list | remove <name>}}

ISSUES & DISCUSSIONS
    issue new <title> [-m <body>]
    issue list [--state open|closed|all]
    issue show <N>
    issue comment <N> -m <body>
    issue close <N> [--reason <text>] | issue reopen <N>
    issue label <N> [--add l1,l2] [--remove l3]
    issue assign <N> [--add \"Name <email>\"] [--remove ...]
    discussion <subcommand>      same surface as `issue` but kind=discussion

PULL REQUESTS
    pr new <title> --source <branch> --target <branch> [-m <body>]
    pr list [--state open|closed|merged|all]
    pr show <N>
    pr comment <N> -m <body>
    pr close <N> [--reason <text>] | pr reopen <N>
    pr merge <N> [--no-ff]
    pr ci-run <N>                run sandboxed .gyt-ci/*.wasm on the
                                 source ref, record the result
    pr label <N> [--add l1,l2] [--remove l3]
    pr assign <N> [--add \"Name <email>\"] [--remove ...]

INCIDENTS
    incident new <title> --severity sev1..sev4 --type TYPE
                                 [--field K=V ...] [type-specific shortcuts]
                                 [--label l1,l2] [--assign \"Name <e>\"] [-m <body>]
    incident list [--state detected|investigating|mitigated|resolved|open|all]
                  [--severity sev1..sev4] [--type T] [--label L]
    incident show <N>
    incident comment <N> -m <body>     (alias: incident update <N> -m <body>)
    incident investigate <N>           detected/mitigated -> investigating
    incident mitigate <N> [--note T]   -> mitigated
    incident resolve <N> --reason T    -> resolved
    incident reopen <N> [--reason T]   resolved/mitigated -> investigating
    incident severity <N> sev1..sev4
    incident label <N> [--add l1,l2] [--remove l3]
    incident assign <N> [--add \"Name <email>\"] [--remove ...]
    incident field <N> set KEY VAL | incident field <N> get KEY
                                 known types (security, outage, bug, data-loss,
                                 performance) get shortcut flags like --cve,
                                 --cwe, --services, --affected-version, ...

UTILITIES
    grep <pattern> [<rev>]
    gc                           prune unreachable objects (keeps reflogs, stash, …)
    getthefuckoutofmyrepo <path>...
                                 permanently rewrite history to purge paths
",
        env!("CARGO_PKG_VERSION")
    );
}
