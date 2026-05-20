// Audit 2026-05: parameterized regression guard against the
// "subcommand --help has side effects" bug class.
//
// Commit 07131c2 fixed a bug where `gyt serve --help` would actually
// bind the listener and start serving before printing the usage banner.
// This file iterates over every public subcommand and asserts that
// `gyt <cmd> --help` (and `-h`):
//
//   - exits with status 0
//   - writes nothing to the current working directory
//   - returns quickly (no listener binds, no network waits)
//   - emits a recognisable usage banner on stdout

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_in_result,
    reason = "tests panic on failure"
)]

#[path = "common/mod.rs"]
mod common;

use common::Env;
use std::path::Path;
use std::time::{Duration, Instant};

// Canonical list, kept in sync with `dispatch` in `src/cli.rs`.
// `filter` is the alias for `getthefuckoutofmyrepo`; both are present
// so a future rename of either is caught.
const SUBCOMMANDS: &[&str] = &[
    "init",
    "blame",
    "keygen",
    "verify",
    "add",
    "status",
    "commit",
    "log",
    "show",
    "diff",
    "branch",
    "clean",
    "switch",
    "restore",
    "reset",
    "rm",
    "tag",
    "cherry-pick",
    "rebase",
    "reflog",
    "grep",
    "gc",
    "stash",
    "worktree",
    "clone",
    "config",
    "fetch",
    "pull",
    "push",
    "remote",
    "merge",
    "ci",
    "issue",
    "discussion",
    "pr",
    "incident",
    "serve",
    "getthefuckoutofmyrepo",
    "filter",
];

fn list_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn check_help(cmd: &str, flag: &str) -> Result<(), String> {
    let env = Env::new(&format!("help-{cmd}-{}", flag.trim_start_matches('-')));
    let cwd = env.path("empty");
    std::fs::create_dir_all(&cwd).unwrap();
    let before = list_entries(&cwd);

    let start = Instant::now();
    let out = env.run_in(&cwd, &[cmd, flag]);
    let elapsed = start.elapsed();

    let after = list_entries(&cwd);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();

    if !out.status.success() {
        return Err(format!(
            "`gyt {cmd} {flag}` exited non-zero (code={:?})\nstdout: {stdout}\nstderr: {stderr}",
            out.status.code()
        ));
    }
    if before != after {
        return Err(format!(
            "`gyt {cmd} {flag}` modified cwd: before={before:?} after={after:?}"
        ));
    }
    if elapsed > Duration::from_secs(3) {
        return Err(format!(
            "`gyt {cmd} {flag}` took {elapsed:?} (>3s); likely bound a listener \
             or did real work before printing help"
        ));
    }
    // Be lenient: many subcommands print "Usage: ..." but some print
    // "gyt <cmd> ..." as the first line. Accept either, as long as
    // *something* describing usage appears.
    let combined = format!("{stdout}\n{stderr}");
    let lower = combined.to_lowercase();
    if !(lower.contains("usage") || lower.contains("gyt ")) {
        return Err(format!(
            "`gyt {cmd} {flag}` printed no usage-like banner.\nstdout: {stdout}\nstderr: {stderr}"
        ));
    }
    Ok(())
}

#[test]
fn every_subcommand_help_exits_zero() {
    let mut failures: Vec<String> = Vec::new();
    for cmd in SUBCOMMANDS {
        if let Err(msg) = check_help(cmd, "--help") {
            failures.push(msg);
        }
    }
    assert!(
        failures.is_empty(),
        "{} subcommand(s) failed --help:\n{}",
        failures.len(),
        failures.join("\n---\n")
    );
}

#[test]
fn every_subcommand_dash_h_works() {
    let mut failures: Vec<String> = Vec::new();
    for cmd in SUBCOMMANDS {
        if let Err(msg) = check_help(cmd, "-h") {
            failures.push(msg);
        }
    }
    assert!(
        failures.is_empty(),
        "{} subcommand(s) failed -h:\n{}",
        failures.len(),
        failures.join("\n---\n")
    );
}

#[test]
fn unknown_subcommand_exits_nonzero_with_helpful_message() {
    let env = Env::new("help-unknown");
    let cwd = env.path("empty");
    std::fs::create_dir_all(&cwd).unwrap();
    let out = env.run_in(&cwd, &["definitely-not-a-command", "--help"]);
    assert!(
        !out.status.success(),
        "unknown subcommand unexpectedly succeeded: \
         stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    )
    .to_lowercase();
    assert!(
        combined.contains("unknown") || combined.contains("command"),
        "unknown-subcommand error lacked 'unknown'/'command' keyword: {combined}"
    );
}
