// CI dispatcher.
//
// WASM is the *only* runtime. Shell scripts and docker were removed because
// neither can be confined to a useful security boundary on a multi-tenant
// host: `sh` runs unbounded with full network + filesystem, and docker
// requires daemon privileges and is regularly exploitable through kernel
// shared state. The wasmtime sandbox in `crate::ci_wasm` is the supported
// execution path.

use crate::ci_wasm::{collect_wasm_scripts, run_ci_wasm};
use crate::cmd::{ci_env, ci_secret};
use crate::errors::{GytError, Result};
use std::path::PathBuf;

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let gyt_dir = cwd.join(".gyt");

    if !args.is_empty() && args[0] == "secret" {
        return run_secret(&args[1..], &gyt_dir);
    }
    if !args.is_empty() && args[0] == "env" {
        return run_env(&args[1..], &gyt_dir);
    }

    let mut output_dir: Option<PathBuf> = None;
    let mut list_mode = false;

    if !args.is_empty() && args[0] == "--help" {
        print_help();
        return Ok(());
    }

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--list" => list_mode = true,
            "--output" => {
                i += 1;
                if i >= args.len() {
                    return Err(GytError::InvalidArgument("--output needs a path".into()));
                }
                output_dir = Some(PathBuf::from(&args[i]));
            }
            // Reject the old --docker flag loudly so legacy CI pipelines
            // surface the migration instead of silently doing the wrong
            // thing (running unsandboxed shell).
            "--docker" => {
                return Err(GytError::InvalidArgument(
                    "--docker is no longer supported; convert your .sh scripts to .wasm (see docs/ci-wasm.md)".into(),
                ));
            }
            _ => {
                eprintln!("gyt ci: unknown flag '{}'", args[i]);
                eprintln!("usage: gyt ci [--list] [--output <dir>]");
                return Ok(());
            }
        }
        i += 1;
    }

    if !gyt_dir.is_dir() {
        return Err(GytError::NotFound(
            "no .gyt directory -- not a gyt repository".into(),
        ));
    }

    let ci_dir = cwd.join(".gyt-ci");
    if !ci_dir.is_dir() {
        eprintln!("gyt ci: no .gyt-ci directory found");
        return Ok(());
    }

    let out = output_dir.unwrap_or_else(|| cwd.join(".gyt-ci-output"));
    if !out.exists() {
        std::fs::create_dir_all(&out).map_err(GytError::Io)?;
    }

    let wasms = collect_wasm_scripts(&ci_dir);

    // Surface .sh files as an explicit deprecation: silently ignoring them
    // would let a workflow author believe their pipeline is running when
    // it isn't.
    let stray_sh = stray_shell_scripts(&ci_dir);
    if !stray_sh.is_empty() {
        eprintln!(
            "gyt ci: warning: {} .sh script(s) in .gyt-ci/ are ignored; only .wasm is supported",
            stray_sh.len()
        );
        for s in &stray_sh {
            eprintln!("  ignored: {}", s.file_name().unwrap().to_string_lossy());
        }
    }

    if list_mode {
        if wasms.is_empty() {
            println!("No WASM CI scripts found in .gyt-ci/");
        } else {
            println!("WASM CI scripts:");
            for w in &wasms {
                println!("  {}", w.file_name().unwrap().to_string_lossy());
            }
        }
        return Ok(());
    }

    if wasms.is_empty() {
        eprintln!("gyt ci: no .wasm scripts found in .gyt-ci/");
        return Ok(());
    }

    println!("Running {} WASM CI scripts...", wasms.len());
    for (idx, wasm) in wasms.iter().enumerate() {
        let name = wasm.file_name().unwrap().to_string_lossy();
        println!("\n  [{}/{}] {name}", idx + 1, wasms.len());
        match run_ci_wasm(wasm, &cwd, &out) {
            Ok(()) => println!("  PASS"),
            Err(e) => {
                println!("  FAIL: {e}");
                return Err(GytError::Ci(format!("WASM CI step {name} failed: {e}")));
            }
        }
    }
    println!("\nAll WASM CI steps PASSED");
    Ok(())
}

fn print_help() {
    eprintln!("Usage: gyt ci [--list] [--output <dir>]");
    eprintln!();
    eprintln!("Runs sandboxed WASM CI scripts from .gyt-ci/.");
    eprintln!();
    eprintln!("Subcommands:");
    eprintln!("  secret          Manage encrypted CI secrets (file storage only;");
    eprintln!("                  WASM scripts must read them as files, never via env)");
    eprintln!("  env             Manage CI environment variables (same caveat)");
    eprintln!();
    eprintln!("Removed: --docker and shell (.sh) scripts. They cannot be sandboxed.");
}

fn stray_shell_scripts(ci_dir: &std::path::Path) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(ci_dir) else {
        return vec![];
    };
    let mut out: Vec<PathBuf> = rd
        .filter_map(std::result::Result::ok)
        .filter(|e| {
            e.path().extension().is_some_and(|ext| ext == "sh")
                && e.file_type().is_ok_and(|t| t.is_file())
        })
        .map(|e| e.path())
        .collect();
    out.sort();
    out
}

fn run_secret(args: &[String], gyt_dir: &std::path::Path) -> Result<()> {
    if args.is_empty() || args[0] == "--help" {
        eprintln!("Usage: gyt ci secret <subcommand> [args]");
        eprintln!();
        eprintln!("Subcommands:");
        eprintln!("  init            Generate or verify the CI encryption key");
        eprintln!("  set <name>      Encrypt a secret from stdin and store it");
        eprintln!("  list            List stored secret names (values never printed)");
        eprintln!("  remove <name>   Delete a stored secret");
        return Ok(());
    }
    match args[0].as_str() {
        "init" => ci_secret::run_init(&args[1..]),
        "set" => ci_secret::run_set(&args[1..], gyt_dir),
        "list" => ci_secret::run_list(&args[1..], gyt_dir),
        "remove" => ci_secret::run_remove(&args[1..], gyt_dir),
        other => Err(GytError::InvalidArgument(format!(
            "unknown ci secret subcommand: {other}"
        ))),
    }
}

fn run_env(args: &[String], gyt_dir: &std::path::Path) -> Result<()> {
    if args.is_empty() || args[0] == "--help" {
        eprintln!("Usage: gyt ci env <subcommand> [args]");
        eprintln!();
        eprintln!("Subcommands:");
        eprintln!("  set <name> <value>   Set a CI environment variable");
        eprintln!("  list                 List CI environment variables");
        eprintln!("  remove <name>        Remove a CI environment variable");
        return Ok(());
    }
    match args[0].as_str() {
        "set" => ci_env::run_set(&args[1..], gyt_dir),
        "list" => ci_env::run_list(&args[1..], gyt_dir),
        "remove" => ci_env::run_remove(&args[1..], gyt_dir),
        other => Err(GytError::InvalidArgument(format!(
            "unknown ci env subcommand: {other}"
        ))),
    }
}
