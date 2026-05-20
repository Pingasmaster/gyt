// CI dispatcher.
//
// WASM is the *only* runtime. Shell scripts and docker were removed because
// neither can be confined to a useful security boundary on a multi-tenant
// host: `sh` runs unbounded with full network + filesystem, and docker
// requires daemon privileges and is regularly exploitable through kernel
// shared state. The wasmtime sandbox in `crate::ci_wasm` is the supported
// execution path.

use crate::ci_wasm::{CiPolicy, CiSlot, collect_wasm_scripts, run_ci_wasm_watched};
use crate::cmd::{ci_env, ci_secret};
use crate::errors::{GytError, Result};
use std::path::PathBuf;

#[expect(
    clippy::indexing_slicing,
    reason = "every args[0] / args[1..] / args[i] access is gated by an explicit args.is_empty() / i < args.len() check"
)]
#[expect(
    clippy::unwrap_used,
    reason = "wasm.file_name() on a PathBuf that came from a successful read_dir entry is always Some; the iteration source guarantees there's a final component"
)]
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
    let mut policy = CiPolicy::default();

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
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("--output needs a path".into())
                })?;
                output_dir = Some(PathBuf::from(v));
            }
            // ── Operator-only permission grants (every flag here
            // widens what the wasm can do; defaults are conservative).
            "--ci-no-repo-read" => policy.repo_read = false,
            "--ci-repo-write" => policy.repo_write = true,
            "--ci-no-output-write" => policy.output_write = false,
            "--ci-read" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("--ci-read needs a path".into())
                })?;
                policy.extra_read.push(PathBuf::from(v));
            }
            "--ci-write" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("--ci-write needs a path".into())
                })?;
                policy.extra_write.push(PathBuf::from(v));
            }
            "--ci-allow-network" => {
                // Reserved vocabulary: no socket-style hostcall is
                // linked even when this is true. The flag exists so
                // future implementation has an operator-grant gate
                // already in place and well-tested.
                policy.network = true;
            }
            "--ci-memory" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("--ci-memory needs a value (e.g. 4096MB)".into())
                })?;
                policy.memory_max = parse_byte_size(v)?;
            }
            "--ci-fuel" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("--ci-fuel needs a value".into())
                })?;
                policy.fuel = v
                    .parse::<u64>()
                    .map_err(|_| GytError::InvalidArgument(format!("--ci-fuel: not a u64: {v}")))?;
            }
            "--ci-time" => {
                i += 1;
                let v = args.get(i).ok_or_else(|| {
                    GytError::InvalidArgument("--ci-time needs seconds".into())
                })?;
                policy.wall_time_secs = v.parse::<u64>().map_err(|_| {
                    GytError::InvalidArgument(format!("--ci-time: not a u64: {v}"))
                })?;
            }
            // Reject the old --docker flag loudly so legacy CI pipelines
            // surface the migration instead of silently doing the wrong
            // thing (running unsandboxed shell).
            "--docker" => {
                return Err(GytError::InvalidArgument(
                    "--docker is no longer supported; convert your .sh scripts to .wasm".into(),
                ));
            }
            _ => {
                eprintln!("gyt ci: unknown flag '{}'", args[i]);
                eprintln!("usage: gyt ci [--list] [--output <dir>] [permission flags — see --help]");
                return Ok(());
            }
        }
        i += 1;
    }

    // If the operator asked for network, currently warn loudly but
    // continue (the run won't actually have network because no
    // hostcall is linked; this is just to give them a clear signal
    // that nothing magical happens).
    if policy.network {
        eprintln!(
            "gyt ci: --ci-allow-network grants are reserved; no network hostcall is yet linked, so no actual network access will be permitted in this run."
        );
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
    // C5: refuse to use the output dir if it (or a parent component of
    // the leaf) is a symlink. A malicious clone could ship a
    // `.gyt-ci-output -> ~/.ssh` symlink; default policy is
    // output_write=true so the wasm gets write access to ~/.ssh.
    if let Ok(meta) = std::fs::symlink_metadata(&out) {
        if meta.file_type().is_symlink() {
            return Err(GytError::Ci(format!(
                "gyt ci: output dir {} is a symlink; refusing (remove it or pass --ci-output)",
                out.display()
            )));
        }
    } else {
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
    print_policy_summary(&policy);

    // Per-job concurrency control, driven by `.gyt/config.toml` (local /
    // operator-controlled, NOT part of a clone, so a malicious repo
    // cannot flip it). The global `[ci] mode` picks the default and the
    // contention domain (per-job vs one shared "all" domain); a
    // `[ci.<job>] mode` override sets a specific job to interrupt /
    // queue / parallel. CiSlot::enter blocks (queue), preempts
    // (interrupt), or is inert (parallel) accordingly.
    let cfg = crate::config::Config::load(&crate::repo::Repo::open(&cwd)?)?;

    for (idx, wasm) in wasms.iter().enumerate() {
        let name = wasm.file_name().unwrap().to_string_lossy();
        let job = wasm
            .file_stem()
            .map_or_else(|| name.clone().into_owned(), |s| s.to_string_lossy().into_owned());
        let mode = cfg.effective_ci_job_mode(&job);
        let domain = cfg.ci_domain_key(&job);
        println!(
            "\n  [{}/{}] {name} ({})",
            idx + 1,
            wasms.len(),
            ci_mode_label(mode)
        );

        // Enter the concurrency domain. This may block (queue mode) or
        // preempt the in-progress holder (interrupt mode) before we run.
        let slot = CiSlot::enter(&gyt_dir, &domain, mode)?;
        let watch = slot.watch();
        let res = run_ci_wasm_watched(wasm, &cwd, &out, &policy, watch.as_ref());
        // Release the slot before reporting so the domain is free the
        // moment this job finishes.
        drop(slot);
        match res {
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

const fn ci_mode_label(mode: crate::config::CiJobMode) -> &'static str {
    match mode {
        crate::config::CiJobMode::Parallel => "parallel",
        crate::config::CiJobMode::Queue => "queue",
        crate::config::CiJobMode::Interrupt => "interrupt",
    }
}

#[expect(
    clippy::integer_division,
    reason = "human-readable MiB conversion: truncating integer division of memory_max to MiB is the intended output"
)]
fn print_policy_summary(p: &CiPolicy) {
    eprintln!(
        "  sandbox: repo_read={}, repo_write={}, output_write={}, extra_read={}, extra_write={}, network={}",
        p.repo_read,
        p.repo_write,
        p.output_write,
        p.extra_read.len(),
        p.extra_write.len(),
        p.network,
    );
    eprintln!(
        "  limits:  memory={} MiB, fuel={}, wall_time={}s",
        p.memory_max / (1024 * 1024),
        p.fuel,
        p.wall_time_secs,
    );
}

/// Parse "1024", "1024MB", "8GB", "512KB". Accepts decimal multipliers
/// (MiB/GiB precision isn't worth the parser cost) — operators size
/// in round MB / GB.
fn parse_byte_size(s: &str) -> Result<usize> {
    let s = s.trim();
    let (num, mult): (&str, usize) = if let Some(n) = s.strip_suffix("GB") {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("MB") {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix("KB") {
        (n, 1024)
    } else if let Some(n) = s.strip_suffix("B") {
        (n, 1)
    } else {
        (s, 1)
    };
    let v: u64 = num.trim().parse().map_err(|_| {
        GytError::InvalidArgument(format!("byte size: not a number: {s}"))
    })?;
    Ok((v as usize) * mult)
}

fn print_help() {
    eprintln!("Usage: gyt ci [--list] [--output <dir>] [permission flags]");
    eprintln!();
    eprintln!("Runs sandboxed WASM CI scripts from .gyt-ci/. Defaults are");
    eprintln!("conservative — a cloned malicious repo cannot widen them.");
    eprintln!();
    eprintln!("Permission flags (each WIDENS the sandbox; defaults are");
    eprintln!("read-only-repo, write-only-output, no network):");
    eprintln!("  --ci-no-repo-read              deny repo reads");
    eprintln!("  --ci-repo-write                allow writes to the repo (not .gyt/)");
    eprintln!("  --ci-no-output-write           deny output writes");
    eprintln!("  --ci-read <PATH>               also allow reads under <PATH>");
    eprintln!("  --ci-write <PATH>              also allow writes under <PATH>");
    eprintln!("  --ci-allow-network             reserved; no network hostcall is");
    eprintln!("                                 currently linked, so this is a noop");
    eprintln!();
    eprintln!("Limits (defaults sized for legitimate Android-class builds):");
    eprintln!("  --ci-memory <SIZE>             memory cap (e.g. 4GB, 512MB)");
    eprintln!("  --ci-fuel <N>                  wasm-instruction cap (default 1e11)");
    eprintln!("  --ci-time <SECS>               wall-time cap (default 14400 = 4h)");
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

#[expect(
    clippy::indexing_slicing,
    reason = "args[0] / args[1..] access is gated by args.is_empty() check on the same line"
)]
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

#[expect(
    clippy::indexing_slicing,
    reason = "args[0] / args[1..] access is gated by args.is_empty() check on the same line"
)]
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
