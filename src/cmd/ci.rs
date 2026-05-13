#![allow(clippy::redundant_closure_for_method_calls)]
use crate::ci_wasm::{collect_wasm_scripts, run_ci_wasm};
use crate::errors::{GytError, Result};
use crate::cmd::{ci_env, ci_secret};
use std::collections::BTreeMap;
use std::path::PathBuf;

pub fn run(args: &[String]) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let gyt_dir = cwd.join(".gyt");

    // Subcommand dispatch: "ci secret ..." and "ci env ..."
    if !args.is_empty() && args[0] == "secret" {
        return run_secret(&args[1..], &gyt_dir);
    }
    if !args.is_empty() && args[0] == "env" {
        return run_env(&args[1..], &gyt_dir);
    }

    // Regular CI execution
    let mut docker_image: Option<String> = None;
    let mut output_dir: Option<PathBuf> = None;
    let mut list_mode = false;

    if !args.is_empty() && args[0] == "--help" {
        eprintln!("Usage: gyt ci [--list] [--docker <image>] [--output <dir>]");
        eprintln!();
        eprintln!("Subcommands:");
        eprintln!("  secret          Manage encrypted CI secrets");
        eprintln!("  env             Manage CI environment variables");
        eprintln!();
        eprintln!("Runs CI scripts from .gyt-ci/.");
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
            "--docker" => {
                i += 1;
                if i >= args.len() {
                    return Err(GytError::InvalidArgument(
                        "--docker needs an image name".into(),
                    ));
                }
                docker_image = Some(args[i].clone());
            }
            _ => {
                eprintln!("gyt ci: unknown flag '{}'", args[i]);
                eprintln!("usage: gyt ci [--list] [--docker <image>] [--output <dir>]");
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

    // Load env vars and secrets
    let env_map = ci_env::load_env(&gyt_dir)?;
    let secret_map = if env_map.is_empty() && !gyt_dir.join("secrets").is_dir() {
        BTreeMap::new()
    } else {
        match ci_secret::ensure_key() {
            Ok(key) => ci_env::load_secrets(&gyt_dir, &key).unwrap_or_default(),
            Err(_) => BTreeMap::new(),
        }
    };

    let wasms = collect_wasm_scripts(&ci_dir);

    if list_mode {
        if !wasms.is_empty() {
            println!("WASM CI scripts:");
            for w in &wasms {
                println!("  {}", w.file_name().unwrap().to_string_lossy());
            }
        }
        let mut entries: Vec<_> = std::fs::read_dir(&ci_dir)
            .map_err(|e| GytError::Ci(format!("reading .gyt-ci/: {e}")))?
            .filter_map(|r| r.ok())
            .filter(|e| {
                e.path().extension().is_some_and(|ext| ext == "sh")
                    && e.file_type().is_ok_and(|t| t.is_file())
            })
            .map(|e| e.path())
            .collect();
        entries.sort();
        if !entries.is_empty() {
            if !wasms.is_empty() {
                println!();
            }
            println!("Shell scripts:");
            for s in &entries {
                println!("  {}", s.file_name().unwrap().to_string_lossy());
            }
        }
        if wasms.is_empty() && entries.is_empty() {
            println!("No CI scripts found in .gyt-ci/");
        }
        return Ok(());
    }

    if !wasms.is_empty() {
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
        return Ok(());
    }

    let mut entries: Vec<_> = std::fs::read_dir(&ci_dir)
        .map_err(|e| GytError::Ci(format!("reading .gyt-ci/: {e}")))?
        .filter_map(|r| r.ok())
        .filter(|e| {
            e.path().extension().is_some_and(|ext| ext == "sh")
                && e.file_type().is_ok_and(|t| t.is_file())
        })
        .map(|e| e.path())
        .collect();
    entries.sort();

    if entries.is_empty() {
        eprintln!("gyt ci: no .wasm or .sh scripts found in .gyt-ci/");
        return Ok(());
    }

    println!("Running {} shell CI scripts...", entries.len());

    for (idx, script) in entries.iter().enumerate() {
        let name = script.file_name().unwrap().to_string_lossy();
        println!("\n  [{}/{}] {name}", idx + 1, entries.len());

        let result = if let Some(ref img) = docker_image {
            run_in_docker(script, img, &cwd, &env_map, &secret_map)
        } else {
            run_shell_script(script, &cwd, &env_map, &secret_map)
        };

        match result {
            Ok(code) => {
                if code == 0 {
                    println!("  PASS");
                } else {
                    println!("  FAIL (exit code {code})");
                    return Err(GytError::Ci(format!("step {name} exited with code {code}")));
                }
            }
            Err(e) => {
                println!("  FAIL: {e}");
                return Err(GytError::Ci(format!("step {name} failed: {e}")));
            }
        }
    }

    println!("\nAll CI steps PASSED");
    Ok(())
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

fn run_shell_script(
    script: &std::path::Path,
    cwd: &std::path::Path,
    env_map: &BTreeMap<String, String>,
    secret_map: &BTreeMap<String, String>,
) -> Result<i32> {
    use std::process::Command;
    let mut cmd = Command::new("sh");
    cmd.arg(script).current_dir(cwd);
    for (k, v) in env_map {
        cmd.env(k, v);
    }
    for (k, v) in secret_map {
        cmd.env(k, v);
    }
    let output = cmd
        .output()
        .map_err(|e| GytError::Ci(format!("running {}: {e}", script.display())))?;

    let raw_stdout = String::from_utf8_lossy(&output.stdout);
    let raw_stderr = String::from_utf8_lossy(&output.stderr);

    let stdout = ci_env::mask_secrets(&raw_stdout, secret_map);
    let stderr = ci_env::mask_secrets(&raw_stderr, secret_map);

    if !stdout.is_empty() {
        print!("{stdout}");
    }
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }

    Ok(output.status.code().unwrap_or(-1))
}

fn run_in_docker(
    script: &std::path::Path,
    image: &str,
    cwd: &std::path::Path,
    env_map: &BTreeMap<String, String>,
    secret_map: &BTreeMap<String, String>,
) -> Result<i32> {
    use std::io::Write as _;
    use std::process::Command;
    let rel = script.file_name().unwrap().to_string_lossy();

    // Write env vars + secrets to a private env-file. Using `--env-file`
    // (rather than `-e KEY=VALUE` on the command line or `cmd.env(...)` on
    // the docker CLI process) is the only way to get values into the
    // container without leaking them via `ps`, `docker inspect`, or the
    // host environment. The file lives in a process-private tempdir and is
    // unlinked on drop.
    let envfile_dir = mktemp_dir("gyt-ci-docker-env")?;
    let envfile_path = envfile_dir.path().join("env");
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&envfile_path)
            .map_err(|e| GytError::Ci(format!("creating env file: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&envfile_path)
                .map_err(|e| GytError::Ci(format!("stat env file: {e}")))?
                .permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&envfile_path, perms)
                .map_err(|e| GytError::Ci(format!("chmod env file: {e}")))?;
        }
        for (k, v) in env_map.iter().chain(secret_map.iter()) {
            // docker --env-file: lines are `KEY=VALUE` with no quoting.
            // Reject keys/values containing newlines (would split lines).
            if k.contains('\n') || v.contains('\n') {
                return Err(GytError::Ci(format!(
                    "env var {k} contains a newline; refusing to pass to docker"
                )));
            }
            writeln!(f, "{k}={v}").map_err(|e| GytError::Ci(format!("env file: {e}")))?;
        }
    }

    let mut cmd = Command::new("docker");
    cmd.args([
        "run",
        "--rm",
        "--network",
        "none",
        // No additional capabilities; workflows should be sandboxed.
        "--cap-drop",
        "ALL",
        "--read-only",
        "-v",
        &format!("{}:/workspace:ro", cwd.display()),
        // tmpfs for /tmp so workflows have a writable scratch area.
        "--tmpfs",
        "/tmp:exec,size=64m",
        "--env-file",
        &envfile_path.to_string_lossy(),
        "-w",
        "/workspace",
    ]);
    cmd.arg(image);
    cmd.arg("sh");
    cmd.arg(format!("/workspace/.gyt-ci/{rel}"));

    let output = cmd
        .output()
        .map_err(|e| GytError::Ci(format!("running docker: {e}")))?;

    let raw_stdout = String::from_utf8_lossy(&output.stdout);
    let raw_stderr = String::from_utf8_lossy(&output.stderr);

    let stdout = ci_env::mask_secrets(&raw_stdout, secret_map);
    let stderr = ci_env::mask_secrets(&raw_stderr, secret_map);

    if !stdout.is_empty() {
        print!("{stdout}");
    }
    if !stderr.is_empty() {
        eprint!("{stderr}");
    }

    Ok(output.status.code().unwrap_or(-1))
}

/// Tiny scoped tempdir that cleans up on drop. We don't use the `tempfile`
/// crate to keep dependencies minimal.
struct ScopedTempDir(PathBuf);
impl ScopedTempDir {
    fn path(&self) -> &std::path::Path {
        &self.0
    }
}
impl Drop for ScopedTempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn mktemp_dir(prefix: &str) -> Result<ScopedTempDir> {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let path = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"));
    std::fs::create_dir_all(&path)
        .map_err(|e| GytError::Ci(format!("create tempdir {}: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        let _ = std::fs::set_permissions(&path, perms);
    }
    Ok(ScopedTempDir(path))
}