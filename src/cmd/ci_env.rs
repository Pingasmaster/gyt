// CI environment variable management — plaintext vars in .gyt/ci-env.toml.
//
// Env vars are stored under a [env] section and injected into CI workflow
// environments. They are NOT encrypted (unlike secrets). Use for non-sensitive
// configuration like DEPLOY_TARGET=staging.

use crate::errors::{GytError, Result};
use std::collections::BTreeMap;
use std::path::Path;

fn env_path(gyt_dir: &Path) -> std::path::PathBuf {
    gyt_dir.join("ci-env.toml")
}

/// Load CI environment variables from .gyt/ci-env.toml [env] section.
pub fn load_env(gyt_dir: &Path) -> Result<BTreeMap<String, String>> {
    let path = env_path(gyt_dir);
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| GytError::Ci(format!("reading ci-env.toml: {e}")))?;
    let mut map = BTreeMap::new();
    let mut in_env = false;
    for line in raw.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_env = line.trim() == "[env]";
            continue;
        }
        if in_env && line.contains('=') && !line.starts_with('#')
            && let Some((k, v)) = line.split_once('=') {
                let key = k.trim().to_string();
                // Strip surrounding quotes from value
                let val = v.trim().trim_matches('"').to_string();
                map.insert(key, val);
            }
    }
    Ok(map)
}

/// Load and decrypt CI secrets from .gyt/secrets/.
pub fn load_secrets(gyt_dir: &Path, key: &[u8; 32]) -> Result<BTreeMap<String, String>> {
    let sec_dir = gyt_dir.join("secrets");
    if !sec_dir.is_dir() {
        return Ok(BTreeMap::new());
    }
    let mut map = BTreeMap::new();
    for entry in
        std::fs::read_dir(&sec_dir).map_err(|e| GytError::Ci(format!("reading secrets: {e}")))?
    {
        let entry = entry.map_err(|e| GytError::Ci(format!("secret entry: {e}")))?;
        if !entry.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let data = std::fs::read(entry.path())
            .map_err(|e| GytError::Ci(format!("reading secret {name}: {e}")))?;
        match super::ci_secret::decrypt(key, &data) {
            Ok(plaintext) => {
                let value = String::from_utf8_lossy(&plaintext).to_string();
                map.insert(name, value);
            }
            Err(e) => {
                eprintln!("warning: failed to decrypt secret '{name}': {e}");
            }
        }
    }
    Ok(map)
}

/// Replace occurrences of secret values with "***" for output masking.
///
/// Very short secrets (< 8 characters) are NOT masked: the false-positive
/// rate of substring matching dominates the security benefit (a 4-char
/// secret will mask common words in unrelated output). Operators who care
/// about secret hygiene should use long random tokens, which the encrypted
/// store generates anyway.
///
/// Secrets are sorted by length (longest first) so that nested matches —
/// e.g. a base64 token that contains a substring of another token — mask
/// correctly.
pub fn mask_secrets(output: &str, secrets: &BTreeMap<String, String>) -> String {
    const MIN_MASK_LEN: usize = 8;
    let mut values: Vec<&String> = secrets
        .values()
        .filter(|v| v.len() >= MIN_MASK_LEN)
        .collect();
    values.sort_by_key(|v| std::cmp::Reverse(v.len()));
    let mut result = output.to_string();
    for value in values {
        result = result.replace(value.as_str(), "***");
    }
    result
}

#[expect(
    clippy::indexing_slicing,
    reason = "args[0]/args[1] are gated by args.len() < 2 check; lines[i] is gated by the while i < lines.len() loop header"
)]
pub fn run_set(args: &[String], gyt_dir: &Path) -> Result<()> {
    if args.len() < 2 || args[0] == "--help" {
        eprintln!("Usage: gyt ci env set <name> <value>");
        eprintln!();
        eprintln!("Set a CI env var in .gyt/ci-env.toml (plaintext, checkable).");
        return Ok(());
    }
    let name = &args[0];
    let value = &args[1];
    let path = env_path(gyt_dir);
    let raw = if path.exists() {
        std::fs::read_to_string(&path)
            .map_err(|e| GytError::Ci(format!("reading ci-env.toml: {e}")))?
    } else {
        String::new()
    };
    let mut lines: Vec<String> = raw.lines().map(std::string::ToString::to_string).collect();
    // Remove existing entry with same name
    let mut i = 0;
    let mut in_env = false;
    let mut has_env_section = false;
    while i < lines.len() {
        let trimmed = lines[i].trim().to_string();
        if trimmed.starts_with('[') {
            in_env = trimmed == "[env]";
            if in_env {
                has_env_section = true;
            }
            i += 1;
            continue;
        }
        if in_env && trimmed.contains('=')
            && let Some((k, _)) = trimmed.split_once('=')
                && k.trim() == name {
                    lines.remove(i);
                    continue;
                }
        i += 1;
    }
    // Add [env] section if missing
    if !has_env_section {
        if !lines.is_empty() && !lines.last().is_none_or(std::string::String::is_empty) {
            lines.push(String::new());
        }
        lines.push("[env]".to_string());
    }
    lines.push(format!("{name} = \"{value}\""));
    std::fs::write(&path, lines.join("\n"))
        .map_err(|e| GytError::Ci(format!("writing ci-env.toml: {e}")))?;
    println!("CI env '{name}' set.");
    Ok(())
}

pub fn run_list(_args: &[String], gyt_dir: &Path) -> Result<()> {
    let env_map = load_env(gyt_dir)?;
    if env_map.is_empty() {
        println!("No CI environment variables set.");
    } else {
        println!("CI environment variables:");
        for (k, v) in &env_map {
            println!("  {k}={v}");
        }
    }
    Ok(())
}

#[expect(
    clippy::indexing_slicing,
    reason = "args[0] is gated by args.is_empty() check; lines[i] is gated by the while i < lines.len() loop header"
)]
pub fn run_remove(args: &[String], gyt_dir: &Path) -> Result<()> {
    if args.is_empty() || args[0] == "--help" {
        eprintln!("Usage: gyt ci env remove <name>");
        return Ok(());
    }
    let name = &args[0];
    let path = env_path(gyt_dir);
    if !path.exists() {
        return Err(GytError::NotFound("ci-env.toml not found".into()));
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| GytError::Ci(format!("reading ci-env.toml: {e}")))?;
    let mut lines: Vec<String> = raw.lines().map(std::string::ToString::to_string).collect();
    let mut i = 0;
    let mut in_env = false;
    let mut removed = false;
    while i < lines.len() {
        let trimmed = lines[i].trim().to_string();
        if trimmed.starts_with('[') {
            in_env = trimmed == "[env]";
            i += 1;
            continue;
        }
        if in_env && trimmed.contains('=')
            && let Some((k, _)) = trimmed.split_once('=')
                && k.trim() == name {
                    lines.remove(i);
                    removed = true;
                    continue;
                }
        i += 1;
    }
    if !removed {
        return Err(GytError::NotFound(format!("CI env '{name}' not found")));
    }
    std::fs::write(&path, lines.join("\n"))
        .map_err(|e| GytError::Ci(format!("writing ci-env.toml: {e}")))?;
    println!("CI env '{name}' removed.");
    Ok(())
}
