// Minimal repo config reader. The on-disk format lives at `.gyt/config.toml`
// and is a tiny subset of TOML — enough for what the CLI actually consults.
//
// Recognized keys:
//   [user]
//   name  = "Alice"
//   email = "alice@example.com"
//
//   [remote.<name>]
//   url = "https://host/path/repo.gyt/"
//
//   [init]
//   create_default_gytignore = true  (opt-in, default false)
//
// Anything else is preserved syntactically but not surfaced via this API.
//
// Environment overrides (used for `commit` author info, useful in CI/tests):
//   GYT_AUTHOR_NAME, GYT_AUTHOR_EMAIL

use crate::errors::{GytError, Result};
use crate::fs_util;
use crate::repo::Repo;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;

/// Repository configuration loaded from `.gyt/config.toml`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Config {
    /// The user's display name.
    pub user_name: Option<String>,
    /// The user's email address.
    pub user_email: Option<String>,
    /// Map remote name -> url.
    pub remotes: BTreeMap<String, String>,
    /// Whether to create a default .gytignore on `gyt init`. Defaults to false (opt-in).
    pub create_default_gytignore: bool,
}

impl Config {
    /// Load repository configuration from `.gyt/config.toml`, applying
    /// environment overrides (`GYT_AUTHOR_NAME`, `GYT_AUTHOR_EMAIL`).
    pub fn load(repo: &Repo) -> Result<Self> {
        let p = repo.gyt_dir.join("config.toml");
        let mut cfg = if p.exists() {
            parse(&fs_util::read_all(&p)?)?
        } else {
            Self::default()
        };
        if let Ok(v) = std::env::var("GYT_AUTHOR_NAME") {
            cfg.user_name = Some(v);
        }
        if let Ok(v) = std::env::var("GYT_AUTHOR_EMAIL") {
            cfg.user_email = Some(v);
        }
        Ok(cfg)
    }

    /// Format as "Name <email>" suitable for inclusion in commit author/committer lines.
    pub fn identity(&self) -> Result<String> {
        let name = self.user_name.as_ref().ok_or_else(|| {
            GytError::Repo(
                "user.name not set (set in .gyt/config.toml or via GYT_AUTHOR_NAME)".into(),
            )
        })?;
        let email = self.user_email.as_ref().ok_or_else(|| {
            GytError::Repo(
                "user.email not set (set in .gyt/config.toml or via GYT_AUTHOR_EMAIL)".into(),
            )
        })?;
        Ok(format!("{name} <{email}>"))
    }

    /// Write this configuration to `.gyt/config.toml` inside the given directory.
    pub fn write(&self, gyt_dir: &Path) -> Result<()> {
        let mut s = String::new();
        if self.user_name.is_some() || self.user_email.is_some() {
            s.push_str("[user]\n");
            if let Some(n) = &self.user_name {
                writeln!(s, "name = {n:#?}").unwrap();
            }
            if let Some(e) = &self.user_email {
                writeln!(s, "email = {e:#?}").unwrap();
            }
            s.push('\n');
        }
        for (name, url) in &self.remotes {
            writeln!(s, "[remote.{name}]").unwrap();
            writeln!(s, "url = {url:#?}\n").unwrap();
        }
        if self.create_default_gytignore {
            s.push_str("\n[init]\ncreate_default_gytignore = true\n");
        }
        fs_util::atomic_write(&gyt_dir.join("config.toml"), s.as_bytes())
    }
}

// Scaffolding: TOML string quoting helper, used in commit phase.
#[allow(dead_code)]
fn quote(s: &str) -> String {
    // Basic-string escaping: backslash, double quote, control chars.
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32).to_string()),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Tiny TOML subset parser.
/// Supports: `[section]`, `[section.subsection]` (one level deep, used for remote.NAME),
/// `key = "value"` with the same escapes as `quote`. Line comments with `#`.
fn parse(bytes: &[u8]) -> Result<Config> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| GytError::Parse("config.toml is not utf-8".into()))?;
    let mut cfg = Config::default();
    let mut section: Vec<String> = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = rest
                .trim()
                .split('.')
                .map(|s| s.trim().to_string())
                .collect();
            for part in &section {
                if part.is_empty() {
                    return Err(GytError::Parse(format!(
                        "config.toml line {}: empty section component",
                        lineno + 1
                    )));
                }
            }
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            GytError::Parse(format!(
                "config.toml line {}: expected `key = value`",
                lineno + 1
            ))
        })?;
        let key = key.trim();
        let raw_value = unquote(value.trim()).ok_or_else(|| {
            GytError::Parse(format!(
                "config.toml line {}: value must be a quoted string",
                lineno + 1
            ))
        })?;
        // Check [init] section first since it only needs a borrow.
        if section.len() == 1 && section[0] == "init" && key == "create_default_gytignore" {
            cfg.create_default_gytignore = raw_value == "true";
            continue;
        }
        match section.as_slice() {
            [s] if s == "user" => match key {
                "name" => cfg.user_name = Some(raw_value),
                "email" => cfg.user_email = Some(raw_value),
                _ => {}
            },
            [s, name] if s == "remote" && key == "url" => {
                cfg.remotes.insert(name.clone(), raw_value);
            }
            _ => {}
        }
    }
    Ok(cfg)
}

fn strip_comment(line: &str) -> &str {
    // Strip `# ...` outside of quoted strings. We don't have multi-line strings.
    let bytes = line.as_bytes();
    let mut in_quote = false;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate() {
        if escape {
            escape = false;
            continue;
        }
        if in_quote {
            if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_quote = false;
            }
            continue;
        }
        if b == b'"' {
            in_quote = true;
        } else if b == b'#' {
            return &line[..i];
        }
    }
    line
}

fn unquote(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes[0] != b'"' || bytes[bytes.len() - 1] != b'"' {
        return None;
    }
    let inner = &s[1..s.len() - 1];
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let n = chars.next()?;
            match n {
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let mut hex = String::with_capacity(4);
                    for _ in 0..4 {
                        hex.push(chars.next()?);
                    }
                    let cp = u32::from_str_radix(&hex, 16).ok()?;
                    out.push(char::from_u32(cp)?);
                }
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_user_section() {
        let toml = r#"
[user]
name = "Alice"
email = "alice@example.com"
"#;
        let cfg = parse(toml.as_bytes()).unwrap();
        assert_eq!(cfg.user_name.as_deref(), Some("Alice"));
        assert_eq!(cfg.user_email.as_deref(), Some("alice@example.com"));
    }

    #[test]
    fn parses_remote_subsection() {
        let toml = r#"
[remote.origin]
url = "https://host/path/repo.gyt/"
[remote.upstream]
url = "https://other/path.gyt/"
"#;
        let cfg = parse(toml.as_bytes()).unwrap();
        assert_eq!(
            cfg.remotes.get("origin").map(String::as_str),
            Some("https://host/path/repo.gyt/")
        );
        assert_eq!(
            cfg.remotes.get("upstream").map(String::as_str),
            Some("https://other/path.gyt/")
        );
    }

    #[test]
    fn round_trip_quote_unquote() {
        let cases = [
            "simple",
            "with spaces",
            r#"with "quote""#,
            "with\nnewline",
            "with\ttab",
            "with\\backslash",
        ];
        for s in cases {
            let q = quote(s);
            assert_eq!(unquote(&q).as_deref(), Some(s), "round-trip {s:?} via {q}");
        }
    }

    #[test]
    fn comments_and_blanks_ignored() {
        let toml = r#"
# top-level comment
[user]
# inline section comment
name = "Bob"  # trailing
email = "b@x"
"#;
        let cfg = parse(toml.as_bytes()).unwrap();
        assert_eq!(cfg.user_name.as_deref(), Some("Bob"));
        assert_eq!(cfg.user_email.as_deref(), Some("b@x"));
    }

    #[test]
    fn rejects_unquoted_value() {
        let toml = "[user]\nname = Bob\n";
        assert!(parse(toml.as_bytes()).is_err());
    }
}
