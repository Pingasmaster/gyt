// Minimal repo config reader. The on-disk format lives at `.gyt/config.toml`
// and is a tiny subset of TOML — enough for what the CLI actually consults.
//
// Lookup precedence (later wins):
//   1. system / global at `$GYT_CONFIG_HOME` or `$HOME/.config/gyt/config.toml`
//   2. repo at `.gyt/config.toml`
//   3. environment overrides (`GYT_AUTHOR_NAME`, `GYT_AUTHOR_EMAIL`)
//
// This means a user can set their name/email once globally and skip the
// per-repo step. A repo file overrides the global, and env vars beat both.
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
//   [commit]
//   sign_required = true  (opt-in, default false)
//
//   [ci]
//   parallel_jobs = "lint,test"   (comma-separated job names — the
//                                  .wasm file stem — that MAY run
//                                  concurrently. Any job NOT listed is
//                                  single-run: starting it preempts an
//                                  in-progress run of the same job.
//                                  Use "*" to allow every job to run
//                                  in parallel. Default: empty, so all
//                                  jobs are single-run.)
//
// Anything else is preserved syntactically but not surfaced via this API.

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
    /// If true, `gyt commit` without `--sign` is rejected.
    pub sign_required: bool,
    /// Global CI concurrency policy (`[ci] mode`). See [`CiConcurrency`].
    pub ci_mode: CiConcurrency,
    /// Per-job CI concurrency overrides (`[ci.<job>] mode`), keyed by the
    /// `.wasm` file stem. Overrides the global default for that job.
    pub ci_job_modes: std::collections::BTreeMap<String, CiJobMode>,
}

/// Global CI concurrency policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CiConcurrency {
    /// Different CI jobs may run at the same time. Each job's own
    /// behavior on a *repeat of the same job* is governed by its
    /// per-job mode (default [`CiJobMode::Parallel`]). This is the
    /// default.
    #[default]
    Parallel,
    /// All CI jobs share a single concurrency domain: at most one CI run
    /// at a time across every job. New runs queue behind the in-progress
    /// one (default per-job mode becomes [`CiJobMode::Queue`]).
    Serial,
}

/// What happens when a CI job is started while a run that contends with
/// it (same domain) is already in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiJobMode {
    /// Run concurrently — no coordination, any number in flight.
    Parallel,
    /// Wait for the in-progress run to finish, then run (FIFO-ish via an
    /// exclusive domain lock).
    Queue,
    /// Preempt the in-progress run: it aborts immediately (no warning),
    /// then this run proceeds.
    Interrupt,
}

impl Config {
    /// The effective concurrency mode for CI job `job` (the `.wasm` file
    /// stem): the per-job override if one is set, otherwise the default
    /// implied by the global [`CiConcurrency`] mode.
    #[must_use]
    pub fn effective_ci_job_mode(&self, job: &str) -> CiJobMode {
        // Per-job section names are stored lowercased by the parser
        // (`[ci.Build]` → key "build"), so look up case-insensitively.
        if let Some(m) = self.ci_job_modes.get(&job.to_ascii_lowercase()) {
            return *m;
        }
        match self.ci_mode {
            CiConcurrency::Serial => CiJobMode::Queue,
            CiConcurrency::Parallel => CiJobMode::Parallel,
        }
    }

    /// The contention-domain key for `job`. Under [`CiConcurrency::Serial`]
    /// every job shares the `"all"` domain (global single-run); under
    /// [`CiConcurrency::Parallel`] each job is its own domain so distinct
    /// jobs never block one another.
    #[must_use]
    pub fn ci_domain_key(&self, job: &str) -> String {
        match self.ci_mode {
            CiConcurrency::Serial => "all".to_string(),
            CiConcurrency::Parallel => job.to_string(),
        }
    }
}

impl Config {
    /// Load repository configuration. The global file (if any) supplies
    /// defaults; the repo file overrides; env vars override both.
    pub fn load(repo: &Repo) -> Result<Self> {
        let mut cfg = match global_config_path() {
            Some(g) if g.exists() => parse(&fs_util::read_all(&g)?)?,
            _ => Self::default(),
        };
        let p = repo.gyt_dir.join("config.toml");
        if p.exists() {
            let repo_cfg = parse(&fs_util::read_all(&p)?)?;
            merge_into(&mut cfg, repo_cfg);
        }
        if let Ok(v) = std::env::var("GYT_AUTHOR_NAME") {
            cfg.user_name = Some(v);
        }
        if let Ok(v) = std::env::var("GYT_AUTHOR_EMAIL") {
            cfg.user_email = Some(v);
        }
        Ok(cfg)
    }

    /// Load the global config alone, applying env overrides. Used by code
    /// paths that need user identity outside of a repo (e.g. `gyt clone`
    /// before a repo exists).
    pub fn load_global() -> Result<Self> {
        let mut cfg = match global_config_path() {
            Some(g) if g.exists() => parse(&fs_util::read_all(&g)?)?,
            _ => Self::default(),
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
                "user.name not set (set ~/.config/gyt/config.toml, .gyt/config.toml, or \
                 GYT_AUTHOR_NAME)"
                    .into(),
            )
        })?;
        let email = self.user_email.as_ref().ok_or_else(|| {
            GytError::Repo(
                "user.email not set (set ~/.config/gyt/config.toml, .gyt/config.toml, or \
                 GYT_AUTHOR_EMAIL)"
                    .into(),
            )
        })?;
        Ok(format!("{name} <{email}>"))
    }

    /// Write this configuration to `.gyt/config.toml` inside the given directory.
    #[expect(
        clippy::unwrap_used,
        clippy::unwrap_in_result,
        reason = "writeln! to String never fails; the Result is only present for io::Write compatibility"
    )]
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
        if self.sign_required {
            s.push_str("\n[commit]\nsign_required = true\n");
        }
        if self.ci_mode != CiConcurrency::default() {
            let m = match self.ci_mode {
                CiConcurrency::Parallel => "parallel",
                CiConcurrency::Serial => "serial",
            };
            writeln!(s, "\n[ci]\nmode = {m:#?}").unwrap();
        }
        for (job, mode) in &self.ci_job_modes {
            let m = match mode {
                CiJobMode::Parallel => "parallel",
                CiJobMode::Queue => "queue",
                CiJobMode::Interrupt => "interrupt",
            };
            writeln!(s, "\n[ci.{job}]\nmode = {m:#?}").unwrap();
        }
        fs_util::atomic_write(&gyt_dir.join("config.toml"), s.as_bytes())
    }
}

/// Where to look for the user's global config. Honors `GYT_CONFIG_HOME` for
/// tests and unusual setups, falling back to `$HOME/.config/gyt/config.toml`.
/// Returns `None` if `HOME` isn't set and the override isn't given.
pub fn global_config_path() -> Option<std::path::PathBuf> {
    if let Ok(p) = std::env::var("GYT_CONFIG_HOME") {
        return Some(std::path::PathBuf::from(p).join("config.toml"));
    }
    let home = std::env::var("HOME").ok()?;
    Some(std::path::PathBuf::from(home).join(".config/gyt/config.toml"))
}

/// Layer `other` on top of `base`. Set fields in `other` overwrite `base`;
/// remotes are unioned (with `other` winning on key collisions).
fn merge_into(base: &mut Config, other: Config) {
    if other.user_name.is_some() {
        base.user_name = other.user_name;
    }
    if other.user_email.is_some() {
        base.user_email = other.user_email;
    }
    for (k, v) in other.remotes {
        base.remotes.insert(k, v);
    }
    if other.create_default_gytignore {
        base.create_default_gytignore = true;
    }
    // M29: per-repo config wins over global, in both directions.
    // Previously `sign_required` was a one-way `if other.sign_required
    // { true }`, so a repo could turn ON signing but never OFF.
    base.sign_required = other.sign_required;
    // CI concurrency: the repo file (loaded second) wins on the global
    // mode if it set one. We can't distinguish "explicitly set to the
    // default" from "unset" for a non-Option enum, so the rule is: a
    // repo whose [ci] mode differs from the default overrides; the
    // common case (repo omits [ci]) leaves the global value intact.
    if other.ci_mode != CiConcurrency::default() {
        base.ci_mode = other.ci_mode;
    }
    // Per-job overrides union, with the repo file winning on collisions.
    for (k, v) in other.ci_job_modes {
        base.ci_job_modes.insert(k, v);
    }
}

// TOML string quoting helper, used in tests only today. Exercised by
// the round_trip_quote_unquote test below; kept here so unquote has a
// counterpart for parity with the format the encoder will emit.
#[cfg(test)]
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

// B16: recognised top-level section names. Anything else is
// refused at parse time — we'd rather an explicit error than let
// a typo (e.g. `[Commit]` instead of `[commit]`) silently downgrade
// a security setting like sign_required.
const KNOWN_SECTIONS: &[&str] = &["user", "remote", "init", "commit", "ci"];

/// Tiny TOML subset parser.
/// Supports: `[section]`, `[section.subsection]` (one level deep, used for remote.NAME),
/// `key = "value"` with the same escapes as `quote`. Line comments with `#`.
#[expect(
    clippy::indexing_slicing,
    reason = "section[0] indexing is gated by `section.len() == 1` check on a preceding line"
)]
pub fn parse(bytes: &[u8]) -> Result<Config> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| GytError::Parse("config.toml is not utf-8".into()))?;
    let mut cfg = Config::default();
    // B16: section names are kept lowercased so that `[Commit]`
    // and `[commit]` route to the same code path; the unknown-
    // section gate below catches actually-unknown sections.
    let mut section: Vec<String> = Vec::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let raw_section: Vec<String> = rest
                .trim()
                .split('.')
                .map(|s| s.trim().to_string())
                .collect();
            section = raw_section
                .iter()
                .map(|s| s.to_ascii_lowercase())
                .collect();
            for (i, part) in section.iter().enumerate() {
                if part.is_empty() {
                    return Err(GytError::Parse(format!(
                        "config.toml line {}: empty section component",
                        lineno + 1
                    )));
                }
                // B16: only the top-level (i == 0) is gated against
                // the known list. Subsections (e.g. `remote.<name>`)
                // are user-named.
                if i == 0 && !KNOWN_SECTIONS.contains(&part.as_str()) {
                    return Err(GytError::Parse(format!(
                        "config.toml line {}: unknown section [{}] \
                         (known: {}). A typo here can silently downgrade \
                         security settings like sign_required.",
                        lineno + 1,
                        raw_section.first().map_or("", String::as_str),
                        KNOWN_SECTIONS.join(", ")
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
        let raw_key = key.trim();
        let key = raw_key.to_ascii_lowercase();
        let trimmed_value = value.trim();
        // Boolean keys are written by Config::write as bare `true` /
        // `false` literals. Accept those without requiring quoting so a
        // CLI-written value round-trips through the parser.
        if section.len() == 1
            && ((section[0] == "init" && key == "create_default_gytignore")
                || (section[0] == "commit" && key == "sign_required"))
        {
            let b = match trimmed_value {
                "true" => true,
                "false" => false,
                other => match unquote(other) {
                    Some(s) if s.eq_ignore_ascii_case("true") => true,
                    Some(s) if s.eq_ignore_ascii_case("false") => false,
                    _ => {
                        return Err(GytError::Parse(format!(
                            "config.toml line {}: expected boolean for {raw_key}",
                            lineno + 1
                        )));
                    }
                },
            };
            if section[0] == "init" {
                cfg.create_default_gytignore = b;
            } else {
                cfg.sign_required = b;
            }
            continue;
        }
        let raw_value = unquote(trimmed_value).ok_or_else(|| {
            GytError::Parse(format!(
                "config.toml line {}: value must be a quoted string",
                lineno + 1
            ))
        })?;
        match section.as_slice() {
            [s] if s == "user" => match key.as_str() {
                "name" => cfg.user_name = Some(raw_value),
                "email" => cfg.user_email = Some(raw_value),
                _ => {
                    return Err(GytError::Parse(format!(
                        "config.toml line {}: unknown key {raw_key} in [user]",
                        lineno + 1
                    )));
                }
            },
            [s, name] if s == "remote" => match key.as_str() {
                "url" => {
                    cfg.remotes.insert(name.clone(), raw_value);
                }
                _ => {
                    return Err(GytError::Parse(format!(
                        "config.toml line {}: unknown key {raw_key} in [remote.{name}]",
                        lineno + 1
                    )));
                }
            },
            [s] if s == "ci" => match key.as_str() {
                "mode" => {
                    cfg.ci_mode = match raw_value.to_ascii_lowercase().as_str() {
                        "parallel" => CiConcurrency::Parallel,
                        "serial" | "queue" | "queued" => CiConcurrency::Serial,
                        other => {
                            return Err(GytError::Parse(format!(
                                "config.toml line {}: [ci] mode must be \
                                 \"parallel\" or \"serial\", got {other:?}",
                                lineno + 1
                            )));
                        }
                    };
                }
                _ => {
                    return Err(GytError::Parse(format!(
                        "config.toml line {}: unknown key {raw_key} in [ci] \
                         (known: mode)",
                        lineno + 1
                    )));
                }
            },
            [s, job] if s == "ci" => match key.as_str() {
                "mode" => {
                    let m = match raw_value.to_ascii_lowercase().as_str() {
                        "parallel" => CiJobMode::Parallel,
                        "queue" | "queued" | "serial" => CiJobMode::Queue,
                        "interrupt" | "preempt" => CiJobMode::Interrupt,
                        other => {
                            return Err(GytError::Parse(format!(
                                "config.toml line {}: [ci.{job}] mode must be \
                                 \"interrupt\", \"queue\", or \"parallel\", \
                                 got {other:?}",
                                lineno + 1
                            )));
                        }
                    };
                    cfg.ci_job_modes.insert(job.clone(), m);
                }
                _ => {
                    return Err(GytError::Parse(format!(
                        "config.toml line {}: unknown key {raw_key} in \
                         [ci.{job}] (known: mode)",
                        lineno + 1
                    )));
                }
            },
            [s] if s == "init" => {
                return Err(GytError::Parse(format!(
                    "config.toml line {}: unknown key {raw_key} in [init]",
                    lineno + 1
                )));
            }
            [s] if s == "commit" => {
                return Err(GytError::Parse(format!(
                    "config.toml line {}: unknown key {raw_key} in [commit]",
                    lineno + 1
                )));
            }
            _ => {
                // Should be unreachable because KNOWN_SECTIONS gate
                // above already rejected unknown top-levels, but be
                // defensive: refuse anything that slipped past.
                return Err(GytError::Parse(format!(
                    "config.toml line {}: stray key {raw_key} outside a known section",
                    lineno + 1
                )));
            }
        }
    }
    Ok(cfg)
}
#[expect(
    clippy::string_slice,
    reason = "byte offsets used are at ASCII / char-boundary positions by construction"
)]
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
#[expect(
    clippy::indexing_slicing,
    clippy::string_slice,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line; byte offsets used are at ASCII / char-boundary positions by construction"
)]
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
    #![expect(
        clippy::unwrap_used,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
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

    #[test]
    fn merge_layers_global_under_repo() {
        let mut base = Config {
            user_name: Some("Alice".into()),
            user_email: Some("alice@global".into()),
            ..Config::default()
        };
        let repo = Config {
            user_email: Some("alice@work".into()),
            ..Config::default()
        };
        merge_into(&mut base, repo);
        // Repo overrides email; name still from global.
        assert_eq!(base.user_name.as_deref(), Some("Alice"));
        assert_eq!(base.user_email.as_deref(), Some("alice@work"));
    }

    /// B16 regression. A misspelled section header in a repo
    /// config could silently downgrade a security setting from the
    /// global config. Previously `[Commit] sign_required = true` (or
    /// any other case variant) was silently dropped because the
    /// match arms below were case-sensitive and the unknown branch
    /// fell through `_ => {}`. Now the parser case-folds known
    /// sections and refuses unknowns at parse time.
    #[test]
    fn parser_accepts_case_variant_of_known_section() {
        // [Commit] and [COMMIT] must route to [commit].
        for header in ["[Commit]", "[COMMIT]", "[commit]"] {
            let body = format!("{header}\nsign_required = true\n");
            let cfg = parse(body.as_bytes()).unwrap();
            assert!(
                cfg.sign_required,
                "header {header} must enable sign_required"
            );
        }
    }

    #[test]
    fn parser_rejects_unknown_section_typo() {
        // The whole point: a typo in [commit] (e.g. [comit]) must
        // raise an explicit error, never silently produce
        // sign_required = false.
        let toml = "[comit]\nsign_required = true\n";
        let err = parse(toml.as_bytes());
        assert!(err.is_err(), "unknown section must error, got: {err:?}");
    }

    #[test]
    fn parser_rejects_unknown_key_in_commit_section() {
        // A typo on the key (e.g. sign_requried) must fail loud.
        let toml = "[commit]\nsign_requried = true\n";
        assert!(parse(toml.as_bytes()).is_err());
    }

    #[test]
    fn parser_accepts_case_variant_of_known_key() {
        let toml = "[commit]\nSign_Required = true\n";
        let cfg = parse(toml.as_bytes()).unwrap();
        assert!(cfg.sign_required);
    }

    #[test]
    fn ci_global_mode_parses_and_defaults() {
        // Default: no [ci] section → Parallel, all jobs default to Parallel.
        let cfg = parse(b"").unwrap();
        assert_eq!(cfg.ci_mode, CiConcurrency::Parallel);
        assert_eq!(cfg.effective_ci_job_mode("anything"), CiJobMode::Parallel);

        // Serial → every job defaults to Queue and shares the "all" domain.
        let cfg = parse(b"[ci]\nmode = \"serial\"\n").unwrap();
        assert_eq!(cfg.ci_mode, CiConcurrency::Serial);
        assert_eq!(cfg.effective_ci_job_mode("build"), CiJobMode::Queue);
        assert_eq!(cfg.ci_domain_key("build"), "all");
        assert_eq!(cfg.ci_domain_key("test"), "all");
    }

    #[test]
    fn ci_per_job_mode_overrides_global() {
        let toml = "[ci]\nmode = \"serial\"\n\
                    [ci.lint]\nmode = \"parallel\"\n\
                    [ci.deploy]\nmode = \"interrupt\"\n";
        let cfg = parse(toml.as_bytes()).unwrap();
        // Global serial → unlisted jobs queue.
        assert_eq!(cfg.effective_ci_job_mode("build"), CiJobMode::Queue);
        // Per-job overrides win.
        assert_eq!(cfg.effective_ci_job_mode("lint"), CiJobMode::Parallel);
        assert_eq!(cfg.effective_ci_job_mode("deploy"), CiJobMode::Interrupt);
        // Job-name lookup is case-insensitive (sections are lowercased).
        assert_eq!(cfg.effective_ci_job_mode("Lint"), CiJobMode::Parallel);
    }

    #[test]
    fn ci_under_parallel_global_per_job_queue_is_per_job_domain() {
        let toml = "[ci.build]\nmode = \"queue\"\n";
        let cfg = parse(toml.as_bytes()).unwrap();
        assert_eq!(cfg.ci_mode, CiConcurrency::Parallel);
        // Default jobs run parallel; the overridden one queues, scoped to
        // its own per-job domain (distinct jobs never contend).
        assert_eq!(cfg.effective_ci_job_mode("test"), CiJobMode::Parallel);
        assert_eq!(cfg.effective_ci_job_mode("build"), CiJobMode::Queue);
        assert_eq!(cfg.ci_domain_key("build"), "build");
        assert_eq!(cfg.ci_domain_key("test"), "test");
    }

    #[test]
    fn ci_invalid_modes_rejected() {
        assert!(parse(b"[ci]\nmode = \"bogus\"\n").is_err());
        assert!(parse(b"[ci.x]\nmode = \"bogus\"\n").is_err());
        assert!(parse(b"[ci]\nunknown = \"x\"\n").is_err());
    }

    #[test]
    #[expect(
        clippy::field_reassign_with_default,
        reason = "building the test fixture by mutating two fields of the default is clearer than a full literal"
    )]
    fn ci_config_round_trips_through_write() {
        let mut cfg = Config::default();
        cfg.ci_mode = CiConcurrency::Serial;
        cfg.ci_job_modes
            .insert("lint".to_string(), CiJobMode::Parallel);
        cfg.ci_job_modes
            .insert("deploy".to_string(), CiJobMode::Interrupt);
        let dir = std::env::temp_dir().join(format!(
            "gyt-cfg-ci-rt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        cfg.write(&dir).unwrap();
        let back = parse(&fs_util::read_all(&dir.join("config.toml")).unwrap()).unwrap();
        assert_eq!(back.ci_mode, CiConcurrency::Serial);
        assert_eq!(back.effective_ci_job_mode("lint"), CiJobMode::Parallel);
        assert_eq!(back.effective_ci_job_mode("deploy"), CiJobMode::Interrupt);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn global_config_path_default_uses_home() {
        // Without HOME set we can't assert much portably; just verify the
        // function returns Some when HOME is present (it normally is on CI),
        // and the path ends with `.config/gyt/config.toml`.
        if let Ok(home) = std::env::var("HOME") {
            let p = global_config_path().unwrap();
            assert!(
                p.starts_with(&home),
                "global config path should be under HOME: {p:?}"
            );
            assert!(p.ends_with(".config/gyt/config.toml"));
        }
    }
}
