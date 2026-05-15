// .gytignore parser + matcher (gitignore-compatible semantics).
//
// gyt does NOT honor .gitignore — only .gytignore. By user decision.
//
// Semantics implemented (per `man gitignore` / gitignore(5)):
// - Lines starting with `#` are comments.
// - Blank lines are ignored.
// - Trailing whitespace is right-trimmed (we do not implement backslash-escaped trailing ws).
// - A leading `!` negates the match.
// - A trailing `/` makes the pattern directory-only.
// - A leading `/` anchors the pattern to the directory containing the .gytignore.
// - A pattern that contains a `/` in the middle is also anchored to the
//   containing directory (this matches gitignore semantics).
// - Otherwise the pattern is "loose" and matches at any depth (basename-style).
// - `*` matches any run of non-`/` bytes; `?` matches one non-`/` byte.
// - `**` is a path-component glob; only recognized when surrounded by `/` or at
//   start / end of the pattern. Matches zero or more path components.
// - `[abc]` / `[a-z]` character classes; `[!abc]` is negated. ASCII-byte based.
//
// Stacking: a deeper file's rules are appended after a shallower file's, so
// last-match-wins automatically gives nested files precedence. Within one
// file the LAST matching line wins.

use crate::errors::{GytError, Result};
use std::path::Path;

/// A parsed pattern. Compiled into a flat sequence of `Tok`s.
#[derive(Debug, Clone)]
struct Rule {
    /// `!` prefix.
    negate: bool,
    /// Trailing `/`.
    dir_only: bool,
    /// Pattern is anchored to `anchor` (because it had a `/` in middle/start,
    /// or because it lives in a subdirectory `.gytignore`).
    /// If not anchored, the pattern matches against any suffix of the path.
    anchored: bool,
    /// The directory the .gytignore lives in, forward-slash, no leading or
    /// trailing slash. "" means workdir root.
    anchor: String,
    /// Compiled tokens. The matcher walks these against a path.
    tokens: Vec<Tok>,
}

/// A single token in a compiled pattern. Slashes appear as explicit `Sep`
/// tokens between segments, except where folded into a `**`-token form.
#[derive(Debug, Clone)]
enum Tok {
    /// Literal byte (matches itself, never matches `/`).
    Lit(u8),
    /// `?` — exactly one non-`/` byte.
    Any,
    /// `*` — zero or more non-`/` bytes.
    Star,
    /// `**/` at the start of a pattern (or following a `Sep` we then folded).
    /// Matches zero or more `component/` blocks, i.e. any prefix that ends at
    /// a path-component boundary.
    DStarSlash,
    /// `/**` at the end of a pattern. Matches an optional `/component(...)`
    /// suffix — i.e. zero or more `/component` segments.
    SlashDStar,
    /// `/**/` in the middle of a pattern. Matches a single `/` (zero
    /// intermediate components) or `/component(/component)*/`.
    SlashDStarSlash,
    /// Character class. `negate=true` for `[!...]`. Ranges expanded into a
    /// list of `(lo, hi)` byte-pairs (inclusive).
    Class { negate: bool, ranges: Vec<(u8, u8)> },
    /// `/`.
    Sep,
}

#[derive(Debug, Default)]
pub struct IgnoreSet {
    rules: Vec<Rule>,
}

impl IgnoreSet {
    /// Empty set — matches nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from the workdir root, loading the root `.gytignore` if present.
    /// Walking subdirectories is the caller's job.
    pub fn load_from_root(workdir: &Path) -> Result<Self> {
        let mut set = Self::new();
        let p = workdir.join(".gytignore");
        match std::fs::read_to_string(&p) {
            Ok(contents) => set.add_file("", &contents)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        Ok(set)
    }

    /// Add the patterns of one .gytignore file. `containing_dir` is the
    /// directory the file lives in, expressed relative to the workdir as
    /// forward-slash bytes, e.g. "" for the root, "src" for `src/.gytignore`.
    pub fn add_file(&mut self, containing_dir: &str, contents: &str) -> Result<()> {
        let anchor = normalize_anchor(containing_dir);
        for raw in contents.lines() {
            if let Some(rule) = parse_line(raw, &anchor)? {
                self.rules.push(rule);
            }
        }
        Ok(())
    }

    /// Match `path` (relative to workdir, forward-slash, no leading `/`).
    /// Returns true iff the last matching rule says "ignore" (non-negated).
    pub fn matched(&self, path: &str, is_dir: bool) -> bool {
        let mut decision = false;
        for rule in &self.rules {
            if rule_matches(rule, path, is_dir) {
                decision = !rule.negate;
            }
        }
        decision
    }
}

fn normalize_anchor(d: &str) -> String {
    let s = d.trim_matches('/');
    s.to_string()
}

fn parse_line(raw: &str, anchor: &str) -> Result<Option<Rule>> {
    // Comments + blanks.
    if raw.starts_with('#') {
        return Ok(None);
    }
    // Right-trim spaces and tabs (we do not implement backslash escapes).
    let trimmed = raw.trim_end_matches([' ', '\t']);
    if trimmed.is_empty() {
        return Ok(None);
    }

    let mut s = trimmed;

    let mut negate = false;
    if let Some(rest) = s.strip_prefix('!') {
        negate = true;
        s = rest;
    }

    // Trailing `/` -> directory-only.
    let mut dir_only = false;
    if let Some(stripped) = s.strip_suffix('/') {
        dir_only = true;
        s = stripped;
    }

    // Leading `/` -> anchored, strip it.
    let mut anchored = false;
    if let Some(rest) = s.strip_prefix('/') {
        anchored = true;
        s = rest;
    }

    // If the (remaining) pattern still contains a `/`, gitignore says it's
    // anchored to the containing directory.
    if s.contains('/') {
        anchored = true;
    }

    // If the .gytignore lives in a subdirectory, the pattern is implicitly
    // tied to that subdirectory (we still allow loose matching *within* that
    // subtree for non-anchored patterns; see `rule_matches`).

    if s.is_empty() {
        return Err(GytError::Parse(format!(
            "empty pattern in .gytignore: {raw:?}"
        )));
    }

    let tokens = compile_tokens(s)?;

    Ok(Some(Rule {
        negate,
        dir_only,
        anchored,
        anchor: anchor.to_string(),
        tokens,
    }))
}
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
fn compile_tokens(pat: &str) -> Result<Vec<Tok>> {
    let bytes = pat.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        match b {
            b'/' => {
                out.push(Tok::Sep);
                i += 1;
            }
            b'?' => {
                out.push(Tok::Any);
                i += 1;
            }
            b'*' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'*' {
                    // `**` only counts as a path-component glob when
                    // surrounded by `/` or pattern boundaries. Otherwise
                    // treat the two stars as a single Star (sequential
                    // Stars collapse).
                    let prev_ok = i == 0 || bytes[i - 1] == b'/';
                    let after = i + 2;
                    let next_ok = after == bytes.len() || bytes[after] == b'/';
                    if prev_ok && next_ok {
                        let leading = i == 0;
                        let trailing = after == bytes.len();
                        match (leading, trailing) {
                            (true, true) => {
                                // Pattern is exactly `**` — matches any path.
                                // Compile as `**/` (which matches any prefix
                                // ending at a component boundary, including
                                // the empty prefix and the whole path).
                                out.push(Tok::DStarSlash);
                                i = bytes.len();
                            }
                            (true, false) => {
                                // `**/...` at start.
                                out.push(Tok::DStarSlash);
                                i = after + 1; // skip "**" and the trailing "/"
                            }
                            (false, true) => {
                                // `.../**` at end. The preceding `/` is part
                                // of this token; pop the Sep we already
                                // pushed.
                                debug_assert!(matches!(out.last(), Some(Tok::Sep)));
                                out.pop();
                                out.push(Tok::SlashDStar);
                                i = bytes.len();
                            }
                            (false, false) => {
                                // `.../**/...` in middle. Pop the leading
                                // Sep, push the combined token, and skip
                                // the trailing `/` too.
                                debug_assert!(matches!(out.last(), Some(Tok::Sep)));
                                out.pop();
                                out.push(Tok::SlashDStarSlash);
                                i = after + 1;
                            }
                        }
                        continue;
                    }
                    // `**` not aligned to slashes — collapse to a single
                    // Star. Skip both bytes; further consecutive stars
                    // will also collapse on the next iteration.
                    out.push(Tok::Star);
                    i += 2;
                    continue;
                }
                out.push(Tok::Star);
                i += 1;
            }
            b'[' => {
                // Parse character class.
                let (class, consumed) = compile_class(&bytes[i..])?;
                out.push(class);
                i += consumed;
            }
            b'\\' => {
                // Escape next byte literally.
                if i + 1 >= bytes.len() {
                    return Err(GytError::Parse(format!(
                        "trailing backslash in pattern: {pat:?}"
                    )));
                }
                out.push(Tok::Lit(bytes[i + 1]));
                i += 2;
            }
            _ => {
                out.push(Tok::Lit(b));
                i += 1;
            }
        }
    }
    Ok(out)
}
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
fn compile_class(bytes: &[u8]) -> Result<(Tok, usize)> {
    // bytes[0] == '['.
    debug_assert_eq!(bytes[0], b'[');
    let mut i = 1;
    let mut negate = false;
    if i < bytes.len() && (bytes[i] == b'!' || bytes[i] == b'^') {
        negate = true;
        i += 1;
    }
    let mut ranges: Vec<(u8, u8)> = Vec::new();
    let mut closed = false;
    while i < bytes.len() {
        if bytes[i] == b']' {
            closed = true;
            i += 1;
            break;
        }
        let lo = bytes[i];
        i += 1;
        if i + 1 < bytes.len() && bytes[i] == b'-' && bytes[i + 1] != b']' {
            let hi = bytes[i + 1];
            i += 2;
            if lo <= hi {
                ranges.push((lo, hi));
            } else {
                ranges.push((hi, lo));
            }
        } else {
            ranges.push((lo, lo));
        }
    }
    if !closed {
        return Err(GytError::Parse(format!(
            "unterminated character class: {:?}",
            std::str::from_utf8(bytes).unwrap_or("<non-utf8>")
        )));
    }
    Ok((Tok::Class { negate, ranges }, i))
}
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
fn rule_matches(rule: &Rule, path: &str, is_dir: bool) -> bool {
    if rule.dir_only && !is_dir {
        return false;
    }

    // Strip the anchor from the path; the pattern is expressed relative to
    // its containing directory. If the path is not under the anchor, the
    // rule can never match.
    let rel = if rule.anchor.is_empty() {
        path
    } else {
        let prefix = &rule.anchor;
        if let Some(rest) = path.strip_prefix(prefix.as_str()) {
            if rest.is_empty() {
                // The path IS the anchor directory itself; rules in a
                // .gytignore can't match the containing directory.
                return false;
            }
            if let Some(after) = rest.strip_prefix('/') {
                after
            } else {
                // Prefix matched but next char isn't `/`, so this is a
                // sibling like "srcfoo" vs anchor "src". Not a match.
                return false;
            }
        } else {
            return false;
        }
    };

    if rule.anchored {
        match_tokens(&rule.tokens, rel.as_bytes())
    } else {
        // Loose pattern: try matching against every "/"-aligned suffix of rel.
        // i.e., rel itself, and the part after each `/`.
        let bytes = rel.as_bytes();
        if match_tokens(&rule.tokens, bytes) {
            return true;
        }
        for (i, &b) in bytes.iter().enumerate() {
            if b == b'/' && match_tokens(&rule.tokens, &bytes[i + 1..]) {
                return true;
            }
        }
        false
    }
}

/// Match a flat token list against a path-bytes string.
fn match_tokens(tokens: &[Tok], path: &[u8]) -> bool {
    match_at(tokens, 0, path, 0)
}
#[expect(
    clippy::indexing_slicing,
    reason = "args[i] / similar indexing is gated by an explicit bounds check on a preceding line"
)]
fn match_at(tokens: &[Tok], ti: usize, path: &[u8], pi: usize) -> bool {
    if ti == tokens.len() {
        return pi == path.len();
    }
    match &tokens[ti] {
        Tok::Lit(b) => {
            if pi < path.len() && path[pi] == *b {
                match_at(tokens, ti + 1, path, pi + 1)
            } else {
                false
            }
        }
        Tok::Any => {
            if pi < path.len() && path[pi] != b'/' {
                match_at(tokens, ti + 1, path, pi + 1)
            } else {
                false
            }
        }
        Tok::Sep => {
            if pi < path.len() && path[pi] == b'/' {
                match_at(tokens, ti + 1, path, pi + 1)
            } else {
                false
            }
        }
        Tok::Class { negate, ranges } => {
            if pi >= path.len() || path[pi] == b'/' {
                return false;
            }
            let c = path[pi];
            let mut hit = false;
            for &(lo, hi) in ranges {
                if c >= lo && c <= hi {
                    hit = true;
                    break;
                }
            }
            if hit ^ *negate {
                match_at(tokens, ti + 1, path, pi + 1)
            } else {
                false
            }
        }
        Tok::Star => {
            // Try consuming 0..=N non-`/` bytes.
            let mut k = pi;
            loop {
                if match_at(tokens, ti + 1, path, k) {
                    return true;
                }
                if k >= path.len() || path[k] == b'/' {
                    return false;
                }
                k += 1;
            }
        }
        Tok::DStarSlash => {
            // Match zero or more `component/` blocks. Resume at any position
            // that is a path-component boundary: pi itself, or right after
            // each `/` from pi onward.
            if match_at(tokens, ti + 1, path, pi) {
                return true;
            }
            for i in pi..path.len() {
                if path[i] == b'/' && match_at(tokens, ti + 1, path, i + 1) {
                    return true;
                }
            }
            false
        }
        Tok::SlashDStar => {
            // Match an optional `/component(/component)*` suffix. Either
            // we are already at the end (zero components), or we are at a
            // `/` and the rest of the path has no leading-empty segments.
            if pi == path.len() {
                return match_at(tokens, ti + 1, path, pi);
            }
            if path[pi] == b'/' && pi + 1 < path.len() {
                // Match the entire remainder.
                return match_at(tokens, ti + 1, path, path.len());
            }
            false
        }
        Tok::SlashDStarSlash => {
            // Match `/` (zero intermediate components) or
            // `/component(/component)*/`. Resume at every `/`-aligned
            // position strictly after pi.
            for i in pi..path.len() {
                if path[i] == b'/' && match_at(tokens, ti + 1, path, i + 1) {
                    return true;
                }
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        clippy::panic,
        reason = "test code: panicking on unexpected input is how a test signals failure"
    )]
    use super::*;

    fn set_with(rules_in_root: &str) -> IgnoreSet {
        let mut s = IgnoreSet::new();
        s.add_file("", rules_in_root).unwrap();
        s
    }

    #[test]
    fn empty_set_matches_nothing() {
        let s = IgnoreSet::new();
        assert!(!s.matched("foo", false));
        assert!(!s.matched("foo/bar", false));
        assert!(!s.matched("", true));
    }

    #[test]
    fn blank_and_comment_lines_ignored() {
        let s = set_with("\n# a comment\n\n   \n*.log\n");
        assert!(s.matched("foo.log", false));
        assert!(!s.matched("foo.txt", false));
    }

    #[test]
    fn loose_pattern_matches_anywhere() {
        let s = set_with("*.log\n");
        assert!(s.matched("foo.log", false));
        assert!(s.matched("dir/foo.log", false));
        assert!(s.matched("a/b/c/foo.log", false));
        assert!(!s.matched("foo.txt", false));
    }

    #[test]
    fn anchored_only_matches_at_root() {
        let s = set_with("/build\n");
        assert!(s.matched("build", false));
        assert!(s.matched("build", true));
        assert!(!s.matched("src/build", false));
        assert!(!s.matched("a/build", true));
    }

    #[test]
    fn anchored_via_middle_slash() {
        // gitignore: a `/` in the middle anchors too.
        let s = set_with("docs/build\n");
        assert!(s.matched("docs/build", false));
        assert!(!s.matched("a/docs/build", false));
    }

    #[test]
    fn directory_only_pattern() {
        let s = set_with("cache/\n");
        assert!(s.matched("cache", true));
        assert!(s.matched("a/cache", true));
        assert!(!s.matched("cache", false));
        assert!(!s.matched("a/cache", false));
    }

    #[test]
    fn double_star_middle() {
        let s = set_with("foo/**/bar\n");
        assert!(s.matched("foo/bar", false));
        assert!(s.matched("foo/x/bar", false));
        assert!(s.matched("foo/x/y/bar", false));
        assert!(!s.matched("foo/bar/baz", false));
        assert!(!s.matched("nope/foo/bar", false));
    }

    #[test]
    fn double_star_leading() {
        let s = set_with("**/build\n");
        assert!(s.matched("build", false));
        assert!(s.matched("a/build", false));
        assert!(s.matched("a/b/build", false));
    }

    #[test]
    fn double_star_trailing() {
        let s = set_with("logs/**\n");
        assert!(s.matched("logs/foo", false));
        assert!(s.matched("logs/a/b/c", false));
        // `logs/**` should also match the directory `logs` itself per
        // gitignore (zero components). Keep that semantic.
        assert!(s.matched("logs", true));
    }

    #[test]
    fn character_class() {
        let s = set_with("a.[ch]\n");
        assert!(s.matched("a.c", false));
        assert!(s.matched("a.h", false));
        assert!(!s.matched("a.cpp", false));
        assert!(!s.matched("a.x", false));
    }

    #[test]
    fn character_class_range_and_negation() {
        let s = set_with("file.[a-c]\n");
        assert!(s.matched("file.a", false));
        assert!(s.matched("file.c", false));
        assert!(!s.matched("file.d", false));

        let s = set_with("[!ab]oo\n");
        assert!(s.matched("coo", false));
        assert!(!s.matched("aoo", false));
        assert!(!s.matched("boo", false));
    }

    #[test]
    fn negation_unignores() {
        let mut s = IgnoreSet::new();
        s.add_file("", "*.log\n!keep.log\n").unwrap();
        assert!(s.matched("foo.log", false));
        assert!(!s.matched("keep.log", false));
        assert!(s.matched("dir/foo.log", false));
        // Loose negation also un-ignores in subdirs.
        assert!(!s.matched("dir/keep.log", false));
    }

    #[test]
    fn last_match_wins() {
        let s = set_with("*.log\n!*.log\n");
        assert!(!s.matched("foo.log", false));
        assert!(!s.matched("dir/foo.log", false));
    }

    #[test]
    fn nested_file_overrides_root() {
        // Root says ignore everything *.log; a nested .gytignore in `src`
        // un-ignores them within src.
        let mut s = IgnoreSet::new();
        s.add_file("", "*.log\n").unwrap();
        s.add_file("src", "!*.log\n").unwrap();
        assert!(s.matched("foo.log", false));
        assert!(s.matched("other/foo.log", false));
        assert!(!s.matched("src/foo.log", false));
        assert!(!s.matched("src/deep/foo.log", false));
    }

    #[test]
    fn nested_file_can_re_ignore() {
        // Root un-ignores; nested file re-ignores in its subtree.
        let mut s = IgnoreSet::new();
        s.add_file("", "*.log\n!special.log\n").unwrap();
        s.add_file("src", "special.log\n").unwrap();
        assert!(!s.matched("special.log", false));
        assert!(s.matched("src/special.log", false));
        assert!(s.matched("src/deep/special.log", false));
    }

    #[test]
    fn question_matches_single_byte() {
        let s = set_with("a?c\n");
        assert!(s.matched("abc", false));
        assert!(s.matched("axc", false));
        assert!(!s.matched("ac", false));
        assert!(!s.matched("abbc", false));
        // `?` does not match `/`.
        assert!(!s.matched("a/c", false));
    }

    #[test]
    fn case_sensitive() {
        let s = set_with("Foo\n");
        assert!(s.matched("Foo", false));
        assert!(!s.matched("foo", false));
        assert!(!s.matched("FOO", false));
    }

    #[test]
    fn comment_hash_only_at_start() {
        // `#` not at start of line is literal.
        let s = set_with("a#b\n");
        assert!(s.matched("a#b", false));
    }

    #[test]
    fn trailing_whitespace_trimmed() {
        let s = set_with("foo   \n");
        assert!(s.matched("foo", false));
    }

    #[test]
    fn anchor_does_not_match_sibling_prefix() {
        // Pattern in `src/.gytignore` must not match a sibling `srcfoo/x`.
        let mut s = IgnoreSet::new();
        s.add_file("src", "x\n").unwrap();
        assert!(s.matched("src/x", false));
        assert!(s.matched("src/deep/x", false));
        assert!(!s.matched("srcfoo/x", false));
    }

    #[test]
    fn load_from_root_reads_dot_gytignore() {
        let dir = tempdir::Dir::new("gyt-ignore-test");
        let p = dir.path().join(".gytignore");
        std::fs::write(&p, b"*.log\n!keep.log\n").unwrap();
        let s = IgnoreSet::load_from_root(dir.path()).unwrap();
        assert!(s.matched("foo.log", false));
        assert!(!s.matched("keep.log", false));
    }

    #[test]
    fn load_from_root_missing_file_is_empty() {
        let dir = tempdir::Dir::new("gyt-ignore-test-missing");
        let s = IgnoreSet::load_from_root(dir.path()).unwrap();
        assert!(!s.matched("foo.log", false));
    }

    #[test]
    fn unterminated_class_is_parse_error() {
        let mut s = IgnoreSet::new();
        let err = s.add_file("", "foo[abc\n").unwrap_err();
        match err {
            GytError::Parse(_) => {}
            other => panic!("expected Parse error, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod tempdir {
    #![expect(
        clippy::unwrap_used,
        reason = "test scaffolding: tmp_dir creation failure in a test means the test cannot run, which is a fatal-loud signal"
    )]
    use std::path::{Path, PathBuf};

    pub struct Dir(PathBuf);

    impl Dir {
        pub fn new(prefix: &str) -> Self {
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.subsec_nanos());
            let p = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
