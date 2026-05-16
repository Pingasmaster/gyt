// ANSI color helpers + control-byte sanitizer for renderer output.
// No external term crate.

use std::io::IsTerminal;

pub fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

/// Sanitize a string before writing it to the user's terminal. The
/// input may come from a commit author, committer, message, ref name,
/// tag tagger, blame line, blob content, or stash subject — any of
/// which can carry an attacker-controlled ANSI escape sequence (e.g.
/// `\x1b]0;PWNED\x07` to set the terminal title, or
/// `\x1b]52;c;<base64>\x07` to write to the clipboard on terminals
/// that honor OSC 52).
///
/// Replaces bytes < 0x20 (except `\t` and `\n`) and the DEL byte
/// 0x7f with `?`. Multi-byte UTF-8 (chars ≥ U+0080) is preserved
/// unchanged. Closes F-D10-01 across every renderer.
pub fn safe_display(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let v = c as u32;
        if v >= 0x80 {
            out.push(c);
        } else if c == '\t' || c == '\n' || (0x20..=0x7e).contains(&v) {
            out.push(c);
        } else {
            // CR / FF / ESC / BEL / DEL / other C0 → drop visibly.
            out.push('?');
        }
    }
    out
}

/// Convenience: borrow a `&str`, return an owned sanitized `String`.
/// Sites that want to interpolate via `{}` use this directly.
#[inline]
#[must_use]
pub fn s(input: &str) -> String {
    safe_display(input)
}

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const BLUE: &str = "\x1b[34m";
pub const CYAN: &str = "\x1b[36m";
pub fn paint(color: &str, s: &str) -> String {
    if use_color() {
        format!("{color}{s}{RESET}")
    } else {
        s.to_string()
    }
}

/// Like `paint`, but with the color decision made by the caller.
/// Lets the caller compute `use_color()` once and pass the result to many
/// `paint_when` invocations without re-checking the terminal each time.
pub fn paint_when(use_color: bool, color: &str, s: &str) -> String {
    if use_color {
        format!("{color}{s}{RESET}")
    } else {
        s.to_string()
    }
}
