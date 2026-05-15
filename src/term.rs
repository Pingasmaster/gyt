// ANSI color helpers. No external term crate.

use std::io::IsTerminal;

pub fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
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
