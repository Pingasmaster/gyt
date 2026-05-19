#![forbid(unsafe_code)]
#![deny(clippy::all)]

use gyt::cli;
use gyt::errors::Result;
use gyt::term;

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            // B18: route the error message through term::safe_display so
            // any attacker-controlled bytes embedded in object fields
            // (commit message, tag name, ref name, etc.) that surface
            // via GytError::Display can't smuggle ANSI/CSI/OSC escapes
            // into the operator's terminal.
            eprintln!("gyt: {}", term::safe_display(&e.to_string()));
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    cli::dispatch(&args)
}
