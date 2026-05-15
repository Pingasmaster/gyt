#![forbid(unsafe_code)]
#![deny(clippy::all)]

use gyt::cli;
use gyt::errors::Result;

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gyt: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    cli::dispatch(&args)
}
