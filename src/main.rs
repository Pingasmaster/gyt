#![forbid(unsafe_code)]
#![deny(clippy::all)]

mod ci_wasm;
mod cli;
mod cmd;
mod compress;
mod config;
mod diff;
mod errors;
mod fs_util;
mod fuzz;
mod hash;
mod ignore;
mod index;
mod merge3;
mod net;
mod object;
mod refs;
mod reflog;
mod repo;
mod term;
mod workdir;

use crate::errors::Result;

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
