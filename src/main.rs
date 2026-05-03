#![forbid(unsafe_code)]
#![deny(clippy::all)]
// Allowed during scaffolding; remove these as modules are filled in.
#![allow(dead_code)]
#![allow(unused_variables)]

mod cli;
mod cmd;
mod compress;
mod diff;
mod errors;
mod fs_util;
mod hash;
mod ignore;
mod index;
mod net;
mod object;
mod refs;
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
