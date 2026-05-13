// Networking modules are scaffolded for future CLI wiring.
#![allow(dead_code)]

pub mod api;
pub mod http;
pub mod protocol;
pub mod refs_policy;
pub mod router;
pub mod server;
pub mod tls;

#[cfg(test)]
pub mod server_stub;

#[cfg(test)]
mod transport_tests;
