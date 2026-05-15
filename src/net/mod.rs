// Networking modules are scaffolded for future CLI wiring.
#![allow(dead_code)]

pub mod api;
pub mod cache;
pub mod h2_server;
pub mod h3_server;
pub mod http;
pub mod metrics;
pub mod protocol;
pub mod rate_limit;
pub mod refs_policy;
pub mod router;
pub mod server;
pub mod ticket;
pub mod tls;

#[cfg(test)]
pub mod server_stub;

#[cfg(test)]
mod transport_tests;
