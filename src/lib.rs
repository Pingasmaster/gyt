// Library re-export of every gyt module so integration tests can
// drive the internals as white-box callers (BLAKE3 hashes, packfile
// codec, object store, ref walker, lock semantics, …) without having
// to approximate everything through subprocess invocation.
//
// `main.rs` still uses these modules through `use gyt::…`. The
// previous direct `mod x;` declarations in `main.rs` are replaced by
// `use gyt::x` where needed; otherwise unchanged.

#![forbid(unsafe_code)]
#![deny(clippy::all)]
// The lib refactor exposed many items as `pub`, which surfaces a
// flurry of pedantic doc-style lints (long first paragraph, missing
// must_use on Self-returning ctors, missing impl_trait_in_associated
// etc.). They're stylistic, not correctness — silence at the crate
// level to keep clippy --all-targets clean. The original behind-the-
// scenes module structure was `mod x;` from main.rs and these never
// fired. Tracked for cleanup if/when we publish the crate.
#![expect(
    clippy::too_long_first_doc_paragraph,
    reason = "crate docs above are a single discussion paragraph; splitting it harms readability"
)]
#![expect(
    clippy::must_use_candidate,
    reason = "pedantic noise on small helpers whose return is conventionally inspected at the call site"
)]
#![expect(
    clippy::return_self_not_must_use,
    reason = "builder methods returning Self are the standard pattern; #[must_use] adds noise without protecting anything"
)]

pub mod ci_wasm;
pub mod cli;
pub mod cmd;
pub mod compress;
pub mod config;
pub mod diff;
pub mod errors;
pub mod fs_util;
pub mod fuzz;
pub mod hash;
pub mod ignore;
pub mod index;
pub mod incidents;
pub mod issues;
pub mod prs;
pub mod merge3;
pub mod net;
pub mod object;
pub mod refs;
pub mod reflog;
pub mod repo;
pub mod term;
pub mod workdir;
