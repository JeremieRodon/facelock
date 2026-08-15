//! The `facelock` CLI as a library.
//!
//! Everything the `facelock` binary does apart from clap wiring and top-level
//! dispatch lives here so it can be integration-tested from `tests/` and shared
//! (gap D6). The binary (`src/main.rs`) is a thin `main` that parses the
//! command line and calls into these modules.
//!
//! The public surface is the domain layer, not an API contract: these modules
//! are `pub` so an out-of-process test — or a sibling crate — can construct a
//! [`health::Health`] and render it, drive [`backend::Backend`] selection, or
//! exercise the [`message`] seam without spawning the binary and scraping
//! stdout. The clap `Cli`/`Commands` types and the `main` dispatch stay
//! bin-private in `main.rs`; nothing outside the binary needs them.

pub mod backend;
pub mod commands;
pub mod direct;
pub mod health;
pub mod ipc_client;
pub mod logging;
pub mod message;
pub mod notifications;
pub mod resolved;
pub mod state_layout;
