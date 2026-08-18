//! Conformance suites for the `facelock` command line.
//!
//! These live in the binary crate, not in `lib.rs` or `tests/`, because every
//! one of them asks a question of `Cli::command()` — the clap tree that only
//! `main.rs` declares. They were `main.rs`'s own `mod tests` until it was 80%
//! test module; splitting them by subject is the whole change.
//!
//! - [`flags`] — what the command line accepts: the short-letter and `--json`
//!   registries, the top-level command set, the setup flag matrix, and the
//!   legacy argv that must keep parsing.
//! - [`capabilities`] — every name `facelock capabilities` emits is backed by
//!   the clap surface it names.
//! - [`docs`] — the reference docs describe the binary that shipped.
//!
//! What is shared is here: the clap-tree navigation helpers all three suites
//! use, and the derive check every one of them presumes.

mod capabilities;
mod docs;
mod flags;

use clap::CommandFactory;

use crate::Cli;

#[test]
fn verify_cli() {
    // Validates the clap derive structure
    Cli::command().debug_assert();
}

/// Collect every command in the tree, keyed by its full invocation path
/// (`facelock bench camera-reopen`), so a failure names the offender.
fn walk<'a>(command: &'a clap::Command, prefix: &str, out: &mut Vec<(String, &'a clap::Command)>) {
    let path = if prefix.is_empty() {
        command.get_name().to_string()
    } else {
        format!("{prefix} {}", command.get_name())
    };
    for sub in command.get_subcommands() {
        walk(sub, &path, out);
    }
    out.push((path, command));
}

/// Descend by subcommand name, naming the missing command on failure.
fn sub<'a>(command: &'a clap::Command, name: &str) -> &'a clap::Command {
    command
        .get_subcommands()
        .find(|c| c.get_name() == name)
        .unwrap_or_else(|| panic!("no `{name}` subcommand"))
}

/// Look an argument up by its clap **id**, which the derive takes from the
/// Rust field name (`no_pam`), not from the long spelling (`--no-pam`).
fn arg<'a>(command: &'a clap::Command, id: &str) -> &'a clap::Arg {
    command
        .get_arguments()
        .find(|a| a.get_id().as_str() == id)
        .unwrap_or_else(|| panic!("`{}` has no `{id}` argument", command.get_name()))
}

/// Assert both halves: the id exists *and* it spells the long name a
/// caller types. Asserting the id alone would let a rename of the
/// spelling pass.
fn assert_long(command: &clap::Command, id: &str, long: &str) {
    assert_eq!(
        arg(command, id).get_long(),
        Some(long),
        "`{}`: the `{id}` arg must spell `--{long}`",
        command.get_name()
    );
}
