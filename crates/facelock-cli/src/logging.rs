//! The one tracing-subscriber init site for the `facelock` binary (gap E9,
//! issue #149).
//!
//! Two contracts live here. Both have been broken by a hand-rolled init before,
//! and both are invisible until something downstream reads the output:
//!
//! **1. The filter targets the bin name.** `RUST_LOG` filters by target, and
//! this binary's own diagnostic events carry the target `facelock` — the
//! `[[bin]] name` in Cargo.toml — not `facelock_cli`, the crate directory's
//! name. That mismatch has silently dropped every diagnostic at an init site
//! three times historically (see `commands/auth.rs`'s prior fix and CHANGELOG).
//!
//! **2. Diagnostics go to stderr, payload goes to stdout.**
//! `tracing_subscriber::fmt()` defaults its writer to **stdout** — the same
//! stream the machine-readable payloads are printed on (`devices --json`,
//! `list --json`, `is-enrolled --json`, and every human-readable renderer).
//! Any event that passed the filter was therefore prepended to the JSON and the
//! output stopped parsing (#149: with `daemon.mode = "daemon"` and the daemon
//! stopped, `facelock devices --json | jq .` failed on the D-Bus fallback WARN
//! that `backend::select` emits). The split is per-process and per-stream, so
//! it cannot be fixed at the `println!` call sites one at a time — it is fixed
//! once, here.
//!
//! [`init_stderr`] is the only sanctioned way to install this process's
//! subscriber. `no_init_site_outside_this_module_builds_its_own_subscriber`
//! enforces that no other file under `src/` touches `tracing_subscriber` at
//! all, which is what keeps a copy-pasted `tracing_subscriber::fmt()` from
//! reintroducing either failure.

/// The environment variable `tracing_subscriber` reads its filter from.
const ENV_LOG: &str = "RUST_LOG";

/// Fallback `EnvFilter` directive string used when `RUST_LOG` is unset.
/// Enables `info` level on `facelock` (this crate's bin target) and
/// `facelock_daemon` (the library every auth-path command pulls in) — the
/// two targets that carry the diagnostics operators care about by default.
pub const DEFAULT_LOG_FILTER: &str = "facelock=info,facelock_daemon=info";

/// Install this process's tracing subscriber, writing every event to
/// **stderr**.
///
/// `with_target` includes each event's target (module path) in the rendered
/// line: the daemon wants it, the CLI does not.
///
/// Panics only in the way `tracing_subscriber`'s own `init()` does — being
/// called twice in one process.
pub fn init_stderr(with_target: bool) {
    let (filter, rejected) = env_filter();

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(with_target)
        // #149. Not a style preference: stdout carries this binary's payloads.
        .with_writer(std::io::stderr)
        .init();

    // Reportable only now that a subscriber exists — the filter has to be
    // built before it can be installed. Silently ignoring a `RUST_LOG` the
    // operator deliberately set is its own papercut: the symptom is "my filter
    // did nothing", which is indistinguishable from "nothing logged".
    if let Some(reason) = rejected {
        tracing::warn!(
            reason = %reason,
            fallback = DEFAULT_LOG_FILTER,
            "RUST_LOG could not be parsed and was ignored"
        );
    }
}

/// The `EnvFilter` to install, plus the reason `RUST_LOG` was rejected when it
/// was set but unparseable.
///
/// `RUST_LOG` unset and `RUST_LOG` invalid both fall back to
/// [`DEFAULT_LOG_FILTER`] — the same outcome the previous
/// `try_from_default_env().unwrap_or_else(..)` produced — but only the second
/// is worth telling the operator about, which is why they are distinguished
/// here rather than collapsed.
fn env_filter() -> (tracing_subscriber::EnvFilter, Option<String>) {
    match std::env::var(ENV_LOG) {
        Ok(raw) => classify_filter(&raw),
        Err(_) => (fallback_filter(), None),
    }
}

/// [`env_filter`] for one already-read `RUST_LOG` value, split out so the
/// accept/reject classification is testable without mutating the process
/// environment (which every other test in this binary shares).
fn classify_filter(raw: &str) -> (tracing_subscriber::EnvFilter, Option<String>) {
    match tracing_subscriber::EnvFilter::try_new(raw) {
        Ok(filter) => (filter, None),
        Err(e) => (fallback_filter(), Some(e.to_string())),
    }
}

fn fallback_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::new(DEFAULT_LOG_FILTER)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn default_log_filter_targets_the_bin_name_not_the_crate_directory_name() {
        // The crate directory is `facelock-cli` (which underscores to
        // `facelock_cli`), but the `[[bin]]` target — and therefore every
        // tracing event's target in this binary — is `facelock`.
        // `facelock_cli=...` matches nothing and silently drops every event.
        assert!(DEFAULT_LOG_FILTER.contains("facelock="));
        assert!(!DEFAULT_LOG_FILTER.contains("facelock_cli"));
        assert!(DEFAULT_LOG_FILTER.contains("facelock_daemon="));
    }

    #[test]
    fn default_log_filter_pinned() {
        assert_eq!(DEFAULT_LOG_FILTER, "facelock=info,facelock_daemon=info");
    }

    /// The fallback string has to actually parse — it is what an operator gets
    /// when their own `RUST_LOG` did not.
    #[test]
    fn the_fallback_filter_parses() {
        assert!(tracing_subscriber::EnvFilter::try_new(DEFAULT_LOG_FILTER).is_ok());
    }

    /// `tests/json_stream_split.rs` forces a guaranteed WARN by handing the
    /// binary this exact `RUST_LOG`. If `tracing_subscriber` ever starts
    /// accepting it, that test emits no diagnostic and silently stops proving
    /// anything — so the fixture is pinned here, next to the code that
    /// classifies it.
    #[test]
    fn the_stream_split_tests_bad_rust_log_fixture_really_is_unparseable() {
        let (_, rejected) = classify_filter("facelock=notalevel");
        assert!(
            rejected.is_some(),
            "`facelock=notalevel` must be rejected: it is the fixture \
             tests/json_stream_split.rs uses to force a WARN"
        );
    }

    /// A valid `RUST_LOG` is honored and reported as such; an unset one falls
    /// back without complaint.
    #[test]
    fn a_valid_rust_log_is_honored_without_a_complaint() {
        assert!(classify_filter("facelock=trace").1.is_none());
        assert!(classify_filter(DEFAULT_LOG_FILTER).1.is_none());
    }

    /// Walks this crate's `src/` tree at test time and asserts that no file
    /// other than this one touches `tracing_subscriber` at all, and that the
    /// three known init sites go through [`init_stderr`].
    ///
    /// Honest scope: this is a textual scan, not a borrow-checked guarantee —
    /// a site could still be added under a re-exported alias, or the strings
    /// split across lines to dodge the substring match. It catches the actual
    /// historical failure mode (copy-pasting a `tracing_subscriber::fmt()`
    /// block into a new command, inheriting the stdout writer and a
    /// hand-rolled filter) and regressions at the three known sites; it is not
    /// a guarantee that *no* site anywhere can ever bypass it.
    #[test]
    fn no_init_site_outside_this_module_builds_its_own_subscriber() {
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut visited_files = 0usize;
        let mut sites_using_helper = Vec::new();

        visit_rs_files(&src_dir, &mut |path, contents| {
            visited_files += 1;
            let is_this_file = path.file_name().and_then(|n| n.to_str()) == Some("logging.rs");
            if !is_this_file {
                assert!(
                    !contents.contains("tracing_subscriber"),
                    "{} builds its own subscriber instead of calling \
                     logging::init_stderr() — see logging.rs's module doc \
                     comment, which owns both the filter and the stderr writer",
                    path.display()
                );
            }
            if contents.contains("logging::init_stderr(") {
                sites_using_helper.push(path.to_path_buf());
            }
        });

        assert!(
            visited_files >= 4,
            "expected to scan at least main.rs, logging.rs, commands/auth.rs, \
             commands/daemon.rs; only found {visited_files} — did the src \
             layout change under this test's feet?"
        );

        // The three call sites this gap originally named. If a command gets
        // its own tracing init in the future, add it here too.
        for expected_substr in ["main.rs", "auth.rs", "daemon.rs"] {
            assert!(
                sites_using_helper
                    .iter()
                    .any(|p| p.to_string_lossy().contains(expected_substr)),
                "expected a call to logging::init_stderr() in a path \
                 containing {expected_substr:?}, found calls only in {sites_using_helper:?}"
            );
        }
    }

    fn visit_rs_files(dir: &Path, f: &mut dyn FnMut(&Path, &str)) {
        let entries = std::fs::read_dir(dir)
            .unwrap_or_else(|e| panic!("failed to read {}: {e}", dir.display()));
        for entry in entries {
            let entry = entry.expect("dir entry read failed");
            let path = entry.path();
            if path.is_dir() {
                visit_rs_files(&path, f);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let contents = std::fs::read_to_string(&path)
                    .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
                f(&path, &contents);
            }
        }
    }
}
