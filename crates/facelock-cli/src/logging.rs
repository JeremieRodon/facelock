//! Shared tracing/`EnvFilter` default for the `facelock` binary (gap E9).
//!
//! `RUST_LOG` filters by target, and this binary's own diagnostic events
//! carry the target `facelock` — the `[[bin]] name` in Cargo.toml — not
//! `facelock_cli`, the crate directory's name. That mismatch has silently
//! dropped every diagnostic at an init site three times historically (see
//! `commands/auth.rs`'s prior fix and CHANGELOG). Every
//! `tracing_subscriber::fmt()` init site in this crate must build its
//! fallback filter through [`default_env_filter`] rather than hand-rolling
//! an `EnvFilter::try_from_default_env().unwrap_or_else(...)` string —
//! `logging_conformance_test` in this module enforces that no other site in
//! `src/` bypasses it.

/// Fallback `EnvFilter` directive string used when `RUST_LOG` is unset.
/// Enables `info` level on `facelock` (this crate's bin target) and
/// `facelock_daemon` (the library every auth-path command pulls in) — the
/// two targets that carry the diagnostics operators care about by default.
pub const DEFAULT_LOG_FILTER: &str = "facelock=info,facelock_daemon=info";

/// The `EnvFilter` every tracing-subscriber init site in this crate must use:
/// honors `RUST_LOG` when set and valid, otherwise falls back to
/// [`DEFAULT_LOG_FILTER`].
pub fn default_env_filter() -> tracing_subscriber::EnvFilter {
    tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| DEFAULT_LOG_FILTER.into())
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

    /// Walks this crate's `src/` tree at test time and asserts that (a) the
    /// raw bypass pattern `EnvFilter::try_from_default_env(` /
    /// `EnvFilter::from_default_env(` appears nowhere outside this file, and
    /// (b) every file that previously hand-rolled a fallback filter now
    /// calls `default_env_filter()`.
    ///
    /// Honest scope: this is a textual scan, not a borrow-checked guarantee
    /// — a call site could still be added and shadowed under a different
    /// name, or the bypass strings could be split across lines/macros to
    /// dodge the substring match. It catches the actual historical failure
    /// mode (copy-pasting the old `EnvFilter::try_from_default_env()...`
    /// block into a new command) and regressions at the three known sites;
    /// it is not a guarantee that *no* site anywhere can ever bypass it.
    #[test]
    fn no_init_site_outside_this_module_bypasses_default_env_filter() {
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut visited_files = 0usize;
        let mut sites_using_helper = Vec::new();

        visit_rs_files(&src_dir, &mut |path, contents| {
            visited_files += 1;
            let is_this_file = path.file_name().and_then(|n| n.to_str()) == Some("logging.rs");
            if !is_this_file {
                assert!(
                    !contents.contains("EnvFilter::try_from_default_env(")
                        && !contents.contains("EnvFilter::from_default_env("),
                    "{} builds an EnvFilter directly instead of calling \
                     logging::default_env_filter() — see logging.rs's module \
                     doc comment",
                    path.display()
                );
            }
            if contents.contains("logging::default_env_filter()") {
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
                "expected a call to logging::default_env_filter() in a path \
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
