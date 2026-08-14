//! Parsed vs resolved configuration (D7).
//!
//! Two different questions, two types:
//!
//! - [`ConfigLoad`] — **what the file says.** `main` performs the one read and
//!   parse for the process and hands every command a `&Config`. Commands do
//!   not re-read the file mid-flow; the deliberate exceptions each carry a
//!   comment at their load site (`daemon` reloads on mtime change, `auth` is
//!   its own one-shot process, `setup` bootstraps and edits the file,
//!   `config` displays/edits the file itself, and `is-enrolled` tolerates a
//!   missing config on its unprivileged path).
//!
//! # `is-enrolled` never comes here
//!
//! `is-enrolled` is dispatched in `main` *before* [`ConfigLoad::read`] runs
//! and must never construct any resolution machinery: no bus, no camera, no
//! store, no probes. See the module docs in `commands/is_enrolled.rs`; a
//! source-level pin lives in this module's tests.

use std::path::PathBuf;

use facelock_core::Config;
use facelock_core::config::ConfigError;

/// The outcome of the process's single config read.
///
/// Carries the failure instead of unwrapping it so `status` can render a
/// broken config file as a finding; every other command goes through
/// [`ConfigLoad::require`], which is the one place load errors are worded.
pub struct ConfigLoad {
    /// The path that was read (after any `--config` override).
    pub path: PathBuf,
    pub result: Result<Config, ConfigError>,
}

impl ConfigLoad {
    /// Read and parse the config file once, from the process's resolved path.
    pub fn read() -> Self {
        Self::read_from(facelock_core::paths::config_path())
    }

    fn read_from(path: PathBuf) -> Self {
        let result = Config::load_from(&path);
        ConfigLoad { path, result }
    }

    /// The parsed config, or the unified load error (D7 item 4): missing file
    /// points at `facelock setup`; a broken file names the path and the parse
    /// error. Every command that needs a config fails through here, so the
    /// wording cannot drift per command.
    pub fn require(self) -> anyhow::Result<Config> {
        match self.result {
            Ok(config) => Ok(config),
            Err(ConfigError::NotFound(_)) => anyhow::bail!(
                "no config file at {} — run 'sudo facelock setup' to create one",
                self.path.display()
            ),
            Err(e) => anyhow::bail!("invalid config at {}: {e}", self.path.display()),
        }
    }

    /// Borrow the config when it parsed; `None` otherwise. For renderers
    /// (`status`) that degrade instead of failing.
    pub fn config(&self) -> Option<&Config> {
        self.result.as_ref().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    #[test]
    fn require_on_missing_file_points_at_setup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let err = ConfigLoad::read_from(path.clone()).require().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no config file"), "{msg}");
        assert!(msg.contains("facelock setup"), "{msg}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");
    }

    #[test]
    fn require_on_broken_file_names_path_and_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "[device\npath=").unwrap();

        let err = ConfigLoad::read_from(path.clone()).require().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid config"), "{msg}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");
    }

    /// The ownership contract: after the one read, the `Config` value is the
    /// source of truth — commands hold `&Config` and keep working even if the
    /// file disappears, because nothing on their path re-reads it.
    #[test]
    fn parsed_config_outlives_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "[storage]\ndb_path = \"/srv/faces/facelock.db\"\n").unwrap();

        let config = ConfigLoad::read_from(path.clone()).require().unwrap();
        fs::remove_file(&path).unwrap();

        assert_eq!(config.storage.db_path, "/srv/faces/facelock.db");
        // A hypothetical re-read would now fail — which is exactly why
        // commands must not perform one.
        assert!(matches!(
            ConfigLoad::read_from(path).result,
            Err(ConfigError::NotFound(_))
        ));
    }

    // -----------------------------------------------------------------------
    // Structural pins (source scan)
    // -----------------------------------------------------------------------
    //
    // These read the crate's own sources at test time. They are blunt — a
    // token count cannot prove call-graph properties — but they turn "parse
    // once" and "is-enrolled probes nothing" from conventions into failures
    // with a file name attached. Comment lines are ignored so prose may
    // mention the tokens.

    fn source_files() -> Vec<(PathBuf, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(PathBuf, String)>) {
            for entry in fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let content = fs::read_to_string(&path).unwrap();
                    out.push((path, content));
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut out,
        );
        out
    }

    fn count_code_occurrences(content: &str, needle: &str) -> usize {
        content
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .map(|l| l.matches(needle).count())
            .sum()
    }

    /// Parse-once pin. `Config::load()` (the global-path read) is allowed only
    /// at the sites below, each of which documents why it re-reads. Adding one
    /// anywhere else re-introduces the 29-call-site sprawl D7 removed — route
    /// the command through the `&Config` that `main` already parsed.
    #[test]
    fn config_load_call_sites_are_pinned() {
        let allowed: &[(&str, usize)] = &[
            // One-shot auth process: its own top-of-process parse.
            ("commands/auth.rs", 1),
            // Daemon startup + mtime-triggered reload both go through
            // build_handler.
            ("commands/daemon.rs", 1),
            // is-enrolled's tolerant read: must answer even with no config.
            ("commands/enrollment_marker.rs", 1),
            // Bootstrap: load-or-create-default, in both wizard and
            // non-interactive entry points (2 sites x 2 calls).
            ("commands/setup.rs", 4),
        ];

        // Assembled at runtime so this test's own literals don't count.
        let needle = format!("Config::load{}", "()");
        for (path, content) in source_files() {
            let rel = path
                .to_string_lossy()
                .split("/src/")
                .last()
                .unwrap()
                .to_string();
            let count = count_code_occurrences(&content, &needle);
            let expected = allowed
                .iter()
                .find(|(p, _)| *p == rel)
                .map(|(_, n)| *n)
                .unwrap_or(0);
            assert_eq!(
                count, expected,
                "{rel}: found {count} global-path config read(s) ({needle}), \
                 expected {expected}. Commands receive &Config from main (see \
                 resolved::ConfigLoad); a mid-command re-read is a D7 regression."
            );
        }
    }

    /// `is-enrolled` isolation pin: its module must not name the resolution
    /// machinery or any transport/store entry point. This guarantees only that
    /// the module itself stays clean — indirect calls would need a reviewer —
    /// but every past regression started with one of these tokens appearing
    /// here.
    #[test]
    fn is_enrolled_module_stays_probe_free() {
        let forbidden = [
            "ConfigLoad",
            "ResolvedConfig",
            "resolved::",
            "send_request(",
            "should_use_direct(",
            "open_store",
            "Camera",
        ];
        let (_, content) = source_files()
            .into_iter()
            .find(|(p, _)| p.ends_with("commands/is_enrolled.rs"))
            .expect("is_enrolled.rs must exist");
        for token in forbidden {
            assert_eq!(
                count_code_occurrences(&content, token),
                0,
                "is_enrolled.rs must not reference {token:?} — it is dispatched \
                 before all resolution machinery and probes nothing (domain map §5)"
            );
        }
    }
}
