//! The one tracing-subscriber init site for the `facelock` binary (gap E9,
//! issue #149).
//!
//! Three contracts live here. The first two have been broken by a hand-rolled
//! init before, and both are invisible until something downstream reads the
//! output:
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
//! Any event that passed the filter was therefore prepended to the JSON and
//! the output stopped parsing (#149: with `daemon.mode = "daemon"` and the
//! daemon stopped, `facelock devices --json | jq .` failed on the D-Bus
//! fallback WARN that `backend::select` emits). The split is per-process and
//! per-stream, so it cannot be fixed at the `println!` call sites one at a
//! time — it is fixed once, here.
//!
//! **3. How loud the process is depends on who is reading.** The CLI's stderr
//! shares a terminal with the wizard's own prompts, so an INFO default
//! interleaved timestamped log lines with the questions and left a succeeding
//! run looking broken. [`Program::Cli`] therefore starts at `warn` and `-v`
//! climbs from there. [`Program::Daemon`] keeps `info`: it writes to the
//! journal, where nothing competes with it and INFO is what
//! `journalctl -u facelock` is expected to show. `RUST_LOG` outranks both.
//!
//! [`init_stderr`] is the only sanctioned way to install this process's
//! subscriber. `no_init_site_outside_this_module_builds_its_own_subscriber`
//! enforces that no other file under `src/` touches `tracing_subscriber` at
//! all, which is what keeps a copy-pasted `tracing_subscriber::fmt()` from
//! reintroducing any of the three.

/// The environment variable `tracing_subscriber` reads its filter from.
const ENV_LOG: &str = "RUST_LOG";

/// Which program this process is running as.
///
/// The two differ in exactly two ways — where they start on [`LADDER`], and
/// whether each event's target is rendered — and both differences follow from
/// the one fact that a call site knows: who reads this stream. So it is one
/// argument rather than two booleans a site could set inconsistently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Program {
    /// Every subcommand a person types, `facelock auth` included: its stderr
    /// is either a terminal someone is reading or the pipe `pam_facelock.so`
    /// opens and never drains, and neither wants INFO by default.
    Cli,
    /// `facelock daemon run`, whose stderr the shipped unit points at the
    /// journal.
    Daemon,
}

impl Program {
    /// Where this program sits on [`LADDER`] before `-v` is counted.
    fn base_rung(self) -> usize {
        match self {
            Program::Cli => 0,
            Program::Daemon => 1,
        }
    }

    /// Whether each event's target (module path) is rendered on the line. The
    /// daemon wants it; the CLI does not.
    fn renders_target(self) -> bool {
        self == Program::Daemon
    }
}

/// The CLI's filter when `RUST_LOG` is unset and no `-v` was given: warnings
/// and errors, and nothing else.
///
/// Every degradation an operator has to act on is already WARN or above — the
/// D-Bus fallback in `backend::select`, an ONNX Runtime that would not load, a
/// provider that could not be queried, an unreadable quirks file, an ignored
/// `RUST_LOG` — so this hides progress reports, not findings.
pub const DEFAULT_CLI_LOG_FILTER: &str = "facelock=warn,facelock_daemon=warn";

/// The daemon's filter, and — one `-v` up — the CLI's. It is also what every
/// command emitted before the CLI default moved, so a user who wants the old
/// output back types one flag rather than learning a filter.
pub const DEFAULT_DAEMON_LOG_FILTER: &str = "facelock=info,facelock_daemon=info";

/// One filter per rung of loudness, quietest first. Each `-v` climbs one rung
/// from the program's [`base_rung`](Program::base_rung); repeats past the top
/// stay at `trace` rather than being an error, because a wrapper script that
/// passes `-vvvv` means "as loud as it goes".
///
/// Every rung names `facelock` — the `[[bin]]` target, per contract 1 above —
/// and `facelock_daemon`, the library the auth path pulls in. `EnvFilter`
/// matches a directive's target as a plain string prefix, so `facelock=` also
/// governs `facelock_camera`, `facelock_face` and every other workspace crate:
/// one rung is what silences, or restores, the camera-negotiation and
/// quirks-loading lines this default was changed for.
const LADDER: [&str; 4] = [
    DEFAULT_CLI_LOG_FILTER,
    DEFAULT_DAEMON_LOG_FILTER,
    "facelock=debug,facelock_daemon=debug",
    "facelock=trace,facelock_daemon=trace",
];

/// Install this process's tracing subscriber, writing every event to
/// **stderr**.
///
/// `verbose` is the count of `-v` on the command line (0 when the flag is
/// absent). It moves this process up [`LADDER`]; `RUST_LOG` overrides the
/// result outright.
///
/// Panics only in the way `tracing_subscriber`'s own `init()` does — being
/// called twice in one process.
pub fn init_stderr(program: Program, verbose: u8) {
    let fallback = filter_for(program, verbose);
    let (directives, rejected) =
        chosen_directives(std::env::var(ENV_LOG).ok().as_deref(), fallback);

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(&directives))
        .with_target(program.renders_target())
        // #149. Not a style preference: stdout carries this binary's payloads.
        .with_writer(std::io::stderr)
        .init();

    // Reportable only now that a subscriber exists — the filter has to be
    // built before it can be installed. Silently ignoring a `RUST_LOG` the
    // operator deliberately set is its own papercut: the symptom is "my filter
    // did nothing", which is indistinguishable from "nothing logged". It is a
    // WARN so that it survives the CLI's own default.
    if let Some(reason) = rejected {
        tracing::warn!(
            reason = %reason,
            fallback = fallback,
            "RUST_LOG could not be parsed and was ignored"
        );
    }
}

/// The rung `program` filters at after `verbose` repeats of `-v`, when
/// `RUST_LOG` says nothing: `facelock` → warn, `-v` → info, `-vv` → debug,
/// `-vvv` → trace, and one rung louder throughout for the daemon, which starts
/// at info.
fn filter_for(program: Program, verbose: u8) -> &'static str {
    let rung = program.base_rung() + usize::from(verbose);
    LADDER[rung.min(LADDER.len() - 1)]
}

/// The directive string this process filters with, plus the reason a
/// `RUST_LOG` that *was* set had to be ignored.
///
/// **`RUST_LOG` outranks `-v`, which outranks the program's default.** An
/// operator who exported a filter has said what they want, including when what
/// they want is quieter than the flags a wrapper script passes; a `-vvv` that
/// could shout over `RUST_LOG=facelock=error` would make the environment
/// variable unreliable, which is the one thing an override cannot be.
///
/// An unset `RUST_LOG` and an unparseable one both fall back to `fallback` —
/// the same outcome the previous `try_from_default_env().unwrap_or_else(..)`
/// produced — but only the second is worth telling the operator about, which
/// is why they are distinguished here rather than collapsed.
///
/// Pure, and takes the already-read variable rather than reading it, so
/// precedence is testable without mutating the process environment (which
/// every other test in this binary shares). The filter `try_new` builds is
/// discarded and the accepted string parsed once more in [`init_stderr`]: one
/// extra parse of a short string, once per process, for a decision function
/// that is a plain `&str` in and `String` out.
fn chosen_directives(rust_log: Option<&str>, fallback: &'static str) -> (String, Option<String>) {
    let Some(raw) = rust_log else {
        return (fallback.to_string(), None);
    };
    match tracing_subscriber::EnvFilter::try_new(raw) {
        Ok(_) => (raw.to_string(), None),
        Err(e) => (fallback.to_string(), Some(e.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    #[test]
    fn every_rung_targets_the_bin_name_not_the_crate_directory_name() {
        // The crate directory is `facelock-cli` (which underscores to
        // `facelock_cli`), but the `[[bin]]` target — and therefore every
        // tracing event's target in this binary — is `facelock`.
        // `facelock_cli=...` matches nothing and silently drops every event.
        for rung in LADDER {
            assert!(rung.contains("facelock="), "`{rung}` names no bin target");
            assert!(!rung.contains("facelock_cli"), "`{rung}` filters nothing");
            assert!(
                rung.contains("facelock_daemon="),
                "`{rung}` drops the auth-path library"
            );
        }
    }

    /// Both defaults verbatim. Changing either is a deliberate edit here, not
    /// a side effect of an edit somewhere else.
    #[test]
    fn default_log_filters_pinned() {
        assert_eq!(DEFAULT_CLI_LOG_FILTER, "facelock=warn,facelock_daemon=warn");
        assert_eq!(
            DEFAULT_DAEMON_LOG_FILTER,
            "facelock=info,facelock_daemon=info"
        );
    }

    /// Every rung has to actually parse — one of them is what an operator gets
    /// when their own `RUST_LOG` did not.
    #[test]
    fn every_rung_parses() {
        for rung in LADDER {
            assert!(
                tracing_subscriber::EnvFilter::try_new(rung).is_ok(),
                "`{rung}` does not parse"
            );
        }
    }

    #[test]
    fn the_cli_starts_quiet_and_the_daemon_starts_at_info() {
        assert_eq!(filter_for(Program::Cli, 0), DEFAULT_CLI_LOG_FILTER);
        assert_eq!(filter_for(Program::Daemon, 0), DEFAULT_DAEMON_LOG_FILTER);
    }

    /// The documented mapping, plus the top of the ladder: `-v` past `trace`
    /// saturates rather than panicking on an out-of-range index.
    #[test]
    fn each_v_climbs_one_rung_and_the_ladder_saturates() {
        assert_eq!(
            filter_for(Program::Cli, 1),
            "facelock=info,facelock_daemon=info"
        );
        assert_eq!(
            filter_for(Program::Cli, 2),
            "facelock=debug,facelock_daemon=debug"
        );
        assert_eq!(
            filter_for(Program::Cli, 3),
            "facelock=trace,facelock_daemon=trace"
        );
        assert_eq!(
            filter_for(Program::Cli, u8::MAX),
            "facelock=trace,facelock_daemon=trace"
        );

        assert_eq!(
            filter_for(Program::Daemon, 1),
            "facelock=debug,facelock_daemon=debug"
        );
        assert_eq!(
            filter_for(Program::Daemon, u8::MAX),
            "facelock=trace,facelock_daemon=trace"
        );
    }

    /// One `-v` is exactly the volume every command had before the CLI default
    /// moved, which is what makes the upgrade note a flag rather than a filter
    /// to learn.
    #[test]
    fn one_v_restores_the_volume_the_cli_used_to_have() {
        assert_eq!(filter_for(Program::Cli, 1), DEFAULT_DAEMON_LOG_FILTER);
    }

    #[test]
    fn an_unset_rust_log_takes_the_programs_own_rung() {
        assert_eq!(
            chosen_directives(None, filter_for(Program::Cli, 0)).0,
            DEFAULT_CLI_LOG_FILTER
        );
        assert_eq!(
            chosen_directives(None, filter_for(Program::Daemon, 0)).0,
            DEFAULT_DAEMON_LOG_FILTER
        );
    }

    #[test]
    fn rust_log_outranks_both_the_default_and_the_v_count() {
        let (chosen, rejected) =
            chosen_directives(Some("facelock=info"), filter_for(Program::Cli, 0));
        assert_eq!(chosen, "facelock=info");
        assert!(rejected.is_none());

        // The direction that is easy to get backwards: `RUST_LOG` wins even
        // when it is the quieter of the two.
        let (chosen, _) = chosen_directives(Some("facelock=error"), filter_for(Program::Cli, 3));
        assert_eq!(chosen, "facelock=error");
    }

    /// `tests/json_stream_split.rs` forces a guaranteed WARN by handing the
    /// binary this exact `RUST_LOG`. If `tracing_subscriber` ever starts
    /// accepting it, that test emits no diagnostic and silently stops proving
    /// anything — so the fixture is pinned here, next to the code that
    /// classifies it.
    #[test]
    fn the_stream_split_tests_bad_rust_log_fixture_really_is_unparseable() {
        let (chosen, rejected) =
            chosen_directives(Some("facelock=notalevel"), DEFAULT_CLI_LOG_FILTER);
        assert!(
            rejected.is_some(),
            "`facelock=notalevel` must be rejected: it is the fixture \
             tests/json_stream_split.rs uses to force a WARN"
        );
        assert_eq!(chosen, DEFAULT_CLI_LOG_FILTER);
    }

    /// A valid `RUST_LOG` is honored and reported as such; an unset one falls
    /// back without complaint.
    #[test]
    fn a_valid_rust_log_is_honored_without_a_complaint() {
        assert!(
            chosen_directives(Some("facelock=trace"), DEFAULT_CLI_LOG_FILTER)
                .1
                .is_none()
        );
        assert!(
            chosen_directives(Some(DEFAULT_CLI_LOG_FILTER), DEFAULT_CLI_LOG_FILTER)
                .1
                .is_none()
        );
    }

    // -- What the streams actually carry ---------------------------------
    //
    // The tests above pin which directive string is chosen. These pin what
    // that string does to real events, which is the thing the gap is about:
    // a `facelock status` run that no longer interleaves INFO with its
    // report, and a `-v` that brings it back.

    /// A `tracing_subscriber::fmt` layer built the way [`init_stderr`] builds
    /// it, but writing into a buffer.
    ///
    /// It rebuilds rather than calling `init_stderr`, which installs a
    /// *process-global* subscriber and so can run at most once per test
    /// binary. What it must share with the real thing is the filter, and that
    /// it takes from [`filter_for`] — the same function `init_stderr` calls.
    fn rendered_events(directives: &str) -> String {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(directives))
            .with_writer(Capture(Arc::clone(&buffer)))
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            // The targets are the real ones, spelled as the emitting crates
            // spell them: `facelock` is this binary, `facelock_camera` is the
            // crate whose format-negotiation lines landed on top of the
            // wizard's prompts, and neither is named by any directive except
            // through the `facelock=` prefix.
            tracing::warn!(target: "facelock", "a warning worth reading");
            tracing::info!(target: "facelock", "an informational line");
            tracing::info!(target: "facelock_camera", "camera format negotiated");
            tracing::debug!(target: "facelock", "a debug line");
        });

        let captured = buffer.lock().expect("capture buffer poisoned").clone();
        String::from_utf8(captured).expect("the fmt layer writes UTF-8")
    }

    /// A `MakeWriter` over a shared buffer, so the events can be read back
    /// after the subscriber that wrote them is gone. `Arc<Mutex<Vec<u8>>>` is
    /// not itself a `MakeWriter` — the blanket impl for `Arc<W>` wants
    /// `&W: Write`, which a `Mutex` is not — so this is the one line of glue.
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl tracing_subscriber::fmt::MakeWriter<'_> for Capture {
        type Writer = Capture;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("capture buffer poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// **The gap.** At the default, a CLI run carries warnings and nothing
    /// below them — including from the workspace crates the `facelock=`
    /// prefix reaches, which is where the noise came from.
    #[test]
    fn the_cli_default_carries_warnings_and_no_progress_reports() {
        let rendered = rendered_events(filter_for(Program::Cli, 0));

        assert!(
            rendered.contains("a warning worth reading"),
            "a WARN must survive the default, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("an informational line"),
            "INFO must not reach stderr by default, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("camera format negotiated"),
            "a workspace crate's INFO must not reach stderr by default \
             (the `facelock=` directive is a target *prefix*), got:\n{rendered}"
        );
    }

    #[test]
    fn v_restores_info_and_vv_adds_debug() {
        let one = rendered_events(filter_for(Program::Cli, 1));
        assert!(one.contains("an informational line"), "got:\n{one}");
        assert!(one.contains("camera format negotiated"), "got:\n{one}");
        assert!(
            !one.contains("a debug line"),
            "`-v` is info, not debug, got:\n{one}"
        );

        let two = rendered_events(filter_for(Program::Cli, 2));
        assert!(two.contains("a debug line"), "got:\n{two}");
    }

    /// The daemon is unaffected by the CLI's new default: `journalctl -u
    /// facelock` shows what it always showed.
    #[test]
    fn the_daemon_still_carries_info() {
        let rendered = rendered_events(filter_for(Program::Daemon, 0));
        assert!(
            rendered.contains("an informational line"),
            "got:\n{rendered}"
        );
    }

    /// `RUST_LOG=info` still wins over the quiet default, end to end rather
    /// than as a string comparison.
    #[test]
    fn a_rust_log_of_info_beats_the_quiet_default_on_the_stream() {
        let (directives, rejected) =
            chosen_directives(Some("facelock=info"), filter_for(Program::Cli, 0));
        assert!(rejected.is_none());

        let rendered = rendered_events(&directives);
        assert!(
            rendered.contains("an informational line"),
            "got:\n{rendered}"
        );
        assert!(
            rendered.contains("camera format negotiated"),
            "got:\n{rendered}"
        );
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
