//! Issue #149: a diagnostic must never land on the stream a payload is
//! printed on.
//!
//! `tracing_subscriber::fmt()` defaults its writer to **stdout**, which is
//! where every `--json` payload is `println!`ed. Any event that passed the
//! filter was therefore prepended to the JSON and `facelock devices --json |
//! jq .` stopped parsing. The unit tests next to those renderers
//! (`commands/devices.rs`, `commands/list.rs`) only ever serialized a struct,
//! so none of them could see it — the corruption happens on the process's
//! streams, not in the string. These tests run the real binary and read the
//! real streams.
//!
//! `is-enrolled --json` is the payload command chosen here because it is the
//! only one that is not root-gated, so this runs unprivileged in CI and on a
//! developer's `cargo test`. The stream split is a property of the subscriber
//! (`crate::logging`), which is process-wide and installed once, so pinning it
//! on one command pins it for all of them.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A `RUST_LOG` value `tracing_subscriber` cannot parse. The binary reports
/// this at WARN, which is what gives these tests a diagnostic that is
/// guaranteed to be emitted on *every* invocation — rather than one that
/// depends on a daemon being absent, a camera being missing, or some other
/// ambient condition a test cannot arrange. `logging.rs` pins the same string
/// so this cannot quietly become parseable and leave the tests asserting
/// nothing.
const UNPARSEABLE_RUST_LOG: &str = "facelock=notalevel";

/// The substring the WARN above renders with. Deliberately free of the level
/// and field names, which `tracing_subscriber` wraps in ANSI escapes.
const WARN_TEXT: &str = "RUST_LOG could not be parsed";

/// A whole installation pointed at `dir`: the marker directory is derived from
/// `storage.db_path`, so this keeps the test off `/var/lib/facelock` and makes
/// the answer deterministic — a user who cannot be enrolled in an empty
/// tempdir always reads as absent.
fn config_in(dir: &Path) -> PathBuf {
    let db_path = dir.join("state").join("facelock.db");
    let path = dir.join("config.toml");
    std::fs::write(
        &path,
        format!("[storage]\ndb_path = \"{}\"\n", db_path.display()),
    )
    .expect("failed to write test config");
    path
}

/// `facelock --config <tmp> is-enrolled --user <absent> --json`, with
/// `RUST_LOG` set to `rust_log` — or removed from the child's environment
/// entirely when `rust_log` is `None`, since the ambient value a developer
/// happens to have exported would otherwise decide what these tests observe.
fn run_is_enrolled_json(dir: &Path, rust_log: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_facelock"));
    command.arg("--config").arg(config_in(dir)).args([
        "is-enrolled",
        "--user",
        "facelock-no-such-account",
        "--json",
    ]);
    match rust_log {
        Some(value) => command.env("RUST_LOG", value),
        None => command.env_remove("RUST_LOG"),
    };
    command
        .output()
        .expect("failed to execute the facelock binary")
}

/// **The #149 regression.** A diagnostic is being emitted; stdout must still
/// be nothing but the payload.
#[test]
fn a_warning_does_not_corrupt_json_on_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    let output = run_is_enrolled_json(tmp.path(), Some(UNPARSEABLE_RUST_LOG));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Non-vacuity first: if no diagnostic was emitted, the assertion below
    // would pass on a binary that still writes its logs to stdout.
    assert!(
        stderr.contains(WARN_TEXT),
        "the fixture must actually produce a warning, or this test proves \
         nothing; got stderr:\n{stderr}"
    );

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("stdout must be parseable JSON, got {e}:\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    assert_eq!(parsed["enrolled"], false);
    assert_eq!(parsed["models"], 0);

    // One line, so a consumer reading a single line off the pipe gets the
    // whole payload and only the payload.
    assert_eq!(
        stdout.trim().lines().count(),
        1,
        "the payload must be the only thing on stdout, got:\n{stdout}"
    );
}

/// The other half of the split: the diagnostic has to still be *somewhere*.
/// Routing it to `/dev/null` would also make the test above pass.
#[test]
fn the_diagnostic_still_reaches_stderr() {
    let tmp = tempfile::tempdir().unwrap();
    let output = run_is_enrolled_json(tmp.path(), Some(UNPARSEABLE_RUST_LOG));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains(WARN_TEXT),
        "the warning belongs on stderr, got stderr:\n{stderr}"
    );
    assert!(
        !stdout.contains(WARN_TEXT),
        "the warning must not be on stdout, got stdout:\n{stdout}"
    );
}

/// The clean-run control. With no `RUST_LOG` there is no diagnostic to
/// misroute, so stdout carries the payload and stderr carries nothing.
///
/// This is what makes the two tests above mean what they say: without it,
/// "the warning is on stderr" would also be satisfied by a binary that is
/// simply noisy on both streams all the time.
#[test]
fn a_clean_run_leaves_stderr_empty_and_the_payload_on_stdout() {
    let tmp = tempfile::tempdir().unwrap();
    let output = run_is_enrolled_json(tmp.path(), None);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or_else(|e| {
        panic!("stdout must be parseable JSON, got {e}:\nstdout:\n{stdout}\nstderr:\n{stderr}")
    });
    assert_eq!(parsed["enrolled"], false);
    assert!(
        stderr.trim().is_empty(),
        "a clean run must say nothing on stderr, got:\n{stderr}"
    );
}
