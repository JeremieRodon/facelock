//! `facelock is-enrolled` — cheap, unprivileged enrollment query.
//!
//! ```text
//! facelock is-enrolled [--user <name>] [--json] [--quiet]
//! ```
//!
//! Named after systemd's `is-*` family (`systemctl is-active`, `is-enabled`),
//! which is the established idiom for this exact shape: a boolean query whose
//! exit code is the contract, printing the state word on stdout and taking the
//! global `--quiet` to suppress it.
//!
//! **The exit code is the contract**, so this drops into a shell one-liner:
//!
//! | Code | Meaning |
//! |------|---------|
//! | `0`  | user has a usable enrollment |
//! | `1`  | not enrolled / not usable |
//! | `2`  | error (bad args, unreadable state) |
//!
//! # "Enrolled" means "face auth is operational for me"
//!
//! This command answers from the per-user marker file written by
//! [`crate::commands::enrollment_marker`] — never from the database, which is
//! `0600 root:root`. The marker sits under two `0711 root:root` directories,
//! so any local user can open its own `0600` marker by name (ADR 010): one
//! `open(2)` answers the question with no group membership, no daemon and no
//! camera. `EACCES` on that open (a hardened or foreign layout) is reported
//! as not-enrolled rather than as an error — an indicator that fails to show
//! is the safe way to be wrong.
//!
//! # The marker is a hint, not authority
//!
//! A marker can drift from the database — an out-of-band DB restore, for
//! instance. That is acceptable because `is-enrolled` only decides whether
//! to show a **UI affordance**. A stale marker degrades gracefully: the
//! indicator appears, the PAM attempt fails, and the password context was
//! running in parallel the whole time. PAM at auth time remains authoritative.
//!
//! # Hard requirements
//!
//! This runs on the lock screen, repeatedly, as an unprivileged user. It must
//! not activate the daemon over D-Bus, must not open a camera, and must never
//! error merely because the marker is unreadable. This is
//! why `list --json` cannot be reused: `commands::list` tries daemon IPC
//! first, which *activates* the system daemon. Nothing in this module may call
//! [`crate::ipc_client::send_request`],
//! [`crate::backend::Backend::select`] (it probes the system bus), or
//! [`crate::direct::open_store`] or [`crate::direct::open_store_existing`].
//!
//! The only syscalls on the hot path are: read `/etc/facelock/config.toml` (for
//! the state directory), and read one marker file.

use std::path::Path;

use crate::commands::enrollment_marker::{self, MarkerState};
use crate::message;

/// Exit code: the user has a usable enrollment.
const EXIT_ENROLLED: i32 = 0;
/// Exit code: no usable enrollment.
const EXIT_NOT_ENROLLED: i32 = 1;
/// Exit code: the question could not be answered.
const EXIT_ERROR: i32 = 2;

/// Run `facelock is-enrolled`, returning the process exit code.
pub fn run(user: Option<String>, json: bool) -> i32 {
    // Pure `$SUDO_USER`/`$USER`/`getpwuid` resolution — no D-Bus, no database.
    let user = crate::ipc_client::resolve_user(user.as_deref());
    let base = enrollment_marker::marker_dir_or_default();
    report(state_in(&base, &user), json)
}

/// Read one user's marker from `base`. The whole of this command's logic, with
/// the state directory injected so tests never touch `/var/lib/facelock`.
fn state_in(base: &Path, user: &str) -> MarkerState {
    enrollment_marker::read_marker_in(base, user)
}

/// Print the result and map it to an exit code.
///
/// Everything printed here is machine-facing — a JSON document or a state
/// word — so it goes out through [`message::payload`], which is also where
/// `--quiet` acts: under it this command prints nothing on stdout and the exit
/// code is the whole answer. A genuine error still explains itself on stderr,
/// since a silent exit 2 is indistinguishable from a broken invocation.
fn report(state: MarkerState, json: bool) -> i32 {
    match &state {
        MarkerState::Unreadable(reason) => {
            eprintln!("facelock is-enrolled: {reason}");
        }
        MarkerState::Enrolled(marker) if json => {
            message::payload(&enrolled_json(Some(marker)));
        }
        MarkerState::Absent if json => {
            message::payload(&enrolled_json(None));
        }
        // The state word, as `systemctl is-active` prints `active`.
        MarkerState::Enrolled(_) => message::payload("enrolled"),
        MarkerState::Absent => message::payload("not-enrolled"),
    }

    exit_code(&state)
}

fn exit_code(state: &MarkerState) -> i32 {
    match state {
        MarkerState::Enrolled(_) => EXIT_ENROLLED,
        MarkerState::Absent => EXIT_NOT_ENROLLED,
        MarkerState::Unreadable(_) => EXIT_ERROR,
    }
}

/// `{"enrolled": bool, "models": N, "updated": "<ISO8601>"}`.
///
/// Serialized through `serde_json` rather than `format!` because `updated` is
/// read back off disk and is not trusted to be a bare RFC 3339 string.
fn enrolled_json(marker: Option<&enrollment_marker::Marker>) -> String {
    let value = match marker {
        Some(marker) => serde_json::json!({
            "enrolled": true,
            "models": marker.models,
            "updated": marker.updated,
        }),
        None => serde_json::json!({
            "enrolled": false,
            "models": 0,
            "updated": serde_json::Value::Null,
        }),
    };
    value.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    use crate::commands::enrollment_marker::write_marker_in;

    #[test]
    fn enrolled_user_exits_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("enrolled");
        write_marker_in(&base, "alice", 2, None).unwrap();

        let state = state_in(&base, "alice");
        assert_eq!(exit_code(&state), 0);
        match state {
            MarkerState::Enrolled(m) => assert_eq!(m.models, 2),
            other => panic!("expected Enrolled, got {other:?}"),
        }
    }

    #[test]
    fn missing_marker_exits_one() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(exit_code(&state_in(tmp.path(), "alice")), 1);
    }

    #[test]
    fn missing_state_directory_exits_one() {
        let tmp = tempfile::tempdir().unwrap();
        // ENOENT on the directory itself, not just the file.
        assert_eq!(exit_code(&state_in(&tmp.path().join("nope"), "alice")), 1);
    }

    #[test]
    fn corrupt_marker_exits_two() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("alice"), b"{\"models\": ").unwrap();
        assert_eq!(exit_code(&state_in(tmp.path(), "alice")), 2);
    }

    #[test]
    fn invalid_user_name_exits_two() {
        let tmp = tempfile::tempdir().unwrap();
        for bad in ["", "..", "../../etc/passwd"] {
            assert_eq!(
                exit_code(&state_in(tmp.path(), bad)),
                2,
                "expected exit 2 for {bad:?}"
            );
        }
    }

    /// `EACCES` must be reported exactly like `ENOENT` (exit 1), never as an
    /// error. Root bypasses mode bits, so this only proves anything unprivileged.
    #[test]
    fn unreadable_marker_exits_one() {
        if nix::unistd::Uid::effective().is_root() {
            // Running as root: mode 0 is not enforced, so there is nothing to
            // assert. The kind-level mapping is covered by
            // enrollment_marker::permission_denied_reads_as_absent_not_error.
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("enrolled");
        write_marker_in(&base, "alice", 1, None).unwrap();

        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(base.join("alice"), fs::Permissions::from_mode(0o000)).unwrap();

        assert!(
            fs::read(base.join("alice")).is_err(),
            "test precondition: the marker must be unreadable"
        );
        assert_eq!(exit_code(&state_in(&base, "alice")), 1);
    }

    /// `is-enrolled` must answer from the marker alone: no database, no D-Bus.
    /// The database path here does not exist, and
    /// `Backend::select`/`send_request` are never on this call path.
    #[test]
    fn answers_without_a_database() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("enrolled");
        write_marker_in(&base, "alice", 1, None).unwrap();

        let db_path = tmp.path().join("facelock.db");
        assert!(!db_path.exists(), "there must be no database at all");

        assert_eq!(exit_code(&state_in(&base, "alice")), 0);
    }

    /// The exit code is the contract, and `--json` does not touch it.
    ///
    /// `--quiet` is not a parameter any more — it acts at the payload sink —
    /// so what is left to pin here is that the two rendering modes agree on
    /// the answer.
    #[test]
    fn json_still_produces_the_contract_exit_codes() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("enrolled");
        write_marker_in(&base, "alice", 1, None).unwrap();

        for json in [false, true] {
            assert_eq!(report(state_in(&base, "alice"), json), 0);
            assert_eq!(report(state_in(&base, "nobody"), json), 1);
        }
    }

    #[test]
    fn json_output_matches_the_documented_shape() {
        let marker = enrollment_marker::Marker {
            models: 2,
            updated: "2026-08-12T00:00:00Z".into(),
        };
        assert_eq!(
            enrolled_json(Some(&marker)),
            r#"{"enrolled":true,"models":2,"updated":"2026-08-12T00:00:00Z"}"#
        );
        assert_eq!(
            enrolled_json(None),
            r#"{"enrolled":false,"models":0,"updated":null}"#
        );
    }

    #[test]
    fn json_escapes_a_hostile_timestamp() {
        let marker = enrollment_marker::Marker {
            models: 1,
            updated: "\" ,\"enrolled\":false".into(),
        };
        let rendered = enrolled_json(Some(&marker));
        // Must still parse, and must still say enrolled.
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed["enrolled"], serde_json::Value::Bool(true));
    }
}
