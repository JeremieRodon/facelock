//! One-shot authentication subcommand.
//!
//! Exit codes: 0 = matched, 1 = no match/timeout, 2 = error.

use std::path::Path;

use facelock_camera::quirks::QuirksDb;
use facelock_camera::{Camera, ResolvedCamera, auto_detect_device_with, validate_device};
use facelock_core::config::Config;
use facelock_core::types::CameraCaps;
use facelock_core::types::MatchResult;
use facelock_daemon::audit::{self, AuditEntry, AuditSource};
use facelock_daemon::auth;
use facelock_daemon::auth::{AuthOutcome, ErrorKind};
use facelock_daemon::rate_limit::RateLimiter;
use facelock_face::FaceEngine;
use facelock_store::FaceStore;
use tracing::{debug, error, info};

pub fn run(user: String, config_path: Option<String>) -> i32 {
    // Deliberate parse (D7): `facelock auth` is its own one-shot process
    // spawned by PAM, so this is its top-of-process read — not a re-read.
    let config = match config_path {
        Some(ref p) => Config::load_from(Path::new(p)),
        None => Config::load(),
    };
    let mut config = match config {
        Ok(c) => c,
        Err(e) => {
            eprintln!("facelock auth: config error: {e}");
            return 2;
        }
    };

    tracing_subscriber::fmt()
        // See crate::logging's module doc for why this must not build its
        // own fallback filter by hand.
        .with_env_filter(crate::logging::default_env_filter())
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    // Loaded once, up front: auto-detection and the interrogation below must
    // be decided by the SAME quirk set, or the device picked and the device
    // classified could disagree.
    let quirks = QuirksDb::load();

    if config.device.path.is_none() {
        match auto_detect_device_with(&quirks) {
            Ok(dev) => {
                info!(device = %dev.path, name = %dev.name, "auto-detected camera");
                config.device.path = Some(dev.path);
            }
            Err(e) => {
                error!("no camera: {e}");
                return 2;
            }
        }
    }

    // Resolve and interrogate the live device before the pre-flight gates so
    // `pre_check` sees the real caps (IR classification, fingerprint),
    // exactly like the daemon does at startup. Tolerant of a device that
    // cannot be queried: non-IR caps with whatever identity sysfs still
    // offers, so `require_ir` rejects rather than a hard error here.
    let device_path = config.device.path.clone().unwrap();
    let resolved = match validate_device(&device_path) {
        Ok(info) => Some(ResolvedCamera::interrogate(info, &quirks)),
        Err(_) => None,
    };
    let caps = resolved
        .as_ref()
        .map(|r| r.caps.clone())
        .unwrap_or_else(|| {
            CameraCaps::unqueryable(facelock_camera::device_fingerprint(&device_path))
        });

    // Best-effort mode fixing before the store is opened: this is the PAM
    // path, the one entry point guaranteed to run on an oneshot-mode install
    // that never starts the daemon and never re-runs setup. A failure only
    // means modes could not be set and must never block an authentication.
    crate::state_layout::ensure_state_layout_best_effort(&config);

    // Open a writable store (the oneshot path runs as root or the facelock
    // group). The rate limiter is SQLite-backed through this database, so its
    // window is shared with the daemon and survives across process invocations.
    // `create`: on a genuinely fresh install this is what brings the
    // rate-limiter's storage into being, so switching to `open_existing` would
    // change auth-path behaviour, not harden it.
    let store = match FaceStore::create(Path::new(&config.storage.db_path)) {
        Ok(s) => s,
        Err(e) => {
            error!("database: {e}");
            return 2;
        }
    };

    let rl = &config.security.rate_limit;
    let rate_limiter = RateLimiter::new(rl.max_attempts, rl.window_secs);

    // The daemon's pre-flight gates (disabled/SSH/lid, enrollment +
    // suppress_unknown, rate limit, require_ir), with the daemon's rejection
    // auditing. This used to be an inline mirror that drifted (#95): rate-limit
    // rejections were never audited and suppress_unknown was ignored.
    if let Some(resp) = auth::pre_check_audited(
        &config,
        &store,
        &user,
        &rate_limiter,
        &caps,
        AuditSource::Oneshot,
    ) {
        // Every pre-flight rejection exits 2 ("error"), which the PAM module
        // maps to PAM_IGNORE — the same code the deleted mirror used for each
        // gate, so a rate-limited or not-enrolled user still falls through to
        // password rather than registering a failed match (exit 1). The
        // suppressed / not-enrolled / rate-limited distinction is carried by
        // the audit record and the tracing output, not the exit code.
        //
        // `oneshot_exit_code` is the single table, so the recommendation to
        // stop collapsing these classes has one place to land. It cannot
        // change anything today: no pre-flight gate produces the one class
        // that maps to 1 (the camera is not open yet).
        debug!(?resp, "pre-check short-circuit");
        return match resp {
            AuthOutcome::Error { kind, .. } => oneshot_exit_code(kind),
            _ => 2,
        };
    }

    // Quirk override takes precedence over the config's warmup value.
    let warmup = resolved
        .as_ref()
        .and_then(|r| r.quirk.as_ref())
        .and_then(|q| q.warmup_frames)
        .unwrap_or(config.device.warmup_frames);
    let camera = match resolved {
        // The camera carries the caps the pre-flight gates just checked.
        Some(resolved) => resolved.open(&config.device),
        // Unqueryable at resolution time: attempt a fresh resolve-and-open so
        // the failure surfaces as the camera error it is.
        None => Camera::open(&config.device, &quirks),
    };
    let mut camera = match camera {
        Ok(c) => c,
        Err(e) => {
            error!("camera: {e}");
            return 2;
        }
    };

    // Discard warmup frames for AGC/AE stabilization.
    for _ in 0..warmup {
        let _ = camera.capture();
    }

    let mut engine =
        match FaceEngine::load(&config.recognition, Path::new(&config.daemon.model_dir)) {
            Ok(e) => e,
            Err(e) => {
                error!("models: {e}");
                return 2;
            }
        };

    // Load embeddings through the decryption-aware path so the oneshot binary
    // handles encrypted templates (encrypt-by-default, Plan 04) — the bare
    // `auth::authenticate` helper reads plaintext only. Decrypt failure degrades
    // to no-match (exit 1 via an empty compare set), never a hard error.
    let mut stored = match crate::direct::load_user_embeddings(&store, &config, &user) {
        Ok(v) => v,
        Err(e) => {
            error!(user = %user, "failed to load embeddings: {e}");
            return 1;
        }
    };
    let models = store.list_models(&user).unwrap_or_default();

    let start = std::time::Instant::now();
    let response = crate::direct::authenticate_and_wipe(
        &mut camera,
        &mut engine,
        &mut stored,
        &models,
        &config,
        &user,
        AuditSource::Oneshot,
    );
    let duration_ms = start.elapsed().as_millis() as u64;

    // Note: authenticate_inner already writes audit entries for the camera-based
    // auth loop. The oneshot path relies on those entries, so no additional audit
    // logging is needed here for the auth result itself.

    if matches!(
        response,
        AuthOutcome::AuthResult(MatchResult { matched: false, .. })
    ) {
        if let Err(e) = rate_limiter.record_failure(&store, &user) {
            error!("rate limit record: {e}");
        }
    }

    match response {
        AuthOutcome::AuthResult(MatchResult {
            matched: true,
            similarity,
            ..
        }) => {
            info!(user = %user, similarity = format!("{similarity:.4}"), "authenticated");
            0
        }
        AuthOutcome::AuthResult(MatchResult {
            matched: false,
            similarity,
            failure_reason,
            ..
        }) => {
            // Exit code stays 1 (PAM falls through to password); the reason is
            // diagnostic only.
            info!(
                user = %user,
                similarity = format!("{similarity:.4}"),
                variance_blocked = failure_reason.is_some(),
                "no match"
            );
            1
        }
        AuthOutcome::Error {
            kind: ErrorKind::AllFramesDark,
            ..
        } => {
            // `authenticate_inner` already audited this one, so unlike the
            // arm below there is nothing to write here.
            info!(user = %user, "all frames dark");
            oneshot_exit_code(ErrorKind::AllFramesDark)
        }
        AuthOutcome::Error { kind, message } => {
            // Errors from authenticate() other than all-frames-dark are
            // storage errors which happen before the auth loop — audit those
            // here, under the class's own label.
            audit::write_audit_entry(
                &config.audit,
                &AuditEntry {
                    timestamp: audit::now_iso8601(),
                    user: user.clone(),
                    result: kind.audit_result().into(),
                    source: Some(AuditSource::Oneshot),
                    similarity: None,
                    frame_count: None,
                    duration_ms: Some(duration_ms),
                    device: config.device.path.clone(),
                    model_label: None,
                    error: Some(message.clone()),
                },
            );
            error!(user = %user, "auth error: {message}");
            oneshot_exit_code(kind)
        }
        _ => {
            error!("unexpected response");
            2
        }
    }
}

/// The process exit code for a rejection of class `kind`.
///
/// The oneshot binary is spawned by the PAM module, which turns this number
/// into a PAM code, so this table is auth policy — it used to be
/// `message.contains("all frames dark")`, one reword away from changing it.
///
/// Exhaustive on purpose: a new class must be assigned a code here.
///
/// Today only the camera-produced class earns exit 1; every rejection reached
/// before the camera collapses to 2 (PAM_IGNORE). That collapse is itself a
/// defect — it softens a rate-limited rejection whenever the daemon is
/// unavailable and PAM falls back to this path — but fixing it changes PAM
/// semantics under `required`/`requisite` stacks and belongs in its own
/// reviewed change. This function is where that fix will land.
fn oneshot_exit_code(kind: ErrorKind) -> i32 {
    match kind {
        // The camera produced no usable image. Not an error the stack should
        // ignore, and not a non-match either; exit 1 keeps PAM falling
        // through to the password.
        ErrorKind::AllFramesDark => 1,
        ErrorKind::Disabled
        | ErrorKind::SshSession
        | ErrorKind::LidClosed
        | ErrorKind::Storage
        | ErrorKind::RateLimited
        | ErrorKind::RateLimitCheckFailed
        | ErrorKind::IrRequired
        | ErrorKind::Internal => 2,
    }
}

#[cfg(test)]
mod tests {
    use super::oneshot_exit_code;
    use facelock_core::config::Config;
    use facelock_core::types::MatchResult;
    use facelock_daemon::audit::AuditSource;
    use facelock_daemon::auth::pre_check_audited;
    use facelock_daemon::auth::{AuthOutcome, ErrorKind};

    /// The coupling, in one place.
    ///
    /// A rejection class has four consequences, and they used to be derived
    /// from four independent substring matches on the same English sentence:
    /// the text the user and the wire see, the audit log's `result` label, the
    /// PAM return code, and this binary's exit code. Rewording a message
    /// silently changed PAM policy, and no test spanned the four.
    ///
    /// This table is that test. The first three columns are asserted directly;
    /// the fourth — PAM's code — is asserted where it can be: the two messages
    /// PAM substring-matches are pinned byte-exactly here, in
    /// `facelock-daemon`'s `frozen_protocol_strings_render_byte_exactly`, and
    /// at the wire in `server_authz.rs`. `pam-facelock` cannot be linked here
    /// (its dependency ceiling is libc/toml/serde/zbus), so its matcher is
    /// pinned by those strings rather than by calling it.
    ///
    /// Changing a value here is changing auth policy. Do it deliberately.
    #[test]
    fn every_rejection_class_pins_its_message_audit_label_and_exit_code() {
        // (class, rendered message with detail "boom", audit result, exit code)
        let table: &[(ErrorKind, &str, &str, i32)] = &[
            (ErrorKind::Disabled, "facelock is disabled", "error", 2),
            (ErrorKind::SshSession, "SSH session detected", "error", 2),
            (ErrorKind::LidClosed, "lid closed", "error", 2),
            (ErrorKind::Storage, "storage error: boom", "error", 2),
            // Frozen: PAM reads this one as a deliberate lockout
            // (PAM_AUTH_ERR, no oneshot retry).
            (ErrorKind::RateLimited, "rate limited", "rate_limited", 2),
            (
                ErrorKind::RateLimitCheckFailed,
                "rate limit check failed: boom",
                "error",
                2,
            ),
            // Frozen: PAM reads this one as PAM_IGNORE.
            (
                ErrorKind::IrRequired,
                "IR camera required for authentication. Set security.require_ir = false to override (NOT RECOMMENDED).",
                "error",
                2,
            ),
            (ErrorKind::AllFramesDark, "all frames dark", "error", 1),
            (ErrorKind::Internal, "boom", "error", 2),
        ];

        for (kind, message, audit_result, exit_code) in table {
            assert_eq!(
                &kind.render("boom"),
                message,
                "{kind:?}: wire/user message changed — PAM and docs/contracts.md read this"
            );
            assert_eq!(
                kind.audit_result(),
                *audit_result,
                "{kind:?}: audit label changed — log consumers read this"
            );
            assert_eq!(
                oneshot_exit_code(*kind),
                *exit_code,
                "{kind:?}: exit code changed — PAM maps this to a return code"
            );
        }

        // A new class must be given a row, not silently inherit a neighbour's
        // policy. `render`, `audit_result` and `oneshot_exit_code` are all
        // exhaustive matches, so this is the only gap left to close.
        assert_eq!(
            table.len(),
            ErrorKind::ALL.len(),
            "every ErrorKind needs a row here"
        );
        for kind in ErrorKind::ALL {
            assert!(
                table.iter().any(|(k, ..)| k == kind),
                "{kind:?} has no row in the coupling table"
            );
        }
    }
    use facelock_daemon::rate_limit::RateLimiter;
    use facelock_store::FaceStore;
    use std::path::Path;

    /// Config for exercising the oneshot pre-flight gates: audit to a temp
    /// file, SSH/lid gates off so the environment cannot short-circuit first.
    fn gate_config(audit_path: &str, suppress_unknown: bool) -> Config {
        Config::parse(&format!(
            r#"
[security]
require_ir = false
abort_if_ssh = false
abort_if_lid_closed = false
suppress_unknown = {suppress_unknown}

[security.rate_limit]
max_attempts = 2
window_secs = 60

[audit]
enabled = true
path = "{audit_path}"
"#
        ))
        .unwrap()
    }

    fn audit_lines(path: &Path) -> Vec<serde_json::Value> {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        content
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    fn rate_limiter(config: &Config) -> RateLimiter {
        let rl = &config.security.rate_limit;
        RateLimiter::new(rl.max_attempts, rl.window_secs)
    }

    /// Caps of an IR-classified device (what these tests used to express as a
    /// bare `device_is_ir: true`).
    fn ir_caps() -> facelock_core::types::CameraCaps {
        facelock_core::types::CameraCaps {
            is_ir: true,
            ..Default::default()
        }
    }

    /// #95 symptom (a): a rate-limited oneshot attempt used to be rejected
    /// with no audit record. Unified on `pre_check_audited`, the rejection
    /// must produce the same `rate_limited` entry the daemon path writes,
    /// stamped with the oneshot source.
    #[test]
    fn rate_limit_rejection_on_oneshot_path_writes_audit_record() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.jsonl");
        let config = gate_config(audit_path.to_str().unwrap(), false);
        let store = FaceStore::open_memory().unwrap();
        store
            .add_model("alice", "front", &[0.5f32; 512], "test-embedder")
            .unwrap();

        let limiter = rate_limiter(&config);
        limiter.record_failure(&store, "alice").unwrap();
        limiter.record_failure(&store, "alice").unwrap();

        let resp = pre_check_audited(
            &config,
            &store,
            "alice",
            &limiter,
            &ir_caps(),
            AuditSource::Oneshot,
        )
        .expect("rate-limited user must short-circuit");
        assert!(
            matches!(resp, AuthOutcome::Error { kind, .. } if kind == ErrorKind::RateLimited),
            "expected rate-limited error, got {resp:?}"
        );

        let lines = audit_lines(&audit_path);
        assert_eq!(lines.len(), 1, "exactly one audit record for the rejection");
        assert_eq!(lines[0]["result"], "rate_limited");
        assert_eq!(lines[0]["source"], "oneshot");
        assert_eq!(lines[0]["user"], "alice");
    }

    /// #95 symptom (b): `suppress_unknown` was ignored on the oneshot path.
    /// With it enabled, an un-enrolled user must yield `Suppressed` (audited
    /// as such), not a plain not-enrolled failure.
    #[test]
    fn suppress_unknown_honored_on_oneshot_path() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.jsonl");
        let config = gate_config(audit_path.to_str().unwrap(), true);
        let store = FaceStore::open_memory().unwrap();

        let resp = pre_check_audited(
            &config,
            &store,
            "nobody",
            &rate_limiter(&config),
            &ir_caps(),
            AuditSource::Oneshot,
        )
        .expect("un-enrolled user must short-circuit");
        assert!(matches!(resp, AuthOutcome::Suppressed));

        let lines = audit_lines(&audit_path);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["result"], "suppressed");
        assert_eq!(lines[0]["source"], "oneshot");
    }

    /// Counterpart to the suppress test: with `suppress_unknown` off, the
    /// same un-enrolled user is a plain non-match, audited as `failure` —
    /// matching the daemon path.
    #[test]
    fn no_models_without_suppress_audits_failure() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.jsonl");
        let config = gate_config(audit_path.to_str().unwrap(), false);
        let store = FaceStore::open_memory().unwrap();

        let resp = pre_check_audited(
            &config,
            &store,
            "nobody",
            &rate_limiter(&config),
            &ir_caps(),
            AuditSource::Oneshot,
        )
        .expect("un-enrolled user must short-circuit");
        assert!(matches!(
            resp,
            AuthOutcome::AuthResult(MatchResult { matched: false, .. })
        ));

        let lines = audit_lines(&audit_path);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0]["result"], "failure");
        assert_eq!(lines[0]["source"], "oneshot");
    }

    /// An enrolled, un-limited user passes the gates with no audit record —
    /// the auth loop itself owns success/failure auditing.
    #[test]
    fn passing_pre_check_writes_no_audit_record() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir.path().join("audit.jsonl");
        let config = gate_config(audit_path.to_str().unwrap(), false);
        let store = FaceStore::open_memory().unwrap();
        store
            .add_model("alice", "front", &[0.5f32; 512], "test-embedder")
            .unwrap();

        let resp = pre_check_audited(
            &config,
            &store,
            "alice",
            &rate_limiter(&config),
            &ir_caps(),
            AuditSource::Oneshot,
        );
        assert!(resp.is_none(), "gates must pass, got {resp:?}");
        assert!(audit_lines(&audit_path).is_empty());
    }
}
