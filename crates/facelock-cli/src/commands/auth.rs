//! One-shot authentication subcommand.
//!
//! Exit codes: 0 = matched, 1 = no match/timeout, 2 = error.

use std::path::Path;

use facelock_camera::quirks::QuirksDb;
use facelock_camera::{Camera, auto_detect_device, is_ir_camera_resolved, validate_device};
use facelock_core::config::Config;
use facelock_core::ipc::DaemonResponse;
use facelock_core::types::MatchResult;
use facelock_daemon::audit::{self, AuditEntry, AuditSource};
use facelock_daemon::auth;
use facelock_daemon::rate_limit::RateLimiter;
use facelock_face::FaceEngine;
use facelock_store::FaceStore;
use tracing::{debug, error, info};

pub fn run(user: String, config_path: Option<String>) -> i32 {
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

    if config.device.path.is_none() {
        match auto_detect_device() {
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

    // Resolve the live device before the pre-flight gates so `pre_check` sees
    // the real IR classification, exactly like the daemon does at startup.
    let device_path = config.device.path.clone().unwrap();
    let quirks = QuirksDb::load();
    let device_info = validate_device(&device_path);
    // Sibling-aware classification: on multi-node USB cameras (e.g. BRIO) only
    // the actual IR sensor node counts as IR, not every node of the device.
    let device_is_ir = device_info
        .as_ref()
        .map(|dev| is_ir_camera_resolved(dev, Some(&quirks)))
        .unwrap_or(false);

    // Device coupling (Plan 02): fingerprint the live camera so the compare loop
    // can skip templates enrolled on a different camera.
    let live_fingerprint = facelock_camera::device_fingerprint(&device_path);

    let device_quirk = device_info
        .ok()
        .and_then(|info| quirks.find_match(&info).cloned());

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
        device_is_ir,
        AuditSource::Oneshot,
    ) {
        // Every pre-flight rejection exits 2 ("error"), which the PAM module
        // maps to PAM_IGNORE — the same code the deleted mirror used for each
        // gate, so a rate-limited or not-enrolled user still falls through to
        // password rather than registering a failed match (exit 1). The
        // suppressed / not-enrolled / rate-limited distinction is carried by
        // the audit record and the tracing output, not the exit code.
        debug!(?resp, "pre-check short-circuit");
        return 2;
    }

    let mut camera = match Camera::open(&config.device, device_quirk.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            error!("camera: {e}");
            return 2;
        }
    };

    // Discard warmup frames for AGC/AE stabilization.
    let warmup = device_quirk
        .and_then(|q| q.warmup_frames)
        .unwrap_or(config.device.warmup_frames);
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
        device_is_ir,
        &live_fingerprint,
        AuditSource::Oneshot,
    );
    let duration_ms = start.elapsed().as_millis() as u64;

    // Note: authenticate_inner already writes audit entries for the camera-based
    // auth loop. The oneshot path relies on those entries, so no additional audit
    // logging is needed here for the auth result itself.

    if matches!(
        response,
        DaemonResponse::AuthResult(MatchResult { matched: false, .. })
    ) {
        if let Err(e) = rate_limiter.record_failure(&store, &user) {
            error!("rate limit record: {e}");
        }
    }

    match response {
        DaemonResponse::AuthResult(MatchResult {
            matched: true,
            similarity,
            ..
        }) => {
            info!(user = %user, similarity = format!("{similarity:.4}"), "authenticated");
            0
        }
        DaemonResponse::AuthResult(MatchResult {
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
        DaemonResponse::Error { message } if message.contains("all frames dark") => {
            info!(user = %user, "all frames dark");
            1
        }
        DaemonResponse::Error { message } => {
            // Errors from authenticate() that aren't "all frames dark" are storage errors
            // which happen before the auth loop — audit those here.
            audit::write_audit_entry(
                &config.audit,
                &AuditEntry {
                    timestamp: audit::now_iso8601(),
                    user: user.clone(),
                    result: "error".into(),
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
            2
        }
        _ => {
            error!("unexpected response");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use facelock_core::config::Config;
    use facelock_core::ipc::DaemonResponse;
    use facelock_core::types::MatchResult;
    use facelock_daemon::audit::AuditSource;
    use facelock_daemon::auth::pre_check_audited;
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
            true,
            AuditSource::Oneshot,
        )
        .expect("rate-limited user must short-circuit");
        assert!(
            matches!(resp, DaemonResponse::Error { ref message } if message.contains("rate limited")),
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
            true,
            AuditSource::Oneshot,
        )
        .expect("un-enrolled user must short-circuit");
        assert!(matches!(resp, DaemonResponse::Suppressed));

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
            true,
            AuditSource::Oneshot,
        )
        .expect("un-enrolled user must short-circuit");
        assert!(matches!(
            resp,
            DaemonResponse::AuthResult(MatchResult { matched: false, .. })
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
            true,
            AuditSource::Oneshot,
        );
        assert!(resp.is_none(), "gates must pass, got {resp:?}");
        assert!(audit_lines(&audit_path).is_empty());
    }
}
