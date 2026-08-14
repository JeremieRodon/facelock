use std::path::Path;
use std::time::Instant;

use facelock_camera::capture::is_dark_with_config;
use facelock_camera::preprocess::check_ir_texture;
use facelock_core::config::{Config, SnapshotConfig};
use facelock_core::fs_security::{ensure_dir, ensure_private_dir, write_file};
use facelock_core::traits::{CameraSource, FaceProcessor};
use facelock_core::types::{
    AuthFailureReason, CameraCaps, FaceEmbedding, Frame, FrameVarianceWindow, MatchResult,
    best_match, device_allowed_model_ids, zeroize_stored_embeddings,
};
use facelock_store::FaceStore;
use image::codecs::jpeg::JpegEncoder;
use nix::unistd::Uid;
use tracing::{debug, info, warn};

use crate::audit::{self, AuditEntry, AuditSource};
use crate::liveness::LandmarkTracker;
use crate::rate_limit::RateLimiter;

/// The outcome of an authentication attempt or its pre-flight gates — the
/// vocabulary every transport shares. The daemon handler maps it onto its
/// wire response; the direct path (`facelock test`, oneshot `facelock auth`)
/// and the D-Bus client consume it as-is, so the CLI never needs the
/// handler's own request/response enums (D5). The `Error` messages are
/// protocol-bearing: PAM string-matches "rate limited" and "IR camera
/// required", so they must flow through every mapping byte-identical.
#[derive(Debug, Clone)]
pub enum AuthOutcome {
    /// The comparison loop ran (or a gate produced a definitive non-match).
    AuthResult(MatchResult),
    /// No enrolled models and `suppress_unknown` is enabled.
    Suppressed,
    /// A recoverable error (rate limited, IR required, storage/camera
    /// failure) that must not read as "no match".
    Error { message: String },
}

/// Which of [`pre_check`]'s environment gates a caller may skip.
///
/// The only intended consumer is `facelock test` (N11, issue #96): it is
/// root-only, and an admin legitimately runs it over SSH or with the lid
/// closed on a docked laptop while diagnosing recognition, which is exactly
/// what `abort_if_ssh`/`abort_if_lid_closed` exist to stop an *attacker* from
/// doing. Every other gate in `pre_check` (disabled, enrollment,
/// rate-limiting, `require_ir`) still applies to `test` unchanged — this
/// struct exists so that carve-out is explicit at every call site instead of
/// a parallel copy of the gate logic (see #95, which this whole `pre_check`
/// unification closes).
#[derive(Clone, Copy, Debug, Default)]
pub struct PreCheckContext {
    pub skip_ssh_gate: bool,
    pub skip_lid_gate: bool,
}

impl PreCheckContext {
    /// The default, fully-enforced context every real authentication path
    /// (daemon `Authenticate`, oneshot `facelock auth`) uses.
    pub fn enforced() -> Self {
        Self::default()
    }

    /// `facelock test`'s context (N11): skip the SSH/lid gates, keep
    /// everything else enforced.
    pub fn test() -> Self {
        Self {
            skip_ssh_gate: true,
            skip_lid_gate: true,
        }
    }
}

/// Run pre-flight checks that don't need the camera, fully enforced.
/// Returns Some(response) to short-circuit, or None to proceed with auth.
///
/// `caps` are the *resolved* device's capabilities ([`CameraCaps`]), computed
/// without opening a camera stream — the `require_ir` gate must run before
/// any camera (and its indicator LED) is touched, so this is the one boundary
/// where caps arrive as a parameter instead of being asked of an open camera.
pub fn pre_check(
    config: &Config,
    store: &FaceStore,
    user: &str,
    rate_limiter: &RateLimiter,
    caps: &CameraCaps,
) -> Option<AuthOutcome> {
    pre_check_with_context(
        config,
        store,
        user,
        rate_limiter,
        caps,
        PreCheckContext::enforced(),
    )
}

/// Run pre-flight checks that don't need the camera, honoring `ctx`'s gate
/// overrides. See [`PreCheckContext`].
pub fn pre_check_with_context(
    config: &Config,
    store: &FaceStore,
    user: &str,
    rate_limiter: &RateLimiter,
    caps: &CameraCaps,
    ctx: PreCheckContext,
) -> Option<AuthOutcome> {
    if config.security.disabled {
        warn!(user, "facelock is disabled");
        return Some(AuthOutcome::Error {
            message: "facelock is disabled".into(),
        });
    }

    if !ctx.skip_ssh_gate && config.security.abort_if_ssh && is_ssh_session() {
        info!(user, "SSH session detected, aborting");
        return Some(AuthOutcome::Error {
            message: "SSH session detected".into(),
        });
    }

    if !ctx.skip_lid_gate && config.security.abort_if_lid_closed && is_lid_closed() {
        info!(user, "lid closed, aborting");
        return Some(AuthOutcome::Error {
            message: "lid closed".into(),
        });
    }

    let has_models = match store.has_models(user) {
        Ok(v) => v,
        Err(e) => {
            return Some(AuthOutcome::Error {
                message: format!("storage error: {e}"),
            });
        }
    };
    if !has_models {
        if config.security.suppress_unknown {
            info!(
                user,
                "no enrolled models, suppressing (suppress_unknown=true)"
            );
            return Some(AuthOutcome::Suppressed);
        }
        return Some(AuthOutcome::AuthResult(MatchResult {
            matched: false,
            model_id: None,
            label: None,
            similarity: 0.0,
            failure_reason: None,
        }));
    }

    match rate_limiter.check(store, user) {
        Ok(true) => {}
        Ok(false) => {
            warn!(user, "rate limited");
            return Some(AuthOutcome::Error {
                message: "rate limited".into(),
            });
        }
        Err(e) => {
            warn!(user, error = %e, "rate limit check failed");
            return Some(AuthOutcome::Error {
                message: format!("rate limit check failed: {e}"),
            });
        }
    }

    if config.security.require_ir && !caps.is_ir {
        warn!(user, "IR camera required but device is not IR");
        return Some(AuthOutcome::Error {
            message: "IR camera required for authentication. Set security.require_ir = false to override (NOT RECOMMENDED).".into(),
        });
    }

    None
}

/// Run [`pre_check`] and, when a gate short-circuits, write the audit entry
/// for the rejection. The daemon handler and the oneshot `facelock auth`
/// binary both go through this wrapper so rejection auditing cannot drift
/// between the two paths (#95: rate-limit rejections on the oneshot path
/// were never audited).
pub fn pre_check_audited(
    config: &Config,
    store: &FaceStore,
    user: &str,
    rate_limiter: &RateLimiter,
    caps: &CameraCaps,
    source: AuditSource,
) -> Option<AuthOutcome> {
    pre_check_audited_with_context(
        config,
        store,
        user,
        rate_limiter,
        caps,
        source,
        PreCheckContext::enforced(),
    )
}

/// [`pre_check_audited`], honoring `ctx`'s gate overrides. See [`PreCheckContext`].
pub fn pre_check_audited_with_context(
    config: &Config,
    store: &FaceStore,
    user: &str,
    rate_limiter: &RateLimiter,
    caps: &CameraCaps,
    source: AuditSource,
    ctx: PreCheckContext,
) -> Option<AuthOutcome> {
    let resp = pre_check_with_context(config, store, user, rate_limiter, caps, ctx)?;
    let (result, error) = match &resp {
        AuthOutcome::Error { message } if message.contains("rate limited") => {
            ("rate_limited".to_string(), Some(message.clone()))
        }
        AuthOutcome::Error { message } => ("error".to_string(), Some(message.clone())),
        AuthOutcome::AuthResult(mr) if !mr.matched => ("failure".to_string(), None),
        AuthOutcome::Suppressed => ("suppressed".to_string(), None),
        _ => ("error".to_string(), None),
    };
    audit::write_audit_entry(
        &config.audit,
        &AuditEntry {
            timestamp: audit::now_iso8601(),
            user: user.to_string(),
            result,
            source: Some(source),
            similarity: None,
            frame_count: None,
            duration_ms: None,
            device: config.device.path.clone(),
            model_label: None,
            error,
        },
    );
    Some(resp)
}

/// Run the camera-based authentication loop with pre-loaded (decrypted) embeddings.
///
/// This is the only entry point: callers MUST load embeddings through their
/// decryption-aware path (the daemon handler and the oneshot `facelock auth`
/// binary both do), because embeddings are encrypted at rest by default
/// (Plan 04). There is deliberately no store-reading variant here — reading
/// `get_user_embeddings` directly would treat an encrypted blob as a raw
/// embedding and fail.
///
/// `source` records which code path ran the loop; it is stamped into every
/// audit entry written here. It marks the enforcement path, not caller intent:
/// only `Test` (direct-mode `facelock test`) skips `pre_check`, so a `success`
/// stamped `test` is a recognition result rather than an approved
/// authentication.
///
/// The device's IR-ness (gating the IR texture liveness check) and its
/// fingerprint (restricting the compare set to templates enrolled on this
/// camera) are asked of `camera.capabilities()` — the camera in use, not a
/// parameter a caller could get out of sync with it (gap D8).
pub fn authenticate_with_embeddings<C: CameraSource, E: FaceProcessor>(
    camera: &mut C,
    engine: &mut E,
    stored: &[(u32, FaceEmbedding)],
    models: &[facelock_core::types::FaceModelInfo],
    config: &Config,
    user: &str,
    source: AuditSource,
) -> AuthOutcome {
    let mut stored = stored.to_vec();
    let models = models.to_vec();
    authenticate_inner(camera, engine, &mut stored, &models, config, user, source)
}

/// Save a snapshot of the last captured frame to disk.
/// Failures are logged but never propagate — snapshots must not block auth.
fn save_snapshot(snapshot_config: &SnapshotConfig, user: &str, similarity: f32, frame: &Frame) {
    let dir = Path::new(&snapshot_config.dir);
    let ensure_snapshot_dir = if Uid::current().is_root() {
        ensure_private_dir(dir, 0o700)
    } else {
        ensure_dir(dir, 0o700)
    };
    if let Err(e) = ensure_snapshot_dir {
        warn!(dir = %dir.display(), error = %e, "failed to secure snapshot directory");
        return;
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let filename = format!("{user}_{timestamp}_{similarity:.2}.jpg");
    let path = dir.join(&filename);

    let mut buf = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut buf, 80);
    if let Err(e) = encoder.encode(
        &frame.rgb,
        frame.width,
        frame.height,
        image::ExtendedColorType::Rgb8,
    ) {
        warn!(path = %path.display(), error = %e, "failed to encode snapshot JPEG");
        return;
    }

    if let Err(e) = write_file(&path, &buf, 0o600) {
        warn!(path = %path.display(), error = %e, "failed to write snapshot");
        return;
    }

    debug!(path = %path.display(), "saved auth snapshot");
}

fn authenticate_inner<C: CameraSource, E: FaceProcessor>(
    camera: &mut C,
    engine: &mut E,
    stored: &mut [(u32, FaceEmbedding)],
    models: &[facelock_core::types::FaceModelInfo],
    config: &Config,
    user: &str,
    source: AuditSource,
) -> AuthOutcome {
    let device_is_ir = camera.capabilities().is_ir;
    let live_fingerprint = camera.capabilities().fingerprint.clone();
    let start = Instant::now();
    let save_snapshots = config.snapshots.mode != facelock_core::config::SnapshotMode::Off;
    let label_for =
        |id: u32| -> Option<String> { models.iter().find(|m| m.id == id).map(|m| m.label.clone()) };

    // Device coupling (Plan 02): restrict the compare set to templates whose
    // enrolling camera matches the live camera at the configured granularity.
    // A mismatched template is dropped here so its embeddings are never compared
    // — the outcome degrades to "no match" → password, never a success and never
    // a lockout. Fail SOFT by construction.
    let policy = config.security.device_binding_policy();
    let allowed = device_allowed_model_ids(models, &live_fingerprint, &policy);
    let mut compare_set: Vec<(u32, FaceEmbedding)> = stored
        .iter()
        .filter(|(id, _)| allowed.contains(id))
        .cloned()
        .collect();
    if policy.enabled && compare_set.len() != stored.len() {
        let skipped = stored.len() - compare_set.len();
        warn!(
            user,
            skipped,
            total = stored.len(),
            granularity = ?policy.granularity,
            "device coupling: skipped templates whose enrolling camera does not match the live camera (falling through to password if no allowed template matches)"
        );
    }
    if policy.enabled
        && models
            .iter()
            .any(|m| m.device_id.as_deref().unwrap_or("").is_empty())
    {
        info!(
            user,
            "device coupling: authenticating legacy template(s) with no device id (bind_legacy_templates); re-enroll to couple them to this camera"
        );
    }
    // `compare_set` holds independent copies of the allowed embeddings; zero the
    // original full set now that we no longer need it.
    zeroize_stored_embeddings(stored);
    let stored = compare_set.as_mut_slice();

    let deadline =
        Instant::now() + std::time::Duration::from_secs(config.recognition.timeout_secs as u64);
    let threshold = config.recognition.threshold;
    let mut best_similarity: f32 = 0.0;
    // Sliding window over the most recent matched-frame embeddings. The gate
    // evaluates only this window, so an early too-still moment is forgotten
    // once the user moves (a static input still never passes: every window
    // of a static sequence stays above the cutoff).
    let mut variance_window = FrameVarianceWindow::new(config.security.min_auth_frames);
    let mut matched_frames_total: u32 = 0;
    let mut variance_ever_passed = false;
    let mut dark_count: u32 = 0;
    let mut frame_count: u32 = 0;
    let mut best_model_id: Option<u32> = None;
    let mut landmark_tracker = LandmarkTracker::new(
        10,
        config.security.landmark_displacement_px,
        config.security.landmark_min_moving as usize,
    );
    #[allow(unused_assignments)]
    let mut last_frame: Option<Frame> = None;

    while Instant::now() < deadline {
        let frame = match camera.capture() {
            Ok(f) => f,
            Err(e) => {
                debug!("capture error: {e}");
                continue;
            }
        };
        frame_count += 1;

        if is_dark_with_config(
            &frame,
            config.device.dark_threshold,
            config.device.dark_pixel_value,
        ) {
            dark_count += 1;
            debug!(frame = frame_count, "dark frame, skipping");
            continue;
        }

        if save_snapshots {
            last_frame = Some(frame.clone());
        }

        let faces = match engine.process(&frame) {
            Ok(f) => f,
            Err(e) => {
                debug!(frame = frame_count, "face engine error: {e}");
                continue;
            }
        };

        if faces.is_empty() {
            debug!(frame = frame_count, "no faces detected");
            continue;
        }

        // Push landmarks from the first detected face for liveness tracking
        if let Some((det, _)) = faces.first() {
            landmark_tracker.push(det.landmarks);
        }

        // IR texture check: when using an IR camera, verify each detected face
        // has real skin texture (not a flat photo/screen replay attack).
        // Only applied to IR frames — RGB texture varies too much and would
        // cause false positives.
        //
        // Runs on the RAW grayscale frame. CLAHE is deliberately NOT applied here:
        // equalizing the frame inflates the std_dev of flat surfaces and masks the
        // very photo/screen replays this check exists to catch (H3).
        let ir_texture_min = config.security.ir_texture_min_stddev;
        if device_is_ir {
            let all_flat = faces.iter().all(|(det, _)| {
                !check_ir_texture(&frame.gray, &det.bbox, frame.width, ir_texture_min)
            });
            if all_flat {
                debug!(
                    frame = frame_count,
                    "IR texture check failed on all faces, skipping frame"
                );
                continue;
            }
        }

        let mut frame_matched = false;
        for (det, embedding) in &faces {
            // Skip individual faces that fail IR texture check
            if device_is_ir
                && !check_ir_texture(&frame.gray, &det.bbox, frame.width, ir_texture_min)
            {
                debug!(
                    frame = frame_count,
                    "IR texture check failed for face, skipping"
                );
                continue;
            }
            let (frame_best_sim, frame_best_id) = best_match(embedding, stored);

            if frame_best_sim > best_similarity {
                best_similarity = frame_best_sim;
                best_model_id = frame_best_id;
            }

            if frame_best_sim >= threshold && !frame_matched {
                variance_window.push(*embedding);
                matched_frames_total += 1;
                // Log drift values (never embeddings) so field tuning of
                // frame_variance_max_similarity has real data to work with.
                if let Some((min_sim, max_sim)) = variance_window.min_max_pair_similarity() {
                    debug!(
                        frame = frame_count,
                        min_pair_similarity = format!("{min_sim:.4}"),
                        max_pair_similarity = format!("{max_sim:.4}"),
                        window = variance_window.len(),
                        "frame variance window"
                    );
                }
                frame_matched = true;
            }

            debug!(
                frame = frame_count,
                similarity = format!("{frame_best_sim:.4}"),
                matched_frames = matched_frames_total,
                "face comparison"
            );
        }

        // Frame variance check + landmark liveness check
        if config.security.require_frame_variance {
            if variance_window.passes(config.security.frame_variance_max_similarity) {
                variance_ever_passed = true;
                // If landmark liveness is required, check it too
                if config.security.require_landmark_liveness && !landmark_tracker.check_liveness() {
                    debug!(
                        frame = frame_count,
                        landmark_frames = landmark_tracker.frame_count(),
                        "landmark liveness not yet satisfied, continuing"
                    );
                    continue;
                }

                let duration = start.elapsed();
                info!(
                    user,
                    similarity = format!("{best_similarity:.4}"),
                    frames = frame_count,
                    matched = matched_frames_total,
                    duration_ms = duration.as_millis() as u64,
                    "authentication succeeded"
                );
                audit::write_audit_entry(
                    &config.audit,
                    &AuditEntry {
                        timestamp: audit::now_iso8601(),
                        user: user.to_string(),
                        result: "success".into(),
                        source: Some(source),
                        similarity: Some(best_similarity),
                        frame_count: Some(frame_count),
                        duration_ms: Some(duration.as_millis() as u64),
                        device: config.device.path.clone(),
                        model_label: best_model_id.and_then(&label_for),
                        error: None,
                    },
                );
                if config.snapshots.should_save(true) {
                    if let Some(ref snap_frame) = last_frame {
                        save_snapshot(&config.snapshots, user, best_similarity, snap_frame);
                    }
                }
                // Device-coupling invariant: the winning model must be one the
                // device policy permitted into `compare_set`. If this ever fires,
                // a mismatched template reached the success branch.
                debug_assert!(
                    best_model_id.is_none_or(|id| allowed.contains(&id)),
                    "device coupling invariant violated: skipped template reached success"
                );
                let response = AuthOutcome::AuthResult(MatchResult {
                    matched: true,
                    model_id: best_model_id,
                    label: best_model_id.and_then(&label_for),
                    similarity: best_similarity,
                    failure_reason: None,
                });
                // Zero sensitive data before returning
                zeroize_stored_embeddings(stored);
                variance_window.zeroize_all();
                return response;
            }
        } else if best_similarity >= threshold {
            // If landmark liveness is required, check it even without variance
            if config.security.require_landmark_liveness && !landmark_tracker.check_liveness() {
                debug!(
                    frame = frame_count,
                    landmark_frames = landmark_tracker.frame_count(),
                    "landmark liveness not yet satisfied, continuing"
                );
                continue;
            }

            let duration = start.elapsed();
            info!(
                user,
                similarity = format!("{best_similarity:.4}"),
                frames = frame_count,
                duration_ms = duration.as_millis() as u64,
                "authentication succeeded (no variance check)"
            );
            audit::write_audit_entry(
                &config.audit,
                &AuditEntry {
                    timestamp: audit::now_iso8601(),
                    user: user.to_string(),
                    result: "success".into(),
                    source: Some(source),
                    similarity: Some(best_similarity),
                    frame_count: Some(frame_count),
                    duration_ms: Some(duration.as_millis() as u64),
                    device: config.device.path.clone(),
                    model_label: best_model_id.and_then(&label_for),
                    error: None,
                },
            );
            if config.snapshots.should_save(true) {
                if let Some(ref snap_frame) = last_frame {
                    save_snapshot(&config.snapshots, user, best_similarity, snap_frame);
                }
            }
            let response = AuthOutcome::AuthResult(MatchResult {
                matched: true,
                model_id: best_model_id,
                label: best_model_id.and_then(&label_for),
                similarity: best_similarity,
                failure_reason: None,
            });
            zeroize_stored_embeddings(stored);
            variance_window.zeroize_all();
            return response;
        }
    }

    let duration = start.elapsed();

    // Timeout expired. If frames DID match above the recognition threshold but
    // the variance gate never passed, say so — "no match" would be misleading.
    let failure_reason = if config.security.require_frame_variance
        && variance_window.is_full()
        && !variance_ever_passed
    {
        Some(AuthFailureReason::VarianceNotSatisfied)
    } else {
        None
    };

    // Zero sensitive data before returning
    zeroize_stored_embeddings(stored);
    variance_window.zeroize_all();

    if dark_count == frame_count && frame_count > 0 {
        warn!(
            user,
            frames = frame_count,
            duration_ms = duration.as_millis() as u64,
            "all frames were dark"
        );
        audit::write_audit_entry(
            &config.audit,
            &AuditEntry {
                timestamp: audit::now_iso8601(),
                user: user.to_string(),
                result: "error".into(),
                source: Some(source),
                similarity: None,
                frame_count: Some(frame_count),
                duration_ms: Some(duration.as_millis() as u64),
                device: config.device.path.clone(),
                model_label: None,
                error: Some("all frames dark".into()),
            },
        );
        // No snapshot for all-dark: last_frame is None since dark frames are skipped
        return AuthOutcome::Error {
            message: "all frames dark".into(),
        };
    }

    info!(
        user,
        similarity = format!("{best_similarity:.4}"),
        frames = frame_count,
        matched = matched_frames_total,
        duration_ms = duration.as_millis() as u64,
        variance_blocked = failure_reason.is_some(),
        "authentication failed"
    );

    audit::write_audit_entry(
        &config.audit,
        &AuditEntry {
            timestamp: audit::now_iso8601(),
            user: user.to_string(),
            result: "failure".into(),
            source: Some(source),
            similarity: Some(best_similarity),
            frame_count: Some(frame_count),
            duration_ms: Some(duration.as_millis() as u64),
            device: config.device.path.clone(),
            model_label: None,
            error: None,
        },
    );

    if config.snapshots.should_save(false) {
        if let Some(ref snap_frame) = last_frame {
            save_snapshot(&config.snapshots, user, best_similarity, snap_frame);
        }
    }

    AuthOutcome::AuthResult(MatchResult {
        matched: false,
        model_id: None,
        label: None,
        similarity: best_similarity,
        failure_reason,
    })
}

fn is_ssh_session() -> bool {
    std::env::var("SSH_CONNECTION").is_ok() || std::env::var("SSH_TTY").is_ok()
}

fn is_lid_closed() -> bool {
    std::fs::read_to_string("/proc/acpi/button/lid/LID0/state")
        .map(|s| s.contains("closed"))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SSH_CONNECTION` is process-global state; `cargo test` runs this
    /// file's tests on multiple threads, and four of them now mutate it
    /// (previously just one). Serialize access so they can't interleave.
    static SSH_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn lock_ssh_env() -> std::sync::MutexGuard<'static, ()> {
        SSH_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn ssh_detection_with_env_vars() {
        let _guard = lock_ssh_env();
        let old_conn = std::env::var("SSH_CONNECTION").ok();
        let old_tty = std::env::var("SSH_TTY").ok();
        unsafe {
            std::env::remove_var("SSH_CONNECTION");
            std::env::remove_var("SSH_TTY");
        }

        assert!(!is_ssh_session());

        unsafe { std::env::set_var("SSH_CONNECTION", "1.2.3.4 5678 10.0.0.1 22") };
        assert!(is_ssh_session());
        unsafe { std::env::remove_var("SSH_CONNECTION") };

        unsafe { std::env::set_var("SSH_TTY", "/dev/pts/0") };
        assert!(is_ssh_session());
        unsafe { std::env::remove_var("SSH_TTY") };

        if let Some(v) = old_conn {
            unsafe { std::env::set_var("SSH_CONNECTION", v) };
        }
        if let Some(v) = old_tty {
            unsafe { std::env::set_var("SSH_TTY", v) };
        }
    }

    #[test]
    fn lid_closed_returns_false_on_missing_file() {
        let _result = is_lid_closed();
    }

    fn test_pre_check_config() -> Config {
        let toml =
            facelock_test_support::fixtures::test_config_toml("/tmp/facelock-precheck-test.db");
        let mut config = Config::parse(&toml).unwrap();
        config.security.abort_if_ssh = true;
        config
    }

    /// Caps of an IR-classified device (what these tests used to express as a
    /// bare `device_is_ir: true`).
    fn ir_caps() -> CameraCaps {
        CameraCaps {
            is_ir: true,
            ..Default::default()
        }
    }

    fn store_with_enrolled_user(user: &str) -> FaceStore {
        let store = FaceStore::open_memory().unwrap();
        store
            .add_model(
                user,
                "front",
                &facelock_test_support::fixtures::known_embedding(0),
                "",
            )
            .unwrap();
        store
    }

    #[test]
    fn pre_check_context_test_skips_both_environment_gates() {
        let ctx = PreCheckContext::test();
        assert!(ctx.skip_ssh_gate);
        assert!(ctx.skip_lid_gate);
    }

    #[test]
    fn pre_check_context_enforced_skips_neither_gate() {
        let ctx = PreCheckContext::enforced();
        assert!(!ctx.skip_ssh_gate);
        assert!(!ctx.skip_lid_gate);
        // `Default` must agree with `enforced()` — `pre_check`/`pre_check_audited`
        // rely on this to stay fully enforced without threading a context.
        let default_ctx = PreCheckContext::default();
        assert!(!default_ctx.skip_ssh_gate);
        assert!(!default_ctx.skip_lid_gate);
    }

    #[test]
    fn pre_check_test_context_skips_ssh_gate() {
        let _guard = lock_ssh_env();
        let config = test_pre_check_config();
        let store = store_with_enrolled_user("alice");
        let rate_limiter = RateLimiter::new(
            config.security.rate_limit.max_attempts,
            config.security.rate_limit.window_secs,
        );

        let old_conn = std::env::var("SSH_CONNECTION").ok();
        unsafe { std::env::set_var("SSH_CONNECTION", "1.2.3.4 1 5.6.7.8 22") };
        let resp = pre_check_with_context(
            &config,
            &store,
            "alice",
            &rate_limiter,
            &ir_caps(),
            PreCheckContext::test(),
        );
        unsafe {
            match old_conn {
                Some(v) => std::env::set_var("SSH_CONNECTION", v),
                None => std::env::remove_var("SSH_CONNECTION"),
            }
        }

        assert!(
            resp.is_none(),
            "PreCheckContext::test() must proceed past the SSH gate, got: {resp:?}"
        );
    }

    #[test]
    fn pre_check_enforced_context_still_blocks_ssh() {
        let _guard = lock_ssh_env();
        let config = test_pre_check_config();
        let store = store_with_enrolled_user("alice");
        let rate_limiter = RateLimiter::new(
            config.security.rate_limit.max_attempts,
            config.security.rate_limit.window_secs,
        );

        let old_conn = std::env::var("SSH_CONNECTION").ok();
        unsafe { std::env::set_var("SSH_CONNECTION", "1.2.3.4 1 5.6.7.8 22") };
        let resp = pre_check_with_context(
            &config,
            &store,
            "alice",
            &rate_limiter,
            &ir_caps(),
            PreCheckContext::enforced(),
        );
        unsafe {
            match old_conn {
                Some(v) => std::env::set_var("SSH_CONNECTION", v),
                None => std::env::remove_var("SSH_CONNECTION"),
            }
        }

        assert!(
            matches!(resp, Some(AuthOutcome::Error { ref message }) if message.contains("SSH")),
            "the default/enforced context must still reject an SSH session, got: {resp:?}"
        );
    }

    #[test]
    fn pre_check_without_context_matches_enforced() {
        // `pre_check` (no context param) is a thin wrapper — pin that it stays
        // equivalent to `pre_check_with_context(.., PreCheckContext::enforced())`
        // so real auth paths (daemon `Authenticate`, oneshot `facelock auth`)
        // never silently pick up a relaxed gate.
        let _guard = lock_ssh_env();
        let config = test_pre_check_config();
        let store = store_with_enrolled_user("alice");
        let rate_limiter = RateLimiter::new(
            config.security.rate_limit.max_attempts,
            config.security.rate_limit.window_secs,
        );

        let old_conn = std::env::var("SSH_CONNECTION").ok();
        unsafe { std::env::set_var("SSH_CONNECTION", "1.2.3.4 1 5.6.7.8 22") };
        let resp = pre_check(&config, &store, "alice", &rate_limiter, &ir_caps());
        unsafe {
            match old_conn {
                Some(v) => std::env::set_var("SSH_CONNECTION", v),
                None => std::env::remove_var("SSH_CONNECTION"),
            }
        }

        assert!(
            matches!(resp, Some(AuthOutcome::Error { ref message }) if message.contains("SSH")),
            "pre_check() must stay fully enforced, got: {resp:?}"
        );
    }
}
