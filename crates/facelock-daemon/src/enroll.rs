use std::time::{Duration, Instant};

use facelock_camera::capture::is_dark_with_config;
use facelock_core::config::Config;
use facelock_core::ipc::DaemonResponse;
use facelock_core::traits::{CameraSource, FaceProcessor};
use facelock_core::types::FaceEmbedding;
use facelock_store::FaceStore;
use facelock_tpm::SoftwareSealer;
use tracing::{debug, info, warn};

use crate::quality;

const MIN_CAPTURES: usize = 3;
const MAX_CAPTURES: usize = 10;
const INTER_FRAME_DELAY: Duration = Duration::from_millis(200);

/// Per-frame rejection tally for the enrollment loop, so a failed enrollment
/// can explain *why* frames were rejected instead of a bare capture count
/// (issue #89: an all-dark session reported only "captured 0 frames").
#[derive(Default)]
struct RejectionStats {
    dark: u32,
    no_face: u32,
    multiple_faces: u32,
    low_quality: u32,
    capture_errors: u32,
    last_capture_error: Option<String>,
}

impl RejectionStats {
    fn total(&self) -> u32 {
        self.dark + self.no_face + self.multiple_faces + self.low_quality + self.capture_errors
    }

    /// Human-readable breakdown appended to the insufficient-captures error,
    /// with a remediation hint when one cause dominates. Empty when nothing
    /// was rejected (e.g. the camera produced no frames at all).
    fn summary(&self) -> String {
        if self.total() == 0 {
            return String::new();
        }
        let mut parts = Vec::new();
        if self.dark > 0 {
            parts.push(format!("{} too dark", self.dark));
        }
        if self.no_face > 0 {
            parts.push(format!("{} no face", self.no_face));
        }
        if self.multiple_faces > 0 {
            parts.push(format!("{} multiple faces", self.multiple_faces));
        }
        if self.low_quality > 0 {
            parts.push(format!("{} low quality", self.low_quality));
        }
        if self.capture_errors > 0 {
            match &self.last_capture_error {
                Some(e) => parts.push(format!("{} capture errors (last: {e})", self.capture_errors)),
                None => parts.push(format!("{} capture errors", self.capture_errors)),
            }
        }
        let hint = self.hint().map(|h| format!(". {h}")).unwrap_or_default();
        format!(" — rejected frames: {}{hint}", parts.join(", "))
    }

    /// Remediation hint when a single cause accounts for the majority of
    /// rejections.
    fn hint(&self) -> Option<&'static str> {
        let majority = self.total() / 2 + 1;
        if self.dark >= majority {
            Some("Hint: the scene is too dark — improve lighting and retry")
        } else if self.capture_errors >= majority {
            Some("Hint: the camera is not delivering usable frames — check device.path and the camera format (see docs/troubleshooting.md)")
        } else if self.no_face >= majority {
            Some("Hint: no face was detected — face the camera directly and check `facelock preview`")
        } else {
            None
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn enroll<C: CameraSource, E: FaceProcessor>(
    camera: &mut C,
    engine: &mut E,
    store: &FaceStore,
    config: &Config,
    user: &str,
    label: &str,
    sealer: Option<&SoftwareSealer>,
    device_id: Option<&str>,
) -> DaemonResponse {
    // Clear any previous model with the same label (re-enrollment)
    match store.remove_model_by_label(user, label) {
        Ok(true) => info!(user, label, "removed existing model for re-enrollment"),
        Ok(false) => {}
        Err(e) => {
            warn!(user, label, "failed to remove existing model: {e}");
            return DaemonResponse::Error {
                message: format!("storage error clearing old model: {e}"),
            };
        }
    }

    // Opt-in hard device binding (Plan 04): when enabled, fold this camera's
    // device id into the AES-GCM AAD so the template can only be decrypted under
    // the same camera. `None` when disabled or when no device id is available.
    let device_aad = config.security.device_aad(device_id);

    // Shared deadline formula (see Config::enroll_timeout_secs): the CLI's
    // D-Bus Enroll timeout is derived from the same value plus margin.
    let enroll_secs = config.enroll_timeout_secs();
    let deadline = Instant::now() + Duration::from_secs(enroll_secs);
    debug!(timeout_secs = enroll_secs, "starting enrollment");
    let mut stored_count: u32 = 0;
    let mut model_id: Option<u32> = None;
    let mut last_capture = Instant::now() - INTER_FRAME_DELAY; // allow immediate first capture
    let mut enrolled_embeddings: Vec<FaceEmbedding> = Vec::with_capacity(MAX_CAPTURES);
    let mut rejections = RejectionStats::default();

    while Instant::now() < deadline && (stored_count as usize) < MAX_CAPTURES {
        // Delay between captures for varied angles
        let since_last = Instant::now().duration_since(last_capture);
        if since_last < INTER_FRAME_DELAY {
            std::thread::sleep(INTER_FRAME_DELAY - since_last);
        }

        let capture_start = Instant::now();
        let frame = match camera.capture() {
            Ok(f) => f,
            Err(e) => {
                debug!("capture error during enroll: {e}");
                rejections.capture_errors += 1;
                rejections.last_capture_error = Some(e.to_string());
                continue;
            }
        };
        let capture_ms = capture_start.elapsed().as_millis();

        if is_dark_with_config(
            &frame,
            config.device.dark_threshold,
            config.device.dark_pixel_value,
        ) {
            warn!(capture_ms, "skipping dark frame during enroll");
            rejections.dark += 1;
            continue;
        }

        let detect_start = Instant::now();
        let faces = match engine.process(&frame) {
            Ok(f) => f,
            Err(e) => {
                warn!("face engine error during enroll: {e}");
                rejections.capture_errors += 1;
                rejections.last_capture_error = Some(e.to_string());
                continue;
            }
        };
        let detect_ms = detect_start.elapsed().as_millis();

        // Require exactly 1 face
        if faces.is_empty() {
            info!(capture_ms, detect_ms, "no face detected during enroll");
            rejections.no_face += 1;
            continue;
        }
        if faces.len() > 1 {
            warn!(
                count = faces.len(),
                "multiple faces detected during enroll, skipping frame"
            );
            rejections.multiple_faces += 1;
            continue;
        }

        let (det, embedding) = &faces[0];

        // Quality gate: skip low-quality frames
        let frame_quality = quality::score_frame(det, &frame.gray, frame.width, frame.height);
        if !quality::meets_quality_threshold(&frame_quality) {
            if let Some(hint) = quality::quality_hint(&frame_quality) {
                debug!(
                    overall = format!("{:.2}", frame_quality.overall),
                    hint, "skipping low-quality enrollment frame"
                );
            } else {
                debug!(
                    overall = format!("{:.2}", frame_quality.overall),
                    "skipping low-quality enrollment frame"
                );
            }
            rejections.low_quality += 1;
            continue;
        }

        // First face: create the model. Subsequent faces: add embeddings.
        // When a sealer is provided, encrypt each embedding before storage.
        let store_result = if let Some(sealer) = sealer {
            match sealer.seal_embedding_with_aad(embedding, device_aad.as_deref()) {
                Ok(encrypted) => match model_id {
                    None => store
                        .add_model_raw_with_device(
                            user,
                            label,
                            &encrypted,
                            true,
                            &config.recognition.embedder_model,
                            device_id,
                        )
                        .map(Some),
                    Some(id) => store.add_embedding_raw(id, &encrypted, true).map(|()| None),
                },
                Err(e) => {
                    warn!("failed to encrypt embedding: {e}");
                    return DaemonResponse::Error {
                        message: format!("encryption error: {e}"),
                    };
                }
            }
        } else {
            match model_id {
                None => store
                    .add_model_with_device(
                        user,
                        label,
                        embedding,
                        &config.recognition.embedder_model,
                        device_id,
                    )
                    .map(Some),
                Some(id) => store.add_embedding(id, embedding).map(|()| None),
            }
        };

        match store_result {
            Ok(Some(id)) => {
                model_id = Some(id);
                stored_count += 1;
                enrolled_embeddings.push(*embedding);
                info!(
                    capture_ms,
                    detect_ms,
                    model_id = id,
                    encrypted = sealer.is_some(),
                    "created model with first embedding"
                );
            }
            Ok(None) => {
                stored_count += 1;
                enrolled_embeddings.push(*embedding);
                debug!(
                    capture_ms,
                    detect_ms,
                    count = stored_count,
                    encrypted = sealer.is_some(),
                    "stored embedding"
                );
            }
            Err(e) => {
                if model_id.is_none() {
                    warn!("failed to create model: {e}");
                    return DaemonResponse::Error {
                        message: format!("storage error: {e}"),
                    };
                } else {
                    warn!("failed to store embedding: {e}");
                }
            }
        }

        last_capture = Instant::now();
    }

    // Check angle diversity: reject if all embeddings are too similar
    if stored_count >= MIN_CAPTURES as u32 && !quality::check_angle_diversity(&enrolled_embeddings)
    {
        warn!(
            user,
            label,
            captured = stored_count,
            "insufficient angle diversity during enrollment"
        );
        return DaemonResponse::Error {
            message: "insufficient angle diversity: please move your head to different angles during enrollment".into(),
        };
    }

    if stored_count < MIN_CAPTURES as u32 {
        warn!(
            user,
            label,
            captured = stored_count,
            required = MIN_CAPTURES,
            dark = rejections.dark,
            no_face = rejections.no_face,
            multiple_faces = rejections.multiple_faces,
            low_quality = rejections.low_quality,
            capture_errors = rejections.capture_errors,
            "insufficient face captures during enrollment"
        );
        return DaemonResponse::Error {
            message: format!(
                "only captured {stored_count} frames, need at least {MIN_CAPTURES}{}",
                rejections.summary()
            ),
        };
    }

    info!(
        user,
        label,
        model_id = model_id.unwrap_or(0),
        embedding_count = stored_count,
        "enrollment complete"
    );

    DaemonResponse::Enrolled {
        model_id: model_id.unwrap_or(0),
        embedding_count: stored_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_empty_when_no_rejections() {
        let stats = RejectionStats::default();
        assert_eq!(stats.summary(), "");
    }

    #[test]
    fn summary_all_dark_includes_lighting_hint() {
        // Issue #89: an all-dark enrollment session must say so, not just
        // "captured 0 frames".
        let stats = RejectionStats {
            dark: 42,
            ..Default::default()
        };
        let s = stats.summary();
        assert!(s.contains("42 too dark"), "got: {s}");
        assert!(s.contains("improve lighting"), "got: {s}");
    }

    #[test]
    fn summary_capture_errors_include_last_error() {
        let stats = RejectionStats {
            capture_errors: 5,
            last_capture_error: Some("unsupported format: NV12".into()),
            ..Default::default()
        };
        let s = stats.summary();
        assert!(
            s.contains("5 capture errors (last: unsupported format: NV12)"),
            "got: {s}"
        );
        assert!(s.contains("check device.path"), "got: {s}");
    }

    #[test]
    fn summary_no_face_majority_hints_preview() {
        let stats = RejectionStats {
            no_face: 10,
            dark: 2,
            ..Default::default()
        };
        let s = stats.summary();
        assert!(s.contains("10 no face"), "got: {s}");
        assert!(s.contains("2 too dark"), "got: {s}");
        assert!(s.contains("facelock preview"), "got: {s}");
    }

    #[test]
    fn summary_mixed_causes_has_no_hint() {
        // No single majority cause -> breakdown only, no misleading hint.
        let stats = RejectionStats {
            dark: 3,
            no_face: 3,
            low_quality: 3,
            ..Default::default()
        };
        let s = stats.summary();
        assert!(s.contains("rejected frames:"), "got: {s}");
        assert!(!s.contains("Hint:"), "got: {s}");
    }

    #[test]
    fn summary_lists_multiple_faces_and_low_quality() {
        let stats = RejectionStats {
            multiple_faces: 2,
            low_quality: 4,
            ..Default::default()
        };
        let s = stats.summary();
        assert!(s.contains("2 multiple faces"), "got: {s}");
        assert!(s.contains("4 low quality"), "got: {s}");
    }
}
