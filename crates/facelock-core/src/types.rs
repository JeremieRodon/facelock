use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// 512-dimensional face embedding (ArcFace output)
pub type FaceEmbedding = [f32; 512];

/// A bounding box in image coordinates
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BoundingBox {
    pub x: f32,
    pub y: f32,
    pub width: f32,
    pub height: f32,
}

/// A 2D point
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Point2D {
    pub x: f32,
    pub y: f32,
}

/// A detected face with bounding box, landmarks, and confidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    pub bbox: BoundingBox,
    pub confidence: f32,
    /// 5-point landmarks: left eye, right eye, nose, left mouth, right mouth
    pub landmarks: [Point2D; 5],
}

/// A camera frame
#[derive(Debug, Clone)]
pub struct Frame {
    /// RGB pixel data (width * height * 3)
    pub rgb: Vec<u8>,
    /// Grayscale pixel data (width * height)
    pub gray: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

impl Drop for Frame {
    fn drop(&mut self) {
        self.rgb.zeroize();
        self.gray.zeroize();
    }
}

/// Zero a face embedding in place (overwrite with 0.0).
/// Use this at security boundaries after embeddings are no longer needed.
pub fn zeroize_embedding(embedding: &mut FaceEmbedding) {
    embedding.zeroize();
}

/// Zero a vector of embedding tuples (model_id, embedding).
pub fn zeroize_stored_embeddings(stored: &mut [(u32, FaceEmbedding)]) {
    for (_, emb) in stored.iter_mut() {
        emb.zeroize();
    }
}

/// A stored face model (metadata only, without embedding)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FaceModelInfo {
    pub id: u32,
    pub user: String,
    pub label: String,
    /// Unix timestamp
    pub created_at: u64,
    /// Which ONNX embedder model generated this enrollment's embeddings.
    /// Empty string means legacy/unknown (pre-migration).
    pub embedder_model: String,
    /// Canonical device fingerprint (`"vid:pid:serial"`) of the camera that
    /// enrolled this model, or `None` for legacy rows (schema < V6) and models
    /// enrolled on a camera with no readable USB identity.
    ///
    /// See [`DeviceFingerprint`] for the honest threat framing: this is
    /// model-granularity at best and forgeable by a programmable USB device —
    /// advisory defense-in-depth, NOT an attested root of trust.
    #[serde(default)]
    pub device_id: Option<String>,
}

/// Stable-ish hardware identity of a capture device.
///
/// Assembled from sysfs USB attributes (`idVendor`/`idProduct`/`serial`) plus
/// the `/dev/v4l/by-path` symlink target. **This is not attestation.**
///
/// - `vid:pid` is **model granularity** — every unit of the same camera model
///   shares it.
/// - `serial` is unit-unique *when present*, but is frequently absent or
///   duplicated across units by vendors.
/// - A **programmable USB device can forge any of these fields.** Consumer UVC
///   cameras have no signed-frame attestation.
///
/// So device coupling built on this raises the bar against the realistic
/// attacker (who plugs in a commodity or different-model camera) but is
/// **advisory defense-in-depth**, not a cryptographic identity.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceFingerprint {
    /// USB vendor ID (lowercase hex, e.g. `"046d"`).
    pub vid: Option<String>,
    /// USB product ID (lowercase hex, e.g. `"085e"`).
    pub pid: Option<String>,
    /// USB `iSerial` string, when the device exposes one.
    pub serial: Option<String>,
    /// Stable `/dev/v4l/by-path/...` symlink target (bus topology). Advisory
    /// only; not part of the canonical id, but recorded for diagnostics.
    pub by_path: Option<String>,
}

impl DeviceFingerprint {
    /// Canonical string form `"vid:pid:serial"` (each missing field rendered
    /// empty). This is what is persisted in `face_models.device_id`.
    pub fn canonical(&self) -> String {
        format!(
            "{}:{}:{}",
            self.vid.as_deref().unwrap_or(""),
            self.pid.as_deref().unwrap_or(""),
            self.serial.as_deref().unwrap_or(""),
        )
    }

    /// Canonical id to persist at enrollment, or `None` when the camera exposes
    /// no usable identity (no vid **and** no pid). A `None` here is stored as a
    /// NULL `device_id` and governed by the legacy-template policy, so coupling
    /// never turns an unidentifiable camera into a hard lockout.
    pub fn canonical_for_storage(&self) -> Option<String> {
        if self.is_unknown() {
            None
        } else {
            Some(self.canonical())
        }
    }

    /// True when neither vendor nor product id could be read — the device has no
    /// identity we can enforce against.
    pub fn is_unknown(&self) -> bool {
        self.vid.is_none() && self.pid.is_none()
    }

    /// True when a unit-unique serial is available.
    pub fn has_serial(&self) -> bool {
        self.serial.as_deref().is_some_and(|s| !s.is_empty())
    }
}

/// Granularity at which a live camera must match a template's enrolling camera.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DeviceMatchGranularity {
    /// Compare `vid:pid` only. Blocks a cross-model camera swap; identical
    /// same-model cameras are accepted. The invisible-to-single-camera default.
    #[default]
    Model,
    /// Require `vid:pid:serial` to match. Blocks even a same-model swap, but only
    /// works on cameras that expose a stable serial.
    Unit,
}

/// Resolved device-binding policy for the auth compare path (derived from config).
#[derive(Debug, Clone, Copy)]
pub struct DeviceBindingPolicy {
    /// Master switch (`security.bind_templates_to_device`).
    pub enabled: bool,
    /// Match granularity (`security.device_match_granularity`).
    pub granularity: DeviceMatchGranularity,
    /// Whether legacy NULL-`device_id` templates are allowed to authenticate
    /// (`security.bind_legacy_templates`). Default allow-with-warn so upgrades
    /// don't break.
    pub allow_legacy: bool,
}

/// Compare a stored canonical device id against the live camera fingerprint at
/// the given granularity.
///
/// A match requires the compared fields to be present and equal on **both**
/// sides: an unknown live camera (no vid/pid) never matches a non-empty stored
/// id, and `Unit` never matches when either side lacks a serial. This is the
/// property that makes a mismatch fall through to password instead of ever
/// reaching a success.
pub fn device_ids_match(
    stored_canonical: &str,
    live: &DeviceFingerprint,
    granularity: DeviceMatchGranularity,
) -> bool {
    // Parse the stored "vid:pid:serial" form. splitn keeps a serial that itself
    // contains ':' intact in the third field.
    let mut parts = stored_canonical.splitn(3, ':');
    let s_vid = parts.next().unwrap_or("");
    let s_pid = parts.next().unwrap_or("");
    let s_serial = parts.next().unwrap_or("");

    let l_vid = live.vid.as_deref().unwrap_or("");
    let l_pid = live.pid.as_deref().unwrap_or("");
    let l_serial = live.serial.as_deref().unwrap_or("");

    // Model-level identity must always be present and equal.
    let model_ok = !s_vid.is_empty()
        && !s_pid.is_empty()
        && s_vid.eq_ignore_ascii_case(l_vid)
        && s_pid.eq_ignore_ascii_case(l_pid);
    if !model_ok {
        return false;
    }

    match granularity {
        DeviceMatchGranularity::Model => true,
        DeviceMatchGranularity::Unit => {
            // Unit match additionally needs a serial present and equal on both sides.
            !s_serial.is_empty() && !l_serial.is_empty() && s_serial == l_serial
        }
    }
}

/// Decide whether a candidate template may be compared against the live camera.
///
/// Returns `true` when the template's embeddings are allowed into the compare
/// set, `false` when the model must be **skipped** (so the outcome degrades to
/// "no match" → password). Never panics; the caller treats `false` as skip, not
/// as an error or a lockout.
pub fn device_binding_allows(
    device_id: Option<&str>,
    live: &DeviceFingerprint,
    policy: &DeviceBindingPolicy,
) -> bool {
    if !policy.enabled {
        return true;
    }
    match device_id {
        // Legacy rows (pre-V6) and models enrolled on an unidentifiable camera
        // carry a NULL / empty id — governed by the legacy policy.
        None | Some("") => policy.allow_legacy,
        Some(stored) => device_ids_match(stored, live, policy.granularity),
    }
}

/// Model ids whose enrolling camera permits comparison against the live camera.
///
/// The auth compare loop must restrict `best_match` to embeddings whose model id
/// is in this set. Any template failing the device binding is omitted, so its
/// embeddings are never compared and a device mismatch can only ever produce
/// "no match" → password, never a success.
pub fn device_allowed_model_ids(
    models: &[FaceModelInfo],
    live: &DeviceFingerprint,
    policy: &DeviceBindingPolicy,
) -> std::collections::HashSet<u32> {
    models
        .iter()
        .filter(|m| device_binding_allows(m.device_id.as_deref(), live, policy))
        .map(|m| m.id)
        .collect()
}

/// AAD seam for Plan 04 (opt-in *hard* device binding).
///
/// Plan 02 binds templates advisorily (skip-on-mismatch in the compare loop).
/// Plan 04 may additionally fold the enrolling camera's identity into the
/// AES-GCM Additional Authenticated Data so a sealed embedding cannot even be
/// decrypted under a different device id. This helper defines the canonical AAD
/// bytes for that future wiring; it is intentionally not yet consumed by the
/// seal/unseal path (doing so now would fail *hard* on unstable ids, which
/// Plan 02 must not).
pub fn device_binding_aad(device_id: Option<&str>) -> Option<Vec<u8>> {
    device_id
        .filter(|s| !s.is_empty())
        .map(|s| format!("facelock-device:{s}").into_bytes())
}

/// Result of a face match attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub matched: bool,
    pub model_id: Option<u32>,
    pub label: Option<String>,
    pub similarity: f32,
}

/// Cosine similarity between two L2-normalized embeddings (= dot product)
pub fn cosine_similarity(a: &FaceEmbedding, b: &FaceEmbedding) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Default maximum consecutive-frame cosine similarity for the passive
/// frame-variance check. Consecutive matched frames must drift by at least
/// `1 - this` (≈0.03) to be accepted, aligning with the documented 0.02–0.10
/// live-face drift range. Configurable via `security.frame_variance_max_similarity`.
///
/// NOTE: frame-variance is a *passive* anti-photo heuristic only. It raises the
/// bar for a *static* image but does NOT defeat a video replay (which contains
/// real inter-frame motion). IR enforcement remains the load-bearing defense.
pub const DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY: f32 = 0.97;

/// Check that matched embeddings show sufficient variance (anti-photo-attack).
/// Compares all consecutive pairs — every pair must differ enough to rule out
/// a static image. Real faces produce micro-movements between frames.
///
/// `max_similarity` is the rejection cutoff: any consecutive pair with cosine
/// similarity strictly greater than `max_similarity` fails the check (too static).
pub fn check_frame_variance(embeddings: &[FaceEmbedding], max_similarity: f32) -> bool {
    if embeddings.len() < 2 {
        return false;
    }
    // Every consecutive pair must show movement (similarity at or below the cutoff).
    // A static photo produces near-identical consecutive embeddings.
    for window in embeddings.windows(2) {
        let sim = cosine_similarity(&window[0], &window[1]);
        if sim > max_similarity {
            return false;
        }
    }
    true
}

/// Convert f32 bits to ordered u32 for constant-time comparison.
/// Positive floats: flip sign bit. Negative floats: flip all bits.
/// Done branchlessly using the sign bit as a mask so that u32 ordering
/// matches f32 ordering across the full range (including negatives).
fn float_bits_to_ordered(bits: u32) -> u32 {
    let mask = ((bits as i32) >> 31) as u32; // all 1s if negative, all 0s if positive
    bits ^ (mask | 0x8000_0000) // flip sign bit always; if negative, flip everything else too
}

/// Find the best cosine similarity between an embedding and a set of stored embeddings.
/// Returns (best_similarity, matching_model_id).
///
/// Always iterates ALL stored embeddings to prevent timing side-channels
/// from revealing which model matched. Uses constant-time conditional
/// selection via the `subtle` crate.
pub fn best_match(
    embedding: &FaceEmbedding,
    stored: &[(u32, FaceEmbedding)],
) -> (f32, Option<u32>) {
    use subtle::{ConditionallySelectable, ConstantTimeGreater};

    // Initialize to -1.0 (minimum possible cosine similarity) so any real
    // similarity will be >= this. We track both the ordered representation
    // (for constant-time comparison) and the raw bits (for the return value).
    let init_bits = (-1.0f32).to_bits();
    let mut best_ord: u32 = float_bits_to_ordered(init_bits);
    let mut best_sim_raw: u32 = init_bits;
    let mut best_id: u32 = u32::MAX; // sentinel for "no match"

    for (id, stored_emb) in stored {
        let sim = cosine_similarity(embedding, stored_emb);
        let sim_bits = sim.to_bits();
        let sim_ord = float_bits_to_ordered(sim_bits);

        // Constant-time: is sim > best_sim?
        let is_greater = sim_ord.ct_gt(&best_ord);

        best_ord = u32::conditional_select(&best_ord, &sim_ord, is_greater);
        best_sim_raw = u32::conditional_select(&best_sim_raw, &sim_bits, is_greater);
        best_id = u32::conditional_select(&best_id, id, is_greater);
    }

    if stored.is_empty() {
        return (0.0, None);
    }

    let best_sim = f32::from_bits(best_sim_raw);
    let matched_id = if best_id == u32::MAX {
        None
    } else {
        Some(best_id)
    };
    (best_sim, matched_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cosine_similarity_identical() {
        let mut a = [0.0f32; 512];
        // Create a unit vector
        let val = 1.0 / (512.0f32).sqrt();
        for x in &mut a {
            *x = val;
        }
        let result = cosine_similarity(&a, &a);
        assert!(
            (result - 1.0).abs() < 1e-5,
            "identical vectors should have similarity ~1.0, got {result}"
        );
    }

    #[test]
    fn cosine_similarity_orthogonal() {
        let mut a = [0.0f32; 512];
        let mut b = [0.0f32; 512];
        // First half nonzero in a, second half nonzero in b
        for i in 0..256 {
            a[i] = 1.0 / (256.0f32).sqrt();
        }
        for i in 256..512 {
            b[i] = 1.0 / (256.0f32).sqrt();
        }
        let result = cosine_similarity(&a, &b);
        assert!(
            result.abs() < 1e-5,
            "orthogonal vectors should have similarity ~0.0, got {result}"
        );
    }

    #[test]
    fn best_match_finds_correct_match_regardless_of_position() {
        // Create a target embedding
        let mut target: FaceEmbedding = [0.0; 512];
        target[0] = 1.0; // unit vector along dim 0

        // Create stored embeddings with the best match at different positions
        let mut stored: Vec<(u32, FaceEmbedding)> = Vec::new();
        for i in 0..5 {
            let mut emb: FaceEmbedding = [0.0; 512];
            emb[i + 1] = 1.0; // orthogonal to target (similarity ~0)
            stored.push((i as u32, emb));
        }

        // Put exact match first
        stored[0].1 = target;
        let (sim1, id1) = best_match(&target, &stored);
        assert!(sim1 > 0.99, "should find match when first");
        assert_eq!(id1, Some(0));

        // Put exact match last
        stored[0].1 = [0.0; 512];
        stored[0].1[1] = 1.0;
        stored[4].1 = target;
        let (sim2, id2) = best_match(&target, &stored);
        assert!(sim2 > 0.99, "should find match when last");
        assert_eq!(id2, Some(4));
    }

    #[test]
    fn best_match_empty_stored_returns_no_match() {
        let target: FaceEmbedding = [0.1; 512];
        let stored: Vec<(u32, FaceEmbedding)> = vec![];
        let (sim, id) = best_match(&target, &stored);
        assert_eq!(sim, 0.0);
        assert_eq!(id, None);
    }

    #[test]
    fn best_match_prefers_positive_over_negative_similarity() {
        // Regression: negative floats have sign bit set, making their u32 bit
        // representation larger than positive floats. Without sign-aware
        // ordering, ct_gt would incorrectly prefer negative similarities.
        let val = 1.0 / (512.0f32).sqrt();

        // Target: uniform unit vector
        let mut target: FaceEmbedding = [0.0; 512];
        for x in target.iter_mut() {
            *x = val;
        }

        // Stored[0]: opposite of target => similarity ~ -1.0
        let mut opposite: FaceEmbedding = [0.0; 512];
        for x in opposite.iter_mut() {
            *x = -val;
        }

        // Stored[1]: same as target => similarity ~ +1.0
        let same = target;

        let stored = vec![(10, opposite), (20, same)];
        let (sim, id) = best_match(&target, &stored);
        assert!(
            sim > 0.99,
            "should pick positive similarity (~1.0), got {sim}"
        );
        assert_eq!(
            id,
            Some(20),
            "should pick model 20 (positive match), not 10 (negative)"
        );

        // Also test with negative match first and a moderate positive match
        let mut partial: FaceEmbedding = [0.0; 512];
        partial[0] = 1.0; // only partially aligned
        let stored2 = vec![(10, opposite), (30, partial)];
        let (sim2, id2) = best_match(&target, &stored2);
        assert!(sim2 > 0.0, "should pick positive similarity, got {sim2}");
        assert_eq!(id2, Some(30));
    }

    #[test]
    fn best_match_all_negative_similarities() {
        // When all similarities are negative, should still pick the least negative
        let val = 1.0 / (512.0f32).sqrt();
        let mut target: FaceEmbedding = [0.0; 512];
        for x in target.iter_mut() {
            *x = val;
        }

        // opposite => sim ~ -1.0
        let mut opposite: FaceEmbedding = [0.0; 512];
        for x in opposite.iter_mut() {
            *x = -val;
        }

        // Nearly opposite => sim ~ -0.5
        let mut nearly_opp: FaceEmbedding = [0.0; 512];
        for (i, x) in nearly_opp.iter_mut().enumerate() {
            *x = if i < 384 { -val } else { val };
        }

        let stored = vec![(1, opposite), (2, nearly_opp)];
        let (sim, id) = best_match(&target, &stored);
        // nearly_opp has sim ~ -0.5, opposite has sim ~ -1.0
        // Should pick -0.5 (less negative = greater)
        assert_eq!(id, Some(2), "should pick the least-negative similarity");
        assert!(sim > -0.6, "similarity should be around -0.5, got {sim}");
    }

    #[test]
    fn float_bits_to_ordered_preserves_ordering() {
        let values = [-1.0f32, -0.5, -0.1, 0.0, 0.1, 0.5, 1.0];
        for window in values.windows(2) {
            let a = super::float_bits_to_ordered(window[0].to_bits());
            let b = super::float_bits_to_ordered(window[1].to_bits());
            assert!(
                a < b,
                "ordered({}) should be < ordered({}), got {} vs {}",
                window[0],
                window[1],
                a,
                b
            );
        }
    }

    #[test]
    fn zeroize_embedding_clears_data() {
        let mut emb: FaceEmbedding = [0.0; 512];
        emb[0] = 1.0;
        emb[100] = -0.5;
        emb[511] = 42.0;

        zeroize_embedding(&mut emb);

        for (i, &val) in emb.iter().enumerate() {
            assert_eq!(val, 0.0, "embedding[{i}] should be zeroed, got {val}");
        }
    }

    #[test]
    fn zeroize_stored_embeddings_clears_all() {
        let emb1: FaceEmbedding = [1.0; 512];
        let emb2: FaceEmbedding = [2.0; 512];
        let mut stored = vec![(1u32, emb1), (2u32, emb2)];

        zeroize_stored_embeddings(&mut stored);

        for (id, emb) in &stored {
            for (i, &val) in emb.iter().enumerate() {
                assert_eq!(
                    val, 0.0,
                    "embedding for model {id} at [{i}] should be zeroed"
                );
            }
        }
    }

    #[test]
    fn frame_drop_zeroes_pixel_data() {
        let rgb = vec![255u8; 640 * 480 * 3];
        let gray = vec![128u8; 640 * 480];

        // Create frame and get raw pointers to the backing memory
        let mut frame = Frame {
            rgb,
            gray,
            width: 640,
            height: 480,
        };

        // Verify data is non-zero before drop
        assert!(frame.rgb.iter().any(|&b| b != 0));
        assert!(frame.gray.iter().any(|&b| b != 0));

        // Zeroize happens on drop, but we can test the explicit zeroize path
        use zeroize::Zeroize;
        frame.rgb.zeroize();
        frame.gray.zeroize();

        assert!(
            frame.rgb.iter().all(|&b| b == 0),
            "RGB data should be zeroed"
        );
        assert!(
            frame.gray.iter().all(|&b| b == 0),
            "gray data should be zeroed"
        );
    }

    /// Build a unit embedding pointing mostly along `axis` with a small tilt so
    /// consecutive frames can be made to drift by a controlled amount.
    fn tilted_unit(primary: f32, secondary: f32) -> FaceEmbedding {
        let mut e: FaceEmbedding = [0.0; 512];
        let norm = (primary * primary + secondary * secondary).sqrt();
        e[0] = primary / norm;
        e[1] = secondary / norm;
        e
    }

    #[test]
    fn frame_variance_rejects_near_static_sequence() {
        // Near-identical consecutive embeddings (drift < 0.03, sim > 0.97) must fail.
        let a = tilted_unit(1.0, 0.02);
        let b = tilted_unit(1.0, 0.03);
        let c = tilted_unit(1.0, 0.04);
        let seq = [a, b, c];
        // Sanity: consecutive similarities are all above 0.97.
        assert!(cosine_similarity(&seq[0], &seq[1]) > 0.97);
        assert!(
            !check_frame_variance(&seq, DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY),
            "near-static sequence must be rejected"
        );
    }

    #[test]
    fn frame_variance_accepts_live_like_sequence() {
        // Live-like drift (>= 0.03 per step, sim < 0.97) must pass.
        let a = tilted_unit(1.0, 0.0);
        let b = tilted_unit(1.0, 0.30);
        let c = tilted_unit(1.0, 0.60);
        let seq = [a, b, c];
        assert!(cosine_similarity(&seq[0], &seq[1]) < 0.97);
        assert!(cosine_similarity(&seq[1], &seq[2]) < 0.97);
        assert!(
            check_frame_variance(&seq, DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY),
            "live-like sequence must pass"
        );
    }

    #[test]
    fn frame_variance_threshold_is_configurable() {
        // A sequence that passes at a strict (low) max_similarity still passes,
        // and one that only just drifts can be tuned by the caller.
        let a = tilted_unit(1.0, 0.10);
        let b = tilted_unit(1.0, 0.30);
        let seq = [a, b];
        let sim = cosine_similarity(&seq[0], &seq[1]);
        // With a max just below the actual similarity, it is rejected...
        assert!(!check_frame_variance(&seq, sim - 0.001));
        // ...and with a max just above, it is accepted.
        assert!(check_frame_variance(&seq, sim + 0.001));
    }

    fn fp(vid: Option<&str>, pid: Option<&str>, serial: Option<&str>) -> DeviceFingerprint {
        DeviceFingerprint {
            vid: vid.map(String::from),
            pid: pid.map(String::from),
            serial: serial.map(String::from),
            by_path: None,
        }
    }

    #[test]
    fn fingerprint_canonical_string_form() {
        assert_eq!(
            fp(Some("046d"), Some("085e"), Some("ABC")).canonical(),
            "046d:085e:ABC"
        );
        assert_eq!(
            fp(Some("046d"), Some("085e"), None).canonical(),
            "046d:085e:"
        );
        assert_eq!(fp(None, None, None).canonical(), "::");
    }

    #[test]
    fn fingerprint_canonical_for_storage_is_none_when_unidentifiable() {
        // No vid/pid → no identity → stored as NULL (legacy-governed), never a lockout.
        assert_eq!(fp(None, None, None).canonical_for_storage(), None);
        assert_eq!(fp(None, None, Some("SER")).canonical_for_storage(), None);
        assert_eq!(
            fp(Some("046d"), Some("085e"), None).canonical_for_storage(),
            Some("046d:085e:".to_string())
        );
    }

    #[test]
    fn device_match_model_granularity_compares_vid_pid_only() {
        let live = fp(Some("046d"), Some("085e"), Some("SERIAL-A"));
        // Same model, different serial → matches at model granularity.
        assert!(device_ids_match(
            "046d:085e:SERIAL-B",
            &live,
            DeviceMatchGranularity::Model
        ));
        // Different model → no match.
        assert!(!device_ids_match(
            "1234:5678:SERIAL-A",
            &live,
            DeviceMatchGranularity::Model
        ));
    }

    #[test]
    fn device_match_is_case_insensitive_on_ids() {
        let live = fp(Some("046D"), Some("085E"), None);
        assert!(device_ids_match(
            "046d:085e:",
            &live,
            DeviceMatchGranularity::Model
        ));
    }

    #[test]
    fn device_match_unit_granularity_requires_serial() {
        let live = fp(Some("046d"), Some("085e"), Some("SERIAL-A"));
        // Same unit → match.
        assert!(device_ids_match(
            "046d:085e:SERIAL-A",
            &live,
            DeviceMatchGranularity::Unit
        ));
        // Same model, different serial → NO match at unit granularity.
        assert!(!device_ids_match(
            "046d:085e:SERIAL-B",
            &live,
            DeviceMatchGranularity::Unit
        ));
        // Stored has serial but live lacks one → no unit match.
        let live_no_serial = fp(Some("046d"), Some("085e"), None);
        assert!(!device_ids_match(
            "046d:085e:SERIAL-A",
            &live_no_serial,
            DeviceMatchGranularity::Unit
        ));
    }

    #[test]
    fn device_match_unknown_live_never_matches_nonempty_stored() {
        let unknown = fp(None, None, None);
        assert!(!device_ids_match(
            "046d:085e:",
            &unknown,
            DeviceMatchGranularity::Model
        ));
        assert!(!device_ids_match(
            "046d:085e:SER",
            &unknown,
            DeviceMatchGranularity::Unit
        ));
    }

    #[test]
    fn device_binding_disabled_allows_everything() {
        let policy = DeviceBindingPolicy {
            enabled: false,
            granularity: DeviceMatchGranularity::Unit,
            allow_legacy: false,
        };
        let unknown = fp(None, None, None);
        assert!(device_binding_allows(
            Some("046d:085e:X"),
            &unknown,
            &policy
        ));
        assert!(device_binding_allows(None, &unknown, &policy));
    }

    #[test]
    fn device_binding_legacy_null_follows_allow_legacy() {
        let live = fp(Some("046d"), Some("085e"), None);
        let allow = DeviceBindingPolicy {
            enabled: true,
            granularity: DeviceMatchGranularity::Model,
            allow_legacy: true,
        };
        let deny = DeviceBindingPolicy {
            allow_legacy: false,
            ..allow
        };
        assert!(device_binding_allows(None, &live, &allow));
        assert!(device_binding_allows(Some(""), &live, &allow));
        assert!(!device_binding_allows(None, &live, &deny));
    }

    /// Regression gate: a template whose device id does not match the live
    /// camera must NEVER be allowed into the compare set. If this ever returns
    /// true, a device mismatch could reach the success branch.
    #[test]
    fn device_mismatch_is_never_allowed() {
        let live = fp(Some("046d"), Some("085e"), Some("REAL"));
        let policy = DeviceBindingPolicy {
            enabled: true,
            granularity: DeviceMatchGranularity::Model,
            allow_legacy: true,
        };
        // A different-model attacker camera template must be skipped.
        assert!(!device_binding_allows(
            Some("ffff:ffff:FAKE"),
            &live,
            &policy
        ));
        // Even with a matching-looking serial but wrong model.
        assert!(!device_binding_allows(
            Some("1234:5678:REAL"),
            &live,
            &policy
        ));
        // And at unit granularity, a same-model different-serial template is skipped.
        let unit = DeviceBindingPolicy {
            granularity: DeviceMatchGranularity::Unit,
            ..policy
        };
        assert!(!device_binding_allows(
            Some("046d:085e:OTHER"),
            &live,
            &unit
        ));
    }

    fn model(id: u32, device_id: Option<&str>) -> FaceModelInfo {
        FaceModelInfo {
            id,
            user: "alice".into(),
            label: format!("m{id}"),
            created_at: 0,
            embedder_model: String::new(),
            device_id: device_id.map(String::from),
        }
    }

    #[test]
    fn allowed_model_ids_excludes_device_mismatch() {
        let live = fp(Some("046d"), Some("085e"), Some("REAL"));
        let policy = DeviceBindingPolicy {
            enabled: true,
            granularity: DeviceMatchGranularity::Model,
            allow_legacy: true,
        };
        let models = vec![
            model(1, Some("046d:085e:REAL")), // same camera → allowed
            model(2, Some("ffff:ffff:FAKE")), // attacker camera → excluded
            model(3, None),                   // legacy → allowed
        ];
        let allowed = device_allowed_model_ids(&models, &live, &policy);
        assert!(allowed.contains(&1));
        assert!(!allowed.contains(&2), "mismatched model must be excluded");
        assert!(allowed.contains(&3));
    }

    #[test]
    fn allowed_model_ids_all_when_disabled() {
        let live = fp(None, None, None);
        let policy = DeviceBindingPolicy {
            enabled: false,
            granularity: DeviceMatchGranularity::Unit,
            allow_legacy: false,
        };
        let models = vec![model(1, Some("046d:085e:X")), model(2, None)];
        let allowed = device_allowed_model_ids(&models, &live, &policy);
        assert_eq!(allowed.len(), 2);
    }

    #[test]
    fn device_binding_aad_seam_shape() {
        assert_eq!(
            device_binding_aad(Some("046d:085e:X")),
            Some(b"facelock-device:046d:085e:X".to_vec())
        );
        assert_eq!(device_binding_aad(None), None);
        assert_eq!(device_binding_aad(Some("")), None);
    }

    #[test]
    fn cosine_similarity_opposite() {
        let mut a = [0.0f32; 512];
        let val = 1.0 / (512.0f32).sqrt();
        for x in &mut a {
            *x = val;
        }
        let mut b = a;
        for x in &mut b {
            *x = -*x;
        }
        let result = cosine_similarity(&a, &b);
        assert!(
            (result + 1.0).abs() < 1e-5,
            "opposite vectors should have similarity ~-1.0, got {result}"
        );
    }
}
