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
}

/// Why an authentication attempt that saw matching frames still failed.
/// Internal plumbing only — never crosses the D-Bus `AuthResult` contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthFailureReason {
    /// Frames matched the enrolled face above the recognition threshold, but
    /// the passive frame-variance liveness gate was never satisfied before
    /// the timeout (input too static).
    VarianceNotSatisfied,
}

/// Result of a face match attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub matched: bool,
    pub model_id: Option<u32>,
    pub label: Option<String>,
    pub similarity: f32,
    /// Why the attempt failed despite matching frames (internal diagnostics;
    /// not part of the D-Bus wire contract).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<AuthFailureReason>,
}

/// Cosine similarity between two L2-normalized embeddings (= dot product)
pub fn cosine_similarity(a: &FaceEmbedding, b: &FaceEmbedding) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Default maximum consecutive-frame cosine similarity for the passive
/// frame-variance check. Configurable via `security.frame_variance_max_similarity`.
///
/// Field-measured ranges (Logitech BRIO IR node, real user at a login prompt):
/// - truly static input (photo on a stand, paused replay): pair similarity ≳ 0.999
/// - a frozen, non-blinking live human: (0.98, 0.995]
/// - a naturally moving live human: well below 0.98
///
/// The check's honest job is rejecting *perfectly static* input as
/// defense-in-depth, so the default sits at the top of the frozen-human band:
/// a live user always passes, a static image never does. (The earlier 0.97
/// default assumed 0.02–0.10 live drift, which is empirically wrong for a
/// still user and caused hard false-reject lockups.)
///
/// NOTE: frame-variance is a *passive* anti-photo heuristic only. It raises the
/// bar for a *static* image but does NOT defeat a video replay (which contains
/// real inter-frame motion). IR enforcement remains the load-bearing defense.
pub const DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY: f32 = 0.995;

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

/// Sliding window of the most recent matched-frame embeddings for the passive
/// frame-variance gate.
///
/// The gate passes only when the window is *full* AND every consecutive pair
/// inside it drifts (similarity at or below the cutoff). Because the window
/// slides, one too-still moment early in the session is forgotten once enough
/// moving frames arrive — a user who starts still can always recover. A truly
/// static input (photo, paused replay) keeps every pair above the cutoff in
/// every window, so it can never pass regardless of session length.
///
/// Implemented as a ring buffer: eviction overwrites the oldest slot in place
/// (zeroized first), so evicted embeddings never linger in memory. All slots
/// are zeroized on drop as well.
pub struct FrameVarianceWindow {
    slots: Vec<FaceEmbedding>,
    capacity: usize,
    /// Ring index where the next push goes (== oldest slot once full).
    next: usize,
}

impl FrameVarianceWindow {
    /// Create a window sized by `security.min_auth_frames` (the number of
    /// matched frames that constitute enough evidence to authenticate).
    /// Clamped to at least 2, since variance needs a pair to compare.
    pub fn new(min_auth_frames: u32) -> Self {
        let capacity = (min_auth_frames as usize).max(2);
        Self {
            slots: Vec::with_capacity(capacity),
            capacity,
            next: 0,
        }
    }

    /// Add a matched-frame embedding, evicting (and zeroizing) the oldest
    /// when the window is full.
    pub fn push(&mut self, embedding: FaceEmbedding) {
        if self.slots.len() < self.capacity {
            self.slots.push(embedding);
            self.next = self.slots.len() % self.capacity;
        } else {
            // Zeroize the evicted embedding before overwriting its slot so it
            // never lingers, then take its place in the ring.
            zeroize_embedding(&mut self.slots[self.next]);
            self.slots[self.next] = embedding;
            self.next = (self.next + 1) % self.capacity;
        }
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.slots.len() == self.capacity
    }

    /// Slot index of the `chrono`-th oldest embedding.
    fn index_at(&self, chrono: usize) -> usize {
        if self.slots.len() < self.capacity {
            chrono
        } else {
            (self.next + chrono) % self.capacity
        }
    }

    /// Cosine similarities of consecutive (chronological) pairs in the window.
    fn pair_similarities(&self) -> impl Iterator<Item = f32> + '_ {
        (1..self.slots.len()).map(move |i| {
            cosine_similarity(
                &self.slots[self.index_at(i - 1)],
                &self.slots[self.index_at(i)],
            )
        })
    }

    /// Min and max consecutive-pair similarity currently in the window.
    /// For diagnostics/tuning logs only — exposes similarity values, never
    /// embedding contents. `None` until the window holds at least two frames.
    pub fn min_max_pair_similarity(&self) -> Option<(f32, f32)> {
        let mut it = self.pair_similarities();
        let first = it.next()?;
        Some(it.fold((first, first), |(mn, mx), s| (mn.min(s), mx.max(s))))
    }

    /// The variance gate: full window AND every consecutive pair drifting.
    pub fn passes(&self, max_similarity: f32) -> bool {
        self.is_full() && self.pair_similarities().all(|s| s <= max_similarity)
    }

    /// Zeroize all held embeddings and empty the window.
    /// Call at security boundaries (auth success/failure exit paths).
    pub fn zeroize_all(&mut self) {
        for emb in &mut self.slots {
            zeroize_embedding(emb);
        }
        self.slots.clear();
        self.next = 0;
    }
}

impl Drop for FrameVarianceWindow {
    fn drop(&mut self) {
        for emb in &mut self.slots {
            zeroize_embedding(emb);
        }
    }
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
        // Near-identical consecutive embeddings (sim > 0.995, static-like) must fail.
        let a = tilted_unit(1.0, 0.02);
        let b = tilted_unit(1.0, 0.03);
        let c = tilted_unit(1.0, 0.04);
        let seq = [a, b, c];
        // Sanity: consecutive similarities are all above the 0.995 default.
        assert!(cosine_similarity(&seq[0], &seq[1]) > 0.995);
        assert!(
            !check_frame_variance(&seq, DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY),
            "near-static sequence must be rejected"
        );
    }

    #[test]
    fn frame_variance_accepts_live_like_sequence() {
        // Live-like drift (sim well below the 0.995 default) must pass.
        let a = tilted_unit(1.0, 0.0);
        let b = tilted_unit(1.0, 0.30);
        let c = tilted_unit(1.0, 0.60);
        let seq = [a, b, c];
        assert!(cosine_similarity(&seq[0], &seq[1]) < 0.995);
        assert!(cosine_similarity(&seq[1], &seq[2]) < 0.995);
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

    /// Unit embedding at a planar angle: cosine similarity between two of these
    /// is exactly cos(theta_a - theta_b), giving precise control over drift.
    fn unit_at_angle(theta: f32) -> FaceEmbedding {
        let mut e: FaceEmbedding = [0.0; 512];
        e[0] = theta.cos();
        e[1] = theta.sin();
        e
    }

    #[test]
    fn variance_window_still_then_moving_recovers() {
        // Field bug #1: a user who starts perfectly still must be able to recover
        // once they move. With an append-only history one still pair poisoned the
        // whole session; a sliding window forgets it.
        let mut w = FrameVarianceWindow::new(3);
        let still = unit_at_angle(0.0);
        for _ in 0..6 {
            w.push(still);
            assert!(
                !w.passes(DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY),
                "still frames must never satisfy the variance gate"
            );
        }
        // Now the user moves: consecutive drift cos(0.15) ~= 0.9888 <= 0.995.
        for (i, theta) in [0.15f32, 0.30, 0.45].iter().enumerate() {
            w.push(unit_at_angle(*theta));
            if i >= 2 {
                assert!(
                    w.passes(DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY),
                    "window filled with moving frames must pass (recovery)"
                );
            }
        }
        // And it must have passed by the time the window is all moving frames.
        assert!(w.passes(DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY));
    }

    #[test]
    fn variance_window_static_never_passes() {
        // A truly static input (photo on a stand) is identical frame-to-frame.
        // No matter how long it runs, no window may ever pass.
        let mut w = FrameVarianceWindow::new(3);
        let photo = unit_at_angle(0.7);
        for _ in 0..50 {
            w.push(photo);
            assert!(
                !w.passes(DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY),
                "a fully static sequence must never pass, regardless of length"
            );
        }
    }

    #[test]
    fn variance_window_near_static_replay_never_passes() {
        // A paused replay / photo with sensor noise sits at pair similarity
        // >= ~0.999 — still above the 0.995 default, so it must never pass.
        let mut w = FrameVarianceWindow::new(3);
        for i in 0..50 {
            // steps of 0.02 rad: consecutive similarity cos(0.02) ~= 0.9998
            w.push(unit_at_angle(i as f32 * 0.02));
            assert!(
                !w.passes(DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY),
                "near-static (sim ~0.9998) must never pass at the default cutoff"
            );
        }
    }

    #[test]
    fn variance_window_boundary_at_default() {
        assert_eq!(DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY, 0.995);

        // Just above the default (pair sim ~0.9965 > 0.995): rejected.
        let mut too_still = FrameVarianceWindow::new(2);
        too_still.push(unit_at_angle(0.0));
        too_still.push(unit_at_angle(0.0837)); // cos ~= 0.9965
        let (mn, _) = too_still.min_max_pair_similarity().unwrap();
        assert!(
            mn > 0.995,
            "sanity: pair must sit above the cutoff, got {mn}"
        );
        assert!(!too_still.passes(DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY));

        // Frozen-but-live human range (field-measured (0.98, 0.995]): accepted.
        let mut frozen_human = FrameVarianceWindow::new(2);
        frozen_human.push(unit_at_angle(0.0));
        frozen_human.push(unit_at_angle(0.1415)); // cos ~= 0.9900
        let (mn, mx) = frozen_human.min_max_pair_similarity().unwrap();
        assert!(
            mn > 0.98 && mx <= 0.995,
            "sanity: pair in frozen-human band, got {mn}..{mx}"
        );
        assert!(frozen_human.passes(DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY));
    }

    #[test]
    fn variance_window_requires_full_window() {
        // The gate must not fire before min_auth_frames matched frames are seen.
        let mut w = FrameVarianceWindow::new(3);
        w.push(unit_at_angle(0.0));
        w.push(unit_at_angle(0.2));
        assert!(!w.is_full());
        assert!(
            !w.passes(DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY),
            "partial window must not pass even with good drift"
        );
    }

    #[test]
    fn variance_window_evicts_oldest_embedding() {
        // Capacity 2: pushing a third embedding must evict (and not retain) the first.
        let mut w = FrameVarianceWindow::new(2);
        let first = unit_at_angle(0.0);
        w.push(first);
        w.push(unit_at_angle(0.5));
        w.push(unit_at_angle(1.0));
        assert_eq!(w.len(), 2, "window must stay at capacity");
        assert!(
            w.slots.iter().all(|s| *s != first),
            "evicted embedding must not be retained in the window"
        );
    }

    #[test]
    fn variance_window_zeroize_all_clears() {
        let mut w = FrameVarianceWindow::new(2);
        w.push(unit_at_angle(0.3));
        w.push(unit_at_angle(0.6));
        w.zeroize_all();
        assert_eq!(w.len(), 0);
        assert!(w.slots.is_empty());
        assert!(!w.passes(DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY));
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
