use crate::error::Result;
use crate::types::{CameraCaps, Detection, FaceEmbedding, Frame};

/// Abstraction over camera frame capture.
///
/// Object-safe: capabilities are computed once at construction and asked of
/// the camera, never threaded alongside it as loose parameters (gap D8).
/// Frame darkness is a property of a frame, not a camera — see the free
/// function `facelock_camera::is_dark_with_config`.
pub trait CameraSource {
    /// Capabilities of the underlying device, computed at construction.
    fn capabilities(&self) -> &CameraCaps;

    /// Capture a frame with full preprocessing (RGB + grayscale + CLAHE).
    fn capture(&mut self) -> Result<Frame>;

    /// Capture a frame with RGB only (no grayscale/CLAHE).
    fn capture_rgb_only(&mut self) -> Result<Frame>;
}

/// Abstraction over face detection + embedding extraction.
pub trait FaceProcessor {
    /// Detect faces and extract embeddings from a frame.
    fn process(&mut self, frame: &Frame) -> Result<Vec<(Detection, FaceEmbedding)>>;
}
