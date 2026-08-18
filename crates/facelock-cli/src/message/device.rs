//! Choosing the capture and inference devices.
//!
//! Camera enumeration, IR auto-detection and its failure modes, plus the
//! model-quality and inference-device pickers.

#[cfg(test)]
use super::sample_text as s;
use super::{Message, fill, translate};

/// Camera and inference-device selection.
///
/// Variant and field names are the machine vocabulary: [`Message::machine`]
/// derives its event line from them.
#[derive(Debug, Clone, PartialEq)]
pub enum DeviceMessage {
    // -- camera selection --
    NoVideoDevices,
    AutoSelectedIrCamera { path: String, name: String },
    AutoSelectedIrCameraPath { path: String },
    SelectedCamera { path: String, name: String },
    SelectedValue { value: String },
    PromptSelectCameraDevice,
    AutoCameraNoDevices,
    AutoCameraNoIr { listed: String, example: String },
    AutoCameraManyIr { count: usize, listed: String },
    CameraDeviceMissing { path: String },

    // -- model quality / inference device --
    PromptSelectModelQuality,
    PromptSelectInferenceDevice,
    SelectedModelsStandard,
    SelectedModelsBalanced,
    SelectedModelsHigh,
    DetectedProvider { detail: String },

    // The three warnings below reach `Terminal::info`, so `--quiet` suppresses
    // them. Deliberate: they have always gone to stdout, and routing them to
    // `error` to make them unsuppressible would move them to stderr, breaking
    // both the byte-identity pins and any script reading setup's stdout.
    // Stream fidelity won; do not "fix" these into `error`.
    ProviderQueryFailed { error: String },
    NvidiaDriverMissing,
    CudaRuntimeMissing,
}

impl Message for DeviceMessage {
    fn localized(&self) -> String {
        use DeviceMessage::*;
        match self {
            NoVideoDevices => translate(
                "  No video devices found.\n  Check that your camera is connected and the v4l2 module is loaded.",
            ),
            AutoSelectedIrCamera { path, name } => fill(
                translate("  Auto-selected IR camera: {path} ({name})"),
                &[("path", path.clone()), ("name", name.clone())],
            ),
            AutoSelectedIrCameraPath { path } => fill(
                translate("  Auto-selected IR camera: {path}"),
                &[("path", path.clone())],
            ),
            SelectedCamera { path, name } => fill(
                translate("  Selected: {path} ({name})"),
                &[("path", path.clone()), ("name", name.clone())],
            ),
            SelectedValue { value } => fill(
                translate("  Selected: {value}"),
                &[("value", value.clone())],
            ),
            PromptSelectCameraDevice => translate("Select camera device"),
            AutoCameraNoDevices => translate(
                "--camera=auto found no video devices; check that the camera is connected and the v4l2 module is loaded",
            ),
            AutoCameraNoIr { listed, example } => fill(
                translate(
                    "--camera=auto found no IR-capable camera among the detected devices:\n{listed}\n  Pass an explicit device path, e.g. --camera={example}",
                ),
                &[("listed", listed.clone()), ("example", example.clone())],
            ),
            AutoCameraManyIr { count, listed } => fill(
                translate(
                    "--camera=auto found {count} IR-capable cameras:\n{listed}\n  Pass an explicit device path to choose one.",
                ),
                &[("count", count.to_string()), ("listed", listed.clone())],
            ),
            CameraDeviceMissing { path } => fill(
                translate(
                    "camera device {path} does not exist; pass a valid /dev/video* path or --camera=auto",
                ),
                &[("path", path.clone())],
            ),
            PromptSelectModelQuality => translate("Select model quality"),
            PromptSelectInferenceDevice => translate("Select inference device"),
            SelectedModelsStandard => {
                translate("  Selected standard models (fast, good accuracy).")
            }
            SelectedModelsBalanced => {
                translate("  Selected balanced models (fast detection, high-accuracy embedding).")
            }
            SelectedModelsHigh => {
                translate("  Selected high-accuracy models (larger, ~40-50ms slower).")
            }
            DetectedProvider { detail } => fill(
                translate("  Detected: {detail}"),
                &[("detail", detail.clone())],
            ),
            ProviderQueryFailed { error } => fill(
                translate(
                    "  ⚠ Could not query the ONNX Runtime for available providers: {error}\n    Selecting cpu. Re-run with an explicit --execution-provider once the\n    runtime is installed if you need GPU inference.",
                ),
                &[("error", error.clone())],
            ),
            NvidiaDriverMissing => translate(
                "  ⚠ NVIDIA driver not detected. Install the NVIDIA driver package\n    before starting the daemon.",
            ),
            CudaRuntimeMissing => translate(
                "  ⚠ CUDA-enabled ONNX Runtime not found. Install onnxruntime-opt-cuda\n    before starting the daemon, or inference will fall back to CPU.",
            ),
        }
    }
}

/// One sample per variant, in enum order, for the sweeps in [`super::Samples`].
///
/// The list is flat, so it cannot cycle and cannot name a variant twice
/// without saying so; `VARIANT_COUNT` is what fails the sweep when a new
/// variant is not sampled at all. The compiler's share of this is `localized`
/// above: no wildcard arm, so a variant that renders nothing does not build.
#[cfg(test)]
impl super::Samples for DeviceMessage {
    const VARIANT_COUNT: usize = 19;

    fn samples() -> Vec<Self> {
        use DeviceMessage::*;
        vec![
            NoVideoDevices,
            AutoSelectedIrCamera {
                path: s("/d"),
                name: s("n"),
            },
            AutoSelectedIrCameraPath { path: s("/d") },
            SelectedCamera {
                path: s("/d"),
                name: s("n"),
            },
            SelectedValue { value: s("v") },
            PromptSelectCameraDevice,
            AutoCameraNoDevices,
            AutoCameraNoIr {
                listed: s("l"),
                example: s("/d"),
            },
            AutoCameraManyIr {
                count: 2,
                listed: s("l"),
            },
            CameraDeviceMissing { path: s("/d") },
            PromptSelectModelQuality,
            PromptSelectInferenceDevice,
            SelectedModelsStandard,
            SelectedModelsBalanced,
            SelectedModelsHigh,
            DetectedProvider { detail: s("d") },
            ProviderQueryFailed { error: s("e") },
            NvidiaDriverMissing,
            CudaRuntimeMissing,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The strings this domain took over from `commands/setup.rs`, pinned to
    /// the bytes those `println!` call sites printed. See the same test in
    /// [`super::super::setup`] for why a failing pin is fixed by restoring
    /// the string, never by editing the expectation.
    #[test]
    fn device_fallback_is_byte_identical() {
        use DeviceMessage::*;

        assert_eq!(
            SelectedModelsStandard.localized(),
            "  Selected standard models (fast, good accuracy)."
        );
        assert_eq!(
            SelectedModelsBalanced.localized(),
            "  Selected balanced models (fast detection, high-accuracy embedding)."
        );
        assert_eq!(
            SelectedModelsHigh.localized(),
            "  Selected high-accuracy models (larger, ~40-50ms slower)."
        );
        assert_eq!(
            DetectedProvider {
                detail: "cuda (available: cpu, cuda)".into()
            }
            .localized(),
            "  Detected: cuda (available: cpu, cuda)"
        );
        assert_eq!(
            ProviderQueryFailed {
                error: "libonnxruntime.so not found".into()
            }
            .localized(),
            "  \u{26a0} Could not query the ONNX Runtime for available providers: libonnxruntime.so not found\n    Selecting cpu. Re-run with an explicit --execution-provider once the\n    runtime is installed if you need GPU inference."
        );
        assert_eq!(
            NvidiaDriverMissing.localized(),
            "  \u{26a0} NVIDIA driver not detected. Install the NVIDIA driver package\n    before starting the daemon."
        );
        assert_eq!(
            CudaRuntimeMissing.localized(),
            "  \u{26a0} CUDA-enabled ONNX Runtime not found. Install onnxruntime-opt-cuda\n    before starting the daemon, or inference will fall back to CPU."
        );
    }
}
