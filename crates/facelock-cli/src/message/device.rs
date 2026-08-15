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
        }
    }
}

/// One sample per variant, in enum order, for the placeholder sweep.
///
/// [`Self::next_sample`] is an exhaustive `match` with no wildcard arm, so a
/// new variant stops this compiling until it is given a sample and linked
/// into the walk — the sweep cannot silently fall behind the vocabulary.
#[cfg(test)]
impl super::Samples for DeviceMessage {
    fn first_sample() -> Self {
        use DeviceMessage::*;
        NoVideoDevices
    }

    fn next_sample(&self) -> Option<Self> {
        use DeviceMessage::*;
        Some(match self {
            NoVideoDevices => AutoSelectedIrCamera {
                path: s("/d"),
                name: s("n"),
            },
            AutoSelectedIrCamera { .. } => AutoSelectedIrCameraPath { path: s("/d") },
            AutoSelectedIrCameraPath { .. } => SelectedCamera {
                path: s("/d"),
                name: s("n"),
            },
            SelectedCamera { .. } => SelectedValue { value: s("v") },
            SelectedValue { .. } => PromptSelectCameraDevice,
            PromptSelectCameraDevice => AutoCameraNoDevices,
            AutoCameraNoDevices => AutoCameraNoIr {
                listed: s("l"),
                example: s("/d"),
            },
            AutoCameraNoIr { .. } => AutoCameraManyIr {
                count: 2,
                listed: s("l"),
            },
            AutoCameraManyIr { .. } => CameraDeviceMissing { path: s("/d") },
            CameraDeviceMissing { .. } => PromptSelectModelQuality,
            PromptSelectModelQuality => PromptSelectInferenceDevice,
            PromptSelectInferenceDevice => return None,
        })
    }
}
