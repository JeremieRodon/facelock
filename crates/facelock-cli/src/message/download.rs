//! Fetching and verifying the ONNX model files.

#[cfg(test)]
use super::sample_text as s;
use super::{Message, fill, translate};

/// Model download and verification.
///
/// Variant and field names are the machine vocabulary: [`Message::machine`]
/// derives its event line from them.
#[derive(Debug, Clone, PartialEq)]
pub enum DownloadMessage {
    ModelPresentOk {
        name: String,
        purpose: String,
    },
    AllModelsPresent,
    ModelsToDownloadHeader,
    ModelToDownloadEntry {
        name: String,
        size_mb: u64,
        purpose: String,
    },
    TotalDownloadSize {
        mb: u64,
    },
    ConfirmDownloadRequiredModels,
    SkippingModelDownload,
    DownloadingModel {
        name: String,
    },
    ModelDownloaded {
        name: String,
    },

    // -- the non-interactive flow, which narrates each file as it goes --
    ModelDownloadPending {
        name: String,
        size_mb: u64,
        purpose: String,
    },
    ModelRedownloading {
        name: String,
    },
    ModelRedownloaded {
        name: String,
    },
}

impl Message for DownloadMessage {
    fn localized(&self) -> String {
        use DownloadMessage::*;
        match self {
            ModelPresentOk { name, purpose } => fill(
                translate("  [ok] {name} ({purpose})"),
                &[("name", name.clone()), ("purpose", purpose.clone())],
            ),
            AllModelsPresent => translate("  All models are already present and verified."),
            ModelsToDownloadHeader => translate("  Models to download:"),
            ModelToDownloadEntry {
                name,
                size_mb,
                purpose,
            } => fill(
                translate("    - {name} (~{size_mb}MB) - {purpose}"),
                &[
                    ("name", name.clone()),
                    ("size_mb", size_mb.to_string()),
                    ("purpose", purpose.clone()),
                ],
            ),
            TotalDownloadSize { mb } => fill(
                translate("  Total download size: ~{mb}MB"),
                &[("mb", mb.to_string())],
            ),
            ConfirmDownloadRequiredModels => translate("Download required models?"),
            SkippingModelDownload => translate("  Skipping model download."),
            DownloadingModel { name } => fill(
                translate("  Downloading {name}..."),
                &[("name", name.clone())],
            ),
            ModelDownloaded { name } => fill(
                translate("  [ok] {name} downloaded and verified"),
                &[("name", name.clone())],
            ),
            ModelDownloadPending {
                name,
                size_mb,
                purpose,
            } => fill(
                translate("  [download] {name} (~{size_mb}MB) - {purpose}"),
                &[
                    ("name", name.clone()),
                    ("size_mb", size_mb.to_string()),
                    ("purpose", purpose.clone()),
                ],
            ),
            ModelRedownloading { name } => fill(
                translate("  [redownload] {name} - checksum mismatch, re-downloading"),
                &[("name", name.clone())],
            ),
            ModelRedownloaded { name } => fill(
                translate("  [ok] {name} re-downloaded and verified"),
                &[("name", name.clone())],
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
impl super::Samples for DownloadMessage {
    const VARIANT_COUNT: usize = 12;

    fn samples() -> Vec<Self> {
        use DownloadMessage::*;
        vec![
            ModelPresentOk {
                name: s("n"),
                purpose: s("p"),
            },
            AllModelsPresent,
            ModelsToDownloadHeader,
            ModelToDownloadEntry {
                name: s("n"),
                size_mb: 1,
                purpose: s("p"),
            },
            TotalDownloadSize { mb: 1 },
            ConfirmDownloadRequiredModels,
            SkippingModelDownload,
            DownloadingModel { name: s("n") },
            ModelDownloaded { name: s("n") },
            ModelDownloadPending {
                name: s("n"),
                size_mb: 1,
                purpose: s("p"),
            },
            ModelRedownloading { name: s("n") },
            ModelRedownloaded { name: s("n") },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The model-progress lines, pinned to the bytes `commands/setup.rs`
    /// printed. The first two are pinned even though they predate this
    /// change: the non-interactive flow now renders them too, so they are
    /// load-bearing on both paths.
    #[test]
    fn download_fallback_is_byte_identical() {
        use DownloadMessage::*;

        assert_eq!(
            ModelPresentOk {
                name: "SCRFD 2.5G".into(),
                purpose: "face detection".into()
            }
            .localized(),
            "  [ok] SCRFD 2.5G (face detection)"
        );
        assert_eq!(
            ModelDownloaded {
                name: "SCRFD 2.5G".into()
            }
            .localized(),
            "  [ok] SCRFD 2.5G downloaded and verified"
        );
        assert_eq!(
            ModelDownloadPending {
                name: "ArcFace R50".into(),
                size_mb: 166,
                purpose: "face embedding".into()
            }
            .localized(),
            "  [download] ArcFace R50 (~166MB) - face embedding"
        );
        assert_eq!(
            ModelRedownloading {
                name: "ArcFace R50".into()
            }
            .localized(),
            "  [redownload] ArcFace R50 - checksum mismatch, re-downloading"
        );
        assert_eq!(
            ModelRedownloaded {
                name: "ArcFace R50".into()
            }
            .localized(),
            "  [ok] ArcFace R50 re-downloaded and verified"
        );
    }
}
