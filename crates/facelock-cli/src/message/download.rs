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
        }
    }
}

/// One sample per variant, in enum order, for the placeholder sweep.
///
/// [`Self::next_sample`] is an exhaustive `match` with no wildcard arm, so a
/// new variant stops this compiling until it is given a sample and linked
/// into the walk — the sweep cannot silently fall behind the vocabulary.
#[cfg(test)]
impl super::Samples for DownloadMessage {
    fn first_sample() -> Self {
        use DownloadMessage::*;
        ModelPresentOk {
            name: s("n"),
            purpose: s("p"),
        }
    }

    fn next_sample(&self) -> Option<Self> {
        use DownloadMessage::*;
        Some(match self {
            ModelPresentOk { .. } => AllModelsPresent,
            AllModelsPresent => ModelsToDownloadHeader,
            ModelsToDownloadHeader => ModelToDownloadEntry {
                name: s("n"),
                size_mb: 1,
                purpose: s("p"),
            },
            ModelToDownloadEntry { .. } => TotalDownloadSize { mb: 1 },
            TotalDownloadSize { .. } => ConfirmDownloadRequiredModels,
            ConfirmDownloadRequiredModels => SkippingModelDownload,
            SkippingModelDownload => DownloadingModel { name: s("n") },
            DownloadingModel { .. } => ModelDownloaded { name: s("n") },
            ModelDownloaded { .. } => return None,
        })
    }
}
