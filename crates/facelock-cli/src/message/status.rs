//! The `facelock status` report's prose.
//!
//! The report *skeleton* — item lines, `[ok]`/`[!!]` markers, `- key:` detail
//! rows — stays structural in the renderer, and config-key-shaped detail keys
//! (`require_ir`, `device.path`, `quirks`, ...) are vocabulary rather than
//! prose, so they stay literal there. Only the sentences live here.

#[cfg(test)]
use super::sample_text as s;
use super::{Message, fill, translate};

/// The `facelock status` report's prose.
///
/// Variant and field names are the machine vocabulary: [`Message::machine`]
/// derives its event line from them.
#[derive(Debug, Clone, PartialEq)]
pub enum StatusMessage {
    StatusHeader,
    StatusLabelConfigFile,
    StatusLabelDaemon,
    StatusLabelOneshotFallback,
    StatusLabelCameraDevice,
    StatusLabelModelDirectory,
    StatusLabelExecutionProvider,
    StatusLabelEncryption,
    StatusLabelEnrolledFaces,
    StatusLabelSecurity,
    StatusLabelNotifications,
    StatusLabelPamModule,
    /// The unknown-is-not-false rendering (N4): the answer could not be
    /// determined, and no value is guessed in its place.
    StatusUnknown {
        why: String,
    },
    StatusConfigValid,
    StatusConfigNotFound,
    StatusConfigInvalid {
        error: String,
    },
    StatusDaemonOneshot,
    StatusDaemonResponding,
    StatusDaemonNotResponding {
        error: String,
    },
    StatusFallbackUsable,
    StatusFallbackNotUsable,
    StatusCameraDeviceExists,
    StatusCameraDeviceNotFound,
    StatusCameraAutoDetect,
    StatusModelsDirNotFound,
    StatusModelsAllPresent,
    StatusModelsSomeMissing,
    StatusPresent,
    StatusMissing,
    StatusEpSupported,
    StatusEpNotBuiltIn,
    StatusEpUnknownName,
    StatusEpUnqueryable {
        error: String,
    },
    StatusSealedKey {
        path: String,
    },
    StatusSealedKeyMissing {
        path: String,
    },
    StatusTpmDeviceMissing {
        path: String,
    },
    StatusKeyFile {
        path: String,
    },
    StatusKeyFileMissing {
        path: String,
    },
    StatusPlaintextEmbeddings,
    StatusNoFacesEnrolled,
    StatusModelCount {
        count: usize,
    },
    StatusMarkerMismatch {
        marker: u32,
        store: u32,
    },
    StatusMarkerUnreadable {
        why: String,
    },
    StatusSecurityDisabled,
    StatusYes,
    StatusNo,
    StatusNotifyOff,
    StatusNotifyTerminal,
    StatusNotifyDesktop,
    StatusNotifyBoth,
    StatusPamInstalled,
    StatusPamInstalledAt {
        path: String,
    },
    StatusPamNotInstalled,
    StatusPamSudoConfigured,
    StatusPamSudoNotConfigured,
}

impl Message for StatusMessage {
    fn localized(&self) -> String {
        use StatusMessage::*;
        match self {
            StatusHeader => translate("facelock system status"),
            StatusLabelConfigFile => translate("Config file"),
            StatusLabelDaemon => translate("Daemon"),
            StatusLabelOneshotFallback => translate("Oneshot fallback"),
            StatusLabelCameraDevice => translate("Camera device"),
            StatusLabelModelDirectory => translate("Model directory"),
            StatusLabelExecutionProvider => translate("Execution provider"),
            StatusLabelEncryption => translate("Encryption"),
            StatusLabelEnrolledFaces => translate("Enrolled faces"),
            StatusLabelSecurity => translate("Security"),
            StatusLabelNotifications => translate("Notifications"),
            StatusLabelPamModule => translate("PAM module"),
            StatusUnknown { why } => fill(
                translate("cannot determine: {why}"),
                &[("why", why.clone())],
            ),
            StatusConfigValid => translate("valid"),
            StatusConfigNotFound => translate("not found"),
            StatusConfigInvalid { error } => {
                fill(translate("invalid: {error}"), &[("error", error.clone())])
            }
            StatusDaemonOneshot => translate("oneshot mode (no daemon)"),
            StatusDaemonResponding => translate("responding"),
            StatusDaemonNotResponding { error } => fill(
                translate("not responding: {error}"),
                &[("error", error.clone())],
            ),
            StatusFallbackUsable => translate(
                "usable (root-invoked PAM can authenticate via 'facelock auth' without the daemon)",
            ),
            StatusFallbackNotUsable => translate(
                "not usable (PAM would fall through to the next auth method if the daemon is unreachable)",
            ),
            StatusCameraDeviceExists => translate("device exists"),
            StatusCameraDeviceNotFound => translate("device not found"),
            StatusCameraAutoDetect => translate("auto-detect enabled"),
            StatusModelsDirNotFound => translate("directory not found"),
            StatusModelsAllPresent => translate("all configured models present"),
            StatusModelsSomeMissing => translate("some models missing (run 'facelock setup')"),
            StatusPresent => translate("present"),
            StatusMissing => translate("MISSING"),
            StatusEpSupported => translate("supported by the installed ONNX Runtime"),
            StatusEpNotBuiltIn => translate(
                "not built into the installed ONNX Runtime — inference will fall back to CPU",
            ),
            StatusEpUnknownName => {
                translate("unknown execution provider (valid: cpu, cuda, rocm, openvino)")
            }
            StatusEpUnqueryable { error } => fill(
                translate("ONNX Runtime not loadable: {error}"),
                &[("error", error.clone())],
            ),
            StatusSealedKey { path } => {
                fill(translate("sealed key: {path}"), &[("path", path.clone())])
            }
            StatusSealedKeyMissing { path } => fill(
                translate("sealed key missing: {path}"),
                &[("path", path.clone())],
            ),
            StatusTpmDeviceMissing { path } => fill(
                translate("TPM device missing: {path}"),
                &[("path", path.clone())],
            ),
            StatusKeyFile { path } => {
                fill(translate("key file: {path}"), &[("path", path.clone())])
            }
            StatusKeyFileMissing { path } => fill(
                translate("key file missing: {path}"),
                &[("path", path.clone())],
            ),
            StatusPlaintextEmbeddings => translate(
                "embeddings stored as plaintext (run 'facelock setup' to enable encryption)",
            ),
            StatusNoFacesEnrolled => translate("no faces enrolled (run 'facelock enroll')"),
            StatusModelCount { count } => fill(
                translate("{count} model(s)"),
                &[("count", count.to_string())],
            ),
            StatusMarkerMismatch { marker, store } => fill(
                translate(
                    "out of date (marker says {marker}, database has {store}) — run 'sudo facelock setup' to reconcile",
                ),
                &[("marker", marker.to_string()), ("store", store.to_string())],
            ),
            StatusMarkerUnreadable { why } => {
                fill(translate("unreadable: {why}"), &[("why", why.clone())])
            }
            StatusSecurityDisabled => translate("ALL SECURITY CHECKS DISABLED"),
            StatusYes => translate("yes"),
            StatusNo => translate("no"),
            StatusNotifyOff => translate("off"),
            StatusNotifyTerminal => translate("terminal"),
            StatusNotifyDesktop => translate("desktop"),
            StatusNotifyBoth => translate("terminal + desktop"),
            StatusPamInstalled => translate("installed"),
            StatusPamInstalledAt { path } => {
                fill(translate("installed at {path}"), &[("path", path.clone())])
            }
            StatusPamNotInstalled => translate("not installed"),
            StatusPamSudoConfigured => translate("configured"),
            StatusPamSudoNotConfigured => translate("not configured for facelock"),
        }
    }
}

/// One sample per variant, in enum order, for the placeholder sweep.
///
/// [`Self::next_sample`] is an exhaustive `match` with no wildcard arm, so a
/// new variant stops this compiling until it is given a sample and linked
/// into the walk — the sweep cannot silently fall behind the vocabulary.
#[cfg(test)]
impl super::Samples for StatusMessage {
    fn first_sample() -> Self {
        use StatusMessage::*;
        StatusHeader
    }

    fn next_sample(&self) -> Option<Self> {
        use StatusMessage::*;
        Some(match self {
            StatusHeader => StatusLabelConfigFile,
            StatusLabelConfigFile => StatusLabelDaemon,
            StatusLabelDaemon => StatusLabelOneshotFallback,
            StatusLabelOneshotFallback => StatusLabelCameraDevice,
            StatusLabelCameraDevice => StatusLabelModelDirectory,
            StatusLabelModelDirectory => StatusLabelExecutionProvider,
            StatusLabelExecutionProvider => StatusLabelEncryption,
            StatusLabelEncryption => StatusLabelEnrolledFaces,
            StatusLabelEnrolledFaces => StatusLabelSecurity,
            StatusLabelSecurity => StatusLabelNotifications,
            StatusLabelNotifications => StatusLabelPamModule,
            StatusLabelPamModule => StatusUnknown { why: s("w") },
            StatusUnknown { .. } => StatusConfigValid,
            StatusConfigValid => StatusConfigNotFound,
            StatusConfigNotFound => StatusConfigInvalid { error: s("e") },
            StatusConfigInvalid { .. } => StatusDaemonOneshot,
            StatusDaemonOneshot => StatusDaemonResponding,
            StatusDaemonResponding => StatusDaemonNotResponding { error: s("e") },
            StatusDaemonNotResponding { .. } => StatusFallbackUsable,
            StatusFallbackUsable => StatusFallbackNotUsable,
            StatusFallbackNotUsable => StatusCameraDeviceExists,
            StatusCameraDeviceExists => StatusCameraDeviceNotFound,
            StatusCameraDeviceNotFound => StatusCameraAutoDetect,
            StatusCameraAutoDetect => StatusModelsDirNotFound,
            StatusModelsDirNotFound => StatusModelsAllPresent,
            StatusModelsAllPresent => StatusModelsSomeMissing,
            StatusModelsSomeMissing => StatusPresent,
            StatusPresent => StatusMissing,
            StatusMissing => StatusEpSupported,
            StatusEpSupported => StatusEpNotBuiltIn,
            StatusEpNotBuiltIn => StatusEpUnknownName,
            StatusEpUnknownName => StatusEpUnqueryable { error: s("e") },
            StatusEpUnqueryable { .. } => StatusSealedKey { path: s("/p") },
            StatusSealedKey { .. } => StatusSealedKeyMissing { path: s("/p") },
            StatusSealedKeyMissing { .. } => StatusTpmDeviceMissing { path: s("/p") },
            StatusTpmDeviceMissing { .. } => StatusKeyFile { path: s("/p") },
            StatusKeyFile { .. } => StatusKeyFileMissing { path: s("/p") },
            StatusKeyFileMissing { .. } => StatusPlaintextEmbeddings,
            StatusPlaintextEmbeddings => StatusNoFacesEnrolled,
            StatusNoFacesEnrolled => StatusModelCount { count: 2 },
            StatusModelCount { .. } => StatusMarkerMismatch {
                marker: 3,
                store: 2,
            },
            StatusMarkerMismatch { .. } => StatusMarkerUnreadable { why: s("w") },
            StatusMarkerUnreadable { .. } => StatusSecurityDisabled,
            StatusSecurityDisabled => StatusYes,
            StatusYes => StatusNo,
            StatusNo => StatusNotifyOff,
            StatusNotifyOff => StatusNotifyTerminal,
            StatusNotifyTerminal => StatusNotifyDesktop,
            StatusNotifyDesktop => StatusNotifyBoth,
            StatusNotifyBoth => StatusPamInstalled,
            StatusPamInstalled => StatusPamInstalledAt { path: s("/p") },
            StatusPamInstalledAt { .. } => StatusPamNotInstalled,
            StatusPamNotInstalled => StatusPamSudoConfigured,
            StatusPamSudoConfigured => StatusPamSudoNotConfigured,
            StatusPamSudoNotConfigured => return None,
        })
    }
}
