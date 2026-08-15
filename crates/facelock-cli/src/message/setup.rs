//! The `facelock setup` wizard's spine.
//!
//! Step banners, the per-step failure-and-retry-hint events, the closing
//! summary, and the non-interactive path. Individual steps own their own
//! vocabulary: see [`device`](super::device), [`download`](super::download),
//! [`system`](super::system) and [`pam`](super::pam).

#[cfg(test)]
use super::sample_text as s;
use super::{Message, fill, translate};

/// The setup wizard's spine.
///
/// Variant and field names are the machine vocabulary: [`Message::machine`]
/// derives its event line from them.
#[derive(Debug, Clone, PartialEq)]
pub enum SetupMessage {
    // -- wizard spine --
    SetupIntro { version: String },
    SetupStepCamera,
    SetupStepModelQuality,
    SetupStepInferenceDevice,
    SetupStepModelDownload,
    SetupStepEncryption,
    SetupStepEnrollment,
    SetupStepEnrollmentSkipped,
    SetupStepTest,
    SetupStepTestSkipped,
    SetupStepDaemon,
    SetupStepPam,
    SetupCompleteHeader,

    // -- step-level failures (error + retry hint, one event) --
    CameraStepFailed { error: String, current: String },
    ModelQualityStepFailed { error: String, current: String },
    InferenceStepFailed { error: String, current: String },
    ModelDownloadStepFailed { error: String },
    EncryptionStepFailed { error: String },
    EnrollStepFailed { error: String },
    TestStepFailed { error: String },
    SystemdStepFailed { error: String },
    GroupStepFailed { error: String },
    PamStepFailed { error: String },

    // -- enrollment and test steps --
    ConfirmEnrollNow,
    EnrollSkipped,
    ConfirmTestRecognition,
    TestSkipped,

    // -- closing summary --
    SummaryCamera { value: String },
    SummaryModels { dir: String, quality: String },
    SummaryInference { value: String },
    SummaryDatabase { value: String },
    SummaryEncryption { value: String },
    SummaryDaemon { status: String },
    DaemonStatusNotConfiguredNoSystemd,
    DaemonStatusDeferred,
    DaemonStatusEnabled,
    DaemonStatusNotConfigured,
    SummaryPam { services: String },
    SummaryPamSkipped,
    SummaryPamNone,
    SummaryFaceEnrolled,
    SummaryFaceNotEnrolledNoEnroll,
    SummaryFaceNotEnrolled,

    // -- non-interactive --
    NonInteractivePreparing,
    CheckingModels { count: usize },
    SetupCompleteShort,
    SetupCompleteEnroll,
}

impl Message for SetupMessage {
    fn localized(&self) -> String {
        use SetupMessage::*;
        match self {
            SetupIntro { version } => fill(
                translate(
                    "\n  Facelock v{version}\n  Linux face authentication\n\n  This wizard will walk you through initial setup:\n    - Camera detection\n    - Model quality and inference device\n    - Model downloads\n    - Embedding encryption (TPM or software)\n    - Face enrollment\n    - Daemon and PAM configuration\n",
                ),
                &[("version", version.clone())],
            ),
            SetupStepCamera => translate("\n--- Step 1: Camera Selection ---\n"),
            SetupStepModelQuality => translate("\n--- Step 2: Model Quality ---\n"),
            SetupStepInferenceDevice => translate("\n--- Step 3: Inference Device ---\n"),
            SetupStepModelDownload => translate("\n--- Step 4: Model Download ---\n"),
            SetupStepEncryption => translate("\n--- Step 5: Embedding Encryption ---\n"),
            SetupStepEnrollment => translate("\n--- Step 6: Face Enrollment ---\n"),
            SetupStepEnrollmentSkipped => {
                translate("\n--- Step 6: Face Enrollment (skipped, --no-enroll) ---\n")
            }
            SetupStepTest => translate("\n--- Step 7: Test Recognition ---\n"),
            SetupStepTestSkipped => {
                translate("\n--- Step 7: Test Recognition (skipped, no face enrolled) ---\n")
            }
            SetupStepDaemon => translate("\n--- Step 8: Daemon Configuration ---\n"),
            SetupStepPam => translate("\n--- Step 9: PAM Configuration ---\n"),
            SetupCompleteHeader => translate("\n--- Setup Complete ---\n"),
            CameraStepFailed { error, current } => fill(
                translate(
                    "  Camera detection failed: {error}\n  You can configure the camera later in the config file.\n  Continuing with current setting: {current}",
                ),
                &[("error", error.clone()), ("current", current.clone())],
            ),
            ModelQualityStepFailed { error, current } => fill(
                translate(
                    "  Model quality selection failed: {error}\n  Continuing with current setting: {current}",
                ),
                &[("error", error.clone()), ("current", current.clone())],
            ),
            InferenceStepFailed { error, current } => fill(
                translate(
                    "  Inference device selection failed: {error}\n  Continuing with current setting: {current}",
                ),
                &[("error", error.clone()), ("current", current.clone())],
            ),
            ModelDownloadStepFailed { error } => fill(
                translate(
                    "  Model download failed: {error}\n  You can retry later with: sudo facelock setup --non-interactive",
                ),
                &[("error", error.clone())],
            ),
            EncryptionStepFailed { error } => fill(
                translate(
                    "  Encryption setup failed: {error}\n  You can configure encryption later with: sudo facelock encrypt --generate-key",
                ),
                &[("error", error.clone())],
            ),
            EnrollStepFailed { error } => fill(
                translate(
                    "  Enrollment failed: {error}\n  You can enroll later with: facelock enroll",
                ),
                &[("error", error.clone())],
            ),
            TestStepFailed { error } => fill(
                translate("  Test failed: {error}\n  You can test later with: facelock test"),
                &[("error", error.clone())],
            ),
            SystemdStepFailed { error } => fill(
                translate(
                    "  Systemd setup failed: {error}\n  You can enable it later with: sudo facelock setup --systemd",
                ),
                &[("error", error.clone())],
            ),
            GroupStepFailed { error } => fill(
                translate(
                    "  Group setup failed: {error}\n  Add manually: sudo usermod -aG facelock <user>",
                ),
                &[("error", error.clone())],
            ),
            PamStepFailed { error } => fill(
                translate(
                    "  PAM setup failed: {error}\n  You can configure PAM later with: sudo facelock setup --pam",
                ),
                &[("error", error.clone())],
            ),
            ConfirmEnrollNow => translate("Would you like to enroll a face now?"),
            EnrollSkipped => translate("  Skipping face enrollment."),
            ConfirmTestRecognition => translate("Would you like to test recognition?"),
            TestSkipped => translate("  Skipping recognition test."),
            SummaryCamera { value } => fill(
                translate("  Camera:     {value}"),
                &[("value", value.clone())],
            ),
            SummaryModels { dir, quality } => fill(
                translate("  Models:     {dir} ({quality})"),
                &[("dir", dir.clone()), ("quality", quality.clone())],
            ),
            SummaryInference { value } => fill(
                translate("  Inference:  {value}"),
                &[("value", value.clone())],
            ),
            SummaryDatabase { value } => fill(
                translate("  Database:   {value}"),
                &[("value", value.clone())],
            ),
            SummaryEncryption { value } => fill(
                translate("  Encryption: {value}"),
                &[("value", value.clone())],
            ),
            SummaryDaemon { status } => fill(
                translate("  Daemon:   {status}"),
                &[("status", status.clone())],
            ),
            DaemonStatusNotConfiguredNoSystemd => translate("not configured (--no-systemd)"),
            DaemonStatusDeferred => translate("configured from the command line"),
            DaemonStatusEnabled => translate("enabled (D-Bus activation)"),
            DaemonStatusNotConfigured => translate("not configured"),
            SummaryPam { services } => fill(
                translate("  PAM:      {services}"),
                &[("services", services.clone())],
            ),
            SummaryPamSkipped => translate("  PAM:      not configured (--no-pam)"),
            SummaryPamNone => translate("  PAM:      not configured"),
            SummaryFaceEnrolled => translate("  Face:     enrolled"),
            SummaryFaceNotEnrolledNoEnroll => {
                translate("  Face:     not enrolled (--no-enroll; run `facelock enroll`)")
            }
            SummaryFaceNotEnrolled => translate("  Face:     not enrolled (run `facelock enroll`)"),
            NonInteractivePreparing => translate("facelock setup: preparing system...\n"),
            CheckingModels { count } => fill(
                translate("Checking {count} model(s)...\n"),
                &[("count", count.to_string())],
            ),
            SetupCompleteShort => translate("\nSetup complete."),
            SetupCompleteEnroll => {
                translate("\nSetup complete. Run `facelock enroll` to register your face.")
            }
        }
    }
}

/// One sample per variant, in enum order, for the placeholder sweep.
///
/// [`Self::next_sample`] is an exhaustive `match` with no wildcard arm, so a
/// new variant stops this compiling until it is given a sample and linked
/// into the walk — the sweep cannot silently fall behind the vocabulary.
#[cfg(test)]
impl super::Samples for SetupMessage {
    fn first_sample() -> Self {
        use SetupMessage::*;
        SetupIntro { version: s("1.0") }
    }

    fn next_sample(&self) -> Option<Self> {
        use SetupMessage::*;
        Some(match self {
            SetupIntro { .. } => SetupStepCamera,
            SetupStepCamera => SetupStepModelQuality,
            SetupStepModelQuality => SetupStepInferenceDevice,
            SetupStepInferenceDevice => SetupStepModelDownload,
            SetupStepModelDownload => SetupStepEncryption,
            SetupStepEncryption => SetupStepEnrollment,
            SetupStepEnrollment => SetupStepEnrollmentSkipped,
            SetupStepEnrollmentSkipped => SetupStepTest,
            SetupStepTest => SetupStepTestSkipped,
            SetupStepTestSkipped => SetupStepDaemon,
            SetupStepDaemon => SetupStepPam,
            SetupStepPam => SetupCompleteHeader,
            SetupCompleteHeader => CameraStepFailed {
                error: s("e"),
                current: s("c"),
            },
            CameraStepFailed { .. } => ModelQualityStepFailed {
                error: s("e"),
                current: s("c"),
            },
            ModelQualityStepFailed { .. } => InferenceStepFailed {
                error: s("e"),
                current: s("c"),
            },
            InferenceStepFailed { .. } => ModelDownloadStepFailed { error: s("e") },
            ModelDownloadStepFailed { .. } => EncryptionStepFailed { error: s("e") },
            EncryptionStepFailed { .. } => EnrollStepFailed { error: s("e") },
            EnrollStepFailed { .. } => TestStepFailed { error: s("e") },
            TestStepFailed { .. } => SystemdStepFailed { error: s("e") },
            SystemdStepFailed { .. } => GroupStepFailed { error: s("e") },
            GroupStepFailed { .. } => PamStepFailed { error: s("e") },
            PamStepFailed { .. } => ConfirmEnrollNow,
            ConfirmEnrollNow => EnrollSkipped,
            EnrollSkipped => ConfirmTestRecognition,
            ConfirmTestRecognition => TestSkipped,
            TestSkipped => SummaryCamera { value: s("v") },
            SummaryCamera { .. } => SummaryModels {
                dir: s("/d"),
                quality: s("q"),
            },
            SummaryModels { .. } => SummaryInference { value: s("v") },
            SummaryInference { .. } => SummaryDatabase { value: s("v") },
            SummaryDatabase { .. } => SummaryEncryption { value: s("v") },
            SummaryEncryption { .. } => SummaryDaemon { status: s("st") },
            SummaryDaemon { .. } => DaemonStatusNotConfiguredNoSystemd,
            DaemonStatusNotConfiguredNoSystemd => DaemonStatusDeferred,
            DaemonStatusDeferred => DaemonStatusEnabled,
            DaemonStatusEnabled => DaemonStatusNotConfigured,
            DaemonStatusNotConfigured => SummaryPam {
                services: s("sudo"),
            },
            SummaryPam { .. } => SummaryPamSkipped,
            SummaryPamSkipped => SummaryPamNone,
            SummaryPamNone => SummaryFaceEnrolled,
            SummaryFaceEnrolled => SummaryFaceNotEnrolledNoEnroll,
            SummaryFaceNotEnrolledNoEnroll => SummaryFaceNotEnrolled,
            SummaryFaceNotEnrolled => NonInteractivePreparing,
            NonInteractivePreparing => CheckingModels { count: 2 },
            CheckingModels { .. } => SetupCompleteShort,
            SetupCompleteShort => SetupCompleteEnroll,
            SetupCompleteEnroll => return None,
        })
    }
}
