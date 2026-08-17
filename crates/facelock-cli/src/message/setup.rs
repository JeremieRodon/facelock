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
    SetupIntro {
        version: String,
    },
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
    CameraStepFailed {
        error: String,
        current: String,
    },
    ModelQualityStepFailed {
        error: String,
        current: String,
    },
    InferenceStepFailed {
        error: String,
        current: String,
    },
    ModelDownloadStepFailed {
        error: String,
    },
    EncryptionStepFailed {
        error: String,
    },
    EnrollStepFailed {
        error: String,
    },
    TestStepFailed {
        error: String,
    },
    SystemdStepFailed {
        error: String,
    },
    GroupStepFailed {
        error: String,
    },
    PamStepFailed {
        error: String,
    },

    // -- enrollment and test steps --
    ConfirmEnrollNow,
    EnrollSkipped,
    ConfirmTestRecognition,
    TestSkipped,

    // -- closing summary --
    SummaryCamera {
        value: String,
    },
    SummaryModels {
        dir: String,
        quality: String,
    },
    SummaryInference {
        value: String,
    },
    SummaryDatabase {
        value: String,
    },
    SummaryEncryption {
        value: String,
    },
    SummaryDaemon {
        status: String,
    },
    DaemonStatusNotConfiguredNoSystemd,
    DaemonStatusDeferred,
    DaemonStatusEnabled,
    DaemonStatusNotConfigured,
    SummaryPam {
        services: String,
    },
    SummaryPamSkipped,
    SummaryPamNone,
    SummaryFaceEnrolled,
    SummaryFaceNotEnrolledNoEnroll,
    SummaryFaceNotEnrolled,

    // -- non-interactive --
    NonInteractivePreparing,
    CheckingModels {
        count: usize,
    },
    SetupCompleteShort,
    SetupCompleteEnroll,

    // -- bootstrap --
    DirectoriesCreated,
    CreatedDefaultConfig {
        path: String,
    },
    EnrollingFace,

    // -- embedding encryption (step 5, and the non-interactive auto policy) --
    EncryptionIntro,
    TpmDetected,
    TpmSealedKeyPresent {
        path: String,
    },
    GeneratingTpmSealedKey,
    TpmSealedKeyWritten {
        path: String,
    },
    EncryptionEnabledTpm,
    KeyfilePresent {
        path: String,
    },
    GeneratingKeyfile,
    KeyfileWritten {
        path: String,
    },
    EncryptionEnabledKeyfile,

    /// The plaintext-storage warning. It reaches [`super::Terminal::info`],
    /// so `--quiet` suppresses it — chosen knowingly: this text has always
    /// gone to stdout, and moving it to `error` to make it unsuppressible
    /// would relocate it to stderr and break the byte-identity pin. Nothing
    /// is gated on it either way; `--encryption=none` is an explicit request,
    /// and `enroll` still refuses to write plaintext embeddings unless
    /// `security.allow_plaintext` is set. Do not "fix" this into `error`.
    EncryptionDisabledWarning,
    EncryptionAlreadyConfigured {
        method: String,
    },
    GeneratedTpmKeyAt {
        path: String,
    },
    EncryptionEnabledTpmAuto,
    GeneratedKeyfileAt {
        path: String,
    },
    EncryptionEnabledKeyfileAuto,
    OrphanModelsWarning {
        db_path: String,
    },
    OrphanModelsRemoved {
        count: u32,
    },

    // -- hyprlock handoff --
    HyprlockHint,
    HyprlockApplied {
        user: String,
    },

    /// A spacer between blocks, and the one variant that says nothing.
    ///
    /// It goes through the sink rather than staying a bare `println!()` so
    /// that `--quiet` silences the spacing along with the block it spaces —
    /// a quiet run that still emitted blank lines would be a stray newline
    /// on an otherwise empty stdout.
    BlankLine,
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
            DirectoriesCreated => translate("  Directories created."),
            CreatedDefaultConfig { path } => fill(
                translate("  Created default config at {path}"),
                &[("path", path.clone())],
            ),
            EnrollingFace => translate("\nEnrolling face..."),
            EncryptionIntro => {
                translate("  Setting up AES-256-GCM encryption for face embeddings.")
            }
            TpmDetected => translate("  TPM 2.0 detected and functional."),
            TpmSealedKeyPresent { path } => fill(
                translate("  TPM-sealed key already exists at {path}."),
                &[("path", path.clone())],
            ),
            GeneratingTpmSealedKey => translate("  Generating and sealing AES key with TPM..."),
            TpmSealedKeyWritten { path } => fill(
                translate("  TPM-sealed key written to {path} (permissions: 0600)."),
                &[("path", path.clone())],
            ),
            EncryptionEnabledTpm => translate("  Encryption enabled (TPM-sealed key)."),
            KeyfilePresent { path } => fill(
                translate("  Encryption key already exists at {path}."),
                &[("path", path.clone())],
            ),
            GeneratingKeyfile => translate("  Generating encryption key..."),
            KeyfileWritten { path } => fill(
                translate("  Key written to {path} (permissions: 0600)."),
                &[("path", path.clone())],
            ),
            EncryptionEnabledKeyfile => translate("  Encryption enabled."),
            EncryptionDisabledWarning => translate(
                "  ⚠ WARNING: encryption disabled (--encryption=none).\n    Biometric templates will be stored UNENCRYPTED in the database.\n    `facelock enroll` refuses to write plaintext embeddings unless\n    security.allow_plaintext is also set in the config.",
            ),
            EncryptionAlreadyConfigured { method } => fill(
                translate("  Encryption already configured ({method})."),
                &[("method", method.clone())],
            ),
            GeneratedTpmKeyAt { path } => fill(
                translate("  [ok] Generated TPM-sealed encryption key at {path}"),
                &[("path", path.clone())],
            ),
            EncryptionEnabledTpmAuto => {
                translate("  [ok] AES-256-GCM encryption enabled (TPM-sealed key).")
            }
            GeneratedKeyfileAt { path } => fill(
                translate("  [ok] Generated encryption key at {path}"),
                &[("path", path.clone())],
            ),
            EncryptionEnabledKeyfileAuto => translate("  [ok] AES-256-GCM encryption enabled."),
            OrphanModelsWarning { db_path } => fill(
                translate(
                    "\n  WARNING: encrypted face models already exist in {db_path} but the\n  encryption key is missing. Generating a new key would make them unreadable.\n",
                ),
                &[("db_path", db_path.clone())],
            ),
            OrphanModelsRemoved { count } => fill(
                translate("  Removed {count} orphaned model(s)."),
                &[("count", count.to_string())],
            ),
            HyprlockHint => translate(
                "\n==> To finish hyprlock integration, run as your normal user:\n==>     facelock hyprlock enable",
            ),
            HyprlockApplied { user } => fill(
                translate("  hyprlock integration applied for {user}."),
                &[("user", user.clone())],
            ),
            // Never `translate("")`: gettext answers an empty msgid with the
            // catalog's own metadata header, so an "empty" translation would
            // print the .mo file's Content-Type block.
            BlankLine => String::new(),
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
            SetupCompleteEnroll => DirectoriesCreated,
            DirectoriesCreated => CreatedDefaultConfig { path: s("/c") },
            CreatedDefaultConfig { .. } => EnrollingFace,
            EnrollingFace => EncryptionIntro,
            EncryptionIntro => TpmDetected,
            TpmDetected => TpmSealedKeyPresent { path: s("/k") },
            TpmSealedKeyPresent { .. } => GeneratingTpmSealedKey,
            GeneratingTpmSealedKey => TpmSealedKeyWritten { path: s("/k") },
            TpmSealedKeyWritten { .. } => EncryptionEnabledTpm,
            EncryptionEnabledTpm => KeyfilePresent { path: s("/k") },
            KeyfilePresent { .. } => GeneratingKeyfile,
            GeneratingKeyfile => KeyfileWritten { path: s("/k") },
            KeyfileWritten { .. } => EncryptionEnabledKeyfile,
            EncryptionEnabledKeyfile => EncryptionDisabledWarning,
            EncryptionDisabledWarning => EncryptionAlreadyConfigured { method: s("Tpm") },
            EncryptionAlreadyConfigured { .. } => GeneratedTpmKeyAt { path: s("/k") },
            GeneratedTpmKeyAt { .. } => EncryptionEnabledTpmAuto,
            EncryptionEnabledTpmAuto => GeneratedKeyfileAt { path: s("/k") },
            GeneratedKeyfileAt { .. } => EncryptionEnabledKeyfileAuto,
            EncryptionEnabledKeyfileAuto => OrphanModelsWarning { db_path: s("/db") },
            OrphanModelsWarning { .. } => OrphanModelsRemoved { count: 2 },
            OrphanModelsRemoved { .. } => HyprlockHint,
            HyprlockHint => HyprlockApplied { user: s("u") },
            HyprlockApplied { .. } => BlankLine,
            BlankLine => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every string this domain took over from a `println!` in
    /// `commands/setup.rs`, pinned to the bytes that call site printed.
    ///
    /// The pins are the contract, not a snapshot: a failing assertion means
    /// the *string* changed, and the fix is to restore the string. Editing
    /// the expectation to match new output inverts the test — a wording
    /// change is a separate decision with its own review, because container
    /// suites and downstream integrations grep this output.
    #[test]
    fn english_fallback_is_byte_identical() {
        use SetupMessage::*;

        // -- bootstrap --
        assert_eq!(DirectoriesCreated.localized(), "  Directories created.");
        assert_eq!(
            CreatedDefaultConfig {
                path: "/etc/facelock/config.toml".into()
            }
            .localized(),
            "  Created default config at /etc/facelock/config.toml"
        );
        assert_eq!(EnrollingFace.localized(), "\nEnrolling face...");

        // -- encryption, interactive --
        assert_eq!(
            EncryptionIntro.localized(),
            "  Setting up AES-256-GCM encryption for face embeddings."
        );
        assert_eq!(
            TpmDetected.localized(),
            "  TPM 2.0 detected and functional."
        );
        assert_eq!(
            TpmSealedKeyPresent {
                path: "/etc/facelock/sealed.key".into()
            }
            .localized(),
            "  TPM-sealed key already exists at /etc/facelock/sealed.key."
        );
        assert_eq!(
            GeneratingTpmSealedKey.localized(),
            "  Generating and sealing AES key with TPM..."
        );
        assert_eq!(
            TpmSealedKeyWritten {
                path: "/etc/facelock/sealed.key".into()
            }
            .localized(),
            "  TPM-sealed key written to /etc/facelock/sealed.key (permissions: 0600)."
        );
        assert_eq!(
            EncryptionEnabledTpm.localized(),
            "  Encryption enabled (TPM-sealed key)."
        );
        assert_eq!(
            KeyfilePresent {
                path: "/etc/facelock/facelock.key".into()
            }
            .localized(),
            "  Encryption key already exists at /etc/facelock/facelock.key."
        );
        assert_eq!(
            GeneratingKeyfile.localized(),
            "  Generating encryption key..."
        );
        assert_eq!(
            KeyfileWritten {
                path: "/etc/facelock/facelock.key".into()
            }
            .localized(),
            "  Key written to /etc/facelock/facelock.key (permissions: 0600)."
        );
        assert_eq!(
            EncryptionEnabledKeyfile.localized(),
            "  Encryption enabled."
        );
        assert_eq!(
            EncryptionDisabledWarning.localized(),
            "  \u{26a0} WARNING: encryption disabled (--encryption=none).\n    Biometric templates will be stored UNENCRYPTED in the database.\n    `facelock enroll` refuses to write plaintext embeddings unless\n    security.allow_plaintext is also set in the config."
        );

        // -- encryption, the non-interactive auto policy --
        assert_eq!(
            EncryptionAlreadyConfigured {
                method: "Tpm".into()
            }
            .localized(),
            "  Encryption already configured (Tpm)."
        );
        assert_eq!(
            GeneratedTpmKeyAt {
                path: "/etc/facelock/sealed.key".into()
            }
            .localized(),
            "  [ok] Generated TPM-sealed encryption key at /etc/facelock/sealed.key"
        );
        assert_eq!(
            EncryptionEnabledTpmAuto.localized(),
            "  [ok] AES-256-GCM encryption enabled (TPM-sealed key)."
        );
        assert_eq!(
            GeneratedKeyfileAt {
                path: "/etc/facelock/facelock.key".into()
            }
            .localized(),
            "  [ok] Generated encryption key at /etc/facelock/facelock.key"
        );
        assert_eq!(
            EncryptionEnabledKeyfileAuto.localized(),
            "  [ok] AES-256-GCM encryption enabled."
        );

        // -- the orphaned-template guard --
        assert_eq!(
            OrphanModelsWarning {
                db_path: "/var/lib/facelock/facelock.db".into()
            }
            .localized(),
            "\n  WARNING: encrypted face models already exist in /var/lib/facelock/facelock.db but the\n  encryption key is missing. Generating a new key would make them unreadable.\n"
        );
        assert_eq!(
            OrphanModelsRemoved { count: 3 }.localized(),
            "  Removed 3 orphaned model(s)."
        );

        // -- hyprlock handoff --
        assert_eq!(
            HyprlockHint.localized(),
            "\n==> To finish hyprlock integration, run as your normal user:\n==>     facelock hyprlock enable"
        );
        assert_eq!(
            HyprlockApplied {
                user: "alice".into()
            }
            .localized(),
            "  hyprlock integration applied for alice."
        );
    }

    /// The spacer renders as nothing, so the sink's trailing newline is the
    /// whole line — the bytes `println!()` produced.
    ///
    /// It must never reach gettext: `dgettext` answers an empty msgid with
    /// the catalog's metadata header, so a translated build would print the
    /// `.mo` file's `Content-Type` block where a blank line belongs. Under a
    /// real catalog this test would fail if the arm ever grew a
    /// `translate("")`, because the C locale used here returns the msgid.
    #[test]
    fn blank_line_is_empty_and_never_translated() {
        assert_eq!(SetupMessage::BlankLine.localized(), "");
    }
}
