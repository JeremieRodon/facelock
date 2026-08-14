//! The Messages seam (D10): user-facing text as typed events.
//!
//! [`UserMessage`] is a vocabulary of things the CLI wants to tell a human —
//! events carrying data, not strings. Rendering happens at the edge, per sink:
//!
//! - [`UserMessage::localized`] — gettext-translated text for a human
//!   (terminal via [`Terminal`], desktop notification bodies, `anyhow` errors
//!   whose `Display` lands on stderr via [`fail`]).
//! - [`UserMessage::machine`] — a C-locale, locale-independent event line for
//!   machine sinks (tracing today; `audit.jsonl` when a message ever needs to
//!   be recorded as well as shown).
//!
//! This is how D2 ("logs stay English") holds *by construction*: a message
//! routed through this type cannot reach a log sink in translated form,
//! because the log rendering never consults gettext. The boundary is the
//! sink, not the string — `bail!` text a human reads on stderr localizes,
//! the same event written to audit/syslog/tracing does not.
//!
//! # Adding a message (the conversion pattern)
//!
//! 1. Add a variant carrying the data (not the formatted string):
//!    `EnrollComplete { model_id: u32, count: u32, label: String }`.
//! 2. Add one arm to [`UserMessage::localized`]. The English template is the
//!    msgid: keep it on a **single source line** with explicit `\n` escapes
//!    (no `\`-continuations, no raw strings) so `just pot` can extract it,
//!    and use **named placeholders** (`{user}`) filled via [`fill`] so
//!    translators can reorder them. Pre-format numbers that need precision
//!    (`format!("{similarity:.2}")`) before filling — Rust formatting is
//!    locale-independent, so numbers stay stable across locales.
//! 3. Replace the `println!`/`eprintln!`/`bail!` site with
//!    `Terminal.info(&msg)` / `Terminal.error(&msg)` / `return Err(fail(msg))`.
//!
//! The English fallback (no `.mo` installed, or the C locale) renders
//! byte-identically to the string the call site used to print; container
//! tests that grep CLI output rely on this.
//!
//! # What must NOT come through here
//!
//! Machine-facing output never localizes: `--json` output, `is-enrolled`'s
//! stdout contract, `audit.jsonl`, syslog/tracing lines, and D-Bus error
//! strings (PAM substring-matches those on the wire — see
//! `pam_code_for_daemon_error` in `pam-facelock`). Route none of them
//! through [`UserMessage::localized`].
//!
//! # Why this lives in `facelock-cli`
//!
//! The two decided constraints (domain map §7): gettext everywhere (D1, via
//! the same ~20-line libc FFI the PAM module uses — `pam_facelock` keeps its
//! own copy and its own text domain), and logs stay English (D2). No non-CLI
//! crate renders user text today, and `facelock-core`'s dependency contract
//! excludes libc — when the daemon D-Bus server moves out of this crate
//! (H7), the seam moves with it or into core alongside that work.

use std::ffi::{CStr, CString};

use facelock_core::notify::NotifyEvent;

// ---------------------------------------------------------------------------
// Gettext (libc FFI) — the CLI's copy of pam-facelock's wrapper, domain
// "facelock". Kept dependency-free on purpose: gettext ships in glibc.
// ---------------------------------------------------------------------------

/// Text domain for CLI translations (`/usr/share/locale/<lang>/LC_MESSAGES/facelock.mo`).
const GETTEXT_DOMAIN: &CStr = c"facelock";

unsafe extern "C" {
    safe fn dgettext(
        domainname: *const libc::c_char,
        msgid: *const libc::c_char,
    ) -> *const libc::c_char;
    safe fn bindtextdomain(
        domainname: *const libc::c_char,
        dirname: *const libc::c_char,
    ) -> *const libc::c_char;
    safe fn bind_textdomain_codeset(
        domainname: *const libc::c_char,
        codeset: *const libc::c_char,
    ) -> *const libc::c_char;
    safe fn setlocale(category: libc::c_int, locale: *const libc::c_char) -> *const libc::c_char;
}

/// Initialize localization for this process. Call once, early in `main`.
///
/// Sets LC_MESSAGES (only) from the environment: translations follow the
/// user's locale without letting LC_NUMERIC and friends leak into in-process
/// C libraries (ONNX Runtime parses floats). Output charset is pinned to
/// UTF-8 regardless of LC_CTYPE. `FACELOCK_LOCALEDIR` overrides the catalog
/// directory — translations only, English fallback otherwise, so it grants
/// nothing security-relevant.
pub fn init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        setlocale(libc::LC_MESSAGES, c"".as_ptr());
        let dir =
            std::env::var("FACELOCK_LOCALEDIR").unwrap_or_else(|_| "/usr/share/locale".to_string());
        if let Ok(c_dir) = CString::new(dir) {
            bindtextdomain(GETTEXT_DOMAIN.as_ptr(), c_dir.as_ptr());
        }
        bind_textdomain_codeset(GETTEXT_DOMAIN.as_ptr(), c"UTF-8".as_ptr());
    });
}

/// Translate a msgid via gettext. Falls back to the original English string
/// if no translation is available or if gettext fails.
///
/// This is the xgettext extraction keyword (`just pot` scans for
/// `translate("...")`), so every call must pass a string literal.
fn translate(msgid: &str) -> String {
    let Ok(c_msgid) = CString::new(msgid) else {
        return msgid.to_string();
    };
    let result = dgettext(GETTEXT_DOMAIN.as_ptr(), c_msgid.as_ptr());
    if result.is_null() {
        return msgid.to_string();
    }
    unsafe { CStr::from_ptr(result) }
        .to_str()
        .unwrap_or(msgid)
        .to_string()
}

/// Substitute named placeholders (`{user}`) in a translated template.
///
/// Values are substituted in order; a value that itself contains a later
/// placeholder token would be re-substituted, so keep placeholder names
/// unlikely to occur in data (they are).
fn fill(template: String, args: &[(&str, String)]) -> String {
    let mut out = template;
    for (name, value) in args {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}

// ---------------------------------------------------------------------------
// The vocabulary
// ---------------------------------------------------------------------------

/// Something the CLI wants to tell a human. Data only — rendering is the
/// sink's job ([`UserMessage::localized`] / [`UserMessage::machine`]).
///
/// Variant and field names are a stable contract: [`UserMessage::machine`]
/// derives its event line from them.
#[derive(Debug, Clone, PartialEq)]
pub enum UserMessage {
    // -- config load (ConfigLoad::require, D7) --
    NoConfigFile {
        path: String,
    },
    InvalidConfig {
        path: String,
        error: String,
    },

    // -- privilege / access (ipc_client) --
    RootRequired {
        hint: String,
    },
    SudoReexecPrompt,
    AccessDeniedRootHint,
    AccessDeniedGroupHint,
    EnrollTimedOutClientSide,

    // -- enroll --
    SetupNotCompleted,
    ConfirmRunSetupNow,
    SetupDidNotComplete,
    RunSetupWhenReady,
    PlaintextEnrollWarning,
    ModelsMissing {
        dir: String,
    },
    StaleEmbedderNote {
        embedder: String,
    },
    Enrolling {
        user: String,
        label: String,
    },
    EnrollLookAtCamera,
    EnrollComplete {
        model_id: u32,
        count: u32,
        label: String,
    },
    TooManyModels {
        user: String,
        count: usize,
    },

    // -- test --
    ModelsNotFoundOfferSetup,
    ConfirmDownloadModels,
    ModelsStillMissingAfterSetup,
    ModelsRequired,
    NoModelsEnrolled {
        user: String,
    },
    RunEnrollFirst,
    NoMatchingEmbedder {
        embedder: String,
    },
    ReenrollHint,
    TestingUser {
        user: String,
    },
    TestLookAtCamera,
    TestMatched {
        similarity: f32,
        seconds: f64,
    },
    TestMatchedModel {
        model_id: u32,
        label: String,
        similarity: f32,
        seconds: f64,
    },
    TestVarianceBlocked {
        similarity: f32,
        seconds: f64,
    },
    TestNoMatch {
        similarity: f32,
        seconds: f64,
    },

    // -- remove / clear --
    ConfirmRemoveModel {
        model_id: u32,
        user: String,
    },
    Cancelled,
    RemovedModel {
        model_id: u32,
        user: String,
    },
    ModelNotFound {
        model_id: u32,
        user: String,
    },
    ConfirmClearAll {
        user: String,
    },
    ClearedModels {
        count: usize,
        user: String,
    },
    AllModelsRemoved {
        user: String,
    },

    // -- desktop/terminal notification bodies (H4's NotifyEvent, rendered) --
    NotifyScanning,
    NotifyWelcome {
        label: String,
    },
    NotifyRecognized {
        similarity: f32,
    },
    NotifyAuthFailed {
        reason: String,
    },

    // -- setup: wizard spine --
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

    // -- setup: step-level failures (error + retry hint, one event) --
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

    // -- setup: camera selection --
    NoVideoDevices,
    AutoSelectedIrCamera {
        path: String,
        name: String,
    },
    AutoSelectedIrCameraPath {
        path: String,
    },
    SelectedCamera {
        path: String,
        name: String,
    },
    SelectedValue {
        value: String,
    },
    PromptSelectCameraDevice,
    AutoCameraNoDevices,
    AutoCameraNoIr {
        listed: String,
        example: String,
    },
    AutoCameraManyIr {
        count: usize,
        listed: String,
    },
    CameraDeviceMissing {
        path: String,
    },

    // -- setup: model quality / inference device --
    PromptSelectModelQuality,
    PromptSelectInferenceDevice,

    // -- setup: model download --
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

    // -- setup: enrollment / test / systemd steps --
    ConfirmEnrollNow,
    EnrollSkipped,
    ConfirmTestRecognition,
    TestSkipped,
    ConfirmDaemonMode,
    SystemdNotDetected,
    SystemdDeclined,
    SystemdSkippedFlag,
    SystemdDeferred,

    // -- setup: group membership --
    CreatingFacelockGroup,
    GroupMembershipNote,
    AlreadyInGroup {
        user: String,
    },
    ConfirmAddToGroup {
        user: String,
    },
    GroupAddSkipped {
        user: String,
    },
    AddedToGroup {
        user: String,
    },

    // -- setup: PAM step --
    PamSkippedFlag {
        dir: String,
    },
    PamModuleMissing {
        path: String,
    },
    ConfiguringPamFor {
        service: String,
    },
    NoPamCandidates {
        dir: String,
    },
    PamLinePreview {
        line: String,
    },
    PromptSelectPamServices,
    PamConfigureFailed {
        service: String,
        error: String,
    },
    NoPamServicesSelected,
    PamFileNotFound {
        path: String,
    },
    PamLineAlreadyPresent {
        path: String,
    },
    PamInsertBeforeAuthHint,
    PamInsertAtTopHint,
    PamModifyPreview {
        path: String,
        line: String,
        hint: String,
        backup: String,
    },
    ConfirmProceed,
    PamSkippedFile {
        path: String,
    },
    PamBackedUp {
        path: String,
        backup: String,
    },
    PamInstalled {
        path: String,
        backup: String,
        service: String,
    },
    PamRemoved {
        path: String,
    },
    PamNoLineFound {
        path: String,
    },
    PamBackupExists {
        path: String,
        backup: String,
    },

    // -- setup: summary --
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

    // -- setup: non-interactive --
    NonInteractivePreparing,
    CheckingModels {
        count: usize,
    },
    SetupCompleteShort,
    SetupCompleteEnroll,
}

impl UserMessage {
    /// Render for a human: gettext at the edge, English fallback
    /// byte-identical to the historical inline string.
    pub fn localized(&self) -> String {
        use UserMessage::*;
        match self {
            NoConfigFile { path } => fill(
                translate("no config file at {path} — run 'sudo facelock setup' to create one"),
                &[("path", path.clone())],
            ),
            InvalidConfig { path, error } => fill(
                translate("invalid config at {path}: {error}"),
                &[("path", path.clone()), ("error", error.clone())],
            ),

            RootRequired { hint } => fill(
                translate("Root required.\n  Run: {hint}"),
                &[("hint", hint.clone())],
            ),
            SudoReexecPrompt => translate("Root required. Re-run with sudo? [Y/n] "),
            AccessDeniedRootHint => translate(
                "Access denied: this operation requires root.\n  Re-run with sudo, or as root.",
            ),
            AccessDeniedGroupHint => translate(
                "Access denied. If you are not in the 'facelock' group, add yourself:\n  sudo usermod -aG facelock $USER\nthen log out and back in (or re-run: sudo facelock setup). Note: some operations require root regardless of group membership.",
            ),
            EnrollTimedOutClientSide => translate(
                "enrollment timed out client-side; the daemon may have completed it — run `facelock list` before retrying",
            ),

            SetupNotCompleted => translate("Setup has not been completed."),
            ConfirmRunSetupNow => translate("Run setup now?"),
            SetupDidNotComplete => translate("Setup did not complete successfully."),
            RunSetupWhenReady => translate("Run 'sudo facelock setup' when ready."),
            PlaintextEnrollWarning => translate(
                "WARNING: encryption.method = \"none\" and security.allow_plaintext = true.\nYour face template will be stored UNENCRYPTED (plaintext biometric data at rest).",
            ),
            ModelsMissing { dir } => fill(
                translate(
                    "Face recognition models not found in {dir}.\nRun `sudo facelock setup` to download them.",
                ),
                &[("dir", dir.clone())],
            ),
            StaleEmbedderNote { embedder } => fill(
                translate(
                    "Note: existing models don't use the configured embedder '{embedder}'.\nOld enrollments will not work with the new embedder. Consider removing them with 'facelock remove'.\n",
                ),
                &[("embedder", embedder.clone())],
            ),
            Enrolling { user, label } => fill(
                translate("Enrolling face for user '{user}' with label '{label}'..."),
                &[("user", user.clone()), ("label", label.clone())],
            ),
            EnrollLookAtCamera => {
                translate("Look at the camera. Slowly turn your head left and right.")
            }
            EnrollComplete {
                model_id,
                count,
                label,
            } => fill(
                translate(
                    "\nFace enrolled successfully!\n  Model ID: {model_id}\n  Embeddings: {count}\n  Label: {label}",
                ),
                &[
                    ("model_id", model_id.to_string()),
                    ("count", count.to_string()),
                    ("label", label.clone()),
                ],
            ),
            TooManyModels { user, count } => fill(
                translate(
                    "\nWarning: user '{user}' has {count} face models. Consider removing old ones with 'facelock remove'.",
                ),
                &[("user", user.clone()), ("count", count.to_string())],
            ),

            ModelsNotFoundOfferSetup => translate("Face recognition models not found."),
            ConfirmDownloadModels => translate("Download models now?"),
            ModelsStillMissingAfterSetup => translate("Models still not found after setup."),
            ModelsRequired => translate("Models required. Run `facelock setup` to download them."),
            NoModelsEnrolled { user } => fill(
                translate("No face models enrolled for user '{user}'."),
                &[("user", user.clone())],
            ),
            RunEnrollFirst => translate("Run 'facelock enroll' to enroll a face first."),
            NoMatchingEmbedder { embedder } => fill(
                translate("Warning: no enrolled models use the configured embedder '{embedder}'."),
                &[("embedder", embedder.clone())],
            ),
            ReenrollHint => translate("Re-enroll with 'facelock enroll' to use the current model."),
            TestingUser { user } => fill(
                translate("Testing face recognition for user '{user}'..."),
                &[("user", user.clone())],
            ),
            TestLookAtCamera => translate("Look at the camera."),
            TestMatched {
                similarity,
                seconds,
            } => fill(
                translate("Matched (similarity: {similarity}) in {seconds}s"),
                &[
                    ("similarity", format!("{similarity:.2}")),
                    ("seconds", format!("{seconds:.2}")),
                ],
            ),
            TestMatchedModel {
                model_id,
                label,
                similarity,
                seconds,
            } => fill(
                translate(
                    "Matched model #{model_id} '{label}' (similarity: {similarity}) in {seconds}s",
                ),
                &[
                    ("model_id", model_id.to_string()),
                    ("label", label.clone()),
                    ("similarity", format!("{similarity:.2}")),
                    ("seconds", format!("{seconds:.2}")),
                ],
            ),
            TestVarianceBlocked {
                similarity,
                seconds,
            } => fill(
                translate(
                    "Face matched (best: {similarity}) but the liveness variance check was not satisfied after {seconds}s — try moving slightly, or tune security.frame_variance_max_similarity",
                ),
                &[
                    ("similarity", format!("{similarity:.2}")),
                    ("seconds", format!("{seconds:.1}")),
                ],
            ),
            TestNoMatch {
                similarity,
                seconds,
            } => fill(
                translate("No match (best: {similarity}) after {seconds}s"),
                &[
                    ("similarity", format!("{similarity:.2}")),
                    ("seconds", format!("{seconds:.1}")),
                ],
            ),

            ConfirmRemoveModel { model_id, user } => fill(
                translate("Remove face model #{model_id} for user '{user}'?"),
                &[("model_id", model_id.to_string()), ("user", user.clone())],
            ),
            Cancelled => translate("Cancelled."),
            RemovedModel { model_id, user } => fill(
                translate("Removed face model #{model_id} for user '{user}'."),
                &[("model_id", model_id.to_string()), ("user", user.clone())],
            ),
            ModelNotFound { model_id, user } => fill(
                translate("Model #{model_id} not found for user '{user}'."),
                &[("model_id", model_id.to_string()), ("user", user.clone())],
            ),
            ConfirmClearAll { user } => fill(
                translate("Remove ALL face models for user '{user}'?"),
                &[("user", user.clone())],
            ),
            ClearedModels { count, user } => fill(
                translate("Removed {count} face model(s) for user '{user}'."),
                &[("count", count.to_string()), ("user", user.clone())],
            ),
            AllModelsRemoved { user } => fill(
                translate("All face models removed for user '{user}'."),
                &[("user", user.clone())],
            ),

            NotifyScanning => translate("Scanning face..."),
            NotifyWelcome { label } => {
                fill(translate("Welcome, {label}"), &[("label", label.clone())])
            }
            NotifyRecognized { similarity } => fill(
                translate("Face recognized ({similarity})"),
                &[("similarity", format!("{similarity:.2}"))],
            ),
            NotifyAuthFailed { reason } => fill(
                translate("Face auth failed: {reason}"),
                &[("reason", reason.clone())],
            ),

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

            ConfirmEnrollNow => translate("Would you like to enroll a face now?"),
            EnrollSkipped => translate("  Skipping face enrollment."),
            ConfirmTestRecognition => translate("Would you like to test recognition?"),
            TestSkipped => translate("  Skipping recognition test."),
            ConfirmDaemonMode => translate("Enable daemon mode with D-Bus activation?"),
            SystemdNotDetected => translate(
                "  systemd not detected. Skipping daemon configuration.\n  Facelock will use oneshot mode for authentication.",
            ),
            SystemdDeclined => {
                translate("  Skipping systemd setup. Facelock will use oneshot mode.")
            }
            SystemdSkippedFlag => translate(
                "  Skipping daemon configuration (--no-systemd).\n  No unit files are written and systemctl is not invoked.",
            ),
            SystemdDeferred => {
                translate("  Answered on the command line; applied once setup finishes.")
            }

            CreatingFacelockGroup => translate("  Creating 'facelock' system group..."),
            GroupMembershipNote => translate(
                "  Note: running daemon commands (preview/test) as a normal user requires\n  membership in the 'facelock' group: sudo usermod -aG facelock <user>",
            ),
            AlreadyInGroup { user } => fill(
                translate("  User '{user}' is already in the 'facelock' group."),
                &[("user", user.clone())],
            ),
            ConfirmAddToGroup { user } => fill(
                translate(
                    "Add user '{user}' to the 'facelock' group? (required to run facelock preview/test without sudo)",
                ),
                &[("user", user.clone())],
            ),
            GroupAddSkipped { user } => fill(
                translate("  Skipped. Add later with: sudo usermod -aG facelock {user}"),
                &[("user", user.clone())],
            ),
            AddedToGroup { user } => fill(
                translate(
                    "  Added '{user}' to the 'facelock' group.\n  NOTE: log out and back in for the new group membership to take effect.",
                ),
                &[("user", user.clone())],
            ),

            PamSkippedFlag { dir } => fill(
                translate(
                    "  Skipping PAM configuration (--no-pam).\n  No file under {dir} is read or modified.",
                ),
                &[("dir", dir.clone())],
            ),
            PamModuleMissing { path } => fill(
                translate(
                    "  PAM module not found at {path}.\n  Install it first, then run: sudo facelock setup --pam",
                ),
                &[("path", path.clone())],
            ),
            ConfiguringPamFor { service } => fill(
                translate("  Configuring PAM for {service}..."),
                &[("service", service.clone())],
            ),
            NoPamCandidates { dir } => fill(
                translate("  No supported PAM service files found in {dir}/."),
                &[("dir", dir.clone())],
            ),
            PamLinePreview { line } => fill(
                translate(
                    "  The following line will be added to each selected /etc/pam.d/<service>:\n\n      {line}\n\n  It is inserted above the first existing 'auth' line. A backup\n  (.facelock-backup) is saved before any change, and you'll be asked\n  to confirm each file individually.\n",
                ),
                &[("line", line.clone())],
            ),
            PromptSelectPamServices => {
                translate("Select services to enable face authentication for")
            }
            PamConfigureFailed { service, error } => fill(
                translate("  Failed to configure {service}: {error}"),
                &[("service", service.clone()), ("error", error.clone())],
            ),
            NoPamServicesSelected => translate("  No PAM services selected."),
            PamFileNotFound { path } => fill(
                translate("PAM service file not found: {path}"),
                &[("path", path.clone())],
            ),
            PamLineAlreadyPresent { path } => fill(
                translate("PAM line already present in {path}. Nothing to do."),
                &[("path", path.clone())],
            ),
            PamInsertBeforeAuthHint => translate("inserted before the first 'auth' line"),
            PamInsertAtTopHint => {
                translate("no 'auth' line found — inserted at the top of the file")
            }
            PamModifyPreview {
                path,
                line,
                hint,
                backup,
            } => fill(
                translate(
                    "\nAbout to modify {path}:\n  + {line}    ({hint})\n  Backup will be saved to: {backup}\n\n(To configure manually instead, add the line above to each service yourself.)",
                ),
                &[
                    ("path", path.clone()),
                    ("line", line.clone()),
                    ("hint", hint.clone()),
                    ("backup", backup.clone()),
                ],
            ),
            ConfirmProceed => translate("Proceed?"),
            PamSkippedFile { path } => {
                fill(translate("Skipped {path}."), &[("path", path.clone())])
            }
            PamBackedUp { path, backup } => fill(
                translate("Backed up {path} -> {backup}"),
                &[("path", path.clone()), ("backup", backup.clone())],
            ),
            PamInstalled {
                path,
                backup,
                service,
            } => fill(
                translate(
                    "Installed facelock PAM line into {path}\n\nTo rollback:\n  sudo cp {backup} {path}\n  # or: sudo facelock setup --pam --remove --service {service}",
                ),
                &[
                    ("path", path.clone()),
                    ("backup", backup.clone()),
                    ("service", service.clone()),
                ],
            ),
            PamRemoved { path } => fill(
                translate("Removed facelock PAM line from {path}"),
                &[("path", path.clone())],
            ),
            PamNoLineFound { path } => fill(
                translate("No facelock PAM line found in {path}. Nothing to remove."),
                &[("path", path.clone())],
            ),
            PamBackupExists { path, backup } => fill(
                translate("Backup exists at {backup}\nTo restore: sudo cp {backup} {path}"),
                &[("path", path.clone()), ("backup", backup.clone())],
            ),

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

    /// Render for a machine sink: the C-locale event line. Derived from the
    /// variant's `Debug` form — variant and field names are the stable
    /// vocabulary, values print locale-independently, and gettext is never
    /// consulted, which is what makes D2 hold by construction.
    pub fn machine(&self) -> String {
        format!("{self:?}")
    }
}

impl From<&NotifyEvent> for UserMessage {
    fn from(event: &NotifyEvent) -> Self {
        match event {
            NotifyEvent::Scanning => UserMessage::NotifyScanning,
            NotifyEvent::Success {
                label: Some(label),
                similarity: _,
            } => UserMessage::NotifyWelcome {
                label: label.clone(),
            },
            NotifyEvent::Success {
                label: None,
                similarity,
            } => UserMessage::NotifyRecognized {
                similarity: *similarity,
            },
            NotifyEvent::Failure { reason } => UserMessage::NotifyAuthFailed {
                reason: reason.clone(),
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

/// The human sink on this terminal. Localized text to stdout/stderr; the
/// same event goes to tracing at debug level in its machine rendering, so
/// `RUST_LOG=facelock=debug` shows the stable C-locale event stream next to
/// whatever the user saw.
pub struct Terminal;

impl Terminal {
    /// Informational message to stdout.
    pub fn info(&self, msg: &UserMessage) {
        tracing::debug!(target: "facelock::message", "{}", msg.machine());
        println!("{}", msg.localized());
    }

    /// Warning/error message to stderr (the process continues).
    pub fn error(&self, msg: &UserMessage) {
        tracing::debug!(target: "facelock::message", "{}", msg.machine());
        eprintln!("{}", msg.localized());
    }

    /// Inline prompt to stderr — no trailing newline; the caller reads the
    /// answer from stdin.
    pub fn prompt(&self, msg: &UserMessage) {
        tracing::debug!(target: "facelock::message", "{}", msg.machine());
        eprint!("{}", msg.localized());
    }

    /// Localized y/N confirmation via the shared stdin reader.
    pub fn confirm(&self, msg: &UserMessage) -> anyhow::Result<bool> {
        tracing::debug!(target: "facelock::message", "{}", msg.machine());
        crate::ipc_client::confirm(&msg.localized())
    }
}

/// An error whose `Display` is destined for a human on stderr (the CLI's
/// `anyhow` exit path) — so it localizes at birth. Never use this for errors
/// that cross the D-Bus wire or land in audit/syslog.
pub fn fail(msg: UserMessage) -> anyhow::Error {
    tracing::debug!(target: "facelock::message", "{}", msg.machine());
    anyhow::anyhow!("{}", msg.localized())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In the test environment no facelock .mo is installed for the C locale,
    /// so `localized()` is the English fallback — these pins are exactly the
    /// bytes the historical inline strings produced (container tests grep
    /// some of them).
    #[test]
    fn english_fallback_is_byte_identical() {
        assert_eq!(
            UserMessage::EnrollComplete {
                model_id: 3,
                count: 12,
                label: "2026-08-14-1".into()
            }
            .localized(),
            "\nFace enrolled successfully!\n  Model ID: 3\n  Embeddings: 12\n  Label: 2026-08-14-1"
        );
        assert_eq!(
            UserMessage::TestNoMatch {
                similarity: 0.5,
                seconds: 1.234
            }
            .localized(),
            "No match (best: 0.50) after 1.2s"
        );
        assert_eq!(
            UserMessage::TestMatchedModel {
                model_id: 7,
                label: "front".into(),
                similarity: 0.876,
                seconds: 0.5
            }
            .localized(),
            "Matched model #7 'front' (similarity: 0.88) in 0.50s"
        );
        assert_eq!(
            UserMessage::NoConfigFile {
                path: "/etc/facelock/config.toml".into()
            }
            .localized(),
            "no config file at /etc/facelock/config.toml — run 'sudo facelock setup' to create one"
        );
        assert_eq!(
            UserMessage::RootRequired {
                hint: "sudo facelock enroll".into()
            }
            .localized(),
            "Root required.\n  Run: sudo facelock enroll"
        );
        assert_eq!(
            UserMessage::ClearedModels {
                count: 2,
                user: "alice".into()
            }
            .localized(),
            "Removed 2 face model(s) for user 'alice'."
        );
    }

    /// Every sample message renders with all placeholders substituted — a
    /// leftover `{name}` means a template/argument mismatch.
    #[test]
    fn no_unfilled_placeholders() {
        for msg in sample_messages() {
            let rendered = msg.localized();
            assert!(
                !rendered.contains('{') && !rendered.contains('}'),
                "unfilled placeholder in {msg:?}: {rendered:?}"
            );
        }
    }

    /// The machine rendering names the variant and its data, and never goes
    /// through gettext — the D2 side of the seam.
    #[test]
    fn machine_rendering_is_the_debug_vocabulary() {
        let msg = UserMessage::EnrollComplete {
            model_id: 3,
            count: 12,
            label: "x".into(),
        };
        let line = msg.machine();
        assert!(line.starts_with("EnrollComplete"), "{line}");
        assert!(line.contains("model_id: 3"), "{line}");
        assert!(line.contains("count: 12"), "{line}");
    }

    /// Unknown msgids fall back to the input string (no catalog installed).
    #[test]
    fn translate_falls_back_to_msgid() {
        assert_eq!(
            translate("facelock test msgid that no catalog contains"),
            "facelock test msgid that no catalog contains"
        );
    }

    #[test]
    fn fill_substitutes_named_placeholders() {
        assert_eq!(
            fill(
                "a {x} b {y} c {x}".to_string(),
                &[("x", "1".to_string()), ("y", "2".to_string())]
            ),
            "a 1 b 2 c 1"
        );
    }

    /// NotifyEvent -> UserMessage mapping mirrors H4's rendering rules:
    /// a labeled success is a welcome, an unlabeled one shows similarity.
    #[test]
    fn notify_event_mapping() {
        assert_eq!(
            UserMessage::from(&NotifyEvent::Scanning),
            UserMessage::NotifyScanning
        );
        assert_eq!(
            UserMessage::from(&NotifyEvent::Success {
                label: Some("Alice".into()),
                similarity: 0.9
            }),
            UserMessage::NotifyWelcome {
                label: "Alice".into()
            }
        );
        assert_eq!(
            UserMessage::from(&NotifyEvent::Success {
                label: None,
                similarity: 0.87
            }),
            UserMessage::NotifyRecognized { similarity: 0.87 }
        );
        assert_eq!(
            UserMessage::from(&NotifyEvent::Failure {
                reason: "no match".into()
            }),
            UserMessage::NotifyAuthFailed {
                reason: "no match".into()
            }
        );
    }

    /// `fail` produces an error whose Display is the localized rendering.
    #[test]
    fn fail_renders_localized_display() {
        let err = fail(UserMessage::ModelsRequired);
        assert_eq!(
            format!("{err}"),
            "Models required. Run `facelock setup` to download them."
        );
    }

    /// Real gettext lookup through a fixture catalog: build a minimal `.mo`
    /// in a tempdir, point the domain at it, and check that `localized()`
    /// translates while `machine()` does not — the D2 seam, exercised
    /// end to end.
    ///
    /// Locale plumbing is process-global, so this test is written to be
    /// harmless to concurrent tests: the fixture translates exactly one
    /// msgid ("Run setup now?"), which no other test pins in English, and
    /// everything is restored on exit. If the environment offers no usable
    /// non-C locale (LANGUAGE is ignored under "C"), the lookup assertions
    /// are skipped; the manual recipe in the module docs of `just pot`
    /// covers that case.
    #[test]
    fn mo_catalog_lookup_translates_localized_but_not_machine() {
        let dir = tempfile::tempdir().unwrap();
        let mo_dir = dir.path().join("xx/LC_MESSAGES");
        std::fs::create_dir_all(&mo_dir).unwrap();
        std::fs::write(
            mo_dir.join("facelock.mo"),
            build_mo(&[("Run setup now?", "XX-RUN-SETUP-NOW")]),
        )
        .unwrap();

        // A non-C locale for LC_MESSAGES, else glibc ignores LANGUAGE.
        let original = setlocale(libc::LC_MESSAGES, std::ptr::null());
        let original: CString = if original.is_null() {
            c"C".to_owned()
        } else {
            unsafe { CStr::from_ptr(original) }.to_owned()
        };
        let usable = [c"en_US.UTF-8", c"en_US.utf8", c"C.UTF-8", c"C.utf8"]
            .into_iter()
            .find(|l| !setlocale(libc::LC_MESSAGES, l.as_ptr()).is_null());
        if usable.is_none() {
            eprintln!("skipping .mo lookup assertions: no usable non-C locale in this environment");
            return;
        }

        // SAFETY: process-global env mutation in a test; restored below.
        unsafe { std::env::set_var("LANGUAGE", "xx") };
        let c_dir = CString::new(dir.path().to_str().unwrap()).unwrap();
        // A fresh binding also invalidates glibc's per-domain catalog cache.
        bindtextdomain(GETTEXT_DOMAIN.as_ptr(), c_dir.as_ptr());
        bind_textdomain_codeset(GETTEXT_DOMAIN.as_ptr(), c"UTF-8".as_ptr());

        let localized = UserMessage::ConfirmRunSetupNow.localized();
        let machine = UserMessage::ConfirmRunSetupNow.machine();
        let missing = translate("facelock msgid absent from the fixture catalog");

        // Restore before asserting so a failure cannot leak state.
        unsafe { std::env::remove_var("LANGUAGE") };
        setlocale(libc::LC_MESSAGES, original.as_ptr());
        bindtextdomain(GETTEXT_DOMAIN.as_ptr(), c"/usr/share/locale".as_ptr());

        assert_eq!(localized, "XX-RUN-SETUP-NOW", "catalog hit must translate");
        assert_eq!(machine, "ConfirmRunSetupNow", "machine rendering must not");
        assert_eq!(
            missing, "facelock msgid absent from the fixture catalog",
            "catalog miss must fall back to the msgid"
        );
    }

    /// Minimal GNU MO encoder: header entry plus the given pairs.
    /// Entries must be sorted by msgid (binary-search format, no hash table).
    fn build_mo(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = vec![(
            Vec::new(),
            b"Content-Type: text/plain; charset=UTF-8\n".to_vec(),
        )];
        entries.extend(
            pairs
                .iter()
                .map(|(id, s)| (id.as_bytes().to_vec(), s.as_bytes().to_vec())),
        );
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let n = entries.len() as u32;
        let orig_table = 28u32;
        let trans_table = orig_table + 8 * n;
        let mut data_off = trans_table + 8 * n;

        // msgids first, then msgstrs, in table order.
        let texts: Vec<&[u8]> = entries
            .iter()
            .map(|(id, _)| id.as_slice())
            .chain(entries.iter().map(|(_, s)| s.as_slice()))
            .collect();
        let mut tables = Vec::new();
        let mut data = Vec::new();
        for text in texts {
            tables.extend((text.len() as u32).to_le_bytes());
            tables.extend(data_off.to_le_bytes());
            data.extend(text);
            data.push(0);
            data_off += text.len() as u32 + 1;
        }

        let mut mo = Vec::new();
        mo.extend(0x950412deu32.to_le_bytes()); // magic
        mo.extend(0u32.to_le_bytes()); // revision
        mo.extend(n.to_le_bytes());
        mo.extend(orig_table.to_le_bytes());
        mo.extend(trans_table.to_le_bytes());
        mo.extend(0u32.to_le_bytes()); // hash size
        mo.extend(0u32.to_le_bytes()); // hash offset
        mo.extend(tables);
        mo.extend(data);
        mo
    }

    /// One constructed value per variant family, for the placeholder sweep.
    fn sample_messages() -> Vec<UserMessage> {
        use UserMessage::*;
        let s = |v: &str| v.to_string();
        vec![
            NoConfigFile { path: s("/p") },
            InvalidConfig {
                path: s("/p"),
                error: s("e"),
            },
            RootRequired { hint: s("h") },
            SudoReexecPrompt,
            AccessDeniedRootHint,
            AccessDeniedGroupHint,
            EnrollTimedOutClientSide,
            SetupNotCompleted,
            ConfirmRunSetupNow,
            SetupDidNotComplete,
            RunSetupWhenReady,
            PlaintextEnrollWarning,
            ModelsMissing { dir: s("/m") },
            StaleEmbedderNote { embedder: s("e") },
            Enrolling {
                user: s("u"),
                label: s("l"),
            },
            EnrollLookAtCamera,
            EnrollComplete {
                model_id: 1,
                count: 2,
                label: s("l"),
            },
            TooManyModels {
                user: s("u"),
                count: 6,
            },
            ModelsNotFoundOfferSetup,
            ConfirmDownloadModels,
            ModelsStillMissingAfterSetup,
            ModelsRequired,
            NoModelsEnrolled { user: s("u") },
            RunEnrollFirst,
            NoMatchingEmbedder { embedder: s("e") },
            ReenrollHint,
            TestingUser { user: s("u") },
            TestLookAtCamera,
            TestMatched {
                similarity: 0.5,
                seconds: 1.0,
            },
            TestMatchedModel {
                model_id: 1,
                label: s("l"),
                similarity: 0.5,
                seconds: 1.0,
            },
            TestVarianceBlocked {
                similarity: 0.5,
                seconds: 1.0,
            },
            TestNoMatch {
                similarity: 0.5,
                seconds: 1.0,
            },
            ConfirmRemoveModel {
                model_id: 1,
                user: s("u"),
            },
            Cancelled,
            RemovedModel {
                model_id: 1,
                user: s("u"),
            },
            ModelNotFound {
                model_id: 1,
                user: s("u"),
            },
            ConfirmClearAll { user: s("u") },
            ClearedModels {
                count: 1,
                user: s("u"),
            },
            AllModelsRemoved { user: s("u") },
            NotifyScanning,
            NotifyWelcome { label: s("l") },
            NotifyRecognized { similarity: 0.5 },
            NotifyAuthFailed { reason: s("r") },
            SetupIntro { version: s("1.0") },
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
            CameraStepFailed {
                error: s("e"),
                current: s("c"),
            },
            ModelQualityStepFailed {
                error: s("e"),
                current: s("c"),
            },
            InferenceStepFailed {
                error: s("e"),
                current: s("c"),
            },
            ModelDownloadStepFailed { error: s("e") },
            EncryptionStepFailed { error: s("e") },
            EnrollStepFailed { error: s("e") },
            TestStepFailed { error: s("e") },
            SystemdStepFailed { error: s("e") },
            GroupStepFailed { error: s("e") },
            PamStepFailed { error: s("e") },
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
            ConfirmEnrollNow,
            EnrollSkipped,
            ConfirmTestRecognition,
            TestSkipped,
            ConfirmDaemonMode,
            SystemdNotDetected,
            SystemdDeclined,
            SystemdSkippedFlag,
            SystemdDeferred,
            CreatingFacelockGroup,
            GroupMembershipNote,
            AlreadyInGroup { user: s("u") },
            ConfirmAddToGroup { user: s("u") },
            GroupAddSkipped { user: s("u") },
            AddedToGroup { user: s("u") },
            PamSkippedFlag { dir: s("/d") },
            PamModuleMissing { path: s("/p") },
            ConfiguringPamFor { service: s("sudo") },
            NoPamCandidates { dir: s("/d") },
            PamLinePreview {
                line: s("auth ..."),
            },
            PromptSelectPamServices,
            PamConfigureFailed {
                service: s("sudo"),
                error: s("e"),
            },
            NoPamServicesSelected,
            PamFileNotFound { path: s("/p") },
            PamLineAlreadyPresent { path: s("/p") },
            PamInsertBeforeAuthHint,
            PamInsertAtTopHint,
            PamModifyPreview {
                path: s("/p"),
                line: s("auth"),
                hint: s("h"),
                backup: s("/b"),
            },
            ConfirmProceed,
            PamSkippedFile { path: s("/p") },
            PamBackedUp {
                path: s("/p"),
                backup: s("/b"),
            },
            PamInstalled {
                path: s("/p"),
                backup: s("/b"),
                service: s("sudo"),
            },
            PamRemoved { path: s("/p") },
            PamNoLineFound { path: s("/p") },
            PamBackupExists {
                path: s("/p"),
                backup: s("/b"),
            },
            SummaryCamera { value: s("v") },
            SummaryModels {
                dir: s("/d"),
                quality: s("q"),
            },
            SummaryInference { value: s("v") },
            SummaryDatabase { value: s("v") },
            SummaryEncryption { value: s("v") },
            SummaryDaemon { status: s("st") },
            DaemonStatusNotConfiguredNoSystemd,
            DaemonStatusDeferred,
            DaemonStatusEnabled,
            DaemonStatusNotConfigured,
            SummaryPam {
                services: s("sudo"),
            },
            SummaryPamSkipped,
            SummaryPamNone,
            SummaryFaceEnrolled,
            SummaryFaceNotEnrolledNoEnroll,
            SummaryFaceNotEnrolled,
            NonInteractivePreparing,
            CheckingModels { count: 2 },
            SetupCompleteShort,
            SetupCompleteEnroll,
        ]
    }
}
