use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::paths;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    NotFound(String),
    #[error("parse error: {0}")]
    Parse(String),
    #[error("validation error: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub device: DeviceConfig,
    #[serde(default)]
    pub recognition: RecognitionConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    #[serde(default)]
    pub notification: NotificationConfig,
    #[serde(default)]
    pub snapshots: SnapshotConfig,
    #[serde(default)]
    pub tpm: TpmConfig,
    #[serde(default)]
    pub encryption: EncryptionConfig,
    #[serde(default)]
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default = "default_max_height")]
    pub max_height: u32,
    #[serde(default)]
    pub rotation: u16,
    /// Number of frames to discard after camera open for AGC/AE stabilization.
    #[serde(default = "default_warmup_frames")]
    pub warmup_frames: u32,
    /// Percentage of pixels that must be dark (< dark_pixel_value) to reject a frame.
    /// Range: 0.0 to 1.0. Default: 0.6 (60%).
    #[serde(default = "default_dark_threshold")]
    pub dark_threshold: f32,
    /// Pixel brightness value below which a pixel is considered "dark".
    /// Range: 0-255. Default: 10.
    #[serde(default = "default_dark_pixel_value")]
    pub dark_pixel_value: u8,
    /// Enable IR emitter control. When true, attempts to activate IR LED
    /// emitters when camera opens and deactivate when camera closes.
    /// Most cameras auto-enable emitters during streaming; enable this
    /// only if your camera requires explicit control.
    #[serde(default)]
    pub ir_emitter: bool,
    /// Seconds to keep the camera open after auth before releasing it.
    /// Avoids warmup frame cost on consecutive auths. Default: 5.
    #[serde(default = "default_camera_release_secs")]
    pub camera_release_secs: u32,
}

impl Default for DeviceConfig {
    fn default() -> Self {
        Self {
            path: None,
            max_height: default_max_height(),
            rotation: 0,
            warmup_frames: default_warmup_frames(),
            dark_threshold: default_dark_threshold(),
            dark_pixel_value: default_dark_pixel_value(),
            ir_emitter: false,
            camera_release_secs: default_camera_release_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecognitionConfig {
    #[serde(default = "default_threshold")]
    pub threshold: f32,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u32,
    #[serde(default = "default_confidence")]
    pub detection_confidence: f32,
    #[serde(default = "default_nms")]
    pub nms_threshold: f32,
    #[serde(default = "default_detector_model")]
    pub detector_model: String,
    /// SHA256 for `detector_model` when the model is not covered by the bundled manifest.
    /// Bundled models are verified against their manifest hash at load time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector_sha256: Option<String>,
    #[serde(default = "default_embedder_model")]
    pub embedder_model: String,
    /// SHA256 for `embedder_model` when the model is not covered by the bundled manifest.
    /// Bundled models are verified against their manifest hash at load time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedder_sha256: Option<String>,
    /// ORT execution provider: "cpu", "cuda", "rocm", or "openvino".
    #[serde(default = "default_execution_provider")]
    pub execution_provider: String,
    /// Number of intra-op threads for ORT inference.
    #[serde(default = "default_threads")]
    pub threads: u32,
}

impl Default for RecognitionConfig {
    fn default() -> Self {
        Self {
            threshold: default_threshold(),
            timeout_secs: default_timeout(),
            detection_confidence: default_confidence(),
            nms_threshold: default_nms(),
            detector_model: default_detector_model(),
            detector_sha256: None,
            embedder_model: default_embedder_model(),
            embedder_sha256: None,
            execution_provider: default_execution_provider(),
            threads: default_threads(),
        }
    }
}

/// How the PAM module reaches the face engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DaemonMode {
    /// Connect to a running facelock-daemon via D-Bus system bus.
    #[default]
    Daemon,
    /// Run facelock-auth per PAM call (no daemon needed).
    Oneshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_model_dir")]
    pub model_dir: String,
    #[serde(default)]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub mode: DaemonMode,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            model_dir: default_model_dir(),
            idle_timeout_secs: 0,
            mode: DaemonMode::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_db_path")]
    pub db_path: String,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    #[serde(default)]
    pub disabled: bool,
    #[serde(default = "default_true")]
    pub abort_if_ssh: bool,
    #[serde(default = "default_true")]
    pub abort_if_lid_closed: bool,
    #[serde(default)]
    pub suppress_unknown: bool,
    #[serde(default = "default_true")]
    pub require_ir: bool,
    #[serde(default = "default_true")]
    pub require_frame_variance: bool,
    /// Require landmark movement between frames to pass liveness check.
    #[serde(default)]
    pub require_landmark_liveness: bool,
    /// Minimum pixel displacement to count a landmark as "moving" between frames.
    #[serde(default = "default_landmark_displacement_px")]
    pub landmark_displacement_px: f32,
    /// Number of landmarks (out of 5) that must show movement for liveness.
    #[serde(default = "default_landmark_min_moving")]
    pub landmark_min_moving: u32,
    #[serde(default = "default_min_auth_frames")]
    pub min_auth_frames: u32,
    /// Minimum per-face standard deviation (on the RAW grayscale frame) required
    /// to pass the IR texture check. Flat photos/screens score low in IR; real
    /// skin has micro-texture. Only applied on IR devices. Default 10.0
    /// (docs calibration: flat < 5, real > 15 on raw frames).
    #[serde(default = "default_ir_texture_min_stddev")]
    pub ir_texture_min_stddev: f32,
    /// Maximum consecutive matched-frame cosine similarity allowed by the passive
    /// frame-variance check, evaluated over a sliding window of the most recent
    /// `min_auth_frames` matches. Higher = more permissive. Default 0.985: truly
    /// static input sits ≳0.999, a frozen live human at 0.98–0.995; the default
    /// sits inside the frozen-human band for margin against static replays (a
    /// fully frozen user recovers via the sliding window as soon as they move).
    /// Passive anti-photo only; does not defeat video replay.
    #[serde(default = "default_frame_variance_max_similarity")]
    pub frame_variance_max_similarity: f32,
    /// Couple each enrolled template to the camera that captured it. When true
    /// (default), the auth path skips any template whose enrolling-camera
    /// fingerprint does not match the live camera at `device_match_granularity`,
    /// so a swapped-in camera degrades to password instead of matching.
    ///
    /// Advisory defense-in-depth only: the fingerprint is model-granularity
    /// (VID:PID) and forgeable by a programmable USB device — NOT attestation.
    #[serde(default = "default_true")]
    pub bind_templates_to_device: bool,
    /// How strictly the live camera must match a template's enrolling camera.
    /// `model` (default) compares VID:PID; `unit` also requires a matching
    /// serial (and enrollment refuses `unit` on cameras with no serial).
    #[serde(default)]
    pub device_match_granularity: crate::types::DeviceMatchGranularity,
    /// Allow legacy templates that predate device coupling (NULL `device_id`,
    /// or models enrolled on a camera with no readable USB identity) to
    /// authenticate. Default true (allow-with-warn) so upgrades don't break;
    /// set false to require every template to carry a matching device id.
    #[serde(default = "default_true")]
    pub bind_legacy_templates: bool,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
}

impl SecurityConfig {
    /// Resolve the device-binding policy consumed by the auth compare path.
    pub fn device_binding_policy(&self) -> crate::types::DeviceBindingPolicy {
        crate::types::DeviceBindingPolicy {
            enabled: self.bind_templates_to_device,
            granularity: self.device_match_granularity,
            allow_legacy: self.bind_legacy_templates,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            window_secs: default_window_secs(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            disabled: false,
            abort_if_ssh: true,
            abort_if_lid_closed: true,
            suppress_unknown: false,
            require_ir: true,
            require_frame_variance: true,
            require_landmark_liveness: false,
            landmark_displacement_px: default_landmark_displacement_px(),
            landmark_min_moving: default_landmark_min_moving(),
            min_auth_frames: default_min_auth_frames(),
            ir_texture_min_stddev: default_ir_texture_min_stddev(),
            frame_variance_max_similarity: default_frame_variance_max_similarity(),
            bind_templates_to_device: true,
            device_match_granularity: crate::types::DeviceMatchGranularity::Model,
            bind_legacy_templates: true,
            rate_limit: RateLimitConfig::default(),
        }
    }
}

/// Controls how auth feedback is delivered.
///
/// - `"off"` — no notifications at all
/// - `"terminal"` — PAM conversation text only ("Identifying face...", "Face recognized.")
/// - `"desktop"` — desktop popups only (via D-Bus/notify-send)
/// - `"both"` — terminal text and desktop popups
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NotificationMode {
    Off,
    #[default]
    Terminal,
    Desktop,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    #[serde(default)]
    pub mode: NotificationMode,
    /// Show prompt text/notification when scanning starts ("Identifying face...")
    #[serde(default = "default_true")]
    pub notify_prompt: bool,
    /// Show notification on successful face match
    #[serde(default = "default_true")]
    pub notify_on_success: bool,
    /// Show notification on failed face match
    #[serde(default = "default_true")]
    pub notify_on_failure: bool,
}

impl Default for NotificationConfig {
    fn default() -> Self {
        Self {
            mode: NotificationMode::Terminal,
            notify_prompt: true,
            notify_on_success: true,
            notify_on_failure: false,
        }
    }
}

impl NotificationConfig {
    /// Whether terminal text (PAM conversation) is enabled
    pub fn terminal(&self) -> bool {
        matches!(
            self.mode,
            NotificationMode::Terminal | NotificationMode::Both
        )
    }

    /// Whether desktop popups are enabled
    pub fn desktop(&self) -> bool {
        matches!(
            self.mode,
            NotificationMode::Desktop | NotificationMode::Both
        )
    }
}

/// When to save camera snapshots.
///
/// - `"off"` — never save snapshots (default)
/// - `"all"` — save on every auth attempt
/// - `"failure"` — save only on failed auth (debugging false rejects)
/// - `"success"` — save only on successful auth (auditing)
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SnapshotMode {
    #[default]
    Off,
    All,
    Failure,
    Success,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    #[serde(default)]
    pub mode: SnapshotMode,
    #[serde(default = "default_snapshot_dir")]
    pub dir: String,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            mode: SnapshotMode::Off,
            dir: default_snapshot_dir(),
        }
    }
}

impl SnapshotConfig {
    /// Whether snapshots should be saved for a given auth outcome.
    pub fn should_save(&self, success: bool) -> bool {
        match self.mode {
            SnapshotMode::Off => false,
            SnapshotMode::All => true,
            SnapshotMode::Success => success,
            SnapshotMode::Failure => !success,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TpmConfig {
    #[serde(default)]
    pub seal_database: bool,
    #[serde(default)]
    pub pcr_binding: bool,
    #[serde(default = "default_pcr_indices")]
    pub pcr_indices: Vec<u32>,
    #[serde(default = "default_tcti")]
    pub tcti: String,
}

impl Default for TpmConfig {
    fn default() -> Self {
        Self {
            seal_database: false,
            pcr_binding: false,
            pcr_indices: default_pcr_indices(),
            tcti: default_tcti(),
        }
    }
}

/// Method for encrypting face embeddings at rest.
///
/// - `"none"` — no encryption (default, embeddings stored as plaintext)
/// - `"keyfile"` — AES-256-GCM with a key file
/// - `"tpm"` — AES-256-GCM with TPM-sealed key (key sealed by TPM, embeddings encrypted with AES)
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionMethod {
    #[default]
    None,
    Keyfile,
    Tpm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    #[serde(default)]
    pub method: EncryptionMethod,
    /// Path to AES-256-GCM key file for `keyfile` method.
    /// Generated by `facelock setup` or `facelock encrypt --generate-key`.
    #[serde(default = "default_encryption_key_path")]
    pub key_path: String,
    /// Path to TPM-sealed AES key for `tpm` method.
    /// Generated by `facelock setup` or `facelock tpm seal-key`.
    #[serde(default = "default_sealed_key_path")]
    pub sealed_key_path: String,
}

impl Default for EncryptionConfig {
    fn default() -> Self {
        Self {
            method: EncryptionMethod::None,
            key_path: default_encryption_key_path(),
            sealed_key_path: default_sealed_key_path(),
        }
    }
}

// Default value functions
fn default_max_height() -> u32 {
    480
}
fn default_warmup_frames() -> u32 {
    2
}
fn default_dark_threshold() -> f32 {
    0.6
}
fn default_camera_release_secs() -> u32 {
    5
}
fn default_dark_pixel_value() -> u8 {
    10
}
fn default_threshold() -> f32 {
    0.80
}
fn default_timeout() -> u32 {
    5
}
fn default_confidence() -> f32 {
    0.5
}
fn default_nms() -> f32 {
    0.4
}
fn default_model_dir() -> String {
    paths::DEFAULT_MODEL_DIR.to_string()
}
fn default_db_path() -> String {
    paths::DEFAULT_DB_PATH.to_string()
}
fn default_snapshot_dir() -> String {
    paths::DEFAULT_SNAPSHOT_DIR.to_string()
}
fn default_min_auth_frames() -> u32 {
    3
}
fn default_landmark_displacement_px() -> f32 {
    1.5
}
fn default_landmark_min_moving() -> u32 {
    3
}
fn default_ir_texture_min_stddev() -> f32 {
    10.0
}
fn default_frame_variance_max_similarity() -> f32 {
    crate::types::DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY
}
fn default_true() -> bool {
    true
}
fn default_max_attempts() -> u32 {
    5
}
fn default_window_secs() -> u64 {
    60
}
fn default_pcr_indices() -> Vec<u32> {
    vec![0, 1, 2, 3, 7]
}
fn default_tcti() -> String {
    "device:/dev/tpmrm0".to_string()
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Enable structured audit logging to JSONL file.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the audit log file.
    #[serde(default = "default_audit_path")]
    pub path: String,
    /// Maximum log file size in MB before rotation.
    #[serde(default = "default_audit_rotate_size")]
    pub rotate_size_mb: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_audit_path(),
            rotate_size_mb: default_audit_rotate_size(),
        }
    }
}

fn default_audit_path() -> String {
    "/var/log/facelock/audit.jsonl".to_string()
}
fn default_audit_rotate_size() -> u32 {
    10
}
fn default_encryption_key_path() -> String {
    "/etc/facelock/encryption.key".to_string()
}
fn default_sealed_key_path() -> String {
    "/etc/facelock/encryption.key.sealed".to_string()
}
fn default_detector_model() -> String {
    "scrfd_2.5g_bnkps.onnx".to_string()
}
fn default_embedder_model() -> String {
    "w600k_r50.onnx".to_string()
}
fn default_execution_provider() -> String {
    "cpu".to_string()
}
fn default_threads() -> u32 {
    4
}

impl Config {
    /// Load config from the default path (respects `FACELOCK_CONFIG` env var).
    pub fn load() -> Result<Self, ConfigError> {
        let path = paths::config_path();
        Self::load_from(&path)
    }

    /// Load config from a specific path.
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                ConfigError::NotFound(path.display().to_string())
            } else {
                ConfigError::Parse(format!("failed to read {}: {e}", path.display()))
            }
        })?;
        Self::parse(&content)
    }

    /// Parse config from a TOML string.
    pub fn parse(toml_str: &str) -> Result<Self, ConfigError> {
        let config: Config =
            toml::from_str(toml_str).map_err(|e| ConfigError::Parse(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Validate config values.
    fn validate(&self) -> Result<(), ConfigError> {
        // device.path is optional — when None, the daemon auto-detects a camera.
        // If explicitly set, reject empty strings.
        if let Some(ref path) = self.device.path {
            if path.is_empty() {
                return Err(ConfigError::Validation(
                    "device.path must not be empty when specified".into(),
                ));
            }
        }
        if !(0.0..=1.0).contains(&self.device.dark_threshold) {
            return Err(ConfigError::Validation(format!(
                "device.dark_threshold must be between 0.0 and 1.0, got {}",
                self.device.dark_threshold
            )));
        }
        if !(0.0..=1.0).contains(&self.recognition.threshold) {
            return Err(ConfigError::Validation(format!(
                "recognition.threshold must be between 0.0 and 1.0, got {}",
                self.recognition.threshold
            )));
        }
        if !matches!(self.device.rotation, 0 | 90 | 180 | 270) {
            return Err(ConfigError::Validation(format!(
                "device.rotation must be 0, 90, 180, or 270, got {}",
                self.device.rotation
            )));
        }
        if self.recognition.timeout_secs == 0 {
            return Err(ConfigError::Validation(
                "recognition.timeout_secs must be > 0".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.security.frame_variance_max_similarity) {
            return Err(ConfigError::Validation(format!(
                "security.frame_variance_max_similarity must be between 0.0 and 1.0, got {}",
                self.security.frame_variance_max_similarity
            )));
        }
        if self.security.ir_texture_min_stddev < 0.0 {
            return Err(ConfigError::Validation(format!(
                "security.ir_texture_min_stddev must be >= 0.0, got {}",
                self.security.ir_texture_min_stddev
            )));
        }
        if let Some(ref sha256) = self.recognition.detector_sha256
            && !is_sha256_hex(sha256)
        {
            return Err(ConfigError::Validation(format!(
                "recognition.detector_sha256 must be a 64-character hex SHA256, got {}",
                sha256
            )));
        }
        if let Some(ref sha256) = self.recognition.embedder_sha256
            && !is_sha256_hex(sha256)
        {
            return Err(ConfigError::Validation(format!(
                "recognition.embedder_sha256 must be a 64-character hex SHA256, got {}",
                sha256
            )));
        }
        Ok(())
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[device]
path = "/dev/video0"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.device.path.as_deref(), Some("/dev/video0"));
        assert_eq!(config.device.max_height, 480);
        assert_eq!(config.recognition.threshold, 0.80);
        assert!(config.security.require_ir);
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[device]
path = "/dev/video2"
max_height = 720
rotation = 90

[recognition]
threshold = 0.5
timeout_secs = 10
detection_confidence = 0.6
nms_threshold = 0.3

[daemon]
model_dir = "/tmp/models"

[storage]
db_path = "/tmp/test.db"

[security]
disabled = false
require_ir = false
require_frame_variance = true
min_auth_frames = 5

[notification]
mode = "off"

[snapshots]
mode = "all"
dir = "/tmp/snaps"

"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.device.path.as_deref(), Some("/dev/video2"));
        assert_eq!(config.device.max_height, 720);
        assert_eq!(config.device.rotation, 90);
        assert_eq!(config.recognition.threshold, 0.5);
        assert_eq!(config.recognition.timeout_secs, 10);
        assert!(!config.security.require_ir);
        assert_eq!(config.security.min_auth_frames, 5);
    }

    #[test]
    fn reject_empty_device_path() {
        let toml = r#"
[device]
path = ""
"#;
        let err = Config::parse(toml).unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn reject_invalid_threshold() {
        let toml = r#"
[device]
path = "/dev/video0"
[recognition]
threshold = 1.5
"#;
        let err = Config::parse(toml).unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn reject_invalid_rotation() {
        let toml = r#"
[device]
path = "/dev/video0"
rotation = 45
"#;
        let err = Config::parse(toml).unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn reject_zero_timeout() {
        let toml = r#"
[device]
path = "/dev/video0"
[recognition]
timeout_secs = 0
"#;
        let err = Config::parse(toml).unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn missing_optional_sections_uses_defaults() {
        let toml = r#"
[device]
path = "/dev/video0"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.storage.db_path, paths::DEFAULT_DB_PATH);
        assert!(config.security.abort_if_ssh);
        assert_eq!(config.snapshots.mode, SnapshotMode::Off);
    }

    #[test]
    fn recognition_gpu_config_defaults() {
        let toml = r#"
[device]
path = "/dev/video0"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.recognition.execution_provider, "cpu");
        assert_eq!(config.recognition.threads, 4);
    }

    #[test]
    fn recognition_gpu_config_custom() {
        let toml = r#"
[device]
path = "/dev/video0"
[recognition]
execution_provider = "cuda"
threads = 8
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.recognition.execution_provider, "cuda");
        assert_eq!(config.recognition.threads, 8);
    }

    #[test]
    fn recognition_sha256_fields_default_to_none() {
        let config = RecognitionConfig::default();
        assert!(config.detector_sha256.is_none());
        assert!(config.embedder_sha256.is_none());
    }

    #[test]
    fn recognition_sha256_fields_validate_format() {
        let toml = r#"
[device]
path = "/dev/video0"
[recognition]
detector_sha256 = "not-a-sha256"
"#;
        let err = Config::parse(toml).unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn recognition_sha256_fields_accept_valid_hex() {
        let toml = r#"
[device]
path = "/dev/video0"
[recognition]
detector_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
embedder_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(
            config.recognition.detector_sha256.as_deref(),
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        );
        assert_eq!(
            config.recognition.embedder_sha256.as_deref(),
            Some("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        );
    }

    #[test]
    fn recognition_sha256_fields_accept_uppercase_hex() {
        let toml = r#"
[device]
path = "/dev/video0"
[recognition]
detector_sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(
            config.recognition.detector_sha256.as_deref(),
            Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        );
    }

    #[test]
    fn recognition_sha256_validation_message_matches_allowed_format() {
        let toml = r#"
[device]
path = "/dev/video0"
[recognition]
detector_sha256 = "not-a-sha256"
"#;
        let err = Config::parse(toml).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("64-character hex SHA256"));
        assert!(!msg.contains("lowercase"));
    }

    #[test]
    fn parse_no_device_section() {
        let toml = r#"
[recognition]
threshold = 0.5
"#;
        let config = Config::parse(toml).unwrap();
        assert!(config.device.path.is_none());
        assert_eq!(config.device.max_height, 480);
        assert_eq!(config.device.rotation, 0);
    }

    #[test]
    fn parse_device_section_without_path() {
        let toml = r#"
[device]
max_height = 720
"#;
        let config = Config::parse(toml).unwrap();
        assert!(config.device.path.is_none());
        assert_eq!(config.device.max_height, 720);
    }

    #[test]
    fn parse_device_with_explicit_path() {
        let toml = r#"
[device]
path = "/dev/video0"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.device.path.as_deref(), Some("/dev/video0"));
    }

    #[test]
    fn idle_timeout_defaults_to_zero() {
        let toml = r#"
[device]
path = "/dev/video0"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.daemon.idle_timeout_secs, 0);
    }

    #[test]
    fn idle_timeout_parses_custom_value() {
        let toml = r#"
[device]
path = "/dev/video0"
[daemon]
idle_timeout_secs = 300
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.daemon.idle_timeout_secs, 300);
    }

    #[test]
    fn tpm_config_defaults() {
        let toml = r#"
[device]
path = "/dev/video0"
"#;
        let config = Config::parse(toml).unwrap();
        assert!(!config.tpm.seal_database);
        assert!(!config.tpm.pcr_binding);
        assert_eq!(config.tpm.pcr_indices, vec![0, 1, 2, 3, 7]);
        assert_eq!(config.tpm.tcti, "device:/dev/tpmrm0");
    }

    #[test]
    fn warmup_frames_default() {
        let toml = r#"
[device]
path = "/dev/video0"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.device.warmup_frames, 2);
    }

    #[test]
    fn warmup_frames_custom() {
        let toml = r#"
[device]
path = "/dev/video0"
warmup_frames = 10
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.device.warmup_frames, 10);
    }

    #[test]
    fn encryption_config_defaults() {
        let toml = r#"
[device]
path = "/dev/video0"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.encryption.method, super::EncryptionMethod::None);
        assert_eq!(config.encryption.key_path, "/etc/facelock/encryption.key");
    }

    #[test]
    fn audit_config_defaults() {
        let toml = r#"
[device]
path = "/dev/video0"
"#;
        let config = Config::parse(toml).unwrap();
        assert!(!config.audit.enabled);
        assert_eq!(config.audit.path, "/var/log/facelock/audit.jsonl");
        assert_eq!(config.audit.rotate_size_mb, 10);
    }

    #[test]
    fn audit_config_custom() {
        let toml = r#"
[device]
path = "/dev/video0"
[audit]
enabled = true
path = "/var/log/custom/audit.jsonl"
rotate_size_mb = 50
"#;
        let config = Config::parse(toml).unwrap();
        assert!(config.audit.enabled);
        assert_eq!(config.audit.path, "/var/log/custom/audit.jsonl");
        assert_eq!(config.audit.rotate_size_mb, 50);
    }

    #[test]
    fn encryption_config_unknown_method_fails() {
        let toml = r#"
[device]
path = "/dev/video0"
[encryption]
method = "bogus"
"#;
        // Unknown encryption methods should be rejected by serde.
        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn encryption_config_tpm_method() {
        let toml = r#"
[device]
path = "/dev/video0"
[encryption]
method = "tpm"
sealed_key_path = "/etc/facelock/custom.sealed"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.encryption.method, super::EncryptionMethod::Tpm);
        assert_eq!(
            config.encryption.sealed_key_path,
            "/etc/facelock/custom.sealed"
        );
    }

    #[test]
    fn encryption_config_sealed_key_path_default() {
        let toml = r#"
[device]
path = "/dev/video0"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(
            config.encryption.sealed_key_path,
            "/etc/facelock/encryption.key.sealed"
        );
    }

    #[test]
    fn encryption_config_keyfile() {
        let toml = r#"
[device]
path = "/dev/video0"
[encryption]
method = "keyfile"
key_path = "/etc/facelock/my.key"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.encryption.method, super::EncryptionMethod::Keyfile);
        assert_eq!(config.encryption.key_path, "/etc/facelock/my.key");
    }

    #[test]
    fn antispoof_thresholds_default() {
        let toml = r#"
[device]
path = "/dev/video0"
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.security.ir_texture_min_stddev, 10.0);
        assert_eq!(
            config.security.frame_variance_max_similarity,
            crate::types::DEFAULT_FRAME_VARIANCE_MAX_SIMILARITY
        );
    }

    #[test]
    fn antispoof_thresholds_custom() {
        let toml = r#"
[device]
path = "/dev/video0"
[security]
ir_texture_min_stddev = 15.0
frame_variance_max_similarity = 0.95
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.security.ir_texture_min_stddev, 15.0);
        assert_eq!(config.security.frame_variance_max_similarity, 0.95);
    }

    #[test]
    fn reject_out_of_range_frame_variance_max_similarity() {
        let toml = r#"
[device]
path = "/dev/video0"
[security]
frame_variance_max_similarity = 1.5
"#;
        let err = Config::parse(toml).unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn reject_negative_ir_texture_min_stddev() {
        let toml = r#"
[device]
path = "/dev/video0"
[security]
ir_texture_min_stddev = -1.0
"#;
        let err = Config::parse(toml).unwrap_err();
        assert!(matches!(err, ConfigError::Validation(_)));
    }

    #[test]
    fn device_binding_defaults_on_at_model_granularity() {
        let toml = r#"
[device]
path = "/dev/video0"
"#;
        let config = Config::parse(toml).unwrap();
        assert!(config.security.bind_templates_to_device);
        assert_eq!(
            config.security.device_match_granularity,
            crate::types::DeviceMatchGranularity::Model
        );
        assert!(config.security.bind_legacy_templates);

        let policy = config.security.device_binding_policy();
        assert!(policy.enabled);
        assert!(policy.allow_legacy);
        assert_eq!(
            policy.granularity,
            crate::types::DeviceMatchGranularity::Model
        );
    }

    #[test]
    fn device_binding_custom_values_parse() {
        let toml = r#"
[device]
path = "/dev/video0"
[security]
bind_templates_to_device = false
device_match_granularity = "unit"
bind_legacy_templates = false
"#;
        let config = Config::parse(toml).unwrap();
        assert!(!config.security.bind_templates_to_device);
        assert_eq!(
            config.security.device_match_granularity,
            crate::types::DeviceMatchGranularity::Unit
        );
        assert!(!config.security.bind_legacy_templates);
    }

    #[test]
    fn device_match_granularity_rejects_unknown() {
        let toml = r#"
[device]
path = "/dev/video0"
[security]
device_match_granularity = "bogus"
"#;
        assert!(Config::parse(toml).is_err());
    }

    #[test]
    fn warmup_frames_zero() {
        let toml = r#"
[device]
path = "/dev/video0"
warmup_frames = 0
"#;
        let config = Config::parse(toml).unwrap();
        assert_eq!(config.device.warmup_frames, 0);
    }
}
