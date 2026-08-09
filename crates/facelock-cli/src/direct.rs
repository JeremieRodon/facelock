//! Direct (daemonless) implementations of CLI operations.
//!
//! Used when daemon is unavailable on D-Bus or `daemon.mode = oneshot`.
//! Opens camera, loads models, and accesses the database directly.

use std::path::Path;

use anyhow::{Context, bail};
use facelock_camera::quirks::QuirksDb;
use facelock_camera::{
    Camera, DeviceInfo, auto_detect_device, is_ir_camera_resolved, list_devices, validate_device,
};
use facelock_core::config::DeviceConfig;
use facelock_core::config::{Config, EncryptionMethod};
use facelock_core::ipc::DaemonResponse;
use facelock_core::types::MatchResult;
use facelock_daemon::audit::AuditSource;
use facelock_face::FaceEngine;
use facelock_store::FaceStore;
use tracing::debug;

pub fn open_store(config: &Config) -> anyhow::Result<FaceStore> {
    FaceStore::open(Path::new(&config.storage.db_path)).context("failed to open database")
}

#[derive(Clone)]
struct ResolvedCameraDevice {
    device: DeviceConfig,
    device_quirk: Option<facelock_camera::quirks::Quirk>,
    device_is_ir: bool,
    device_fingerprint: facelock_core::types::DeviceFingerprint,
}

struct OpenedCamera {
    camera: Camera<'static>,
    device_is_ir: bool,
    device_fingerprint: facelock_core::types::DeviceFingerprint,
}

fn build_resolved_camera_device(
    config: &Config,
    device_info: DeviceInfo,
    quirks: &QuirksDb,
) -> ResolvedCameraDevice {
    let mut device = config.device.clone();
    device.path = Some(device_info.path.clone());

    ResolvedCameraDevice {
        device_fingerprint: facelock_camera::device_fingerprint(&device_info.path),
        device_quirk: quirks.find_match(&device_info).cloned(),
        // Sibling-aware: on multi-node USB cameras only the IR sensor node
        // counts as IR, not every node sharing the quirk's VID:PID.
        device_is_ir: is_ir_camera_resolved(&device_info, Some(quirks)),
        device,
    }
}

fn resolve_camera_device(config: &Config) -> anyhow::Result<ResolvedCameraDevice> {
    let quirks = QuirksDb::load();
    let device_info = match config.device.path.as_deref() {
        Some(path) => validate_device(path)
            .with_context(|| format!("failed to query configured camera {path}"))?,
        None => {
            auto_detect_device().context("no camera device specified and auto-detection failed")?
        }
    };

    Ok(build_resolved_camera_device(config, device_info, &quirks))
}

fn open_camera_context(config: &Config) -> anyhow::Result<OpenedCamera> {
    let resolved = resolve_camera_device(config)?;
    let mut camera = Camera::open(&resolved.device, resolved.device_quirk.as_ref())
        .context("failed to open camera")?;

    // Discard warmup frames for AGC/AE stabilization.
    // Quirk override takes precedence over config value.
    let warmup = resolved
        .device_quirk
        .and_then(|q| q.warmup_frames)
        .unwrap_or(resolved.device.warmup_frames);
    if warmup > 0 {
        debug!(warmup, "discarding warmup frames");
        for _ in 0..warmup {
            let _ = camera.capture();
        }
    }

    Ok(OpenedCamera {
        camera,
        device_is_ir: resolved.device_is_ir,
        device_fingerprint: resolved.device_fingerprint,
    })
}

/// Open camera with quirks support and warmup frame discarding.
pub fn open_camera(config: &Config) -> anyhow::Result<Camera<'static>> {
    Ok(open_camera_context(config)?.camera)
}

pub fn load_engine(config: &Config) -> anyhow::Result<FaceEngine> {
    FaceEngine::load(&config.recognition, Path::new(&config.daemon.model_dir))
        .context("failed to load face engine")
}

/// Direct authentication — returns the full match result (including an
/// internal failure reason when frames matched but a liveness gate blocked).
///
/// This backs `facelock test` only, and it deliberately skips `pre_check`
/// (rate limiting, `require_ir`, SSH/lid abort), so its audit entries are
/// stamped `AuditSource::Test`: a success here is a recognition result, not a
/// policy-approved authentication.
pub fn authenticate(config: &Config, user: &str) -> anyhow::Result<MatchResult> {
    let store = open_store(config)?;

    if !store.has_models(user).context("storage error")? {
        return Ok(MatchResult {
            matched: false,
            model_id: None,
            label: None,
            similarity: 0.0,
            failure_reason: None,
        });
    }

    let OpenedCamera {
        mut camera,
        device_is_ir,
        device_fingerprint,
    } = open_camera_context(config)?;
    let mut engine = load_engine(config)?;

    // Load embeddings with encryption support, matching the daemon handler path.
    let stored = load_user_embeddings(&store, config, user)?;
    let models = store.list_models(user).unwrap_or_default();

    // Shared with daemon mode (crates/facelock-daemon/src/auth.rs). A local copy
    // of this loop previously lived here and silently drifted — do not re-fork it.
    let response = facelock_daemon::auth::authenticate_with_embeddings(
        &mut camera,
        &mut engine,
        &stored,
        &models,
        config,
        user,
        device_is_ir,
        &device_fingerprint,
        AuditSource::Test,
    );

    match response {
        DaemonResponse::AuthResult(result) => Ok(result),
        DaemonResponse::Error { message } => bail!("{message}"),
        _ => bail!("unexpected auth response"),
    }
}

/// Initialize a software sealer based on encryption config.
/// Returns `None` if encryption is disabled.
fn init_software_sealer(config: &Config) -> anyhow::Result<Option<facelock_tpm::SoftwareSealer>> {
    match config.encryption.method {
        EncryptionMethod::Keyfile => {
            let key_path = Path::new(&config.encryption.key_path);
            // Encrypt-by-default (finding #8): generate the key on first use so
            // the keyfile default actually encrypts new templates.
            if !key_path.exists() {
                facelock_tpm::SoftwareSealer::generate_key_file(key_path)
                    .context("failed to auto-generate encryption key")?;
                debug!("generated encryption key at {}", key_path.display());
            }
            Ok(Some(
                facelock_tpm::SoftwareSealer::from_key_file(key_path)
                    .context("failed to initialize software encryption sealer")?,
            ))
        }
        EncryptionMethod::Tpm => {
            #[cfg(feature = "tpm")]
            {
                let sealed_path = Path::new(&config.encryption.sealed_key_path);
                let mut tpm = facelock_tpm::TpmSealer::new(&config.tpm.tcti)
                    .context("TPM initialization failed")?;
                let key = tpm.unseal_key_from_file(sealed_path).with_context(|| {
                    format!("failed to unseal AES key from {}", sealed_path.display())
                })?;
                Ok(Some(facelock_tpm::SoftwareSealer::from_key(key)))
            }
            #[cfg(not(feature = "tpm"))]
            {
                bail!(
                    "encryption method is 'tpm' but TPM support is not compiled in \
                     (rebuild with --features tpm)"
                );
            }
        }
        EncryptionMethod::None => Ok(None),
    }
}

/// Load user embeddings, decrypting software-encrypted or TPM-sealed blobs as needed.
/// Mirrors `Handler::load_user_embeddings` from the daemon path.
pub fn load_user_embeddings(
    store: &FaceStore,
    config: &Config,
    user: &str,
) -> anyhow::Result<Vec<(u32, facelock_core::types::FaceEmbedding)>> {
    let software_sealer = init_software_sealer(config)?;

    // Fast path: no encryption configured
    if software_sealer.is_none() {
        return store
            .get_user_embeddings(user)
            .context("storage error loading embeddings");
    }

    // Slow path: load raw blobs (with device ids for opt-in AAD) and decrypt
    let sealer = software_sealer.unwrap();
    let raw_rows = store
        .get_user_embeddings_raw_with_device(user)
        .context("storage error loading raw embeddings")?;

    let mut results = Vec::with_capacity(raw_rows.len());
    for (id, blob, sealed, device_id) in &raw_rows {
        let embedding = if *sealed && facelock_tpm::is_software_encrypted(blob) {
            let aad = config.security.device_aad(device_id.as_deref());
            sealer
                .unseal_embedding_with_aad(blob, aad.as_deref())
                .with_context(|| format!("software decryption failed for embedding {id}"))?
        } else if *sealed {
            #[cfg(feature = "tpm")]
            {
                bail!(
                    "embedding {id} is TPM-sealed but direct path only supports software encryption — use the daemon"
                );
            }
            #[cfg(not(feature = "tpm"))]
            {
                bail!("embedding {id} is TPM-sealed but TPM support is not compiled in");
            }
        } else {
            // Plaintext raw embedding
            anyhow::ensure!(
                blob.len() == 512 * 4,
                "invalid raw embedding size for id {id}: expected {} bytes, got {}",
                512 * 4,
                blob.len()
            );
            let floats: &[f32] = bytemuck::cast_slice(blob);
            let mut emb = [0f32; 512];
            emb.copy_from_slice(floats);
            emb
        };
        results.push((*id, embedding));
    }
    Ok(results)
}

/// Direct enrollment — returns (model_id, embedding_count).
pub fn enroll(config: &Config, user: &str, label: &str) -> anyhow::Result<(u32, u32)> {
    // Refuse to store a plaintext template unless explicitly opted in.
    config
        .ensure_enroll_encryption_allowed()
        .map_err(|m| anyhow::anyhow!(m))?;

    let store = open_store(config)?;
    let opened = open_camera_context(config)?;
    let device_id = opened.device_fingerprint.canonical_for_storage();
    let mut camera = opened.camera;
    let mut engine = load_engine(config)?;

    // Initialize sealer if encryption is configured
    let software_sealer = init_software_sealer(config)?;

    // Shared with daemon mode (facelock-daemon/src/enroll.rs): same quality
    // gate, angle-diversity check, rejection breakdown, and deadline. A local
    // copy of this loop previously lived here and silently drifted (no
    // quality/diversity gates, no rejection breakdown) — do not re-fork it.
    let response = facelock_daemon::enroll::enroll(
        &mut camera,
        &mut engine,
        &store,
        config,
        user,
        label,
        software_sealer.as_ref(),
        device_id.as_deref(),
    );

    match response {
        DaemonResponse::Enrolled {
            model_id,
            embedding_count,
        } => Ok((model_id, embedding_count)),
        DaemonResponse::Error { message } => bail!("{message}"),
        _ => bail!("unexpected enroll response"),
    }
}

/// Direct device listing (no daemon needed).
pub fn list_devices_direct() -> anyhow::Result<()> {
    let devices = list_devices().context("failed to enumerate devices")?;

    if devices.is_empty() {
        println!("No video devices found.");
        return Ok(());
    }

    // Consult the quirks DB so the displayed [IR] tag matches the authoritative
    // decision the auth path makes (e.g. a quirks `force_ir` camera), with
    // node-level disambiguation for multi-node USB devices.
    let quirks = facelock_camera::QuirksDb::load();
    let sources = facelock_camera::classify_ir_sources(&devices, Some(&quirks));
    println!("Available video devices:\n");
    for (dev, source) in devices.iter().zip(&sources) {
        let ir_tag = if *source != facelock_camera::IrSource::None {
            " [IR]"
        } else {
            ""
        };
        println!("  {}{ir_tag}", dev.path);
        println!("    Name:    {}", dev.name);
        println!("    Driver:  {}", dev.driver);

        if !dev.formats.is_empty() {
            println!("    Formats:");
            for fmt in &dev.formats {
                let sizes: Vec<String> =
                    fmt.sizes.iter().map(|(w, h)| format!("{w}x{h}")).collect();
                println!(
                    "      {} ({}) — {}",
                    fmt.fourcc.trim(),
                    fmt.description,
                    if sizes.is_empty() {
                        "no sizes reported".to_string()
                    } else {
                        sizes.join(", ")
                    }
                );
            }
        }
        println!();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use facelock_camera::FormatInfo;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_config() -> Config {
        Config::parse(
            r#"
[device]
warmup_frames = 2
"#,
        )
        .unwrap()
    }

    fn make_device(path: &str, name: &str, fourcc: &str) -> DeviceInfo {
        DeviceInfo {
            path: path.to_string(),
            name: name.to_string(),
            driver: "uvcvideo".to_string(),
            capabilities: vec!["VIDEO_CAPTURE".to_string()],
            formats: vec![FormatInfo {
                fourcc: fourcc.to_string(),
                description: "Test".to_string(),
                sizes: vec![(640, 480)],
            }],
        }
    }

    fn write_quirks_dir(contents: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("facelock-direct-tests-{unique}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("test.toml"), contents).unwrap();
        dir
    }

    #[test]
    fn auto_detected_device_inherits_quirk_state() {
        let config = test_config();
        let device = make_device("/dev/video2", "Logitech BRIO IR", "MJPG");
        let dir = write_quirks_dir(
            r#"
[[quirk]]
name_pattern = "(?i)brio.*ir"
force_ir = true
warmup_frames = 9
"#,
        );
        let mut quirks = QuirksDb::default();
        quirks.load_dir(&dir);

        let resolved = build_resolved_camera_device(&config, device, &quirks);

        assert_eq!(resolved.device.path.as_deref(), Some("/dev/video2"));
        assert!(resolved.device_is_ir);
        assert_eq!(
            resolved.device_quirk.as_ref().and_then(|q| q.warmup_frames),
            Some(9)
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn unmatched_device_keeps_default_warmup_and_non_ir_state() {
        let config = test_config();
        let device = make_device("/dev/video3", "USB Camera", "MJPG");
        let quirks = QuirksDb::default();

        let resolved = build_resolved_camera_device(&config, device, &quirks);

        assert_eq!(resolved.device.path.as_deref(), Some("/dev/video3"));
        assert_eq!(resolved.device.warmup_frames, 2);
        assert!(!resolved.device_is_ir);
        assert!(resolved.device_quirk.is_none());
    }
}
