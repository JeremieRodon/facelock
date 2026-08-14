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
use facelock_core::traits::{CameraSource, FaceProcessor};
use facelock_core::types::{MatchResult, zeroize_stored_embeddings};
use facelock_daemon::audit::AuditSource;
use facelock_daemon::auth::{PreCheckContext, pre_check_audited_with_context};
use facelock_daemon::rate_limit::RateLimiter;
use facelock_face::FaceEngine;
use facelock_store::{FaceStore, StoreError};
use tracing::debug;

/// Open the face database, applying the state-directory layout first.
///
/// This is the single choke point for every direct-mode store access —
/// `enroll`, `list`, `remove`, `clear`, `test`, `preview` and the marker
/// refresh all arrive here — which is why the layout hook lives at this layer
/// rather than being repeated at each command. `daemon`, `auth` and `setup`
/// keep their own explicit calls: they are cheap, and they document that those
/// three must not depend on some later store access to fix the modes for them.
///
/// A layout failure only means modes could not be set — it cannot change what
/// is read — so it is logged rather than blocking the caller; unprivileged
/// callers hit it constantly.
pub fn open_store(config: &Config) -> anyhow::Result<FaceStore> {
    crate::state_layout::ensure_state_layout_best_effort(config);

    // `create`: first-time `enroll` legitimately brings the database into
    // being here.
    FaceStore::create(Path::new(&config.storage.db_path)).context("failed to open database")
}

/// Like [`open_store`], but never creates: [`StoreError::Absent`] comes back
/// as a value instead of an empty database materializing at the path.
///
/// This is the constructor for guards and reporters — the call shapes that
/// need "fresh install" and "cannot read" to be different answers. The typed
/// error is the point: callers match `Absent` to proceed on "nothing
/// enrolled" and treat every other class as "cannot tell", without sniffing
/// message strings.
pub fn open_store_existing(config: &Config) -> Result<FaceStore, StoreError> {
    crate::state_layout::ensure_state_layout_best_effort(config);
    FaceStore::open_existing(Path::new(&config.storage.db_path))
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
/// This backs `facelock test` only (root-only, N11/issue #96). It runs the
/// same pre-flight gates real authentication does — disabled check,
/// enrollment/`suppress_unknown`, rate-limit *check*, `require_ir` — via
/// `pre_check_audited_with_context`, except SSH/lid abort, which exist to
/// stop an *attacker*'s physical-access shortcuts and are explicitly skipped
/// for `test` via [`PreCheckContext::test`]. A failed attempt here never
/// consumes the shared rate-limit budget: unlike the daemon and oneshot
/// paths, this function simply never calls `RateLimiter::record_failure`.
/// Audit entries are stamped `AuditSource::Test`.
pub fn authenticate(config: &Config, user: &str) -> anyhow::Result<MatchResult> {
    let store = open_store(config)?;

    // Cheap device classification only (no camera I/O), so a pre-check
    // rejection never touches the camera. `open_camera_context` below
    // re-resolves the same device once opening actually proceeds.
    let device_is_ir = resolve_camera_device(config)
        .context("failed to resolve camera device")?
        .device_is_ir;

    let rl = &config.security.rate_limit;
    let rate_limiter = RateLimiter::new(rl.max_attempts, rl.window_secs);

    if let Some(resp) = pre_check_audited_with_context(
        config,
        &store,
        user,
        &rate_limiter,
        device_is_ir,
        AuditSource::Test,
        PreCheckContext::test(),
    ) {
        return match resp {
            DaemonResponse::AuthResult(mr) => Ok(mr),
            // `suppress_unknown` short-circuit: no result to report, same as
            // the plain not-enrolled case below from `test`'s point of view.
            DaemonResponse::Suppressed => Ok(MatchResult {
                matched: false,
                model_id: None,
                label: None,
                similarity: 0.0,
                failure_reason: None,
            }),
            DaemonResponse::Error { message } => bail!("{message}"),
            _ => bail!("unexpected pre-check response"),
        };
    }

    let OpenedCamera {
        mut camera,
        device_is_ir,
        device_fingerprint,
    } = open_camera_context(config)?;
    let mut engine = load_engine(config)?;

    // Load embeddings with encryption support, matching the daemon handler path.
    let mut stored = load_user_embeddings(&store, config, user)?;
    // Same shape as the daemon's `handle_authenticate` (C3): a storage failure
    // is an error, not an empty model list that guarantees "no match". No
    // rate-limit charge exists on this path, but the falsehood is the same.
    let models = store
        .list_models(user)
        .context("storage error listing face models")?;

    // Shared with daemon mode (crates/facelock-daemon/src/auth.rs). A local copy
    // of this loop previously lived here and silently drifted — do not re-fork it.
    let response = authenticate_and_wipe(
        &mut camera,
        &mut engine,
        &mut stored,
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

/// Run the shared camera auth loop, then wipe the caller-side decrypted
/// embeddings (#100). `authenticate_with_embeddings` copies the compare set
/// and zeroizes only its own copies, so without this the plaintext templates
/// passed in would outlive authentication in the caller's memory.
#[allow(clippy::too_many_arguments)]
pub fn authenticate_and_wipe<C: CameraSource, E: FaceProcessor>(
    camera: &mut C,
    engine: &mut E,
    stored: &mut [(u32, facelock_core::types::FaceEmbedding)],
    models: &[facelock_core::types::FaceModelInfo],
    config: &Config,
    user: &str,
    device_is_ir: bool,
    live_fingerprint: &facelock_core::types::DeviceFingerprint,
    source: AuditSource,
) -> DaemonResponse {
    let response = facelock_daemon::auth::authenticate_with_embeddings(
        camera,
        engine,
        stored,
        models,
        config,
        user,
        device_is_ir,
        live_fingerprint,
        source,
    );
    zeroize_stored_embeddings(stored);
    response
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

/// Load user embeddings, decrypting software-encrypted or TPM-sealed blobs as
/// needed. Mirrors `Handler::load_user_embeddings` from the daemon path,
/// including directly TPM-sealed rows (version byte 0x01/0x03) written when
/// `tpm.seal_database` is enabled — previously those failed here, which broke
/// `bench`, `preview --text-only`, `test` and oneshot on sealed stores (B3).
pub fn load_user_embeddings(
    store: &FaceStore,
    config: &Config,
    user: &str,
) -> anyhow::Result<Vec<(u32, facelock_core::types::FaceEmbedding)>> {
    let software_sealer = init_software_sealer(config)?;

    // Fast path: nothing is configured that could have written encrypted rows.
    // `seal_database` forces the raw path even without a software sealer, so a
    // TPM-sealed blob is never misread as a raw embedding.
    if software_sealer.is_none() && !config.tpm.seal_database {
        return store
            .get_user_embeddings(user)
            .context("storage error loading embeddings");
    }

    // Slow path: load raw blobs (with device ids for opt-in AAD) and decrypt
    let raw_rows = store
        .get_user_embeddings_raw_with_device(user)
        .context("storage error loading raw embeddings")?;

    // Connect to the TPM lazily, only when a TPM-sealed row is present.
    let mut tpm_sealer: Option<facelock_tpm::TpmSealer> = None;

    let mut results = Vec::with_capacity(raw_rows.len());
    for (id, blob, sealed, device_id) in &raw_rows {
        let embedding = if *sealed && facelock_tpm::is_software_encrypted(blob) {
            let sealer = software_sealer.as_ref().with_context(|| {
                format!("embedding {id} is software-encrypted but no key is configured")
            })?;
            let aad = config.security.device_aad(device_id.as_deref());
            sealer
                .unseal_embedding_with_aad(blob, aad.as_deref())
                .with_context(|| format!("software decryption failed for embedding {id}"))?
        } else if *sealed {
            // TPM-sealed (version byte 0x01/0x03), matching the daemon at
            // `Handler::load_user_embeddings`. Without the `tpm` feature the
            // passthrough sealer reports a clear "compile with tpm" error
            // instead of misreading the blob.
            let sealer = match tpm_sealer.as_mut() {
                Some(s) => s,
                None => {
                    let s = facelock_tpm::TpmSealer::new(&config.tpm.tcti)
                        .context("TPM initialization failed")?;
                    tpm_sealer.insert(s)
                }
            };
            sealer
                .unseal_embedding(blob)
                .with_context(|| format!("TPM unseal failed for embedding {id}"))?
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
        let device = make_device("/dev/video2", "BRIO IR", "GREY");
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

    // --- N8: encrypted-store loading in the direct path ---

    #[test]
    fn load_user_embeddings_decrypts_software_sealed_rows() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("facelock.key");
        let config = Config::parse(&format!(
            "[encryption]\nmethod = \"keyfile\"\nkey_path = \"{}\"\n",
            key_path.display()
        ))
        .unwrap();

        facelock_tpm::SoftwareSealer::generate_key_file(&key_path).unwrap();
        let sealer = facelock_tpm::SoftwareSealer::from_key_file(&key_path).unwrap();
        let emb: facelock_core::types::FaceEmbedding = [0.25; 512];
        let blob = sealer.seal_embedding(&emb).unwrap();

        let store = FaceStore::open_memory().unwrap();
        store
            .add_model_raw("alice", "front", &blob, true, "embedder")
            .unwrap();

        let loaded = load_user_embeddings(&store, &config, "alice").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1, emb);
    }

    /// B3: a TPM-sealed row (version byte 0x01, written under
    /// `tpm.seal_database`) must reach the TPM unseal path — never be misread
    /// as a raw embedding via the fast path. Without the `tpm` feature the
    /// passthrough sealer reports a clear "without TPM support" error; actual
    /// hardware unsealing cannot be asserted in CI and is exercised only on a
    /// machine with a TPM.
    #[cfg(not(feature = "tpm"))]
    #[test]
    fn tpm_sealed_rows_error_clearly_without_tpm_support() {
        let config =
            Config::parse("[encryption]\nmethod = \"none\"\n\n[tpm]\nseal_database = true\n")
                .unwrap();
        let store = FaceStore::open_memory().unwrap();
        let mut blob = vec![0x01u8];
        blob.extend_from_slice(&[0u8; 64]);
        store
            .add_model_raw("alice", "front", &blob, true, "embedder")
            .unwrap();

        let err = load_user_embeddings(&store, &config, "alice").unwrap_err();
        let chain = format!("{err:#}");
        assert!(chain.contains("TPM unseal failed for embedding"), "{chain}");
        assert!(chain.contains("without TPM support"), "{chain}");
    }

    /// `seal_database` forces the raw-row path even with no software sealer;
    /// plaintext rows stored before sealing was enabled must still load.
    #[test]
    fn seal_database_slow_path_still_loads_plaintext_rows() {
        let config =
            Config::parse("[encryption]\nmethod = \"none\"\n\n[tpm]\nseal_database = true\n")
                .unwrap();
        let store = FaceStore::open_memory().unwrap();
        let emb: facelock_core::types::FaceEmbedding = [0.75; 512];
        store.add_model("alice", "front", &emb, "embedder").unwrap();

        let loaded = load_user_embeddings(&store, &config, "alice").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1, emb);
    }

    // --- D11 (#100): caller-side wipe of decrypted embeddings ---

    /// The compare set handed to `authenticate_with_embeddings` is copied
    /// internally and only the copies are zeroized; `authenticate_and_wipe`
    /// must wipe the caller's buffer too. Covers the `facelock auth` and
    /// direct-mode callers, which both go through this helper; the daemon
    /// handler's inline wipe at its call site cannot be black-box asserted
    /// from here.
    #[test]
    fn authenticate_and_wipe_zeroizes_caller_embeddings() {
        use facelock_test_support::{MockCamera, MockFaceEngine, fixtures};

        let emb = fixtures::known_embedding(1);
        let mut camera = MockCamera::bright(64, 64, 4);
        let mut engine = MockFaceEngine::one_face(emb);
        let config = Config::parse(
            r#"
[recognition]
threshold = 0.45
timeout_secs = 2

[security]
require_ir = false
require_frame_variance = false
require_landmark_liveness = false
abort_if_ssh = false
abort_if_lid_closed = false
"#,
        )
        .unwrap();

        let mut stored = vec![(1u32, emb)];
        let models = vec![facelock_core::types::FaceModelInfo {
            id: 1,
            user: "alice".into(),
            label: "front".into(),
            created_at: 0,
            embedder_model: String::new(),
            device_id: None,
        }];
        let fingerprint = facelock_core::types::DeviceFingerprint {
            vid: None,
            pid: None,
            serial: None,
            by_path: None,
        };

        let response = authenticate_and_wipe(
            &mut camera,
            &mut engine,
            &mut stored,
            &models,
            &config,
            "alice",
            false,
            &fingerprint,
            AuditSource::Test,
        );

        assert!(
            matches!(
                response,
                DaemonResponse::AuthResult(MatchResult { matched: true, .. })
            ),
            "auth loop must run to completion: {response:?}"
        );
        for (id, e) in &stored {
            assert!(
                e.iter().all(|&v| v == 0.0),
                "caller-side embedding {id} was not wiped"
            );
        }
    }
}
