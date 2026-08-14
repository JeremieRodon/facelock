use std::time::{Duration, Instant};

use facelock_core::config::{Config, EncryptionMethod};
use facelock_core::ipc::{DaemonRequest, DaemonResponse, PreviewFace};
use facelock_core::traits::{CameraSource, FaceProcessor};
use facelock_core::types::{best_match, zeroize_stored_embeddings};
use facelock_store::FaceStore;
use image::codecs::jpeg::JpegEncoder;
use tracing::{debug, info, warn};

use crate::audit::AuditSource;
use crate::auth;
use crate::enroll;
use crate::rate_limit::RateLimiter;

/// Type alias for the camera factory closure.
type CameraFactory<C> = Box<dyn Fn(&Config) -> Result<C, String> + Send + Sync>;

/// Fallback camera release delay when config value is 0 (shouldn't happen with default).
const CAMERA_DEBOUNCE_FALLBACK: Duration = Duration::from_secs(5);
const JPEG_BUF_CAPACITY: usize = 128 * 1024;

pub struct Handler<C: CameraSource, E: FaceProcessor> {
    pub config: Config,
    pub engine: E,
    pub store: FaceStore,
    pub rate_limiter: RateLimiter,
    pub device_is_ir: bool,
    /// Live camera fingerprint used to couple templates to their enrolling
    /// camera (Plan 02). Computed once at handler build from the resolved device.
    pub device_fingerprint: facelock_core::types::DeviceFingerprint,
    pub shutdown_requested: bool,
    camera: Option<C>,
    camera_factory: Option<CameraFactory<C>>,
    camera_last_used: Instant,
    jpeg_buf: Vec<u8>,
    /// Quirk-overridden warmup frames (takes precedence over config if `Some`).
    warmup_frames_override: Option<u32>,
    #[cfg(feature = "tpm")]
    tpm_sealer: Option<facelock_tpm::TpmSealer>,
    software_sealer: Option<facelock_tpm::SoftwareSealer>,
    /// Why the software sealer could not be initialized for a configured
    /// encryption method. `Some` means enroll must fail CLOSED rather than
    /// silently downgrade to plaintext biometric storage (auth is unaffected).
    sealer_init_error: Option<String>,
}

impl<C: CameraSource, E: FaceProcessor> Handler<C, E> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Config,
        engine: E,
        store: FaceStore,
        rate_limiter: RateLimiter,
        device_is_ir: bool,
        device_fingerprint: facelock_core::types::DeviceFingerprint,
        camera_factory: Option<CameraFactory<C>>,
        warmup_frames_override: Option<u32>,
    ) -> Result<Self, String> {
        #[cfg(feature = "tpm")]
        let tpm_sealer = if config.tpm.seal_database {
            match facelock_tpm::TpmSealer::new(&config.tpm.tcti) {
                Ok(sealer) => {
                    info!("TPM sealer initialized for seal_database");
                    Some(sealer)
                }
                Err(e) => {
                    warn!("failed to initialize TPM sealer: {e}");
                    None
                }
            }
        } else {
            None
        };

        // Initialize software sealer based on encryption method. On failure for a
        // method that requires encryption, we record `sealer_init_error` and leave
        // the sealer `None` so ENROLL can fail closed (see `handle`). We do NOT
        // fail the whole handler here: that would take the daemon down and block
        // the auth path, which must keep falling through to password as before.
        let mut sealer_init_error: Option<String> = None;
        let software_sealer = match config.encryption.method {
            EncryptionMethod::Keyfile => {
                let key_path = std::path::Path::new(&config.encryption.key_path);
                // Encrypt-by-default (finding #8): auto-generate the key on first
                // use so a keyfile default actually encrypts. Safe — if a key was
                // lost, any prior encrypted rows were already unreadable, and a new
                // key only affects future writes; plaintext rows stay readable.
                if !key_path.exists() {
                    match facelock_tpm::SoftwareSealer::generate_key_file(key_path) {
                        Ok(()) => info!(
                            "generated encryption key at {} (encrypt-by-default)",
                            key_path.display()
                        ),
                        // Not necessarily fatal on its own; the read-back below is
                        // the authoritative check for whether encryption works.
                        Err(e) => warn!(
                            "failed to auto-generate encryption key at {}: {e}",
                            key_path.display()
                        ),
                    }
                }
                match facelock_tpm::SoftwareSealer::from_key_file(key_path) {
                    Ok(sealer) => {
                        info!(
                            "software encryption sealer initialized from {}",
                            key_path.display()
                        );
                        Some(sealer)
                    }
                    Err(e) => {
                        // Fail CLOSED on enroll: record the cause so `handle`
                        // refuses to enroll rather than silently storing the
                        // biometric template as plaintext (finding: silent
                        // plaintext downgrade).
                        let msg = format!(
                            "{} keyfile could not be created/read: {e}",
                            key_path.display()
                        );
                        warn!(
                            "software encryption sealer unavailable — enroll will be refused: {msg}"
                        );
                        sealer_init_error = Some(msg);
                        None
                    }
                }
            }
            EncryptionMethod::Tpm => {
                #[cfg(feature = "tpm")]
                {
                    let sealed_path = std::path::Path::new(&config.encryption.sealed_key_path);
                    let mut tpm = facelock_tpm::TpmSealer::new(&config.tpm.tcti)
                        .map_err(|e| format!("TPM initialization failed: {e}"))?;
                    let key = tpm.unseal_key_from_file(sealed_path).map_err(|e| {
                        format!(
                            "failed to unseal AES key from {}: {e}",
                            sealed_path.display()
                        )
                    })?;
                    info!("AES key unsealed from TPM ({})", sealed_path.display());
                    Some(facelock_tpm::SoftwareSealer::from_key(key))
                }
                #[cfg(not(feature = "tpm"))]
                {
                    return Err(
                        "encryption method is 'tpm' but TPM support is not compiled in \
                         (rebuild with --features tpm)"
                            .into(),
                    );
                }
            }
            EncryptionMethod::None => None,
        };

        Ok(Self {
            config,
            engine,
            store,
            rate_limiter,
            device_is_ir,
            device_fingerprint,
            shutdown_requested: false,
            camera: None,
            camera_factory,
            camera_last_used: Instant::now(),
            jpeg_buf: Vec::with_capacity(JPEG_BUF_CAPACITY),
            warmup_frames_override,
            #[cfg(feature = "tpm")]
            tpm_sealer,
            software_sealer,
            sealer_init_error,
        })
    }

    pub fn maybe_release_camera(&mut self) {
        let debounce = if self.config.device.camera_release_secs > 0 {
            Duration::from_secs(self.config.device.camera_release_secs as u64)
        } else {
            CAMERA_DEBOUNCE_FALLBACK
        };
        if self.camera.is_some() && self.camera_last_used.elapsed() > debounce {
            debug!("releasing camera (debounce)");
            self.camera = None;
        }
    }

    fn acquire_camera(&mut self) -> Result<(), DaemonResponse> {
        if self.camera.is_none() {
            debug!("opening camera");
            if let Some(ref factory) = self.camera_factory {
                let mut cam = factory(&self.config).map_err(|e| DaemonResponse::Error {
                    message: format!("failed to open camera: {e}"),
                })?;
                // Discard warmup frames for AGC/AE stabilization.
                // Quirk override takes precedence over config value.
                let warmup = self
                    .warmup_frames_override
                    .unwrap_or(self.config.device.warmup_frames);
                if warmup > 0 {
                    debug!(warmup, "discarding warmup frames");
                    for _ in 0..warmup {
                        let _ = cam.capture();
                    }
                }
                self.camera = Some(cam);
            } else {
                return Err(DaemonResponse::Error {
                    message: "no camera available".into(),
                });
            }
        }
        self.camera_last_used = Instant::now();
        Ok(())
    }

    fn release_camera(&mut self) {
        if self.camera.is_some() {
            debug!("releasing camera");
            self.camera = None;
        }
    }

    /// Load user embeddings, decrypting TPM-sealed or software-encrypted blobs.
    /// Falls back to the standard `get_user_embeddings` path when no encryption is active.
    fn load_user_embeddings(
        &mut self,
        user: &str,
    ) -> Result<Vec<(u32, facelock_core::types::FaceEmbedding)>, DaemonResponse> {
        // Check if any encryption is configured that requires raw blob handling
        let needs_raw = self.software_sealer.is_some();
        #[cfg(feature = "tpm")]
        let needs_raw = needs_raw || self.tpm_sealer.is_some();

        if !needs_raw {
            // Fast path: no encryption, use standard method (no overhead)
            return self
                .store
                .get_user_embeddings(user)
                .map_err(|e| DaemonResponse::Error {
                    message: format!("storage error: {e}"),
                });
        }

        // Slow path: load raw blobs (with each template's device id, for opt-in
        // AAD binding) and decrypt as needed.
        let raw_rows = self
            .store
            .get_user_embeddings_raw_with_device(user)
            .map_err(|e| DaemonResponse::Error {
                message: format!("storage error: {e}"),
            })?;

        let mut results = Vec::with_capacity(raw_rows.len());
        for (id, blob, sealed, device_id) in &raw_rows {
            let embedding = if *sealed && facelock_tpm::is_software_encrypted(blob) {
                // Software-encrypted (version byte 0x02)
                let sealer =
                    self.software_sealer
                        .as_ref()
                        .ok_or_else(|| DaemonResponse::Error {
                            message: format!(
                                "embedding {id} is software-encrypted but no key is configured"
                            ),
                        })?;
                // Hard device binding (opt-in): derive AAD from this template's
                // own device id. `None` when disabled — matching enroll.
                let aad = self.config.security.device_aad(device_id.as_deref());
                sealer
                    .unseal_embedding_with_aad(blob, aad.as_deref())
                    .map_err(|e| DaemonResponse::Error {
                        message: format!("software decryption failed for embedding {id}: {e}"),
                    })?
            } else if *sealed {
                // TPM-sealed (version byte 0x01)
                #[cfg(feature = "tpm")]
                {
                    let sealer = self
                        .tpm_sealer
                        .as_mut()
                        .ok_or_else(|| DaemonResponse::Error {
                            message: "TPM-sealed embeddings exist but TPM is not available".into(),
                        })?;
                    sealer
                        .unseal_embedding(blob)
                        .map_err(|e| DaemonResponse::Error {
                            message: format!("TPM unseal failed for embedding {id}: {e}"),
                        })?
                }
                #[cfg(not(feature = "tpm"))]
                {
                    return Err(DaemonResponse::Error {
                        message: format!(
                            "embedding {id} is TPM-sealed but TPM support is not compiled in"
                        ),
                    });
                }
            } else {
                // Plaintext raw embedding
                if blob.len() != 512 * 4 {
                    return Err(DaemonResponse::Error {
                        message: format!(
                            "invalid raw embedding size for id {id}: expected {} bytes, got {}",
                            512 * 4,
                            blob.len()
                        ),
                    });
                }
                let floats: &[f32] = bytemuck::cast_slice(blob);
                let mut emb = [0f32; 512];
                emb.copy_from_slice(floats);
                emb
            };

            results.push((*id, embedding));
        }
        Ok(results)
    }

    pub fn handle(&mut self, request: DaemonRequest) -> DaemonResponse {
        debug!(?request, "handling request");
        match request {
            DaemonRequest::Ping => DaemonResponse::Ok,

            DaemonRequest::Shutdown => {
                info!("shutdown requested via IPC");
                self.release_camera();
                self.shutdown_requested = true;
                DaemonResponse::Ok
            }

            DaemonRequest::ReleaseCamera => {
                self.release_camera();
                DaemonResponse::Ok
            }

            DaemonRequest::Authenticate { user } => self.handle_authenticate(user, true),

            DaemonRequest::Enroll { user, label } => {
                // Refuse to enroll a plaintext template unless explicitly opted in.
                if let Err(message) = self.config.ensure_enroll_encryption_allowed() {
                    warn!(user, "enroll refused: {message}");
                    return DaemonResponse::Error { message };
                }
                // Fail CLOSED: an encryption method is configured but its sealer
                // could not be initialized (e.g. keyfile IO/permission error).
                // Refuse to enroll rather than silently storing the biometric
                // template as plaintext. This is enroll-only — the auth path is
                // untouched and keeps falling through to password as before. The
                // legitimate `method = "none"` + `allow_plaintext` path is handled
                // above and never reaches here (its sealer is intentionally None).
                if self.config.encryption.method != EncryptionMethod::None
                    && self.software_sealer.is_none()
                {
                    let cause = self.sealer_init_error.clone().unwrap_or_else(|| {
                        "the configured encryption sealer could not be initialized".to_string()
                    });
                    let message = format!(
                        "refusing to enroll: {cause}. Storing your face would otherwise fall \
                         back to plaintext. Fix the keyfile path/permissions (or set \
                         encryption.method = \"none\" with security.allow_plaintext = true to \
                         intentionally store plaintext)."
                    );
                    warn!(user, "enroll refused (encryption unavailable): {message}");
                    return DaemonResponse::Error { message };
                }
                if let Err(resp) = self.acquire_camera() {
                    return resp;
                }

                let mut camera = self.camera.take().unwrap();
                let device_id = self.device_fingerprint.canonical_for_storage();
                let result = enroll::enroll(
                    &mut camera,
                    &mut self.engine,
                    &self.store,
                    &self.config,
                    &user,
                    &label,
                    self.software_sealer.as_ref(),
                    device_id.as_deref(),
                );
                self.camera = Some(camera);
                self.camera_last_used = Instant::now();
                result
            }

            DaemonRequest::ListModels { user } => match self.store.list_models(&user) {
                Ok(models) => DaemonResponse::Models(models),
                Err(e) => DaemonResponse::Error {
                    message: format!("storage error: {e}"),
                },
            },

            DaemonRequest::RemoveModel { user, model_id } => {
                match self.store.remove_model(&user, model_id) {
                    Ok(_) => DaemonResponse::Removed,
                    Err(e) => DaemonResponse::Error {
                        message: format!("storage error: {e}"),
                    },
                }
            }

            DaemonRequest::ClearModels { user } => match self.store.clear_user(&user) {
                Ok(_) => DaemonResponse::Removed,
                Err(e) => DaemonResponse::Error {
                    message: format!("storage error: {e}"),
                },
            },

            DaemonRequest::ListDevices => {
                use facelock_camera::{IrSource, QuirksDb, classify_ir_sources, list_devices};
                // Consult the quirks DB so the reported is_ir matches the
                // authoritative decision the auth path makes, with node-level
                // disambiguation for multi-node USB devices.
                let quirks = QuirksDb::load();
                match list_devices() {
                    Ok(devices) => {
                        let sources = classify_ir_sources(&devices, Some(&quirks));
                        DaemonResponse::Devices(
                            devices
                                .iter()
                                .zip(&sources)
                                .map(|(d, source)| facelock_core::ipc::IpcDeviceInfo {
                                    path: d.path.clone(),
                                    name: d.name.clone(),
                                    driver: d.driver.clone(),
                                    is_ir: *source != IrSource::None,
                                    formats: d
                                        .formats
                                        .iter()
                                        .map(|f| facelock_core::ipc::IpcFormatInfo {
                                            fourcc: f.fourcc.clone(),
                                            description: f.description.clone(),
                                            sizes: f.sizes.clone(),
                                        })
                                        .collect(),
                                })
                                .collect(),
                        )
                    }
                    Err(e) => DaemonResponse::Error {
                        message: format!("device enumeration failed: {e}"),
                    },
                }
            }

            DaemonRequest::PreviewFrame => {
                if let Err(resp) = self.acquire_camera() {
                    return resp;
                }
                let camera = self.camera.as_mut().unwrap();
                match camera.capture_rgb_only() {
                    Ok(frame) => self.encode_frame_response(&frame.rgb, frame.width, frame.height),
                    Err(e) => DaemonResponse::Error {
                        message: format!("capture error: {e}"),
                    },
                }
            }

            DaemonRequest::PreviewDetectFrame { user } => {
                if let Err(resp) = self.acquire_camera() {
                    return resp;
                }
                // Take camera for split borrow, put back after
                let mut camera = self.camera.take().unwrap();
                let result = match camera.capture() {
                    Ok(frame) => {
                        let faces = self.detect_and_match(&frame, &user);
                        self.jpeg_buf.clear();
                        let mut encoder = JpegEncoder::new_with_quality(&mut self.jpeg_buf, 60);
                        match encoder.encode(
                            &frame.rgb,
                            frame.width,
                            frame.height,
                            image::ExtendedColorType::Rgb8,
                        ) {
                            Ok(()) => DaemonResponse::DetectFrame {
                                jpeg_data: std::mem::take(&mut self.jpeg_buf),
                                faces,
                            },
                            Err(e) => DaemonResponse::Error {
                                message: format!("JPEG encode error: {e}"),
                            },
                        }
                    }
                    Err(e) => DaemonResponse::Error {
                        message: format!("capture error: {e}"),
                    },
                };
                self.camera = Some(camera);
                result
            }
        }
    }

    /// Run an `Authenticate` request.
    ///
    /// `charge_failed_attempt` controls whether a non-matching result
    /// consumes the shared (SQLite-backed) rate-limit budget for `user`.
    /// `handle()` always passes `true`, preserving real-authentication
    /// behavior exactly.
    ///
    /// The D-Bus layer (`commands/daemon.rs`) passes `false` when the caller
    /// is root (N11, issue #96): `facelock test` is root-only and reaches
    /// the daemon through this same `Authenticate` method, and a failed test
    /// run must not lock the user out of real authentication. This costs
    /// nothing security-wise — root already has unrestricted access to the
    /// rate-limit table directly. `pre_check_audited`'s rate-limit *check*
    /// (whether `user` is already over budget) is unaffected either way: an
    /// already-limited user still sees "rate limited" here regardless of
    /// `charge_failed_attempt`, because that decision is made before this
    /// function knows whether the attempt itself will fail.
    pub fn handle_authenticate(
        &mut self,
        user: String,
        charge_failed_attempt: bool,
    ) -> DaemonResponse {
        if let Some(resp) = auth::pre_check_audited(
            &self.config,
            &self.store,
            &user,
            &self.rate_limiter,
            self.device_is_ir,
            AuditSource::Daemon,
        ) {
            return resp;
        }

        // A storage failure here must surface as an error, never fold into an
        // empty model list (C3, issue #105): empty `models` means an empty
        // device-allowed set, a guaranteed "no match", and a rate-limit charge
        // for an attempt the user never got to make — retries then walk
        // straight into a lockout. Matches what `pre_check` already returns
        // for the same failure class, and runs before the camera is touched.
        let models = match self.store.list_models(&user) {
            Ok(m) => m,
            Err(e) => {
                return DaemonResponse::Error {
                    message: format!("storage error: {e}"),
                };
            }
        };

        if let Err(resp) = self.acquire_camera() {
            return resp;
        }

        // Pre-load and decrypt embeddings (handles TPM + software encryption)
        let mut stored = match self.load_user_embeddings(&user) {
            Ok(s) => s,
            Err(resp) => return resp,
        };

        // Split borrows: take camera out, run auth, put it back
        let mut camera = self.camera.take().unwrap();
        let result = auth::authenticate_with_embeddings(
            &mut camera,
            &mut self.engine,
            &stored,
            &models,
            &self.config,
            &user,
            self.device_is_ir,
            &self.device_fingerprint,
            AuditSource::Daemon,
        );
        // `authenticate_with_embeddings` works on an internal copy;
        // wipe the caller-side plaintext set too (#100).
        zeroize_stored_embeddings(&mut stored);
        self.camera = Some(camera);
        self.camera_last_used = Instant::now();
        // Only failed auths count against the rate limit, and only when the
        // caller hasn't been exempted (see doc comment above).
        if let DaemonResponse::AuthResult(ref mr) = result {
            if !mr.matched && charge_failed_attempt {
                if let Err(e) = self.rate_limiter.record_failure(&self.store, &user) {
                    warn!(user, error = %e, "failed to record auth failure");
                }
            }
        }
        result
    }

    fn encode_frame_response(&mut self, rgb: &[u8], width: u32, height: u32) -> DaemonResponse {
        self.jpeg_buf.clear();
        let mut encoder = JpegEncoder::new_with_quality(&mut self.jpeg_buf, 60);
        match encoder.encode(rgb, width, height, image::ExtendedColorType::Rgb8) {
            Ok(()) => DaemonResponse::Frame {
                jpeg_data: std::mem::take(&mut self.jpeg_buf),
            },
            Err(e) => DaemonResponse::Error {
                message: format!("JPEG encode error: {e}"),
            },
        }
    }

    fn detect_and_match(
        &mut self,
        frame: &facelock_core::types::Frame,
        user: &str,
    ) -> Vec<PreviewFace> {
        let detections = match self.engine.process(frame) {
            Ok(d) => d,
            Err(e) => {
                debug!("face engine error during preview: {e}");
                return Vec::new();
            }
        };

        let stored = self.load_user_embeddings(user).unwrap_or_default();
        let threshold = self.config.recognition.threshold;

        detections
            .into_iter()
            .map(|(det, embedding)| {
                let (best_sim, _) = best_match(&embedding, &stored);
                PreviewFace {
                    x: det.bbox.x,
                    y: det.bbox.y,
                    width: det.bbox.width,
                    height: det.bbox.height,
                    confidence: det.confidence,
                    similarity: best_sim,
                    recognized: best_sim >= threshold,
                }
            })
            .collect()
    }
}
