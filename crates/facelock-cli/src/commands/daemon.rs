//! The `facelock daemon` command: process setup for the D-Bus server.
//!
//! The server itself — the `org.facelock.Daemon` service, per-method
//! authorization, capture slot, idle timeout — lives in
//! `facelock_daemon::server` so its authorization layer is integration-
//! testable (D6). This command keeps the process-level concerns: the root
//! check, tracing init, and building the production handler from config
//! (camera resolution, model/EP probes, state layout — all of which lean on
//! CLI-shared modules like `crate::resolved` and `crate::state_layout`).

use std::path::Path;

use facelock_camera::quirks::QuirksDb;
use facelock_camera::{
    Camera, ResolvedCamera, auto_detect_device, is_ir_camera_resolved, validate_device,
};
use facelock_core::config::Config;
use facelock_core::notify::NotifierFactory;
use facelock_daemon::rate_limit::RateLimiter;
use facelock_daemon::server::{ProductionHandler, ProductionRebuild};
use facelock_face::FaceEngine;
use facelock_store::FaceStore;
use tracing::{error, info, warn};

/// Type alias for the camera factory closure.
type CameraFactory = Box<dyn Fn(&Config) -> Result<Camera<'static>, String> + Send + Sync>;

/// Build a new handler from config. Used at startup and for live config reload.
/// Returns the handler and idle_timeout_secs from the loaded config.
fn build_handler(config_path: Option<&str>) -> Result<(ProductionHandler, u64), String> {
    // Deliberate re-read (D7): this is the daemon's config lifecycle — one
    // parse at startup, one per mtime-triggered reload (maybe_reload_handler).
    // Everything downstream consumes the Config held by the handler.
    let config = match config_path {
        Some(p) => Config::load_from(Path::new(p)),
        None => Config::load(),
    };
    let mut config = config.map_err(|e| format!("failed to load config: {e}"))?;

    // Before anything opens the store: the daemon runs as root, so this is
    // where an upgraded install converges on the documented modes. A handful
    // of stat calls in the steady state.
    crate::state_layout::ensure_state_layout(&config).map_err(|e| format!("{e:#}"))?;

    let quirks = QuirksDb::load();

    if config.device.path.is_none() {
        let info = auto_detect_device()
            .map_err(|e| format!("no camera device specified and auto-detection failed: {e}"))?;
        let is_ir = is_ir_camera_resolved(&info, Some(&quirks));
        info!(device = %info.path, name = %info.name, ir = is_ir, "auto-detected camera device");
        config.device.path = Some(info.path);
    }

    let device_path = config.device.path.clone().unwrap();

    // Resolve and interrogate the device once, up front. The resulting caps
    // gate `pre_check` before any camera is opened, and every camera the
    // factory opens carries the same interrogation. Tolerant of a device
    // that cannot be queried: the daemon still starts (auth keeps falling
    // through to password), with non-IR caps and whatever identity sysfs
    // still offers.
    let resolved = match validate_device(&device_path) {
        Ok(info) => {
            let resolved = ResolvedCamera::interrogate(info, &quirks);
            info!(
                device = %device_path,
                ir = resolved.caps.is_ir,
                name = %resolved.info.name,
                "camera device"
            );
            Some(resolved)
        }
        Err(e) => {
            warn!("failed to query device {device_path}: {e}");
            None
        }
    };
    let device_caps = resolved
        .as_ref()
        .map(|r| r.caps.clone())
        .unwrap_or_else(|| facelock_core::types::CameraCaps {
            fingerprint: facelock_camera::device_fingerprint(&device_path),
            ..Default::default()
        });

    // Explicit resolution before construction (D7): name what is missing or
    // misconfigured up front — the engine's load error is opaque about
    // missing model files, and ORT falls back to CPU silently when the
    // configured provider isn't compiled into the installed runtime.
    let models = crate::resolved::ModelFiles::probe(&config);
    if !models.all_present() {
        let missing: Vec<String> = models
            .missing()
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        return Err(format!(
            "model files missing: {} — run 'sudo facelock setup' to download them",
            missing.join(", ")
        ));
    }
    let ep = crate::resolved::ExecutionProviderFact::probe(&config);
    match &ep.status {
        crate::resolved::EpStatus::Available => {
            info!(provider = %ep.configured, "execution provider resolved");
        }
        crate::resolved::EpStatus::NotBuiltIn => {
            warn!(
                provider = %ep.configured,
                "configured execution provider is not built into the installed \
                 ONNX Runtime; inference will fall back to CPU"
            );
        }
        crate::resolved::EpStatus::Unqueryable(e) => {
            warn!("could not query ONNX Runtime for provider availability: {e}");
        }
        // The engine load below fails with the provider registry's error,
        // which names the valid values.
        crate::resolved::EpStatus::UnknownName => {}
    }

    let engine = FaceEngine::load(&config.recognition, Path::new(&config.daemon.model_dir))
        .map_err(|e| format!("failed to load face engine: {e}"))?;

    // `create`: a fresh install with nobody enrolled still needs a store for
    // rate limiting.
    let store = FaceStore::create(Path::new(&config.storage.db_path))
        .map_err(|e| format!("failed to open database: {e}"))?;

    let rate_limiter = RateLimiter::new(
        config.security.rate_limit.max_attempts,
        config.security.rate_limit.window_secs,
    );

    // Device coupling (Plan 02): the interrogated fingerprint rides on the
    // caps, so enroll can record it and auth can require it. Advisory only
    // (model-granularity, spoofable) — see facelock_core::types::DeviceFingerprint.
    info!(
        device = %device_path,
        device_id = %device_caps.fingerprint.canonical(),
        "camera device fingerprint"
    );

    let idle_timeout_secs = config.daemon.idle_timeout_secs;
    let warmup_override = resolved
        .as_ref()
        .and_then(|r| r.quirk.as_ref())
        .and_then(|q| q.warmup_frames);
    let camera_factory: CameraFactory = match resolved {
        // Reuse the startup interrogation for every (re)open, exactly as the
        // startup-captured quirk used to be reused.
        Some(resolved) => Box::new(move |config: &Config| {
            resolved
                .clone()
                .open(&config.device)
                .map_err(|e| e.to_string())
        }),
        // Unqueryable at startup: retry a fresh resolve-and-open per request
        // so a later-appearing device surfaces its own open error (or works).
        None => Box::new(move |config: &Config| {
            Camera::open(&config.device, &QuirksDb::load()).map_err(|e| e.to_string())
        }),
    };
    let handler = facelock_daemon::handler::Handler::new(
        config,
        engine,
        store,
        rate_limiter,
        device_caps,
        Some(camera_factory),
        warmup_override,
    )?;

    Ok((handler, idle_timeout_secs))
}

pub fn run(config_path: Option<String>, notifier_factory: NotifierFactory) -> anyhow::Result<()> {
    crate::ipc_client::require_root("sudo facelock daemon")?;

    // Init tracing (daemon uses its own tracing setup with target=true).
    // See crate::logging's module doc for why this must not build its own
    // fallback filter by hand.
    tracing_subscriber::fmt()
        .with_env_filter(crate::logging::default_env_filter())
        .with_target(true)
        .init();

    info!("facelock daemon starting");

    let (handler, idle_timeout_secs) = match build_handler(config_path.as_deref()) {
        Ok(r) => r,
        Err(e) => {
            error!("{e}");
            std::process::exit(1);
        }
    };

    let config_mtime = std::fs::metadata(facelock_core::paths::config_path())
        .and_then(|m| m.modified())
        .ok();

    // The reload recipe: same builder, no explicit path — `Config::load()`
    // honors the process-level config override `main` set for --config runs.
    let rebuild: ProductionRebuild =
        Box::new(|| build_handler(None).map(|(handler, _idle)| handler));

    facelock_daemon::server::run(
        handler,
        idle_timeout_secs,
        config_mtime,
        Some(rebuild),
        notifier_factory,
    )
    .map_err(Into::into)
}
