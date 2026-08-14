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
    Camera, ResolvedCamera, auto_detect_device_with, is_ir_camera_resolved, validate_device,
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
///
/// Which file that is comes from `Config::load()` — i.e. from the
/// process-level config override `run` installs — and from nowhere else.
/// This used to take an explicit path for the startup call while the reload
/// recipe passed `None`; the two agreed only because `main` sets the
/// override too. A caller that set one without the other would have started
/// on one file and reloaded from another, silently. One source of truth
/// makes that unrepresentable, and it is the same one `server`'s mtime watch
/// stats (`paths::config_path()`).
fn build_handler() -> Result<(ProductionHandler, u64), String> {
    // Deliberate re-read (D7): this is the daemon's config lifecycle — one
    // parse at startup, one per mtime-triggered reload (maybe_reload_handler).
    // Everything downstream consumes the Config held by the handler.
    let mut config = Config::load().map_err(|e| format!("failed to load config: {e}"))?;

    // Before anything opens the store: the daemon runs as root, so this is
    // where an upgraded install converges on the documented modes. A handful
    // of stat calls in the steady state.
    crate::state_layout::ensure_state_layout(&config).map_err(|e| format!("{e:#}"))?;

    let quirks = QuirksDb::load();

    if config.device.path.is_none() {
        // The DB loaded above, not a second load: the quirk set that picks the
        // device must be the one that then classifies it.
        let info = auto_detect_device_with(&quirks)
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
        .unwrap_or_else(|| {
            facelock_core::types::CameraCaps::unqueryable(facelock_camera::device_fingerprint(
                &device_path,
            ))
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
    // Resolve and interrogate afresh on every (re)open rather than replaying
    // the startup interrogation. Replaying it would let a device swapped in at
    // the same /dev/videoN after startup inherit the startup device's `is_ir`
    // and fingerprint — caps it never demonstrated — which is exactly the
    // invariant `ResolvedCamera` exists to hold: the caps a camera carries are
    // the caps that camera showed. Reopens happen at idle-timeout frequency,
    // not per frame, so the extra interrogation is not on the hot path. A
    // device that is unqueryable at startup gets the same treatment, and so
    // still surfaces its own open error (or works) if it appears later.
    let camera_factory: CameraFactory = Box::new(move |config: &Config| {
        Camera::open(&config.device, &QuirksDb::load()).map_err(|e| e.to_string())
    });
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

/// `--config` is honored through the process-level override `main` installs
/// before dispatch, which is what `Config::load()` and
/// `paths::config_path()` both read — so startup, the live reload and the
/// mtime watch cannot disagree about which file is the config.
pub fn run(notifier_factory: NotifierFactory) -> anyhow::Result<()> {
    crate::ipc_client::require_root("sudo facelock daemon")?;

    // Init tracing (daemon uses its own tracing setup with target=true).
    // See crate::logging's module doc for why this must not build its own
    // fallback filter by hand.
    tracing_subscriber::fmt()
        .with_env_filter(crate::logging::default_env_filter())
        .with_target(true)
        .init();

    info!("facelock daemon starting");

    let (handler, idle_timeout_secs) = match build_handler() {
        Ok(r) => r,
        Err(e) => {
            error!("{e}");
            std::process::exit(1);
        }
    };

    let config_mtime = std::fs::metadata(facelock_core::paths::config_path())
        .and_then(|m| m.modified())
        .ok();

    // The reload recipe: the same builder reading the same file.
    let rebuild: ProductionRebuild = Box::new(|| build_handler().map(|(handler, _idle)| handler));

    facelock_daemon::server::run(
        handler,
        idle_timeout_secs,
        config_mtime,
        Some(rebuild),
        notifier_factory,
    )
    .map_err(Into::into)
}
