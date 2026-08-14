//! The `org.facelock.Daemon` D-Bus server: per-method authorization,
//! caller-identity resolution, capture-slot contention control, live config
//! reload, idle timeout, and the serve loop.
//!
//! This lives in the daemon library (not the `facelock` binary) so the
//! authorization layer is reachable from integration tests (D6). Process
//! concerns stay with the binary: the root check, tracing init, and
//! constructing the production handler — the server receives a built handler
//! plus an injected rebuild recipe ([`HandlerRebuild`]) for the live reload.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use facelock_camera::Camera;
use facelock_core::dbus_interface::{
    AuthResult, BUS_NAME, DeviceInfo, ModelInfo, OBJECT_PATH, PreviewFaceInfo,
};
use facelock_core::notify::{Notifier, NotifierFactory, NotifyEvent, notify_desktop_if_enabled};
use facelock_core::traits::{CameraSource, FaceProcessor};
use facelock_face::FaceEngine;
use futures_util::StreamExt;
use nix::unistd::{Uid, User};
use tracing::{error, info, warn};
use zbus::{fdo, interface, object_server::SignalEmitter};

use crate::handler::{AuthIntent, DaemonRequest, DaemonResponse, Handler};

/// Production type alias for the handler with real Camera and FaceEngine.
pub type ProductionHandler = Handler<Camera<'static>, FaceEngine>;

/// Rebuilds the handler from the on-disk config. Injected by the binary
/// (which owns config parsing and handler construction) and invoked by the
/// live config reload when the config file's mtime advances. `None` disables
/// live reload (tests).
pub type HandlerRebuild<C, E> = Box<dyn Fn() -> Result<Handler<C, E>, String> + Send + Sync>;

/// [`HandlerRebuild`] with the production camera and engine.
pub type ProductionRebuild = HandlerRebuild<Camera<'static>, FaceEngine>;

/// Failures bringing up or running the D-Bus server.
#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error(transparent)]
    Bus(#[from] zbus::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Maximum time to wait for the handler mutex before returning a "busy" error.
/// This prevents D-Bus clients from hanging indefinitely if a previous auth
/// call is stuck (e.g., camera blocking on DQBUF).
const HANDLER_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Try to acquire the handler mutex with a timeout.
/// Uses try_lock in a polling loop to avoid blocking the thread indefinitely.
fn lock_handler_with_timeout<H>(
    handler: &Mutex<H>,
) -> std::result::Result<MutexGuard<'_, H>, fdo::Error> {
    let deadline = Instant::now() + HANDLER_LOCK_TIMEOUT;
    let mut waited = false;
    loop {
        match handler.try_lock() {
            Ok(guard) => {
                if waited {
                    warn!("handler lock acquired after waiting");
                }
                return Ok(guard);
            }
            Err(TryLockError::Poisoned(e)) => {
                error!("handler mutex poisoned (previous operation panicked), recovering");
                return Ok(e.into_inner());
            }
            Err(TryLockError::WouldBlock) => {
                if !waited {
                    warn!("handler lock contention — waiting for previous operation");
                    waited = true;
                }
                if Instant::now() >= deadline {
                    error!(
                        "handler lock timeout after {HANDLER_LOCK_TIMEOUT:?} — previous operation is stuck"
                    );
                    return Err(fdo::Error::Failed(
                        "daemon busy: previous operation timed out".into(),
                    ));
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// Tracks whether a camera-capture operation is currently in flight.
///
/// Camera captures serialize on the handler mutex; without this guard a
/// second caller would queue on that mutex for up to `HANDLER_LOCK_TIMEOUT`
/// (10s), letting any authorized caller stall others (local DoS). The slot
/// lets capture methods reject concurrent requests immediately with a
/// "daemon busy" error instead. Callers (PAM, CLI) treat that like any other
/// daemon error and degrade to password auth — never a lockout. Per-user
/// rate limiting is unaffected; this is orthogonal contention control.
#[derive(Debug, Default)]
struct CaptureSlot {
    busy: AtomicBool,
}

impl CaptureSlot {
    /// Try to claim the capture slot. Returns a RAII guard on success, or an
    /// immediate "daemon busy" error if another capture is already in flight.
    fn try_acquire(self: &Arc<Self>, operation: &str) -> fdo::Result<CaptureGuard> {
        if self
            .busy
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            Ok(CaptureGuard(Arc::clone(self)))
        } else {
            warn!(
                operation = operation,
                "capture already in flight — rejecting immediately with busy"
            );
            Err(fdo::Error::Failed(format!(
                "daemon busy: another capture operation is in progress ({operation} rejected)"
            )))
        }
    }
}

/// RAII guard for [`CaptureSlot`]; releases the slot when dropped
/// (including on panic unwind inside a blocking task).
#[derive(Debug)]
struct CaptureGuard(Arc<CaptureSlot>);

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::Release);
    }
}

/// Raw camera frames require privilege: only root gets them. When frames are
/// not allowed the bytes are stripped — the caller gets detection and
/// recognition metadata only, never raw camera/IR imagery. Per-method
/// authorization already confines the preview methods to root; this strip is
/// the regression hedge that keeps imagery out of a non-root reply anyway.
fn sanitize_preview_jpeg(jpeg_data: Vec<u8>, allow_frames: bool) -> Vec<u8> {
    if allow_frames { jpeg_data } else { Vec::new() }
}

/// A resolved D-Bus caller: the UID the bus daemon vouches for
/// (`GetConnectionUnixUser`) and its resolved username. Public (with public
/// fields) so integration tests can drive the method-level entry points with
/// synthetic identities.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CallerIdentity {
    pub uid: u32,
    pub username: Option<String>,
}

impl CallerIdentity {
    fn display_name(&self) -> String {
        self.username
            .clone()
            .unwrap_or_else(|| format!("UID {}", self.uid))
    }
}

async fn resolve_caller_identity(
    hdr: &zbus::message::Header<'_>,
    connection: &zbus::Connection,
) -> fdo::Result<CallerIdentity> {
    let sender = hdr
        .sender()
        .ok_or_else(|| fdo::Error::Failed("no sender in D-Bus message".into()))?;

    let dbus_proxy = fdo::DBusProxy::new(connection)
        .await
        .map_err(|e| fdo::Error::Failed(format!("failed to create DBus proxy: {e}")))?;
    let uid = dbus_proxy
        .get_connection_unix_user(sender.as_ref().into())
        .await
        .map_err(|e| fdo::Error::Failed(format!("failed to get caller UID: {e}")))?;

    let username = uid_to_username(uid);
    Ok(CallerIdentity { uid, username })
}

/// Declare the D-Bus method vocabulary once: the variants, their wire names,
/// and [`Method::ALL`] all come from this single list.
///
/// The matrix tests iterate `ALL`, so `ALL` being *complete* is what makes
/// them mean anything — and a hand-written second copy of the variant list is
/// exactly the thing that drifts. Generating it removes the possibility: a
/// method added here lands in `ALL` and in `name()` or does not exist. (Drift
/// could only ever under-test, since [`Method::scope`]'s catch-all keeps an
/// unlisted method root-only, but a test that claims completeness should have
/// it.)
macro_rules! declare_methods {
    ($($variant:ident => $wire:literal,)+) => {
        /// Every method on the `org.facelock.Daemon` D-Bus interface. Keep in
        /// sync with the `#[interface]` block below — the one direction no
        /// type can enforce, and what
        /// `interface_methods_and_the_authz_matrix_are_the_same_set` pins by
        /// scanning this file. This enum plus [`Method::scope`] is the
        /// authorization matrix; the in-module unit tests pin the table
        /// itself, and tests/server_authz.rs exercises it through the
        /// method-level entry points (D6).
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        enum Method {
            $($variant,)+
        }

        impl Method {
            /// Every variant, complete by construction — see
            /// [`declare_methods`].
            #[cfg(test)]
            const ALL: &'static [Method] = &[$(Method::$variant,)+];

            /// The wire name, which is what denial messages and capture-slot
            /// contention errors quote.
            fn name(self) -> &'static str {
                match self {
                    $(Method::$variant => $wire,)+
                }
            }
        }
    };
}

declare_methods! {
    Authenticate => "Authenticate",
    TestAuthenticate => "TestAuthenticate",
    Enroll => "Enroll",
    ListModels => "ListModels",
    RemoveModel => "RemoveModel",
    ClearModels => "ClearModels",
    PreviewFrame => "PreviewFrame",
    PreviewDetectFrame => "PreviewDetectFrame",
    ListDevices => "ListDevices",
    ReleaseCamera => "ReleaseCamera",
    Ping => "Ping",
    Shutdown => "Shutdown",
}

impl Method {
    /// Authorization target for each method.
    ///
    /// `Authenticate` is the only user-scoped method: screen lockers run
    /// their PAM stack as the user, so a user must be able to request
    /// authentication for themselves — that is architecture, not policy.
    /// Everything else is root-only. In particular `PreviewDetectFrame`,
    /// which runs per-frame with no rate limit, must never be reachable by
    /// an unprivileged caller: together with score redaction this closes the
    /// similarity hill-climbing oracle by construction. The catch-all arm
    /// makes any future method root-only until it is deliberately opened up.
    ///
    /// `TestAuthenticate` is listed explicitly rather than left to the
    /// catch-all: it is the entry point that does *not* charge the rate
    /// limit, so its root-only scope is the whole reason it is safe to
    /// offer, not an incidental default.
    fn scope(self) -> Scope {
        match self {
            Method::Authenticate => Scope::UserScoped,
            Method::TestAuthenticate => Scope::Root,
            _ => Scope::Root,
        }
    }
}

/// Who may call a D-Bus method. The bus policy admits root and the facelock
/// group to the whole interface; this in-daemon check (keyed on the caller
/// UID from `GetConnectionUnixUser`) is the per-method decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scope {
    /// Root only.
    Root,
    /// Root, or a non-root caller acting on their own username.
    UserScoped,
}

/// The single per-method authorization decision point. `target_user` is the
/// username a user-scoped method acts on; root-scoped methods ignore it.
/// Fails closed: a user-scoped call without a target user is denied.
fn authorize_method(
    caller: &CallerIdentity,
    method: Method,
    target_user: Option<&str>,
) -> fdo::Result<()> {
    match method.scope() {
        Scope::Root => require_root(caller, method.name()),
        Scope::UserScoped => {
            let user = target_user.ok_or_else(|| {
                fdo::Error::Failed(format!("{} requires a target user", method.name()))
            })?;
            require_user_authorized(caller, user, method.name())
        }
    }
}

fn require_root(caller: &CallerIdentity, operation: &str) -> fdo::Result<()> {
    if caller.uid == 0 {
        return Ok(());
    }

    let caller_name = caller.display_name();
    warn!(
        operation = operation,
        caller_uid = caller.uid,
        caller_name = %caller_name,
        "D-Bus caller not authorized for privileged operation"
    );
    Err(fdo::Error::AccessDenied(format!(
        "{operation} requires root (caller: '{caller_name}', UID {})",
        caller.uid
    )))
}

fn require_user_authorized(
    caller: &CallerIdentity,
    user: &str,
    operation: &str,
) -> fdo::Result<()> {
    if caller.uid == 0 {
        return Ok(());
    }

    let caller_name = caller.username.clone().ok_or_else(|| {
        fdo::Error::Failed(format!("failed to resolve UID {} to username", caller.uid))
    })?;

    if caller_name == user {
        return Ok(());
    }

    warn!(
        operation = operation,
        caller_uid = caller.uid,
        caller_name = %caller_name,
        requested_user = %user,
        "D-Bus caller not authorized to act on behalf of requested user"
    );
    Err(fdo::Error::AccessDenied(format!(
        "{operation} not authorized: caller '{caller_name}' (UID {}) cannot act as '{user}'",
        caller.uid
    )))
}

fn uid_to_username(uid: u32) -> Option<String> {
    User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|user| user.name)
}

/// Current time as seconds since an arbitrary epoch (Instant-based).
/// Used for idle timeout tracking without wall-clock dependency.
fn now_secs() -> u64 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_secs()
}

/// Encode a recoverable authentication error into the `AuthResult` wire
/// format (`model_id == -2`, `label` = error message) instead of a D-Bus
/// error.
///
/// A D-Bus error reply makes clients treat the daemon as broken: the PAM
/// module would fall back to a fresh root oneshot attempt, silently
/// escalating past daemon-side state such as rate limiting. In-band encoding
/// lets the PAM client classify the error (rate limited → PAM_AUTH_ERR,
/// everything else → PAM_IGNORE) without retrying.
/// See docs/contracts.md ("Authenticate error encoding").
fn recoverable_auth_error(message: String) -> AuthResult {
    AuthResult {
        matched: false,
        model_id: -2,
        label: message,
        similarity: 0.0,
    }
}

/// `model_id` for an unmatched attempt in which the detector saw nobody (and
/// for the pre-camera gates, which reject before a face could be seen).
const NO_MATCH_NO_FACE: i32 = -1;

/// `model_id` for an unmatched attempt in which the detector *did* see a face.
///
/// PAM needs this distinction to choose `PAM_AUTH_ERR` (we looked at you and
/// said no) over `PAM_IGNORE` (we have no opinion), and it cannot read it off
/// `similarity`, which is redacted to `0.0` for every non-root caller — so a
/// hyprlock user's genuine no-match used to be indistinguishable from an empty
/// frame (#108's N12, deferred to #109 and never carried).
///
/// A pre-`-4` PAM module decodes this as a plain no-match (its `match` falls
/// through to the same arm as `-1`), so the sentinel is safe to emit at a
/// daemon that is newer than the installed module.
const NO_MATCH_FACE_SEEN: i32 = -4;

/// The `model_id` field for a [`MatchResult`] on the wire.
///
/// A matched attempt carries the winning model's id; an unmatched one carries
/// the sentinel that says whether a face was there at all.
fn wire_model_id(result: &facelock_core::types::MatchResult) -> i32 {
    match result.model_id {
        Some(id) => id as i32,
        None if result.face_detected && !result.matched => NO_MATCH_FACE_SEEN,
        None => NO_MATCH_NO_FACE,
    }
}

/// The `org.facelock.Daemon` service.
///
/// Generic over the handler's camera and engine so integration tests can
/// construct it around mocks ([`FacelockService::new`]) and drive the
/// method-level entry points (`*_as`) with synthetic caller identities (D6).
/// The `#[interface]` block below binds the production types and owns only
/// the zbus glue: caller-identity resolution and signal emission.
pub struct FacelockService<C, E>
where
    C: CameraSource + Send + 'static,
    E: FaceProcessor + Send + 'static,
{
    handler: Arc<Mutex<Handler<C, E>>>,
    /// Timestamp of last D-Bus method call (seconds since daemon start).
    last_activity: Arc<AtomicU64>,
    /// Config file mtime when the handler was last built.
    /// Used to detect config changes and reload on next request.
    config_mtime: Arc<Mutex<Option<std::time::SystemTime>>>,
    /// In-flight guard for camera-capture operations (DoS control).
    capture_slot: Arc<CaptureSlot>,
    /// Builds per-user notifiers for auth outcomes. Injected from `main` so
    /// the server never names the delivery implementation (D9) — a
    /// prerequisite for moving this server out of facelock-cli.
    notifier_factory: NotifierFactory,
    /// Rebuilds the handler from on-disk config for the live reload. `None`
    /// disables reload (tests).
    rebuild: Option<HandlerRebuild<C, E>>,
}

impl<C, E> FacelockService<C, E>
where
    C: CameraSource + Send + 'static,
    E: FaceProcessor + Send + 'static,
{
    /// Construct the service around a built handler. [`run_dbus_server`]
    /// does this with production types; integration tests with mocks.
    pub fn new(
        handler: Handler<C, E>,
        startup_config_mtime: Option<std::time::SystemTime>,
        rebuild: Option<HandlerRebuild<C, E>>,
        notifier_factory: NotifierFactory,
    ) -> Self {
        Self {
            handler: Arc::new(Mutex::new(handler)),
            last_activity: Arc::new(AtomicU64::new(now_secs())),
            config_mtime: Arc::new(Mutex::new(startup_config_mtime)),
            capture_slot: Arc::new(CaptureSlot::default()),
            notifier_factory,
            rebuild,
        }
    }

    /// Check if the config file has been modified since the handler was built.
    /// If so, reload config, rebuild the engine/store/handler, and swap it in.
    /// Called at the start of authenticate and enroll — the two methods that
    /// depend on cached ONNX models and config values.
    fn maybe_reload_handler(&self) {
        // No rebuild recipe injected (tests): live reload is disabled.
        let Some(rebuild) = self.rebuild.as_ref() else {
            return;
        };
        let config_path = facelock_core::paths::config_path();
        let current_mtime = std::fs::metadata(&config_path)
            .and_then(|m| m.modified())
            .ok();

        // A poisoned lock is not a reason to reload: keep serving with the
        // handler already built, exactly as the two swap sites below do.
        let needs_reload = match self.config_mtime.lock() {
            Ok(stored) => matches!((*stored, current_mtime), (Some(old), Some(new)) if new > old),
            Err(_) => false,
        };

        if !needs_reload {
            return;
        }

        info!("config file changed, reloading");

        let new_handler = match rebuild() {
            Ok(handler) => handler,
            Err(e) => {
                warn!("failed to reload config: {e} — continuing with old config");
                return;
            }
        };

        // Swap in the new handler
        if let Ok(mut guard) = self.handler.lock() {
            *guard = new_handler;
        }

        // Update stored mtime
        if let Ok(mut stored) = self.config_mtime.lock() {
            *stored = current_mtime;
        }

        info!("handler reloaded with new config");
    }

    // ------------------------------------------------------------------
    // Method-level entry points (D6): everything each wire method does
    // except zbus mechanics — activity/reload bookkeeping, authorization,
    // capture-slot contention, handler dispatch, response mapping, and
    // similarity redaction. `caller` arrives resolved, so integration tests
    // exercise the full path with synthetic identities; production resolves
    // it from the message header in the `#[interface]` glue below.
    // ------------------------------------------------------------------

    /// The real-authentication entry point: every PAM stack, every locker,
    /// the polkit agent. A failed attempt ALWAYS charges the rate-limit
    /// budget, whatever the caller's UID.
    ///
    /// It used to charge only non-root callers, on the theory that a root
    /// caller must be root-only `facelock test` (N11). That inference was
    /// wrong in the direction that matters: `sudo` is setuid-root, and
    /// `login`, `su` and root-run greeters run their PAM stack as root too,
    /// so real failed authentications arrived here as UID 0 and were never
    /// charged. The diagnostic carve-out now lives in
    /// [`FacelockService::test_authenticate_as`], where it is asked for
    /// explicitly instead of inferred.
    pub async fn authenticate_as(
        &self,
        caller: CallerIdentity,
        user: &str,
    ) -> fdo::Result<AuthResult> {
        self.run_authentication(caller, user, Method::Authenticate, AuthIntent::Authenticate)
            .await
    }

    /// The root-only diagnostic entry point behind `facelock test` (N11,
    /// issue #96). Same authentication, same reply shape, two deliberate
    /// differences: a failed attempt charges no rate-limit budget, and the
    /// SSH/lid physical-presence gates are skipped — an admin who is already
    /// root may legitimately diagnose recognition over SSH or with the lid
    /// closed on a docked laptop. Everything else (`disabled`, enrollment,
    /// the rate-limit *check*, `require_ir`) still applies.
    ///
    /// Root-only is what makes that safe, and it is enforced by the same
    /// table-driven [`authorize_method`] as every other privileged method.
    pub async fn test_authenticate_as(
        &self,
        caller: CallerIdentity,
        user: &str,
    ) -> fdo::Result<AuthResult> {
        self.run_authentication(caller, user, Method::TestAuthenticate, AuthIntent::Test)
            .await
    }

    /// The body both authentication entry points share, so the diagnostic
    /// method cannot drift from the real one: same authorization table, same
    /// capture slot, same handler call, same in-band error encoding, same
    /// notification, same redaction. Only `method` (which authorization
    /// applies) and `intent` (what the attempt costs and which gates run)
    /// differ.
    async fn run_authentication(
        &self,
        caller: CallerIdentity,
        user: &str,
        method: Method,
        intent: AuthIntent,
    ) -> fdo::Result<AuthResult> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        self.maybe_reload_handler();
        authorize_method(&caller, method, Some(user))?;
        let caller_is_root = caller.uid == 0;
        let capture_guard = self.capture_slot.try_acquire(method.name())?;
        let handler = self.handler.clone();
        let notifier_factory = self.notifier_factory.clone();
        let user = user.to_string();
        let result = tokio::task::spawn_blocking(move || {
            let mut handler = lock_handler_with_timeout(&handler)?;
            let response = handler.handle_authenticate(user.clone(), intent);
            // Notification settings come from the handler's config — the
            // freshest parse, since maybe_reload_handler ran at method entry.
            // No mid-request file re-read (D7).
            let notify_config = handler.config.notification.clone();
            drop(handler);
            // Capture finished — free the slot before slower follow-up work
            // (notifications) so the next auth isn't rejected needlessly.
            drop(capture_guard);
            match response {
                DaemonResponse::AuthResult(result) => {
                    // Send desktop notification (fire-and-forget, runs as root → setpriv)
                    notify_auth_outcome(&notify_config, notifier_factory(&user).as_ref(), &result);

                    Ok(AuthResult {
                        matched: result.matched,
                        model_id: wire_model_id(&result),
                        label: result.label.unwrap_or_default(),
                        similarity: result.similarity as f64,
                    })
                }
                DaemonResponse::Suppressed => {
                    // No enrolled models + suppress_unknown enabled.
                    // Return model_id=-3 as a marker so the PAM module
                    // can map this to PAM_AUTHINFO_UNAVAIL.
                    Ok(AuthResult {
                        matched: false,
                        model_id: -3,
                        label: String::new(),
                        similarity: 0.0,
                    })
                }
                DaemonResponse::Error { message } => Ok(recoverable_auth_error(message)),
                other => Err(fdo::Error::Failed(format!(
                    "unexpected response: {other:?}"
                ))),
            }
        })
        .await
        .map_err(|e| fdo::Error::Failed(format!("task join error: {e}")))?;

        // The similarity score is root-only (a hill-climbing oracle
        // otherwise); the score has already reached the audit log unredacted
        // inside the handler.
        result.map(|auth| auth.redact_similarity_unless_root(caller_is_root))
    }

    pub async fn enroll_as(
        &self,
        caller: CallerIdentity,
        user: &str,
        label: &str,
    ) -> fdo::Result<(u32, u32)> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        self.maybe_reload_handler();
        authorize_method(&caller, Method::Enroll, None)?;
        let capture_guard = self.capture_slot.try_acquire("Enroll")?;
        let handler = self.handler.clone();
        let user = user.to_string();
        let label = label.to_string();
        tokio::task::spawn_blocking(move || {
            let _capture_guard = capture_guard;
            let mut handler = lock_handler_with_timeout(&handler)?;
            let request = DaemonRequest::Enroll { user, label };
            let response = handler.handle(request);
            match response {
                DaemonResponse::Enrolled {
                    model_id,
                    embedding_count,
                } => Ok((model_id, embedding_count)),
                DaemonResponse::Error { message } => Err(fdo::Error::Failed(message)),
                other => Err(fdo::Error::Failed(format!(
                    "unexpected response: {other:?}"
                ))),
            }
        })
        .await
        .map_err(|e| fdo::Error::Failed(format!("task join error: {e}")))?
    }

    pub async fn list_models_as(
        &self,
        caller: CallerIdentity,
        user: &str,
    ) -> fdo::Result<Vec<ModelInfo>> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        authorize_method(&caller, Method::ListModels, None)?;
        let handler = self.handler.clone();
        let user = user.to_string();
        tokio::task::spawn_blocking(move || {
            let mut handler = lock_handler_with_timeout(&handler)?;
            let request = DaemonRequest::ListModels { user };
            let response = handler.handle(request);
            match response {
                DaemonResponse::Models(models) => Ok(models
                    .into_iter()
                    .map(|m| ModelInfo {
                        id: m.id,
                        user: m.user,
                        label: m.label,
                        created_at: m.created_at,
                        embedder_model: m.embedder_model,
                        // D-Bus has no Option: empty string == NULL/legacy.
                        device_id: m.device_id.unwrap_or_default(),
                    })
                    .collect()),
                DaemonResponse::Error { message } => Err(fdo::Error::Failed(message)),
                other => Err(fdo::Error::Failed(format!(
                    "unexpected response: {other:?}"
                ))),
            }
        })
        .await
        .map_err(|e| fdo::Error::Failed(format!("task join error: {e}")))?
    }

    pub async fn remove_model_as(
        &self,
        caller: CallerIdentity,
        user: &str,
        model_id: u32,
    ) -> fdo::Result<()> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        authorize_method(&caller, Method::RemoveModel, None)?;
        let handler = self.handler.clone();
        let user = user.to_string();
        tokio::task::spawn_blocking(move || {
            let mut handler = lock_handler_with_timeout(&handler)?;
            let request = DaemonRequest::RemoveModel { user, model_id };
            let response = handler.handle(request);
            match response {
                // C8 (Phase E): the wire reply is unit, so "removed" and
                // "nothing to remove" are indistinguishable to the caller.
                DaemonResponse::Removed => Ok(()),
                DaemonResponse::Error { message } => Err(fdo::Error::Failed(message)),
                other => Err(fdo::Error::Failed(format!(
                    "unexpected response: {other:?}"
                ))),
            }
        })
        .await
        .map_err(|e| fdo::Error::Failed(format!("task join error: {e}")))?
    }

    pub async fn clear_models_as(&self, caller: CallerIdentity, user: &str) -> fdo::Result<()> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        authorize_method(&caller, Method::ClearModels, None)?;
        let handler = self.handler.clone();
        let user = user.to_string();
        tokio::task::spawn_blocking(move || {
            let mut handler = lock_handler_with_timeout(&handler)?;
            let request = DaemonRequest::ClearModels { user };
            let response = handler.handle(request);
            match response {
                DaemonResponse::Removed => Ok(()),
                DaemonResponse::Error { message } => Err(fdo::Error::Failed(message)),
                other => Err(fdo::Error::Failed(format!(
                    "unexpected response: {other:?}"
                ))),
            }
        })
        .await
        .map_err(|e| fdo::Error::Failed(format!("task join error: {e}")))?
    }

    pub async fn preview_frame_as(&self, caller: CallerIdentity) -> fdo::Result<Vec<u8>> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        authorize_method(&caller, Method::PreviewFrame, None)?;
        let capture_guard = self.capture_slot.try_acquire("PreviewFrame")?;
        let handler = self.handler.clone();
        tokio::task::spawn_blocking(move || {
            let _capture_guard = capture_guard;
            let mut handler = lock_handler_with_timeout(&handler)?;
            let request = DaemonRequest::PreviewFrame;
            let response = handler.handle(request);
            match response {
                DaemonResponse::Frame { jpeg_data } => Ok(jpeg_data),
                DaemonResponse::Error { message } => Err(fdo::Error::Failed(message)),
                other => Err(fdo::Error::Failed(format!(
                    "unexpected response: {other:?}"
                ))),
            }
        })
        .await
        .map_err(|e| fdo::Error::Failed(format!("task join error: {e}")))?
    }

    pub async fn preview_detect_frame_as(
        &self,
        caller: CallerIdentity,
        user: &str,
    ) -> fdo::Result<(Vec<u8>, Vec<PreviewFaceInfo>)> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        // Root-only: preview runs per-frame with neither pre_check nor the
        // rate limiter, so for any weaker caller this method would be a
        // continuous similarity feed at camera framerate.
        authorize_method(&caller, Method::PreviewDetectFrame, None)?;
        let caller_is_root = caller.uid == 0;

        let capture_guard = self.capture_slot.try_acquire("PreviewDetectFrame")?;
        let handler = self.handler.clone();
        let user = user.to_string();
        tokio::task::spawn_blocking(move || {
            let _capture_guard = capture_guard;
            let mut handler = lock_handler_with_timeout(&handler)?;
            let request = DaemonRequest::PreviewDetectFrame { user };
            let response = handler.handle(request);
            match response {
                DaemonResponse::DetectFrame { jpeg_data, faces } => {
                    let jpeg_data = sanitize_preview_jpeg(jpeg_data, caller_is_root);
                    let face_infos: Vec<PreviewFaceInfo> = faces
                        .into_iter()
                        .map(|f| {
                            PreviewFaceInfo {
                                x: f.x as f64,
                                y: f.y as f64,
                                width: f.width as f64,
                                height: f.height as f64,
                                confidence: f.confidence as f64,
                                similarity: f.similarity as f64,
                                recognized: f.recognized,
                            }
                            // Defense in depth: authorization above already
                            // restricts this method to root, but the score
                            // must stay redacted even if that ever regresses.
                            .redact_similarity_unless_root(caller_is_root)
                        })
                        .collect();
                    Ok((jpeg_data, face_infos))
                }
                DaemonResponse::Error { message } => Err(fdo::Error::Failed(message)),
                other => Err(fdo::Error::Failed(format!(
                    "unexpected response: {other:?}"
                ))),
            }
        })
        .await
        .map_err(|e| fdo::Error::Failed(format!("task join error: {e}")))?
    }

    pub async fn list_devices_as(&self, caller: CallerIdentity) -> fdo::Result<Vec<DeviceInfo>> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        authorize_method(&caller, Method::ListDevices, None)?;
        let handler = self.handler.clone();
        tokio::task::spawn_blocking(move || {
            let mut handler = lock_handler_with_timeout(&handler)?;
            let request = DaemonRequest::ListDevices;
            let response = handler.handle(request);
            match response {
                // C9 (Phase E): the wire DeviceInfo carries no formats, so
                // per-device format/resolution detail is dropped here.
                DaemonResponse::Devices(devices) => Ok(devices
                    .into_iter()
                    .map(|d| DeviceInfo {
                        path: d.path,
                        name: d.name,
                        driver: d.driver,
                        is_ir: d.is_ir,
                    })
                    .collect()),
                DaemonResponse::Error { message } => Err(fdo::Error::Failed(message)),
                other => Err(fdo::Error::Failed(format!(
                    "unexpected response: {other:?}"
                ))),
            }
        })
        .await
        .map_err(|e| fdo::Error::Failed(format!("task join error: {e}")))?
    }

    pub async fn release_camera_as(&self, caller: CallerIdentity) -> fdo::Result<()> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        authorize_method(&caller, Method::ReleaseCamera, None)?;
        let handler = self.handler.clone();
        tokio::task::spawn_blocking(move || {
            let mut handler = lock_handler_with_timeout(&handler)?;
            let request = DaemonRequest::ReleaseCamera;
            let response = handler.handle(request);
            match response {
                DaemonResponse::Ok => Ok(()),
                DaemonResponse::Error { message } => Err(fdo::Error::Failed(message)),
                other => Err(fdo::Error::Failed(format!(
                    "unexpected response: {other:?}"
                ))),
            }
        })
        .await
        .map_err(|e| fdo::Error::Failed(format!("task join error: {e}")))?
    }

    pub async fn ping_as(&self, caller: CallerIdentity) -> fdo::Result<String> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        authorize_method(&caller, Method::Ping, None)?;
        Ok("pong".to_string())
    }

    pub async fn shutdown_as(&self, caller: CallerIdentity) -> fdo::Result<()> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        authorize_method(&caller, Method::Shutdown, None)?;
        let handler = self.handler.clone();
        tokio::task::spawn_blocking(move || {
            let mut handler = lock_handler_with_timeout(&handler)?;
            match handler.handle(DaemonRequest::Shutdown) {
                DaemonResponse::Ok => Ok(()),
                DaemonResponse::Error { message } => Err(fdo::Error::Failed(message)),
                other => Err(fdo::Error::Failed(format!(
                    "unexpected response: {other:?}"
                ))),
            }
        })
        .await
        .map_err(|e| fdo::Error::Failed(format!("task join error: {e}")))?
    }
}

#[interface(name = "org.facelock.Daemon")]
impl FacelockService<Camera<'static>, FaceEngine> {
    async fn authenticate(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
        user: &str,
    ) -> fdo::Result<AuthResult> {
        let caller = resolve_caller_identity(&hdr, connection).await?;
        let result = self.authenticate_as(caller, user).await;

        // Emit auth_attempted signal (best-effort, don't fail auth if signal
        // fails). The payload deliberately carries no similarity score — the
        // raw biometric score is a spoof-tuning oracle for anyone able to
        // receive the broadcast; `matched` + user is enough for consumers.
        if let Ok(ref auth_result) = result {
            let _ = Self::auth_attempted(&ctxt, user, auth_result.matched).await;
        }

        result
    }

    /// The root-only diagnostic counterpart of `Authenticate`, behind
    /// `facelock test`. Identical wire shape (`s` in, `AuthResult` out,
    /// same `-1`/`-2`/`-3` sentinels) — see
    /// [`FacelockService::test_authenticate_as`] for the two behavioral
    /// differences.
    async fn test_authenticate(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
        user: &str,
    ) -> fdo::Result<AuthResult> {
        let caller = resolve_caller_identity(&hdr, connection).await?;
        let result = self.test_authenticate_as(caller, user).await;

        // Emitted for the same reason and with the same payload as
        // `Authenticate`'s: a camera-backed attempt happened for `user`.
        if let Ok(ref auth_result) = result {
            let _ = Self::auth_attempted(&ctxt, user, auth_result.matched).await;
        }

        result
    }

    async fn enroll(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        user: &str,
        label: &str,
    ) -> fdo::Result<(u32, u32)> {
        let caller = resolve_caller_identity(&hdr, connection).await?;
        self.enroll_as(caller, user, label).await
    }

    async fn list_models(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        user: &str,
    ) -> fdo::Result<Vec<ModelInfo>> {
        let caller = resolve_caller_identity(&hdr, connection).await?;
        self.list_models_as(caller, user).await
    }

    async fn remove_model(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        user: &str,
        model_id: u32,
    ) -> fdo::Result<()> {
        let caller = resolve_caller_identity(&hdr, connection).await?;
        self.remove_model_as(caller, user, model_id).await
    }

    async fn clear_models(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        user: &str,
    ) -> fdo::Result<()> {
        let caller = resolve_caller_identity(&hdr, connection).await?;
        self.clear_models_as(caller, user).await
    }

    async fn preview_frame(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<Vec<u8>> {
        let caller = resolve_caller_identity(&hdr, connection).await?;
        self.preview_frame_as(caller).await
    }

    async fn preview_detect_frame(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        user: &str,
    ) -> fdo::Result<(Vec<u8>, Vec<PreviewFaceInfo>)> {
        let caller = resolve_caller_identity(&hdr, connection).await?;
        self.preview_detect_frame_as(caller, user).await
    }

    async fn list_devices(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<Vec<DeviceInfo>> {
        let caller = resolve_caller_identity(&hdr, connection).await?;
        self.list_devices_as(caller).await
    }

    async fn release_camera(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<()> {
        let caller = resolve_caller_identity(&hdr, connection).await?;
        self.release_camera_as(caller).await
    }

    async fn ping(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<String> {
        let caller = resolve_caller_identity(&hdr, connection).await?;
        self.ping_as(caller).await
    }

    async fn shutdown(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<()> {
        let caller = resolve_caller_identity(&hdr, connection).await?;
        self.shutdown_as(caller).await
    }

    /// Signal emitted after each authentication attempt.
    ///
    /// Carries only the user and the match outcome — never the raw
    /// similarity score (an information leak / spoof-tuning oracle).
    /// The bus policy additionally restricts who may receive this signal.
    #[zbus(signal)]
    async fn auth_attempted(
        emitter: &SignalEmitter<'_>,
        user: &str,
        matched: bool,
    ) -> zbus::Result<()>;
}

/// Map an auth outcome to its desktop notification and deliver it through
/// the injected notifier, honoring the notification config.
///
/// Pure decision + injected delivery: the tests below assert emit/no-emit
/// with a recording notifier; production passes the per-user desktop
/// notifier built by the injected [`NotifierFactory`].
fn notify_auth_outcome(
    config: &facelock_core::config::NotificationConfig,
    notifier: &dyn Notifier,
    result: &facelock_core::types::MatchResult,
) {
    let event = if result.matched {
        NotifyEvent::Success {
            label: result.label.clone(),
            similarity: result.similarity,
        }
    } else {
        NotifyEvent::Failure {
            reason: "no match".into(),
        }
    };
    notify_desktop_if_enabled(config, notifier, &event);
}

/// Run the daemon's D-Bus server until shutdown (signal, D-Bus `Shutdown`,
/// or idle timeout). Blocking: builds its own multi-threaded tokio runtime.
pub fn run(
    handler: ProductionHandler,
    idle_timeout_secs: u64,
    startup_config_mtime: Option<std::time::SystemTime>,
    rebuild: Option<ProductionRebuild>,
    notifier_factory: NotifierFactory,
) -> Result<(), ServerError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(run_dbus_server(
        handler,
        idle_timeout_secs,
        startup_config_mtime,
        rebuild,
        notifier_factory,
    ))
}

/// Bitmask (low 32-bit word, caps 0-31) of the capabilities the daemon keeps
/// after startup: CAP_SETUID (bit 7) and CAP_SETGID (bit 6).
///
/// These two are required for the desktop-notification privilege-drop: the
/// daemon runs as root and execs `runuser`/`su` to `setgroups()` + `setuid()`
/// into the user's session bus (see `notifications.rs::send_as_user`). Under
/// `NoNewPrivileges` that exec cannot regain privilege, so the caps must be
/// retained — and held in the inheritable set so systemd `AmbientCapabilities`
/// survives the exec into the non-setuid `runuser`. Every other capability is
/// dropped. Factored into a pure `const fn` so the mask can be unit-tested
/// without calling `capset` (which needs privilege and may fail in CI).
const fn retained_capability_mask() -> u32 {
    // CAP_SETGID = 6, CAP_SETUID = 7.
    (1 << 7) | (1 << 6)
}

/// Drop all Linux capabilities except CAP_SETUID + CAP_SETGID, and set
/// PR_SET_NO_NEW_PRIVS.
///
/// After initialization the daemon has already opened the camera fd, loaded
/// models, connected to D-Bus, and opened the database. It no longer needs any
/// elevated capabilities EXCEPT the two required to drop privilege for desktop
/// notifications (`runuser` → `setgroups`/`setuid`); those are retained via
/// [`retained_capability_mask`] in the effective, permitted, AND inheritable
/// sets, and everything else is cleared.
///
/// Returns `Ok(())` on success. Errors are non-fatal — the caller should
/// warn and continue.
fn drop_capabilities() -> std::result::Result<(), String> {
    // capget/capset use syscall numbers directly since libc doesn't expose
    // the cap structs on all platforms.
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    // _LINUX_CAPABILITY_VERSION_3 = 0x20080522
    const LINUX_CAP_V3: u32 = 0x2008_0522;

    unsafe {
        // Prevent the process (and children) from ever gaining new privileges
        let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if ret != 0 {
            return Err(format!(
                "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Retain exactly CAP_SETUID + CAP_SETGID (needed for the runuser/su
        // notification privilege-drop); clear every other capability. The
        // retained bits go in effective, permitted, AND inheritable — the
        // inheritable set is what lets systemd AmbientCapabilities keep these
        // caps across the exec into the non-setuid `runuser` under
        // NoNewPrivileges. V3 uses two CapData structs (caps 0-31 and 32-63);
        // the retained caps (6, 7) live in the low word, so the high word
        // stays fully zeroed.
        let keep = retained_capability_mask();
        let mut header = CapHeader {
            version: LINUX_CAP_V3,
            pid: 0,
        };
        let mut data = [
            CapData {
                effective: keep,
                permitted: keep,
                inheritable: keep,
            },
            CapData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        let ret = libc::syscall(
            libc::SYS_capset,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        );
        if ret != 0 {
            return Err(format!(
                "capset syscall failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

async fn run_dbus_server(
    handler: ProductionHandler,
    idle_timeout_secs: u64,
    startup_config_mtime: Option<std::time::SystemTime>,
    rebuild: Option<ProductionRebuild>,
    notifier_factory: NotifierFactory,
) -> Result<(), ServerError> {
    // Production builds the service through the same constructor the tests
    // use, so an invariant added to `new` cannot silently skip the only
    // instance that authenticates anyone. The struct literal this replaces
    // existed to keep the two handles below; cloning them back off the
    // service is what that cost.
    let service = FacelockService::new(handler, startup_config_mtime, rebuild, notifier_factory);
    let handler = service.handler.clone();
    let last_activity = service.last_activity.clone();

    let _connection = zbus::connection::Builder::system()?
        .name(BUS_NAME)?
        .serve_at(OBJECT_PATH, service)?
        .build()
        .await?;

    info!("facelock daemon running on D-Bus system bus as {BUS_NAME}");

    // Drop capabilities now that initialization is complete — camera fd is
    // open, models are loaded, D-Bus is connected, database is open.
    match drop_capabilities() {
        Ok(()) => info!(
            "retained CAP_SETUID+CAP_SETGID for notification privilege-drop; dropped all others and set no-new-privs"
        ),
        Err(e) => warn!("failed to drop capabilities (continuing): {e}"),
    }

    // Spawn a background task to release the camera on system suspend.
    // Best-effort: if logind is unavailable, log a warning and continue.
    let handler_for_sleep = handler.clone();
    tokio::spawn(async move {
        if let Err(e) = watch_sleep_signals(handler_for_sleep).await {
            tracing::warn!("failed to watch logind sleep signals: {e}");
        }
    });

    // Wait for shutdown signal (SIGTERM or SIGINT)
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("received SIGINT, shutting down");
        }
        _ = sigterm.recv() => {
            info!("received SIGTERM, shutting down");
        }
        _ = poll_shutdown(handler, last_activity, idle_timeout_secs) => {
            info!("shutdown requested via D-Bus or idle timeout, shutting down");
        }
    }

    info!("goodbye");
    Ok(())
}

/// Watch for logind `PrepareForSleep` signals.
///
/// On suspend (arg=true), release the camera so V4L2 handles don't go stale.
/// On resume (arg=false), just log — the camera will be re-acquired on demand.
///
/// Manual testing:
/// ```bash
/// # Start daemon, then:
/// sudo systemctl suspend
/// # After resume, check: journalctl -u facelock-daemon --since "5 min ago"
/// ```
async fn watch_sleep_signals(handler: Arc<Mutex<ProductionHandler>>) -> zbus::Result<()> {
    let connection = zbus::Connection::system().await?;
    let proxy = zbus::Proxy::new(
        &connection,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )
    .await?;

    let mut stream = proxy.receive_signal("PrepareForSleep").await?;
    info!("watching logind PrepareForSleep signals for camera suspend/resume");

    while let Some(signal) = stream.next().await {
        let suspending: bool = signal.body().deserialize().unwrap_or(false);
        if suspending {
            let handler = handler.clone();
            let _ = tokio::task::spawn_blocking(move || match handler.try_lock() {
                Ok(mut h) => {
                    h.handle(DaemonRequest::ReleaseCamera);
                    info!("released camera for suspend");
                }
                Err(_) => {
                    warn!("could not release camera for suspend: handler busy");
                }
            })
            .await;
        } else {
            info!("resumed from suspend, camera will reacquire on demand");
        }
    }
    Ok(())
}

/// Poll the handler's shutdown_requested flag, idle camera release, and idle timeout.
/// All mutex access goes through spawn_blocking to avoid blocking the
/// tokio runtime (which would deadlock D-Bus method dispatch).
async fn poll_shutdown(
    handler: Arc<Mutex<ProductionHandler>>,
    last_activity: Arc<AtomicU64>,
    idle_timeout_secs: u64,
) {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        // Check idle timeout (0 = disabled)
        if idle_timeout_secs > 0 {
            let last = last_activity.load(Ordering::Relaxed);
            let now = now_secs();
            if now.saturating_sub(last) >= idle_timeout_secs {
                info!(
                    idle_secs = now.saturating_sub(last),
                    timeout = idle_timeout_secs,
                    "idle timeout reached, initiating shutdown"
                );
                return;
            }
        }

        let handler = handler.clone();
        let should_shutdown = tokio::task::spawn_blocking(move || {
            if let Ok(mut h) = handler.try_lock() {
                if h.shutdown_requested {
                    return true;
                }
                h.maybe_release_camera();
            }
            false
        })
        .await
        .unwrap_or(false);

        if should_shutdown {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(uid: u32, username: Option<&str>) -> CallerIdentity {
        CallerIdentity {
            uid,
            username: username.map(str::to_string),
        }
    }

    #[test]
    fn bus_name_constants() {
        assert_eq!(BUS_NAME, "org.facelock.Daemon");
        assert_eq!(OBJECT_PATH, "/org/facelock/Daemon");
    }

    #[test]
    fn recoverable_auth_errors_are_encoded_in_band() {
        // Recoverable errors (rate limited, IR required, camera/storage
        // failures) must travel in the AuthResult wire format with
        // model_id == -2, not as D-Bus errors: a D-Bus error would make the
        // PAM client fall back to a fresh root oneshot attempt, silently
        // bypassing daemon-side state such as rate limiting.
        let result = recoverable_auth_error("rate limited".to_string());
        assert!(!result.matched);
        assert_eq!(result.model_id, -2);
        assert_eq!(result.label, "rate limited");
        assert_eq!(result.similarity, 0.0);
    }

    use facelock_core::config::{NotificationConfig, NotificationMode};
    use facelock_core::types::MatchResult;
    use facelock_test_support::RecordingNotifier;

    fn match_result(matched: bool) -> MatchResult {
        MatchResult {
            matched,
            model_id: matched.then_some(1),
            label: matched.then(|| "front".to_string()),
            similarity: 0.42,
            face_detected: true,
            failure_reason: None,
        }
    }

    fn desktop_config() -> NotificationConfig {
        NotificationConfig {
            mode: NotificationMode::Both,
            notify_prompt: true,
            notify_on_success: true,
            notify_on_failure: true,
        }
    }

    /// D9: a failed auth emits a Failure notification through the injected
    /// notifier when the config enables desktop failure notifications.
    #[test]
    fn failed_auth_emits_failure_notification_when_enabled() {
        let recorder = RecordingNotifier::new();
        notify_auth_outcome(&desktop_config(), &recorder, &match_result(false));
        assert_eq!(
            recorder.events(),
            vec![NotifyEvent::Failure {
                reason: "no match".into()
            }]
        );
    }

    /// D9: under the default config (terminal-only mode, and
    /// notify_on_failure = false) the same failed auth emits nothing.
    #[test]
    fn failed_auth_emits_nothing_under_default_config() {
        let recorder = RecordingNotifier::new();
        notify_auth_outcome(
            &NotificationConfig::default(),
            &recorder,
            &match_result(false),
        );
        assert_eq!(recorder.events(), vec![]);
    }

    /// A successful auth carries the label and similarity into the event.
    #[test]
    fn successful_auth_emits_success_event_with_match_data() {
        let recorder = RecordingNotifier::new();
        notify_auth_outcome(&desktop_config(), &recorder, &match_result(true));
        assert_eq!(
            recorder.events(),
            vec![NotifyEvent::Success {
                label: Some("front".into()),
                similarity: 0.42
            }]
        );
    }

    // --- Authorization matrix (N13) ---
    //
    // Authenticate is the only user-scoped method; everything else is
    // root-only. These tests iterate Method::ALL, which `declare_methods!`
    // generates from the same list as the variants — so a new method really
    // cannot be added without landing in the matrix.

    /// The wire method set and the authorization matrix must be the same
    /// set. `Method` is what [`authorize_method`] keys on, and zbus derives
    /// the wire name from the `#[interface]` function name — nothing in the
    /// type system ties the two together, so a method added to the interface
    /// without a `Method` variant would be a wire method the matrix tests
    /// above never see. Scanning the source is how the repo pins structural
    /// facts a type cannot (same idiom as the CLI's backend-seam pins); the
    /// live introspection XML is unavailable here because `#[interface]` is
    /// implemented only for the production `Camera`/`FaceEngine` handler.
    #[test]
    fn interface_methods_and_the_authz_matrix_are_the_same_set() {
        // Assembled at runtime so this literal doesn't match itself.
        let marker = format!("#[{}(name = \"org.facelock.Daemon\")]", "interface");
        let after_marker = include_str!("server.rs")
            .split_once(&marker)
            .expect("the #[interface] block")
            .1;
        // The impl ends at the first `}` in column 0; every brace inside it
        // is indented.
        let block = after_marker
            .split_once("\n}\n")
            .expect("the #[interface] block's closing brace")
            .0;

        let mut on_wire: Vec<String> = Vec::new();
        let mut previous = "";
        for line in block.lines() {
            let line = line.trim();
            // Signals are declared in the same block but are not methods.
            if let Some(rest) = line.strip_prefix("async fn ") {
                if !previous.contains("(signal)") {
                    on_wire.push(rest.split('(').next().unwrap().to_string());
                }
            }
            if !line.is_empty() {
                previous = line;
            }
        }

        let mut in_matrix: Vec<String> = Method::ALL.iter().map(|m| snake_case(m.name())).collect();
        on_wire.sort();
        in_matrix.sort();
        assert_eq!(
            on_wire, in_matrix,
            "every #[interface] method needs a Method variant (and vice versa) — \
             the authorization matrix is keyed on that enum"
        );
    }

    /// The wire name in the snake_case form zbus derives for the
    /// `#[interface]` function, which is what the scan above compares
    /// against.
    fn snake_case(name: &str) -> String {
        let mut out = String::with_capacity(name.len() + 3);
        for (i, ch) in name.char_indices() {
            if ch.is_ascii_uppercase() {
                if i > 0 {
                    out.push('_');
                }
                out.push(ch.to_ascii_lowercase());
            } else {
                out.push(ch);
            }
        }
        out
    }

    #[test]
    fn authz_matrix_root_is_allowed_everywhere() {
        let root = caller(0, Some("root"));
        for method in Method::ALL.iter().copied() {
            assert!(
                authorize_method(&root, method, Some("alice")).is_ok(),
                "root must be allowed to call {method:?}"
            );
        }
    }

    #[test]
    fn authz_matrix_every_method_is_root_only_except_authenticate() {
        for method in Method::ALL.iter().copied() {
            let expected = if method == Method::Authenticate {
                Scope::UserScoped
            } else {
                Scope::Root
            };
            assert_eq!(method.scope(), expected, "{method:?}");
        }
    }

    #[test]
    fn authz_matrix_non_root_is_denied_every_root_scoped_method() {
        let alice = caller(1000, Some("alice"));
        for method in Method::ALL.iter().copied() {
            if method == Method::Authenticate {
                continue;
            }
            let err = authorize_method(&alice, method, Some("alice")).unwrap_err();
            assert!(
                matches!(err, fdo::Error::AccessDenied(_)),
                "{method:?} must deny a non-root caller, got: {err:?}"
            );
        }
    }

    #[test]
    fn oracle_and_metadata_methods_deny_non_root() {
        // The methods N13 retargeted, pinned by name: PreviewDetectFrame is
        // the continuous score feed (no pre_check, no rate limit); the rest
        // were group- or user-reachable metadata surfaces.
        let alice = caller(1000, Some("alice"));
        for method in [
            Method::PreviewDetectFrame,
            Method::ListModels,
            Method::ListDevices,
            Method::Ping,
            Method::ReleaseCamera,
        ] {
            let err = authorize_method(&alice, method, Some("alice")).unwrap_err();
            assert!(
                matches!(err, fdo::Error::AccessDenied(_)),
                "{method:?} must deny a non-root caller"
            );
        }
    }

    #[test]
    fn authenticate_allows_non_root_caller_for_themselves() {
        assert!(
            authorize_method(
                &caller(1000, Some("alice")),
                Method::Authenticate,
                Some("alice")
            )
            .is_ok()
        );
    }

    #[test]
    fn authenticate_denies_non_root_caller_for_another_user() {
        let err = authorize_method(
            &caller(1000, Some("alice")),
            Method::Authenticate,
            Some("bob"),
        )
        .unwrap_err();
        assert!(matches!(err, fdo::Error::AccessDenied(_)));
    }

    #[test]
    fn authenticate_fails_closed_for_unresolvable_caller_username() {
        // A non-root caller whose UID cannot be resolved to a username can
        // never match the target user.
        assert!(
            authorize_method(&caller(1000, None), Method::Authenticate, Some("alice")).is_err()
        );
    }

    #[test]
    fn user_scoped_method_without_target_user_fails_closed() {
        assert!(authorize_method(&caller(0, Some("root")), Method::Authenticate, None).is_err());
        assert!(
            authorize_method(&caller(1000, Some("alice")), Method::Authenticate, None).is_err()
        );
    }

    #[test]
    fn capture_slot_grants_when_free() {
        let slot = Arc::new(CaptureSlot::default());
        assert!(slot.try_acquire("Authenticate").is_ok());
    }

    #[test]
    fn capture_slot_rejects_concurrent_capture_immediately() {
        let slot = Arc::new(CaptureSlot::default());
        let _guard = slot.try_acquire("Authenticate").expect("first acquire");
        let err = slot.try_acquire("Authenticate").unwrap_err();
        // Busy must surface as a plain daemon error so PAM degrades to
        // password (never a lockout), and the message must say "busy".
        match err {
            fdo::Error::Failed(msg) => assert!(msg.contains("busy"), "message: {msg}"),
            other => panic!("expected fdo::Error::Failed, got {other:?}"),
        }
    }

    #[test]
    fn capture_slot_frees_on_guard_drop() {
        let slot = Arc::new(CaptureSlot::default());
        let guard = slot.try_acquire("Authenticate").expect("first acquire");
        drop(guard);
        assert!(
            slot.try_acquire("Authenticate").is_ok(),
            "slot must be reusable after the previous capture finishes"
        );
    }

    #[test]
    fn preview_jpeg_stripped_when_frames_not_allowed() {
        let jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0];
        assert!(sanitize_preview_jpeg(jpeg, false).is_empty());
    }

    #[test]
    fn preview_jpeg_kept_when_frames_allowed() {
        let jpeg = vec![0xFF, 0xD8, 0xFF, 0xE0];
        assert_eq!(sanitize_preview_jpeg(jpeg.clone(), true), jpeg);
    }

    #[test]
    fn retained_capability_mask_is_exactly_setuid_and_setgid() {
        // Cap bit numbers per <linux/capability.h>.
        const CAP_SETGID: u32 = 6;
        const CAP_SETUID: u32 = 7;
        const CAP_DAC_OVERRIDE: u32 = 1;
        const CAP_NET_RAW: u32 = 13;
        const CAP_SYS_ADMIN: u32 = 21;

        let mask = retained_capability_mask();

        // Exactly the two caps required for the runuser/su notification
        // privilege-drop are retained.
        assert_eq!(mask, (1 << CAP_SETUID) | (1 << CAP_SETGID));
        assert_eq!(mask, 0b1100_0000);

        // The two we want are present.
        assert_ne!(mask & (1 << CAP_SETUID), 0, "CAP_SETUID must be retained");
        assert_ne!(mask & (1 << CAP_SETGID), 0, "CAP_SETGID must be retained");

        // Dangerous caps are NOT retained.
        assert_eq!(
            mask & (1 << CAP_SYS_ADMIN),
            0,
            "CAP_SYS_ADMIN must be dropped"
        );
        assert_eq!(mask & (1 << CAP_NET_RAW), 0, "CAP_NET_RAW must be dropped");
        assert_eq!(
            mask & (1 << CAP_DAC_OVERRIDE),
            0,
            "CAP_DAC_OVERRIDE must be dropped"
        );

        // Exactly two bits set, and none in the high word (caps 32-63).
        assert_eq!(mask.count_ones(), 2);
    }
}
