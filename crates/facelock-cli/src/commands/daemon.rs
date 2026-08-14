use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

use facelock_camera::quirks::QuirksDb;
use facelock_camera::{Camera, auto_detect_device, is_ir_camera_resolved, validate_device};
use facelock_core::config::Config;
use facelock_core::dbus_interface::{
    AuthResult, BUS_NAME, DeviceInfo, ModelInfo, OBJECT_PATH, PreviewFaceInfo,
};
use facelock_core::ipc::{DaemonRequest, DaemonResponse};
use facelock_daemon::handler::Handler;
use facelock_daemon::rate_limit::RateLimiter;
use facelock_face::FaceEngine;
use facelock_store::FaceStore;
use futures_util::StreamExt;
use nix::unistd::{Uid, User};
use tracing::{error, info, warn};
use zbus::{fdo, interface, object_server::SignalEmitter};

/// Production type alias for the handler with real Camera and FaceEngine.
type ProductionHandler = Handler<Camera<'static>, FaceEngine>;

/// Maximum time to wait for the handler mutex before returning a "busy" error.
/// This prevents D-Bus clients from hanging indefinitely if a previous auth
/// call is stuck (e.g., camera blocking on DQBUF).
const HANDLER_LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Try to acquire the handler mutex with a timeout.
/// Uses try_lock in a polling loop to avoid blocking the thread indefinitely.
fn lock_handler_with_timeout(
    handler: &Mutex<ProductionHandler>,
) -> std::result::Result<MutexGuard<'_, ProductionHandler>, fdo::Error> {
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

/// Raw camera frames require privilege: root gets them unconditionally (the
/// `PreviewFrame` contract), and a non-root caller only after an interactive
/// polkit authorization for `org.facelock.preview-frames`. When frames are
/// not allowed the bytes are stripped — the caller gets detection and
/// recognition metadata only, never raw camera/IR imagery.
fn sanitize_preview_jpeg(jpeg_data: Vec<u8>, allow_frames: bool) -> Vec<u8> {
    if allow_frames { jpeg_data } else { Vec::new() }
}

/// Polkit action a non-root caller must be authorized for to receive raw
/// preview frame bytes. Shipped in `dbus/org.facelock.policy`
/// (installed to /usr/share/polkit-1/actions/).
const PREVIEW_FRAMES_ACTION_ID: &str = "org.facelock.preview-frames";

/// `AllowUserInteraction` flag for `CheckAuthorization` — lets the caller's
/// polkit agent prompt interactively on the first frame request.
const POLKIT_ALLOW_USER_INTERACTION: u32 = 0x1;

/// How long a *granted* frame authorization is cached per caller connection.
/// The polkit grant itself (`auth_self_keep`) is what bounds the real
/// authorization lifetime (~5 min); this cache only saves the per-frame
/// round-trip and dies with the caller's bus connection or this TTL,
/// whichever comes first.
const AUTHZ_GRANTED_TTL: Duration = Duration::from_secs(120);

/// How long a *denied* (or errored) polkit verdict is cached. Short, so a
/// dismissed prompt can be retried quickly — but long enough that a caller
/// polling frames doesn't re-trigger an agent prompt on every frame.
const AUTHZ_DENIED_TTL: Duration = Duration::from_secs(15);

/// Upper bound on cached caller connections (DoS control).
const AUTHZ_CACHE_MAX_ENTRIES: usize = 64;

/// Give up on a polkit interaction (user typing a password) after this long.
const POLKIT_INTERACTION_TIMEOUT: Duration = Duration::from_secs(120);

/// Cached authorization state for one caller connection (unique bus name).
#[derive(Clone, Copy, Debug, PartialEq)]
enum AuthzEntry {
    /// A `CheckAuthorization` round-trip is in flight for this caller.
    InFlight,
    /// Polkit answered; valid until `expires_at`.
    Decided {
        authorized: bool,
        expires_at: Instant,
    },
}

/// Result of a frame-authorization cache lookup.
#[derive(Clone, Copy, Debug, PartialEq)]
enum FrameAuthz {
    /// Polkit authorized this caller connection (cached, unexpired).
    Granted,
    /// Polkit denied this caller (or the check errored) — fail closed.
    Refused,
    /// A polkit check is already in flight — metadata only for now.
    Pending,
    /// No usable cache entry; the caller was marked in-flight and a polkit
    /// check must be started.
    NeedsCheck,
}

/// The single authorization decision point for raw preview frame bytes:
/// root always gets frames; a non-root caller only with a fresh polkit
/// grant. Denied, pending, errored, or unknown states all FAIL CLOSED.
fn allow_preview_jpeg(caller_is_root: bool, authz: FrameAuthz) -> bool {
    caller_is_root || authz == FrameAuthz::Granted
}

/// Per-connection cache of polkit frame-authorization verdicts, keyed by the
/// caller's unique bus name (`:1.42`). Entries die with the caller's bus
/// connection (see [`watch_bus_disconnects`]) or their TTL, whichever first.
#[derive(Debug, Default)]
struct PreviewAuthzCache {
    entries: Mutex<HashMap<String, AuthzEntry>>,
}

impl PreviewAuthzCache {
    /// Look up the cached verdict for `caller`. If there is none (or it
    /// expired), atomically mark the caller in-flight and return
    /// [`FrameAuthz::NeedsCheck`] so that exactly one polkit round-trip is
    /// started per caller connection.
    fn begin_or_lookup(&self, caller: &str, now: Instant) -> FrameAuthz {
        let Ok(mut entries) = self.entries.lock() else {
            // Poisoned cache: fail closed without starting new checks.
            return FrameAuthz::Refused;
        };

        match entries.get(caller) {
            Some(AuthzEntry::InFlight) => return FrameAuthz::Pending,
            Some(AuthzEntry::Decided {
                authorized,
                expires_at,
            }) if *expires_at > now => {
                return if *authorized {
                    FrameAuthz::Granted
                } else {
                    FrameAuthz::Refused
                };
            }
            _ => {}
        }

        // Missing or expired — bound the cache before inserting.
        entries.retain(|_, entry| match entry {
            AuthzEntry::InFlight => true,
            AuthzEntry::Decided { expires_at, .. } => *expires_at > now,
        });
        if entries.len() >= AUTHZ_CACHE_MAX_ENTRIES {
            // Evict the decided entry closest to expiry; never evict
            // in-flight entries (their completion handler expects them).
            let victim = entries
                .iter()
                .filter_map(|(name, entry)| match entry {
                    AuthzEntry::Decided { expires_at, .. } => Some((name.clone(), *expires_at)),
                    AuthzEntry::InFlight => None,
                })
                .min_by_key(|(_, expires_at)| *expires_at);
            match victim {
                Some((name, _)) => {
                    entries.remove(&name);
                }
                None => {
                    // Cache full of in-flight checks — refuse to start
                    // another one (fail closed, no polkit storm).
                    warn!(caller, "frame authz cache full of in-flight checks");
                    return FrameAuthz::Pending;
                }
            }
        }

        entries.insert(caller.to_string(), AuthzEntry::InFlight);
        FrameAuthz::NeedsCheck
    }

    /// Record the outcome of a polkit round-trip. `Ok(true)` caches a grant,
    /// `Ok(false)` a denial, and `Err` (polkit unreachable, D-Bus error,
    /// timeout) is treated as a denial — FAIL CLOSED. The result is dropped
    /// if the caller's entry vanished (connection already closed).
    fn complete(&self, caller: &str, verdict: Result<bool, String>, now: Instant) {
        let authorized = match verdict {
            Ok(authorized) => authorized,
            Err(e) => {
                warn!(caller, error = %e, "polkit frame authorization check failed — failing closed");
                false
            }
        };
        let ttl = if authorized {
            AUTHZ_GRANTED_TTL
        } else {
            AUTHZ_DENIED_TTL
        };

        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        // Only settle an in-flight check; if the entry is gone the caller
        // disconnected and the verdict must not outlive the connection.
        if let Some(entry @ AuthzEntry::InFlight) = entries.get_mut(caller) {
            *entry = AuthzEntry::Decided {
                authorized,
                expires_at: now + ttl,
            };
        }
    }

    /// Drop all cached state for a caller (its bus connection went away).
    fn evict(&self, caller: &str) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(caller);
        }
    }
}

/// Reply shape of `org.freedesktop.PolicyKit1.Authority.CheckAuthorization`.
#[derive(Debug, serde::Deserialize, zbus::zvariant::Type)]
struct PolkitAuthorizationResult {
    is_authorized: bool,
    #[allow(dead_code)]
    is_challenge: bool,
    #[allow(dead_code)]
    details: HashMap<String, String>,
}

async fn polkit_authority_proxy(
    connection: &zbus::Connection,
) -> std::result::Result<zbus::Proxy<'static>, String> {
    zbus::Proxy::new(
        connection,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
    .await
    .map_err(|e| format!("polkit authority proxy: {e}"))
}

/// Ask polkit whether the caller connection is authorized for
/// [`PREVIEW_FRAMES_ACTION_ID`], allowing interactive agent prompts.
/// The caller's unique bus name doubles as the cancellation id.
async fn check_polkit_frame_authorization(
    connection: &zbus::Connection,
    caller: &str,
) -> std::result::Result<bool, String> {
    let proxy = polkit_authority_proxy(connection).await?;

    let mut subject_details: HashMap<&str, zbus::zvariant::Value<'_>> = HashMap::new();
    subject_details.insert("name", zbus::zvariant::Value::from(caller));
    let details: HashMap<&str, &str> = HashMap::new();

    let result: PolkitAuthorizationResult = proxy
        .call(
            "CheckAuthorization",
            &(
                ("system-bus-name", subject_details),
                PREVIEW_FRAMES_ACTION_ID,
                details,
                POLKIT_ALLOW_USER_INTERACTION,
                caller,
            ),
        )
        .await
        .map_err(|e| format!("CheckAuthorization failed: {e}"))?;

    Ok(result.is_authorized)
}

/// Background task: run one polkit check for `caller` and settle the cache.
/// Never blocks a D-Bus method reply and never holds the capture slot, so a
/// pending agent prompt cannot starve `Authenticate`.
async fn run_frame_authz_check(
    connection: zbus::Connection,
    cache: Arc<PreviewAuthzCache>,
    caller: String,
) {
    let verdict = match tokio::time::timeout(
        POLKIT_INTERACTION_TIMEOUT,
        check_polkit_frame_authorization(&connection, &caller),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => {
            // Best effort: tell polkit to tear down the pending prompt.
            if let Ok(proxy) = polkit_authority_proxy(&connection).await {
                let _: std::result::Result<(), _> = proxy
                    .call("CancelCheckAuthorization", &(caller.as_str(),))
                    .await;
            }
            Err("polkit authorization timed out".to_string())
        }
    };

    if let Ok(authorized) = &verdict {
        info!(caller = %caller, authorized, "polkit frame authorization verdict");
    }
    cache.complete(&caller, verdict, Instant::now());
}

/// Evict cached frame authorizations when their bus connection disappears
/// (`NameOwnerChanged` with no new owner for a unique name), so a grant can
/// never outlive the caller's connection.
async fn watch_bus_disconnects(
    connection: zbus::Connection,
    cache: Arc<PreviewAuthzCache>,
) -> zbus::Result<()> {
    let proxy = fdo::DBusProxy::new(&connection).await?;
    let mut stream = proxy.receive_name_owner_changed().await?;
    while let Some(signal) = stream.next().await {
        let Ok(args) = signal.args() else { continue };
        if args.new_owner().is_none() {
            let name = args.name().to_string();
            if name.starts_with(':') {
                cache.evict(&name);
            }
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CallerIdentity {
    uid: u32,
    username: Option<String>,
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

/// Every method on the `org.facelock.Daemon` D-Bus interface. Keep in sync
/// with the `#[interface]` block below — the daemon has no integration seam
/// for its D-Bus layer, so this enum plus [`Method::scope`] is the testable
/// authorization matrix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Method {
    Authenticate,
    Enroll,
    ListModels,
    RemoveModel,
    ClearModels,
    PreviewFrame,
    PreviewDetectFrame,
    ListDevices,
    ReleaseCamera,
    Ping,
    Shutdown,
}

impl Method {
    #[cfg(test)]
    const ALL: [Method; 11] = [
        Method::Authenticate,
        Method::Enroll,
        Method::ListModels,
        Method::RemoveModel,
        Method::ClearModels,
        Method::PreviewFrame,
        Method::PreviewDetectFrame,
        Method::ListDevices,
        Method::ReleaseCamera,
        Method::Ping,
        Method::Shutdown,
    ];

    fn name(self) -> &'static str {
        match self {
            Method::Authenticate => "Authenticate",
            Method::Enroll => "Enroll",
            Method::ListModels => "ListModels",
            Method::RemoveModel => "RemoveModel",
            Method::ClearModels => "ClearModels",
            Method::PreviewFrame => "PreviewFrame",
            Method::PreviewDetectFrame => "PreviewDetectFrame",
            Method::ListDevices => "ListDevices",
            Method::ReleaseCamera => "ReleaseCamera",
            Method::Ping => "Ping",
            Method::Shutdown => "Shutdown",
        }
    }

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
    fn scope(self) -> Scope {
        match self {
            Method::Authenticate => Scope::UserScoped,
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

struct FacelockService {
    handler: Arc<Mutex<ProductionHandler>>,
    /// Timestamp of last D-Bus method call (seconds since daemon start).
    last_activity: Arc<AtomicU64>,
    /// Config file mtime when the handler was last built.
    /// Used to detect config changes and reload on next request.
    config_mtime: Arc<Mutex<Option<std::time::SystemTime>>>,
    /// UID of the caller that currently owns preview camera cleanup rights.
    camera_owner_uid: Arc<Mutex<Option<u32>>>,
    /// In-flight guard for camera-capture operations (DoS control).
    capture_slot: Arc<CaptureSlot>,
    /// Per-connection polkit frame-authorization cache (PreviewDetectFrame).
    preview_authz: Arc<PreviewAuthzCache>,
}

impl FacelockService {
    fn clear_camera_owner(&self) {
        if let Ok(mut owner) = self.camera_owner_uid.lock() {
            *owner = None;
        }
    }

    fn set_camera_owner(&self, uid: u32) {
        if let Ok(mut owner) = self.camera_owner_uid.lock() {
            *owner = Some(uid);
        }
    }

    /// Check if the config file has been modified since the handler was built.
    /// If so, reload config, rebuild the engine/store/handler, and swap it in.
    /// Called at the start of authenticate and enroll — the two methods that
    /// depend on cached ONNX models and config values.
    fn maybe_reload_handler(&self) {
        let config_path = facelock_core::paths::config_path();
        let current_mtime = std::fs::metadata(&config_path)
            .and_then(|m| m.modified())
            .ok();

        let needs_reload = {
            let stored = self.config_mtime.lock().unwrap();
            match (*stored, current_mtime) {
                (Some(old), Some(new)) => new > old,
                _ => false,
            }
        };

        if !needs_reload {
            return;
        }

        info!("config file changed, reloading");

        let new_handler = match build_handler(None) {
            Ok((handler, _idle)) => handler,
            Err(e) => {
                warn!("failed to reload config: {e} — continuing with old config");
                return;
            }
        };

        // Swap in the new handler
        if let Ok(mut guard) = self.handler.lock() {
            *guard = new_handler;
        }
        self.clear_camera_owner();

        // Update stored mtime
        if let Ok(mut stored) = self.config_mtime.lock() {
            *stored = current_mtime;
        }

        info!("handler reloaded with new config");
    }
}

#[interface(name = "org.facelock.Daemon")]
impl FacelockService {
    async fn authenticate(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        #[zbus(signal_context)] ctxt: SignalEmitter<'_>,
        user: &str,
    ) -> fdo::Result<AuthResult> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        self.maybe_reload_handler();
        let caller = resolve_caller_identity(&hdr, connection).await?;
        authorize_method(&caller, Method::Authenticate, Some(user))?;
        let caller_is_root = caller.uid == 0;
        self.clear_camera_owner();
        let capture_guard = self.capture_slot.try_acquire("Authenticate")?;
        let handler = self.handler.clone();
        let user = user.to_string();
        let signal_user = user.clone();
        let result = tokio::task::spawn_blocking(move || {
            let mut handler = lock_handler_with_timeout(&handler)?;
            // N11: a root caller (e.g. root-only `facelock test`) is exempt
            // from rate-limit consumption on a failed attempt — root already
            // has unrestricted access to the rate-limit table directly, and
            // without this a few `facelock test` runs would lock the user
            // out of real authentication. See `Handler::handle_authenticate`.
            let response = handler.handle_authenticate(user.clone(), !caller_is_root);
            drop(handler);
            // Capture finished — free the slot before slower follow-up work
            // (notifications) so the next auth isn't rejected needlessly.
            drop(capture_guard);
            match response {
                DaemonResponse::AuthResult(result) => {
                    // Send desktop notification (fire-and-forget, runs as root → setpriv)
                    let event = if result.matched {
                        crate::notifications::NotifyEvent::Success {
                            label: result.label.clone(),
                            similarity: result.similarity,
                        }
                    } else {
                        crate::notifications::NotifyEvent::Failure {
                            reason: "no match".into(),
                        }
                    };
                    // Re-read notification config from disk so changes
                    // take effect without daemon restart
                    let notify_config = Config::load().map(|c| c.notification).unwrap_or_default();
                    crate::notifications::notify_if_enabled_for_user(&notify_config, &event, &user);

                    Ok(AuthResult {
                        matched: result.matched,
                        model_id: result.model_id.map(|id| id as i32).unwrap_or(-1),
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
        let result = result.map(|auth| auth.redact_similarity_unless_root(caller_is_root));

        // Emit auth_attempted signal (best-effort, don't fail auth if signal
        // fails). The payload deliberately carries no similarity score — the
        // raw biometric score is a spoof-tuning oracle for anyone able to
        // receive the broadcast; `matched` + user is enough for consumers.
        if let Ok(ref auth_result) = result {
            let _ = Self::auth_attempted(&ctxt, &signal_user, auth_result.matched).await;
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
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        self.maybe_reload_handler();
        let caller = resolve_caller_identity(&hdr, connection).await?;
        authorize_method(&caller, Method::Enroll, None)?;
        self.clear_camera_owner();
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

    async fn list_models(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        user: &str,
    ) -> fdo::Result<Vec<ModelInfo>> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        let caller = resolve_caller_identity(&hdr, connection).await?;
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

    async fn remove_model(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        user: &str,
        model_id: u32,
    ) -> fdo::Result<()> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        let caller = resolve_caller_identity(&hdr, connection).await?;
        authorize_method(&caller, Method::RemoveModel, None)?;
        let handler = self.handler.clone();
        let user = user.to_string();
        tokio::task::spawn_blocking(move || {
            let mut handler = lock_handler_with_timeout(&handler)?;
            let request = DaemonRequest::RemoveModel { user, model_id };
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

    async fn clear_models(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        user: &str,
    ) -> fdo::Result<()> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        let caller = resolve_caller_identity(&hdr, connection).await?;
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

    async fn preview_frame(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<Vec<u8>> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        let caller = resolve_caller_identity(&hdr, connection).await?;
        authorize_method(&caller, Method::PreviewFrame, None)?;
        let capture_guard = self.capture_slot.try_acquire("PreviewFrame")?;
        let handler = self.handler.clone();
        let result = tokio::task::spawn_blocking(move || {
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
        .map_err(|e| fdo::Error::Failed(format!("task join error: {e}")))?;
        if result.is_ok() {
            self.set_camera_owner(caller.uid);
        }
        result
    }

    async fn preview_detect_frame(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
        user: &str,
    ) -> fdo::Result<(Vec<u8>, Vec<PreviewFaceInfo>)> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        let caller = resolve_caller_identity(&hdr, connection).await?;
        // Root-only: preview runs per-frame with neither pre_check nor the
        // rate limiter, so for any weaker caller this method would be a
        // continuous similarity feed at camera framerate.
        authorize_method(&caller, Method::PreviewDetectFrame, None)?;
        let caller_is_root = caller.uid == 0;

        // Frame-byte authorization (root bypasses polkit). Resolved BEFORE
        // the capture slot is claimed so a pending interactive polkit prompt
        // can never hold the slot and starve Authenticate.
        let authz = if caller_is_root {
            FrameAuthz::Granted
        } else {
            let sender = hdr
                .sender()
                .ok_or_else(|| fdo::Error::Failed("no sender in D-Bus message".into()))?
                .to_string();
            let authz = self.preview_authz.begin_or_lookup(&sender, Instant::now());
            if authz == FrameAuthz::NeedsCheck {
                // Exactly one polkit round-trip per caller connection; the
                // verdict lands in the cache for subsequent frame requests.
                tokio::spawn(run_frame_authz_check(
                    connection.clone(),
                    self.preview_authz.clone(),
                    sender,
                ));
            }
            authz
        };
        let allow_frames = allow_preview_jpeg(caller_is_root, authz);

        let capture_guard = self.capture_slot.try_acquire("PreviewDetectFrame")?;
        let handler = self.handler.clone();
        let user = user.to_string();
        let result = tokio::task::spawn_blocking(move || {
            let _capture_guard = capture_guard;
            let mut handler = lock_handler_with_timeout(&handler)?;
            let request = DaemonRequest::PreviewDetectFrame { user };
            let response = handler.handle(request);
            match response {
                DaemonResponse::DetectFrame { jpeg_data, faces } => {
                    let jpeg_data = sanitize_preview_jpeg(jpeg_data, allow_frames);
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
        .map_err(|e| fdo::Error::Failed(format!("task join error: {e}")))?;
        if result.is_ok() {
            self.set_camera_owner(caller.uid);
        }
        result
    }

    async fn list_devices(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<Vec<DeviceInfo>> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        let caller = resolve_caller_identity(&hdr, connection).await?;
        authorize_method(&caller, Method::ListDevices, None)?;
        let handler = self.handler.clone();
        tokio::task::spawn_blocking(move || {
            let mut handler = lock_handler_with_timeout(&handler)?;
            let request = DaemonRequest::ListDevices;
            let response = handler.handle(request);
            match response {
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

    async fn release_camera(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<()> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        let caller = resolve_caller_identity(&hdr, connection).await?;
        authorize_method(&caller, Method::ReleaseCamera, None)?;
        let handler = self.handler.clone();
        let result = tokio::task::spawn_blocking(move || {
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
        .map_err(|e| fdo::Error::Failed(format!("task join error: {e}")))?;
        if result.is_ok() {
            self.clear_camera_owner();
        }
        result
    }

    async fn ping(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<String> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        let caller = resolve_caller_identity(&hdr, connection).await?;
        authorize_method(&caller, Method::Ping, None)?;
        Ok("pong".to_string())
    }

    async fn shutdown(
        &self,
        #[zbus(header)] hdr: zbus::message::Header<'_>,
        #[zbus(connection)] connection: &zbus::Connection,
    ) -> fdo::Result<()> {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
        let caller = resolve_caller_identity(&hdr, connection).await?;
        authorize_method(&caller, Method::Shutdown, None)?;
        self.clear_camera_owner();
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

/// Type alias for the camera factory closure.
type CameraFactory = Box<dyn Fn(&Config) -> Result<Camera<'static>, String> + Send + Sync>;

/// Build a new handler from config. Used at startup and for live config reload.
/// Returns the handler and idle_timeout_secs from the loaded config.
fn build_handler(config_path: Option<&str>) -> Result<(ProductionHandler, u64), String> {
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

    let device_is_ir = match validate_device(&device_path) {
        Ok(info) => {
            // Sibling-aware: on multi-node USB cameras only the IR sensor
            // node counts as IR, not every node sharing the quirk's VID:PID.
            let is_ir = is_ir_camera_resolved(&info, Some(&quirks));
            info!(device = %device_path, ir = is_ir, name = %info.name, "camera device");
            is_ir
        }
        Err(e) => {
            warn!("failed to query device {device_path}: {e}");
            false
        }
    };

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

    let device_quirk = validate_device(&device_path)
        .ok()
        .and_then(|info| quirks.find_match(&info).cloned());

    let quirk_for_factory = device_quirk.clone();
    let camera_factory: CameraFactory = Box::new(move |config: &Config| {
        Camera::open(&config.device, quirk_for_factory.as_ref()).map_err(|e| e.to_string())
    });

    // Device coupling (Plan 02): fingerprint the resolved camera once so enroll
    // can record it and auth can require it. Advisory only (model-granularity,
    // spoofable) — see facelock_core::types::DeviceFingerprint.
    let device_fingerprint = facelock_camera::device_fingerprint(&device_path);
    info!(
        device = %device_path,
        device_id = %device_fingerprint.canonical(),
        "camera device fingerprint"
    );

    let idle_timeout_secs = config.daemon.idle_timeout_secs;
    let warmup_override = device_quirk.and_then(|q| q.warmup_frames);
    let handler = Handler::new(
        config,
        engine,
        store,
        rate_limiter,
        device_is_ir,
        device_fingerprint,
        Some(camera_factory),
        warmup_override,
    )?;

    Ok((handler, idle_timeout_secs))
}

pub fn run(config_path: Option<String>) -> anyhow::Result<()> {
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

    let handler = Arc::new(Mutex::new(handler));

    // Build and run the tokio runtime for the D-Bus server
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    rt.block_on(run_dbus_server(handler, idle_timeout_secs, config_mtime))
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
    handler: Arc<Mutex<ProductionHandler>>,
    idle_timeout_secs: u64,
    startup_config_mtime: Option<std::time::SystemTime>,
) -> anyhow::Result<()> {
    let last_activity = Arc::new(AtomicU64::new(now_secs()));
    let preview_authz = Arc::new(PreviewAuthzCache::default());
    let service = FacelockService {
        handler: handler.clone(),
        last_activity: last_activity.clone(),
        config_mtime: Arc::new(Mutex::new(startup_config_mtime)),
        camera_owner_uid: Arc::new(Mutex::new(None)),
        capture_slot: Arc::new(CaptureSlot::default()),
        preview_authz: preview_authz.clone(),
    };

    let _connection = zbus::connection::Builder::system()?
        .name(BUS_NAME)?
        .serve_at(OBJECT_PATH, service)?
        .build()
        .await?;

    info!("facelock daemon running on D-Bus system bus as {BUS_NAME}");

    // Evict cached frame authorizations when their caller disconnects, so a
    // polkit grant can never outlive the caller's bus connection.
    let conn_for_watch = _connection.clone();
    tokio::spawn(async move {
        if let Err(e) = watch_bus_disconnects(conn_for_watch, preview_authz).await {
            warn!("failed to watch bus disconnects for authz eviction: {e}");
        }
    });

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
async fn watch_sleep_signals(handler: Arc<Mutex<ProductionHandler>>) -> anyhow::Result<()> {
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

    // --- Authorization matrix (N13) ---
    //
    // Authenticate is the only user-scoped method; everything else is
    // root-only. These tests iterate Method::ALL so a new method cannot be
    // added without landing in the matrix.

    #[test]
    fn authz_matrix_root_is_allowed_everywhere() {
        let root = caller(0, Some("root"));
        for method in Method::ALL {
            assert!(
                authorize_method(&root, method, Some("alice")).is_ok(),
                "root must be allowed to call {method:?}"
            );
        }
    }

    #[test]
    fn authz_matrix_every_method_is_root_only_except_authenticate() {
        for method in Method::ALL {
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
        for method in Method::ALL {
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

    // --- Frame authorization decision logic (polkit-gated frames) ---

    #[test]
    fn root_gets_frames_regardless_of_polkit_state() {
        for authz in [
            FrameAuthz::Granted,
            FrameAuthz::Refused,
            FrameAuthz::Pending,
            FrameAuthz::NeedsCheck,
        ] {
            assert!(allow_preview_jpeg(true, authz), "root denied at {authz:?}");
        }
    }

    #[test]
    fn non_root_gets_frames_only_when_polkit_granted() {
        assert!(allow_preview_jpeg(false, FrameAuthz::Granted));
        assert!(!allow_preview_jpeg(false, FrameAuthz::Refused));
        // Pending / not-yet-checked states FAIL CLOSED.
        assert!(!allow_preview_jpeg(false, FrameAuthz::Pending));
        assert!(!allow_preview_jpeg(false, FrameAuthz::NeedsCheck));
    }

    #[test]
    fn authz_cache_first_lookup_starts_a_check() {
        let cache = PreviewAuthzCache::default();
        let now = Instant::now();
        assert_eq!(cache.begin_or_lookup(":1.5", now), FrameAuthz::NeedsCheck);
        // Second lookup while the check is in flight must not start another.
        assert_eq!(cache.begin_or_lookup(":1.5", now), FrameAuthz::Pending);
    }

    #[test]
    fn authz_cache_polkit_authorized_grants_until_ttl() {
        let cache = PreviewAuthzCache::default();
        let now = Instant::now();
        assert_eq!(cache.begin_or_lookup(":1.5", now), FrameAuthz::NeedsCheck);
        cache.complete(":1.5", Ok(true), now);
        assert_eq!(cache.begin_or_lookup(":1.5", now), FrameAuthz::Granted);
        // Still granted just before the TTL...
        let almost = now + AUTHZ_GRANTED_TTL - Duration::from_secs(1);
        assert_eq!(cache.begin_or_lookup(":1.5", almost), FrameAuthz::Granted);
        // ...and re-checked (never silently extended) after it.
        let expired = now + AUTHZ_GRANTED_TTL + Duration::from_secs(1);
        assert_eq!(
            cache.begin_or_lookup(":1.5", expired),
            FrameAuthz::NeedsCheck
        );
    }

    #[test]
    fn authz_cache_polkit_denied_refuses_then_allows_retry() {
        let cache = PreviewAuthzCache::default();
        let now = Instant::now();
        assert_eq!(cache.begin_or_lookup(":1.5", now), FrameAuthz::NeedsCheck);
        cache.complete(":1.5", Ok(false), now);
        assert_eq!(cache.begin_or_lookup(":1.5", now), FrameAuthz::Refused);
        // A dismissed prompt can be retried after the short denial TTL.
        let retry = now + AUTHZ_DENIED_TTL + Duration::from_secs(1);
        assert_eq!(cache.begin_or_lookup(":1.5", retry), FrameAuthz::NeedsCheck);
    }

    #[test]
    fn authz_cache_polkit_error_fails_closed() {
        let cache = PreviewAuthzCache::default();
        let now = Instant::now();
        assert_eq!(cache.begin_or_lookup(":1.5", now), FrameAuthz::NeedsCheck);
        cache.complete(":1.5", Err("polkit unreachable".into()), now);
        // A polkit/D-Bus error must never grant frames.
        assert_eq!(cache.begin_or_lookup(":1.5", now), FrameAuthz::Refused);
        assert!(!allow_preview_jpeg(false, FrameAuthz::Refused));
    }

    #[test]
    fn authz_cache_eviction_kills_grant_with_connection() {
        let cache = PreviewAuthzCache::default();
        let now = Instant::now();
        assert_eq!(cache.begin_or_lookup(":1.5", now), FrameAuthz::NeedsCheck);
        cache.complete(":1.5", Ok(true), now);
        assert_eq!(cache.begin_or_lookup(":1.5", now), FrameAuthz::Granted);
        // Caller's bus connection went away — grant dies with it.
        cache.evict(":1.5");
        assert_eq!(cache.begin_or_lookup(":1.5", now), FrameAuthz::NeedsCheck);
    }

    #[test]
    fn authz_cache_drops_verdict_for_disconnected_caller() {
        let cache = PreviewAuthzCache::default();
        let now = Instant::now();
        assert_eq!(cache.begin_or_lookup(":1.5", now), FrameAuthz::NeedsCheck);
        // Connection dies while the polkit check is in flight.
        cache.evict(":1.5");
        cache.complete(":1.5", Ok(true), now);
        // The late verdict must not resurrect a grant for a dead connection
        // (a reconnecting caller re-runs the polkit check).
        assert_eq!(cache.begin_or_lookup(":1.5", now), FrameAuthz::NeedsCheck);
    }

    #[test]
    fn authz_cache_is_bounded() {
        let cache = PreviewAuthzCache::default();
        let now = Instant::now();
        for i in 0..(AUTHZ_CACHE_MAX_ENTRIES * 2) {
            let name = format!(":1.{i}");
            assert_eq!(cache.begin_or_lookup(&name, now), FrameAuthz::NeedsCheck);
            cache.complete(&name, Ok(true), now);
        }
        let len = cache.entries.lock().unwrap().len();
        assert!(
            len <= AUTHZ_CACHE_MAX_ENTRIES,
            "cache grew unbounded: {len} entries"
        );
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
