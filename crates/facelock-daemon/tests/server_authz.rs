//! Authorization-layer integration tests for the D-Bus service (D6),
//! exercised through the real `FacelockService` with a real `Handler` built
//! around mock camera/engine and an in-memory store — the tests that were
//! impossible while the server lived in the bin-only CLI crate.
//!
//! Covered here: the method-level entry points end to end minus zbus —
//! per-method authorization (denials, the Authenticate self-scope, the
//! root-only catch-all), the in-band `-2`/`-3` sentinel encoding with its
//! byte-exact protocol strings, similarity redaction for non-root callers,
//! the N11 root rate-limit exemption, and the rule that a denied caller
//! never starts a polkit round-trip.
//!
//! NOT covered here, deliberately: the zbus wiring — caller-identity
//! resolution from message headers (`GetConnectionUnixUser`), signal
//! emission, D-Bus activation, the bus policy, and real polkit round-trips.
//! A live system bus in unit-style tests is fragile; the container tiers
//! (`just test-arch-pam`, `just test-arch-integration`) prove that layer
//! against a real bus and PAM stack.

use std::sync::Arc;

use facelock_core::config::Config;
use facelock_core::notify::{Notifier, NullNotifier};
use facelock_core::types::CameraCaps;
use facelock_daemon::handler::Handler;
use facelock_daemon::rate_limit::RateLimiter;
use facelock_daemon::server::{CallerIdentity, FacelockService};
use facelock_store::FaceStore;
use facelock_test_support::fixtures;
use facelock_test_support::{MockCamera, MockFaceEngine};
use zbus::fdo;

type MockService = FacelockService<MockCamera, MockFaceEngine>;

/// Gates configured so the mock flow reaches the comparison loop: no IR
/// requirement, no variance/liveness gates, environment aborts off,
/// plaintext store (no sealer), audit off.
fn test_config(max_attempts: u32, timeout_secs: u32) -> Config {
    Config::parse(&format!(
        r#"
[recognition]
threshold = 0.45
timeout_secs = {timeout_secs}

[security]
require_ir = false
require_frame_variance = false
require_landmark_liveness = false
abort_if_ssh = false
abort_if_lid_closed = false

[security.rate_limit]
max_attempts = {max_attempts}
window_secs = 60

[encryption]
method = "none"

[audit]
enabled = false
"#
    ))
    .unwrap()
}

fn handler_with(
    config: Config,
    engine: MockFaceEngine,
    store: FaceStore,
) -> Handler<MockCamera, MockFaceEngine> {
    let rate_limiter = RateLimiter::new(
        config.security.rate_limit.max_attempts,
        config.security.rate_limit.window_secs,
    );
    let factory: Box<dyn Fn(&Config) -> Result<MockCamera, String> + Send + Sync> =
        Box::new(|_| Ok(MockCamera::bright(64, 64, 60)));
    Handler::new(
        config,
        engine,
        store,
        rate_limiter,
        CameraCaps::default(),
        Some(factory),
        None,
    )
    .unwrap()
}

fn service(handler: Handler<MockCamera, MockFaceEngine>) -> MockService {
    // No rebuild recipe (reload disabled) and a null notifier: tests assert
    // authorization and encoding, not delivery.
    FacelockService::new(
        handler,
        None,
        None,
        Arc::new(|_user: &str| Box::new(NullNotifier) as Box<dyn Notifier>),
    )
}

fn matching_service_for(user: &str) -> MockService {
    let emb = fixtures::known_embedding(1);
    let store = FaceStore::open_memory().unwrap();
    store
        .add_model(user, "front", &emb, "test-embedder")
        .unwrap();
    service(handler_with(
        test_config(5, 2),
        MockFaceEngine::one_face(emb),
        store,
    ))
}

fn caller(uid: u32, username: Option<&str>) -> CallerIdentity {
    CallerIdentity {
        uid,
        username: username.map(str::to_string),
    }
}

fn root() -> CallerIdentity {
    caller(0, Some("root"))
}

fn alice() -> CallerIdentity {
    caller(1000, Some("alice"))
}

#[track_caller]
fn assert_denied<T: std::fmt::Debug>(result: fdo::Result<T>, entry_point: &str) {
    match result {
        Err(fdo::Error::AccessDenied(_)) => {}
        other => panic!("{entry_point}: expected AccessDenied, got {other:?}"),
    }
}

#[track_caller]
fn assert_not_denied<T: std::fmt::Debug>(result: fdo::Result<T>, entry_point: &str) {
    if let Err(fdo::Error::AccessDenied(msg)) = result {
        panic!("{entry_point}: root must pass authorization, denied: {msg}");
    }
}

/// N13 through the real service: every entry point except Authenticate
/// denies a non-root caller with AccessDenied — including the metadata
/// surfaces (ListModels, ListDevices, Ping) and the continuous-score feed
/// (PreviewDetectFrame). A denied caller must never reach the handler, the
/// capture slot, or polkit.
#[tokio::test]
async fn every_entry_point_except_authenticate_denies_non_root() {
    let svc = matching_service_for("alice");
    let a = alice();

    assert_denied(svc.enroll_as(a.clone(), "alice", "front").await, "Enroll");
    assert_denied(svc.list_models_as(a.clone(), "alice").await, "ListModels");
    assert_denied(
        svc.remove_model_as(a.clone(), "alice", 1).await,
        "RemoveModel",
    );
    assert_denied(svc.clear_models_as(a.clone(), "alice").await, "ClearModels");
    assert_denied(svc.preview_frame_as(a.clone()).await, "PreviewFrame");
    assert_denied(svc.list_devices_as(a.clone()).await, "ListDevices");
    assert_denied(svc.release_camera_as(a.clone()).await, "ReleaseCamera");
    assert_denied(svc.ping_as(a.clone()).await, "Ping");
    assert_denied(svc.shutdown_as(a.clone()).await, "Shutdown");

    // The denial must fire before any polkit work: the check-starter panics
    // if a denied caller ever gets as far as the frame-authz lookup.
    let result = svc
        .preview_detect_frame_as(a, "alice", Some(":1.5".into()), |_sender| {
            panic!("a denied caller must not start a polkit round-trip")
        })
        .await;
    assert_denied(result, "PreviewDetectFrame");
}

/// Root passes authorization on every entry point. Handler-side outcomes
/// vary (this environment has no real cameras and refuses plaintext
/// enrollment), so the pin is "never AccessDenied", plus full success
/// assertions where the mock flow guarantees one.
#[tokio::test]
async fn root_passes_authorization_on_every_entry_point() {
    let svc = matching_service_for("alice");
    let r = root();

    assert_eq!(svc.ping_as(r.clone()).await.unwrap(), "pong");
    assert_eq!(
        svc.list_models_as(r.clone(), "alice").await.unwrap().len(),
        1
    );
    // C8 (wire, Phase E): the unit reply cannot say whether model 99 existed.
    svc.remove_model_as(r.clone(), "alice", 99).await.unwrap();
    svc.clear_models_as(r.clone(), "alice").await.unwrap();
    svc.release_camera_as(r.clone()).await.unwrap();
    let jpeg = svc.preview_frame_as(r.clone()).await.unwrap();
    assert!(
        !jpeg.is_empty(),
        "mock camera preview must produce JPEG bytes"
    );
    assert_not_denied(svc.list_devices_as(r.clone()).await, "ListDevices");
    // `method = "none"` without allow_plaintext: enroll refuses fast, but as
    // a handler error — authorization must already have passed.
    assert_not_denied(svc.enroll_as(r.clone(), "alice", "front").await, "Enroll");
    svc.shutdown_as(r).await.unwrap();
}

/// Authenticate is the one user-scoped method: a user may request
/// authentication for themselves (screen lockers run PAM as the user),
/// never for anyone else, and an unresolvable username fails closed.
#[tokio::test]
async fn authenticate_is_scoped_to_the_caller_own_user() {
    let svc = matching_service_for("alice");

    let own = svc.authenticate_as(alice(), "alice").await.unwrap();
    assert!(own.matched, "self-request must run the real comparison");

    assert_denied(
        svc.authenticate_as(alice(), "bob").await,
        "Authenticate (cross-user)",
    );
    assert!(
        svc.authenticate_as(caller(1000, None), "alice")
            .await
            .is_err(),
        "an unresolvable caller username must fail closed"
    );

    let as_root = svc.authenticate_as(root(), "alice").await.unwrap();
    assert!(as_root.matched, "root may authenticate any user");
}

/// N12 through the real service: the similarity score is a hill-climbing
/// oracle and is zeroed for every non-root caller; the boolean outcome and
/// matched model survive. Root sees the real score.
#[tokio::test]
async fn similarity_is_redacted_for_non_root_callers() {
    let svc = matching_service_for("alice");

    let unredacted = svc.authenticate_as(root(), "alice").await.unwrap();
    assert!(unredacted.matched);
    assert!(
        unredacted.similarity > 0.9,
        "identical embeddings must score high for root, got {}",
        unredacted.similarity
    );

    let redacted = svc.authenticate_as(alice(), "alice").await.unwrap();
    assert!(redacted.matched, "redaction must not change the outcome");
    assert_eq!(redacted.model_id, unredacted.model_id);
    assert_eq!(
        redacted.similarity, 0.0,
        "score must be zeroed for non-root"
    );
}

/// Recoverable failures travel in-band as `model_id == -2` with the message
/// in `label` — never as a D-Bus error, which would make PAM fall back to a
/// fresh root oneshot and silently bypass daemon-side state. The two
/// protocol strings PAM matches must arrive byte-identical.
#[tokio::test]
async fn rate_limited_flows_in_band_with_the_exact_protocol_string() {
    let emb = fixtures::known_embedding(1);
    let store = FaceStore::open_memory().unwrap();
    store
        .add_model("alice", "front", &emb, "test-embedder")
        .unwrap();
    // Exhaust the budget before the service ever runs.
    let limiter = RateLimiter::new(1, 60);
    limiter.record_failure(&store, "alice").unwrap();

    let svc = service(handler_with(
        test_config(1, 1),
        MockFaceEngine::one_face(emb),
        store,
    ));

    let result = svc.authenticate_as(alice(), "alice").await.unwrap();
    assert!(!result.matched);
    assert_eq!(result.model_id, -2, "recoverable error sentinel");
    assert_eq!(
        result.label, "rate limited",
        "PAM string-matches this exactly"
    );
}

#[tokio::test]
async fn require_ir_flows_in_band_with_the_exact_protocol_string() {
    let emb = fixtures::known_embedding(1);
    let store = FaceStore::open_memory().unwrap();
    store
        .add_model("alice", "front", &emb, "test-embedder")
        .unwrap();
    let mut config = test_config(5, 1);
    config.security.require_ir = true;

    // CameraCaps::default() is non-IR, so the gate must reject in-band.
    let svc = service(handler_with(config, MockFaceEngine::one_face(emb), store));

    let result = svc.authenticate_as(alice(), "alice").await.unwrap();
    assert!(!result.matched);
    assert_eq!(result.model_id, -2);
    assert!(
        result.label.contains("IR camera required"),
        "PAM string-matches \"IR camera required\", got: {}",
        result.label
    );
}

/// `suppress_unknown` + no enrolled models maps to the `-3` sentinel, which
/// PAM turns into PAM_AUTHINFO_UNAVAIL so the stack falls through.
#[tokio::test]
async fn suppress_unknown_maps_to_the_minus_three_sentinel() {
    let mut config = test_config(5, 1);
    config.security.suppress_unknown = true;

    let svc = service(handler_with(
        config,
        MockFaceEngine::no_faces(),
        FaceStore::open_memory().unwrap(),
    ));

    let result = svc.authenticate_as(alice(), "alice").await.unwrap();
    assert!(!result.matched);
    assert_eq!(result.model_id, -3, "suppressed sentinel");
    assert!(result.label.is_empty());
}

/// N11 wiring: the service exempts root callers from rate-limit consumption
/// (`facelock test` reaches the daemon through Authenticate, and failed test
/// runs must not lock the user out), while a user's own failed attempts
/// still charge the shared budget.
#[tokio::test]
async fn root_failed_attempts_do_not_charge_the_rate_limit() {
    let emb = fixtures::known_embedding(1);
    let store = FaceStore::open_memory().unwrap();
    store
        .add_model("alice", "front", &emb, "test-embedder")
        .unwrap();

    // Budget of one failed attempt; the engine never sees a face.
    let svc = service(handler_with(
        test_config(1, 1),
        MockFaceEngine::no_faces(),
        store,
    ));

    // Two consecutive failed ROOT attempts: neither is charged, so the
    // second still runs the comparison instead of reporting "rate limited".
    for attempt in 0..2 {
        let result = svc.authenticate_as(root(), "alice").await.unwrap();
        assert!(!result.matched);
        assert_eq!(
            result.model_id, -1,
            "root attempt {attempt} must be an ordinary non-match, not a rate-limit rejection: {result:?}"
        );
    }

    // Alice's own failed attempt IS charged...
    let charged = svc.authenticate_as(alice(), "alice").await.unwrap();
    assert!(!charged.matched);
    assert_eq!(charged.model_id, -1);

    // ...so her next attempt is rejected in-band before the camera runs.
    let limited = svc.authenticate_as(alice(), "alice").await.unwrap();
    assert_eq!(limited.model_id, -2);
    assert_eq!(limited.label, "rate limited");
}

/// The root preview path end to end: frames and per-face metadata with the
/// unredacted score (root-only), and no polkit involvement.
#[tokio::test]
async fn preview_detect_frame_for_root_returns_frames_and_scores() {
    let svc = matching_service_for("alice");

    let (jpeg, faces) = svc
        .preview_detect_frame_as(root(), "alice", None, |_sender| {
            panic!("root must never need a polkit round-trip")
        })
        .await
        .unwrap();

    assert!(!jpeg.is_empty(), "root gets raw frame bytes");
    assert_eq!(faces.len(), 1);
    assert!(faces[0].recognized);
    assert!(
        faces[0].similarity > 0.9,
        "root sees the unredacted score, got {}",
        faces[0].similarity
    );
}
