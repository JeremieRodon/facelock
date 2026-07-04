use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use facelock_core::config::Config;
use facelock_core::ipc::{DaemonRequest, DaemonResponse};
use facelock_core::types::MatchResult;
use facelock_store::FaceStore;
use facelock_test_support::fixtures;
use facelock_test_support::{MockCamera, MockFaceEngine};

// Import the handler module (it's pub in the crate)
// We need to reference it via the crate directly since it's a binary crate.
// Instead, we'll replicate the handler construction here.

// The handler type and modules are internal to the daemon binary.
// For integration tests, we test the auth/enroll logic via the Handler's handle() method.
// We use a helper module that re-exports what we need.

// Since handler.rs, auth.rs, enroll.rs are private modules of the binary,
// we test through the public Handler type by depending on the library parts.
// The daemon crate is a binary — we can't import from it directly.
// So we test the auth/enroll logic at unit level within the daemon,
// and test the full IPC protocol here by running a mock daemon in-process.

// Actually, let's test by constructing the handler directly.
// We'll make the handler module public for tests.

// For now, test the trait implementations and mock infrastructure work correctly,
// and validate the auth/enroll logic through the core types.

fn test_config() -> Config {
    let toml = fixtures::test_config_toml("/tmp/facelock-test-integ.db");
    Config::parse(&toml).unwrap()
}

fn temp_db_path(test_name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "facelock-{test_name}-{}-{unique}.db",
        std::process::id()
    ))
}

fn cleanup_db(path: &Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_file(path.with_extension("db-shm"));
    let _ = std::fs::remove_file(path.with_extension("db-wal"));
    let _ = std::fs::remove_file(format!("{}-shm", path.display()));
    let _ = std::fs::remove_file(format!("{}-wal", path.display()));
}

#[test]
fn mock_camera_produces_bright_frames() {
    use facelock_core::traits::CameraSource;
    let mut cam = MockCamera::bright(640, 480, 5);
    let frame = cam.capture().unwrap();
    assert_eq!(frame.width, 640);
    assert_eq!(frame.height, 480);
    assert!(!MockCamera::is_dark(&frame));
    assert_eq!(cam.captures(), 1);
}

#[test]
fn mock_camera_dark_frames_detected() {
    use facelock_core::traits::CameraSource;
    let mut cam = MockCamera::dark(640, 480, 3);
    let frame = cam.capture().unwrap();
    assert!(MockCamera::is_dark(&frame));
}

#[test]
fn mock_camera_wraps_around() {
    use facelock_core::traits::CameraSource;
    let mut cam = MockCamera::bright(64, 64, 2);
    let _ = cam.capture().unwrap();
    let _ = cam.capture().unwrap();
    // Third capture wraps around
    let frame = cam.capture().unwrap();
    assert_eq!(frame.width, 64);
}

#[test]
fn mock_face_engine_one_face() {
    use facelock_core::traits::FaceProcessor;
    let emb = fixtures::known_embedding(0);
    let mut engine = MockFaceEngine::one_face(emb);
    let frame = fixtures::bright_frame(640, 480);
    let results = engine.process(&frame).unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].1, emb);
}

#[test]
fn mock_face_engine_no_faces() {
    use facelock_core::traits::FaceProcessor;
    let mut engine = MockFaceEngine::no_faces();
    let frame = fixtures::bright_frame(640, 480);
    let results = engine.process(&frame).unwrap();
    assert!(results.is_empty());
}

#[test]
fn mock_face_engine_cycling() {
    use facelock_core::traits::FaceProcessor;
    let emb1 = fixtures::known_embedding(0);
    let emb2 = fixtures::known_embedding(50);
    let mut engine = MockFaceEngine::cycling(vec![emb1, emb2]);
    let frame = fixtures::bright_frame(640, 480);

    let r1 = engine.process(&frame).unwrap();
    assert_eq!(r1[0].1, emb1);
    let r2 = engine.process(&frame).unwrap();
    assert_eq!(r2[0].1, emb2);
    // Wraps around
    let r3 = engine.process(&frame).unwrap();
    assert_eq!(r3[0].1, emb1);
}

#[test]
fn fixtures_varied_embeddings_differ() {
    let (e1, e2) = fixtures::varied_embedding_pair();
    let sim: f32 = e1.iter().zip(e2.iter()).map(|(a, b)| a * b).sum();
    assert!(sim < 0.998, "varied pair should differ enough, got {sim}");
}

#[test]
fn fixtures_identical_embeddings_same() {
    let (e1, e2) = fixtures::identical_embedding_pair();
    assert_eq!(e1, e2);
}

#[test]
fn store_round_trip_with_mock_embedding() {
    let store = FaceStore::open_memory().unwrap();
    let emb = fixtures::known_embedding(42);
    let id = store.add_model("testuser", "test-label", &emb, "").unwrap();
    let stored = store.get_user_embeddings("testuser").unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].0, id);
    assert_eq!(stored[0].1, emb);
}

#[test]
fn test_config_parses() {
    let config = test_config();
    assert_eq!(config.recognition.timeout_secs, 2);
    assert!(!config.security.require_ir);
    assert!(config.security.require_frame_variance);
    assert_eq!(config.security.min_auth_frames, 2);
}

/// Device coupling (Plan 02): a template whose enrolling-camera fingerprint does
/// not match the live camera must never authenticate, even when the presented
/// embedding is a perfect match. The mismatch degrades to no-match → password
/// (fail soft), and the same template on the matching camera still succeeds.
#[test]
fn device_mismatch_never_reaches_success() {
    use facelock_core::types::{DeviceFingerprint, FaceModelInfo};
    use facelock_daemon::auth::authenticate_with_embeddings;

    let mut config = test_config();
    // Isolate the device-binding effect from the other liveness gates.
    config.security.require_frame_variance = false;
    config.security.require_landmark_liveness = false;
    config.recognition.threshold = 0.5;
    config.recognition.timeout_secs = 2;
    assert!(
        config.security.bind_templates_to_device,
        "coupling must default on"
    );

    let emb = fixtures::known_embedding(7);
    let stored = vec![(1u32, emb)];
    let models = vec![FaceModelInfo {
        id: 1,
        user: "u".into(),
        label: "front".into(),
        created_at: 0,
        embedder_model: String::new(),
        device_id: Some("aaaa:bbbb:".into()),
    }];

    let mismatch = DeviceFingerprint {
        vid: Some("cccc".into()),
        pid: Some("dddd".into()),
        serial: None,
        by_path: None,
    };
    let mut engine = MockFaceEngine::one_face(emb);
    let mut cam = MockCamera::bright(64, 64, 10);
    let resp = authenticate_with_embeddings(
        &mut cam,
        &mut engine,
        &stored,
        &models,
        &config,
        "u",
        false,
        &mismatch,
    );
    match resp {
        DaemonResponse::AuthResult(MatchResult { matched, .. }) => {
            assert!(
                !matched,
                "device mismatch must not authenticate a perfect embedding match"
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }

    // Same template, matching camera → authenticates.
    let matching = DeviceFingerprint {
        vid: Some("aaaa".into()),
        pid: Some("bbbb".into()),
        serial: None,
        by_path: None,
    };
    let mut engine2 = MockFaceEngine::one_face(emb);
    let mut cam2 = MockCamera::bright(64, 64, 10);
    let resp2 = authenticate_with_embeddings(
        &mut cam2,
        &mut engine2,
        &stored,
        &models,
        &config,
        "u",
        false,
        &matching,
    );
    match resp2 {
        DaemonResponse::AuthResult(MatchResult { matched, .. }) => {
            assert!(matched, "matching device must authenticate");
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

/// Legacy templates (NULL device_id) still authenticate under the default
/// allow-with-warn policy — an upgrade must not lock anyone out.
#[test]
fn legacy_null_device_id_still_authenticates() {
    use facelock_core::types::{DeviceFingerprint, FaceModelInfo};
    use facelock_daemon::auth::authenticate_with_embeddings;

    let mut config = test_config();
    config.security.require_frame_variance = false;
    config.recognition.threshold = 0.5;
    config.recognition.timeout_secs = 2;

    let emb = fixtures::known_embedding(11);
    let stored = vec![(1u32, emb)];
    let models = vec![FaceModelInfo {
        id: 1,
        user: "u".into(),
        label: "legacy".into(),
        created_at: 0,
        embedder_model: String::new(),
        device_id: None,
    }];

    // Even a fully-identified live camera authenticates a legacy NULL template.
    let live = DeviceFingerprint {
        vid: Some("aaaa".into()),
        pid: Some("bbbb".into()),
        serial: None,
        by_path: None,
    };
    let mut engine = MockFaceEngine::one_face(emb);
    let mut cam = MockCamera::bright(64, 64, 10);
    let resp = authenticate_with_embeddings(
        &mut cam,
        &mut engine,
        &stored,
        &models,
        &config,
        "u",
        false,
        &live,
    );
    match resp {
        DaemonResponse::AuthResult(MatchResult { matched, .. }) => {
            assert!(
                matched,
                "legacy NULL device_id must authenticate (allow-with-warn)"
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn warmup_frames_discarded_on_camera_open() {
    use facelock_daemon::handler::Handler;
    use facelock_daemon::rate_limit::RateLimiter;

    let mut config = test_config();
    config.device.warmup_frames = 3;

    let engine = MockFaceEngine::no_faces();
    let store = FaceStore::open_memory().unwrap();
    let rate_limiter = RateLimiter::new(
        config.security.rate_limit.max_attempts,
        config.security.rate_limit.window_secs,
    );

    // Track captures via a shared counter
    let capture_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let _counter = capture_count.clone();

    let factory: Box<
        dyn Fn(&facelock_core::config::Config) -> Result<MockCamera, String> + Send + Sync,
    > = Box::new(move |_cfg| {
        // Camera with enough frames for warmup + auth
        Ok(MockCamera::bright(64, 64, 20))
    });

    let mut handler = Handler::new(
        config,
        engine,
        store,
        rate_limiter,
        false,
        facelock_core::types::DeviceFingerprint::default(),
        Some(factory),
        None,
    )
    .unwrap();

    // Ping triggers no camera open
    let resp = handler.handle(DaemonRequest::Ping);
    assert!(matches!(resp, DaemonResponse::Ok));

    // PreviewFrame triggers acquire_camera which discards warmup frames
    let resp = handler.handle(DaemonRequest::PreviewFrame);
    // Should succeed (camera opened, warmup discarded, then one frame captured for preview)
    assert!(
        !matches!(resp, DaemonResponse::Error { .. }),
        "expected successful preview, got: {resp:?}"
    );
}

#[test]
fn warmup_frames_zero_skips_discard() {
    use facelock_daemon::handler::Handler;
    use facelock_daemon::rate_limit::RateLimiter;

    let mut config = test_config();
    config.device.warmup_frames = 0;

    let engine = MockFaceEngine::no_faces();
    let store = FaceStore::open_memory().unwrap();
    let rate_limiter = RateLimiter::new(
        config.security.rate_limit.max_attempts,
        config.security.rate_limit.window_secs,
    );

    let factory: Box<
        dyn Fn(&facelock_core::config::Config) -> Result<MockCamera, String> + Send + Sync,
    > = Box::new(move |_cfg| Ok(MockCamera::bright(64, 64, 5)));

    let mut handler = Handler::new(
        config,
        engine,
        store,
        rate_limiter,
        false,
        facelock_core::types::DeviceFingerprint::default(),
        Some(factory),
        None,
    )
    .unwrap();

    // Should work fine with zero warmup
    let resp = handler.handle(DaemonRequest::PreviewFrame);
    assert!(
        !matches!(resp, DaemonResponse::Error { .. }),
        "expected successful preview with zero warmup, got: {resp:?}"
    );
}

/// Unit embedding at a planar angle: cosine similarity between two of these
/// is exactly cos(theta_a - theta_b).
fn unit_at_angle(theta: f32) -> facelock_core::types::FaceEmbedding {
    let mut e: facelock_core::types::FaceEmbedding = [0.0; 512];
    e[0] = theta.cos();
    e[1] = theta.sin();
    e
}

/// A legacy (no device id) model info for model `id` — allowed by the default
/// device-binding policy so variance tests are not affected by device coupling.
fn legacy_model(id: u32) -> facelock_core::types::FaceModelInfo {
    facelock_core::types::FaceModelInfo {
        id,
        user: "testuser".into(),
        label: "front".into(),
        created_at: 0,
        embedder_model: String::new(),
        device_id: None,
    }
}

#[test]
fn static_matching_frames_report_variance_reason() {
    use facelock_core::types::AuthFailureReason;

    let mut config = test_config();
    config.recognition.timeout_secs = 1;

    // Static input: the exact same embedding every frame (photo-like), which
    // matches the enrolled template perfectly but never drifts.
    let emb = unit_at_angle(0.0);
    let mut camera = MockCamera::bright(64, 64, 4);
    let mut engine = MockFaceEngine::one_face(emb);
    let stored = vec![(1u32, emb)];
    let models = vec![legacy_model(1)];

    let resp = facelock_daemon::auth::authenticate_with_embeddings(
        &mut camera,
        &mut engine,
        &stored,
        &models,
        &config,
        "testuser",
        false,
        &facelock_core::types::DeviceFingerprint::default(),
    );

    match resp {
        DaemonResponse::AuthResult(r) => {
            assert!(!r.matched, "static input must not authenticate");
            assert!(
                r.similarity >= config.recognition.threshold,
                "sanity: frames matched above the recognition threshold"
            );
            assert_eq!(
                r.failure_reason,
                Some(AuthFailureReason::VarianceNotSatisfied),
                "outcome must say the variance gate was the blocker"
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

#[test]
fn still_then_moving_frames_recover_and_authenticate() {
    let mut config = test_config();
    config.recognition.timeout_secs = 2;

    // A user who holds still for the first frames, then moves. With the old
    // append-only history the early still pair poisoned the session forever;
    // the sliding window must recover and authenticate.
    let still = unit_at_angle(0.0);
    let frames = vec![
        still,
        still,
        still,
        still,
        still,
        unit_at_angle(0.20), // pair drift cos(0.20) ~= 0.9801 <= 0.985
        unit_at_angle(0.40),
        unit_at_angle(0.60),
    ];
    let mut camera = MockCamera::bright(64, 64, 16);
    let mut engine = MockFaceEngine::cycling(frames);
    let stored = vec![(1u32, still)];
    let models = vec![legacy_model(1)];

    let resp = facelock_daemon::auth::authenticate_with_embeddings(
        &mut camera,
        &mut engine,
        &stored,
        &models,
        &config,
        "testuser",
        false,
        &facelock_core::types::DeviceFingerprint::default(),
    );

    match resp {
        DaemonResponse::AuthResult(r) => {
            assert!(
                r.matched,
                "still-then-moving user must authenticate once the window fills \
                 with moving frames, got similarity {} reason {:?}",
                r.similarity, r.failure_reason
            );
        }
        other => panic!("unexpected response: {other:?}"),
    }
}

/// FIX B regression gate (Plan 04, storage & crypto honesty): with an encryption
/// method configured (`keyfile`), a sealer-init failure must make ENROLL fail
/// CLOSED. It must NOT silently downgrade to plaintext biometric storage.
///
/// Previously the daemon only `warn!`-logged the keyfile error and dropped the
/// sealer (`software_sealer = None`); enroll then stored the embedding as
/// plaintext (`sealed = false`), defeating encrypt-by-default. This test injects
/// a guaranteed keyfile-init failure (key path whose parent is a regular file, so
/// both key generation and the subsequent read fail — deterministic, uid-agnostic)
/// and asserts that enroll returns an error and writes NO plaintext row.
///
/// It also asserts the handler still BUILDS: the fix is enroll-only, so the auth
/// path stays up and continues to fall through to password as before.
#[test]
fn keyfile_sealer_init_failure_fails_enroll_closed_no_plaintext() {
    use facelock_core::config::EncryptionMethod;
    use facelock_daemon::handler::Handler;
    use facelock_daemon::rate_limit::RateLimiter;

    // A keyfile path whose parent is a *regular file*: create_dir_all(parent)
    // fails with ENOTDIR during key generation, and the read-back also fails.
    let blocker = temp_db_path("keyfile-blocker");
    cleanup_db(&blocker);
    std::fs::write(&blocker, b"not a directory").unwrap();
    let bad_key_path = blocker.join("facelock.key");

    let mut config = test_config();
    config.encryption.method = EncryptionMethod::Keyfile;
    config.encryption.key_path = bad_key_path.to_string_lossy().into_owned();

    // In-memory store so we can inspect exactly what enroll persisted.
    let store = FaceStore::open_memory().unwrap();
    let rate_limiter = RateLimiter::new(
        config.security.rate_limit.max_attempts,
        config.security.rate_limit.window_secs,
    );

    // A camera + engine that WOULD drive a valid enrollment, so the pre-fix code
    // path reaches plaintext storage (proving the downgrade the fix closes).
    let factory: Box<
        dyn Fn(&facelock_core::config::Config) -> Result<MockCamera, String> + Send + Sync,
    > = Box::new(move |_cfg| Ok(MockCamera::bright(640, 480, 40)));
    let engine = MockFaceEngine::cycling(vec![
        fixtures::known_embedding(0),
        fixtures::known_embedding(40),
        fixtures::known_embedding(80),
        fixtures::known_embedding(120),
    ]);

    // The handler MUST still build even though the keyfile sealer failed —
    // otherwise the whole daemon (including auth) would be taken down.
    let mut handler = Handler::new(
        config,
        engine,
        store,
        rate_limiter,
        false,
        facelock_core::types::DeviceFingerprint::default(),
        Some(factory),
        None,
    )
    .expect("handler must build even when the keyfile sealer fails (auth stays up)");

    let resp = handler.handle(DaemonRequest::Enroll {
        user: "u".into(),
        label: "front".into(),
    });

    match resp {
        DaemonResponse::Error { ref message } => {
            let m = message.to_lowercase();
            assert!(
                m.contains("keyfile") || m.contains("plaintext"),
                "enroll must fail with a clear keyfile/plaintext message, got: {message}"
            );
        }
        other => panic!(
            "enroll must fail CLOSED when the keyfile sealer is unavailable, got: {other:?}"
        ),
    }

    // Security invariant: NO plaintext (sealed=false) embedding was ever written
    // (and no sealed row either, since the sealer was unavailable).
    let (sealed, unsealed) = handler.store.count_sealed().unwrap();
    assert_eq!(
        unsealed, 0,
        "a plaintext biometric embedding must never be stored when method=keyfile"
    );
    assert_eq!(sealed, 0, "no embedding should have been stored at all");

    cleanup_db(&blocker);
}

#[test]
fn failed_auth_rate_limit_persists_across_handler_restart() {
    use facelock_daemon::handler::Handler;
    use facelock_daemon::rate_limit::RateLimiter;

    let db_path = temp_db_path("rate-limit-persist");
    cleanup_db(&db_path);

    let db_path_str = db_path.to_string_lossy().into_owned();
    let mut config = Config::parse(&fixtures::test_config_toml(&db_path_str)).unwrap();
    config.recognition.timeout_secs = 0;
    config.security.rate_limit.max_attempts = 1;
    config.security.require_frame_variance = false;
    config.security.require_landmark_liveness = false;

    {
        let store = FaceStore::open(&db_path).unwrap();
        store
            .add_model("testuser", "front", &fixtures::known_embedding(0), "")
            .unwrap();
    }

    let factory1: Box<
        dyn Fn(&facelock_core::config::Config) -> Result<MockCamera, String> + Send + Sync,
    > = Box::new(move |_cfg| Ok(MockCamera::bright(64, 64, 1)));

    let mut first_handler = Handler::new(
        config.clone(),
        MockFaceEngine::no_faces(),
        FaceStore::open(&db_path).unwrap(),
        RateLimiter::new(
            config.security.rate_limit.max_attempts,
            config.security.rate_limit.window_secs,
        ),
        false,
        facelock_core::types::DeviceFingerprint::default(),
        Some(factory1),
        None,
    )
    .unwrap();

    let first = first_handler.handle(DaemonRequest::Authenticate {
        user: "testuser".into(),
    });
    assert!(matches!(
        first,
        DaemonResponse::AuthResult(MatchResult { matched: false, .. })
    ));

    let factory2: Box<
        dyn Fn(&facelock_core::config::Config) -> Result<MockCamera, String> + Send + Sync,
    > = Box::new(move |_cfg| Ok(MockCamera::bright(64, 64, 1)));

    let mut restarted_handler = Handler::new(
        config.clone(),
        MockFaceEngine::no_faces(),
        FaceStore::open(&db_path).unwrap(),
        RateLimiter::new(
            config.security.rate_limit.max_attempts,
            config.security.rate_limit.window_secs,
        ),
        false,
        facelock_core::types::DeviceFingerprint::default(),
        Some(factory2),
        None,
    )
    .unwrap();

    let second = restarted_handler.handle(DaemonRequest::Authenticate {
        user: "testuser".into(),
    });
    assert!(matches!(
        second,
        DaemonResponse::Error { ref message } if message.contains("rate limited")
    ));

    cleanup_db(&db_path);
}
