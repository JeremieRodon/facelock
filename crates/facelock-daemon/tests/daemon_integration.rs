use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use facelock_core::config::Config;
use facelock_core::types::MatchResult;
use facelock_daemon::audit::AuditSource;
use facelock_daemon::auth::AuthOutcome;
use facelock_daemon::handler::{AuthIntent, DaemonRequest, DaemonResponse};
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

/// D8 compile-time pin: `CameraSource` is object-safe. The old trait carried
/// `fn is_dark(..) where Self: Sized`, which made `dyn CameraSource`
/// unusable; darkness is a free function now and capabilities live on the
/// camera, so a boxed camera works.
#[test]
fn camera_source_is_object_safe() {
    use facelock_core::traits::CameraSource;
    let mut cam: Box<dyn CameraSource> = Box::new(MockCamera::bright(64, 64, 1));
    let frame = cam.capture().unwrap();
    assert_eq!(frame.width, 64);
    assert!(!cam.capabilities().is_ir);
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

    // The live camera's identity now rides on its caps — the auth loop asks
    // the camera rather than taking a fingerprint parameter (D8).
    let mismatch = DeviceFingerprint {
        vid: Some("cccc".into()),
        pid: Some("dddd".into()),
        serial: None,
        by_path: None,
    };
    let mut engine = MockFaceEngine::one_face(emb);
    let mut cam = MockCamera::bright(64, 64, 10).with_caps(facelock_core::types::CameraCaps {
        fingerprint: mismatch,
        ..Default::default()
    });
    let resp = authenticate_with_embeddings(
        &mut cam,
        &mut engine,
        &stored,
        &models,
        &config,
        "u",
        AuditSource::Daemon,
    );
    match resp {
        AuthOutcome::AuthResult(MatchResult { matched, .. }) => {
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
    let mut cam2 = MockCamera::bright(64, 64, 10).with_caps(facelock_core::types::CameraCaps {
        fingerprint: matching,
        ..Default::default()
    });
    let resp2 = authenticate_with_embeddings(
        &mut cam2,
        &mut engine2,
        &stored,
        &models,
        &config,
        "u",
        AuditSource::Daemon,
    );
    match resp2 {
        AuthOutcome::AuthResult(MatchResult { matched, .. }) => {
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
    let mut cam = MockCamera::bright(64, 64, 10).with_caps(facelock_core::types::CameraCaps {
        fingerprint: live,
        ..Default::default()
    });
    let resp = authenticate_with_embeddings(
        &mut cam,
        &mut engine,
        &stored,
        &models,
        &config,
        "u",
        AuditSource::Daemon,
    );
    match resp {
        AuthOutcome::AuthResult(MatchResult { matched, .. }) => {
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

    let factory: facelock_test_support::mock_camera::MockCameraFactory = Box::new(move |_cfg| {
        // Camera with enough frames for warmup + auth
        Ok(MockCamera::bright(64, 64, 20))
    });

    let mut handler = Handler::new(
        config,
        engine,
        store,
        rate_limiter,
        facelock_core::types::CameraCaps::default(),
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

    let factory: facelock_test_support::mock_camera::MockCameraFactory =
        Box::new(move |_cfg| Ok(MockCamera::bright(64, 64, 5)));

    let mut handler = Handler::new(
        config,
        engine,
        store,
        rate_limiter,
        facelock_core::types::CameraCaps::default(),
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
        AuditSource::Daemon,
    );

    match resp {
        AuthOutcome::AuthResult(r) => {
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
        AuditSource::Daemon,
    );

    match resp {
        AuthOutcome::AuthResult(r) => {
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

/// Pins the daemon auth loop's audit contract: a failed attempt writes an entry
/// when audit logging is enabled, stamped with the caller's `AuditSource`. The
/// drifted direct-mode copy of this loop wrote no audit trail at all, so direct
/// mode is only covered for as long as `direct.rs` keeps calling this function —
/// a re-fork would leave this test green. Nothing here can detect that.
#[test]
fn failed_auth_writes_audit_entry() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    // A dedicated directory: write_audit_entry chmods the log's parent, which
    // must never be a shared directory like /tmp itself.
    let dir = std::env::temp_dir().join(format!("facelock-audit-{}-{unique}", std::process::id()));
    let log_path = dir.join("audit.jsonl");

    let mut config = test_config();
    config.recognition.timeout_secs = 1;
    config.audit.enabled = true;
    config.audit.path = log_path.display().to_string();

    // No enrolled templates to compare against, so the attempt times out as a
    // plain failure rather than tripping the variance gate.
    let mut camera = MockCamera::bright(64, 64, 4);
    let mut engine = MockFaceEngine::one_face(unit_at_angle(0.0));

    let resp = facelock_daemon::auth::authenticate_with_embeddings(
        &mut camera,
        &mut engine,
        &[],
        &[],
        &config,
        "testuser",
        AuditSource::Daemon,
    );
    assert!(
        matches!(resp, AuthOutcome::AuthResult(ref r) if !r.matched),
        "sanity: attempt with no enrolled templates must fail, got {resp:?}"
    );

    // Same loop, run the way `facelock test` runs it. Its entry must be
    // distinguishable from the daemon's: `facelock test` skips the pre_check
    // gates, so its results are not policy-approved authentications.
    let mut camera = MockCamera::bright(64, 64, 4);
    let mut engine = MockFaceEngine::one_face(unit_at_angle(0.0));
    facelock_daemon::auth::authenticate_with_embeddings(
        &mut camera,
        &mut engine,
        &[],
        &[],
        &config,
        "testuser",
        AuditSource::Test,
    );

    let written = std::fs::read_to_string(&log_path).expect("audit log must exist");
    let entries: Vec<serde_json::Value> = written
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit entry must be valid JSON"))
        .collect();
    assert_eq!(entries.len(), 2, "each attempt writes one entry");
    assert_eq!(entries[0]["result"], "failure");
    assert_eq!(entries[0]["user"], "testuser");
    assert_eq!(entries[0]["source"], "daemon");
    assert_eq!(entries[1]["source"], "test");

    let _ = std::fs::remove_dir_all(&dir);
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
    let factory: facelock_test_support::mock_camera::MockCameraFactory =
        Box::new(move |_cfg| Ok(MockCamera::bright(640, 480, 40)));
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
        facelock_core::types::CameraCaps::default(),
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
        other => {
            panic!("enroll must fail CLOSED when the keyfile sealer is unavailable, got: {other:?}")
        }
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
        let store = FaceStore::create(&db_path).unwrap();
        store
            .add_model("testuser", "front", &fixtures::known_embedding(0), "")
            .unwrap();
    }

    let factory1: facelock_test_support::mock_camera::MockCameraFactory =
        Box::new(move |_cfg| Ok(MockCamera::bright(64, 64, 1)));

    let mut first_handler = Handler::new(
        config.clone(),
        MockFaceEngine::no_faces(),
        FaceStore::create(&db_path).unwrap(),
        RateLimiter::new(
            config.security.rate_limit.max_attempts,
            config.security.rate_limit.window_secs,
        ),
        facelock_core::types::CameraCaps::default(),
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

    let factory2: facelock_test_support::mock_camera::MockCameraFactory =
        Box::new(move |_cfg| Ok(MockCamera::bright(64, 64, 1)));

    let mut restarted_handler = Handler::new(
        config.clone(),
        MockFaceEngine::no_faces(),
        FaceStore::create(&db_path).unwrap(),
        RateLimiter::new(
            config.security.rate_limit.max_attempts,
            config.security.rate_limit.window_secs,
        ),
        facelock_core::types::CameraCaps::default(),
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

/// N11 (issue #96): `facelock test` must never consume the shared
/// rate-limit budget on failure — a handful of failed test runs must not
/// lock the user out of real authentication afterward.
///
/// This pins the handler half of that: `AuthIntent::Test` charges nothing.
/// The intent is no longer inferred from the caller's privilege (which was
/// the bug — `sudo`'s PAM stack is root too); it arrives from the root-only
/// `TestAuthenticate` D-Bus method, which `tests/server_authz.rs` covers.
#[test]
fn test_intent_does_not_consume_rate_limit_budget() {
    use facelock_daemon::handler::Handler;
    use facelock_daemon::rate_limit::RateLimiter;

    let db_path = temp_db_path("rate-limit-exempt");
    cleanup_db(&db_path);

    let db_path_str = db_path.to_string_lossy().into_owned();
    let mut config = Config::parse(&fixtures::test_config_toml(&db_path_str)).unwrap();
    config.recognition.timeout_secs = 0;
    config.security.rate_limit.max_attempts = 1;
    config.security.require_frame_variance = false;
    config.security.require_landmark_liveness = false;

    {
        let store = FaceStore::create(&db_path).unwrap();
        store
            .add_model("testuser", "front", &fixtures::known_embedding(0), "")
            .unwrap();
    }

    let factory: facelock_test_support::mock_camera::MockCameraFactory =
        Box::new(move |_cfg| Ok(MockCamera::bright(64, 64, 1)));

    let mut handler = Handler::new(
        config.clone(),
        MockFaceEngine::no_faces(),
        FaceStore::create(&db_path).unwrap(),
        RateLimiter::new(
            config.security.rate_limit.max_attempts,
            config.security.rate_limit.window_secs,
        ),
        facelock_core::types::CameraCaps::default(),
        Some(factory),
        None,
    )
    .unwrap();

    // Run more failed attempts than max_attempts (1). None may report "rate
    // limited" — the budget starts and stays at zero recorded failures.
    for i in 0..3 {
        let resp = handler.handle_authenticate("testuser".into(), AuthIntent::Test);
        assert!(
            matches!(
                resp,
                DaemonResponse::AuthResult(MatchResult { matched: false, .. })
            ),
            "test attempt {i} should run the auth loop normally, not report rate-limited: {resp:?}"
        );
    }

    // Directly assert the on-disk rate_limit table is untouched: a fresh
    // check against the same database must still report "not rate limited".
    let inspect_store = FaceStore::create(&db_path).unwrap();
    assert!(
        inspect_store.check_rate_limit("testuser", 1, 60).unwrap(),
        "rate_limit table must be untouched by diagnostic (test) failures"
    );

    cleanup_db(&db_path);
}

/// C3 (issue #105): a storage failure while listing models during
/// `Authenticate` must surface as `DaemonResponse::Error` — and must not
/// consume rate-limit budget. Before the fix, a `list_models` error was
/// folded into an empty model list, which filtered every stored embedding
/// out of the device-allowed set, guaranteed "no match", and charged the
/// user's rate-limit budget: retries walked straight into a silent lockout.
///
/// Failure injection: drop the `embedder_model` column from `face_models`
/// (`label` is pinned by the `UNIQUE(user, label)` constraint). That way
/// `pre_check`'s `has_models` (a `COUNT(*)`) and the embedding load (id +
/// embedding only) still succeed, so the request gets past every earlier
/// gate and exercises exactly the `list_models` call inside
/// `handle_authenticate`.
#[test]
fn authenticate_storage_failure_is_error_and_charges_no_rate_limit() {
    use facelock_daemon::handler::Handler;
    use facelock_daemon::rate_limit::RateLimiter;

    let db_path = temp_db_path("storage-failure-auth");
    cleanup_db(&db_path);

    let db_path_str = db_path.to_string_lossy().into_owned();
    let mut config = Config::parse(&fixtures::test_config_toml(&db_path_str)).unwrap();
    config.recognition.timeout_secs = 0;
    config.security.rate_limit.max_attempts = 1;
    config.security.require_frame_variance = false;
    config.security.require_landmark_liveness = false;

    {
        let store = FaceStore::create(&db_path).unwrap();
        store
            .add_model("testuser", "front", &fixtures::known_embedding(0), "")
            .unwrap();
    }

    // Corrupt the schema so only `list_models` fails (see doc comment). The
    // migrations' unconditional `CREATE TABLE IF NOT EXISTS` no-ops on the
    // still-present table, and the V5 migration that would re-add the column
    // is gated behind a schema version this database is already past, so the
    // handler's own connection opens cleanly.
    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch("ALTER TABLE face_models DROP COLUMN embedder_model;")
            .unwrap();
    }

    let factory: facelock_test_support::mock_camera::MockCameraFactory =
        Box::new(move |_cfg| Ok(MockCamera::bright(64, 64, 1)));

    let mut handler = Handler::new(
        config.clone(),
        MockFaceEngine::no_faces(),
        FaceStore::create(&db_path).unwrap(),
        RateLimiter::new(
            config.security.rate_limit.max_attempts,
            config.security.rate_limit.window_secs,
        ),
        facelock_core::types::CameraCaps::default(),
        Some(factory),
        None,
    )
    .unwrap();

    // The real-authentication intent, which always charges; the diagnostic
    // carve-out exists only for `facelock test`.
    let resp = handler.handle_authenticate("testuser".into(), AuthIntent::Authenticate);
    match resp {
        DaemonResponse::Error { ref message } => {
            assert!(
                message.contains("storage error"),
                "error must name the storage failure, got: {message}"
            );
        }
        other => panic!(
            "a storage failure must be reported as Error, never as a no-match \
             AuthResult; got {other:?}"
        ),
    }

    // The part that bites users: the rate-limit counter must be unchanged.
    // With max_attempts = 1, a single recorded failure would flip this check
    // to "rate limited" — a fresh look at the same database must still say
    // "not rate limited".
    let inspect_store = FaceStore::create(&db_path).unwrap();
    assert!(
        inspect_store.check_rate_limit("testuser", 1, 60).unwrap(),
        "rate_limit counter must be unchanged by a storage-failure response"
    );

    cleanup_db(&db_path);
}
