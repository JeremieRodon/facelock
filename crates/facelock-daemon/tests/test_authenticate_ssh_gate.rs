//! The SSH physical-presence gate across the two authentication entry
//! points, pinned through the real service (D6).
//!
//! `abort_if_ssh` exists to stop an *attacker* from authenticating a face
//! session from a remote shell. It is not meant to stop an admin — already
//! root, by construction, since `facelock test` requires it — from
//! diagnosing recognition over SSH, which is why `PreCheckContext::test`
//! exists (N11). Before `TestAuthenticate` there was nowhere on the daemon
//! transport to apply that context: `test` arrived as an ordinary
//! `Authenticate` call, indistinguishable from real auth, so the carve-out
//! could only ever work in direct/oneshot mode. Now it applies on both.
//!
//! One test, alone in its own integration binary on purpose: it mutates
//! `SSH_CONNECTION`, which is process-global state. Cargo gives each
//! integration test file its own process, so owning this file means owning
//! the environment — no lock to forget, and no sibling test that could
//! observe the mutation.

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

/// The camera factory `Handler::new` takes. Named because the spelled-out
/// type trips `clippy::type_complexity`, which the `--all-targets` lint gate
/// makes a hard failure. Each integration test file is its own crate, so this
/// cannot be shared without exporting a test-only type from production code.
type MockCameraFactory = Box<dyn Fn(&Config) -> Result<MockCamera, String> + Send + Sync>;

#[tokio::test]
async fn test_authenticate_skips_the_ssh_gate_that_authenticate_enforces() {
    let config = Config::parse(
        r#"
[recognition]
threshold = 0.45
timeout_secs = 2

[security]
require_ir = false
require_frame_variance = false
require_landmark_liveness = false
abort_if_ssh = true
abort_if_lid_closed = false

[encryption]
method = "none"

[audit]
enabled = false
"#,
    )
    .unwrap();

    let emb = fixtures::known_embedding(1);
    let store = FaceStore::open_memory().unwrap();
    store
        .add_model("alice", "front", &emb, "test-embedder")
        .unwrap();
    let rate_limiter = RateLimiter::new(
        config.security.rate_limit.max_attempts,
        config.security.rate_limit.window_secs,
    );
    let factory: MockCameraFactory = Box::new(|_| Ok(MockCamera::bright(64, 64, 60)));
    let handler = Handler::new(
        config,
        MockFaceEngine::one_face(emb),
        store,
        rate_limiter,
        CameraCaps::default(),
        Some(factory),
        None,
    )
    .unwrap();
    let svc = FacelockService::new(
        handler,
        None,
        None,
        Arc::new(|_user: &str| Box::new(NullNotifier) as Box<dyn Notifier>),
    );
    let root = CallerIdentity {
        uid: 0,
        username: Some("root".into()),
    };

    let previous = std::env::var("SSH_CONNECTION").ok();
    unsafe { std::env::set_var("SSH_CONNECTION", "1.2.3.4 5678 10.0.0.1 22") };

    // Real authentication: the gate fires, in-band, before the camera runs.
    let real = svc.authenticate_as(root.clone(), "alice").await.unwrap();
    assert!(!real.matched);
    assert_eq!(real.model_id, -2, "recoverable error sentinel: {real:?}");
    assert_eq!(real.label, "SSH session detected");

    // The diagnostic entry point runs the comparison anyway.
    let diagnostic = svc.test_authenticate_as(root, "alice").await.unwrap();
    assert!(
        diagnostic.matched,
        "TestAuthenticate must skip the SSH gate and reach the comparison \
         loop, got: {diagnostic:?}"
    );

    match previous {
        Some(value) => unsafe { std::env::set_var("SSH_CONNECTION", value) },
        None => unsafe { std::env::remove_var("SSH_CONNECTION") },
    }
}
