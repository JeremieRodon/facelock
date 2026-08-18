//! Out-of-process test for the CLI domain layer (gap D6, cross-cutting C1).
//!
//! This file compiles against the `facelock_cli` *library* target. Before that
//! target existed, `facelock-cli` was bin-only, so the only way to reach the
//! `status` renderer from outside was to spawn the `facelock` binary and scrape
//! stdout — which cannot produce a `Health` whose facts are *unknown*: that
//! state only arises from a broken/absent config or an unreadable store on the
//! live system, exactly what a black-box test cannot stage. Here the renderer
//! is a plain function over a synthetic `Health`, so the N4 rule it exists to
//! enforce — "unknown is not false" — is pinned as a property of the public API
//! with no root, filesystem, camera, or bus.

use facelock_cli::backend::DaemonPing;
use facelock_cli::commands::status;
use facelock_cli::health::{ConfigHealth, ConfigOutcome, Health, PamWiring};
use facelock_cli::resolved::Fact;

/// A `Health` whose every probe-backed fact is `Unknown` — the shape
/// `Health::probe` returns when the config does not parse, reconstructed here
/// without touching the system.
fn health_all_unknown() -> Health {
    let why = "config not available";
    Health {
        config: ConfigHealth {
            path: "/etc/facelock/config.toml".to_string(),
            outcome: ConfigOutcome::NotFound,
        },
        daemon: Fact::unknown(why),
        oneshot_fallback: Fact::unknown(why),
        camera: Fact::unknown(why),
        models: Fact::unknown(why),
        execution_provider: Fact::unknown(why),
        encryption: Fact::unknown(why),
        user: "alice".to_string(),
        enrolled: Fact::unknown(why),
        security: Fact::unknown(why),
        notifications: Fact::unknown(why),
        pam: PamWiring {
            module_path: "/lib/security/pam_facelock.so".to_string(),
            installed_at: None,
            configured: Vec::new(),
            not_checked: Vec::new(),
        },
    }
}

#[test]
fn unknown_daemon_fact_renders_as_undetermined_never_as_a_verdict() {
    let report = status::render(&health_all_unknown());

    // The reason an undetermined fact could not be established is surfaced
    // verbatim...
    assert!(
        report.contains("cannot determine: config not available"),
        "unknown facts must render their reason, got:\n{report}"
    );
    // ...and an undetermined daemon must never be rendered as either known
    // verdict ("responding" / "not responding"). N4: unknown is not false.
    assert!(
        !report.contains("responding"),
        "an Unknown daemon fact must not collapse to a responding/not-responding \
         verdict, got:\n{report}"
    );
}

#[test]
fn unknown_and_known_failure_render_differently() {
    // Same renderer, same section: flipping the daemon fact from Unknown to a
    // probed failure must change the rendered verdict. A bin-only crate could
    // assert this only against a live daemon; here it is a pure comparison over
    // two synthetic inputs.
    let unknown = status::render(&health_all_unknown());

    let mut degraded = health_all_unknown();
    degraded.daemon = Fact::probed(DaemonPing::NotResponding {
        error: "connection refused".to_string(),
    });
    let degraded = status::render(&degraded);

    assert!(!unknown.contains("connection refused"));
    assert!(
        degraded.contains("not responding: connection refused"),
        "a probed failure must render its transport error, got:\n{degraded}"
    );
    assert_ne!(
        unknown, degraded,
        "unknown and known-false must not render identically (N4)"
    );
}
