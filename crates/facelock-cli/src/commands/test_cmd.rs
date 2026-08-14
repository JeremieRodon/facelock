use std::time::Instant;


use facelock_core::Config;
use facelock_core::ipc::{DaemonRequest, DaemonResponse};

use crate::ipc_client;
use crate::notifications::{NotifyEvent, notify_if_enabled};

pub fn run(config: &Config, user: Option<String>) -> anyhow::Result<()> {
    // N11 (issue #96): `facelock test` is root-only regardless of transport
    // (direct or daemon-mediated) — keeps similarity scores and full detail,
    // and lets both the daemon and direct paths safely exempt failed test
    // runs from rate-limit consumption (root already has unrestricted access
    // to the rate-limit table). Must run before any prompt or output (C6).
    ipc_client::require_root("sudo facelock test")?;


    // Check models exist — offer to run setup if missing
    let model_dir = std::path::Path::new(&config.daemon.model_dir);
    let detector = model_dir.join(&config.recognition.detector_model);
    let embedder = model_dir.join(&config.recognition.embedder_model);
    if !detector.exists() || !embedder.exists() {
        println!("Face recognition models not found.");
        if crate::ipc_client::confirm("Download models now?")? {
            crate::commands::setup::run(false)?;
            if !detector.exists() || !embedder.exists() {
                anyhow::bail!("Models still not found after setup.");
            }
        } else {
            anyhow::bail!("Models required. Run `facelock setup` to download them.");
        }
    }

    let user = ipc_client::resolve_user(user.as_deref());
    let notif_config = &config.notification;

    // Check if user has enrolled models before attempting auth. Three-way
    // discrimination (C7, issue #105): a store that opens with zero models
    // and a store that doesn't exist yet both mean "not enrolled" — but a
    // store that is present and cannot be read is an error, and must never be
    // reported as "no models enrolled".
    let has_models = if ipc_client::should_use_direct(config) {
        direct_user_has_models(config, &user)?
    } else {
        // Propagate a failed query instead of folding it into "no models
        // enrolled" — an AccessDenied here carries its own actionable hint.
        let request = DaemonRequest::ListModels { user: user.clone() };
        match ipc_client::send_request(&request)? {
            DaemonResponse::Models(m) => !m.is_empty(),
            DaemonResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
            other => anyhow::bail!("unexpected response from daemon: {other:?}"),
        }
    };
    if !has_models {
        println!("No face models enrolled for user '{user}'.");
        println!("Run 'facelock enroll' to enroll a face first.");
        return Ok(());
    }

    // Warn if no enrolled models match the current embedder. Same failure
    // policy as above (C4): the store was readable one query ago, so a
    // failure here is propagated rather than guessed either way (the two
    // branches used to guess in opposite directions).
    {
        let config_embedder = &config.recognition.embedder_model;
        let has_matching = if ipc_client::should_use_direct(config) {
            // `open_store_existing`: the store answered has_models one query
            // ago, so it exists; if it vanished since, that is an error, not
            // a cue to create an empty one and warn about a stale embedder.
            let store = crate::direct::open_store_existing(config)?;
            store
                .has_models_for_embedder(&user, config_embedder)
                .map_err(|e| anyhow::anyhow!("storage error: {e}"))?
        } else {
            let request = DaemonRequest::ListModels { user: user.clone() };
            match ipc_client::send_request(&request)? {
                DaemonResponse::Models(m) => m
                    .iter()
                    .any(|model| model.embedder_model == *config_embedder),
                DaemonResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
                other => anyhow::bail!("unexpected response from daemon: {other:?}"),
            }
        };
        if !has_matching {
            println!(
                "Warning: no enrolled models use the configured embedder '{config_embedder}'."
            );
            println!("Re-enroll with 'facelock enroll' to use the current model.");
            return Ok(());
        }
    }

    println!("Testing face recognition for user '{user}'...");
    println!("Look at the camera.");

    notify_if_enabled(notif_config, &NotifyEvent::Scanning);

    if ipc_client::should_use_direct(config) {
        let start = Instant::now();
        match crate::direct::authenticate(config, &user) {
            Ok(result) if result.matched => {
                let elapsed = start.elapsed();
                println!(
                    "Matched (similarity: {:.2}) in {:.2}s",
                    result.similarity,
                    elapsed.as_secs_f64()
                );
                notify_if_enabled(
                    notif_config,
                    &NotifyEvent::Success {
                        label: result.label.clone(),
                        similarity: result.similarity,
                    },
                );
            }
            Ok(result) => {
                let elapsed = start.elapsed();
                if result.failure_reason
                    == Some(facelock_core::types::AuthFailureReason::VarianceNotSatisfied)
                {
                    println!(
                        "Face matched (best: {:.2}) but the liveness variance check was not \
                         satisfied after {:.1}s — try moving slightly, or tune \
                         security.frame_variance_max_similarity",
                        result.similarity,
                        elapsed.as_secs_f64()
                    );
                    notify_if_enabled(
                        notif_config,
                        &NotifyEvent::Failure {
                            reason: "face matched but liveness variance not satisfied".to_string(),
                        },
                    );
                } else {
                    println!(
                        "No match (best: {:.2}) after {:.1}s",
                        result.similarity,
                        elapsed.as_secs_f64()
                    );
                    notify_if_enabled(
                        notif_config,
                        &NotifyEvent::Failure {
                            reason: format!("no match (best similarity: {:.2})", result.similarity),
                        },
                    );
                }
            }
            Err(e) => {
                notify_if_enabled(
                    notif_config,
                    &NotifyEvent::Failure {
                        reason: e.to_string(),
                    },
                );
                return Err(e);
            }
        }
        return Ok(());
    }

    let request = DaemonRequest::Authenticate { user: user.clone() };

    let start = Instant::now();
    let response = ipc_client::send_request(&request)?;
    let elapsed = start.elapsed();

    match response {
        DaemonResponse::AuthResult(result) => {
            if result.matched {
                let model_id = result.model_id.unwrap_or(0);
                let label = result.label.as_deref().unwrap_or("unknown");
                println!(
                    "Matched model #{model_id} '{label}' (similarity: {:.2}) in {:.2}s",
                    result.similarity,
                    elapsed.as_secs_f64()
                );
                notify_if_enabled(
                    notif_config,
                    &NotifyEvent::Success {
                        label: result.label.clone(),
                        similarity: result.similarity,
                    },
                );
            } else if config.security.require_frame_variance
                && result.similarity >= config.recognition.threshold
            {
                // The D-Bus AuthResult contract carries no failure reason, but
                // matched=false with similarity above the recognition threshold
                // means a liveness gate (frame variance) blocked the attempt.
                println!(
                    "Face matched (best: {:.2}) but the liveness variance check was not \
                     satisfied after {:.1}s — try moving slightly, or tune \
                     security.frame_variance_max_similarity",
                    result.similarity,
                    elapsed.as_secs_f64()
                );
                notify_if_enabled(
                    notif_config,
                    &NotifyEvent::Failure {
                        reason: "face matched but liveness variance not satisfied".to_string(),
                    },
                );
            } else {
                println!(
                    "No match (best: {:.2}) after {:.1}s",
                    result.similarity,
                    elapsed.as_secs_f64()
                );
                notify_if_enabled(
                    notif_config,
                    &NotifyEvent::Failure {
                        reason: format!("no match (best similarity: {:.2})", result.similarity),
                    },
                );
            }
        }
        other => {
            notify_if_enabled(
                notif_config,
                &NotifyEvent::Failure {
                    reason: "unexpected daemon response".to_string(),
                },
            );
            anyhow::bail!("unexpected response from daemon: {other:?}");
        }
    }

    Ok(())
}

/// Direct-transport "does this user have enrolled models?" with the C7
/// three-way discrimination, now carried by [`StoreError`]'s variants:
///
/// - store opens, zero models      → `Ok(false)` ("no models enrolled" is true)
/// - `StoreError::Absent` (fresh)  → `Ok(false)` (no database created; same message)
/// - any other failure class       → `Err`, never "no models"
///
/// For the error, the per-user enrollment marker is consulted **for the
/// message only** — it is readable in exactly the cases the database is not,
/// and lets the error say what the user actually wants to know ("you appear
/// to be enrolled; the database is the problem"). The marker can be stale,
/// hence "appear to"; it never influences the decision, only the wording.
fn direct_user_has_models(config: &Config, user: &str) -> anyhow::Result<bool> {
    let store = match crate::direct::open_store_existing(config) {
        Ok(store) => store,
        Err(facelock_store::StoreError::Absent { .. }) => return Ok(false),
        Err(e) => return Err(unreadable_store_error(config, user, &anyhow::Error::new(e))),
    };
    match store.has_models(user) {
        Ok(v) => Ok(v),
        Err(e) => Err(unreadable_store_error(
            config,
            user,
            &anyhow::anyhow!("storage error: {e}"),
        )),
    }
}

/// Build the "store present but unreadable" error (C7). With a readable
/// marker the message leads with the enrollment count; without one it still
/// names the real problem — it must never claim "no models enrolled".
fn unreadable_store_error(config: &Config, user: &str, cause: &anyhow::Error) -> anyhow::Error {
    use super::enrollment_marker::{MarkerState, marker_dir, read_marker_in};
    match read_marker_in(&marker_dir(config), user) {
        MarkerState::Enrolled(marker) => anyhow::anyhow!(
            "You appear to have {} enrolled model(s), but the face database at {} \
             can't be read right now ({cause:#}).",
            marker.models,
            config.storage.db_path
        ),
        _ => anyhow::anyhow!(
            "the face database at {} can't be read ({cause:#})",
            config.storage.db_path
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn config_with_db(db_path: &Path) -> Config {
        let mut config = Config::parse("").expect("defaults parse");
        config.storage.db_path = db_path.to_string_lossy().into_owned();
        config
    }

    /// C7 branch 1+2: a fresh (absent) store and an open store with zero
    /// models both report "not enrolled".
    #[test]
    fn absent_store_and_zero_models_read_as_not_enrolled() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");
        let config = config_with_db(&db_path);

        // Absent (fresh): the StoreError::Absent variant, read as "not
        // enrolled" without creating anything.
        assert!(!direct_user_has_models(&config, "alice").unwrap());

        // Open store, models for someone else only.
        {
            let store = facelock_store::FaceStore::create(&db_path).unwrap();
            store
                .add_model("bob", "front", &[0.5f32; 512], "embedder")
                .unwrap();
        }
        assert!(!direct_user_has_models(&config, "alice").unwrap());
        assert!(direct_user_has_models(&config, "bob").unwrap());
    }

    /// The `Absent` arm answers "not enrolled" as a *value*: the probe must
    /// not manufacture the empty database the create-based `open_store` used
    /// to leave behind.
    #[test]
    fn absent_store_probe_creates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");

        assert!(!direct_user_has_models(&config_with_db(&db_path), "alice").unwrap());
        assert!(
            !db_path.exists(),
            "probing enrollment must not create the database it reports absent"
        );
    }

    /// C7 branch 3: a present-but-unreadable store is an error and must not
    /// claim "no models". Without a marker the message still names the real
    /// problem.
    #[test]
    fn unreadable_store_is_an_error_not_no_models() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");
        std::fs::write(&db_path, b"this is not a sqlite database").unwrap();

        let err = direct_user_has_models(&config_with_db(&db_path), "alice").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("can't be read"),
            "error must name the real problem: {msg}"
        );
        assert!(
            !msg.contains("appear to have"),
            "no marker, so no enrollment claim: {msg}"
        );
    }

    /// C7 branch 3 with a readable marker: the error leads with the (hedged)
    /// enrollment count.
    #[test]
    fn unreadable_store_error_reports_marker_count() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");
        std::fs::write(&db_path, b"this is not a sqlite database").unwrap();

        let config = config_with_db(&db_path);
        let marker_base = super::super::enrollment_marker::marker_dir(&config);
        super::super::enrollment_marker::write_marker_in(&marker_base, "alice", 3, None).unwrap();

        let err = direct_user_has_models(&config, "alice").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("appear to have 3 enrolled model(s)"),
            "marker must enrich the message: {msg}"
        );
        assert!(msg.contains("can't be read"), "{msg}");
    }

    /// `--user other` degradation: no marker for that user, so the error
    /// falls back to the plain accurate message — still an error, never
    /// "no models enrolled".
    #[test]
    fn unreadable_store_for_other_user_degrades_to_plain_error() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");
        std::fs::write(&db_path, b"this is not a sqlite database").unwrap();

        let config = config_with_db(&db_path);
        let marker_base = super::super::enrollment_marker::marker_dir(&config);
        super::super::enrollment_marker::write_marker_in(&marker_base, "alice", 3, None).unwrap();

        let err = direct_user_has_models(&config, "someone-else").unwrap_err();
        let msg = format!("{err:#}");
        assert!(!msg.contains("appear to have"), "{msg}");
        assert!(msg.contains("can't be read"), "{msg}");
    }
}
