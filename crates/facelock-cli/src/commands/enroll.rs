use anyhow::Context;
use chrono::Local;

use facelock_core::Config;
use facelock_core::ipc::{DaemonRequest, DaemonResponse};
use facelock_core::types::FaceModelInfo;

use crate::ipc_client;

pub fn run(
    user: Option<String>,
    label: Option<String>,
    skip_setup_check: bool,
) -> anyhow::Result<()> {
    // Setup gate: prompt user if setup hasn't been run.
    // Setup includes model downloads, encryption, and face enrollment,
    // so if setup runs successfully we're done — no need to enroll again.
    if !skip_setup_check {
        let marker = std::path::Path::new(super::setup::SETUP_COMPLETE_MARKER);
        if !marker.exists() {
            ipc_client::require_root("sudo facelock setup")?;
            println!("Setup has not been completed.");
            if ipc_client::confirm("Run setup now?")? {
                super::setup::run(false)?;
                if !marker.exists() {
                    anyhow::bail!("Setup did not complete successfully.");
                }
                // Setup includes face enrollment (Step 4), so we're done
                return Ok(());
            } else {
                println!("Run 'sudo facelock setup' when ready.");
                return Ok(());
            }
        }
    }

    ipc_client::require_root("sudo facelock enroll")?;

    let config = Config::load().context("failed to load config")?;

    // Encryption posture (Plan 04): refuse plaintext enrollment unless opted in;
    // warn prominently when the opt-in is active.
    if config.encryption.method == facelock_core::config::EncryptionMethod::None {
        if config.security.allow_plaintext {
            eprintln!(
                "WARNING: encryption.method = \"none\" and security.allow_plaintext = true.\n\
                 Your face template will be stored UNENCRYPTED (plaintext biometric data at rest)."
            );
        } else if let Err(message) = config.ensure_enroll_encryption_allowed() {
            anyhow::bail!(message);
        }
    }

    // Check models exist
    let model_dir = std::path::Path::new(&config.daemon.model_dir);
    let detector = model_dir.join(&config.recognition.detector_model);
    let embedder = model_dir.join(&config.recognition.embedder_model);
    if !detector.exists() || !embedder.exists() {
        anyhow::bail!(
            "Face recognition models not found in {}.\nRun `sudo facelock setup` to download them.",
            config.daemon.model_dir
        );
    }

    let user = ipc_client::resolve_user(user.as_deref());

    let label = match label {
        Some(label) => label,
        None => {
            let date = Local::now().format("%Y-%m-%d").to_string();
            next_label(&date, &user, &config)?
        }
    };

    // Warn if existing models use a different embedder than currently
    // configured. One failure policy (C4, issue #105): a store or daemon
    // failure propagates instead of silently skipping the warning — the
    // enrollment ahead needs the very store this check just failed to read.
    {
        let config_embedder = &config.recognition.embedder_model;
        let has_stale = if ipc_client::should_use_direct(&config) {
            let store = crate::direct::open_store(&config)?;
            let has_any = store
                .has_models(&user)
                .map_err(|e| anyhow::anyhow!("storage error: {e}"))?;
            let has_matching = store
                .has_models_for_embedder(&user, config_embedder)
                .map_err(|e| anyhow::anyhow!("storage error: {e}"))?;
            has_any && !has_matching
        } else {
            let request = DaemonRequest::ListModels { user: user.clone() };
            match ipc_client::send_request(&request)? {
                DaemonResponse::Models(m) => {
                    !m.is_empty()
                        && !m
                            .iter()
                            .any(|model| model.embedder_model == *config_embedder)
                }
                DaemonResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
                other => anyhow::bail!("unexpected response from daemon: {other:?}"),
            }
        };
        if has_stale {
            println!(
                "Note: existing models don't use the configured embedder '{config_embedder}'."
            );
            println!(
                "Old enrollments will not work with the new embedder. Consider removing them with 'facelock remove'.\n"
            );
        }
    }

    println!("Enrolling face for user '{user}' with label '{label}'...");
    println!("Look at the camera. Slowly turn your head left and right.");

    if ipc_client::should_use_direct(&config) {
        ipc_client::require_root("sudo facelock enroll")?;
        let (model_id, embedding_count) = crate::direct::enroll(&config, &user, &label)?;
        println!(
            "\nFace enrolled successfully!\n  Model ID: {model_id}\n  Embeddings: {embedding_count}\n  Label: {label}"
        );
        super::enrollment_marker::refresh(&config, &user);
        check_model_count(&user, &config);
        return Ok(());
    }

    // Dedicated call with a timeout derived from the daemon's enrollment
    // deadline — the shared 15s proxy would abort mid-enrollment (issue #89).
    // send_enroll yields Enrolled or an error, so there is no other arm.
    let response = ipc_client::send_enroll(&user, &label, &config)?;

    if let DaemonResponse::Enrolled {
        model_id,
        embedding_count,
    } = response
    {
        println!(
            "\nFace enrolled successfully!\n  Model ID: {model_id}\n  Embeddings: {embedding_count}\n  Label: {label}"
        );
        super::enrollment_marker::refresh(&config, &user);
        check_model_count(&user, &config);
    }

    Ok(())
}

/// List a user's models, honoring direct mode. Unlike a bare `send_request`,
/// this never touches D-Bus in direct mode — an unconditional D-Bus call here
/// would *activate* the system daemon and silently flip the subsequent
/// enrollment from direct to daemon mode (issue #89 validation fallout).
///
/// One failure policy (C4, issue #105): failures propagate; they must not
/// read as "this user has no models".
fn list_user_models(user: &str, config: &Config) -> anyhow::Result<Vec<FaceModelInfo>> {
    if ipc_client::should_use_direct(config) {
        let store = crate::direct::open_store(config)?;
        store
            .list_models(user)
            .map_err(|e| anyhow::anyhow!("storage error: {e}"))
    } else {
        match ipc_client::send_request(&DaemonRequest::ListModels {
            user: user.to_string(),
        })? {
            DaemonResponse::Models(models) => Ok(models),
            DaemonResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
            other => anyhow::bail!("unexpected response from daemon: {other:?}"),
        }
    }
}

/// Generate the next available label like "2026-03-15-1", "2026-03-15-2", etc.
fn next_label(date_prefix: &str, user: &str, config: &Config) -> anyhow::Result<String> {
    let max_suffix = list_user_models(user, config)?
        .iter()
        .filter_map(|m| {
            m.label
                .strip_prefix(date_prefix)
                .and_then(|rest| rest.strip_prefix('-'))
                .and_then(|n| n.parse::<u32>().ok())
        })
        .max()
        .unwrap_or(0);

    Ok(format!("{date_prefix}-{}", max_suffix + 1))
}

fn check_model_count(user: &str, config: &Config) {
    // Post-success advisory only: the enrollment already committed, so a
    // failed count here must not turn a successful enrollment into a
    // reported failure.
    if let Ok(models) = list_user_models(user, config) {
        if models.len() > 5 {
            println!(
                "\nWarning: user '{user}' has {} face models. Consider removing old ones with 'facelock remove'.",
                models.len()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// `mode = "oneshot"` pins `should_use_direct` without touching D-Bus.
    fn oneshot_config_with_db(db_path: &Path) -> Config {
        let mut config = Config::parse("[daemon]\nmode = \"oneshot\"\n").expect("config parses");
        config.storage.db_path = db_path.to_string_lossy().into_owned();
        config
    }

    /// C4: a store failure while picking the next label propagates — it must
    /// not silently fall back to a "-1" suffix.
    #[test]
    fn next_label_propagates_store_failure() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");
        std::fs::write(&db_path, b"this is not a sqlite database").unwrap();

        let config = oneshot_config_with_db(&db_path);
        assert!(next_label("2026-08-13", "alice", &config).is_err());
    }

    #[test]
    fn next_label_counts_existing_labels() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");
        {
            let store = facelock_store::FaceStore::create(&db_path).unwrap();
            let emb = [0.5f32; 512];
            store
                .add_model("alice", "2026-08-13-1", &emb, "embedder")
                .unwrap();
            store
                .add_model("alice", "2026-08-13-2", &emb, "embedder")
                .unwrap();
        }

        let config = oneshot_config_with_db(&db_path);
        assert_eq!(
            next_label("2026-08-13", "alice", &config).unwrap(),
            "2026-08-13-3"
        );
        // A fresh prefix (or user) starts at -1.
        assert_eq!(
            next_label("2026-08-14", "alice", &config).unwrap(),
            "2026-08-14-1"
        );
        assert_eq!(
            next_label("2026-08-13", "bob", &config).unwrap(),
            "2026-08-13-1"
        );
    }
}
