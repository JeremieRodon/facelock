use facelock_core::Config;
use facelock_core::ipc::{DaemonRequest, DaemonResponse};
use facelock_store::StoreError;

use crate::ipc_client;

pub fn run(config: &Config, user: Option<String>, yes: bool) -> anyhow::Result<()> {
    // ClearModels is root-only on the daemon side too, so demand root up front.
    // Otherwise the user gets prompted Y/N first and only then hits AccessDenied.
    ipc_client::require_root("sudo facelock clear")?;

    let user = ipc_client::resolve_user(user.as_deref());

    // Check if user has any models before prompting. One failure policy (C4,
    // issue #105): a failed check propagates. The old D-Bus branch folded any
    // failure into "no models enrolled" and exited 0 having deleted nothing,
    // while the direct branch on the identical failure proceeded to delete.
    let has_models = if ipc_client::should_use_direct(config) {
        direct_user_has_models(config, &user)?
    } else {
        let request = DaemonRequest::ListModels { user: user.clone() };
        daemon_user_has_models(ipc_client::send_request(&request))?
    };
    if !has_models {
        println!("No face models enrolled for user '{user}'.");
        return Ok(());
    }

    if !yes {
        let confirmed = ipc_client::confirm(&format!("Remove ALL face models for user '{user}'?"))?;
        if !confirmed {
            println!("Cancelled.");
            return Ok(());
        }
    }

    if ipc_client::should_use_direct(config) {
        // `open_store_existing`: has_models above just proved the database is
        // there. If it vanished since, deleting has nothing to do — erroring
        // beats re-creating an empty database in its place.
        let store = crate::direct::open_store_existing(config)?;
        let count = store
            .clear_user(&user)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        println!("Removed {count} face model(s) for user '{user}'.");
        // The user has no models by construction, so drop the marker outright.
        super::enrollment_marker::forget(config, &user);
        return Ok(());
    }

    let request = DaemonRequest::ClearModels { user: user.clone() };

    let response = ipc_client::send_request(&request)?;

    match response {
        DaemonResponse::Removed => {
            println!("All face models removed for user '{user}'.");
            super::enrollment_marker::forget(config, &user);
        }
        other => {
            anyhow::bail!("unexpected response from daemon: {other:?}");
        }
    }

    Ok(())
}

/// Direct-transport half of the pre-prompt check: a store that cannot be
/// opened or queried is an error, never "no models" and never "assume yes and
/// prompt anyway". [`StoreError::Absent`] alone reads as "no models" — a
/// fresh install has provably nothing to delete, and the probe must not
/// create the database it is about to report empty.
fn direct_user_has_models(config: &Config, user: &str) -> anyhow::Result<bool> {
    let store = match crate::direct::open_store_existing(config) {
        Ok(store) => store,
        Err(StoreError::Absent { .. }) => return Ok(false),
        Err(e) => return Err(e.into()),
    };
    store
        .has_models(user)
        .map_err(|e| anyhow::anyhow!("storage error: {e}"))
}

/// Interpret the daemon's `ListModels` reply as "does the user have models".
/// Transport failures and error replies propagate (C4) — they must never read
/// as "no models enrolled".
fn daemon_user_has_models(response: anyhow::Result<DaemonResponse>) -> anyhow::Result<bool> {
    match response? {
        DaemonResponse::Models(m) => Ok(!m.is_empty()),
        DaemonResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
        other => anyhow::bail!("unexpected response from daemon: {other:?}"),
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

    /// C4, D-Bus transport: a transport failure must propagate, not read as
    /// "no models enrolled" (which printed success and deleted nothing).
    #[test]
    fn daemon_transport_failure_propagates() {
        let err = daemon_user_has_models(Err(anyhow::anyhow!("D-Bus timeout"))).unwrap_err();
        assert!(format!("{err:#}").contains("D-Bus timeout"));
    }

    /// C4, D-Bus transport: an explicit daemon error reply is an error too.
    #[test]
    fn daemon_error_reply_propagates() {
        let err = daemon_user_has_models(Ok(DaemonResponse::Error {
            message: "storage error: disk I/O error".into(),
        }))
        .unwrap_err();
        assert!(format!("{err:#}").contains("storage error"));
    }

    #[test]
    fn daemon_unexpected_reply_propagates() {
        let err = daemon_user_has_models(Ok(DaemonResponse::Ok)).unwrap_err();
        assert!(format!("{err:#}").contains("unexpected response"));
    }

    #[test]
    fn daemon_model_lists_map_to_bool() {
        assert!(!daemon_user_has_models(Ok(DaemonResponse::Models(vec![]))).unwrap());
        let model = facelock_core::types::FaceModelInfo {
            id: 1,
            user: "alice".into(),
            label: "front".into(),
            created_at: 0,
            embedder_model: String::new(),
            device_id: None,
        };
        assert!(daemon_user_has_models(Ok(DaemonResponse::Models(vec![model]))).unwrap());
    }

    /// C4, direct transport: an unreadable store must propagate as an error,
    /// not assume-yes (the old behavior prompted the user for a deletion that
    /// was doomed to fail).
    #[test]
    fn direct_unreadable_store_propagates() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");
        std::fs::write(&db_path, b"this is not a sqlite database").unwrap();

        assert!(direct_user_has_models(&config_with_db(&db_path), "alice").is_err());
    }

    /// The `Absent` variant reads as "no models" without creating anything:
    /// before the typed error, this probe ran as root and left an empty
    /// database at the path as a side effect of finding nothing to delete.
    #[test]
    fn direct_absent_store_reads_as_no_models_without_creating() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");

        assert!(!direct_user_has_models(&config_with_db(&db_path), "alice").unwrap());
        assert!(
            !db_path.exists(),
            "the pre-prompt probe must not create the database it reports empty"
        );
    }

    #[test]
    fn direct_healthy_store_maps_to_bool() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");
        {
            let store = facelock_store::FaceStore::create(&db_path).unwrap();
            store
                .add_model("alice", "front", &[0.5f32; 512], "embedder")
                .unwrap();
        }

        let config = config_with_db(&db_path);
        assert!(direct_user_has_models(&config, "alice").unwrap());
        assert!(!direct_user_has_models(&config, "bob").unwrap());
    }
}
