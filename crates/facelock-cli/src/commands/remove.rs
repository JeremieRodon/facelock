use facelock_core::Config;
use facelock_core::ipc::{DaemonRequest, DaemonResponse};

use crate::ipc_client;
use crate::message::{Terminal, UserMessage};

pub fn run(config: &Config, model_id: u32, user: Option<String>, yes: bool) -> anyhow::Result<()> {
    // C6: root check must run before the confirmation prompt below — a group
    // member confirming a destructive action only to then hit AccessDenied
    // is exactly the bug this ordering fixes. RemoveModel is root-only on the
    // daemon side too, so this applies regardless of transport.
    ipc_client::require_root(&format!("sudo facelock remove {model_id}"))?;

    let user = ipc_client::resolve_user(user.as_deref());

    if !yes {
        let confirmed = Terminal.confirm(&UserMessage::ConfirmRemoveModel {
            model_id,
            user: user.clone(),
        })?;
        if !confirmed {
            Terminal.info(&UserMessage::Cancelled);
            return Ok(());
        }
    }

    if ipc_client::should_use_direct(config) {
        let store = crate::direct::open_store(config)?;
        let removed = store
            .remove_model(&user, model_id)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        if removed {
            Terminal.info(&UserMessage::RemovedModel {
                model_id,
                user: user.clone(),
            });
        } else {
            Terminal.info(&UserMessage::ModelNotFound {
                model_id,
                user: user.clone(),
            });
        }
        // Recompute from the list we already have open rather than decrementing:
        // same cost, and it cannot drift from the database.
        let remaining = store.list_models(&user).ok().map(|m| m.len() as u32);
        drop(store);
        if let Some(remaining) = remaining {
            super::enrollment_marker::set(config, &user, remaining);
        }
        return Ok(());
    }

    let request = DaemonRequest::RemoveModel {
        user: user.clone(),
        model_id,
    };

    let response = ipc_client::send_request(&request)?;

    match response {
        DaemonResponse::Removed => {
            Terminal.info(&UserMessage::RemovedModel {
                model_id,
                user: user.clone(),
            });
            super::enrollment_marker::refresh(config, &user);
        }
        other => {
            anyhow::bail!("unexpected response from daemon: {other:?}");
        }
    }

    Ok(())
}
