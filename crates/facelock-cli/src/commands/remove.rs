use facelock_core::Config;

use crate::backend::Backend;
use crate::ipc_client;
use crate::message::{Terminal, UserMessage};

pub fn run(config: &Config, model_id: u32, user: Option<String>, yes: bool) -> anyhow::Result<()> {
    // C6: root check must run before the confirmation prompt below — a group
    // member confirming a destructive action only to then hit AccessDenied
    // is exactly the bug this ordering fixes. RemoveModel is root-only on the
    // daemon side too, so this applies regardless of transport.
    ipc_client::require_root(&format!("sudo facelock remove {model_id}"))?;

    let user = ipc_client::resolve_user(user.as_deref());

    // One selection for the whole command (D1), before the unbounded prompt.
    let backend = Backend::select(config);

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

    match backend.remove_model(&user, model_id)? {
        Some(false) => Terminal.info(&UserMessage::ModelNotFound {
            model_id,
            user: user.clone(),
        }),
        // `None`: the daemon reply cannot say whether the model existed
        // (wire-stable), so a completed request reports as removed — as the
        // daemon path always has.
        Some(true) | None => Terminal.info(&UserMessage::RemovedModel {
            model_id,
            user: user.clone(),
        }),
    }

    super::enrollment_marker::refresh(&backend, config, &user);
    Ok(())
}
