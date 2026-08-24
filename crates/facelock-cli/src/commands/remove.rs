use facelock_core::Config;

use crate::backend::Backend;
use crate::ipc_client;
use crate::message::{FaceMessage, Terminal};

pub fn run(config: &Config, model_id: u32, user: Option<String>, yes: bool) -> anyhow::Result<()> {
    // C6: the root check runs before the confirmation prompt below — a user
    // confirming a destructive action only to then hit AccessDenied is
    // exactly the bug this ordering fixes. The check lives in `main`'s
    // `require_root_for` gate, ahead of the config parse (issue #191);
    // RemoveModel is root-only on the daemon side too, so it applies
    // regardless of transport.
    let user = ipc_client::resolve_user(user.as_deref());

    // One selection for the whole command (D1), before the unbounded prompt.
    let backend = Backend::select(config);

    if !yes {
        let confirmed = Terminal.confirm(&FaceMessage::ConfirmRemoveModel {
            model_id,
            user: user.clone(),
        })?;
        if !confirmed {
            Terminal.info(&FaceMessage::Cancelled);
            return Ok(());
        }
    }

    match backend.remove_model(&user, model_id)? {
        Some(false) => Terminal.info(&FaceMessage::ModelNotFound {
            model_id,
            user: user.clone(),
        }),
        // `None`: the daemon reply cannot say whether the model existed
        // (wire-stable), so a completed request reports as removed — as the
        // daemon path always has.
        Some(true) | None => Terminal.info(&FaceMessage::RemovedModel {
            model_id,
            user: user.clone(),
        }),
    }

    super::enrollment_marker::refresh(&backend, config, &user);
    Ok(())
}
