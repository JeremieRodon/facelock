use facelock_core::Config;

use crate::backend::Backend;
use crate::ipc_client;
use crate::message::{FaceMessage, Terminal};

pub fn run(config: &Config, user: Option<String>, yes: bool) -> anyhow::Result<()> {
    // ClearModels is root-only on the daemon side too, so demand root up front.
    // Otherwise the user gets prompted Y/N first and only then hits AccessDenied.
    ipc_client::require_root("sudo facelock clear")?;

    let user = ipc_client::resolve_user(user.as_deref());

    // One selection for the whole command (D1): the old code probed the bus
    // here and again after the unbounded confirmation prompt below, so the
    // transport could flip between the check and the deletion.
    let backend = Backend::select(config);

    // Check if user has any models before prompting. One failure policy (C4,
    // issue #105), now owned by the backend seam: a failed check propagates —
    // never "no models enrolled", never "assume yes and prompt anyway" — and
    // a provably absent database reads as "no models" without being created.
    if !backend.has_models(&user)? {
        Terminal.info(&FaceMessage::NoModelsEnrolled { user: user.clone() });
        return Ok(());
    }

    if !yes {
        let confirmed = Terminal.confirm(&FaceMessage::ConfirmClearAll { user: user.clone() })?;
        if !confirmed {
            Terminal.info(&FaceMessage::Cancelled);
            return Ok(());
        }
    }

    match backend.clear_models(&user)? {
        // The direct backend counted what it deleted; the daemon reply
        // cannot carry a count (wire-stable), so the message differs.
        Some(count) => Terminal.info(&FaceMessage::ClearedModels {
            count,
            user: user.clone(),
        }),
        None => Terminal.info(&FaceMessage::AllModelsRemoved { user: user.clone() }),
    }

    // The user has no models by construction, so drop the marker outright.
    super::enrollment_marker::forget(config, &user);
    Ok(())
}
