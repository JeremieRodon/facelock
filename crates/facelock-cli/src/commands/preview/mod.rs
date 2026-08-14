mod font;
mod render;
mod text_only;
#[cfg(feature = "wayland")]
mod wayland_preview;

use facelock_core::Config;

use crate::backend::{Backend, BackendKind};
use crate::ipc_client;
use crate::message::{Terminal, UserMessage};

pub fn run(config: &Config, text_only: bool, user: Option<String>) -> anyhow::Result<()> {
    // DEC-6/N13: `PreviewDetectFrame` is root-only now — it was the last
    // unprivileged consumer of a per-frame similarity score (the
    // hill-climbing oracle N12/N13 close by construction).
    ipc_client::require_root("sudo facelock preview")?;

    // One user-resolution implementation (C5, issue #105). The local
    // getpwuid-only version this replaces resolved `sudo facelock preview`
    // to *root*, so the preview never recognized the actual user.
    let user = ipc_client::resolve_user(user.as_deref());

    let backend = Backend::select(config);

    if !backend.caps().graphical_preview {
        // A direct backend has only the local text preview — a capability
        // stated by the selection, not discovered at a failure site. Why it
        // is unavailable depends on the kind: a stopped daemon is a degraded
        // state, not a configuration choice (the old single message blamed
        // "oneshot mode" for both).
        if !text_only {
            Terminal.error(&graphical_unavailable_message(backend.kind()));
        }
        return text_only::run_direct(config, &user);
    }

    if text_only {
        return text_only::run(&user);
    }

    run_graphical(&user)
}

/// Why graphical preview is unavailable on a direct backend, accurately per
/// kind.
fn graphical_unavailable_message(kind: BackendKind) -> UserMessage {
    match kind {
        BackendKind::DirectByFallback => UserMessage::PreviewGraphicalDaemonUnreachable,
        _ => UserMessage::PreviewGraphicalNeedsDaemonOneshot,
    }
}

#[cfg(feature = "wayland")]
fn run_graphical(user: &str) -> anyhow::Result<()> {
    match wayland_preview::run(user) {
        Ok(()) => Ok(()),
        Err(e) => {
            tracing::warn!("Wayland preview failed: {e}");
            eprintln!(
                "Wayland preview unavailable: {e}\n\
                 Falling back to text-only mode.\n"
            );
            text_only::run(user)
        }
    }
}

#[cfg(not(feature = "wayland"))]
fn run_graphical(user: &str) -> anyhow::Result<()> {
    eprintln!(
        "Graphical preview not available (compiled without wayland feature).\n\
         Using text-only mode.\n"
    );
    text_only::run(user)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The misattribution pin (D1): a *stopped* daemon must render the
    /// degraded fallback message, never the "configured off" oneshot wording
    /// — the old single message told users with a crashed daemon that they
    /// had chosen oneshot mode.
    #[test]
    fn stopped_daemon_is_not_blamed_on_configuration() {
        assert_eq!(
            graphical_unavailable_message(BackendKind::DirectByFallback),
            UserMessage::PreviewGraphicalDaemonUnreachable
        );
        assert_eq!(
            graphical_unavailable_message(BackendKind::DirectByConfig),
            UserMessage::PreviewGraphicalNeedsDaemonOneshot
        );
    }

    /// C5 (issue #105): preview resolves its user through the one shared
    /// resolver, whose precedence honors SUDO_USER — the deleted local
    /// implementation used getpwuid only, so `sudo facelock preview`
    /// previewed for root and never recognized anyone. The euid-0 half of
    /// the bug cannot be reproduced in a unit test; what this pins is the
    /// resolver's SUDO_USER precedence, which is exactly the behavior the
    /// getpwuid-only version lacked.
    #[test]
    fn shared_resolver_honors_sudo_user() {
        // SAFETY: process-global env mutation; no other test in this binary
        // asserts on SUDO_USER (checked), and the one concurrent reader
        // (`resolve_user_no_flag_falls_through`) only requires a non-empty
        // result.
        unsafe { std::env::set_var("SUDO_USER", "preview-c5-alice") };
        let resolved = crate::ipc_client::resolve_user(None);
        unsafe { std::env::remove_var("SUDO_USER") };
        assert_eq!(resolved, "preview-c5-alice");

        // The explicit flag still wins over the environment.
        assert_eq!(crate::ipc_client::resolve_user(Some("bob")), "bob");
    }
}
