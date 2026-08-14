mod font;
mod render;
mod text_only;
#[cfg(feature = "wayland")]
mod wayland_preview;

use facelock_core::Config;

use crate::ipc_client;

pub fn run(config: &Config, text_only: bool, user: Option<String>) -> anyhow::Result<()> {
    // DEC-6/N13: `PreviewDetectFrame` is root-only now — it was the last
    // unprivileged consumer of a per-frame similarity score (the
    // hill-climbing oracle N12/N13 close by construction).
    ipc_client::require_root("sudo facelock preview")?;

    // One user-resolution implementation (C5, issue #105). The local
    // getpwuid-only version this replaces resolved `sudo facelock preview`
    // to *root*, so the preview never recognized the actual user.
    let user = ipc_client::resolve_user(user.as_deref());

    if ipc_client::should_use_direct(config) {
        if !text_only {
            eprintln!(
                "Graphical preview requires the daemon. In oneshot mode, use --text-only.\n\
                 Falling back to text-only mode.\n"
            );
        }
        return text_only::run_direct(config, &user);
    }

    if text_only {
        return text_only::run(&user);
    }

    run_graphical(&user)
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
