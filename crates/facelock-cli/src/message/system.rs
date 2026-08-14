//! Wiring facelock into the system: the daemon unit and the `facelock` group.

#[cfg(test)]
use super::sample_text as s;
use super::{Message, fill, translate};

/// Daemon unit and `facelock` group setup.
///
/// Variant and field names are the machine vocabulary: [`Message::machine`]
/// derives its event line from them.
#[derive(Debug, Clone, PartialEq)]
pub enum SystemMessage {
    // -- enrollment and test steps --
    ConfirmDaemonMode,
    SystemdNotDetected,
    SystemdDeclined,
    SystemdSkippedFlag,
    SystemdDeferred,

    // -- group membership --
    CreatingFacelockGroup,
    GroupMembershipNote,
    AlreadyInGroup { user: String },
    ConfirmAddToGroup { user: String },
    GroupAddSkipped { user: String },
    AddedToGroup { user: String },
}

impl Message for SystemMessage {
    fn localized(&self) -> String {
        use SystemMessage::*;
        match self {
            ConfirmDaemonMode => translate("Enable daemon mode with D-Bus activation?"),
            SystemdNotDetected => translate(
                "  systemd not detected. Skipping daemon configuration.\n  Facelock will use oneshot mode for authentication.",
            ),
            SystemdDeclined => {
                translate("  Skipping systemd setup. Facelock will use oneshot mode.")
            }
            SystemdSkippedFlag => translate(
                "  Skipping daemon configuration (--no-systemd).\n  No unit files are written and systemctl is not invoked.",
            ),
            SystemdDeferred => {
                translate("  Answered on the command line; applied once setup finishes.")
            }
            CreatingFacelockGroup => translate("  Creating 'facelock' system group..."),
            GroupMembershipNote => translate(
                "  Note: running daemon commands (preview/test) as a normal user requires\n  membership in the 'facelock' group: sudo usermod -aG facelock <user>",
            ),
            AlreadyInGroup { user } => fill(
                translate("  User '{user}' is already in the 'facelock' group."),
                &[("user", user.clone())],
            ),
            ConfirmAddToGroup { user } => fill(
                translate(
                    "Add user '{user}' to the 'facelock' group? (required to run facelock preview/test without sudo)",
                ),
                &[("user", user.clone())],
            ),
            GroupAddSkipped { user } => fill(
                translate("  Skipped. Add later with: sudo usermod -aG facelock {user}"),
                &[("user", user.clone())],
            ),
            AddedToGroup { user } => fill(
                translate(
                    "  Added '{user}' to the 'facelock' group.\n  NOTE: log out and back in for the new group membership to take effect.",
                ),
                &[("user", user.clone())],
            ),
        }
    }
}

/// One sample per variant, in enum order, for the placeholder sweep.
///
/// [`Self::next_sample`] is an exhaustive `match` with no wildcard arm, so a
/// new variant stops this compiling until it is given a sample and linked
/// into the walk — the sweep cannot silently fall behind the vocabulary.
#[cfg(test)]
impl super::Samples for SystemMessage {
    fn first_sample() -> Self {
        use SystemMessage::*;
        ConfirmDaemonMode
    }

    fn next_sample(&self) -> Option<Self> {
        use SystemMessage::*;
        Some(match self {
            ConfirmDaemonMode => SystemdNotDetected,
            SystemdNotDetected => SystemdDeclined,
            SystemdDeclined => SystemdSkippedFlag,
            SystemdSkippedFlag => SystemdDeferred,
            SystemdDeferred => CreatingFacelockGroup,
            CreatingFacelockGroup => GroupMembershipNote,
            GroupMembershipNote => AlreadyInGroup { user: s("u") },
            AlreadyInGroup { .. } => ConfirmAddToGroup { user: s("u") },
            ConfirmAddToGroup { .. } => GroupAddSkipped { user: s("u") },
            GroupAddSkipped { .. } => AddedToGroup { user: s("u") },
            AddedToGroup { .. } => return None,
        })
    }
}
