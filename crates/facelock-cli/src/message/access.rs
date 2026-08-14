//! Getting in: config load, privilege, and which backend answered.
//!
//! What a command says before it does its own work — the config file is
//! missing or unparseable, the operation needs root, the bus refused us, or
//! the daemon is not there and the direct path took over.

#[cfg(test)]
use super::sample_text as s;
use super::{Message, fill, translate};

/// Getting in: config, privilege, backend.
///
/// Variant and field names are the machine vocabulary: [`Message::machine`]
/// derives its event line from them.
#[derive(Debug, Clone, PartialEq)]
pub enum AccessMessage {
    // -- config load (ConfigLoad::require, D7) --
    NoConfigFile { path: String },
    InvalidConfig { path: String, error: String },

    // -- privilege and access --
    RootRequired { hint: String },
    SudoReexecPrompt,
    AccessDeniedRootHint,
    AccessDeniedGroupHint,
    EnrollTimedOutClientSide,

    // -- backend selection (D1) --
    DaemonUnreachableFallback,
    PreviewGraphicalNeedsDaemonOneshot,
    PreviewGraphicalDaemonUnreachable,
}

impl Message for AccessMessage {
    fn localized(&self) -> String {
        use AccessMessage::*;
        match self {
            NoConfigFile { path } => fill(
                translate("no config file at {path} — run 'sudo facelock setup' to create one"),
                &[("path", path.clone())],
            ),
            InvalidConfig { path, error } => fill(
                translate("invalid config at {path}: {error}"),
                &[("path", path.clone()), ("error", error.clone())],
            ),
            RootRequired { hint } => fill(
                translate("Root required.\n  Run: {hint}"),
                &[("hint", hint.clone())],
            ),
            // The "[Y/n]" hint is appended by the sink, not carried here:
            // `Terminal::confirm_default_yes` owns both the hint and the
            // English answer tokens it parses.
            SudoReexecPrompt => translate("Root required. Re-run with sudo?"),
            AccessDeniedRootHint => translate(
                "Access denied: this operation requires root.\n  Re-run with sudo, or as root.",
            ),
            AccessDeniedGroupHint => translate(
                "Access denied. If you are not in the 'facelock' group, add yourself:\n  sudo usermod -aG facelock $USER\nthen log out and back in (or re-run: sudo facelock setup). Note: some operations require root regardless of group membership.",
            ),
            EnrollTimedOutClientSide => translate(
                "enrollment timed out client-side; the daemon may have completed it — run `facelock list` before retrying",
            ),
            DaemonUnreachableFallback => translate(
                "Warning: daemon.mode = \"daemon\" but the facelock daemon is unreachable — falling back to direct camera access.\nStart it with: sudo systemctl start facelock-daemon",
            ),
            PreviewGraphicalNeedsDaemonOneshot => translate(
                "Graphical preview requires the daemon. In oneshot mode, use --text-only.\nFalling back to text-only mode.\n",
            ),
            PreviewGraphicalDaemonUnreachable => translate(
                "Graphical preview requires the daemon, which is configured but not reachable.\nFalling back to text-only mode. Start the daemon with: sudo systemctl start facelock-daemon\n",
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
impl super::Samples for AccessMessage {
    fn first_sample() -> Self {
        use AccessMessage::*;
        NoConfigFile { path: s("/p") }
    }

    fn next_sample(&self) -> Option<Self> {
        use AccessMessage::*;
        Some(match self {
            NoConfigFile { .. } => InvalidConfig {
                path: s("/p"),
                error: s("e"),
            },
            InvalidConfig { .. } => RootRequired { hint: s("h") },
            RootRequired { .. } => SudoReexecPrompt,
            SudoReexecPrompt => AccessDeniedRootHint,
            AccessDeniedRootHint => AccessDeniedGroupHint,
            AccessDeniedGroupHint => EnrollTimedOutClientSide,
            EnrollTimedOutClientSide => DaemonUnreachableFallback,
            DaemonUnreachableFallback => PreviewGraphicalNeedsDaemonOneshot,
            PreviewGraphicalNeedsDaemonOneshot => PreviewGraphicalDaemonUnreachable,
            PreviewGraphicalDaemonUnreachable => return None,
        })
    }
}
