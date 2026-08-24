//! Explicit biometric data destruction: `facelock data purge` (#233).
//!
//! Every line this domain renders is bound by two rules from
//! `docs/contracts.md` ("Fixed-root purge boundary"): a purge that refused
//! anything must never read as complete destruction, and no line may imply
//! that unlinking erases media. [`PurgeMessage::ErasureCaveat`] carries the
//! second rule and is printed on every completed run, successful or not.

#[cfg(test)]
use super::sample_text as s;
use super::{Message, fill, translate};

/// What `facelock data purge` says to a human.
///
/// Variant and field names are the machine vocabulary: [`Message::machine`]
/// derives its event line from them.
#[derive(Debug, Clone, PartialEq)]
pub enum PurgeMessage {
    // -- authorization, separate from the ordinary `--yes` prompt bypass --
    DestructionNotAuthorized,
    ConfirmPurge,
    Cancelled,

    // -- what the run did --
    DryRunHeader,
    DryRunScope,
    RemovedCount { count: usize },
    NothingRemoved,

    // -- what it did not do; the honesty half of the report --
    RemnantsHeader { count: usize },
    RemnantLine { logical: String, detail: String },
    ExternalHeader { count: usize },
    ExternalLine { field: String, path: String },
    ConfigNote { reason: String },
    Interrupted,
    NotComplete,
    CompleteWithinRoots,
    ErasureCaveat,

    // -- lifecycle outcome --
    DaemonRestored,
    ActivationLeftBarred { path: String },
    LifecycleRestoreFailed { reason: String },
}

impl Message for PurgeMessage {
    fn localized(&self) -> String {
        use PurgeMessage::*;
        match self {
            // Names both gates so a caller who supplied `--yes` and got
            // refused learns why: prompt suppression is not authorization.
            DestructionNotAuthorized => translate(
                "Refusing to destroy biometric data without explicit authorization.\n  Re-run with --allow-destruction. --yes only skips the prompt; it does not authorize destruction.\n  Use --dry-run to see what would be removed.",
            ),
            ConfirmPurge => translate(
                "This permanently destroys every enrolled face and all retained Facelock state in /etc/facelock, /var/lib/facelock and /var/log/facelock. Continue?",
            ),
            Cancelled => translate("Cancelled. Nothing was removed."),
            DryRunHeader => {
                translate("Dry run: nothing will be removed. Reporting what purge would find.")
            }
            // The scope sentence, not a verdict. Report mode classifies the
            // configured paths and stops; it never opens the roots. Saying
            // "removed nothing" or "nothing was retained" here would be a
            // claim about work that did not happen, and a reader could take
            // it for "my biometric data is already gone".
            DryRunScope => translate(
                "Scope: configured paths only. The contents of /etc/facelock, /var/lib/facelock and /var/log/facelock were NOT examined, so this reports nothing about what is stored there. A real purge traverses them and reports what it removed and retained.",
            ),
            RemovedCount { count } => fill(
                translate("Removed {count} name(s) from the compiled Facelock roots."),
                &[("count", count.to_string())],
            ),
            NothingRemoved => translate("Removed nothing: there was no retained state to remove."),
            RemnantsHeader { count } => fill(
                translate("{count} object(s) inside the roots were retained:"),
                &[("count", count.to_string())],
            ),
            RemnantLine { logical, detail } => fill(
                translate("  {logical} — {detail}"),
                &[("logical", logical.clone()), ("detail", detail.clone())],
            ),
            ExternalHeader { count } => fill(
                translate(
                    "{count} configured path(s) lie outside the compiled roots and were left untouched by design:",
                ),
                &[("count", count.to_string())],
            ),
            ExternalLine { field, path } => fill(
                translate("  {field} = {path}"),
                &[("field", field.clone()), ("path", path.clone())],
            ),
            ConfigNote { reason } => fill(
                translate(
                    "The configuration could not be fully classified ({reason}), so external state may exist that this report does not name.",
                ),
                &[("reason", reason.clone())],
            ),
            Interrupted => {
                translate("Interrupted: the purge stopped at a deletion boundary before finishing.")
            }
            // The sentence the contract requires instead of a completion
            // claim whenever anything at all was retained.
            NotComplete => translate(
                "Facelock data was NOT completely destroyed. The remnants above are still present; re-run after resolving them, or remove the external paths yourself.",
            ),
            CompleteWithinRoots => translate(
                "Nothing was retained inside the compiled roots, and no configured path lies outside them.",
            ),
            // Printed on every completed run. `docs/contracts.md` forbids
            // describing purge as forensic destruction.
            ErasureCaveat => translate(
                "Removing a name is not erasure. Filesystem deletion does not securely erase SSDs, snapshots, or backups.",
            ),
            DaemonRestored => translate("Daemon lifecycle restored to its prior state."),
            // The purge is already done and already reported above; this is
            // about the daemon, and it needs someone to act.
            LifecycleRestoreFailed { reason } => fill(
                translate(
                    "The purge finished and is reported above, but the daemon lifecycle could not be restored: {reason}\nFace authentication may stay off until this is resolved. Check `systemctl status facelock-daemon.service` and /run/systemd/system.control.",
                ),
                &[("reason", reason.clone())],
            ),
            ActivationLeftBarred { path } => fill(
                translate(
                    "Daemon activation is still barred by {path}. Face authentication stays off until you remove that file and run `systemctl daemon-reload`, or reboot.",
                ),
                &[("path", path.clone())],
            ),
        }
    }
}

/// One sample per variant, in enum order, for the sweeps in [`super::Samples`].
#[cfg(test)]
impl super::Samples for PurgeMessage {
    const VARIANT_COUNT: usize = 19;

    fn samples() -> Vec<Self> {
        use PurgeMessage::*;
        vec![
            DestructionNotAuthorized,
            ConfirmPurge,
            Cancelled,
            DryRunHeader,
            DryRunScope,
            RemovedCount { count: 3 },
            NothingRemoved,
            RemnantsHeader { count: 2 },
            RemnantLine {
                logical: s("/etc/facelock/x"),
                detail: s("symbolic link"),
            },
            ExternalHeader { count: 1 },
            ExternalLine {
                field: s("storage.db_path"),
                path: s("/srv/db"),
            },
            ConfigNote { reason: s("r") },
            Interrupted,
            NotComplete,
            CompleteWithinRoots,
            ErasureCaveat,
            DaemonRestored,
            ActivationLeftBarred {
                path: s("/run/systemd/system.control/facelock-daemon.service"),
            },
            LifecycleRestoreFailed { reason: s("r") },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two contract sentences this domain exists to guarantee.
    #[test]
    fn the_erasure_caveat_never_claims_erasure() {
        let text = PurgeMessage::ErasureCaveat.localized();
        assert!(text.contains("not securely erase"));
        assert!(!text.to_lowercase().contains("forensic"));
    }

    /// A refusal names the authorization flag and says `--yes` is not it.
    #[test]
    fn the_authorization_refusal_distinguishes_the_two_flags() {
        let text = PurgeMessage::DestructionNotAuthorized.localized();
        assert!(text.contains("--allow-destruction"));
        assert!(text.contains("--yes"));
    }

    /// The incomplete verdict must not read as success.
    #[test]
    fn the_incomplete_verdict_says_so_in_the_negative() {
        let text = PurgeMessage::NotComplete.localized();
        assert!(text.contains("NOT completely destroyed"));
    }
}
