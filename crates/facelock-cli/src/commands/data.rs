//! `facelock data` — the retained-state domain, and its one verb, `purge`.
//!
//! This is where the two layers below meet: [`crate::lifecycle::LifecycleLease`]
//! owns the exclusion interval and [`facelock_core::purge`] does the
//! descriptor-anchored traversal. Neither knows about the other; the
//! composition contract lives here.
//!
//! # The composition, in order
//!
//! 1. root check first, ahead of every prompt and side effect (C6);
//! 2. `--dry-run` short-circuits to [`facelock_core::purge::report_remnants`]
//!    — it deletes nothing, so it neither needs the destruction
//!    authorization nor takes the lease, and a preview must not stop the
//!    daemon as a side effect;
//! 3. the destruction authorization, then the ordinary confirmation;
//! 4. acquire the lease: flock, prove activation delegates, mask the unit,
//!    stop the daemon, prove the bus name unowned;
//! 5. run the engine through [`facelock_core::purge::purge_with_interrupt`],
//!    handing it the lease's interrupt flag;
//! 6. **[`crate::lifecycle::LifecycleLease::mark_operation_finished`] the
//!    instant the engine returns**, before rendering anything. A
//!    signal-triggered restore blocks on that acknowledgement, so every
//!    statement between the engine returning and this call is time a signal
//!    handler is held off;
//! 7. release — restoring the daemon, or deliberately leaving activation
//!    barred for a caller who uninstalls next.
//!
//! The engine is infallible by construction (`purge_with_interrupt` returns
//! a report, never an error), so step 6 needs no `?`-safe wrapper. A panic
//! between acquisition and release is still covered: `LifecycleLease`'s
//! `Drop` marks the gate itself before restoring.
//!
//! # What the report may and may not say
//!
//! `docs/contracts.md` ("Fixed-root purge boundary") forbids two claims, and
//! [`render_report`] is where both are enforced: a run that retained
//! anything — a remnant inside the roots, a configured path outside them, an
//! unclassifiable config, or an interrupt — must not read as complete
//! destruction, and no run may imply that unlinking erases media. The
//! erasure caveat therefore prints on every completed run, and the
//! completeness verdict is taken from [`PurgeReport::is_complete`] rather
//! than from whether deletion appeared to succeed.

use facelock_core::purge::{
    PurgeOptions, PurgeReport, RemnantKind, purge_with_interrupt, report_remnants,
    sanitize_for_display,
};

use crate::ipc_client;
use crate::lifecycle::LifecycleLease;
use crate::message::{PurgeMessage, Terminal, fail, payload};

/// What `facelock data purge` was asked to do.
///
/// Plain data, the way [`crate::commands::pam::PamRequest`] is: the clap
/// types stay in the binary (`args::DataCli`), so this layer is constructible
/// in a test without a command line, and `--json`'s implications are already
/// resolved by the conversion rather than re-derived here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PurgeRequest {
    /// The destruction authorization. Never set by `--yes` or `--json`.
    pub allow_destruction: bool,
    /// Confirmation prompt suppressed (`--yes`, or implied by `--json`).
    pub no_confirm: bool,
    /// Report only; delete nothing, take no lease.
    pub dry_run: bool,
    /// Keep the daemon stopped and activation barred after purging.
    pub leave_activation_barred: bool,
    /// Emit the machine document instead of the human report.
    pub json: bool,
}

/// How the daemon was left, for the tail of the report.
enum Lifecycle {
    /// The lease restored the prior state.
    Restored,
    /// The barrier is still in place at this path.
    Barred(String),
}

pub fn run(request: PurgeRequest) -> anyhow::Result<()> {
    let PurgeRequest {
        allow_destruction,
        no_confirm,
        dry_run,
        leave_activation_barred,
        json,
    } = request;

    // C6: first statement, ahead of the confirmation prompt, the lease, and
    // any output. Scripted rather than interactive — a destructive command
    // invoked from an uninstall script must fail loudly, not offer to
    // re-exec itself under sudo.
    ipc_client::require_root_scripted("sudo facelock data purge")?;

    if dry_run {
        if !json {
            Terminal.info(&PurgeMessage::DryRunHeader);
        }
        let report = report_remnants(&PurgeOptions::production());
        render_report(&report, json, None);
        return Ok(());
    }

    if !allow_destruction {
        return Err(fail(PurgeMessage::DestructionNotAuthorized));
    }

    if !no_confirm && !Terminal.confirm(&PurgeMessage::ConfirmPurge)? {
        Terminal.info(&PurgeMessage::Cancelled);
        return Ok(());
    }

    // From here the daemon is stopped and activation is barred until the
    // lease is released on some path.
    let lease = LifecycleLease::acquire_system()?;
    let interrupt = lease.interrupt_flag();

    let report = purge_with_interrupt(&PurgeOptions::production(), &interrupt);

    // Immediately, on every path: a signal-triggered restore is waiting on
    // this before it unmasks and restarts the daemon. Nothing may come
    // between the engine returning and this call.
    lease.mark_operation_finished();

    let lifecycle = if leave_activation_barred {
        Lifecycle::Barred(
            lease
                .release_leaving_activation_barred()?
                .display()
                .to_string(),
        )
    } else {
        lease.release()?;
        Lifecycle::Restored
    };

    render_report(&report, json, Some(lifecycle));
    Ok(())
}

/// Render one report, honestly.
///
/// `lifecycle` is present only when a lease was held; a dry run holds none.
fn render_report(report: &PurgeReport, json: bool, lifecycle: Option<Lifecycle>) {
    if json {
        payload(&json_document(report, lifecycle.as_ref()));
        return;
    }

    if report.removed.is_empty() {
        Terminal.info(&PurgeMessage::NothingRemoved);
    } else {
        Terminal.info(&PurgeMessage::RemovedCount {
            count: report.removed.len(),
        });
    }

    if interrupted(report) {
        Terminal.info(&PurgeMessage::Interrupted);
    }

    if !report.remnants.is_empty() {
        Terminal.info(&PurgeMessage::RemnantsHeader {
            count: report.remnants.len(),
        });
        for remnant in &report.remnants {
            Terminal.info(&PurgeMessage::RemnantLine {
                logical: sanitize_for_display(&remnant.logical),
                detail: sanitize_for_display(&remnant.detail),
            });
        }
    }

    if !report.external.is_empty() {
        Terminal.info(&PurgeMessage::ExternalHeader {
            count: report.external.len(),
        });
        for external in &report.external {
            Terminal.info(&PurgeMessage::ExternalLine {
                field: sanitize_for_display(&external.field),
                path: sanitize_for_display(&external.path),
            });
        }
    }

    if let Some(reason) = &report.config_note {
        Terminal.info(&PurgeMessage::ConfigNote {
            reason: sanitize_for_display(reason),
        });
    }

    // The verdict comes from the engine's own refusal to claim completeness,
    // never from "deletion did not error".
    if report.is_complete() {
        Terminal.info(&PurgeMessage::CompleteWithinRoots);
    } else {
        Terminal.info(&PurgeMessage::NotComplete);
    }

    // Unconditional: true of a complete run and an incomplete one alike.
    Terminal.info(&PurgeMessage::ErasureCaveat);

    match lifecycle {
        Some(Lifecycle::Restored) => Terminal.info(&PurgeMessage::DaemonRestored),
        Some(Lifecycle::Barred(path)) => {
            Terminal.info(&PurgeMessage::ActivationLeftBarred { path })
        }
        None => {}
    }
}

/// The machine half: the engine's own `Serialize` shape plus the verdict.
///
/// `complete` is the field a script branches on, and it is
/// [`PurgeReport::is_complete`] verbatim — a caller that trusted the exit
/// status alone would read a partial purge as a finished one, which is the
/// claim `docs/contracts.md` forbids. `secure_erasure` is a constant `false`
/// for the same reason: it is there so no consumer has to infer it.
fn json_document(report: &PurgeReport, lifecycle: Option<&Lifecycle>) -> String {
    serde_json::json!({
        "removed": report.removed,
        "remnants": report.remnants,
        "external": report.external,
        "config_note": report.config_note,
        "complete": report.is_complete(),
        "interrupted": interrupted(report),
        "secure_erasure": false,
        "activation_barred": matches!(lifecycle, Some(Lifecycle::Barred(_))),
        "activation_barrier_path": match lifecycle {
            Some(Lifecycle::Barred(path)) => serde_json::Value::String(path.clone()),
            _ => serde_json::Value::Null,
        },
    })
    .to_string()
}

/// Whether the engine stopped early on the interrupt flag, as opposed to
/// refusing individual objects on safety grounds.
fn interrupted(report: &PurgeReport) -> bool {
    report
        .remnants
        .iter()
        .any(|remnant| remnant.kind == RemnantKind::Interrupted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use facelock_core::purge::{ExternalRemnant, Remnant, Removed, RemovedKind};

    fn report_with(
        removed: &[&str],
        remnants: Vec<Remnant>,
        external: Vec<ExternalRemnant>,
    ) -> PurgeReport {
        PurgeReport {
            removed: removed
                .iter()
                .map(|logical| Removed {
                    logical: (*logical).to_string(),
                    kind: RemovedKind::File,
                })
                .collect(),
            remnants,
            external,
            config_note: None,
        }
    }

    fn remnant(logical: &str, kind: RemnantKind) -> Remnant {
        Remnant {
            logical: logical.to_string(),
            kind,
            detail: "reason".to_string(),
        }
    }

    fn document(report: &PurgeReport, lifecycle: Option<&Lifecycle>) -> serde_json::Value {
        serde_json::from_str(&json_document(report, lifecycle)).expect("valid JSON")
    }

    #[test]
    fn interrupted_is_distinct_from_a_safety_refusal() {
        let symlink = report_with(
            &[],
            vec![remnant("/etc/facelock/a", RemnantKind::SymbolicLink)],
            vec![],
        );
        assert!(
            !interrupted(&symlink),
            "a symlink refusal is not an interrupt"
        );

        let cut_short = report_with(
            &[],
            vec![remnant("/var/lib/facelock", RemnantKind::Interrupted)],
            vec![],
        );
        assert!(interrupted(&cut_short));
    }

    /// An external remnant defeats completeness even though names were
    /// removed. This is the case the contract singles out: purge "must not
    /// claim that all Facelock data is gone".
    #[test]
    fn an_external_remnant_defeats_completeness() {
        let report = report_with(
            &["/var/lib/facelock/facelock.db"],
            vec![],
            vec![ExternalRemnant {
                field: "storage.db_path".to_string(),
                path: "/srv/faces.db".to_string(),
            }],
        );
        assert!(!report.is_complete());

        let document = document(&report, None);
        assert_eq!(document["complete"], serde_json::json!(false));
        assert_eq!(document["external"][0]["field"], "storage.db_path");
    }

    /// A run that removed everything it saw but could not classify the
    /// configuration is still not complete.
    #[test]
    fn an_unclassifiable_config_defeats_completeness() {
        let mut report = report_with(&["/etc/facelock/config.toml"], vec![], vec![]);
        report.config_note = Some("unparseable".to_string());
        assert!(!report.is_complete());
        assert_eq!(
            document(&report, None)["complete"],
            serde_json::json!(false)
        );
    }

    /// The document never advertises secure erasure, on any run.
    #[test]
    fn the_document_never_claims_secure_erasure() {
        let clean = report_with(&["/etc/facelock/config.toml"], vec![], vec![]);
        assert!(clean.is_complete());
        let document = document(&clean, None);
        assert_eq!(document["complete"], serde_json::json!(true));
        assert_eq!(document["secure_erasure"], serde_json::json!(false));
    }

    #[test]
    fn a_barred_release_names_the_barrier_in_the_document() {
        let report = report_with(&[], vec![], vec![]);
        let barred =
            Lifecycle::Barred("/run/systemd/system.control/facelock-daemon.service".to_string());
        let barred = document(&report, Some(&barred));
        assert_eq!(barred["activation_barred"], serde_json::json!(true));
        assert_eq!(
            barred["activation_barrier_path"],
            "/run/systemd/system.control/facelock-daemon.service"
        );

        let restored = document(&report, Some(&Lifecycle::Restored));
        assert_eq!(restored["activation_barred"], serde_json::json!(false));
        assert!(restored["activation_barrier_path"].is_null());
    }

    /// Control characters in an attacker-chosen file name cannot reach the
    /// terminal unescaped. The engine sanitizes for `Display`; the human
    /// report re-applies it because it renders the fields, not the `Display`.
    #[test]
    fn remnant_names_are_sanitized_for_the_human_report() {
        assert_eq!(
            sanitize_for_display("/etc/facelock/\x1b[31mevil"),
            "/etc/facelock/\\x1b[31mevil"
        );
    }
}
