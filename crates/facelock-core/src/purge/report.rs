//! Structured purge outcome: what was deleted, what was refused, and why.

use std::collections::HashSet;
use std::fmt;

use serde::Serialize;

/// Why an object inside a compiled root was retained instead of deleted.
///
/// The coarse category is machine-matchable; `Remnant::detail` carries the
/// precise human-readable reason (mirroring the reference implementation's
/// messages).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RemnantKind {
    /// A symbolic link, or a fixed path component that is one. Never followed.
    SymbolicLink,
    /// A regular file with more than one link.
    HardLink,
    /// Not a regular file or directory (FIFO, socket, device, ...).
    NonRegular,
    /// Wrong owner, or a group/world-writable mode, on the object or on a
    /// fixed path component.
    UntrustedOwnershipOrMode,
    /// A mount boundary: differing device or mount ID, a mountpoint path, or
    /// a root that is itself a mount point.
    MountBoundary,
    /// A directory below the 64-level depth cap.
    DepthLimitExceeded,
    /// The 10,000-entry cap was reached; the whole root subtree is retained.
    NodeLimitExceeded,
    /// An identity re-proof failed: the object, the fixed chain, or the
    /// traversal chain changed while the engine was operating.
    ChangedDuringTraversal,
    /// A quarantine candidate name was already occupied; the collision is
    /// preserved.
    QuarantineCollision,
    /// A quarantined object could not be restored to its public name and is
    /// retained under the quarantine name for recovery.
    QuarantineRetained,
    /// The object changed during quarantine and was atomically restored.
    RestoredAfterQuarantine,
    /// The opaque PAM rollback subtree is not an empty trusted directory.
    PamRollbackState,
    /// `/proc/self/mountinfo` could not be read; nothing can be proven.
    MountTopologyUnavailable,
    /// The file's name was removed but its inode is still reachable through
    /// an external hard link; the data is not gone.
    ExternalHardLink,
    /// An inspect, open, enumerate, unlink, or rmdir syscall failed.
    Inaccessible,
}

/// A retained object inside a compiled root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Remnant {
    /// Fixed logical path (always under a compiled root), e.g.
    /// `/var/lib/facelock/facelock.db`.
    pub logical: String,
    pub kind: RemnantKind,
    /// Exact reason, aligned with the reference implementation's messages.
    pub detail: String,
}

impl fmt::Display for Remnant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({})",
            sanitize_for_display(&self.logical),
            sanitize_for_display(&self.detail)
        )
    }
}

/// A configured path outside every compiled root. Reported, never followed,
/// never deleted; its existence means purge must not claim all Facelock data
/// is gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExternalRemnant {
    /// The configuration field, e.g. `storage.db_path`.
    pub field: String,
    /// The configured path exactly as written.
    pub path: String,
}

impl fmt::Display for ExternalRemnant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}={}",
            sanitize_for_display(&self.field),
            sanitize_for_display(&self.path)
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum RemovedKind {
    File,
    Directory,
}

/// A successfully deleted name. Name removal only: this makes no claim about
/// SSD flash translation layers, snapshots, backups, or journal history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Removed {
    pub logical: String,
    pub kind: RemovedKind,
}

/// The complete outcome of one purge or report pass.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
pub struct PurgeReport {
    /// Names removed, in deletion order.
    pub removed: Vec<Removed>,
    /// Objects retained inside the compiled roots, with reasons.
    pub remnants: Vec<Remnant>,
    /// Configured paths outside the compiled roots, untouched by design.
    pub external: Vec<ExternalRemnant>,
    /// Set when the configuration could not be fully classified, so external
    /// state may exist that this report does not name.
    pub config_note: Option<String>,
}

impl PurgeReport {
    /// True only when nothing was refused and the configuration was fully
    /// classified. A false result means retained state remains and the caller
    /// must name the remnants rather than describe the purge as complete.
    pub fn is_complete(&self) -> bool {
        self.remnants.is_empty() && self.external.is_empty() && self.config_note.is_none()
    }
}

/// Escape control characters so an attacker-chosen file name cannot corrupt
/// terminal output or logs (the reference's `report_text`).
pub fn sanitize_for_display(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        let code = ch as u32;
        if code < 0x20 || (0x7f..=0x9f).contains(&code) {
            out.push_str(&format!("\\x{code:02x}"));
        } else {
            out.push(ch);
        }
    }
    out
}

/// Accumulates the report during a pass, deduplicates repeated findings, and
/// tracks protected logical paths that later traversal must not touch.
#[derive(Debug, Default)]
pub(crate) struct Reporter {
    report: PurgeReport,
    protected: HashSet<String>,
    seen: HashSet<String>,
}

impl Reporter {
    pub fn remnant(&mut self, logical: &str, kind: RemnantKind, detail: impl Into<String>) {
        self.protected.insert(logical.to_string());
        if !self.seen.insert(format!("remnant\0{logical}")) {
            return;
        }
        let detail = detail.into();
        tracing::warn!(logical, ?kind, detail, "purge remnant retained");
        self.report.remnants.push(Remnant {
            logical: logical.to_string(),
            kind,
            detail,
        });
    }

    /// An external hard link discovered after unlink. The public name is
    /// already gone, so this does not protect the path; it only records that
    /// the data is still reachable elsewhere.
    pub fn external_hardlink(&mut self, logical: &str) {
        if !self.seen.insert(format!("external-hardlink\0{logical}")) {
            return;
        }
        tracing::warn!(logical, "external hard-link remnant retained");
        self.report.remnants.push(Remnant {
            logical: logical.to_string(),
            kind: RemnantKind::ExternalHardLink,
            detail: "inode remains linked after quarantine unlink".to_string(),
        });
    }

    pub fn external(&mut self, field: &str, path: &str) {
        if !self.seen.insert(format!("external\0{field}\0{path}")) {
            return;
        }
        tracing::warn!(field, path, "external remnant retained");
        self.report.external.push(ExternalRemnant {
            field: field.to_string(),
            path: path.to_string(),
        });
    }

    /// Only the first unclassifiable-configuration reason is kept, matching
    /// the reference.
    pub fn config_note(&mut self, reason: impl Into<String>) {
        if self.report.config_note.is_none() {
            let reason = reason.into();
            tracing::warn!(reason, "configuration could not be fully classified");
            self.report.config_note = Some(reason);
        }
    }

    pub fn removed(&mut self, logical: &str, kind: RemovedKind) {
        tracing::debug!(logical, ?kind, "purged");
        self.report.removed.push(Removed {
            logical: logical.to_string(),
            kind,
        });
    }

    pub fn is_protected(&self, logical: &str) -> bool {
        self.protected.contains(logical)
    }

    pub fn into_report(self) -> PurgeReport {
        self.report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_escapes_control_characters() {
        assert_eq!(sanitize_for_display("plain"), "plain");
        assert_eq!(sanitize_for_display("a\nb"), "a\\x0ab");
        assert_eq!(sanitize_for_display("\x1b[31mred"), "\\x1b[31mred");
        assert_eq!(sanitize_for_display("\u{7f}"), "\\x7f");
        assert_eq!(sanitize_for_display("ünïcode"), "ünïcode");
    }

    #[test]
    fn reporter_deduplicates_and_protects() {
        let mut reporter = Reporter::default();
        reporter.remnant(
            "/etc/facelock/a",
            RemnantKind::SymbolicLink,
            "symbolic link",
        );
        reporter.remnant(
            "/etc/facelock/a",
            RemnantKind::HardLink,
            "second report is dropped",
        );
        assert!(reporter.is_protected("/etc/facelock/a"));
        assert!(!reporter.is_protected("/etc/facelock/b"));
        let report = reporter.into_report();
        assert_eq!(report.remnants.len(), 1);
        assert_eq!(report.remnants[0].kind, RemnantKind::SymbolicLink);
    }

    #[test]
    fn config_note_keeps_first_reason() {
        let mut reporter = Reporter::default();
        reporter.config_note("first");
        reporter.config_note("second");
        assert_eq!(reporter.into_report().config_note.as_deref(), Some("first"));
    }

    #[test]
    fn completeness_requires_no_findings() {
        let mut reporter = Reporter::default();
        reporter.removed("/var/log/facelock/audit.jsonl", RemovedKind::File);
        assert!(reporter.into_report().is_complete());

        let mut reporter = Reporter::default();
        reporter.external("storage.db_path", "/srv/db");
        assert!(!reporter.into_report().is_complete());

        let mut reporter = Reporter::default();
        reporter.config_note("unparseable");
        assert!(!reporter.into_report().is_complete());
    }

    #[test]
    fn external_hardlink_does_not_protect() {
        let mut reporter = Reporter::default();
        reporter.external_hardlink("/var/lib/facelock/facelock.db");
        assert!(!reporter.is_protected("/var/lib/facelock/facelock.db"));
        let report = reporter.into_report();
        assert_eq!(report.remnants[0].kind, RemnantKind::ExternalHardLink);
    }
}
