//! Race-safe destruction of retained Facelock state inside the fixed roots.
//!
//! This is the traversal/deletion engine behind explicit biometric data purge
//! (issue #233). It implements the frozen fixed-root purge boundary from
//! `docs/contracts.md` ("Fixed-root purge boundary") and mirrors the
//! descriptor-anchored Debian `postrm` helper, which is the reference
//! implementation of the same envelope.
//!
//! The envelope, in brief:
//!
//! - Only the compiled roots are ever traversed: `/etc/facelock`,
//!   `/var/lib/facelock`, `/var/log/facelock`. The roots themselves are never
//!   removed; their parents are outside the purge boundary.
//! - Every path component from the fixed anchor down is pinned with an
//!   `O_DIRECTORY | O_NOFOLLOW` descriptor and every later operation is
//!   directory-relative (`openat`, `fstatat`, `renameat2`, `unlinkat`).
//!   Public pathnames are never re-resolved for deletion.
//! - Mount identity is proven from `/proc/self/fdinfo` mount IDs checked
//!   against `/proc/self/mountinfo`, plus an `st_dev` match against the opened
//!   root, plus a mountpoint-table lookup. The engine never crosses a mount.
//! - Deletion goes through an atomic `renameat2(RENAME_NOREPLACE)` quarantine
//!   inside the trusted parent, with the complete fixed chain and the
//!   quarantined object's identity re-proven before and after the move.
//! - Traversal is iterative and bounded: at most [`MAX_TRAVERSAL_DEPTH`]
//!   descendant-directory levels and [`MAX_TRAVERSAL_NODES`] inspected entries
//!   per root.
//! - Configured paths outside the compiled roots (`daemon.model_dir`,
//!   `storage.db_path`, `encryption.key_path`, `encryption.sealed_key_path`,
//!   `audit.path`, `snapshots.dir`) are external remnants: reported, never
//!   followed, never deleted.
//! - Anything that cannot be proven safe is retained and reported. Repeated
//!   purge is safe. Unlinking is name removal, not physical erasure.
//!
//! Deviations from the Perl reference are deliberate and commented at each
//! site; the two structural ones are that Rust uses native `*at` syscalls on
//! the pinned descriptors instead of `/proc/self/fd/<fd>` path strings (Perl
//! has no `openat`), and that configuration is classified with the real TOML
//! parser instead of a hand-rolled line scanner (the maintainer script had no
//! dependencies available).
//!
//! The engine takes no locks and does not stop the daemon; lifecycle
//! exclusion (daemon stop, lock, D-Bus activation inhibition) and the CLI
//! surface are owned by sibling changes.

mod config_scan;
mod engine;
mod fd;
mod mounts;
mod report;

pub use engine::{PurgeError, PurgeOptions, TestEnvironment, purge, report_remnants};
pub use report::{
    ExternalRemnant, PurgeReport, Remnant, RemnantKind, Removed, RemovedKind, sanitize_for_display,
};

/// The only recursive purge roots. Fixed at compile time; configuration can
/// never add to them (`docs/contracts.md`, "Fixed-root purge boundary").
pub const PURGE_ROOTS: [&str; 3] = ["/etc/facelock", "/var/lib/facelock", "/var/log/facelock"];

/// Maximum descendant-directory depth below a purge root.
pub const MAX_TRAVERSAL_DEPTH: u32 = 64;

/// Maximum inspected directory entries per purge root.
pub const MAX_TRAVERSAL_NODES: u64 = 10_000;

/// Fixed path of the opaque PAM rollback subtree. A nonempty directory here is
/// unresolved PAM cleanup evidence and is always retained.
pub(crate) const PAM_BACKUPS_LOGICAL: &str = "/var/lib/facelock/pam-backups";

/// Direct children of this directory are enrollment markers, deliberately
/// owned by the enrolled user rather than root.
pub(crate) const ENROLLED_DIR_LOGICAL: &str = "/var/lib/facelock/enrolled";
