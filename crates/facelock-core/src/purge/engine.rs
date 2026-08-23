//! The descriptor-anchored traversal and deletion engine.
//!
//! Control flow mirrors the Debian `postrm` purge helper function for
//! function: `open_fixed_root`, `fixed_root_is_current`, the iterative
//! bounded traversal, the `renameat2(RENAME_NOREPLACE)` quarantine with
//! identity re-proof, and no-replace recovery. Deviations are commented at
//! each site.

use std::ffi::{CStr, CString};
use std::io::Read;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::config_scan;
use super::fd::{
    DirStream, Stat, fstat, lstat_at, lstat_path, open_dir, open_dir_at, open_file_at,
    rename_noreplace, unlink_at,
};
use super::mounts::MountTable;
use super::report::{PurgeReport, RemnantKind, RemovedKind, Reporter};
use super::{
    ENROLLED_DIR_LOGICAL, MAX_TRAVERSAL_DEPTH, MAX_TRAVERSAL_NODES, PAM_BACKUPS_LOGICAL,
    PURGE_ROOTS,
};

/// Configuration classification reads at most this much of `config.toml`.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Bounded number of quarantine name candidates before giving up.
const MAX_QUARANTINE_ATTEMPTS: u32 = 32;

/// Remnant detail for a subtree retained because the caller interrupted the
/// purge. Like the node-cap case, retained entries are deliberately not
/// enumerated: the report names the containing root rather than implying only
/// one entry remains.
const INTERRUPTED_DETAIL: &str =
    "purge interrupted; entries in this root that were not yet processed are retained";

/// Options construction failures. The engine itself never fails: every
/// runtime refusal becomes a reported remnant instead, because a safety
/// refusal must not leave the caller half-purged with no report.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PurgeError {
    /// Test-environment overrides are refused for a privileged caller, so a
    /// real purge can never be redirected through the environment.
    #[error("test environment overrides are refused for a privileged caller")]
    PrivilegedTestEnvironment,
    /// The test prefix must be an absolute path without NUL bytes.
    #[error("test prefix must be an absolute path without NUL bytes")]
    InvalidTestPrefix,
}

/// Relocates the engine below a disposable directory for tests. Mirrors the
/// reference implementation's `FACELOCK_PURGE_TEST_*` overrides, including
/// the rule that a privileged caller can never use them.
#[derive(Debug, Clone)]
pub struct TestEnvironment {
    /// Absolute directory that stands in for `/`. The fixed logical roots
    /// are resolved beneath it.
    pub prefix: PathBuf,
    /// Expected owner of trusted directories and files (normally root).
    pub trusted_uid: u32,
    /// Expected group of trusted directories and files.
    pub trusted_gid: u32,
    /// Alternate mount topology source; defaults to `/proc/self/mountinfo`.
    pub mountinfo_path: Option<PathBuf>,
    /// Alternate depth cap; defaults to [`MAX_TRAVERSAL_DEPTH`].
    pub max_depth: Option<u32>,
    /// Alternate node cap; defaults to [`MAX_TRAVERSAL_NODES`].
    pub max_nodes: Option<u64>,
}

/// How a purge or report pass runs. Production options use the compiled
/// anchors and caps; construction cannot loosen the envelope, only a
/// non-privileged test environment can relocate it.
pub struct PurgeOptions {
    prefix: Option<PathBuf>,
    anchor: CString,
    trusted_uid: u32,
    trusted_gid: u32,
    mountinfo_path: PathBuf,
    max_depth: u32,
    max_nodes: u64,
    pause: Option<PauseHook>,
}

pub(crate) type PauseHook = Box<dyn Fn(PausePoint, &str)>;

/// Race-window instrumentation points for tests, mirroring the reference
/// implementation's pause points. Production never installs a hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PausePoint {
    AfterRootOpen,
    BeforeConfigOpen,
    BeforeRegularOpen,
    BeforeRegularQuarantineMove,
    AfterRegularQuarantine,
    BeforeRegularDelete,
    BeforeDirectoryQuarantineMove,
    AfterDirectoryQuarantine,
    BeforeDirectoryDelete,
}

impl PurgeOptions {
    /// The production envelope: real roots, root-owned trust, kernel mount
    /// topology, compiled caps.
    pub fn production() -> Self {
        PurgeOptions {
            prefix: None,
            anchor: CString::from(c"/"),
            trusted_uid: 0,
            trusted_gid: 0,
            mountinfo_path: PathBuf::from("/proc/self/mountinfo"),
            max_depth: MAX_TRAVERSAL_DEPTH,
            max_nodes: MAX_TRAVERSAL_NODES,
            pause: None,
        }
    }

    /// Relocate the engine below a disposable prefix for tests. Refused for
    /// a privileged caller: a root process must only ever purge the compiled
    /// roots, so no environment can redirect its deletions.
    pub fn with_test_environment(env: TestEnvironment) -> Result<Self, PurgeError> {
        // SAFETY: geteuid cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return Err(PurgeError::PrivilegedTestEnvironment);
        }
        if !env.prefix.is_absolute() {
            return Err(PurgeError::InvalidTestPrefix);
        }
        // Normalize away trailing separators so prefix + logical joins are
        // exact byte concatenations.
        let prefix: PathBuf = env.prefix.components().collect();
        let anchor = CString::new(prefix.as_os_str().as_bytes())
            .map_err(|_| PurgeError::InvalidTestPrefix)?;
        Ok(PurgeOptions {
            prefix: Some(prefix),
            anchor,
            trusted_uid: env.trusted_uid,
            trusted_gid: env.trusted_gid,
            mountinfo_path: env
                .mountinfo_path
                .unwrap_or_else(|| PathBuf::from("/proc/self/mountinfo")),
            max_depth: env.max_depth.unwrap_or(MAX_TRAVERSAL_DEPTH),
            max_nodes: env.max_nodes.unwrap_or(MAX_TRAVERSAL_NODES),
            pause: None,
        })
    }

    #[cfg(test)]
    fn with_pause_hook(mut self, hook: PauseHook) -> Self {
        self.pause = Some(hook);
        self
    }
}

impl Default for PurgeOptions {
    fn default() -> Self {
        PurgeOptions::production()
    }
}

impl std::fmt::Debug for PurgeOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PurgeOptions")
            .field("prefix", &self.prefix)
            .field("trusted_uid", &self.trusted_uid)
            .field("trusted_gid", &self.trusted_gid)
            .field("mountinfo_path", &self.mountinfo_path)
            .field("max_depth", &self.max_depth)
            .field("max_nodes", &self.max_nodes)
            .finish_non_exhaustive()
    }
}

/// Destroy every provably safe object inside the compiled purge roots.
///
/// Infallible by design: every failure is a reported remnant, deletion stops
/// where proof stops, and repeating the call is always safe. The roots
/// themselves are never removed. Success removes names only — it is not
/// physical erasure of media.
pub fn purge(options: &PurgeOptions) -> PurgeReport {
    // A never-set flag: the uninterruptible entry point is a thin wrapper.
    let never = AtomicBool::new(false);
    run(options, Mode::Purge, &never)
}

/// [`purge`], but polling `interrupt` at every deletion boundary.
///
/// Each unlink and each rmdir happens inside one traversal step, and every
/// step begins by loading the flag, so no deletion starts after the flag is
/// observed set. At most the single in-flight deletion transaction completes
/// (or safely restores) after the flag rises; quarantine transactions never
/// straddle a poll, so an interrupt cannot strand an object under a
/// quarantine name.
///
/// On interrupt the engine stops deleting and still returns a report: names
/// removed so far are listed exactly, and every root whose processing was cut
/// short (or never started) is reported as a [`RemnantKind::Interrupted`]
/// remnant, so [`PurgeReport::is_complete`] is false and the caller can name
/// what remains.
pub fn purge_with_interrupt(options: &PurgeOptions, interrupt: &AtomicBool) -> PurgeReport {
    run(options, Mode::Purge, interrupt)
}

/// Classify configured external paths and report remnants without deleting
/// anything (the reference implementation's `report` operation, run at
/// package removal time).
pub fn report_remnants(options: &PurgeOptions) -> PurgeReport {
    let never = AtomicBool::new(false);
    run(options, Mode::Report, &never)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Report,
    Purge,
}

fn run(options: &PurgeOptions, mode: Mode, interrupt: &AtomicBool) -> PurgeReport {
    if interrupt.load(Ordering::SeqCst) {
        // Interrupted before any work: report promptly without touching disk.
        let mut reporter = Reporter::default();
        if let Mode::Purge = mode {
            for logical in PURGE_ROOTS {
                reporter.remnant(logical, RemnantKind::Interrupted, INTERRUPTED_DETAIL);
            }
        }
        return reporter.into_report();
    }
    let mounts = match MountTable::load(&options.mountinfo_path) {
        Ok(mounts) => mounts,
        Err(err) => {
            // Without mount topology nothing can be proven; refuse everything.
            let mut reporter = Reporter::default();
            match mode {
                Mode::Purge => {
                    for logical in PURGE_ROOTS {
                        reporter.remnant(
                            logical,
                            RemnantKind::MountTopologyUnavailable,
                            format!("mount topology is unavailable: {err}"),
                        );
                    }
                }
                Mode::Report => {
                    reporter.config_note(format!("mount topology is unavailable: {err}"));
                }
            }
            return reporter.into_report();
        }
    };
    let mut ctx = Ctx {
        options,
        mounts,
        reporter: Reporter::default(),
        interrupt,
    };
    ctx.inspect_external_configuration();
    if let Mode::Purge = mode {
        for logical in PURGE_ROOTS {
            if ctx.interrupted() {
                // Roots not yet processed are retained wholesale; keep
                // reporting so every unfinished root is named.
                ctx.reporter
                    .remnant(logical, RemnantKind::Interrupted, INTERRUPTED_DETAIL);
                continue;
            }
            if ctx.reporter.is_protected(logical) {
                continue;
            }
            let Some(root) = ctx.open_fixed_root(logical) else {
                continue;
            };
            ctx.purge_root(&root);
        }
    }
    ctx.reporter.into_report()
}

/// One pinned, identity-proven component of a directory chain.
#[derive(Clone)]
struct ChainLink {
    parent: Rc<OwnedFd>,
    handle: Rc<OwnedFd>,
    name: CString,
    /// `fstat` of `handle` at pin time.
    before: Stat,
    mount_id: u64,
}

/// A fully pinned purge root: the fixed anchor plus every component descriptor
/// down to the root directory, each proven trusted, non-symlink, and on the
/// anchor's mount.
struct OpenedRoot {
    base_path: CString,
    base: Rc<OwnedFd>,
    base_before: Stat,
    base_mount_id: u64,
    chain: Vec<ChainLink>,
    root: Rc<OwnedFd>,
    before: Stat,
    mount_id: u64,
    dev: u64,
    logical: &'static str,
}

/// One directory being enumerated during iterative traversal.
struct Frame {
    handle: Rc<OwnedFd>,
    stream: DirStream,
    /// `None` only for the root frame, which is never removed.
    parent: Option<Rc<OwnedFd>>,
    name: Option<CString>,
    logical: String,
    before: Stat,
    depth: u32,
    /// False once any child was refused; a directory with a refused child is
    /// never moved.
    children_removed: bool,
    /// Pinned descendant chain from (but excluding) the root down to this
    /// directory, revalidated immediately before every deletion.
    path_chain: Vec<ChainLink>,
}

enum ChildOutcome {
    /// Removed, absent, or otherwise not blocking the parent's removal.
    Kept,
    /// Retained; the parent directory becomes a remnant too.
    Refused,
    /// A trusted subdirectory to descend into.
    Descend(Box<Frame>),
    /// The per-root node cap was hit; the whole root is retained.
    AbortRoot,
}

enum EntryFlavor {
    File,
    Directory,
}

impl EntryFlavor {
    fn noun(&self) -> &'static str {
        match self {
            EntryFlavor::File => "entry",
            EntryFlavor::Directory => "directory",
        }
    }

    fn same_identity(&self, expected: &Stat, actual: &Stat) -> bool {
        match self {
            EntryFlavor::File => expected.same_identity(actual),
            EntryFlavor::Directory => expected.same_directory_identity(actual),
        }
    }
}

fn is_direct_enrollment_marker(logical: &str) -> bool {
    logical
        .strip_prefix(ENROLLED_DIR_LOGICAL)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|name| !name.is_empty() && !name.contains('/'))
}

/// A root-owned (or test-owned) directory that neither group nor world can
/// write. Every traversed directory must satisfy this before its entries are
/// trusted.
fn trusted_directory(st: &Stat, trusted_uid: u32, trusted_gid: u32) -> bool {
    st.is_dir() && st.uid == trusted_uid && st.gid == trusted_gid && st.mode & 0o022 == 0
}

/// A deletable leaf: a single-link regular file with trusted ownership and a
/// non-group/world-writable mode. The only exception is an owner-only direct
/// enrollment marker, deliberately owned by the enrolled user.
fn trusted_regular(logical: &str, st: &Stat, trusted_uid: u32, trusted_gid: u32) -> bool {
    if !st.is_regular() || st.nlink != 1 {
        return false;
    }
    if is_direct_enrollment_marker(logical) {
        return st.mode & 0o077 == 0;
    }
    st.uid == trusted_uid && st.gid == trusted_gid && st.mode & 0o022 == 0
}

/// Directory-entry names come from the kernel, but display strings must not
/// assume UTF-8. Deletion always operates on the raw bytes; the lossy string
/// is for reporting and the two ASCII logical-path comparisons only.
fn lossy_name(name: &CStr) -> String {
    String::from_utf8_lossy(name.to_bytes()).into_owned()
}

fn parent_logical(logical: &str) -> &str {
    logical
        .rsplit_once('/')
        .map(|(parent, _)| parent)
        .unwrap_or("")
}

struct Ctx<'a> {
    options: &'a PurgeOptions,
    mounts: MountTable,
    reporter: Reporter,
    interrupt: &'a AtomicBool,
}

impl Ctx<'_> {
    fn interrupted(&self) -> bool {
        self.interrupt.load(Ordering::SeqCst)
    }

    fn pause(&self, point: PausePoint, logical: &str) {
        if let Some(hook) = &self.options.pause {
            hook(point, logical);
        }
    }

    /// The descriptor's mount ID, but only when it can also be proven to name
    /// a currently mounted filesystem. With a test prefix the currency check
    /// is skipped: synthetic mountinfo fixtures name exact fake mountpoints
    /// but cannot alter the kernel mount ID of their disposable directories.
    fn proven_mount_id(&self, fd: BorrowedFd<'_>) -> Option<u64> {
        let id = super::fd::mount_id(fd)?;
        if self.options.prefix.is_some() || self.mounts.contains_id(id) {
            Some(id)
        } else {
            None
        }
    }

    /// Whether the actual (prefix-joined) path of a logical path is itself a
    /// mountpoint. Detects bind mounts whose device number is unchanged.
    fn is_mountpoint(&self, logical: &str) -> bool {
        let mut actual = Vec::new();
        if let Some(prefix) = &self.options.prefix {
            actual.extend_from_slice(prefix.as_os_str().as_bytes());
        }
        actual.extend_from_slice(logical.as_bytes());
        self.mounts.is_mountpoint(&actual)
    }

    fn trusted_directory(&self, st: &Stat) -> bool {
        trusted_directory(st, self.options.trusted_uid, self.options.trusted_gid)
    }

    fn trusted_regular(&self, logical: &str, st: &Stat) -> bool {
        trusted_regular(
            logical,
            st,
            self.options.trusted_uid,
            self.options.trusted_gid,
        )
    }

    /// Pin the fixed anchor and every component of one compiled root with
    /// `O_DIRECTORY | O_NOFOLLOW` descriptors, proving each component
    /// trusted, unchanged across its open, and on a proven mount. `None`
    /// with no report means the root does not exist.
    fn open_fixed_root(&mut self, logical: &'static str) -> Option<OpenedRoot> {
        let base_path = self.options.anchor.clone();
        let base_before = match lstat_path(&base_path) {
            Ok(st) => st,
            Err(err) => {
                self.reporter.remnant(
                    logical,
                    RemnantKind::Inaccessible,
                    format!("cannot inspect fixed traversal anchor: {err}"),
                );
                return None;
            }
        };
        if base_before.is_symlink() || !self.trusted_directory(&base_before) {
            self.reporter.remnant(
                logical,
                RemnantKind::UntrustedOwnershipOrMode,
                "fixed traversal anchor is not a trusted directory",
            );
            return None;
        }
        let base = match open_dir(&base_path) {
            Ok(fd) => Rc::new(fd),
            Err(err) => {
                self.reporter.remnant(
                    logical,
                    RemnantKind::Inaccessible,
                    format!("cannot open fixed traversal anchor: {err}"),
                );
                return None;
            }
        };
        let base_opened = match fstat(base.as_fd()) {
            Ok(st) if base_before.same_directory_identity(&st) => st,
            _ => {
                self.reporter.remnant(
                    logical,
                    RemnantKind::ChangedDuringTraversal,
                    "fixed traversal anchor changed while it was opened",
                );
                return None;
            }
        };
        let Some(base_mount_id) = self.proven_mount_id(base.as_fd()) else {
            self.reporter.remnant(
                logical,
                RemnantKind::MountBoundary,
                "cannot prove fixed traversal anchor mount identity",
            );
            return None;
        };

        let parts: Vec<&str> = logical.split('/').filter(|part| !part.is_empty()).collect();
        let mut chain: Vec<ChainLink> = Vec::with_capacity(parts.len());
        let mut parent = base.clone();
        let mut parent_mount_id = base_mount_id;
        let mut component_logical = String::new();
        for (index, part) in parts.iter().enumerate() {
            component_logical.push('/');
            component_logical.push_str(part);
            let Ok(name) = CString::new(*part) else {
                return None; // compiled constants never contain NUL
            };
            let before = match lstat_at(parent.as_fd(), &name) {
                Ok(st) => st,
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => return None,
                Err(err) => {
                    self.reporter.remnant(
                        &component_logical,
                        RemnantKind::Inaccessible,
                        format!("cannot inspect fixed path component: {err}"),
                    );
                    return None;
                }
            };
            if before.is_symlink() {
                self.reporter.remnant(
                    &component_logical,
                    RemnantKind::SymbolicLink,
                    "fixed path component is a symbolic link",
                );
                return None;
            }
            if !self.trusted_directory(&before) {
                self.reporter.remnant(
                    &component_logical,
                    RemnantKind::UntrustedOwnershipOrMode,
                    "fixed path component is not a trusted directory",
                );
                return None;
            }
            let handle = match open_dir_at(parent.as_fd(), &name) {
                Ok(fd) => Rc::new(fd),
                Err(err) => {
                    self.reporter.remnant(
                        &component_logical,
                        RemnantKind::Inaccessible,
                        format!("cannot open fixed path component: {err}"),
                    );
                    return None;
                }
            };
            let opened = match fstat(handle.as_fd()) {
                Ok(st) if before.same_directory_identity(&st) => st,
                _ => {
                    self.reporter.remnant(
                        &component_logical,
                        RemnantKind::ChangedDuringTraversal,
                        "fixed path component changed while it was opened",
                    );
                    return None;
                }
            };
            let Some(mount_id) = self.proven_mount_id(handle.as_fd()) else {
                self.reporter.remnant(
                    &component_logical,
                    RemnantKind::MountBoundary,
                    "cannot prove fixed path component mount identity",
                );
                return None;
            };
            // Intermediate components (/etc, /var, /var/lib) may legitimately
            // be their own filesystems; only the facelock root itself must
            // not be a mount point.
            if index == parts.len() - 1
                && (mount_id != parent_mount_id || self.is_mountpoint(logical))
            {
                self.reporter
                    .remnant(logical, RemnantKind::MountBoundary, "root is a mount point");
                return None;
            }
            chain.push(ChainLink {
                parent: parent.clone(),
                handle: handle.clone(),
                name,
                before: opened,
                mount_id,
            });
            parent = handle;
            parent_mount_id = mount_id;
        }
        let last = chain.last()?;
        let root_handle = last.handle.clone();
        let before = last.before;
        Some(OpenedRoot {
            base_path,
            base,
            base_before: base_opened,
            base_mount_id,
            chain,
            root: root_handle,
            before,
            mount_id: parent_mount_id,
            dev: before.dev,
            logical,
        })
    }

    /// Re-prove the entire fixed chain — anchor and every pinned component —
    /// immediately before a deletion is allowed to proceed.
    fn fixed_root_is_current(&mut self, root: &OpenedRoot) -> bool {
        let base_ok = match (
            lstat_path(&root.base_path),
            fstat(root.base.as_fd()),
            self.proven_mount_id(root.base.as_fd()),
        ) {
            (Ok(public), Ok(opened), Some(mount)) => {
                root.base_before.same_directory_identity(&public)
                    && root.base_before.same_directory_identity(&opened)
                    && mount == root.base_mount_id
            }
            _ => false,
        };
        if !base_ok {
            self.reporter.remnant(
                root.logical,
                RemnantKind::ChangedDuringTraversal,
                "fixed traversal anchor changed before deletion",
            );
            return false;
        }
        for link in &root.chain {
            let entry_ok = match (
                lstat_at(link.parent.as_fd(), &link.name),
                fstat(link.handle.as_fd()),
            ) {
                (Ok(public), Ok(opened)) => {
                    link.before.same_directory_identity(&public)
                        && link.before.same_directory_identity(&opened)
                }
                _ => false,
            };
            if !entry_ok {
                self.reporter.remnant(
                    root.logical,
                    RemnantKind::ChangedDuringTraversal,
                    "fixed path chain changed before deletion",
                );
                return false;
            }
            // A fresh reopen proves the public name still resolves to the
            // pinned directory on the pinned mount.
            let current = match open_dir_at(link.parent.as_fd(), &link.name) {
                Ok(fd) => fd,
                Err(_) => {
                    self.reporter.remnant(
                        root.logical,
                        RemnantKind::ChangedDuringTraversal,
                        "fixed path chain cannot be reopened before deletion",
                    );
                    return false;
                }
            };
            let reopen_ok = match (
                fstat(current.as_fd()),
                self.proven_mount_id(current.as_fd()),
            ) {
                (Ok(st), Some(mount)) => {
                    link.before.same_directory_identity(&st) && mount == link.mount_id
                }
                _ => false,
            };
            if !reopen_ok {
                self.reporter.remnant(
                    root.logical,
                    RemnantKind::ChangedDuringTraversal,
                    "fixed path chain mount changed before deletion",
                );
                return false;
            }
        }
        true
    }

    /// Re-prove every pinned descendant directory between the root and the
    /// object about to be deleted.
    fn traversal_chain_is_current(&mut self, chain: &[ChainLink], logical: &str) -> bool {
        for link in chain {
            let ok = match (
                lstat_at(link.parent.as_fd(), &link.name),
                fstat(link.handle.as_fd()),
                self.proven_mount_id(link.handle.as_fd()),
            ) {
                (Ok(public), Ok(opened), Some(mount)) => {
                    link.before.same_directory_identity(&public)
                        && link.before.same_directory_identity(&opened)
                        && mount == link.mount_id
                }
                _ => false,
            };
            if !ok {
                self.reporter.remnant(
                    logical,
                    RemnantKind::ChangedDuringTraversal,
                    "opened descendant path changed before deletion",
                );
                return false;
            }
        }
        true
    }

    /// Prove an opened descendant sits on the root's filesystem and mount:
    /// equal `st_dev`, equal proven mount ID, and not itself a mountpoint
    /// path (which catches same-device bind mounts). Reports on failure and
    /// returns the proven mount ID on success.
    fn opened_on_root_mount(
        &mut self,
        fd: BorrowedFd<'_>,
        root: &OpenedRoot,
        logical: &str,
    ) -> Option<u64> {
        let proven = match (fstat(fd), self.proven_mount_id(fd)) {
            (Ok(st), Some(mount))
                if st.dev == root.dev && mount == root.mount_id && !self.is_mountpoint(logical) =>
            {
                Some(mount)
            }
            _ => None,
        };
        if proven.is_none() {
            self.reporter
                .remnant(logical, RemnantKind::MountBoundary, "mount boundary");
        }
        proven
    }

    /// Read `/etc/facelock/config.toml` through the pinned root descriptor
    /// and report configured paths outside the compiled roots as external
    /// remnants. Purely observational: nothing is deleted here, and external
    /// paths are never opened or resolved.
    fn inspect_external_configuration(&mut self) {
        let Some(root) = self.open_fixed_root("/etc/facelock") else {
            return;
        };
        let logical = "/etc/facelock/config.toml";
        let name = c"config.toml";
        let before = match lstat_at(root.root.as_fd(), name) {
            Ok(st) => st,
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => return,
            Err(err) => {
                self.reporter.remnant(
                    logical,
                    RemnantKind::Inaccessible,
                    format!("cannot inspect configuration: {err}"),
                );
                return;
            }
        };
        if !self.trusted_regular(logical, &before) || before.size > MAX_CONFIG_BYTES as i64 {
            self.reporter.remnant(
                logical,
                RemnantKind::UntrustedOwnershipOrMode,
                "configuration is not a trusted single-link regular file",
            );
            return;
        }
        self.pause(PausePoint::BeforeConfigOpen, logical);
        let file = match open_file_at(root.root.as_fd(), name) {
            Ok(fd) => fd,
            Err(err) => {
                self.reporter.remnant(
                    logical,
                    RemnantKind::Inaccessible,
                    format!("cannot open configuration: {err}"),
                );
                return;
            }
        };
        let opened_ok = matches!(fstat(file.as_fd()), Ok(st) if before.same_identity(&st));
        if !opened_ok {
            self.reporter.remnant(
                logical,
                RemnantKind::ChangedDuringTraversal,
                "configuration changed while it was inspected",
            );
            return;
        }
        if self
            .opened_on_root_mount(file.as_fd(), &root, logical)
            .is_none()
        {
            return;
        }
        let mut raw = Vec::new();
        let mut reader = std::fs::File::from(file).take(MAX_CONFIG_BYTES + 1);
        if let Err(err) = reader.read_to_end(&mut raw) {
            self.reporter.remnant(
                logical,
                RemnantKind::Inaccessible,
                format!("cannot read configuration: {err}"),
            );
            return;
        }
        if raw.len() as u64 > MAX_CONFIG_BYTES {
            // Grew past the proven size while open; classify nothing from it.
            self.reporter
                .config_note("configuration exceeds the classification size limit");
            return;
        }
        let findings = config_scan::classify_config(&raw);
        for note in findings.notes {
            self.reporter.config_note(note);
        }
        for (field, path) in findings.external {
            self.reporter.external(&field, &path);
        }
    }

    /// Iterative bounded traversal of one pinned root.
    fn purge_root(&mut self, root: &OpenedRoot) {
        self.pause(PausePoint::AfterRootOpen, root.logical);
        if !self.fixed_root_is_current(root) {
            return;
        }
        let stream = match DirStream::open(root.root.as_fd()) {
            Ok(stream) => stream,
            Err(err) => {
                self.reporter.remnant(
                    root.logical,
                    RemnantKind::Inaccessible,
                    format!("cannot enumerate opened root: {err}"),
                );
                return;
            }
        };
        let mut stack: Vec<Frame> = vec![Frame {
            handle: root.root.clone(),
            stream,
            parent: None,
            name: None,
            logical: root.logical.to_string(),
            before: root.before,
            depth: 0,
            children_removed: true,
            path_chain: Vec::new(),
        }];
        let mut nodes_seen: u64 = 0;
        while let Some(top) = stack.last_mut() {
            // The cancellation boundary. Every unlink and rmdir happens
            // inside exactly one iteration, so polling here is a check
            // before each deletion; once the flag is observed set, no
            // further deletion starts in any root.
            if self.interrupted() {
                self.reporter
                    .remnant(root.logical, RemnantKind::Interrupted, INTERRUPTED_DETAIL);
                return;
            }
            let entry = top.stream.next_entry();
            let name = match entry {
                Err(err) => {
                    let logical = stack
                        .last()
                        .map(|frame| frame.logical.clone())
                        .unwrap_or_else(|| root.logical.to_string());
                    self.reporter.remnant(
                        &logical,
                        RemnantKind::Inaccessible,
                        format!("cannot continue reading directory: {err}"),
                    );
                    return;
                }
                Ok(None) => {
                    let Some(frame) = stack.pop() else { break };
                    let removed = self.finish_frame(frame, root);
                    if !removed && let Some(parent) = stack.last_mut() {
                        parent.children_removed = false;
                    }
                    continue;
                }
                Ok(Some(name)) => name,
            };
            let outcome = {
                let Some(frame) = stack.last() else { break };
                let child_logical = format!("{}/{}", frame.logical, lossy_name(&name));
                if self.reporter.is_protected(&child_logical) {
                    ChildOutcome::Refused
                } else {
                    nodes_seen += 1;
                    if nodes_seen > self.options.max_nodes {
                        // The unvisited entries are deliberately not
                        // enumerated once the ceiling is reached. Name the
                        // retained root subtree that contains all of them
                        // rather than implying only the first unseen child
                        // remains.
                        self.reporter.remnant(
                            root.logical,
                            RemnantKind::NodeLimitExceeded,
                            format!("node limit exceeded ({})", self.options.max_nodes),
                        );
                        ChildOutcome::AbortRoot
                    } else {
                        self.process_child(frame, &name, &child_logical, root)
                    }
                }
            };
            match outcome {
                ChildOutcome::Kept => {}
                ChildOutcome::Refused => {
                    if let Some(frame) = stack.last_mut() {
                        frame.children_removed = false;
                    }
                }
                ChildOutcome::Descend(frame) => stack.push(*frame),
                ChildOutcome::AbortRoot => return,
            }
        }
    }

    /// Inspect one directory entry and either delete it (regular file),
    /// refuse it, or descend into it (trusted directory).
    fn process_child(
        &mut self,
        frame: &Frame,
        name: &CString,
        child_logical: &str,
        root: &OpenedRoot,
    ) -> ChildOutcome {
        let before = match lstat_at(frame.handle.as_fd(), name) {
            Ok(st) => st,
            // Already gone: not a refusal.
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => return ChildOutcome::Kept,
            Err(err) => {
                self.reporter.remnant(
                    child_logical,
                    RemnantKind::Inaccessible,
                    format!("cannot inspect: {err}"),
                );
                return ChildOutcome::Refused;
            }
        };
        // PAM rollback state is opaque to the purge. Only an exact trusted
        // empty directory is eligible for removal; every other object at the
        // fixed path is unresolved cleanup evidence regardless of whether the
        // generic traversal could otherwise delete its type.
        if child_logical == PAM_BACKUPS_LOGICAL && !before.is_dir() {
            self.reporter.remnant(
                child_logical,
                RemnantKind::PamRollbackState,
                "PAM rollback state path is not a trusted empty directory",
            );
            return ChildOutcome::Refused;
        }
        if before.is_symlink() {
            self.reporter
                .remnant(child_logical, RemnantKind::SymbolicLink, "symbolic link");
            return ChildOutcome::Refused;
        }
        if before.is_regular() {
            return if self.purge_regular_entry(frame, name, child_logical, &before, root) {
                ChildOutcome::Kept
            } else {
                ChildOutcome::Refused
            };
        }
        if !before.is_dir() {
            self.reporter
                .remnant(child_logical, RemnantKind::NonRegular, "non-regular object");
            return ChildOutcome::Refused;
        }
        if !self.trusted_directory(&before) {
            self.reporter.remnant(
                child_logical,
                RemnantKind::UntrustedOwnershipOrMode,
                "wrong owner or unsafe directory mode",
            );
            return ChildOutcome::Refused;
        }
        let child_depth = frame.depth + 1;
        if child_depth > self.options.max_depth {
            self.reporter.remnant(
                child_logical,
                RemnantKind::DepthLimitExceeded,
                format!("depth limit exceeded ({})", self.options.max_depth),
            );
            return ChildOutcome::Refused;
        }
        let handle = match open_dir_at(frame.handle.as_fd(), name) {
            Ok(fd) => Rc::new(fd),
            Err(err) => {
                self.reporter.remnant(
                    child_logical,
                    RemnantKind::Inaccessible,
                    format!("cannot open directory: {err}"),
                );
                return ChildOutcome::Refused;
            }
        };
        let opened = match fstat(handle.as_fd()) {
            Ok(st) if before.same_directory_identity(&st) => st,
            _ => {
                self.reporter.remnant(
                    child_logical,
                    RemnantKind::ChangedDuringTraversal,
                    "directory changed while it was opened",
                );
                return ChildOutcome::Refused;
            }
        };
        let Some(mount_id) = self.opened_on_root_mount(handle.as_fd(), root, child_logical) else {
            return ChildOutcome::Refused;
        };
        let mut stream = match DirStream::open(handle.as_fd()) {
            Ok(stream) => stream,
            Err(err) => {
                self.reporter.remnant(
                    child_logical,
                    RemnantKind::Inaccessible,
                    format!("cannot enumerate directory: {err}"),
                );
                return ChildOutcome::Refused;
            }
        };
        if child_logical == PAM_BACKUPS_LOGICAL {
            match stream.next_entry() {
                Err(err) => {
                    self.reporter.remnant(
                        child_logical,
                        RemnantKind::PamRollbackState,
                        format!("cannot inspect PAM rollback state: {err}"),
                    );
                    return ChildOutcome::Refused;
                }
                Ok(Some(_)) => {
                    self.reporter.remnant(
                        child_logical,
                        RemnantKind::PamRollbackState,
                        "PAM rollback state remains after removal cleanup",
                    );
                    return ChildOutcome::Refused;
                }
                Ok(None) => stream.rewind(),
            }
        }
        let mut path_chain = frame.path_chain.clone();
        path_chain.push(ChainLink {
            parent: frame.handle.clone(),
            handle: handle.clone(),
            name: name.clone(),
            before: opened,
            mount_id,
        });
        ChildOutcome::Descend(Box::new(Frame {
            handle,
            stream,
            parent: Some(frame.handle.clone()),
            name: Some(name.clone()),
            logical: child_logical.to_string(),
            before,
            depth: child_depth,
            children_removed: true,
            path_chain,
        }))
    }

    /// Quarantine and delete one proven regular file. Returns true only when
    /// the name was removed.
    fn purge_regular_entry(
        &mut self,
        frame: &Frame,
        name: &CStr,
        logical: &str,
        before: &Stat,
        root: &OpenedRoot,
    ) -> bool {
        let parent = frame.handle.as_fd();
        if before.nlink != 1 {
            self.reporter
                .remnant(logical, RemnantKind::HardLink, "hard-linked regular file");
            return false;
        }
        if !self.trusted_regular(logical, before) {
            self.reporter.remnant(
                logical,
                RemnantKind::UntrustedOwnershipOrMode,
                "wrong owner or unsafe mode",
            );
            return false;
        }
        self.pause(PausePoint::BeforeRegularOpen, logical);
        let opened_fd = match open_file_at(parent, name) {
            Ok(fd) => fd,
            Err(err) => {
                self.reporter.remnant(
                    logical,
                    RemnantKind::Inaccessible,
                    format!("cannot open regular file: {err}"),
                );
                return false;
            }
        };
        let opened_ok = matches!(fstat(opened_fd.as_fd()), Ok(st) if before.same_identity(&st));
        if !opened_ok {
            self.reporter.remnant(
                logical,
                RemnantKind::ChangedDuringTraversal,
                "regular file changed while it was opened",
            );
            return false;
        }
        if self
            .opened_on_root_mount(opened_fd.as_fd(), root, logical)
            .is_none()
        {
            return false;
        }
        let current_ok = matches!(lstat_at(parent, name), Ok(st) if before.same_identity(&st));
        if !current_ok {
            self.reporter.remnant(
                logical,
                RemnantKind::ChangedDuringTraversal,
                "changed before unlink",
            );
            return false;
        }
        if !self.fixed_root_is_current(root)
            || !self.traversal_chain_is_current(&frame.path_chain, logical)
        {
            return false;
        }
        let Some(qname) = self.quarantine_entry(
            parent,
            name,
            logical,
            before,
            PausePoint::BeforeRegularQuarantineMove,
        ) else {
            return false;
        };
        let q_logical = format!("{}/{}", frame.logical, lossy_name(&qname));
        self.pause(PausePoint::AfterRegularQuarantine, logical);
        // Reopen the admitted quarantine name and prove the original identity
        // before anything irreversible.
        let q_public = lstat_at(parent, &qname).ok();
        let mut proven: Option<OwnedFd> = None;
        if q_public.as_ref().is_some_and(|st| before.same_identity(st))
            && let Ok(qfd) = open_file_at(parent, &qname)
            && matches!(fstat(qfd.as_fd()), Ok(st) if before.same_identity(&st))
            && self
                .opened_on_root_mount(qfd.as_fd(), root, &q_logical)
                .is_some()
        {
            proven = Some(qfd);
        }
        let Some(qfd) = proven else {
            let identity = q_public.unwrap_or(*before);
            self.restore_quarantined(parent, name, &qname, logical, &identity, EntryFlavor::File);
            return false;
        };
        let q_identity = q_public.unwrap_or(*before);
        if !self.fixed_root_is_current(root)
            || !self.traversal_chain_is_current(&frame.path_chain, logical)
        {
            self.restore_quarantined(
                parent,
                name,
                &qname,
                logical,
                &q_identity,
                EntryFlavor::File,
            );
            return false;
        }
        let final_st = lstat_at(parent, &qname).ok();
        if !final_st.as_ref().is_some_and(|st| before.same_identity(st)) {
            let identity = final_st.unwrap_or(q_identity);
            self.restore_quarantined(parent, name, &qname, logical, &identity, EntryFlavor::File);
            return false;
        }
        self.pause(PausePoint::BeforeRegularDelete, logical);
        if let Err(err) = unlink_at(parent, &qname, false) {
            match lstat_at(parent, &qname) {
                Ok(st) if before.same_identity(&st) => {
                    // Restore instead of stranding the file under a hidden name.
                    self.restore_quarantined(parent, name, &qname, logical, &st, EntryFlavor::File);
                }
                _ => {
                    self.reporter.remnant(
                        &q_logical,
                        RemnantKind::Inaccessible,
                        format!("unlink failed: {err}"),
                    );
                }
            }
            return false;
        }
        // The still-open inode must reach link count zero; otherwise an
        // external hard link retains the data and purge must not claim it is
        // gone.
        if !matches!(fstat(qfd.as_fd()), Ok(st) if st.nlink == 0) {
            self.reporter.external_hardlink(logical);
        }
        drop(qfd);
        drop(opened_fd);
        self.reporter.removed(logical, RemovedKind::File);
        true
    }

    /// Close out a fully enumerated directory frame; delete it when it is a
    /// proven-empty descendant whose children were all removed. Returns true
    /// only when the directory was removed (the root frame returns whether
    /// the fixed chain is still current, and is itself never removed).
    fn finish_frame(&mut self, frame: Frame, root: &OpenedRoot) -> bool {
        let Frame {
            handle,
            stream,
            parent,
            name,
            logical,
            before,
            depth,
            children_removed,
            path_chain,
        } = frame;
        if let Err(err) = stream.finish() {
            self.reporter.remnant(
                &logical,
                RemnantKind::Inaccessible,
                format!("cannot finish reading directory: {err}"),
            );
            return false;
        }
        if depth == 0 {
            // The compiled roots stay as inert empty anchors: their parents
            // are outside the purge boundary, so removing a root cannot use
            // the same in-root quarantine transaction as descendants.
            return self.fixed_root_is_current(root);
        }
        // A refused child makes this directory a retained remnant. Do not
        // move the administrator-visible path merely to discover that the
        // quarantine is nonempty when rmdir is attempted.
        if !children_removed {
            return false;
        }
        let (Some(parent), Some(name)) = (parent, name) else {
            return false;
        };
        let unchanged = match (fstat(handle.as_fd()), lstat_at(parent.as_fd(), &name)) {
            (Ok(opened), Ok(public)) => {
                before.same_directory_identity(&opened) && before.same_directory_identity(&public)
            }
            _ => false,
        };
        if !unchanged {
            self.reporter.remnant(
                &logical,
                RemnantKind::ChangedDuringTraversal,
                "directory changed before removal",
            );
            return false;
        }
        let parent_chain = &path_chain[..path_chain.len().saturating_sub(1)];
        if !self.fixed_root_is_current(root)
            || !self.traversal_chain_is_current(parent_chain, &logical)
        {
            return false;
        }
        let Some(qname) = self.quarantine_entry(
            parent.as_fd(),
            &name,
            &logical,
            &before,
            PausePoint::BeforeDirectoryQuarantineMove,
        ) else {
            return false;
        };
        let q_logical = format!("{}/{}", parent_logical(&logical), lossy_name(&qname));
        self.pause(PausePoint::AfterDirectoryQuarantine, &logical);
        let q_public = lstat_at(parent.as_fd(), &qname).ok();
        let mut proven: Option<OwnedFd> = None;
        if q_public
            .as_ref()
            .is_some_and(|st| before.same_directory_identity(st))
            && let Ok(qfd) = open_dir_at(parent.as_fd(), &qname)
            && matches!(fstat(qfd.as_fd()), Ok(st) if before.same_directory_identity(&st))
            && self
                .opened_on_root_mount(qfd.as_fd(), root, &q_logical)
                .is_some()
        {
            proven = Some(qfd);
        }
        let Some(qfd) = proven else {
            let identity = q_public.unwrap_or(before);
            self.restore_quarantined(
                parent.as_fd(),
                &name,
                &qname,
                &logical,
                &identity,
                EntryFlavor::Directory,
            );
            return false;
        };
        let q_identity = q_public.unwrap_or(before);
        if !self.fixed_root_is_current(root)
            || !self.traversal_chain_is_current(parent_chain, &logical)
        {
            drop(qfd);
            self.restore_quarantined(
                parent.as_fd(),
                &name,
                &qname,
                &logical,
                &q_identity,
                EntryFlavor::Directory,
            );
            return false;
        }
        let final_st = lstat_at(parent.as_fd(), &qname).ok();
        if !final_st
            .as_ref()
            .is_some_and(|st| before.same_directory_identity(st))
        {
            drop(qfd);
            let identity = final_st.unwrap_or(q_identity);
            self.restore_quarantined(
                parent.as_fd(),
                &name,
                &qname,
                &logical,
                &identity,
                EntryFlavor::Directory,
            );
            return false;
        }
        self.pause(PausePoint::BeforeDirectoryDelete, &logical);
        if let Err(err) = unlink_at(parent.as_fd(), &qname, true) {
            match lstat_at(parent.as_fd(), &qname) {
                Ok(st) if before.same_directory_identity(&st) => {
                    self.restore_quarantined(
                        parent.as_fd(),
                        &name,
                        &qname,
                        &logical,
                        &st,
                        EntryFlavor::Directory,
                    );
                }
                _ => {
                    self.reporter.remnant(
                        &q_logical,
                        RemnantKind::Inaccessible,
                        format!("directory removal failed: {err}"),
                    );
                }
            }
            return false;
        }
        drop(qfd);
        self.reporter.removed(&logical, RemovedKind::Directory);
        true
    }

    /// Atomically move a proven entry to a bounded in-parent quarantine name
    /// with `RENAME_NOREPLACE`. A colliding candidate is preserved and
    /// reported, never replaced.
    fn quarantine_entry(
        &mut self,
        parent: BorrowedFd<'_>,
        name: &CStr,
        logical: &str,
        before: &Stat,
        pause_point: PausePoint,
    ) -> Option<CString> {
        for attempt in 0..MAX_QUARANTINE_ATTEMPTS {
            let candidate = format!(
                ".facelock-purge-{:x}-{:x}-{:02x}",
                before.dev, before.ino, attempt
            );
            let Ok(candidate) = CString::new(candidate) else {
                return None; // hex digits never contain NUL
            };
            if candidate.as_bytes() == name.to_bytes() {
                continue;
            }
            self.pause(pause_point, logical);
            match rename_noreplace(parent, name, &candidate) {
                Ok(()) => return Some(candidate),
                Err(err) if err.raw_os_error() == Some(libc::EEXIST) => {
                    let collision_logical =
                        format!("{}/{}", parent_logical(logical), lossy_name(&candidate));
                    self.reporter.remnant(
                        &collision_logical,
                        RemnantKind::QuarantineCollision,
                        "quarantine name collision",
                    );
                }
                Err(err) => {
                    self.reporter.remnant(
                        logical,
                        RemnantKind::Inaccessible,
                        format!("cannot quarantine entry atomically: {err}"),
                    );
                    return None;
                }
            }
        }
        self.reporter.remnant(
            logical,
            RemnantKind::QuarantineCollision,
            "no collision-free quarantine name is available",
        );
        None
    }

    /// Recover a quarantined entry to its public name with the same atomic
    /// no-replace operation, so a replacement that appeared at the public
    /// name preserves both the replacement and the quarantine remnant.
    fn restore_quarantined(
        &mut self,
        parent: BorrowedFd<'_>,
        name: &CStr,
        qname: &CStr,
        logical: &str,
        identity: &Stat,
        flavor: EntryFlavor,
    ) -> bool {
        let q_logical = format!("{}/{}", parent_logical(logical), lossy_name(qname));
        let noun = flavor.noun();
        match rename_noreplace(parent, qname, name) {
            Ok(()) => {}
            Err(err) if err.raw_os_error() == Some(libc::EEXIST) => {
                self.reporter.remnant(
                    logical,
                    RemnantKind::ChangedDuringTraversal,
                    format!("replacement appeared while the verified {noun} was quarantined"),
                );
                self.reporter.remnant(
                    &q_logical,
                    RemnantKind::QuarantineRetained,
                    format!("quarantined {noun} retained for recovery"),
                );
                return false;
            }
            Err(err) => {
                self.reporter.remnant(
                    &q_logical,
                    RemnantKind::QuarantineRetained,
                    format!("cannot restore quarantined {noun} atomically: {err}"),
                );
                return false;
            }
        }
        let restored_ok =
            matches!(lstat_at(parent, name), Ok(st) if flavor.same_identity(identity, &st));
        if !restored_ok {
            self.reporter.remnant(
                logical,
                RemnantKind::ChangedDuringTraversal,
                format!("restored {noun} identity is ambiguous"),
            );
            return false;
        }
        self.reporter.remnant(
            logical,
            RemnantKind::RestoredAfterQuarantine,
            format!("{noun} changed during quarantine and was restored"),
        );
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::purge::report::PurgeReport;
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};

    fn euid() -> u32 {
        // SAFETY: geteuid cannot fail.
        unsafe { libc::geteuid() }
    }

    fn egid() -> u32 {
        // SAFETY: getegid cannot fail.
        unsafe { libc::getegid() }
    }

    /// Test environments are refused for root by design, so the scenario
    /// tests require an unprivileged runner (as the reference test suite
    /// does).
    macro_rules! require_unprivileged {
        () => {
            if euid() == 0 {
                eprintln!("skipping: purge scenario tests require an unprivileged caller");
                return;
            }
        };
    }

    struct Fixture {
        tmp: tempfile::TempDir,
    }

    impl Fixture {
        /// A prefix with all three compiled roots created.
        fn new() -> Fixture {
            let fx = Fixture::bare();
            for root in PURGE_ROOTS {
                fx.mkdir(root);
            }
            fx
        }

        /// A prefix with no roots at all.
        fn bare() -> Fixture {
            Fixture {
                tmp: tempfile::tempdir().expect("tempdir"),
            }
        }

        fn path(&self, logical: &str) -> PathBuf {
            self.tmp.path().join(&logical[1..])
        }

        /// Create a logical directory (and parents), all mode 0755 so every
        /// chain component is trusted.
        fn mkdir(&self, logical: &str) {
            fs::create_dir_all(self.path(logical)).expect("mkdir");
            let mut current = self.tmp.path().to_path_buf();
            for component in Path::new(&logical[1..]).components() {
                current.push(component);
                fs::set_permissions(&current, fs::Permissions::from_mode(0o755)).expect("chmod");
            }
        }

        /// Create a logical regular file, mode 0600.
        fn write(&self, logical: &str, contents: &str) {
            let path = self.path(logical);
            fs::write(&path, contents).expect("write");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        }

        fn chmod(&self, logical: &str, mode: u32) {
            fs::set_permissions(self.path(logical), fs::Permissions::from_mode(mode))
                .expect("chmod");
        }

        /// A sentinel location inside the prefix but outside every compiled
        /// root; the traversal must never reach it.
        fn outside(&self, name: &str) -> PathBuf {
            let dir = self.tmp.path().join("outside");
            fs::create_dir_all(&dir).expect("mkdir outside");
            dir.join(name)
        }

        fn env(&self) -> TestEnvironment {
            TestEnvironment {
                prefix: self.tmp.path().to_path_buf(),
                trusted_uid: euid(),
                trusted_gid: egid(),
                mountinfo_path: None,
                max_depth: None,
                max_nodes: None,
            }
        }

        fn options(&self) -> PurgeOptions {
            PurgeOptions::with_test_environment(self.env()).expect("test options")
        }

        /// A synthetic mountinfo naming the given actual paths as
        /// mountpoints, the way the reference test fixtures do (a real mount
        /// would need root).
        fn mountinfo(&self, mountpoints: &[&Path]) -> PathBuf {
            let path = self.tmp.path().join("mountinfo");
            let mut text = String::from("22 1 0:5 / / rw shared:1 - ext4 /dev/root rw\n");
            for (index, mountpoint) in mountpoints.iter().enumerate() {
                text.push_str(&format!(
                    "{} 22 0:{} / {} rw shared:2 - tmpfs tmpfs rw\n",
                    30 + index,
                    40 + index,
                    mountpoint.display()
                ));
            }
            fs::write(&path, text).expect("write mountinfo");
            path
        }

        /// The first quarantine candidate name the engine will pick for the
        /// object currently at this logical path.
        fn qname_for(&self, logical: &str) -> String {
            let meta = fs::symlink_metadata(self.path(logical)).expect("stat");
            format!(".facelock-purge-{:x}-{:x}-00", meta.dev(), meta.ino())
        }
    }

    fn remnant<'r>(report: &'r PurgeReport, logical: &str) -> &'r crate::purge::Remnant {
        report
            .remnants
            .iter()
            .find(|remnant| remnant.logical == logical)
            .unwrap_or_else(|| panic!("expected a remnant at {logical}: {report:?}"))
    }

    fn removed(report: &PurgeReport, logical: &str) -> bool {
        report.removed.iter().any(|entry| entry.logical == logical)
    }

    #[test]
    fn purges_files_and_directories_and_keeps_roots() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write(
            "/etc/facelock/config.toml",
            "[storage]\ndb_path = \"/var/lib/facelock/facelock.db\"\n",
        );
        fx.write("/var/lib/facelock/facelock.db", "embeddings");
        fx.mkdir("/var/lib/facelock/models/sub");
        fx.write("/var/lib/facelock/models/sub/model.onnx", "weights");
        fx.write("/var/log/facelock/audit.jsonl", "audit");

        let report = purge(&fx.options());

        assert!(report.is_complete(), "{report:?}");
        assert!(removed(&report, "/etc/facelock/config.toml"));
        assert!(removed(&report, "/var/lib/facelock/facelock.db"));
        assert!(removed(&report, "/var/lib/facelock/models/sub/model.onnx"));
        assert!(removed(&report, "/var/lib/facelock/models/sub"));
        assert!(removed(&report, "/var/lib/facelock/models"));
        for root in PURGE_ROOTS {
            assert!(fx.path(root).is_dir(), "{root} must remain as an anchor");
            assert!(!removed(&report, root), "{root} must never be removed");
            assert_eq!(
                fs::read_dir(fx.path(root)).expect("read root").count(),
                0,
                "{root} must be empty"
            );
        }
    }

    #[test]
    fn absent_roots_are_clean() {
        require_unprivileged!();
        let fx = Fixture::bare();
        let report = purge(&fx.options());
        assert!(report.is_complete(), "{report:?}");
        assert!(report.removed.is_empty());
    }

    #[test]
    fn repeated_purge_is_safe() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/facelock.db", "embeddings");
        assert!(purge(&fx.options()).is_complete());
        let second = purge(&fx.options());
        assert!(second.is_complete(), "{second:?}");
        assert!(second.removed.is_empty());
    }

    #[test]
    fn symlink_is_refused_and_target_survives() {
        require_unprivileged!();
        let fx = Fixture::new();
        let secret = fx.outside("secret");
        fs::write(&secret, "must survive").expect("write");
        symlink(&secret, fx.path("/var/lib/facelock/link")).expect("symlink");

        let report = purge(&fx.options());

        let found = remnant(&report, "/var/lib/facelock/link");
        assert_eq!(found.kind, RemnantKind::SymbolicLink);
        assert!(!report.is_complete());
        assert!(fx.path("/var/lib/facelock/link").symlink_metadata().is_ok());
        assert_eq!(fs::read(&secret).expect("read"), b"must survive");
    }

    #[test]
    fn symlinked_directory_contents_are_never_entered() {
        require_unprivileged!();
        let fx = Fixture::new();
        let outside_dir = fx.outside("dir");
        fs::create_dir(&outside_dir).expect("mkdir");
        fs::write(outside_dir.join("sentinel"), "must survive").expect("write");
        symlink(&outside_dir, fx.path("/var/lib/facelock/escape")).expect("symlink");

        let report = purge(&fx.options());

        assert_eq!(
            remnant(&report, "/var/lib/facelock/escape").kind,
            RemnantKind::SymbolicLink
        );
        assert_eq!(
            fs::read(outside_dir.join("sentinel")).expect("read"),
            b"must survive"
        );
    }

    #[test]
    fn hard_linked_file_is_refused() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/facelock.db", "embeddings");
        let keep = fx.outside("keep");
        fs::hard_link(fx.path("/var/lib/facelock/facelock.db"), &keep).expect("hard link");

        let report = purge(&fx.options());

        let found = remnant(&report, "/var/lib/facelock/facelock.db");
        assert_eq!(found.kind, RemnantKind::HardLink);
        assert!(fx.path("/var/lib/facelock/facelock.db").exists());
        assert_eq!(fs::read(&keep).expect("read"), b"embeddings");
    }

    #[test]
    fn non_regular_object_is_refused() {
        require_unprivileged!();
        let fx = Fixture::new();
        let fifo = fx.path("/var/lib/facelock/pipe");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect("cstring");
        // SAFETY: valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

        let report = purge(&fx.options());

        assert_eq!(
            remnant(&report, "/var/lib/facelock/pipe").kind,
            RemnantKind::NonRegular
        );
        assert!(fifo.symlink_metadata().is_ok());
    }

    #[test]
    fn group_writable_file_and_directory_are_refused() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/shared.db", "embeddings");
        fx.chmod("/var/lib/facelock/shared.db", 0o620);
        fx.mkdir("/var/lib/facelock/shared-dir");
        fx.write("/var/lib/facelock/shared-dir/inner", "kept");
        fx.chmod("/var/lib/facelock/shared-dir", 0o775);

        let report = purge(&fx.options());

        assert_eq!(
            remnant(&report, "/var/lib/facelock/shared.db").kind,
            RemnantKind::UntrustedOwnershipOrMode
        );
        assert_eq!(
            remnant(&report, "/var/lib/facelock/shared-dir").kind,
            RemnantKind::UntrustedOwnershipOrMode
        );
        assert!(fx.path("/var/lib/facelock/shared.db").exists());
        assert_eq!(
            fs::read(fx.path("/var/lib/facelock/shared-dir/inner")).expect("read"),
            b"kept"
        );
    }

    #[test]
    fn wrong_trusted_owner_refuses_the_anchor() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/facelock.db", "embeddings");
        let mut env = fx.env();
        env.trusted_uid = euid().wrapping_add(1);
        let options = PurgeOptions::with_test_environment(env).expect("options");

        let report = purge(&options);

        for root in PURGE_ROOTS {
            assert_eq!(
                remnant(&report, root).kind,
                RemnantKind::UntrustedOwnershipOrMode
            );
        }
        assert!(report.removed.is_empty());
        assert!(fx.path("/var/lib/facelock/facelock.db").exists());
    }

    #[test]
    fn enrollment_markers_use_the_owner_only_exception() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.mkdir("/var/lib/facelock/enrolled");
        fx.write("/var/lib/facelock/enrolled/alice", "{}");
        fx.write("/var/lib/facelock/enrolled/bob", "{}");
        fx.chmod("/var/lib/facelock/enrolled/bob", 0o640);

        let report = purge(&fx.options());

        assert!(removed(&report, "/var/lib/facelock/enrolled/alice"));
        assert_eq!(
            remnant(&report, "/var/lib/facelock/enrolled/bob").kind,
            RemnantKind::UntrustedOwnershipOrMode
        );
        assert!(fx.path("/var/lib/facelock/enrolled/bob").exists());
        // A refused child keeps the parent directory in place.
        assert!(fx.path("/var/lib/facelock/enrolled").is_dir());
        assert!(!removed(&report, "/var/lib/facelock/enrolled"));
    }

    #[test]
    fn nonempty_pam_backups_subtree_is_opaque() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.mkdir("/var/lib/facelock/pam-backups");
        fx.write(
            "/var/lib/facelock/pam-backups/sudo.123-000000001",
            "rollback",
        );

        let report = purge(&fx.options());

        assert_eq!(
            remnant(&report, "/var/lib/facelock/pam-backups").kind,
            RemnantKind::PamRollbackState
        );
        assert_eq!(
            fs::read(fx.path("/var/lib/facelock/pam-backups/sudo.123-000000001")).expect("read"),
            b"rollback"
        );
    }

    #[test]
    fn empty_pam_backups_directory_is_removed() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.mkdir("/var/lib/facelock/pam-backups");
        let report = purge(&fx.options());
        assert!(report.is_complete(), "{report:?}");
        assert!(removed(&report, "/var/lib/facelock/pam-backups"));
    }

    #[test]
    fn pam_backups_path_that_is_not_a_directory_is_retained() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/pam-backups", "not a directory");
        let report = purge(&fx.options());
        assert_eq!(
            remnant(&report, "/var/lib/facelock/pam-backups").kind,
            RemnantKind::PamRollbackState
        );
        assert!(fx.path("/var/lib/facelock/pam-backups").exists());
    }

    #[test]
    fn root_that_is_a_mount_point_is_refused() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/facelock.db", "embeddings");
        fx.write("/var/log/facelock/audit.jsonl", "audit");
        let state_root = fx.path("/var/lib/facelock");
        let mut env = fx.env();
        env.mountinfo_path = Some(fx.mountinfo(&[&state_root]));
        let options = PurgeOptions::with_test_environment(env).expect("options");

        let report = purge(&options);

        let found = remnant(&report, "/var/lib/facelock");
        assert_eq!(found.kind, RemnantKind::MountBoundary);
        assert_eq!(found.detail, "root is a mount point");
        assert!(fx.path("/var/lib/facelock/facelock.db").exists());
        // The sibling root is unaffected.
        assert!(removed(&report, "/var/log/facelock/audit.jsonl"));
    }

    #[test]
    fn bind_mount_inside_a_root_is_refused() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.mkdir("/var/lib/facelock/bind");
        fx.write("/var/lib/facelock/bind/sentinel", "must survive");
        fx.write("/var/lib/facelock/facelock.db", "embeddings");
        let bind = fx.path("/var/lib/facelock/bind");
        let mut env = fx.env();
        env.mountinfo_path = Some(fx.mountinfo(&[&bind]));
        let options = PurgeOptions::with_test_environment(env).expect("options");

        let report = purge(&options);

        let found = remnant(&report, "/var/lib/facelock/bind");
        assert_eq!(found.kind, RemnantKind::MountBoundary);
        assert_eq!(found.detail, "mount boundary");
        assert_eq!(
            fs::read(fx.path("/var/lib/facelock/bind/sentinel")).expect("read"),
            b"must survive"
        );
        assert!(removed(&report, "/var/lib/facelock/facelock.db"));
    }

    #[test]
    fn nested_mount_below_a_subdirectory_is_refused() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.mkdir("/var/lib/facelock/a/b");
        fx.write("/var/lib/facelock/a/b/sentinel", "must survive");
        fx.write("/var/lib/facelock/a/file", "removable");
        let nested = fx.path("/var/lib/facelock/a/b");
        let mut env = fx.env();
        env.mountinfo_path = Some(fx.mountinfo(&[&nested]));
        let options = PurgeOptions::with_test_environment(env).expect("options");

        let report = purge(&options);

        assert_eq!(
            remnant(&report, "/var/lib/facelock/a/b").kind,
            RemnantKind::MountBoundary
        );
        assert!(removed(&report, "/var/lib/facelock/a/file"));
        assert!(!removed(&report, "/var/lib/facelock/a"));
        assert_eq!(
            fs::read(fx.path("/var/lib/facelock/a/b/sentinel")).expect("read"),
            b"must survive"
        );
    }

    #[test]
    fn depth_cap_retains_deep_subtrees_and_cleans_shallow_ones() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.mkdir("/var/lib/facelock/a/b/c");
        fx.write("/var/lib/facelock/a/b/c/deep", "must survive");
        fx.write("/var/lib/facelock/a/b/shallow", "removable");
        let mut env = fx.env();
        env.max_depth = Some(2);
        let options = PurgeOptions::with_test_environment(env).expect("options");

        let report = purge(&options);

        let found = remnant(&report, "/var/lib/facelock/a/b/c");
        assert_eq!(found.kind, RemnantKind::DepthLimitExceeded);
        assert!(removed(&report, "/var/lib/facelock/a/b/shallow"));
        assert!(!removed(&report, "/var/lib/facelock/a/b"));
        assert!(!removed(&report, "/var/lib/facelock/a"));
        assert_eq!(
            fs::read(fx.path("/var/lib/facelock/a/b/c/deep")).expect("read"),
            b"must survive"
        );
    }

    #[test]
    fn node_cap_reports_the_whole_root_as_retained() {
        require_unprivileged!();
        let fx = Fixture::new();
        for index in 0..4 {
            fx.write(&format!("/var/lib/facelock/file-{index}"), "data");
        }
        let mut env = fx.env();
        env.max_nodes = Some(2);
        let options = PurgeOptions::with_test_environment(env).expect("options");

        let report = purge(&options);

        let found = remnant(&report, "/var/lib/facelock");
        assert_eq!(found.kind, RemnantKind::NodeLimitExceeded);
        let survivors = fs::read_dir(fx.path("/var/lib/facelock"))
            .expect("read dir")
            .count();
        assert_eq!(survivors, 2, "traversal must stop at the cap");
    }

    #[test]
    fn external_config_paths_are_reported_and_untouched() {
        require_unprivileged!();
        let fx = Fixture::new();
        let model_dir = fx.outside("models");
        fs::create_dir(&model_dir).expect("mkdir");
        fs::write(model_dir.join("model.onnx"), "weights").expect("write");
        fx.write(
            "/etc/facelock/config.toml",
            &format!(
                "[daemon]\nmodel_dir = \"{}\"\n\n[storage]\ndb_path = \"/var/lib/facelock/../../etc/shadow\"\n",
                model_dir.display()
            ),
        );

        let report = purge(&fx.options());

        assert!(!report.is_complete());
        let fields: Vec<(&str, &str)> = report
            .external
            .iter()
            .map(|entry| (entry.field.as_str(), entry.path.as_str()))
            .collect();
        assert!(fields.contains(&("daemon.model_dir", model_dir.to_str().expect("utf8"))));
        assert!(fields.contains(&("storage.db_path", "/var/lib/facelock/../../etc/shadow")));
        // Classification happened before the config file itself was purged.
        assert!(removed(&report, "/etc/facelock/config.toml"));
        assert_eq!(
            fs::read(model_dir.join("model.onnx")).expect("read"),
            b"weights"
        );
    }

    #[test]
    fn report_mode_classifies_without_deleting() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write(
            "/etc/facelock/config.toml",
            "[storage]\ndb_path = \"/srv/facelock.db\"\n",
        );
        fx.write("/var/lib/facelock/facelock.db", "embeddings");

        let report = report_remnants(&fx.options());

        assert!(report.removed.is_empty());
        assert_eq!(report.external.len(), 1);
        assert!(fx.path("/etc/facelock/config.toml").exists());
        assert!(fx.path("/var/lib/facelock/facelock.db").exists());
    }

    #[test]
    fn unparseable_configuration_makes_the_report_incomplete() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/etc/facelock/config.toml", "[unterminated\n");
        let report = purge(&fx.options());
        assert_eq!(
            report.config_note.as_deref(),
            Some("configuration is not valid TOML")
        );
        assert!(!report.is_complete());
        // The invalid file is still inside the root and still purgeable.
        assert!(removed(&report, "/etc/facelock/config.toml"));
    }

    #[test]
    fn mount_topology_unavailable_refuses_everything() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/facelock.db", "embeddings");
        let mut env = fx.env();
        env.mountinfo_path = Some(fx.tmp.path().join("missing-mountinfo"));
        let options = PurgeOptions::with_test_environment(env).expect("options");

        let report = purge(&options);

        for root in PURGE_ROOTS {
            assert_eq!(
                remnant(&report, root).kind,
                RemnantKind::MountTopologyUnavailable
            );
        }
        assert!(report.removed.is_empty());
        assert!(fx.path("/var/lib/facelock/facelock.db").exists());
    }

    #[test]
    fn root_component_replaced_by_symlink_is_refused() {
        require_unprivileged!();
        let fx = Fixture::bare();
        fx.mkdir("/etc/facelock");
        fx.mkdir("/var/log/facelock");
        fx.mkdir("/var/lib");
        fx.write("/var/log/facelock/audit.jsonl", "audit");
        let outside_dir = fx.outside("fake-root");
        fs::create_dir(&outside_dir).expect("mkdir");
        fs::write(outside_dir.join("sentinel"), "must survive").expect("write");
        symlink(&outside_dir, fx.path("/var/lib/facelock")).expect("symlink");

        let report = purge(&fx.options());

        assert_eq!(
            remnant(&report, "/var/lib/facelock").kind,
            RemnantKind::SymbolicLink
        );
        assert_eq!(
            fs::read(outside_dir.join("sentinel")).expect("read"),
            b"must survive"
        );
        // The other roots are still cleaned.
        assert!(removed(&report, "/var/log/facelock/audit.jsonl"));
    }

    #[test]
    fn config_swapped_to_symlink_before_open_is_refused_and_protected() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write(
            "/etc/facelock/config.toml",
            "[storage]\ndb_path = \"/srv/db\"\n",
        );
        let secret = fx.outside("secret");
        fs::write(&secret, "must survive").expect("write");
        let config_path = fx.path("/etc/facelock/config.toml");
        let secret_for_hook = secret.clone();
        let fired = Cell::new(false);
        let options = fx.options().with_pause_hook(Box::new(move |point, _| {
            if point == PausePoint::BeforeConfigOpen && !fired.replace(true) {
                fs::remove_file(&config_path).expect("remove");
                symlink(&secret_for_hook, &config_path).expect("symlink");
            }
        }));

        let report = purge(&options);

        let found = remnant(&report, "/etc/facelock/config.toml");
        assert_eq!(found.kind, RemnantKind::Inaccessible);
        assert!(found.detail.starts_with("cannot open configuration"));
        // The refusal protects the path from the later traversal: the
        // planted symlink must still be there and the target untouched.
        assert!(
            fx.path("/etc/facelock/config.toml")
                .symlink_metadata()
                .expect("lstat")
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&secret).expect("read"), b"must survive");
    }

    #[test]
    fn file_swapped_to_symlink_before_open_is_refused() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/victim.db", "embeddings");
        let secret = fx.outside("secret");
        fs::write(&secret, "must survive").expect("write");
        let victim = fx.path("/var/lib/facelock/victim.db");
        let secret_for_hook = secret.clone();
        let fired = Cell::new(false);
        let options = fx
            .options()
            .with_pause_hook(Box::new(move |point, logical| {
                if point == PausePoint::BeforeRegularOpen
                    && logical == "/var/lib/facelock/victim.db"
                    && !fired.replace(true)
                {
                    fs::remove_file(&victim).expect("remove");
                    symlink(&secret_for_hook, &victim).expect("symlink");
                }
            }));

        let report = purge(&options);

        let found = remnant(&report, "/var/lib/facelock/victim.db");
        assert_eq!(found.kind, RemnantKind::Inaccessible);
        assert!(found.detail.starts_with("cannot open regular file"));
        assert_eq!(fs::read(&secret).expect("read"), b"must survive");
    }

    #[test]
    fn object_swapped_before_quarantine_is_restored_not_deleted() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/victim.db", "original");
        let victim = fx.path("/var/lib/facelock/victim.db");
        let fired = Cell::new(false);
        let options = fx
            .options()
            .with_pause_hook(Box::new(move |point, logical| {
                if point == PausePoint::BeforeRegularQuarantineMove
                    && logical == "/var/lib/facelock/victim.db"
                    && !fired.replace(true)
                {
                    // Swap in a different inode at the public name; the identity
                    // re-proof after the rename must reject it and restore it.
                    fs::remove_file(&victim).expect("remove");
                    fs::write(&victim, "replacement").expect("write");
                    fs::set_permissions(&victim, fs::Permissions::from_mode(0o600)).expect("chmod");
                }
            }));

        let report = purge(&options);

        let found = remnant(&report, "/var/lib/facelock/victim.db");
        assert_eq!(found.kind, RemnantKind::RestoredAfterQuarantine);
        assert!(!removed(&report, "/var/lib/facelock/victim.db"));
        assert_eq!(
            fs::read(fx.path("/var/lib/facelock/victim.db")).expect("read"),
            b"replacement"
        );
    }

    #[test]
    fn replacement_during_quarantine_preserves_both_objects() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/victim.db", "original");
        let qname = fx.qname_for("/var/lib/facelock/victim.db");
        let victim = fx.path("/var/lib/facelock/victim.db");
        let quarantine_path = fx.path("/var/lib/facelock").join(&qname);
        let fired = Cell::new(false);
        let options = fx
            .options()
            .with_pause_hook(Box::new(move |point, logical| {
                if point == PausePoint::AfterRegularQuarantine
                    && logical == "/var/lib/facelock/victim.db"
                    && !fired.replace(true)
                {
                    // Invalidate the quarantined object's identity and occupy the
                    // public name so the no-replace recovery collides.
                    fs::set_permissions(&quarantine_path, fs::Permissions::from_mode(0o666))
                        .expect("chmod");
                    fs::write(&victim, "replacement").expect("write");
                }
            }));

        let report = purge(&options);

        let public = remnant(&report, "/var/lib/facelock/victim.db");
        assert_eq!(public.kind, RemnantKind::ChangedDuringTraversal);
        assert!(public.detail.starts_with("replacement appeared"));
        let quarantined = remnant(&report, &format!("/var/lib/facelock/{qname}"));
        assert_eq!(quarantined.kind, RemnantKind::QuarantineRetained);
        assert_eq!(
            fs::read(fx.path("/var/lib/facelock/victim.db")).expect("read"),
            b"replacement"
        );
        assert_eq!(
            fs::read(fx.path("/var/lib/facelock").join(&qname)).expect("read"),
            b"original"
        );
    }

    #[test]
    fn hard_link_added_before_delete_is_reported_after_unlink() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/victim.db", "embeddings");
        let qname = fx.qname_for("/var/lib/facelock/victim.db");
        let quarantine_path = fx.path("/var/lib/facelock").join(&qname);
        let keep = fx.outside("keep");
        let keep_for_hook = keep.clone();
        let fired = Cell::new(false);
        let options = fx
            .options()
            .with_pause_hook(Box::new(move |point, logical| {
                if point == PausePoint::BeforeRegularDelete
                    && logical == "/var/lib/facelock/victim.db"
                    && !fired.replace(true)
                {
                    // The last inode-conditional check has passed; a link created
                    // now must be detected by the post-unlink link count.
                    fs::hard_link(&quarantine_path, &keep_for_hook).expect("hard link");
                }
            }));

        let report = purge(&options);

        assert!(removed(&report, "/var/lib/facelock/victim.db"));
        let found = remnant(&report, "/var/lib/facelock/victim.db");
        assert_eq!(found.kind, RemnantKind::ExternalHardLink);
        assert!(!report.is_complete());
        assert_eq!(fs::read(&keep).expect("read"), b"embeddings");
    }

    #[test]
    fn quarantine_name_collision_is_preserved() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/victim.db", "embeddings");
        let qname = fx.qname_for("/var/lib/facelock/victim.db");
        let collision_logical = format!("/var/lib/facelock/{qname}");
        // Occupy the first candidate name with an untrusted file so it is
        // refused wherever readdir happens to order it.
        fx.write(&collision_logical, "collision");
        fx.chmod(&collision_logical, 0o666);

        let report = purge(&fx.options());

        assert!(removed(&report, "/var/lib/facelock/victim.db"));
        assert!(!fx.path("/var/lib/facelock/victim.db").exists());
        remnant(&report, &collision_logical);
        assert_eq!(
            fs::read(fx.path(&collision_logical)).expect("read"),
            b"collision"
        );
    }

    #[test]
    fn directory_changed_during_quarantine_is_restored() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.mkdir("/var/lib/facelock/empty");
        let qname = fx.qname_for("/var/lib/facelock/empty");
        let quarantine_path = fx.path("/var/lib/facelock").join(&qname);
        let fired = Cell::new(false);
        let options = fx
            .options()
            .with_pause_hook(Box::new(move |point, logical| {
                if point == PausePoint::AfterDirectoryQuarantine
                    && logical == "/var/lib/facelock/empty"
                    && !fired.replace(true)
                {
                    fs::set_permissions(&quarantine_path, fs::Permissions::from_mode(0o775))
                        .expect("chmod");
                }
            }));

        let report = purge(&options);

        let found = remnant(&report, "/var/lib/facelock/empty");
        assert_eq!(found.kind, RemnantKind::RestoredAfterQuarantine);
        assert!(fx.path("/var/lib/facelock/empty").is_dir());
        assert!(!removed(&report, "/var/lib/facelock/empty"));
    }

    #[test]
    fn fixed_chain_change_after_root_open_stops_deletion() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/facelock.db", "embeddings");
        let outside_dir = fx.outside("swapped-root");
        fs::create_dir(&outside_dir).expect("mkdir");
        let root_path = fx.path("/var/lib/facelock");
        let moved_away = fx.outside("moved-away");
        let fired = Cell::new(false);
        let options = fx
            .options()
            .with_pause_hook(Box::new(move |point, logical| {
                if point == PausePoint::AfterRootOpen
                    && logical == "/var/lib/facelock"
                    && !fired.replace(true)
                {
                    // Swap the pinned root's public name to a different directory.
                    fs::rename(&root_path, &moved_away).expect("rename");
                    fs::rename(&outside_dir, &root_path).expect("rename");
                }
            }));

        let report = purge(&options);

        let found = remnant(&report, "/var/lib/facelock");
        assert_eq!(found.kind, RemnantKind::ChangedDuringTraversal);
        assert!(!removed(&report, "/var/lib/facelock/facelock.db"));
        assert_eq!(
            fs::read(fx.outside("moved-away").join("facelock.db")).expect("read"),
            b"embeddings"
        );
    }

    #[test]
    fn test_environment_rejects_a_relative_prefix() {
        require_unprivileged!();
        let err = PurgeOptions::with_test_environment(TestEnvironment {
            prefix: PathBuf::from("relative/prefix"),
            trusted_uid: euid(),
            trusted_gid: egid(),
            mountinfo_path: None,
            max_depth: None,
            max_nodes: None,
        })
        .expect_err("relative prefix must be refused");
        assert_eq!(err, PurgeError::InvalidTestPrefix);
    }

    #[test]
    fn production_options_use_the_compiled_envelope() {
        let options = PurgeOptions::production();
        assert_eq!(options.trusted_uid, 0);
        assert_eq!(options.trusted_gid, 0);
        assert_eq!(options.max_depth, MAX_TRAVERSAL_DEPTH);
        assert_eq!(options.max_nodes, MAX_TRAVERSAL_NODES);
        assert!(options.prefix.is_none());
    }

    #[test]
    fn direct_enrollment_marker_paths_are_exact() {
        assert!(is_direct_enrollment_marker(
            "/var/lib/facelock/enrolled/alice"
        ));
        assert!(!is_direct_enrollment_marker("/var/lib/facelock/enrolled"));
        assert!(!is_direct_enrollment_marker(
            "/var/lib/facelock/enrolled/sub/alice"
        ));
        assert!(!is_direct_enrollment_marker("/var/lib/facelock/enrolled/"));
        assert!(!is_direct_enrollment_marker("/etc/facelock/enrolled/alice"));
    }

    #[test]
    fn trusted_regular_enforces_the_marker_exception_scope() {
        let marker = Stat {
            dev: 1,
            ino: 2,
            mode: libc::S_IFREG | 0o600,
            nlink: 1,
            uid: 12345,
            gid: 12345,
            size: 10,
        };
        // Wrong-owner files pass only as direct enrollment markers.
        assert!(trusted_regular(
            "/var/lib/facelock/enrolled/alice",
            &marker,
            0,
            0
        ));
        assert!(!trusted_regular(
            "/var/lib/facelock/facelock.db",
            &marker,
            0,
            0
        ));
        assert!(!trusted_regular(
            "/var/lib/facelock/enrolled/sub/alice",
            &marker,
            0,
            0
        ));
        // A group-accessible marker is refused even in place.
        let mut open_marker = marker;
        open_marker.mode = libc::S_IFREG | 0o640;
        assert!(!trusted_regular(
            "/var/lib/facelock/enrolled/alice",
            &open_marker,
            0,
            0
        ));
        // Hard links and non-regular objects never qualify.
        let mut linked = marker;
        linked.nlink = 2;
        assert!(!trusted_regular(
            "/var/lib/facelock/enrolled/alice",
            &linked,
            0,
            0
        ));
        let mut trusted_root_file = marker;
        trusted_root_file.uid = 0;
        trusted_root_file.gid = 0;
        assert!(trusted_regular(
            "/var/lib/facelock/facelock.db",
            &trusted_root_file,
            0,
            0
        ));
        let mut group_writable = trusted_root_file;
        group_writable.mode = libc::S_IFREG | 0o620;
        assert!(!trusted_regular(
            "/var/lib/facelock/facelock.db",
            &group_writable,
            0,
            0
        ));
    }

    #[test]
    fn trusted_directory_enforces_owner_and_mode() {
        let dir = Stat {
            dev: 1,
            ino: 2,
            mode: libc::S_IFDIR | 0o755,
            nlink: 2,
            uid: 0,
            gid: 0,
            size: 0,
        };
        assert!(trusted_directory(&dir, 0, 0));
        assert!(!trusted_directory(&dir, 1000, 1000));
        let mut group_writable = dir;
        group_writable.mode = libc::S_IFDIR | 0o775;
        assert!(!trusted_directory(&group_writable, 0, 0));
        let mut file = dir;
        file.mode = libc::S_IFREG | 0o755;
        assert!(!trusted_directory(&file, 0, 0));
    }

    #[test]
    fn preset_interrupt_reports_all_roots_and_deletes_nothing() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.write("/var/lib/facelock/facelock.db", "embeddings");
        let flag = AtomicBool::new(true);

        let report = purge_with_interrupt(&fx.options(), &flag);

        for root in PURGE_ROOTS {
            assert_eq!(remnant(&report, root).kind, RemnantKind::Interrupted);
        }
        assert!(report.removed.is_empty());
        assert!(!report.is_complete());
        assert!(fx.path("/var/lib/facelock/facelock.db").exists());
    }

    #[test]
    fn interrupt_mid_traversal_stops_deleting_and_accounts_exactly() {
        require_unprivileged!();
        let fx = Fixture::new();
        let files: Vec<String> = (0..5)
            .map(|index| format!("/var/lib/facelock/file-{index}"))
            .collect();
        for logical in &files {
            fx.write(logical, "data");
        }
        let sentinel = fx.outside("sentinel");
        fs::write(&sentinel, "must survive").expect("write");
        let flag = std::sync::Arc::new(AtomicBool::new(false));
        let flag_for_hook = flag.clone();
        let options = fx
            .options()
            .with_pause_hook(Box::new(move |point, logical| {
                if point == PausePoint::BeforeRegularDelete && logical == "/var/lib/facelock/file-2"
                {
                    flag_for_hook.store(true, Ordering::SeqCst);
                }
            }));

        let report = purge_with_interrupt(&options, &flag);

        // The single in-flight deletion completes; nothing after it starts.
        assert!(removed(&report, "/var/lib/facelock/file-2"));
        assert_eq!(
            remnant(&report, "/var/lib/facelock").kind,
            RemnantKind::Interrupted
        );
        assert!(!report.is_complete());
        // Exact accounting: a file is in the removed list iff it is gone.
        for logical in &files {
            assert_eq!(
                removed(&report, logical),
                !fx.path(logical).exists(),
                "removed list and disk state disagree for {logical}"
            );
        }
        // A root never reached is reported, not silently skipped; the root
        // finished before the flag rose carries no interrupt remnant.
        assert_eq!(
            remnant(&report, "/var/log/facelock").kind,
            RemnantKind::Interrupted
        );
        assert!(
            !report
                .remnants
                .iter()
                .any(|entry| entry.logical == "/etc/facelock")
        );
        assert_eq!(fs::read(&sentinel).expect("read"), b"must survive");
    }

    #[test]
    fn interrupt_after_the_last_file_deletion_still_reports_partial() {
        require_unprivileged!();
        let fx = Fixture::new();
        fx.mkdir("/var/lib/facelock/dir");
        fx.write("/var/lib/facelock/dir/only", "data");
        let flag = std::sync::Arc::new(AtomicBool::new(false));
        let flag_for_hook = flag.clone();
        let options = fx
            .options()
            .with_pause_hook(Box::new(move |point, logical| {
                if point == PausePoint::BeforeRegularDelete
                    && logical == "/var/lib/facelock/dir/only"
                {
                    flag_for_hook.store(true, Ordering::SeqCst);
                }
            }));

        let report = purge_with_interrupt(&options, &flag);

        assert!(removed(&report, "/var/lib/facelock/dir/only"));
        assert!(!fx.path("/var/lib/facelock/dir/only").exists());
        // The wind-down rmdir of the now-empty parent is itself a deletion
        // and must not run once the flag is up.
        assert!(fx.path("/var/lib/facelock/dir").is_dir());
        assert!(!removed(&report, "/var/lib/facelock/dir"));
        assert_eq!(
            remnant(&report, "/var/lib/facelock").kind,
            RemnantKind::Interrupted
        );
        assert!(!report.is_complete());
    }
}
