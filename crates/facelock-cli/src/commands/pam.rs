//! `facelock pam add | remove | status` — the `/etc/pam.d` writer.
//!
//! This is the most dangerous text the CLI writes: a bad line in
//! `/etc/pam.d/sudo` costs a `sudo`, a bad line in `/etc/pam.d/system-auth`
//! costs the machine. The module is built around that.
//!
//! # Why a verb
//!
//! The writer used to be reachable only as `setup --pam [--service X]
//! [--remove] [--yes] [--if-present]` — two `requires = "pam"` modifiers
//! hanging off a flag, which is what a missing verb looks like. Four defects
//! came out of that shape, and they are one refactor rather than four:
//!
//! 1. **Flag-on-flag.** `--service`/`--remove` only meant anything with
//!    `--pam`, so the action lived in a flag and its object in another flag.
//! 2. **One service per process.** `--service` was an `Option<String>`, so a
//!    wrapper wanting three services ran three processes: three root checks,
//!    three module checks, three previews, three copies of the closing hint —
//!    and no atomicity, since a failure on the third left the first two
//!    written.
//! 3. **`--yes` meant two things.** It suppressed the per-file confirmation
//!    *and* unlocked [`SENSITIVE_SERVICES`], so there was no way to say
//!    "unattended, and still refuse `system-auth`". [`PamRequest::no_confirm`]
//!    and [`PamRequest::allow_sensitive`] are now separate, and
//!    **`--no-confirm` never implies `--allow-sensitive`**. `setup --yes`
//!    keeps its combined meaning and is the one documented exception; the
//!    alias maps it onto both.
//! 4. **A no-op was indistinguishable from an action.** The old writer
//!    returned `Ok(())` for *installed*, *already present* and *declined*
//!    alike, which is why integrations pre-grepped `/etc/pam.d/<service>` for
//!    `pam_facelock.so` — a shell reimplementation of
//!    [`is_facelock_pam_line`]. [`Outcome`] is that answer, and
//!    `pam status --json` is the probe that replaces the grep.
//!
//! # Two-phase, and what that does and does not promise
//!
//! [`plan_writes`] validates **every** requested service — name well-formed,
//! file present (subject to `--if-present`), sensitive-gate, and what the edit
//! would be — before [`apply_add`]/[`apply_remove`] touches anything. A
//! validation failure therefore writes nothing at all, which is what gives a
//! caller's `set -e` loop real all-or-nothing semantics for the failure mode
//! that actually happens: a typo'd or gated service name.
//!
//! It is **not** a transaction. A write-phase I/O error on service N — a full
//! disk, a read-only mount — leaves services 1..N-1 written. Those are
//! reported per service ([`Outcome::Failed`]) and the process exits non-zero;
//! the remaining services are still attempted, because each is an independent
//! file with its own backup and a half-reported plan is harder to recover from
//! than a fully-reported one. The rollback is the `.facelock-backup` file the
//! write phase makes before each edit, and nothing here deletes it.
//!
//! **Continue and report is the policy on every entry point**, not just on the
//! verb: [`apply_all`] is the one phase-two loop, and the four entry points
//! differ only in how they *read* its rows — [`write_in`] as an exit code, the
//! three `setup --pam` aliases as a `Result` through [`first_failure`], once
//! every service has been attempted. The aliases used to stop at the first
//! failure, which made the paragraph above true of one caller and false of
//! three (invisibly, since `setup` passes one service at a time).
//!
//! # Confinement
//!
//! A service name is **one path component** ([`confined`]), rejected before
//! any I/O on every verb. `base.join(service)` is not a confinement
//! primitive: an absolute `service` *replaces* `base` outright.
//!
//! A well-formed name still has to survive the *filesystem*: on an authselect
//! system `/etc/pam.d/system-auth` and `/etc/pam.d/password-auth` are symlinks
//! into `/etc/authselect`, and `read`/`copy`/`write` follow a symlink without
//! being asked to. Editing through one writes a file authselect regenerates,
//! and drops the `.facelock-backup` beside the *link* rather than beside the
//! file that changed. So [`resolve_service_path`] stats the entry with
//! `symlink_metadata` and, when it is a link, canonicalizes it: a target under
//! `base` is followed (the real file is read, rewritten and backed up), and a
//! target anywhere else — or one that cannot be resolved at all — is a
//! validation failure, so the two-phase rule applies and nothing is written
//! for the whole run. A *hard* link is refused outright: `nlink > 1` says the
//! inode has another name and does not say where, which is the one question
//! confinement exists to answer.
//!
//! Because a link inside `base` **is** followed, the sensitive gate runs twice
//! — on the name as typed and on the file it resolved to ([`gate_sensitive`]).
//! Otherwise `alias -> system-auth` is an ungated name for a gated file.
//!
//! # Vendor directories
//!
//! A service name is not a file in one directory. Linux-PAM reads `/etc/pam.d`
//! first and a compile-time *vendor* directory second — `/usr/lib/pam.d` on
//! every distribution that enables the feature — and packages have moved their
//! configuration there: on current Arch, `polkit` ships
//! `/usr/lib/pam.d/polkit-1` and `/etc/pam.d/polkit-1` does not exist. So
//! [`PamDirs`] is an ordered search path, [`Target::locate`] takes the whole of
//! it, and the first directory holding the name wins.
//!
//! **Only the first directory is ever written to.** The rest are package-owned:
//! an edit there is clobbered by the next upgrade and makes `pacman -Qkk`
//! report a modified file. A service that resolves only in a vendor directory
//! is *copied* into `/etc/pam.d` with the facelock line already in it — one
//! atomic write of the final content — and the copy carries a provenance
//! header saying what it was forked from. That is what the `/etc` layer is
//! for.
//!
//! # Enumeration
//!
//! `status` answers about the services it is *given*, which leaves the same
//! blind spot from the other side: it will report `sudo` fine while a
//! configured `polkit-1` or `omarchy-lock-face` is broken, because nobody
//! named it. `pam status --all` is the enumerating form — [`scan_directories`]
//! walks the resolved directories for files that name `pam_facelock.so` and
//! feeds the names it finds to the same [`status_reports`] the explicit form
//! uses, so the two cannot answer differently about one service.
//!
//! **It parses; it keeps no manifest.** A state file listing what facelock has
//! edited drifts the moment anyone edits `/etc/pam.d` by hand, restores a
//! backup, or removes a package — and then `status` reports fiction with
//! confidence. A directory scan is ground truth.
//!
//! **A directory that could not be listed is reported, not treated as empty.**
//! "Nothing is configured here" and "I could not look here" are different
//! answers, and rendering them the same is what made a broken lock stack and a
//! healthy one look identical. See [`DirState`].
//!
//! # Limits
//!
//! `remove` takes no backup of its own and relies on the one `add` wrote.
//! Stated in `docs/contracts.md` ("facelock pam Semantics", Limits) rather
//! than fixed here.
//!
//! A replace writes a new inode, so it carries what it is told to carry: mode,
//! owner and the SELinux label. **POSIX ACLs and every other xattr are not
//! carried** — a `setfacl`'d service file loses its ACL on the first `pam
//! add`. No distribution ships one, and reconstructing an arbitrary ACL is not
//! something this should be guessing at, so it is written down rather than
//! attempted.

use std::ffi::OsStr;
use std::fs;
use std::io::IsTerminal;
use std::path::{Component, Path, PathBuf};

use dialoguer::Confirm;

use crate::message::{Message, PamMessage, Terminal, fail};

/// The PAM configuration directory every write lands in — the *first* entry of
/// the search path, and the only one this module ever modifies.
///
/// The search path itself is [`PamDirs`], which every engine function takes as
/// a parameter so tests drive the whole writer against a tempdir,
/// unprivileged.
pub const PAM_DIR: &str = "/etc/pam.d";

/// The line this command adds and removes. Matching is by module name rather
/// than by these bytes — see [`is_facelock_pam_line`].
pub const PAM_LINE: &str = "auth      sufficient pam_facelock.so";

/// Where the PAM module may be installed, in probe order — first hit wins.
///
/// A list rather than one path because this repository **ships the packaging
/// that puts it elsewhere**: `dist/facelock.spec` installs to
/// `%{_libdir}/security/`, which is `/usr/lib64/security` on x86-64 Fedora and
/// RHEL, so on the distribution whose spec file is in this tree a single
/// hardcoded `/lib/security` made `pam add` refuse with "module not installed"
/// while the module was installed (#170).
///
/// `/lib/security` stays first so the answer on usrmerged Arch — where it is
/// the same file as `/usr/lib/security/pam_facelock.so` — does not change.
/// There is deliberately **no** Debian multiarch triple
/// (`/usr/lib/<triple>/security`): Debian's idiomatic path is
/// `pam-auth-update` rather than a hand-inserted line, which this command does
/// not do, so a probe path for it would suggest support that is not there.
///
/// This is the one list. `crate::health` reads it rather than keeping a second
/// copy, because two lists that drift is the bug class this closes.
pub const PAM_MODULE_PATHS: &[&str] = &[
    "/lib/security/pam_facelock.so",
    "/usr/lib/security/pam_facelock.so",
    "/usr/lib64/security/pam_facelock.so",
];

/// Services whose stacks can lock the machine, or the network, out. Adding
/// face auth here needs `--allow-sensitive` (`--yes` on the `setup` alias);
/// **removing** it needs no gate on sensitivity, because removal can only take
/// away a way to authenticate — the confinement rules still apply to it, and
/// to `status`, like any other verb.
///
/// Six of the eight are *shared stacks* — files other service files `include`,
/// so an edit here reaches `su`, `passwd`, `chsh` and the display manager at
/// once — and which name a distribution uses is the only difference between
/// them: `system-auth` and `password-auth` on Fedora/RHEL and Arch,
/// `system-auth-ac` and `password-auth-ac` where RHEL's older `authconfig`
/// wrote the real file and left the unsuffixed name pointing at it,
/// `common-auth` on Debian and Ubuntu, `system-login` on Arch. Gating only the
/// Arch spelling made the gate a coin flip on the operator's distro. `login`
/// (TTY login) and `sshd` (the network path) are the two that lock you out of
/// a specific door rather than all of them.
///
/// The list is matched against the name as typed **and** against the file that
/// name resolves to ([`gate_sensitive`]), because a symlink inside the
/// directory is otherwise an ungated name for a gated file — which is exactly
/// the shape `authconfig` leaves behind.
///
/// Every name here is also in each packager's `FACELOCK_PAM_SERVICES`, pinned
/// by a test, so an uninstall strips a line this gate let through.
pub const SENSITIVE_SERVICES: &[&str] = &[
    "common-auth",
    "login",
    "password-auth",
    "password-auth-ac",
    "sshd",
    "system-auth",
    "system-auth-ac",
    "system-login",
];

/// The service a bare `pam add` / `setup --pam` means.
pub const DEFAULT_PAM_SERVICE: &str = "sudo";

/// Suffix of the copy taken before any edit. Never deleted by this module.
const BACKUP_SUFFIX: &str = ".facelock-backup";

/// The `--json` `error` value for a service name confinement rejected.
///
/// A fixed C-locale string, deliberately **not** the rendered
/// [`PamMessage::PamInvalidServiceName`]: that goes through
/// [`crate::message::Message::localized`], and `--json` output must never
/// localize (see the "What must NOT come through here" list in
/// `crate::message`). `message::init` sets `LC_MESSAGES` from the environment,
/// so routing the localized text here would make a documented machine field
/// change with the operator's locale. The human still gets the localized
/// message, on stderr.
const INVALID_SERVICE_NAME: &str = "invalid service name";

/// The `--json` `error` value for a service file that is a symlink leading out
/// of the directory it was found in. Fixed C-locale text for the same reason
/// as [`INVALID_SERVICE_NAME`]; the human gets the localized message, which
/// names the target, on stderr.
///
/// **It is a fixed name for the class, not a rendering of the directory that
/// was violated.** It spells [`PAM_DIR`] because that is the directory the
/// case is about in practice and because a documented constant may not vary
/// with the machine — an entry in a vendor directory pointing outside *that*
/// directory reports this same token, and the human message
/// ([`Rejected::message`], which carries the base) is what names the real
/// one.
const SYMLINKED_OUT_OF_DIR: &str = "symlinked outside /etc/pam.d";

/// The `--json` `error` value for a service file with more than one name.
/// Fixed C-locale text, as above.
const HARD_LINKED: &str = "hard-linked service file";

// ---------------------------------------------------------------------------
// The search path
// ---------------------------------------------------------------------------

/// Where a service name is looked up, in order, and where a write may land.
///
/// A newtype rather than a bare slice for one reason: **the first entry is the
/// override directory**, the only one this module writes to, and that is an
/// invariant worth a constructor. An empty list would leave no directory to
/// write to at all, so [`PamDirs::new`] substitutes the defaults for one —
/// `config_dirs = []` is a mistake, not a request to disable the writer.
///
/// Every engine function takes it as a parameter, which is what lets the whole
/// writer be driven against a tempdir pair by an unprivileged test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PamDirs {
    dirs: Vec<PathBuf>,
}

impl PamDirs {
    /// The search path, or [`PamConfig`]'s default when the list cannot be
    /// used.
    ///
    /// Three ways it cannot be. **Empty** is a mistake rather than a request to
    /// disable the writer — there would be no directory left to write to. **A
    /// first entry that is also a later entry** (spelled twice, or reached
    /// through a symlink) collapses the override layer onto a read-only one,
    /// which is how "never write to a vendor directory" would stop being true
    /// without anyone editing this file. **Any non-absolute entry** poisons
    /// the whole list: a relative first
    /// entry would resolve the write target against the invoking shell's
    /// working directory, so `cd /tmp && sudo facelock pam add` would edit
    /// `/tmp/<dir>/sudo` and report it as though it were the real thing. Only
    /// root can write `/etc/facelock/config.toml`, so this is a mistake to
    /// catch rather than an attack to defend against, and catching it is the
    /// same policy a broken config gets: fall back to the default and say so.
    ///
    /// The whole list is rejected rather than the offending entry filtered
    /// out, because a list with a hole in it is not the search order anyone
    /// wrote down.
    ///
    /// [`PamConfig`]: facelock_core::config::PamConfig
    pub(crate) fn new(dirs: Vec<PathBuf>) -> Self {
        if dirs.is_empty() {
            return Self::default();
        }
        if let Some(relative) = dirs.iter().find(|dir| !dir.is_absolute()) {
            tracing::warn!(
                entry = %relative.display(),
                "ignoring [pam] config_dirs: every entry must be an absolute path"
            );
            return Self::default();
        }
        // The write directory may not *be* one of the read-only ones, however
        // it is spelled. `Origin::Local` is decided by comparing the current
        // base against the first entry, which is a comparison of paths, so
        // `["/etc/pam.d", "/etc/pam.d"]` — or a first entry that is a symlink
        // onto a later one — would make the vendor layer and the override
        // layer the same directory and quietly turn "never write to a vendor
        // directory" into a write to one. Canonicalized because that is the
        // question: two names for one directory are one directory.
        let canonical: Vec<PathBuf> = dirs
            .iter()
            .map(|dir| fs::canonicalize(dir).unwrap_or_else(|_| dir.clone()))
            .collect();
        if let Some(alias) = canonical[1..].iter().find(|dir| **dir == canonical[0]) {
            tracing::warn!(
                first = %dirs[0].display(),
                alias = %alias.display(),
                "ignoring [pam] config_dirs: the override directory is also a search directory"
            );
            return Self::default();
        }
        PamDirs { dirs }
    }

    /// The machine's search path: `[pam] config_dirs` when the config file
    /// parses, the defaults when it does not.
    ///
    /// This is the module's own read of the config, and the exception is
    /// deliberate: `main` dispatches `pam` *ahead* of the process-wide parse
    /// precisely so a missing or broken config cannot be the thing that stops
    /// an operator editing `/etc/pam.d` (see the dispatch comment in
    /// `main.rs`). A config that does not parse therefore yields the default
    /// list rather than an error — the same policy `is-enrolled` has for its
    /// unprivileged path. The path itself is resolved by
    /// `facelock_core::paths::config_path`, which ignores `FACELOCK_CONFIG` in
    /// a privileged process, so the environment cannot redirect where a root
    /// `pam add` writes.
    pub(crate) fn system() -> Self {
        crate::resolved::ConfigLoad::read()
            .config()
            .map_or_else(Self::default, Self::from_config)
    }

    /// The search path a config that has *already been parsed* names.
    ///
    /// `facelock status` holds a [`crate::resolved::ConfigLoad`] before it
    /// probes anything, so it reads `[pam] config_dirs` from that rather than
    /// opening the file a second time through [`PamDirs::system`] — which is
    /// also what keeps `health.rs` out of the canonical-config-read pin in
    /// `resolved.rs`.
    pub(crate) fn from_config(config: &facelock_core::Config) -> Self {
        Self::new(
            config
                .pam
                .config_dirs
                .iter()
                .map(PathBuf::from)
                .collect::<Vec<PathBuf>>(),
        )
    }

    /// The directory writes land in: the first entry.
    fn overrides(&self) -> &Path {
        // `new` and `default` both guarantee a non-empty list; the fallback
        // keeps the guarantee total rather than trusting it.
        self.dirs.first().map_or(Path::new(PAM_DIR), |dir| dir)
    }

    /// The directories, in search order.
    fn iter(&self) -> impl Iterator<Item = &Path> {
        self.dirs.iter().map(|dir| dir.as_path())
    }

    /// The whole search path for a message that names where it looked.
    pub(crate) fn display(&self) -> String {
        self.dirs
            .iter()
            .map(|dir| dir.display().to_string())
            .collect::<Vec<String>>()
            .join(", ")
    }
}

/// A one-directory search path: what every test that predates vendor
/// resolution means by "the PAM directory", and still the shape of a machine
/// with no vendor `pam.d`. Shared with `setup.rs`'s tests, which drive the
/// wizard's step 9 against a tempdir the same way.
#[cfg(test)]
pub(crate) fn only(dir: impl AsRef<Path>) -> PamDirs {
    PamDirs::from(dir.as_ref())
}

impl Default for PamDirs {
    fn default() -> Self {
        PamDirs {
            dirs: facelock_core::config::PamConfig::default()
                .config_dirs
                .into_iter()
                .map(PathBuf::from)
                .collect(),
        }
    }
}

/// One directory, which is what a test — and the setup wizard's tempdir-driven
/// step 9 — means by "the PAM directory".
impl From<&Path> for PamDirs {
    fn from(dir: &Path) -> Self {
        PamDirs::new(vec![dir.to_path_buf()])
    }
}

// ---------------------------------------------------------------------------
// Exit codes
// ---------------------------------------------------------------------------

/// `pam status`: every requested service carries the facelock line.
const STATUS_PRESENT: i32 = 0;
/// `pam status`: a requested service file exists without the line.
const STATUS_MISSING: i32 = 1;
/// `pam status`: a requested service file is absent, unreadable, or misnamed.
const STATUS_ERROR: i32 = 2;

/// `pam add` / `pam remove`: every service reached its requested state.
const WRITE_OK: i32 = 0;
/// `pam add` / `pam remove`: at least one service could not be written.
const WRITE_FAILED: i32 = 1;

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

/// Which verb ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PamAction {
    Add,
    Remove,
    /// The default, so that a [`PamRequest`] built field by field reads and
    /// never writes until something names a verb on purpose.
    #[default]
    Status,
}

impl PamAction {
    /// The word this action reports as `"command"` in `--json`. Part of the
    /// output contract, so it is spelled here once rather than at the call
    /// site.
    fn word(self) -> &'static str {
        match self {
            PamAction::Add => "add",
            PamAction::Remove => "remove",
            PamAction::Status => "status",
        }
    }
}

/// A resolved `facelock pam` invocation.
///
/// Plain data, like [`crate::commands::setup::SetupArgs`]: the clap types stay
/// in the binary (`args.rs`), so this is what the library sees and what tests
/// construct. Fields that do not apply to an action are ignored by it —
/// `allow_sensitive` by `remove` and `status`, `dry_run` by `status`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PamRequest {
    pub action: PamAction,
    /// Requested services, in the order given. Empty means
    /// [`DEFAULT_PAM_SERVICE`].
    pub services: Vec<String>,
    /// `status` only: report every service on the search path that carries the
    /// facelock line instead of the named ones.
    ///
    /// A flag rather than a new meaning for a bare `pam status`, because that
    /// invocation's exit code is 0/1/2 *about `sudo`* today and an integrator
    /// may already branch on it; making it 0/1/2 about whatever happens to be
    /// on the machine would change an answer without changing a command line.
    /// It is mutually exclusive with `services` — enumerating and naming are
    /// two different questions, and a request that did both would have to pick
    /// one silently.
    pub all: bool,
    /// Suppress prompts. **Never** unlocks [`SENSITIVE_SERVICES`].
    ///
    /// `--json` implies it (the conversion in the binary's `args.rs` sets it):
    /// a prompt on stderr in front of a document a `jq` pipeline is waiting
    /// for is a hang, and the machine caller is by definition unattended.
    pub no_confirm: bool,
    /// Accept the risk of editing a [`SENSITIVE_SERVICES`] entry.
    pub allow_sensitive: bool,
    /// Treat a missing service file as success rather than an error.
    pub if_present: bool,
    /// Report the resolved plan and write nothing.
    pub dry_run: bool,
    /// Emit one JSON document on stdout instead of human text.
    pub json: bool,
}

/// Which write is running. [`PamAction::Status`] is not a write, and this is
/// where that stops being something every function downstream has to re-check.
///
/// Past the one conversion in [`WriteAction::of`], a plan, an apply and a
/// report cannot be handed a request that only asked to read — so the dead
/// arms that used to answer "what does an add do with a status?" are not
/// omissions here, they are unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteAction {
    Add,
    Remove,
}

impl WriteAction {
    /// The write this action asks for, or `None` for `status`.
    fn of(action: PamAction) -> Option<Self> {
        match action {
            PamAction::Add => Some(WriteAction::Add),
            PamAction::Remove => Some(WriteAction::Remove),
            PamAction::Status => None,
        }
    }
}

/// One write, as everything the two phases need that is not the target list.
///
/// It exists so [`plan_writes`] and [`apply_all`] take *one* value describing
/// the run instead of the same facts spread over three parameters in two
/// orders. That spread was the live defect: `install_for_setup(services,
/// no_confirm, allow_sensitive)` and `install_one_in(base, service,
/// allow_sensitive, no_confirm)` both type-check when swapped, and the swap
/// silently unlocks the sensitive-service gate. Named fields, one construction
/// per entry point.
struct WriteRequest<'a> {
    action: WriteAction,
    request: &'a PamRequest,
    /// The flag that unlocks [`SENSITIVE_SERVICES`] **on this surface**:
    /// `--allow-sensitive` on the verb, `--yes` on the `setup --pam` alias,
    /// which keeps its combined meaning. The refusal has to name the flag the
    /// caller can actually reach.
    remedy: &'a str,
}

// ---------------------------------------------------------------------------
// Outcomes — the `--json` vocabulary
// ---------------------------------------------------------------------------

/// What happened to one service.
///
/// The `action` string of a `--json` service object. **These words are a
/// stability contract**: existing words keep their meaning and new ones may be
/// added, so a consumer must tolerate a word it does not know rather than
/// treat it as an error. They are spelled in one place on purpose — the whole
/// vocabulary is visible in [`Outcome::word`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    /// `add`: the line was written (or, under `--dry-run`, would be).
    Installed,
    /// `add`: the service resolved only in a vendor directory, so an
    /// `/etc/pam.d` copy carrying the line was created from it (or would be).
    ///
    /// A new word rather than `installed`, because what happened to the
    /// machine is different: a file that did not exist now shadows a
    /// package-owned one and will not track its updates.
    Overridden,
    /// `remove`: the line was deleted (or would be).
    Removed,
    /// The service resolves only in a vendor directory and nothing was
    /// written. What `remove` reports (there is nothing of facelock's to take
    /// out of a file it never wrote) and what `status` reports for a service
    /// that has no `/etc/pam.d` copy and no facelock line.
    ///
    /// **Not `absent`.** The service file exists; it is the local override
    /// that does not, and `add` would create one. Overloading `absent` would
    /// change the meaning of a word integrators already branch on.
    VendorOnly,
    /// The service was already in the requested state.
    Unchanged,
    /// The service file does not exist.
    ///
    /// It is a success on `add` and `remove` — the verb asked for a state the
    /// file cannot be in, and `--if-present` said that is fine — and on
    /// `status` it is an error (exit 2) unless `--if-present` was given there
    /// too, because "is this service configured?" has no answer for a service
    /// that is not installed.
    Absent,
    /// The operator answered no at the per-file confirmation.
    Declined,
    /// The write failed. Carries the error for the `"error"` field.
    ///
    /// That field is a diagnostic, not a contract: `Failed` and `Unknown` both
    /// interpolate an `io::Error`, whose text comes from the C library's
    /// `strerror` and therefore follows `LC_MESSAGES` like any other OS
    /// string. A consumer branches on `action`; it must not match on `error`.
    Failed(String),
    /// `status`: the file exists and carries a facelock line.
    Present,
    /// `status`: the file exists and carries no facelock line.
    Missing,
    /// `status`: the file exists but could not be read.
    Unknown(String),
}

impl Outcome {
    fn word(&self) -> &'static str {
        match self {
            Outcome::Installed => "installed",
            Outcome::Overridden => "overridden",
            Outcome::VendorOnly => "vendor-only",
            Outcome::Removed => "removed",
            Outcome::Unchanged => "unchanged",
            Outcome::Absent => "absent",
            Outcome::Declined => "declined",
            Outcome::Failed(_) => "failed",
            Outcome::Present => "present",
            Outcome::Missing => "missing",
            Outcome::Unknown(_) => "unknown",
        }
    }

    /// The `"error"` field, when this outcome carries one.
    fn error(&self) -> Option<&str> {
        match self {
            Outcome::Failed(error) | Outcome::Unknown(error) => Some(error),
            _ => None,
        }
    }
}

/// One row of the report.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceReport {
    service: String,
    /// The file this row is about, or `None` when the *name* was rejected and
    /// no path was ever resolved. Reporting `/etc/pam.d/../escape` there named
    /// a path nothing went near, which reads as a path that was acted on.
    path: Option<String>,
    outcome: Outcome,
    /// The `.facelock-backup` path, when one exists on disk after the
    /// operation. `null` otherwise — including for every `--dry-run` service,
    /// which writes no backup.
    backup: Option<String>,
    /// The vendor file this row's `/etc` entry hides, when it hides one.
    ///
    /// The fact `status` needs to say "configured, and this copy will not
    /// track the package's updates" — and the reason it is on the row rather
    /// than derived by the reporter is that [`Target::locate`] is where the
    /// search path is walked, so anywhere else would be a second walk that
    /// could disagree with the first. `None` on every machine with no vendor
    /// directory, which is why the `--json` key is omitted rather than
    /// emitted as `null`.
    shadows: Option<String>,
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/// What a service is planned to become.
///
/// [`Plan::Rewrite`] carries the bytes it was derived from, so "there is an
/// edit to make" and "here is what it is being made from" cannot disagree.
/// **Which** edit is deliberately not recorded: the verb is
/// [`WriteRequest::action`], and a plan that named one too was a second copy
/// of it — the copy each `apply` function then had to check against its own,
/// with an unreachable "this plan is for the other verb" failure on the end of
/// both. Nor is the insertion point: it is a scan of `content`
/// ([`insertion_hint`]), and memoizing it made a third fact that could go
/// stale against the bytes beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Plan {
    /// The file needs rewriting, from these bytes.
    Rewrite { content: String },
    /// The service resolved only in a vendor directory and `add` will create
    /// the local override from these bytes — the vendor file's, which the copy
    /// carries the facelock line and a provenance header on top of.
    ///
    /// A plan of its own rather than a flag beside [`Plan::Rewrite`]: the two
    /// write different files and print different things, and which one is
    /// happening is decided once, in [`plan_writes`], rather than re-derived
    /// by each applier from the target's origin.
    Override { content: String },
    /// The service resolves only in a vendor directory and this verb does not
    /// write there. `remove`'s answer, and a no-op.
    VendorOnly,
    /// Already in the requested state.
    NoChange,
    /// No service file, and `--if-present` said that is fine.
    Absent,
}

/// Which directory of the search path a name was found in.
///
/// The one fact that decides whether a write is an edit or a copy, kept beside
/// the path rather than re-derived by comparing prefixes at each use site.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Origin {
    /// Found in the override directory, so the file is edited in place. Every
    /// service on a machine with no vendor `pam.d` is this.
    Local,
    /// Found only in a vendor directory. Carries the override path a copy
    /// would be written to, since that — not [`Target::path`] — is where any
    /// write for this service lands.
    Vendor { override_path: PathBuf },
    /// Found in no directory at all. Carries every path tried, because the
    /// refusal has to name them: "not found in `/etc/pam.d`" is a misleading
    /// half-answer once there is more than one place to look.
    Nowhere { tried: Vec<PathBuf> },
}

/// A validated service: which file the name resolves to, where it was found,
/// where its backup goes, and what is planned for it.
///
/// [`Target::locate`] is the only place a service name becomes a path — the
/// join, the confinement rule, the symlink rule and the search order are
/// applied there and nowhere else — so `status` cannot answer about a
/// different file than `add` would write.
#[derive(Debug, Clone)]
struct Target {
    service: String,
    /// The file the name resolved to: the override file when one exists, the
    /// vendor file when only that does, and the path the override *would* have
    /// when nothing exists anywhere.
    path: PathBuf,
    origin: Origin,
    /// The vendor file an [`Origin::Local`] hit hides, if it hides one.
    ///
    /// Not folded into [`Origin`]: `Local` is the fact that decides *how to
    /// write* — in place, never a copy — and that decision is the same whether
    /// or not a package also ships the name. What shadowing decides is what to
    /// *say*, and only `status` says it.
    shadowed: Option<PathBuf>,
    backup: PathBuf,
    plan: Plan,
}

impl Target {
    /// Resolve one service against `dirs`, or say why it cannot be.
    ///
    /// The plan starts as [`Plan::NoChange`], which is the truth for a caller
    /// that is not going to write — `status` uses this and leaves it alone.
    /// [`plan_writes`] fills it in.
    fn locate(dirs: &PamDirs, service: &str) -> Result<Self, Rejected> {
        if confined(service).is_err() {
            return Err(Rejected::Name);
        }
        let (path, origin) = resolve_service_path(dirs, service)?;
        Ok(Target {
            service: service.to_string(),
            backup: backup_path(write_target(&path, &origin)),
            shadowed: shadowed_vendor(dirs, service, &origin),
            path,
            origin,
            plan: Plan::NoChange,
        })
    }

    /// The file a write for this target lands in: the resolved file for an
    /// in-place edit, the override path for a vendor copy. Never a vendor
    /// directory.
    fn write_path(&self) -> &Path {
        write_target(&self.path, &self.origin)
    }

    fn path_string(&self) -> String {
        self.path.display().to_string()
    }

    /// The `path` field of this target's report row: the file the operation
    /// acted on. That is the resolved file for every plan but
    /// [`Plan::Override`], whose subject is the override it creates rather
    /// than the vendor file it read.
    fn reported_path(&self) -> String {
        match self.plan {
            Plan::Override { .. } => self.write_path().display().to_string(),
            _ => self.path_string(),
        }
    }

    fn backup_string(&self) -> String {
        self.backup.display().to_string()
    }

    /// Whether the service file exists anywhere on the search path.
    fn exists(&self) -> bool {
        !matches!(self.origin, Origin::Nowhere { .. })
    }

    /// Every path the resolver looked at, for the not-found refusal. A service
    /// that *was* found and then vanished — deleted between the resolve and
    /// the read — reports the one path it was found at, which is the only one
    /// that would tell the operator anything.
    fn tried_paths(&self) -> String {
        match &self.origin {
            Origin::Nowhere { tried } => tried
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<String>>()
                .join(", "),
            Origin::Local | Origin::Vendor { .. } => self.path_string(),
        }
    }

    /// The backup path if it exists on disk, for the report's `backup` field.
    fn existing_backup(&self) -> Option<String> {
        existing_backup_for(self.write_path())
    }

    /// The row's `shadows` field: the vendor file this entry hides.
    fn shadows_string(&self) -> Option<String> {
        self.shadowed
            .as_ref()
            .map(|vendor| vendor.display().to_string())
    }
}

/// The package-owned file an `/etc` entry hides, if the same name also exists
/// further down the search path.
///
/// Only an [`Origin::Local`] hit can shadow anything: `Vendor` *is* the
/// package's file, and `Nowhere` is no file at all. The probe is one `lstat`
/// per remaining directory and it deliberately does **not** look inside the
/// files — an entry that exists is enough to hide the name from Linux-PAM,
/// whatever it contains.
fn shadowed_vendor(dirs: &PamDirs, service: &str, origin: &Origin) -> Option<PathBuf> {
    if !matches!(origin, Origin::Local) {
        return None;
    }
    dirs.iter()
        .skip(1)
        .map(|base| base.join(service))
        .find(|path| fs::symlink_metadata(path).is_ok())
}

/// Where a write lands, as a free function so [`Target::locate`] can derive the
/// backup path before the `Target` exists.
fn write_target<'a>(path: &'a Path, origin: &'a Origin) -> &'a Path {
    match origin {
        Origin::Vendor { override_path } => override_path,
        Origin::Local | Origin::Nowhere { .. } => path,
    }
}

/// Why a service could not be resolved.
///
/// Both phases reject the same three things and report them differently —
/// [`plan_writes`] as an `Err` that stops the whole run, [`status_reports`] as
/// an `unknown` row beside the services it could answer about — so the reason
/// is a value here rather than a rendered message at each site. Every piece
/// that differs between them (the fixed machine reason, the localized text,
/// whether a `path` was resolved, whether a backup is worth probing for) hangs
/// off it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Rejected {
    /// The name is not one path component, so nothing was resolved at all.
    Name,
    /// The entry is a symlink whose target is outside the directory the entry
    /// itself was found in, or one that cannot be resolved to prove otherwise.
    ///
    /// `base` is that directory rather than the whole search path: with
    /// several directories the rule is **per directory**, so
    /// `/etc/pam.d/polkit-1 -> /usr/lib/pam.d/polkit-1` is out of base and
    /// refused, even though the target sits in a directory facelock would have
    /// searched next. Carrying it here is what lets the refusal name the
    /// directory that was actually violated.
    OutOfBase {
        link: PathBuf,
        target: PathBuf,
        base: PathBuf,
    },
    /// The entry is a regular file reachable by more than one name. Which
    /// other names is exactly what a link count does not say, so the edit
    /// cannot be shown to stay inside the directory.
    HardLinked { link: PathBuf, links: u64 },
}

impl Rejected {
    /// The `--json` `error` value: fixed C-locale text, never the localized
    /// message. See [`INVALID_SERVICE_NAME`].
    fn reason(&self) -> &'static str {
        match self {
            Rejected::Name => INVALID_SERVICE_NAME,
            Rejected::OutOfBase { .. } => SYMLINKED_OUT_OF_DIR,
            Rejected::HardLinked { .. } => HARD_LINKED,
        }
    }

    /// The localized refusal, for a human on stderr.
    fn message(&self, service: &str) -> PamMessage {
        match self {
            Rejected::Name => PamMessage::PamInvalidServiceName {
                service: service.to_string(),
            },
            Rejected::OutOfBase { link, target, base } => PamMessage::PamServiceSymlinkedOutside {
                path: link.display().to_string(),
                target: target.display().to_string(),
                dir: base.display().to_string(),
            },
            Rejected::HardLinked { link, links } => PamMessage::PamServiceHardLinked {
                path: link.display().to_string(),
                links: links.to_string(),
            },
        }
    }

    /// The entry this is about, when there is one: a real, confined path that
    /// was `lstat`ed. `None` for a rejected *name*, where nothing was resolved.
    fn link(&self) -> Option<&Path> {
        match self {
            Rejected::Name => None,
            Rejected::OutOfBase { link, .. } | Rejected::HardLinked { link, .. } => {
                Some(link.as_path())
            }
        }
    }

    /// The row's `path`. `None` for a rejected name: naming the path it
    /// *would* have resolved to reads as one that was acted on.
    fn path(&self) -> Option<String> {
        Some(self.link()?.display().to_string())
    }

    /// The row's `backup`. Probed for a rejected entry, because a facelock
    /// version that wrote through it left one there and it is what a recovery
    /// needs; not probed for a rejected name, which would `stat`
    /// `/etc/pam.d/../escape.facelock-backup` for a name the whole point of
    /// [`confined`] is to not act on.
    fn backup(&self) -> Option<String> {
        existing_backup_for(self.link()?)
    }
}

/// The `.facelock-backup` beside `path`, if one is on disk. Both report paths
/// derive the field the same way, so they cannot disagree about what `backup`
/// means.
fn existing_backup_for(path: &Path) -> Option<String> {
    let backup = backup_path(path);
    backup.exists().then(|| backup.display().to_string())
}

/// A PAM service name is **one path component** under [`PAM_DIR`].
///
/// Rejected before any I/O, on `add`, `remove` and `status` alike: empty,
/// containing `/`, equal to `.` or `..`, or carrying an interior NUL. This is
/// the check the old writer did not have — `pam_install_in` did a bare
/// `base.join(service)`, and an absolute `service` *replaces* `base`, so
/// `--service /etc/shadow` resolved to `/etc/shadow`; `pam_remove_in` stripped
/// a leading `/` and nothing else, which left `..` intact.
fn confined(service: &str) -> anyhow::Result<()> {
    let mut components = Path::new(service).components();
    // A trailing slash is dropped by `components`, so the round-trip
    // comparison is what rejects `sudo/` as well as `a/b` and `/etc/shadow`.
    let single_component = matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(name)), None) if name == OsStr::new(service)
    );
    if single_component && !service.contains('\0') {
        return Ok(());
    }
    Err(fail(PamMessage::PamInvalidServiceName {
        service: service.to_string(),
    }))
}

/// The file a validated `service` names on the search path, and which
/// directory it came from — or the reason it cannot be written through.
///
/// **First hit wins, and a hit that is refused is still a hit.** Each
/// directory is asked in turn; the first one holding an entry for the name
/// answers, whether the answer is a path or a refusal. Falling through to the
/// next directory after a refusal would let a vendor file silently take over
/// from an `/etc` entry this declined to follow, which is the opposite of what
/// the refusal is for.
///
/// The per-entry rules below are unchanged from the single-directory writer,
/// with one restatement forced by there being several: a symlink must resolve
/// under **the directory the entry was found in**, not under some union of
/// them. `/etc/pam.d/polkit-1 -> /usr/lib/pam.d/polkit-1` is therefore
/// [`Rejected::OutOfBase`] and refused, even though the target is in a
/// directory the search would have reached next: it is a link out of `/etc`,
/// and following it would put an edit in a package-owned file.
///
/// `confined` checks the *name*; this checks what the filesystem does with it,
/// and there are two ways for a well-formed name to reach a file this cannot
/// account for.
///
/// **Symlinks.** `read_to_string` follows one, and so does every write that is
/// not a `rename`,
/// so on an authselect system `/etc/pam.d/system-auth -> /etc/authselect/…`
/// would be edited in place — a file authselect regenerates, with the backup
/// left beside the link rather than beside the file that changed. A link that
/// stays under `base` is followed on purpose: `base.join(service)` and its
/// target are the same file, and the operator asked about that file; the
/// resolved path is what gets read, written and backed up, so the backup lands
/// beside the real file. A link that cannot be resolved at all — dangling,
/// looping, or any other resolve error — is a fault too: the rule is "prove it
/// stays inside", and an unresolvable link proves nothing. That is why
/// `--if-present` does not forgive one; absence is a fact, and this is the
/// absence of an answer.
///
/// **Hard links.** A symlink can be followed to somewhere and checked. A
/// second *hard* link cannot: `nlink > 1` says another name for this inode
/// exists and says nothing about where, so an edit here silently changes a
/// file this cannot name — the confinement rule's whole subject. The atomic
/// replace does not retire the rule, as this comment once said it would: a
/// rename writes a *new* inode, so it does not corrupt the other name, it
/// silently leaves it holding the old content — an operator who asked for one
/// file to carry the line gets one of its names carrying it and the rest not,
/// which is a worse answer than a refusal. A `/etc` that has been through a
/// deduplicating backup or `jdupes -L` can trip this without any adversary
/// involved, so the message says how to break the link.
fn resolve_service_path(dirs: &PamDirs, service: &str) -> Result<(PathBuf, Origin), Rejected> {
    let overrides = dirs.overrides();
    let mut tried = Vec::new();

    for base in dirs.iter() {
        let entry = base.join(service);
        let Some(resolved) = resolve_in(base, &entry) else {
            tried.push(entry);
            continue;
        };
        let path = resolved?;
        let origin = if base == overrides {
            Origin::Local
        } else {
            Origin::Vendor {
                override_path: overrides.join(service),
            }
        };
        return Ok((path, origin));
    }

    // Nothing anywhere. The path is where an override would go, which is what
    // every message about a service that is not installed should name; `tried`
    // is what the not-found refusal lists.
    Ok((overrides.join(service), Origin::Nowhere { tried }))
}

/// One directory's answer for one entry: `None` when there is nothing there,
/// otherwise the file to act on or the reason not to.
fn resolve_in(base: &Path, entry: &Path) -> Option<Result<PathBuf, Rejected>> {
    let metadata = match fs::symlink_metadata(entry) {
        Ok(metadata) => metadata,
        // Nothing here. This is the *only* reason the search moves on: an
        // absence is a fact about the directory.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return None,
        // An entry that exists but cannot be examined — `EACCES` on a
        // hardened `/etc/pam.d`, `EIO` or `ESTALE` on a network mount — is not
        // an absence, and treating it as one turns an honest failure into a
        // confident wrong answer: the service would resolve to the *vendor*
        // copy and `status` would report `vendor-only` for a service the
        // override configures. So the search stops here and the entry is
        // returned unexamined; the read that follows reports the error, which
        // is what the single-directory writer did with the same input
        // (`status` → `unknown`, exit 2; `add` → the read error).
        Err(_) => return Some(Ok(entry.to_path_buf())),
    };

    if !metadata.file_type().is_symlink() {
        return Some(hard_link_checked(entry.to_path_buf()));
    }

    Some(match (fs::canonicalize(entry), fs::canonicalize(base)) {
        // The link stays inside the directory, so the *target* is the file
        // that will be read, written and backed up — and therefore the file
        // the link-count rule is about. Checking only the entry would let
        // `alias -> real` reach a multiply-named inode under a name that
        // looks single, which is the same hole the sensitive gate's second
        // call exists to close.
        (Ok(target), Ok(root)) if target.starts_with(&root) => hard_link_checked(target),
        (Ok(target), _) => Err(Rejected::OutOfBase {
            link: entry.to_path_buf(),
            target,
            base: base.to_path_buf(),
        }),
        (Err(_), _) => Err(Rejected::OutOfBase {
            target: fs::read_link(entry).unwrap_or_else(|_| entry.to_path_buf()),
            link: entry.to_path_buf(),
            base: base.to_path_buf(),
        }),
    })
}

/// `path`, or the refusal if the file it names has more than one name.
///
/// One implementation for both ways a name reaches a file — the entry itself
/// and the target of an in-directory symlink — because the rule is about the
/// *inode*, and under an atomic replace a second name is not a theoretical
/// concern: `rename` writes a new inode, so an edit made through one name
/// leaves every other name holding the old content. A `remove` that reported
/// `removed` while a hard-linked `password-auth-ac` kept the facelock line
/// would be a fail-open on the shared auth stack, reported as success.
///
/// A path this cannot `stat` is passed through: the read that follows reports
/// the error, which is the same answer every other unexaminable entry gets.
fn hard_link_checked(path: PathBuf) -> Result<PathBuf, Rejected> {
    use std::os::unix::fs::MetadataExt;

    let Ok(metadata) = fs::metadata(&path) else {
        return Ok(path);
    };
    // `is_file` matters: a directory's link count is its subdirectory count,
    // and a directory where a service file should be is a read error reported
    // as one, not a link fault.
    if metadata.is_file() && metadata.nlink() > 1 {
        return Err(Rejected::HardLinked {
            links: metadata.nlink(),
            link: path,
        });
    }
    Ok(path)
}

// ---------------------------------------------------------------------------
// Enumeration
// ---------------------------------------------------------------------------

/// What happened to one directory of the search path.
///
/// The distinction this type exists for is [`DirState::Unreadable`] against
/// [`DirState::Scanned`] with nothing in it: a directory that could not be
/// listed has told us **nothing**, and folding that into "no services here"
/// is how a broken lock stack and a healthy one came to render identically.
#[derive(Debug, Clone, PartialEq, Eq)]
enum DirState {
    /// Listed. Whatever it holds is in the scan's names.
    Scanned,
    /// Not there. A directory that does not exist demonstrably holds no
    /// service files, so this is a fact rather than the absence of one — and
    /// it is **not** an error: the default search path names a vendor
    /// directory many machines simply do not have, so treating its absence as
    /// unanswerable would make every one of them report exit 2 forever.
    Absent,
    /// There, and not listable — a permission, mount or I/O failure. The
    /// answer for this directory is unknown, so the scan's answer is
    /// incomplete and its exit code says so.
    Unreadable(String),
}

impl DirState {
    /// The word this state reports in `--json`.
    fn word(&self) -> &'static str {
        match self {
            DirState::Scanned => "scanned",
            DirState::Absent => "absent",
            DirState::Unreadable(_) => "unreadable",
        }
    }

    fn error(&self) -> Option<&str> {
        match self {
            DirState::Unreadable(error) => Some(error),
            DirState::Scanned | DirState::Absent => None,
        }
    }
}

/// One directory of the search path, and what came of listing it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryScan {
    path: PathBuf,
    state: DirState,
}

/// The result of walking the whole search path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Scan {
    /// Every service **name** worth reporting on, sorted and de-duplicated.
    /// Names, not paths: which file a name resolves to is [`Target::locate`]'s
    /// answer and must not be decided twice.
    names: Vec<String>,
    /// Every directory searched, in search order, whether or not it yielded
    /// anything. In the document so a reader can see what was looked at
    /// rather than infer it.
    directories: Vec<DirectoryScan>,
}

impl Scan {
    /// The directories that stop this scan being a complete answer.
    fn unreadable(&self) -> impl Iterator<Item = (&Path, &str)> {
        self.directories
            .iter()
            .filter_map(|dir| dir.state.error().map(|error| (dir.path.as_path(), error)))
    }

    /// The directories that produced an answer — listed, or proven not to
    /// exist. What "nothing is configured" may be said *about*: a directory
    /// this could not open supports no such claim.
    fn answered(&self) -> Vec<String> {
        self.directories
            .iter()
            .filter(|dir| dir.state.error().is_none())
            .map(|dir| dir.path.display().to_string())
            .collect()
    }
}

/// Names that live in a `pam.d` directory and are not services.
///
/// Every one of these can carry the facelock line — `sudo.facelock-backup` is
/// a byte copy of a configured file, and a `.pacsave` is the configuration a
/// removed package left behind — and none of them is a service Linux-PAM will
/// ever be asked for. Reporting them as configured services would be the
/// report being confidently wrong, which is the failure mode enumeration
/// exists to remove rather than add.
const NON_SERVICE_SUFFIXES: &[&str] = &[
    BACKUP_SUFFIX,
    ".pacnew",
    ".pacsave",
    ".pacorig",
    ".rpmnew",
    ".rpmsave",
    ".rpmorig",
    ".dpkg-old",
    ".dpkg-new",
    ".dpkg-dist",
    "~",
];

/// Whether a directory entry's name is worth resolving as a service.
///
/// Dotfiles are excluded as a class: this module's own in-flight temp file is
/// `.<service>.facelock-<pid>-<nanos>`, and nothing else that starts with a
/// dot is a service anyone authenticates against.
fn is_service_name(name: &str) -> bool {
    !name.starts_with('.')
        && !NON_SERVICE_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix))
        && confined(name).is_ok()
}

/// Whether this file is one the scan should report on: it carries the facelock
/// line, or it could not be read to find out.
///
/// The second half is the point. Omitting a file this could not read would
/// report "not configured" for a machine that is configured — the exact
/// confident wrongness enumeration is for — so an unreadable entry is carried
/// into the report, where [`status_reports`] turns it into an `unknown` row
/// with the errno and exit 2. A file that vanished between the listing and the
/// read is not carried: it is gone, which is an answer.
///
/// **Only a regular file is read, and the metadata that decides it is the
/// *followed* one.** `read_to_string` on a FIFO blocks until a writer appears,
/// which is forever on a `/etc/pam.d` nobody is writing to — and this scan is
/// what `facelock status` runs, so the command whose whole job is to report a
/// broken machine would hang on one. A socket or a device node is the same
/// class. The `is_dir` check at the call site cannot cover it: that one is
/// `lstat`, so a symlink to a directory or to a FIFO survives it. A
/// non-regular entry in a `pam.d` directory is not a service file under any
/// reading, so skipping it loses nothing.
///
/// **"Not a regular file" and "could not be examined" are different answers**,
/// and only the first is a skip. A `stat` that *fails* — a symlink into a
/// directory this may not traverse, a symlink loop, a dead network mount —
/// says nothing about what is there, so the entry falls through to the read,
/// which reports it. Treating a failed `stat` as "not a regular file" made an
/// entry the named form calls `unknown` vanish from `--all` entirely, which is
/// the same rule `resolve_in` already refuses to apply one layer down. It
/// cannot reintroduce the hang: the hang needs an `open` that blocks, and an
/// entry whose `stat` cannot resolve the path cannot `open` through it either.
fn worth_reporting(path: &Path) -> bool {
    match fs::metadata(path) {
        // Stat-ed, and it is not something a PAM stack could ever read.
        Ok(metadata) if !metadata.is_file() => return false,
        // Gone between the listing and now. Absence is an answer.
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        // A regular file, or an entry this could not examine. Both go to the
        // read, which distinguishes them.
        _ => {}
    }
    match fs::read_to_string(path) {
        Ok(content) => content.lines().any(is_facelock_pam_line),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

/// Walk the search path for every service that names `pam_facelock.so`.
///
/// Names are collected across **all** directories and resolved afterwards, so
/// a vendor file carrying the line puts its name in the report even when
/// `/etc/pam.d` shadows it — and the row then says `missing`, because the file
/// Linux-PAM actually reads has no line in it. Dropping the name instead would
/// hide precisely the machine an operator cannot otherwise explain.
fn scan_directories(dirs: &PamDirs) -> Scan {
    let mut names: Vec<String> = Vec::new();
    let mut directories = Vec::new();

    for base in dirs.iter() {
        let state = match fs::read_dir(base) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    // A subdirectory is not a service file. `file_type` here
                    // does not follow symlinks, so a link is kept and handed
                    // to `Target::locate`, which is what owns the rule about
                    // where a link may point.
                    if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                        continue;
                    }
                    // A name this cannot spell is a name it cannot resolve.
                    // `to_string_lossy` would substitute U+FFFD and hand
                    // `Target::locate` a name no file has, which reports a
                    // configured service as `absent` — a path that does not
                    // exist, presented as the answer. Skipped and logged
                    // instead: a PAM service name is looked up by a byte
                    // string PAM itself takes from a config file, and nothing
                    // that is not UTF-8 is a service this can act on.
                    let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                        tracing::warn!(
                            path = %entry.path().display(),
                            "skipping a PAM service file whose name is not valid UTF-8"
                        );
                        continue;
                    };
                    if !is_service_name(&name) || !worth_reporting(&entry.path()) {
                        continue;
                    }
                    if !names.contains(&name) {
                        names.push(name);
                    }
                }
                DirState::Scanned
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => DirState::Absent,
            Err(error) => DirState::Unreadable(error.to_string()),
        };
        directories.push(DirectoryScan {
            path: base.to_path_buf(),
            state,
        });
    }

    // Sorted so two runs on one machine print the same report: `read_dir`
    // yields whatever order the filesystem happens to hold.
    names.sort();
    Scan { names, directories }
}

/// One service that carries the facelock line, as `facelock status` sees it.
///
/// Lives here rather than in `crate::health` because it is this module's
/// answer: the scan, the resolution and the read all belong to the writer, and
/// a second implementation in the health probe is the drift this replaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredService {
    pub service: String,
    /// The file the name resolved to — the one Linux-PAM reads.
    pub path: String,
    /// The vendor file this `/etc` copy hides, when it hides one. A service
    /// configured this way will not track the package's updates.
    pub shadows: Option<String>,
}

/// A place the scan could not get an answer from: a directory it could not
/// list, or a service file it could not read.
///
/// Kept separate from the configured list rather than merged into it as a
/// falsy entry — "not checked" is not "not configured", and a report that
/// cannot tell them apart is the one this gap replaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotChecked {
    pub path: String,
    pub error: String,
}

/// What `facelock status` reports in one line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfiguredScan {
    pub services: Vec<ConfiguredService>,
    pub not_checked: Vec<NotChecked>,
}

/// Everything on this machine that carries the facelock line, for
/// `facelock status`'s summary.
///
/// **The same scan `pam status --all` runs**, down to the row builder, so the
/// two commands cannot disagree about one service. The sink is silent because
/// `status` renders a report and the writer's per-service lines interleaved
/// into it would be output from a probe, not from the renderer.
pub(crate) fn configured_scan(dirs: &PamDirs) -> ConfiguredScan {
    let sink = Sink::silent();
    let scan = scan_directories(dirs);
    let reports = status_reports(dirs, &scan.names, &sink);

    let services = reports
        .iter()
        .filter(|report| report.outcome == Outcome::Present)
        .map(|report| ConfiguredService {
            service: report.service.clone(),
            path: report.path.clone().unwrap_or_default(),
            shadows: report.shadows.clone(),
        })
        .collect();

    // Both kinds of "could not tell", in one list: a directory that would not
    // list and a service file that would not read are the same fact about the
    // report — part of it is missing — and the summary line has to be able to
    // say so without knowing which.
    let not_checked = scan
        .unreadable()
        .map(|(path, error)| NotChecked {
            path: path.display().to_string(),
            error: error.to_string(),
        })
        .chain(reports.iter().filter_map(|report| {
            match &report.outcome {
                Outcome::Unknown(error) => Some(NotChecked {
                    path: report
                        .path
                        .clone()
                        .unwrap_or_else(|| report.service.clone()),
                    error: error.clone(),
                }),
                _ => None,
            }
        }))
        .collect();

    ConfiguredScan {
        services,
        not_checked,
    }
}

/// Refuse a [`SENSITIVE_SERVICES`] entry unless the caller accepted the risk.
///
/// Called twice per service, on the name as typed and again on the file that
/// name resolved to: the gate protects the *file*, and a symlink
/// `alias -> system-auth` inside `/etc/pam.d` is a way to reach a gated file
/// under a name the first check waves through. Only `add` is gated —
/// see [`SENSITIVE_SERVICES`].
fn gate_sensitive(name: &str, write: &WriteRequest) -> anyhow::Result<()> {
    if write.action != WriteAction::Add
        || write.request.allow_sensitive
        || !SENSITIVE_SERVICES.contains(&name)
    {
        return Ok(());
    }
    Err(fail(PamMessage::PamSensitiveRefused {
        service: name.to_string(),
        remedy: write.remedy.to_string(),
    }))
}

/// The last component of a resolved path, for the gate to test. A path with no
/// final component cannot be a service file, and the empty string is in no
/// list, so it falls through to the read that reports it.
fn file_name_of(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Requested services, defaulted and de-duplicated, in the order given.
///
/// De-duplication is not cosmetic: `--service sudo --service sudo` would
/// otherwise emit two report rows for one file, the second of them
/// `unchanged` because the first had just written it.
fn requested_services(services: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for service in services {
        if !out.iter().any(|seen| seen == service) {
            out.push(service.clone());
        }
    }
    if out.is_empty() {
        out.push(DEFAULT_PAM_SERVICE.to_string());
    }
    out
}

/// Phase one: validate and read every requested service, or fail having
/// written nothing.
///
/// Every rejection here is an `Err`, not a report row, and the caller performs
/// no writes on `Err` — that is the whole point of the phase. Errors render on
/// stderr as text and never as a JSON document, the same contract
/// `is-enrolled` has for its unanswerable case.
///
/// The service list is resolved here rather than passed in: a caller that
/// handed in one list while the request named another had two lists to keep
/// in step, and `install_one_in` did exactly that — it acted on one service
/// while its request said "none, so `sudo`".
fn plan_writes(dirs: &PamDirs, write: &WriteRequest) -> anyhow::Result<Vec<Target>> {
    let services = requested_services(&write.request.services);
    let mut targets = Vec::with_capacity(services.len());

    for service in &services {
        // On the name as typed, before any I/O.
        gate_sensitive(service, write)?;

        let located = Target::locate(dirs, service).map_err(|why| fail(why.message(service)))?;
        // ...and again on the file the name reached — in whichever directory
        // that was. A link `alias -> system-auth` inside the directory is a
        // gated file behind an ungated name, and so is a vendor
        // `/usr/lib/pam.d/system-auth` reached under an ungated alias. The
        // gate is on the file.
        gate_sensitive(&file_name_of(&located.path), write)?;

        let display = located.path_string();

        let content = match fs::read_to_string(&located.path) {
            Ok(content) => Some(content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !write.request.if_present {
                    // Every path tried, not just the override directory's:
                    // "not found in /etc/pam.d" is a misleading half-answer on
                    // a machine that also has a vendor directory.
                    return Err(fail(PamMessage::PamFileNotFound {
                        paths: located.tried_paths(),
                    }));
                }
                None
            }
            // `--if-present` converts a missing file into a no-op and nothing
            // else: a permission or I/O failure stays fatal.
            Err(error) => {
                return Err(anyhow::Error::new(error).context(format!("failed to read {display}")));
            }
        };

        let plan = match (content, &located.origin) {
            (None, _) => Plan::Absent,
            // A service whose only copy is package-owned. `remove` has
            // nothing to do — it never wrote there — and says so rather than
            // reporting a file it did not touch as `unchanged`.
            (Some(_), Origin::Vendor { .. }) if write.action == WriteAction::Remove => {
                Plan::VendorOnly
            }
            // ...and `add` creates the local override instead of editing the
            // package's file, unless the vendor file already carries the line,
            // in which case there is nothing an override would add.
            (Some(content), Origin::Vendor { override_path }) => {
                if content.lines().any(is_facelock_pam_line) {
                    Plan::NoChange
                } else {
                    // Phase one, so the copy's destination is validated before
                    // anything is written — including under `--dry-run`, which
                    // is a preview of the real run and must not promise a write
                    // into a directory that cannot take one. The in-place edit
                    // has no equivalent check because its destination is the
                    // file it just read.
                    writable_override_dir(override_path)?;
                    Plan::Override { content }
                }
            }
            // The same question for both verbs — "does the line exist?" — and
            // opposite answers about whether that means work to do.
            (Some(content), Origin::Local | Origin::Nowhere { .. }) => {
                let present = content.lines().any(is_facelock_pam_line);
                if present == (write.action == WriteAction::Remove) {
                    Plan::Rewrite { content }
                } else {
                    Plan::NoChange
                }
            }
        };

        targets.push(Target { plan, ..located });
    }

    Ok(targets)
}

/// Refuse in phase one if the override a vendor-only service needs cannot be
/// created — the directory is missing, or not writable by this process.
///
/// `faccessat` with `AT_EACCESS` rather than a mode check: what matters is
/// whether *this* process may write there, which mode bits alone do not answer
/// (root ignores them, a read-only mount overrides them).
fn writable_override_dir(override_path: &Path) -> anyhow::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let dir = override_path.parent().unwrap_or(Path::new("/"));
    let refuse = |error: std::io::Error| {
        fail(PamMessage::PamOverrideDirUnwritable {
            dir: dir.display().to_string(),
            path: override_path.display().to_string(),
            error: error.to_string(),
        })
    };

    let c_dir = CString::new(dir.as_os_str().as_bytes()).map_err(|_| {
        refuse(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path contains embedded NUL",
        ))
    })?;
    // SAFETY: `c_dir` is a NUL-terminated C string that outlives the call, and
    // `faccessat` only reads it.
    let ok = unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            c_dir.as_ptr(),
            libc::W_OK | libc::X_OK,
            libc::AT_EACCESS,
        )
    } == 0;
    if ok {
        return Ok(());
    }
    Err(refuse(std::io::Error::last_os_error()))
}

fn backup_path(path: &Path) -> PathBuf {
    // Built by appending to the string rather than with `set_extension`, which
    // would replace a service name's existing suffix.
    PathBuf::from(format!("{}{BACKUP_SUFFIX}", path.display()))
}

/// Whether a PAM config line references pam_facelock, regardless of spacing.
///
/// Matches on the module name, not on [`PAM_LINE`]'s bytes, so a hand-edited
/// line with different spacing is still recognized — and a commented-out one
/// is not.
pub fn is_facelock_pam_line(line: &str) -> bool {
    let trimmed = line.trim();
    !trimmed.starts_with('#') && trimmed.contains("pam_facelock.so")
}

/// Whether a line begins a PAM `auth` rule, which is where the facelock line
/// has to go above.
fn has_auth_keyword(line: &str) -> bool {
    line.trim_start().starts_with("auth")
}

/// Where the line will land in `content`, as the message that says so.
///
/// Derived from the same scan [`with_line_inserted`] makes, at the two places
/// that report it — the preview and the dry-run row. Recording the answer on
/// the plan instead gave the preview a way to promise a placement the write
/// then contradicted.
fn insertion_hint(content: &str) -> PamMessage {
    if content.lines().any(has_auth_keyword) {
        PamMessage::PamInsertBeforeAuthHint
    } else {
        PamMessage::PamInsertAtTopHint
    }
}

/// Insert [`PAM_LINE`] above the first `auth` line, or at the very top if
/// there is none. Trailing-newline behavior of the original is preserved.
fn with_line_inserted(content: &str) -> String {
    let mut new_lines: Vec<String> = Vec::new();
    let mut inserted = false;

    for line in content.lines() {
        if !inserted && has_auth_keyword(line) {
            new_lines.push(PAM_LINE.to_string());
            inserted = true;
        }
        new_lines.push(line.to_string());
    }

    if !inserted {
        new_lines.insert(0, PAM_LINE.to_string());
    }

    let mut output = new_lines.join("\n");
    if content.ends_with('\n') {
        output.push('\n');
    }
    output
}

/// Drop every facelock line, preserving the original's trailing newline.
fn with_line_removed(content: &str) -> String {
    let mut output = content
        .lines()
        .filter(|line| !is_facelock_pam_line(line))
        .collect::<Vec<&str>>()
        .join("\n");
    if content.ends_with('\n') {
        output.push('\n');
    }
    output
}

/// The two comment lines a vendor copy carries, so the next reader knows the
/// file is a local override and what it was forked from.
///
/// Above everything, including the facelock line: it is provenance for the
/// whole file, not for the line. `is_facelock_pam_line` skips comments, so it
/// never affects what `remove` takes out or what `status` sees.
fn provenance_header(vendor: &Path) -> String {
    format!(
        "# Copied from {} by facelock {} on {}.\n\
         # This local override shadows the vendor file and will not track vendor updates.\n",
        vendor.display(),
        env!("CARGO_PKG_VERSION"),
        chrono::Local::now().format("%Y-%m-%d"),
    )
}

// ---------------------------------------------------------------------------
// The atomic replace
// ---------------------------------------------------------------------------

/// Write `content` to `path` as a temp file and a rename, carrying `model`'s
/// mode and owner — and `path`'s own SELinux context — onto the new file.
///
/// **Every write this module makes goes through here** — the in-place edit,
/// the vendor copy, and the `.facelock-backup` — and there is one
/// implementation rather than one per verb because they need the same
/// property: a `/etc/pam.d/polkit-1` truncated by a kill between the truncate
/// and the last byte breaks polkit auth machine-wide, and a half-written
/// `system-auth` breaks the machine. A rename is atomic, so a reader sees
/// either the old file or the new one and never a short one. It is also what
/// makes the destination safe to *name*: a rename replaces the name rather
/// than following it, so neither a service file nor a backup path that someone
/// has turned into a symlink can redirect the bytes.
///
/// `model` is the file whose ownership the result must have: the target itself
/// for an in-place edit — where this preserves what was already there — and
/// the vendor file for a copy, where it is the only provenance available. The
/// temp file is created in the destination's own directory, because a rename
/// across filesystems is not a rename at all, and it is removed on any failure
/// so a refused write leaves no debris in `/etc/pam.d`.
///
/// The SELinux context is taken from the file being **replaced**, not from
/// `model`: an in-place edit must keep the label it had, and a copy into
/// `/etc/pam.d` must *not* inherit the vendor file's `/usr` label. When there
/// is no file to take one from — the copy case — the temp file already has the
/// destination directory's type by SELinux's own type-transition rules, which
/// is the label the new file should have. So the copy is best-effort by
/// construction: failing it degrades to the label the file would have had
/// anyway.
fn replace_atomically(path: &Path, content: &str, model: &Path) -> std::io::Result<()> {
    use std::io::{Error, ErrorKind, Write};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let dir = path
        .parent()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "no parent directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "no file name"))?;
    let model = fs::metadata(model)?;

    // A dotted name so that even a reader enumerating the directory mid-write
    // sees something obviously not a service file, and unique per process and
    // instant so two concurrent runs cannot collide on it. `create_new` is the
    // check that they did not.
    let temp = dir.join(format!(
        ".{}.facelock-{}-{}",
        name.to_string_lossy(),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default(),
    ));

    // Every piece of metadata is applied to the **open descriptor**, before
    // the `fsync` and before the rename. By path it would be a window — a
    // `chmod` on a name, which is a different question from a `chmod` on the
    // file this just wrote — and it would leave the mode, owner and label
    // outside the `fsync` that is supposed to make the new file durable.
    let written = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(model.mode())
            .open(&temp)?;
        file.write_all(content.as_bytes())?;

        // `OpenOptions::mode` is masked by the umask, so the mode is set again
        // rather than trusted: a service file that came out 0600 because the
        // caller's umask was 0177 is unreadable to every PAM stack that uses
        // it.
        file.set_permissions(fs::Permissions::from_mode(model.mode()))?;
        let current = file.metadata()?;
        if (model.uid(), model.gid()) != (current.uid(), current.gid()) {
            fchown(&file, model.uid(), model.gid())?;
        }
        copy_selinux_context(path, &file);

        file.sync_all()?;
        drop(file);
        fs::rename(&temp, path)
    })();

    if written.is_err() {
        // Best effort: the write already failed, and the report names that
        // failure rather than whatever went wrong tidying up after it.
        let _ = fs::remove_file(&temp);
        return written;
    }

    // The rename is what makes the content visible; this is what makes it
    // survive a power cut, and it is best-effort for the same reason `fsync`
    // on a directory is optional on every filesystem that matters.
    if let Ok(handle) = fs::File::open(dir) {
        let _ = handle.sync_all();
    }
    Ok(())
}

/// `fchown(2)`, which `std::fs` does not expose.
///
/// On the descriptor rather than on the path: `chown(2)` follows symlinks and
/// resolves the name again, so it answers a question about whatever the name
/// points at *now* instead of about the file this just wrote.
fn fchown(file: &fs::File, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;

    // SAFETY: the descriptor is owned by `file` and stays open for the call.
    if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Carry the label of the file at `from` onto the open `to`, if there is one
/// to carry.
///
/// The destination is the descriptor, like the mode and the owner: the label
/// belongs to the file this wrote, not to a name that could be something else
/// by the time the call lands. The source is read by path with `lgetxattr`,
/// which is a read of a file that already exists and is not required to be the
/// one being replaced — it simply is, in every case this has.
///
/// Silent when the source has no label (no SELinux, or a filesystem without
/// xattrs), because that is the overwhelmingly common case and it is not a
/// failure. Noisy only when a label existed and could not be set, which is the
/// one combination that leaves the new file labelled differently from the old.
fn copy_selinux_context(from: &Path, to: &fs::File) {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::AsRawFd;

    const SELINUX_XATTR: &std::ffi::CStr = c"security.selinux";
    // Longer than any policy's context; a label that does not fit is left to
    // the type transition rather than truncated, which would be worse.
    let mut context = [0u8; 256];

    let Ok(c_from) = CString::new(from.as_os_str().as_bytes()) else {
        return;
    };

    // SAFETY: the C string outlives the call, and the buffer's length is
    // passed as its capacity, so the call cannot write past it.
    let read = unsafe {
        libc::lgetxattr(
            c_from.as_ptr(),
            SELINUX_XATTR.as_ptr(),
            context.as_mut_ptr().cast(),
            context.len(),
        )
    };
    if read <= 0 {
        return;
    }

    // SAFETY: as above; `read` bytes were just written into `context`, and the
    // descriptor is owned by `to` and stays open for the call.
    let set = unsafe {
        libc::fsetxattr(
            to.as_raw_fd(),
            SELINUX_XATTR.as_ptr(),
            context.as_ptr().cast(),
            read as usize,
            0,
        )
    };
    if set != 0 {
        tracing::warn!(
            source = %from.display(),
            error = %std::io::Error::last_os_error(),
            "could not carry the SELinux context onto the new PAM service file"
        );
    }
}

// ---------------------------------------------------------------------------
// Output routing
// ---------------------------------------------------------------------------

/// Which seam sink one line of this command's human text goes to.
///
/// Named rather than decided inline because two of this module's lines must
/// survive `--quiet`, and "which stream, suppressible or not" is then a rule
/// worth pinning with a test instead of re-reading `apply_add` for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    /// `Terminal::info` — stdout, silenced by `--quiet`. Ordinary progress.
    Info,
    /// `Terminal::notice` — stdout, which `--quiet` does not reach. For the
    /// lines an operator needs *and* that have to stay on stdout to keep the
    /// bytes a normal run prints byte-identical.
    Notice,
    /// `Terminal::error` — stderr, never silenced.
    Error,
    /// Nothing is printed: `--json` replaces the human rendering, and the
    /// document carries the same fact in a field.
    Dropped,
}

/// Where this invocation's human text goes.
///
/// `--json` replaces the human rendering of the payload, so [`Sink::info`] is
/// silenced under it — but [`Sink::error`] is not. stdout is the answer and
/// stderr is everything else (contracts.md, "CLI Output Streams"), so a
/// diagnostic belongs on stderr whether or not a JSON document is being
/// written to stdout. `--quiet` is handled one layer down, by the message
/// seam, which silences `Terminal::info`, and never `Terminal::error` or
/// `Terminal::notice`.
#[derive(Clone, Copy)]
struct Sink {
    json: bool,
    /// Whether a `failed` row gets its human rendering here.
    ///
    /// The verb's rows *are* its output, so each failure is written to stderr
    /// as it happens, interleaved with the services around it. The three
    /// `setup --pam` aliases hand the failure back as an `Err` and their
    /// caller renders it — `setup`'s wizard as `PamConfigureFailed`, the
    /// standalone path through `main` — so rendering it here as well would
    /// print it twice.
    report_failures: bool,
    /// Print nothing at all, on either stream.
    ///
    /// Not the same as `--json`, which silences the human rendering because a
    /// document replaces it and still writes diagnostics to stderr. This is
    /// for a caller that is not producing output at this moment:
    /// [`configured_scan`], whose rows become one line of a report a different
    /// module renders. Without it, `facelock status` would interleave the
    /// writer's per-service lines into its own report.
    silent: bool,
}

impl Sink {
    /// The verb's sink. `--json` decides whether the human half is rendered
    /// at all; the report is this invocation's output either way.
    fn verb(json: bool) -> Self {
        Sink {
            json,
            report_failures: true,
            silent: false,
        }
    }

    /// The sink of a caller that has no `--json` to offer and returns its
    /// failures instead of printing them: the three `setup --pam` aliases.
    fn human() -> Self {
        Sink {
            json: false,
            report_failures: false,
            silent: false,
        }
    }

    /// The sink of a caller that is gathering facts rather than reporting
    /// them: [`configured_scan`]. See [`Sink::silent`].
    fn silent() -> Self {
        Sink {
            json: false,
            report_failures: false,
            silent: true,
        }
    }

    fn info(&self, msg: &dyn Message) {
        self.emit(self.info_route(), msg);
    }

    /// Ordinary progress: stdout, and `--quiet` may have it. `--json` replaces
    /// the human rendering wholesale, so under it there is nothing to print.
    fn info_route(&self) -> Route {
        if self.json {
            Route::Dropped
        } else {
            Route::Info
        }
    }

    fn error(&self, msg: &dyn Message) {
        self.emit(Route::Error, msg);
    }

    /// The context a per-file confirmation needs to be answerable.
    ///
    /// It is `info` when nothing is being asked — nobody is waiting on it, so
    /// `--quiet` may have it. When the question *will* be asked it has to be
    /// seen, so it goes to the sink that `--quiet` cannot reach, on the stream
    /// the prompt is on: see [`preview_route`].
    fn preview(&self, msg: &dyn Message, prompting: bool) {
        self.emit(preview_route(self.json, prompting), msg);
    }

    /// A line that must be seen and must stay on stdout — the rollback
    /// instructions. Dropped under `--json`, where the document's `backup`
    /// field is the same fact in machine form.
    fn notice(&self, msg: &dyn Message) {
        self.emit(self.notice_route(), msg);
    }

    /// Split out from [`Sink::notice`] so the rule is assertable without
    /// capturing stdout, the way [`preview_route`] is.
    fn notice_route(&self) -> Route {
        if self.json {
            Route::Dropped
        } else {
            Route::Notice
        }
    }

    fn emit(&self, route: Route, msg: &dyn Message) {
        if self.silent {
            return;
        }
        match route {
            Route::Info => Terminal.info(msg),
            Route::Notice => Terminal.notice(msg),
            Route::Error => Terminal.error(msg),
            Route::Dropped => {}
        }
    }
}

/// Where the pre-confirmation preview goes, as a pure function of the two
/// facts that decide it.
///
/// The preview says which file is about to change, what line goes in and where
/// the backup lands; a "Proceed?" with that suppressed is a question with no
/// subject. So when the prompt will be asked it is never `Info`:
///
/// - human mode → `Notice`, which prints the same bytes on the same stream a
///   normal run always printed, and keeps printing them under `--quiet`;
/// - `--json` → `Error`, because stdout is holding a document a parser is
///   reading and the prompt itself is on stderr, so that is where its context
///   belongs. Unreachable from the CLI, where `--json` implies `--no-confirm`;
///   the engine takes plain data, so a library caller can still get here.
fn preview_route(json: bool, prompting: bool) -> Route {
    match (json, prompting) {
        (false, false) => Route::Info,
        (false, true) => Route::Notice,
        (true, false) => Route::Dropped,
        (true, true) => Route::Error,
    }
}

/// Whether the per-file confirmation can be asked at all.
///
/// **Both streams, not just stdin.** dialoguer's `Confirm` reads *and* draws
/// through `Term::stderr()`, so `sudo facelock pam add --service sudo
/// 2>install.log` — stdin a TTY, stderr a file — made `interact()` fail with
/// "not a terminal", which the writer reported as `failed` having written
/// nothing. Redirecting a log is not a reason to refuse to install.
///
/// Proceeding is the answer a closed stdin has always got, and it is what
/// makes `setup --pam` work from a provisioning script: the prompt defaults to
/// yes, so skipping it changes whether you are asked, not the outcome. The
/// sensitive-service gate is decided in the validation phase, before any
/// prompt exists, so nothing here can unlock it.
fn should_prompt(no_confirm: bool, stdin_is_tty: bool, stderr_is_tty: bool) -> bool {
    !no_confirm && stdin_is_tty && stderr_is_tty
}

// ---------------------------------------------------------------------------
// Applying
// ---------------------------------------------------------------------------

/// Phase two for `add`: preview, confirm, back up, write — one service.
///
/// Message order is the old `pam_install_in`'s, byte for byte: the
/// already-present notice, or the preview, the confirmation, the backup line
/// and the installed line with its rollback instructions.
fn apply_add(target: &Target, no_confirm: bool, sink: &Sink) -> Outcome {
    let path = target.reported_path();

    // A vendor copy is `Plan::Override`: a different destination, no backup —
    // there is no `/etc` file to preserve — and a notice of its own, since
    // creating a shadowing file is a durable change with a maintenance
    // consequence the operator has to be told about.
    let (content, from_vendor) = match &target.plan {
        Plan::NoChange => {
            sink.info(&PamMessage::PamLineAlreadyPresent { path });
            return Outcome::Unchanged;
        }
        Plan::Absent => {
            sink.info(&PamMessage::PamServiceAbsentSkipped { path });
            return Outcome::Absent;
        }
        // `plan_writes` builds `VendorOnly` for `remove` alone, so `add`
        // cannot reach it. Answered as the no-op it names rather than with an
        // invented write; the assertion is where a debug build says the
        // invariant broke.
        Plan::VendorOnly => {
            debug_assert!(false, "a vendor-only plan reached `add`");
            sink.info(&PamMessage::PamVendorOnly { path });
            return Outcome::VendorOnly;
        }
        Plan::Rewrite { content } => (content.as_str(), false),
        Plan::Override { content } => (content.as_str(), true),
    };
    let backup = target.backup_string();

    // Decided before the preview is printed, because it decides where the
    // preview goes: a question that will be asked needs its context seen.
    let prompting = should_prompt(
        no_confirm,
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
    );

    // Two previews, because they promise different things: the in-place edit
    // names the backup it is about to take, and the copy has none to name —
    // its undo is deleting the file it is about to create.
    if from_vendor {
        sink.preview(
            &PamMessage::PamOverridePreview {
                path: path.clone(),
                vendor: target.path_string(),
                line: PAM_LINE.to_string(),
                hint: insertion_hint(content).localized(),
            },
            prompting,
        );
    } else {
        sink.preview(
            &PamMessage::PamModifyPreview {
                path: path.clone(),
                line: PAM_LINE.to_string(),
                hint: insertion_hint(content).localized(),
                backup: backup.clone(),
            },
            prompting,
        );
    }

    let proceed = if !prompting {
        true
    } else {
        match Confirm::new()
            .with_prompt(PamMessage::ConfirmProceed.localized())
            .default(true)
            .interact()
        {
            Ok(answer) => answer,
            Err(error) => return Outcome::Failed(format!("failed to read confirmation: {error}")),
        }
    };

    if !proceed {
        sink.info(&PamMessage::PamSkippedFile { path });
        return Outcome::Declined;
    }

    // No backup for a copy: there is no `/etc` file to preserve, and copying
    // the *vendor* file to `<service>.facelock-backup` would name a backup of
    // a file nothing changed. Deleting the override is the undo, and the
    // notice below says so.
    //
    // The backup goes through the same atomic replace as the edit it protects,
    // and for two reasons beyond symmetry. `fs::copy` opens its destination
    // `O_CREAT|O_TRUNC` and **follows symlinks**, so a symlink planted at
    // `<service>.facelock-backup` sent the copy's bytes to wherever it pointed
    // — the confinement rules cover the service path and never covered this
    // one, and `rename` replaces the *name* rather than following it. And a
    // `copy` killed halfway leaves a short backup, which is exactly the file
    // `PamInstalled` tells the operator to restore from. `content` is the
    // bytes phase one read, so the backup is the file this is about to
    // replace, not whatever the path holds by the time the copy runs.
    if !from_vendor {
        if let Err(error) = replace_atomically(&target.backup, content, &target.path) {
            return Outcome::Failed(format!("failed to back up {path} to {backup}: {error}"));
        }
        sink.info(&PamMessage::PamBackedUp {
            path: path.clone(),
            backup: backup.clone(),
        });
    }

    // The copy and the line-insert are one write of the final content: two
    // renames where one will do is two chances to leave a service file
    // half-configured. `target.path` is the mode-and-owner model either way —
    // the file itself for an edit, the vendor original for a copy.
    let with_line = with_line_inserted(content);
    let written = if from_vendor {
        format!("{}{with_line}", provenance_header(&target.path))
    } else {
        with_line
    };
    if let Err(error) = replace_atomically(target.write_path(), &written, &target.path) {
        return Outcome::Failed(format!("failed to write {path}: {error}"));
    }

    // `notice`, not `info`: these are the messages that tell an operator who
    // has just changed an auth stack how to undo it, so `--quiet` must not
    // take them. Still stdout, so a normal run prints the same bytes it always
    // did. Under `--json` the row's `backup` field carries the same fact.
    if from_vendor {
        sink.notice(&PamMessage::PamVendorOverridden {
            path,
            vendor: target.path_string(),
            service: target.service.clone(),
        });
        return Outcome::Overridden;
    }
    sink.notice(&PamMessage::PamInstalled {
        path,
        backup,
        service: target.service.clone(),
    });
    Outcome::Installed
}

/// Phase two for `remove` — one service.
///
/// No confirmation and no new backup, which is what the old `pam_remove_in`
/// did: removal only takes away a way to authenticate, so there is nothing to
/// be talked out of, and `setup --pam --remove` has never prompted. An
/// existing backup is reported so the operator knows a full restore is
/// available.
fn apply_remove(target: &Target, sink: &Sink) -> Outcome {
    let path = target.path_string();

    let outcome = match &target.plan {
        Plan::Absent => {
            sink.info(&PamMessage::PamServiceAbsent { path });
            // Returns before the backup notice, as the old writer did.
            return Outcome::Absent;
        }
        // The service exists only as a package-owned file. `remove` never
        // writes to a vendor directory, so there is nothing to take out —
        // reported as itself rather than as `unchanged`, which would claim
        // this had looked at a file in `/etc/pam.d`.
        Plan::VendorOnly => {
            sink.info(&PamMessage::PamVendorOnly { path });
            return Outcome::VendorOnly;
        }
        Plan::NoChange => {
            sink.info(&PamMessage::PamNoLineFound { path: path.clone() });
            Outcome::Unchanged
        }
        // `remove` still takes no backup of its own — it relies on the one
        // `add` wrote, which is the remaining entry under "Limits" in
        // docs/contracts.md. The write itself is atomic, like every other.
        Plan::Rewrite { content } => {
            match replace_atomically(&target.path, &with_line_removed(content), &target.path) {
                Ok(()) => {
                    sink.info(&PamMessage::PamRemoved { path: path.clone() });
                    Outcome::Removed
                }
                Err(error) => Outcome::Failed(format!("failed to write {path}: {error}")),
            }
        }
        // `plan_writes` builds `Override` for `add` alone. Answered like
        // `VendorOnly` rather than with a failure of its own: if that ever
        // stopped being true, the safe answer is still "write nothing to a
        // vendor directory", and the assertion is where a debug build says the
        // invariant broke.
        Plan::Override { .. } => {
            debug_assert!(false, "an override plan reached `remove`");
            sink.info(&PamMessage::PamVendorOnly { path });
            return Outcome::VendorOnly;
        }
    };

    if let Some(backup) = target.existing_backup() {
        sink.info(&PamMessage::PamBackupExists { path, backup });
    }

    outcome
}

/// Render the resolved plan for `--dry-run`, writing nothing.
fn report_plan(target: &Target, action: WriteAction, sink: &Sink) -> Outcome {
    let path = target.reported_path();
    match (&target.plan, action) {
        (Plan::Rewrite { content }, WriteAction::Add) => {
            sink.info(&PamMessage::PamPlanAdd {
                path,
                hint: insertion_hint(content).localized(),
            });
            Outcome::Installed
        }
        (Plan::Rewrite { .. }, WriteAction::Remove) => {
            sink.info(&PamMessage::PamPlanRemove { path });
            Outcome::Removed
        }
        (Plan::Override { content }, _) => {
            sink.info(&PamMessage::PamPlanOverride {
                path,
                vendor: target.path_string(),
                hint: insertion_hint(content).localized(),
            });
            Outcome::Overridden
        }
        (Plan::VendorOnly, _) => {
            sink.info(&PamMessage::PamVendorOnly { path });
            Outcome::VendorOnly
        }
        (Plan::NoChange, _) => {
            sink.info(&PamMessage::PamPlanNoChange { path });
            Outcome::Unchanged
        }
        (Plan::Absent, _) => {
            sink.info(&PamMessage::PamPlanAbsent { path });
            Outcome::Absent
        }
    }
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/// `{"command", "dry_run", "services": [{"service", "path", "action",
/// "backup"}]}`, with `"error"` present on a `failed` or `unknown` service.
///
/// An object rather than a bare array so a later top-level field is an
/// additive change instead of a document-type change. Built through
/// `serde_json::json!` rather than `format!` (E10, the same reason as
/// `commands::list::list_json`): a service name reaches here from argv, and
/// confinement rejects `/` but not `"`, so `--service 'a"b'` would otherwise
/// emit invalid JSON.
fn report_json(
    action: PamAction,
    dry_run: bool,
    reports: &[ServiceReport],
    directories: &[DirectoryScan],
) -> String {
    let services: Vec<serde_json::Value> = reports
        .iter()
        .map(|report| {
            let mut value = serde_json::json!({
                "service": report.service,
                "path": report.path,
                "action": report.outcome.word(),
                "backup": report.backup,
            });
            if let (Some(error), Some(object)) = (report.outcome.error(), value.as_object_mut()) {
                object.insert("error".to_string(), serde_json::Value::String(error.into()));
            }
            // Omitted rather than `null` when there is nothing shadowed: every
            // row on a machine with no vendor directory would otherwise carry
            // a key that is always null, and the absent-key form is the one
            // `error` already established for a field that is sometimes there.
            if let (Some(vendor), Some(object)) = (&report.shadows, value.as_object_mut()) {
                object.insert(
                    "shadows".to_string(),
                    serde_json::Value::String(vendor.clone()),
                );
            }
            value
        })
        .collect();

    let mut document = serde_json::json!({
        "command": action.word(),
        "dry_run": dry_run,
        "services": services,
    });

    // `status` alone carries `module_path`: it is the verb that answers "is
    // this machine wired up", and "the line is present but the module it names
    // is at a path nothing looks at" is the state an integrator could not
    // otherwise see. `add` and `remove` refuse before writing when the module
    // is absent, so the question is already answered for them. A property of
    // the machine, not of a service, so it is top-level rather than repeated
    // in every service object — `null` when no candidate hit.
    if let (PamAction::Status, Some(object)) = (action, document.as_object_mut()) {
        let found = installed_module_path().map(|path| path.display().to_string());
        object.insert("module_path".to_string(), serde_json::json!(found));
    }

    // `--all` alone carries `directories`: it is the only form that claims to
    // have looked everywhere, so it is the only one that owes the reader an
    // account of where it looked and which of those places answered. A named
    // request resolves through the search path without listing it, and an
    // empty array there would read as "nothing searched".
    if let (false, Some(object)) = (directories.is_empty(), document.as_object_mut()) {
        let scanned: Vec<serde_json::Value> = directories
            .iter()
            .map(|dir| {
                let mut value = serde_json::json!({
                    "path": dir.path.display().to_string(),
                    "status": dir.state.word(),
                });
                if let (Some(error), Some(object)) = (dir.state.error(), value.as_object_mut()) {
                    object.insert("error".to_string(), serde_json::Value::String(error.into()));
                }
                value
            })
            .collect();
        object.insert("directories".to_string(), serde_json::Value::Array(scanned));
    }

    document.to_string()
}

/// Emit the machine document on stdout, if this invocation asked for one.
///
/// The `--json` test lives here rather than at each caller, so "was a document
/// requested?" is asked once. Through [`crate::message::payload`], so
/// `--quiet` reaches it without this function knowing the flag exists: under
/// it the document is dropped and the exit code is the whole answer, which is
/// `is-enrolled --quiet --json`'s rule generalized to every payload.
///
/// `dry_run` is a parameter rather than read off the request because `status`
/// has no dry run: it reports `false` whatever a library caller left in the
/// field, since a read that always happens cannot have been a preview.
fn emit_json(
    request: &PamRequest,
    dry_run: bool,
    reports: &[ServiceReport],
    directories: &[DirectoryScan],
) {
    if request.json {
        crate::message::payload(&report_json(request.action, dry_run, reports, directories));
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Run `facelock pam …`, returning the process exit code.
///
/// **C6 ordering.** `add` and `remove` check root as their first statement,
/// before any output, any read of `/etc/pam.d`, and `--dry-run`. A dry run
/// that succeeded unprivileged would be a misleading preview of a command that
/// cannot run, and making the check conditional on a flag is exactly the
/// ordering subtlety C6 exists to prevent. `pam status` needs no root and
/// takes none.
///
/// The refusal is the hard-error kind (`require_root_scripted`), not the
/// interactive sudo re-exec: standalone `setup --pam` has never re-execed —
/// `setup::needs_root_precheck` says so and a test pins it — and silently
/// re-running a `/etc/pam.d` edit under `sudo` from a wrapper script is a
/// surprise, not a convenience.
pub fn run(request: PamRequest) -> anyhow::Result<i32> {
    // `status` needs no root and returns before the check, as it always has.
    if request.action == PamAction::Status {
        return Ok(status_in(&PamDirs::system(), &request));
    }

    // C6: the first statement of the write path, before the config read the
    // search path needs. Resolving the search path first would be harmless
    // today — the read is silent and cannot fail — but "first statement" is
    // the property this rule pins, and a rule that has to be re-argued from
    // the current implementation is not a rule.
    crate::ipc_client::require_root_scripted(&format!(
        "sudo facelock pam {}",
        request.action.word()
    ))?;

    if request.action == PamAction::Add {
        require_module_installed()?;
    }

    write_in(&PamDirs::system(), &request)
}

/// Whether the PAM module is where the line needs it to be.
///
/// A property of the machine, not of a service, so it is asked once per
/// invocation rather than per service — and asked here rather than by each
/// caller spelling [`PAM_MODULE_PATHS`] itself, which is how `setup` came to
/// have its own copy of the test.
pub(crate) fn module_installed() -> bool {
    installed_module_path().is_some()
}

/// The candidate the module was found at, or `None`. The probe is **read
/// only**: it finds the module and never installs, copies or links it —
/// placing it is the packager's job, and writing into the directory `ld.so`
/// loads auth modules from is not something a CLI should do.
pub(crate) fn installed_module_path() -> Option<PathBuf> {
    first_existing(PAM_MODULE_PATHS)
}

/// The first candidate that exists. Split out so the order is testable without
/// a machine that has the module installed in three places.
fn first_existing(candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(Path::new)
        .find(|path| path.exists())
        .map(Path::to_path_buf)
}

/// The precondition the line is useless without, as the refusal to write.
///
/// The refusal names **every** candidate: an operator whose distribution puts
/// the module somewhere unlisted can then see what facelock looked for rather
/// than guess which single path it wanted.
fn require_module_installed() -> anyhow::Result<()> {
    if module_installed() {
        return Ok(());
    }
    Err(fail(PamMessage::PamModuleNotInstalled {
        paths: PAM_MODULE_PATHS.join(", "),
        path: PAM_MODULE_PATHS.first().unwrap_or(&"").to_string(),
    }))
}

/// Whether `service` has a file anywhere on the search path.
///
/// The wizard's menu question (`setup.rs`'s `candidates_in`), asked through the
/// resolver rather than with a `base.join(name).exists()` of its own: a
/// candidate that ships only in a vendor directory — `polkit-1` on current
/// Arch — is offerable, and `pam add` will configure it. An entry this refuses
/// to follow is *not* offered: the menu should not propose a service the
/// writer will then decline.
pub(crate) fn service_exists(dirs: &PamDirs, service: &str) -> bool {
    Target::locate(dirs, service).is_ok_and(|target| target.exists())
}

/// Whether `service` under `dirs` carries the facelock line.
///
/// The question `status` answers, for a caller that wants the boolean and has
/// no exit code to produce — `setup`'s hyprlock handoff, which read
/// `/etc/pam.d/hyprlock` itself and so had its own copy of "where does this
/// name resolve to" beside this module's. An unreadable or unresolvable
/// service is `false`: the caller decides whether to *offer* something, and
/// "cannot tell" is not a reason to.
pub(crate) fn is_configured(dirs: &PamDirs, service: &str) -> bool {
    let Ok(target) = Target::locate(dirs, service) else {
        return false;
    };
    fs::read_to_string(&target.path).is_ok_and(|content| content.lines().any(is_facelock_pam_line))
}

/// Phase two, for every target.
///
/// **Continue and report**, and that is now true of all four entry points
/// rather than of the verb alone. A write-phase failure on service N is one
/// independent file's failure: the rest still have their own backups and their
/// own chance of succeeding, and a half-reported plan is harder to recover
/// from than a fully-reported one. What the entry points differ in is how they
/// *read* the rows — [`write_in`] turns them into an exit code, the three
/// `setup` aliases into a `Result` through [`first_failure`], once every
/// service has been attempted.
fn apply_all(targets: &[Target], write: &WriteRequest, sink: &Sink) -> Vec<ServiceReport> {
    targets
        .iter()
        .map(|target| {
            let outcome = if write.request.dry_run {
                report_plan(target, write.action, sink)
            } else {
                match write.action {
                    WriteAction::Add => apply_add(target, write.request.no_confirm, sink),
                    WriteAction::Remove => apply_remove(target, sink),
                }
            };

            if let (Outcome::Failed(error), true) = (&outcome, sink.report_failures) {
                sink.error(&PamMessage::PamConfigureFailed {
                    service: target.service.clone(),
                    error: error.clone(),
                });
            }

            ServiceReport {
                service: target.service.clone(),
                path: Some(target.reported_path()),
                // An `overridden` row has no backup **by construction**: the
                // copy preserved nothing, so a `.facelock-backup` sitting at
                // the override path is some earlier run's, and offering it as
                // this run's rollback would promise a restore of a file this
                // did not touch. Deleting the override is the undo, and the
                // notice says so.
                backup: match (&outcome, write.request.dry_run) {
                    (_, true) | (Outcome::Overridden, _) => None,
                    _ => target.existing_backup(),
                },
                // The row that *creates* the shadow is the one the resolver
                // could not report it for: at `locate` time there was no
                // `/etc` entry, so `Origin::Vendor` has nothing to hide yet.
                // After the copy, the file it was read from is exactly what
                // it hides — and under `--dry-run` exactly what it would.
                // Leaving this `None` would put the key on every later
                // `status` row and withhold it from the one that made the
                // fact true.
                shadows: match &outcome {
                    Outcome::Overridden => Some(target.path_string()),
                    _ => target.shadows_string(),
                },
                outcome,
            }
        })
        .collect()
}

/// The closing copy-pasteable hint, once per invocation and after every
/// service — not once per service, as a shell loop over the old
/// one-service-per-process CLI produced. It is human-facing text, so `--json`
/// and `--quiet` both drop it; `--dry-run` keeps it, so a dry run is a
/// faithful preview of what the real run prints.
fn emit_extension_hint(sink: &Sink) {
    sink.info(&PamMessage::PamExtensionHint {
        line: PAM_LINE.to_string(),
    });
}

/// The first failure among the rows, for a caller whose answer is a `Result`
/// rather than an exit code. Every service has already been attempted.
fn first_failure(reports: &[ServiceReport]) -> anyhow::Result<()> {
    for report in reports {
        if let Outcome::Failed(error) = &report.outcome {
            return Err(anyhow::anyhow!(error.clone()));
        }
    }
    Ok(())
}

/// `add` / `remove` against `base`. The engine tests drive this directly, so
/// it performs no root or module check — [`run`] owns those.
fn write_in(dirs: &PamDirs, request: &PamRequest) -> anyhow::Result<i32> {
    let Some(action) = WriteAction::of(request.action) else {
        // `run` routes `status` to `status_in` and never gets here. Delegating
        // rather than falling through is what stops a future caller from
        // getting a *removal* out of a request that asked to read.
        return Ok(status_in(dirs, request));
    };
    let write = WriteRequest {
        action,
        request,
        remedy: "--allow-sensitive",
    };
    let sink = Sink::verb(request.json);

    // Phase one. An `Err` here has written nothing, by construction.
    let targets = plan_writes(dirs, &write)?;
    let reports = apply_all(&targets, &write, &sink);

    if action == WriteAction::Add {
        emit_extension_hint(&sink);
    }
    emit_json(request, request.dry_run, &reports, &[]);

    Ok(if first_failure(&reports).is_err() {
        WRITE_FAILED
    } else {
        WRITE_OK
    })
}

/// `pam status` against `base`.
///
/// Unprivileged by design (DEC-6): `/etc/pam.d/*` is `0644`, this never
/// writes, and it is the probe an integration wants without `sudo` — the one
/// that replaces `grep -q pam_facelock.so /etc/pam.d/<service>`. An unreadable
/// file reports `unknown` and exits 2 rather than pretending it is missing.
///
/// The exit code is the answer, on `grep`'s scale and `is-enrolled`'s: 0 every
/// service has the line, 1 at least one does not, 2 at least one could not be
/// answered. The worst outcome wins.
fn status_in(dirs: &PamDirs, request: &PamRequest) -> i32 {
    let sink = Sink::verb(request.json);
    if request.all {
        return status_all_in(dirs, request, &sink);
    }
    let reports = status_reports(dirs, &requested_services(&request.services), &sink);

    emit_json(request, false, &reports, &[]);

    reports
        .iter()
        .map(|report| status_code(&report.outcome, request.if_present))
        .max()
        .unwrap_or(STATUS_PRESENT)
}

/// `pam status --all`: every service on the search path that names the module.
///
/// The rows come from the same [`status_reports`] the named form uses, so a
/// service reported here is reported identically when it is asked for by name.
/// Three things decide the exit code, and each is a different question:
///
/// - the worst row, exactly as in the named form;
/// - **nothing configured is [`STATUS_MISSING`]**, not 0. A machine with no
///   facelock line anywhere is not "fine", it is not set up, and it is the
///   same answer `pam status` gives for a service file with no line in it.
///   `--if-present` does not change it either: there are no `absent` rows to
///   forgive here — a name only reaches the report by having been found — so
///   the flag has nothing to convert;
/// - **a directory that would not list is [`STATUS_ERROR`]**, because the
///   enumeration is then incomplete and a 0 or a 1 would be a claim about
///   services this never saw.
fn status_all_in(dirs: &PamDirs, request: &PamRequest, sink: &Sink) -> i32 {
    let scan = scan_directories(dirs);
    let reports = status_reports(dirs, &scan.names, sink);

    // After the rows: the services are the answer, and this is why the answer
    // may be short. On stderr, like every other "could not tell" line here.
    let unchecked: Vec<String> = scan
        .unreadable()
        .map(|(path, error)| {
            sink.error(&PamMessage::PamStatusDirUnreadable {
                dir: path.display().to_string(),
                error: error.to_string(),
            });
            path.display().to_string()
        })
        .collect();

    // **The empty answer has to be qualified by what could not be looked at.**
    // An unqualified "no service file under <every directory> carries the
    // line" is a claim about a directory this failed to open, and read
    // `2>/dev/null` — the ordinary way to take the human answer — it asserts
    // exactly what enumeration exists to stop it asserting. Three cases, and
    // the third is why this is not a one-line guard: when *nothing* could be
    // read there is no set of directories to say "none here" about, and the
    // per-directory lines above are already the whole answer.
    if reports.is_empty() {
        let answered = scan.answered();
        if unchecked.is_empty() {
            sink.info(&PamMessage::PamStatusNoServices {
                dirs: dirs.display(),
            });
        } else if !answered.is_empty() {
            sink.info(&PamMessage::PamStatusNoServicesIncomplete {
                dirs: answered.join(", "),
                unchecked: unchecked.join(", "),
            });
        } else {
            // Nothing was read, so there is no set of directories to say
            // "none here" about. stdout still gets a line: a human reading it
            // alone would otherwise get a sentence in the other two branches
            // and silence in the one where the machine is worst off. It
            // asserts only what is true — that nothing could be read.
            sink.info(&PamMessage::PamStatusNothingReadable {
                dirs: unchecked.join(", "),
            });
        }
    }

    emit_json(request, false, &reports, &scan.directories);

    let worst = reports
        .iter()
        .map(|report| status_code(&report.outcome, request.if_present))
        .max()
        .unwrap_or(STATUS_PRESENT);
    let nothing_configured = if reports.is_empty() {
        STATUS_MISSING
    } else {
        STATUS_PRESENT
    };
    let unreadable = if unchecked.is_empty() {
        STATUS_PRESENT
    } else {
        STATUS_ERROR
    };
    worst.max(nothing_configured).max(unreadable)
}

/// One report row per service. Split out from [`status_in`] so the rows —
/// which are the `--json` payload — are assertable without capturing stdout.
fn status_reports(dirs: &PamDirs, services: &[String], sink: &Sink) -> Vec<ServiceReport> {
    services
        .iter()
        .map(|service| {
            // Both rejections read as `unknown`, the same word an unreadable
            // file gets: the question "does this service carry the line?" has
            // no answer this may go and look for. Not an `Err` return either
            // — `status` owns its exit codes, and a usage error is exit 2
            // rather than the generic exit 1 `main` gives an `anyhow` failure.
            let target = match Target::locate(dirs, service) {
                Ok(target) => target,
                Err(why) => {
                    sink.error(&why.message(service));
                    return ServiceReport {
                        service: service.clone(),
                        path: why.path(),
                        outcome: Outcome::Unknown(why.reason().to_string()),
                        backup: why.backup(),
                        // Nothing was resolved, so there is nothing this could
                        // be shadowing.
                        shadows: None,
                    };
                }
            };
            let display = target.path_string();

            let vendor_only = matches!(target.origin, Origin::Vendor { .. });

            let outcome = match fs::read_to_string(&target.path) {
                // Read before the vendor test, not after: a service whose
                // vendor file already carries the line — a distribution that
                // ships face auth in its own PAM stack — *is* configured, and
                // reporting it `vendor-only` would send an integrator off to
                // create an override that adds nothing.
                Ok(content) if content.lines().any(is_facelock_pam_line) => {
                    // Configured either way; the second line says the copy is
                    // a local override, which is what tells an operator it
                    // will not follow the package's updates.
                    match &target.shadowed {
                        Some(vendor) => sink.info(&PamMessage::PamStatusOverride {
                            path: display.clone(),
                            vendor: vendor.display().to_string(),
                        }),
                        None => sink.info(&PamMessage::PamStatusPresent {
                            path: display.clone(),
                        }),
                    }
                    Outcome::Present
                }
                // Exists, carries no line, and has no `/etc/pam.d` copy for
                // one to be added to. `missing` would be true of the file and
                // misleading about the machine: `add` will create an override
                // here rather than edit what `status` just named.
                Ok(_) if vendor_only => {
                    sink.info(&PamMessage::PamStatusVendorOnly {
                        path: display.clone(),
                    });
                    Outcome::VendorOnly
                }
                Ok(_) => {
                    sink.info(&PamMessage::PamStatusMissing {
                        path: display.clone(),
                    });
                    Outcome::Missing
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // Every path tried, like `add`'s refusal: the same
                    // question must not be answered two ways by two verbs.
                    // The row's `path` field stays the first directory's —
                    // where an override would go — because it is one string,
                    // and `contracts.md` says which of the two it is.
                    sink.info(&PamMessage::PamStatusAbsent {
                        paths: target.tried_paths(),
                    });
                    Outcome::Absent
                }
                Err(error) => {
                    sink.error(&PamMessage::PamStatusUnknown {
                        path: display.clone(),
                        error: error.to_string(),
                    });
                    Outcome::Unknown(error.to_string())
                }
            };

            ServiceReport {
                service: target.service.clone(),
                path: Some(display),
                outcome,
                backup: target.existing_backup(),
                shadows: target.shadows_string(),
            }
        })
        .collect()
}

/// `grep`'s scale, and `is-enrolled`'s. The worst outcome across the requested
/// services wins, which is why this is a function of one outcome and the
/// caller takes the max.
fn status_code(outcome: &Outcome, if_present: bool) -> i32 {
    match outcome {
        Outcome::Present => STATUS_PRESENT,
        Outcome::Missing => STATUS_MISSING,
        // `--if-present` means the same thing here as on `add` and `remove`:
        // a service file that is not installed is not an error, so the row is
        // still reported and the exit code is decided by the services that do
        // exist. It converts *absence* and nothing else.
        Outcome::Absent if if_present => STATUS_PRESENT,
        Outcome::Absent | Outcome::Unknown(_) => STATUS_ERROR,
        // The service exists and does not carry the line, which is exactly
        // what `missing` means to a caller branching on the exit code. The
        // word is what says *why* `add` will behave differently here, and
        // `--if-present` does not convert it: this is not an absence.
        Outcome::VendorOnly => STATUS_MISSING,
        // Not reachable: `status_reports` produces the five words above and no
        // other. Spelled out rather than left to a `_` arm so that a word
        // added to the vocabulary has to be given a code here on purpose —
        // under a wildcard, a new `status` outcome would silently be exit 2.
        Outcome::Installed
        | Outcome::Overridden
        | Outcome::Removed
        | Outcome::Unchanged
        | Outcome::Declined
        | Outcome::Failed(_) => STATUS_ERROR,
    }
}

// ---------------------------------------------------------------------------
// The `setup --pam` alias
// ---------------------------------------------------------------------------

/// The three aliases take the same [`PamRequest`] the verb does.
///
/// They used to take loose parameters, in two different orders —
/// `install_for_setup(services, no_confirm, allow_sensitive)` beside
/// `install_one_in(base, service, allow_sensitive, no_confirm)` — so a swapped
/// pair type-checked and quietly unlocked the sensitive-service gate. `setup`
/// builds a request, names every field, and the writer reads the same value in
/// both phases.
///
/// The `remedy` is `--yes` on all three: `setup --yes` keeps its combined
/// meaning — it is the documented exception to the flag split — so the refusal
/// has to name the flag this surface actually honours.
///
/// Root is re-checked in the two that `run_with_plan` reaches directly for a
/// standalone `--pam`, which does not take the base setup's root pre-check.
/// `install_one_in` is the wizard's, and the wizard has already checked.
///
/// `setup --pam [--service X]`.
pub(crate) fn install_for_setup(request: &PamRequest) -> anyhow::Result<()> {
    debug_assert_eq!(request.action, PamAction::Add);
    crate::ipc_client::require_root_scripted("sudo facelock setup --pam")?;
    require_module_installed()?;

    let write = WriteRequest {
        action: WriteAction::Add,
        request,
        remedy: "--yes",
    };
    let sink = Sink::human();
    let reports = apply_all(&plan_writes(&PamDirs::system(), &write)?, &write, &sink);
    // Before the hint, which the alias has never printed after a failure —
    // unlike the verb, whose closing hint fires whatever the rows say.
    first_failure(&reports)?;
    emit_extension_hint(&sink);
    Ok(())
}

/// `setup --pam --remove [--if-present]`.
pub(crate) fn remove_for_setup(request: &PamRequest) -> anyhow::Result<()> {
    debug_assert_eq!(request.action, PamAction::Remove);
    crate::ipc_client::require_root_scripted("sudo facelock setup --pam --remove")?;

    let write = WriteRequest {
        action: WriteAction::Remove,
        request,
        remedy: "--yes",
    };
    let sink = Sink::human();
    let reports = apply_all(&plan_writes(&PamDirs::system(), &write)?, &write, &sink);
    first_failure(&reports)
}

/// One service, against `base`, with the wizard's semantics: the multi-select
/// already *is* the per-service consent, and the module check already ran, so
/// neither is repeated here — nor is the closing hint, which the wizard emits
/// itself once, after step 9, whatever that step decided.
pub(crate) fn install_one_in(dirs: &PamDirs, request: &PamRequest) -> anyhow::Result<()> {
    debug_assert_eq!(request.action, PamAction::Add);
    let write = WriteRequest {
        action: WriteAction::Add,
        request,
        remedy: "--yes",
    };
    let sink = Sink::human();
    let reports = apply_all(&plan_writes(dirs, &write)?, &write, &sink);
    first_failure(&reports)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    // -----------------------------------------------------------------------
    // Goldens captured from `main` (4c8cf28) before the extraction.
    //
    // Produced by running that commit's `pam_install_in` / `pam_remove_in`
    // against a tempdir and dumping the resulting bytes — not written by hand.
    // They are the regression guard the whole refactor turns on: the file this
    // command leaves behind must be the file the old one left behind, byte for
    // byte, including where the line lands and whether a trailing newline
    // survives.
    // -----------------------------------------------------------------------

    /// A service whose first `auth` line is not its first line.
    const SUDO_BEFORE: &str = "#%PAM-1.0\nauth\t\tinclude\t\tsystem-auth\naccount\t\tinclude\t\tsystem-auth\nsession\t\tinclude\t\tsystem-auth\n";
    const SUDO_AFTER: &str = "#%PAM-1.0\nauth      sufficient pam_facelock.so\nauth\t\tinclude\t\tsystem-auth\naccount\t\tinclude\t\tsystem-auth\nsession\t\tinclude\t\tsystem-auth\n";

    /// A service with no `auth` line at all: the line goes to the very top,
    /// *above* the `#%PAM-1.0` header. That is what `main` did, so that is
    /// what the golden says.
    const POLKIT_BEFORE: &str =
        "#%PAM-1.0\naccount\t\tinclude\t\tsystem-auth\npassword\tinclude\t\tsystem-auth\n";
    const POLKIT_AFTER: &str = "auth      sufficient pam_facelock.so\n#%PAM-1.0\naccount\t\tinclude\t\tsystem-auth\npassword\tinclude\t\tsystem-auth\n";

    /// A service that already carries the line: untouched, and no backup.
    const OMARCHY_PRESENT: &str = "#%PAM-1.0\nauth      sufficient pam_facelock.so\nauth\t\tinclude\t\tsystem-auth\naccount\t\tinclude\t\tsystem-auth\n";
    const OMARCHY_REMOVED: &str =
        "#%PAM-1.0\nauth\t\tinclude\t\tsystem-auth\naccount\t\tinclude\t\tsystem-auth\n";

    /// A file with no trailing newline keeps not having one.
    const NO_NEWLINE_BEFORE: &str = "#%PAM-1.0\nauth\t\tinclude\t\tsystem-auth";
    const NO_NEWLINE_AFTER: &str =
        "#%PAM-1.0\nauth      sufficient pam_facelock.so\nauth\t\tinclude\t\tsystem-auth";

    fn seeded(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::TempDir::new().unwrap();
        for (name, content) in files {
            fs::write(dir.path().join(name), content).unwrap();
        }
        dir
    }

    /// Every entry under `dir` and its exact bytes. Enumerating the directory
    /// rather than the files we wrote is what catches a stray
    /// `.facelock-backup` appearing where none should.
    fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (
                    entry.file_name().to_string_lossy().into_owned(),
                    fs::read(entry.path()).unwrap_or_default(),
                )
            })
            .collect()
    }

    fn add(services: &[&str]) -> PamRequest {
        PamRequest {
            action: PamAction::Add,
            services: services.iter().map(|s| s.to_string()).collect(),
            no_confirm: true,
            ..PamRequest::default()
        }
    }

    fn remove(services: &[&str]) -> PamRequest {
        PamRequest {
            action: PamAction::Remove,
            services: services.iter().map(|s| s.to_string()).collect(),
            no_confirm: true,
            ..PamRequest::default()
        }
    }

    fn read(dir: &tempfile::TempDir, name: &str) -> String {
        fs::read_to_string(dir.path().join(name)).unwrap()
    }

    // -- byte identity with `main` ------------------------------------------

    #[test]
    fn add_reproduces_main_byte_for_byte() {
        for (service, before, after) in [
            ("sudo", SUDO_BEFORE, SUDO_AFTER),
            ("polkit-1", POLKIT_BEFORE, POLKIT_AFTER),
            ("omarchy-lock-face", OMARCHY_PRESENT, OMARCHY_PRESENT),
            ("sudo", NO_NEWLINE_BEFORE, NO_NEWLINE_AFTER),
        ] {
            let dir = seeded(&[(service, before)]);
            let code = write_in(&only(dir.path()), &add(&[service])).unwrap();

            assert_eq!(code, WRITE_OK, "{service}");
            assert_eq!(read(&dir, service), after, "{service} content");
        }
    }

    /// The backup is a byte copy of the original, and it only appears when
    /// something was actually written.
    #[test]
    fn add_backup_is_the_original_and_only_exists_on_a_real_write() {
        let dir = seeded(&[("sudo", SUDO_BEFORE)]);
        write_in(&only(dir.path()), &add(&["sudo"])).unwrap();
        assert_eq!(read(&dir, "sudo.facelock-backup"), SUDO_BEFORE);

        let untouched = seeded(&[("omarchy-lock-face", OMARCHY_PRESENT)]);
        let before = snapshot(untouched.path());
        write_in(&only(untouched.path()), &add(&["omarchy-lock-face"])).unwrap();
        assert_eq!(
            before,
            snapshot(untouched.path()),
            "an already-configured service must not gain a backup"
        );
    }

    #[test]
    fn remove_reproduces_main_byte_for_byte() {
        let dir = seeded(&[
            ("omarchy-lock-face", OMARCHY_PRESENT),
            ("sudo", SUDO_BEFORE),
        ]);
        let code = write_in(&only(dir.path()), &remove(&["omarchy-lock-face", "sudo"])).unwrap();

        assert_eq!(code, WRITE_OK);
        assert_eq!(read(&dir, "omarchy-lock-face"), OMARCHY_REMOVED);
        assert_eq!(read(&dir, "sudo"), SUDO_BEFORE, "no line, no rewrite");
    }

    /// The `setup --pam` alias reaches the writer through `install_one_in`,
    /// not through `write_in`, so the goldens have to cover it too — the two
    /// entry points sharing an engine is the claim, and this is what makes it
    /// a checked one rather than a comment.
    #[test]
    fn the_setup_alias_writes_the_same_bytes_as_the_verb() {
        for (service, before, after) in [
            ("sudo", SUDO_BEFORE, SUDO_AFTER),
            ("polkit-1", POLKIT_BEFORE, POLKIT_AFTER),
            ("omarchy-lock-face", OMARCHY_PRESENT, OMARCHY_PRESENT),
            ("sudo", NO_NEWLINE_BEFORE, NO_NEWLINE_AFTER),
        ] {
            let via_alias = seeded(&[(service, before)]);
            install_one_in(
                &only(via_alias.path()),
                &PamRequest {
                    allow_sensitive: true,
                    ..add(&[service])
                },
            )
            .unwrap();

            let via_verb = seeded(&[(service, before)]);
            write_in(&only(via_verb.path()), &add(&[service])).unwrap();

            assert_eq!(read(&via_alias, service), after, "{service} via the alias");
            assert_eq!(
                snapshot(via_alias.path()),
                snapshot(via_verb.path()),
                "{service}: the alias and the verb must leave the same directory"
            );
        }
    }

    /// `add` then `remove` is a round trip, which is the property that makes
    /// the rollback advice in `PamInstalled` true.
    #[test]
    fn add_then_remove_restores_the_original_bytes() {
        for before in [SUDO_BEFORE, POLKIT_BEFORE, NO_NEWLINE_BEFORE] {
            let dir = seeded(&[("sudo", before)]);
            write_in(&only(dir.path()), &add(&["sudo"])).unwrap();
            write_in(&only(dir.path()), &remove(&["sudo"])).unwrap();
            assert_eq!(read(&dir, "sudo"), before);
        }
    }

    // -- confinement --------------------------------------------------------

    #[test]
    fn one_path_component_is_the_whole_rule() {
        for good in ["sudo", "polkit-1", "omarchy-lock-face", "..x", "a\"b"] {
            assert!(confined(good).is_ok(), "{good} must be accepted");
        }
        for bad in [
            "",
            ".",
            "..",
            "/",
            "/etc/shadow",
            "../shadow",
            "a/b",
            "sudo/",
            "./sudo",
            "sudo\0",
        ] {
            assert!(confined(bad).is_err(), "{bad:?} must be rejected");
        }
    }

    /// The property `pam_remove_absolute_service_stays_anchored_under_base`
    /// protected — never touch a file outside `base` — now holds by rejecting
    /// the name before any I/O rather than by re-anchoring it. The old writer
    /// stripped a leading `/` on removal and stripped nothing on install, so
    /// `--service /etc/shadow` resolved to `/etc/shadow` on the install side.
    #[test]
    fn an_absolute_service_is_rejected_before_any_io() {
        for action in [PamAction::Add, PamAction::Remove] {
            let dir = tempfile::TempDir::new().unwrap();
            let base = dir.path().join("pam.d");
            fs::create_dir(&base).unwrap();
            let outside = dir.path().join("outside-service");
            fs::write(&outside, OMARCHY_PRESENT).unwrap();

            let request = PamRequest {
                action,
                services: vec![outside.to_str().unwrap().to_string()],
                no_confirm: true,
                if_present: true,
                ..PamRequest::default()
            };
            let error = write_in(&only(&base), &request).unwrap_err().to_string();

            assert!(error.contains("Invalid PAM service name"), "got: {error}");
            assert_eq!(fs::read_to_string(&outside).unwrap(), OMARCHY_PRESENT);
            assert!(fs::read_dir(&base).unwrap().next().is_none());
        }
    }

    #[test]
    fn a_parent_traversal_is_rejected_before_any_io() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().join("pam.d");
        fs::create_dir(&base).unwrap();
        fs::write(dir.path().join("shadow"), "root:!:1::::::\n").unwrap();

        for action in [PamAction::Add, PamAction::Remove] {
            let request = PamRequest {
                action,
                services: vec!["../shadow".to_string()],
                no_confirm: true,
                if_present: true,
                ..PamRequest::default()
            };
            assert!(write_in(&only(&base), &request).is_err());
        }
        assert_eq!(
            fs::read_to_string(dir.path().join("shadow")).unwrap(),
            "root:!:1::::::\n"
        );
    }

    // -- two-phase ----------------------------------------------------------

    /// The plan's acceptance criterion: a validation failure on service two
    /// leaves service one byte-identical and makes no backup. Without the
    /// phase split, `sudo` would already be written by the time `sshd` was
    /// rejected.
    #[test]
    fn a_validation_failure_writes_nothing_at_all() {
        for second in ["sshd", "does-not-exist", "../escape"] {
            let dir = seeded(&[("sudo", SUDO_BEFORE), ("sshd", SUDO_BEFORE)]);
            let before = snapshot(dir.path());

            let error = write_in(&only(dir.path()), &add(&["sudo", second])).unwrap_err();

            assert_eq!(
                before,
                snapshot(dir.path()),
                "`{second}` was rejected, so `sudo` must be untouched: {error}"
            );
        }
    }

    #[test]
    fn a_valid_multi_service_add_writes_every_service() {
        let dir = seeded(&[("sudo", SUDO_BEFORE), ("polkit-1", POLKIT_BEFORE)]);

        let code = write_in(&only(dir.path()), &add(&["sudo", "polkit-1"])).unwrap();

        assert_eq!(code, WRITE_OK);
        assert_eq!(read(&dir, "sudo"), SUDO_AFTER);
        assert_eq!(read(&dir, "polkit-1"), POLKIT_AFTER);
    }

    // -- the flag split -----------------------------------------------------

    /// The defect the split exists to fix: unattended and "allowed to edit
    /// system-auth" are different authorizations, and the first must never
    /// imply the second.
    #[test]
    fn no_confirm_does_not_unlock_a_sensitive_service() {
        for service in SENSITIVE_SERVICES {
            let dir = seeded(&[(service, SUDO_BEFORE)]);
            let before = snapshot(dir.path());

            let error = write_in(&only(dir.path()), &add(&[service]))
                .unwrap_err()
                .to_string();

            assert!(
                error.contains(&format!("Refusing to modify '{service}'")),
                "got: {error}"
            );
            assert!(
                error.contains("--allow-sensitive"),
                "the refusal must name the flag that unlocks it: {error}"
            );
            assert_eq!(before, snapshot(dir.path()));
        }
    }

    #[test]
    fn allow_sensitive_unlocks_it() {
        let dir = seeded(&[("sshd", SUDO_BEFORE)]);
        let request = PamRequest {
            allow_sensitive: true,
            ..add(&["sshd"])
        };

        assert_eq!(write_in(&only(dir.path()), &request).unwrap(), WRITE_OK);
        assert_eq!(read(&dir, "sshd"), SUDO_AFTER);
    }

    /// Removal is the safe direction, so it is not gated at all: a user who
    /// wired `system-auth` must be able to unwire it without arguing with the
    /// CLI about it.
    #[test]
    fn remove_is_never_gated_by_the_sensitive_list() {
        let dir = seeded(&[("system-auth", OMARCHY_PRESENT)]);

        assert_eq!(
            write_in(&only(dir.path()), &remove(&["system-auth"])).unwrap(),
            WRITE_OK
        );
        assert_eq!(read(&dir, "system-auth"), OMARCHY_REMOVED);
    }

    // -- --if-present -------------------------------------------------------

    #[test]
    fn if_present_turns_a_missing_service_into_a_no_op_on_both_verbs() {
        for action in [PamAction::Add, PamAction::Remove] {
            let dir = tempfile::TempDir::new().unwrap();
            let request = PamRequest {
                action,
                services: vec!["omarchy-lock-face".to_string()],
                no_confirm: true,
                if_present: true,
                ..PamRequest::default()
            };

            assert_eq!(write_in(&only(dir.path()), &request).unwrap(), WRITE_OK);
            assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
        }
    }

    #[test]
    fn a_missing_service_without_if_present_still_errors() {
        for request in [add(&["omarchy-lock-face"]), remove(&["omarchy-lock-face"])] {
            let dir = tempfile::TempDir::new().unwrap();

            let error = write_in(&only(dir.path()), &request)
                .unwrap_err()
                .to_string();

            assert!(
                error.contains("PAM service file not found:"),
                "got: {error}"
            );
            assert!(error.contains("omarchy-lock-face"), "got: {error}");
            assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
        }
    }

    /// `--if-present` converts a missing file into success and nothing else.
    /// A directory where a service file should be is a read failure, not an
    /// absence, and stays fatal. (The old test used `.` for this; `.` is now
    /// rejected as a service name before any I/O, so the unreadable target has
    /// to be a validly-named one.)
    #[test]
    fn if_present_does_not_suppress_other_read_errors() {
        for request in [add(&["sudo"]), remove(&["sudo"])] {
            let dir = tempfile::TempDir::new().unwrap();
            fs::create_dir(dir.path().join("sudo")).unwrap();
            let request = PamRequest {
                if_present: true,
                ..request
            };

            let error = write_in(&only(dir.path()), &request)
                .unwrap_err()
                .to_string();

            assert!(error.contains("failed to read"), "got: {error}");
        }
    }

    // -- --dry-run ----------------------------------------------------------

    #[test]
    fn dry_run_writes_nothing_and_succeeds() {
        let dir = seeded(&[
            ("sudo", SUDO_BEFORE),
            ("omarchy-lock-face", OMARCHY_PRESENT),
        ]);
        let before = snapshot(dir.path());

        for action in [PamAction::Add, PamAction::Remove] {
            let request = PamRequest {
                action,
                services: vec!["sudo".to_string(), "omarchy-lock-face".to_string()],
                dry_run: true,
                no_confirm: true,
                ..PamRequest::default()
            };
            assert_eq!(write_in(&only(dir.path()), &request).unwrap(), WRITE_OK);
        }

        assert_eq!(before, snapshot(dir.path()));
    }

    #[test]
    fn dry_run_reports_the_action_it_would_take() {
        let dir = seeded(&[
            ("sudo", SUDO_BEFORE),
            ("omarchy-lock-face", OMARCHY_PRESENT),
        ]);
        let request = PamRequest {
            dry_run: true,
            json: true,
            ..add(&["sudo", "omarchy-lock-face"])
        };
        let write = WriteRequest {
            action: WriteAction::Add,
            request: &request,
            remedy: "--x",
        };
        let targets = plan_writes(&only(dir.path()), &write).unwrap();

        let sink = Sink::verb(true);
        let words: Vec<&str> = targets
            .iter()
            .map(|t| report_plan(t, WriteAction::Add, &sink).word())
            .collect();

        assert_eq!(words, ["installed", "unchanged"]);
    }

    // -- status -------------------------------------------------------------

    #[test]
    fn status_exit_codes_follow_grep() {
        let dir = seeded(&[
            ("omarchy-lock-face", OMARCHY_PRESENT),
            ("sudo", SUDO_BEFORE),
        ]);
        let status = |services: &[&str]| {
            status_in(
                &only(dir.path()),
                &PamRequest {
                    action: PamAction::Status,
                    services: services.iter().map(|s| s.to_string()).collect(),
                    ..PamRequest::default()
                },
            )
        };

        assert_eq!(status(&["omarchy-lock-face"]), STATUS_PRESENT);
        assert_eq!(status(&["sudo"]), STATUS_MISSING);
        assert_eq!(status(&["not-a-service"]), STATUS_ERROR);
        assert_eq!(status(&["../escape"]), STATUS_ERROR, "usage error");
        // The worst outcome wins across services.
        assert_eq!(status(&["omarchy-lock-face", "sudo"]), STATUS_MISSING);
        assert_eq!(
            status(&["omarchy-lock-face", "not-a-service"]),
            STATUS_ERROR
        );
    }

    /// `status` never writes, whatever it is asked about.
    #[test]
    fn status_writes_nothing() {
        let dir = seeded(&[("sudo", SUDO_BEFORE)]);
        let before = snapshot(dir.path());

        status_in(
            &only(dir.path()),
            &PamRequest {
                action: PamAction::Status,
                services: vec!["sudo".into(), "absent".into(), "../escape".into()],
                ..PamRequest::default()
            },
        );

        assert_eq!(before, snapshot(dir.path()));
    }

    // -- JSON ---------------------------------------------------------------

    #[test]
    fn json_document_shape_is_the_contract() {
        let reports = [ServiceReport {
            service: "sudo".into(),
            path: Some("/etc/pam.d/sudo".into()),
            outcome: Outcome::Installed,
            backup: Some("/etc/pam.d/sudo.facelock-backup".into()),
            shadows: None,
        }];
        let value: serde_json::Value =
            serde_json::from_str(&report_json(PamAction::Add, false, &reports, &[])).unwrap();

        assert_eq!(value["command"], "add");
        assert_eq!(value["dry_run"], false);
        assert_eq!(value["services"][0]["service"], "sudo");
        assert_eq!(value["services"][0]["path"], "/etc/pam.d/sudo");
        assert_eq!(value["services"][0]["action"], "installed");
        assert_eq!(
            value["services"][0]["backup"],
            "/etc/pam.d/sudo.facelock-backup"
        );
        assert!(value["services"][0].get("error").is_none());
    }

    #[test]
    fn json_carries_the_error_only_when_there_is_one() {
        let reports = [
            ServiceReport {
                service: "sudo".into(),
                path: Some("/etc/pam.d/sudo".into()),
                outcome: Outcome::Failed("disk full".into()),
                backup: None,
                shadows: None,
            },
            ServiceReport {
                service: "polkit-1".into(),
                path: Some("/etc/pam.d/polkit-1".into()),
                outcome: Outcome::Unchanged,
                backup: None,
                shadows: None,
            },
        ];
        let value: serde_json::Value =
            serde_json::from_str(&report_json(PamAction::Add, false, &reports, &[])).unwrap();

        assert_eq!(value["services"][0]["action"], "failed");
        assert_eq!(value["services"][0]["error"], "disk full");
        assert_eq!(value["services"][0]["backup"], serde_json::Value::Null);
        assert!(value["services"][1].get("error").is_none());
    }

    /// **The `--json` `error` field must never carry localized text.** The
    /// human gets `PamInvalidServiceName` through the seam, on stderr, where
    /// gettext belongs; the machine field gets a fixed C-locale string. Pinned
    /// to that exact string, so re-routing `confined`'s localized error back
    /// into the row fails here instead of silently making a documented field
    /// change with `LC_MESSAGES`.
    #[test]
    fn a_rejected_name_reports_a_locale_independent_reason() {
        let dir = tempfile::TempDir::new().unwrap();
        let sink = Sink::verb(true);

        let reports = status_reports(&only(dir.path()), &["../escape".to_string()], &sink);

        assert_eq!(
            reports[0].outcome,
            Outcome::Unknown(INVALID_SERVICE_NAME.to_string())
        );
        assert_eq!(INVALID_SERVICE_NAME, "invalid service name");
        // ...and it is what lands in the document.
        let value: serde_json::Value =
            serde_json::from_str(&report_json(PamAction::Status, false, &reports, &[])).unwrap();
        assert_eq!(value["services"][0]["error"], "invalid service name");
        assert_eq!(value["services"][0]["action"], "unknown");
        // N3: a name that was rejected is never resolved, so nothing — not
        // even the backup probe — goes near the filesystem for it.
        assert_eq!(reports[0].backup, None);
    }

    /// E10: a service name reaches here from argv and confinement rejects `/`
    /// but not `"`, so the document has to be built by a serializer rather
    /// than by `format!`.
    #[test]
    fn json_escapes_a_service_name_containing_a_quote() {
        let reports = [ServiceReport {
            service: "a\"b".into(),
            path: Some("/etc/pam.d/a\"b".into()),
            outcome: Outcome::Missing,
            backup: None,
            shadows: None,
        }];
        let rendered = report_json(PamAction::Status, false, &reports, &[]);
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(value["services"][0]["service"], "a\"b");
    }

    /// Every word in the vocabulary is distinct and stable; this is the list
    /// `docs/contracts.md` documents.
    #[test]
    fn outcome_vocabulary_is_pinned() {
        let words: Vec<&str> = [
            Outcome::Installed,
            Outcome::Overridden,
            Outcome::VendorOnly,
            Outcome::Removed,
            Outcome::Unchanged,
            Outcome::Absent,
            Outcome::Declined,
            Outcome::Failed(String::new()),
            Outcome::Present,
            Outcome::Missing,
            Outcome::Unknown(String::new()),
        ]
        .iter()
        .map(Outcome::word)
        .collect();

        assert_eq!(
            words,
            [
                "installed",
                "overridden",
                "vendor-only",
                "removed",
                "unchanged",
                "absent",
                "declined",
                "failed",
                "present",
                "missing",
                "unknown",
            ]
        );
    }

    // -- misc ---------------------------------------------------------------

    #[test]
    fn no_service_means_sudo_and_duplicates_collapse() {
        assert_eq!(requested_services(&[]), [DEFAULT_PAM_SERVICE]);
        assert_eq!(
            requested_services(&["sudo".into(), "polkit-1".into(), "sudo".into()]),
            ["sudo", "polkit-1"]
        );
    }

    #[test]
    fn facelock_line_detection_ignores_spacing_and_comments() {
        assert!(is_facelock_pam_line(PAM_LINE));
        assert!(is_facelock_pam_line("auth  sufficient  pam_facelock.so"));
        assert!(!is_facelock_pam_line("#auth sufficient pam_facelock.so"));
        assert!(!is_facelock_pam_line("auth include system-login"));
    }

    /// The shared auth stacks of every distribution this runs on, plus the two
    /// single doors. Gating only Arch's spelling of the shared stack made the
    /// gate a function of the operator's distribution, which is not a security
    /// boundary.
    #[test]
    fn sensitive_services_cover_every_distributions_shared_stack() {
        for shared in [
            "system-auth",
            "system-auth-ac",
            "password-auth",
            "password-auth-ac",
            "common-auth",
            "system-login",
        ] {
            assert!(
                SENSITIVE_SERVICES.contains(&shared),
                "{shared} is a shared auth stack and must be gated"
            );
        }
        assert!(SENSITIVE_SERVICES.contains(&"login"));
        assert!(SENSITIVE_SERVICES.contains(&"sshd"));
        assert!(!SENSITIVE_SERVICES.contains(&"sudo"));
        assert!(!SENSITIVE_SERVICES.contains(&"polkit-1"));
    }

    // -- the confirmation guard ---------------------------------------------

    /// dialoguer draws and reads the prompt through `Term::stderr()`, so a
    /// redirected stderr makes it unanswerable even with stdin on a TTY —
    /// which is what `sudo facelock pam add --service sudo 2>install.log` is,
    /// and it used to report `failed` having written nothing.
    #[test]
    fn a_prompt_is_asked_only_when_both_streams_are_a_terminal() {
        for (no_confirm, stdin_tty, stderr_tty, expected) in [
            (false, true, true, true),
            (false, true, false, false),
            (false, false, true, false),
            (false, false, false, false),
            // `--no-confirm` answers before either stream is consulted.
            (true, true, true, false),
            (true, true, false, false),
            (true, false, true, false),
            (true, false, false, false),
        ] {
            assert_eq!(
                should_prompt(no_confirm, stdin_tty, stderr_tty),
                expected,
                "no_confirm={no_confirm} stdin_tty={stdin_tty} stderr_tty={stderr_tty}"
            );
        }
    }

    /// Not being asked is not a licence to write into a gated service: the
    /// gate is decided in phase one, before a prompt exists to skip.
    #[test]
    fn skipping_the_prompt_never_unlocks_the_gate() {
        let dir = seeded(&[("system-auth", SUDO_BEFORE)]);
        let before = snapshot(dir.path());

        assert!(write_in(&only(dir.path()), &add(&["system-auth"])).is_err());
        assert_eq!(before, snapshot(dir.path()));
    }

    // -- what --quiet and --json may not silence -----------------------------

    /// The preview names the file, the line and the backup path; a "Proceed?"
    /// with that suppressed is a question with no subject. So whenever the
    /// question will be asked it leaves the sink `--quiet` can reach.
    #[test]
    fn a_prompt_that_will_be_asked_keeps_its_context() {
        // Nobody is being asked: ordinary progress, suppressible.
        assert_eq!(preview_route(false, false), Route::Info);
        assert_eq!(preview_route(true, false), Route::Dropped);

        // Being asked: stdout in human mode (same bytes a normal run always
        // printed, and `--quiet` does not reach `notice`), stderr under
        // `--json`, where the prompt itself is and where stdout is holding a
        // document.
        assert_eq!(preview_route(false, true), Route::Notice);
        assert_eq!(preview_route(true, true), Route::Error);
    }

    /// The rollback instructions are the one message that tells a locked-out
    /// operator how to get back in. `--quiet` must not take them; `--json`
    /// does, because the row's `backup` field is the same fact.
    #[test]
    fn the_rollback_advice_survives_quiet() {
        // `notice` is the unsuppressible stdout sink — see
        // `message::tests::quiet_silences_stdout_except_notice`, which pins
        // that `--quiet` does not reach it.
        assert_eq!(
            Sink::human().notice_route(),
            Route::Notice,
            "the rollback advice must not be silenceable by --quiet"
        );
        assert_eq!(Sink::verb(true).notice_route(), Route::Dropped);

        let dir = seeded(&[("sudo", SUDO_BEFORE)]);
        write_in(&only(dir.path()), &add(&["sudo"])).unwrap();
        // ...and the fact it carries is the one the JSON row carries.
        assert_eq!(
            read(&dir, "sudo.facelock-backup"),
            SUDO_BEFORE,
            "the backup the advice names has to be the original file"
        );
    }

    // -- symlinked service files --------------------------------------------

    /// The authselect shape: `/etc/pam.d/system-auth` is a symlink into
    /// `/etc/authselect`. `read`/`copy`/`write` follow it, so without this the
    /// writer edits a generated file — which authselect regenerates away —
    /// and drops the backup beside the link rather than beside what changed.
    #[test]
    fn a_symlink_out_of_base_is_a_validation_failure() {
        for action in [PamAction::Add, PamAction::Remove] {
            let dir = tempfile::TempDir::new().unwrap();
            let base = dir.path().join("pam.d");
            fs::create_dir(&base).unwrap();
            let outside = dir.path().join("authselect-system-auth");
            fs::write(&outside, OMARCHY_PRESENT).unwrap();
            std::os::unix::fs::symlink(&outside, base.join("system-auth")).unwrap();

            let request = PamRequest {
                action,
                services: vec!["system-auth".to_string()],
                no_confirm: true,
                allow_sensitive: true,
                ..PamRequest::default()
            };
            let error = write_in(&only(&base), &request).unwrap_err().to_string();

            assert!(error.contains("it is a symlink to"), "got: {error}");
            assert!(
                error.contains(outside.to_str().unwrap()),
                "the refusal must name the target: {error}"
            );
            assert_eq!(
                fs::read_to_string(&outside).unwrap(),
                OMARCHY_PRESENT,
                "nothing outside the directory may be written"
            );
            assert!(
                !backup_path(&outside).exists(),
                "and nothing outside it may gain a backup"
            );
        }
    }

    /// `..` inside the *link* is the same escape as `..` inside the name, and
    /// `confined` cannot see it: the name is one component either way.
    #[test]
    fn a_symlink_traversing_out_of_base_is_rejected_too() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().join("pam.d");
        fs::create_dir(&base).unwrap();
        fs::write(dir.path().join("shadow"), "root:!:1::::::\n").unwrap();
        std::os::unix::fs::symlink("../shadow", base.join("sudo")).unwrap();

        assert!(write_in(&only(&base), &add(&["sudo"])).is_err());
        assert_eq!(
            fs::read_to_string(dir.path().join("shadow")).unwrap(),
            "root:!:1::::::\n"
        );
    }

    /// A link that stays inside the directory is the operator's own alias for
    /// a file they asked about, so it is followed — and the write and the
    /// backup both land on the real file, not beside the link.
    #[test]
    fn a_symlink_inside_base_is_followed_to_the_real_file() {
        let dir = seeded(&[("sudo", SUDO_BEFORE)]);
        std::os::unix::fs::symlink("sudo", dir.path().join("sudo-alias")).unwrap();

        assert_eq!(
            write_in(&only(dir.path()), &add(&["sudo-alias"])).unwrap(),
            WRITE_OK
        );

        assert_eq!(read(&dir, "sudo"), SUDO_AFTER, "the real file is rewritten");
        assert_eq!(read(&dir, "sudo.facelock-backup"), SUDO_BEFORE);
        assert!(
            !dir.path().join("sudo-alias.facelock-backup").exists(),
            "the backup belongs beside the file that changed"
        );
        assert!(
            dir.path().join("sudo-alias").is_symlink(),
            "the link itself must not be replaced by a regular file"
        );
    }

    /// A validation failure, so the two-phase rule covers it: a run naming a
    /// good service and an escaping one writes nothing at all.
    #[test]
    fn a_symlink_rejection_writes_nothing_for_the_whole_run() {
        let dir = seeded(&[("sudo", SUDO_BEFORE)]);
        let outside = dir.path().parent().unwrap().join("facelock-escape-target");
        fs::write(&outside, SUDO_BEFORE).unwrap();
        std::os::unix::fs::symlink(&outside, dir.path().join("polkit-1")).unwrap();
        let before = snapshot(dir.path());

        assert!(write_in(&only(dir.path()), &add(&["sudo", "polkit-1"])).is_err());

        assert_eq!(before, snapshot(dir.path()));
        fs::remove_file(&outside).unwrap();
    }

    /// `status` has no all-or-nothing phase, so the same rejection is a row
    /// rather than an `Err` — with a fixed C-locale reason, like a rejected
    /// name, and exit 2.
    #[test]
    fn status_reports_an_escaping_symlink_as_unknown() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().join("pam.d");
        fs::create_dir(&base).unwrap();
        let outside = dir.path().join("authselect-system-auth");
        fs::write(&outside, OMARCHY_PRESENT).unwrap();
        std::os::unix::fs::symlink(&outside, base.join("system-auth")).unwrap();

        let sink = Sink::verb(true);
        let reports = status_reports(&only(&base), &["system-auth".to_string()], &sink);

        assert_eq!(
            reports[0].outcome,
            Outcome::Unknown(SYMLINKED_OUT_OF_DIR.to_string())
        );
        assert_eq!(SYMLINKED_OUT_OF_DIR, "symlinked outside /etc/pam.d");
        // The link is a real, confined path this did `lstat`, unlike a
        // rejected name — so it is reported rather than nulled.
        assert_eq!(
            reports[0].path,
            Some(base.join("system-auth").display().to_string())
        );
        assert_eq!(
            status_in(
                &only(&base),
                &PamRequest {
                    action: PamAction::Status,
                    services: vec!["system-auth".to_string()],
                    ..PamRequest::default()
                }
            ),
            STATUS_ERROR
        );
    }

    /// A second *hard* link cannot be followed and checked the way a symlink
    /// can: the link count says another name exists and not where it is, so an
    /// edit here changes a file this cannot name.
    /// The same rule, reached through an in-directory alias — which is how it
    /// was bypassable: the link count was checked on the entry as typed and
    /// not on the file the entry reached, exactly the hole `gate_sensitive`'s
    /// second call exists to close.
    ///
    /// The shape is the one `SENSITIVE_SERVICES`' own doc describes: RHEL's
    /// `authconfig` leaves `system-auth -> system-auth-ac`, and a dedupe pass
    /// (`jdupes -L`, a hard-link-preserving restore) links `password-auth-ac`
    /// onto the same inode. Under the atomic replace, `remove --service
    /// system-auth` would then report `removed` while `password-auth-ac` — the
    /// stack sshd reads on that distribution — kept the facelock line: a
    /// fail-open on the shared auth stack, reported as success, with no backup
    /// to show what happened.
    #[test]
    fn a_hard_link_reached_through_an_alias_is_refused_too() {
        for action in [PamAction::Add, PamAction::Remove] {
            let dir = tempfile::TempDir::new().unwrap();
            let base = dir.path().join("pam.d");
            fs::create_dir(&base).unwrap();
            let real = base.join("system-auth-ac");
            fs::write(&real, OMARCHY_PRESENT).unwrap();
            let sibling = base.join("password-auth-ac");
            fs::hard_link(&real, &sibling).unwrap();
            std::os::unix::fs::symlink("system-auth-ac", base.join("system-auth")).unwrap();
            let before = snapshot(&base);

            let request = PamRequest {
                action,
                services: vec!["system-auth".to_string()],
                no_confirm: true,
                allow_sensitive: true,
                ..PamRequest::default()
            };
            let error = write_in(&only(&base), &request).unwrap_err().to_string();

            assert!(error.contains("names for the same file"), "got: {error}");
            assert!(
                error.contains(real.to_str().unwrap()),
                "the refusal names the file with two names, which is where the \
                 fix has to be applied: {error}"
            );
            assert_eq!(
                before,
                snapshot(&base),
                "{action:?}: nothing may be written for the whole run"
            );
            assert_eq!(
                fs::read_to_string(&sibling).unwrap(),
                OMARCHY_PRESENT,
                "{action:?}: the other name still carries the facelock line, \
                 which is the fail-open this refusal prevents"
            );
        }

        // ...and `status`, which has no all-or-nothing phase, reports it as
        // the same `unknown` an entry it will not follow always got.
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().join("pam.d");
        fs::create_dir(&base).unwrap();
        fs::write(base.join("real"), OMARCHY_PRESENT).unwrap();
        fs::hard_link(base.join("real"), base.join("second-name")).unwrap();
        std::os::unix::fs::symlink("real", base.join("alias")).unwrap();

        let sink = Sink::verb(true);
        let reports = status_reports(&only(&base), &["alias".to_string()], &sink);
        assert_eq!(
            reports[0].outcome,
            Outcome::Unknown(HARD_LINKED.to_string())
        );
        assert_eq!(status_code(&reports[0].outcome, false), STATUS_ERROR);
    }

    #[test]
    fn a_hard_linked_service_file_is_a_validation_failure() {
        for action in [PamAction::Add, PamAction::Remove] {
            let dir = tempfile::TempDir::new().unwrap();
            let base = dir.path().join("pam.d");
            fs::create_dir(&base).unwrap();
            let outside = dir.path().join("second-name");
            fs::write(&outside, OMARCHY_PRESENT).unwrap();
            fs::hard_link(&outside, base.join("sudo")).unwrap();

            let request = PamRequest {
                action,
                services: vec!["sudo".to_string()],
                no_confirm: true,
                ..PamRequest::default()
            };
            let error = write_in(&only(&base), &request).unwrap_err().to_string();

            assert!(error.contains("names for the same file"), "got: {error}");
            assert_eq!(
                fs::read_to_string(&outside).unwrap(),
                OMARCHY_PRESENT,
                "the file behind the other name must be untouched"
            );
            assert!(!backup_path(&base.join("sudo")).exists());
        }
    }

    /// One name is the normal case and must stay quiet — the check is
    /// `nlink > 1`, not "is a link".
    #[test]
    fn a_single_linked_service_file_is_untouched_by_the_rule() {
        let dir = seeded(&[("sudo", SUDO_BEFORE)]);
        assert_eq!(
            write_in(&only(dir.path()), &add(&["sudo"])).unwrap(),
            WRITE_OK
        );
        assert_eq!(read(&dir, "sudo"), SUDO_AFTER);
    }

    /// `status` answers with a row rather than an `Err`, with the fixed
    /// C-locale reason and exit 2.
    #[test]
    fn status_reports_a_hard_linked_service_as_unknown() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().join("pam.d");
        fs::create_dir(&base).unwrap();
        fs::write(dir.path().join("second-name"), OMARCHY_PRESENT).unwrap();
        fs::hard_link(dir.path().join("second-name"), base.join("sudo")).unwrap();

        let sink = Sink::verb(true);
        let reports = status_reports(&only(&base), &["sudo".to_string()], &sink);

        assert_eq!(
            reports[0].outcome,
            Outcome::Unknown(HARD_LINKED.to_string())
        );
        assert_eq!(HARD_LINKED, "hard-linked service file");
        assert_eq!(
            status_in(
                &only(&base),
                &PamRequest {
                    action: PamAction::Status,
                    services: vec!["sudo".to_string()],
                    ..PamRequest::default()
                }
            ),
            STATUS_ERROR
        );
    }

    // -- the gate follows the file, not the name -----------------------------

    /// A symlink *inside* the directory is followed, so the name typed on the
    /// command line is not the only way to reach a gated file. Without the
    /// second check, `--service alias` installs into `system-auth` with no
    /// `--allow-sensitive` anywhere in the invocation.
    #[test]
    fn the_sensitive_gate_follows_a_link_to_the_real_file() {
        let make = || {
            let dir = seeded(&[("system-auth", SUDO_BEFORE)]);
            std::os::unix::fs::symlink("system-auth", dir.path().join("alias")).unwrap();
            dir
        };

        let refused = make();
        let before = snapshot(refused.path());
        let error = write_in(&only(refused.path()), &add(&["alias"]))
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("Refusing to modify 'system-auth'"),
            "the refusal names the file the link reaches: {error}"
        );
        assert!(error.contains("--allow-sensitive"), "got: {error}");
        assert_eq!(before, snapshot(refused.path()), "and writes nothing");

        // ...and the flag still unlocks it, through the link.
        let allowed = make();
        let request = PamRequest {
            allow_sensitive: true,
            ..add(&["alias"])
        };
        assert_eq!(write_in(&only(allowed.path()), &request).unwrap(), WRITE_OK);
        assert_eq!(read(&allowed, "system-auth"), SUDO_AFTER);
    }

    /// The gate is `add`-only and stays that way on the resolved file too:
    /// unwiring a gated service must not need an argument about it.
    #[test]
    fn the_resolved_gate_does_not_reach_remove() {
        let dir = seeded(&[("system-auth", OMARCHY_PRESENT)]);
        std::os::unix::fs::symlink("system-auth", dir.path().join("alias")).unwrap();

        assert_eq!(
            write_in(&only(dir.path()), &remove(&["alias"])).unwrap(),
            WRITE_OK
        );
        assert_eq!(read(&dir, "system-auth"), OMARCHY_REMOVED);
    }

    // -- status --if-present -------------------------------------------------

    /// The pair that could not be written before: install the optional
    /// integrations with `--if-present`, then verify with the same flag. Only
    /// absence is converted — an unreadable file or a bad name is still 2.
    #[test]
    fn status_if_present_stops_an_absent_service_forcing_exit_2() {
        let dir = seeded(&[
            ("omarchy-lock-face", OMARCHY_PRESENT),
            ("sudo", SUDO_BEFORE),
        ]);
        let status = |services: &[&str], if_present| {
            status_in(
                &only(dir.path()),
                &PamRequest {
                    action: PamAction::Status,
                    services: services.iter().map(|s| s.to_string()).collect(),
                    if_present,
                    ..PamRequest::default()
                },
            )
        };

        assert_eq!(status(&["not-a-service"], false), STATUS_ERROR);
        assert_eq!(status(&["not-a-service"], true), STATUS_PRESENT);
        // The services that do exist still decide the answer.
        assert_eq!(
            status(&["omarchy-lock-face", "not-a-service"], true),
            STATUS_PRESENT
        );
        assert_eq!(status(&["sudo", "not-a-service"], true), STATUS_MISSING);
        // ...and it converts absence only.
        assert_eq!(status(&["../escape"], true), STATUS_ERROR);
    }

    /// `install_for_setup` edits `/etc/pam.d` and `run_with_plan` reaches it
    /// directly for a standalone `--pam`, so it must refuse non-root itself
    /// (C6: before any other check and any output). Regression: routing
    /// standalone `--pam` through it once let an unprivileged `facelock setup
    /// --pam` read and report on `/etc/pam.d/sudo`.
    #[test]
    fn setup_alias_refuses_without_root() {
        if nix::unistd::Uid::current().is_root() {
            return; // the check cannot fire; nothing to assert
        }
        for error in [
            install_for_setup(&PamRequest {
                allow_sensitive: true,
                ..add(&["sudo"])
            })
            .unwrap_err(),
            remove_for_setup(&PamRequest {
                if_present: true,
                ..remove(&["sudo"])
            })
            .unwrap_err(),
        ] {
            let error = error.to_string();
            assert!(
                error.contains("Root required"),
                "expected the root refusal before any other check, got: {error}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Vendor directories (P1)
    //
    // The bug these exist for: on current Arch `polkit` ships
    // /usr/lib/pam.d/polkit-1 and /etc/pam.d/polkit-1 does not exist, so a
    // writer that only ever looked in /etc/pam.d could not configure the
    // service at all. Every case below is driven against a tempdir *pair*,
    // which is what the search path being a parameter is for.
    // -----------------------------------------------------------------------

    /// An `/etc` directory and a vendor directory, in that order.
    fn pair() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let root = tempfile::TempDir::new().unwrap();
        let etc = root.path().join("etc");
        let vendor = root.path().join("vendor");
        fs::create_dir(&etc).unwrap();
        fs::create_dir(&vendor).unwrap();
        (root, etc, vendor)
    }

    fn both(etc: &Path, vendor: &Path) -> PamDirs {
        PamDirs::new(vec![etc.to_path_buf(), vendor.to_path_buf()])
    }

    fn header_lines(content: &str) -> usize {
        content
            .lines()
            .filter(|line| line.starts_with("# Copied from "))
            .count()
    }

    /// The headline case. The vendor file is read, an `/etc` override is
    /// created from it with the line in place, and the package's own file is
    /// byte-identical afterwards — asserted on the bytes, because the failure
    /// this guards against is a successful-looking run that edited `/usr`.
    #[test]
    fn a_vendor_only_service_gets_an_etc_override() {
        let (_root, etc, vendor) = pair();
        fs::write(vendor.join("polkit-1"), POLKIT_BEFORE).unwrap();
        let before = snapshot(&vendor);

        let sink = Sink::verb(false);
        let write = WriteRequest {
            action: WriteAction::Add,
            request: &add(&["polkit-1"]),
            remedy: "--allow-sensitive",
        };
        let targets = plan_writes(&both(&etc, &vendor), &write).unwrap();
        let reports = apply_all(&targets, &write, &sink);

        assert_eq!(reports[0].outcome, Outcome::Overridden);
        assert_eq!(
            reports[0].path.as_deref(),
            Some(etc.join("polkit-1").to_str().unwrap()),
            "the row is about the file that was created, not the one that was read"
        );
        assert_eq!(reports[0].backup, None, "a copy has nothing to back up");

        let written = fs::read_to_string(etc.join("polkit-1")).unwrap();
        assert_eq!(header_lines(&written), 1);
        assert!(
            written.ends_with(POLKIT_AFTER),
            "below the header the bytes are what an in-place edit would have \
             produced: {written}"
        );
        assert_eq!(before, snapshot(&vendor), "the vendor file is untouched");
    }

    /// Second `add`: the override now exists, so the service resolves in
    /// `/etc` and is edited in place — no copy, no second header, and the
    /// vendor file still untouched.
    #[test]
    fn a_second_add_edits_the_override_and_writes_no_second_header() {
        let (_root, etc, vendor) = pair();
        fs::write(vendor.join("polkit-1"), POLKIT_BEFORE).unwrap();
        let dirs = both(&etc, &vendor);
        let before = snapshot(&vendor);

        assert_eq!(write_in(&dirs, &add(&["polkit-1"])).unwrap(), WRITE_OK);
        let first = fs::read_to_string(etc.join("polkit-1")).unwrap();
        assert_eq!(write_in(&dirs, &add(&["polkit-1"])).unwrap(), WRITE_OK);
        let second = fs::read_to_string(etc.join("polkit-1")).unwrap();

        assert_eq!(first, second, "the second add is a no-op");
        assert_eq!(header_lines(&second), 1);
        assert_eq!(before, snapshot(&vendor));

        // ...and a service that was in `/etc` all along never gains a header
        // at all.
        let (_root2, etc2, vendor2) = pair();
        fs::write(etc2.join("sudo"), SUDO_BEFORE).unwrap();
        fs::write(vendor2.join("sudo"), POLKIT_BEFORE).unwrap();
        write_in(&both(&etc2, &vendor2), &add(&["sudo"])).unwrap();

        assert_eq!(
            fs::read_to_string(etc2.join("sudo")).unwrap(),
            SUDO_AFTER,
            "an /etc entry shadows the vendor one and is edited byte for byte"
        );
        assert_eq!(
            fs::read_to_string(vendor2.join("sudo")).unwrap(),
            POLKIT_BEFORE
        );
    }

    /// `remove` resolves the same way so it can *report* a vendor-only
    /// service, and then writes nothing: exit 0, no `/etc` file invented, the
    /// package's file untouched.
    #[test]
    fn remove_on_a_vendor_only_service_is_a_no_op() {
        let (_root, etc, vendor) = pair();
        fs::write(vendor.join("polkit-1"), OMARCHY_PRESENT).unwrap();
        let before = snapshot(&vendor);

        let code = write_in(&both(&etc, &vendor), &remove(&["polkit-1"])).unwrap();

        assert_eq!(code, WRITE_OK);
        assert!(snapshot(&etc).is_empty(), "removal creates nothing");
        assert_eq!(
            before,
            snapshot(&vendor),
            "not even a vendor file that carries the line is edited"
        );
    }

    /// The not-found refusal names **every** path tried. Naming only
    /// `/etc/pam.d` would send an operator to create a file that a vendor
    /// directory may already hold.
    #[test]
    fn an_absent_service_names_every_directory_searched() {
        let (_root, etc, vendor) = pair();

        let error = write_in(&both(&etc, &vendor), &add(&["polkit-1"]))
            .unwrap_err()
            .to_string();

        assert!(
            error.contains("PAM service file not found:"),
            "got: {error}"
        );
        for dir in [&etc, &vendor] {
            let path = dir.join("polkit-1");
            assert!(
                error.contains(path.to_str().unwrap()),
                "the refusal must name {}: {error}",
                path.display()
            );
        }
    }

    /// `status` on a vendor-only service reports it as itself — not `absent`,
    /// which would be false about the file, and not `missing`, which would be
    /// misleading about what `add` is going to do. Exit 1: the service exists
    /// and does not carry the line.
    #[test]
    fn status_reports_a_vendor_only_service_as_vendor_only() {
        let (_root, etc, vendor) = pair();
        fs::write(vendor.join("polkit-1"), POLKIT_BEFORE).unwrap();

        let sink = Sink::verb(true);
        let reports = status_reports(&both(&etc, &vendor), &["polkit-1".to_string()], &sink);

        assert_eq!(reports[0].outcome, Outcome::VendorOnly);
        assert_eq!(reports[0].outcome.word(), "vendor-only");
        assert_eq!(
            reports[0].path.as_deref(),
            Some(vendor.join("polkit-1").to_str().unwrap()),
            "the row names the file that exists"
        );
        assert_eq!(status_code(&reports[0].outcome, false), STATUS_MISSING);
        // `--if-present` converts absence and nothing else; this is not one.
        assert_eq!(status_code(&reports[0].outcome, true), STATUS_MISSING);
    }

    /// ...unless the vendor file already carries the line, which is a
    /// distribution shipping face auth in its own PAM stack. That machine *is*
    /// configured, and reporting `vendor-only` would send an integrator off to
    /// create an override that adds nothing.
    #[test]
    fn a_vendor_file_that_carries_the_line_is_present() {
        let (_root, etc, vendor) = pair();
        fs::write(vendor.join("omarchy-lock-face"), OMARCHY_PRESENT).unwrap();
        let dirs = both(&etc, &vendor);

        let sink = Sink::verb(true);
        let reports = status_reports(&dirs, &["omarchy-lock-face".to_string()], &sink);
        assert_eq!(reports[0].outcome, Outcome::Present);
        assert!(is_configured(&dirs, "omarchy-lock-face"));

        // ...and `add` writes no override for it, because there is nothing an
        // override would add.
        assert_eq!(
            write_in(&dirs, &add(&["omarchy-lock-face"])).unwrap(),
            WRITE_OK
        );
        assert!(snapshot(&etc).is_empty());
    }

    /// First hit wins, and only the first directory is ever written to.
    #[test]
    fn the_first_directory_holding_the_name_answers() {
        let (_root, etc, vendor) = pair();
        fs::write(etc.join("sudo"), SUDO_BEFORE).unwrap();
        fs::write(vendor.join("sudo"), OMARCHY_PRESENT).unwrap();
        let dirs = both(&etc, &vendor);

        let target = Target::locate(&dirs, "sudo").unwrap();

        assert_eq!(target.path, etc.join("sudo"));
        assert_eq!(target.origin, Origin::Local);
        assert_eq!(target.write_path(), etc.join("sudo"));
    }

    /// The multi-directory restatement of #194's symlink rule: the target must
    /// be under the directory the *entry* was found in, so an `/etc` entry
    /// pointing into a vendor directory is out of base and refused. Decided
    /// deliberately, and written down in contracts.md: following it would put
    /// an edit in a package-owned file, which is the one thing this must never
    /// do.
    #[test]
    fn an_etc_entry_symlinked_into_a_vendor_directory_is_refused() {
        let (_root, etc, vendor) = pair();
        fs::write(vendor.join("polkit-1"), POLKIT_BEFORE).unwrap();
        std::os::unix::fs::symlink(vendor.join("polkit-1"), etc.join("polkit-1")).unwrap();
        let before = snapshot(&vendor);

        let error = write_in(&both(&etc, &vendor), &add(&["polkit-1"]))
            .unwrap_err()
            .to_string();

        assert!(error.contains("it is a symlink to"), "got: {error}");
        assert!(
            error.contains(etc.to_str().unwrap()),
            "the refusal names the directory that was violated: {error}"
        );
        assert_eq!(before, snapshot(&vendor));
        assert!(!backup_path(&vendor.join("polkit-1")).exists());
    }

    /// The sensitive gate is applied to the file the name resolved to, in
    /// whichever directory that was: a vendor `system-auth` reached under an
    /// ungated alias still refuses.
    #[test]
    fn the_sensitive_gate_reaches_a_vendor_file() {
        let (_root, etc, vendor) = pair();
        fs::write(vendor.join("system-auth"), SUDO_BEFORE).unwrap();
        std::os::unix::fs::symlink("system-auth", vendor.join("harmless")).unwrap();
        let dirs = both(&etc, &vendor);

        for service in ["system-auth", "harmless"] {
            let error = write_in(&dirs, &add(&[service])).unwrap_err().to_string();
            assert!(
                error.contains("sensitive PAM service"),
                "{service}: got {error}"
            );
        }
        assert!(snapshot(&etc).is_empty(), "a refusal writes nothing");
    }

    /// `--dry-run` previews the copy and writes nothing — including the
    /// override it says it would create.
    #[test]
    fn dry_run_on_a_vendor_only_service_writes_nothing() {
        let (_root, etc, vendor) = pair();
        fs::write(vendor.join("polkit-1"), POLKIT_BEFORE).unwrap();
        let before = snapshot(&vendor);

        let request = PamRequest {
            dry_run: true,
            ..add(&["polkit-1"])
        };
        let sink = Sink::verb(false);
        let write = WriteRequest {
            action: WriteAction::Add,
            request: &request,
            remedy: "--allow-sensitive",
        };
        let targets = plan_writes(&both(&etc, &vendor), &write).unwrap();
        let reports = apply_all(&targets, &write, &sink);

        assert_eq!(reports[0].outcome, Outcome::Overridden);
        assert!(snapshot(&etc).is_empty());
        assert_eq!(before, snapshot(&vendor));
    }

    /// The wizard's menu asks the resolver, so a candidate that ships only in
    /// a vendor directory is offered — which is the half of this bug that
    /// would otherwise have kept `polkit-1` out of `setup`'s multi-select on
    /// exactly the machines where `pam add` had just started working.
    #[test]
    fn a_vendor_only_candidate_is_visible_to_the_wizard() {
        let (_root, etc, vendor) = pair();
        let dirs = both(&etc, &vendor);

        assert!(!service_exists(&dirs, "polkit-1"));
        fs::write(vendor.join("polkit-1"), POLKIT_BEFORE).unwrap();
        assert!(service_exists(&dirs, "polkit-1"));

        // An entry the writer would refuse is not offered: the menu must not
        // propose a service that then fails.
        std::os::unix::fs::symlink(vendor.join("polkit-1"), etc.join("hyprlock")).unwrap();
        assert!(!service_exists(&dirs, "hyprlock"));
    }

    // -- the atomic replace -------------------------------------------------

    /// Mode and owner are carried across, because the replace writes a *new*
    /// inode: a service file that came back 0644 when it was 0640, or owned by
    /// the wrong group, is a permissions regression on the file that decides
    /// whether the machine can be logged into.
    #[test]
    fn an_in_place_edit_keeps_the_files_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = seeded(&[("sudo", SUDO_BEFORE)]);
        let path = dir.path().join("sudo");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();

        write_in(&only(dir.path()), &add(&["sudo"])).unwrap();

        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o640
        );
        assert_eq!(read(&dir, "sudo"), SUDO_AFTER);
    }

    /// A vendor copy takes the vendor file's mode: it is the only provenance
    /// there is for a file that did not exist a moment ago.
    #[test]
    fn a_vendor_copy_takes_the_vendor_files_mode() {
        use std::os::unix::fs::PermissionsExt;

        let (_root, etc, vendor) = pair();
        let source = vendor.join("polkit-1");
        fs::write(&source, POLKIT_BEFORE).unwrap();
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).unwrap();

        write_in(&both(&etc, &vendor), &add(&["polkit-1"])).unwrap();

        assert_eq!(
            fs::metadata(etc.join("polkit-1"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
    }

    /// A failed replace leaves no debris. The temp file is what a reader of
    /// `/etc/pam.d` would otherwise find sitting next to the service files.
    #[test]
    fn a_failed_replace_removes_its_temp_file() {
        let dir = tempfile::TempDir::new().unwrap();
        // A directory where the destination file should be: the rename cannot
        // land, so the write fails after the temp file has been created.
        fs::create_dir(dir.path().join("sudo")).unwrap();

        assert!(replace_atomically(&dir.path().join("sudo"), "x\n", dir.path()).is_err());

        let leftovers: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != "sudo")
            .collect();
        assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
    }

    /// A successful run leaves none either — the assertion the goldens cannot
    /// make, since `snapshot` compares two runs and a temp file present in
    /// both would cancel out.
    #[test]
    fn a_successful_write_leaves_no_temp_file() {
        let dir = seeded(&[("sudo", SUDO_BEFORE)]);
        write_in(&only(dir.path()), &add(&["sudo"])).unwrap();

        let names: Vec<String> = snapshot(dir.path()).into_keys().collect();
        assert_eq!(names, ["sudo", "sudo.facelock-backup"]);
    }

    /// An override that cannot be created is refused in **phase one**, so a
    /// run naming a good service and a vendor-only one on a read-only `/etc`
    /// writes nothing at all.
    #[test]
    fn an_unwritable_override_directory_is_a_phase_one_refusal() {
        use std::os::unix::fs::PermissionsExt;

        // Root ignores the mode bits, so the check this asserts cannot fail
        // for root and the test would be vacuous.
        if nix::unistd::Uid::effective().is_root() {
            return;
        }

        let (_root, etc, vendor) = pair();
        fs::write(etc.join("sudo"), SUDO_BEFORE).unwrap();
        fs::write(vendor.join("polkit-1"), POLKIT_BEFORE).unwrap();
        fs::set_permissions(&etc, fs::Permissions::from_mode(0o555)).unwrap();
        let before = snapshot(&etc);

        let error = write_in(&both(&etc, &vendor), &add(&["sudo", "polkit-1"]))
            .unwrap_err()
            .to_string();

        assert!(error.contains("not writable"), "got: {error}");
        assert_eq!(before, snapshot(&etc), "phase one writes nothing at all");
        fs::set_permissions(&etc, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// An `overridden` row never reports a backup, even when a
    /// `.facelock-backup` is lying at the override path from an earlier run:
    /// the copy preserved nothing, so that file is not this run's rollback and
    /// offering it would promise a restore of a file this did not touch.
    #[test]
    fn an_override_reports_no_backup_even_when_a_stale_one_exists() {
        let (_root, etc, vendor) = pair();
        fs::write(vendor.join("polkit-1"), POLKIT_BEFORE).unwrap();
        // What an earlier add-then-`rm`-the-override leaves behind.
        fs::write(etc.join("polkit-1.facelock-backup"), SUDO_BEFORE).unwrap();

        let sink = Sink::verb(false);
        let write = WriteRequest {
            action: WriteAction::Add,
            request: &add(&["polkit-1"]),
            remedy: "--allow-sensitive",
        };
        let targets = plan_writes(&both(&etc, &vendor), &write).unwrap();
        let reports = apply_all(&targets, &write, &sink);

        assert_eq!(reports[0].outcome, Outcome::Overridden);
        assert_eq!(reports[0].backup, None);
        assert_eq!(
            fs::read_to_string(etc.join("polkit-1.facelock-backup")).unwrap(),
            SUDO_BEFORE,
            "and the stale file is left exactly as it was found"
        );
    }

    /// `status` answers "where did you look?" the way `add` does. The row's
    /// machine `path` stays the single first-directory path, which is where an
    /// override would go.
    #[test]
    fn status_on_an_absent_service_names_every_directory_searched() {
        let (_root, etc, vendor) = pair();
        let dirs = both(&etc, &vendor);

        let target = Target::locate(&dirs, "polkit-1").unwrap();
        let tried = target.tried_paths();

        for dir in [&etc, &vendor] {
            let path = dir.join("polkit-1");
            assert!(
                tried.contains(path.to_str().unwrap()),
                "{} unnamed: {tried}",
                path.display()
            );
        }

        let sink = Sink::verb(true);
        let reports = status_reports(&dirs, &["polkit-1".to_string()], &sink);
        assert_eq!(reports[0].outcome, Outcome::Absent);
        assert_eq!(
            reports[0].path.as_deref(),
            Some(etc.join("polkit-1").to_str().unwrap()),
            "the machine field is one path: where an override would go"
        );
    }

    /// A relative `config_dirs` entry poisons the whole list. A relative first
    /// entry would resolve the write target against the invoking shell's
    /// working directory, so `cd /tmp && sudo facelock pam add` would edit
    /// `/tmp/<dir>/sudo` and report it as though it were `/etc/pam.d/sudo`.
    #[test]
    fn a_relative_config_dir_falls_back_to_the_default_list() {
        for list in [
            vec![PathBuf::from("pam.d")],
            // ...and a relative entry anywhere poisons it, not just first: a
            // list with a hole in it is not the search order anyone wrote.
            vec![PathBuf::from("/etc/pam.d"), PathBuf::from("vendor/pam.d")],
        ] {
            assert_eq!(
                PamDirs::new(list.clone()),
                PamDirs::default(),
                "{list:?} must not be used as a search path"
            );
        }

        assert_eq!(
            PamDirs::new(vec![PathBuf::from("/a"), PathBuf::from("/b")]),
            PamDirs::new(vec![PathBuf::from("/a"), PathBuf::from("/b")]),
            "an absolute list is taken as written"
        );
        assert_eq!(
            PamDirs::new(vec![PathBuf::from("/a")]).overrides(),
            Path::new("/a")
        );
    }

    /// The backup is a write like any other, so it goes through the same
    /// atomic replace — which is what makes a symlink planted at
    /// `<service>.facelock-backup` harmless. `fs::copy` opened its destination
    /// `O_CREAT|O_TRUNC` and followed the link, sending the service file's
    /// bytes wherever it pointed; `rename` replaces the name.
    #[test]
    fn a_symlinked_backup_path_is_replaced_not_followed() {
        let dir = tempfile::TempDir::new().unwrap();
        let base = dir.path().join("pam.d");
        fs::create_dir(&base).unwrap();
        fs::write(base.join("sudo"), SUDO_BEFORE).unwrap();
        let victim = dir.path().join("victim");
        fs::write(&victim, "SECRET-CONTENT\n").unwrap();
        std::os::unix::fs::symlink(&victim, backup_path(&base.join("sudo"))).unwrap();

        assert_eq!(write_in(&only(&base), &add(&["sudo"])).unwrap(), WRITE_OK);

        assert_eq!(
            fs::read_to_string(&victim).unwrap(),
            "SECRET-CONTENT\n",
            "the file the planted link pointed at must not be written"
        );
        let backup = backup_path(&base.join("sudo"));
        assert!(!backup.is_symlink(), "the link is replaced, not followed");
        assert_eq!(fs::read_to_string(&backup).unwrap(), SUDO_BEFORE);
        assert_eq!(fs::read_to_string(base.join("sudo")).unwrap(), SUDO_AFTER);
    }

    /// An entry that exists but cannot be examined is **not** an absence. It
    /// stops the search where it is, so the read that follows reports the
    /// error — the answer the single-directory writer gave for the same input.
    /// Falling through instead made `status` report `vendor-only` for a
    /// service the unreadable override configures: an honest failure turned
    /// into a confident wrong answer, and on `add` it would have renamed a
    /// copy of the vendor file over the override without taking a backup.
    #[test]
    fn an_unreadable_first_directory_is_not_an_absence() {
        use std::os::unix::fs::PermissionsExt;

        // Root traverses a 0000 directory, so the stat would succeed and the
        // assertion would be vacuous.
        if nix::unistd::Uid::effective().is_root() {
            return;
        }

        let (_root, etc, vendor) = pair();
        fs::write(etc.join("polkit-1"), OMARCHY_PRESENT).unwrap();
        fs::write(vendor.join("polkit-1"), POLKIT_BEFORE).unwrap();
        let dirs = both(&etc, &vendor);
        fs::set_permissions(&etc, fs::Permissions::from_mode(0o000)).unwrap();

        let sink = Sink::verb(true);
        let reports = status_reports(&dirs, &["polkit-1".to_string()], &sink);
        let outcome = reports[0].outcome.clone();
        let path = reports[0].path.clone();
        // Restore before asserting, so a failure does not leave a 0000
        // directory behind for the tempdir teardown to trip over.
        fs::set_permissions(&etc, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(
            matches!(outcome, Outcome::Unknown(_)),
            "expected an honest non-answer, got {outcome:?}"
        );
        assert_eq!(status_code(&outcome, false), STATUS_ERROR);
        assert_eq!(
            path.as_deref(),
            Some(etc.join("polkit-1").to_str().unwrap()),
            "and it is about the entry it could not examine, not the vendor copy"
        );
    }

    /// The override directory may not also be one of the read-only ones,
    /// however it is spelled: that would make "never write to a vendor
    /// directory" false without anyone editing this module.
    #[test]
    fn an_override_directory_that_aliases_a_search_directory_is_rejected() {
        let (_root, etc, vendor) = pair();
        let link = etc.parent().unwrap().join("etclink");
        std::os::unix::fs::symlink(&vendor, &link).unwrap();

        for list in [
            // Spelled twice.
            vec![etc.clone(), vendor.clone(), etc.clone()],
            // ...and reached through a symlink, which is the same directory.
            vec![link.clone(), vendor.clone()],
        ] {
            assert_eq!(
                PamDirs::new(list.clone()),
                PamDirs::default(),
                "{list:?} must not be used as a search path"
            );
        }

        // A distinct pair is still taken as written.
        assert_eq!(
            PamDirs::new(vec![etc.clone(), vendor.clone()]).overrides(),
            etc.as_path()
        );
    }

    /// The search path is a value with an invariant: there is always a
    /// directory to write to, and it is the first one.
    #[test]
    fn the_write_target_is_the_first_directory() {
        assert_eq!(PamDirs::default().overrides(), Path::new(PAM_DIR));
        assert_eq!(
            PamDirs::default(),
            PamDirs::new(Vec::new()),
            "an empty list is a mistake, not a request to disable the writer"
        );
        assert_eq!(
            PamDirs::default().iter().collect::<Vec<&Path>>(),
            [Path::new("/etc/pam.d"), Path::new("/usr/lib/pam.d")],
            "Linux-PAM's own precedence: /etc first, the vendor directory second"
        );
    }

    // -----------------------------------------------------------------------
    // The module probe (P1b, #170)
    // -----------------------------------------------------------------------

    /// First hit wins, and the *order* is the contract: `/lib/security` stays
    /// first so the answer on usrmerged Arch does not change.
    #[test]
    fn the_module_probe_takes_the_first_candidate_that_exists() {
        let dir = tempfile::TempDir::new().unwrap();
        let candidates: Vec<String> = ["a", "b", "c"]
            .iter()
            .map(|name| dir.path().join(name).display().to_string())
            .collect();
        let list: Vec<&str> = candidates.iter().map(String::as_str).collect();

        assert_eq!(first_existing(&list), None, "a miss is None, not a guess");

        fs::write(dir.path().join("b"), "").unwrap();
        fs::write(dir.path().join("c"), "").unwrap();
        assert_eq!(
            first_existing(&list),
            Some(dir.path().join("b")),
            "the earlier of two hits wins"
        );

        fs::write(dir.path().join("a"), "").unwrap();
        assert_eq!(first_existing(&list), Some(dir.path().join("a")));
    }

    /// The regression that matters: the module installed **only** at the last
    /// candidate. `dist/facelock.spec` puts it at `%{_libdir}/security`, which
    /// is `/usr/lib64/security` on x86-64 Fedora and RHEL, and the old single
    /// path made `pam add` refuse on the distribution this repository ships a
    /// spec file for.
    #[test]
    fn a_module_at_the_last_candidate_is_still_found() {
        let dir = tempfile::TempDir::new().unwrap();
        let candidates: Vec<String> = ["lib", "usr-lib", "usr-lib64"]
            .iter()
            .map(|name| dir.path().join(name).display().to_string())
            .collect();
        let list: Vec<&str> = candidates.iter().map(String::as_str).collect();
        fs::write(dir.path().join("usr-lib64"), "").unwrap();

        assert_eq!(first_existing(&list), Some(dir.path().join("usr-lib64")));
    }

    /// The refusal names every candidate, so an operator on an unlisted layout
    /// can see what to add rather than guess which single path was wanted.
    #[test]
    fn the_module_refusal_names_every_candidate() {
        let message = PamMessage::PamModuleNotInstalled {
            paths: PAM_MODULE_PATHS.join(", "),
            path: PAM_MODULE_PATHS[0].to_string(),
        }
        .localized();

        for candidate in PAM_MODULE_PATHS {
            assert!(
                message.contains(candidate),
                "{candidate} unnamed: {message}"
            );
        }
    }

    /// The probe order, pinned. `/lib/security` first keeps Arch's answer the
    /// answer it was; `/usr/lib64/security` is Fedora's; there is deliberately
    /// no Debian multiarch triple, because Debian's path is `pam-auth-update`
    /// and this command does not do that.
    #[test]
    fn the_module_probe_order_is_the_contract() {
        assert_eq!(
            PAM_MODULE_PATHS,
            [
                "/lib/security/pam_facelock.so",
                "/usr/lib/security/pam_facelock.so",
                "/usr/lib64/security/pam_facelock.so",
            ]
        );
        // One list, and there is deliberately nothing to assert about it:
        // `health::PAM_MODULE_PATHS` is a `pub use` of this const, not a
        // second declaration, so an equality check here could not fail. The
        // re-export *is* the guarantee that `status` cannot say "installed"
        // where `pam add` says "not installed" — re-declaring the list would
        // have to delete it, which is a diff a reader sees.
    }

    /// `pam status --json` carries the resolved module path as a new
    /// **top-level** key: it is a property of the machine, not of a service,
    /// and "the line is present but the module it names is at a path nothing
    /// looks at" is the state an integrator could not otherwise see. `add` and
    /// `remove` refuse before writing when it is missing, so their documents
    /// do not carry it.
    #[test]
    fn status_json_carries_the_module_path_and_the_write_verbs_do_not() {
        let rows = [ServiceReport {
            service: "sudo".to_string(),
            path: Some("/etc/pam.d/sudo".to_string()),
            outcome: Outcome::Present,
            backup: None,
            shadows: None,
        }];

        let status: serde_json::Value =
            serde_json::from_str(&report_json(PamAction::Status, false, &rows, &[])).unwrap();
        assert!(
            status.get("module_path").is_some(),
            "the key is always present on status, null when nothing hit"
        );
        assert_eq!(
            status["module_path"],
            installed_module_path()
                .map(|path| serde_json::json!(path.display().to_string()))
                .unwrap_or(serde_json::Value::Null)
        );

        for action in [PamAction::Add, PamAction::Remove] {
            let document: serde_json::Value =
                serde_json::from_str(&report_json(action, false, &rows, &[])).unwrap();
            assert!(document.get("module_path").is_none(), "{action:?}");
        }
    }

    // -----------------------------------------------------------------------
    // Enumeration — `pam status --all` (P3)
    //
    // The blind spot these exist for: `status` could only answer about names
    // it was given, so a configured `omarchy-lock-face` was invisible and
    // "not configured" and "not checked" rendered identically.
    // -----------------------------------------------------------------------

    fn status_all(dirs: &PamDirs, if_present: bool) -> i32 {
        status_in(
            dirs,
            &PamRequest {
                action: PamAction::Status,
                all: true,
                if_present,
                ..PamRequest::default()
            },
        )
    }

    /// The headline: every configured service is listed, from both
    /// directories, whether or not anyone named it.
    #[test]
    fn all_lists_every_configured_service() {
        let (_root, etc, vendor) = pair();
        fs::write(etc.join("sudo"), SUDO_AFTER).unwrap();
        fs::write(etc.join("uninvolved"), SUDO_BEFORE).unwrap();
        fs::write(vendor.join("omarchy-lock-face"), OMARCHY_PRESENT).unwrap();

        let scan = scan_directories(&both(&etc, &vendor));
        assert_eq!(
            scan.names,
            ["omarchy-lock-face", "sudo"],
            "sorted, and the \
             service with no facelock line is not in the report at all"
        );

        let reports = status_reports(&both(&etc, &vendor), &scan.names, &Sink::verb(true));
        assert!(reports.iter().all(|row| row.outcome == Outcome::Present));
        assert_eq!(status_all(&both(&etc, &vendor), false), STATUS_PRESENT);
    }

    /// A service configured through an `/etc` copy of a package's file is
    /// reported as such: still `present`, and the row names the vendor file it
    /// hides — which is what says the copy will not follow the package's
    /// updates.
    #[test]
    fn an_etc_override_is_reported_as_one() {
        let (_root, etc, vendor) = pair();
        fs::write(vendor.join("polkit-1"), POLKIT_BEFORE).unwrap();
        fs::write(etc.join("polkit-1"), POLKIT_AFTER).unwrap();

        let reports = status_reports(
            &both(&etc, &vendor),
            &["polkit-1".to_string()],
            &Sink::verb(true),
        );

        assert_eq!(reports[0].outcome, Outcome::Present);
        assert_eq!(
            reports[0].shadows.as_deref(),
            Some(vendor.join("polkit-1").to_str().unwrap())
        );
        let value: serde_json::Value =
            serde_json::from_str(&report_json(PamAction::Status, false, &reports, &[])).unwrap();
        assert_eq!(
            value["services"][0]["shadows"],
            vendor.join("polkit-1").to_str().unwrap()
        );
    }

    /// ...and a service that shadows nothing carries no key at all, so a
    /// machine with no vendor directory emits the document it always did.
    #[test]
    fn a_service_that_shadows_nothing_carries_no_shadows_key() {
        let dir = seeded(&[("sudo", SUDO_AFTER)]);
        let reports = status_reports(&only(dir.path()), &["sudo".to_string()], &Sink::verb(true));

        assert_eq!(reports[0].shadows, None);
        let value: serde_json::Value =
            serde_json::from_str(&report_json(PamAction::Status, false, &reports, &[])).unwrap();
        assert!(value["services"][0].get("shadows").is_none());
    }

    /// A vendor file carrying the line while `/etc` shadows it without one is
    /// **not configured**, and the name still has to appear: the file
    /// Linux-PAM reads has no line in it, and dropping the name would hide
    /// exactly the machine an operator cannot otherwise explain.
    #[test]
    fn a_shadowed_vendor_line_is_reported_as_missing_not_as_configured() {
        let (_root, etc, vendor) = pair();
        fs::write(vendor.join("polkit-1"), OMARCHY_PRESENT).unwrap();
        fs::write(etc.join("polkit-1"), POLKIT_BEFORE).unwrap();

        let dirs = both(&etc, &vendor);
        let scan = scan_directories(&dirs);
        assert_eq!(scan.names, ["polkit-1"]);

        let reports = status_reports(&dirs, &scan.names, &Sink::verb(true));
        assert_eq!(
            reports[0].outcome,
            Outcome::Missing,
            "the /etc file is the one PAM reads, and it has no line"
        );
        assert_eq!(status_all(&dirs, false), STATUS_MISSING);
    }

    /// Nothing configured is exit 1, not 0 — a machine with no facelock line
    /// anywhere is not "fine", it is not set up — and `--if-present` does not
    /// convert it, because there is no `absent` row here to forgive.
    #[test]
    fn nothing_configured_is_exit_one_with_and_without_if_present() {
        let (_root, etc, vendor) = pair();
        fs::write(etc.join("sudo"), SUDO_BEFORE).unwrap();

        let dirs = both(&etc, &vendor);
        assert!(scan_directories(&dirs).names.is_empty());
        assert_eq!(status_all(&dirs, false), STATUS_MISSING);
        assert_eq!(status_all(&dirs, true), STATUS_MISSING);
    }

    /// **The distinction the gap exists for.** A directory that could not be
    /// listed is reported as unread and forces exit 2; it never reads as "no
    /// services here". Skipped as root, where the mode bits are ignored and
    /// the assertion would be vacuous.
    #[test]
    fn an_unreadable_directory_is_not_checked_rather_than_not_configured() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (_root, etc, vendor) = pair();
        fs::write(etc.join("sudo"), SUDO_AFTER).unwrap();
        fs::set_permissions(&vendor, fs::Permissions::from_mode(0o000)).unwrap();

        let dirs = both(&etc, &vendor);
        let scan = scan_directories(&dirs);
        assert_eq!(scan.names, ["sudo"], "what could be read is still reported");
        assert_eq!(
            scan.unreadable().map(|(path, _)| path).collect::<Vec<_>>(),
            [vendor.as_path()]
        );
        assert_eq!(
            status_all(&dirs, false),
            STATUS_ERROR,
            "a configured service and an unread directory is still an \
             incomplete answer"
        );

        let document: serde_json::Value = serde_json::from_str(&report_json(
            PamAction::Status,
            false,
            &[],
            &scan.directories,
        ))
        .unwrap();
        assert_eq!(document["directories"][0]["status"], "scanned");
        assert!(document["directories"][0].get("error").is_none());
        assert_eq!(document["directories"][1]["status"], "unreadable");
        assert!(document["directories"][1]["error"].is_string());

        fs::set_permissions(&vendor, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// A directory that is *not there* is a different answer from one that
    /// would not open: it demonstrably holds no service files, so it is
    /// reported as absent and does not raise the exit code. The default search
    /// path names a vendor directory many machines do not have, and treating
    /// that as unanswerable would make every one of them exit 2 forever.
    #[test]
    fn a_missing_directory_is_absent_rather_than_unreadable() {
        let (_root, etc, vendor) = pair();
        fs::write(etc.join("sudo"), SUDO_AFTER).unwrap();
        fs::remove_dir(&vendor).unwrap();

        let dirs = both(&etc, &vendor);
        let scan = scan_directories(&dirs);
        assert_eq!(scan.directories[1].state, DirState::Absent);
        assert_eq!(scan.unreadable().count(), 0);
        assert_eq!(status_all(&dirs, false), STATUS_PRESENT);
    }

    /// The `--json` document is the same document, with one additive
    /// top-level key. A named request does not carry it — it never claimed to
    /// have looked everywhere.
    #[test]
    fn only_all_carries_the_directories_key() {
        let (_root, etc, vendor) = pair();
        fs::write(etc.join("sudo"), SUDO_AFTER).unwrap();

        let dirs = both(&etc, &vendor);
        let scan = scan_directories(&dirs);
        let reports = status_reports(&dirs, &scan.names, &Sink::verb(true));

        let named: serde_json::Value =
            serde_json::from_str(&report_json(PamAction::Status, false, &reports, &[])).unwrap();
        assert!(named.get("directories").is_none());

        let enumerated: serde_json::Value = serde_json::from_str(&report_json(
            PamAction::Status,
            false,
            &reports,
            &scan.directories,
        ))
        .unwrap();
        assert_eq!(enumerated["command"], "status");
        assert_eq!(enumerated["dry_run"], false);
        assert_eq!(enumerated["services"][0]["action"], "present");
        assert_eq!(
            enumerated["directories"][0]["path"],
            etc.to_str().unwrap(),
            "the directories are in search order"
        );
        assert_eq!(
            enumerated["directories"][1]["path"],
            vendor.to_str().unwrap()
        );
    }

    /// A `.facelock-backup` is a byte copy of a configured file and is not a
    /// service. Neither is a `.pacsave`, a `~` file, or this module's own
    /// in-flight temp file. Reporting one as configured would be the report
    /// being confidently wrong, which is what enumeration is for removing.
    #[test]
    fn backups_and_package_manager_leftovers_are_not_services() {
        let dir = seeded(&[
            ("sudo", SUDO_AFTER),
            ("sudo.facelock-backup", SUDO_AFTER),
            ("polkit-1.pacsave", SUDO_AFTER),
            ("hyprlock.rpmsave", SUDO_AFTER),
            ("login.dpkg-old", SUDO_AFTER),
            ("swaylock~", SUDO_AFTER),
            (".sudo.facelock-1234-5678", SUDO_AFTER),
        ]);

        assert_eq!(scan_directories(&only(dir.path())).names, ["sudo"]);
    }

    /// A service file that could not be read is carried into the report, not
    /// omitted: leaving it out would report "not configured" for a machine
    /// this could not check. It lands as `unknown`, which is exit 2. Skipped
    /// as root, which ignores the mode bits.
    #[test]
    fn an_unreadable_service_file_is_reported_rather_than_skipped() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = seeded(&[("sudo", SUDO_AFTER)]);
        fs::set_permissions(dir.path().join("sudo"), fs::Permissions::from_mode(0o000)).unwrap();

        let dirs = only(dir.path());
        assert_eq!(scan_directories(&dirs).names, ["sudo"]);
        let reports = status_reports(&dirs, &["sudo".to_string()], &Sink::verb(true));
        assert!(matches!(reports[0].outcome, Outcome::Unknown(_)));
        assert_eq!(status_all(&dirs, false), STATUS_ERROR);

        fs::set_permissions(dir.path().join("sudo"), fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// The scan reports what the resolver would accept: an entry symlinked out
    /// of its directory is neither followed nor silently dropped — it becomes
    /// the same `unknown` row a named request gets for it.
    #[test]
    fn an_escaping_symlink_found_by_the_scan_is_reported_as_unknown() {
        let (_root, etc, vendor) = pair();
        let outside = vendor.join("elsewhere");
        fs::write(&outside, SUDO_AFTER).unwrap();
        std::os::unix::fs::symlink(&outside, etc.join("hyprlock")).unwrap();

        // The scan reads *through* the link to decide the name is worth
        // reporting; the resolver is what refuses to act on it.
        let dirs = PamDirs::new(vec![etc.clone()]);
        assert_eq!(scan_directories(&dirs).names, ["hyprlock"]);

        let reports = status_reports(&dirs, &["hyprlock".to_string()], &Sink::verb(true));
        assert_eq!(
            reports[0].outcome,
            Outcome::Unknown(SYMLINKED_OUT_OF_DIR.to_string())
        );
        assert_eq!(status_all(&dirs, false), STATUS_ERROR);
    }

    /// `--all` and a named request answer identically about one service. They
    /// share [`status_reports`], and this is the assertion that says so —
    /// a second row builder for the enumerating form is the drift this
    /// forbids.
    #[test]
    fn all_and_a_named_request_agree_about_one_service() {
        let (_root, etc, vendor) = pair();
        fs::write(vendor.join("polkit-1"), POLKIT_BEFORE).unwrap();
        fs::write(etc.join("polkit-1"), POLKIT_AFTER).unwrap();

        let dirs = both(&etc, &vendor);
        let enumerated = status_reports(&dirs, &scan_directories(&dirs).names, &Sink::verb(true));
        let named = status_reports(&dirs, &["polkit-1".to_string()], &Sink::verb(true));

        assert_eq!(enumerated, named);
    }

    /// **Nothing found is not "nothing configured" when something could not be
    /// read.** The unqualified sentence names every directory on the search
    /// path, so under `2>/dev/null` — the ordinary way to take the human
    /// answer — it asserted the one thing this flag exists to stop it
    /// asserting. Skipped as root, which ignores the mode bits.
    #[test]
    fn an_empty_answer_is_qualified_by_what_could_not_be_read() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (_root, etc, vendor) = pair();
        fs::write(etc.join("plain"), SUDO_BEFORE).unwrap();
        fs::set_permissions(&vendor, fs::Permissions::from_mode(0o000)).unwrap();

        let dirs = both(&etc, &vendor);
        let scan = scan_directories(&dirs);
        assert!(scan.names.is_empty());
        assert_eq!(
            scan.answered(),
            [etc.display().to_string()],
            "only the directory that produced an answer may be spoken for"
        );
        assert_eq!(status_all(&dirs, false), STATUS_ERROR);

        // The two sentences are different, and the qualified one names the
        // unread directory as unread rather than as searched.
        let qualified = PamMessage::PamStatusNoServicesIncomplete {
            dirs: etc.display().to_string(),
            unchecked: vendor.display().to_string(),
        }
        .localized();
        assert!(qualified.contains("could not be checked"), "{qualified}");
        assert!(
            !PamMessage::PamStatusNoServices {
                dirs: dirs.display()
            }
            .localized()
            .contains("could not be checked")
        );

        fs::set_permissions(&vendor, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// ...and when *no* directory could be read there is no set to scope an
    /// emptiness to, so the line says only that — never that nothing is
    /// configured. stdout still carries one, because a human reading it alone
    /// would otherwise get a sentence in the other two branches and silence in
    /// the one where the machine is worst off.
    #[test]
    fn nothing_readable_at_all_says_so_without_claiming_nothing_is_configured() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (_root, etc, vendor) = pair();
        for dir in [&etc, &vendor] {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o000)).unwrap();
        }

        let dirs = both(&etc, &vendor);
        let scan = scan_directories(&dirs);
        assert!(scan.answered().is_empty());
        assert_eq!(scan.unreadable().count(), 2);
        assert_eq!(status_all(&dirs, false), STATUS_ERROR);

        let line = PamMessage::PamStatusNothingReadable {
            dirs: dirs.display(),
        }
        .localized();
        assert!(
            line.contains("No directory on the search path could be read"),
            "{line}"
        );
        assert!(
            !line.contains("carries the facelock PAM line"),
            "it must not assert anything about what is configured: {line}"
        );

        for dir in [&etc, &vendor] {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    /// **An entry that exists and cannot be examined must not vanish.** The
    /// followed-metadata guard first treated every `stat` failure as "not a
    /// regular file", so a symlink into a directory the caller may not
    /// traverse dropped out of `--all` and out of `facelock status` while
    /// `--service` on the same name still said `unknown`, exit 2 — the two
    /// forms disagreeing about one service, which is what sharing a row
    /// builder is supposed to make impossible. Skipped as root, which
    /// traverses anything.
    #[test]
    fn a_symlink_into_an_untraversable_directory_is_unknown_not_invisible() {
        use std::os::unix::fs::PermissionsExt;

        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let (_root, etc, vendor) = pair();
        fs::write(etc.join("sudo"), SUDO_AFTER).unwrap();
        fs::write(vendor.join("real"), SUDO_AFTER).unwrap();
        std::os::unix::fs::symlink(vendor.join("real"), etc.join("hyprlock")).unwrap();
        fs::set_permissions(&vendor, fs::Permissions::from_mode(0o000)).unwrap();

        let dirs = PamDirs::new(vec![etc.clone()]);
        let scan = scan_directories(&dirs);
        assert_eq!(
            scan.names,
            ["hyprlock", "sudo"],
            "the entry this could not examine is carried, not dropped"
        );

        let reports = status_reports(&dirs, &scan.names, &Sink::verb(true));
        assert!(matches!(reports[0].outcome, Outcome::Unknown(_)));
        assert_eq!(status_all(&dirs, false), STATUS_ERROR);

        // The invariant the hole falsified: both forms answer the same.
        let named = status_reports(&dirs, &["hyprlock".to_string()], &Sink::verb(true));
        assert_eq!(reports[0], named[0]);

        fs::set_permissions(&vendor, fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The same hole reached by a route root cannot escape either: a symlink
    /// loop, whose `stat` fails with `ELOOP` for every caller.
    #[test]
    fn a_symlink_loop_is_unknown_not_invisible() {
        let dir = seeded(&[("sudo", SUDO_AFTER)]);
        std::os::unix::fs::symlink(dir.path().join("loop-b"), dir.path().join("loop-a")).unwrap();
        std::os::unix::fs::symlink(dir.path().join("loop-a"), dir.path().join("loop-b")).unwrap();

        let dirs = only(dir.path());
        let scan = scan_directories(&dirs);
        assert_eq!(scan.names, ["loop-a", "loop-b", "sudo"]);

        let reports = status_reports(&dirs, &scan.names, &Sink::verb(true));
        assert!(matches!(reports[0].outcome, Outcome::Unknown(_)));
        assert_eq!(status_all(&dirs, false), STATUS_ERROR);

        let named = status_reports(&dirs, &["loop-a".to_string()], &Sink::verb(true));
        assert_eq!(reports[0], named[0]);
    }

    /// **A FIFO in a scanned directory must not hang the command.**
    /// `read_to_string` on one blocks until a writer appears, which is forever
    /// on a `/etc/pam.d` nobody is writing to — and this scan is what
    /// `facelock status` runs, so the diagnostic command would hang on exactly
    /// the broken machine it exists to describe. The test *is* the assertion:
    /// before the followed-metadata check it did not return.
    #[test]
    fn a_fifo_entry_is_skipped_rather_than_read() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let dir = seeded(&[("sudo", SUDO_AFTER)]);
        let fifo = dir.path().join("fifo-service");
        let c_fifo = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        // SAFETY: a NUL-terminated path that outlives the call; `mkfifo` only
        // reads it.
        assert_eq!(unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o644) }, 0);

        // A symlink onto the FIFO too: `file_type` at the call site is an
        // lstat, so a link is the way a non-regular file gets past it.
        std::os::unix::fs::symlink(&fifo, dir.path().join("linked-fifo")).unwrap();

        assert_eq!(scan_directories(&only(dir.path())).names, ["sudo"]);
    }

    /// A directory reached through a symlink is not an unreadable service
    /// file. It used to survive the `lstat` skip, fail the read with EISDIR,
    /// and land as `unknown` — a real directory reported as a service this
    /// could not answer for.
    #[test]
    fn a_symlink_to_a_directory_is_not_a_service() {
        let (_root, etc, vendor) = pair();
        fs::write(etc.join("sudo"), SUDO_AFTER).unwrap();
        std::os::unix::fs::symlink(&vendor, etc.join("linked-dir")).unwrap();

        let dirs = PamDirs::new(vec![etc.clone()]);
        assert_eq!(scan_directories(&dirs).names, ["sudo"]);
        assert_eq!(status_all(&dirs, false), STATUS_PRESENT);
    }

    /// A name this cannot spell is a name it cannot resolve. `to_string_lossy`
    /// substituted U+FFFD and handed the resolver a name no file has, so a
    /// configured service was reported `absent` at a path that does not exist
    /// — and under `--if-present` that scored 0, which is "everything fine".
    #[test]
    fn a_non_utf8_entry_name_is_skipped_not_mangled() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = seeded(&[("sudo", SUDO_AFTER)]);
        let bad = dir.path().join(OsStr::from_bytes(b"bad\xffname"));
        fs::write(&bad, SUDO_AFTER).unwrap();

        let dirs = only(dir.path());
        assert_eq!(
            scan_directories(&dirs).names,
            ["sudo"],
            "the unspellable name is skipped, not reported at a path that does not exist"
        );
        assert_eq!(status_all(&dirs, true), STATUS_PRESENT);
    }

    /// The row that *creates* the shadow carries it. `Origin::Vendor` has
    /// nothing to hide at resolve time, so without this the `overridden` row —
    /// the one that makes the fact true — was the only row without the key,
    /// while `status` reported it a second later.
    #[test]
    fn an_overridden_row_names_the_vendor_file_it_now_shadows() {
        let (_root, etc, vendor) = pair();
        fs::write(vendor.join("polkit-1"), POLKIT_BEFORE).unwrap();

        let request = add(&["polkit-1"]);
        let write = WriteRequest {
            action: WriteAction::Add,
            request: &request,
            remedy: "--allow-sensitive",
        };
        let dirs = both(&etc, &vendor);
        let targets = plan_writes(&dirs, &write).unwrap();
        let reports = apply_all(&targets, &write, &Sink::verb(true));

        assert_eq!(reports[0].outcome, Outcome::Overridden);
        assert_eq!(
            reports[0].shadows.as_deref(),
            Some(vendor.join("polkit-1").to_str().unwrap())
        );
        let value: serde_json::Value =
            serde_json::from_str(&report_json(PamAction::Add, false, &reports, &[])).unwrap();
        assert_eq!(
            value["services"][0]["shadows"],
            vendor.join("polkit-1").to_str().unwrap()
        );

        // ...and the next `status` agrees, now through the resolver.
        let after = status_reports(&dirs, &["polkit-1".to_string()], &Sink::verb(true));
        assert_eq!(after[0].shadows, reports[0].shadows);
    }
}
