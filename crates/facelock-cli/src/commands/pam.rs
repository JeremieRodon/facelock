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
//! # Limits
//!
//! The write is `fs::write`: truncate in place, not a temp file and a rename,
//! so a kill between the truncate and the last byte leaves a short service
//! file. `remove` takes no backup of its own and relies on the one `add`
//! wrote. Both are stated in `docs/contracts.md` ("facelock pam Semantics",
//! Limits) rather than fixed here, because an atomic replace has to carry the
//! mode, owner and SELinux context across, which is the same primitive the
//! vendor-to-`/etc` copy needs; see the `TODO(P1)` markers below.

use std::ffi::OsStr;
use std::fs;
use std::io::IsTerminal;
use std::path::{Component, Path, PathBuf};

use dialoguer::Confirm;

use crate::message::{Message, PamMessage, Terminal, fail};

/// The real PAM configuration directory. Every engine function takes it as a
/// parameter so tests drive the whole writer against a tempdir, unprivileged.
pub const PAM_DIR: &str = "/etc/pam.d";

/// The line this command adds and removes. Matching is by module name rather
/// than by these bytes — see [`is_facelock_pam_line`].
pub const PAM_LINE: &str = "auth      sufficient pam_facelock.so";

/// Where the PAM module has to be for the line to mean anything.
pub const PAM_MODULE_PATH: &str = "/lib/security/pam_facelock.so";

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
/// of [`PAM_DIR`]. Fixed C-locale text for the same reason as
/// [`INVALID_SERVICE_NAME`]; the human gets the localized message, which names
/// the target, on stderr. It spells the real directory rather than the `base`
/// under test because it is a documented constant, not a rendering.
const SYMLINKED_OUT_OF_DIR: &str = "symlinked outside /etc/pam.d";

/// The `--json` `error` value for a service file with more than one name.
/// Fixed C-locale text, as above.
const HARD_LINKED: &str = "hard-linked service file";

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
    /// `remove`: the line was deleted (or would be).
    Removed,
    /// The service was already in the requested state.
    Unchanged,
    /// The service file does not exist, and `--if-present` allowed that.
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
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

/// What a service is planned to become.
///
/// The variants that rewrite the file carry the bytes they were derived from,
/// so "there is an edit to make" and "here is what it is being made from"
/// cannot disagree. Holding them apart — a plan beside an `Option<String>` —
/// made two representations of one fact, and every consumer had to re-check
/// the pairing.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Plan {
    /// Insert the line. `at_top` records that the file has no `auth` line, so
    /// the preview and the dry-run report can say where it lands.
    Add { at_top: bool, content: String },
    /// Delete the line.
    Remove { content: String },
    /// Already in the requested state.
    NoChange,
    /// No service file, and `--if-present` said that is fine.
    Absent,
}

/// A validated service, with the file already read.
#[derive(Debug, Clone)]
struct Target {
    service: String,
    path: PathBuf,
    backup: PathBuf,
    plan: Plan,
}

impl Target {
    fn path_string(&self) -> String {
        self.path.display().to_string()
    }

    fn backup_string(&self) -> String {
        self.backup.display().to_string()
    }

    /// The backup path if it exists on disk, for the report's `backup` field.
    fn existing_backup(&self) -> Option<String> {
        existing_backup_for(&self.path)
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

/// A link this refuses to write through.
///
/// Both phases reject the same two shapes and report them differently —
/// [`plan_writes`] as an `Err` that stops the whole run, [`status_reports`] as
/// an `unknown` row beside the services it could answer about — so the reason
/// is a value here rather than a rendered message at each site. Everything
/// that differs between the two (the fixed machine reason, the localized text,
/// the row's `path` and `backup`) hangs off it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LinkFault {
    /// A symlink whose target is outside `base`, or one that cannot be
    /// resolved to prove otherwise.
    OutOfBase { link: PathBuf, target: PathBuf },
    /// A regular file reachable by more than one name. Which other names is
    /// exactly what a link count does not say, so the edit cannot be shown to
    /// stay inside the directory.
    HardLinked { link: PathBuf, links: u64 },
}

impl LinkFault {
    /// The `--json` `error` value: fixed C-locale text, never the localized
    /// message. See [`INVALID_SERVICE_NAME`].
    fn reason(&self) -> &'static str {
        match self {
            LinkFault::OutOfBase { .. } => SYMLINKED_OUT_OF_DIR,
            LinkFault::HardLinked { .. } => HARD_LINKED,
        }
    }

    /// The localized refusal, for a human on stderr.
    fn message(&self, base: &Path) -> PamMessage {
        match self {
            LinkFault::OutOfBase { link, target } => PamMessage::PamServiceSymlinkedOutside {
                path: link.display().to_string(),
                target: target.display().to_string(),
                dir: base.display().to_string(),
            },
            LinkFault::HardLinked { link, links } => PamMessage::PamServiceHardLinked {
                path: link.display().to_string(),
                links: links.to_string(),
            },
        }
    }

    /// The entry this is about: a real, confined path that was `lstat`ed, so
    /// unlike a rejected *name* it is worth reporting.
    fn link(&self) -> &Path {
        match self {
            LinkFault::OutOfBase { link, .. } | LinkFault::HardLinked { link, .. } => link,
        }
    }
}

/// The file a validated `service` names under `base`, or the reason it cannot
/// be written through.
///
/// `confined` checks the *name*; this checks what the filesystem does with it,
/// and there are two ways for a well-formed name to reach a file this cannot
/// account for.
///
/// **Symlinks.** `read_to_string`, `fs::copy` and `fs::write` all follow one,
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
/// file this cannot name — the confinement rule's whole subject. Refusing is
/// the conservative reading, and it is temporary: the atomic temp-and-rename
/// replace under "Limits" writes a new inode and leaves the other name alone,
/// which makes the question moot. A `/etc` that has been through a
/// deduplicating backup or `jdupes -L` can trip this without any adversary
/// involved, so the message says how to break the link.
fn resolve_service_path(base: &Path, service: &str) -> Result<PathBuf, LinkFault> {
    use std::os::unix::fs::MetadataExt;

    let path = base.join(service);
    // No entry, or an entry this cannot stat: there is nothing to follow. The
    // read that follows reports the error, or `--if-present` forgives it.
    let Ok(metadata) = fs::symlink_metadata(&path) else {
        return Ok(path);
    };

    if !metadata.file_type().is_symlink() {
        // `is_file` matters: a directory's link count is its subdirectory
        // count, and a directory where a service file should be is a read
        // error reported as one, not a link fault.
        if metadata.is_file() && metadata.nlink() > 1 {
            return Err(LinkFault::HardLinked {
                link: path,
                links: metadata.nlink(),
            });
        }
        return Ok(path);
    }

    match (fs::canonicalize(&path), fs::canonicalize(base)) {
        (Ok(target), Ok(root)) if target.starts_with(&root) => Ok(target),
        (Ok(target), _) => Err(LinkFault::OutOfBase { link: path, target }),
        (Err(_), _) => Err(LinkFault::OutOfBase {
            target: fs::read_link(&path).unwrap_or_else(|_| path.clone()),
            link: path,
        }),
    }
}

/// Refuse a [`SENSITIVE_SERVICES`] entry unless the caller accepted the risk.
///
/// Called twice per service, on the name as typed and again on the file that
/// name resolved to: the gate protects the *file*, and a symlink
/// `alias -> system-auth` inside `/etc/pam.d` is a way to reach a gated file
/// under a name the first check waves through. Only `add` is gated —
/// see [`SENSITIVE_SERVICES`].
fn gate_sensitive(
    service: &str,
    action: PamAction,
    allow_sensitive: bool,
    remedy: &str,
) -> anyhow::Result<()> {
    if action != PamAction::Add || allow_sensitive || !SENSITIVE_SERVICES.contains(&service) {
        return Ok(());
    }
    Err(fail(PamMessage::PamSensitiveRefused {
        service: service.to_string(),
        remedy: remedy.to_string(),
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

/// Phase one: validate and read every service, or fail having written nothing.
///
/// Every rejection here is an `Err`, not a report row, and the caller performs
/// no writes on `Err` — that is the whole point of the phase. Errors render on
/// stderr as text and never as a JSON document, the same contract
/// `is-enrolled` has for its unanswerable case.
fn plan_writes(
    base: &Path,
    action: PamAction,
    services: &[String],
    request: &PamRequest,
    sensitive_remedy: &str,
) -> anyhow::Result<Vec<Target>> {
    let mut targets = Vec::with_capacity(services.len());

    for service in services {
        confined(service)?;
        // On the name as typed, before any I/O.
        gate_sensitive(service, action, request.allow_sensitive, sensitive_remedy)?;

        let path =
            resolve_service_path(base, service).map_err(|fault| fail(fault.message(base)))?;
        // ...and again on the file the name reached. A link `alias ->
        // system-auth` inside the directory is a gated file behind an ungated
        // name, and the gate is on the file.
        gate_sensitive(
            &file_name_of(&path),
            action,
            request.allow_sensitive,
            sensitive_remedy,
        )?;

        let backup = backup_path(&path);
        let display = path.display().to_string();

        let content = match fs::read_to_string(&path) {
            Ok(content) => Some(content),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !request.if_present {
                    return Err(fail(PamMessage::PamFileNotFound { path: display }));
                }
                None
            }
            // `--if-present` converts a missing file into a no-op and nothing
            // else: a permission or I/O failure stays fatal.
            Err(error) => {
                return Err(anyhow::Error::new(error).context(format!("failed to read {display}")));
            }
        };

        let plan = match (content, action) {
            (None, _) => Plan::Absent,
            (Some(content), PamAction::Add) => {
                if content.lines().any(is_facelock_pam_line) {
                    Plan::NoChange
                } else {
                    Plan::Add {
                        at_top: !content.lines().any(has_auth_keyword),
                        content,
                    }
                }
            }
            (Some(content), PamAction::Remove) => {
                if content.lines().any(is_facelock_pam_line) {
                    Plan::Remove { content }
                } else {
                    Plan::NoChange
                }
            }
            (Some(_), PamAction::Status) => Plan::NoChange,
        };

        targets.push(Target {
            service: service.clone(),
            path,
            backup,
            plan,
        });
    }

    Ok(targets)
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
}

impl Sink {
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
    let path = target.path_string();

    let (at_top, content) = match &target.plan {
        Plan::NoChange => {
            sink.info(&PamMessage::PamLineAlreadyPresent { path });
            return Outcome::Unchanged;
        }
        Plan::Absent => {
            sink.info(&PamMessage::PamServiceAbsentSkipped { path });
            return Outcome::Absent;
        }
        Plan::Add { at_top, content } => (*at_top, content.as_str()),
        // `plan_writes` is the only thing that builds a plan, and it never
        // hands an add a removal. Reported as a failure rather than as
        // "nothing to do" so a bug in this file cannot exit 0 having done
        // nothing while claiming the service is configured.
        Plan::Remove { .. } => return Outcome::Failed(internal_plan_mismatch(&path)),
    };
    let backup = target.backup_string();

    // Decided before the preview is printed, because it decides where the
    // preview goes: a question that will be asked needs its context seen.
    let prompting = should_prompt(
        no_confirm,
        std::io::stdin().is_terminal(),
        std::io::stderr().is_terminal(),
    );

    // The insertion point is decided before prompting, so the preview is
    // accurate rather than a guess the write could contradict.
    let hint = if at_top {
        PamMessage::PamInsertAtTopHint
    } else {
        PamMessage::PamInsertBeforeAuthHint
    };
    sink.preview(
        &PamMessage::PamModifyPreview {
            path: path.clone(),
            line: PAM_LINE.to_string(),
            hint: hint.localized(),
            backup: backup.clone(),
        },
        prompting,
    );

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

    if let Err(error) = fs::copy(&target.path, &target.backup) {
        return Outcome::Failed(format!("failed to back up {path} to {backup}: {error}"));
    }
    sink.info(&PamMessage::PamBackedUp {
        path: path.clone(),
        backup: backup.clone(),
    });

    // TODO(P1): truncate-in-place. A kill between the truncate and the last
    // byte leaves a short service file; the fix is a temp file and a rename
    // that carries mode, owner and SELinux context across, which is the same
    // primitive the vendor-to-/etc copy needs. Documented under "Limits" in
    // docs/contracts.md until then; the backup above is the recovery.
    if let Err(error) = fs::write(&target.path, with_line_inserted(content)) {
        return Outcome::Failed(format!("failed to write {path}: {error}"));
    }

    // `notice`, not `info`: this is the one message that tells an operator who
    // has just changed an auth stack how to undo it, so `--quiet` must not
    // take it. Still stdout, so a normal run prints the same bytes it always
    // did. Under `--json` the row's `backup` field carries the same fact.
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
        Plan::NoChange => {
            sink.info(&PamMessage::PamNoLineFound { path: path.clone() });
            Outcome::Unchanged
        }
        // TODO(P1): truncate-in-place, and `remove` takes no backup of its
        // own — it relies on the one `add` wrote. Both are stated under
        // "Limits" in docs/contracts.md; the atomic replace is the same work
        // as in `apply_add`.
        Plan::Remove { content } => match fs::write(&target.path, with_line_removed(content)) {
            Ok(()) => {
                sink.info(&PamMessage::PamRemoved { path: path.clone() });
                Outcome::Removed
            }
            Err(error) => Outcome::Failed(format!("failed to write {path}: {error}")),
        },
        // See `apply_add`: an impossible plan is a bug here, not a no-op.
        Plan::Add { .. } => Outcome::Failed(internal_plan_mismatch(&path)),
    };

    if let Some(backup) = target.existing_backup() {
        sink.info(&PamMessage::PamBackupExists { path, backup });
    }

    outcome
}

/// A plan that does not match the verb applying it. Unreachable — `plan_writes`
/// builds every plan and builds it for the verb that asked — and phrased as a
/// failure rather than a panic, so the process reports it and exits non-zero
/// instead of aborting mid-way through a multi-service run.
fn internal_plan_mismatch(path: &str) -> String {
    format!("internal error: plan for {path} does not match the requested action")
}

/// Render the resolved plan for `--dry-run`, writing nothing.
fn report_plan(target: &Target, sink: &Sink) -> Outcome {
    let path = target.path_string();
    match &target.plan {
        Plan::Add { at_top, .. } => {
            let at_top = *at_top;
            let hint = if at_top {
                PamMessage::PamInsertAtTopHint
            } else {
                PamMessage::PamInsertBeforeAuthHint
            };
            sink.info(&PamMessage::PamPlanAdd {
                path,
                hint: hint.localized(),
            });
            Outcome::Installed
        }
        Plan::Remove { .. } => {
            sink.info(&PamMessage::PamPlanRemove { path });
            Outcome::Removed
        }
        Plan::NoChange => {
            sink.info(&PamMessage::PamPlanNoChange { path });
            Outcome::Unchanged
        }
        Plan::Absent => {
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
fn report_json(action: PamAction, dry_run: bool, reports: &[ServiceReport]) -> String {
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
            value
        })
        .collect();

    serde_json::json!({
        "command": action.word(),
        "dry_run": dry_run,
        "services": services,
    })
    .to_string()
}

/// Emit the machine document on stdout.
///
/// Through [`message::payload`], so `--quiet` reaches it without this function
/// knowing the flag exists: under it the document is dropped and the exit code
/// is the whole answer, which is `is-enrolled --quiet --json`'s rule
/// generalized to every payload.
fn emit_json(action: PamAction, dry_run: bool, reports: &[ServiceReport]) {
    crate::message::payload(&report_json(action, dry_run, reports));
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
    if request.action == PamAction::Status {
        return Ok(status_in(Path::new(PAM_DIR), &request));
    }

    crate::ipc_client::require_root_scripted(&format!(
        "sudo facelock pam {}",
        request.action.word()
    ))?;

    if request.action == PamAction::Add {
        require_module_installed()?;
    }

    write_in(Path::new(PAM_DIR), &request)
}

/// The precondition the line is useless without. Hoisted out of the per-service
/// loop: it is a property of the machine, not of a service.
fn require_module_installed() -> anyhow::Result<()> {
    if Path::new(PAM_MODULE_PATH).exists() {
        return Ok(());
    }
    Err(fail(PamMessage::PamModuleNotInstalled {
        path: PAM_MODULE_PATH.to_string(),
    }))
}

/// `add` / `remove` against `base`. The engine tests drive this directly, so
/// it performs no root or module check — [`run`] owns those.
fn write_in(base: &Path, request: &PamRequest) -> anyhow::Result<i32> {
    let action = request.action;
    if action == PamAction::Status {
        // `run` routes `status` to `status_in` and never gets here. Delegating
        // rather than falling through is what stops a future caller from
        // getting a *removal* out of a request that asked to read.
        return Ok(status_in(base, request));
    }
    let services = requested_services(&request.services);
    let sink = Sink { json: request.json };

    // Phase one. An `Err` here has written nothing, by construction.
    let targets = plan_writes(base, action, &services, request, "--allow-sensitive")?;

    // Phase two.
    let mut reports = Vec::with_capacity(targets.len());
    for target in &targets {
        let outcome = if request.dry_run {
            report_plan(target, &sink)
        } else if action == PamAction::Add {
            apply_add(target, request.no_confirm, &sink)
        } else {
            apply_remove(target, &sink)
        };

        if let Outcome::Failed(error) = &outcome {
            sink.error(&PamMessage::PamConfigureFailed {
                service: target.service.clone(),
                error: error.clone(),
            });
        }

        reports.push(ServiceReport {
            service: target.service.clone(),
            path: Some(target.path_string()),
            outcome,
            backup: (!request.dry_run)
                .then(|| target.existing_backup())
                .flatten(),
        });
    }

    // One hint per invocation, after every service — not once per service, as
    // a shell loop over the old one-service-per-process CLI produced. It is
    // human-facing text, so `--json` and `--quiet` both drop it; `--dry-run`
    // keeps it, so a dry run is a faithful preview of what the real run prints.
    if action == PamAction::Add {
        sink.info(&PamMessage::PamExtensionHint {
            line: PAM_LINE.to_string(),
        });
    }

    if request.json {
        emit_json(action, request.dry_run, &reports);
    }

    Ok(
        if reports
            .iter()
            .any(|report| matches!(report.outcome, Outcome::Failed(_)))
        {
            WRITE_FAILED
        } else {
            WRITE_OK
        },
    )
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
fn status_in(base: &Path, request: &PamRequest) -> i32 {
    let sink = Sink { json: request.json };
    let reports = status_reports(base, &requested_services(&request.services), &sink);

    if request.json {
        emit_json(PamAction::Status, false, &reports);
    }

    reports
        .iter()
        .map(|report| status_code(&report.outcome, request.if_present))
        .max()
        .unwrap_or(STATUS_PRESENT)
}

/// One report row per service. Split out from [`status_in`] so the rows —
/// which are the `--json` payload — are assertable without capturing stdout.
fn status_reports(base: &Path, services: &[String], sink: &Sink) -> Vec<ServiceReport> {
    services
        .iter()
        .map(|service| {
            // A rejected name is answered without touching the filesystem —
            // including the backup probe below, which would otherwise `stat`
            // `/etc/pam.d/../escape.facelock-backup` for a name the whole
            // point of `confined` is to not act on.
            if confined(service).is_err() {
                // Not an `Err` return: `status` owns its exit codes, and a
                // usage error is exit 2 rather than the generic exit 1 `main`
                // gives an `anyhow` failure. The human rendering is the
                // invalid-name message rather than `PamStatusUnknown`, which
                // would report a path this never went near as "unreadable".
                sink.error(&PamMessage::PamInvalidServiceName {
                    service: service.clone(),
                });
                return ServiceReport {
                    service: service.clone(),
                    path: None,
                    outcome: Outcome::Unknown(INVALID_SERVICE_NAME.to_string()),
                    backup: None,
                };
            }

            let path = match resolve_service_path(base, service) {
                Ok(path) => path,
                // Read as `unknown`, the same word an unreadable file gets:
                // the question "does this service carry the line?" has no
                // answer this may go and look for. `path` is the entry — a
                // real, confined path this did `lstat` — and its backup is
                // probed, because a facelock version that wrote through the
                // link left it there and it is what a recovery needs.
                Err(fault) => {
                    sink.error(&fault.message(base));
                    return ServiceReport {
                        service: service.clone(),
                        path: Some(fault.link().display().to_string()),
                        outcome: Outcome::Unknown(fault.reason().to_string()),
                        backup: existing_backup_for(fault.link()),
                    };
                }
            };
            let display = path.display().to_string();

            let outcome = match fs::read_to_string(&path) {
                Ok(content) if content.lines().any(is_facelock_pam_line) => {
                    sink.info(&PamMessage::PamStatusPresent {
                        path: display.clone(),
                    });
                    Outcome::Present
                }
                Ok(_) => {
                    sink.info(&PamMessage::PamStatusMissing {
                        path: display.clone(),
                    });
                    Outcome::Missing
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    sink.info(&PamMessage::PamStatusAbsent {
                        path: display.clone(),
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
                service: service.clone(),
                path: Some(display),
                outcome,
                backup: existing_backup_for(&path),
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
        // exist. It converts *absence* and nothing else — an unreadable file
        // or a rejected name is still exit 2.
        Outcome::Absent if if_present => STATUS_PRESENT,
        _ => STATUS_ERROR,
    }
}

// ---------------------------------------------------------------------------
// The `setup --pam` alias
// ---------------------------------------------------------------------------

/// `setup --pam [--service X]`, routed through the same engine.
///
/// `setup --yes` keeps its combined meaning — it is the documented exception
/// to the flag split — so the caller maps it onto **both** knobs, and the
/// refusal names `--yes` rather than `--allow-sensitive` because that is the
/// flag this surface actually honours.
///
/// Root is re-checked here rather than only at the `setup` entry point:
/// `run_with_plan` reaches this directly for a standalone `--pam`, which does
/// not take the base setup's root pre-check.
pub fn install_for_setup(
    services: &[String],
    no_confirm: bool,
    allow_sensitive: bool,
) -> anyhow::Result<()> {
    crate::ipc_client::require_root_scripted("sudo facelock setup --pam")?;
    require_module_installed()?;

    let request = PamRequest {
        action: PamAction::Add,
        services: services.to_vec(),
        no_confirm,
        allow_sensitive,
        ..PamRequest::default()
    };
    let targets = plan_writes(
        Path::new(PAM_DIR),
        PamAction::Add,
        &requested_services(services),
        &request,
        "--yes",
    )?;

    let sink = Sink { json: false };
    for target in &targets {
        if let Outcome::Failed(error) = apply_add(target, request.no_confirm, &sink) {
            return Err(anyhow::anyhow!(error));
        }
    }
    sink.info(&PamMessage::PamExtensionHint {
        line: PAM_LINE.to_string(),
    });
    Ok(())
}

/// `setup --pam --remove [--if-present]`, routed through the same engine.
pub fn remove_for_setup(services: &[String], if_present: bool) -> anyhow::Result<()> {
    crate::ipc_client::require_root_scripted("sudo facelock setup --pam --remove")?;

    let request = PamRequest {
        action: PamAction::Remove,
        services: services.to_vec(),
        if_present,
        ..PamRequest::default()
    };
    let targets = plan_writes(
        Path::new(PAM_DIR),
        PamAction::Remove,
        &requested_services(services),
        &request,
        "--yes",
    )?;

    let sink = Sink { json: false };
    for target in &targets {
        if let Outcome::Failed(error) = apply_remove(target, &sink) {
            return Err(anyhow::anyhow!(error));
        }
    }
    Ok(())
}

/// One service, against `base`, with the wizard's semantics: the multi-select
/// already *is* the per-service consent, and the module check already ran, so
/// neither is repeated here.
pub(crate) fn install_one_in(
    base: &Path,
    service: &str,
    allow_sensitive: bool,
    no_confirm: bool,
) -> anyhow::Result<()> {
    let request = PamRequest {
        action: PamAction::Add,
        allow_sensitive,
        no_confirm,
        ..PamRequest::default()
    };
    let services = vec![service.to_string()];
    let targets = plan_writes(base, PamAction::Add, &services, &request, "--yes")?;

    let sink = Sink { json: false };
    for target in &targets {
        // `request.no_confirm`, never the parameter: one value reaches both
        // phases, so the request cannot describe a run the apply does not do.
        if let Outcome::Failed(error) = apply_add(target, request.no_confirm, &sink) {
            return Err(anyhow::anyhow!(error));
        }
    }
    Ok(())
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
            let code = write_in(dir.path(), &add(&[service])).unwrap();

            assert_eq!(code, WRITE_OK, "{service}");
            assert_eq!(read(&dir, service), after, "{service} content");
        }
    }

    /// The backup is a byte copy of the original, and it only appears when
    /// something was actually written.
    #[test]
    fn add_backup_is_the_original_and_only_exists_on_a_real_write() {
        let dir = seeded(&[("sudo", SUDO_BEFORE)]);
        write_in(dir.path(), &add(&["sudo"])).unwrap();
        assert_eq!(read(&dir, "sudo.facelock-backup"), SUDO_BEFORE);

        let untouched = seeded(&[("omarchy-lock-face", OMARCHY_PRESENT)]);
        let before = snapshot(untouched.path());
        write_in(untouched.path(), &add(&["omarchy-lock-face"])).unwrap();
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
        let code = write_in(dir.path(), &remove(&["omarchy-lock-face", "sudo"])).unwrap();

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
            install_one_in(via_alias.path(), service, true, true).unwrap();

            let via_verb = seeded(&[(service, before)]);
            write_in(via_verb.path(), &add(&[service])).unwrap();

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
            write_in(dir.path(), &add(&["sudo"])).unwrap();
            write_in(dir.path(), &remove(&["sudo"])).unwrap();
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
            let error = write_in(&base, &request).unwrap_err().to_string();

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
            assert!(write_in(&base, &request).is_err());
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

            let error = write_in(dir.path(), &add(&["sudo", second])).unwrap_err();

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

        let code = write_in(dir.path(), &add(&["sudo", "polkit-1"])).unwrap();

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

            let error = write_in(dir.path(), &add(&[service]))
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

        assert_eq!(write_in(dir.path(), &request).unwrap(), WRITE_OK);
        assert_eq!(read(&dir, "sshd"), SUDO_AFTER);
    }

    /// Removal is the safe direction, so it is not gated at all: a user who
    /// wired `system-auth` must be able to unwire it without arguing with the
    /// CLI about it.
    #[test]
    fn remove_is_never_gated_by_the_sensitive_list() {
        let dir = seeded(&[("system-auth", OMARCHY_PRESENT)]);

        assert_eq!(
            write_in(dir.path(), &remove(&["system-auth"])).unwrap(),
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

            assert_eq!(write_in(dir.path(), &request).unwrap(), WRITE_OK);
            assert!(fs::read_dir(dir.path()).unwrap().next().is_none());
        }
    }

    #[test]
    fn a_missing_service_without_if_present_still_errors() {
        for request in [add(&["omarchy-lock-face"]), remove(&["omarchy-lock-face"])] {
            let dir = tempfile::TempDir::new().unwrap();

            let error = write_in(dir.path(), &request).unwrap_err().to_string();

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

            let error = write_in(dir.path(), &request).unwrap_err().to_string();

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
            assert_eq!(write_in(dir.path(), &request).unwrap(), WRITE_OK);
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
        let services = requested_services(&request.services);
        let targets = plan_writes(dir.path(), PamAction::Add, &services, &request, "--x").unwrap();

        let sink = Sink { json: true };
        let words: Vec<&str> = targets
            .iter()
            .map(|t| report_plan(t, &sink).word())
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
                dir.path(),
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
            dir.path(),
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
        }];
        let value: serde_json::Value =
            serde_json::from_str(&report_json(PamAction::Add, false, &reports)).unwrap();

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
            },
            ServiceReport {
                service: "polkit-1".into(),
                path: Some("/etc/pam.d/polkit-1".into()),
                outcome: Outcome::Unchanged,
                backup: None,
            },
        ];
        let value: serde_json::Value =
            serde_json::from_str(&report_json(PamAction::Add, false, &reports)).unwrap();

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
        let sink = Sink { json: true };

        let reports = status_reports(dir.path(), &["../escape".to_string()], &sink);

        assert_eq!(
            reports[0].outcome,
            Outcome::Unknown(INVALID_SERVICE_NAME.to_string())
        );
        assert_eq!(INVALID_SERVICE_NAME, "invalid service name");
        // ...and it is what lands in the document.
        let value: serde_json::Value =
            serde_json::from_str(&report_json(PamAction::Status, false, &reports)).unwrap();
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
        }];
        let rendered = report_json(PamAction::Status, false, &reports);
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(value["services"][0]["service"], "a\"b");
    }

    /// Every word in the vocabulary is distinct and stable; this is the list
    /// `docs/contracts.md` documents.
    #[test]
    fn outcome_vocabulary_is_pinned() {
        let words: Vec<&str> = [
            Outcome::Installed,
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

        assert!(write_in(dir.path(), &add(&["system-auth"])).is_err());
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
            Sink { json: false }.notice_route(),
            Route::Notice,
            "the rollback advice must not be silenceable by --quiet"
        );
        assert_eq!(Sink { json: true }.notice_route(), Route::Dropped);

        let dir = seeded(&[("sudo", SUDO_BEFORE)]);
        write_in(dir.path(), &add(&["sudo"])).unwrap();
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
            let error = write_in(&base, &request).unwrap_err().to_string();

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

        assert!(write_in(&base, &add(&["sudo"])).is_err());
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
            write_in(dir.path(), &add(&["sudo-alias"])).unwrap(),
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

        assert!(write_in(dir.path(), &add(&["sudo", "polkit-1"])).is_err());

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

        let sink = Sink { json: true };
        let reports = status_reports(&base, &["system-auth".to_string()], &sink);

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
                &base,
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
            let error = write_in(&base, &request).unwrap_err().to_string();

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
        assert_eq!(write_in(dir.path(), &add(&["sudo"])).unwrap(), WRITE_OK);
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

        let sink = Sink { json: true };
        let reports = status_reports(&base, &["sudo".to_string()], &sink);

        assert_eq!(
            reports[0].outcome,
            Outcome::Unknown(HARD_LINKED.to_string())
        );
        assert_eq!(HARD_LINKED, "hard-linked service file");
        assert_eq!(
            status_in(
                &base,
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
        let error = write_in(refused.path(), &add(&["alias"]))
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
        assert_eq!(write_in(allowed.path(), &request).unwrap(), WRITE_OK);
        assert_eq!(read(&allowed, "system-auth"), SUDO_AFTER);
    }

    /// The gate is `add`-only and stays that way on the resolved file too:
    /// unwiring a gated service must not need an argument about it.
    #[test]
    fn the_resolved_gate_does_not_reach_remove() {
        let dir = seeded(&[("system-auth", OMARCHY_PRESENT)]);
        std::os::unix::fs::symlink("system-auth", dir.path().join("alias")).unwrap();

        assert_eq!(write_in(dir.path(), &remove(&["alias"])).unwrap(), WRITE_OK);
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
                dir.path(),
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
            install_for_setup(&["sudo".to_string()], true, true).unwrap_err(),
            remove_for_setup(&["sudo".to_string()], true).unwrap_err(),
        ] {
            let error = error.to_string();
            assert!(
                error.contains("Root required"),
                "expected the root refusal before any other check, got: {error}"
            );
        }
    }
}
